"""Planner + orchestrator against a simulated node (no network). The real node behaviour is
covered by agent tests and by S-004 on the lab."""

import json
from pathlib import Path

import pytest
from django.urls import reverse
from django.utils import timezone

from apps.checks.tests.test_engine import FX
from apps.execution import services
from apps.execution.agent_client import AgentResponse
from apps.execution.models import Job, JobState, JobType
from apps.inventory.models import HostKey, InventorySnapshot
from apps.remediation import orchestrator, planner
from apps.remediation.models import ItemState, PlanState, RemediationPlan

pytestmark = pytest.mark.django_db(transaction=True)


class FakeNode:
    """Server state as the agent would report it."""

    def __init__(self, behaviour=None):
        self.f2b = None
        self.ssh = {
            "permitrootlogin": "without-password",
            "passwordauthentication": "yes",
            "permitemptypasswords": "no",
            "maxauthtries": "6",
            "logingracetime": "120",
            "x11forwarding": "yes",
        }
        self.packages = {"fail2ban": None}
        self.pending = {}  # snapshot_id -> previous state
        self.behaviour = behaviour or {}
        self.calls = []

    def call(self, action, params=None, deadline_s=60):
        self.calls.append(action)
        b = self.behaviour.get(action)
        if b == "transport":
            return AgentResponse(action=action, state="TRANSPORT_ERROR", error_code="timeout")
        if b == "failed":
            return AgentResponse(action=action, state="FAILED", error_code="validation_failed")
        ok = lambda r: AgentResponse(action=action, state="OK", result=r, os_profile="ubuntu-24.04")  # noqa: E731
        if action == "system.ping.v1":
            return ok({"hostname": "nx-server"})
        if action == "pkg.install_security_tool.v1":
            self.packages[params["package"]] = "1.0.2-3ubuntu0.1"
            return ok({"installed": True})
        if action == "system.collect_facts.v1":
            return ok({"packages": self.packages})
        if action == "fail2ban.apply_sshd_profile.v1":
            sid = "a" * 32
            self.pending[sid] = ("f2b", self.f2b)
            self.f2b = {
                "enabled": True,
                "maxretry": params["maxretry"],
                "bantime": params["bantime_s"],
                "findtime": params["findtime_s"],
            }
            if self.behaviour.get("f2b_wrong"):
                self.f2b["maxretry"] = 10
            return ok({"snapshot_id": sid})
        if action == "fail2ban.read_status.v1":
            return ok({"service": "active", "sshd": self.f2b})
        if action == "ssh.apply_hardening_profile.v1":
            sid = "b" * 32
            self.pending[sid] = ("ssh", dict(self.ssh))
            self.ssh.update(
                permitrootlogin="no",
                maxauthtries=str(params["max_auth_tries"]),
                logingracetime=str(params["login_grace_time_s"]),
                x11forwarding="no",
                passwordauthentication="no" if not params["password_authentication"] else "yes",
            )
            return ok({"snapshot_id": sid})
        if action == "ssh.read_effective_config.v1":
            if self.behaviour.get("ssh_lost_after_apply") and "ssh.apply_hardening_profile.v1" in self.calls:
                return AgentResponse(action=action, state="TRANSPORT_ERROR", error_code="auth_failed")
            return ok({"config_valid": True, "effective": self.ssh})
        if action == "mutation.commit.v1":
            self.pending.pop(params["snapshot_id"], None)
            return ok({"committed": True, "timer_cancelled": True, "rolled_back": False})
        if action == "mutation.rollback_now.v1":
            kind, prev = self.pending.pop(params["snapshot_id"])
            if kind == "f2b":
                self.f2b = prev
            else:
                self.ssh = prev
            return ok({"rolled_back": True})
        if action == "mutation.snapshot_status.v1":
            # the node-side timer fired while we were away
            if params["snapshot_id"] in self.pending:
                kind, prev = self.pending.pop(params["snapshot_id"])
                self.ssh = prev if kind == "ssh" else self.ssh
            return ok({"rolled_back": self.behaviour.get("timer_works", True)})
        raise AssertionError(action)


@pytest.fixture
def lab(project, lab_nodes, admin):
    for n in lab_nodes.values():
        HostKey.objects.create(
            node=n,
            key_type="ssh-ed25519",
            public_key="AAAA",
            fingerprint_sha256="x",
            confirmed_by=admin,
            confirmed_at=timezone.now(),
        )
    return lab_nodes


@pytest.fixture
def baseline_run(project, lab, operator, monkeypatch):
    def collect(node, job=None, log=None):
        facts = json.loads((Path(FX) / f"lab_{node.name.replace('nx-', '')}_baseline.json").read_text("utf-8"))
        return InventorySnapshot.objects.create(
            node=node, job=job, collected_at=timezone.now(), facts=facts, agent_version="1.0.0", sha256="0" * 64
        )

    monkeypatch.setattr("apps.inventory.collector.collect_node", collect)
    job = services.create_job(JobType.AUDIT, project, operator)
    job.refresh_from_db()
    return job.audit_run


def test_planner_from_real_lab_baseline(baseline_run, operator):
    plan = planner.create_plan(baseline_run, operator, key_only_confirmed=False)
    steps = [(i.node.name, i.action_id, i.check_ids) for i in plan.items.all()]
    assert steps[0] == ("nx-server", "pkg.install_security_tool.v1", ["F2B-01"])
    assert ("nx-server", "fail2ban.apply_sshd_profile.v1", ["F2B-01", "F2B-02", "F2B-03"]) in steps
    ssh_steps = [s for s in steps if s[1] == "ssh.apply_hardening_profile.v1"]
    assert {s[0] for s in ssh_steps} == {"nx-gateway", "nx-server"}
    assert all("SSH-02" not in s[2] for s in ssh_steps)  # not confirmed -> password login untouched
    srv_ssh = plan.items.get(node__name="nx-server", action_id="ssh.apply_hardening_profile.v1")
    assert srv_ssh.params["password_authentication"] is True and srv_ssh.risk == "MEDIUM"
    assert {n["check_id"] for n in plan.not_covered} >= {"SSH-02", "SYS-04", "FW-03", "IDS-01"}
    # order: install -> fail2ban -> ssh (low risk first)
    orders = [i.action_id for i in plan.items.all()]
    assert orders.index("fail2ban.apply_sshd_profile.v1") < orders.index("ssh.apply_hardening_profile.v1")


def test_planner_key_only_confirmed_is_high_risk(baseline_run, operator):
    plan = planner.create_plan(baseline_run, operator, key_only_confirmed=True)
    srv = plan.items.get(node__name="nx-server", action_id="ssh.apply_hardening_profile.v1")
    assert srv.params["password_authentication"] is False and "SSH-02" in srv.check_ids
    assert srv.risk == "HIGH" and plan.risk == "HIGH"


def approve_and_run(client_as, admin, plan, fake_nodes, monkeypatch, sleep_calls=None):
    monkeypatch.setattr(orchestrator, "client_for", lambda node: fake_nodes[node.name])
    monkeypatch.setattr(
        orchestrator.time, "sleep", lambda s: (sleep_calls if sleep_calls is not None else []).append(s)
    )
    monkeypatch.setattr("apps.inventory.collector.collect_node", _post_collect(fake_nodes))
    r = client_as(admin).post(reverse("remediation:plan_approve", args=[plan.project_id, plan.id]), {"confirm": "on"})
    assert r.status_code == 302
    plan.refresh_from_db()
    return plan, Job.objects.get(id=plan.job_id)


def _post_collect(fake_nodes):
    def collect(node, job=None, log=None):
        f = json.loads((Path(FX) / f"lab_{node.name.replace('nx-', '')}_baseline.json").read_text("utf-8"))
        fake = fake_nodes.get(node.name)
        if fake:
            f["ssh"]["result"]["effective"].update(fake.ssh)
            if fake.f2b:
                f["system"]["result"]["packages"]["fail2ban"] = "1.0.2"
                f["system"]["result"]["services"]["fail2ban"] = "active"
                f["fail2ban"]["result"] = {"installed": True, "service": "active", "jails": ["sshd"], "sshd": fake.f2b}
        return InventorySnapshot.objects.create(
            node=node, job=job, collected_at=timezone.now(), facts=f, agent_version="1.0.0", sha256="0" * 64
        )

    return collect


def only_server_plan(baseline_run, operator):
    plan = planner.create_plan(baseline_run, operator, key_only_confirmed=False)
    plan.items.exclude(node__name="nx-server").delete()
    return plan


def test_happy_path_verified_and_before_after(client_as, admin, operator, baseline_run, monkeypatch):
    plan = only_server_plan(baseline_run, operator)
    srv = FakeNode()
    plan, job = approve_and_run(client_as, admin, plan, {"nx-server": srv}, monkeypatch)
    assert plan.state == PlanState.VERIFIED, [(i.action_id, i.state, i.result) for i in plan.items.all()]
    assert job.state == JobState.SUCCEEDED
    assert set(plan.items.values_list("state", flat=True)) == {ItemState.VERIFIED}
    # verification used fresh calls after apply; commit only after verification
    assert srv.calls.index("ssh.read_effective_config.v1") < len(srv.calls) - 1
    assert srv.calls[-1] == "mutation.commit.v1"
    post = {(r.node.name, r.check_id): r.status for r in plan.post_audit_run.results.select_related("node")}
    assert post[("nx-server", "SSH-01")] == "PASS" and post[("nx-server", "F2B-02")] == "PASS"
    page = client_as(admin).get(reverse("remediation:plan_detail", args=[plan.project_id, plan.id])).content.decode()
    assert "До / после" in page


def test_failed_verification_rolls_back(client_as, admin, operator, baseline_run, monkeypatch):
    plan = only_server_plan(baseline_run, operator)
    srv = FakeNode({"f2b_wrong": True})
    plan, job = approve_and_run(client_as, admin, plan, {"nx-server": srv}, monkeypatch)
    f2b = plan.items.get(action_id="fail2ban.apply_sshd_profile.v1")
    assert f2b.state == ItemState.ROLLED_BACK and "mutation.rollback_now.v1" in srv.calls
    assert srv.f2b is None  # node back to previous state
    assert plan.items.get(action_id="ssh.apply_hardening_profile.v1").state == ItemState.SKIPPED
    assert plan.state == PlanState.PARTIAL and job.state == JobState.ROLLED_BACK  # install was verified


def test_lost_connection_waits_for_node_timer(client_as, admin, operator, baseline_run, monkeypatch):
    plan = only_server_plan(baseline_run, operator)
    plan.items.exclude(action_id="ssh.apply_hardening_profile.v1").delete()
    srv = FakeNode({"ssh_lost_after_apply": True, "mutation.rollback_now.v1": "transport"})
    sleeps = []
    plan, job = approve_and_run(client_as, admin, plan, {"nx-server": srv}, monkeypatch, sleeps)
    item = plan.items.get()
    assert item.state == ItemState.ROLLED_BACK, item.result
    assert sleeps and sleeps[0] >= 90  # waited for the node-side timer
    assert srv.ssh["permitrootlogin"] == "without-password"
    assert job.state == JobState.ROLLED_BACK and plan.state == PlanState.ROLLED_BACK


def test_unconfirmed_rollback_is_unknown(client_as, admin, operator, baseline_run, monkeypatch):
    plan = only_server_plan(baseline_run, operator)
    plan.items.exclude(action_id="ssh.apply_hardening_profile.v1").delete()
    srv = FakeNode(
        {
            "ssh_lost_after_apply": True,
            "mutation.rollback_now.v1": "transport",
            "mutation.snapshot_status.v1": "transport",
        }
    )
    plan, job = approve_and_run(client_as, admin, plan, {"nx-server": srv}, monkeypatch, [])
    assert plan.items.get().state == ItemState.UNKNOWN
    assert plan.state == PlanState.UNKNOWN and job.state == JobState.UNKNOWN  # never a fake success


def test_agent_validation_failure_changes_nothing(client_as, admin, operator, baseline_run, monkeypatch):
    plan = only_server_plan(baseline_run, operator)
    plan.items.exclude(action_id="ssh.apply_hardening_profile.v1").delete()
    srv = FakeNode({"ssh.apply_hardening_profile.v1": "failed"})
    plan, job = approve_and_run(client_as, admin, plan, {"nx-server": srv}, monkeypatch)
    assert plan.items.get().state == ItemState.FAILED and plan.state == PlanState.FAILED
    assert "mutation.commit.v1" not in srv.calls and plan.post_audit_run is None


def test_plan_tampering_after_approval_is_refused(client_as, admin, operator, baseline_run, monkeypatch):
    plan = only_server_plan(baseline_run, operator)
    srv = FakeNode()
    monkeypatch.setattr(orchestrator, "client_for", lambda node: srv)
    monkeypatch.setattr("apps.execution.tasks.run_job.apply_async", lambda *a, **k: None)
    client_as(admin).post(reverse("remediation:plan_approve", args=[plan.project_id, plan.id]), {"confirm": "on"})
    plan.refresh_from_db()
    item = plan.items.first()
    item.params = {**item.params, "package": "suricata"}
    item.save()
    job = Job.objects.get(id=plan.job_id)
    from apps.execution.tasks import run_job

    run_job(str(job.id))
    job.refresh_from_db()
    assert job.state == JobState.FAILED and srv.calls == []


def test_operator_cannot_approve_and_confirm_required(client_as, operator, admin, baseline_run):
    plan = planner.create_plan(baseline_run, operator, key_only_confirmed=False)
    r = client_as(operator).post(
        reverse("remediation:plan_approve", args=[plan.project_id, plan.id]), {"confirm": "on"}
    )
    assert r.status_code == 403
    client_as(admin).post(reverse("remediation:plan_approve", args=[plan.project_id, plan.id]))  # no confirm
    plan.refresh_from_db()
    assert plan.state == PlanState.DRAFT


def test_create_plan_view(client_as, operator, baseline_run):
    r = client_as(operator).post(reverse("remediation:plan_create", args=[baseline_run.project_id, baseline_run.id]))
    assert r.status_code == 302
    assert RemediationPlan.objects.count() == 1


@pytest.mark.parametrize("key_only", [False, True])
def test_plan_params_satisfy_agent_schemas(baseline_run, operator, key_only):
    """Contract: every parameter the controller sends must pass the agent's own validation."""
    from nixfort_agent.registry import load_all

    registry = load_all()
    plan = planner.create_plan(baseline_run, operator, key_only_confirmed=key_only)
    assert plan.items.exists()
    for item in plan.items.all():
        registry[item.action_id].params.validate(item.params)  # raises Rejected on mismatch


def test_controller_knows_every_agent_action():
    from apps.execution.agent_client import KNOWN_ACTIONS
    from nixfort_agent.registry import load_all

    agent = load_all()
    assert set(KNOWN_ACTIONS) <= set(agent)
    for name, mutating in KNOWN_ACTIONS.items():
        assert agent[name].mutating == mutating, name
