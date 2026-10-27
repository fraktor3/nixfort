"""Firewall step (nft.apply_policy.v1): plan from the active flow policy, TCP probes before/after,
rollback when a critical ALLOW breaks or a DENY stays open. Simulated gateway + test client;
the real nft rules are tested against the kernel in agent/tests/test_nft_real.py."""

import ipaddress

import pytest
from django.urls import reverse

from apps.execution import services
from apps.execution.agent_client import AgentResponse
from apps.execution.models import Job, JobState, JobType
from apps.policy.models import ConnectivityTest, Flow, FlowPolicyVersion
from apps.remediation import orchestrator, planner
from apps.remediation.models import ItemState, PlanState

from .test_remediation import _post_collect

pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture
def active_policy(project, lab, admin):
    pv = FlowPolicyVersion.objects.create(project=project, version=1, status="ACTIVE", author=admin)
    for name, port, action, critical in (
        ("web", 80, "ALLOW", True),
        ("app", 8080, "DENY", False),
        ("ssh", 22, "DENY", False),
    ):
        f = Flow(
            policy_version=pv,
            name=name,
            src_cidr="10.88.0.0/24",
            dst_node=lab["server"],
            dst_ip="10.99.0.10",
            port=port,
            action=action,
            critical=critical,
            probe_from=lab["client"],
        )
        f.full_clean()
        f.save()
    return pv


class Net:
    """Gateway agent + client probes over one simulated routed network."""

    def __init__(self, behaviour=None, listening=(22, 80, 8080)):
        self.table = None  # params of the applied policy
        self.pending = {}
        self.listening = set(listening)
        self.b = behaviour or {}
        self.calls = []

    def reachable(self, src_ip, dst, port):
        if port not in self.listening:
            return "CLOSED"
        if self.table is None:
            return "OPEN"
        rules = [] if self.b.get("broken_rules") else self.table["forward_allow"]
        for r in rules:
            if ipaddress.ip_address(src_ip) in ipaddress.ip_network(r["src"]) and (r["dst"], r["port"]) == (dst, port):
                return "OPEN"
        return "TIMEOUT"

    def for_node(self, node):
        net = self
        name = getattr(node, "name", node)

        class Client:
            def call(self, action, params=None, deadline_s=60):
                net.calls.append((name, action))
                ok = lambda r: AgentResponse(action=action, state="OK", result=r, os_profile="ubuntu-24.04")  # noqa: E731
                if net.b.get(action) == "transport" and (action != "nft.inspect.v1" or net.table is not None):
                    return AgentResponse(action=action, state="TRANSPORT_ERROR", error_code="timeout")
                if action == "system.ping.v1":
                    return ok({})
                if name == "nx-client" and action == "net.tcp_probe.v1":
                    return ok(
                        {
                            "results": [
                                {**t, "result": net.reachable("10.88.0.10", t["ip"], t["port"]), "latency_ms": 3}
                                for t in params["targets"]
                            ]
                        }
                    )
                if name == "nx-gateway":
                    if action == "nft.apply_policy.v1":
                        sid = "c" * 32
                        net.pending[sid] = net.table
                        net.table = params
                        return ok({"snapshot_id": sid, "rules_sha256": planner.rules_sha256(params)})
                    if action == "nft.inspect.v1":
                        t = net.table
                        return ok(
                            {
                                "nixfort_table_present": t is not None,
                                "policy_meta": {
                                    "policy_version": t["policy_version"],
                                    "rules_sha256": planner.rules_sha256(t),
                                }
                                if t
                                else None,
                                "nixfort_chains": {"forward": {"policy": "drop"}, "input": {"policy": "drop"}}
                                if t
                                else {},
                                "nixfort_input_ssh_sources": sorted(t["management_sources"]) if t else [],
                                "conflict": {"docker": False, "foreign_base_chains": []},
                            }
                        )
                    if action == "mutation.commit.v1":
                        net.pending.pop(params["snapshot_id"])
                        return ok({"committed": True, "timer_cancelled": True, "rolled_back": False})
                    if action == "mutation.rollback_now.v1":
                        net.table = net.pending.pop(params["snapshot_id"])
                        return ok({"rolled_back": True})
                    if action == "mutation.snapshot_status.v1":
                        if params["snapshot_id"] in net.pending:  # node-side timer fired
                            net.table = net.pending.pop(params["snapshot_id"])
                        return ok({"rolled_back": True})
                raise AssertionError((name, action))

        return Client()


def fw_plan(run, operator):
    plan = planner.create_plan(run, operator, key_only_confirmed=False)
    plan.items.exclude(action_id="nft.apply_policy.v1").delete()
    return plan


def run_plan(client_as, admin, plan, net, monkeypatch):
    monkeypatch.setattr(orchestrator, "client_for", net.for_node)
    monkeypatch.setattr(orchestrator.time, "sleep", lambda s: net.calls.append(("sleep", s)))
    monkeypatch.setattr("apps.inventory.collector.collect_node", _post_collect({}))
    r = client_as(admin).post(reverse("remediation:plan_approve", args=[plan.project_id, plan.id]), {"confirm": "on"})
    assert r.status_code == 302
    plan.refresh_from_db()
    return plan, Job.objects.get(id=plan.job_id)


def probes(item, phase):
    return {(r.port, r.result, r.verdict) for r in ConnectivityTest.objects.filter(plan_item=item, phase=phase)}


def test_plan_contains_firewall_step_from_policy(active_policy, baseline_run, operator, project):
    project.admin_sources = ["10.0.2.2"]
    project.save()
    plan = planner.create_plan(baseline_run, operator, key_only_confirmed=False)
    item = plan.items.get(action_id="nft.apply_policy.v1")
    assert item.node.name == "nx-gateway" and item.risk == "HIGH" and plan.risk == "HIGH"
    assert item.check_ids == ["FW-02", "FW-03"]
    assert item.params["forward_allow"] == [{"src": "10.88.0.0/24", "dst": "10.99.0.10", "port": 80}]
    assert item.params["management_sources"] == ["10.77.0.10", "10.0.2.2"]
    assert item.order == max(i.order for i in plan.items.filter(node=item.node))  # firewall last on its node
    assert not any(n["check_id"] in {"FW-02", "FW-03"} for n in plan.not_covered)
    # contract with the agent: schema and the hash written into the table comment
    from nixfort_agent.actions import nft as agent_nft
    from nixfort_agent.registry import load_all

    validated = load_all()["nft.apply_policy.v1"].params.validate(item.params)
    assert agent_nft.rules_sha256(validated) == planner.rules_sha256(item.params)


def test_no_active_policy_no_firewall_step(baseline_run, operator):
    plan = planner.create_plan(baseline_run, operator, key_only_confirmed=False)
    assert not plan.items.filter(action_id="nft.apply_policy.v1").exists()


def test_critical_allow_without_probe_node_is_not_planned(active_policy, baseline_run, operator):
    active_policy.flows.filter(port=80).update(probe_from=None)
    plan = planner.create_plan(baseline_run, operator, key_only_confirmed=False)
    assert not plan.items.filter(action_id="nft.apply_policy.v1").exists()
    assert any("тестовый узел" in n["reason"] for n in plan.not_covered)


def test_firewall_verified_with_proven_blocking(client_as, admin, operator, active_policy, baseline_run, monkeypatch):
    net = Net()
    plan, job = run_plan(client_as, admin, fw_plan(baseline_run, operator), net, monkeypatch)
    item = plan.items.get()
    assert item.state == ItemState.VERIFIED, item.result
    assert plan.state == PlanState.VERIFIED and job.state == JobState.SUCCEEDED
    assert probes(item, "BASELINE") == {(80, "OPEN", "OK"), (8080, "OPEN", "OK"), (22, "OPEN", "OK")}
    assert probes(item, "POST") == {(80, "OPEN", "OK"), (8080, "TIMEOUT", "OK"), (22, "TIMEOUT", "OK")}
    # order: baseline probes -> apply -> new connection inspect -> post probes -> commit
    seq = [a for _, a in net.calls]
    assert seq.index("net.tcp_probe.v1") < seq.index("nft.apply_policy.v1") < seq.index("nft.inspect.v1")
    assert seq[-1] == "mutation.commit.v1" or "mutation.commit.v1" in seq
    page = client_as(admin).get(reverse("remediation:plan_detail", args=[plan.project_id, plan.id])).content.decode()
    assert "Пробы соединений" in page and "блокировка доказана" in page


def test_broken_critical_allow_is_rolled_back_and_proven(
    client_as, admin, operator, active_policy, baseline_run, monkeypatch
):
    net = Net({"broken_rules": True})  # AT-13: the rule for :80 does not work
    plan, job = run_plan(client_as, admin, fw_plan(baseline_run, operator), net, monkeypatch)
    item = plan.items.get()
    assert item.state == ItemState.ROLLED_BACK, item.result
    assert net.table is None  # gateway back to the previous state
    assert (80, "TIMEOUT", "VIOLATION") in probes(item, "POST")
    assert (80, "OPEN", "OK") in {(p, r, "OK") for p, r, _ in probes(item, "AFTER_ROLLBACK")}
    assert "снова работают" in item.result["after_rollback"]
    assert plan.state == PlanState.ROLLED_BACK and job.state == JobState.ROLLED_BACK


def test_lost_management_waits_for_node_timer(client_as, admin, operator, active_policy, baseline_run, monkeypatch):
    net = Net({"nft.inspect.v1": "transport", "mutation.rollback_now.v1": "transport"})
    plan, job = run_plan(client_as, admin, fw_plan(baseline_run, operator), net, monkeypatch)
    item = plan.items.get()
    assert item.state == ItemState.ROLLED_BACK, item.result
    assert ("sleep", 120) in net.calls  # rollback_timeout_s 90 + 30
    assert net.table is None and probes(item, "AFTER_ROLLBACK")


def test_deny_on_closed_port_is_unprovable_not_success(
    client_as, admin, operator, active_policy, baseline_run, monkeypatch
):
    net = Net(listening=(22, 80))  # nothing listens on 8080 before the change
    plan, _ = run_plan(client_as, admin, fw_plan(baseline_run, operator), net, monkeypatch)
    item = plan.items.get()
    assert item.state == ItemState.VERIFIED
    assert (8080, "CLOSED", "UNPROVABLE") in probes(item, "POST")


def test_policy_changed_after_planning_is_refused(client_as, admin, operator, active_policy, baseline_run, monkeypatch):
    plan = fw_plan(baseline_run, operator)
    active_policy.status = "SUPERSEDED"
    active_policy.save()
    FlowPolicyVersion.objects.create(project=active_policy.project, version=2, status="ACTIVE")
    net = Net()
    plan, _ = run_plan(client_as, admin, plan, net, monkeypatch)
    assert plan.items.get().state == ItemState.FAILED
    assert not any(a == "nft.apply_policy.v1" for _, a in net.calls)


def test_connectivity_check_job_and_page(client_as, operator, active_policy, project, monkeypatch):
    from apps.policy import connectivity

    net = Net()
    net.table = {"forward_allow": [{"src": "10.88.0.0/24", "dst": "10.99.0.10", "port": 80}]}
    monkeypatch.setattr(connectivity, "client_for", net.for_node)
    r = client_as(operator).post(reverse("policy:connectivity_run", args=[project.id]))
    assert r.status_code == 302
    job = Job.objects.get(type=JobType.CONNECTIVITY)
    assert job.state == JobState.SUCCEEDED, job.result
    rows = {(t.port, t.result, t.verdict) for t in ConnectivityTest.objects.filter(job=job)}
    assert rows == {(80, "OPEN", "OK"), (8080, "TIMEOUT", "OK"), (22, "TIMEOUT", "OK")}
    page = client_as(operator).get(reverse("policy:connectivity", args=[project.id])).content.decode()
    assert "Проверить соединения" in page and "TIMEOUT" in page


def test_viewer_cannot_run_connectivity(client_as, viewer, active_policy, project):
    r = client_as(viewer).post(reverse("policy:connectivity_run", args=[project.id]))
    assert r.status_code == 403
    assert not Job.objects.filter(type=JobType.CONNECTIVITY).exists()
    assert services  # imported for the job engine
