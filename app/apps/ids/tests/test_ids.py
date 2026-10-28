"""Suricata step of a plan, IDS events and protection scenarios against a simulated lab
(the rules themselves were checked against real Suricata 7.0.3 on live traffic, agent/tests/test_suricata_real.py)."""

import ipaddress

import pytest
from django.urls import reverse
from django.utils import timezone

from apps.execution.agent_client import AgentResponse
from apps.execution.models import Job, JobState, JobType
from apps.ids import scenarios
from apps.ids.models import IdsEvent, ProtectionTest
from apps.policy.models import Flow, FlowPolicyVersion
from apps.remediation import orchestrator, planner
from apps.remediation.models import ItemState, PlanState
from apps.remediation.tests.test_remediation import _post_collect

pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture
def policy(project, lab, admin):
    pv = FlowPolicyVersion.objects.create(project=project, version=1, status="ACTIVE", author=admin)
    for name, port, action, critical in (("web", 80, "ALLOW", True), ("app", 8080, "DENY", False),
                                         ("ssh", 22, "DENY", False)):  # fmt: skip
        f = Flow(policy_version=pv, name=name, src_cidr="10.88.0.0/24", dst_node=lab["server"], dst_ip="10.99.0.10",
                 port=port, action=action, critical=critical, probe_from=lab["client"])  # fmt: skip
        f.full_clean()
        f.save()
    return pv


class Lab:
    """Gateway (nftables + Suricata), server (sshd + Fail2ban), client (attacker)."""

    def __init__(self, firewall=True, sensor="ok", f2b=True, suricata_installed=False):
        self.firewall, self.sensor, self.f2b = firewall, sensor, f2b
        self.allowed = {("10.99.0.10", 80)}
        self.listening = {("10.99.0.10", 22), ("10.99.0.10", 80), ("10.99.0.10", 8080), ("10.77.0.30", 22)}
        self.eve, self.banned, self.failures = [], [], 0
        self.suricata = {"installed": suricata_installed, "service": "failed", "iface": ["eth0"]}
        self.calls = []
        self.pcap = None  # what net.capture.v1 on the gateway returns (None: tcpdump is missing)
        self.host_fw = None  # SSH sources allowed by the server's host firewall (None: no host firewall)

    def _event(self, sid, src, dst, port):
        ts = timezone.now().astimezone(timezone.get_fixed_timezone(180)).isoformat()
        self.eve.append({"timestamp": ts, "event_type": "alert", "src_ip": src, "src_port": 40000, "dest_ip": dst,
                         "dest_port": port, "proto": "TCP", "alert": {"signature_id": sid, "signature": f"NIXFORT {sid}",
                                                                      "severity": 3}})  # fmt: skip

    def reach(self, src, dst, port):
        if (dst, port) not in self.listening:
            return "CLOSED"
        via_gateway = dst.startswith("10.99.")
        if via_gateway and self.firewall and (dst, port) not in self.allowed:
            return "TIMEOUT"
        if (
            dst == "10.77.0.30"
            and self.host_fw is not None
            and not any(ipaddress.ip_address(src) in ipaddress.ip_network(n, strict=False) for n in self.host_fw)
        ):
            return "TIMEOUT"  # host firewall on the server: policy drop
        if dst == "10.77.0.30" and src in self.banned:
            return "CLOSED"
        return "OPEN"

    def for_node(self, node):
        lab, name = self, node.name

        class C:
            def call(self, action, params=None, deadline_s=60):
                lab.calls.append((name, action))
                ok = lambda r: AgentResponse(action=action, state="OK", result=r, os_profile="ubuntu-24.04")  # noqa: E731
                p = params or {}
                if action == "system.ping.v1":
                    return ok({})
                if name == "nx-client":
                    src_data, src_mgmt = "10.88.0.10", "10.77.0.40"
                    if action == "net.send_ids_test.v1":
                        sent = lab.reach(src_data, p["ip"], p["port"]) == "OPEN"
                        if sent and lab.sensor == "ok":
                            lab._event(9000001, src_data, p["ip"], p["port"])
                        return ok({"sent": sent})
                    if action == "net.tcp_probe.v1":
                        res = [{**t, "result": lab.reach(src_data, t["ip"], t["port"]), "latency_ms": 1}
                               for t in p["targets"]]  # fmt: skip
                        if len(res) >= 20 and lab.sensor == "ok":
                            lab._event(9000002, src_data, p["targets"][0]["ip"], p["targets"][0]["port"])
                        return ok({"results": res})
                    if action == "net.load_test.v1":
                        reachable = lab.reach(src_data, p["ip"], p["port"]) == "OPEN"
                        n = p["connections"]
                        ok_n = n if reachable else 0
                        if lab.sensor == "ok":  # a burst of new connections trips the "many SYN" rule
                            lab._event(9000002, src_data, p["ip"], p["port"])
                        return ok(
                            {
                                "target": f"{p['ip']}:{p['port']}",
                                "attempted": n,
                                "succeeded": ok_n,
                                "refused": 0 if reachable else n,
                                "timed_out": 0,
                                "unreachable": 0,
                                "error": 0,
                                "service_available": reachable,
                                "avg_latency_ms": 2.0 if reachable else None,
                                "p95_latency_ms": 3.0 if reachable else None,
                                "rate_per_s": 100.0,
                            }
                        )
                    if action == "net.ssh_login_attempts.v1":
                        src = src_mgmt if p["ip"].startswith("10.77.") else src_data
                        out = []
                        for i in range(p["count"]):
                            r = lab.reach(src, p["ip"], p["port"])
                            if r == "OPEN":
                                r = "REJECTED"
                                lab.failures += 1
                                if lab.f2b and lab.failures >= 5 and src not in lab.banned:
                                    lab.banned.append(src)
                            out.append({"attempt": i + 1, "result": r, "latency_ms": 5})
                        if p["ip"].startswith("10.99.") and lab.sensor == "ok":
                            lab._event(9000003, src_data, p["ip"], 22)
                        summ = {
                            k: sum(1 for x in out if x["result"] == k)
                            for k in ("REJECTED", "CLOSED", "TIMEOUT", "ERROR")
                        }
                        return ok({"attempts": out, "summary": summ})
                if name == "nx-gateway":
                    if action == "net.capture.v1":
                        if lab.pcap is None:
                            return AgentResponse(action=action, state="REJECTED", error_code="tool_missing")
                        import base64

                        return ok({"pcap_b64": base64.b64encode(lab.pcap).decode(), "captured": 240,
                                   "dropped_by_kernel": 0, "truncated": False})  # fmt: skip
                    if action == "suricata.read_events.v1":
                        if lab.sensor == "unreadable":
                            return ok({"eve_available": False, "reason": "eve_unreadable", "events": []})
                        import json

                        from nixfort_agent import parsers

                        evs = parsers.parse_eve_lines([json.dumps(e) for e in lab.eve], p["since_ts"],
                                                      set(p["types"]), p["limit"])  # fmt: skip
                        return ok({"eve_available": True, "reason": None, "events": evs})
                    if action == "pkg.install_security_tool.v1":
                        lab.suricata["installed"] = True
                        return ok({"installed": True})
                    if action == "system.collect_facts.v1":
                        return ok({"packages": {"suricata": "7.0.3" if lab.suricata["installed"] else None}})
                    if action == "suricata.apply_sensor_profile.v1":
                        lab.prev = dict(lab.suricata)
                        lab.suricata.update(service="active", iface=[p["interface"]])
                        return ok({"snapshot_id": "d" * 32})
                    if action == "suricata.read_status.v1":
                        s = lab.suricata
                        return ok({"installed": s["installed"], "service": s["service"], "version": "7.0.3",
                                   "config_test": {"ok": True}, "af_packet_interfaces": s["iface"],
                                   "eve": {"enabled": True, "readable": lab.sensor != "unreadable"},
                                   "nixfort_test_rule_loaded": True})  # fmt: skip
                    if action == "mutation.commit.v1":
                        return ok({"committed": True, "timer_cancelled": True, "rolled_back": False})
                    if action == "mutation.rollback_now.v1":
                        lab.suricata = lab.prev
                        return ok({"rolled_back": True})
                if name == "nx-server" and action == "nft.inspect.v1":
                    if lab.host_fw is None:
                        return ok({"nixfort_table_present": False, "nixfort_chains": {}})
                    return ok({"nixfort_table_present": True, "nixfort_chains": {"input": {"policy": "drop"}},
                               "nixfort_input_ssh_sources": list(lab.host_fw), "nixfort_input_ports": [80]})  # fmt: skip
                if name == "nx-server" and action == "fail2ban.read_status.v1":
                    if not lab.f2b:
                        return ok({"service": "inactive", "sshd": None})
                    return ok({"service": "active", "sshd": {"enabled": True, "maxretry": 5, "bantime": 600,
                                                              "banned_ips": list(lab.banned)}})  # fmt: skip
                raise AssertionError((name, action))

        return C()


def run_job(client_as, user, url, lab, monkeypatch):
    monkeypatch.setattr(scenarios, "client_for", lab.for_node)
    monkeypatch.setattr(scenarios.time, "sleep", lambda s: None)
    r = client_as(user).post(url)
    return r


# ---------------------------------------------------------------- plan step
def test_sensor_step_installs_configures_and_verifies(client_as, admin, operator, baseline_run, monkeypatch):
    plan = planner.create_plan(baseline_run, operator, key_only_confirmed=False)
    plan.items.exclude(node__name="nx-gateway").delete()
    plan.items.filter(action_id="ssh.apply_hardening_profile.v1").delete()
    lab = Lab()
    monkeypatch.setattr(orchestrator, "client_for", lab.for_node)
    monkeypatch.setattr("apps.inventory.collector.collect_node", _post_collect({}))
    client_as(admin).post(reverse("remediation:plan_approve", args=[plan.project_id, plan.id]), {"confirm": "on"})
    plan.refresh_from_db()
    states = {i.action_id: i.state for i in plan.items.all()}
    assert states == {"pkg.install_security_tool.v1": ItemState.VERIFIED,
                      "suricata.apply_sensor_profile.v1": ItemState.VERIFIED}, plan.items.values("result")  # fmt: skip
    assert plan.state == PlanState.VERIFIED and lab.suricata["iface"] == ["enp0s9"]


def test_sensor_not_listening_is_rolled_back(client_as, admin, operator, baseline_run, monkeypatch):
    plan = planner.create_plan(baseline_run, operator, key_only_confirmed=False)
    plan.items.exclude(action_id="suricata.apply_sensor_profile.v1").delete()
    lab = Lab(suricata_installed=True, sensor="unreadable")  # EVE unreadable -> verification fails
    monkeypatch.setattr(orchestrator, "client_for", lab.for_node)
    client_as(admin).post(reverse("remediation:plan_approve", args=[plan.project_id, plan.id]), {"confirm": "on"})
    item = plan.items.get()
    assert item.state == ItemState.ROLLED_BACK and "EVE" in item.result["reason"]
    assert lab.suricata["service"] == "failed"


# ---------------------------------------------------------------- protection scenarios
def _test(scenario):
    return ProtectionTest.objects.filter(scenario=scenario).latest("created_at")


def test_ids_marker_detected(client_as, operator, project, policy, monkeypatch):
    lab = Lab()
    r = run_job(client_as, operator, reverse("ids:protection_run", args=[project.id, "IDS_MARKER"]), lab, monkeypatch)
    assert r.status_code == 302
    t = _test("IDS_MARKER")
    assert t.verdict == "PROTECTED", t.layers
    assert ("nx-client", "net.send_ids_test.v1") in lab.calls
    assert IdsEvent.objects.filter(signature_id=9000001, src_ip="10.88.0.10").exists()
    assert Job.objects.get(type=JobType.IDS_TEST).state == JobState.SUCCEEDED


def test_ids_marker_log_unavailable_is_not_no_attack(client_as, operator, project, policy, monkeypatch):
    run_job(client_as, operator, reverse("ids:protection_run", args=[project.id, "IDS_MARKER"]), Lab(sensor="unreadable"),
            monkeypatch)  # fmt: skip
    t = _test("IDS_MARKER")
    assert t.verdict == "ERROR" and t.layers[0]["ok"] is None and "недоступен" in t.layers[0]["observed"]
    run_job(client_as, operator, reverse("ids:protection_run", args=[project.id, "IDS_MARKER"]), Lab(sensor="blind"),
            monkeypatch)  # fmt: skip
    t = _test("IDS_MARKER")
    assert t.verdict == "NOT_PROTECTED" and t.layers[0]["observed"] == "событий нет"


def test_port_scan(client_as, admin, project, policy, monkeypatch):
    run_job(client_as, admin, reverse("ids:protection_run", args=[project.id, "PORT_SCAN"]), Lab(), monkeypatch)
    t = _test("PORT_SCAN")
    assert t.verdict == "PROTECTED", t.layers
    assert t.details["open_ports"] == [80]
    run_job(client_as, admin, reverse("ids:protection_run", args=[project.id, "PORT_SCAN"]), Lab(firewall=False),
            monkeypatch)  # fmt: skip
    t = _test("PORT_SCAN")
    assert t.verdict == "PARTIAL" and t.layers[0]["ok"] is False and "8080" in t.layers[0]["observed"]


def test_ssh_bruteforce_defence_in_depth(client_as, admin, project, policy, monkeypatch):
    lab = Lab()
    run_job(client_as, admin, reverse("ids:protection_run", args=[project.id, "SSH_BRUTEFORCE"]), lab, monkeypatch)
    t = _test("SSH_BRUTEFORCE")
    assert t.verdict == "PROTECTED", t.layers
    assert [lay["layer"] for lay in t.layers] == ["Межсетевой экран (шлюз)", "Suricata (шлюз)", "Fail2ban (сервер)"]
    assert t.details["through_gateway"]["REJECTED"] == 0 and "10.77.0.40" in lab.banned


def test_ssh_bruteforce_without_fail2ban(client_as, admin, project, policy, monkeypatch):
    run_job(client_as, admin, reverse("ids:protection_run", args=[project.id, "SSH_BRUTEFORCE"]), Lab(f2b=False),
            monkeypatch)  # fmt: skip
    t = _test("SSH_BRUTEFORCE")
    assert t.verdict == "PARTIAL" and t.layers[-1]["ok"] is False


def test_attacks_are_admin_only(client_as, operator, viewer, project, policy):
    r = client_as(operator).post(reverse("ids:protection_run", args=[project.id, "PORT_SCAN"]))
    assert r.status_code == 403
    r = client_as(viewer).post(reverse("ids:protection_run", args=[project.id, "IDS_MARKER"]))
    assert r.status_code == 403
    assert not Job.objects.exists()


def test_fetch_events_and_pages(client_as, operator, project, policy, monkeypatch):
    lab = Lab()
    lab._event(9000002, "10.88.0.10", "10.99.0.10", 22)
    lab.eve.append({"timestamp": "bad", "event_type": "alert", "alert": {"signature_id": 1}})
    run_job(client_as, operator, reverse("ids:fetch", args=[project.id]), lab, monkeypatch)
    assert IdsEvent.objects.count() == 1
    run_job(client_as, operator, reverse("ids:fetch", args=[project.id]), lab, monkeypatch)  # nothing new
    assert IdsEvent.objects.count() == 1
    page = client_as(operator).get(reverse("ids:sensor", args=[project.id])).content.decode()
    assert "sid 9000002" in page and "NIXFORT" not in page  # rule prefix is not shown
    page = client_as(operator).get(reverse("ids:protection", args=[project.id])).content.decode()
    assert "Подбор пароля SSH" in page and "только администратор" in page
    assert ipaddress  # noqa


def test_activation_failed_on_node_is_failed_not_unknown(client_as, admin, operator, baseline_run, monkeypatch):
    """S-006: the agent restored the previous state itself -> the step is FAILED with a clear reason."""
    plan = planner.create_plan(baseline_run, operator, key_only_confirmed=False)
    plan.items.exclude(action_id="suricata.apply_sensor_profile.v1").delete()
    lab = Lab(suricata_installed=True)
    real = lab.for_node

    def for_node(node):
        c = real(node)
        orig = c.call

        def call(action, params=None, deadline_s=60):
            if action == "suricata.apply_sensor_profile.v1":
                return AgentResponse(action=action, state="FAILED", error_code="activation_failed")
            return orig(action, params, deadline_s)

        c.call = call
        return c

    monkeypatch.setattr(orchestrator, "client_for", for_node)
    client_as(admin).post(reverse("remediation:plan_approve", args=[plan.project_id, plan.id]), {"confirm": "on"})
    plan.refresh_from_db()
    item = plan.items.get()
    assert item.state == ItemState.FAILED and "восстановил прежнюю" in item.result["reason"]
    assert plan.state == PlanState.FAILED


def test_load_resilience(client_as, admin, project, policy, monkeypatch):
    lab = Lab()  # 80 allowed, 8080/22 denied
    run_job(client_as, admin, reverse("ids:protection_run", args=[project.id, "LOAD"]), lab, monkeypatch)
    t = ProtectionTest.objects.filter(scenario="LOAD").latest("created_at")
    kinds = [lay["layer"] for lay in t.layers]
    assert "Доступность сервиса" in kinds and "Межсетевой экран (шлюз)" in kinds and "Suricata (шлюз)" in kinds
    avail = next(x for x in t.layers if x["layer"] == "Доступность сервиса")
    fw = next(x for x in t.layers if x["layer"] == "Межсетевой экран (шлюз)")
    assert avail["ok"] is True and fw["ok"] is True
    assert t.verdict == "PROTECTED", t.layers


def test_load_requires_admin(client_as, operator, project, policy):
    r = client_as(operator).post(reverse("ids:protection_run", args=[project.id, "LOAD"]))
    assert r.status_code == 403
    assert not Job.objects.filter(type=JobType.PROTECTION_TEST).exists()


def test_load_resilience_records_gateway_traffic(client_as, admin, project, policy, monkeypatch, settings, tmp_path):
    """T-025: the gateway is recorded during the load; the burst is visible in the analysis, verdict unchanged."""
    import shutil

    from apps.pcap.models import PcapCapture
    from apps.pcap.tests.test_pcap import make_pcap

    if not shutil.which("tshark"):
        pytest.skip("needs tshark")
    settings.NIXFORT_DATA_DIR = tmp_path
    lab = Lab()
    lab.pcap = make_pcap([(1_800_000_000 + i * 0.002, "10.88.0.10", "10.99.0.10", 80 if i < 120 else 8080, True)
                          for i in range(240)])  # fmt: skip
    run_job(client_as, admin, reverse("ids:protection_run", args=[project.id, "LOAD"]), lab, monkeypatch)
    t = ProtectionTest.objects.filter(scenario="LOAD").latest("created_at")
    assert t.verdict == "PROTECTED"
    assert ("nx-gateway", "net.capture.v1") in lab.calls
    cap = PcapCapture.objects.get(job=t.job)
    assert cap.state == "DONE" and cap.node.name == "nx-gateway" and cap.interface == "enp0s9"
    c = t.details["capture"]
    assert c["packets"] == 240 and c["peak_syn"] > 0 and "Всплеск попыток TCP-соединений" in c["findings"]
    page = client_as(admin).get(reverse("ids:protection_detail", args=[project.id, t.id])).content.decode()
    assert "Трафик на шлюзе во время проверки" in page and "<svg" in page and "полный разбор" in page


def test_load_resilience_without_capture_keeps_verdict(client_as, admin, project, policy, monkeypatch):
    lab = Lab()  # tcpdump missing on the gateway
    run_job(client_as, admin, reverse("ids:protection_run", args=[project.id, "LOAD"]), lab, monkeypatch)
    t = ProtectionTest.objects.filter(scenario="LOAD").latest("created_at")
    assert t.verdict == "PROTECTED" and t.details["capture"]["state"] == "FAILED"
    assert "tool_missing" in t.details["capture"]["error"]
    page = client_as(admin).get(reverse("ids:protection_detail", args=[project.id, t.id])).content.decode()
    assert "Запись трафика не получена" in page


def test_bruteforce_stopped_by_server_host_firewall(client_as, admin, project, policy, monkeypatch):
    """S-009: with the host firewall the direct attempts never reach sshd — that is protection, not a Fail2ban
    failure. Fail2ban is reported as «not needed» (no data), the verdict is PROTECTED."""
    lab = Lab()
    lab.host_fw = ["10.0.2.2", "10.77.0.10"]  # the client (10.77.0.40) is not a management source
    run_job(client_as, admin, reverse("ids:protection_run", args=[project.id, "SSH_BRUTEFORCE"]), lab, monkeypatch)
    t = ProtectionTest.objects.filter(scenario="SSH_BRUTEFORCE").latest("created_at")
    hfw = next(x for x in t.layers if x["layer"] == "Хостовый межсетевой экран (сервер)")
    f2b = next(x for x in t.layers if x["layer"] == "Fail2ban (сервер)")
    assert hfw["ok"] is True and "дошли до sshd: 0 из 7" in hfw["observed"]
    assert f2b["ok"] is None and "не потребовался" in f2b["observed"]
    assert t.verdict == "PROTECTED" and lab.banned == []


def test_bruteforce_client_allowed_by_host_firewall_still_checks_fail2ban(client_as, admin, project, policy,
                                                                           monkeypatch):  # fmt: skip
    lab = Lab()
    lab.host_fw = ["10.77.0.0/24"]  # the whole management network may SSH -> Fail2ban is the layer that acts
    run_job(client_as, admin, reverse("ids:protection_run", args=[project.id, "SSH_BRUTEFORCE"]), lab, monkeypatch)
    t = ProtectionTest.objects.filter(scenario="SSH_BRUTEFORCE").latest("created_at")
    assert "Хостовый межсетевой экран (сервер)" not in [x["layer"] for x in t.layers]
    assert next(x for x in t.layers if x["layer"] == "Fail2ban (сервер)")["ok"] is True
