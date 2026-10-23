import shutil

import pytest
from django.urls import reverse
from django.utils import timezone

from apps.execution.agent_client import AgentClient, AgentResponse, parse_response
from apps.inventory import collector
from apps.inventory.adapters import nmap
from apps.inventory.models import HostKey, Node

pytestmark = pytest.mark.django_db


def test_nmap_argv_is_fixed_and_scoped():
    argv = nmap.build_argv(["10.77.0.30", "10.77.0.20"], "common", ["10.77.0.0/24"]) if shutil.which("nmap") else None
    if argv:
        assert argv[1:5] == ["-sT", "-Pn", "-n", "--max-rate"]
        assert argv[-3:] == ["--", "10.77.0.20", "10.77.0.30"]
    for targets, code in [
        (["8.8.8.8"], "target_out_of_scope"),
        (["10.77.0.1;id"], "bad_targets"),
        (["-oN/tmp/x"], "bad_targets"),
        ([], "bad_targets"),
    ]:
        with pytest.raises(nmap.NmapError) as e:
            nmap.build_argv(targets, "common", ["10.77.0.0/24"])
        assert e.value.code == code
    with pytest.raises(nmap.NmapError):
        nmap.build_argv(["10.77.0.1"], "-sU", ["10.77.0.0/24"])


@pytest.mark.skipif(not shutil.which("nmap"), reason="nmap not installed")
def test_nmap_real_scan_localhost():
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        nmap.PROFILES["_t"] = ["-p", str(port)]
        try:
            res = nmap.run(["127.0.0.1"], "_t", ["127.0.0.0/8"])
        finally:
            del nmap.PROFILES["_t"]
    assert res["hosts"][0]["open_ports"] == [port]


def test_nmap_xml_parser_rejects_entities():
    evil = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>'
    with pytest.raises(Exception):  # defusedxml forbids entity declarations
        nmap.parse_xml(evil)


def test_scan_out_of_scope_blocked_before_nmap(client_as, operator, project, monkeypatch):
    Node.objects.create(project=project, name="bad", mgmt_ip="10.77.0.99", roles=["server"])
    project.cidrs = ["10.88.0.0/24"]  # node now outside the project's networks
    project.save()
    called = []
    monkeypatch.setattr("apps.inventory.adapters.nmap.run", lambda *a, **k: called.append(a))
    r = client_as(operator).post(reverse("inventory:portscan_run", args=[project.id]))
    assert r.status_code == 302 and called == []
    from apps.core.models import AuditEvent

    assert AuditEvent.objects.filter(outcome="DENIED", safe_metadata__reason="nmap_target_out_of_scope").exists()


def test_parse_response_rejects_mismatch():
    ok = b'{"protocol":"nixfort.agent/1","request_id":"r1","action":"a","state":"OK","result":{}}'
    assert parse_response(ok, "a", "r1").ok
    assert parse_response(ok, "a", "r2").error_code == "response_mismatch"
    assert parse_response(ok, "b", "r1").error_code == "response_mismatch"
    assert parse_response(b"garbage", "a", "r1").state == "PROTOCOL_ERROR"
    bad_state = ok.replace(b'"OK"', b'"PWNED"')
    assert parse_response(bad_state, "a", "r1").state == "PROTOCOL_ERROR"


def test_controller_refuses_unknown_action():
    with pytest.raises(ValueError):
        AgentClient(transport=None).call("system.exec.v1")


def test_collector_transport_failure_marks_node(project, lab_nodes, admin, monkeypatch):
    node = lab_nodes["server"]
    HostKey.objects.create(
        node=node,
        key_type="ssh-ed25519",
        public_key="AAAA",
        fingerprint_sha256="x",
        confirmed_by=admin,
        confirmed_at=timezone.now(),
    )

    class FakeClient:
        calls = 0

        def call(self, action, params, deadline_s=60):
            FakeClient.calls += 1
            return AgentResponse(action=action, state="TRANSPORT_ERROR", error_code="unreachable")

    monkeypatch.setattr(collector, "client_for", lambda n: FakeClient())
    node.refresh_from_db()
    snap = collector.collect_node(node)
    assert FakeClient.calls == 1  # stops after the first transport failure
    assert all(f["state"] == "TRANSPORT_ERROR" for f in snap.facts.values())
    node.refresh_from_db()
    assert node.status == Node.Status.UNREACHABLE


def test_collector_unconfirmed_key_does_not_connect(project, lab_nodes, monkeypatch):
    node = lab_nodes["server"]
    snap = collector.collect_node(node)
    assert {f["error_code"] for f in snap.facts.values()} == {"host_key_not_confirmed"}
    node.refresh_from_db()
    assert node.status == Node.Status.KEY_PENDING
