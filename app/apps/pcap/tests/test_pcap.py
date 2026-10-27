"""Traffic analyzer: storage checks, TShark analysis of generated traffic, capture through the agent, rights."""

import base64
import shutil
import struct

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from django.utils import timezone

from apps.execution.agent_client import AgentResponse
from apps.execution.models import Job, JobState
from apps.inventory.models import HostKey, InventorySnapshot
from apps.pcap import analyzer, handlers, storage
from apps.pcap.models import PcapCapture

pytestmark = pytest.mark.django_db(transaction=True)
needs_tshark = pytest.mark.skipif(not shutil.which("tshark"), reason="needs tshark")


def _ip(a: str) -> bytes:
    return bytes(int(x) for x in a.split("."))


def make_pcap(packets: list[tuple[float, str, str, int, bool]]) -> bytes:
    """Minimal valid pcap: Ethernet / IPv4 / TCP headers. (time, src, dst, dport, syn)."""
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for t, src, dst, dport, syn in packets:
        tcp = struct.pack("!HHIIBBHHH", 40000, dport, 1, 0, 5 << 4, 0x02 if syn else 0x10, 64240, 0, 0)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, _ip(src), _ip(dst))
        frame = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00" + ip + tcp
        sec, usec = int(t), int((t - int(t)) * 1e6)
        out.append(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)
    return b"".join(out)


SCAN = make_pcap([(1_800_000_000 + i * 0.01, "10.88.0.10", "10.99.0.10", 1000 + i, True) for i in range(40)]
                 + [(1_800_000_001 + i * 0.1, "10.88.0.10", "10.99.0.10", 22, True) for i in range(6)])  # fmt: skip


@pytest.fixture
def data_dir(settings, tmp_path):
    settings.NIXFORT_DATA_DIR = tmp_path
    return tmp_path


def test_storage_rejects_non_pcap_and_names_by_hash(data_dir):
    with pytest.raises(storage.PcapRejected):
        storage.store_bytes(b"MZ\x90\x00 not a capture")
    digest, size = storage.store_bytes(SCAN)
    assert storage.path_of(digest).read_bytes() == SCAN and size == len(SCAN)
    with pytest.raises(ValueError):
        storage.path_of("../../etc/passwd")


@needs_tshark
def test_analysis_finds_scan_and_ssh_attempts(data_dir):
    digest, _ = storage.store_bytes(SCAN)
    a = analyzer.analyze(storage.path_of(digest))
    assert a["packets"] == 46 and a["tcp_new_connections"] == 46
    kinds = {f["kind"] for f in a["findings"]}
    assert {"scan", "ssh_bruteforce"} <= kinds
    assert a["top_sources"][0]["ip"] == "10.88.0.10"
    assert sum(a["timeline"]["syn"]) == 46


def test_summary_of_garbage_is_empty():
    assert analyzer.summarize("not\ttshark\toutput\n")["packets"] == 0


@needs_tshark
def test_upload_page_flow(client_as, operator, viewer, project, data_dir):
    url = reverse("pcap:upload", args=[project.id])
    r = client_as(operator).post(url, {"file": SimpleUploadedFile("lab scan.pcap", SCAN)})
    assert r.status_code == 302
    cap = PcapCapture.objects.get()
    assert cap.state == "DONE" and cap.original_name == "lab scan.pcap", cap.error
    page = client_as(viewer).get(reverse("pcap:detail", args=[project.id, cap.id])).content.decode()
    assert "Признаки сканирования портов" in page and "<svg" in page
    # viewer may look, but not download raw traffic or upload
    assert client_as(viewer).get(reverse("pcap:download", args=[project.id, cap.id])).status_code == 403
    assert client_as(viewer).post(url, {"file": SimpleUploadedFile("x.pcap", SCAN)}).status_code == 403
    r = client_as(operator).get(reverse("pcap:download", args=[project.id, cap.id]))
    assert r.status_code == 200 and b"".join(r.streaming_content) == SCAN


def test_upload_rejects_wrong_format(client_as, operator, project, data_dir):
    r = client_as(operator).post(reverse("pcap:upload", args=[project.id]),
                                 {"file": SimpleUploadedFile("evil.pcap", b"#!/bin/sh\nrm -rf /\n")})  # fmt: skip
    assert r.status_code == 302 and not PcapCapture.objects.exists()
    assert not list((data_dir / "pcap").glob("*"))  # nothing kept


@needs_tshark
def test_capture_through_agent(client_as, operator, project, lab_nodes, admin, data_dir, monkeypatch):
    gw = lab_nodes["gateway"]
    HostKey.objects.create(node=gw, key_type="ssh-ed25519", public_key="AAAA", fingerprint_sha256="x",
                           confirmed_by=admin, confirmed_at=timezone.now())  # fmt: skip
    InventorySnapshot.objects.create(
        node=gw, collected_at=timezone.now(), sha256="0" * 64,
        facts={"system": {"state": "OK", "result": {"interfaces": [{"name": "lo"}, {"name": "enp0s9", "ipv4": ["10.88.0.1/24"]}]}}},
    )  # fmt: skip
    calls = []

    class C:
        def call(self, action, params=None, deadline_s=60):
            calls.append((action, params))
            return AgentResponse(action=action, state="OK", os_profile="ubuntu-24.04",
                                 result={"pcap_b64": base64.b64encode(SCAN).decode(), "captured": 46,
                                         "dropped_by_kernel": 0, "truncated": False})  # fmt: skip

    monkeypatch.setattr(handlers, "client_for", lambda node: C())
    page = client_as(operator).get(reverse("pcap:list", args=[project.id])).content.decode()
    assert "enp0s9" in page and "датчик IDS" in page and ", lo (" not in page
    r = client_as(operator).post(reverse("pcap:capture", args=[project.id]),
                                 {"target": f"{gw.id}:enp0s9", "duration_s": 10, "profile": "no_ssh"})  # fmt: skip
    assert r.status_code == 302
    cap = PcapCapture.objects.get()
    assert cap.state == "DONE" and cap.analysis["packets"] == 46
    assert calls == [("net.capture.v1", {"interface": "enp0s9", "duration_s": 10, "max_packets": 5000,
                                         "profile": "no_ssh"})]  # fmt: skip
    assert Job.objects.get().state == JobState.SUCCEEDED
    # an interface the inventory does not know is refused by the form
    client_as(operator).post(reverse("pcap:capture", args=[project.id]),
                             {"target": f"{gw.id}:eth9", "duration_s": 10, "profile": "all"})  # fmt: skip
    assert PcapCapture.objects.count() == 1


@needs_tshark
def test_connection_burst_is_a_finding_but_not_a_scan(data_dir):
    burst = make_pcap(
        [
            (1_800_000_000 + i * 0.002, "10.88.0.10", "10.99.0.10", 80 if i % 2 else 8080, True) for i in range(150)
        ]  # fmt: skip
        + [(1_800_000_001 + i * 0.1, "10.88.0.20", "10.99.0.10", 80, True) for i in range(10)]
    )
    digest, _ = storage.store_bytes(burst)
    f = analyzer.analyze(storage.path_of(digest))["findings"]
    assert [x["kind"] for x in f] == ["conn_burst"]
    assert f[0]["src"] == "10.88.0.10" and f[0]["value"] == 150 and "80, 8080" in f[0]["detail"]
    # a real scan is reported as a scan, not additionally as a burst
    many = make_pcap([(1_800_000_000 + i * 0.001, "10.88.0.10", "10.99.0.10", 1000 + i, True) for i in range(150)])
    digest, _ = storage.store_bytes(many)
    assert [x["kind"] for x in analyzer.analyze(storage.path_of(digest))["findings"]] == ["scan"]
