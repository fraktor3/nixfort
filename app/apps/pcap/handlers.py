"""Job handlers: live capture on a node (then analyse) and analysis of an uploaded file."""

from __future__ import annotations

import base64
import binascii

from django.utils import timezone

from apps.execution import services as job_services
from apps.execution.agent_client import client_for  # module-level: tests monkeypatch handlers.client_for
from apps.execution.models import Job, JobState, JobType
from apps.execution.registry import register
from apps.execution.transport import TransportError

from . import analyzer, storage
from .models import PcapCapture


def _log(job):
    return lambda m, lvl="INFO": job_services.log(job, m, lvl)


def _fail(cap: PcapCapture, msg: str, log) -> tuple[str, dict]:
    cap.state, cap.error, cap.finished_at = PcapCapture.State.FAILED, msg[:300], timezone.now()
    cap.save(update_fields=["state", "error", "finished_at", "updated_at"])
    log(msg, "ERROR")
    return JobState.FAILED, {"capture": str(cap.id), "error": msg}


def _analyse(cap: PcapCapture, log) -> tuple[str, dict]:
    try:
        cap.analysis = analyzer.analyze(storage.path_of(cap.sha256))
    except (analyzer.AnalysisError, OSError) as exc:
        return _fail(cap, f"анализ не выполнен: {exc}", log)
    cap.state, cap.finished_at = PcapCapture.State.DONE, timezone.now()
    cap.save(update_fields=["analysis", "state", "finished_at", "updated_at"])
    a = cap.analysis
    log(f"пакетов {a['packets']}, новых TCP-соединений {a['tcp_new_connections']}, "
        f"находок {len(a['findings'])}", "INFO")  # fmt: skip
    return JobState.SUCCEEDED, {"capture": str(cap.id), "packets": a["packets"]}


@register(JobType.CAPTURE)
def capture(job: Job):
    cap = PcapCapture.objects.filter(id=job.params.get("capture_id"), project=job.project).first()
    if cap is None:
        return JobState.FAILED, {"error": "not_found"}
    log = _log(job)
    node = cap.node
    if node is None or node.confirmed_hostkey is None:
        return _fail(cap, "ключ узла не подтверждён", log)
    cap.started_at = timezone.now()
    cap.save(update_fields=["started_at", "updated_at"])
    log(f"захват трафика на {node.name}/{cap.interface} в течение {cap.duration_s} с…", "INFO")
    try:
        r = client_for(node).call("net.capture.v1", {
            "interface": cap.interface, "duration_s": cap.duration_s,
            "max_packets": 5000, "profile": cap.profile,
        }, deadline_s=int(cap.duration_s) + 60)  # fmt: skip
    except TransportError as exc:
        return _fail(cap, f"узел недоступен ({exc.code})", log)
    if not r.ok:
        return _fail(cap, f"захват не выполнен ({r.state} {r.error_code})", log)
    try:
        data = base64.b64decode(r.result.get("pcap_b64", ""), validate=True)
        sha, size = storage.store_bytes(data)
    except (binascii.Error, ValueError, storage.PcapRejected) as exc:
        return _fail(cap, f"данные захвата некорректны: {exc}", log)
    cap.sha256, cap.size, cap.truncated = sha, size, bool(r.result.get("truncated"))
    cap.save(update_fields=["sha256", "size", "truncated", "updated_at"])
    log(f"получено {size} байт (захвачено пакетов: {r.result.get('captured')}), анализ…", "INFO")
    return _analyse(cap, log)


@register(JobType.PCAP_ANALYZE)
def analyze_upload(job: Job):
    cap = PcapCapture.objects.filter(id=job.params.get("capture_id"), project=job.project).first()
    if cap is None:
        return JobState.FAILED, {"error": "not_found"}
    return _analyse(cap, _log(job))
