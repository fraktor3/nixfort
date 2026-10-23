"""Job handlers of the inventory module."""

from __future__ import annotations

from django.utils import timezone

from apps.execution import services
from apps.execution.models import Job, JobState, JobType
from apps.execution.registry import register
from apps.execution.transport import TransportError, fetch_host_key

from . import collector
from . import validators as v
from .adapters import nmap
from .models import Node, PortScan


def _target_nodes(job: Job) -> list[Node]:
    if job.node_id:
        return [job.node]
    return list(job.project.nodes.filter(is_active=True).select_related("hostkey"))


@register(JobType.INVENTORY)
def inventory(job: Job):
    nodes = _target_nodes(job)
    ok, failed, skipped = [], [], []
    for i, node in enumerate(nodes):
        services.set_progress(job, int(i * 100 / max(1, len(nodes))), phase=f"узел {node.name}")
        if node.confirmed_hostkey is None:
            skipped.append(node.name)
            services.log(job, f"{node.name}: ключ узла не подтверждён — пропущен", "WARN")
            continue
        snap = collector.collect_node(node, job, log=lambda m: services.log(job, m))
        states = {k: f["state"] for k, f in snap.facts.items()}
        (ok if all(s == "OK" for s in states.values()) else failed).append(node.name)
    result = {"ok": ok, "failed": failed, "skipped": skipped}
    if not ok:
        return JobState.FAILED, result
    return (JobState.SUCCEEDED if not failed and not skipped else JobState.PARTIAL), result


@register(JobType.FETCH_HOSTKEY)
def fetch_hostkey(job: Job):
    from . import services as inv_services

    node = job.node
    try:
        key_type, blob = fetch_host_key(node.mgmt_ip, node.ssh_port)
    except TransportError as exc:
        services.log(job, f"Не удалось получить ключ: {exc.code}", "ERROR")
        return JobState.FAILED, {"error": exc.code}
    _, _, fp = v.parse_hostkey_line(f"{key_type} {blob}")
    inv_services.set_hostkey(
        node, {"key_type": key_type, "public_key": blob, "fingerprint_sha256": fp}, job.requested_by, source="fetched"
    )
    services.log(job, f"Получен ключ {key_type} {fp}. Сверьте отпечаток с узлом и подтвердите.")
    return JobState.SUCCEEDED, {"fingerprint": fp}


@register(JobType.PORT_SCAN)
def port_scan(job: Job):
    project = job.project
    profile = job.params.get("profile", "common")
    nodes = _target_nodes(job)
    # The controller sits only in the management network: scan management addresses (ADR-023).
    targets = sorted({n.mgmt_ip for n in nodes})
    scan = PortScan.objects.create(project=project, job=job, targets=targets, ports=profile, started_at=timezone.now())
    services.log(job, f"Nmap -sT, профиль «{profile}», цели: {', '.join(targets)}")
    try:
        result = nmap.run(targets, profile, project.cidrs)
    except nmap.NmapError as exc:
        services.log(job, f"Сканирование не выполнено: {exc.code}", "ERROR")
        scan.result = {"error": exc.code}
        scan.finished_at = timezone.now()
        scan.save(update_fields=["result", "finished_at"])
        return JobState.FAILED, {"error": exc.code}
    scan.result = result
    scan.finished_at = timezone.now()
    scan.save(update_fields=["result", "finished_at"])
    for h in result["hosts"]:
        services.log(job, f"{h['ip']}: открыты {', '.join(map(str, h['open_ports'])) or 'нет'} (из сети управления)")
    return JobState.SUCCEEDED, {"scan_id": str(scan.id), "hosts": len(result["hosts"])}


def nmap_scope_error(project, nodes) -> str | None:
    """Pre-check before creating a scan job: everything must be inside the project (AT-05)."""
    targets = sorted({n.mgmt_ip for n in nodes})
    try:
        nmap.build_argv(targets, "common", project.cidrs) if targets else None
    except nmap.NmapError as exc:
        return exc.code if exc.code != "tool_missing" else None
    return None if targets else "no_targets"
