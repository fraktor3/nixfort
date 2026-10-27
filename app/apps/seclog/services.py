"""Collect the security-log summary: SSH auth failures + Fail2ban bans from each server (via the agent),
and IDS alert counts from the database."""

from __future__ import annotations

from datetime import timedelta

from django.db.models import Count, Max
from django.utils import timezone

from apps.execution.agent_client import client_for
from apps.execution.models import JobState
from apps.execution.transport import TransportError

from .models import SecuritySummary


def _call(client_factory, node, action, params=None):
    from apps.execution.agent_client import AgentResponse

    try:
        return client_factory(node).call(action, params or {}, deadline_s=60)
    except TransportError as exc:
        return AgentResponse(action=action, state="TRANSPORT_ERROR", error_code=exc.code)


def collect(job, log, client_factory=None) -> tuple[str, dict]:
    client_factory = client_factory or client_for
    project = job.project
    window = int(job.params.get("hours", 24))
    rec = SecuritySummary.objects.create(project=project, job=job, created_by=job.requested_by, window_hours=window)
    servers = [n for n in project.nodes.filter(is_active=True) if n.has_role("server")]
    rows = []
    for node in servers:
        row = {"node": node.name, "reachable": True}
        if node.confirmed_hostkey is None:
            rows.append({**row, "reachable": False, "note": "ключ узла не подтверждён"})
            continue
        auth = _call(client_factory, node, "system.read_auth_failures.v1", {"hours": window})
        f2b = _call(client_factory, node, "fail2ban.read_status.v1")
        if not auth.ok and not f2b.ok:
            rows.append({**row, "reachable": False, "note": f"узел недоступен ({auth.error_code or f2b.error_code})"})
            continue
        sshd = (f2b.result or {}).get("sshd") or {} if f2b.ok else {}
        row["auth"] = ({"total": auth.result.get("total"), "by_source": auth.result.get("by_source", []),
                        "by_user": auth.result.get("by_user", [])} if auth.ok else None)  # fmt: skip
        row["fail2ban"] = ({"service": (f2b.result or {}).get("service"), "enabled": sshd.get("enabled"),
                            "banned_ips": sshd.get("banned_ips", []), "currently_banned": sshd.get("currently_banned"),
                            "total_banned": sshd.get("total_banned")} if f2b.ok else None)  # fmt: skip
        rows.append(row)
        log(f"{node.name}: неудачных входов {row['auth']['total'] if row.get('auth') else '—'}, "
            f"в бане {len((row.get('fail2ban') or {}).get('banned_ips') or [])}", "INFO")  # fmt: skip

    since = timezone.now() - timedelta(hours=window)
    from apps.ids.models import IdsEvent

    qs = IdsEvent.objects.filter(project=project, ts__gte=since, event_type="alert")
    by_sig = (qs.values("signature_id", "signature").annotate(n=Count("id"), last=Max("ts"))
              .order_by("-n")[:20])  # fmt: skip
    ids = {"alerts": qs.count(),
           "by_signature": [{"sid": b["signature_id"], "signature": b["signature"], "count": b["n"],
                             "last": b["last"].isoformat()} for b in by_sig]}  # fmt: skip

    rec.data = {"servers": rows, "ids": ids, "window_hours": window}
    rec.state = SecuritySummary.State.DONE
    rec.save(update_fields=["data", "state", "updated_at"])
    state = JobState.SUCCEEDED if any(r["reachable"] for r in rows) or not servers else JobState.PARTIAL
    return state, {"summary": str(rec.id), "servers": len(rows)}
