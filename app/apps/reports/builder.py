"""Builds the data of a report «before / changes / after / evidence / residual risk / limitations».

Only normalized data from the database is used: results, explanations, plan steps, probe results, IDS
event summaries. Never configuration texts, keys or raw agent output; the whole document is passed
through the secret filter once more.
"""

from __future__ import annotations

import hashlib
import json

from django.conf import settings
from django.utils import timezone

from apps.checks import domain
from apps.checks.models import AuditRun
from apps.core.redact import redact

SCHEMA = "nixfort.report/1"
BAD = ("FAIL", "UNKNOWN", "ERROR")

# The 7 mandatory elements of a report (TESTING.md, metric «полнота отчёта»).
ELEMENTS = (
    ("scope", "Объект: проект, узлы, ОС, версии, время"),
    ("before", "Исходное состояние (аудит «до»)"),
    ("changes", "Выполненные изменения: шаги, кто утвердил, итог, откаты"),
    ("after", "Итоговое состояние и сравнение «до / после»"),
    ("evidence", "Доказательства: наблюдаемые значения, пробы соединений, проверка защиты"),
    ("residual", "Остаточные риски: что не исправлено и почему"),
    ("limitations", "Ограничения выводов"),
)

LIMITATIONS = (
    "Выводы относятся только к узлам проекта и моменту сбора данных; аудит выполнен по каталогу из 21 проверки "
    f"(версия {domain.CATALOG_VERSION}), а не по всем возможным требованиям.",
    "PASS проверки IDS-03 означает, что датчик настроен на интерфейс и пишет журнал, но не гарантирует, что виден "
    "весь трафик сети.",
    "Если на датчике не установлены правила дистрибутива (suricata-update), используются только демонстрационные "
    "тестовые правила (sid 9000001–9000003): тестовый маркер, сканирование портов, подбор пароля SSH.",
    "Сканирование Nmap выполняется только по адресам сети управления (ADR-023); доступность рабочих адресов "
    "подтверждается TCP-пробами с тестового клиента.",
    "Блокировка запрещённого соединения считается доказанной, только если до изменения оно было открыто.",
    "Отчёт не содержит паролей, ключей и текстов конфигураций.",
)


def _node_info(node) -> dict:
    snap = node.snapshots.order_by("-collected_at").first()
    sysf = ((snap.facts.get("system") or {}).get("result") or {}) if snap else {}
    os_ = sysf.get("os") or {}
    return {
        "name": node.name,
        "mgmt_ip": node.mgmt_ip,
        "data_ips": node.data_ips,
        "roles": node.roles,
        "os": os_.get("pretty_name") or " ".join(x for x in (os_.get("id"), os_.get("version")) if x) or None,
        "kernel": os_.get("kernel"),
        "agent_version": snap.agent_version if snap else None,
        "inventory_at": snap.collected_at.isoformat() if snap else None,
        "hostkey": node.confirmed_hostkey.fingerprint_sha256 if node.confirmed_hostkey else None,
    }


def _run(run: AuditRun) -> dict:
    results = []
    for r in run.results.select_related("node").order_by("node__name", "check_id"):
        d = domain.BY_ID.get(r.check_id)
        results.append(
            {
                "node": r.node.name,
                "check_id": r.check_id,
                "title": d.title if d else r.check_id,
                "severity": d.severity if d else "",
                "status": r.status,
                "observed": r.observed,
                "expected": r.expected,
                "explanation": r.explanation,
            }
        )
    return {
        "run_id": str(run.id),
        "at": run.created_at.isoformat(),
        "purpose": run.purpose,
        "policy_version": run.policy_version,
        "totals": (run.summary or {}).get("total", {}),
        "results": results,
    }


def _plans(project, start, end) -> list[dict]:
    from apps.remediation.models import RemediationPlan

    out = []
    qs = (
        RemediationPlan.objects.filter(project=project, approved_at__gte=start, approved_at__lte=end)
        .select_related("approved_by")
        .order_by("approved_at")
    )
    for p in qs:
        items = []
        for i in p.items.select_related("node").order_by("order"):
            res = i.result or {}
            items.append(
                {
                    "node": i.node.name,
                    "action": i.action_id,
                    "description": i.description,
                    "checks": i.check_ids,
                    "risk": i.risk,
                    "reversible": i.reversible,
                    "state": i.state,
                    "result": res.get("reason") or res.get("verify") or "",
                    "after_rollback": res.get("after_rollback") or "",
                    "probes": [
                        {
                            "phase": t.phase,
                            "flow": t.flow_name,
                            "action": t.action,
                            "critical": t.critical,
                            "target": f"{t.src_cidr} → {t.dst_ip}:{t.port}",
                            "result": t.result,
                            "verdict": t.verdict,
                            "note": t.note,
                        }
                        for t in i.probes.order_by("created_at", "dst_ip", "port")
                    ],
                }
            )
        out.append(
            {
                "plan_id": str(p.id),
                "approved_by": p.approved_by.get_username() if p.approved_by else None,
                "approved_at": p.approved_at.isoformat() if p.approved_at else None,
                "finished_at": p.finished_at.isoformat() if p.finished_at else None,
                "state": p.state,
                "risk": p.risk,
                "options": p.options,
                "items": items,
                "not_covered": p.not_covered,
            }
        )
    return out


def _connectivity(project) -> dict | None:
    from apps.execution.models import Job, JobType
    from apps.policy.models import ConnectivityTest

    job = Job.objects.filter(project=project, type=JobType.CONNECTIVITY).order_by("-created_at").first()
    if not job:
        return None
    rows = ConnectivityTest.objects.filter(job=job).order_by("dst_ip", "port")
    return {
        "at": job.created_at.isoformat(),
        "rows": [
            {
                "flow": t.flow_name,
                "action": t.action,
                "critical": t.critical,
                "target": f"{t.src_cidr} → {t.dst_ip}:{t.port}",
                "probe": t.probe_node,
                "result": t.result,
                "verdict": t.verdict,
                "note": t.note,
            }  # fmt: skip
            for t in rows
        ],
    }


def _protection(project) -> list[dict]:
    from apps.ids.models import ProtectionTest

    latest: dict = {}
    for t in ProtectionTest.objects.filter(project=project).order_by("-created_at"):
        latest.setdefault(t.scenario, t)
    return [
        {
            "scenario": t.get_scenario_display(),
            "verdict": t.verdict,
            "verdict_label": t.get_verdict_display(),
            "at": t.created_at.isoformat(),
            "layers": t.layers,
        }  # fmt: skip
        for s, t in sorted(latest.items())
    ]


def _ids(project, since) -> dict:
    from django.db.models import Count, Max

    from apps.ids.models import IdsEvent

    qs = IdsEvent.objects.filter(project=project, ts__gte=since, event_type="alert")
    by = (
        qs.values("signature_id", "signature")
        .annotate(n=Count("id"), last=Max("ts"))
        .order_by("-n", "signature_id")[:20]
    )
    return {
        "since": since.isoformat(),
        "alerts": qs.count(),
        "by_signature": [
            {"sid": b["signature_id"], "signature": b["signature"], "count": b["n"], "last": b["last"].isoformat()}
            for b in by
        ],
    }


def _policy(project) -> dict | None:
    from apps.policy.models import FlowPolicyVersion

    pv = FlowPolicyVersion.objects.filter(project=project, status="ACTIVE").first()
    if not pv:
        return None
    return {
        "version": pv.version,
        "flows": [
            {
                "name": f.name,
                "src": f.src_cidr,
                "dst": f"{f.dst_ip}:{f.port}",
                "action": f.action,
                "critical": f.critical,
                "probe_from": f.probe_from.name if f.probe_from_id else None,
            }  # fmt: skip
            for f in pv.flows.select_related("probe_from").order_by("dst_ip", "port")
        ],
    }


def build(project, before: AuditRun, after: AuditRun, user) -> dict:
    b, a = _run(before), _run(after)
    before_map = {(r["node"], r["check_id"]): r for r in b["results"]}
    comparison = []
    for r in a["results"]:
        prev = before_map.get((r["node"], r["check_id"]))
        if r["status"] == "NOT_APPLICABLE" and (not prev or prev["status"] == "NOT_APPLICABLE"):
            continue
        comparison.append(
            {
                "node": r["node"],
                "check_id": r["check_id"],
                "title": r["title"],
                "severity": r["severity"],
                "before": prev["status"] if prev else None,
                "after": r["status"],
                "changed": (prev["status"] if prev else None) != r["status"],
                "observed": r["observed"],
                "expected": r["expected"],
                "explanation": r["explanation"],
            }
        )
    plans = _plans(project, before.created_at, after.created_at)
    reasons = {(n["node"], n["check_id"]): n["reason"] for p in plans for n in p["not_covered"]}
    residual = [
        {
            "node": r["node"],
            "check_id": r["check_id"],
            "title": r["title"],
            "severity": r["severity"],
            "status": r["status"],
            "explanation": r["explanation"],
            "why_not_fixed": reasons.get((r["node"], r["check_id"]), ""),
        }
        for r in a["results"]
        if r["status"] in BAD
    ]
    nodes = [_node_info(n) for n in project.nodes.filter(is_active=True).select_related("hostkey").order_by("name")]
    data = {
        "schema": SCHEMA,
        "generated_at": timezone.now().isoformat(),
        "generated_by": user.get_username() if user else None,
        "nixfort_version": settings.NIXFORT_VERSION,
        "catalog_version": domain.CATALOG_VERSION,
        "scope": {
            "project": {
                "name": project.name,
                "description": project.description,
                "cidrs": project.cidrs,
                "controller_ip": project.controller_ip,
                "admin_sources": project.admin_sources,
            },
            "nodes": nodes,
            "policy": _policy(project),
        },
        "before": b,
        "after": a,
        "comparison": comparison,
        "changes": plans,
        "evidence": {
            "connectivity": _connectivity(project),
            "protection": _protection(project),
            "ids": _ids(project, before.created_at),
        },
        "residual": residual,
        "limitations": list(LIMITATIONS),
    }
    data = redact(data)
    data["completeness"] = completeness(data)
    return data


def completeness(data: dict) -> list[dict]:
    """Which of the 7 mandatory elements the report actually contains (an empty list counts: «нет остаточных
    рисков» or «изменений не было» is a statement; a missing section is not)."""
    present = {
        "scope": bool(data.get("scope", {}).get("nodes")),
        "before": bool(data.get("before", {}).get("results")),
        "changes": isinstance(data.get("changes"), list),
        "after": bool(data.get("after", {}).get("results")) and isinstance(data.get("comparison"), list),
        "evidence": bool(data.get("comparison")) and "evidence" in data,
        "residual": isinstance(data.get("residual"), list),
        "limitations": bool(data.get("limitations")),
    }
    return [{"key": k, "label": label, "present": present[k]} for k, label in ELEMENTS]


def digest(data: dict) -> str:
    return hashlib.sha256(canonical(data)).hexdigest()


def canonical(data: dict) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
