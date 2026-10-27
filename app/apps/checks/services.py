"""Audit engine: collect facts, apply the catalog, persist immutable results."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime

from django.db import transaction
from django.utils import timezone

from apps.inventory import collector
from apps.inventory.models import Node
from apps.policy.services import active_policy

from . import domain
from .models import AuditRun, CheckResult, Evidence


def ctx_for(node: Node, policy_version: int | None) -> domain.Ctx:
    return domain.Ctx(
        roles=frozenset(node.roles or []),
        expected_tcp_ports=frozenset(node.expected_tcp_ports or []),
        ids_interface=node.ids_interface or "",
        controller_ip=node.project.controller_ip,
        active_policy_version=policy_version,
    )


def _evidence(node, snap, key, fact) -> Evidence:
    collected = fact.get("collected_at")
    return Evidence.objects.create(
        node=node,
        snapshot=snap,
        source=collector.ACTION_OF.get(key, key),
        collected_at=datetime.fromisoformat(collected) if collected else snap.collected_at,
        sha256=hashlib.sha256(json.dumps(fact, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
    )


@transaction.atomic
def evaluate_node(run: AuditRun, node: Node, snap, policy_version: int | None) -> Counter:
    facts = snap.facts if snap else {}
    ctx = ctx_for(node, policy_version)
    ev_cache: dict[str, Evidence] = {}
    counts: Counter = Counter()
    for check in domain.CATALOG:
        out = domain.evaluate(check, facts, ctx)
        res = CheckResult.objects.create(
            audit_run=run,
            node=node,
            check_id=check.id,
            status=out.status,
            observed=out.observed,
            expected=out.expected,
            explanation=out.explanation,
        )
        if out.status != domain.NA and snap:
            for key in check.facts:
                if key in facts:
                    if key not in ev_cache:
                        ev_cache[key] = _evidence(node, snap, key, facts[key])
                    res.evidence.add(ev_cache[key])
        counts[out.status] += 1
    return counts


def run_audit(job, purpose: str = "baseline", node_ids: list[str] | None = None, log=None, progress=None) -> AuditRun:
    project = job.project
    policy = active_policy(project)
    run = AuditRun.objects.create(
        project=project,
        job=job,
        initiated_by=job.requested_by,
        catalog_version=domain.CATALOG_VERSION,
        policy_version=policy.version if policy else None,
        purpose=purpose,
    )
    nodes = project.nodes.filter(is_active=True).select_related("hostkey", "project")
    if node_ids:
        nodes = nodes.filter(id__in=node_ids)
    nodes = list(nodes)
    total: Counter = Counter()
    per_node = {}
    for i, node in enumerate(nodes):
        if progress:
            progress(int(i * 100 / max(1, len(nodes))), f"узел {node.name}")
        managed = bool(set(node.roles) & collector.MANAGED_ROLES)
        if not managed:
            continue  # test clients are not audited
        if node.confirmed_hostkey is None:
            snap = None
            if log:
                log(f"{node.name}: ключ не подтверждён, проверки получат статус «нет данных»", "WARN")
        else:
            snap = collector.collect_node(node, job, log=log)
        c = evaluate_node(run, node, snap, policy.version if policy else None)
        per_node[node.name] = dict(c)
        total += c
    run.summary = {"total": dict(total), "nodes": per_node}
    run.state = AuditRun.State.DONE
    run.finished_at = timezone.now()
    run.save(update_fields=["summary", "state", "finished_at", "updated_at"])
    return run
