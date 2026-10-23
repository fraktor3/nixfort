"""Builds a remediation plan from FAIL results of an audit run (docs/CHECKS_CATALOG.md «Группировка»)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.db import transaction

from apps.checks.models import AuditRun
from apps.core import audit
from apps.core.models import Action

from .models import RemediationItem, RemediationPlan

RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
SUPPORTED_NOW = {"pkg.install_security_tool.v1", "fail2ban.apply_sshd_profile.v1", "ssh.apply_hardening_profile.v1"}
# Default hardening values (CHECKS_CATALOG expectations).
SSH_PROFILE = {"permit_root_login": "no", "max_auth_tries": 4, "login_grace_time_s": 60, "x11_forwarding": False}
F2B_PROFILE = {"maxretry": 5, "bantime_s": 600, "findtime_s": 600}


@dataclass
class Draft:
    node: Any
    order_key: int
    check_ids: list[str]
    action_id: str
    params: dict
    risk: str
    reversible: bool
    description: str


def _facts(run: AuditRun, node) -> dict:
    snap = node.snapshots.filter(job=run.job).first() or node.snapshots.first()
    return snap.facts if snap else {}


def build(run: AuditRun, key_only_confirmed: bool) -> tuple[list[Draft], list[dict]]:
    fails = run.results.filter(status="FAIL").select_related("node", "node__project")
    by_node: dict = {}
    for r in fails:
        by_node.setdefault(r.node, set()).add(r.check_id)
    drafts: list[Draft] = []
    not_covered: list[dict] = []
    for node, ids in sorted(by_node.items(), key=lambda kv: kv[0].name):
        facts = _facts(run, node)
        packages = ((facts.get("system") or {}).get("result") or {}).get("packages") or {}

        # Fail2ban: install if missing, then the sshd jail profile
        f2b = sorted(ids & {"F2B-01", "F2B-02", "F2B-03"})
        if f2b:
            if not packages.get("fail2ban"):
                drafts.append(
                    Draft(
                        node,
                        0,
                        ["F2B-01"],
                        "pkg.install_security_tool.v1",
                        {"package": "fail2ban"},
                        "LOW",
                        False,
                        "Установить Fail2ban из репозитория дистрибутива",
                    )
                )
            drafts.append(
                Draft(
                    node,
                    1,
                    f2b,
                    "fail2ban.apply_sshd_profile.v1",
                    {
                        **F2B_PROFILE,
                        "ignore_ips": [node.project.controller_ip],
                        "rollback_timeout_s": settings.NIXFORT_ROLLBACK_TIMEOUT_S,
                    },
                    "LOW",
                    True,
                    "Включить защиту SSH от перебора: maxretry 5, блокировка 600 с",
                )
            )

        # SSH hardening (never weakens a setting that is already compliant)
        ssh_ids = sorted(ids & {"SSH-01", "SSH-02", "SSH-03", "SSH-04", "SSH-05", "SSH-06"})
        if ssh_ids and "SSH-07" not in ids:
            effective = ((facts.get("ssh") or {}).get("result") or {}).get("effective") or {}
            already_key_only = effective.get("passwordauthentication") == "no"
            disable_password = already_key_only or ("SSH-02" in ids and key_only_confirmed)
            if "SSH-02" in ids and not disable_password:
                ssh_ids.remove("SSH-02")
                not_covered.append(
                    {
                        "node": node.name,
                        "check_id": "SSH-02",
                        "reason": "Не подтверждено, что вход по ключу у администраторов работает",
                    }
                )
            if ssh_ids:
                drafts.append(
                    Draft(
                        node,
                        2,
                        ssh_ids,
                        "ssh.apply_hardening_profile.v1",
                        {
                            **SSH_PROFILE,
                            "password_authentication": not disable_password,
                            "rollback_timeout_s": settings.NIXFORT_ROLLBACK_TIMEOUT_S,
                        },
                        "HIGH" if disable_password and not already_key_only else "MEDIUM",
                        True,
                        "Усиленный профиль SSH" + (" (вход только по ключу)" if disable_password else ""),
                    )
                )
        elif "SSH-07" in ids:
            not_covered.append(
                {
                    "node": node.name,
                    "check_id": "SSH-07",
                    "reason": "Конфигурация sshd некорректна — изменения SSH заблокированы до ручного исправления",
                }
            )

        covered = {c for d in drafts if d.node == node for c in d.check_ids}
        for cid in sorted(ids - covered):
            reason = {
                "SYS-01": "ОС не поддерживается — только рекомендация",
                "SYS-02": "Синхронизация времени — только рекомендация",
                "SYS-03": "Системный журнал — только рекомендация",
                "SYS-04": "Лишние службы отключаются вручную (или запрещаются политикой на шлюзе)",
            }.get(cid, "Исправление появится на следующем этапе (nftables, Suricata)")
            if not any(n["node"] == node.name and n["check_id"] == cid for n in not_covered):
                not_covered.append({"node": node.name, "check_id": cid, "reason": reason})
    drafts.sort(key=lambda d: (d.order_key, d.node.name))
    return drafts, not_covered


def plan_hash(items) -> str:
    canon = [
        {"node": str(i.node_id), "order": i.order, "action": i.action_id, "params": i.params, "checks": i.check_ids}
        for i in items
    ]
    return hashlib.sha256(json.dumps(canon, sort_keys=True).encode()).hexdigest()


@transaction.atomic
def create_plan(run: AuditRun, user, key_only_confirmed: bool, request=None) -> RemediationPlan:
    drafts, not_covered = build(run, key_only_confirmed)
    risk = max((d.risk for d in drafts), key=lambda r: RISK_ORDER[r], default="LOW")
    plan = RemediationPlan.objects.create(
        project=run.project,
        audit_run=run,
        created_by=user,
        risk=risk,
        options={"key_only_confirmed": key_only_confirmed},
        not_covered=not_covered,
    )
    for i, d in enumerate(drafts):
        RemediationItem.objects.create(
            plan=plan,
            node=d.node,
            order=i,
            check_ids=d.check_ids,
            action_id=d.action_id,
            params=d.params,
            risk=d.risk,
            reversible=d.reversible,
            description=d.description,
        )
    audit.log(
        user,
        Action.PLAN_CREATED,
        obj=plan,
        project=run.project,
        request=request,
        items=len(drafts),
        risk=risk,
        key_only_confirmed=key_only_confirmed,
    )
    return plan
