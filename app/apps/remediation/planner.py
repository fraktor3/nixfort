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
SUPPORTED_NOW = {
    "pkg.install_security_tool.v1",
    "fail2ban.apply_sshd_profile.v1",
    "ssh.apply_hardening_profile.v1",
    "nft.apply_policy.v1",
    "nft.apply_host_firewall.v1",
    "suricata.apply_sensor_profile.v1",
}
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


def nft_params(project, policy, gateway) -> dict:
    """Agent parameters of nft.apply_policy.v1 from the active flow policy. Only ALLOW flows become rules:
    DENY is enforced by `policy drop` and is proven by probes. Order is canonical (same policy -> same hash)."""
    forward, inbound = [], []
    for f in policy.flows.filter(action="ALLOW").order_by("dst_ip", "port", "src_cidr"):
        if f.dst_node_id == gateway.id:
            rule = {"src": f.src_cidr, "port": f.port}
            if rule not in inbound:
                inbound.append(rule)
        else:
            rule = {"src": f.src_cidr, "dst": f.dst_ip, "port": f.port}
            if rule not in forward:
                forward.append(rule)
    return {
        "policy_version": policy.version,
        "management_sources": project.management_sources,
        "forward_allow": forward,
        "input_allow": inbound,
        "rollback_timeout_s": settings.NIXFORT_ROLLBACK_TIMEOUT_S,
    }


def host_rules_sha256(params: dict) -> str:
    """Same hash the agent writes into the server host-firewall table comment (actions/nft.py)."""
    canon = {k: params[k] for k in ("version", "management_sources", "allow_ports")}
    return hashlib.sha256(json.dumps(canon, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def rules_sha256(params: dict) -> str:
    """Same canonical hash as the agent writes into the table comment (agent: actions/nft.py)."""
    canon = {k: params[k] for k in ("policy_version", "management_sources", "forward_allow", "input_allow")}
    return hashlib.sha256(json.dumps(canon, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _nft_drafts(run: AuditRun, node, ids: set[str], packages: dict, facts: dict) -> tuple[list[Draft], list[dict]]:
    from apps.policy.models import FlowPolicyVersion

    fw = sorted(ids & {"FW-02", "FW-03", "FW-04"})
    if not fw and "FW-01" not in ids:
        return [], []
    drafts: list[Draft] = []
    miss = lambda cid, why: {"node": node.name, "check_id": cid, "reason": why}  # noqa: E731
    nft = (facts.get("nft") or {}).get("result") or {}
    conflict = nft.get("conflict") or {}
    services = ((facts.get("system") or {}).get("result") or {}).get("services") or {}
    conflicting = (
        services.get("ufw") == "active"
        or services.get("firewalld") == "active"
        or conflict.get("ufw")
        or conflict.get("firewalld")
        or conflict.get("docker")
        or conflict.get("foreign_base_chains")
    )
    if conflicting:
        why = "Другой менеджер правил (UFW, firewalld, Docker или чужие цепочки) устраняется вручную"
        return [], [miss(c, why) for c in sorted(ids & {"FW-01", "FW-02", "FW-03", "FW-04"})]
    policy = FlowPolicyVersion.objects.filter(project=node.project, status="ACTIVE").first()
    if policy is None:
        return [], [miss(c, "Нет активной политики соединений") for c in fw]
    if not node.has_role("gateway"):
        return [], [miss(c, "Политика применяется только на узле с ролью «шлюз»") for c in fw]
    if not packages.get("nftables"):
        drafts.append(
            Draft(
                node,
                0,
                ["FW-01"],
                "pkg.install_security_tool.v1",
                {"package": "nftables"},
                "LOW",
                False,
                "Установить nftables из репозитория дистрибутива",
            )
        )
    params = nft_params(node.project, policy, node)
    if len(params["forward_allow"]) > 200 or len(params["input_allow"]) > 20:
        return [], [miss(c, "Слишком много разрешающих потоков для одного шлюза") for c in fw]
    flows = list(policy.flows.all())
    if any(f.action == "ALLOW" and f.critical and f.probe_from_id is None for f in flows):
        why = "У критичного разрешающего потока не задан тестовый узел: сохранность доступа нельзя проверить"
        return [], [miss(c, why) for c in fw]
    unprobed = sum(1 for f in flows if f.probe_from_id is None)
    allowed = len(params["forward_allow"]) + len(params["input_allow"])
    desc = (
        f"Межсетевой экран по политике v{policy.version}: разрешить {allowed} поток(ов), остальной транзит "
        f"запрещён; SSH к шлюзу только с {', '.join(params['management_sources'])}. "
        f"Проверка пробами до/после ({len(flows) - unprobed} из {len(flows)} потоков)"
    )
    drafts.append(Draft(node, 4, fw or ["FW-02"], "nft.apply_policy.v1", params, "HIGH", True, desc[:300]))
    return drafts, []


def _ids_drafts(node, ids: set[str], packages: dict) -> tuple[list[Draft], list[dict]]:
    """Suricata sensor: install if missing, then the sensor profile (interface + NIXFORT detection rules)."""
    fail = sorted(ids & {"IDS-01", "IDS-02", "IDS-03"})
    if not fail:
        return [], []
    if not node.has_role("ids_sensor") or not node.ids_interface:
        return [], [{"node": node.name, "check_id": c, "reason": "У узла не задан интерфейс датчика IDS"} for c in fail]
    drafts = []
    if not packages.get("suricata"):
        drafts.append(
            Draft(
                node,
                0,
                ["IDS-01"],
                "pkg.install_security_tool.v1",
                {"package": "suricata"},
                "LOW",
                False,
                "Установить Suricata из репозитория дистрибутива",
            )
        )
    drafts.append(
        Draft(
            node,
            3,
            fail,
            "suricata.apply_sensor_profile.v1",
            {
                "interface": node.ids_interface,
                "test_rules": True,
                "rollback_timeout_s": max(settings.NIXFORT_ROLLBACK_TIMEOUT_S, 180),
            },
            "MEDIUM",
            True,
            f"Датчик Suricata на интерфейсе {node.ids_interface}: журнал EVE, тестовые правила "
            "(тестовый маркер, сканирование портов, подбор пароля SSH)",
        )
    )
    return drafts, []


def _hostfw_drafts(node, ids: set[str], packages: dict) -> tuple[list[Draft], list[dict]]:
    """Server host firewall (HFW-01): install nftables if missing, then an input-only profile that opens the
    node's declared ports and SSH from management, dropping the rest."""
    if "HFW-01" not in ids:
        return [], []
    if not node.has_role("server"):
        return [], [{"node": node.name, "check_id": "HFW-01", "reason": "Хостовый экран применяется на сервере"}]
    drafts = []
    if not packages.get("nftables"):
        drafts.append(Draft(node, 0, ["HFW-01"], "pkg.install_security_tool.v1", {"package": "nftables"}, "LOW",
                            False, "Установить nftables из репозитория дистрибутива"))  # fmt: skip
    allow_ports = sorted({int(p) for p in (node.expected_tcp_ports or []) if int(p) != 22})
    params = {
        "version": 1,
        "management_sources": node.project.management_sources,
        "allow_ports": allow_ports,
        "rollback_timeout_s": settings.NIXFORT_ROLLBACK_TIMEOUT_S,
    }
    desc = (
        f"Хостовый межсетевой экран сервера: открыты порты {allow_ports or 'нет'} и SSH с "
        f"{', '.join(params['management_sources'])}, остальной входящий трафик запрещён"
    )
    drafts.append(Draft(node, 5, ["HFW-01"], "nft.apply_host_firewall.v1", params, "HIGH", True, desc[:300]))
    return drafts, []


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
                    "reason": "Конфигурация sshd некорректна, изменения SSH заблокированы до ручного исправления",
                }
            )

        fw_drafts, fw_missing = _nft_drafts(run, node, ids, packages, facts)
        drafts += fw_drafts
        not_covered += fw_missing
        ids_drafts, ids_missing = _ids_drafts(node, ids, packages)
        drafts += ids_drafts
        not_covered += ids_missing
        hfw_drafts, hfw_missing = _hostfw_drafts(node, ids, packages)
        drafts += hfw_drafts
        not_covered += hfw_missing

        covered = {c for d in drafts if d.node == node for c in d.check_ids}
        for cid in sorted(ids - covered):
            reason = {
                "SYS-01": "ОС не поддерживается: только рекомендация",
                "SYS-02": "Синхронизация времени: только рекомендация",
                "SYS-03": "Системный журнал: только рекомендация",
                "SYS-04": "Лишние службы отключаются вручную (или запрещаются политикой на шлюзе)",
            }.get(cid, "Автоматического исправления нет")
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
