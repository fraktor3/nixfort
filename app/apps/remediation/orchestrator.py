"""Safe execution of an approved plan (ARCHITECTURE §6).

Per item, strictly sequential, under the node mutation lock:
  PRECHECK -> APPLY (agent: snapshot, validate, arm node-side rollback timer, activate)
  -> VERIFY through a NEW SSH connection (each agent call is a new connection)
  -> COMMIT (cancel timer)  or  ROLLBACK (rollback_now; if the node is unreachable, wait for the timer)
Success is claimed only on verified facts. Anything unproven is UNKNOWN.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from django.conf import settings
from django.utils import timezone

from apps.core import audit
from apps.core.models import Action, Outcome
from apps.execution import services as jobs
from apps.execution.agent_client import AgentClient, AgentResponse, client_for
from apps.execution.models import Job, JobState
from apps.execution.transport import TransportError

from .models import ItemState, PlanState, RemediationItem, RemediationPlan
from .planner import plan_hash

# Agent request deadlines per domain (seconds): apt and the Suricata engine start are slow on lab VMs.
DEADLINES = {"pkg": 540, "suricata": 300}


class ItemOutcome(Exception):
    def __init__(self, state: str, reason: str):
        self.state = state
        self.reason = reason


# ---------------------------------------------------------------- verification per action
def _verify_pkg(client: AgentClient, item: RemediationItem, env: dict | None = None) -> tuple[bool, str, dict]:
    r = client.call("system.collect_facts.v1")
    if not r.ok:
        return False, f"нет данных после установки ({r.state} {r.error_code})", r.as_fact()
    version = (r.result.get("packages") or {}).get(item.params["package"])
    return bool(version), (f"установлен {version}" if version else "пакет не обнаружен"), {"version": version}


def _verify_f2b(client: AgentClient, item: RemediationItem, env: dict | None = None) -> tuple[bool, str, dict]:
    r = client.call("fail2ban.read_status.v1")
    if not r.ok:
        return False, f"состояние не получено ({r.state} {r.error_code})", r.as_fact()
    s = r.result.get("sshd") or {}
    p = item.params
    ok = (
        r.result.get("service") == "active"
        and s.get("enabled")
        and s.get("maxretry") == p["maxretry"]
        and s.get("bantime") == p["bantime_s"]
        and s.get("findtime") == p["findtime_s"]
    )
    return bool(ok), ("jail sshd активен с параметрами профиля" if ok else f"фактически: {s}"), {"sshd": s}


def _verify_ssh(client: AgentClient, item: RemediationItem, env: dict | None = None) -> tuple[bool, str, dict]:
    r = client.call("ssh.read_effective_config.v1")  # new SSH session = management access survived
    if not r.ok:
        return False, f"нет нового SSH-соединения или данных ({r.state} {r.error_code})", r.as_fact()
    eff = r.result.get("effective") or {}
    p = item.params
    want = {
        "permitrootlogin": "no",
        "passwordauthentication": "no" if not p["password_authentication"] else "yes",
        "permitemptypasswords": "no",
        "maxauthtries": str(p["max_auth_tries"]),
        "logingracetime": str(p["login_grace_time_s"]),
        "x11forwarding": "yes" if p["x11_forwarding"] else "no",
    }
    diff = {k: (eff.get(k), v) for k, v in want.items() if eff.get(k) != v}
    if not r.result.get("config_valid"):
        return False, "sshd -t после изменения не проходит", {"effective": eff}
    return (
        (not diff),
        ("эффективные параметры совпадают (sshd -T)" if not diff else f"расхождения: {diff}"),
        {"effective": eff},
    )


# ---------------------------------------------------------------- firewall: table facts + TCP probes
def _nft_probe(item: RemediationItem, env: dict, phase: str) -> list:
    from apps.policy import connectivity
    from apps.policy.models import FlowPolicyVersion

    policy = FlowPolicyVersion.objects.get(project=item.plan.project_id, version=item.params["policy_version"])
    probes = connectivity.run_probes(connectivity.policy_flows(policy), env["client_factory"])
    baseline = None
    if phase != "BASELINE":
        stored = item.result.get("baseline") or {}
        baseline = {p.flow.id: stored.get(str(p.flow.id), "NOT_RUN") for p in probes}
    rows = connectivity.record(
        probes,
        project=item.plan.project,
        policy=policy,
        phase=phase,
        job=env.get("job"),
        plan_item=item,
        baseline=baseline,
    )
    for r in rows:
        env["log"](
            f"проба {phase}: {r.action} {r.src_cidr} → {r.dst_ip}:{r.port} = {r.result} ({r.get_verdict_display()})",
            "INFO",
        )
    return rows


def _verify_nft(client: AgentClient, item: RemediationItem, env: dict | None = None) -> tuple[bool, str, dict]:
    from apps.policy import connectivity

    from .planner import rules_sha256

    r = client.call("nft.inspect.v1")  # new SSH session = management access to the gateway survived
    if not r.ok:
        return False, f"нет нового SSH-соединения со шлюзом или данных ({r.state} {r.error_code})", r.as_fact()
    p = item.params
    meta = r.result.get("policy_meta") or {}
    chains = r.result.get("nixfort_chains") or {}
    sources = r.result.get("nixfort_input_ssh_sources") or []
    problems = []
    if meta.get("policy_version") != p["policy_version"] or meta.get("rules_sha256") != rules_sha256(p):
        problems.append(f"в ядре не та версия правил ({meta})")
    if (chains.get("forward") or {}).get("policy") != "drop":
        problems.append("у цепочки forward нет policy drop")
    missing = [ip for ip in p["management_sources"] if ip not in sources]
    if missing:
        problems.append(f"нет разрешения SSH для {', '.join(missing)}")
    evidence = {"policy_meta": meta, "chains": chains, "ssh_sources": sources}
    if problems:
        return False, "; ".join(problems), evidence
    rows = _nft_probe(item, env, "POST")
    bad = connectivity.blocking_violations(rows)
    evidence["probes"] = [
        {"flow": f"{x.action} {x.dst_ip}:{x.port}", "result": x.result, "verdict": x.verdict} for x in rows
    ]
    if bad:
        return (
            False,
            "нарушены ожидания политики: "
            + "; ".join(f"{x.action} {x.src_cidr} → {x.dst_ip}:{x.port} = {x.result} ({x.note})" for x in bad),
            evidence,
        )
    ok_n = sum(1 for x in rows if x.verdict == "OK")
    return True, f"правила v{p['policy_version']} в ядре, пробы: {ok_n} из {len(rows)} соответствуют", evidence


def _verify_suricata(client: AgentClient, item: RemediationItem, env: dict | None = None) -> tuple[bool, str, dict]:
    r = client.call("suricata.read_status.v1", deadline_s=180)
    if not r.ok:
        return False, f"состояние датчика не получено ({r.state} {r.error_code})", r.as_fact()
    res = r.result
    eve = res.get("eve") or {}
    iface = item.params["interface"]
    problems = []
    if res.get("service") != "active":
        problems.append(f"служба {res.get('service')}")
    if not (res.get("config_test") or {}).get("ok"):
        problems.append("suricata -T не проходит")
    if iface not in (res.get("af_packet_interfaces") or []):
        problems.append(f"датчик не слушает {iface}")
    if not (eve.get("enabled") and eve.get("readable")):
        problems.append("журнал EVE недоступен")
    if item.params.get("test_rules") and not res.get("nixfort_test_rule_loaded"):
        problems.append("правила NIXFORT не загружены")
    evidence = {
        k: res.get(k) for k in ("service", "version", "af_packet_interfaces", "eve", "nixfort_test_rule_loaded")
    }
    if problems:
        return False, "; ".join(problems), evidence
    return True, f"Suricata {res.get('version')} работает на {iface}, EVE пишется, правила NIXFORT загружены", evidence


VERIFY: dict[str, Callable[..., tuple[bool, str, dict]]] = {
    "suricata.apply_sensor_profile.v1": _verify_suricata,
    "pkg.install_security_tool.v1": _verify_pkg,
    "fail2ban.apply_sshd_profile.v1": _verify_f2b,
    "ssh.apply_hardening_profile.v1": _verify_ssh,
    "nft.apply_policy.v1": _verify_nft,
}


def _after_rollback(item: RemediationItem, env: dict) -> tuple[bool, str]:
    """Firewall: prove with probes that critical ALLOW flows work again after the rollback."""
    if item.action_id != "nft.apply_policy.v1":
        return True, ""
    rows = _nft_probe(item, env, "AFTER_ROLLBACK")
    broken = [r for r in rows if r.action == "ALLOW" and r.critical and r.result != "OPEN"]
    if broken:
        return False, "после отката критичные соединения не восстановлены: " + ", ".join(
            f"{r.dst_ip}:{r.port}={r.result}" for r in broken
        )
    return True, "после отката критичные соединения снова работают (подтверждено пробами)"


def _precheck_nft(item: RemediationItem, env: dict) -> None:
    from apps.policy.models import FlowPolicyVersion

    active = FlowPolicyVersion.objects.filter(project=item.plan.project_id, status="ACTIVE").first()
    if active is None or active.version != item.params["policy_version"]:
        raise ItemOutcome(
            ItemState.FAILED, "активная политика изменилась после составления плана — составьте план заново"
        )
    rows = _nft_probe(item, env, "BASELINE")
    item.result = {**item.result, "baseline": {str(r.flow_id): r.result for r in rows}}
    item.save(update_fields=["result", "updated_at"])


def _save(item: RemediationItem, state: str, **result: Any) -> None:
    item.state = state
    item.result = {**item.result, **result}
    item.save(update_fields=["state", "result", "snapshot_id", "updated_at"])


# ---------------------------------------------------------------- one item
def run_item(job: Job, item: RemediationItem, log: Callable[[str, str], None], client_factory=None, sleep=None) -> str:
    client_factory = client_factory or client_for
    sleep = sleep or time.sleep
    node = item.node
    if node.confirmed_hostkey is None:
        raise ItemOutcome(ItemState.FAILED, "ключ узла не подтверждён")
    with jobs.node_mutation_lock(node):
        client = client_factory(node)
        pre = client.call("system.ping.v1")
        if not pre.ok:
            raise ItemOutcome(ItemState.FAILED, f"узел недоступен до изменения ({pre.error_code}) — ничего не менялось")
        if pre.os_profile not in ("ubuntu-24.04", "astra-1.8"):
            raise ItemOutcome(ItemState.FAILED, f"ОС не поддерживается ({pre.os_profile}) — изменения запрещены")

        env = {"job": job, "client_factory": client_factory, "log": log}
        if item.action_id == "nft.apply_policy.v1":
            log(f"{node.name}: пробы соединений до изменения", "INFO")
            _precheck_nft(item, env)
        _save(item, ItemState.APPLYING)
        log(f"{node.name}: {item.action_id} — применение", "INFO")
        resp = client.call(item.action_id, item.params, deadline_s=DEADLINES.get(item.action_id.split(".")[0], 120))
        if resp.state in ("FAILED", "REJECTED"):
            raise ItemOutcome(
                ItemState.FAILED,
                f"агент не применил изменение: {resp.state} {resp.error_code} — исходная конфигурация не изменена",
            )
        if resp.state != "OK":
            # transport/protocol error during a mutation: we do not know what happened on the node
            return _recover_unknown(item, resp, log, client_factory, sleep, env=env)
        sid = resp.result.get("snapshot_id", "")
        item.snapshot_id = sid
        _save(item, ItemState.VERIFYING, apply=resp.result)

        verify_client = client_factory(node)  # fresh client: every call is a new SSH connection
        ok, why, evidence = VERIFY[item.action_id](verify_client, item, env)
        log(f"{node.name}: постпроверка — {'OK' if ok else 'НЕ ПРОЙДЕНА'}: {why}", "INFO" if ok else "WARN")
        if not item.reversible:
            if ok:
                _save(item, ItemState.VERIFIED, verify=why, evidence=evidence)
                return ItemState.VERIFIED
            raise ItemOutcome(ItemState.UNKNOWN, f"необратимое действие не подтверждено: {why}")
        if ok:
            c = verify_client.call("mutation.commit.v1", {"snapshot_id": sid})
            if c.ok and c.result.get("committed"):
                _save(item, ItemState.VERIFIED, verify=why, evidence=evidence, commit=c.result)
                return ItemState.VERIFIED
            if c.ok and c.result.get("rolled_back"):
                raise ItemOutcome(
                    ItemState.ROLLED_BACK, "таймер отката сработал раньше подтверждения — изменение отменено узлом"
                )
            return _recover_unknown(item, c, log, client_factory, sleep, env=env)
        # verification failed -> roll back now, then prove the rollback
        return _rollback(item, why, log, client_factory, sleep, env=env)


def _rolled_back(item, why: str, rollback: dict, env: dict | None, message: str) -> None:
    """The node reports the rollback; for the firewall it is additionally proven by probes."""
    proven, note = _after_rollback(item, env) if env else (True, "")
    if not proven:
        _save(item, ItemState.UNKNOWN, reason=why, rollback=rollback, after_rollback=note)
        raise ItemOutcome(ItemState.UNKNOWN, f"{message}; {note} — требуется ручная проверка")
    _save(item, ItemState.ROLLED_BACK, reason=why, rollback=rollback, after_rollback=note)
    raise ItemOutcome(ItemState.ROLLED_BACK, f"{message}" + (f"; {note}" if note else ""))


def _rollback(item, why, log, client_factory, sleep, env=None) -> str:
    log(f"{item.node.name}: откат ({why})", "WARN")
    try:
        rb = client_factory(item.node).call("mutation.rollback_now.v1", {"snapshot_id": item.snapshot_id})
    except TransportError as exc:
        rb = AgentResponse(action="mutation.rollback_now.v1", state="TRANSPORT_ERROR", error_code=exc.code)
    if rb.ok and rb.result.get("rolled_back"):
        _rolled_back(item, why, rb.result, env, f"постпроверка не пройдена ({why}); откат выполнен")
    return _recover_unknown(item, rb, log, client_factory, sleep, reason=why, env=env)


def _recover_unknown(item, resp, log, client_factory, sleep, reason: str = "", env=None) -> str:
    """Node did not answer during a mutation. Wait for the node-side timer, then ask again."""
    if not item.snapshot_id or not item.reversible:
        raise ItemOutcome(
            ItemState.UNKNOWN,
            f"связь потеряна во время изменения ({resp.error_code}); "
            "состояние узла не подтверждено — проверьте узел вручную",
        )
    wait = int(item.params.get("rollback_timeout_s", settings.NIXFORT_ROLLBACK_TIMEOUT_S)) + 30
    log(f"{item.node.name}: нет связи ({resp.error_code}); ожидание автоотката на узле {wait} с", "WARN")
    sleep(wait)
    try:
        st = client_factory(item.node).call("mutation.snapshot_status.v1", {"snapshot_id": item.snapshot_id})
    except TransportError as exc:
        st = AgentResponse(action="mutation.snapshot_status.v1", state="TRANSPORT_ERROR", error_code=exc.code)
    if st.ok and st.result.get("rolled_back"):
        _rolled_back(
            item,
            reason or "потеря связи",
            st.result,
            env,
            "связь была потеряна; узел сам откатил изменение (подтверждено)",
        )
    raise ItemOutcome(
        ItemState.UNKNOWN,
        "откат не подтверждён — требуется ручная проверка узла "
        "(см. docs/LAB_SETUP.md: консоль VirtualBox, /var/lib/nixfort/snapshots)",
    )


# ---------------------------------------------------------------- whole plan
def execute(
    job: Job, log: Callable[[str, str], None], progress: Callable[[int, str], None], client_factory=None, sleep=None
) -> tuple[str, dict]:
    # resolved at call time (not at import) so that tests and future transports can substitute them
    client_factory = client_factory or (lambda node: client_for(node))
    sleep = sleep or (lambda s: time.sleep(s))
    plan = RemediationPlan.objects.select_related("project").get(id=job.params["plan_id"], project=job.project)
    items = list(plan.items.select_related("node", "node__project", "node__hostkey"))
    if plan.state != PlanState.APPROVED or plan.plan_hash != plan_hash(items):
        log("План изменён после утверждения или не утверждён — выполнение запрещено", "ERROR")
        return JobState.FAILED, {"error": "plan_not_approved_or_modified"}
    plan.state = PlanState.EXECUTING
    plan.job = job
    plan.save(update_fields=["state", "job", "updated_at"])
    outcomes: list[str] = []
    for i, item in enumerate(items):
        progress(int(i * 90 / max(1, len(items))), f"{item.node.name}: {item.action_id}")
        if outcomes and outcomes[-1] != ItemState.VERIFIED:
            _save(item, ItemState.SKIPPED, reason="предыдущий шаг не подтверждён")
            outcomes.append(ItemState.SKIPPED)
            continue
        try:
            state = run_item(job, item, log, client_factory, sleep)
        except ItemOutcome as o:
            state = o.state
            _save(item, o.state, reason=o.reason)
            log(f"{item.node.name}: {item.action_id} — {o.reason}", "ERROR" if o.state == ItemState.UNKNOWN else "WARN")
        except jobs.NodeBusy:
            state = ItemState.FAILED
            _save(item, state, reason="на узле уже выполняется другое изменение")
        outcomes.append(state)
        if state == ItemState.ROLLED_BACK:
            audit.log(
                job.requested_by,
                Action.ROLLBACK,
                obj=item,
                project=plan.project_id,
                outcome=Outcome.FAILED,
                node=item.node.name,
                agent_action=item.action_id,
            )

    verified = outcomes.count(ItemState.VERIFIED)
    if outcomes and verified == len(outcomes):
        plan_state, job_state = PlanState.VERIFIED, JobState.SUCCEEDED
    elif ItemState.UNKNOWN in outcomes:
        plan_state, job_state = PlanState.UNKNOWN, JobState.UNKNOWN
    elif ItemState.ROLLED_BACK in outcomes:
        plan_state, job_state = (PlanState.PARTIAL if verified else PlanState.ROLLED_BACK), JobState.ROLLED_BACK
    elif verified:
        plan_state, job_state = PlanState.PARTIAL, JobState.PARTIAL
    else:
        plan_state, job_state = PlanState.FAILED, JobState.FAILED

    # Post-change audit of affected nodes for the before/after report
    if verified:
        from apps.checks.services import run_audit

        progress(92, "повторный аудит")
        node_ids = sorted({str(i.node_id) for i in items})
        post = run_audit(job, purpose="post_change", node_ids=node_ids, log=lambda m, lvl="INFO": log(m, lvl))
        plan.post_audit_run = post
    plan.state = plan_state
    plan.finished_at = timezone.now()
    plan.save(update_fields=["state", "finished_at", "post_audit_run", "updated_at"])
    audit.log(
        job.requested_by,
        Action.PLAN_FINISHED,
        obj=plan,
        project=plan.project_id,
        outcome=Outcome.SUCCESS if plan_state == PlanState.VERIFIED else Outcome.FAILED,
        state=plan_state,
    )
    if job_state == JobState.ROLLED_BACK:
        jobs.transition(job, JobState.ROLLING_BACK, phase="откат")
    return job_state, {"plan": str(plan.id), "plan_state": plan_state, "items": outcomes}
