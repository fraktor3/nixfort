"""TCP probes of policy flows from test nodes and their evaluation (NODE_AGENT_PROTOCOL §6, ARCHITECTURE §6).

Semantics: ALLOW must be OPEN. DENY is "blocked" when the probe gets no connection (TIMEOUT/CLOSED/UNREACHABLE),
but blocking is PROVEN only if the same flow was OPEN on the baseline - otherwise it may simply be a closed port.
A probe error never counts as success.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from apps.execution.agent_client import client_for
from apps.execution.transport import TransportError

from .models import ConnectivityTest, Flow, FlowPolicyVersion

PROBE_TIMEOUT_MS = 1500
BLOCKED = {"TIMEOUT", "CLOSED", "UNREACHABLE"}
V = ConnectivityTest.Verdict


@dataclass
class Probe:
    flow: Flow
    result: str
    latency_ms: int | None
    probe_node: str
    note: str = ""


def run_probes(flows: list[Flow], client_factory=None) -> list[Probe]:
    """One net.tcp_probe call per test node (≤ 50 targets each)."""
    client_factory = client_factory or client_for
    out: list[Probe] = []
    by_node: dict = {}
    for f in flows:
        if f.probe_from_id is None:
            out.append(Probe(f, "NOT_RUN", None, "", "у потока не задан тестовый узел"))
        elif f.probe_from.confirmed_hostkey is None:
            out.append(Probe(f, "NOT_RUN", None, f.probe_from.name, "ключ тестового узла не подтверждён"))
        else:
            by_node.setdefault(f.probe_from, []).append(f)
    for node, group in by_node.items():
        for i in range(0, len(group), 50):
            chunk = group[i : i + 50]
            targets = [{"ip": f.dst_ip, "port": f.port} for f in chunk]
            try:
                r = client_factory(node).call(
                    "net.tcp_probe.v1", {"targets": targets, "timeout_ms": PROBE_TIMEOUT_MS}, deadline_s=120
                )
            except TransportError as exc:
                out += [Probe(f, "ERROR", None, node.name, f"тестовый узел недоступен ({exc.code})") for f in chunk]
                continue
            results = (r.result or {}).get("results") or [] if r.ok else []
            if len(results) != len(chunk):
                why = f"{r.state} {r.error_code or ''}".strip()
                out += [Probe(f, "ERROR", None, node.name, f"проба не выполнена ({why})") for f in chunk]
                continue
            for f, res in zip(chunk, results, strict=True):
                same = res.get("ip") == f.dst_ip and res.get("port") == f.port
                result = res.get("result") if same else "ERROR"
                if result not in {"OPEN", *BLOCKED}:
                    result = "ERROR"
                out.append(Probe(f, result, res.get("latency_ms"), node.name))
    order = {f.id: i for i, f in enumerate(flows)}
    return sorted(out, key=lambda p: order[p.flow.id])


def evaluate(flow: Flow, result: str, baseline: str | None) -> tuple[str, str]:
    """Verdict of one probe. `baseline` is the result of the same flow before the change (None = no baseline)."""
    if result == "NOT_RUN":
        return V.NOT_CHECKED, ""
    if result == "ERROR":
        return V.UNPROVABLE, "ошибка пробы — результат не засчитывается"
    if flow.action == Flow.Action.ALLOW:
        if result == "OPEN":
            return V.OK, "соединение работает"
        if baseline is not None and baseline != "OPEN":
            return V.UNPROVABLE, "соединение не работало и до изменения (служба не запущена?)"
        return V.VIOLATION, "разрешённое соединение не работает"
    # DENY
    if result == "OPEN":
        return V.VIOLATION, "запрещённое соединение открыто"
    if baseline is None:
        return V.OK, "соединение не устанавливается"
    if baseline == "OPEN":
        return V.OK, "блокировка доказана: до изменения порт был открыт"
    return V.UNPROVABLE, "блокировка не доказуема: порт был закрыт и до изменения"


def record(
    probes: list[Probe],
    *,
    project,
    policy: FlowPolicyVersion,
    phase: str,
    job=None,
    plan_item=None,
    baseline: dict | None = None,
) -> list[ConnectivityTest]:
    rows = []
    for p in probes:
        base = baseline.get(p.flow.id) if baseline is not None else None
        verdict, why = evaluate(p.flow, p.result, base if baseline is not None else None)
        if phase == ConnectivityTest.Phase.BASELINE:
            verdict, why = (V.NOT_CHECKED, "") if p.result == "NOT_RUN" else (V.OK, "исходное состояние")
        rows.append(
            ConnectivityTest(
                project=project,
                job=job,
                plan_item=plan_item,
                phase=phase,
                flow=p.flow,
                policy_version=policy.version,
                flow_name=p.flow.name[:100],
                src_cidr=p.flow.src_cidr,
                dst_ip=p.flow.dst_ip,
                port=p.flow.port,
                action=p.flow.action,
                critical=p.flow.critical,
                probe_node=p.probe_node,
                result=p.result,
                latency_ms=p.latency_ms,
                verdict=verdict,
                note=(p.note or why)[:200],
            )
        )
    return ConnectivityTest.objects.bulk_create(rows)


def blocking_violations(rows: list[ConnectivityTest]) -> list[ConnectivityTest]:
    """Violations that must cancel a firewall change: a critical ALLOW that is not OPEN (broken, or not provable
    because the probe failed), or a DENY that is still open."""
    bad = []
    for r in rows:
        if r.action == Flow.Action.ALLOW and r.critical and r.result != "OPEN":
            bad.append(r)  # unproven availability of a critical flow is not accepted
        elif r.action == Flow.Action.DENY and r.verdict == V.VIOLATION:
            bad.append(r)
    return bad


def active_policy(project) -> FlowPolicyVersion | None:
    return FlowPolicyVersion.objects.filter(project=project, status=FlowPolicyVersion.Status.ACTIVE).first()


def policy_flows(policy: FlowPolicyVersion) -> list[Flow]:
    return list(policy.flows.select_related("dst_node", "probe_from", "probe_from__hostkey").order_by("dst_ip", "port"))


def check_now(job, log: Callable[[str, str], None], client_factory=None) -> tuple[str, dict]:
    """Job CONNECTIVITY: probe the active policy as it is now."""
    from apps.execution.models import JobState

    policy = active_policy(job.project)
    if policy is None:
        log("В проекте нет активной политики соединений", "ERROR")
        return JobState.FAILED, {"error": "no_active_policy"}
    flows = policy_flows(policy)
    probes = run_probes(flows, client_factory)
    rows = record(
        probes, project=job.project, policy=policy, phase=ConnectivityTest.Phase.CHECK, job=job, baseline=None
    )
    summary: dict[str, int] = {}
    for r in rows:
        summary[r.verdict] = summary.get(r.verdict, 0) + 1
        log(f"{r.action} {r.src_cidr} → {r.dst_ip}:{r.port}: {r.result} — {r.get_verdict_display()}", "INFO")
    state = JobState.SUCCEEDED if rows and summary.get(V.OK, 0) == len(rows) else JobState.PARTIAL
    if not any(r.result in {"OPEN", *BLOCKED} for r in rows):
        state = JobState.FAILED
    return state, {"policy_version": policy.version, "summary": summary}
