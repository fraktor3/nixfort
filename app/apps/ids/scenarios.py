"""Protection tests: simulated attacks from the test client and what each defence layer did.

Principle (as everywhere in NIXFORT): a layer is credited only on observed evidence — a refused/timed-out
connection, a Fail2ban ban list, a Suricata alert from the attacking address. «Sensor log unavailable» is
reported as such and never as «no attack detected».
"""

from __future__ import annotations

import ipaddress
import time
from collections.abc import Callable
from datetime import datetime, timedelta

from django.utils import timezone

from apps.execution.agent_client import client_for
from apps.execution.transport import TransportError
from apps.inventory.models import Node
from apps.policy.models import Flow, FlowPolicyVersion

from .models import IdsEvent, ProtectionTest

TEST_SID, SCAN_SID, BRUTE_SID = 9000001, 9000002, 9000003
LOAD_CONNECTIONS, LOAD_CONCURRENCY, LOAD_DURATION = 120, 25, 8
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
              *range(1000, 1020)]  # fmt: skip
SENSOR_WAIT_S = 6  # EVE is flushed asynchronously
V = ProtectionTest.Verdict


class ScenarioError(Exception):
    pass


# ---------------------------------------------------------------- nodes and agent calls
def _node(project, role: str, need_data_ip: bool = False) -> Node:
    for n in project.nodes.filter(is_active=True).select_related("hostkey").order_by("name"):
        if n.has_role(role) and n.confirmed_hostkey and (n.data_ips or not need_data_ip):
            return n
    raise ScenarioError(f"нет узла с ролью «{role}» и подтверждённым ключом")


def _call(client_factory, node, action, params=None, deadline_s=60):
    try:
        return client_factory(node).call(action, params or {}, deadline_s=deadline_s)
    except TransportError as exc:
        from apps.execution.agent_client import AgentResponse

        return AgentResponse(action=action, state="TRANSPORT_ERROR", error_code=exc.code)


def fetch_events(project, sensor: Node, job, since: datetime | None, client_factory) -> tuple[bool, str, list]:
    """Read new alerts/anomalies from the sensor and store them. Returns (log_available, reason, events)."""
    params = {"since_ts": since.isoformat(timespec="seconds") if since else None, "limit": 500,
              "types": ["alert", "anomaly"]}  # fmt: skip
    r = _call(client_factory, sensor, "suricata.read_events.v1", params, deadline_s=60)
    if not r.ok:
        return False, f"датчик не ответил ({r.state} {r.error_code or ''})".strip(), []
    if not r.result.get("eve_available"):
        why = {"eve_disabled": "журнал EVE выключен", "eve_unreadable": "журнал EVE недоступен для чтения"}
        return False, why.get(r.result.get("reason"), "журнал EVE недоступен"), []
    rows = []
    for ev in r.result.get("events") or []:
        try:
            ts = datetime.fromisoformat(str(ev.get("timestamp")))
        except ValueError:
            continue
        if ts.tzinfo is None:
            continue
        alert = ev.get("alert") or {}
        rows.append(
            IdsEvent(
                project=project,
                node=sensor,
                job=job,
                ts=ts,
                event_type=str(ev.get("event_type"))[:10],
                signature_id=alert.get("signature_id") if isinstance(alert.get("signature_id"), int) else None,
                signature=str(alert.get("signature") or "")[:256],
                severity=alert.get("severity") if isinstance(alert.get("severity"), int) else None,
                src_ip=_ip(ev.get("src_ip")),
                src_port=_port(ev.get("src_port")),
                dest_ip=_ip(ev.get("dest_ip")),
                dest_port=_port(ev.get("dest_port")),
                proto=str(ev.get("proto") or "")[:10],
            )
        )
    IdsEvent.objects.bulk_create(rows, ignore_conflicts=True)
    return True, "", rows


def _ip(v):
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return None


def _port(v):
    return v if isinstance(v, int) and 0 <= v <= 65535 else None


def _alerts(events, sid: int, src_ips: list[str]) -> list:
    return [e for e in events if e.signature_id == sid and e.src_ip in src_ips]


def _policy(project) -> FlowPolicyVersion | None:
    return FlowPolicyVersion.objects.filter(project=project, status="ACTIVE").first()


def _expected(policy, client: Node, dst_ip: str, port: int) -> str | None:
    """ALLOW / DENY from the active policy for client -> dst:port, None when the policy says nothing."""
    if policy is None:
        return None
    for f in policy.flows.filter(dst_ip=dst_ip, port=port):
        net = ipaddress.ip_network(f.src_cidr, strict=False)
        if any(ipaddress.ip_address(ip) in net for ip in client.data_ips):
            return f.action
    return None


def _verdict(layers: list[dict]) -> str:
    oks = [lay["ok"] for lay in layers if lay["ok"] is not None]
    if not oks:
        return V.ERROR
    if all(oks):
        return V.PROTECTED
    return V.PARTIAL if any(oks) else V.NOT_PROTECTED


def _ids_layer(available: bool, reason: str, hits: list, what: str) -> dict:
    if not available:
        return {"layer": "Suricata (шлюз)", "expected": what, "observed": reason, "ok": None}
    if hits:
        e = hits[0]
        observed = f"событие sid {e.signature_id} «{e.signature}» {e.src_ip} → {e.dest_ip}:{e.dest_port}"
        return {"layer": "Suricata (шлюз)", "expected": what, "observed": observed, "ok": True}
    return {"layer": "Suricata (шлюз)", "expected": what, "observed": "событий нет", "ok": False}


# ---------------------------------------------------------------- scenarios
def ids_marker(job, log, client_factory, sleep) -> ProtectionTest:
    project = job.project
    sensor, client = _node(project, "ids_sensor"), _node(project, "test_client", need_data_ip=True)
    policy = _policy(project)
    flows = (
        list(policy.flows.filter(action=Flow.Action.ALLOW, probe_from=client).order_by("-critical")) if policy else []
    )
    if not flows:
        raise ScenarioError("нет разрешённого потока политики с пробой с тестового клиента — некуда отправить маркер")
    f = flows[0]
    since = timezone.now() - timedelta(seconds=5)
    log(f"{client.name} → {f.dst_ip}:{f.port}: отправка тестовой строки NIXFORT-IDS-TEST-7f3a", "INFO")
    r = _call(client_factory, client, "net.send_ids_test.v1", {"ip": f.dst_ip, "port": f.port})
    sent = r.ok and r.result.get("sent")
    what = f"событие sid {TEST_SID} от {', '.join(client.data_ips)}"
    if not sent:
        layer = {"layer": "Suricata (шлюз)", "expected": what, "observed": "тестовое соединение не установлено",
                 "ok": None}  # fmt: skip
        return _save(job, ProtectionTest.Scenario.IDS_MARKER, [layer], {"target": f"{f.dst_ip}:{f.port}"})
    sleep(SENSOR_WAIT_S)
    available, reason, events = fetch_events(project, sensor, job, since, client_factory)
    hits = _alerts(events, TEST_SID, client.data_ips)
    return _save(
        job,
        ProtectionTest.Scenario.IDS_MARKER,
        [_ids_layer(available, reason, hits, what)],
        {"target": f"{f.dst_ip}:{f.port}", "events": len(events)},
    )


def port_scan(job, log, client_factory, sleep) -> ProtectionTest:
    project = job.project
    sensor = _node(project, "ids_sensor")
    client = _node(project, "test_client", need_data_ip=True)
    server = _node(project, "server", need_data_ip=True)
    ip = server.data_ips[0]
    policy = _policy(project)
    since = timezone.now() - timedelta(seconds=5)
    log(f"{client.name} → {ip}: сканирование {len(SCAN_PORTS)} TCP-портов", "INFO")
    targets = [{"ip": ip, "port": p} for p in SCAN_PORTS]
    r = _call(client_factory, client, "net.tcp_probe.v1", {"targets": targets, "timeout_ms": 300}, deadline_s=90)
    if not r.ok:
        raise ScenarioError(f"сканирование не выполнено ({r.state} {r.error_code})")
    open_ports = sorted(x["port"] for x in r.result.get("results") or [] if x.get("result") == "OPEN")
    allowed = sorted(p for p in SCAN_PORTS if _expected(policy, client, ip, p) == Flow.Action.ALLOW)
    denied_open = [p for p in open_ports if _expected(policy, client, ip, p) == Flow.Action.DENY]
    unlisted_open = [p for p in open_ports if _expected(policy, client, ip, p) is None]
    if policy is None:
        fw = {"layer": "Межсетевой экран (шлюз)", "expected": "нет активной политики",
              "observed": f"открыты: {open_ports or 'нет'}", "ok": None}  # fmt: skip
    else:
        ok = not denied_open and not unlisted_open
        fw = {
            "layer": "Межсетевой экран (шлюз)",
            "expected": f"снаружи доступны только разрешённые политикой порты: {allowed or 'нет'}",
            "observed": f"открыты: {open_ports or 'нет'}"
            + (f"; запрещённые, но открытые: {denied_open}" if denied_open else "")
            + (f"; не описанные в политике, но открытые: {unlisted_open}" if unlisted_open else ""),
            "ok": ok,
        }
    sleep(SENSOR_WAIT_S)
    available, reason, events = fetch_events(project, sensor, job, since, client_factory)
    ids = _ids_layer(available, reason, _alerts(events, SCAN_SID, client.data_ips),
                     f"событие «сканирование портов» (sid {SCAN_SID}) от {', '.join(client.data_ips)}")  # fmt: skip
    return _save(job, ProtectionTest.Scenario.PORT_SCAN, [fw, ids], {"target": ip, "open_ports": open_ports})


def ssh_bruteforce(job, log, client_factory, sleep) -> ProtectionTest:
    project = job.project
    sensor = _node(project, "ids_sensor")
    client = _node(project, "test_client", need_data_ip=True)
    server = _node(project, "server", need_data_ip=True)
    policy = _policy(project)
    data_ip = server.data_ips[0]
    layers, details = [], {}

    # A. through the gateway (users -> servers network)
    since = timezone.now() - timedelta(seconds=5)
    log(f"A. {client.name} → {data_ip}:22 через шлюз: 6 попыток входа под несуществующими пользователями", "INFO")
    a = _call(client_factory, client, "net.ssh_login_attempts.v1", {"ip": data_ip, "port": 22, "count": 6},
              deadline_s=90)  # fmt: skip
    if not a.ok:
        raise ScenarioError(f"попытки входа не выполнены ({a.state} {a.error_code})")
    sa = a.result.get("summary") or {}
    details["through_gateway"] = sa
    expected = _expected(policy, client, data_ip, 22)
    if expected == Flow.Action.DENY:
        layers.append({
            "layer": "Межсетевой экран (шлюз)",
            "expected": "SSH из сети пользователей запрещён политикой — соединения не устанавливаются",
            "observed": f"дошли до sshd: {sa.get('REJECTED', 0)} из 6; не установлены: "
                        f"{sa.get('TIMEOUT', 0) + sa.get('CLOSED', 0)}",
            "ok": sa.get("REJECTED", 0) == 0,
        })  # fmt: skip
    sleep(SENSOR_WAIT_S)
    available, reason, events = fetch_events(project, sensor, job, since, client_factory)
    layers.append(_ids_layer(available, reason, _alerts(events, BRUTE_SID, client.data_ips),
                             f"событие «подбор пароля SSH» (sid {BRUTE_SID}) от {', '.join(client.data_ips)}"))  # fmt: skip

    # B. inside the management network (no gateway on the path): only the server's own Fail2ban can help
    st = _call(client_factory, server, "fail2ban.read_status.v1")
    jail = (st.result or {}).get("sshd") or {} if st.ok else {}
    if st.ok and jail.get("enabled"):
        log(f"B. {client.name} → {server.mgmt_ip}:22 напрямую (сеть управления): 7 попыток входа", "INFO")
        b = _call(client_factory, client, "net.ssh_login_attempts.v1",
                  {"ip": server.mgmt_ip, "port": 22, "count": 7}, deadline_s=120)  # fmt: skip
        sb = (b.result or {}).get("summary") or {} if b.ok else {}
        details["direct"] = sb
        sleep(3)
        after = _call(client_factory, server, "fail2ban.read_status.v1")
        banned = (((after.result or {}).get("sshd") or {}).get("banned_ips") or []) if after.ok else []
        ok = client.mgmt_ip in banned
        layers.append({
            "layer": "Fail2ban (сервер)",
            "expected": f"адрес {client.mgmt_ip} заблокирован после {jail.get('maxretry')} неудачных попыток",
            "observed": (f"{client.mgmt_ip} в списке блокировки (снимется через {jail.get('bantime')} с)" if ok
                         else f"в списке блокировки: {banned or 'пусто'}")
                        + f"; попытки: дошли {sb.get('REJECTED', 0)}, отклонены {sb.get('CLOSED', 0) + sb.get('TIMEOUT', 0)}",
            "ok": ok,
        })  # fmt: skip
    else:
        layers.append({"layer": "Fail2ban (сервер)", "expected": "jail sshd включён",
                       "observed": "Fail2ban на сервере не настроен — шаг B не выполнялся", "ok": False})  # fmt: skip
    return _save(job, ProtectionTest.Scenario.SSH_BRUTEFORCE, layers, details)


def load_resilience(job, log, client_factory, sleep) -> ProtectionTest:
    """Controlled resilience check: a burst of short TCP connections from the client, measured two ways —
    against an ALLOWED service (it must stay responsive) and against a DENIED port (the firewall must absorb
    the burst before it reaches the service). Suricata should flag the burst. Bounded; this is not a DoS tool.
    """
    project = job.project
    sensor = _node(project, "ids_sensor")
    client = _node(project, "test_client", need_data_ip=True)
    server = _node(project, "server", need_data_ip=True)
    policy = _policy(project)
    data_ip = server.data_ips[0]
    allowed = [p for p in (80, 443, 8080, 3306) if _expected(policy, client, data_ip, p) == Flow.Action.ALLOW]
    denied = [p for p in (8080, 22, 3306, 23) if _expected(policy, client, data_ip, p) == Flow.Action.DENY]
    if not allowed:
        raise ScenarioError("в политике нет разрешённого сервиса для проверки устойчивости")
    layers, details = [], {}
    since = timezone.now() - timedelta(seconds=5)

    # A. load against an allowed service — it must keep answering
    ap = allowed[0]
    log(f"A. нагрузка на разрешённый сервис {data_ip}:{ap} — {LOAD_CONNECTIONS} коротких соединений", "INFO")
    a = _call(
        client_factory,
        client,
        "net.load_test.v1",
        {
            "ip": data_ip,
            "port": ap,
            "connections": LOAD_CONNECTIONS,
            "concurrency": LOAD_CONCURRENCY,
            "duration_s": LOAD_DURATION,
        },
        deadline_s=LOAD_DURATION + 30,
    )
    if not a.ok:
        raise ScenarioError(f"нагрузка не выполнена ({a.state} {a.error_code})")
    ra = a.result
    details["allowed"] = {
        k: ra.get(k) for k in ("attempted", "succeeded", "refused", "timed_out", "avg_latency_ms", "rate_per_s")
    }
    layers.append({
        "layer": "Доступность сервиса",
        "expected": f"разрешённый сервис {data_ip}:{ap} остаётся доступен под нагрузкой",
        "observed": f"успешных соединений {ra.get('succeeded')} из {ra.get('attempted')} "
                    f"(темп {ra.get('rate_per_s')}/с, средняя задержка {ra.get('avg_latency_ms')} мс)",
        "ok": bool(ra.get("service_available")),
    })  # fmt: skip

    # B. load against a denied port — the firewall must absorb it before the service
    if denied:
        dp = denied[0]
        log(f"B. нагрузка на запрещённый порт {data_ip}:{dp} — межсетевой экран должен поглотить её", "INFO")
        b = _call(
            client_factory,
            client,
            "net.load_test.v1",
            {
                "ip": data_ip,
                "port": dp,
                "connections": LOAD_CONNECTIONS,
                "concurrency": LOAD_CONCURRENCY,
                "duration_s": LOAD_DURATION,
            },
            deadline_s=LOAD_DURATION + 30,
        )
        rb = b.result if b.ok else {}
        details["denied"] = {k: rb.get(k) for k in ("attempted", "succeeded", "timed_out", "refused")}
        layers.append({
            "layer": "Межсетевой экран (шлюз)",
            "expected": f"нагрузка на запрещённый порт {dp} не доходит до сервиса",
            "observed": f"успешных соединений {rb.get('succeeded', 0)} из {rb.get('attempted', 0)}; "
                        f"не установлено: {(rb.get('timed_out', 0) or 0) + (rb.get('refused', 0) or 0)}",
            "ok": b.ok and rb.get("succeeded", 1) == 0,
        })  # fmt: skip

    # service still responsive right after the load
    sleep(2)
    chk = _call(
        client_factory, client, "net.tcp_probe.v1", {"targets": [{"ip": data_ip, "port": ap}], "timeout_ms": 1500}
    )
    after_open = chk.ok and (chk.result.get("results") or [{}])[0].get("result") == "OPEN"
    layers.append({
        "layer": "Сервис после нагрузки",
        "expected": "сервис отвечает после снятия нагрузки",
        "observed": "сервис доступен" if after_open else "сервис не ответил",
        "ok": after_open,
    })  # fmt: skip

    # Suricata should have flagged the burst (many new connections from one source)
    sleep(SENSOR_WAIT_S)
    available, reason, events = fetch_events(project, sensor, job, since, client_factory)
    hits = _alerts(events, SCAN_SID, client.data_ips)
    layers.append(
        _ids_layer(
            available, reason, hits, f"событие о всплеске соединений (sid {SCAN_SID}) от {', '.join(client.data_ips)}"
        )
    )
    return _save(job, ProtectionTest.Scenario.LOAD, layers, details)


SCENARIOS: dict[str, Callable] = {
    ProtectionTest.Scenario.IDS_MARKER: ids_marker,
    ProtectionTest.Scenario.PORT_SCAN: port_scan,
    ProtectionTest.Scenario.SSH_BRUTEFORCE: ssh_bruteforce,
    ProtectionTest.Scenario.LOAD: load_resilience,
}


def _save(job, scenario, layers, details) -> ProtectionTest:
    verdict = _verdict(layers)
    summary = "; ".join(f"{lay['layer']}: {'да' if lay['ok'] else 'нет' if lay['ok'] is False else 'н/д'}"
                        for lay in layers)  # fmt: skip
    return ProtectionTest.objects.create(
        project=job.project, job=job, scenario=scenario, verdict=verdict, layers=layers, details=details,
        summary=summary[:300],
    )  # fmt: skip


def run(job, log, client_factory=None, sleep=None):
    from apps.execution.models import JobState

    client_factory = client_factory or (lambda node: client_for(node))
    sleep = sleep or (lambda s: time.sleep(s))
    scenario = job.params.get("scenario")
    if scenario not in SCENARIOS:
        return JobState.FAILED, {"error": "unknown_scenario"}
    try:
        t = SCENARIOS[scenario](job, log, client_factory, sleep)
    except ScenarioError as exc:
        t = _save(job, scenario, [], {"error": str(exc)})
        t.summary = str(exc)[:300]
        t.save(update_fields=["summary"])
        log(str(exc), "ERROR")
        return JobState.FAILED, {"test": str(t.id), "error": str(exc)}
    for lay in t.layers:
        mark = "OK" if lay["ok"] else "НЕТ" if lay["ok"] is False else "н/д"
        log(f"{lay['layer']}: {mark} — {lay['observed']}", "INFO" if lay["ok"] else "WARN")
    state = {V.PROTECTED: JobState.SUCCEEDED, V.PARTIAL: JobState.PARTIAL}.get(t.verdict, JobState.FAILED)
    return state, {"test": str(t.id), "verdict": t.verdict}


def fetch_job(job, log, client_factory=None):
    """Job IDS_FETCH: new events since the newest stored one (or the tail of the log)."""
    from apps.execution.models import JobState

    client_factory = client_factory or (lambda node: client_for(node))
    try:
        sensor = _node(job.project, "ids_sensor")
    except ScenarioError as exc:
        log(str(exc), "ERROR")
        return JobState.FAILED, {"error": str(exc)}
    last = IdsEvent.objects.filter(node=sensor).order_by("-ts").first()
    available, reason, events = fetch_events(job.project, sensor, job, last.ts if last else None, client_factory)
    if not available:
        log(f"{sensor.name}: {reason}", "ERROR")
        return JobState.FAILED, {"eve_available": False, "reason": reason}
    log(f"{sensor.name}: новых событий {len(events)}", "INFO")
    return JobState.SUCCEEDED, {"eve_available": True, "new_events": len(events)}
