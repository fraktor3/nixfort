"""The project overview: where the segment stands and what to do next.

Everything here is computed from stored records (audit runs, plans, protection tests, summaries, reports);
nothing is invented and nothing is called on the nodes. A missing record is shown as missing.
"""

from __future__ import annotations

import ipaddress
from html import escape

from django.urls import reverse

# Defence layers in the order an attacker meets them; each is a set of catalogue prefixes.
LAYERS = [
    ("FW", "Межсетевой экран шлюза", "фильтрация между сетями"),
    ("IDS", "Обнаружение вторжений", "Suricata на шлюзе"),
    ("HFW", "Хостовый экран", "входящие на сервере"),
    ("SSH", "Доступ по SSH", "настройки sshd"),
    ("F2B", "Fail2ban", "блокировка перебора"),
    ("SYS", "Система", "ОС, время, журнал, службы"),
]
RANK = {"FAIL": 4, "ERROR": 3, "UNKNOWN": 2, "PASS": 1}


def _ratio(results) -> dict | None:
    applicable = [r for r in results if r.status != "NOT_APPLICABLE"]
    if not applicable:
        return None
    passed = sum(1 for r in applicable if r.status == "PASS")
    worst = max((r.status for r in applicable), key=lambda s: RANK.get(s, 0))
    return {"passed": passed, "total": len(applicable), "worst": worst,
            "failed": [r.check_id for r in applicable if r.status != "PASS"]}  # fmt: skip


def defence_matrix(project, nodes, latest, first):
    """Rows = layers, columns = nodes; each cell: passed/applicable in the latest audit and in the first one."""
    if latest is None:
        return None
    by = {}
    for r in latest.results.all():
        by.setdefault((r.check_id.split("-")[0], r.node_id), []).append(r)
    was = {}
    if first is not None and first.id != latest.id:
        for r in first.results.all():
            was.setdefault((r.check_id.split("-")[0], r.node_id), []).append(r)
    shown = [n for n in nodes if any(_ratio(by.get((p, n.id), [])) for p, _, _ in LAYERS)]
    rows = []
    for prefix, title, hint in LAYERS:
        cells = []
        for n in shown:
            now = _ratio(by.get((prefix, n.id), []))
            before = _ratio(was.get((prefix, n.id), [])) if was else None
            cells.append({"now": now, "was": before})
        if any(c["now"] for c in cells):
            rows.append({"prefix": prefix, "title": title, "hint": hint, "cells": cells})
    hidden = [n.name for n in nodes if n not in shown]
    return {"nodes": shown, "rows": rows, "hidden": hidden}


def _fmt(dt) -> str:
    from django.utils import timezone

    return timezone.localtime(dt).strftime("%d.%m %H:%M") if dt else ""


def cycle(project, nodes, runs, plans, protection, summary, report):
    """The NIXFORT work order with each step's evidence and the first step that still needs doing."""
    pid = project.id
    steps = []
    no_key = [n for n in nodes if n.confirmed_hostkey is None]
    no_inv = [n for n in nodes if n.last_inventory_at is None]
    if not nodes:
        steps.append(("Узлы", "узлов нет", False, reverse("inventory:node_create", args=[pid])))
    elif no_key:
        steps.append(("Узлы", f"не подтверждён ключ: {', '.join(n.name for n in no_key[:2])}", False,
                      reverse("inventory:node_detail", args=[pid, no_key[0].id])))  # fmt: skip
    elif no_inv:
        steps.append(("Узлы", f"нет инвентаризации: {', '.join(n.name for n in no_inv[:2])}", False, None))
    else:
        last = max(n.last_inventory_at for n in nodes)
        steps.append(("Узлы", f"{len(nodes)} · ключи подтверждены · {_fmt(last)}", True, None))
    latest = runs[0] if runs else None
    if latest:
        fails = (latest.summary.get("total") or {}).get("FAIL", 0)
        steps.append(("Аудит", f"{_fmt(latest.created_at)} · нарушений {fails}", True,
                      reverse("checks:run_detail", args=[pid, latest.id])))  # fmt: skip
    else:
        steps.append(("Аудит", "ещё не выполнялся", False, reverse("checks:run_list", args=[pid])))
    plan = plans[0] if plans else None
    first_fails = (runs[-1].summary.get("total") or {}).get("FAIL", 0) if runs else 0
    if plan and plan.state == "VERIFIED":
        steps.append(("Исправления", f"применены · {plan.items.count()} шагов", True,
                      reverse("remediation:plan_detail", args=[pid, plan.id])))  # fmt: skip
    elif plan:
        steps.append(("Исправления", plan.get_state_display().lower(), plan.state not in ("DRAFT", "APPROVED", "EXECUTING"),
                      reverse("remediation:plan_detail", args=[pid, plan.id])))  # fmt: skip
    elif latest and first_fails:
        steps.append(("Исправления", "плана нет", False, reverse("checks:run_detail", args=[pid, latest.id])))
    else:
        steps.append(("Исправления", "не требуются" if latest else "после аудита", bool(latest), None))
    if protection:
        ok = sum(1 for t in protection if t.verdict == "PROTECTED")
        steps.append(("Проверка защиты", f"сработала в {ok} из {len(protection)} сценариев", True,
                      reverse("ids:protection", args=[pid])))  # fmt: skip
    else:
        steps.append(("Проверка защиты", "сценарии не запускались", False, reverse("ids:protection", args=[pid])))
    if summary:
        fails = sum((s.get("auth") or {}).get("total") or 0 for s in summary.data.get("servers", []))
        steps.append(("Журналы", f"{_fmt(summary.created_at)} · неудачных входов {fails}", True,
                      reverse("seclog:seclog", args=[pid])))  # fmt: skip
    else:
        steps.append(("Журналы", "сводки нет", False, reverse("seclog:seclog", args=[pid])))
    fresh_report = report and latest and report.created_at >= latest.created_at
    if fresh_report:
        steps.append(("Отчёт", f"{_fmt(report.created_at)} · SHA-256 {report.sha256[:8]}", True,
                      reverse("reports:detail", args=[pid, report.id])))  # fmt: skip
    else:
        steps.append(("Отчёт", "есть более новый аудит" if report else "не сформирован", False,
                      reverse("reports:list", args=[pid])))  # fmt: skip
    out, next_found = [], False
    for title, state, done, url in steps:
        is_next = not done and not next_found
        next_found = next_found or is_next
        out.append({"title": title, "state": state, "done": done, "next": is_next, "url": url})
    return out


def next_action(project, steps, nodes, runs, plans):
    """The one primary action of the overview, derived from the first unfinished step."""
    pid = project.id
    nxt = next((s for s in steps if s["next"]), None)
    if nxt is None:
        return {"label": "Повторить аудит", "url": reverse("checks:run_start", args=[pid]), "post": True}
    t = nxt["title"]
    if t == "Узлы":
        if not nodes:
            return {"label": "Добавить узел", "url": nxt["url"], "post": False}
        if nxt["url"]:
            return {"label": "Подтвердить ключ узла", "url": nxt["url"], "post": False}
        return {
            "label": "Инвентаризация всех узлов",
            "url": reverse("inventory:inventory_run", args=[pid]),
            "post": True,
        }
    if t == "Аудит":
        return {"label": "Запустить аудит", "url": reverse("checks:run_start", args=[pid]), "post": True}
    if t == "Исправления":
        if plans and plans[0].state == "DRAFT":
            return {"label": "Рассмотреть план", "url": nxt["url"], "post": False}
        return {"label": "Сформировать план", "url": nxt["url"], "post": False}
    if t == "Проверка защиты":
        return {"label": "Проверить защиту", "url": nxt["url"], "post": False}
    if t == "Журналы":
        return {"label": "Собрать журналы", "url": nxt["url"], "post": False}
    return {"label": "Сформировать отчёт", "url": nxt["url"], "post": False}


def finding(latest, nodes) -> str | None:
    """One sentence about the most important fact in the latest audit."""
    if latest is None:
        return None
    names = {n.id: n.name for n in nodes}
    bad = [r for r in latest.results.all() if r.status in ("FAIL", "ERROR", "UNKNOWN")]
    if not bad:
        return "По последнему аудиту все применимые проверки пройдены."
    bad.sort(key=lambda r: (-RANK.get(r.status, 0), r.check_id))
    head = ", ".join(f"{r.check_id} на {names.get(r.node_id, '?')}" for r in bad[:4])
    more = f" и ещё {len(bad) - 4}" if len(bad) > 4 else ""
    fails = sum(1 for r in bad if r.status == "FAIL")
    rest = len(bad) - fails
    what = f"не пройдено {fails}" + (f", без данных {rest}" if rest else "")
    return f"В последнем аудите {what}: {head}{more}."


# ---------------------------------------------------------------- segment scheme (server-side SVG)
def _net_name(project, cidr: str, nodes) -> str:
    net = ipaddress.ip_network(cidr, strict=False)
    if project.controller_ip and ipaddress.ip_address(project.controller_ip) in net:
        return "сеть управления"
    roles = set()
    for n in nodes:
        if any(ipaddress.ip_address(ip) in net for ip in n.data_ips or []):
            roles.update(n.roles)
    if "server" in roles:
        return "сеть серверов"
    if "test_client" in roles:
        return "сеть пользователей"
    return "сеть"


def node_states(matrix) -> dict:
    """Node name -> "pass" | "fail" | "unknown" from the defence matrix (the worst applicable layer wins)."""
    out = {}
    if not matrix:
        return out
    for j, n in enumerate(matrix["nodes"]):
        cells = [row["cells"][j]["now"] for row in matrix["rows"] if row["cells"][j]["now"]]
        worst = max((c["worst"] for c in cells), key=lambda w: RANK.get(w, 0), default=None)
        out[n.name] = {"PASS": "pass", "FAIL": "fail"}.get(worst, "unknown") if worst else "na"
    return out


STATE_FILL = {"pass": "#2a7343", "fail": "#b8262c", "unknown": "#9a6411", "na": "none"}
STATE_WORD = {
    "pass": "все уровни в норме",
    "fail": "есть нарушения",
    "unknown": "нет данных",
    "na": "проверки не применяются",
}


def segment_svg(project, nodes, states: dict | None = None) -> str:
    """The segment as the engineer draws it: one band per subnet, one column per host (the controller first),
    a square where the host has an address in that subnet. The square on each host card is its audit state."""
    states = states or {}
    cols = [("NIXFORT", "контроллер", [project.controller_ip], None)]
    for n in nodes:
        role = (
            "шлюз"
            if n.has_role("gateway")
            else "сервер"
            if n.has_role("server")
            else "клиент"
            if n.has_role("test_client")
            else ""
        )
        cols.append((n.name, role, [n.mgmt_ip, *(n.data_ips or [])], states.get(n.name, "na")))
    lanes = list(project.cidrs or [])
    if not lanes:
        return ""
    width, left, card_h, top, lane_h, band = 520, 132, 40, 64, 56, 30
    col_w = (width - left) / max(len(cols), 1)
    height = top + lane_h * len(lanes) - (lane_h - band) // 2 + 2
    out = [f'<svg class="chart scheme" viewBox="0 0 {width} {height}" role="img" '
           f'aria-label="Схема сегмента: подсети и узлы" xmlns="http://www.w3.org/2000/svg" font-family="Plex, sans-serif">']  # fmt: skip
    for i, cidr in enumerate(lanes):
        y = top + lane_h * i
        out.append(f'<rect x="0" y="{y}" width="{width}" height="{band}" fill="#eef1f4"/>')
        out.append(
            f'<text x="8" y="{y + 13}" font-size="12" fill="#121518">{escape(_net_name(project, cidr, nodes))}</text>'
        )
        out.append(f'<text x="8" y="{y + 25}" font-size="11" fill="#535a61" font-family="Plex Mono, monospace">'
                   f'{escape(cidr)}</text>')  # fmt: skip
    for j, (name, role, ips, state) in enumerate(cols):
        cx = left + col_w * j + col_w / 2
        cw = min(col_w - 8, 92)
        hits = []
        for i, cidr in enumerate(lanes):
            net = ipaddress.ip_network(cidr, strict=False)
            ip = next((a for a in ips if a and ipaddress.ip_address(a) in net), None)
            if ip:
                hits.append((top + lane_h * i + band / 2, ip))
        if hits:
            out.append(f'<line x1="{cx}" y1="{card_h}" x2="{cx}" y2="{hits[-1][0]}" stroke="#121518" '
                       f'stroke-width="{2 if role == "шлюз" else 1.2}"/>')  # fmt: skip
        out.append(
            f'<rect x="{cx - cw / 2}" y="0.5" width="{cw}" height="{card_h - 1}" fill="#fbfcfc" stroke="#121518"/>'
        )
        short = name[3:] if name.startswith("nx-") else name
        out.append(f'<text x="{cx}" y="17" font-size="12" text-anchor="middle" fill="#121518" '
                   f'font-family="Plex Mono, monospace">{escape(short)}</text>')  # fmt: skip
        out.append(f'<text x="{cx}" y="31" font-size="11" text-anchor="middle" fill="#535a61">{escape(role)}</text>')
        if state:
            fill = STATE_FILL[state]
            stroke = ' stroke="#8d949b"' if fill == "none" else ""
            out.append(f'<rect x="{cx - cw / 2 + 5}" y="6" width="7" height="7" fill="{fill}"{stroke}>'
                       f'<title>{escape(name)}: {STATE_WORD[state]}</title></rect>')  # fmt: skip
        for y, ip in hits:
            out.append(f'<rect x="{cx - 4}" y="{y - 4}" width="8" height="8" fill="#121518"/>')
            out.append(f'<text x="{cx + 8}" y="{y + 4}" font-size="11" fill="#121518" '
                       f'font-family="Plex Mono, monospace">.{escape(ip.rsplit(".", 1)[-1])}</text>')  # fmt: skip
    out.append("</svg>")
    return "".join(out)
