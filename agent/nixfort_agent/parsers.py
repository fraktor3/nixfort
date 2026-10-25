"""Pure parsers of tool outputs. No I/O here - everything is unit-tested on fixtures."""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

# --- systemctl show -p LoadState -p ActiveState ------------------------------------------


def parse_key_values(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


def unit_state(show_output: str) -> str:
    """'active' | 'inactive' | 'failed' | 'absent' from `systemctl show -p LoadState -p ActiveState`."""
    kv = parse_key_values(show_output)
    if kv.get("LoadState") in {"not-found", "masked"} or not kv:
        return "absent" if kv.get("LoadState") != "masked" else "inactive"
    state = kv.get("ActiveState", "")
    if state in {"active", "reloading", "activating"}:
        return "active"
    if state == "failed":
        return "failed"
    return "inactive"


# --- dpkg-query -W -f='${Package}\t${db:Status-Status}\t${Version}\n' -------------------------


def parse_dpkg(text: str, wanted: tuple[str, ...]) -> dict[str, str | None]:
    found: dict[str, str | None] = {name: None for name in wanted}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[0] in found and parts[1] == "installed":
            found[parts[0]] = parts[2]
    return found


# --- ip -j addr / ip -j route -------------------------------------------------------------


def parse_ip_addr(text: str) -> tuple[list[dict[str, Any]], bool]:
    """Returns (interfaces, ipv6_global_present)."""
    data = json.loads(text or "[]")
    ifaces = []
    ipv6 = False
    for item in data:
        v4 = []
        for a in item.get("addr_info", []):
            if a.get("family") == "inet":
                v4.append(f"{a.get('local')}/{a.get('prefixlen')}")
            elif a.get("family") == "inet6" and a.get("scope") == "global":
                ipv6 = True
        ifaces.append({"name": item.get("ifname"), "state": item.get("operstate"), "ipv4": v4})
    return ifaces, ipv6


def parse_ip_route(text: str) -> list[dict[str, Any]]:
    data = json.loads(text or "[]")
    return [{"dst": r.get("dst"), "gateway": r.get("gateway"), "dev": r.get("dev")} for r in data]


# --- ss -H -ltnp -------------------------------------------------------------------------

_PROC = re.compile(r'users:\(\("([^"]{1,64})"')


def _split_addr(local: str) -> tuple[str, int] | None:
    host, sep, port = local.rpartition(":")
    if not sep or not port.isdigit():
        return None
    host = host.strip("[]").split("%", 1)[0]
    if host == "*":
        host = "0.0.0.0"  # noqa: S104 - parsing ss output, not binding
    return host, int(port)


def parse_ss_listeners(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 4 or cols[0] != "LISTEN":
            continue
        addr = _split_addr(cols[3])
        if addr is None:
            continue
        m = _PROC.search(line)
        host, port = addr
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        out.append(
            {"proto": "tcp", "addr": host, "port": port, "loopback": loopback, "process": m.group(1) if m else None}
        )
    out.sort(key=lambda x: (x["port"], x["addr"]))
    return out


# --- sshd -T -----------------------------------------------------------------------------

SSHD_KEYS = (
    "permitrootlogin",
    "passwordauthentication",
    "permitemptypasswords",
    "maxauthtries",
    "logingracetime",
    "x11forwarding",
    "pubkeyauthentication",
    "kbdinteractiveauthentication",
    "port",
)


def parse_sshd_t(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, _, value = line.strip().partition(" ")
        key = key.lower()
        if key in SSHD_KEYS and key not in out:
            out[key] = value.strip()
    return out


# --- fail2ban-client ---------------------------------------------------------------------


def parse_f2b_jail_list(text: str) -> list[str]:
    for line in text.splitlines():
        if "Jail list:" in line:
            _, _, rest = line.partition("Jail list:")
            return [j.strip() for j in rest.split(",") if j.strip()]
    return []


def parse_f2b_jail_status(text: str) -> dict[str, Any]:
    banned_now = None
    banned: list[str] = []
    for line in text.splitlines():
        if "Currently banned:" in line:
            v = line.split("Currently banned:", 1)[1].strip()
            banned_now = int(v) if v.isdigit() else None
        elif "Banned IP list:" in line:
            banned = line.split("Banned IP list:", 1)[1].split()
    return {"currently_banned": banned_now, "banned_ips": banned}


def parse_int_value(text: str) -> int | None:
    v = text.strip().splitlines()[-1].strip() if text.strip() else ""
    return int(v) if re.fullmatch(r"-?\d+", v) else None


# --- nft -j list ruleset -----------------------------------------------------------------

_META = re.compile(r"policy_version=(\d+)\s+(?:plan_hash|rules_sha256)=([0-9a-f]{64})")


def parse_nft_ruleset(text: str, own_table: str = "nixfort") -> dict[str, Any]:
    data = json.loads(text or '{"nftables": []}')
    tables: list[dict[str, str]] = []
    chains: list[dict[str, Any]] = []
    own_comment = None
    own_rules: list[dict[str, Any]] = []
    for obj in data.get("nftables", []):
        if "table" in obj:
            t = obj["table"]
            tables.append({"family": t.get("family"), "name": t.get("name")})
            if t.get("family") == "inet" and t.get("name") == own_table:
                own_comment = t.get("comment")
        elif "chain" in obj:
            c = obj["chain"]
            chains.append(
                {
                    "family": c.get("family"),
                    "table": c.get("table"),
                    "name": c.get("name"),
                    "hook": c.get("hook"),
                    "policy": c.get("policy"),
                }
            )
        elif "rule" in obj:
            r = obj["rule"]
            if r.get("family") == "inet" and r.get("table") == own_table:
                own_rules.append({"chain": r.get("chain"), "expr": r.get("expr", [])})
    own_present = any(t["family"] == "inet" and t["name"] == own_table for t in tables)
    foreign_base = [
        f"{c['family']} {c['table']} {c['name']}"
        for c in chains
        if c["hook"] in {"input", "forward"}
        and c["policy"] == "drop"
        and not (c["family"] == "inet" and c["table"] == own_table)
    ]
    docker = any(c["name"] in {"DOCKER", "DOCKER-USER"} for c in chains)
    own_chains = {c["name"]: c for c in chains if c["family"] == "inet" and c["table"] == own_table}
    meta = None
    if own_comment:
        m = _META.search(own_comment)
        if m:
            meta = {"policy_version": int(m.group(1)), "rules_sha256": m.group(2)}
    return {
        "tables": tables,
        "nixfort_table_present": own_present,
        "nixfort_chains": {name: {"hook": c["hook"], "policy": c["policy"]} for name, c in sorted(own_chains.items())},
        "nixfort_input_ssh_sources": _ssh_sources(own_rules),
        "policy_meta": meta,
        "conflict": {"docker": docker, "foreign_base_chains": foreign_base},
    }


def _ssh_sources(rules: list[dict[str, Any]]) -> list[str]:
    """Source IPs that have an `accept` for tcp dport 22 in our input chain."""
    sources: list[str] = []
    for r in rules:
        if r["chain"] != "input":
            continue
        exprs = r["expr"]
        if not any("accept" in e for e in exprs):
            continue
        dport22 = False
        saddrs: list[str] = []
        for e in exprs:
            m = e.get("match") if isinstance(e, dict) else None
            if not m:
                continue
            left = m.get("left", {})
            payload = left.get("payload", {}) if isinstance(left, dict) else {}
            right = m.get("right")
            if payload.get("field") == "dport" and right == 22:
                dport22 = True
            if payload.get("protocol") == "ip" and payload.get("field") == "saddr":
                if isinstance(right, str):
                    saddrs.append(right)
                elif isinstance(right, dict) and "set" in right:
                    saddrs.extend(x for x in right["set"] if isinstance(x, str))
        if dport22:
            sources.extend(saddrs)
    return sorted(set(sources))


# --- suricata --dump-config --------------------------------------------------------------


def parse_suricata_dump(text: str) -> dict[str, Any]:
    kv: dict[str, str] = {}
    for line in text.splitlines():
        if " = " in line:
            k, _, v = line.partition(" = ")
            kv[k.strip()] = v.strip()
    eve_enabled = False
    eve_file = None
    for k, v in kv.items():
        m = re.fullmatch(r"outputs\.(\d+)\.eve-log\.enabled", k)
        if m and v.lower() in {"yes", "true", "on"}:
            eve_enabled = True
            eve_file = kv.get(f"outputs.{m.group(1)}.eve-log.filename", "eve.json")
    log_dir = kv.get("default-log-dir", "/var/log/suricata/")
    if eve_file and not eve_file.startswith("/"):
        eve_file = log_dir.rstrip("/") + "/" + eve_file
    ifaces = sorted(
        {v for k, v in kv.items() if re.fullmatch(r"af-packet\.\d+\.interface", k) and v and v != "default"}
    )
    rule_files = [v for k, v in kv.items() if re.fullmatch(r"rule-files\.\d+", k)]
    return {
        "eve_enabled": eve_enabled,
        "eve_path": eve_file,
        "af_packet_interfaces": ifaces,
        "rule_files": rule_files,
    }


def parse_suricata_version(text: str) -> str | None:
    m = re.search(r"version (\d+\.\d+\.\d+)", text)
    return m.group(1) if m else None


EVE_FIELDS = ("timestamp", "event_type", "src_ip", "src_port", "dest_ip", "dest_port", "proto")


def _ts(value: Any):
    """EVE timestamps carry the node's UTC offset (2026-10-26T01:14:06.272047+0300): compare as instants,
    never as strings. Unparsable -> None."""
    from datetime import datetime

    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else None


def parse_eve_lines(lines: list[str], since_ts: str | None, types: set[str], limit: int) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    since = _ts(since_ts) if since_ts else None
    for line in lines:
        try:
            ev = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(ev, dict) or ev.get("event_type") not in types:
            continue
        if since is not None:
            ts = _ts(ev.get("timestamp"))
            if ts is None or ts <= since:
                continue
        item = {k: ev.get(k) for k in EVE_FIELDS}
        alert = ev.get("alert")
        if isinstance(alert, dict):
            item["alert"] = {
                "signature_id": alert.get("signature_id"),
                "signature": str(alert.get("signature", ""))[:256],
                "severity": alert.get("severity"),
            }
        events.append(item)
    return events[-limit:]
