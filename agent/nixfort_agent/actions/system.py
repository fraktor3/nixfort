"""Read-only system facts."""

from __future__ import annotations

import os
import socket
from typing import Any

from .. import AGENT_VERSION, parsers
from ..context import Context
from ..errors import ToolError
from ..registry import action
from ..schema import EMPTY, Int, Obj

PACKAGES = ("nftables", "fail2ban", "suricata", "openssh-server")
SERVICES = ("ssh", "nftables", "fail2ban", "suricata", "ufw", "firewalld")


@action("system.ping.v1", EMPTY)
def ping(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    return {"agent_version": AGENT_VERSION, "os_profile": ctx.profile.name, "hostname": socket.gethostname()}


def unit_state(ctx: Context, unit_key: str) -> str:
    res = ctx.tool("systemctl", "show", "-p", "LoadState", "-p", "ActiveState", ctx.profile.units[unit_key], timeout=10)
    return parsers.unit_state(res.stdout)


def ufw_active(ctx: Context) -> bool:
    """ufw.service may be 'active' while the firewall is disabled; ask ufw itself."""
    if not os.access(ctx.profile.bin("ufw"), os.X_OK):
        return False
    res = ctx.tool("ufw", "status", timeout=10)
    return res.stdout.strip().lower().startswith("status: active")


def packages(ctx: Context) -> dict[str, str | None]:
    res = ctx.tool("dpkg_query", "-W", "-f", "${Package}\t${db:Status-Status}\t${Version}\n", *PACKAGES, timeout=15)
    return parsers.parse_dpkg(res.stdout, PACKAGES)


def time_sync(ctx: Context) -> dict[str, Any]:
    res = ctx.tool("timedatectl", "show", timeout=10)
    kv = parsers.parse_key_values(res.stdout)
    synced = kv.get("NTPSynchronized")
    service = None
    for key in ("timesyncd", "chrony"):
        if unit_state(ctx, key) == "active":
            service = ctx.profile.units[key]
            break
    return {"service": service, "synchronized": None if synced is None else synced == "yes"}


@action("system.collect_facts.v1", EMPTY)
def collect_facts(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    u = os.uname()
    addr = ctx.tool("ip", "-j", "addr", "show", timeout=10)
    route = ctx.tool("ip", "-j", "-4", "route", "show", timeout=10)
    if addr.returncode != 0 or route.returncode != 0:
        raise ToolError("tool_failed", "ip")
    interfaces, ipv6 = parsers.parse_ip_addr(addr.stdout)
    try:
        ip_forward = ctx.read_file(ctx.profile.paths["ip_forward"]).strip() == "1"
    except OSError:
        ip_forward = None
    services = {name: unit_state(ctx, name) for name in SERVICES}
    services["ufw"] = "active" if ufw_active(ctx) else ("inactive" if services["ufw"] != "absent" else "absent")
    return {
        "os": {
            "id": ctx.os_release.get("ID"),
            "version": ctx.os_release.get("VERSION_ID"),
            "pretty_name": ctx.os_release.get("PRETTY_NAME"),
            "arch": u.machine,
            "kernel": u.release,
        },
        "os_profile": ctx.profile.name,
        "os_supported": ctx.profile.supported,
        "hostname": socket.gethostname(),
        "interfaces": interfaces,
        "routes": parsers.parse_ip_route(route.stdout),
        "time_sync": time_sync(ctx),
        "journald_active": unit_state(ctx, "journald") == "active",
        "ip_forward": ip_forward,
        "ipv6_present": ipv6,
        "packages": packages(ctx),
        "services": services,
    }


@action("system.collect_listeners.v1", EMPTY)
def collect_listeners(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    res = ctx.tool("ss", "-H", "-ltnp", timeout=10)
    if res.returncode != 0:
        raise ToolError("tool_failed", "ss")
    return {"listeners": parsers.parse_ss_listeners(res.stdout)}


@action("system.read_auth_failures.v1", Obj({"hours": Int(1, 168)}))
def read_auth_failures(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    """Recent SSH authentication failures from journald (sshd): counts per source IP and per attempted user.
    Read-only; only aggregated counts and the attempted usernames are returned, never passwords or full lines."""
    if not os.access(ctx.profile.bin("journalctl"), os.X_OK):
        from ..errors import ToolError

        raise ToolError("tool_missing", "journalctl")
    res = ctx.tool("journalctl", "_COMM=sshd", "--since", f"-{int(params['hours'])}h",
                   "--no-pager", "-q", "-o", "cat", timeout=30)  # fmt: skip
    data = parsers.parse_auth_failures(res.stdout)
    data["window_hours"] = int(params["hours"])
    return data
