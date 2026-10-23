"""Fail2ban: read status of the sshd jail via fail2ban-client (effective values)."""

from __future__ import annotations

import os
from typing import Any

from .. import parsers
from ..context import Context
from ..registry import action
from ..schema import EMPTY
from .system import unit_state


def jail_param(ctx: Context, jail: str, name: str) -> int | None:
    res = ctx.tool("fail2ban_client", "get", jail, name, timeout=10)
    return parsers.parse_int_value(res.stdout) if res.returncode == 0 else None


@action("fail2ban.read_status.v1", EMPTY)
def read_status(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    service = unit_state(ctx, "fail2ban")
    installed = os.access(ctx.profile.bin("fail2ban_client"), os.X_OK)
    result: dict[str, Any] = {"installed": installed, "service": service, "jails": [], "sshd": None}
    if not installed or service != "active":
        return result
    status = ctx.tool("fail2ban_client", "status", timeout=10)
    jails = parsers.parse_f2b_jail_list(status.stdout) if status.returncode == 0 else []
    result["jails"] = jails
    if "sshd" in jails:
        st = ctx.tool("fail2ban_client", "status", "sshd", timeout=10)
        detail = parsers.parse_f2b_jail_status(st.stdout) if st.returncode == 0 else {}
        result["sshd"] = {
            "enabled": True,
            "maxretry": jail_param(ctx, "sshd", "maxretry"),
            "bantime": jail_param(ctx, "sshd", "bantime"),
            "findtime": jail_param(ctx, "sshd", "findtime"),
            **detail,
        }
    else:
        result["sshd"] = {"enabled": False}
    return result


# ------------------------------------------------------------------ sshd jail profile (mutating)
from .. import mutation  # noqa: E402
from ..errors import AgentError, Rejected  # noqa: E402
from ..fsutil import atomic_write  # noqa: E402
from ..schema import Int, IPv4OrCIDR, ListOf, Obj, Str  # noqa: E402


def render_jail(p: dict[str, Any]) -> str:
    ignore = " ".join(["127.0.0.1/8", "::1", *p["ignore_ips"]])
    return (
        "# Managed by NIXFORT. Manual changes will be overwritten.\n"
        "[sshd]\n"
        "enabled = true\n"
        "backend = systemd\n"
        "port = ssh\n"
        f"maxretry = {int(p['maxretry'])}\n"
        f"findtime = {int(p['findtime_s'])}\n"
        f"bantime = {int(p['bantime_s'])}\n"
        f"ignoreip = {ignore}\n"
    )


def f2b_validate(ctx: Context) -> tuple[bool, str]:
    res = ctx.tool("fail2ban_client", "-t", timeout=30)
    return res.returncode == 0, (res.stderr or res.stdout)[-300:]


def f2b_activate(ctx: Context) -> None:
    ctx.tool("systemctl", "enable", ctx.profile.units["fail2ban"], timeout=30)
    res = ctx.tool("systemctl", "restart", ctx.profile.units["fail2ban"], timeout=60)
    if res.returncode != 0:
        raise AgentError("tool_failed", "fail2ban restart failed")
    # wait until the server answers (restart is asynchronous)
    import time

    for _ in range(20):
        if ctx.tool("fail2ban_client", "ping", timeout=5).returncode == 0:
            return
        time.sleep(0.5)
    raise AgentError("tool_failed", "fail2ban did not come up")


def _reapply_f2b(ctx: Context, snap) -> dict[str, Any]:
    ok, _ = f2b_validate(ctx)
    if not ok:
        return {"service_reloaded": False, "restored_config_valid": False}
    f2b_activate(ctx)
    return {"service_reloaded": True, "restored_config_valid": True}


mutation.REAPPLY["fail2ban"] = _reapply_f2b


@action(
    "fail2ban.apply_sshd_profile.v1",
    Obj(
        {
            "maxretry": Int(3, 5),
            "bantime_s": Int(600, 86400),
            "findtime_s": Int(60, 3600),
            "ignore_ips": ListOf(IPv4OrCIDR(), max_len=10, unique=True),
            "rollback_timeout_s": Int(30, 300),
        }
    ),
    mutating=True,
)
def apply_sshd_profile(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    if not os.access(ctx.profile.bin("fail2ban_client"), os.X_OK):
        raise Rejected("tool_missing", "fail2ban is not installed")
    path = ctx.profile.paths["f2b_owned"]
    result = mutation.guarded_apply(
        ctx,
        kind="fail2ban",
        files=[path],
        write_candidate=lambda: atomic_write(path, render_jail(params).encode(), 0o644),
        validate=lambda: f2b_validate(ctx),
        activate=lambda: f2b_activate(ctx),
        rollback_timeout_s=params["rollback_timeout_s"],
    )
    return result


@action("fail2ban.unban.v1", Obj({"ip": Str(max_len=15, pattern=r"\d{1,3}(\.\d{1,3}){3}")}), mutating=True)
def unban(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    from ..schema import IPv4

    ip = IPv4().validate(params["ip"], "params.ip")
    res = ctx.tool("fail2ban_client", "set", "sshd", "unbanip", ip, timeout=15)
    return {"unbanned": res.returncode == 0}
