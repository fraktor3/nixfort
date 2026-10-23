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
