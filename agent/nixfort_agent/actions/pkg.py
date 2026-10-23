"""Installation of security tools from a fixed allowlist (ADR-013). Irreversible: no snapshot."""

from __future__ import annotations

from typing import Any

from ..context import Context
from ..errors import AgentError
from ..parsers import parse_dpkg
from ..registry import action
from ..schema import Obj, Str

# package -> exact apt packages (python3-systemd: Fail2ban's systemd journal backend)
PACKAGES: dict[str, tuple[str, ...]] = {
    "fail2ban": ("fail2ban", "python3-systemd"),
    "suricata": ("suricata",),
    "nftables": ("nftables",),
}
APT_ENV = {"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a"}


@action("pkg.install_security_tool.v1", Obj({"package": Str(choices=frozenset(PACKAGES))}), mutating=True)
def install(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    pkgs = PACKAGES[params["package"]]
    upd = ctx.tool("apt_get", "update", "-q", timeout=240, extra_env=APT_ENV)
    if upd.returncode != 0:
        raise AgentError("tool_failed", "apt-get update failed (no repository access?)")
    res = ctx.tool(
        "apt_get",
        "install",
        "-y",
        "-q",
        "--no-install-recommends",
        "-o",
        "Dpkg::Options::=--force-confdef",
        "-o",
        "Dpkg::Options::=--force-confold",
        *pkgs,
        timeout=480,
        extra_env=APT_ENV,
    )
    if res.returncode != 0:
        raise AgentError("tool_failed", "apt-get install failed")
    q = ctx.tool("dpkg_query", "-W", "-f", "${Package}\t${db:Status-Status}\t${Version}\n", *pkgs, timeout=15)
    versions = parse_dpkg(q.stdout, pkgs)
    if not all(versions.values()):
        raise AgentError("tool_failed", "package not installed after apt-get")
    return {"installed": True, "package": params["package"], "versions": versions}
