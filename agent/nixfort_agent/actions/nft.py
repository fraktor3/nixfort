"""nftables: inspect ruleset ownership and conflicts (read-only)."""

from __future__ import annotations

import hashlib
import os
import re
from typing import Any

from .. import parsers
from ..context import Context
from ..errors import ToolError
from ..registry import action
from ..schema import EMPTY
from .system import ufw_active, unit_state

OWN_TABLE = "nixfort"


def own_table_text(ctx: Context) -> str | None:
    res = ctx.tool("nft", "list", "table", "inet", OWN_TABLE, timeout=10)
    return res.stdout if res.returncode == 0 else None


@action("nft.inspect.v1", EMPTY)
def inspect(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    if not os.access(ctx.profile.bin("nft"), os.X_OK):
        raise ToolError("tool_missing", "nft")
    ver = ctx.tool("nft", "--version", timeout=5)
    m = re.search(r"v(\d+\.\d+\.\d+)", ver.stdout)
    res = ctx.tool("nft", "-j", "list", "ruleset", timeout=15)
    if res.returncode != 0:
        raise ToolError("tool_failed", "nft list ruleset")
    parsed = parsers.parse_nft_ruleset(res.stdout, OWN_TABLE)
    text = own_table_text(ctx) if parsed["nixfort_table_present"] else None
    parsed["conflict"]["ufw"] = ufw_active(ctx)
    parsed["conflict"]["firewalld"] = unit_state(ctx, "firewalld") == "active"
    parsed["nft_version"] = m.group(1) if m else None
    parsed["nixfort_ruleset_sha256"] = hashlib.sha256(text.encode()).hexdigest() if text else None
    return parsed


# ------------------------------------------------------------------ policy (mutating)
import json  # noqa: E402

from .. import mutation  # noqa: E402
from ..errors import AgentError, Rejected  # noqa: E402
from ..fsutil import atomic_write  # noqa: E402
from ..schema import Int, IPv4, IPv4OrCIDR, ListOf, Obj  # noqa: E402

INCLUDE_LINE = 'include "/etc/nftables.d/*.nft"'
HEADER = "# Managed by NIXFORT. Manual changes will be overwritten. Rollback: NIXFORT snapshots.\n"


def rules_sha256(p: dict[str, Any]) -> str:
    """Canonical hash of the rule set; the controller computes the same value to verify FW-02."""
    canon = {k: p[k] for k in ("policy_version", "management_sources", "forward_allow", "input_allow")}
    return hashlib.sha256(json.dumps(canon, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def render_policy(p: dict[str, Any]) -> str:
    """Only validated, typed values (addresses, networks, integers) reach the file. Lines 1-2 make the
    replacement atomic and idempotent; DENY flows are not written - `policy drop` enforces them."""
    mgmt = ", ".join(p["management_sources"])
    lines = [
        HEADER.rstrip("\n"),
        f"table inet {OWN_TABLE} {{}}",
        f"delete table inet {OWN_TABLE}",
        f"table inet {OWN_TABLE} {{",
        f'\tcomment "nixfort policy_version={int(p["policy_version"])} rules_sha256={rules_sha256(p)}"',
        "\tchain input {",
        "\t\ttype filter hook input priority filter; policy drop;",
        '\t\tiif "lo" accept',
        "\t\tct state established,related accept",
        "\t\tct state invalid drop",
        "\t\tmeta l4proto { icmp, ipv6-icmp } accept",
        f"\t\tip saddr {{ {mgmt} }} tcp dport 22 accept",
    ]
    for r in p["input_allow"]:
        lines.append(f"\t\tip saddr {r['src']} tcp dport {int(r['port'])} accept")
    lines += [
        "\t}",
        "\tchain forward {",
        "\t\ttype filter hook forward priority filter; policy drop;",
        "\t\tct state established,related accept",
        "\t\tct state invalid drop",
        "\t\tmeta l4proto { icmp, ipv6-icmp } accept",
    ]
    for r in p["forward_allow"]:
        lines.append(f"\t\tip saddr {r['src']} ip daddr {r['dst']} tcp dport {int(r['port'])} accept")
    lines += ["\t}", "}", ""]
    return "\n".join(lines)


def _conf_with_include(ctx: Context) -> str | None:
    """nftables.conf with our include appended, or None when it is already there."""
    path = ctx.profile.paths["nft_conf"]
    try:
        text = ctx.read_file(path)
    except OSError:
        text = "#!/usr/sbin/nft -f\n\nflush ruleset\n"
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("include") and "/etc/nftables.d/" in s:
            return None
    return text.rstrip("\n") + "\n\n# NIXFORT policy (managed table inet nixfort)\n" + INCLUDE_LINE + "\n"


def _service_enabled(ctx: Context) -> bool:
    res = ctx.tool("systemctl", "is-enabled", ctx.profile.units["nftables"], timeout=10)
    return res.stdout.strip() == "enabled"


def _check(ctx: Context, path: str) -> tuple[bool, str]:
    res = ctx.tool("nft", "-c", "-f", path, timeout=20)
    return res.returncode == 0, (res.stderr or res.stdout).strip()[-300:]


def _validate(ctx: Context) -> tuple[bool, str]:
    ok, detail = _check(ctx, ctx.profile.paths["nft_owned"])
    if not ok:
        return ok, detail
    # what nftables.service loads at boot must stay valid too
    conf = ctx.profile.paths["nft_conf"]
    return _check(ctx, conf) if os.path.exists(conf) else (True, "")


def _load_owned(ctx: Context) -> None:
    res = ctx.tool("nft", "-f", ctx.profile.paths["nft_owned"], timeout=20)
    if res.returncode != 0:
        raise AgentError("tool_failed", "nft -f failed")


def _reapply_nft(ctx: Context, snap) -> dict[str, Any]:
    """After restore_files: the previous file is the source of truth for our table."""
    owned = ctx.profile.paths["nft_owned"]
    if os.path.exists(owned):
        ok, _ = _check(ctx, owned)
        if not ok:
            return {"service_reloaded": False, "restored_config_valid": False}
        _load_owned(ctx)
    elif own_table_text(ctx) is not None:
        res = ctx.tool("nft", "delete", "table", "inet", OWN_TABLE, timeout=20)
        if res.returncode != 0:
            raise AgentError("tool_failed", "nft delete table failed")
    if not (snap.meta.get("extra") or {}).get("service_was_enabled", True):
        # disable only; never `stop` - nftables.service ExecStop flushes the whole ruleset
        ctx.tool("systemctl", "disable", ctx.profile.units["nftables"], timeout=30)
    return {"service_reloaded": True, "restored_config_valid": True}


mutation.REAPPLY["nft"] = _reapply_nft


def _preconditions(ctx: Context) -> None:
    if not os.access(ctx.profile.bin("nft"), os.X_OK):
        raise Rejected("tool_missing", "nftables is not installed")
    try:
        forward = ctx.read_file(ctx.profile.paths["ip_forward"]).strip()
    except OSError:
        forward = ""
    if forward != "1":
        raise Rejected("conflict", "net.ipv4.ip_forward is not 1 - node is not a gateway")
    if ufw_active(ctx):
        raise Rejected("conflict", "ufw is active")
    if unit_state(ctx, "firewalld") == "active":
        raise Rejected("conflict", "firewalld is active")
    res = ctx.tool("nft", "-j", "list", "ruleset", timeout=15)
    if res.returncode != 0:
        raise AgentError("tool_failed", "nft list ruleset")
    conflict = parsers.parse_nft_ruleset(res.stdout, OWN_TABLE)["conflict"]
    if conflict["docker"] or conflict["foreign_base_chains"]:
        raise Rejected("conflict", "foreign rules: " + ", ".join(conflict["foreign_base_chains"] or ["docker"]))


@action(
    "nft.apply_policy.v1",
    Obj(
        {
            "policy_version": Int(1, 1_000_000),
            "management_sources": ListOf(IPv4(), max_len=4, min_len=1, unique=True),
            "forward_allow": ListOf(
                Obj({"src": IPv4OrCIDR(), "dst": IPv4(), "port": Int(1, 65535)}), max_len=200, unique=True
            ),
            "input_allow": ListOf(Obj({"src": IPv4OrCIDR(), "port": Int(1, 65535)}), max_len=20, unique=True),
            "rollback_timeout_s": Int(30, 300),
        }
    ),
    mutating=True,
)
def apply_policy(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    _preconditions(ctx)
    owned = ctx.profile.paths["nft_owned"]
    conf = ctx.profile.paths["nft_conf"]
    new_conf = _conf_with_include(ctx)
    was_enabled = _service_enabled(ctx)

    def write_candidate() -> None:
        atomic_write(owned, render_policy(params).encode(), 0o600)
        if new_conf is not None:
            atomic_write(conf, new_conf.encode(), 0o755)

    def activate() -> None:
        _load_owned(ctx)
        if not was_enabled:  # persistence across reboot; reverted on rollback
            res = ctx.tool("systemctl", "enable", ctx.profile.units["nftables"], timeout=30)
            if res.returncode != 0:
                raise AgentError("tool_failed", "systemctl enable nftables failed")

    result = mutation.guarded_apply(
        ctx,
        kind="nft",
        files=[owned, conf],
        write_candidate=write_candidate,
        validate=lambda: _validate(ctx),
        activate=activate,
        rollback_timeout_s=params["rollback_timeout_s"],
        extra={"service_was_enabled": was_enabled},
    )
    text = own_table_text(ctx)
    result["rules_sha256"] = rules_sha256(params)
    result["ruleset_sha256"] = hashlib.sha256(text.encode()).hexdigest() if text else None
    return result
