"""Suricata IDS: status, configuration test and recent EVE events (read-only)."""

from __future__ import annotations

import os
from typing import Any

from .. import parsers
from ..context import Context
from ..errors import ToolError
from ..registry import action
from ..schema import EMPTY, Int, ListOf, Nullable, Obj, Str
from .system import unit_state

TEST_SID = 9000001
MAX_EVE_TAIL = 4 * 1024 * 1024


def dump_config(ctx: Context) -> dict[str, Any]:
    res = ctx.tool("suricata", "--dump-config", "-c", ctx.profile.paths["suricata_yaml"], timeout=30)
    if res.returncode != 0:
        raise ToolError("tool_failed", "suricata --dump-config")
    return parsers.parse_suricata_dump(res.stdout)


def config_test(ctx: Context) -> dict[str, Any]:
    res = ctx.tool("suricata", "-T", "-c", ctx.profile.paths["suricata_yaml"], timeout=120)
    return {"ok": res.returncode == 0, "stderr_tail": (res.stderr or res.stdout).strip()[-500:]}


@action("suricata.read_status.v1", EMPTY)
def read_status(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    installed = os.access(ctx.profile.bin("suricata"), os.X_OK)
    out: dict[str, Any] = {"installed": installed, "service": unit_state(ctx, "suricata")}
    if not installed:
        return out
    ver = ctx.tool("suricata", "-V", timeout=10)
    cfg = dump_config(ctx)
    eve_path = cfg["eve_path"]
    readable = bool(eve_path) and os.path.isfile(eve_path) and os.access(eve_path, os.R_OK)
    out.update(
        {
            "version": parsers.parse_suricata_version(ver.stdout + ver.stderr),
            "config_test": config_test(ctx),
            "eve": {
                "enabled": cfg["eve_enabled"],
                "path": eve_path,
                "readable": readable,
                "size": os.path.getsize(eve_path) if readable else None,
            },
            "af_packet_interfaces": cfg["af_packet_interfaces"],
            "nixfort_test_rule_loaded": any(r.endswith("nixfort-test.rules") for r in cfg["rule_files"]),
        }
    )
    return out


def _tail_lines(path: str, max_bytes: int) -> list[str]:
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(max(0, size - max_bytes))
        data = fh.read()
    lines = data.decode("utf-8", errors="replace").splitlines()
    return lines[1:] if size > max_bytes else lines  # first line may be cut


@action(
    "suricata.read_events.v1",
    Obj(
        {
            "since_ts": Nullable(Str(max_len=40, pattern=r"\d{4}-\d{2}-\d{2}T[0-9:.+\-]{8,30}")),
            "limit": Int(1, 500),
            "types": ListOf(Str(choices=frozenset({"alert", "anomaly"})), max_len=2, min_len=1, unique=True),
        }
    ),
)
def read_events(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    cfg = dump_config(ctx)
    path = cfg["eve_path"]
    if not cfg["eve_enabled"] or not path:
        return {"eve_available": False, "reason": "eve_disabled", "events": []}
    if not os.path.isfile(path) or not os.access(path, os.R_OK):
        return {"eve_available": False, "reason": "eve_unreadable", "events": []}
    events = parsers.parse_eve_lines(
        _tail_lines(path, MAX_EVE_TAIL), params["since_ts"], set(params["types"]), params["limit"]
    )
    return {"eve_available": True, "reason": None, "events": events}


# ------------------------------------------------------------------ sensor profile (mutating)
import time  # noqa: E402

from .. import mutation  # noqa: E402
from ..errors import AgentError, Rejected  # noqa: E402
from ..fsutil import atomic_write  # noqa: E402
from ..schema import Bool  # noqa: E402

# Detection rules shipped by NIXFORT (sid range 9000001-9000099). Fixed text: no parameter reaches it.
SCAN_SID = 9000002
BRUTE_SID = 9000003
TEST_RULES = (
    "# Managed by NIXFORT. Demonstration detection rules for the protection tests.\n"
    'alert tcp any any -> any any (msg:"NIXFORT-IDS-TEST marker"; flow:established,to_server; '
    f'content:"NIXFORT-IDS-TEST-7f3a"; classtype:misc-activity; sid:{TEST_SID}; rev:1;)\n'
    'alert tcp any any -> $HOME_NET any (msg:"NIXFORT port scan: many SYN from one source"; flags:S,12; '
    f"threshold: type both, track by_src, count 20, seconds 10; classtype:attempted-recon; sid:{SCAN_SID}; rev:1;)\n"
    'alert tcp any any -> $HOME_NET 22 (msg:"NIXFORT SSH brute force: many connections to port 22"; '
    "flow:to_server; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; "
    f"classtype:attempted-admin; sid:{BRUTE_SID}; rev:1;)\n"
)


def render_sensor(ctx: Context, p: dict[str, Any]) -> str:
    """Suricata include file. Sequences in an included file REPLACE the original ones (verified on 7.0.3):
    af-packet is fully defined here; existing distribution rules (suricata-update) are kept."""
    rules = []
    if p["test_rules"]:
        rules.append(ctx.profile.paths["suricata_test_rules"])
    if os.path.isfile(ctx.profile.paths["suricata_dist_rules"]):
        rules.append("suricata.rules")
    lines = [
        "%YAML 1.1",
        "---",
        "# Managed by NIXFORT. Manual changes will be overwritten. Rollback: NIXFORT snapshots.",
        "af-packet:",
        f"  - interface: {p['interface']}",
        "    threads: 1",
        "    cluster-id: 99",
        "    cluster-type: cluster_flow",
        "    defrag: yes",
        "    checksum-checks: auto",
        "rule-files:" if rules else "rule-files: []",
        *[f"  - {r}" for r in rules],
        "",
    ]
    return "\n".join(lines)


def _yaml_with_include(ctx: Context) -> str | None:
    path = ctx.profile.paths["suricata_yaml"]
    owned = ctx.profile.paths["suricata_owned"]
    text = ctx.read_file(path)
    for line in text.splitlines():
        if line.startswith("include:") and owned in line:
            return None
    return text.rstrip("\n") + f"\n\n# NIXFORT sensor profile\ninclude: {owned}\n"


def _active_state(ctx: Context) -> str:
    res = ctx.tool("systemctl", "show", "-p", "ActiveState", ctx.profile.units["suricata"], timeout=10)
    return parsers.parse_key_values(res.stdout).get("ActiveState", "")


def _enabled(ctx: Context) -> bool:
    return ctx.tool("systemctl", "is-enabled", ctx.profile.units["suricata"], timeout=10).stdout.strip() == "enabled"


def _restart(ctx: Context) -> None:
    unit = ctx.profile.units["suricata"]
    # S-006: right after `apt-get install` the packaged service crash-loops on its default interface (eth0) and
    # systemd blocks further starts ("Start request repeated too quickly"). Clear that state first.
    ctx.tool("systemctl", "reset-failed", unit, timeout=15)
    res = ctx.tool("systemctl", "restart", unit, timeout=120)
    if res.returncode != 0:
        raise AgentError("tool_failed", "suricata restart failed")
    for _ in range(30):  # forking service: wait until it is really up, and still up a moment later
        if _active_state(ctx) == "active":
            time.sleep(1)
            if _active_state(ctx) == "active":
                return
        time.sleep(1)
    raise AgentError("tool_failed", "suricata did not stay active")


def _validate(ctx: Context) -> tuple[bool, str]:
    t = config_test(ctx)
    return t["ok"], t["stderr_tail"]


def _reapply_suricata(ctx: Context, snap) -> dict[str, Any]:
    extra = snap.meta.get("extra") or {}
    unit = ctx.profile.units["suricata"]
    ok, _ = _validate(ctx)
    if not ok:
        return {"service_reloaded": False, "restored_config_valid": False}
    if extra.get("service_was_active"):
        _restart(ctx)
    else:
        ctx.tool("systemctl", "stop", unit, timeout=60)
    if not extra.get("service_was_enabled", True):
        ctx.tool("systemctl", "disable", unit, timeout=30)
    return {"service_reloaded": True, "restored_config_valid": True}


mutation.REAPPLY["suricata"] = _reapply_suricata


@action(
    "suricata.apply_sensor_profile.v1",
    Obj(
        {
            "interface": Str(max_len=15, pattern=r"[a-z][a-z0-9]{0,14}"),
            "test_rules": Bool(),
            "rollback_timeout_s": Int(30, 300),
        }
    ),
    mutating=True,
)
def apply_sensor_profile(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    if not os.access(ctx.profile.bin("suricata"), os.X_OK):
        raise Rejected("tool_missing", "suricata is not installed")
    if not os.path.isdir(os.path.join(ctx.profile.paths["sys_class_net"], params["interface"])):
        raise Rejected("invalid_params", "interface does not exist on this node")
    owned = ctx.profile.paths["suricata_owned"]
    rules = ctx.profile.paths["suricata_test_rules"]
    conf = ctx.profile.paths["suricata_yaml"]
    try:
        new_conf = _yaml_with_include(ctx)
    except OSError:
        raise Rejected("tool_missing", "suricata.yaml not found") from None
    was_active = _active_state(ctx) == "active"
    was_enabled = _enabled(ctx)

    def write_candidate() -> None:
        atomic_write(owned, render_sensor(ctx, params).encode(), 0o644)
        if params["test_rules"]:
            atomic_write(rules, TEST_RULES.encode(), 0o644)
        if new_conf is not None:
            atomic_write(conf, new_conf.encode(), 0o644)

    def activate() -> None:
        if not was_enabled:
            ctx.tool("systemctl", "enable", ctx.profile.units["suricata"], timeout=30)
        _restart(ctx)

    return mutation.guarded_apply(
        ctx,
        kind="suricata",
        files=[owned, rules, conf],
        write_candidate=write_candidate,
        validate=lambda: _validate(ctx),
        activate=activate,
        rollback_timeout_s=params["rollback_timeout_s"],
        extra={"service_was_active": was_active, "service_was_enabled": was_enabled},
    )
