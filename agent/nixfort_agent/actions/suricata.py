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
