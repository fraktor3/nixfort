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
