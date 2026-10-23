"""Rollback fired by the node-side timer (no controller involved)."""

from __future__ import annotations

import logging

from .__main__ import _real_context, _setup_logging
from .errors import AgentError
from .mutation import perform_rollback
from .registry import load_all
from .snapshots import validate_id

log = logging.getLogger("nixfort-agent")


def main(argv: list[str]) -> int:
    _setup_logging("/var/log/nixfort-agent.log")
    if len(argv) != 1:
        return 64
    try:
        snap_id = validate_id(argv[0])
    except AgentError:
        return 64
    load_all()  # registers REAPPLY handlers of every kind
    ctx = _real_context(300)
    result = perform_rollback(ctx, snap_id)
    log.warning("timer rollback snapshot=%s result=%s", snap_id, result)
    return 0 if result.get("rolled_back") else 1
