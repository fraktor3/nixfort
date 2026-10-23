"""Node-side automatic rollback (ADR-007): armed BEFORE a change, cancelled only by the controller
after a successful post-check. If the controller loses the node, the node restores itself."""

from __future__ import annotations

from .context import Context
from .errors import AgentError
from .parsers import parse_key_values


def unit_name(snap_id: str) -> str:
    return f"nixfort-rb-{snap_id}"


def arm(ctx: Context, snap_id: str, timeout_s: int) -> None:
    res = ctx.tool(
        "systemd_run",
        f"--unit={unit_name(snap_id)}",
        f"--on-active={int(timeout_s)}s",
        "--timer-property=AccuracySec=1s",
        "--description=NIXFORT automatic rollback",
        ctx.profile.paths["rollback_launcher"],
        snap_id,
        timeout=15,
    )
    if res.returncode != 0:
        raise AgentError("timer_failed", res.stderr[-200:])
    if not is_active(ctx, snap_id):
        raise AgentError("timer_failed", "timer not active after arm")


def is_active(ctx: Context, snap_id: str) -> bool:
    res = ctx.tool("systemctl", "show", f"{unit_name(snap_id)}.timer", "-p", "ActiveState", timeout=10)
    return parse_key_values(res.stdout).get("ActiveState") == "active"


def cancel(ctx: Context, snap_id: str) -> bool:
    """Stop the timer. Returns True if it was active (i.e. rollback had not fired yet)."""
    was_active = is_active(ctx, snap_id)
    ctx.tool("systemctl", "stop", f"{unit_name(snap_id)}.timer", timeout=15)
    ctx.tool("systemctl", "reset-failed", f"{unit_name(snap_id)}.timer", f"{unit_name(snap_id)}.service", timeout=15)
    if is_active(ctx, snap_id):
        raise AgentError("timer_failed", "timer still active after stop")
    return was_active
