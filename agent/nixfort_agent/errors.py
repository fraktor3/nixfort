"""Agent error types. Each maps to a response state and a safe error_code."""

from __future__ import annotations


class AgentError(Exception):
    """Base class. `state` is the response state, `code` the safe error_code."""

    state = "ERROR"
    code = "internal_error"

    def __init__(self, code: str | None = None, detail: str = "") -> None:
        if code is not None:
            self.code = code
        self.detail = detail  # goes to the local agent log only, never to stdout
        super().__init__(self.code)


class Rejected(AgentError):
    """Request is invalid or not allowed on this node. Nothing was executed."""

    state = "REJECTED"
    code = "invalid_request"


class Failed(AgentError):
    """Action ran correctly but its goal was not reached (e.g. candidate config invalid)."""

    state = "FAILED"
    code = "validation_failed"


class ToolError(AgentError):
    """External tool problem: missing, timed out, unexpected output."""

    state = "ERROR"
    code = "tool_failed"


ERROR_CODES = frozenset(
    {
        "invalid_request",
        "unknown_action",
        "invalid_params",
        "unsupported_os",
        "tool_missing",
        "tool_timeout",
        "tool_failed",
        "validation_failed",
        "conflict_firewall_manager",
        "snapshot_not_found",
        "timer_failed",
        "rollback_failed",
        "output_too_large",
        "internal_error",
    }
)
