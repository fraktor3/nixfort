"""Request/response envelope of the agent protocol (docs/NODE_AGENT_PROTOCOL.md §2-3)."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from . import AGENT_VERSION, PROTOCOL
from .errors import AgentError, Rejected
from .registry import REGISTRY, Action
from .schema import Int, Str

MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
_ENVELOPE_KEYS = {"protocol", "request_id", "action", "params", "deadline_s"}
_ACTION_NAME = Str(max_len=64, pattern=r"[a-z0-9_]+\.[a-z0-9_]+\.v[0-9]+")
_DEADLINE = Int(1, 600)


@dataclass(frozen=True)
class Request:
    request_id: str
    action: Action
    params: dict[str, Any]
    deadline_s: int


def parse_request(raw: bytes, echo: dict[str, Any]) -> Request:
    """Validate the envelope and params. Fills `echo` (request_id, action) as soon as they
    are known, so that error responses can reference them."""
    if len(raw) > MAX_REQUEST_BYTES:
        raise Rejected("invalid_request", "request too large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise Rejected("invalid_request", "not json") from None
    if not isinstance(data, dict) or set(data) != _ENVELOPE_KEYS:
        raise Rejected("invalid_request", "bad envelope keys")
    if data["protocol"] != PROTOCOL:
        raise Rejected("invalid_request", "protocol mismatch")
    rid = data["request_id"]
    try:
        if not isinstance(rid, str) or str(uuid.UUID(rid)) != rid.lower():
            raise ValueError
    except ValueError:
        raise Rejected("invalid_request", "bad request_id") from None
    echo["request_id"] = rid
    name = _ACTION_NAME.validate(data["action"], "action") if isinstance(data["action"], str) else None
    if name is None:
        raise Rejected("invalid_request", "bad action")
    echo["action"] = name
    act = REGISTRY.get(name)
    if act is None:
        raise Rejected("unknown_action", name)
    deadline = _DEADLINE.validate(data["deadline_s"], "deadline_s")
    params = act.params.validate(data["params"], "params")
    return Request(rid, act, params, deadline)


def build_response(
    echo: dict[str, Any],
    state: str,
    result: dict[str, Any] | None,
    error_code: str | None,
    os_profile: str,
    started: float,
) -> bytes:
    body = {
        "protocol": PROTOCOL,
        "request_id": echo.get("request_id"),
        "action": echo.get("action"),
        "state": state,
        "result": result if result is not None else {},
        "error_code": error_code,
        "agent_version": AGENT_VERSION,
        "os_profile": os_profile,
        "duration_ms": int((time.monotonic() - started) * 1000),
    }
    out = json.dumps(body, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(out) > MAX_RESPONSE_BYTES:
        body.update(state="ERROR", result={}, error_code="output_too_large")
        out = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return out


def error_response(echo: dict[str, Any], err: AgentError, os_profile: str, started: float) -> bytes:
    return build_response(echo, err.state, None, err.code, os_profile, started)
