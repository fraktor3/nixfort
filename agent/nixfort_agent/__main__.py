"""Entry point: one request on stdin -> one response on stdout. Always exit 0."""

from __future__ import annotations

import logging
import sys
import time

from .context import Context
from .errors import AgentError, Rejected
from .osprofile import UNSUPPORTED, parse_os_release, select_profile
from .protocol import MAX_REQUEST_BYTES, build_response, error_response, parse_request
from .registry import load_all

log = logging.getLogger("nixfort-agent")
log.addHandler(logging.NullHandler())
log.propagate = False


def _setup_logging(path: str) -> None:
    try:
        handler: logging.Handler = logging.FileHandler(path, encoding="utf-8")
    except OSError:
        handler = logging.NullHandler()  # not root (tests) - logging is best effort only
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)


def handle(raw: bytes, ctx_factory=None) -> bytes:
    started = time.monotonic()
    echo: dict = {"request_id": None, "action": None}
    profile_name = UNSUPPORTED.name
    try:
        load_all()
        req = parse_request(raw, echo)
        ctx = ctx_factory(req.deadline_s) if ctx_factory else _real_context(req.deadline_s)
        profile_name = ctx.profile.name
        if req.action.needs_supported_os and not ctx.profile.supported:
            raise Rejected("unsupported_os", ctx.os_release.get("ID", "?"))
        log.info("action=%s request_id=%s", req.action.name, req.request_id)
        result = req.action.handler(ctx, req.params)
        return build_response(echo, "OK", result, None, profile_name, started)
    except AgentError as err:
        log.warning("action=%s state=%s code=%s detail=%s", echo.get("action"), err.state, err.code, err.detail)
        return error_response(echo, err, profile_name, started)
    except Exception:  # noqa: BLE001 - last resort, never leak traceback to stdout
        log.exception("internal error in action=%s", echo.get("action"))
        return build_response(echo, "ERROR", None, "internal_error", profile_name, started)


def _real_context(deadline_s: int) -> Context:
    from .osprofile import UBUNTU_2404

    try:
        with open(UBUNTU_2404.paths["os_release"], encoding="utf-8") as fh:
            osr = parse_os_release(fh.read())
    except OSError:
        osr = {}
    return Context(profile=select_profile(osr), os_release=osr, deadline_s=float(deadline_s))


def main() -> int:
    _setup_logging("/var/log/nixfort-agent.log")
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    sys.stdout.buffer.write(handle(raw))
    sys.stdout.buffer.write(b"\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
