"""The ONLY place in the agent that starts external programs.

Rules: argv is a list (never a shell string), binary is an absolute path from
the OS profile, environment is minimal, every call has a timeout and an output cap.
"""

from __future__ import annotations

import os
import subprocess  # noqa: S404 - controlled usage, see module docstring
from dataclasses import dataclass

from .errors import ToolError

SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
DEFAULT_MAX_OUTPUT = 256 * 1024


@dataclass(frozen=True)
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    truncated: bool


def run(
    argv: list[str],
    timeout: float,
    max_output: int = DEFAULT_MAX_OUTPUT,
    input_text: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> RunResult:
    if not argv or not all(isinstance(a, str) for a in argv):
        raise ToolError("internal_error", "argv must be a non-empty list of str")
    if not os.path.isabs(argv[0]):
        raise ToolError("internal_error", f"binary must be an absolute path: {argv[0]!r}")
    if not os.access(argv[0], os.X_OK):
        raise ToolError("tool_missing", argv[0])
    env = dict(SAFE_ENV)
    if extra_env:
        env.update(extra_env)
    try:
        proc = subprocess.run(  # noqa: S603 - list argv, no shell
            argv,
            input=input_text.encode() if input_text is not None else None,
            stdin=None if input_text is not None else subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            env=env,
            check=False,
            close_fds=True,
        )
    except subprocess.TimeoutExpired:
        raise ToolError("tool_timeout", " ".join(argv[:2])) from None
    except OSError as exc:
        raise ToolError("tool_failed", f"{argv[0]}: {exc.__class__.__name__}") from None
    out, err = proc.stdout, proc.stderr
    truncated = len(out) > max_output or len(err) > max_output
    return RunResult(
        returncode=proc.returncode,
        stdout=out[:max_output].decode("utf-8", errors="replace"),
        stderr=err[:max_output].decode("utf-8", errors="replace"),
        truncated=truncated,
    )
