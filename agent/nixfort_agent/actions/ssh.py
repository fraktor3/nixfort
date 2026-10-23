"""SSH server: read effective configuration."""

from __future__ import annotations

import os
from typing import Any

from .. import parsers
from ..context import Context
from ..errors import ToolError
from ..registry import action
from ..schema import EMPTY


def ensure_privsep_dir(ctx: Context) -> None:
    """Ubuntu 24.04 uses socket activation; /run/sshd may not exist yet and then
    `sshd -t` fails with 'Missing privilege separation directory'. Creating this
    runtime directory (tmpfs) is harmless and is what ssh.service does itself."""
    path = ctx.profile.paths["sshd_privsep_dir"]
    if not os.path.isdir(path):
        try:
            os.makedirs(path, mode=0o755, exist_ok=True)
        except OSError:
            pass  # sshd -t will then report the real problem


def validate(ctx: Context) -> tuple[bool, str]:
    ensure_privsep_dir(ctx)
    res = ctx.tool("sshd", "-t", timeout=15)
    return res.returncode == 0, res.stderr.strip()[-500:]


def effective(ctx: Context) -> dict[str, str]:
    ensure_privsep_dir(ctx)
    res = ctx.tool("sshd", "-T", timeout=15)
    if res.returncode != 0:
        raise ToolError("tool_failed", "sshd -T")
    return parsers.parse_sshd_t(res.stdout)


@action("ssh.read_effective_config.v1", EMPTY)
def read_effective_config(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    ok, stderr = validate(ctx)
    cfg = effective(ctx) if ok else {}
    return {"config_valid": ok, "validate_stderr": stderr, "effective": cfg}
