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


# ------------------------------------------------------------------ hardening profile (mutating)
from .. import mutation  # noqa: E402
from ..errors import Rejected  # noqa: E402
from ..fsutil import atomic_write  # noqa: E402
from ..schema import Bool, Int, Obj, Str  # noqa: E402

HEADER = "# Managed by NIXFORT. Manual changes will be overwritten. Rollback: NIXFORT snapshots.\n"


def render_profile(p: dict[str, Any]) -> str:
    """Only the values from validated, typed parameters reach the file (no free text)."""
    lines = [
        HEADER,
        f"PermitRootLogin {p['permit_root_login']}",
        f"PasswordAuthentication {'no' if not p['password_authentication'] else 'yes'}",
        "PermitEmptyPasswords no",
        f"MaxAuthTries {int(p['max_auth_tries'])}",
        f"LoginGraceTime {int(p['login_grace_time_s'])}",
        f"X11Forwarding {'yes' if p['x11_forwarding'] else 'no'}",
        "",
    ]
    return "\n".join(lines)


def _include_present(ctx: Context) -> bool:
    try:
        text = ctx.read_file("/etc/ssh/sshd_config")
    except OSError:
        return False
    return any(line.strip().lower().startswith("include") and "sshd_config.d" in line for line in text.splitlines())


def reload_sshd(ctx: Context) -> None:
    # try-reload-or-restart: reloads a running sshd; with socket activation and no running sshd it is
    # a no-op and the next connection starts sshd with the new configuration.
    res = ctx.tool("systemctl", "try-reload-or-restart", ctx.profile.units["ssh"], timeout=30)
    if res.returncode != 0:
        from ..errors import AgentError

        raise AgentError("tool_failed", "sshd reload failed")


def _reapply_ssh(ctx: Context, snap) -> dict[str, Any]:
    ok, _ = validate(ctx)
    if not ok:  # the restored (previous) config is invalid: do not reload, report
        return {"service_reloaded": False, "restored_config_valid": False}
    reload_sshd(ctx)
    return {"service_reloaded": True, "restored_config_valid": True}


mutation.REAPPLY["ssh"] = _reapply_ssh


@action(
    "ssh.apply_hardening_profile.v1",
    Obj(
        {
            "permit_root_login": Str(choices=frozenset({"no"})),
            "password_authentication": Bool(),
            "max_auth_tries": Int(1, 6),
            "login_grace_time_s": Int(10, 120),
            "x11_forwarding": Bool(),
            "rollback_timeout_s": Int(30, 300),
        }
    ),
    mutating=True,
)
def apply_hardening_profile(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    path = ctx.profile.paths["sshd_owned"]
    if not _include_present(ctx):
        raise Rejected("validation_failed", "sshd_config has no Include of sshd_config.d")
    ok, _ = validate(ctx)
    if not ok:  # SSH-07: never touch an already broken configuration
        raise Rejected("validation_failed", "current sshd configuration is invalid")
    result = mutation.guarded_apply(
        ctx,
        kind="ssh",
        files=[path],
        write_candidate=lambda: atomic_write(path, render_profile(params).encode(), 0o644),
        validate=lambda: validate(ctx),
        activate=lambda: reload_sshd(ctx),
        rollback_timeout_s=params["rollback_timeout_s"],
    )
    result["effective"] = effective(ctx)
    return result
