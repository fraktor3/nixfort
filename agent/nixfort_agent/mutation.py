"""Common machinery for mutating actions: snapshot -> validate -> arm timer -> apply,
and the matching commit / rollback. Domain modules register how to re-apply their kind."""

from __future__ import annotations

import fcntl
import os
import time
from collections.abc import Callable
from typing import Any

from . import rollback_timer, snapshots
from .context import Context
from .errors import AgentError

# kind -> function(ctx, snapshot) that makes restored files effective (reload service, nft -f ...)
REAPPLY: dict[str, Callable[[Context, snapshots.Snapshot], dict[str, Any]]] = {}


class _Lock:
    """Serialises rollback of one snapshot (timer-fired rollback vs. rollback_now)."""

    def __init__(self, snap: snapshots.Snapshot):
        self.path = os.path.join(snap.dir, ".lock")

    def __enter__(self):
        self.fh = open(self.path, "w")  # noqa: SIM115
        fcntl.flock(self.fh, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        fcntl.flock(self.fh, fcntl.LOCK_UN)
        self.fh.close()


def perform_rollback(ctx: Context, snap_id: str) -> dict[str, Any]:
    snap = snapshots.load(ctx, snap_id)
    with _Lock(snap):
        snap = snapshots.load(ctx, snap_id)  # re-read under lock
        if snap.meta["rolled_back"]:
            return snap.meta["rollback_result"] or {"rolled_back": True}
        if snap.meta["committed"]:
            raise AgentError("rollback_failed", "snapshot already committed")
        try:
            changed = snapshots.restore_files(snap)
            reapply = REAPPLY[snap.meta["kind"]](ctx, snap)
            result = {"rolled_back": True, "files_restored": changed, **reapply}
        except AgentError as exc:
            result = {"rolled_back": False, "error_code": exc.code}
        except Exception:  # noqa: BLE001 - recorded, the controller decides (UNKNOWN)
            result = {"rolled_back": False, "error_code": "rollback_failed"}
        snap.meta["rolled_back"] = bool(result.get("rolled_back"))
        snap.meta["rollback_result"] = result
        snap.meta["rolled_back_at"] = time.time()
        snap.save()
        return result


def guarded_apply(
    ctx: Context,
    kind: str,
    files: list[str],
    write_candidate: Callable[[], None],
    validate: Callable[[], tuple[bool, str]],
    activate: Callable[[], None],
    rollback_timeout_s: int,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The only path a mutation may take (ARCHITECTURE §6):
    snapshot -> write candidate -> validate (if invalid: restore, FAILED, nothing activated)
    -> arm node-side rollback timer -> activate. The controller then verifies and commits."""
    from .errors import Failed

    snap = snapshots.create(ctx, kind, files, extra)
    try:
        write_candidate()
        ok, detail = validate()
    except Exception:
        snapshots.restore_files(snap)
        raise
    if not ok:
        snapshots.restore_files(snap)
        snap.meta["rolled_back"] = True
        snap.meta["rollback_result"] = {"rolled_back": True, "reason": "validation_failed"}
        snap.save()
        raise Failed("validation_failed", detail[-300:])
    try:
        rollback_timer.arm(ctx, snap.id, rollback_timeout_s)
    except AgentError:
        snapshots.restore_files(snap)  # never change anything without a safety net
        raise
    try:
        activate()
    except AgentError as exc:
        rb = perform_rollback(ctx, snap.id)
        rollback_timer.cancel(ctx, snap.id)
        if rb.get("rolled_back"):
            # S-006: the previous state is restored and confirmed by the agent -> a clean FAILED, not "unknown"
            raise Failed("activation_failed", f"{exc.code}: {exc.detail}"[-300:]) from None
        raise AgentError("rollback_failed", f"activation failed ({exc.code}) and rollback failed") from None
    return {
        "snapshot_id": snap.id,
        "validated": True,
        "applied": True,
        "timer_armed": True,
        "rollback_timeout_s": rollback_timeout_s,
    }


def commit(ctx: Context, snap_id: str) -> dict[str, Any]:
    snap = snapshots.load(ctx, snap_id)
    with _Lock(snap):
        snap = snapshots.load(ctx, snap_id)
        if snap.meta["rolled_back"]:
            return {"committed": False, "timer_cancelled": False, "rolled_back": True}
        was_active = rollback_timer.cancel(ctx, snap_id)
        if was_active:
            snap.meta["committed"] = True
            snap.meta["committed_at"] = time.time()
            snap.save()
            return {"committed": True, "timer_cancelled": True, "rolled_back": False}
    # Timer had already fired: the rollback service is running or finished. Wait for its result.
    for _ in range(60):
        snap = snapshots.load(ctx, snap_id)
        if snap.meta["rolled_back"] or snap.meta.get("rollback_result"):
            return {"committed": False, "timer_cancelled": False, "rolled_back": snap.meta["rolled_back"]}
        time.sleep(0.5)
    raise AgentError("timer_failed", "timer not active and no rollback result")
