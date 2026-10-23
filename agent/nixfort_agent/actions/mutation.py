"""mutation.* actions: commit, rollback now, snapshot status."""

from __future__ import annotations

from typing import Any

from .. import mutation, rollback_timer, snapshots
from ..context import Context
from ..registry import action
from ..schema import Obj, Str

SNAP = Obj({"snapshot_id": Str(max_len=32, pattern=r"[0-9a-f]{32}")})


@action("mutation.commit.v1", SNAP, mutating=True)
def commit(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    return mutation.commit(ctx, params["snapshot_id"])


@action("mutation.rollback_now.v1", SNAP, mutating=True)
def rollback_now(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    sid = params["snapshot_id"]
    snapshots.load(ctx, sid)
    try:
        rollback_timer.cancel(ctx, sid)
    finally:
        result = mutation.perform_rollback(ctx, sid)
    return result


@action("mutation.snapshot_status.v1", SNAP, needs_supported_os=False)
def status(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    snap = snapshots.load(ctx, params["snapshot_id"])
    m = snap.meta
    return {
        "exists": True,
        "kind": m["kind"],
        "committed": m["committed"],
        "rolled_back": m["rolled_back"],
        "rollback_result": m.get("rollback_result"),
        "timer_active": rollback_timer.is_active(ctx, snap.id),
    }
