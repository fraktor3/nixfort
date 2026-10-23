"""Snapshots of NIXFORT-owned objects before a change, and their restoration.

Layout: <snapshots_dir>/<id>/meta.json + f<N> copies. Only paths listed by the action itself
(constants from the OS profile) are ever snapshotted or restored.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
import uuid
from dataclasses import dataclass
from typing import Any

from . import fsutil
from .context import Context
from .errors import AgentError, Rejected

SNAP_ID = re.compile(r"[0-9a-f]{32}")
KINDS = ("ssh", "fail2ban", "nft", "suricata")


def validate_id(snap_id: str) -> str:
    if not isinstance(snap_id, str) or not SNAP_ID.fullmatch(snap_id):
        raise Rejected("invalid_params", "bad snapshot id")
    return snap_id


@dataclass
class Snapshot:
    id: str
    dir: str
    meta: dict[str, Any]

    def save(self) -> None:
        fsutil.atomic_write(os.path.join(self.dir, "meta.json"), json.dumps(self.meta, indent=1).encode(), 0o600)


def _root(ctx: Context) -> str:
    return ctx.profile.paths["snapshots_dir"]


def create(ctx: Context, kind: str, files: list[str], extra: dict[str, Any] | None = None) -> Snapshot:
    if kind not in KINDS:
        raise AgentError("internal_error", f"bad kind {kind}")
    snap_id = uuid.uuid4().hex
    d = os.path.join(_root(ctx), snap_id)
    os.makedirs(d, mode=0o700)
    entries = []
    for i, path in enumerate(files):
        entry: dict[str, Any] = {"path": path, "existed": os.path.exists(path)}
        if entry["existed"]:
            st = os.stat(path)
            shutil.copy2(path, os.path.join(d, f"f{i}"))
            entry.update(copy=f"f{i}", mode=st.st_mode & 0o7777, sha256=fsutil.sha256_file(path))
        entries.append(entry)
    snap = Snapshot(
        snap_id,
        d,
        {
            "id": snap_id,
            "kind": kind,
            "created_at": time.time(),
            "files": entries,
            "extra": extra or {},
            "committed": False,
            "rolled_back": False,
            "rollback_result": None,
        },
    )
    snap.save()
    return snap


def load(ctx: Context, snap_id: str) -> Snapshot:
    validate_id(snap_id)
    d = os.path.join(_root(ctx), snap_id)
    try:
        with open(os.path.join(d, "meta.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
    except FileNotFoundError:
        raise AgentError("snapshot_not_found", snap_id) from None
    return Snapshot(snap_id, d, meta)


def restore_files(snap: Snapshot) -> list[str]:
    """Put every snapshotted file back exactly (content + mode); files that did not exist are removed."""
    changed = []
    for e in snap.meta["files"]:
        if e["existed"]:
            with open(os.path.join(snap.dir, e["copy"]), "rb") as fh:
                data = fh.read()
            if fsutil.sha256_file(e["path"]) != e["sha256"]:
                fsutil.atomic_write(e["path"], data, e["mode"])
                changed.append(e["path"])
        elif fsutil.remove_if_exists(e["path"]):
            changed.append(e["path"])
    return changed
