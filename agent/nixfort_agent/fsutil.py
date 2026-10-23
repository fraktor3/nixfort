"""Filesystem helpers for files owned by NIXFORT. Atomic writes, fixed modes."""

from __future__ import annotations

import hashlib
import os
import tempfile


def sha256_file(path: str) -> str | None:
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except FileNotFoundError:
        return None


def atomic_write(path: str, data: bytes, mode: int = 0o644) -> None:
    """Write via a temp file in the same directory + fsync + rename (no half-written configs)."""
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o755, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".nixfort-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def remove_if_exists(path: str) -> bool:
    try:
        os.unlink(path)
        return True
    except FileNotFoundError:
        return False
