"""Where PCAP files live. Name on disk = SHA-256 (SECURITY.md T10): a malicious filename can never shape the
path, and identical captures deduplicate. A file is accepted only if its magic bytes are a real pcap/pcapng."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from django.conf import settings

MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MiB
# pcap (LE/BE, microsecond + nanosecond) and pcapng
MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")
_HEX = re.compile(r"[0-9a-f]{64}")


class PcapRejected(Exception):
    pass


def is_pcap(head: bytes) -> bool:
    return any(head.startswith(m) for m in MAGICS)


def _dir() -> Path:
    d = Path(str(settings.NIXFORT_DATA_DIR)) / "pcap"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d


def path_of(digest: str) -> Path:
    if not _HEX.fullmatch(digest or ""):
        raise ValueError("bad digest")
    return _dir() / f"{digest}.pcap"


def store_bytes(data: bytes) -> tuple[str, int]:
    if not data:
        raise PcapRejected("Файл пуст.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise PcapRejected("Файл больше 100 МБ.")
    if not is_pcap(data[:4]):
        raise PcapRejected("Это не файл PCAP/PCAPNG (неверная сигнатура).")
    digest = hashlib.sha256(data).hexdigest()
    path = path_of(digest)
    if not path.exists():
        tmp = path.with_suffix(".pcap.tmp")
        tmp.write_bytes(data)
        tmp.chmod(0o600)
        tmp.replace(path)
    return digest, len(data)
