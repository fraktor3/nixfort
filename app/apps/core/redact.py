"""Secret redaction for logs, job logs and audit metadata (SECURITY §4 п.6)."""

from __future__ import annotations

import logging
import re
from typing import Any

SECRET_KEYS = re.compile(r"(pass(word)?|secret|token|private|api[_-]?key|credential|^key$)", re.I)
SECRET_VALUES = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"(?i)(password|passwd|pwd|secret|token)\s*[=:]\s*\S+"),
]
MASK = "***"


def redact_text(text: str) -> str:
    for rx in SECRET_VALUES:
        text = rx.sub(lambda m: (m.group(1) + "=" + MASK) if m.lastindex else MASK, text)
    return text


def redact(value: Any, _depth: int = 0) -> Any:
    if _depth > 8:
        return MASK
    if isinstance(value, dict):
        return {k: (MASK if SECRET_KEYS.search(str(k)) else redact(v, _depth + 1)) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact(v, _depth + 1) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


class RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg)
        if record.args:
            record.args = (
                tuple(redact(a) for a in record.args) if isinstance(record.args, tuple) else redact(record.args)
            )
        return True
