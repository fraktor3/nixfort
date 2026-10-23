"""Job handlers registry. A handler receives the Job and returns (final_state, result_dict)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .models import Job

Handler = Callable[[Job], tuple[str, dict[str, Any]]]
HANDLERS: dict[str, Handler] = {}


def register(job_type: str):
    def deco(fn: Handler) -> Handler:
        HANDLERS[job_type] = fn
        return fn

    return deco
