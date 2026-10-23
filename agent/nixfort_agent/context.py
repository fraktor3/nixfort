"""Execution context passed to every action handler.

All I/O goes through the context so handlers can be unit-tested with fakes.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import runner
from .errors import ToolError
from .osprofile import Profile


@dataclass
class Context:
    profile: Profile
    os_release: dict[str, str]
    deadline_s: float
    run: Callable[..., runner.RunResult] = runner.run
    read_file: Callable[[str], str] = field(default=lambda p: Path(p).read_text(encoding="utf-8", errors="replace"))
    started: float = field(default_factory=time.monotonic)

    def remaining(self) -> float:
        return self.deadline_s - (time.monotonic() - self.started)

    def timeout(self, wanted: float) -> float:
        left = self.remaining()
        if left <= 0.5:
            raise ToolError("tool_timeout", "request deadline exceeded")
        return min(wanted, left - 0.5)

    def tool(self, key: str, *args: str, timeout: float = 30.0, **kw) -> runner.RunResult:
        """Run a profile binary with fixed arguments."""
        return self.run([self.profile.bin(key), *args], timeout=self.timeout(timeout), **kw)
