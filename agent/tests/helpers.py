"""Test helpers: fake runner and context factory."""

from __future__ import annotations

import json
import uuid

from nixfort_agent import PROTOCOL
from nixfort_agent.context import Context
from nixfort_agent.osprofile import UBUNTU_2404, UNSUPPORTED
from nixfort_agent.runner import RunResult


class FakeRunner:
    """Maps a tuple(argv[1:]) prefix to RunResult. Records calls."""

    def __init__(self, table: dict[tuple[str, ...], RunResult] | None = None):
        self.table = table or {}
        self.calls: list[list[str]] = []

    def __call__(self, argv, timeout, **kw):
        assert isinstance(argv, list), "argv must be a list"
        assert argv[0].startswith("/"), "binary must be absolute"
        self.calls.append(argv)
        key = tuple(argv[1:])
        if key in self.table:
            return self.table[key]
        # longest prefix match
        best = None
        for k, v in self.table.items():
            if key[: len(k)] == k and (best is None or len(k) > len(best[0])):
                best = (k, v)
        if best:
            return best[1]
        return RunResult(1, "", "not mocked", False)


def ok(stdout: str = "", stderr: str = "", rc: int = 0) -> RunResult:
    return RunResult(rc, stdout, stderr, False)


def make_ctx(runner=None, supported=True, files=None, deadline=60.0):
    files = files or {}

    def read_file(p):
        if p in files:
            return files[p]
        raise OSError(p)

    return Context(
        profile=UBUNTU_2404 if supported else UNSUPPORTED,
        os_release={"ID": "ubuntu", "VERSION_ID": "24.04"} if supported else {"ID": "fedora"},
        deadline_s=deadline,
        run=runner or FakeRunner(),
        read_file=read_file,
    )


def request(action: str, params: dict | None = None, **over) -> bytes:
    body = {
        "protocol": PROTOCOL,
        "request_id": str(uuid.uuid4()),
        "action": action,
        "params": params if params is not None else {},
        "deadline_s": 30,
    }
    body.update(over)
    return json.dumps(body).encode()
