"""Network probes executed FROM this node (role test_client). Pure sockets, no tools."""

from __future__ import annotations

import errno
import socket
import time
from typing import Any

from ..context import Context
from ..registry import action
from ..schema import Int, IPv4, ListOf, Obj

IDS_TEST_MARKER = b"NIXFORT-IDS-TEST-7f3a"

_UNREACH = {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EACCES, errno.EPERM}


def probe(ip: str, port: int, timeout_s: float) -> dict[str, Any]:
    t0 = time.monotonic()
    result = "ERROR"
    try:
        with socket.create_connection((ip, port), timeout=timeout_s):
            result = "OPEN"
    except ConnectionRefusedError:
        result = "CLOSED"
    except TimeoutError:
        result = "TIMEOUT"
    except OSError as exc:
        result = "UNREACHABLE" if exc.errno in _UNREACH else "ERROR"
    latency = int((time.monotonic() - t0) * 1000)
    return {"ip": ip, "port": port, "result": result, "latency_ms": latency}


@action(
    "net.tcp_probe.v1",
    Obj(
        {
            "targets": ListOf(Obj({"ip": IPv4(), "port": Int(1, 65535)}), max_len=50, min_len=1),
            "timeout_ms": Int(200, 5000),
        }
    ),
)
def tcp_probe(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    timeout_s = params["timeout_ms"] / 1000
    results = []
    for t in params["targets"]:
        ctx.timeout(timeout_s)  # raises if the request deadline is exhausted
        results.append(probe(t["ip"], t["port"], timeout_s))
    return {"results": results}


@action("net.send_ids_test.v1", Obj({"ip": IPv4(), "port": Int(1, 65535)}))
def send_ids_test(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    try:
        with socket.create_connection((params["ip"], params["port"]), timeout=3) as s:
            s.sendall(IDS_TEST_MARKER + b"\r\n")
            return {"sent": True}
    except OSError:
        return {"sent": False}


@action(
    "net.ssh_login_attempts.v1",
    Obj({"ip": IPv4(), "port": Int(1, 65535), "count": Int(1, 10)}),
)
def ssh_login_attempts(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    """Protection test «password guessing»: `count` SSH logins as non-existent users, no password is ever sent
    (BatchMode). The target's sshd logs «Invalid user …» — exactly what Fail2ban counts. Host key checking is off
    on purpose: this is an attack simulation, nothing secret is transmitted and nothing is stored."""
    from ..errors import ToolError

    results = []
    for i in range(1, params["count"] + 1):
        t0 = time.monotonic()
        try:
            res = ctx.tool(
                "ssh_client",
                "-n",
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=3",
                "-o", "LogLevel=ERROR",
                "-p", str(params["port"]),
                "-l", f"nixfort-test-{i}",
                params["ip"],
                "true",
                timeout=8,
            )  # fmt: skip
            err = (res.stderr or "").lower()
            if "permission denied" in err:
                outcome = "REJECTED"  # reached sshd, authentication refused
            elif "refused" in err:
                outcome = "CLOSED"
            elif "timed out" in err:
                outcome = "TIMEOUT"
            else:
                outcome = "ERROR"
        except ToolError as exc:
            if exc.code == "tool_missing":
                raise
            outcome = "TIMEOUT"
        results.append({"attempt": i, "result": outcome, "latency_ms": int((time.monotonic() - t0) * 1000)})
    summary = {k: sum(1 for r in results if r["result"] == k) for k in ("REJECTED", "CLOSED", "TIMEOUT", "ERROR")}
    return {"attempts": results, "summary": summary}
