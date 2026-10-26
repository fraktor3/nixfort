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


# ------------------------------------------------------------------ resilience under load (test_client)
import concurrent.futures  # noqa: E402
import threading  # noqa: E402


@action(
    "net.load_test.v1",
    Obj(
        {
            "ip": IPv4(),
            "port": Int(1, 65535),
            "connections": Int(10, 500),
            "concurrency": Int(1, 50),
            "duration_s": Int(1, 20),
        }
    ),
)
def load_test(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    """Bounded resilience check from this node: open up to `connections` short-lived TCP connections to one
    target (at most `concurrency` at once, for at most `duration_s`), and measure how the service responds —
    how many connections succeed, are refused or time out, and the latency. This is a responsiveness probe
    for the lab, not a denial-of-service tool: it is hard-capped on every axis and targets one chosen service.
    """
    ip, port = params["ip"], params["port"]
    total = params["connections"]
    t_start = time.monotonic()
    deadline = t_start + min(params["duration_s"], max(1.0, ctx.remaining() - 2))
    counts = {"succeeded": 0, "refused": 0, "timed_out": 0, "unreachable": 0, "error": 0}
    latencies: list[float] = []
    lock = threading.Lock()
    started = 0

    def one() -> None:
        t0 = time.monotonic()
        outcome = "error"
        try:
            with socket.create_connection((ip, port), timeout=2):
                outcome = "succeeded"
        except ConnectionRefusedError:
            outcome = "refused"
        except TimeoutError:
            outcome = "timed_out"
        except OSError as exc:
            outcome = "unreachable" if exc.errno in _UNREACH else "error"
        dt = (time.monotonic() - t0) * 1000
        with lock:
            counts[outcome] += 1
            if outcome == "succeeded":
                latencies.append(dt)

    with concurrent.futures.ThreadPoolExecutor(max_workers=params["concurrency"]) as pool:
        futures = []
        while started < total and time.monotonic() < deadline:
            futures.append(pool.submit(one))
            started += 1
        for f in concurrent.futures.as_completed(futures):
            f.result()

    elapsed = max(0.001, time.monotonic() - t_start)
    done = sum(counts.values())
    lat_sorted = sorted(latencies)
    return {
        "target": f"{ip}:{port}",
        "attempted": done,
        **counts,
        "service_available": counts["succeeded"] > 0,
        "avg_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else None,
        "p95_latency_ms": round(lat_sorted[int(len(lat_sorted) * 0.95) - 1], 1) if lat_sorted else None,
        "rate_per_s": round(done / elapsed, 1),
    }
