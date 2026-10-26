"""Traffic capture for the analyzer (T-020): a short, bounded tcpdump on one interface of this node.

Bounded on every axis: duration ≤ 60 s, ≤ 5000 packets, headers only (snaplen 96 bytes — enough for
Ethernet/IP/TCP/UDP headers and the start of the payload, not for documents or passwords), no user filter
expressions (fixed profiles only), the file never leaves /var/lib/nixfort/tmp except as this response.
"""

from __future__ import annotations

import base64
import os
import uuid
from typing import Any

from ..context import Context
from ..errors import Rejected, ToolError
from ..registry import action
from ..schema import Int, Obj, Str

SNAPLEN = 96
MAX_BYTES = 700 * 1024  # base64 of this still fits the 1 MiB response limit
# Fixed capture profiles (BPF expressions are never taken from the request).
PROFILES = {
    "all": [],
    "ip": ["ip"],
    "no_ssh": ["not", "tcp", "port", "22"],
}


@action(
    "net.capture.v1",
    Obj(
        {
            "interface": Str(max_len=15, pattern=r"[a-z][a-z0-9]{0,14}"),
            "duration_s": Int(3, 60),
            "max_packets": Int(10, 5000),
            "profile": Str(choices=frozenset(PROFILES)),
        }
    ),
)
def capture(ctx: Context, params: dict[str, Any]) -> dict[str, Any]:
    iface = params["interface"]
    if not os.path.isdir(os.path.join(ctx.profile.paths["sys_class_net"], iface)):
        raise Rejected("invalid_params", "interface does not exist on this node")
    if not os.access(ctx.profile.bin("tcpdump"), os.X_OK):
        raise Rejected("tool_missing", "tcpdump is not installed")
    tmp = ctx.profile.paths["tmp_dir"]
    os.makedirs(tmp, mode=0o700, exist_ok=True)
    path = os.path.join(tmp, f"capture-{uuid.uuid4().hex}.pcap")  # .pcap: allowed by the tcpdump AppArmor profile
    argv = [
        "--signal=INT",
        str(int(params["duration_s"])),
        ctx.profile.bin("tcpdump"),
        "-i", iface,
        "-n",
        "-s", str(SNAPLEN),
        "-c", str(int(params["max_packets"])),
        "-Z", "root",  # keep root so the file can be written in our 0700 directory
        "-U",
        "-w", path,
        *PROFILES[params["profile"]],
    ]  # fmt: skip
    try:
        res = ctx.tool("timeout", *argv, timeout=params["duration_s"] + 15)
        # 0: packet limit reached; 124: duration elapsed (tcpdump got SIGINT and flushed the file)
        if res.returncode not in (0, 124) or not os.path.isfile(path):
            raise ToolError("tool_failed", f"tcpdump rc={res.returncode}")
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            data = fh.read(MAX_BYTES)
        stats = _stats(res.stderr)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return {
        "interface": iface,
        "profile": params["profile"],
        "duration_s": params["duration_s"],
        "snaplen": SNAPLEN,
        "size": size,
        "truncated": size > MAX_BYTES,
        "captured": stats.get("captured"),
        "dropped_by_kernel": stats.get("dropped"),
        "pcap_b64": base64.b64encode(data).decode("ascii"),
    }


def _stats(stderr: str) -> dict[str, int]:
    """'12 packets captured' / '0 packets dropped by kernel' from tcpdump's summary."""
    out: dict[str, int] = {}
    for line in (stderr or "").splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and parts[0].isdigit() and parts[1] == "packets":
            if parts[2] == "captured":
                out["captured"] = int(parts[0])
            elif parts[2:5] == ["dropped", "by", "kernel"]:
                out["dropped"] = int(parts[0])
    return out
