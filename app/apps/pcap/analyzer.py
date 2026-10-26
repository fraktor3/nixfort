"""Traffic analysis with TShark (the Wireshark engine). One field-extraction pass is aggregated in Python:
protocols, top talkers, conversations, destination ports, a per-second timeline, and simple findings
(port scan / SSH brute force) derived from the SYN pattern. No user filter expressions ever reach tshark,
no payload is read, and analysis runs under a wall-clock timeout and a memory limit (SECURITY.md T10).
"""

from __future__ import annotations

import ipaddress
import resource
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any

from .storage import is_pcap

TSHARK = shutil.which("tshark") or "/usr/bin/tshark"
TIMEOUT_S = 120
MEM_LIMIT = 1024 * 1024 * 1024  # 1 GiB address space in the child
MAX_PACKETS = 200_000
MAX_BUCKETS = 120
SCAN_DISTINCT_PORTS = 20  # one source → this many distinct destination ports ⇒ scan
BRUTE_SYN_TO_22 = 5  # this many new connections to port 22 from one source ⇒ brute force
FIELDS = ["frame.time_relative", "ip.src", "ip.dst", "frame.len", "tcp.srcport", "tcp.dstport",
          "tcp.flags.syn", "tcp.flags.ack", "udp.srcport", "udp.dstport", "_ws.col.Protocol"]  # fmt: skip


class AnalysisError(Exception):
    pass


def _isnum(x: str) -> bool:
    try:
        float(x)
        return True
    except ValueError:
        return False


def _limits() -> None:  # pragma: no cover - runs in the child
    resource.setrlimit(resource.RLIMIT_AS, (MEM_LIMIT, MEM_LIMIT))


def analyze(path: Path | str) -> dict[str, Any]:
    path = Path(path)
    if not is_pcap(path.read_bytes()[:4]):
        raise AnalysisError("файл не является PCAP/PCAPNG (неверная сигнатура)")
    argv = [TSHARK, "-r", str(path), "-n", "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    for f in FIELDS:
        argv += ["-e", f]
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, no user expressions
            argv, capture_output=True, timeout=TIMEOUT_S, preexec_fn=_limits, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise AnalysisError("анализ прерван по тайм-ауту") from exc
    if proc.returncode != 0:
        raise AnalysisError("tshark не смог прочитать файл: " + proc.stderr.decode("utf-8", "replace")[-200:])
    return summarize(proc.stdout.decode("utf-8", "replace"))


def _service_port(sp: str, dp: str) -> int | None:
    cand = [int(x) for x in (sp, dp) if x.isdigit()]
    if not cand:
        return None
    low = min(cand)
    return low if low <= 49151 else None


def summarize(tsv: str) -> dict[str, Any]:
    protos: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    talkers: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    convs: dict[tuple, list[int]] = defaultdict(lambda: [0, 0])
    ports: dict[tuple, int] = defaultdict(int)
    scan_ports: dict[str, set] = defaultdict(set)  # src → distinct dst ports seen with SYN
    ssh_syn: dict[str, int] = defaultdict(int)  # src → SYN to port 22
    times: list[tuple[float, int, bool]] = []  # (t, bytes, is_new_tcp_conn)
    total_bytes = new_conns = 0
    last_t = 0.0

    packets = 0
    for line in tsv.splitlines():
        if not line:
            continue
        f = (line.split("\t") + [""] * len(FIELDS))[: len(FIELDS)]
        t_rel, src, dst, length, tsp, tdp, syn, ack, usp, udp_, label = f
        if not length.isdigit():  # a real captured frame always has a numeric length
            continue
        t = float(t_rel) if _isnum(t_rel) else 0.0
        n = int(length)
        packets += 1
        if packets > MAX_PACKETS:
            packets = MAX_PACKETS
            break
        total_bytes += n
        last_t = max(last_t, t)
        is_syn = syn in ("1", "True") and ack in ("0", "", "False")
        if is_syn:
            new_conns += 1
        times.append((t, n, is_syn))
        protos[(label or "—").split("/")[0][:24]][0] += 1
        protos[(label or "—").split("/")[0][:24]][1] += n
        if src:
            talkers[src][0] += 1
            talkers[src][1] += n
        if src and dst:
            pair = tuple(sorted((src, dst)))
            convs[pair][0] += 1
            convs[pair][1] += n
        if tsp or tdp:
            svc = _service_port(tsp, tdp)
            if svc is not None:
                ports[("TCP", svc)] += 1
            if is_syn and src and tdp.isdigit():
                scan_ports[src].add(int(tdp))
                if int(tdp) == 22:
                    ssh_syn[src] += 1
        elif usp or udp_:
            svc = _service_port(usp, udp_)
            if svc is not None:
                ports[("UDP", svc)] += 1

    def top(d, key, n=15):
        return sorted((key(k, v) for k, v in d.items()), key=lambda x: -x["frames"])[:n]

    findings = _findings(scan_ports, ssh_syn, talkers)
    return {
        "packets": packets,
        "bytes": total_bytes,
        "duration_s": round(last_t, 3),
        "tcp_new_connections": new_conns,
        "protocols": top(protos, lambda k, v: {"protocol": k, "frames": v[0], "bytes": v[1]}),
        "top_sources": top(talkers, lambda k, v: {"ip": k, "frames": v[0], "bytes": v[1], "is_private": _priv(k)}),
        "conversations": top(convs, lambda k, v: {"a": k[0], "b": k[1], "frames": v[0], "bytes": v[1]}),
        "ports": top(ports, lambda k, v: {"proto": k[0], "port": k[1], "frames": v}),
        "timeline": _timeline(times, last_t),
        "findings": findings,
    }


def _findings(scan_ports, ssh_syn, talkers) -> list[dict]:
    out = []
    for src, dports in sorted(scan_ports.items(), key=lambda kv: -len(kv[1])):
        if len(dports) >= SCAN_DISTINCT_PORTS:
            out.append({
                "kind": "scan", "severity": "HIGH", "src": src, "value": len(dports),
                "title": "Признаки сканирования портов",
                "detail": f"{src}: обращения к {len(dports)} различным портам за время захвата.",
            })  # fmt: skip
    for src, cnt in sorted(ssh_syn.items(), key=lambda kv: -kv[1]):
        if cnt >= BRUTE_SYN_TO_22:
            out.append({
                "kind": "ssh_bruteforce", "severity": "HIGH", "src": src, "value": cnt,
                "title": "Признаки подбора пароля SSH",
                "detail": f"{src}: {cnt} новых подключений к порту 22 за время захвата.",
            })  # fmt: skip
    return out


def _priv(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _timeline(times: list[tuple[float, int, bool]], duration: float) -> dict[str, Any]:
    if not times:
        return {"bucket_s": 1, "packets": [], "syn": [], "bytes": []}
    buckets = max(1, min(MAX_BUCKETS, int(duration) + 1))
    width = (duration / buckets) if duration > 0 else 1.0
    pk = [0] * buckets
    sy = [0] * buckets
    by = [0] * buckets
    for t, n, is_syn in times:
        i = min(buckets - 1, int(t / width)) if width else 0
        pk[i] += 1
        by[i] += n
        if is_syn:
            sy[i] += 1
    return {"bucket_s": round(width, 3) if duration > 0 else 1, "packets": pk, "syn": sy, "bytes": by}
