"""Nmap adapter: fixed profiles only, targets restricted to the project (SECURITY T11, ADR-009)."""

from __future__ import annotations

import ipaddress
import shutil
import subprocess  # noqa: S404 - list argv, constant binary, timeout

from defusedxml import ElementTree

PROFILES = {
    # profile -> nmap port arguments (constants)
    "common": [
        "-p",
        "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,3306,3389,"
        "5432,5900,6379,8000,8080,8443,9000,9200,11211,27017",
    ],
    "top100": ["--top-ports", "100"],
}
TIMEOUT_S = 300


class NmapError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def build_argv(targets: list[str], profile: str, allowed_networks: list[str]) -> list[str]:
    if profile not in PROFILES:
        raise NmapError("bad_profile")
    if not 1 <= len(targets) <= 64:
        raise NmapError("bad_targets")
    nets = [ipaddress.IPv4Network(n) for n in allowed_networks]
    clean: list[str] = []
    for t in targets:
        try:
            ip = ipaddress.IPv4Address(t)
        except ValueError:
            raise NmapError("bad_targets") from None
        if not any(ip in n for n in nets):
            raise NmapError("target_out_of_scope")
        clean.append(str(ip))
    binary = shutil.which("nmap", path="/usr/bin:/usr/local/bin")
    if not binary:
        raise NmapError("tool_missing")
    return [
        binary,
        "-sT",
        "-Pn",
        "-n",
        "--max-rate",
        "200",
        "--host-timeout",
        "120s",
        "--max-retries",
        "1",
        *PROFILES[profile],
        "-oX",
        "-",
        "--",
        *sorted(set(clean)),
    ]


def run(targets: list[str], profile: str, allowed_networks: list[str]) -> dict:
    argv = build_argv(targets, profile, allowed_networks)
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=TIMEOUT_S, check=False)  # noqa: S603
    except subprocess.TimeoutExpired:
        raise NmapError("tool_timeout") from None
    if proc.returncode != 0:
        raise NmapError("tool_failed")
    return parse_xml(proc.stdout[: 4 * 1024 * 1024])


def parse_xml(data: bytes) -> dict:
    root = ElementTree.fromstring(data)
    hosts = []
    for h in root.findall("host"):
        addr = h.find("address[@addrtype='ipv4']")
        status = h.find("status")
        ports = []
        for p in h.findall("ports/port"):
            st = p.find("state")
            svc = p.find("service")
            ports.append(
                {
                    "port": int(p.get("portid", "0")),
                    "proto": p.get("protocol"),
                    "state": st.get("state") if st is not None else "unknown",
                    "service": svc.get("name") if svc is not None else None,
                }
            )
        hosts.append(
            {
                "ip": addr.get("addr") if addr is not None else None,
                "status": status.get("state") if status is not None else "unknown",
                "open_ports": sorted(p["port"] for p in ports if p["state"] == "open"),
                "ports": ports,
            }
        )
    run_stats = root.find("runstats/finished")
    return {
        "nmap_version": root.get("version"),
        "args": root.get("args"),
        "finished": run_stats.get("timestr") if run_stats is not None else None,
        "hosts": hosts,
    }
