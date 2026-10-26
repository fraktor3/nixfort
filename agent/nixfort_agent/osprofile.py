"""OS profiles: every OS-specific path, binary and unit name lives here.

Adding a new OS (e.g. ALT, RED OS) = adding a profile, not changing actions.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

SUPPORTED = ("ubuntu-24.04", "astra-1.8")


@dataclass(frozen=True)
class Profile:
    name: str
    supported: bool
    bins: dict[str, tuple[str, ...]] = field(default_factory=dict)
    units: dict[str, str] = field(default_factory=dict)
    paths: dict[str, str] = field(default_factory=dict)

    def bin(self, key: str) -> str:
        """Absolute path of a tool: first existing candidate (usrmerge differences between
        distributions), otherwise the first candidate - the runner then reports tool_missing."""
        candidates = self.bins[key]
        for path in candidates:
            if os.access(path, os.X_OK):
                return path
        return candidates[0]


_DEBIAN_BINS = {
    "ip": ("/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"),
    "ss": ("/usr/bin/ss", "/usr/sbin/ss", "/bin/ss"),
    "systemctl": ("/usr/bin/systemctl", "/bin/systemctl"),
    "systemd_run": ("/usr/bin/systemd-run",),
    "timedatectl": ("/usr/bin/timedatectl",),
    "dpkg_query": ("/usr/bin/dpkg-query",),
    "apt_get": ("/usr/bin/apt-get",),
    "sshd": ("/usr/sbin/sshd",),
    "nft": ("/usr/sbin/nft", "/sbin/nft"),
    "fail2ban_client": ("/usr/bin/fail2ban-client",),
    "suricata": ("/usr/bin/suricata",),
    "ufw": ("/usr/sbin/ufw",),
    "ssh_client": ("/usr/bin/ssh",),
    "tcpdump": ("/usr/bin/tcpdump", "/usr/sbin/tcpdump"),
    "timeout": ("/usr/bin/timeout",),
}

_DEBIAN_PATHS = {
    "os_release": "/etc/os-release",
    "ip_forward": "/proc/sys/net/ipv4/ip_forward",
    "sshd_dropin_dir": "/etc/ssh/sshd_config.d",
    "sshd_owned": "/etc/ssh/sshd_config.d/00-nixfort.conf",
    "sshd_privsep_dir": "/run/sshd",
    "f2b_owned": "/etc/fail2ban/jail.d/nixfort-sshd.local",
    "nft_conf": "/etc/nftables.conf",
    "nft_dropin_dir": "/etc/nftables.d",
    "nft_owned": "/etc/nftables.d/nixfort.nft",
    "suricata_yaml": "/etc/suricata/suricata.yaml",
    "suricata_owned": "/etc/suricata/nixfort-sensor.yaml",
    "suricata_rules_dir": "/etc/suricata/rules",
    "suricata_test_rules": "/etc/suricata/rules/nixfort-test.rules",
    "suricata_dist_rules": "/var/lib/suricata/rules/suricata.rules",
    "sys_class_net": "/sys/class/net",
    "state_dir": "/var/lib/nixfort",
    "snapshots_dir": "/var/lib/nixfort/snapshots",
    "tmp_dir": "/var/lib/nixfort/tmp",
    "agent_log": "/var/log/nixfort-agent.log",
    "rollback_launcher": "/usr/local/sbin/nixfort-agent-rollback",
}

_DEBIAN_UNITS = {
    "ssh": "ssh.service",
    "ssh_socket": "ssh.socket",
    "nftables": "nftables.service",
    "fail2ban": "fail2ban.service",
    "suricata": "suricata.service",
    "ufw": "ufw.service",
    "firewalld": "firewalld.service",
    "journald": "systemd-journald.service",
    "timesyncd": "systemd-timesyncd.service",
    "chrony": "chrony.service",
}

UBUNTU_2404 = Profile("ubuntu-24.04", True, dict(_DEBIAN_BINS), dict(_DEBIAN_UNITS), dict(_DEBIAN_PATHS))
# Astra Linux SE 1.8 is Debian 12 based; same layout. Verified on the lab before claiming support.
ASTRA_18 = Profile("astra-1.8", True, dict(_DEBIAN_BINS), dict(_DEBIAN_UNITS), dict(_DEBIAN_PATHS))
UNSUPPORTED = Profile("unsupported", False, dict(_DEBIAN_BINS), dict(_DEBIAN_UNITS), dict(_DEBIAN_PATHS))


def parse_os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key.strip()] = value
    return out


def select_profile(os_release: dict[str, str]) -> Profile:
    os_id = os_release.get("ID", "").lower()
    version = os_release.get("VERSION_ID", "")
    if os_id == "ubuntu" and version == "24.04":
        return UBUNTU_2404
    if os_id in {"astra", "astralinux"} and version.startswith("1.8"):
        return ASTRA_18
    return UNSUPPORTED
