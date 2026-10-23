"""Strict validators for network-facing input (SECURITY §4 п.3)."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re

from django.core.exceptions import ValidationError

NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
IFACE_RE = re.compile(r"^[a-z0-9]{1,15}$")
NODE_ROLES = ("gateway", "server", "ids_sensor", "test_client")
SUPPORTED_OS = (("ubuntu-24.04", "Ubuntu Server 24.04 LTS"), ("astra-1.8", "Astra Linux SE 1.8"))
HOSTKEY_TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa")


def validate_name(value: str) -> None:
    if not isinstance(value, str) or not NAME_RE.fullmatch(value):
        raise ValidationError("Допустимы латинские буквы, цифры, «.», «_», «-», до 64 символов.")


def parse_ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except ValueError:
        raise ValidationError(f"Некорректный IPv4-адрес: {str(value)[:40]}") from None


def parse_network(value: str, allow_public: bool = False) -> str:
    try:
        net = ipaddress.IPv4Network(str(value).strip(), strict=True)
    except ValueError:
        raise ValidationError(f"Некорректная IPv4-сеть (пример 10.88.0.0/24): {str(value)[:40]}") from None
    if not allow_public and not net.is_private:
        raise ValidationError(f"Разрешены только частные сети (RFC 1918): {net}")
    if net.prefixlen < 8:
        raise ValidationError(f"Слишком широкая сеть: {net}")
    return str(net)


def parse_ip_or_network(value: str) -> str:
    s = str(value).strip()
    return parse_network(s) if "/" in s else parse_ipv4(s)


def split_list(text: str) -> list[str]:
    return [p for p in re.split(r"[\s,;]+", text or "") if p]


def parse_ports(text: str, max_items: int = 64) -> list[int]:
    out: list[int] = []
    for p in split_list(text):
        if not p.isdigit() or not 1 <= int(p) <= 65535:
            raise ValidationError(f"Некорректный порт: {p[:10]}")
        out.append(int(p))
    if len(out) > max_items:
        raise ValidationError(f"Не больше {max_items} портов.")
    return sorted(set(out))


def ip_in_networks(ip: str, networks: list[str]) -> bool:
    addr = ipaddress.IPv4Address(ip)
    return any(addr in ipaddress.IPv4Network(n) for n in networks)


def parse_hostkey_line(line: str) -> tuple[str, str, str]:
    """'ssh-ed25519 AAAA... comment' -> (key_type, base64_blob, 'SHA256:...')."""
    parts = (line or "").strip().split()
    if len(parts) < 2 or parts[0] not in HOSTKEY_TYPES:
        raise ValidationError("Ожидается строка открытого ключа: «ssh-ed25519 AAAA…».")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError:
        raise ValidationError("Повреждённый ключ (base64).") from None
    # The blob starts with the length-prefixed key type; it must match the declared type.
    if len(blob) < 4 or blob[4 : 4 + int.from_bytes(blob[:4], "big")] != parts[0].encode():
        raise ValidationError("Тип ключа не совпадает с содержимым.")
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return parts[0], parts[1], fp
