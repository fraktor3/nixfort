"""Minimal strict validation of action parameters (no third-party deps).

Every field either returns a normalized value or raises Rejected("invalid_params").
Unknown keys are always rejected.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any

from .errors import Rejected

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _bad(path: str, why: str) -> Rejected:
    return Rejected("invalid_params", f"{path}: {why}")


class Field:
    def validate(self, value: Any, path: str) -> Any:  # pragma: no cover - interface
        raise NotImplementedError


class Str(Field):
    def __init__(self, max_len: int = 256, pattern: str | None = None, choices: frozenset[str] | None = None):
        self.max_len = max_len
        self.pattern = re.compile(pattern) if pattern else None
        self.choices = choices

    def validate(self, value: Any, path: str) -> str:
        if not isinstance(value, str):
            raise _bad(path, "expected string")
        if len(value) > self.max_len:
            raise _bad(path, "too long")
        if _CONTROL.search(value):
            raise _bad(path, "control characters")
        if self.choices is not None and value not in self.choices:
            raise _bad(path, "not allowed value")
        if self.pattern is not None and not self.pattern.fullmatch(value):
            raise _bad(path, "pattern mismatch")
        return value


class Int(Field):
    def __init__(self, min_value: int, max_value: int):
        self.min_value = min_value
        self.max_value = max_value

    def validate(self, value: Any, path: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise _bad(path, "expected integer")
        if not self.min_value <= value <= self.max_value:
            raise _bad(path, "out of range")
        return value


class Bool(Field):
    def validate(self, value: Any, path: str) -> bool:
        if not isinstance(value, bool):
            raise _bad(path, "expected boolean")
        return value


class IPv4(Field):
    def validate(self, value: Any, path: str) -> str:
        s = Str(max_len=15).validate(value, path)
        try:
            return str(ipaddress.IPv4Address(s))
        except ValueError:
            raise _bad(path, "invalid IPv4 address") from None


class IPv4OrCIDR(Field):
    def validate(self, value: Any, path: str) -> str:
        s = Str(max_len=18).validate(value, path)
        try:
            if "/" in s:
                return str(ipaddress.IPv4Network(s, strict=True))
            return str(ipaddress.IPv4Address(s))
        except ValueError:
            raise _bad(path, "invalid IPv4 address or network") from None


class Nullable(Field):
    def __init__(self, inner: Field):
        self.inner = inner

    def validate(self, value: Any, path: str) -> Any:
        if value is None:
            return None
        return self.inner.validate(value, path)


class ListOf(Field):
    def __init__(self, item: Field, max_len: int, min_len: int = 0, unique: bool = False):
        self.item = item
        self.max_len = max_len
        self.min_len = min_len
        self.unique = unique

    def validate(self, value: Any, path: str) -> list[Any]:
        if not isinstance(value, list):
            raise _bad(path, "expected list")
        if not self.min_len <= len(value) <= self.max_len:
            raise _bad(path, "bad list length")
        out = [self.item.validate(v, f"{path}[{i}]") for i, v in enumerate(value)]
        if self.unique:
            seen = [repr(v) for v in out]
            if len(set(seen)) != len(seen):
                raise _bad(path, "duplicate items")
        return out


class Obj(Field):
    def __init__(self, fields: Mapping[str, Field], optional: frozenset[str] = frozenset()):
        self.fields = dict(fields)
        self.optional = optional

    def validate(self, value: Any, path: str = "params") -> dict[str, Any]:
        if not isinstance(value, dict):
            raise _bad(path, "expected object")
        unknown = set(value) - set(self.fields)
        if unknown:
            raise _bad(path, "unknown keys")
        out: dict[str, Any] = {}
        for name, field in self.fields.items():
            if name not in value:
                if name in self.optional:
                    continue
                raise _bad(f"{path}.{name}", "missing")
            out[name] = field.validate(value[name], f"{path}.{name}")
        return out


EMPTY = Obj({})
