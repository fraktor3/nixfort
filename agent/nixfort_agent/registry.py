"""Allowlist of actions. Only what is registered here can ever run."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .context import Context
from .schema import Obj

Handler = Callable[[Context, dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class Action:
    name: str
    params: Obj
    handler: Handler
    mutating: bool
    needs_supported_os: bool


REGISTRY: dict[str, Action] = {}


def action(name: str, params: Obj, mutating: bool = False, needs_supported_os: bool | None = None):
    def deco(fn: Handler) -> Handler:
        if name in REGISTRY:
            raise RuntimeError(f"duplicate action {name}")
        REGISTRY[name] = Action(
            name=name,
            params=params,
            handler=fn,
            mutating=mutating,
            needs_supported_os=mutating if needs_supported_os is None else needs_supported_os,
        )
        return fn

    return deco


def load_all() -> dict[str, Action]:
    # Importing the modules registers their actions.
    from .actions import fail2ban, net, nft, ssh, suricata, system  # noqa: F401

    return REGISTRY
