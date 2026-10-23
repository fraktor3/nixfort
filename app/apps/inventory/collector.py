"""Inventory collection through the node agent. Produces immutable InventorySnapshot records."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from django.utils import timezone

from apps.core import audit
from apps.core.models import Action, Outcome
from apps.execution.agent_client import AgentResponse, client_for
from apps.execution.transport import TransportError

from .models import InventorySnapshot, Node

# fact key -> agent action
ACTION_OF = {
    "system": "system.collect_facts.v1",
    "listeners": "system.collect_listeners.v1",
    "ssh": "ssh.read_effective_config.v1",
    "fail2ban": "fail2ban.read_status.v1",
    "nft": "nft.inspect.v1",
    "suricata": "suricata.read_status.v1",
}

MANAGED_ROLES = {"gateway", "server", "ids_sensor"}


def fact_keys_for(node: Node) -> list[str]:
    roles = set(node.roles or [])
    keys = ["system"]
    if roles & MANAGED_ROLES:
        keys += ["listeners", "ssh"]
    if "server" in roles:
        keys.append("fail2ban")
    if "gateway" in roles:
        keys.append("nft")
    if "ids_sensor" in roles:
        keys.append("suricata")
    return keys


TRANSPORT_STATUS = {
    "unreachable": Node.Status.UNREACHABLE,
    "timeout": Node.Status.UNREACHABLE,
    "host_key_mismatch": Node.Status.KEY_PENDING,
    "host_key_not_confirmed": Node.Status.KEY_PENDING,
}


def _sha(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def collect_node(node: Node, job=None, log=None) -> InventorySnapshot:
    """Run all read actions applicable to the node. Never raises for node-side problems:
    failures are recorded per action, so that checks become ERROR/UNKNOWN, never PASS."""
    facts: dict[str, Any] = {}
    agent_version = ""
    try:
        client = client_for(node)
    except TransportError as exc:
        client = None
        transport_error = exc.code
    else:
        transport_error = None
    for key in fact_keys_for(node):
        if client is None or transport_error:
            resp = AgentResponse(action=ACTION_OF[key], state="TRANSPORT_ERROR", error_code=transport_error)
        else:
            resp = client.call(ACTION_OF[key], {}, deadline_s=150 if key == "suricata" else 60)
            if resp.state == "TRANSPORT_ERROR":
                transport_error = resp.error_code  # no point in trying the remaining actions
        fact = resp.as_fact()
        fact["collected_at"] = timezone.now().isoformat()
        facts[key] = fact
        agent_version = resp.agent_version or agent_version
        if log:
            log(f"{node.name}: {ACTION_OF[key]} → {resp.state}" + (f" ({resp.error_code})" if resp.error_code else ""))
    snap = InventorySnapshot.objects.create(
        node=node,
        job=job,
        collected_at=timezone.now(),
        facts=facts,
        agent_version=agent_version[:20],
        sha256=_sha(facts),
    )
    _update_node_status(node, facts, transport_error, job)
    return snap


def _update_node_status(node: Node, facts: dict, transport_error: str | None, job) -> None:
    if transport_error:
        status = TRANSPORT_STATUS.get(transport_error, Node.Status.UNREACHABLE)
        if transport_error == "host_key_mismatch":
            audit.log(
                job.requested_by if job else None,
                Action.HOSTKEY_MISMATCH,
                obj=node,
                project=node.project_id,
                outcome=Outcome.DENIED,
                node=node.name,
            )
    else:
        system = facts.get("system", {})
        if system.get("state") == "OK" and not system.get("result", {}).get("os_supported", False):
            status = Node.Status.UNSUPPORTED
        else:
            status = Node.Status.READY
    node.status = status
    fields = ["status", "updated_at"]
    if not transport_error:
        node.last_inventory_at = timezone.now()
        fields.append("last_inventory_at")
    node.save(update_fields=fields)


def latest_snapshot(node: Node, max_age_s: int | None = None) -> InventorySnapshot | None:
    snap = node.snapshots.order_by("-collected_at").first()
    if snap and max_age_s is not None and (timezone.now() - snap.collected_at).total_seconds() > max_age_s:
        return None
    return snap
