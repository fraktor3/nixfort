"""Inventory domain services (used by views and by other modules)."""

from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from apps.core import audit
from apps.core.models import Action

from .models import HostKey, Node


def node_operational_status(node: Node) -> str:
    if node.confirmed_hostkey is None:
        return Node.Status.KEY_PENDING
    return node.status if node.status != Node.Status.KEY_PENDING else Node.Status.READY


@transaction.atomic
def set_hostkey(node: Node, data: dict, user, request=None, source: str = "manual") -> HostKey:
    """Store a new (unconfirmed) host key. Any change resets confirmation -> operations blocked."""
    hk = HostKey.objects.select_for_update().filter(node=node).first()
    if hk and hk.fingerprint_sha256 == data["fingerprint_sha256"]:
        return hk
    if hk:
        hk.delete()
    hk = HostKey.objects.create(node=node, source=source, **data)
    node.status = Node.Status.KEY_PENDING
    node.save(update_fields=["status", "updated_at"])
    audit.log(
        user,
        Action.HOSTKEY_ADDED,
        obj=node,
        project=node.project,
        request=request,
        fingerprint=hk.fingerprint_sha256,
        source=source,
    )
    return hk


@transaction.atomic
def confirm_hostkey(node: Node, user, request=None) -> HostKey:
    hk = HostKey.objects.select_for_update().get(node=node)
    hk.confirmed_by = user
    hk.confirmed_at = timezone.now()
    hk.save(update_fields=["confirmed_by", "confirmed_at", "updated_at"])
    node.status = Node.Status.READY
    node.save(update_fields=["status", "updated_at"])
    audit.log(
        user,
        Action.HOSTKEY_CONFIRMED,
        obj=node,
        project=node.project,
        request=request,
        fingerprint=hk.fingerprint_sha256,
    )
    return hk
