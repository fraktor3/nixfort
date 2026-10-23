"""Single entry point for writing the audit journal."""

from __future__ import annotations

from typing import Any

from django.http import HttpRequest

from .models import Action, AuditEvent, Outcome
from .redact import redact


def client_ip(request: HttpRequest | None) -> str | None:
    if request is None:
        return None
    # nginx sets X-Real-IP; only trust it because web is reachable only through nginx.
    ip = request.META.get("HTTP_X_REAL_IP") or request.META.get("REMOTE_ADDR")
    return ip or None


def log(
    actor,
    action: Action | str,
    obj: Any = None,
    project=None,
    outcome: Outcome | str = Outcome.SUCCESS,
    request: HttpRequest | None = None,
    **meta: Any,
) -> AuditEvent:
    user = actor if getattr(actor, "is_authenticated", False) else None
    project_id = getattr(project, "id", project)
    return AuditEvent.objects.create(
        actor=user,
        actor_name=(user.get_username() if user else str(meta.pop("actor_name", "") or "система"))[:150],
        action=str(action),
        object_type=obj.__class__.__name__ if obj is not None else "",
        object_id=str(getattr(obj, "pk", "") or "")[:64],
        project_id=project_id,
        outcome=str(outcome),
        ip=client_ip(request),
        safe_metadata=redact(meta),
    )
