"""Flow policy: versioning, conflict detection, activation."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from apps.core import audit
from apps.core.models import Action

from .models import Flow, FlowPolicyVersion


class PolicyError(Exception):
    pass


@dataclass(frozen=True)
class Conflict:
    kind: str  # "contradiction" | "duplicate"
    a: Flow
    b: Flow

    @property
    def message(self) -> str:
        if self.kind == "contradiction":
            return f"Противоречие: «{self.a}» и «{self.b}» — пересекающиеся источники, разные действия."
        return f"Дубликат: «{self.a}» и «{self.b}»."


def find_conflicts(version: FlowPolicyVersion) -> list[Conflict]:
    flows = list(version.flows.all())
    out: list[Conflict] = []
    for i, a in enumerate(flows):
        na = ipaddress.ip_network(a.src_cidr, strict=False)
        for b in flows[i + 1 :]:
            if a.dst_ip != b.dst_ip or a.port != b.port:
                continue
            if not na.overlaps(ipaddress.ip_network(b.src_cidr, strict=False)):
                continue
            out.append(Conflict("contradiction" if a.action != b.action else "duplicate", a, b))
    return out


@transaction.atomic
def get_or_create_draft(project, user, request=None) -> FlowPolicyVersion:
    """Return the project's draft; if none, create it as a copy of the active version."""
    draft = FlowPolicyVersion.objects.select_for_update().filter(project=project, status="DRAFT").first()
    if draft:
        return draft
    last = FlowPolicyVersion.objects.filter(project=project).aggregate(m=Max("version"))["m"] or 0
    draft = FlowPolicyVersion.objects.create(project=project, version=last + 1, author=user)
    active = FlowPolicyVersion.objects.filter(project=project, status="ACTIVE").first()
    if active:
        for f in active.flows.all():
            f.pk = None
            f.id = None
            f._state.adding = True
            f.policy_version = draft
            f.save()
    audit.log(
        user,
        Action.POLICY_VERSION_CREATED,
        obj=draft,
        project=project,
        request=request,
        version=draft.version,
        copied_from=active.version if active else None,
    )
    return draft


@transaction.atomic
def activate(version: FlowPolicyVersion, user, request=None) -> FlowPolicyVersion:
    version = FlowPolicyVersion.objects.select_for_update().get(pk=version.pk)
    if version.status != FlowPolicyVersion.Status.DRAFT:
        raise PolicyError("Активировать можно только черновик.")
    if not version.flows.exists():
        raise PolicyError("Политика пуста.")
    conflicts = [c for c in find_conflicts(version) if c.kind == "contradiction"]
    if conflicts:
        raise PolicyError(conflicts[0].message)
    FlowPolicyVersion.objects.filter(project=version.project, status="ACTIVE").update(status="SUPERSEDED")
    version.status = FlowPolicyVersion.Status.ACTIVE
    version.activated_at = timezone.now()
    version.save(update_fields=["status", "activated_at", "updated_at"])
    audit.log(
        user,
        Action.POLICY_ACTIVATED,
        obj=version,
        project=version.project,
        request=request,
        version=version.version,
        flows=version.flows.count(),
    )
    return version


def active_policy(project) -> FlowPolicyVersion | None:
    return FlowPolicyVersion.objects.filter(project=project, status="ACTIVE").first()
