"""Role-based access control (ARCHITECTURE §9). All checks run on the server."""

from __future__ import annotations

import enum
from functools import wraps

from django.core.exceptions import PermissionDenied
from django.db.models import TextChoices
from django.http import Http404


class Role(TextChoices):
    ADMIN = "ADMIN", "Администратор"
    OPERATOR = "OPERATOR", "Оператор"
    VIEWER = "VIEWER", "Наблюдатель"


class Perm(enum.StrEnum):
    VIEW_PROJECT = "view_project"
    EDIT_PROJECT = "edit_project"  # project, nodes, policy drafts
    CREATE_PROJECT = "create_project"
    ACTIVATE_POLICY = "activate_policy"
    CONFIRM_HOSTKEY = "confirm_hostkey"
    RUN_JOBS = "run_jobs"  # inventory, scan, audit, pcap, ids
    CREATE_PLAN = "create_plan"
    APPROVE_PLAN = "approve_plan"  # approve AND execute a remediation plan
    EXPORT_REPORT = "export_report"
    MANAGE_USERS = "manage_users"
    VIEW_GLOBAL_AUDIT = "view_global_audit"


ROLE_PERMS: dict[str, frozenset[Perm]] = {
    Role.ADMIN: frozenset(Perm),
    Role.OPERATOR: frozenset(
        {
            Perm.VIEW_PROJECT,
            Perm.EDIT_PROJECT,
            Perm.CREATE_PROJECT,
            Perm.RUN_JOBS,
            Perm.CREATE_PLAN,
            Perm.EXPORT_REPORT,
        }
    ),
    Role.VIEWER: frozenset({Perm.VIEW_PROJECT, Perm.EXPORT_REPORT}),
}

READ_ONLY_PERMS = frozenset({Perm.VIEW_PROJECT, Perm.EXPORT_REPORT})

# Permissions that only make sense globally (not inside one project).
GLOBAL_ONLY = frozenset({Perm.CREATE_PROJECT, Perm.MANAGE_USERS, Perm.VIEW_GLOBAL_AUDIT})


def roles_of(user, project=None) -> set[str]:
    if not getattr(user, "is_authenticated", False) or not user.is_active:
        return set()
    from apps.accounts.models import RoleAssignment

    qs = RoleAssignment.objects.filter(user=user)
    project_id = getattr(project, "id", project)
    if project_id is None:
        qs = qs.filter(project__isnull=True)
    else:
        from django.db.models import Q

        qs = qs.filter(Q(project__isnull=True) | Q(project_id=project_id))
    return set(qs.values_list("role", flat=True))


def has_perm(user, perm: Perm, project=None) -> bool:
    if perm in GLOBAL_ONLY:
        project = None
    return any(perm in ROLE_PERMS.get(r, frozenset()) for r in roles_of(user, project))


def require(user, perm: Perm, project=None, request=None) -> None:
    if has_perm(user, perm, project):
        return
    from . import audit
    from .models import Action, Outcome

    audit.log(user, Action.ACCESS_DENIED, project=project, outcome=Outcome.DENIED, request=request, perm=str(perm))
    raise PermissionDenied


def visible_projects(user):
    """Projects the user may see. Global role -> all; otherwise only assigned ones."""
    from apps.inventory.models import Project

    if not getattr(user, "is_authenticated", False):
        return Project.objects.none()
    from apps.accounts.models import RoleAssignment

    ras = RoleAssignment.objects.filter(user=user)
    if ras.filter(project__isnull=True).exists():
        return Project.objects.all()
    return Project.objects.filter(id__in=ras.values("project_id"))


def get_project_or_404(user, project_id):
    """Objects of a project the user cannot see are reported as 404, not 403 (no existence leak)."""
    try:
        return visible_projects(user).get(id=project_id)
    except Exception as exc:  # DoesNotExist, ValidationError on bad UUID
        raise Http404 from exc


def perm_required(perm: Perm, project_kwarg: str | None = "project_id"):
    """View decorator: resolves the project from URL kwargs (404 if invisible), then checks perm."""

    def deco(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            project = None
            if project_kwarg and project_kwarg in kwargs:
                project = get_project_or_404(request.user, kwargs[project_kwarg])
                request.project = project
                if getattr(project, "is_archived", False) and perm not in READ_ONLY_PERMS:
                    raise PermissionDenied("Проект в архиве: изменения запрещены.")
            require(request.user, perm, project, request=request)
            return view(request, *args, **kwargs)

        return wrapper

    return deco
