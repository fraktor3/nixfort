from django.contrib.auth.decorators import login_not_required
from django.core.paginator import Paginator
from django.db import connection
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET

from .models import Action, AuditEvent
from .rbac import Perm, has_perm, visible_projects


@login_not_required
@require_GET
def healthz(request):
    try:
        with connection.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
    except Exception:  # noqa: BLE001 - health endpoint must not raise
        return JsonResponse({"status": "db_unavailable"}, status=503)
    return JsonResponse({"status": "ok"})


def dashboard(request):
    from apps.execution.models import Job

    projects = visible_projects(request.user).order_by("name")
    jobs = Job.objects.filter(project__in=projects).select_related("project").order_by("-created_at")[:10]
    return render(request, "core/dashboard.html", {"projects": projects, "jobs": jobs})


def audit_log(request):
    projects = visible_projects(request.user)
    qs = AuditEvent.objects.all()
    if not has_perm(request.user, Perm.VIEW_GLOBAL_AUDIT):
        qs = qs.filter(project_id__in=projects.values("id"))
    action = request.GET.get("action", "")
    if action in Action.values:
        qs = qs.filter(action=action)
    actor = request.GET.get("actor", "").strip()[:150]
    if actor:
        qs = qs.filter(actor_name__icontains=actor)
    page = Paginator(qs.order_by("-ts"), 50).get_page(request.GET.get("page"))
    return render(
        request,
        "core/audit_log.html",
        {"page": page, "actions": Action.choices, "sel_action": action, "actor": actor},
    )
