"""Page: security-log summary and its history."""

from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST, require_safe

from apps.core.rbac import Perm, has_perm, perm_required
from apps.execution import services as job_services
from apps.execution.models import JobType

from .models import SecuritySummary


@require_safe
@perm_required(Perm.VIEW_PROJECT)
def seclog(request, project_id):
    project = request.project
    selected = None
    if request.GET.get("s"):
        selected = get_object_or_404(SecuritySummary, id=request.GET["s"], project=project)
    else:
        selected = SecuritySummary.objects.filter(project=project, state="DONE").first()
    servers = (selected.data.get("servers") or []) if selected else []
    auth_total = sum(((r.get("auth") or {}).get("total") or 0) for r in servers)
    banned_total = sum(len((r.get("fail2ban") or {}).get("banned_ips") or []) for r in servers)
    return render(request, "seclog/seclog.html", {
        "auth_total": auth_total, "banned_total": banned_total,
        "project": project,
        "s": selected,
        "history": SecuritySummary.objects.filter(project=project)[:15],
        "can_run": has_perm(request.user, Perm.RUN_JOBS, project) and not project.is_archived,
    })  # fmt: skip


@require_POST
@perm_required(Perm.RUN_JOBS)
def refresh(request, project_id):
    job = job_services.create_job(JobType.SECURITY_LOGS, request.project, request.user,
                                  params={"hours": 24}, request=request)  # fmt: skip
    return redirect("execution:job_detail", project_id=project_id, job_id=job.id)
