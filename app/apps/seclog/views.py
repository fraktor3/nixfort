from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.core.rbac import Perm, has_perm, perm_required
from apps.execution import services as job_services
from apps.execution.models import JobType

from .models import SecuritySummary


@perm_required(Perm.VIEW_PROJECT)
def seclog(request, project_id):
    project = request.project
    selected = None
    if request.GET.get("s"):
        selected = get_object_or_404(SecuritySummary, id=request.GET["s"], project=project)
    else:
        selected = SecuritySummary.objects.filter(project=project, state="DONE").first()
    return render(request, "seclog/seclog.html", {
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
