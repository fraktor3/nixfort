from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.core.rbac import Perm, has_perm, perm_required

from . import services
from .models import Job, JobType


@perm_required(Perm.VIEW_PROJECT)
def job_list(request, project_id):
    jobs = Job.objects.filter(project=request.project).select_related("node", "requested_by")[:100]
    can_run = has_perm(request.user, Perm.RUN_JOBS, request.project) and not request.project.is_archived
    return render(request, "execution/job_list.html", {"project": request.project, "jobs": jobs, "can_run": can_run})


@perm_required(Perm.VIEW_PROJECT)
def job_detail(request, project_id, job_id):
    job = get_object_or_404(Job.objects.select_related("node", "requested_by"), id=job_id, project=request.project)
    tpl = "execution/_job_status.html" if request.headers.get("HX-Request") else "execution/job_detail.html"
    return render(request, tpl, {"project": request.project, "job": job, "logs": job.logs.all()[:500]})


@require_POST
@perm_required(Perm.RUN_JOBS)
def noop_create(request, project_id):
    job = services.create_job(JobType.NOOP_TEST, request.project, request.user, params={"seconds": 5}, request=request)
    messages.info(request, "Тестовое задание поставлено в очередь.")
    return redirect("execution:job_detail", project_id=project_id, job_id=job.id)
