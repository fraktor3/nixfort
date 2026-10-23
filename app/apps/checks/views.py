from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.core.rbac import Perm, has_perm, perm_required
from apps.execution import services as job_services
from apps.execution.models import JobType

from . import domain
from .models import AuditRun, CheckResult


@perm_required(Perm.VIEW_PROJECT)
def run_list(request, project_id):
    runs = AuditRun.objects.filter(project=request.project).select_related("initiated_by")[:30]
    return render(
        request,
        "checks/run_list.html",
        {
            "project": request.project,
            "runs": runs,
            "catalog": domain.CATALOG,
            "can_run": has_perm(request.user, Perm.RUN_JOBS, request.project) and not request.project.is_archived,
        },
    )


@require_POST
@perm_required(Perm.RUN_JOBS)
def run_start(request, project_id):
    job = job_services.create_job(
        JobType.AUDIT, request.project, request.user, params={"purpose": "baseline"}, request=request
    )
    return redirect("execution:job_detail", project_id=project_id, job_id=job.id)


@perm_required(Perm.VIEW_PROJECT)
def run_detail(request, project_id, run_id):
    run = get_object_or_404(AuditRun, id=run_id, project=request.project)
    results = list(run.results.select_related("node"))
    nodes = sorted({r.node for r in results}, key=lambda n: n.name)
    grid = {(r.node_id, r.check_id): r for r in results}
    rows = []
    for check in domain.CATALOG:
        cells = [grid.get((n.id, check.id)) for n in nodes]
        if all(c is None or c.status == "NOT_APPLICABLE" for c in cells):
            continue
        rows.append({"check": check, "cells": cells})
    return render(
        request,
        "checks/run_detail.html",
        {
            "project": request.project,
            "run": run,
            "nodes": nodes,
            "rows": rows,
            "total": run.summary.get("total", {}),
            "can_plan": has_perm(request.user, Perm.CREATE_PLAN, request.project) and not request.project.is_archived,
        },
    )


@perm_required(Perm.VIEW_PROJECT)
def result_detail(request, project_id, run_id, result_id):
    res = get_object_or_404(
        CheckResult.objects.select_related("node", "audit_run"),
        id=result_id,
        audit_run_id=run_id,
        audit_run__project=request.project,
    )
    return render(
        request,
        "checks/result_detail.html",
        {"project": request.project, "r": res, "check": res.definition, "evidence": res.evidence.all()},
    )
