from django.contrib import messages
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.checks.models import AuditRun
from apps.core import audit
from apps.core.models import Action
from apps.core.rbac import Perm, has_perm, perm_required
from apps.execution import services as job_services
from apps.execution.models import JobType

from . import planner
from .models import PlanState, RemediationPlan


@perm_required(Perm.VIEW_PROJECT)
def plan_list(request, project_id):
    plans = RemediationPlan.objects.filter(project=request.project).select_related("created_by", "approved_by")[:50]
    return render(request, "remediation/plan_list.html", {"project": request.project, "plans": plans})


@require_POST
@perm_required(Perm.CREATE_PLAN)
def plan_create(request, project_id, run_id):
    run = get_object_or_404(AuditRun, id=run_id, project=request.project)
    key_only = request.POST.get("key_only_confirmed") == "on"
    plan = planner.create_plan(run, request.user, key_only, request=request)
    if not plan.items.exists():
        messages.info(request, "Автоматически исправимых нарушений нет. Остальное — в списке «не покрыто».")
    return redirect("remediation:plan_detail", project_id=project_id, plan_id=plan.id)


@perm_required(Perm.VIEW_PROJECT)
def plan_detail(request, project_id, plan_id):
    plan = get_object_or_404(
        RemediationPlan.objects.select_related("audit_run", "post_audit_run", "job"),
        id=plan_id,
        project=request.project,
    )
    items = plan.items.select_related("node")
    before_after = _before_after(plan)
    return render(
        request,
        "remediation/plan_detail.html",
        {
            "project": request.project,
            "plan": plan,
            "items": items,
            "before_after": before_after,
            "can_approve": has_perm(request.user, Perm.APPROVE_PLAN, request.project)
            and plan.state == PlanState.DRAFT
            and items.exists()
            and not request.project.is_archived,
            "can_reject": has_perm(request.user, Perm.CREATE_PLAN, request.project) and plan.state == PlanState.DRAFT,
        },
    )


def _before_after(plan):
    if not plan.post_audit_run_id:
        return []
    before = {(r.node_id, r.check_id): r for r in plan.audit_run.results.select_related("node")}
    rows = []
    for r in plan.post_audit_run.results.select_related("node").order_by("node__name", "check_id"):
        b = before.get((r.node_id, r.check_id))
        if r.status == "NOT_APPLICABLE" and (not b or b.status == "NOT_APPLICABLE"):
            continue
        rows.append(
            {
                "node": r.node.name,
                "check_id": r.check_id,
                "before": b.status if b else "—",
                "after": r.status,
                "changed": (b.status if b else None) != r.status,
                "title": r.definition.title,
            }
        )
    return rows


@require_POST
@perm_required(Perm.APPROVE_PLAN)
def plan_approve(request, project_id, plan_id):
    with transaction.atomic():
        plan = get_object_or_404(RemediationPlan.objects.select_for_update(), id=plan_id, project=request.project)
        if plan.state != PlanState.DRAFT:
            messages.error(request, "План уже утверждён, отклонён или выполнен.")
            return redirect("remediation:plan_detail", project_id=project_id, plan_id=plan_id)
        if request.POST.get("confirm") != "on":
            messages.error(request, "Подтвердите, что ознакомились с планом и рисками.")
            return redirect("remediation:plan_detail", project_id=project_id, plan_id=plan_id)
        items = list(plan.items.all())
        plan.plan_hash = planner.plan_hash(items)
        plan.state = PlanState.APPROVED
        plan.approved_by = request.user
        plan.approved_at = timezone.now()
        plan.save(update_fields=["plan_hash", "state", "approved_by", "approved_at", "updated_at"])
        audit.log(
            request.user,
            Action.PLAN_APPROVED,
            obj=plan,
            project=request.project,
            request=request,
            plan_hash=plan.plan_hash,
            items=len(items),
            risk=plan.risk,
        )
        job = job_services.create_job(
            JobType.PLAN_EXECUTE, request.project, request.user, params={"plan_id": str(plan.id)}, request=request
        )
        plan.job = job
        plan.save(update_fields=["job", "updated_at"])
    return redirect("execution:job_detail", project_id=project_id, job_id=job.id)


@require_POST
@perm_required(Perm.CREATE_PLAN)
def plan_reject(request, project_id, plan_id):
    plan = get_object_or_404(RemediationPlan, id=plan_id, project=request.project, state=PlanState.DRAFT)
    plan.state = PlanState.REJECTED
    plan.save(update_fields=["state", "updated_at"])
    audit.log(request.user, Action.PLAN_REJECTED, obj=plan, project=request.project, request=request)
    return redirect("remediation:plan_list", project_id=project_id)
