from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.core import audit
from apps.core.models import Action
from apps.core.rbac import Perm, has_perm, perm_required

from . import services
from .forms import FlowForm
from .models import Flow, FlowPolicyVersion


@perm_required(Perm.VIEW_PROJECT)
def policy_overview(request, project_id):
    project = request.project
    versions = FlowPolicyVersion.objects.filter(project=project)
    draft = versions.filter(status="DRAFT").first()
    active = versions.filter(status="ACTIVE").first()
    shown = draft if request.GET.get("show") != "active" and draft else active
    ctx = {
        "project": project,
        "versions": versions,
        "draft": draft,
        "active": active,
        "shown": shown,
        "flows": shown.flows.select_related("dst_node", "probe_from") if shown else [],
        "conflicts": services.find_conflicts(shown) if shown else [],
        "can_edit": has_perm(request.user, Perm.EDIT_PROJECT, project) and not project.is_archived,
        "can_activate": has_perm(request.user, Perm.ACTIVATE_POLICY, project) and not project.is_archived,
    }
    return render(request, "policy/overview.html", ctx)


@require_POST
@perm_required(Perm.EDIT_PROJECT)
def draft_create(request, project_id):
    services.get_or_create_draft(request.project, request.user, request)
    messages.success(request, "Черновик политики готов к редактированию.")
    return redirect("policy:overview", project_id=project_id)


@perm_required(Perm.EDIT_PROJECT)
def flow_edit(request, project_id, flow_id=None):
    project = request.project
    draft = services.get_or_create_draft(project, request.user, request)
    flow = get_object_or_404(Flow, id=flow_id, policy_version=draft) if flow_id else None
    form = FlowForm(request.POST or None, instance=flow, project=project, policy_version=draft)
    if request.method == "POST" and form.is_valid():
        f = form.save()
        audit.log(
            request.user,
            Action.POLICY_UPDATED,
            obj=f,
            project=project,
            request=request,
            version=draft.version,
            flow=str(f),
        )
        messages.success(request, "Поток сохранён.")
        return redirect("policy:overview", project_id=project_id)
    return render(request, "policy/flow_form.html", {"project": project, "form": form, "draft": draft})


@require_POST
@perm_required(Perm.EDIT_PROJECT)
def flow_delete(request, project_id, flow_id):
    flow = get_object_or_404(Flow, id=flow_id, policy_version__project=request.project, policy_version__status="DRAFT")
    audit.log(
        request.user, Action.POLICY_UPDATED, obj=flow, project=request.project, request=request, deleted=str(flow)
    )
    flow.delete()
    messages.success(request, "Поток удалён из черновика.")
    return redirect("policy:overview", project_id=project_id)


@require_POST
@perm_required(Perm.ACTIVATE_POLICY)
def activate(request, project_id):
    draft = FlowPolicyVersion.objects.filter(project=request.project, status="DRAFT").first()
    if not draft:
        messages.error(request, "Нет черновика.")
    else:
        try:
            services.activate(draft, request.user, request)
            messages.success(request, f"Политика v{draft.version} активирована.")
        except services.PolicyError as exc:
            messages.error(request, str(exc))
    return redirect("policy:overview", project_id=project_id)


# ---------------------------------------------------------------- connectivity (TCP probes of the flows)
from apps.execution import services as job_services  # noqa: E402
from apps.execution.models import Job, JobType  # noqa: E402

from .models import ConnectivityTest  # noqa: E402


@perm_required(Perm.VIEW_PROJECT)
def connectivity(request, project_id):
    project = request.project
    jobs = Job.objects.filter(project=project, type=JobType.CONNECTIVITY).order_by("-created_at")[:10]
    selected = None
    if request.GET.get("job"):
        selected = get_object_or_404(Job, id=request.GET["job"], project=project, type=JobType.CONNECTIVITY)
    elif jobs:
        selected = jobs[0]
    rows = list(ConnectivityTest.objects.filter(job=selected)) if selected else []
    return render(
        request,
        "policy/connectivity.html",
        {
            "project": project,
            "jobs": jobs,
            "selected": selected,
            "rows": rows,
            "active": FlowPolicyVersion.objects.filter(project=project, status="ACTIVE").first(),
            "can_run": has_perm(request.user, Perm.RUN_JOBS, project) and not project.is_archived,
        },
    )


@require_POST
@perm_required(Perm.RUN_JOBS)
def connectivity_run(request, project_id):
    job = job_services.create_job(JobType.CONNECTIVITY, request.project, request.user, request=request)
    return redirect("execution:job_detail", project_id=project_id, job_id=job.id)
