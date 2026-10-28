from django.contrib import messages
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from apps.core import audit
from apps.core.models import Action
from apps.core.rbac import Perm, has_perm, perm_required, require, visible_projects
from apps.execution import services as job_services
from apps.execution.models import JobType

from . import services
from .forms import HostKeyForm, NodeForm, ProjectForm
from .models import HostKey, Node, PortScan, Project


def project_list(request):
    projects = visible_projects(request.user).order_by("status", "name")
    return render(request, "inventory/project_list.html", {"projects": projects})


@perm_required(Perm.CREATE_PROJECT, project_kwarg=None)
def project_create(request):
    form = ProjectForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            project = form.save(commit=False)
            project.created_by = request.user
            project.save()
            audit.log(
                request.user,
                Action.PROJECT_CREATED,
                obj=project,
                project=project,
                request=request,
                name=project.name,
                cidrs=project.cidrs,
            )
        messages.success(request, "Проект создан.")
        return redirect("inventory:project_detail", project_id=project.id)
    return render(request, "inventory/project_form.html", {"form": form})


@perm_required(Perm.VIEW_PROJECT)
def project_detail(request, project_id):
    from apps.checks.models import AuditRun
    from apps.execution.models import Job
    from apps.ids.models import ProtectionTest
    from apps.policy.models import FlowPolicyVersion
    from apps.reports.models import Report
    from apps.seclog.models import SecuritySummary

    from . import overview

    project = request.project
    nodes = list(project.nodes.filter(is_active=True).select_related("hostkey").order_by("name"))
    active_policy = FlowPolicyVersion.objects.filter(project=project, status=FlowPolicyVersion.Status.ACTIVE).first()
    jobs = Job.objects.filter(project=project).select_related("node").order_by("-created_at")[:8]
    runs = list(AuditRun.objects.filter(project=project, state="DONE").order_by("-created_at"))
    plans = list(project.plans.order_by("-created_at")[:1])
    latest_tests = {}
    for t in ProtectionTest.objects.filter(project=project).order_by("-created_at")[:40]:
        latest_tests.setdefault(t.scenario, t)
    protection = list(latest_tests.values())
    summary = SecuritySummary.objects.filter(project=project, state="DONE").order_by("-created_at").first()
    report = Report.objects.filter(project=project).order_by("-created_at").first()
    latest, first = (runs[0], runs[-1]) if runs else (None, None)
    steps = overview.cycle(project, nodes, runs, plans, protection, summary, report)
    can_run = has_perm(request.user, Perm.RUN_JOBS, project) and not project.is_archived
    matrix = overview.defence_matrix(project, nodes, latest, first)
    ctx = {
        "project": project,
        "nodes": nodes,
        "active_policy": active_policy,
        "flows": active_policy.flows.order_by("port") if active_policy else [],
        "jobs": jobs,
        "steps": steps,
        "action": overview.next_action(project, steps, nodes, runs, plans) if can_run else None,
        "matrix": matrix,
        "latest_run": latest,
        "first_run": first if first and latest and first.id != latest.id else None,
        "finding": overview.finding(latest, nodes),
        "scheme": overview.segment_svg(project, nodes, overview.node_states(matrix)),
        "protection": sorted(protection, key=lambda t: t.scenario),
        "can_edit": has_perm(request.user, Perm.EDIT_PROJECT, project) and not project.is_archived,
        "can_run": can_run,
        "is_admin": has_perm(request.user, Perm.APPROVE_PLAN, project),
        "archive_url": reverse("inventory:project_archive", args=[project.id]),
    }
    return render(request, "inventory/project_detail.html", ctx)


@perm_required(Perm.EDIT_PROJECT)
def project_edit(request, project_id):
    project = request.project
    form = ProjectForm(request.POST or None, instance=project)
    if request.method == "POST" and form.is_valid():
        form.save()
        audit.log(
            request.user,
            Action.PROJECT_UPDATED,
            obj=project,
            project=project,
            request=request,
            changed=form.changed_data,
        )
        messages.success(request, "Проект сохранён.")
        return redirect("inventory:project_detail", project_id=project.id)
    return render(request, "inventory/project_form.html", {"form": form, "project": project})


@require_POST
@perm_required(Perm.APPROVE_PLAN)
def project_archive(request, project_id):
    project = request.project
    project.status = Project.Status.ARCHIVED
    project.save(update_fields=["status", "updated_at"])
    audit.log(request.user, Action.PROJECT_ARCHIVED, obj=project, project=project, request=request)
    messages.success(request, "Проект перенесён в архив.")
    return redirect("inventory:project_detail", project_id=project.id)


@perm_required(Perm.EDIT_PROJECT)
def node_create(request, project_id):
    project = request.project
    form = NodeForm(request.POST or None, project=project)
    if request.method == "POST" and form.is_valid():
        node = form.save()
        audit.log(
            request.user,
            Action.NODE_CREATED,
            obj=node,
            project=project,
            request=request,
            name=node.name,
            mgmt_ip=node.mgmt_ip,
            roles=node.roles,
        )
        messages.success(request, "Узел добавлен. Теперь добавьте и подтвердите его SSH-ключ.")
        return redirect("inventory:node_detail", project_id=project.id, node_id=node.id)
    return render(request, "inventory/node_form.html", {"form": form, "project": project})


def _node(request, node_id) -> Node:
    return get_object_or_404(Node.objects.select_related("project"), id=node_id, project=request.project)


@perm_required(Perm.VIEW_PROJECT)
def node_detail(request, project_id, node_id):
    node = _node(request, node_id)
    snapshot = node.snapshots.first()
    ctx = {
        "project": request.project,
        "node": node,
        "hostkey": HostKey.objects.filter(node=node).first(),
        "snapshot": snapshot,
        "can_edit": has_perm(request.user, Perm.EDIT_PROJECT, request.project),
        "can_confirm": has_perm(request.user, Perm.CONFIRM_HOSTKEY, request.project),
        "can_run": has_perm(request.user, Perm.RUN_JOBS, request.project),
        "hostkey_form": HostKeyForm(),
    }
    return render(request, "inventory/node_detail.html", ctx)


@perm_required(Perm.EDIT_PROJECT)
def node_edit(request, project_id, node_id):
    node = _node(request, node_id)
    form = NodeForm(request.POST or None, instance=node, project=request.project)
    if request.method == "POST" and form.is_valid():
        form.save()
        audit.log(
            request.user,
            Action.NODE_UPDATED,
            obj=node,
            project=request.project,
            request=request,
            changed=form.changed_data,
        )
        messages.success(request, "Узел сохранён.")
        return redirect("inventory:node_detail", project_id=project_id, node_id=node.id)
    return render(request, "inventory/node_form.html", {"form": form, "project": request.project, "node": node})


@require_POST
@perm_required(Perm.EDIT_PROJECT)
def node_deactivate(request, project_id, node_id):
    node = _node(request, node_id)
    node.is_active = False
    node.save(update_fields=["is_active", "updated_at"])
    audit.log(request.user, Action.NODE_DEACTIVATED, obj=node, project=request.project, request=request)
    messages.success(request, "Узел отключён (история сохранена).")
    return redirect("inventory:project_detail", project_id=project_id)


@require_POST
@perm_required(Perm.EDIT_PROJECT)
def hostkey_set(request, project_id, node_id):
    node = _node(request, node_id)
    form = HostKeyForm(request.POST)
    if form.is_valid():
        services.set_hostkey(node, form.cleaned_data["public_key"], request.user, request)
        messages.info(request, "Ключ сохранён. Администратор должен сверить отпечаток и подтвердить его.")
    else:
        messages.error(request, "; ".join(form.errors.get("public_key", ["Ошибка"])))
    return redirect("inventory:node_detail", project_id=project_id, node_id=node.id)


@require_POST
@perm_required(Perm.CONFIRM_HOSTKEY)
def hostkey_confirm(request, project_id, node_id):
    node = _node(request, node_id)
    if not HostKey.objects.filter(node=node).exists():
        messages.error(request, "Сначала добавьте ключ.")
    else:
        require(request.user, Perm.CONFIRM_HOSTKEY, request.project, request)
        services.confirm_hostkey(node, request.user, request)
        messages.success(request, "Ключ подтверждён. Операции с узлом разрешены.")
    return redirect("inventory:node_detail", project_id=project_id, node_id=node.id)


@require_POST
@perm_required(Perm.RUN_JOBS)
def inventory_run(request, project_id, node_id=None):
    node = _node(request, node_id) if node_id else None
    job = job_services.create_job(JobType.INVENTORY, request.project, request.user, node=node, request=request)
    return redirect("execution:job_detail", project_id=project_id, job_id=job.id)


@require_POST
@perm_required(Perm.EDIT_PROJECT)
def hostkey_fetch(request, project_id, node_id):
    node = _node(request, node_id)
    require(request.user, Perm.RUN_JOBS, request.project, request)
    job = job_services.create_job(JobType.FETCH_HOSTKEY, request.project, request.user, node=node, request=request)
    return redirect("execution:job_detail", project_id=project_id, job_id=job.id)


@require_POST
@perm_required(Perm.RUN_JOBS)
def portscan_run(request, project_id):
    from .handlers import nmap_scope_error

    profile = request.POST.get("profile", "common")
    if profile not in ("common", "top100"):
        profile = "common"
    nodes = list(request.project.nodes.filter(is_active=True))
    err = nmap_scope_error(request.project, nodes)
    if err:
        audit.log(
            request.user,
            Action.ACCESS_DENIED,
            project=request.project,
            request=request,
            outcome="DENIED",
            reason=f"nmap_{err}",
        )
        messages.error(request, "Сканирование отклонено: цели вне подсетей проекта или не заданы.")
        return redirect("inventory:portscan_list", project_id=project_id)
    job = job_services.create_job(
        JobType.PORT_SCAN, request.project, request.user, params={"profile": profile}, request=request
    )
    return redirect("execution:job_detail", project_id=project_id, job_id=job.id)


@perm_required(Perm.VIEW_PROJECT)
def portscan_list(request, project_id):
    scans = PortScan.objects.filter(project=request.project)[:20]
    return render(
        request,
        "inventory/portscan_list.html",
        {
            "project": request.project,
            "scans": scans,
            "can_run": has_perm(request.user, Perm.RUN_JOBS, request.project) and not request.project.is_archived,
        },
    )
