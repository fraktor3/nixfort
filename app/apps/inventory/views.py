from django.contrib import messages
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.core import audit
from apps.core.models import Action
from apps.core.rbac import Perm, has_perm, perm_required, require, visible_projects

from . import services
from .forms import HostKeyForm, NodeForm, ProjectForm
from .models import HostKey, Node, Project


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
    project = request.project
    nodes = project.nodes.filter(is_active=True).select_related("hostkey")
    from apps.policy.models import FlowPolicyVersion

    active_policy = FlowPolicyVersion.objects.filter(project=project, status=FlowPolicyVersion.Status.ACTIVE).first()
    from apps.execution.models import Job

    jobs = Job.objects.filter(project=project).order_by("-created_at")[:10]
    ctx = {
        "project": project,
        "nodes": nodes,
        "active_policy": active_policy,
        "jobs": jobs,
        "can_edit": has_perm(request.user, Perm.EDIT_PROJECT, project) and not project.is_archived,
        "can_run": has_perm(request.user, Perm.RUN_JOBS, project) and not project.is_archived,
        "is_admin": has_perm(request.user, Perm.APPROVE_PLAN, project),
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
