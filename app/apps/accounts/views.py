"""Pages: users list, new user, user card (roles, enable and disable). Sign-in is Django's LoginView (urls.py)."""

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST, require_safe

from apps.core import audit
from apps.core.models import Action
from apps.core.rbac import Perm, Role, perm_required

from .forms import RoleAssignForm, UserCreateForm
from .models import RoleAssignment


@require_safe
@perm_required(Perm.MANAGE_USERS, project_kwarg=None)
def user_list(request):
    users = get_user_model().objects.order_by("username").prefetch_related("role_assignments__project")
    return render(request, "accounts/user_list.html", {"users": users})


@perm_required(Perm.MANAGE_USERS, project_kwarg=None)
def user_create(request):
    form = UserCreateForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        d = form.cleaned_data
        with transaction.atomic():
            user = get_user_model()(username=d["username"])
            user.set_password(d["password1"])
            user.save()
            RoleAssignment.objects.create(user=user, role=d["role"], project=d["project"], granted_by=request.user)
            audit.log(
                request.user,
                Action.USER_CREATED,
                obj=user,
                project=d["project"],
                request=request,
                username=user.username,
                role=d["role"],
            )
        messages.success(request, f"Пользователь {user.username} создан.")
        return redirect("accounts:user_detail", user_id=user.pk)
    return render(request, "accounts/user_form.html", {"form": form})


@perm_required(Perm.MANAGE_USERS, project_kwarg=None)
def user_detail(request, user_id):
    user = get_object_or_404(get_user_model(), pk=user_id)
    form = RoleAssignForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        d = form.cleaned_data
        try:
            with transaction.atomic():
                ra = RoleAssignment.objects.create(
                    user=user, role=d["role"], project=d["project"], granted_by=request.user
                )
                audit.log(
                    request.user,
                    Action.ROLE_GRANTED,
                    obj=ra,
                    project=d["project"],
                    request=request,
                    username=user.username,
                    role=d["role"],
                )
            messages.success(request, "Роль назначена.")
        except IntegrityError:
            messages.error(request, "У пользователя уже есть роль в этой области. Сначала снимите её.")
        return redirect("accounts:user_detail", user_id=user.pk)
    return render(
        request,
        "accounts/user_detail.html",
        {"u": user, "form": form, "roles": user.role_assignments.select_related("project")},
    )


@require_POST
@perm_required(Perm.MANAGE_USERS, project_kwarg=None)
def role_revoke(request, user_id, ra_id):
    ra = get_object_or_404(RoleAssignment, pk=ra_id, user_id=user_id)
    if ra.user_id == request.user.pk and ra.role == Role.ADMIN and ra.project_id is None:
        messages.error(request, "Нельзя снять глобальную роль администратора с самого себя.")
        return redirect("accounts:user_detail", user_id=user_id)
    audit.log(
        request.user,
        Action.ROLE_REVOKED,
        obj=ra,
        project=ra.project_id,
        request=request,
        username=ra.user.username,
        role=ra.role,
    )
    ra.delete()
    messages.success(request, "Роль снята.")
    return redirect("accounts:user_detail", user_id=user_id)


@require_POST
@perm_required(Perm.MANAGE_USERS, project_kwarg=None)
def user_toggle_active(request, user_id):
    user = get_object_or_404(get_user_model(), pk=user_id)
    if user.pk == request.user.pk:
        messages.error(request, "Нельзя отключить собственную учётную запись.")
    else:
        user.is_active = not user.is_active
        user.save(update_fields=["is_active"])
        audit.log(
            request.user,
            Action.USER_UPDATED,
            obj=user,
            request=request,
            username=user.username,
            is_active=user.is_active,
        )
        messages.success(request, "Статус учётной записи изменён.")
    return redirect("accounts:user_detail", user_id=user_id)
