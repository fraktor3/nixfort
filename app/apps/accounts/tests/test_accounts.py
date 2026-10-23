import pytest
from django.contrib.auth import get_user_model
from django.core.management import CommandError, call_command
from django.urls import reverse

from apps.accounts.models import RoleAssignment
from apps.core.models import Action, AuditEvent
from apps.core.rbac import Role

pytestmark = pytest.mark.django_db
PWD = "Very-Strong-Pass-123"


def test_login_logout_audited(client, admin):
    r = client.post(reverse("accounts:login"), {"username": "admin", "password": PWD})
    assert r.status_code == 302
    assert AuditEvent.objects.filter(action=Action.LOGIN, actor=admin).exists()
    client.post(reverse("accounts:logout"))
    assert AuditEvent.objects.filter(action=Action.LOGOUT, actor=admin).exists()


def test_failed_login_generic_message_and_audit(client, admin):
    r = client.post(reverse("accounts:login"), {"username": "admin", "password": "wrong"})
    assert "Неверный логин или пароль" in r.content.decode()
    r2 = client.post(reverse("accounts:login"), {"username": "nobody", "password": "wrong"})
    assert r.content.decode().count("Неверный") == r2.content.decode().count("Неверный")  # no user enumeration
    assert AuditEvent.objects.filter(action=Action.LOGIN_FAILED).count() >= 2


def test_lockout_after_5_failures(client, admin):
    for _ in range(5):
        client.post(reverse("accounts:login"), {"username": "admin", "password": "wrong"})
    r = client.post(reverse("accounts:login"), {"username": "admin", "password": PWD})
    assert r.status_code == 429 or "заблокирован" in r.content.decode()
    assert "_auth_user_id" not in client.session


def test_createadmin_once(monkeypatch):
    pw = iter([PWD, PWD])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(pw))
    call_command("createadmin", username="boss")
    u = get_user_model().objects.get(username="boss")
    assert RoleAssignment.objects.filter(user=u, role=Role.ADMIN, project__isnull=True).exists()
    with pytest.raises(CommandError):
        call_command("createadmin", username="boss2")


def test_createadmin_weak_password(monkeypatch):
    pw = iter(["123", "123"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(pw))
    with pytest.raises(CommandError):
        call_command("createadmin", username="boss")


@pytest.mark.parametrize("who", ["operator", "viewer"])
def test_user_management_forbidden(client_as, request, who):
    user = request.getfixturevalue(who)
    c = client_as(user)
    assert c.get(reverse("accounts:user_list")).status_code == 403
    assert AuditEvent.objects.filter(action=Action.ACCESS_DENIED, actor=user).exists()


def test_admin_creates_user(client_as, admin):
    c = client_as(admin)
    r = c.post(
        reverse("accounts:user_create"),
        {"username": "ivan", "password1": PWD, "password2": PWD, "role": Role.VIEWER, "project": ""},
    )
    assert r.status_code == 302
    assert RoleAssignment.objects.filter(user__username="ivan", role=Role.VIEWER).exists()
    assert AuditEvent.objects.filter(action=Action.USER_CREATED).exists()


def test_admin_cannot_remove_own_admin(client_as, admin):
    ra = RoleAssignment.objects.get(user=admin)
    client_as(admin).post(reverse("accounts:role_revoke", args=[admin.pk, ra.id]))
    assert RoleAssignment.objects.filter(pk=ra.pk).exists()
