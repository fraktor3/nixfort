import pytest
from django.urls import reverse

from apps.core import audit
from apps.core.models import Action, AuditEvent
from apps.core.rbac import ROLE_PERMS, Perm, Role, has_perm
from apps.core.redact import redact, redact_text

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize("role", list(Role))
@pytest.mark.parametrize("perm", list(Perm))
def test_rbac_matrix_global(make_user, role, perm):
    user = make_user(f"u_{role}_{perm}", role)
    assert has_perm(user, perm) == (perm in ROLE_PERMS[role])


def test_viewer_cannot_approve_or_run(viewer, project):
    assert has_perm(viewer, Perm.VIEW_PROJECT, project)
    for p in (Perm.RUN_JOBS, Perm.APPROVE_PLAN, Perm.EDIT_PROJECT, Perm.ACTIVATE_POLICY, Perm.CONFIRM_HOSTKEY):
        assert not has_perm(viewer, p, project)


def test_operator_cannot_approve_plan_or_confirm_key(operator, project):
    assert has_perm(operator, Perm.RUN_JOBS, project)
    assert not has_perm(operator, Perm.APPROVE_PLAN, project)
    assert not has_perm(operator, Perm.CONFIRM_HOSTKEY, project)
    assert not has_perm(operator, Perm.ACTIVATE_POLICY, project)


def test_project_scoped_role(make_user, project, other_project):
    u = make_user("scoped", Role.OPERATOR, project=project)
    assert has_perm(u, Perm.RUN_JOBS, project)
    assert not has_perm(u, Perm.RUN_JOBS, other_project)
    assert not has_perm(u, Perm.CREATE_PROJECT)  # global-only perm needs a global role


def test_inactive_user_has_no_perms(make_user):
    u = make_user("gone", Role.ADMIN)
    u.is_active = False
    u.save()
    assert not has_perm(u, Perm.VIEW_PROJECT)


def test_audit_event_is_append_only(admin):
    ev = audit.log(admin, Action.LOGIN)
    ev.outcome = "FAILED"
    with pytest.raises(PermissionError):
        ev.save()
    with pytest.raises(PermissionError):
        ev.delete()
    with pytest.raises(PermissionError):
        AuditEvent.objects.filter(pk=ev.pk).update(outcome="FAILED")
    with pytest.raises(PermissionError):
        AuditEvent.objects.all().delete()
    assert AuditEvent.objects.get(pk=ev.pk).outcome == "SUCCESS"


def test_audit_redacts_secrets(admin):
    ev = audit.log(admin, Action.USER_CREATED, password="hunter2", nested={"token": "abc", "ok": 1})
    assert ev.safe_metadata == {"password": "***", "nested": {"token": "***", "ok": 1}}


def test_redact_text():
    key = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
    assert "AAAA" not in redact_text(f"x {key} y")
    assert redact_text("password=qwerty other") == "password=*** other"
    assert redact({"api_key": "k", "list": ["secret: s1"]}) == {"api_key": "***", "list": ["secret=***"]}


def test_healthz_public(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_healthz_db_down(client, monkeypatch):
    from django.db import connection

    def boom(*a, **k):
        raise RuntimeError("down")

    monkeypatch.setattr(connection, "cursor", boom)
    assert client.get("/healthz").status_code == 503


@pytest.mark.parametrize("url", ["/", "/projects/", "/audit/", "/accounts/users/"])
def test_login_required(client, url):
    r = client.get(url)
    assert r.status_code == 302
    assert r["Location"].startswith(reverse("accounts:login"))


def test_security_headers(client_as, admin):
    r = client_as(admin).get("/")
    assert r.status_code == 200
    assert "default-src 'self'" in r["Content-Security-Policy"]
    assert r["X-Frame-Options"] == "DENY"
    assert r["X-Content-Type-Options"] == "nosniff"


def test_audit_log_visibility(client_as, make_user, project, other_project, admin):
    audit.log(admin, Action.PROJECT_UPDATED, project=project, marker="A")
    audit.log(admin, Action.PROJECT_UPDATED, project=other_project, marker="B")
    u = make_user("pv", Role.VIEWER, project=project)
    body = client_as(u).get("/audit/").content.decode()
    assert "&#x27;A&#x27;" in body or "'A'" in body
    assert "'B'" not in body and "&#x27;B&#x27;" not in body
