"""Security regression tests (audit T-029, OWASP WSTG): every page is closed to strangers, no role can write
beyond its rights, CSRF, open redirect, Host header, stored XSS, security headers, PDF without network."""

import re
import uuid

import pytest
from django.test import Client
from django.urls import URLPattern, URLResolver, get_resolver

from apps.core.rbac import Role

PUBLIC = {"accounts:login", "core:healthz", "core:terms", "core:privacy"}


def _patterns(resolver=None, prefix="", ns=None):
    """(name, route) for every URL of the app, routes joined across includes."""
    resolver = resolver or get_resolver()
    for p in resolver.url_patterns:
        if isinstance(p, URLResolver):
            yield from _patterns(p, prefix + str(p.pattern), p.namespace or ns)
        elif isinstance(p, URLPattern) and p.name:
            yield (f"{ns}:{p.name}" if ns else p.name), prefix + str(p.pattern)


def _fill(route: str, project_id) -> str:
    def sub(m):
        conv, name = m.group(1) or "str", m.group(2)
        if name == "project_id":
            return str(project_id)
        return {"int": "1", "uuid": str(uuid.uuid4()), "slug": "x", "path": "x"}.get(conv, "x")

    return "/" + re.sub(r"<(?:(\w+):)?(\w+)>", sub, route)


def _all_urls(project_id):
    return [(name, _fill(route, project_id)) for name, route in _patterns()]


def test_url_enumeration_sees_the_whole_app(project):
    names = {n for n, _ in _all_urls(project.id)}
    assert len(names) > 40
    assert {"core:dashboard", "accounts:user_create", "reports:download", "pcap:upload"} <= names


@pytest.mark.parametrize("method", ["get", "post"])
def test_every_page_is_closed_to_anonymous(client, project, method):
    for name, url in _all_urls(project.id):
        if name in PUBLIC:
            continue
        r = getattr(client, method)(url)
        ok = r.status_code in (403, 404, 405) or (r.status_code == 302 and "/accounts/login/" in r["Location"])
        assert ok, f"{name} {url} {method}: {r.status_code}"


def test_viewer_cannot_write_anywhere(client, project, make_user):
    """A viewer may read, never change: every POST ends in 403/404/405 and changes nothing."""
    from apps.core.models import Action, AuditEvent

    viewer = make_user("viewer", Role.VIEWER, project)
    client.force_login(viewer)
    before = AuditEvent.objects.exclude(action=Action.ACCESS_DENIED).count()
    for name, url in _all_urls(project.id):
        if name in PUBLIC or name == "accounts:logout":
            continue
        r = client.post(url, {"confirm": "yes", "name": "x"})
        assert r.status_code in (403, 404, 405), f"{name} {url}: {r.status_code}"
    assert AuditEvent.objects.exclude(action=Action.ACCESS_DENIED).count() == before  # only denials journaled


def test_login_requires_csrf_token(db):
    c = Client(enforce_csrf_checks=True)
    r = c.post("/accounts/login/", {"username": "a", "password": "b"})
    assert r.status_code == 403


def test_logout_is_post_only(client, admin):
    client.force_login(admin)
    assert client.get("/accounts/logout/").status_code == 405


@pytest.mark.parametrize(
    "target",
    ["https://evil.example/", "//evil.example/", "/\\evil.example/", "https:evil.example", "\\\\evil.example",
     "javascript:alert(1)", "http://testserver@evil.example/"],
)  # fmt: skip
def test_login_next_never_leaves_the_site(client, make_user, target):
    make_user("u1", Role.VIEWER)
    r = client.post(f"/accounts/login/?next={target}", {"username": "u1", "password": "Very-Strong-Pass-123"})
    assert r.status_code == 302
    loc = r["Location"]
    assert loc.startswith("/") and not loc.startswith("//") and "evil" not in loc and "javascript" not in loc


def test_foreign_host_header_is_rejected(client, db):
    r = client.get("/accounts/login/", HTTP_HOST="evil.example")
    assert r.status_code == 400


def test_stored_markup_is_escaped(client, admin, project):
    from apps.inventory.models import Project

    payload = "<script>alert(1)</script><img src=x onerror=alert(2)>\"'"
    Project.objects.filter(pk=project.pk).update(name=payload, description=payload)
    client.force_login(admin)
    for url in ("/", f"/projects/{project.id}/", "/projects/"):
        body = client.get(url).content.decode()
        assert "<script>alert(1)" not in body and "<img src=x" not in body, url


@pytest.mark.parametrize("url", ["/accounts/login/", "/nope-404/"])
def test_security_headers_everywhere(client, db, url):
    r = client.get(url)
    csp = r["Content-Security-Policy"]
    for d in ("default-src 'self'", "script-src 'self'", "frame-ancestors 'none'", "base-uri 'none'",
              "form-action 'self'", "object-src 'none'"):  # fmt: skip
        assert d in csp, d
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert r["X-Frame-Options"] == "DENY"
    assert r["X-Content-Type-Options"] == "nosniff"
    assert r["Referrer-Policy"] == "same-origin"
    assert r["Cross-Origin-Opener-Policy"] == "same-origin"


def test_pages_with_data_are_not_cached(client, admin, project):
    client.force_login(admin)
    r = client.get(f"/projects/{project.id}/")
    assert "no-store" in r["Cache-Control"]


def test_session_cookie_flags(client, make_user):
    make_user("u2", Role.VIEWER)
    r = client.post("/accounts/login/", {"username": "u2", "password": "Very-Strong-Pass-123"})
    c = r.cookies["sessionid"]
    assert c["httponly"] and c["samesite"] == "Lax"


def test_prod_settings_are_strict():
    import importlib
    import os

    env = {
        "DJANGO_SECRET_KEY": "k" * 64, "DJANGO_ALLOWED_HOSTS": "10.77.0.10",
        "DJANGO_CSRF_TRUSTED_ORIGINS": "https://10.77.0.10", "POSTGRES_DB": "x", "POSTGRES_USER": "x",
        "POSTGRES_PASSWORD": "x",
    }  # fmt: skip
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        prod = importlib.import_module("config.settings.prod")
        importlib.reload(prod)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    assert not prod.DEBUG
    assert prod.SESSION_COOKIE_SECURE and prod.CSRF_COOKIE_SECURE and prod.SESSION_COOKIE_HTTPONLY
    assert prod.SECURE_HSTS_SECONDS >= 31536000
    assert prod.SECURE_PROXY_SSL_HEADER == ("HTTP_X_FORWARDED_PROTO", "https")


def test_pdf_renderer_fetches_nothing():
    from apps.reports.views import NoFetch

    f = NoFetch()
    for url in ("file:///etc/passwd", "http://169.254.169.254/latest/meta-data/", "https://example.org/x.css"):
        with pytest.raises(ValueError):
            f(url)


def test_lockout_counts_the_real_client_address(rf):
    """django-axes takes the address nginx puts into X-Real-IP, the same one the audit journal records."""
    from axes.helpers import get_client_ip_address

    req = rf.get("/accounts/login/", HTTP_X_REAL_IP="10.77.0.1", REMOTE_ADDR="172.18.0.5")
    assert get_client_ip_address(req) == "10.77.0.1"


def test_nginx_config_hardening():
    from pathlib import Path

    conf = (Path(__file__).resolve().parents[4] / "deploy" / "nginx.conf").read_text()
    assert "server_tokens off;" in conf and "ssl_session_tickets off;" in conf
    assert "TLSv1.2 TLSv1.3" in conf and "TLSv1.1" not in conf and "CBC" not in conf
    assert "limit_req zone=login" in conf  # sign-in attempts are rate limited
    assert "resolver 127.0.0.11" in conf and "proxy_pass $web;" in conf  # no nginx restart after an update
    assert conf.count("proxy_set_header X-Real-IP $remote_addr;") == 2  # the client cannot forge X-Real-IP
