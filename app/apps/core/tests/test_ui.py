"""Interface invariants: no internal product name on screens, every static reference exists,
and the HTML stays compatible with the CSP (no inline styles or scripts)."""

import re
from pathlib import Path

import pytest
from django.conf import settings
from django.urls import reverse

TEMPLATES = Path(settings.BASE_DIR) / "templates"
STATIC = Path(settings.BASE_DIR) / "static"


def _pages(project):
    pid = project.id
    return [
        reverse("core:dashboard"),
        reverse("inventory:project_list"),
        reverse("inventory:project_detail", args=[pid]),
        reverse("checks:run_list", args=[pid]),
        reverse("remediation:plan_list", args=[pid]),
        reverse("policy:overview", args=[pid]),
        reverse("policy:connectivity", args=[pid]),
        reverse("inventory:portscan_list", args=[pid]),
        reverse("ids:sensor", args=[pid]),
        reverse("ids:protection", args=[pid]),
        reverse("pcap:list", args=[pid]),
        reverse("seclog:seclog", args=[pid]),
        reverse("reports:list", args=[pid]),
        reverse("execution:job_list", args=[pid]),
        reverse("core:audit_log"),
        reverse("accounts:user_list"),
        reverse("core:terms"),
        reverse("core:privacy"),
    ]


@pytest.mark.django_db
def test_no_product_name_and_no_inline_style(client_as, admin, project, lab_nodes):
    c = client_as(admin)
    for url in _pages(project):
        r = c.get(url)
        assert r.status_code == 200, url
        html = r.content.decode()
        assert "nixfort" not in html.lower(), url
        assert " style=" not in html and "<style" not in html, url
        assert not re.search(r"<script(?![^>]*\bsrc=)", html), url


@pytest.mark.django_db
def test_login_page_is_plain(client):
    html = client.get(reverse("accounts:login")).content.decode()
    assert "nixfort" not in html.lower()
    assert 'name="username"' in html and 'name="password"' in html and "сборка" in html


def test_every_static_reference_exists():
    refs = set()
    for f in TEMPLATES.rglob("*.html"):
        refs.update(re.findall(r"{%\s*static\s+'([^']+)'\s*%}", f.read_text(encoding="utf-8")))
    assert refs, "no static references found"
    missing = [r for r in refs if not (STATIC / r).is_file()]
    assert missing == []


def test_relative_dates():
    from datetime import timedelta

    from django.utils import timezone

    from apps.core.templatetags.nx import nb, sig, when

    now = timezone.now()
    assert when(now).startswith("сегодня ")
    assert when(now - timedelta(days=1)).startswith("вчера ")
    assert when(None) == "–"
    assert sig("NIXFORT SSH brute force") == "SSH brute force"
    assert nb("правила NIXFORT загружены") == "тестовые правила загружены"
