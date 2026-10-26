"""Report: built from a real lab baseline + a simulated remediation, immutable, 7/7 elements, no secrets,
same SHA-256 for what is shown and what is downloaded."""

import json

import pytest
from django.urls import reverse

from apps.checks.models import AuditRun
from apps.core.models import Action, AuditEvent
from apps.remediation import planner
from apps.remediation.tests.test_remediation import FakeNode, approve_and_run, only_server_plan
from apps.reports import builder
from apps.reports.models import Report

pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture
def after_change(client_as, admin, operator, baseline_run, monkeypatch):
    plan = only_server_plan(baseline_run, operator)
    plan, _ = approve_and_run(client_as, admin, plan, {"nx-server": FakeNode()}, monkeypatch)
    return baseline_run, plan


def make(client_as, user, project, before, after):
    return client_as(user).post(reverse("reports:create", args=[project.id]), {"before": before.id, "after": after.id})


def test_report_before_after_complete(client_as, operator, project, after_change):
    before, plan = after_change
    after = plan.post_audit_run
    r = make(client_as, operator, project, before, after)
    assert r.status_code == 302
    rep = Report.objects.get()
    d = rep.data
    assert all(e["present"] for e in d["completeness"]) and len(d["completeness"]) == 7
    changed = {(c["node"], c["check_id"]) for c in d["comparison"] if c["changed"]}
    assert ("nx-server", "F2B-02") in changed and ("nx-server", "SSH-01") in changed
    assert d["changes"][0]["items"] and d["changes"][0]["approved_by"] == "admin"
    assert any(x["check_id"] == "SSH-02" and "ключ" in x["why_not_fixed"] for x in d["residual"])
    assert rep.sha256 == builder.digest(d)
    page = client_as(operator).get(reverse("reports:detail", args=[project.id, rep.id])).content.decode()
    for section in ("1. Объект проверки", "2. Исходное", "3. Выполненные", "4. Итоговое", "5. Доказательства",
                    "6. Остаточные", "7. Ограничения", "7 из 7"):  # fmt: skip
        assert section in page
    assert AuditEvent.objects.filter(action=Action.REPORT_EXPORTED).exists()


def test_json_download_matches_hash_and_has_no_secrets(client_as, operator, project, after_change):
    before, plan = after_change
    make(client_as, operator, project, before, plan.post_audit_run)
    rep = Report.objects.get()
    r = client_as(operator).get(reverse("reports:download", args=[project.id, rep.id, "json"]))
    assert r.status_code == 200 and r["X-Report-SHA256"] == rep.sha256
    import hashlib

    assert hashlib.sha256(r.content).hexdigest() == rep.sha256
    text = r.content.decode()
    assert "PRIVATE KEY" not in text and "controller_ed25519" not in text
    assert json.loads(text)["schema"] == "nixfort.report/1"


def test_pdf_download(client_as, operator, project, after_change):
    pytest.importorskip("weasyprint")
    before, plan = after_change
    make(client_as, operator, project, before, plan.post_audit_run)
    rep = Report.objects.get()
    r = client_as(operator).get(reverse("reports:download", args=[project.id, rep.id, "pdf"]))
    assert r.status_code == 200 and r.content[:5] == b"%PDF-" and len(r.content) > 10_000
    import os

    if os.environ.get("NIXFORT_DUMP_PDF"):  # manual visual check
        with open(os.environ["NIXFORT_DUMP_PDF"], "wb") as fh:
            fh.write(r.content)


def test_report_is_immutable_and_tamper_is_detected(client_as, operator, project, after_change):
    before, plan = after_change
    make(client_as, operator, project, before, plan.post_audit_run)
    rep = Report.objects.get()
    rep.title = "x"
    with pytest.raises(PermissionError):
        rep.save()
    data = {**rep.data, "residual": []}
    Report.objects.filter(pk=rep.pk).update(data=data)  # behind the model's back
    r = client_as(operator).get(reverse("reports:download", args=[project.id, rep.id, "json"]))
    assert r.status_code == 409


def test_without_changes_still_states_it(client_as, operator, project, baseline_run):
    make(client_as, operator, project, baseline_run, baseline_run)
    rep = Report.objects.get()
    assert rep.data["changes"] == [] and all(e["present"] for e in rep.data["completeness"])
    page = client_as(operator).get(reverse("reports:detail", args=[project.id, rep.id])).content.decode()
    assert "планов изменений не было" in page


def test_rights(client_as, viewer, operator, project, baseline_run, other_project, make_user):
    # a viewer (e.g. an auditor) may build and export reports: it is read-only (ROLE_PERMS)
    assert make(client_as, viewer, project, baseline_run, baseline_run).status_code == 302
    rep = Report.objects.get()
    assert client_as(viewer).get(reverse("reports:download", args=[project.id, rep.id, "json"])).status_code == 200
    stranger = make_user("stranger", None)
    assert client_as(stranger).get(reverse("reports:detail", args=[project.id, rep.id])).status_code == 404
    # another project's audit run cannot be mixed into this report
    foreign = AuditRun.objects.create(project=other_project, catalog_version="x", state="DONE")
    assert make(client_as, operator, project, baseline_run, foreign).status_code == 404
    assert planner  # imported for fixtures
