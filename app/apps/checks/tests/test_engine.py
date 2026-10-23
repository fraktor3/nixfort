import json
from pathlib import Path

import pytest
from django.urls import reverse
from django.utils import timezone

from apps.checks.models import CheckResult
from apps.execution import services
from apps.execution.models import JobState, JobType
from apps.inventory.models import HostKey, InventorySnapshot

pytestmark = pytest.mark.django_db(transaction=True)
FX = Path(__file__).parent / "fixtures"


@pytest.fixture
def confirmed(lab_nodes, admin):
    for n in lab_nodes.values():
        HostKey.objects.create(
            node=n,
            key_type="ssh-ed25519",
            public_key="AAAA",
            fingerprint_sha256="SHA256:x",
            confirmed_by=admin,
            confirmed_at=timezone.now(),
        )
    return lab_nodes


@pytest.fixture
def fake_collect(monkeypatch):
    calls = []

    def collect(node, job=None, log=None):
        name = node.name.replace("nx-", "")
        facts = json.loads((FX / f"lab_{name}_baseline.json").read_text(encoding="utf-8"))
        calls.append(node.name)
        return InventorySnapshot.objects.create(
            node=node, job=job, collected_at=timezone.now(), facts=facts, agent_version="1.0.0", sha256="0" * 64
        )

    monkeypatch.setattr("apps.inventory.collector.collect_node", collect)
    return calls


def test_audit_job_end_to_end(project, confirmed, operator, fake_collect):
    job = services.create_job(JobType.AUDIT, project, operator)
    job.refresh_from_db()
    assert job.state == JobState.SUCCEEDED, job.safe_error_code
    run = job.audit_run
    assert sorted(fake_collect) == ["nx-gateway", "nx-server"]  # test client is not audited
    srv = {r.check_id: r.status for r in run.results.filter(node=confirmed["server"])}
    assert srv["SSH-01"] == "FAIL" and srv["SYS-04"] == "FAIL" and srv["SSH-03"] == "PASS"
    assert run.summary["total"]["FAIL"] > 0
    r = run.results.get(node=confirmed["server"], check_id="SSH-01")
    ev = r.evidence.get()
    assert ev.source == "ssh.read_effective_config.v1" and len(ev.sha256) == 64


def test_results_are_immutable(project, confirmed, operator, fake_collect):
    job = services.create_job(JobType.AUDIT, project, operator)
    job.refresh_from_db()
    res = CheckResult.objects.filter(audit_run=job.audit_run).first()
    res.status = "PASS"
    with pytest.raises(PermissionError):
        res.save()


def test_unconfirmed_key_nodes_get_unknown_not_pass(project, lab_nodes, operator, fake_collect):
    job = services.create_job(JobType.AUDIT, project, operator)
    job.refresh_from_db()
    statuses = set(job.audit_run.results.values_list("status", flat=True))
    assert statuses <= {"UNKNOWN", "NOT_APPLICABLE"}
    assert fake_collect == []  # nothing contacted without a confirmed key


def test_audit_pages(client_as, project, confirmed, operator, viewer, fake_collect):
    job = services.create_job(JobType.AUDIT, project, operator)
    job.refresh_from_db()
    run = job.audit_run
    c = client_as(viewer)
    assert c.get(reverse("checks:run_list", args=[project.id])).status_code == 200
    page = c.get(reverse("checks:run_detail", args=[project.id, run.id])).content.decode()
    assert "SSH-01" in page and "nx-server" in page
    res = run.results.get(node=confirmed["server"], check_id="SSH-01")
    detail = c.get(reverse("checks:result_detail", args=[project.id, run.id, res.id])).content.decode()
    assert "ssh.read_effective_config.v1" in detail
    assert c.post(reverse("checks:run_start", args=[project.id])).status_code == 403
