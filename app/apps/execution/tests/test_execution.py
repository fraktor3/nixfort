from datetime import timedelta

import pytest
from django.utils import timezone

from apps.core.rbac import Role
from apps.execution import services
from apps.execution.models import Job, JobState, JobType
from apps.execution.tasks import watchdog

pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    monkeypatch.setattr("apps.execution.handlers.time.sleep", lambda s: None)


def test_noop_job_runs_to_success(project, operator):
    job = services.create_job(JobType.NOOP_TEST, project, operator, params={"seconds": 2})
    job.refresh_from_db()
    assert job.state == JobState.SUCCEEDED
    assert job.progress == 100 and job.started_at and job.finished_at
    assert job.queue == "readonly"
    assert job.logs.exists()


def test_viewer_cannot_create_job(project, viewer):
    from django.core.exceptions import PermissionDenied

    with pytest.raises(PermissionDenied):
        services.create_job(JobType.NOOP_TEST, project, viewer)


def test_plan_execute_needs_admin_and_uses_mutation_queue(project, operator, admin, monkeypatch):
    from django.core.exceptions import PermissionDenied

    with pytest.raises(PermissionDenied):
        services.create_job(JobType.PLAN_EXECUTE, project, operator)
    monkeypatch.setattr("apps.execution.tasks.run_job.apply_async", lambda *a, **k: None)
    job = services.create_job(JobType.PLAN_EXECUTE, project, admin)
    assert job.queue == "mutation"


def _job(project, user, state=JobState.QUEUED, **kw):
    return Job.objects.create(
        type=JobType.NOOP_TEST,
        project=project,
        requested_by=user,
        state=state,
        deadline_at=kw.pop("deadline_at", timezone.now() + timedelta(minutes=5)),
        **kw,
    )


ALL = list(JobState)


@pytest.mark.parametrize("src", ALL)
@pytest.mark.parametrize("dst", ALL)
def test_transition_matrix(project, operator, src, dst):
    from apps.execution.models import ALLOWED_TRANSITIONS

    job = _job(project, operator, state=src)
    if dst in ALLOWED_TRANSITIONS.get(src, ()):
        services.transition(job, dst)
        job.refresh_from_db()
        assert job.state == dst
    else:
        with pytest.raises(services.InvalidTransition):
            services.transition(job, dst)


def test_rights_rechecked_in_worker(project, make_user):
    from apps.accounts.models import RoleAssignment
    from apps.execution.tasks import run_job

    u = make_user("temp", Role.OPERATOR)
    job = _job(project, u)
    RoleAssignment.objects.filter(user=u).delete()  # role revoked after creation
    run_job(str(job.id))
    job.refresh_from_db()
    assert job.state == JobState.CANCELLED and job.safe_error_code == "permission_revoked"


def test_watchdog_marks_unknown(project, operator):
    job = _job(project, operator, state=JobState.RUNNING, deadline_at=timezone.now() - timedelta(seconds=1))
    assert watchdog() == 1
    job.refresh_from_db()
    assert job.state == JobState.UNKNOWN and job.safe_error_code == "deadline_exceeded"


def test_crashing_handler_is_failed_not_success(project, operator, monkeypatch):
    from apps.execution import registry

    def boom(job):
        raise RuntimeError("password=secret123")

    monkeypatch.setitem(registry.HANDLERS, JobType.NOOP_TEST, boom)
    monkeypatch.setattr("apps.execution.tasks._loaded", True)
    job = services.create_job(JobType.NOOP_TEST, project, operator)
    job.refresh_from_db()
    assert job.state == JobState.FAILED and job.safe_error_code == "internal_error"


def test_node_lock(lab_nodes):
    node = lab_nodes["gateway"]
    with services.node_mutation_lock(node):
        with pytest.raises(services.NodeBusy):
            with services.node_mutation_lock(node):
                pass
    with services.node_mutation_lock(node):
        pass


def test_job_log_redacts(project, operator):
    job = _job(project, operator)
    services.log(job, "connect password=hunter2 ok")
    assert "hunter2" not in job.logs.get().message


def test_job_page_and_htmx(client_as, project, operator):
    job = _job(project, operator)
    c = client_as(operator)
    r = c.get(f"/projects/{project.id}/jobs/{job.id}/")
    assert r.status_code == 200 and "hx-get" in r.content.decode()
    r2 = c.get(f"/projects/{project.id}/jobs/{job.id}/", HTTP_HX_REQUEST="true")
    assert "<html" not in r2.content.decode()


def test_broker_down_gives_failed_job_not_500(client_as, project, operator, monkeypatch):
    from kombu.exceptions import OperationalError

    def down(*a, **k):
        raise OperationalError("Error 104 while writing to socket. Connection reset by peer.")

    monkeypatch.setattr("apps.execution.tasks.run_job.apply_async", down)
    r = client_as(operator).post(f"/projects/{project.id}/jobs/noop/")
    assert r.status_code == 302
    job = Job.objects.get()
    assert job.state == JobState.FAILED and job.safe_error_code == "broker_unavailable"
    assert "Redis" in job.logs.get().message
