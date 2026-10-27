"""Job engine: creation, state machine, logging, node mutation lock (ARCHITECTURE §4, §6)."""

from __future__ import annotations

import threading
import uuid
from contextlib import contextmanager
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.core import audit
from apps.core.models import Action, Outcome
from apps.core.rbac import Perm, require
from apps.core.redact import redact, redact_text

from .models import ALLOWED_TRANSITIONS, MUTATION_TYPES, TERMINAL_STATES, Job, JobLog, JobState, JobType

# Seconds until the watchdog declares a job UNKNOWN.
JOB_TIMEOUTS: dict[str, int] = {
    JobType.NOOP_TEST: 120,
    JobType.INVENTORY: 300,
    JobType.FETCH_HOSTKEY: 60,
    JobType.PORT_SCAN: 600,
    JobType.AUDIT: 600,
    JobType.PLAN_EXECUTE: 1800,
    JobType.CONNECTIVITY: 300,
    JobType.IDS_FETCH: 120,
    JobType.IDS_TEST: 120,
    JobType.PROTECTION_TEST: 300,
    JobType.CAPTURE: 120,
    JobType.PCAP_ANALYZE: 300,
    JobType.REPORT: 300,
    JobType.SECURITY_LOGS: 300,
}

JOB_PERMS: dict[str, Perm] = {t: Perm.RUN_JOBS for t in JobType.values}
JOB_PERMS[JobType.PLAN_EXECUTE] = Perm.APPROVE_PLAN
# Simulated attacks change node state (a Fail2ban ban) -> administrators only.
JOB_PERMS[JobType.PROTECTION_TEST] = Perm.APPROVE_PLAN


class InvalidTransition(Exception):
    pass


class NodeBusy(Exception):
    pass


def create_job(job_type: str, project, user, node=None, params: dict[str, Any] | None = None, request=None) -> Job:
    """Validate rights, persist the job, enqueue it after commit."""
    if job_type not in JobType.values:
        raise ValueError(f"unknown job type {job_type}")
    require(user, JOB_PERMS[job_type], project, request=request)
    if node is not None and node.project_id != project.id:
        raise ValueError("node does not belong to project")
    job = Job.objects.create(
        type=job_type,
        project=project,
        node=node,
        requested_by=user,
        queue="mutation" if job_type in MUTATION_TYPES else "readonly",
        params=params or {},
        deadline_at=timezone.now() + timedelta(seconds=JOB_TIMEOUTS[job_type]),
    )
    audit.log(
        user,
        Action.JOB_CREATED,
        obj=job,
        project=project,
        request=request,
        type=job_type,
        node=str(node) if node else None,
    )
    transaction.on_commit(lambda: enqueue(job))
    return job


def enqueue(job: Job) -> None:
    """Hand the job to the broker. If the broker is unreachable the job becomes FAILED with an
    explicit reason instead of an HTTP 500 and a job silently stuck in QUEUED."""
    from kombu.exceptions import OperationalError

    from .tasks import run_job

    try:
        run_job.apply_async(
            args=[str(job.id)],
            queue=job.queue,
            retry=True,
            retry_policy={"max_retries": 2, "interval_start": 0.5, "interval_step": 0.5},
        )
    except OperationalError:
        import logging

        logging.getLogger(__name__).exception("broker unavailable, job %s not queued", job.id)
        transition(job, JobState.FAILED, phase="очередь недоступна", error_code="broker_unavailable")
        log(
            job,
            "Брокер заданий (Redis) недоступен: задание не поставлено в очередь. Проверьте make selfcheck.",
            JobLog.Level.ERROR,
        )


@transaction.atomic
def transition(
    job: Job, new_state: str, phase: str | None = None, error_code: str | None = None, result: dict | None = None
) -> Job:
    locked = Job.objects.select_for_update().get(pk=job.pk)
    if new_state not in ALLOWED_TRANSITIONS.get(locked.state, frozenset()):
        raise InvalidTransition(f"{locked.state} -> {new_state}")
    now = timezone.now()
    locked.state = new_state
    fields = ["state", "updated_at"]
    if phase is not None:
        locked.phase = phase[:60]
        fields.append("phase")
    if error_code is not None:
        locked.safe_error_code = error_code[:40]
        fields.append("safe_error_code")
    if result is not None:
        locked.result = redact(result)
        fields.append("result")
    if new_state == JobState.RUNNING and locked.started_at is None:
        locked.started_at = now
        fields.append("started_at")
    if new_state in TERMINAL_STATES:
        locked.finished_at = now
        locked.progress = 100 if new_state == JobState.SUCCEEDED else locked.progress
        fields += ["finished_at", "progress"]
    locked.save(update_fields=fields)
    if new_state in TERMINAL_STATES:
        audit.log(
            locked.requested_by,
            Action.JOB_FINISHED,
            obj=locked,
            project=locked.project_id,
            outcome=Outcome.SUCCESS if new_state == JobState.SUCCEEDED else Outcome.FAILED,
            type=locked.type,
            state=new_state,
            error_code=locked.safe_error_code or None,
        )
    job.__dict__.update(
        {
            f: getattr(locked, f)
            for f in ("state", "phase", "safe_error_code", "result", "started_at", "finished_at", "progress")
        }
    )
    return locked


def set_progress(job: Job, progress: int, phase: str | None = None) -> None:
    fields: dict[str, Any] = {"progress": max(0, min(100, int(progress)))}
    if phase is not None:
        fields["phase"] = phase[:60]
    Job.objects.filter(pk=job.pk).update(**fields, updated_at=timezone.now())
    for k, val in fields.items():
        setattr(job, k, val)


def log(job: Job, message: str, level: str = JobLog.Level.INFO) -> None:
    JobLog.objects.create(job=job, level=level, message=redact_text(str(message))[:1000])


# --- node mutation lock --------------------------------------------------------------------

_local_locks: dict[str, threading.Lock] = {}
_local_guard = threading.Lock()


@contextmanager
def node_mutation_lock(node, ttl_s: int = 1800):
    """At most one mutation per node at a time (SECURITY T9). Redis lock in deployments,
    in-process lock in unit tests. Raises NodeBusy immediately if taken."""
    key = f"nixfort:lock:node:{node.pk}"
    if getattr(settings, "NIXFORT_REDIS_LOCKS", True):
        import redis

        client = redis.Redis.from_url(settings.REDIS_URL)
        token = uuid.uuid4().hex
        if not client.set(key, token, nx=True, ex=ttl_s):
            raise NodeBusy(str(node))
        try:
            yield
        finally:
            # release only our own lock
            client.eval(
                "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end",
                1,
                key,
                token,
            )
    else:
        with _local_guard:
            lock = _local_locks.setdefault(key, threading.Lock())
        if not lock.acquire(blocking=False):
            raise NodeBusy(str(node))
        try:
            yield
        finally:
            lock.release()
