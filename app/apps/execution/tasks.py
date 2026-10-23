"""Celery entry points. No automatic retries: mutations must never be repeated blindly (SECURITY T9)."""

from __future__ import annotations

import importlib
import logging

from celery import shared_task
from django.apps import apps as django_apps
from django.utils import timezone

from apps.core.rbac import has_perm

from . import services
from .models import Job, JobState
from .registry import HANDLERS

logger = logging.getLogger(__name__)
_loaded = False


def load_handlers() -> None:
    global _loaded
    if _loaded:
        return
    for cfg in django_apps.get_app_configs():
        if cfg.name.startswith("apps."):
            try:
                importlib.import_module(f"{cfg.name}.handlers")
            except ModuleNotFoundError as exc:
                if exc.name != f"{cfg.name}.handlers":
                    raise
    _loaded = True


@shared_task(name="execution.run_job", acks_late=False, autoretry_for=(), max_retries=0)
def run_job(job_id: str) -> None:
    load_handlers()
    job = Job.objects.select_related("project", "requested_by", "node").get(pk=job_id)
    if job.state != JobState.QUEUED:
        logger.warning("job %s is %s, not QUEUED: skipping", job_id, job.state)
        return
    # Rights are re-checked at execution time (role may have been revoked since creation).
    if job.requested_by is None or not has_perm(job.requested_by, services.JOB_PERMS[job.type], job.project):
        services.transition(job, JobState.CANCELLED, phase="нет прав", error_code="permission_revoked")
        return
    handler = HANDLERS.get(job.type)
    if handler is None:
        services.transition(job, JobState.RUNNING)
        services.transition(job, JobState.FAILED, error_code="no_handler")
        return
    services.transition(job, JobState.RUNNING, phase="старт")
    try:
        final_state, result = handler(job)
    except Exception:  # noqa: BLE001 - convert any crash into an honest FAILED/UNKNOWN
        logger.exception("job %s crashed", job_id)
        job.refresh_from_db()
        if job.state == JobState.RUNNING:
            # A crashed mutation leaves the node state unknown; read-only jobs simply failed.
            state = JobState.UNKNOWN if job.is_mutation else JobState.FAILED
            services.transition(job, state, error_code="internal_error")
        elif job.state == JobState.ROLLING_BACK:
            services.transition(job, JobState.UNKNOWN, error_code="internal_error")
        return
    job.refresh_from_db()
    if not job.is_terminal:
        services.transition(job, final_state, phase="готово", result=result)


@shared_task(name="execution.watchdog")
def watchdog() -> int:
    """Jobs past their deadline become UNKNOWN (worker died, node hung). Never SUCCEEDED."""
    n = 0
    for job in Job.objects.filter(
        state__in=[JobState.QUEUED, JobState.RUNNING, JobState.ROLLING_BACK], deadline_at__lt=timezone.now()
    ):
        try:
            services.transition(job, JobState.UNKNOWN, phase="истёк срок", error_code="deadline_exceeded")
            services.log(job, "Задание не завершилось вовремя: состояние неизвестно, требуется проверка.", "ERROR")
            n += 1
        except services.InvalidTransition:
            continue
    return n
