"""Job handler that executes an approved plan (queue «mutation»)."""

from apps.execution import services
from apps.execution.models import Job, JobType
from apps.execution.registry import register

from . import orchestrator


@register(JobType.PLAN_EXECUTE)
def plan_execute(job: Job):
    return orchestrator.execute(
        job,
        log=lambda m, lvl="INFO": services.log(job, m, lvl),
        progress=lambda p, ph: services.set_progress(job, p, ph),
    )
