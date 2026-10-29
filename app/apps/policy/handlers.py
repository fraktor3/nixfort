"""Job handler of the connectivity check."""

from apps.execution import services
from apps.execution.models import Job, JobType
from apps.execution.registry import register

from . import connectivity


@register(JobType.CONNECTIVITY)
def connectivity_check(job: Job):
    return connectivity.check_now(job, log=lambda m, lvl="INFO": services.log(job, m, lvl))
