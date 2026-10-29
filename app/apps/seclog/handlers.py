"""Job handler of the security-log summary."""

from apps.execution import services as job_services
from apps.execution.models import Job, JobType
from apps.execution.registry import register

from . import services


@register(JobType.SECURITY_LOGS)
def security_logs(job: Job):
    return services.collect(job, log=lambda m, lvl="INFO": job_services.log(job, m, lvl))
