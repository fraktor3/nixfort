from apps.execution import services
from apps.execution.models import Job, JobType
from apps.execution.registry import register

from . import scenarios


def _log(job):
    return lambda m, lvl="INFO": services.log(job, m, lvl)


@register(JobType.IDS_FETCH)
def ids_fetch(job: Job):
    return scenarios.fetch_job(job, _log(job))


@register(JobType.IDS_TEST)
def ids_test(job: Job):
    job.params = {**job.params, "scenario": "IDS_MARKER"}
    return scenarios.run(job, _log(job))


@register(JobType.PROTECTION_TEST)
def protection_test(job: Job):
    return scenarios.run(job, _log(job))
