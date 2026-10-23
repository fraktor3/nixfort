"""Built-in handlers. Domain modules register their own handlers in their handlers.py."""

from __future__ import annotations

import time

from . import services
from .models import Job, JobState, JobType
from .registry import register


@register(JobType.NOOP_TEST)
def noop(job: Job):
    seconds = int(job.params.get("seconds", 3))
    seconds = max(1, min(30, seconds))
    for i in range(seconds):
        time.sleep(1)
        services.set_progress(job, int((i + 1) * 100 / seconds), phase=f"шаг {i + 1}/{seconds}")
    services.log(job, f"Тестовое задание выполнено за {seconds} с")
    return JobState.SUCCEEDED, {"seconds": seconds}
