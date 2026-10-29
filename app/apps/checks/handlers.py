"""Job handler of the audit (queue «readonly»)."""

from apps.execution import services
from apps.execution.models import Job, JobState, JobType
from apps.execution.registry import register

from . import services as audit_services


@register(JobType.AUDIT)
def audit(job: Job):
    run = audit_services.run_audit(
        job,
        purpose=job.params.get("purpose", "baseline"),
        node_ids=job.params.get("node_ids"),
        log=lambda m, lvl="INFO": services.log(job, m, lvl),
        progress=lambda p, ph: services.set_progress(job, p, ph),
    )
    t = run.summary.get("total", {})
    services.log(job, "Итог: " + ", ".join(f"{k}={v}" for k, v in sorted(t.items())))
    # The audit job itself succeeded if it produced results; FAIL results are findings, not job errors.
    # ERROR results mean some facts could not be collected -> PARTIAL.
    state = JobState.PARTIAL if t.get("ERROR") else JobState.SUCCEEDED
    return state, {"audit_run": str(run.id), "total": t}
