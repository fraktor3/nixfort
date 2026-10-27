from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.core.rbac import Perm, has_perm, perm_required
from apps.execution import services as job_services
from apps.execution.models import Job, JobType
from apps.pcap import charts
from apps.pcap.models import PcapCapture

from .models import IdsEvent, ProtectionTest


def _sensor_status(project):
    """Latest Suricata facts of the sensor node(s) from the inventory."""
    out = []
    for n in project.nodes.filter(is_active=True).order_by("name"):
        if not n.has_role("ids_sensor"):
            continue
        snap = n.snapshots.order_by("-collected_at").first()
        fact = (snap.facts.get("suricata") or {}) if snap else {}
        out.append({"node": n, "at": snap.collected_at if snap else None, "state": fact.get("state"),
                    "r": fact.get("result") or {}})  # fmt: skip
    return out


@perm_required(Perm.VIEW_PROJECT)
def sensor(request, project_id):
    project = request.project
    events = IdsEvent.objects.filter(project=project).select_related("node")
    only_nixfort = request.GET.get("all") != "1"
    if only_nixfort:
        events = events.filter(signature_id__gte=9000001, signature_id__lte=9000099)
    last_fetch = Job.objects.filter(project=project, type=JobType.IDS_FETCH).order_by("-created_at").first()
    return render(
        request,
        "ids/sensor.html",
        {
            "project": project,
            "sensors": _sensor_status(project),
            "events": events[:200],
            "only_nixfort": only_nixfort,
            "last_fetch": last_fetch,
            "can_run": has_perm(request.user, Perm.RUN_JOBS, project) and not project.is_archived,
        },
    )


@require_POST
@perm_required(Perm.RUN_JOBS)
def fetch(request, project_id):
    job = job_services.create_job(JobType.IDS_FETCH, request.project, request.user, request=request)
    return redirect("execution:job_detail", project_id=project_id, job_id=job.id)


@perm_required(Perm.VIEW_PROJECT)
def protection(request, project_id):
    project = request.project
    tests = list(ProtectionTest.objects.filter(project=project).select_related("job")[:30])
    latest = {}
    for t in tests:
        latest.setdefault(t.scenario, t)
    return render(
        request,
        "ids/protection.html",
        {
            "project": project,
            "scenarios": [(s, latest.get(s.value)) for s in ProtectionTest.Scenario],
            "history": tests,
            "can_marker": has_perm(request.user, Perm.RUN_JOBS, project) and not project.is_archived,
            "can_attack": has_perm(request.user, Perm.APPROVE_PLAN, project) and not project.is_archived,
        },
    )


@require_POST
@perm_required(Perm.RUN_JOBS)
def protection_run(request, project_id, scenario):
    if scenario not in ProtectionTest.Scenario.values:
        return redirect("ids:protection", project_id=project_id)
    if scenario == ProtectionTest.Scenario.IDS_MARKER:
        job = job_services.create_job(JobType.IDS_TEST, request.project, request.user, request=request)
    else:  # create_job re-checks the permission (administrators only)
        job = job_services.create_job(
            JobType.PROTECTION_TEST, request.project, request.user, params={"scenario": scenario}, request=request
        )
    return redirect("execution:job_detail", project_id=project_id, job_id=job.id)


@perm_required(Perm.VIEW_PROJECT)
def protection_detail(request, project_id, test_id):
    t = get_object_or_404(ProtectionTest, id=test_id, project=request.project)
    cap_id = ((t.details or {}).get("capture") or {}).get("id")
    cap = PcapCapture.objects.filter(id=cap_id, project=request.project).first() if cap_id else None
    tl = charts.timeline_charts(cap.analysis) if cap and cap.state == PcapCapture.State.DONE else {}
    return render(request, "ids/protection_detail.html", {"project": request.project, "t": t, "cap": cap, "tl": tl})
