from django.contrib import messages
from django.http import FileResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.core import audit
from apps.core.models import Action
from apps.core.rbac import Perm, has_perm, perm_required
from apps.execution import services as job_services
from apps.execution.models import JobType

from . import charts, storage
from .models import PcapCapture

PROFILES = [("ip", "Весь IP-трафик"), ("no_ssh", "Без SSH (порт 22)"), ("all", "Все кадры")]
ROLE_LABEL = {"gateway": "шлюз", "ids_sensor": "датчик IDS"}


def _targets(project):
    """Capturable (node, interface) pairs from the latest inventory of gateway/sensor nodes (not loopback)."""
    out = []
    for n in project.nodes.filter(is_active=True).order_by("name"):
        if not (n.has_role("gateway") or n.has_role("ids_sensor")):
            continue
        snap = n.snapshots.order_by("-collected_at").first()
        ifaces = ((snap.facts.get("system") or {}).get("result") or {}).get("interfaces") if snap else None
        names = [i["name"] for i in (ifaces or []) if i.get("name") and i["name"] != "lo"]
        if not names and n.ids_interface:
            names = [n.ids_interface]
        roles = ", ".join(ROLE_LABEL[r] for r in n.roles if r in ROLE_LABEL)
        for name in names:
            out.append({"value": f"{n.id}:{name}", "label": f"{n.name}, {name} ({roles})",
                        "node": n, "iface": name})  # fmt: skip
    return out


@perm_required(Perm.VIEW_PROJECT)
def pcap_list(request, project_id):
    project = request.project
    return render(request, "pcap/list.html", {
        "project": project,
        "items": PcapCapture.objects.filter(project=project).select_related("node", "created_by")[:50],
        "targets": _targets(project),
        "profiles": PROFILES,
        "can_run": has_perm(request.user, Perm.RUN_JOBS, project) and not project.is_archived,
    })  # fmt: skip


@require_POST
@perm_required(Perm.RUN_JOBS)
def capture_start(request, project_id):
    project = request.project
    target = request.POST.get("target", "")
    valid = {t["value"]: t for t in _targets(project)}
    if target not in valid:
        messages.error(request, "Выберите узел и интерфейс из списка.")
        return redirect("pcap:list", project_id=project_id)
    t = valid[target]
    profile = request.POST.get("profile") if request.POST.get("profile") in dict(PROFILES) else "ip"
    try:
        duration = max(3, min(60, int(request.POST.get("duration_s") or 10)))
    except ValueError:
        duration = 10
    if t["node"].confirmed_hostkey is None:
        messages.error(request, "Ключ узла не подтверждён.")
        return redirect("pcap:list", project_id=project_id)
    cap = PcapCapture.objects.create(
        project=project, node=t["node"], created_by=request.user, source=PcapCapture.Source.CAPTURE,
        interface=t["iface"], profile=profile, duration_s=duration,
    )  # fmt: skip
    job = job_services.create_job(JobType.CAPTURE, project, request.user, node=t["node"],
                                  params={"capture_id": str(cap.id)}, request=request)  # fmt: skip
    cap.job = job
    cap.save(update_fields=["job", "updated_at"])
    return redirect("execution:job_detail", project_id=project_id, job_id=job.id)


@require_POST
@perm_required(Perm.RUN_JOBS)
def upload(request, project_id):
    project = request.project
    f = request.FILES.get("file")
    if not f:
        messages.error(request, "Выберите файл.")
        return redirect("pcap:list", project_id=project_id)
    data = f.read(storage.MAX_UPLOAD_BYTES + 1)
    try:
        sha, size = storage.store_bytes(data)
    except storage.PcapRejected as exc:
        messages.error(request, str(exc))
        return redirect("pcap:list", project_id=project_id)
    cap = PcapCapture.objects.create(
        project=project, created_by=request.user, source=PcapCapture.Source.UPLOAD,
        original_name=f.name[:120], sha256=sha, size=size,
    )  # fmt: skip
    audit.log(request.user, Action.PCAP_UPLOADED, obj=cap, project=project, request=request, sha256=sha, size=size)
    job = job_services.create_job(JobType.PCAP_ANALYZE, project, request.user,
                                  params={"capture_id": str(cap.id)}, request=request)  # fmt: skip
    cap.job = job
    cap.save(update_fields=["job", "updated_at"])
    return redirect("execution:job_detail", project_id=project_id, job_id=job.id)


@perm_required(Perm.VIEW_PROJECT)
def pcap_detail(request, project_id, pcap_id):
    cap = get_object_or_404(PcapCapture.objects.select_related("node", "job"), id=pcap_id, project=request.project)
    return render(request, "pcap/detail.html", {
        "project": request.project, "r": cap, "tl": charts.timeline_charts(cap.analysis),
        "can_download": has_perm(request.user, Perm.RUN_JOBS, request.project),
    })  # fmt: skip


@perm_required(Perm.RUN_JOBS)
def download(request, project_id, pcap_id):
    cap = get_object_or_404(PcapCapture, id=pcap_id, project=request.project)
    if not cap.sha256:
        messages.error(request, "Файл ещё не готов.")
        return redirect("pcap:detail", project_id=project_id, pcap_id=pcap_id)
    path = storage.path_of(cap.sha256)
    name = (cap.original_name or f"capture-{cap.created_at:%Y%m%d-%H%M%S}.pcap").replace("/", "_")
    audit.log(request.user, Action.PCAP_UPLOADED, obj=cap, project=request.project, request=request,
              action_detail="download", sha256=cap.sha256)  # fmt: skip
    return FileResponse(
        open(path, "rb"), as_attachment=True, filename=name, content_type="application/vnd.tcpdump.pcap"
    )
