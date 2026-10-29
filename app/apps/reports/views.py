"""Pages: reports list and one report; JSON and PDF downloads."""

from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.views.decorators.http import require_POST

from apps.checks.models import AuditRun
from apps.core import audit
from apps.core.models import Action
from apps.core.rbac import Perm, has_perm, perm_required

from . import builder
from .models import Report


def _runs(project):
    return list(AuditRun.objects.filter(project=project, state="DONE").order_by("created_at"))


@perm_required(Perm.VIEW_PROJECT)
def report_list(request, project_id):
    project = request.project
    runs = _runs(project)
    return render(
        request,
        "reports/report_list.html",
        {
            "project": project,
            "reports": Report.objects.filter(project=project).select_related("generated_by", "before_run", "after_run")[
                :50
            ],
            "runs": runs,
            "default_before": runs[0].id if runs else None,
            "default_after": runs[-1].id if runs else None,
            "can_create": has_perm(request.user, Perm.EXPORT_REPORT, project) and not project.is_archived,
        },
    )


@require_POST
@perm_required(Perm.EXPORT_REPORT)
def report_create(request, project_id):
    project = request.project
    before = get_object_or_404(AuditRun, id=request.POST.get("before"), project=project, state="DONE")
    after = get_object_or_404(AuditRun, id=request.POST.get("after"), project=project, state="DONE")
    if after.created_at < before.created_at:
        messages.error(request, "Аудит «после» должен быть не раньше аудита «до».")
        return redirect("reports:list", project_id=project_id)
    data = builder.build(project, before, after, request.user)
    report = Report.objects.create(
        project=project,
        title=f"Отчёт о защищённости «{project.name}»",
        before_run=before,
        after_run=after,
        generated_by=request.user,
        data=data,
        sha256=builder.digest(data),
    )
    audit.log(request.user, Action.REPORT_EXPORTED, obj=report, project=project, request=request,
              format="create", sha256=report.sha256)  # fmt: skip
    return redirect("reports:detail", project_id=project_id, report_id=report.id)


def _ctx(report):
    d = report.data
    changed = [c for c in d.get("comparison", []) if c["changed"]]
    totals = lambda run: {k: v for k, v in (run.get("totals") or {}).items() if v}  # noqa: E731
    return {
        "report": report,
        "d": d,
        "changed": changed,
        "before_totals": totals(d["before"]),
        "after_totals": totals(d["after"]),
        "complete": sum(1 for e in d.get("completeness", []) if e["present"]),
    }


@perm_required(Perm.VIEW_PROJECT)
def report_detail(request, project_id, report_id):
    report = get_object_or_404(Report, id=report_id, project=request.project)
    ctx = {**_ctx(report), "project": request.project,
           "can_export": has_perm(request.user, Perm.EXPORT_REPORT, request.project)}  # fmt: skip
    return render(request, "reports/report_detail.html", ctx)


@perm_required(Perm.EXPORT_REPORT)
def report_download(request, project_id, report_id, fmt):
    report = get_object_or_404(Report, id=report_id, project=request.project)
    name = f"security-report-{report.created_at:%Y%m%d-%H%M}"
    if fmt == "json":
        body = builder.canonical(report.data)
        if builder.digest(report.data) != report.sha256:  # stored data was altered behind our back
            return HttpResponse("Целостность отчёта нарушена", status=409)
        resp = HttpResponse(body, content_type="application/json; charset=utf-8")
        resp["X-Report-SHA256"] = report.sha256
    elif fmt == "pdf":
        try:
            from weasyprint import HTML
        except (ImportError, OSError):
            messages.error(request, "PDF недоступен: не установлена библиотека WeasyPrint.")
            return redirect("reports:detail", project_id=project_id, report_id=report_id)
        html = render_to_string("reports/report_print.html", {**_ctx(report), "project": request.project})
        resp = HttpResponse(HTML(string=html).write_pdf(), content_type="application/pdf")
    else:
        return HttpResponse(status=404)
    resp["Content-Disposition"] = f'attachment; filename="{name}.{fmt}"'
    audit.log(request.user, Action.REPORT_EXPORTED, obj=report, project=request.project, request=request,
              format=fmt, sha256=report.sha256)  # fmt: skip
    return resp
