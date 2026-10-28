import hashlib
from functools import lru_cache
from pathlib import Path

from django.conf import settings

from .rbac import Perm, Role, has_perm, roles_of, visible_projects

# Project navigation: (group, [(label, url name, namespaces that make it current)]).
PROJECT_NAV = [
    (
        None,
        [
            (
                "Обзор",
                "inventory:project_detail",
                (
                    "inventory:project_detail",
                    "inventory:node_detail",
                    "inventory:node_create",
                    "inventory:node_edit",
                    "inventory:project_edit",
                ),
            )
        ],
    ),
    (
        "Сегмент",
        [
            ("Политика соединений", "policy:overview", ("policy:overview", "policy:flow_create", "policy:flow_edit")),
            ("Проверка соединений", "policy:connectivity", ("policy:connectivity",)),
            ("Сканирование портов", "inventory:portscan_list", ("inventory:portscan_list",)),
        ],
    ),
    (
        "Защита",
        [
            ("Аудит", "checks:run_list", ("checks",)),
            ("Исправления", "remediation:plan_list", ("remediation",)),
            ("Датчик IDS", "ids:sensor", ("ids:sensor",)),
            ("Проверка защиты", "ids:protection", ("ids:protection", "ids:protection_detail")),
        ],
    ),
    (
        "Анализ",
        [
            ("Трафик", "pcap:list", ("pcap",)),
            ("Журналы безопасности", "seclog:seclog", ("seclog",)),
        ],
    ),
    (
        "Итоги",
        [
            ("Отчёты", "reports:list", ("reports",)),
            ("Задания", "execution:job_list", ("execution",)),
        ],
    ),
]
ROLE_ORDER = [Role.ADMIN, Role.OPERATOR, Role.VIEWER]
# Phone tab bar: the three places used most, the rest is behind «Меню».
PROJECT_TABS = [("Обзор", "inventory:project_detail"), ("Аудит", "checks:run_list"), ("Задания", "execution:job_list")]


@lru_cache(maxsize=1)
def build_id() -> str:
    """Short id of what is deployed: BUILD_COMMIT if the image was built with it, else a hash of templates
    and static sources. Shown on the login page and in the user menu, so a stale deployment is visible."""
    commit = getattr(settings, "BUILD_COMMIT", "")
    if commit:
        return commit[:10]
    h = hashlib.sha256()
    base = Path(settings.BASE_DIR)
    for sub in ("templates", "static/css", "static/js"):
        for f in sorted((base / sub).rglob("*")):
            if f.is_file():
                h.update(str(f.relative_to(base)).encode())
                h.update(f.read_bytes())
    return h.hexdigest()[:10]


def _jump(project, groups):
    """Targets of the quick jump («/»): sections, nodes and checks of the current project."""
    from django.urls import reverse

    items = []
    for g in groups:
        for i in g["items"]:
            items.append({"kind": "раздел", "label": i["label"], "url": reverse(i["url"], args=[project.id])})
    for n in project.nodes.filter(is_active=True).order_by("name"):
        items.append(
            {"kind": "узел", "label": n.name, "url": reverse("inventory:node_detail", args=[project.id, n.id])}
        )
    from apps.checks import domain

    runs = reverse("checks:run_list", args=[project.id])
    latest = project.audit_runs.order_by("-created_at").first()
    base = reverse("checks:run_detail", args=[project.id, latest.id]) if latest else runs
    for c in domain.CATALOG:
        items.append({"kind": "проверка", "label": f"{c.id} {c.title}", "url": f"{base}?q={c.id}" if latest else runs})
    return items


def _current(request) -> str:
    m = getattr(request, "resolver_match", None)
    return f"{m.namespace}:{m.url_name}" if m else ""


def nav(request):
    user = getattr(request, "user", None)
    if not getattr(user, "is_authenticated", False):
        return {"ui_name": settings.UI_PRODUCT_NAME, "build": build_id()}
    project = getattr(request, "project", None)
    here = _current(request)
    groups = []
    if project is not None:
        from apps.execution.models import Job

        drafts = project.plans.filter(state="DRAFT").count()
        running = Job.objects.filter(project=project, state__in=["QUEUED", "RUNNING", "ROLLING_BACK"]).count()
        for title, items in PROJECT_NAV:
            rows = []
            for label, name, match in items:
                cur = any(here == m or here.startswith(m + ":") or (":" not in m and here.split(":")[0] == m)
                          for m in match)  # fmt: skip
                count = drafts if name == "remediation:plan_list" and drafts else None
                live = f"{running} в работе" if name == "execution:job_list" and running else None
                rows.append({"label": label, "url": name, "current": cur, "count": count, "live": live})
            groups.append({"title": title, "items": rows})
    roles = roles_of(user, project)
    role = next((r.label for r in ROLE_ORDER if r.value in roles), "")
    from django.urls import reverse

    if project is not None:
        tabs = [{"label": label, "url": reverse(name, args=[project.id]),
                 "current": here.split(":")[0] == name.split(":")[0]} for label, name in PROJECT_TABS]  # fmt: skip
        tabs[0]["current"] = here.startswith("inventory:")
        jump = _jump(project, groups)
    else:
        tabs = [{"label": "Обзор", "url": reverse("core:dashboard"), "current": here == "core:dashboard"},
                {"label": "Проекты", "url": reverse("inventory:project_list"), "current": here.startswith("inventory:")},
                {"label": "Журнал", "url": reverse("core:audit_log"), "current": here == "core:audit_log"}]  # fmt: skip
        jump = []
    projects = list(visible_projects(user).order_by("status", "name")[:20])
    jump += [
        {"kind": "проект", "label": p.name, "url": reverse("inventory:project_detail", args=[p.id])} for p in projects
    ]
    jump += [{"kind": "раздел", "label": "Журнал действий", "url": reverse("core:audit_log")},
             {"kind": "раздел", "label": "Все проекты", "url": reverse("inventory:project_list")}]  # fmt: skip
    return {
        "ui_name": settings.UI_PRODUCT_NAME,
        "build": build_id(),
        "nav_tabs": tabs,
        "nav_projects": projects,
        "jump": jump,
        "can_manage_users": has_perm(user, Perm.MANAGE_USERS),
        "can_create_project": has_perm(user, Perm.CREATE_PROJECT),
        "nav_project": project,
        "nav_groups": groups,
        "nav_here": here,
        "nav_role": role,
    }
