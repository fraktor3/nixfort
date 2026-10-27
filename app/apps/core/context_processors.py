from django.conf import settings

from .rbac import Perm, Role, has_perm, roles_of

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


def _current(request) -> str:
    m = getattr(request, "resolver_match", None)
    return f"{m.namespace}:{m.url_name}" if m else ""


def nav(request):
    user = getattr(request, "user", None)
    if not getattr(user, "is_authenticated", False):
        return {}
    project = getattr(request, "project", None)
    here = _current(request)
    groups = []
    if project is not None:
        drafts = project.plans.filter(state="DRAFT").count()
        for title, items in PROJECT_NAV:
            rows = []
            for label, name, match in items:
                cur = any(here == m or here.startswith(m + ":") or (":" not in m and here.split(":")[0] == m)
                          for m in match)  # fmt: skip
                count = drafts if name == "remediation:plan_list" and drafts else None
                rows.append({"label": label, "url": name, "current": cur, "count": count})
            groups.append({"title": title, "items": rows})
    roles = roles_of(user, project)
    role = next((r.label for r in ROLE_ORDER if r.value in roles), "")
    return {
        "nixfort_version": settings.NIXFORT_VERSION,
        "can_manage_users": has_perm(user, Perm.MANAGE_USERS),
        "can_create_project": has_perm(user, Perm.CREATE_PROJECT),
        "nav_project": project,
        "nav_groups": groups,
        "nav_here": here,
        "nav_role": role,
    }
