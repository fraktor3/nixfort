from django import template

register = template.Library()

STATUS_CLASSES = {
    # checks
    "PASS": "success",
    "FAIL": "danger",
    "UNKNOWN": "secondary",
    "ERROR": "warning",
    "NOT_APPLICABLE": "light",
    # jobs
    "QUEUED": "secondary",
    "RUNNING": "primary",
    "SUCCEEDED": "success",
    "FAILED": "danger",
    "PARTIAL": "warning",
    "CANCELLED": "secondary",
    "ROLLING_BACK": "warning",
    "ROLLED_BACK": "info",
    # plans / misc
    "DRAFT": "secondary",
    "APPROVED": "primary",
    "EXECUTING": "primary",
    "VERIFIED": "success",
    "REJECTED": "dark",
    "ACTIVE": "success",
    "SUPERSEDED": "secondary",
    "ARCHIVED": "secondary",
    "READY": "success",
    "KEY_PENDING": "warning",
    "UNREACHABLE": "danger",
    "UNSUPPORTED": "dark",
    "OPEN": "success",
    "CLOSED": "secondary",
    "TIMEOUT": "secondary",
    "SUCCESS": "success",
    "DENIED": "danger",
}


@register.filter
def status_class(value) -> str:
    return STATUS_CLASSES.get(str(value), "secondary")


@register.filter
def add_class(field, css: str):
    widget = field.field.widget
    existing = widget.attrs.get("class", "")
    if field.errors:
        css += " is-invalid"
    return field.as_widget(attrs={"class": f"{existing} {css}".strip()})


@register.filter
def widget_type(field) -> str:
    return field.field.widget.__class__.__name__


@register.filter
def split(value: str) -> list[str]:
    return str(value).split()


@register.filter
def get_item(mapping, key):
    return mapping.get(key) if isinstance(mapping, dict) else None


@register.filter
def isodt(value) -> str:
    """ISO-8601 string from a stored JSON document -> local «dd.mm.YYYY HH:MM:SS»."""
    from datetime import datetime

    from django.utils import timezone

    try:
        dt = datetime.fromisoformat(str(value))
    except ValueError:
        return str(value or "–")
    if dt.tzinfo is not None:
        dt = timezone.localtime(dt)
    return dt.strftime("%d.%m.%Y %H:%M:%S")


ST = {
    "pass": {"PASS", "SUCCEEDED", "VERIFIED", "ACTIVE", "READY", "SUCCESS", "OK", "PROTECTED", "DONE", "COMMITTED"},
    "fail": {"FAIL", "FAILED", "UNREACHABLE", "DENIED", "VIOLATION", "NOT_PROTECTED", "UNSUPPORTED"},
    "unknown": {"UNKNOWN", "PARTIAL", "ROLLING_BACK", "KEY_PENDING", "ROLLED_BACK", "INCONCLUSIVE"},
    "error": {"ERROR"},
    "run": {"RUNNING", "EXECUTING", "APPROVED", "VERIFYING", "APPLYING", "PENDING"},
}


@register.filter
def st(value) -> str:
    """CSS class of a status mark: s-pass, s-fail, s-unknown, s-error, s-run or s-na."""
    v = str(value)
    for cls, values in ST.items():
        if v in values:
            return f"s-{cls}"
    return "s-na"


@register.filter
def pct(part, whole) -> int:
    try:
        return max(0, min(100, round(100 * float(part) / float(whole))))
    except (TypeError, ValueError, ZeroDivisionError):
        return 0


ROLE_NAMES = {"gateway": "шлюз", "server": "сервер", "ids_sensor": "датчик IDS", "test_client": "тестовый клиент"}


@register.filter
def role_names(roles) -> str:
    return ", ".join(ROLE_NAMES.get(r, r) for r in roles or [])


@register.filter
def job_label(job) -> str:
    """The job's type, with the scenario named for protection tests (four in a row otherwise look the same)."""
    label = job.get_type_display()
    scenario = (job.params or {}).get("scenario")
    if scenario:
        from apps.ids.models import ProtectionTest

        if scenario in ProtectionTest.Scenario.values:
            name = ProtectionTest.Scenario(scenario).label
            label = f"{label}: {name[:1].lower()}{name[1:]}"
    return label


@register.filter
def add_describedby(field):
    """Render a field tied to its help text (aria-describedby), so limits are announced with the field."""
    return field.as_widget(attrs={"aria-describedby": f"{field.auto_id}_help"})


@register.filter
def status_ru(value) -> str:
    """Russian label of a check status code (PASS -> «Соответствует»); other values pass through."""
    from apps.checks.models import CheckStatus
    from apps.remediation.models import ItemState, PlanState

    for choices in (CheckStatus, ItemState, PlanState):
        if value in choices.values:
            return choices(value).label
    return value or "–"


@register.filter
def pairs(mapping) -> list:
    """dict -> [(key, value)]; avoids Django resolving `.items` to a key named «items»."""
    return list(mapping.items()) if isinstance(mapping, dict) else []


SEVERITY_RU = {"CRITICAL": "критическая", "HIGH": "высокая", "MEDIUM": "средняя", "LOW": "низкая"}


@register.filter
def severity_ru(value) -> str:
    return SEVERITY_RU.get(str(value), str(value or "–"))


RISK_RU = {"HIGH": "высокий", "MEDIUM": "средний", "LOW": "низкий"}


@register.filter
def risk_ru(value) -> str:
    return RISK_RU.get(str(value), str(value or "–"))


@register.filter
def when(value) -> str:
    """Compact local time for lists: «сегодня 11:51», «вчера 18:02», «26.10 09:15», «26.10.2025».
    The full timestamp goes into a title attribute next to it (filter `full`)."""
    from datetime import datetime, timedelta

    from django.utils import timezone

    if not value:
        return "–"
    if not isinstance(value, datetime):
        try:
            value = datetime.fromisoformat(str(value))
        except ValueError:
            return str(value)
    if timezone.is_aware(value):
        value = timezone.localtime(value)
    today = timezone.localdate()
    d = value.date()
    if d == today:
        return f"сегодня {value:%H:%M}"
    if d == today - timedelta(days=1):
        return f"вчера {value:%H:%M}"
    if d.year == today.year:
        return f"{value:%d.%m %H:%M}"
    return f"{value:%d.%m.%Y}"


@register.filter
def full(value) -> str:
    """Full local timestamp «28.10.2026 11:51:49» (for titles and documents)."""
    from datetime import datetime

    from django.utils import timezone

    if not value:
        return ""
    if not isinstance(value, datetime):
        return isodt(value)
    if timezone.is_aware(value):
        value = timezone.localtime(value)
    return f"{value:%d.%m.%Y %H:%M:%S}"


@register.filter
def sig(value) -> str:
    """Suricata rule message without the deployment prefix of the bundled test rules."""
    s = str(value or "")
    for prefix in ("NIXFORT ", "NIXFORT: "):
        if s.startswith(prefix):
            return s[len(prefix) :]
    return s


@register.filter
def short_cidrs(cidrs) -> str:
    """First subnet and «+N» for the rest (lists keep one line per row)."""
    cidrs = list(cidrs or [])
    if not cidrs:
        return "–"
    return cidrs[0] + (f" +{len(cidrs) - 1}" if len(cidrs) > 1 else "")


_DEBRAND = [
    ("правила NIXFORT", "тестовые правила"),
    ("Правила NIXFORT", "Тестовые правила"),
    ("Политика NIXFORT", "Политика сегмента"),
    ("таблица NIXFORT", "управляемая таблица правил"),
    ("NIXFORT не будет вносить изменения", "изменения не будут вноситься"),
    ("NIXFORT-", ""),
    ("NIXFORT ", ""),
    ("NIXFORT", ""),
]


@register.filter
def nb(value) -> str:
    """Text stored by earlier versions (results, plan steps, logs) without the internal product name."""
    s = "" if value is None else str(value)
    if "NIXFORT" not in s:
        return s
    for a, b in _DEBRAND:
        s = s.replace(a, b)
    return s
