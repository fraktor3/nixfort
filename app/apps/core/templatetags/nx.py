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
        return str(value or "—")
    if dt.tzinfo is not None:
        dt = timezone.localtime(dt)
    return dt.strftime("%d.%m.%Y %H:%M:%S")
