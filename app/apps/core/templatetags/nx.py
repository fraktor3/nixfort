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
