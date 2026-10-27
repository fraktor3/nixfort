from django.conf import settings
from django.db import models

from apps.core.models import BaseModel


class SecuritySummary(BaseModel):
    """A point-in-time security-log summary of a project: SSH auth failures and Fail2ban bans per server,
    plus a count of IDS alerts. Read-only snapshot; `data` is what was collected at `created_at`."""

    class State(models.TextChoices):
        RUNNING = "RUNNING", "Собирается"
        DONE = "DONE", "Готово"
        FAILED = "FAILED", "Ошибка"

    project = models.ForeignKey("inventory.Project", on_delete=models.CASCADE, related_name="security_summaries")
    job = models.ForeignKey("execution.Job", null=True, on_delete=models.SET_NULL, related_name="+")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    state = models.CharField(max_length=8, choices=State.choices, default=State.RUNNING)
    window_hours = models.PositiveIntegerField(default=24)
    data = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]
