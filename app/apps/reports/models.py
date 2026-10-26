from django.conf import settings
from django.db import models

from apps.core.models import BaseModel


class Report(BaseModel):
    """Immutable security report of a project: a normalized JSON snapshot + its SHA-256.
    HTML, PDF and JSON are renderings of the same data (what you download is what was hashed)."""

    project = models.ForeignKey("inventory.Project", on_delete=models.CASCADE, related_name="reports")
    title = models.CharField(max_length=200)
    before_run = models.ForeignKey("checks.AuditRun", on_delete=models.PROTECT, related_name="+")
    after_run = models.ForeignKey("checks.AuditRun", on_delete=models.PROTECT, related_name="+")
    generated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    data = models.JSONField()
    sha256 = models.CharField(max_length=64)

    class Meta:
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        if self.pk and Report.objects.filter(pk=self.pk).exists():
            raise PermissionError("Report is immutable")
        super().save(*args, **kwargs)
