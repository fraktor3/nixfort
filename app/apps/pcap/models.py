from django.conf import settings
from django.db import models

from apps.core.models import BaseModel


class PcapCapture(BaseModel):
    """A traffic capture on a node, or an uploaded PCAP, with its TShark analysis. The file lives on disk under
    its SHA-256; `analysis` is a pure function of that file, so the record is effectively immutable once DONE."""

    class Source(models.TextChoices):
        CAPTURE = "CAPTURE", "Запись на узле"
        UPLOAD = "UPLOAD", "Загруженный файл"

    class State(models.TextChoices):
        PENDING = "PENDING", "Ожидает"
        DONE = "DONE", "Готово"
        FAILED = "FAILED", "Ошибка"

    project = models.ForeignKey("inventory.Project", on_delete=models.CASCADE, related_name="captures")
    node = models.ForeignKey("inventory.Node", null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    job = models.ForeignKey("execution.Job", null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    source = models.CharField(max_length=10, choices=Source.choices)
    interface = models.CharField(max_length=15, blank=True)
    profile = models.CharField(max_length=10, blank=True)
    duration_s = models.PositiveIntegerField(null=True, blank=True)
    original_name = models.CharField(max_length=120, blank=True)
    sha256 = models.CharField(max_length=64, blank=True)
    size = models.PositiveBigIntegerField(null=True, blank=True)
    truncated = models.BooleanField(default=False)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    state = models.CharField(max_length=8, choices=State.choices, default=State.PENDING)
    error = models.CharField(max_length=300, blank=True)
    analysis = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]

    @property
    def origin(self) -> str:
        if self.source == self.Source.CAPTURE:
            return f"{self.node.name if self.node else '—'}/{self.interface}, {self.duration_s} с"
        return self.original_name or "файл"
