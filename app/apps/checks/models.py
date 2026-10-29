"""Audit data: AuditRun, CheckResult per node and check, Evidence (source and SHA-256 of the facts)."""

from django.conf import settings
from django.db import models

from apps.core.models import BaseModel

from .domain import STATUSES


class CheckStatus(models.TextChoices):
    PASS = "PASS", "Соответствует"
    FAIL = "FAIL", "Нарушение"
    UNKNOWN = "UNKNOWN", "Нет данных"
    NOT_APPLICABLE = "NOT_APPLICABLE", "Не применимо"
    ERROR = "ERROR", "Ошибка проверки"


assert set(CheckStatus.values) == set(STATUSES)  # noqa: S101 - import-time consistency guard


class AuditRun(BaseModel):
    class State(models.TextChoices):
        RUNNING = "RUNNING", "Выполняется"
        DONE = "DONE", "Завершён"
        FAILED = "FAILED", "Ошибка"

    project = models.ForeignKey("inventory.Project", on_delete=models.CASCADE, related_name="audit_runs")
    job = models.OneToOneField("execution.Job", null=True, on_delete=models.SET_NULL, related_name="audit_run")
    initiated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    catalog_version = models.CharField(max_length=20)
    policy_version = models.PositiveIntegerField(null=True, blank=True)
    purpose = models.CharField(max_length=20, default="baseline")  # baseline | post_change
    state = models.CharField(max_length=10, choices=State.choices, default=State.RUNNING)
    summary = models.JSONField(default=dict, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]


class Evidence(BaseModel):
    """Where a result came from: snapshot, agent action, time and a hash of the raw fact."""

    node = models.ForeignKey("inventory.Node", on_delete=models.CASCADE, related_name="+")
    snapshot = models.ForeignKey("inventory.InventorySnapshot", null=True, on_delete=models.SET_NULL, related_name="+")
    source = models.CharField(max_length=60)
    collected_at = models.DateTimeField(null=True)
    sha256 = models.CharField(max_length=64)


class CheckResult(BaseModel):
    audit_run = models.ForeignKey(AuditRun, on_delete=models.CASCADE, related_name="results")
    node = models.ForeignKey("inventory.Node", on_delete=models.CASCADE, related_name="check_results")
    check_id = models.CharField(max_length=10, db_index=True)
    status = models.CharField(max_length=15, choices=CheckStatus.choices)
    observed = models.JSONField(null=True, blank=True)
    expected = models.JSONField(null=True, blank=True)
    explanation = models.TextField(blank=True)
    evidence = models.ManyToManyField(Evidence, blank=True)

    class Meta:
        ordering = ["node__name", "check_id"]
        constraints = [models.UniqueConstraint(fields=["audit_run", "node", "check_id"], name="uniq_result")]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise PermissionError("CheckResult is immutable (FR-AUD-02)")
        super().save(*args, **kwargs)

    @property
    def definition(self):
        from .domain import BY_ID

        return BY_ID.get(self.check_id)
