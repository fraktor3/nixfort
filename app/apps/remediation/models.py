"""Remediation plans and their items (one action on one node)."""

from django.conf import settings
from django.db import models

from apps.core.models import BaseModel


class PlanState(models.TextChoices):
    DRAFT = "DRAFT", "Черновик"
    APPROVED = "APPROVED", "Утверждён"
    REJECTED = "REJECTED", "Отклонён"
    EXECUTING = "EXECUTING", "Выполняется"
    VERIFIED = "VERIFIED", "Применён и подтверждён"
    PARTIAL = "PARTIAL", "Частично"
    ROLLED_BACK = "ROLLED_BACK", "Откачен"
    FAILED = "FAILED", "Не применён"
    UNKNOWN = "UNKNOWN", "Состояние неизвестно"


class ItemState(models.TextChoices):
    PENDING = "PENDING", "Ожидает"
    APPLYING = "APPLYING", "Применяется"
    VERIFYING = "VERIFYING", "Проверяется"
    VERIFIED = "VERIFIED", "Подтверждён"
    FAILED = "FAILED", "Не применён"
    ROLLED_BACK = "ROLLED_BACK", "Откачен"
    UNKNOWN = "UNKNOWN", "Неизвестно"
    SKIPPED = "SKIPPED", "Пропущен"


class RemediationPlan(BaseModel):
    project = models.ForeignKey("inventory.Project", on_delete=models.CASCADE, related_name="plans")
    audit_run = models.ForeignKey("checks.AuditRun", on_delete=models.PROTECT, related_name="plans")
    post_audit_run = models.ForeignKey(
        "checks.AuditRun", null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    state = models.CharField(max_length=12, choices=PlanState.choices, default=PlanState.DRAFT)
    risk = models.CharField(max_length=6, default="LOW")
    options = models.JSONField(default=dict, blank=True)
    not_covered = models.JSONField(default=list, blank=True)  # FAIL results without automatic fix
    plan_hash = models.CharField(max_length=64, blank=True)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    job = models.ForeignKey("execution.Job", null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]


class RemediationItem(BaseModel):
    plan = models.ForeignKey(RemediationPlan, on_delete=models.CASCADE, related_name="items")
    node = models.ForeignKey("inventory.Node", on_delete=models.PROTECT, related_name="+")
    order = models.PositiveSmallIntegerField()
    check_ids = models.JSONField(default=list)
    action_id = models.CharField(max_length=60)
    params = models.JSONField(default=dict)
    risk = models.CharField(max_length=6)
    reversible = models.BooleanField(default=True)
    description = models.CharField(max_length=300)
    state = models.CharField(max_length=12, choices=ItemState.choices, default=ItemState.PENDING)
    snapshot_id = models.CharField(max_length=32, blank=True)
    result = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["order"]
