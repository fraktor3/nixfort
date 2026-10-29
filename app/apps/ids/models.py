"""Suricata events read from the sensor and protection test results."""

from django.db import models

from apps.core.models import BaseModel

# Suricata rules shipped with the agent (sensor profile): sid range reserved for the test rules.
TEST_RULE_SIDS = (9000001, 9000099)


class IdsEvent(BaseModel):
    """One Suricata EVE event (alert/anomaly) read from a sensor. Only whitelisted fields are kept."""

    project = models.ForeignKey("inventory.Project", on_delete=models.CASCADE, related_name="ids_events")
    node = models.ForeignKey("inventory.Node", on_delete=models.CASCADE, related_name="ids_events")
    job = models.ForeignKey("execution.Job", null=True, on_delete=models.SET_NULL, related_name="+")
    ts = models.DateTimeField()
    event_type = models.CharField(max_length=10)
    signature_id = models.BigIntegerField(null=True)
    signature = models.CharField(max_length=256, blank=True)
    severity = models.PositiveSmallIntegerField(null=True)
    src_ip = models.GenericIPAddressField(null=True)
    src_port = models.PositiveIntegerField(null=True)
    dest_ip = models.GenericIPAddressField(null=True)
    dest_port = models.PositiveIntegerField(null=True)
    proto = models.CharField(max_length=10, blank=True)

    class Meta:
        ordering = ["-ts"]
        constraints = [
            models.UniqueConstraint(
                fields=["node", "ts", "event_type", "signature_id", "src_ip", "src_port", "dest_ip", "dest_port"],
                name="uniq_ids_event",
            )
        ]


class ProtectionTest(BaseModel):
    """Result of one protection scenario: what each defence layer did against a simulated attack."""

    class Scenario(models.TextChoices):
        IDS_MARKER = "IDS_MARKER", "Тестовое событие IDS"
        PORT_SCAN = "PORT_SCAN", "Сканирование портов"
        SSH_BRUTEFORCE = "SSH_BRUTEFORCE", "Подбор пароля SSH"
        LOAD = "LOAD", "Проверка устойчивости под нагрузкой"

    class Verdict(models.TextChoices):
        PROTECTED = "PROTECTED", "Защита сработала"
        PARTIAL = "PARTIAL", "Частично"
        NOT_PROTECTED = "NOT_PROTECTED", "Защита не сработала"
        ERROR = "ERROR", "Проверка не выполнена"

    project = models.ForeignKey("inventory.Project", on_delete=models.CASCADE, related_name="protection_tests")
    job = models.ForeignKey("execution.Job", null=True, on_delete=models.SET_NULL, related_name="+")
    scenario = models.CharField(max_length=20, choices=Scenario.choices)
    verdict = models.CharField(max_length=15, choices=Verdict.choices)
    layers = models.JSONField(default=list)  # [{layer, expected, observed, ok: true|false|null}]
    details = models.JSONField(default=dict)
    summary = models.CharField(max_length=300, blank=True)

    class Meta:
        ordering = ["-created_at"]
