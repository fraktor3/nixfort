"""Connection policy versions, their flows and connectivity probe results."""

from __future__ import annotations

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from apps.core.models import BaseModel
from apps.inventory import validators as v
from apps.inventory.models import Node, Project


class FlowPolicyVersion(BaseModel):
    class Status(models.TextChoices):
        DRAFT = "DRAFT", "Черновик"
        ACTIVE = "ACTIVE", "Активна"
        SUPERSEDED = "SUPERSEDED", "Заменена"

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="policy_versions")
    version = models.PositiveIntegerField()
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.DRAFT)
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    change_summary = models.CharField("Что изменено", max_length=300, blank=True)
    activated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-version"]
        constraints = [
            models.UniqueConstraint(fields=["project", "version"], name="uniq_policy_version"),
            models.UniqueConstraint(
                fields=["project"], condition=models.Q(status="ACTIVE"), name="one_active_policy_per_project"
            ),
            models.UniqueConstraint(
                fields=["project"], condition=models.Q(status="DRAFT"), name="one_draft_policy_per_project"
            ),
        ]

    def __str__(self) -> str:
        return f"v{self.version} ({self.get_status_display()})"

    @property
    def editable(self) -> bool:
        return self.status == self.Status.DRAFT


class Flow(BaseModel):
    """Expected TCP/IPv4 interaction. ALLOW must keep working, DENY must be blocked (verified by probes)."""

    class Action(models.TextChoices):
        ALLOW = "ALLOW", "Разрешить"
        DENY = "DENY", "Запретить"

    policy_version = models.ForeignKey(FlowPolicyVersion, on_delete=models.CASCADE, related_name="flows")
    name = models.CharField("Назначение", max_length=100)
    src_cidr = models.CharField("Источник (IP или подсеть)", max_length=18)
    dst_node = models.ForeignKey(Node, on_delete=models.PROTECT, related_name="+", verbose_name="Узел назначения")
    dst_ip = models.GenericIPAddressField("IP назначения", protocol="IPv4")
    port = models.PositiveIntegerField("TCP-порт")
    action = models.CharField("Действие", max_length=5, choices=Action.choices)
    critical = models.BooleanField("Критичный (нарушение → откат)", default=False)
    probe_from = models.ForeignKey(
        Node, null=True, blank=True, on_delete=models.PROTECT, related_name="+", verbose_name="Проверять с узла"
    )

    class Meta:
        ordering = ["dst_ip", "port", "action"]

    def __str__(self) -> str:
        return f"{self.action} {self.src_cidr} → {self.dst_ip}:{self.port}"

    def clean(self):
        errors = {}
        try:
            self.src_cidr = v.parse_ip_or_network(self.src_cidr)
        except ValidationError as exc:
            errors["src_cidr"] = exc.messages[0]
        if not 1 <= int(self.port or 0) <= 65535:
            errors["port"] = "Порт 1–65535."
        pv = self.policy_version
        if self.dst_node_id:
            if self.dst_node.project_id != pv.project_id:
                errors["dst_node"] = "Узел из другого проекта."
            elif self.dst_ip and self.dst_ip not in self.dst_node.all_ips:
                errors["dst_ip"] = "Этот IP не принадлежит выбранному узлу."
        if self.probe_from_id:
            pf = self.probe_from
            if pf.project_id != pv.project_id or not pf.has_role("test_client"):
                errors["probe_from"] = "Нужен узел этого проекта с ролью «тестовый клиент»."
            elif "src_cidr" not in errors:
                import ipaddress

                src = ipaddress.ip_network(self.src_cidr, strict=False)
                if not any(ipaddress.ip_address(ip) in src for ip in pf.data_ips):
                    errors["probe_from"] = (
                        "У тестового узла нет рабочего адреса внутри источника, поэтому проверка будет недостоверной."
                    )
        if errors:
            raise ValidationError(errors)


class ConnectivityTest(BaseModel):
    """One TCP probe of one flow from its test node, with the verdict against expectations.
    Flow fields are copied: the result stays readable after the policy changes."""

    class Phase(models.TextChoices):
        CHECK = "CHECK", "Проверка"
        BASELINE = "BASELINE", "До изменения"
        POST = "POST", "После изменения"
        AFTER_ROLLBACK = "AFTER_ROLLBACK", "После отката"

    class Verdict(models.TextChoices):
        OK = "OK", "Соответствует"
        VIOLATION = "VIOLATION", "Нарушение"
        UNPROVABLE = "UNPROVABLE", "Не доказуемо"
        NOT_CHECKED = "NOT_CHECKED", "Не проверено"

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="connectivity_tests")
    job = models.ForeignKey("execution.Job", null=True, on_delete=models.SET_NULL, related_name="+")
    plan_item = models.ForeignKey(
        "remediation.RemediationItem", null=True, blank=True, on_delete=models.CASCADE, related_name="probes"
    )
    phase = models.CharField(max_length=15, choices=Phase.choices)
    flow = models.ForeignKey(Flow, null=True, on_delete=models.SET_NULL, related_name="+")
    policy_version = models.PositiveIntegerField()
    flow_name = models.CharField(max_length=100)
    src_cidr = models.CharField(max_length=18)
    dst_ip = models.GenericIPAddressField(protocol="IPv4")
    port = models.PositiveIntegerField()
    action = models.CharField(max_length=5)
    critical = models.BooleanField(default=False)
    probe_node = models.CharField(max_length=64, blank=True)
    result = models.CharField(max_length=12)  # OPEN | CLOSED | TIMEOUT | UNREACHABLE | ERROR | NOT_RUN
    latency_ms = models.PositiveIntegerField(null=True)
    verdict = models.CharField(max_length=12, choices=Verdict.choices)
    note = models.CharField(max_length=200, blank=True)

    class Meta:
        ordering = ["created_at", "dst_ip", "port"]
