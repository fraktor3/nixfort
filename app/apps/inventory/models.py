from __future__ import annotations

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from apps.core.models import BaseModel

from . import validators as v


class Project(BaseModel):
    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", "Активен"
        ARCHIVED = "ARCHIVED", "В архиве"

    name = models.CharField("Название", max_length=100, unique=True)
    description = models.TextField("Описание", blank=True, max_length=2000)
    cidrs = models.JSONField("Подсети", default=list)
    controller_ip = models.GenericIPAddressField("IP контроллера NIXFORT (mgmt)", protocol="IPv4")
    # Extra sources that keep SSH access to the gateway after the firewall policy is applied (FW-04).
    admin_sources = models.JSONField("Дополнительные адреса администраторов", default=list, blank=True)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.ACTIVE)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    def clean(self):
        if not isinstance(self.cidrs, list) or not 1 <= len(self.cidrs) <= 16:
            raise ValidationError({"cidrs": "Укажите от 1 до 16 подсетей."})
        self.cidrs = [v.parse_network(c) for c in self.cidrs]
        if self.controller_ip and not v.ip_in_networks(self.controller_ip, self.cidrs):
            raise ValidationError({"controller_ip": "IP контроллера должен входить в подсети проекта."})
        if not isinstance(self.admin_sources, list) or len(self.admin_sources) > 3:
            raise ValidationError({"admin_sources": "Не больше 3 адресов."})
        self.admin_sources = [v.parse_ipv4(ip) for ip in self.admin_sources]

    @property
    def management_sources(self) -> list[str]:
        """Who must keep SSH to the gateway: the controller first, then administrators (≤ 4 in total)."""
        out = [self.controller_ip]
        for ip in self.admin_sources or []:
            if ip not in out:
                out.append(ip)
        return out[:4]

    @property
    def is_archived(self) -> bool:
        return self.status == self.Status.ARCHIVED


class Node(BaseModel):
    class Status(models.TextChoices):
        KEY_PENDING = "KEY_PENDING", "Ключ не подтверждён"
        READY = "READY", "Готов"
        UNREACHABLE = "UNREACHABLE", "Недоступен"
        UNSUPPORTED = "UNSUPPORTED", "ОС не поддерживается"

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="nodes")
    name = models.CharField("Имя", max_length=64, validators=[v.validate_name])
    mgmt_ip = models.GenericIPAddressField("IP управления", protocol="IPv4")
    data_ips = models.JSONField("Рабочие IP", default=list, blank=True)
    ssh_port = models.PositiveIntegerField("SSH-порт", default=22)
    roles = models.JSONField("Роли", default=list)
    expected_os = models.CharField("Ожидаемая ОС", max_length=20, choices=v.SUPPORTED_OS, default="ubuntu-24.04")
    expected_tcp_ports = models.JSONField("Ожидаемые TCP-порты", default=list, blank=True)
    ids_interface = models.CharField("Интерфейс датчика IDS", max_length=15, blank=True)
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.KEY_PENDING)
    is_active = models.BooleanField(default=True)
    last_inventory_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(fields=["project", "name"], name="uniq_node_name_in_project"),
            models.UniqueConstraint(fields=["project", "mgmt_ip"], name="uniq_node_mgmt_ip_in_project"),
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.mgmt_ip})"

    def clean(self):
        errors: dict[str, str] = {}
        cidrs = self.project.cidrs if self.project_id else []
        if self.mgmt_ip and cidrs and not v.ip_in_networks(self.mgmt_ip, cidrs):
            errors["mgmt_ip"] = "Адрес вне подсетей проекта."
        if not isinstance(self.data_ips, list) or len(self.data_ips) > 8:
            errors["data_ips"] = "Не больше 8 рабочих адресов."
        else:
            try:
                self.data_ips = [v.parse_ipv4(ip) for ip in self.data_ips]
                bad = [ip for ip in self.data_ips if cidrs and not v.ip_in_networks(ip, cidrs)]
                if bad:
                    errors["data_ips"] = f"Адреса вне подсетей проекта: {', '.join(bad)}"
            except ValidationError as exc:
                errors["data_ips"] = exc.messages[0]
        if not 1 <= int(self.ssh_port or 0) <= 65535:
            errors["ssh_port"] = "Порт 1–65535."
        if not isinstance(self.roles, list) or not self.roles or any(r not in v.NODE_ROLES for r in self.roles):
            errors["roles"] = "Выберите хотя бы одну роль."
        if "ids_sensor" in (self.roles or []):
            if not v.IFACE_RE.fullmatch(self.ids_interface or ""):
                errors["ids_interface"] = "Для датчика IDS укажите интерфейс (например enp0s9)."
        elif self.ids_interface and not v.IFACE_RE.fullmatch(self.ids_interface):
            errors["ids_interface"] = "Некорректное имя интерфейса."
        if not isinstance(self.expected_tcp_ports, list) or any(
            not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535 for p in self.expected_tcp_ports
        ):
            errors["expected_tcp_ports"] = "Список портов 1–65535."
        if errors:
            raise ValidationError(errors)

    @property
    def all_ips(self) -> list[str]:
        return [self.mgmt_ip, *self.data_ips]

    def has_role(self, role: str) -> bool:
        return role in (self.roles or [])

    @property
    def confirmed_hostkey(self) -> HostKey | None:
        hk = getattr(self, "hostkey", None)
        return hk if hk and hk.confirmed_at else None


class HostKey(BaseModel):
    """SSH host key of a node. Operations require a key confirmed by an administrator."""

    node = models.OneToOneField(Node, on_delete=models.CASCADE, related_name="hostkey")
    key_type = models.CharField(max_length=32)
    public_key = models.TextField()
    fingerprint_sha256 = models.CharField(max_length=60)
    source = models.CharField(max_length=20, default="manual")  # manual | fetched
    confirmed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    confirmed_at = models.DateTimeField(null=True, blank=True)


class InventorySnapshot(BaseModel):
    """Immutable result of one inventory collection for one node."""

    node = models.ForeignKey(Node, on_delete=models.CASCADE, related_name="snapshots")
    job = models.ForeignKey("execution.Job", null=True, on_delete=models.SET_NULL, related_name="+")
    collected_at = models.DateTimeField()
    facts = models.JSONField(default=dict)
    agent_version = models.CharField(max_length=20, blank=True)
    sha256 = models.CharField(max_length=64)

    class Meta:
        ordering = ["-collected_at"]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise PermissionError("InventorySnapshot is immutable")
        super().save(*args, **kwargs)


class PortScan(BaseModel):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="port_scans")
    job = models.ForeignKey("execution.Job", null=True, on_delete=models.SET_NULL, related_name="+")
    targets = models.JSONField(default=list)
    ports = models.CharField(max_length=200)
    result = models.JSONField(default=dict)
    started_at = models.DateTimeField(null=True)
    finished_at = models.DateTimeField(null=True)

    class Meta:
        ordering = ["-created_at"]
