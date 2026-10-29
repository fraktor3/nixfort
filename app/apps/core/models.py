"""Shared base model (UUID, timestamps) and the append-only audit journal (AuditEvent)."""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models


class BaseModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class Action(models.TextChoices):
    LOGIN = "LOGIN", "Вход"
    LOGIN_FAILED = "LOGIN_FAILED", "Неудачный вход"
    LOGOUT = "LOGOUT", "Выход"
    ACCESS_DENIED = "ACCESS_DENIED", "Отказ в доступе"
    USER_CREATED = "USER_CREATED", "Создан пользователь"
    USER_UPDATED = "USER_UPDATED", "Изменён пользователь"
    ROLE_GRANTED = "ROLE_GRANTED", "Назначена роль"
    ROLE_REVOKED = "ROLE_REVOKED", "Снята роль"
    PROJECT_CREATED = "PROJECT_CREATED", "Создан проект"
    PROJECT_UPDATED = "PROJECT_UPDATED", "Изменён проект"
    PROJECT_ARCHIVED = "PROJECT_ARCHIVED", "Проект в архиве"
    NODE_CREATED = "NODE_CREATED", "Добавлен узел"
    NODE_UPDATED = "NODE_UPDATED", "Изменён узел"
    NODE_DEACTIVATED = "NODE_DEACTIVATED", "Узел отключён"
    HOSTKEY_ADDED = "HOSTKEY_ADDED", "Добавлен ключ узла"
    HOSTKEY_CONFIRMED = "HOSTKEY_CONFIRMED", "Подтверждён ключ узла"
    HOSTKEY_MISMATCH = "HOSTKEY_MISMATCH", "Несовпадение ключа узла"
    POLICY_VERSION_CREATED = "POLICY_VERSION_CREATED", "Создана версия политики"
    POLICY_UPDATED = "POLICY_UPDATED", "Изменена политика"
    POLICY_ACTIVATED = "POLICY_ACTIVATED", "Активирована политика"
    JOB_CREATED = "JOB_CREATED", "Создано задание"
    JOB_FINISHED = "JOB_FINISHED", "Задание завершено"
    PLAN_CREATED = "PLAN_CREATED", "Создан план"
    PLAN_APPROVED = "PLAN_APPROVED", "План утверждён"
    PLAN_REJECTED = "PLAN_REJECTED", "План отклонён"
    PLAN_FINISHED = "PLAN_FINISHED", "План выполнен"
    ROLLBACK = "ROLLBACK", "Откат"
    REPORT_EXPORTED = "REPORT_EXPORTED", "Экспорт отчёта"
    PCAP_UPLOADED = "PCAP_UPLOADED", "Загружен PCAP"


class Outcome(models.TextChoices):
    SUCCESS = "SUCCESS", "Успех"
    DENIED = "DENIED", "Отказ"
    FAILED = "FAILED", "Ошибка"


class AppendOnlyQuerySet(models.QuerySet):
    def update(self, **kwargs):  # noqa: ARG002
        raise PermissionError("AuditEvent is append-only")

    def delete(self):
        raise PermissionError("AuditEvent is append-only")


class AuditEvent(models.Model):
    """Append-only journal of user and system actions (SECURITY T13)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ts = models.DateTimeField(auto_now_add=True, db_index=True)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT)
    actor_name = models.CharField(max_length=150, blank=True)  # survives user rename, readable in reports
    action = models.CharField(max_length=40, choices=Action.choices, db_index=True)
    object_type = models.CharField(max_length=40, blank=True)
    object_id = models.CharField(max_length=64, blank=True)
    project_id = models.UUIDField(null=True, blank=True, db_index=True)
    outcome = models.CharField(max_length=10, choices=Outcome.choices, default=Outcome.SUCCESS)
    ip = models.GenericIPAddressField(null=True, blank=True)
    safe_metadata = models.JSONField(default=dict, blank=True)

    objects = AppendOnlyQuerySet.as_manager()

    class Meta:
        ordering = ["-ts"]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise PermissionError("AuditEvent is append-only")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise PermissionError("AuditEvent is append-only")

    def __str__(self) -> str:
        return f"{self.ts:%Y-%m-%d %H:%M:%S} {self.actor_name} {self.action} {self.outcome}"
