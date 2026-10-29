"""Jobs: type, queue, state machine, progress and the job log."""

from __future__ import annotations

from django.conf import settings
from django.db import models

from apps.core.models import BaseModel


class JobType(models.TextChoices):
    NOOP_TEST = "NOOP_TEST", "Тестовое задание"
    INVENTORY = "INVENTORY", "Инвентаризация"
    FETCH_HOSTKEY = "FETCH_HOSTKEY", "Получение ключа узла"
    PORT_SCAN = "PORT_SCAN", "Сканирование портов"
    AUDIT = "AUDIT", "Аудит"
    PLAN_EXECUTE = "PLAN_EXECUTE", "Выполнение плана"
    CONNECTIVITY = "CONNECTIVITY", "Проверка соединений"
    IDS_FETCH = "IDS_FETCH", "События IDS"
    IDS_TEST = "IDS_TEST", "Тестовое событие IDS"
    PROTECTION_TEST = "PROTECTION_TEST", "Проверка защиты"
    CAPTURE = "CAPTURE", "Захват трафика"
    PCAP_ANALYZE = "PCAP_ANALYZE", "Анализ PCAP"
    REPORT = "REPORT", "Отчёт"
    SECURITY_LOGS = "SECURITY_LOGS", "Журналы безопасности"


MUTATION_TYPES = frozenset({JobType.PLAN_EXECUTE})


class JobState(models.TextChoices):
    QUEUED = "QUEUED", "В очереди"
    RUNNING = "RUNNING", "Выполняется"
    SUCCEEDED = "SUCCEEDED", "Успешно"
    FAILED = "FAILED", "Ошибка"
    PARTIAL = "PARTIAL", "Частично"
    CANCELLED = "CANCELLED", "Отменено"
    ROLLING_BACK = "ROLLING_BACK", "Откат"
    ROLLED_BACK = "ROLLED_BACK", "Откачено"
    UNKNOWN = "UNKNOWN", "Состояние неизвестно"


TERMINAL_STATES = frozenset(
    {JobState.SUCCEEDED, JobState.FAILED, JobState.PARTIAL, JobState.CANCELLED, JobState.ROLLED_BACK, JobState.UNKNOWN}
)

# ARCHITECTURE §4. Anything not listed is forbidden.
ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    JobState.QUEUED: frozenset({JobState.RUNNING, JobState.CANCELLED, JobState.UNKNOWN, JobState.FAILED}),
    JobState.RUNNING: frozenset(
        {
            JobState.SUCCEEDED,
            JobState.FAILED,
            JobState.PARTIAL,
            JobState.UNKNOWN,
            JobState.ROLLING_BACK,
            JobState.CANCELLED,
        }
    ),
    JobState.ROLLING_BACK: frozenset({JobState.ROLLED_BACK, JobState.UNKNOWN, JobState.FAILED}),
}


class Job(BaseModel):
    type = models.CharField(max_length=20, choices=JobType.choices)
    project = models.ForeignKey("inventory.Project", on_delete=models.CASCADE, related_name="jobs")
    node = models.ForeignKey("inventory.Node", null=True, blank=True, on_delete=models.SET_NULL, related_name="jobs")
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    queue = models.CharField(max_length=10, default="readonly")
    state = models.CharField(max_length=14, choices=JobState.choices, default=JobState.QUEUED, db_index=True)
    phase = models.CharField(max_length=60, blank=True)
    progress = models.PositiveSmallIntegerField(default=0)
    params = models.JSONField(default=dict, blank=True)
    result = models.JSONField(default=dict, blank=True)
    safe_error_code = models.CharField(max_length=40, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    deadline_at = models.DateTimeField()

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.get_type_display()} [{self.get_state_display()}]"

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def is_mutation(self) -> bool:
        return self.type in MUTATION_TYPES


class JobLog(models.Model):
    class Level(models.TextChoices):
        INFO = "INFO", "Инфо"
        WARN = "WARN", "Внимание"
        ERROR = "ERROR", "Ошибка"

    job = models.ForeignKey(Job, on_delete=models.CASCADE, related_name="logs")
    ts = models.DateTimeField(auto_now_add=True)
    level = models.CharField(max_length=5, choices=Level.choices, default=Level.INFO)
    message = models.CharField(max_length=1000)

    class Meta:
        ordering = ["ts", "id"]
