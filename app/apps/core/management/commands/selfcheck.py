"""Operational self-check of a deployed controller (run after every `make up`).

Checks what healthchecks cannot: the broker accepts authenticated clients from other containers,
both worker queues consume tasks, migrations are applied, tools are present.
Exit code 0 only if everything required passed.
"""

from __future__ import annotations

import os
import shutil
import time
import uuid

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import connection
from django.db.migrations.executor import MigrationExecutor


class Command(BaseCommand):
    help = "Проверка работоспособности контроллера NIXFORT: БД, Redis, очереди, инструменты, ключ."

    def add_arguments(self, parser):
        parser.add_argument("--key", action="store_true", help="проверить ключ контроллера (запуск в воркере)")
        parser.add_argument("--timeout", type=int, default=20)

    def handle(self, *args, **opts):
        self.failed = False
        self._step("PostgreSQL: соединение", self._db)
        self._step("PostgreSQL: миграции применены", self._migrations)
        self._step("Redis: аутентифицированный PING", self._redis)
        for queue in ("readonly", "mutation"):
            self._step(
                f"Celery: очередь «{queue}» принимает и выполняет задачи",
                lambda q=queue: self._queue(q, opts["timeout"]),
            )
        for tool in ("nmap", "tshark"):
            self._step(f"Инструмент {tool}", lambda t=tool: shutil.which(t) or self._fail(f"{t} не найден"))
        if opts["key"]:
            self._step("Ключ контроллера читается", self._key)
        if self.failed:
            self.stderr.write(self.style.ERROR("ИТОГ: есть ошибки"))
            raise SystemExit(1)
        self.stdout.write(self.style.SUCCESS("ИТОГ: всё в порядке"))

    def _step(self, title, fn):
        try:
            detail = fn()
            self.stdout.write(
                self.style.SUCCESS("[OK]   ") + title + (f" — {detail}" if isinstance(detail, str) else "")
            )
        except Exception as exc:  # noqa: BLE001 - report every failure, never stop at the first one
            self.failed = True
            self.stdout.write(self.style.ERROR("[FAIL] ") + f"{title} — {exc.__class__.__name__}: {exc}")

    @staticmethod
    def _fail(msg):
        raise RuntimeError(msg)

    def _db(self):
        with connection.cursor() as cur:
            cur.execute("SELECT 1")
        return connection.vendor

    def _migrations(self):
        plan = MigrationExecutor(connection).migration_plan(MigrationExecutor(connection).loader.graph.leaf_nodes())
        if plan:
            raise RuntimeError(f"не применено миграций: {len(plan)}")

    def _redis(self):
        import redis

        if not redis.Redis.from_url(settings.REDIS_URL, socket_timeout=5).ping():
            raise RuntimeError("нет ответа")

    def _queue(self, queue, timeout):
        import redis

        from apps.execution.tasks import selfcheck_ping

        token = uuid.uuid4().hex
        selfcheck_ping.apply_async(args=[token, queue], queue=queue)
        r = redis.Redis.from_url(settings.REDIS_URL, socket_timeout=5)
        key = f"nixfort:selfcheck:{token}:{queue}"
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            host = r.get(key)
            if host:
                return f"выполнено воркером {host.decode()}"
            time.sleep(0.5)
        raise RuntimeError(f"нет ответа за {timeout} с (воркер не запущен или не подключён к брокеру)")

    def _key(self):
        path = settings.NIXFORT_CONTROLLER_KEY_PATH
        if not os.access(path, os.R_OK):
            raise RuntimeError(f"{path} недоступен для чтения")
        import paramiko

        paramiko.Ed25519Key.from_private_key_file(path)
        return path
