# T-001 — Каркас репозитория и запуск контроллера

| Поле | Значение |
|---|---|
| Приоритет | P1 |
| Зависит от | — |
| Модули | корень репо, `app/config`, `deploy/`, `.github/workflows/` |
| Читать | PROJECT_CONTEXT, ARCHITECTURE §1, §2, §10, §11; SECURITY §4 п.10; DECISIONS ADR-014, ADR-015 |
| AT | AT-01 (частично) |

## Цель
Пустое, но правильно устроенное Django-приложение, которое запускается одной командой в Docker Compose на nx-controller по HTTPS и проходит тесты локально на Windows и в CI.

## Что сделать
1. `pyproject.toml` (Python ≥3.12, setuptools): зависимости — `Django~=5.2`, `psycopg[binary]~=3.2`, `celery~=5.4`, `redis~=5.0`, `gunicorn`, `django-axes`, `paramiko~=3.5`, `defusedxml`, `weasyprint` (extra `pdf`); dev — `pytest`, `pytest-django`, `pytest-cov`, `ruff`, `mypy`, `pip-audit`, `django-stubs`. Настройки `ruff` (line-length 110, правила E,F,I,B,S,UP) и `pytest` (`DJANGO_SETTINGS_MODULE=config.settings.test`, маркер `integration`).
   Правило ruff `S602,S604,S605,S607` (shell) — **ошибка**, без исключений.
2. Django-проект в `app/`: `manage.py`, `config/settings/{base,dev,test,prod}.py`, `config/urls.py`, `config/celery.py`, `config/wsgi.py`.
   - `base`: русский язык (`ru`), `TIME_ZONE="Europe/Moscow"`, `USE_TZ=True`, `DEFAULT_AUTO_FIELD` не используется — модели будут с UUID; шаблоны `app/templates`, статика `app/static`; все секреты из окружения (`os.environ[...]`, без значений по умолчанию в prod).
   - `test`: SQLite в памяти, `CELERY_TASK_ALWAYS_EAGER=True`, быстрый хешер паролей.
   - `prod`: `DEBUG=False`, `SECURE_*`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SECURE_HSTS_SECONDS=31536000`, `X_FRAME_OPTIONS="DENY"`, `SECURE_PROXY_SSL_HEADER`, `SESSION_COOKIE_AGE=1800`.
   - Пустые приложения (только `apps.py`, `__init__.py`, `migrations/__init__.py`) для: core, accounts, inventory, policy, execution, checks, remediation, ids, pcap, reports — в `app/apps/`, подключены в `INSTALLED_APPS` как `apps.<name>`.
3. Celery: `config/celery.py`, две очереди `readonly`, `mutation`; маршрутизация задач по имени (`*.mutation.*` → mutation), `task_acks_late=False`, `worker_prefetch_multiplier=1`, `task_time_limit` 900 с.
4. Health: `GET /healthz` (без аутентификации) → 200 `{"status":"ok"}` после проверки соединения с БД; ничего лишнего не раскрывает.
5. Базовый шаблон `base.html` с Bootstrap 5.3 и htmx **из `static/vendor/`** (файлы скачать и положить в репо, CDN не использовать), русская навигация-заглушка.
6. Docker:
   - `deploy/Dockerfile` (python:3.12-slim): системные пакеты `nmap tshark` (с `DEBIAN_FRONTEND=noninteractive`, ответ «нет» на вопрос wireshark-common), библиотеки WeasyPrint (`libpango-1.0-0 libpangoft2-1.0-0 fonts-dejavu`); пользователь `nixfort` (uid 10001), `USER nixfort`.
   - `compose.yaml`: `postgres:16`, `redis:7`, `web` (gunicorn), `worker-readonly` (`-Q readonly -c 4`), `worker-mutation` (`-Q mutation -c 1`), `beat`, `nginx`. Postgres/Redis без `ports:`. nginx публикует `443`. Healthcheck у postgres, web. Секрет `controller_ed25519` монтируется только в worker'ы (`secrets:` из `./secrets/controller_ed25519`).
   - `deploy/nginx.conf`: TLS (самоподписанный сертификат генерируется `deploy/gen-selfsigned.sh` в `./secrets/tls/`), редирект 80→443, `client_max_body_size 110m`, заголовки безопасности, проксирование на web, раздача `/static/`.
   - `deploy/entrypoint.sh`: `migrate`, `collectstatic` для web.
7. `Makefile`: `up`, `down`, `logs`, `test` (локально), `itest` (в контейнере web: `pytest -m integration`), `lint`, `createadmin` (заглушка — команда появится в T-002), `tls`.
8. CI `.github/workflows/ci.yml`: Python 3.12, `pip install -e .[dev]`, `ruff check`, `ruff format --check`, `pytest -m "not integration"`, `pip-audit` (не блокирует, но выводит).
9. README «Быстрый запуск» — проверить, что команды верны.

## Границы
- Никаких моделей, бизнес-логики, страниц кроме base и healthz.
- Не устанавливать Docker Desktop на Windows.

## Критерии готовности
- [ ] Локально на Windows: `pytest -m "not integration"` зелёный (тест healthz).
- [ ] `ruff check` и `ruff format --check` без ошибок.
- [ ] На nx-controller: `make tls && make up` → все контейнеры healthy; `https://127.0.0.1:8443/healthz` (с Windows через проброс) → ok.
- [ ] Процессы web и worker в контейнерах не root (`docker compose exec web id`).
- [ ] `docker compose ps` — postgres и redis без опубликованных портов.
- [ ] CI на GitHub зелёный.

## Тесты
- `tests/test_healthz.py`: 200 и тело; при недоступной БД — 503.
- `tests/test_settings_prod.py`: импорт prod-настроек без SECRET_KEY → ошибка (не молчаливое значение по умолчанию).

## Обновить документы
- `docs/STATUS.md`, README (если команды изменились).
