# NIXFORT — архитектура

Версия документа: 1.0 (22.10.2026). Владелец: архитектор. Изменения — только через `docs/DECISIONS.md`.

## 1. Общая схема

```
Браузер ──HTTPS──► Nginx ──► Gunicorn / Django (web)
                                  │  SQL                │ enqueue
                                  ▼                     ▼
                             PostgreSQL            Redis (broker)
                                  ▲                     │
                                  │            ┌────────┴─────────┐
                                  │            ▼                  ▼
                                  └── worker-readonly      worker-mutation
                                      (concurrency=4)      (concurrency=1)
                                      Nmap, TShark,         планы исправлений,
                                      инвентаризация,       применение/откат
                                      аудит, пробы
                                            │ SSH (Paramiko, RejectPolicy, ключ контроллера)
                                            ▼
                     ┌───────────── nixfort-agent (forced command, sudo только на себя) ───────────┐
                     │ nx-gateway: nftables, Suricata │ nx-server: sshd, Fail2ban │ nx-client: пробы │
                     └──────────────────────────────────────────────────────────────────────────┘
```

Стиль: **модульный монолит** (Django) + 2 пула фоновых воркеров + отдельный узловой агент. Микросервисов нет.

Контейнеры (`compose.yaml`): `nginx`, `web`, `worker-readonly`, `worker-mutation`, `beat` (сторож зависших заданий), `postgres`, `redis`. Postgres и Redis не публикуют порты наружу.

## 2. Структура репозитория

```
nixfort/
├── AGENTS.md  README.md  compose.yaml  .env.example  .gitignore  pyproject.toml  Makefile  conftest.py
├── app/                              # Django-проект (контроллер)
│   ├── manage.py
│   ├── config/                       # settings/{base,dev,test,prod}.py, urls.py, celery.py, wsgi.py
│   ├── templates/                    # страницы по модулям (accounts/, checks/, …) + base.html и core/_nav.html
│   ├── static/                       # css/app.css, js/app.js, img/mark.svg; vendor/: htmx и шрифты IBM Plex
│   └── apps/                         # модули предметной области, см. таблицу ниже
├── agent/                            # узловой агент, ТОЛЬКО стандартная библиотека Python 3
│   ├── run.py  rollback.py           # точки входа: обработка запроса и автооткат по таймеру
│   ├── install.sh                    # установка агента на узел
│   ├── nixfort_agent/
│   │   ├── __main__.py               # читает JSON из stdin, пишет JSON в stdout
│   │   ├── protocol.py  schema.py    # конверт запроса/ответа и проверка параметров
│   │   ├── registry.py               # allowlist «действие → обработчик»
│   │   ├── context.py  errors.py     # контекст вызова, коды ошибок
│   │   ├── runner.py                 # единственная обёртка subprocess (таймаут, лимит вывода)
│   │   ├── osprofile.py              # пути и команды по ОС (ubuntu-24.04, astra-1.8)
│   │   ├── parsers.py  fsutil.py     # разбор вывода утилит, безопасная запись файлов
│   │   ├── mutation.py  snapshots.py  rollback_timer.py  rollback_main.py   # снимок → применение → автооткат
│   │   └── actions/                  # system, ssh, nft, fail2ban, suricata, net, capture, pkg, mutation
│   ├── tools/make_request.py         # ручной запрос к агенту при отладке на стенде
│   └── tests/
├── deploy/                           # Dockerfile, entrypoint.sh, nginx.conf, генераторы .env и сертификата
├── lab/                              # внесение дефектов, скрипты стенда, отчёты испытаний (lab/reports)
├── tests/                            # интеграционный тест SSH с настоящим агентом
├── docs/                             # архитектура, протокол, проверки, безопасность, решения, карточки задач
└── thesis/                           # материалы текста ВКР
```

Каждый модуль `app/apps/<модуль>/` устроен одинаково, поэтому место любого кода предсказуемо:

| Файл | Что в нём |
|---|---|
| `models.py` | данные модуля |
| `views.py`, `urls.py` | страницы и их адреса; проверка прав декоратором `perm_required` |
| `services.py` | операции предметной области, которые вызывают страницы и задания |
| `handlers.py` | обработчики фоновых заданий модуля (регистрация `@register(JobType.…)`) |
| `forms.py` | формы ввода |
| `tests/` | тесты модуля |

| Модуль | Отвечает за | Особые файлы |
|---|---|---|
| `core` | права (RBAC), журнал действий, общие базовые модели, обзор всех проектов, оформление страниц | `rbac.py`, `audit.py`, `redact.py`, `middleware.py`, `context_processors.py` (меню, быстрый переход), `templatetags/nx.py` (фильтры шаблонов), `storage.py` (статика с хешем) |
| `accounts` | пользователи и роли, вход | `signals.py` (вход и выход в журнал) |
| `inventory` | проекты, узлы, ключи узлов, инвентаризация, сканирование портов, обзор проекта | `collector.py`, `overview.py` (порядок работы, матрица, схема), `validators.py`, `adapters/nmap.py` |
| `policy` | политика соединений и пробы | `connectivity.py` |
| `execution` | задания, очереди, блокировки, связь с агентом | `agent_client.py` (`call_node` — вызов без исключений), `transport.py` (SSH), `registry.py`, `tasks.py` (Celery) |
| `checks` | аудит | `domain.py` (каталог проверок, чистая логика без БД и сети) |
| `remediation` | планы исправлений | `planner.py` (план из нарушений), `orchestrator.py` (выполнение с автооткатом) |
| `ids` | датчик Suricata, проверка защиты | `scenarios.py` (имитация атак и оценка уровней защиты) |
| `pcap` | запись и разбор трафика | `analyzer.py` (TShark), `charts.py` (графики SVG), `storage.py` |
| `seclog` | сводка журналов безопасности | |
| `reports` | отчёты HTML, PDF, JSON | `builder.py` (неизменяемый снимок данных) |

Правило зависимостей между модулями (стрелка = «может импортировать»):
```
core, accounts ◄── все
inventory ◄── accounts, policy, checks, remediation, ids, reports
execution ◄── inventory, policy, checks, remediation, ids, pcap, seclog, reports
policy ◄── checks, remediation, ids, reports
checks ◄── remediation, reports
remediation ◄── reports
ids ◄── seclog, reports
pcap ◄── ids
```
Исключения, все только на чтение: `core/rbac.py` читает роли (`accounts`) и проекты (`inventory`) для проверки доступа; экраны-сводки `core/views.py`, `core/context_processors.py`, `core/templatetags/nx.py` и `inventory/views.py` (обзор проекта) читают модели других модулей для отображения и ничего в них не меняют; `core/management/commands/selfcheck.py` проверяет очередь заданий.
Обратные импорты запрещены. Изменения в чужом модуле — только через его `services.py` или задание.

## 3. Модель данных (логическая)

Все сущности: `id UUID`, `created_at`, `updated_at`. Статусы — `TextChoices`.

| Модуль | Сущность | Ключевые поля |
|---|---|---|
| accounts | User (django) + `RoleAssignment` | user, role ∈ {ADMIN, OPERATOR, VIEWER}, project (null = глобально) |
| core | `AuditEvent` | actor, action, object_type, object_id, project, outcome, safe_metadata JSON, ts. **Только вставка**, update/delete запрещены на уровне модели |
| inventory | `Project` | name, description, cidrs JSON[list[str]], controller_ip (ADR-022), admin_sources JSON[≤3 IPv4] (ADR-035), status {ACTIVE, ARCHIVED} |
| inventory | `Node` | project, name, mgmt_ip, data_ips JSON, ssh_port, roles JSON[list] ⊂ {gateway, server, ids_sensor, test_client}, expected_os, os_profile, expected_tcp_ports JSON, ids_interface, status {NEW, KEY_PENDING, READY, UNREACHABLE, UNSUPPORTED}, last_inventory_at |
| inventory | `HostKey` | node, key_type, fingerprint_sha256, public_key, confirmed_by, confirmed_at |
| inventory | `InventorySnapshot` | node, job, collected_at, facts JSON, agent_version, sha256. Неизменяем |
| inventory | `PortScan` | project, job, targets, ports, result JSON, started/finished |
| policy | `FlowPolicyVersion` | project, version int, status {DRAFT, ACTIVE, SUPERSEDED}, author, change_summary |
| policy | `Flow` | policy_version, name, src_cidr (IP или подсеть, ADR-019), dst_node, dst_ip, port, action {ALLOW, DENY}, critical bool, probe_from (Node test_client с рабочим IP внутри src_cidr) |
| execution | `Job` | type, project, node?, requested_by, queue {readonly, mutation}, state, phase, progress, params JSON, result JSON, safe_error_code, started/finished, deadline_at |
| execution | `JobLog` | job, ts, level, message (без секретов) |
| checks | `AuditRun` | project, job, catalog_version, policy_version, state |
| checks | `CheckResult` | audit_run, node, check_id, status, observed JSON, expected JSON, explanation, evidence |
| checks | `Evidence` | node, source (action_id), collected_at, content JSON (redacted), sha256 |
| remediation | `RemediationPlan` | project, audit_run, created_by, state, risk {LOW, MEDIUM, HIGH}, plan_hash, approved_by, approved_at |
| remediation | `RemediationItem` | plan, node, check_ids JSON, action_id, params JSON, order, state, snapshot_id (на узле), result JSON |
| policy | `ConnectivityTest` | project, job, plan_item?, phase {CHECK, BASELINE, POST, AFTER_ROLLBACK}, копия потока (версия, src, dst, порт, действие, критичность), probe_node, result {OPEN, CLOSED, TIMEOUT, UNREACHABLE, ERROR, NOT_RUN}, latency_ms, verdict {OK, VIOLATION, UNPROVABLE, NOT_CHECKED}, note |
| ids | `IdsEvent` | node, ts, event_type, src_ip, src_port, dst_ip, dst_port, proto, signature_id, signature, severity |
| pcap | `PcapCapture` | project, node?, job?, source {CAPTURE, UPLOAD}, interface, profile, duration_s, original_name, sha256, size, truncated, state, analysis JSON (протоколы, адреса, порты, соединения, timeline, findings) |
| reports | `Report` | project, title, before_run, after_run, generated_by, data JSON (неизменяемый), sha256 |

## 4. Состояния

**Статус проверки** (`CheckStatus`): `PASS`, `FAIL`, `UNKNOWN` (нет/устарели данные), `NOT_APPLICABLE` (роль узла), `ERROR` (технический сбой). PASS без доказательства невозможен.

**Задание** (`JobState`):
```
QUEUED → RUNNING → SUCCEEDED | FAILED | PARTIAL | UNKNOWN
                 → ROLLING_BACK → ROLLED_BACK | UNKNOWN
QUEUED/RUNNING → CANCELLED (только readonly; для mutation — через откат)
```
Переходы проверяет `execution.services.transition(job, new_state)`; недопустимый переход — исключение. Сторож (`beat`, раз в минуту): `RUNNING` после `deadline_at` → `UNKNOWN` + запись в журнал. Мутации **никогда** не повторяются автоматически.

**План исправления** (`PlanState`):
```
DRAFT → APPROVED → EXECUTING → VERIFIED
                             → ROLLED_BACK (откат подтверждён проверкой)
                             → FAILED (ничего не применено)
                             → UNKNOWN (состояние узла не подтверждено — критическое уведомление + инструкция ручного восстановления)
DRAFT → REJECTED
```
Утверждённый план неизменяем (`plan_hash` = sha256 канонического JSON элементов).

## 5. Выполнение действий на узлах

1. Контроллер хранит **один** приватный ключ (файл-секрет, монтируется в worker-контейнеры, права 0400). В БД — только путь/отпечаток.
2. Подключение: Paramiko, `RejectPolicy`, host key загружается из `HostKey` (подтверждённого администратором). Несовпадение → `ERROR host_key_mismatch`, узел → `KEY_PENDING`.
3. На узле пользователь `nixfort`, в `authorized_keys`:
   `restrict,command="sudo -n /usr/local/sbin/nixfort-agent" ssh-ed25519 AAAA... nixfort-controller`
   sudoers: `nixfort ALL=(root) NOPASSWD: /usr/local/sbin/nixfort-agent ""` (без аргументов).
4. Контроллер пишет в stdin один JSON-запрос (≤ 64 KiB), читает JSON-ответ (≤ 1 MiB). Контракт — `NODE_AGENT_PROTOCOL.md`.
5. На контроллере `execution/agent_client.py` знает каталог действий (зеркало registry агента) и валидирует параметры **до** отправки. Агент валидирует **повторно** (не доверяет контроллеру).
6. Конфиги (sshd, jail, nft, suricata) **рендерит агент** из своих шаблонов по структурированным параметрам. Контроллер никогда не передаёт текст конфигурации или команды.

## 6. Алгоритм безопасного изменения (оркестратор `remediation/orchestrator.py`)

Для каждого элемента плана, строго последовательно, с блокировкой узла (`select_for_update` на Node + Redis-lock `node:<id>:mutation`):

```
1. PRECHECK   свежая инвентаризация (≤ 15 мин) иначе собрать; host key подтверждён; ОС поддерживается;
              для nft: нет UFW/firewalld, есть management-allow; для SSH key-only: вход по ключу проверен.
2. BASELINE   (для nft) TCP-пробы по всем flow политики → ConnectivityTest(BASELINE).
              deny-flow, закрытый уже на baseline, помечается «блокировка не доказуема» → итог UNKNOWN по этому flow.
3. APPLY      один вызов агента `<domain>.apply_*.v1` с параметрами и rollback_timeout_s (по умолчанию 90 с).
              Агент сам: снимок → рендер кандидата → валидация (sshd -t / nft -c -f / fail2ban-client -t / suricata -T)
              → ставит таймер отката (systemd-run) → применяет → возвращает snapshot_id.
              Валидация не прошла → ничего не применено → FAILED.
4. VERIFY     НОВОЕ SSH-соединение к узлу (доказывает, что управление не потеряно);
              read-действие эффективной конфигурации (sshd -T, fail2ban-client get, nft list table);
              для nft — TCP-пробы POST: каждый critical ALLOW должен быть OPEN, каждый доказуемый DENY — CLOSED.
5a. COMMIT    всё ок → `mutation.commit.v1(snapshot_id)` отменяет таймер → элемент VERIFIED.
5b. ROLLBACK  что-то не так → `mutation.rollback_now.v1(snapshot_id)`; если узел недоступен — ждём срабатывания
              таймера (timeout + 30 с) и проверяем восстановление пробами/чтением → ROLLED_BACK; не подтвердилось → UNKNOWN.
6. После всех элементов — повторный аудит затронутых проверок (post-audit) для отчёта «до/после».
```
Ошибка любого элемента останавливает последующие элементы плана (они остаются `SKIPPED`).

## 7. Безопасность сетевых операций
- Nmap: только `-sT -Pn -n`, порты из фиксированного профиля (`top-100` или список портов проекта), цели — только IP узлов проекта / внутри `Project.cidrs`; `--max-rate 200`, таймаут 300 с. Вывод `-oX -` парсится `defusedxml`.
- TShark: только чтение файла, профили `protocols` (`-q -z io,phs`) и `conversations` (`-q -z conv,ip -z conv,tcp`), таймаут 120 с, `prlimit` по памяти, отдельный временный каталог, удаление после анализа.
- Загрузка PCAP: ≤ 100 MiB, проверка magic-байтов (pcap `d4c3b2a1`/`a1b2c3d4`/наносекундные, pcapng `0a0d0d0a`), имя на диске = sha256.

## 8. Интерфейс (страницы)
Вход · Обзор · Проекты · Проект: обзор (порядок работы, уровни защиты по узлам, схема сегмента) · Узел · Политика соединений · Проверка соединений · Сканирование портов · Аудит (результаты с фильтрами, доказательства в боковой панели) · Исправления (план, утверждение, ход выполнения, до и после) · Датчик IDS · Проверка защиты · Трафик · Журналы безопасности · Отчёты · Задания · Журнал действий · Пользователи (только ADMIN) · Условия использования · Политика конфиденциальности.
Прогресс заданий — htmx-опрос каждые 2 с. Цвет только у отклонений (ADR-058): нарушение и ошибка красные, «нет данных» жёлтый, «в работе» синий; норма пишется обычным текстом. Нет индикатора «сеть защищена». Название продукта в интерфейсе не показывается. Раскладки: телефон < 768 px, планшет 768–1279 px, компьютер от 1280 px.

## 9. Права ролей
| Действие | ADMIN | OPERATOR | VIEWER |
|---|---|---|---|
| Просмотр проекта, результатов, отчётов | ✓ | ✓ | ✓ |
| Создание/изменение проекта, узлов, политики | ✓ | ✓ (кроме активации политики) | — |
| Подтверждение host key, активация политики | ✓ | — | — |
| Инвентаризация, Nmap, аудит, PCAP | ✓ | ✓ | — |
| Создание плана исправления | ✓ | ✓ | — |
| **Подтверждение и запуск плана** | ✓ | — | — |
| Пользователи и роли | ✓ | — | — |
Проверка прав — на сервере, в каждом view и в задании worker (повторно), через `core.rbac.require(user, perm, project)`. Объекты другого проекта → 404.

## 10. Конфигурация и секреты
`.env` (не в git): `DJANGO_SECRET_KEY`, `POSTGRES_PASSWORD`, `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`. Ключ SSH контроллера — `./secrets/controller_ed25519` (в `.gitignore`), монтируется только в worker'ы. `DEBUG=False` в prod-настройках; `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, HSTS, `X_FRAME_OPTIONS=DENY`, CSP базовый. Ограничение попыток входа — `django-axes` (5 попыток / 15 мин).

## 11. Среда разработки
- Код — в папке `nixfort/` на Windows (Cursor), git → GitHub (private).
- Локально (Windows): Python 3.12 venv, `pytest -m "not integration"` на SQLite, Celery в eager-режиме.
- Интеграция: на `nx-controller` `git pull && docker compose up -d --build`, интеграционные тесты внутри контейнера `web`.
- Агент разворачивается на узлы скриптом `agent/install.sh` (копирование по scp с контроллера).
