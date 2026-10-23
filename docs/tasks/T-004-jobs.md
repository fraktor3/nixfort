# T-004 — Движок фоновых заданий

| Поле | Значение |
|---|---|
| Приоритет | P1 |
| Зависит от | T-003 |
| Модули | `app/apps/execution` |
| Читать | ARCHITECTURE §1, §4 (Задание), §6 (блокировки); SECURITY T8, T9 |
| AT | AT-20 |

## Цель
Единый механизм длительных операций: запись Job, постановка в нужную очередь, контролируемые переходы состояний, блокировка узла для изменений, журнал шагов, сторож зависших заданий, страница прогресса.

## Что сделать
1. Модели `Job`, `JobLog` (§3). `JobType` enum: `INVENTORY`, `PORT_SCAN`, `AUDIT`, `PLAN_EXECUTE`, `IDS_FETCH`, `IDS_TEST`, `PCAP_ANALYZE`, `REPORT`, `NOOP_TEST`. Тип определяет очередь: `PLAN_EXECUTE` → mutation, остальные → readonly.
2. `execution.services`:
   - `create_job(type, project, user, node=None, params) -> Job` — RBAC-проверка, валидация params по схеме типа, `deadline_at = now + timeout(type)`, запись AuditEvent, `transaction.on_commit` → постановка Celery-задачи `execution.run_job(job_id)` в нужную очередь.
   - `transition(job, new_state, phase=None, error_code=None)` — только разрешённые переходы (§4), иначе `InvalidTransition`; `select_for_update`.
   - `log(job, level, message)` — с фильтром секретов (общий с core.audit).
   - Контекстный менеджер `node_mutation_lock(node)` — Redis-lock `nixfort:lock:node:<id>` (TTL = deadline) + `select_for_update` на Node; занят → `NodeBusy`.
3. Реестр обработчиков: `execution.registry.register(JobType)(handler)`; `run_job` загружает Job, **повторно** проверяет права инициатора (`core.rbac.has_perm`), переводит в RUNNING, вызывает handler, по результату — SUCCEEDED/FAILED/PARTIAL/UNKNOWN. Исключение handler → FAILED с `error_code="internal_error"` (трассировка — только в лог приложения).
   Мутационные задания **не перезапускаются** (Celery `autoretry` запрещён, `acks_late=False`).
4. Сторож (`beat`, каждые 60 с): `RUNNING`/`QUEUED` с `deadline_at < now` → `UNKNOWN` + JobLog + AuditEvent.
5. `NOOP_TEST` handler (для проверки механизма): спит `params.seconds` (1..30), пишет прогресс.
6. UI: страница задания (состояние, фаза, прогресс-бар, журнал) с htmx-обновлением каждые 2 с; список заданий проекта.

## Границы
- Реальных handler'ов (SSH, Nmap) нет — только NOOP_TEST.

## Критерии готовности
- [ ] NOOP_TEST проходит QUEUED→RUNNING→SUCCEEDED, прогресс виден в UI (на стенде, реальный Celery).
- [ ] Недопустимый переход → исключение (unit).
- [ ] Две мутации на один узел одновременно → вторая `NodeBusy`.
- [ ] `docker compose kill worker-readonly` во время NOOP_TEST(30) → через ≤2 мин задание UNKNOWN (AT-20).
- [ ] Пользователь без прав не создаёт задание; права перепроверяются в worker (unit с подменой роли между созданием и запуском).

## Тесты
- `execution/tests/test_transitions.py` (полная матрица), `test_services.py`, `test_watchdog.py`, `test_lock.py` (fakeredis или мок), `test_rbac_recheck.py`.

## Обновить документы
- `docs/STATUS.md`
