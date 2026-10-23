# T-002 — Пользователи, роли, RBAC, журнал действий

| Поле | Значение |
|---|---|
| Приоритет | P1 |
| Зависит от | T-001 |
| Модули | `app/apps/core`, `app/apps/accounts`, `app/templates` |
| Читать | ARCHITECTURE §3 (accounts, core), §9, §10; SECURITY §3 T4, T5, T13; §4 п.4, 7, 8 |
| AT | AT-02, AT-19 |

## Цель
Вход в систему, три роли с проверкой прав на сервере, неизменяемый журнал действий.

## Что сделать
1. `core`:
   - `models.BaseModel` (abstract): `id = UUIDField(primary_key, default=uuid4, editable=False)`, `created_at`, `updated_at`.
   - `AuditEvent(BaseModel)`: `actor` (FK User, null), `action` (CharField, choices из `core.audit.Action`), `object_type`, `object_id`, `project_id` (UUID, null), `outcome` ∈ {SUCCESS, DENIED, FAILED}, `safe_metadata` JSON, `ip` (GenericIPAddressField, null). `save()` при существующей записи → `PermissionError`; `delete()` → `PermissionError`; QuerySet `update/delete` тоже запрещены (кастомный менеджер).
   - `core.audit.log(actor, action, obj=None, project=None, outcome="SUCCESS", **meta)` — единственная точка записи; фильтр секретов: ключи `password, secret, token, key, private` в meta заменяются на `"***"`.
   - `core.rbac`: enum `Role` {ADMIN, OPERATOR, VIEWER}; enum `Perm` (по таблице ARCHITECTURE §9); матрица `ROLE_PERMS`; `has_perm(user, perm, project=None) -> bool`; `require(user, perm, project=None)` → `PermissionDenied` + запись `AuditEvent(outcome=DENIED)`; миксин `PermRequiredMixin` и декоратор `perm_required(perm, project_kwarg="project_id")`.
2. `accounts`:
   - `RoleAssignment(BaseModel)`: user, role, project (FK на `inventory.Project`, **null=True**; в этой задаче FK объявить строкой `"inventory.Project"` — модель Project появится в T-003, поэтому пока поле `project_id = UUIDField(null=True)` без FK; в T-003 заменить на FK миграцией). Уникальность (user, project).
   - Вход/выход (Django auth views, свои шаблоны на русском), сообщение об ошибке без раскрытия существования логина.
   - `django-axes`: 5 неудачных попыток / 15 мин блокировка по паре логин+IP; события входа/выхода/неудачи → AuditEvent (через сигналы).
   - management-команда `createadmin`: интерактивно спрашивает логин и пароль (с подтверждением), валидация пароля Django (≥12 символов), выдаёт глобальную роль ADMIN. Если ADMIN уже есть — отказ (bootstrap только один раз). Обновить `make createadmin`.
   - Страницы (только ADMIN): список пользователей, создание пользователя, назначение/снятие роли, деактивация. Все изменения → AuditEvent.
3. Журнал действий: страница «Журнал» (ADMIN и VIEWER/OPERATOR — только события своих проектов; глобальные — только ADMIN), фильтры по действию, пользователю, дате; пагинация 50.
4. Все страницы, кроме входа и `/healthz`, требуют входа (`LoginRequiredMiddleware` Django 5.1+ с исключениями).
5. Django admin: отключить в prod (`/admin/` не подключать в prod-URL) — чтобы не было обходного пути мимо журнала.

## Границы
- Никакого SSO/MFA. Никаких проектов/узлов (T-003).

## Критерии готовности
- [ ] Без входа любой URL (кроме входа/healthz) → редирект на вход.
- [ ] VIEWER не открывает страницы управления пользователями (403 + AuditEvent DENIED).
- [ ] 6-я неверная попытка входа блокируется, событие в журнале.
- [ ] Попытка изменить/удалить AuditEvent в коде → исключение (тест).
- [ ] `createadmin` второй раз → отказ.

## Тесты
- `core/tests/test_rbac.py` — матрица прав по всем ролям и Perm (параметризованный тест).
- `core/tests/test_audit.py` — неизменяемость (save/delete/update/queryset.delete), редактирование секретов в meta.
- `accounts/tests/test_auth.py` — вход/выход, axes-блокировка, редирект без входа, createadmin.
- `accounts/tests/test_users_views.py` — доступ по ролям.

## Обновить документы
- `docs/STATUS.md`
