# T-003 — Проекты, узлы, ключи, политика соединений

| Поле | Значение |
|---|---|
| Приоритет | P1 |
| Зависит от | T-002 |
| Модули | `app/apps/inventory`, `app/apps/policy`, `app/apps/accounts` (FK) |
| Читать | ARCHITECTURE §3 (inventory, policy), §8, §9; SECURITY §4 п.3; PROJECT_CONTEXT «Стенд» |
| AT | AT-18 (частично), AT-24 IDOR |

## Цель
Пользователь описывает сегмент: проект с подсетями, узлы с ролями и ожидаемыми портами, политику разрешённых/запрещённых соединений с версиями.

## Что сделать
1. `inventory.models`: `Project`, `Node`, `HostKey`, `InventorySnapshot` (только модель, без логики сбора), `PortScan` (только модель) — поля по ARCHITECTURE §3.
   - Валидация `Project.cidrs`: список IPv4-сетей (`ipaddress.IPv4Network(strict=True)`), 1..16 шт., только частные диапазоны RFC1918 (по умолчанию; флаг `allow_public=False`).
   - `Node`: `name` regex `^[A-Za-z0-9._-]{1,64}$`, уникален в проекте; `mgmt_ip` и каждый `data_ips` — IPv4 и **внутри cidrs проекта**; `ssh_port` 1..65535; `roles` — непустое подмножество {gateway, server, ids_sensor, test_client}; `expected_tcp_ports` — список int 1..65535 ≤ 64; `ids_interface` regex `^[a-z0-9]{1,15}$` или пусто (обязателен при роли ids_sensor). Предупреждение (не ошибка) о дубле адреса между узлами.
   - `Node.status` по умолчанию `KEY_PENDING`.
   - `HostKey`: `key_type` ∈ {ssh-ed25519, ecdsa-sha2-nistp256, ssh-rsa}, `fingerprint_sha256` формат `SHA256:<base64>`, `public_key` (base64), `confirmed_by`, `confirmed_at`. Ввод вручную ADMIN-ом в этой задаче (автополучение — T-006).
   - Удаления нет: проект архивируется (`ARCHIVED`), узел — `is_active=False`.
2. `accounts.RoleAssignment.project_id` → FK на Project (миграция).
3. `policy.models`: `FlowPolicyVersion`, `Flow` по §3.
   - Создание новой версии копирует потоки предыдущей (`DRAFT`). Активация (только ADMIN): `DRAFT → ACTIVE`, прежняя `ACTIVE → SUPERSEDED`, атомарно.
   - `Flow`: source — либо `src_node`, либо `src_cidr` (ровно одно); `dst_node` + `dst_ip` (должен принадлежать data_ips/mgmt_ip узла); `port`; `action` ALLOW/DENY; `critical`; `probe_from` — узел с ролью test_client (обязателен для проверяемых потоков).
   - `policy.services.find_conflicts(version) -> list[Conflict]`: одинаковые (src, dst, port) с разными action; ALLOW и DENY перекрываются по CIDR. Активация версии с конфликтами запрещена.
4. Страницы (Bootstrap): список проектов, создание/редактирование, обзор проекта; список узлов, карточка узла (пока без фактов), форма узла; ввод host key; политика: список версий, редактор потоков DRAFT, кнопка «Проверить конфликты», «Активировать».
5. Все изменения → `core.audit.log`. Все view — через RBAC (§9), объекты фильтруются по проекту пользователя; чужой → 404.

## Границы
- Никакого SSH, Nmap, сбора фактов.

## Критерии готовности
- [ ] Можно завести стендовый проект (cidrs 10.77/10.88/10.99), 4 узла, политику из AT-12 (3 потока).
- [ ] Неверные IP/CIDR/имена/порты/инъекционные строки отклоняются формой с понятной ошибкой.
- [ ] Конфликтная политика не активируется.
- [ ] OPERATOR не может активировать политику и подтвердить ключ; VIEWER только читает.
- [ ] Пользователь проекта A получает 404 на объекты проекта B.

## Тесты
- `inventory/tests/test_validators.py` (включая строки `; rm -rf /`, `$(id)`, `a\nb`, `../..`, `10.0.0.1/33`, публичные сети).
- `policy/tests/test_conflicts.py`, `test_activation.py` (атомарность, одна ACTIVE).
- `tests/test_idor.py` — по всем detail/edit URL этой задачи.

## Обновить документы
- `docs/STATUS.md`; при отклонении от §3 — сообщить архитектору.
