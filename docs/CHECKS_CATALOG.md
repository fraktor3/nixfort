# Каталог проверок NIXFORT, версия каталога `2026.1`

21 проверка. Каждая проверка — запись в `app/apps/checks/catalog.py` (ID, домен, название, серьёзность, применимость по ролям, источник фактов, функция оценки, исправление, источник требования) и **чистая функция** `evaluate(facts, ctx) -> CheckOutcome(status, observed, expected, explanation)`.

Общие правила оценки:
- Нужных фактов нет / снимок старше 15 мин / ОС `unsupported` → `UNKNOWN` (объяснение: чего не хватает).
- Агент вернул `ERROR` → `ERROR` с `error_code`.
- Роль узла не подходит → `NOT_APPLICABLE`.
- Источники требований: **CIS** — CIS Ubuntu Linux 24.04 LTS Benchmark; **ФСТЭК** — «Рекомендации по обеспечению безопасной настройки операционных систем Linux» (ФСТЭК России, 2022). Точные пункты уточняются при написании гл. 2 ВКР (поле `source_ref`).

Роли: `G` gateway, `S` server, `I` ids_sensor, `*` любой управляемый узел (кроме test_client).

| ID | Домен | Проверка | Роли | Факты (action) | PASS, если | Сер. | Исправление |
|---|---|---|---|---|---|---|---|
| SYS-01 | SYS | Поддерживаемая ОС | * | collect_facts | os_profile ∈ {ubuntu-24.04, astra-1.8} и arch=amd64 | HIGH | — (только рекомендация) |
| SYS-02 | SYS | Синхронизация времени | * | collect_facts | time_sync.synchronized = true | MEDIUM | — |
| SYS-03 | SYS | Системный журнал | * | collect_facts | journald_active = true | MEDIUM | — |
| SYS-04 | SYS | Нет неожиданных TCP-служб | * | collect_listeners | каждый прослушиваемый порт (не loopback) ∈ Node.expected_tcp_ports | HIGH | — (рекомендация отключить службу вручную) |
| SSH-01 | SSH | Запрет входа root | * | ssh.read_effective_config | permitrootlogin = no | HIGH | ssh.apply_hardening_profile |
| SSH-02 | SSH | Вход только по ключу | * | ssh.read_effective_config | passwordauthentication = no | HIGH | ssh.apply_hardening_profile (precondition: вход по ключу подтверждён) |
| SSH-03 | SSH | Пустые пароли запрещены | * | ssh.read_effective_config | permitemptypasswords = no | HIGH | ssh.apply_hardening_profile |
| SSH-04 | SSH | Лимит попыток входа | * | ssh.read_effective_config | maxauthtries ≤ 4 | MEDIUM | ssh.apply_hardening_profile |
| SSH-05 | SSH | Время на вход | * | ssh.read_effective_config | logingracetime ≤ 60 | LOW | ssh.apply_hardening_profile |
| SSH-06 | SSH | X11 forwarding выключен | * | ssh.read_effective_config | x11forwarding = no | LOW | ssh.apply_hardening_profile |
| SSH-07 | SSH | Конфигурация sshd корректна | * | ssh.read_effective_config | config_valid = true | HIGH | — (FAIL блокирует любые SSH-исправления) |
| FW-01 | FW | nftables без конфликтов | G | collect_facts + nft.inspect | nftables установлен; ufw и firewalld не active; conflict пуст | HIGH | pkg.install_security_tool(nftables) если не установлен; конфликт — только вручную |
| FW-02 | FW | Политика NIXFORT применена | G | nft.inspect | nixfort_table_present и policy_meta.policy_version = активная версия политики | HIGH | nft.apply_policy |
| FW-03 | FW | Запрет по умолчанию в forward | G | nft.inspect | у chain forward таблицы nixfort policy = drop | HIGH | nft.apply_policy |
| FW-04 | FW | Управляющий доступ сохранён | G | nft.inspect | в chain input есть accept tcp/22 от всех management_sources проекта | CRITICAL | nft.apply_policy |
| F2B-01 | F2B | Fail2ban установлен и работает | S | collect_facts | пакет установлен и служба active | HIGH | pkg.install_security_tool(fail2ban) |
| F2B-02 | F2B | Jail sshd включён | S | fail2ban.read_status | sshd.enabled = true | HIGH | fail2ban.apply_sshd_profile |
| F2B-03 | F2B | Параметры защиты от перебора | S | fail2ban.read_status | maxretry ≤ 5 и bantime ≥ 600 | MEDIUM | fail2ban.apply_sshd_profile |
| IDS-01 | IDS | Suricata установлена и работает | I | collect_facts | пакет установлен и служба active | HIGH | pkg.install_security_tool(suricata) |
| IDS-02 | IDS | Конфигурация Suricata корректна | I | suricata.read_status | config_test.ok = true | HIGH | suricata.apply_sensor_profile |
| IDS-03 | IDS | Датчик наблюдает нужный интерфейс и пишет EVE | I | suricata.read_status | Node.ids_interface ∈ af_packet_interfaces и eve.enabled и eve.readable | HIGH | suricata.apply_sensor_profile |

Примечание к IDS-03: PASS означает «датчик настроен на интерфейс», а не «датчик видит весь трафик». Это ограничение показывается в объяснении.

## Группировка исправлений в план
Генератор плана (`remediation/planner.py`) объединяет FAIL одного узла по action:
- все SSH-01..06 → один элемент `ssh.apply_hardening_profile.v1` (SSH-02 включается, только если отмечено «вход по ключу проверен»);
- F2B-02, F2B-03 → один `fail2ban.apply_sshd_profile.v1` (ignore_ips = mgmt IP контроллера);
- FW-02..04 → один `nft.apply_policy.v1` (параметры строятся из активной политики);
- IDS-02, IDS-03 → один `suricata.apply_sensor_profile.v1`;
- F2B-01 / IDS-01 / FW-01 (нет пакета) → `pkg.install_security_tool.v1` **перед** соответствующей настройкой.
Порядок элементов в плане: install → fail2ban → ssh → suricata → nft (от низкого риска к высокому).
Уровень риска плана = максимальный риск элемента: nft и SSH-02 — HIGH, ssh прочее и suricata — MEDIUM, fail2ban и install — LOW.
