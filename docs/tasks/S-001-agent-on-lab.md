# S-001 — Агент на стенде (выполняет Cursor, проверка на реальных ВМ)

| Поле | Значение |
|---|---|
| Зависит от | T-000 (стенд готов), ssh-доступ с Windows: `ssh nx-controller`, `nx-gateway`, `nx-server`, `nx-client` (см. WORKFLOW.md «Доступ Cursor к стенду») |
| Код | `agent/` — **код не менять** без указания архитектора; если что-то не работает — зафиксировать вывод |
| Читать | `agent/README.md`, `docs/NODE_AGENT_PROTOCOL.md` §1–3, §6 |

## Цель
Установить агент на nx-gateway, nx-server, nx-client и подтвердить, что все read-действия работают на настоящей Ubuntu 24.04.

## Шаги
1. На nx-controller: клонировать репозиторий в `~/nixfort` (или `git pull`). Создать ключ контроллера:
   `mkdir -p ~/nixfort/secrets && ssh-keygen -t ed25519 -N "" -C nixfort-controller -f ~/nixfort/secrets/controller_ed25519`
2. Для каждого узла N ∈ {10.77.0.20, 10.77.0.30, 10.77.0.40} (с nx-controller, пользователь labadmin):
   ```
   scp -r ~/nixfort/agent labadmin@N:/tmp/nixfort-agent-src
   scp ~/nixfort/secrets/controller_ed25519.pub labadmin@N:/tmp/controller.pub
   ssh labadmin@N 'cd /tmp/nixfort-agent-src && sudo sh install.sh /tmp/controller.pub 10.77.0.10'
   ```
   Сохранить вывод install.sh (там отпечатки host key).
3. С nx-controller для каждого узла выполнить и сохранить ответы:
   ```
   cd ~/nixfort
   for a in system.ping.v1 system.collect_facts.v1 system.collect_listeners.v1 ssh.read_effective_config.v1 fail2ban.read_status.v1 nft.inspect.v1 suricata.read_status.v1; do
     python3 agent/tools/make_request.py $a | ssh -i secrets/controller_ed25519 nixfort@N; echo; done
   ```
4. Проба соединений с клиента (nx-client = 10.77.0.40):
   ```
   python3 agent/tools/make_request.py net.tcp_probe.v1 '{"targets":[{"ip":"10.99.0.10","port":80},{"ip":"10.99.0.10","port":8080},{"ip":"10.99.0.10","port":22},{"ip":"10.99.0.10","port":9}],"timeout_ms":1500}' | ssh -i secrets/controller_ed25519 nixfort@10.77.0.40
   ```
   Ожидается: 80 OPEN, 8080 OPEN, 22 OPEN, 9 CLOSED.
5. Негативные проверки безопасности (каждая должна дать отказ):
   - `ssh -i secrets/controller_ed25519 nixfort@10.77.0.30 id` → вывод агента `REJECTED invalid_request` (forced command игнорирует команду), а не результат `id`.
   - `ssh -t -i secrets/controller_ed25519 nixfort@10.77.0.30` → оболочки нет: ssh сообщает, что PTY не выделен, агент ждёт JSON; нажать Ctrl+D → ответ `REJECTED`.
   - На узле от labadmin: `sudo -u nixfort sudo -n /bin/sh -c id` → «a password is required».
6. Сохранить все ответы в `lab/reports/S-001-<дата>.md` (без приватных ключей!). Сравнить с ожиданиями ниже.

## Ожидания
- `system.ping.v1` → `state: OK`, `os_profile: ubuntu-24.04`.
- `collect_facts`: на gateway `ip_forward: true`; на server в `packages` есть openssh-server, нет fail2ban/suricata; `journald_active: true`; `time_sync.synchronized` true или false (зафиксировать).
- `collect_listeners` на server: 22, 80, 8080.
- `ssh.read_effective_config`: `config_valid: true`, есть `permitrootlogin`, `passwordauthentication`.
- `fail2ban.read_status` на server: `installed: false`.
- `nft.inspect` на gateway: `state: OK`, `nixfort_table_present: false`.
- `suricata.read_status`: `installed: false`.
Любое `ERROR` / неожиданное значение — не исправлять самостоятельно, а записать в отчёт полностью.

## Отчёт
Файл `lab/reports/S-001-*.md` + краткая сводка: что OK, что нет. Руководитель коммитит и пишет архитектору «S-001 готово».
