# Протокол узлового агента `nixfort-agent` v1

Агент — единственный компонент, выполняющий действия с правами root на узле. Это главная граница безопасности системы.

## 1. Установка на узле
- Код: `/opt/nixfort-agent/nixfort_agent/` (root:root, 0755/0644). Шаблоны: `/opt/nixfort-agent/templates/`.
- Лаунчер: `/usr/local/sbin/nixfort-agent` → `exec /usr/bin/python3 -I -S /opt/nixfort-agent/run.py` (root:root 0755). `-I` — изолированный режим (игнор PYTHON* и user site).
- Пользователь `nixfort` (без пароля, shell `/bin/sh`), `~nixfort/.ssh/authorized_keys`:
  `restrict,command="sudo -n /usr/local/sbin/nixfort-agent" ssh-ed25519 AAAA... nixfort-controller`
  (`restrict` = no-pty, no-port/agent/X11-forwarding, no-user-rc).
- `/etc/sudoers.d/nixfort` (0440): `nixfort ALL=(root) NOPASSWD: /usr/local/sbin/nixfort-agent ""`
- Рабочие каталоги: `/var/lib/nixfort/snapshots/` (0700), `/var/lib/nixfort/tmp/` (0700), журнал `/var/log/nixfort-agent.log` (0600).
- Файлы, которыми владеет NIXFORT (только их агент меняет):
  - `/etc/ssh/sshd_config.d/00-nixfort.conf`
  - `/etc/fail2ban/jail.d/nixfort-sshd.local`
  - `/etc/nftables.d/nixfort.nft` + таблица `inet nixfort` в ядре
  - `/etc/suricata/nixfort-sensor.yaml` (include) и `/etc/suricata/rules/nixfort-test.rules`
- Установка: `agent/install.sh` (идемпотентна), запускается администратором стенда один раз.

## 2. Запрос (stdin, UTF-8 JSON, ≤ 64 KiB)
```json
{
  "protocol": "nixfort.agent/1",
  "request_id": "8b0c5c1e-...-uuid4",
  "action": "ssh.read_effective_config.v1",
  "params": {},
  "deadline_s": 60
}
```
Правила валидации (иначе ответ `state=REJECTED`):
- ровно эти 5 ключей; `protocol` точное совпадение; `request_id` — UUID; `action` ∈ registry; `deadline_s` ∈ [1, 600];
- `params` проверяются схемой действия: только объявленные ключи, типы, enum, диапазоны, regex. Неизвестный ключ → отказ.
- Строки: запрещены управляющие символы, `\0`, длина ≤ 256 (если не указано иное).

## 3. Ответ (stdout, JSON, ≤ 1 MiB)
```json
{
  "protocol": "nixfort.agent/1",
  "request_id": "...",
  "action": "...",
  "state": "OK | FAILED | REJECTED | ERROR",
  "result": { },
  "error_code": null,
  "agent_version": "1.0.0",
  "os_profile": "ubuntu-24.04",
  "duration_ms": 412
}
```
- `OK` — действие выполнено, `result` по схеме действия.
- `FAILED` — действие корректно отработало, но цель не достигнута (например, валидация кандидата не прошла; ничего не применено).
- `REJECTED` — запрос невалиден/действие запрещено на этом узле.
- `ERROR` — сбой (таймаут, исключение). `error_code` из словаря ниже. Трассировки в ответ не попадают (только в журнал агента, без секретов).

`error_code`: `invalid_request`, `unknown_action`, `invalid_params`, `unsupported_os`, `tool_missing`, `tool_timeout`, `tool_failed`, `validation_failed`, `conflict_firewall_manager`, `snapshot_not_found`, `timer_failed`, `rollback_failed`, `output_too_large`, `internal_error`.

## 4. Общие правила реализации
- Внешние команды — только через `runner.run(argv: list[str], timeout, max_output=256 KiB, env=minimal)`. `env` = `{"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}`.
- Пути и бинарники — константы в `osprofile.py`. Параметры никогда не становятся путём или именем программы.
- Запись файлов — атомарно: временный файл в том же каталоге (`0600`), `fsync`, `os.replace`, затем нужные права.
- Определение ОС: `/etc/os-release` (`ID`, `VERSION_ID`) → профиль `ubuntu-24.04` | `astra-1.8` | иначе `unsupported` (read-действия `system.*` работают, мутации → `REJECTED unsupported_os`).
- Каждое действие объявляет `mutating: bool`. Агент не знает роль узла в проекте — допустимость действия для роли проверяет контроллер. Агент дополнительно проверяет факты на узле: nft-мутации только если `net.ipv4.ip_forward=1` и нет активных UFW/firewalld; suricata-мутации только если пакет установлен.

## 5. Механизм снимков и автоотката
- `snapshots.create(kind)` → `snapshot_id` (uuid4 hex). Каталог `/var/lib/nixfort/snapshots/<id>/`: копии принадлежащих NIXFORT файлов (или маркер «файла не было»), для nft — `nft list table inet nixfort` (или маркер «таблицы не было»), `meta.json` (kind, created_at, sha256 файлов).
- `rollback_timer.arm(snapshot_id, timeout_s)` → `systemd-run --unit=nixfort-rb-<id> --on-active=<timeout_s> --timer-property=AccuracySec=1s /usr/local/sbin/nixfort-agent-rollback <id>` (отдельный лаунчер, принимает только id формата `^[0-9a-f]{32}$`).
- `mutation.commit.v1` → `systemctl stop nixfort-rb-<id>.timer`; снимок хранится ещё 7 дней.
- Откат = восстановить файлы из снимка → применить (reload соответствующей службы / `nft -f`) → записать результат в `meta.json`.

## 6. Каталог действий v1

Обозначения: R — только чтение, M — изменение (всегда со снимком и таймером).

| action | Тип | params | result (основное) |
|---|---|---|---|
| `system.ping.v1` | R | — | `{"agent_version","os_profile","hostname"}` |
| `system.collect_facts.v1` | R | — | os(id, version, arch, kernel), hostname, interfaces[{name, ipv4[], state}], routes[], time_sync{service, synchronized}, journald_active, ip_forward, ipv6_present, packages{nftables, fail2ban, suricata, openssh-server: version\|null}, services{ssh, nftables, fail2ban, suricata, ufw, firewalld: active\|inactive\|absent} |
| `system.collect_listeners.v1` | R | — | listeners[{proto, addr, port, process}] (из `ss -H -ltnp`) |
| `ssh.read_effective_config.v1` | R | — | `sshd -T` → dict нужных ключей; `config_valid` (`sshd -t`), `validate_stderr` (обрезан) |
| `ssh.apply_hardening_profile.v1` | M | `permit_root_login: "no"`, `password_authentication: bool`, `max_auth_tries: int 1..6`, `login_grace_time_s: int 10..120`, `x11_forwarding: bool`, `rollback_timeout_s: int 30..300` | `snapshot_id`, `validated`, `applied`, `timer_armed` |
| `fail2ban.read_status.v1` | R | — | service, jails[], sshd{enabled, maxretry, bantime, findtime, currently_banned, banned_ips[]} (через `fail2ban-client get`) |
| `fail2ban.apply_sshd_profile.v1` | M | `maxretry: 3..5`, `bantime_s: 600..86400`, `findtime_s: 60..3600`, `ignore_ips: list[IPv4/CIDR] ≤10`, `rollback_timeout_s` | `snapshot_id`, `validated`, `applied`, `timer_armed` |
| `fail2ban.unban.v1` | M* | `ip: IPv4` | `{unbanned: bool}` (*без снимка — лабораторная операция снятия тестовой блокировки) |
| `nft.inspect.v1` | R | — | nft_version, tables[{family, name}], nixfort_table_present, nixfort_ruleset_sha256, conflict{ufw, firewalld, docker, foreign_base_chains[]}, policy_meta (из комментария таблицы: policy_version, plan_hash) |
| `nft.apply_policy.v1` | M | `management_sources: list[IPv4] 1..4`, `forward_rules: list[{src: CIDR\|IPv4, dst: IPv4, port: 1..65535, action: accept\|drop}] ≤200`, `input_allow_ports: list[int] ≤20`, `policy_meta: {policy_version: int, plan_hash: hex64}`, `rollback_timeout_s` | `snapshot_id`, `validated`, `applied`, `timer_armed`, `ruleset_sha256` |
| `suricata.read_status.v1` | R | — | service, version, config_test{ok, stderr_tail}, eve{enabled, path, readable, size}, af_packet_interfaces[], nixfort_test_rule_loaded |
| `suricata.read_events.v1` | R | `since_ts: ISO8601 \| null`, `limit: 1..500`, `types: subset{alert, anomaly}` | events[] (только поля: timestamp, event_type, src_ip, src_port, dest_ip, dest_port, proto, alert{signature_id, signature, severity}) |
| `suricata.apply_sensor_profile.v1` | M | `interface: ^[a-z0-9]{1,15}$` (должен существовать на узле), `enable_test_rule: bool`, `rollback_timeout_s` | `snapshot_id`, `validated (suricata -T)`, `applied`, `timer_armed` |
| `pkg.install_security_tool.v1` | M | `package: enum{fail2ban, suricata, nftables}` | `{installed: bool, version}` (`apt-get install -y --no-install-recommends`, `DEBIAN_FRONTEND=noninteractive`, таймаут 300 с; без снимка — отмечается в плане как необратимое) |
| `net.tcp_probe.v1` | R | `targets: list[{ip: IPv4, port: int}] ≤50`, `timeout_ms: 200..5000` | results[{ip, port, result: OPEN\|CLOSED\|TIMEOUT\|UNREACHABLE, latency_ms}] (сокеты Python, без внешних программ) |
| `net.send_ids_test.v1` | R* | `ip: IPv4`, `port: int` | `{sent: bool}` — TCP-соединение и отправка фиксированной строки `NIXFORT-IDS-TEST-7f3a` (для тестового правила Suricata) |
| `mutation.commit.v1` | M | `snapshot_id: ^[0-9a-f]{32}$` | `{timer_cancelled: bool}` |
| `mutation.rollback_now.v1` | M | `snapshot_id` | `{rolled_back: bool, service_reloaded: bool}` |
| `mutation.snapshot_status.v1` | R | `snapshot_id` | `{exists, kind, timer_active, rolled_back, committed}` |

Семантика TCP-проб: `OPEN` — handshake успешен; `CLOSED` — RST (порт закрыт/reject); `TIMEOUT` — нет ответа (типично для `drop`); `UNREACHABLE` — ICMP unreachable/нет маршрута. Для deny-flow «заблокировано» = `TIMEOUT` или `CLOSED` **при условии**, что на baseline было `OPEN`.

## 7. Шаблон nftables (рендерит агент)
```
table inet nixfort {}
delete table inet nixfort
table inet nixfort {
  comment "nixfort policy_version=<N> plan_hash=<hash>"
  chain input {
    type filter hook input priority 0; policy drop;
    iif "lo" accept
    ct state established,related accept
    ct state invalid drop
    ip protocol icmp accept
    ip saddr { <management_sources> } tcp dport 22 accept
    tcp dport { <input_allow_ports> } accept        # если список не пуст
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    ct state invalid drop
    ip protocol icmp accept
    ip saddr <src> ip daddr <dst> tcp dport <port> accept   # для каждого ALLOW
  }
}
```
Строки 1–2 делают замену атомарной и идемпотентной (работает и на старых версиях nft, без `destroy`). Правила DENY явно не пишутся — их обеспечивает `policy drop`; DENY-flow в политике нужны для **проверки**. Чужие таблицы не трогаются; если обнаружены чужие base-chain на hook forward/input с `policy drop` — `conflict`, мутация запрещена.

Персистентность: файл `/etc/nftables.d/nixfort.nft` + строка `include "/etc/nftables.d/*.nft"` в `/etc/nftables.conf` (добавляется агентом один раз, со снимком).

## 8. Реализация (агент 1.1.0)
Реализованы: все read-действия, `mutation.commit.v1`, `mutation.rollback_now.v1`, `mutation.snapshot_status.v1`, `pkg.install_security_tool.v1` (fail2ban+python3-systemd, suricata, nftables), `fail2ban.apply_sshd_profile.v1`, `fail2ban.unban.v1`, `ssh.apply_hardening_profile.v1`.
В работе: `nft.apply_policy.v1`, `suricata.apply_sensor_profile.v1`.

Общий путь изменения (`nixfort_agent/mutation.py: guarded_apply`): снимок → запись кандидата → проверка (при ошибке — восстановление, FAILED) → таймер отката (`systemd-run`, при ошибке — восстановление, ERROR timer_failed) → активация (при ошибке — откат). Откат по таймеру выполняет `/usr/local/sbin/nixfort-agent-rollback <id>` (0700, только root, не в sudoers). Повторный откат идемпотентен (блокировка файла снимка).
