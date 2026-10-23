# nixfort-agent — узловой агент NIXFORT

Единственный компонент, который выполняет действия с правами root на управляемом узле. Протокол и каталог действий — `docs/NODE_AGENT_PROTOCOL.md`.

## Устройство
| Файл | Назначение |
|---|---|
| `nixfort_agent/__main__.py` | вход: 1 JSON-запрос из stdin → 1 JSON-ответ в stdout, выход всегда 0 |
| `nixfort_agent/protocol.py` | проверка конверта запроса, сборка ответа, лимиты 64 KiB / 1 MiB |
| `nixfort_agent/schema.py` | строгая валидация параметров (неизвестные ключи — отказ) |
| `nixfort_agent/registry.py` | allowlist действий (`@action(...)`) |
| `nixfort_agent/runner.py` | **единственное** место запуска внешних программ: список аргументов, абсолютный путь, таймаут, лимит вывода, минимальное окружение |
| `nixfort_agent/osprofile.py` | пути, бинарники и службы по ОС (ubuntu-24.04, astra-1.8) |
| `nixfort_agent/context.py` | контекст действия (профиль ОС, дедлайн, runner) — подменяется в тестах |
| `nixfort_agent/parsers.py` | чистые парсеры вывода утилит |
| `nixfort_agent/actions/*.py` | действия по доменам |
| `install.sh` | установка на узел (пользователь `nixfort`, forced command, sudoers) |
| `tools/make_request.py` | сформировать запрос для ручной проверки |

## Реализовано (этап 1, только чтение)
`system.ping.v1`, `system.collect_facts.v1`, `system.collect_listeners.v1`, `ssh.read_effective_config.v1`, `fail2ban.read_status.v1`, `nft.inspect.v1`, `suricata.read_status.v1`, `suricata.read_events.v1`, `net.tcp_probe.v1`, `net.send_ids_test.v1`.

Следующий этап: снимки, таймер отката, `*.apply_*`, `mutation.*`, `pkg.install_security_tool.v1`.

## Тесты
Только стандартная библиотека, запуск из каталога `agent/`:
```bash
python3 -m unittest discover -s tests -t .
```
(или `pytest agent/tests` из корня). Тест `NftRealTests` запускается только от root при наличии `nft` (в отдельном сетевом namespace).

## Установка на узел стенда
С nx-controller (где лежит репозиторий и ключ `secrets/controller_ed25519`):
```bash
scp -r agent labadmin@10.77.0.30:/tmp/nixfort-agent-src
ssh labadmin@10.77.0.30 'cd /tmp/nixfort-agent-src && sudo sh install.sh /tmp/controller.pub 10.77.0.10'
```
(предварительно скопировать `secrets/controller_ed25519.pub` в `/tmp/controller.pub` на узле).

Проверка:
```bash
python3 agent/tools/make_request.py system.collect_facts.v1 | ssh -i secrets/controller_ed25519 nixfort@10.77.0.30
```
