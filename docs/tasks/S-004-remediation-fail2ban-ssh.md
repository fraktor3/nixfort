# S-004 — Первые безопасные исправления на стенде: Fail2ban и SSH (Cursor + руководитель)

| Поле | Значение |
|---|---|
| Зависит от | S-003 принята; коммит с T-009…T-011 запушен |
| Код | не менять; ошибки — полный вывод в отчёт |
| Читать | `docs/ARCHITECTURE.md` §6, `docs/NODE_AGENT_PROTOCOL.md` §5, §8, `docs/DECISIONS.md` ADR-030…033 |

## Часть A — обновление (Cursor)
1. nx-controller: `cd ~/nixfort && git pull && make up` → `make selfcheck` (без [FAIL]) → `make itest` (ожидается ≥ 369 passed).
2. Обновить агента на трёх узлах (ключ контроллера тот же):
   ```
   for n in 10.77.0.20 10.77.0.30 10.77.0.40; do
     scp -r ~/nixfort/agent labadmin@$n:/tmp/nixfort-agent-src
     scp ~/nixfort/secrets/controller_ed25519.pub labadmin@$n:/tmp/controller.pub
     ssh labadmin@$n 'cd /tmp/nixfort-agent-src && sudo sh install.sh /tmp/controller.pub 10.77.0.10'
   done
   ```
   В выводе — `agent_version":"1.1.0"`. Проверить: `ls -l /usr/local/sbin/nixfort-agent-rollback` → `-rwx------ root`.
   (Если `secrets/controller_ed25519.pub` недоступен из-за владельца 10001 — `sudo cat` его во временный файл.)
3. Проверить доступ узлов к репозиторию Ubuntu: `ssh labadmin@10.77.0.30 'sudo apt-get update -q' | tail -2` (нужен для установки Fail2ban).
4. **Снимок до изменений** уже есть (`lab-baseline`). Ничего не делать.

## Часть B — исправление через интерфейс (руководитель нажимает, Cursor наблюдает и проверяет)
5. Руководитель: «Аудит» → «Запустить аудит» → дождаться итога (как в S-003).
6. На странице результата: флажок «Вход по ключу проверен» **НЕ ставить** (первый прогон — без отключения паролей) → «Сформировать план исправлений».
7. Ожидаемый план (5 шагов): 1) nx-server: установить Fail2ban; 2) nx-server: профиль Fail2ban; 3–4) nx-gateway и nx-server: усиленный профиль SSH (SSH-01, 03–06). В «не покрыто»: SSH-02 (нет подтверждения ключа), SYS-04, FW-02/03, IDS-01..03. Скриншот плана.
8. Руководитель: галочка подтверждения → «Утвердить и выполнить». Страница задания: шаги, проверки, «Подтверждён». Ожидается: задание «Успешно», план «Применён и подтверждён», внизу плана таблица «До / после»: F2B-01..03 и SSH-01, 03–06 стали PASS, SSH-02 остался FAIL. Скриншоты.
9. Cursor на узлах (только чтение): `sudo cat /etc/ssh/sshd_config.d/00-nixfort.conf`, `sudo sshd -T | grep -E 'permitrootlogin|maxauthtries|logingracetime|x11forwarding|passwordauthentication'`, `sudo cat /etc/fail2ban/jail.d/nixfort-sshd.local`, `sudo fail2ban-client status sshd`, `systemctl list-timers --all | grep nixfort` (пусто — таймеры отменены), `sudo ls /var/lib/nixfort/snapshots` и `sudo grep -h committed /var/lib/nixfort/snapshots/*/meta.json`.
10. Проверить, что руководитель по-прежнему входит на ВМ по своему ключу (`ssh nx-server hostname` с Windows).

## Часть C — проверка защиты: подбор пароля (Cursor)
11. С nx-client на рабочий адрес сервера, 6 попыток под несуществующим пользователем:
    ```
    ssh labadmin@10.77.0.40 'for i in 1 2 3 4 5 6; do ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 nouser$i@10.99.0.10 true; done; nc -zv -w3 10.99.0.10 22'
    ```
    Ожидается: последняя команда — таймаут/отказ (IP клиента заблокирован).
12. На сервере: `sudo fail2ban-client status sshd` → в «Banned IP list» адрес `10.88.0.10`. Контроллер (10.77.0.10) не заблокирован (ignoreip) — инвентаризация nx-server в интерфейсе проходит.
13. Снять блокировку: `ssh labadmin@10.77.0.30 'sudo fail2ban-client set sshd unbanip 10.88.0.10'`, повторить `nc` с клиента → succeeded.

## Часть D — автооткат на узле без контроллера (Cursor, ручной вызов агента)
14. На nx-controller, от имени контроллера (ключ — во временной копии, удалить после):
    ```
    sudo cp secrets/controller_ed25519 /tmp/ck && sudo chown $USER /tmp/ck
    python3 agent/tools/make_request.py ssh.apply_hardening_profile.v1 '{"permit_root_login":"no","password_authentication":true,"max_auth_tries":3,"login_grace_time_s":60,"x11_forwarding":false,"rollback_timeout_s":30}' | ssh -i /tmp/ck nixfort@10.77.0.20
    ```
    Записать `snapshot_id`. **commit не вызывать.** Сразу: `ssh labadmin@10.77.0.20 'sudo sshd -T | grep maxauthtries'` → `3`.
15. Подождать 45 с. Снова `sshd -T | grep maxauthtries` → `4` (вернулся профиль из шага 8), `systemctl list-timers --all | grep nixfort` → пусто, в `/var/log/nixfort-agent.log` строка `timer rollback snapshot=<id> result={'rolled_back': True ...}`.
16. Запрос `mutation.snapshot_status.v1` с этим id → `rolled_back: true`. `rm /tmp/ck`.

## Отчёт
`lab/reports/S-004-<дата>.md` + скриншоты `lab/reports/S-004/`: план, ход задания, «до/после», бан клиента, автооткат. Руководитель коммитит, пушит и пишет архитектору «S-004 готово».
