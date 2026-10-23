# S-002 — восстановление ВМ nx-controller (2026-10-23)

Код проекта не менялся. Снапшоты не восстанавливались и не удалялись. RAM и CPU виртуальных машин не менялись. `nx-gateway`, `nx-server` и `nx-client` оставлены выключенными.

## Причина

VirtualBox не получил AMD-V и работает через Hyper-V (NEM). В `D:\virtual_machine\nx-controller\Logs\VBox.log`:

```
HM: HMR3Init: Attempting fall back to NEM: AMD-V is not available
NEM: WHvCapabilityCodeHypervisorPresent is TRUE
```

`Get-ComputerInfo`: `HyperVisorPresent = True`. `wsl --status` показывает дистрибутив Ubuntu версии 2 (WSL2). `bcdedit /enum` в этой сессии не вывел `hypervisorlaunchtype`.

На SATA-контроллере кэш ввода-вывода хоста был выключен (`useHostIOCache="false"`). Под этой нагрузкой (Docker на 4 ГБ RAM плюс медленный диск через NEM) гость переставал отвечать: в журнале VirtualBox сброс порта AHCI и остановка примерно на 43-й секунде, SSH `127.0.0.1:2210` не отдавал баннер. Позже в журнале: `Guest seems to be unresponsive. Last heartbeat received 150 seconds ago`, затем `Guest is alive`.

Места на диске достаточно, это не причина: диск D (файлы ВМ) свободен на 762 ГБ, диск C — на 159 ГБ.

Память Windows на момент диагностики: свободно около 8472 МБ из 16332 МБ видимых. Увеличивать RAM ВМ нельзя: при включённом контроллере свободно остаётся около 4 ГБ.

## Что изменено

- `nx-controller` принудительно выключена (`controlvm poweroff`), затем запускалась заново.
- На всех четырёх ВМ у контроллера SATA включён кэш хоста: `VBoxManage storagectl <vm> --name SATA --hostiocache on`. В текущей секции Hardware файла `.vbox` у всех четырёх `useHostIOCache="true"`. Записи внутри снапшотов не менялись (`false` там — историческое состояние снимка).
- Исключение Microsoft Defender для `D:\virtual_machine` не добавлено: без прав администратора `Add-MpPreference` вернул «недостаточно разрешений», запрос UAC был отменён.

Hyper-V / NEM не отключался.

Последствия, если позже отключить Hyper-V (платформу виртуальных машин и WSL2), чтобы VirtualBox снова получил AMD-V: виртуальные машины станут заметно быстрее и реже будут замирать на диске. WSL2 и функции Hyper-V перестанут работать, пока компонент снова не включат. Это действие не выполнялось.

## Загрузка после кэша

После включения кэша `nx-controller` загрузилась. SSH ответил на первой минуте (`uptime`: up 0 min, load 2.22).

```
free -h
               total        used        free      shared  buff/cache   available
Mem:           3.8Gi       867Mi       2.7Gi        15Mi       504Mi       3.0Gi
Swap:             0B          0B          0B

df -h
/dev/sda2        25G  5.8G   18G  25% /

dmesg
dmesg: read kernel buffer failed: Operation not permitted
```

Повтор с `sudo` не выполнен: к этому моменту SSH снова перестал отвечать.

`make ps` (контейнеры поднялись сами, `restart: unless-stopped`):

```
nixfort-beat-1              Up
nixfort-nginx-1             Up          0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp
nixfort-postgres-1          Up (healthy)
nixfort-redis-1             Up (healthy)
nixfort-web-1               Up (healthy)
nixfort-worker-mutation-1   Up
nixfort-worker-readonly-1   Up
```

## make selfcheck

Первый запуск, контейнер `web` — все строки `[OK]`, итог без `[FAIL]`:

```
[OK]   PostgreSQL: соединение — postgresql
[OK]   PostgreSQL: миграции применены
[OK]   Redis: аутентифицированный PING
[OK]   Celery: очередь «readonly» принимает и выполняет задачи — выполнено воркером 6ffcdb54653d
[OK]   Celery: очередь «mutation» принимает и выполняет задачи — выполнено воркером 87b625c76866
[OK]   Инструмент nmap — /usr/bin/nmap
[OK]   Инструмент tshark — /usr/bin/tshark
ИТОГ: всё в порядке
```

Вторая часть (`docker compose exec worker-mutation python manage.py selfcheck --key`) не завершилась: вывод остановился на этой команде, гость снова перестал отвечать на SSH (таймаут баннера, пауза heartbeat около 150 с). Строки `[FAIL]` нет. `make itest` из-за этого не запускался.

## Отключение Hyper-V (решение руководителя, 2026-10-23)

Все четыре ВМ выключены. `wsl --shutdown` выполнен. Скрипт `lab/scripts/disable-hyperv.ps1` запускается от администратора и делает три вещи:

- `bcdedit /set hypervisorlaunchtype off` — гипервизор Windows не стартует при следующей загрузке, VirtualBox сможет занять AMD-V напрямую.
- Целостность памяти (изоляция ядра): `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity` / `Enabled` = 0.
- `Add-MpPreference -ExclusionPath "D:\virtual_machine"`.

Код проекта, диски и снапшоты не менялись. RAM и CPU ВМ не менялись.

**Как вернуть обратно** (тоже от администратора, затем перезагрузка):

```
bcdedit /set hypervisorlaunchtype auto
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 1 /f
Remove-MpPreference -ExclusionPath "D:\virtual_machine"
```

После `hypervisorlaunchtype auto` и перезагрузки снова заработают WSL2 и Hyper-V, а VirtualBox опять может уйти в режим NEM.

## После перезагрузки (AMD-V)

Руководитель перезагрузил хост. В новом `D:\virtual_machine\nx-controller\Logs\VBox.log` VirtualBox занял AMD-V сам, без NEM:

```
HM: HMR3Init: AMD-V w/ nested paging
HM: Using AMD-V implementation 2.0
HM: Enabled SVM
HM: VT-x/AMD-V enable method: VirtualBox
```

Строк `NEM:` и `fall back` в этом журнале нет. SVM в BIOS уже включён, менять его не нужно.

Запущен только `nx-controller`. SSH ответил на первой минуте (`uptime`: up 1 min, load 1.29). `make ps`: postgres, redis и web — healthy, nginx, beat и оба воркера — Up.

`make selfcheck` (обе части), строк `[FAIL]` нет:

```
[OK]   PostgreSQL: соединение — postgresql
[OK]   PostgreSQL: миграции применены
[OK]   Redis: аутентифицированный PING
[OK]   Celery: очередь «readonly» принимает и выполняет задачи
[OK]   Celery: очередь «mutation» принимает и выполняет задачи
[OK]   Инструмент nmap — /usr/bin/nmap
[OK]   Инструмент tshark — /usr/bin/tshark
ИТОГ: всё в порядке

[OK]   Ключ контроллера читается — /run/secrets/controller_ed25519
ИТОГ: всё в порядке
```

`make itest` завершился с кодом 0. В полосе прогресса pytest: 341 точка (passed) и 3 `s` (skipped), символов `F` и `E` нет. Строку «N passed» pytest в этом запуске не напечатал (вывод только полоса), счёт снят с символов полосы.

Затем по одной: `nx-server` — `ssh` сразу вернул `nx-server`; `nx-gateway` — один таймаут баннера, со второй попытки `nx-gateway`; `nx-client` — сразу `nx-client`. Все четыре ВМ включены.
