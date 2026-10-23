# Сборка испытательного стенда (VirtualBox, Windows, 16 ГБ RAM)

Задача T-000. Выполняет руководитель проекта. Время: 3–4 часа. Результат — 4 ВМ, снапшот `clean-base` у каждой.

## 0. Что понадобится
- VirtualBox 7.x (+ Extension Pack не обязателен).
- ISO **Ubuntu Server 24.04.x LTS amd64** (ubuntu.com/download/server).
- ~60 ГБ свободного места.
- На Windows: Git, Python 3.12 (для локальных тестов), Cursor.
- Если в Windows включены WSL2/Hyper-V — VirtualBox работает, но медленнее. Docker Desktop на Windows **не нужен**.

## 1. Ресурсы ВМ
| ВМ | RAM | CPU | Диск | Адаптер 1 | Адаптер 2 | Адаптер 3 | Адаптер 4 |
|---|---|---|---|---|---|---|---|
| nx-controller | 4096 МБ | 2 | 25 ГБ | NAT | Внутр. сеть `nx-mgmt` | — | — |
| nx-gateway | 1536 МБ | 2 | 12 ГБ | NAT | `nx-mgmt` | `nx-users` | `nx-servers` |
| nx-server | 1024 МБ | 1 | 10 ГБ | NAT | `nx-mgmt` | `nx-servers` | — |
| nx-client | 768 МБ | 1 | 10 ГБ | NAT | `nx-mgmt` | `nx-users` | — |
Итого ≈ 7,4 ГБ RAM. Во время работы держи открытыми только нужные ВМ.

Интерфейсы внутри Ubuntu обычно: адаптер 1 → `enp0s3`, 2 → `enp0s8`, 3 → `enp0s9`, 4 → `enp0s10`. Проверь командой `ip -br link` и подставь свои имена.

NAT-адаптер нужен для `apt` и `git`. Он не мешает схеме: маршруты между users и servers заданы явно через шлюз.

## 2. Базовая ВМ
1. Создай ВМ `nx-base` (Linux/Ubuntu 64, 2048 МБ, 1 CPU, 12 ГБ), только адаптер 1 = NAT.
2. Установка Ubuntu Server: язык English, раскладка по вкусу, тип установки «Ubuntu Server» (не minimized), сеть по DHCP, **без** LVM-шифрования, пользователь `labadmin`, **включи «Install OpenSSH server»**, дополнительных snap не ставь.
3. После установки:
   ```bash
   sudo apt update && sudo apt -y full-upgrade
   sudo apt -y install python3 curl ca-certificates net-tools tcpdump netcat-openbsd
   sudo poweroff
   ```
4. В VirtualBox: Клонировать `nx-base` 4 раза → «Полный клон», «Сгенерировать новые MAC-адреса для всех адаптеров». Имена: `nx-controller`, `nx-gateway`, `nx-server`, `nx-client`. Задай RAM/CPU/адаптеры по таблице.

## 3. На КАЖДОЙ клонированной ВМ (уникальность)
```bash
sudo hostnamectl set-hostname nx-gateway          # своё имя
sudo rm -f /etc/ssh/ssh_host_* && sudo dpkg-reconfigure openssh-server
sudo rm -f /etc/machine-id /var/lib/dbus/machine-id && sudo systemd-machine-id-setup
```
Без этого у клонов одинаковые SSH host key — проверка отпечатков в NIXFORT потеряет смысл.

## 4. Сеть (netplan)
Создай `/etc/netplan/60-nixfort-lab.yaml` (права `sudo chmod 600`), затем `sudo netplan apply`.

**nx-controller**
```yaml
network:
  version: 2
  ethernets:
    enp0s8: {addresses: [10.77.0.10/24]}
```
**nx-gateway**
```yaml
network:
  version: 2
  ethernets:
    enp0s8:  {addresses: [10.77.0.20/24]}
    enp0s9:  {addresses: [10.88.0.1/24]}
    enp0s10: {addresses: [10.99.0.1/24]}
```
и включи маршрутизацию:
```bash
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/60-nixfort-lab.conf && sudo sysctl --system
```
**nx-server**
```yaml
network:
  version: 2
  ethernets:
    enp0s8: {addresses: [10.77.0.30/24]}
    enp0s9:
      addresses: [10.99.0.10/24]
      routes: [{to: 10.88.0.0/24, via: 10.99.0.1}]
```
**nx-client**
```yaml
network:
  version: 2
  ethernets:
    enp0s8: {addresses: [10.77.0.40/24]}
    enp0s9:
      addresses: [10.88.0.10/24]
      routes: [{to: 10.99.0.0/24, via: 10.88.0.1}]
```

## 5. Роли ВМ
**nx-server** — тестовые службы:
```bash
sudo apt -y install nginx
sudo tee /etc/systemd/system/lab-extra.service >/dev/null <<'UNIT'
[Unit]
Description=Lab extra service on :8080 (intentional defect)
After=network-online.target
[Service]
ExecStart=/usr/bin/python3 -m http.server 8080 --directory /var/empty
DynamicUser=yes
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
sudo mkdir -p /var/empty && sudo systemctl daemon-reload && sudo systemctl enable --now lab-extra
```
Fail2ban и Suricata **не устанавливай** — их установит и настроит NIXFORT (это часть демонстрации).

**nx-controller** — Docker:
```bash
sudo apt -y install docker.io docker-compose-v2 git
sudo usermod -aG docker labadmin   # перелогинься
docker compose version
```

**nx-gateway, nx-client** — ничего дополнительно.

## 6. Проверка схемы (обязательно!)
С `nx-client`:
```bash
ip route get 10.99.0.10          # должно быть: via 10.88.0.1 dev enp0s9
nc -zv -w2 10.99.0.10 80         # succeeded
nc -zv -w2 10.99.0.10 8080       # succeeded
```
На `nx-gateway` во время `nc` с клиента: `sudo tcpdump -ni enp0s9 tcp port 80` — пакеты видны. **Значит трафик идёт через шлюз.**
С `nx-controller`: `ping -c1 10.77.0.20`, `10.77.0.30`, `10.77.0.40` — отвечают.

## 7. Доступ с Windows
В VirtualBox → ВМ → Сеть → Адаптер 1 (NAT) → Проброс портов:
| ВМ | Хост 127.0.0.1:порт | Гость |
|---|---|---|
| nx-controller | 2210 → 22, 8443 → 443 | |
| nx-gateway | 2220 → 22 | |
| nx-server | 2230 → 22 | |
| nx-client | 2240 → 22 | |
Подключение: `ssh -p 2210 labadmin@127.0.0.1`. Веб NIXFORT позже: `https://127.0.0.1:8443`.

## 8. Снапшоты
На всех 4 ВМ (выключенных): снапшот **`clean-base`**. К нему откатываемся перед каждым экспериментом.

## 9. Отчёт о выполнении T-000
Пришли архитектору вывод команд из п.6 и `ip -br addr` со всех ВМ.

## Позже (выполняется в T-006)
Установка агента: `agent/install.sh` на gateway/server/client, ключ контроллера, подтверждение отпечатков в веб-интерфейсе.
