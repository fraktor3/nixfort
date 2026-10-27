#!/usr/bin/env bash
# NIXFORT lab: the 8 intentional defects for acceptance test AT-06 and the experiment (S-011).
# LAB VIRTUAL MACHINES ONLY, on top of the `clean-base` snapshot. Idempotent.
#
# Run from nx-controller (the repository there has LF line endings):
#   ssh labadmin@10.77.0.30 'sudo bash -s -- server'  < ~/nixfort/lab/inject_defects.sh
#   ssh labadmin@10.77.0.20 'sudo bash -s -- gateway' < ~/nixfort/lab/inject_defects.sh
#
# Defects (expected failing checks in the NIXFORT audit):
#   1 PermitRootLogin yes            nx-server  SSH-01
#   2 PasswordAuthentication yes     nx-server  SSH-02
#   3 MaxAuthTries 10                nx-server  SSH-04
#   4 X11Forwarding yes              nx-server  SSH-06
#   5 no Fail2ban / jail sshd        nx-server  F2B-01 (F2B-02, F2B-03)
#   6 extra service on :8080         nx-server  SYS-04 (and HFW-01: no host firewall)
#   7 no forward filtering           nx-gateway FW-02, FW-03
#   8 no IDS sensor on the gateway   nx-gateway IDS-01 (IDS-02, IDS-03)
# 5 and 8 are the clean-base state (the packages are not installed): the script only verifies it.
set -euo pipefail

role="${1:-}"
host="$(hostname)"
fail() { echo "ОШИБКА: $*" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || fail "нужен root (sudo bash -s -- <role>)"

installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }

case "$role" in
server)
    [ "$host" = "nx-server" ] || fail "это $host, а не nx-server"
    [ -e /etc/ssh/sshd_config.d/00-nixfort.conf ] && fail "на узле уже есть настройки NIXFORT — восстановите снимок clean-base"
    # 10-: after NIXFORT's own 00-nixfort.conf (which wins once applied), before 50-cloud-init.conf
    cat > /etc/ssh/sshd_config.d/10-lab-defects.conf <<'CONF'
# NIXFORT lab defects (AT-06 / S-011). Not for real systems.
PermitRootLogin yes
PasswordAuthentication yes
MaxAuthTries 10
X11Forwarding yes
CONF
    chmod 644 /etc/ssh/sshd_config.d/10-lab-defects.conf
    mkdir -p /run/sshd
    sshd -t || fail "sshd -t не прошёл"
    systemctl try-reload-or-restart ssh.service
    systemctl enable --now lab-extra.service >/dev/null 2>&1 || fail "нет службы lab-extra (LAB_SETUP §5)"
    installed fail2ban && fail "Fail2ban уже установлен — восстановите снимок clean-base"
    echo "1-4: $(sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|maxauthtries|x11forwarding) ' | tr '\n' ' ')"
    echo "5: fail2ban не установлен"
    echo "6: lab-extra $(systemctl is-active lab-extra.service); слушает: $(ss -Hltn 'sport = :8080' | wc -l) сокет(а) на :8080"
    ;;
gateway)
    [ "$host" = "nx-gateway" ] || fail "это $host, а не nx-gateway"
    nft list table inet nixfort >/dev/null 2>&1 && fail "на шлюзе уже есть таблица inet nixfort — восстановите снимок clean-base"
    installed suricata && fail "Suricata уже установлена — восстановите снимок clean-base"
    sysctl -q -w net.ipv4.ip_forward=1
    echo "7: ip_forward=$(sysctl -n net.ipv4.ip_forward); правил forward нет: $(nft list ruleset 2>/dev/null | grep -c 'hook forward' || true) цепочек forward"
    echo "8: suricata не установлена"
    ;;
*)
    fail "укажите роль: server или gateway"
    ;;
esac
echo "Дефекты для роли $role внесены."
