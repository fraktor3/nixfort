#!/bin/sh
# Install / update the NIXFORT node agent on a managed node.
# Usage (as root, from the agent/ directory copied to the node):
#   sudo sh install.sh /path/to/controller_ed25519.pub [CONTROLLER_IP]
# Idempotent: safe to run again to update the agent code.
set -eu

PUBKEY_FILE="${1:?usage: install.sh <controller_pubkey_file> [controller_ip]}"
CONTROLLER_IP="${2:-}"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/nixfort-agent
AGENT_USER=nixfort
AGENT_HOME=/var/lib/nixfort-home

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
command -v sudo >/dev/null || { echo "sudo is required" >&2; exit 1; }

# Validate the public key: exactly one ed25519 key line.
KEY_LINE="$(grep -E '^ssh-ed25519 [A-Za-z0-9+/=]+( [A-Za-z0-9@._-]+)?$' "$PUBKEY_FILE" | head -n1 || true)"
[ -n "$KEY_LINE" ] || { echo "invalid ed25519 public key file" >&2; exit 1; }
if [ -n "$CONTROLLER_IP" ]; then
  echo "$CONTROLLER_IP" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || { echo "invalid controller ip" >&2; exit 1; }
fi

# 1. Code (root-owned, not writable by anyone else).
install -d -o root -g root -m 0755 "$DEST" "$DEST/nixfort_agent" "$DEST/nixfort_agent/actions" "$DEST/templates"
install -o root -g root -m 0644 "$SRC_DIR"/nixfort_agent/*.py "$DEST/nixfort_agent/"
install -o root -g root -m 0644 "$SRC_DIR"/nixfort_agent/actions/*.py "$DEST/nixfort_agent/actions/"
if [ -d "$SRC_DIR/templates" ] && ls "$SRC_DIR"/templates/* >/dev/null 2>&1; then
  install -o root -g root -m 0644 "$SRC_DIR"/templates/* "$DEST/templates/"
fi
install -o root -g root -m 0644 "$SRC_DIR/run.py" "$DEST/run.py"
find "$DEST" -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true

# 2. Launchers.
cat > /usr/local/sbin/nixfort-agent <<'LAUNCH'
#!/bin/sh
exec /usr/bin/python3 -I -S /opt/nixfort-agent/run.py
LAUNCH
chown root:root /usr/local/sbin/nixfort-agent && chmod 0755 /usr/local/sbin/nixfort-agent

# 3. State directories and log.
install -d -o root -g root -m 0700 /var/lib/nixfort /var/lib/nixfort/snapshots /var/lib/nixfort/tmp
touch /var/log/nixfort-agent.log && chown root:root /var/log/nixfort-agent.log && chmod 0600 /var/log/nixfort-agent.log

# 4. Restricted service account (no password login).
if ! id "$AGENT_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$AGENT_HOME" --create-home --shell /bin/sh "$AGENT_USER"
fi
passwd -l "$AGENT_USER" >/dev/null 2>&1 || true
install -d -o "$AGENT_USER" -g "$AGENT_USER" -m 0700 "$AGENT_HOME/.ssh"
FROM=""
[ -n "$CONTROLLER_IP" ] && FROM="from=\"$CONTROLLER_IP\","
printf '%srestrict,command="sudo -n /usr/local/sbin/nixfort-agent" %s\n' "$FROM" "$KEY_LINE" > "$AGENT_HOME/.ssh/authorized_keys"
chown "$AGENT_USER:$AGENT_USER" "$AGENT_HOME/.ssh/authorized_keys" && chmod 0600 "$AGENT_HOME/.ssh/authorized_keys"

# 5. sudo: only the launcher, only without arguments.
TMP_SUDO="$(mktemp)"
printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/nixfort-agent ""\n' "$AGENT_USER" > "$TMP_SUDO"
visudo -cf "$TMP_SUDO" >/dev/null
install -o root -g root -m 0440 "$TMP_SUDO" /etc/sudoers.d/nixfort
rm -f "$TMP_SUDO"

# 6. Self-test.
OUT="$(printf '{"protocol":"nixfort.agent/1","request_id":"00000000-0000-4000-8000-000000000000","action":"system.ping.v1","params":{},"deadline_s":10}' | /usr/local/sbin/nixfort-agent)"
echo "$OUT" | grep -q '"state":"OK"' || { echo "self-test failed: $OUT" >&2; exit 1; }
echo "nixfort-agent installed: $OUT"
echo "SSH host key fingerprints of this node (confirm them in NIXFORT):"
for k in /etc/ssh/ssh_host_*_key.pub; do [ -f "$k" ] && command -v ssh-keygen >/dev/null && ssh-keygen -lf "$k"; done; exit 0
