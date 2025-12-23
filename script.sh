#!/usr/bin/env bash
set -euo pipefail

# Root kontrolü
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Script root olarak çalıştırılmalı"
  exit 1
fi

# Ayarlar
SSH_PORT="${SSH_PORT:-22}"
ALLOW_HTTP="${ALLOW_HTTP:-true}"
ALLOW_HTTPS="${ALLOW_HTTPS:-true}"
DISABLE_SSH_PASSWORD_AUTH="${DISABLE_SSH_PASSWORD_AUTH:-false}"
ENABLE_UNATTENDED_UPGRADES="${ENABLE_UNATTENDED_UPGRADES:-true}"
ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-true}"

BACKUP_DIR="/root/security-backups-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Aktif SSH bağlantısından port algıla
if [[ -n "${SSH_CONNECTION:-}" ]]; then
  detected_port="$(echo "$SSH_CONNECTION" | awk '{print $4}')"
  [[ -n "$detected_port" ]] && SSH_PORT="$detected_port"
fi

# Gerekli paketler
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  ufw fail2ban openssh-server \
  unattended-upgrades apt-listchanges \
  ca-certificates curl vim rsyslog

systemctl enable rsyslog >/dev/null 2>&1 || true
systemctl start rsyslog  >/dev/null 2>&1 || true

# Firewall
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw limit "${SSH_PORT}/tcp"
[[ "$ALLOW_HTTP" == "true" ]] && ufw allow 80/tcp
[[ "$ALLOW_HTTPS" == "true" ]] && ufw allow 443/tcp
ufw --force enable

# sysctl ayarları
SYSCTL_FILE="/etc/sysctl.d/99-hardening.conf"
[[ -f "$SYSCTL_FILE" ]] && cp -a "$SYSCTL_FILE" "$BACKUP_DIR/99-hardening.conf.bak"

cat > "$SYSCTL_FILE" <<'EOF'
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1

net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0

net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0

net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0

net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1

net.ipv4.tcp_syncookies=1
net.ipv4.tcp_rfc1337=1
net.ipv4.ip_forward=0

net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1

kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.yama.ptrace_scope=1
EOF

sysctl --system >/dev/null

# SSH ayarları
SSHD_CONFIG="/etc/ssh/sshd_config"
cp -a "$SSHD_CONFIG" "$BACKUP_DIR/sshd_config.bak"

ensure_sshd() {
  local key="$1" value="$2"
  if grep -qE "^\s*${key}\s+" "$SSHD_CONFIG"; then
    sed -i -E "s|^\s*${key}\s+.*|${key} ${value}|g" "$SSHD_CONFIG"
  else
    echo "${key} ${value}" >> "$SSHD_CONFIG"
  fi
}

ensure_sshd "Port" "$SSH_PORT"
ensure_sshd "PermitRootLogin" "no"
ensure_sshd "X11Forwarding" "no"
ensure_sshd "MaxAuthTries" "4"
ensure_sshd "LoginGraceTime" "30"
ensure_sshd "ClientAliveInterval" "300"
ensure_sshd "ClientAliveCountMax" "2"
ensure_sshd "AllowTcpForwarding" "no"
ensure_sshd "PermitTunnel" "no"

if [[ "$DISABLE_SSH_PASSWORD_AUTH" == "true" ]]; then
  ensure_sshd "PasswordAuthentication" "no"
  ensure_sshd "KbdInteractiveAuthentication" "no"
  ensure_sshd "ChallengeResponseAuthentication" "no"
else
  ensure_sshd "PubkeyAuthentication" "yes"
fi

if sshd -t; then
  systemctl restart ssh || systemctl restart sshd
else
  cp -a "$BACKUP_DIR/sshd_config.bak" "$SSHD_CONFIG"
  exit 1
fi

# Fail2ban
if [[ "$ENABLE_FAIL2BAN" == "true" ]]; then
  JAIL_LOCAL="/etc/fail2ban/jail.local"
  [[ -f "$JAIL_LOCAL" ]] && cp -a "$JAIL_LOCAL" "$BACKUP_DIR/jail.local.bak"

  cat > "$JAIL_LOCAL" <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ${SSH_PORT}
mode = aggressive
EOF

  systemctl enable fail2ban
  systemctl restart fail2ban
fi

# Otomatik güncellemeler
if [[ "$ENABLE_UNATTENDED_UPGRADES" == "true" ]]; then
  dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null || true
  systemctl enable unattended-upgrades >/dev/null 2>&1 || true
  systemctl restart unattended-upgrades >/dev/null 2>&1 || true
fi

# Durum bilgisi
ufw status verbose || true
[[ "$ENABLE_FAIL2BAN" == "true" ]] && fail2ban-client status sshd || true
ss -tunlp || true

echo "Yedekler: $BACKUP_DIR"

