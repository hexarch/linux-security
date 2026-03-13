#!/usr/bin/env bash
# Linux Security Hardening Script - Kullanıcı Dostu Sürüm
# Kaynak: https://github.com/hexarch/linux-security
set -euo pipefail

# =============================================================================
# ORTAM DEĞİŞKENLERİ (isteğe bağlı - script başına tanımlanabilir)
# =============================================================================
# SSH_PORT=22                    # SSH portu (varsayılan: 22)
# PERMIT_ROOT_LOGIN=no           # no=root kapalı | prohibit-password=root sadece key ile
# ALLOWED_IPS=                    # Boş=bütün IPler | 1.2.3.4,5.6.7.8=sadece bu IPler
# ALLOW_HTTP=true                # 80 portu (true/false)
# ALLOW_HTTPS=true               # 443 portu (true/false)
# DISABLE_SSH_PASSWORD_AUTH=false # Şifre ile SSH kapat (SSH key şart!)
# ENABLE_UNATTENDED_UPGRADES=true
# ENABLE_FAIL2BAN=true
# NONINTERACTIVE=0                # 1=otomatik onay, 0=her adımda sor
# DRY_RUN=0                      # 1=değişiklik yapma, sadece göster
# =============================================================================

# Renkler (terminal desteklemiyorsa boş)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[UYARI]${NC} $*"; }
log_error() { echo -e "${RED}[HATA]${NC} $*"; }

# Root kontrolü
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  log_error "Script root olarak çalıştırılmalı: sudo bash script.sh"
  exit 1
fi

# =============================================================================
# ÖN KONTROLLER
# =============================================================================
log_info "Ön kontroller yapılıyor..."

# Bağlantı bilgisi
CURRENT_IP=""
if [[ -n "${SSH_CONNECTION:-}" ]]; then
  CURRENT_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
  SSH_PORT="${SSH_PORT:-$(echo "$SSH_CONNECTION" | awk '{print $4}')}"
  log_info "SSH ile bağlısınız. IP: $CURRENT_IP, Port: ${SSH_PORT:-22}"
else
  SSH_PORT="${SSH_PORT:-22}"
  log_warn "Konsol modunda veya SSH değil. Port: $SSH_PORT"
fi

# SSH key kontrolü
AUTH_KEYS_FILE="/root/.ssh/authorized_keys"
if [[ -L "$AUTH_KEYS_FILE" ]]; then
  AUTH_KEYS_FILE=$(readlink -f "$AUTH_KEYS_FILE")
fi
KEY_COUNT=0
[[ -f "$AUTH_KEYS_FILE" ]] && KEY_COUNT=$(grep -c -E "^(ssh-|ecdsa-)" "$AUTH_KEYS_FILE" 2>/dev/null || echo 0)

if [[ "$KEY_COUNT" -eq 0 ]]; then
  log_error "SSH key bulunamadı! ($AUTH_KEYS_FILE)"
  log_error "Script çalıştırmadan önce: ssh-copy-id root@sunucu"
  log_error "Aksi halde sunucuya tekrar bağlanamazsınız!"
  [[ "${NONINTERACTIVE:-0}" -eq 0 ]] && read -p "Yine de devam etmek istiyor musunuz? (evet/hayir): " resp
  [[ "${resp:-hayir}" != "evet" ]] && exit 1
else
  log_ok "Kayıtlı SSH key sayısı: $KEY_COUNT"
fi

# Proxmox tespiti
if [[ -d /etc/pve ]] && [[ -f /usr/bin/pvesh ]]; then
  log_warn "Proxmox VE tespit edildi. Port 8006 (web panel) firewall'da açık olmayacak."
  log_warn "Proxmox için Nginx reverse proxy + 443 kullanmanız önerilir."
fi

# IP whitelist uyarısı
ALLOWED_IPS="${ALLOWED_IPS:-}"
if [[ -n "$ALLOWED_IPS" ]] && [[ -n "$CURRENT_IP" ]]; then
  if ! echo ",$ALLOWED_IPS," | grep -q ",$CURRENT_IP,"; then
    log_error "IP'niz ($CURRENT_IP) ALLOWED_IPS listesinde yok! Bağlantınız kesilecek."
    log_error "ALLOWED_IPS='$ALLOWED_IPS' - kendi IP'nizi ekleyin: ALLOWED_IPS='$CURRENT_IP,$ALLOWED_IPS'"
    exit 1
  fi
fi

# =============================================================================
# BANNER
# =============================================================================
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Linux Güvenlik Sertleştirme Scripti                       ║${NC}"
echo -e "${BLUE}║     UFW • Fail2ban • SSH • sysctl • Otomatik Güncelleme      ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

BACKUP_DIR="/root/security-backups-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Ayarlar
ALLOW_HTTP="${ALLOW_HTTP:-true}"
ALLOW_HTTPS="${ALLOW_HTTPS:-true}"
DISABLE_SSH_PASSWORD_AUTH="${DISABLE_SSH_PASSWORD_AUTH:-false}"
ENABLE_UNATTENDED_UPGRADES="${ENABLE_UNATTENDED_UPGRADES:-true}"
ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-true}"
PERMIT_ROOT_LOGIN="${PERMIT_ROOT_LOGIN:-no}"  # no | prohibit-password

# Onay (interaktif mod)
if [[ "${NONINTERACTIVE:-0}" -eq 0 ]] && [[ "${DRY_RUN:-0}" -eq 0 ]]; then
  echo "Yapılacak değişiklikler:"
  echo "  • UFW firewall (SSH:$SSH_PORT, HTTP:${ALLOW_HTTP}, HTTPS:${ALLOW_HTTPS})"
  [[ -n "$ALLOWED_IPS" ]] && echo "  • Sadece şu IPler: $ALLOWED_IPS"
  echo "  • SSH: PermitRootLogin=$PERMIT_ROOT_LOGIN"
  echo "  • sysctl kernel/network sertleştirmesi"
  echo "  • Fail2ban (brute-force koruma)"
  echo "  • Otomatik güvenlik güncellemeleri"
  echo ""
  read -p "Devam etmek istiyor musunuz? (evet/hayir): " confirm
  [[ "$confirm" != "evet" ]] && { log_info "İptal edildi."; exit 0; }
fi

# Dry-run
if [[ "${DRY_RUN:-0}" -eq 1 ]]; then
  log_warn "DRY_RUN=1 - Değişiklik yapılmayacak, sadece simülasyon."
  log_info "Backup: $BACKUP_DIR"
  log_info "SSH_PORT=$SSH_PORT, PERMIT_ROOT_LOGIN=$PERMIT_ROOT_LOGIN"
  log_info "ALLOWED_IPS=${ALLOWED_IPS:-tümü}"
  exit 0
fi

# =============================================================================
# PAKET KURULUMU
# =============================================================================
log_info "Gerekli paketler kuruluyor..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  ufw fail2ban openssh-server \
  unattended-upgrades apt-listchanges \
  ca-certificates curl vim rsyslog

systemctl enable rsyslog >/dev/null 2>&1 || true
systemctl start rsyslog >/dev/null 2>&1 || true
log_ok "Paketler kuruldu."

# =============================================================================
# FIREWALL (UFW)
# =============================================================================
log_info "UFW firewall yapılandırılıyor..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

if [[ -n "$ALLOWED_IPS" ]]; then
  # Sadece belirli IPlerden izin
  for ip in ${ALLOWED_IPS//,/ }; do
    ip=$(echo "$ip" | xargs)
    [[ -z "$ip" ]] && continue
    ufw allow from "$ip" to any port "${SSH_PORT}/tcp" comment "SSH"
    [[ "$ALLOW_HTTP" == "true" ]] && ufw allow from "$ip" to any port 80 comment "HTTP"
    [[ "$ALLOW_HTTPS" == "true" ]] && ufw allow from "$ip" to any port 443 comment "HTTPS"
  done
  log_ok "IP kısıtlaması: $ALLOWED_IPS"
else
  # Tüm IPler (rate limit ile)
  ufw limit "${SSH_PORT}/tcp"
  [[ "$ALLOW_HTTP" == "true" ]] && ufw allow 80/tcp
  [[ "$ALLOW_HTTPS" == "true" ]] && ufw allow 443/tcp
fi

ufw --force enable
log_ok "UFW etkin."

# =============================================================================
# SYSCTL
# =============================================================================
log_info "Kernel/network sertleştirmesi uygulanıyor..."
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
log_ok "sysctl ayarları uygulandı."

# =============================================================================
# SSH AYARLARI
# =============================================================================
log_info "SSH sertleştirmesi uygulanıyor..."
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
ensure_sshd "PermitRootLogin" "$PERMIT_ROOT_LOGIN"
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

if sshd -t 2>/dev/null; then
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
  log_ok "SSH yeniden başlatıldı."
else
  log_error "SSH config hatası, eski haline alınıyor."
  cp -a "$BACKUP_DIR/sshd_config.bak" "$SSHD_CONFIG"
  exit 1
fi

# =============================================================================
# FAIL2BAN
# =============================================================================
if [[ "$ENABLE_FAIL2BAN" == "true" ]]; then
  log_info "Fail2ban yapılandırılıyor..."
  JAIL_LOCAL="/etc/fail2ban/jail.local"
  [[ -f "$JAIL_LOCAL" ]] && cp -a "$JAIL_LOCAL" "$BACKUP_DIR/jail.local.bak"

  IGNOREIP="127.0.0.1/8"
  [[ -n "$ALLOWED_IPS" ]] && IGNOREIP="$IGNOREIP $(echo "$ALLOWED_IPS" | sed 's/,/ /g')"
  [[ -n "$CURRENT_IP" ]] && IGNOREIP="$IGNOREIP $CURRENT_IP"

  cat > "$JAIL_LOCAL" <<EOF
[DEFAULT]
ignoreip = $IGNOREIP
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = $SSH_PORT
mode = aggressive
EOF

  systemctl enable fail2ban
  systemctl restart fail2ban
  log_ok "Fail2ban etkin."
fi

# =============================================================================
# OTOMATIK GÜNCELLEMELER
# =============================================================================
if [[ "$ENABLE_UNATTENDED_UPGRADES" == "true" ]]; then
  log_info "Otomatik güvenlik güncellemeleri etkinleştiriliyor..."
  dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true
  systemctl enable unattended-upgrades >/dev/null 2>&1 || true
  systemctl restart unattended-upgrades >/dev/null 2>&1 || true
  log_ok "Unattended-upgrades etkin."
fi

# =============================================================================
# SONUÇ
# =============================================================================
echo ""
log_ok "Güvenlik sertleştirmesi tamamlandı!"
echo ""
echo "Yedekler: $BACKUP_DIR"
echo ""
echo "Geri alma:"
echo "  sshd:  cp $BACKUP_DIR/sshd_config.bak /etc/ssh/sshd_config && systemctl restart ssh"
echo "  sysctl: cp $BACKUP_DIR/99-hardening.conf.bak /etc/sysctl.d/99-hardening.conf && sysctl --system"
echo ""
ufw status verbose | head -30 || true
[[ "$ENABLE_FAIL2BAN" == "true" ]] && fail2ban-client status sshd 2>/dev/null || true
