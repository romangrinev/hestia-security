#!/bin/bash
# =============================================================================
# INSTALL SCRIPT — установка security scripts на HestiaCP сервер
# Запускать от root: bash install.sh
# =============================================================================
set -e

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'; NC='\033[0m'
log()  { echo -e "${GRN}[+]${NC} $1"; }
warn() { echo -e "${YLW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

[ "$(id -u)" -ne 0 ] && err "Запускайте от root: sudo bash install.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- 1. Конфиг ---
if [ ! -f /etc/security-audit.env ]; then
  cp "$SCRIPT_DIR/security-audit.env.example" /etc/security-audit.env
  chmod 600 /etc/security-audit.env
  warn "Создан /etc/security-audit.env — заполните RESEND_API_KEY и RESEND_TO"
  warn "Затем повторно запустите install.sh или настройте cron вручную"
else
  log "/etc/security-audit.env уже существует"
fi

# --- 2. Зависимости ---
log "Проверка зависимостей..."
apt-get install -y curl git inotify-tools fail2ban >/dev/null 2>&1
log "Зависимости установлены"

# --- 3. Права на скрипты ---
chmod +x "$SCRIPT_DIR"/*.sh
log "Права на скрипты выставлены"

# --- 4. Cron ---
CRON_FILE="/etc/cron.d/security-monitoring"
if [ ! -f "$CRON_FILE" ]; then
  cat > "$CRON_FILE" <<EOF
# Security monitoring cron jobs
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Ежедневный аудит безопасности в 3:00
0 3 * * * root bash ${SCRIPT_DIR}/01-security-audit.sh >> /var/log/security-audit.log 2>&1

# Авто-восстановление git каждые 6 часов
0 */6 * * * root bash ${SCRIPT_DIR}/04-git-auto-restore.sh >> /var/log/git-auto-restore.log 2>&1
EOF
  log "Cron создан: $CRON_FILE"
else
  log "Cron уже существует: $CRON_FILE"
fi

# --- 5. Итог ---
echo ""
log "============================================================"
log "Установка завершена!"
log "============================================================"
echo ""
echo "  Следующие шаги:"
echo "  1. Заполните /etc/security-audit.env (RESEND_API_KEY, RESEND_TO)"
echo "  2. Запустите хардинг: sudo bash ${SCRIPT_DIR}/03-hardening.sh"
echo "  3. Запустите аудит:   sudo bash ${SCRIPT_DIR}/01-security-audit.sh"
echo ""
warn "Аудит запускается автоматически каждый день в 3:00 (UTC)"
warn "Git auto-restore — каждые 6 часов"
