#!/bin/bash
# =============================================================================
# INSTALL SCRIPT — install security scripts on a HestiaCP server
# Run as root: bash install.sh
# =============================================================================
set -e

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'; NC='\033[0m'
log()  { echo -e "${GRN}[+]${NC} $1"; }
warn() { echo -e "${YLW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

[ "$(id -u)" -ne 0 ] && err "Run as root: sudo bash install.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- 1. Config ---
if [ ! -f /etc/security-audit.env ]; then
  cp "$SCRIPT_DIR/security-audit.env.example" /etc/security-audit.env
  chmod 600 /etc/security-audit.env
  warn "Created /etc/security-audit.env — fill in RESEND_API_KEY and RESEND_TO"
  warn "Then re-run install.sh or configure cron manually"
else
  log "/etc/security-audit.env already exists"
fi

# --- 2. Dependencies ---
log "Checking dependencies..."
apt-get install -y curl git inotify-tools fail2ban >/dev/null 2>&1
log "Dependencies installed"

# --- 3. Script permissions ---
chmod +x "$SCRIPT_DIR"/*.sh
log "Script permissions set"

# --- 4. Cron ---
CRON_FILE="/etc/cron.d/security-monitoring"
if [ ! -f "$CRON_FILE" ]; then
  cat > "$CRON_FILE" <<'EOF'
# Security monitoring cron jobs
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
EOF
  log "Cron created: $CRON_FILE"
else
  log "Cron already exists: $CRON_FILE"
fi

ensure_cron_line() {
  local line="$1"
  grep -Fqx "$line" "$CRON_FILE" || echo "$line" >> "$CRON_FILE"
}

ensure_cron_line "0 3 * * * root bash ${SCRIPT_DIR}/01-security-audit.sh >> /var/log/security-audit.log 2>&1"
ensure_cron_line "0 */6 * * * root bash ${SCRIPT_DIR}/04-git-auto-restore.sh >> /var/log/git-auto-restore.log 2>&1"
ensure_cron_line "*/30 * * * * root bash ${SCRIPT_DIR}/06-binary-integrity-guard.sh >> /var/log/binary-integrity-guard.log 2>&1"
ensure_cron_line "*/15 * * * * root bash ${SCRIPT_DIR}/07-tmp-ioc-guard.sh >> /var/log/tmp-ioc-guard.log 2>&1"
ensure_cron_line "20 4 * * * root bash ${SCRIPT_DIR}/08-guards-smoke-check.sh >> /var/log/guards-smoke-check.log 2>&1"

# --- 5. Summary ---
echo ""
log "============================================================"
log "Installation complete!"
log "============================================================"
echo ""
echo "  Next steps:"
echo "  1. Fill in /etc/security-audit.env (RESEND_API_KEY, RESEND_TO)"
echo "  2. Run hardening: sudo bash ${SCRIPT_DIR}/03-hardening.sh"
echo "  3. Run audit:     sudo bash ${SCRIPT_DIR}/01-security-audit.sh"
echo ""
warn "Audit runs automatically every day at 3:00 (UTC)"
warn "Git auto-restore — every 6 hours"
warn "Binary integrity guard — every 30 minutes"
warn "Tmp IOC quarantine guard — every 15 minutes"
warn "Guards smoke-check — daily at 04:20"
