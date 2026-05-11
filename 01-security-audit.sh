#!/bin/bash
# =============================================================================
# SECURITY AUDIT SCRIPT â€” Ð¾Ð±Ð½Ð°Ñ€ÑƒÐ¶ÐµÐ½Ð¸Ðµ Ð²ÐµÐºÑ‚Ð¾Ñ€Ð° Ð·Ð°Ñ€Ð°Ð¶ÐµÐ½Ð¸Ñ
# Ð—Ð°Ð¿ÑƒÑÐºÐ°Ñ‚ÑŒ Ð¾Ñ‚ root: sudo bash 01-security-audit.sh 2>&1 | tee audit-report.txt
# =============================================================================

# ÐÐ²Ñ‚Ð¾-Ð¾Ð¿Ñ€ÐµÐ´ÐµÐ»ÐµÐ½Ð¸Ðµ Ð¿Ð¾Ð»ÑŒÐ·Ð¾Ð²Ð°Ñ‚ÐµÐ»ÐµÐ¹ HestiaCP (Ð¸Ð»Ð¸ Ð·Ð°Ð´Ð°Ð¹Ñ‚Ðµ Ð²Ñ€ÑƒÑ‡Ð½ÑƒÑŽ Ð² /etc/security-audit.env)
# USERS=("user1" "user2")   # Ñ€Ð°ÑÐºÐ¾Ð¼Ð¼ÐµÐ½Ñ‚Ð¸Ñ€ÑƒÐ¹Ñ‚Ðµ Ñ‡Ñ‚Ð¾Ð±Ñ‹ Ð¿ÐµÑ€ÐµÐ¾Ð¿Ñ€ÐµÐ´ÐµÐ»Ð¸Ñ‚ÑŒ
if [ -z "${USERS+x}" ]; then
  if command -v v-list-users &>/dev/null; then
    mapfile -t USERS < <(sudo /usr/local/hestia/bin/v-list-users plain 2>/dev/null | awk 'NR>2 && $1 != "admin" {print $1}')
  else
    mapfile -t USERS < <(ls /home/ | grep -vE '^(admin|lost\+found|ubuntu)$')
  fi
fi

REPORT_DIR="/root/security-audit-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"

# IP Ñ ÐºÐ¾Ñ‚Ð¾Ñ€Ð¾Ð³Ð¾ Ñ€Ð°Ð·Ñ€ÐµÑˆÑ‘Ð½ SSH (Ð¾Ð¿Ñ€ÐµÐ´ÐµÐ»ÑÐµÐ¼ Ð¸Ð· iptables, Ð¸Ð»Ð¸ Ð·Ð°Ð´Ð°Ð¹Ñ‚Ðµ Ð²Ñ€ÑƒÑ‡Ð½ÑƒÑŽ)
TRUSTED_SSH_IP=$(iptables -L INPUT -n --line-numbers 2>/dev/null \
  | awk '$3=="ACCEPT" && $5=="tcp" && /dpt:22/' \
  | awk '{print $8}' | grep -v '0.0.0.0' | head -1)
[ -z "$TRUSTED_SSH_IP" ] && TRUSTED_SSH_IP="67.185.203.213"

# --- RESEND ÐÐÐ¡Ð¢Ð ÐžÐ™ÐšÐ˜ ---
# Ð—Ð°Ð¼ÐµÐ½Ð¸Ñ‚Ðµ Ð½Ð° Ð²Ð°ÑˆÐ¸ Ð·Ð½Ð°Ñ‡ÐµÐ½Ð¸Ñ Ð¸Ð»Ð¸ Ð²Ñ‹Ð½ÐµÑÐ¸Ñ‚Ðµ Ð² /etc/security-audit.env
RESEND_API_KEY="re_Ð’ÐÐ¨_API_ÐšÐ›Ð®Ð§"
RESEND_FROM="security@Ð’ÐÐ¨_Ð”ÐžÐœÐ•Ð.com"
RESEND_TO="admin@Ð’ÐÐ¨_EMAIL.com"
HOSTNAME="$(hostname -f)"
ALERT_SUBJECTS=()   # Ð½Ð°ÐºÐ°Ð¿Ð»Ð¸Ð²Ð°ÐµÐ¼ Ñ‚ÐµÐ¼Ñ‹ Ð°Ð»ÐµÑ€Ñ‚Ð¾Ð²
ALERT_BODIES=()     # Ð½Ð°ÐºÐ°Ð¿Ð»Ð¸Ð²Ð°ÐµÐ¼ Ñ‚ÐµÐ»Ð° Ð°Ð»ÐµÑ€Ñ‚Ð¾Ð²

# Ð—Ð°Ð³Ñ€ÑƒÐ¶Ð°ÐµÐ¼ ÐºÐ¾Ð½Ñ„Ð¸Ð³ Ð¸Ð· Ñ„Ð°Ð¹Ð»Ð° ÐµÑÐ»Ð¸ ÐµÑÑ‚ÑŒ (Ñ‡Ñ‚Ð¾Ð±Ñ‹ Ð½Ðµ Ñ…Ñ€Ð°Ð½Ð¸Ñ‚ÑŒ ÐºÐ»ÑŽÑ‡Ð¸ Ð² ÑÐºÑ€Ð¸Ð¿Ñ‚Ðµ)
[ -f /etc/security-audit.env ] && source /etc/security-audit.env

# ÐžÑ‚Ð¿Ñ€Ð°Ð²ÐºÐ° Ð¿Ð¸ÑÑŒÐ¼Ð° Ñ‡ÐµÑ€ÐµÐ· Resend API
# $1 â€” Ñ‚ÐµÐ¼Ð°, $2 â€” Ð¿ÑƒÑ‚ÑŒ Ðº Ñ„Ð°Ð¹Ð»Ñƒ Ñ Ñ‚ÐµÐ»Ð¾Ð¼ Ð¿Ð¸ÑÑŒÐ¼Ð° (plain text)
send_resend_email() {
  local SUBJECT="$1"
  local BODY_FILE="$2"
  local TMPJSON
  TMPJSON=$(mktemp /tmp/resend-body-XXXXXX.json)

  # Ð˜ÑÐ¿Ð¾Ð»ÑŒÐ·ÑƒÐµÐ¼ python3 Ð´Ð»Ñ ÐºÐ¾Ñ€Ñ€ÐµÐºÑ‚Ð½Ð¾Ð³Ð¾ JSON-ÐºÐ¾Ð´Ð¸Ñ€Ð¾Ð²Ð°Ð½Ð¸Ñ (Ð¸Ð·Ð±ÐµÐ³Ð°ÐµÐ¼ "Argument list too long")
  python3 - "$SUBJECT" "$RESEND_FROM" "$RESEND_TO" "$BODY_FILE" <<'PYEOF' > "$TMPJSON"
import json, sys
subject = sys.argv[1]
from_addr = sys.argv[2]
to_addr = sys.argv[3]
body_file = sys.argv[4]
with open(body_file, 'r', errors='replace') as f:
    body = f.read()
data = {"from": from_addr, "to": [to_addr], "subject": subject, "text": body}
print(json.dumps(data))
PYEOF

  local HTTP_CODE
  HTTP_CODE=$(curl -s -o /tmp/resend-response.json -w "%{http_code}" \
    -X POST https://api.resend.com/emails \
    -H "Authorization: Bearer ${RESEND_API_KEY}" \
    -H "Content-Type: application/json" \
    --data "@${TMPJSON}")

  rm -f "$TMPJSON"

  if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    log "Email Ð¾Ñ‚Ð¿Ñ€Ð°Ð²Ð»ÐµÐ½ Ñ‡ÐµÑ€ÐµÐ· Resend: $SUBJECT"
  else
    warn "ÐžÑˆÐ¸Ð±ÐºÐ° Ð¾Ñ‚Ð¿Ñ€Ð°Ð²ÐºÐ¸ email (HTTP $HTTP_CODE): $(cat /tmp/resend-response.json 2>/dev/null)"
  fi
}

# Ð”Ð¾Ð±Ð°Ð²Ð¸Ñ‚ÑŒ Ð°Ð»ÐµÑ€Ñ‚ Ð² Ð¾Ñ‡ÐµÑ€ÐµÐ´ÑŒ (Ð±ÑƒÐ´ÐµÑ‚ Ð¾Ñ‚Ð¿Ñ€Ð°Ð²Ð»ÐµÐ½ Ð¾Ð´Ð½Ð¸Ð¼ Ð¿Ð¸ÑÑŒÐ¼Ð¾Ð¼ Ð² ÐºÐ¾Ð½Ñ†Ðµ)
queue_alert() {
  local label="$1"
  local content="$2"
  ALERT_SUBJECTS+=("$label")
  ALERT_BODIES+=("$content")
  alert "$label"
}

RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${GRN}[+]${NC} $1"; }
warn() { echo -e "${YLW}[!]${NC} $1"; }
alert() { echo -e "${RED}[ALERT]${NC} $1"; }

echo "============================================================"
echo " SECURITY AUDIT â€” $(date)"
echo "============================================================"

# --- 1. Ð¡Ð˜Ð¡Ð¢Ð•ÐœÐÐÐ¯ Ð˜ÐÐ¤ÐžÐ ÐœÐÐ¦Ð˜Ð¯ ---
log "=== 1. Ð¡Ð˜Ð¡Ð¢Ð•ÐœÐÐÐ¯ Ð˜ÐÐ¤ÐžÐ ÐœÐÐ¦Ð˜Ð¯ ==="
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME)"
echo "Kernel: $(uname -r)"
echo "Uptime: $(uptime)"
echo "HestiaCP version: $(cat /usr/local/hestia/conf/hestia.conf 2>/dev/null | grep VERSION || echo 'Ð½Ðµ Ð½Ð°Ð¹Ð´ÐµÐ½Ð¾')"

# --- 2. ÐŸÐžÐ¡Ð›Ð•Ð”ÐÐ˜Ð• Ð’Ð¥ÐžÐ”Ð« ÐÐ Ð¡Ð•Ð Ð’Ð•Ð  ---
log "=== 2. ÐŸÐžÐ¡Ð›Ð•Ð”ÐÐ˜Ð• Ð’Ð¥ÐžÐ”Ð« SSH (last 50) ==="
last -n 50 | tee "$REPORT_DIR/last-logins.txt"

# ÐÐµÑƒÐ´Ð°Ñ‡Ð½Ñ‹Ðµ SSH Ð²Ñ…Ð¾Ð´Ñ‹ â€” Ð¿Ð¾ÐºÐ°Ð·Ñ‹Ð²Ð°ÐµÐ¼ Ñ‚Ð¾Ð»ÑŒÐºÐ¾ ÑÑ‡Ñ‘Ñ‚Ñ‡Ð¸Ðº (fail2ban Ð·Ð°Ñ‰Ð¸Ñ‰Ð°ÐµÑ‚)
grep "Failed password" /var/log/auth.log 2>/dev/null \
  | tee "$REPORT_DIR/failed-ssh-logins.txt" > /dev/null
FAILED_COUNT=$(wc -l < "$REPORT_DIR/failed-ssh-logins.txt")
if [ "$FAILED_COUNT" -gt 10 ]; then
  warn "ÐÐµÑƒÐ´Ð°Ñ‡Ð½Ñ‹Ñ… Ð¿Ð¾Ð¿Ñ‹Ñ‚Ð¾Ðº Ð²Ñ…Ð¾Ð´Ð° SSH Ð² auth.log: $FAILED_COUNT (fail2ban Ð°ÐºÑ‚Ð¸Ð²ÐµÐ½)"
else
  log "âœ“ ÐÐµÑƒÐ´Ð°Ñ‡Ð½Ñ‹Ñ… SSH Ð¿Ð¾Ð¿Ñ‹Ñ‚Ð¾Ðº: $FAILED_COUNT"
fi

# ÐŸÑ€Ð¸Ð½ÑÑ‚Ñ‹Ðµ Ð¿Ð°Ñ€Ð¾Ð»Ð¸ â€” Ð°Ð»ÐµÑ€Ñ‚ Ñ‚Ð¾Ð»ÑŒÐºÐ¾ Ð´Ð»Ñ IP Ð½Ðµ Ð¸Ð· Ð²Ð°Ð¹Ñ‚Ð»Ð¸ÑÑ‚Ð°
grep "Accepted password" /var/log/auth.log 2>/dev/null \
  | tee "$REPORT_DIR/accepted-password-logins.txt" > /dev/null
PASSWD_FROM_UNKNOWN=$(grep "Accepted password" /var/log/auth.log 2>/dev/null \
  | grep -v "$TRUSTED_SSH_IP")
if [ -n "$PASSWD_FROM_UNKNOWN" ]; then
  warn "ÐŸÑ€Ð¸Ð½ÑÑ‚Ñ‹Ðµ Ð¿Ð°Ñ€Ð¾Ð»Ð¸ Ñ Ð½ÐµÐ·Ð½Ð°ÐºÐ¾Ð¼Ñ‹Ñ… IP (ÐŸÐžÐ”ÐžÐ—Ð Ð˜Ð¢Ð•Ð›Ð¬ÐÐž):"
  echo "$PASSWD_FROM_UNKNOWN" | tee -a "$REPORT_DIR/accepted-password-logins.txt"
  queue_alert "SSH: Ð¿Ñ€Ð¸Ð½ÑÑ‚Ñ‹Ðµ Ð¿Ð°Ñ€Ð¾Ð»Ð¸ Ñ Ð½ÐµÐ¸Ð·Ð²ÐµÑÑ‚Ð½Ñ‹Ñ… IP" "$PASSWD_FROM_UNKNOWN"
else
  log "âœ“ ÐŸÑ€Ð¸Ð½ÑÑ‚Ñ‹Ñ… Ð¿Ð°Ñ€Ð¾Ð»ÐµÐ¹ Ñ Ð½ÐµÐ·Ð½Ð°ÐºÐ¾Ð¼Ñ‹Ñ… IP Ð½ÐµÑ‚ (Ñ‚Ð¾Ð»ÑŒÐºÐ¾ $TRUSTED_SSH_IP Ð¸Ð»Ð¸ ÐºÐ»ÑŽÑ‡Ð¸)"
fi

# --- 3. ÐÐšÐ¢Ð˜Ð’ÐÐ«Ð• Ð¡Ð•Ð¡Ð¡Ð˜Ð˜ Ð˜ ÐŸÐ ÐžÐ¦Ð•Ð¡Ð¡Ð« ---
log "=== 3. ÐÐšÐ¢Ð˜Ð’ÐÐ«Ð• Ð¡Ð•Ð¡Ð¡Ð˜Ð˜ ==="
w
echo ""
log "ÐŸÐ¾Ð´Ð¾Ð·Ñ€Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ñ‹Ðµ Ð¿Ñ€Ð¾Ñ†ÐµÑÑÑ‹ (PHP/Python/Perl/curl/wget Ð¾Ñ‚ Ð²ÐµÐ±-Ð¿Ð¾Ð»ÑŒÐ·Ð¾Ð²Ð°Ñ‚ÐµÐ»ÐµÐ¹):"
ps aux | grep -E "(php|python|perl|wget|curl|nc |ncat|bash -i|sh -i)" \
  | grep -v grep | tee "$REPORT_DIR/suspicious-processes.txt"

# --- 4. Ð¡Ð•Ð¢Ð•Ð’Ð«Ð• Ð¡ÐžÐ•Ð”Ð˜ÐÐ•ÐÐ˜Ð¯ ---
log "=== 4. ÐÐ•Ð¡Ð¢ÐÐÐ”ÐÐ Ð¢ÐÐ«Ð• Ð¡Ð•Ð¢Ð•Ð’Ð«Ð• Ð¡ÐžÐ•Ð”Ð˜ÐÐ•ÐÐ˜Ð¯ ==="
echo "Ð¡Ð»ÑƒÑˆÐ°ÑŽÑ‰Ð¸Ðµ Ð¿Ð¾Ñ€Ñ‚Ñ‹:"
ss -tlnp | tee "$REPORT_DIR/listening-ports.txt"

EXT_CONNS=$(ss -tnp | grep ESTAB | grep -vE ':80 |:443 |:22 |:3306 |:8083 ')
if [ -n "$EXT_CONNS" ]; then
  warn "ÐÐºÑ‚Ð¸Ð²Ð½Ñ‹Ðµ Ð²Ð½ÐµÑˆÐ½Ð¸Ðµ ÑÐ¾ÐµÐ´Ð¸Ð½ÐµÐ½Ð¸Ñ (Ð½Ðµ 80/443/22/3306):"
  echo "$EXT_CONNS" | tee "$REPORT_DIR/external-connections.txt"
else
  log "âœ“ ÐÐµÑÑ‚Ð°Ð½Ð´Ð°Ñ€Ñ‚Ð½Ñ‹Ñ… Ð²Ð½ÐµÑˆÐ½Ð¸Ñ… ÑÐ¾ÐµÐ´Ð¸Ð½ÐµÐ½Ð¸Ð¹ Ð½ÐµÑ‚"
fi

# --- 4b. ÐŸÐ ÐžÐ’Ð•Ð ÐšÐ IPTABLES ---
log "=== 4b. ÐŸÐ ÐžÐ’Ð•Ð ÐšÐ IPTABLES ==="
IPTABLES_RULES=$(iptables -L INPUT -n --line-numbers 2>/dev/null)
echo "$IPTABLES_RULES" | tee "$REPORT_DIR/iptables-input.txt"

# ÐŸÑ€Ð¾Ð²ÐµÑ€ÑÐµÐ¼: SSH (Ð¿Ð¾Ñ€Ñ‚ 22) Ð½Ðµ Ð´Ð¾Ð»Ð¶ÐµÐ½ Ð±Ñ‹Ñ‚ÑŒ Ð¾Ñ‚ÐºÑ€Ñ‹Ñ‚ Ð´Ð»Ñ 0.0.0.0/0 ÐºÐ°Ðº SOURCE
# Ð˜ÑÐ¿Ð¾Ð»ÑŒÐ·ÑƒÐµÐ¼ awk Ñ‡Ñ‚Ð¾Ð±Ñ‹ Ð¿Ñ€Ð¾Ð²ÐµÑ€Ð¸Ñ‚ÑŒ Ð¸Ð¼ÐµÐ½Ð½Ð¾ ÐºÐ¾Ð»Ð¾Ð½ÐºÑƒ source (5), Ð° Ð½Ðµ destination
SSH_OPEN=$(iptables -L INPUT -n --line-numbers 2>/dev/null \
  | awk '$2=="ACCEPT" && $5=="0.0.0.0/0"' | grep 'dpt:22')
if [ -n "$SSH_OPEN" ]; then
  queue_alert "IPTABLES: SSH Ð¾Ñ‚ÐºÑ€Ñ‹Ñ‚ Ð´Ð»Ñ Ð²ÑÐµÐ³Ð¾ Ð¼Ð¸Ñ€Ð°!" "ÐŸÑ€Ð°Ð²Ð¸Ð»Ð¾ Ñ€Ð°Ð·Ñ€ÐµÑˆÐ°ÐµÑ‚ SSH Ñ 0.0.0.0/0 â€” ÑÐ»ÐµÐ´ÑƒÐµÑ‚ Ð¾Ð³Ñ€Ð°Ð½Ð¸Ñ‡Ð¸Ñ‚ÑŒ Ð¿Ð¾ IP:\n$SSH_OPEN"
else
  log "âœ“ SSH Ð¾Ð³Ñ€Ð°Ð½Ð¸Ñ‡ÐµÐ½ Ð¿Ð¾ IP (0.0.0.0/0 Ð½Ðµ Ñ€Ð°Ð·Ñ€ÐµÑˆÑ‘Ð½ ÐºÐ°Ðº source)"
fi

# ÐŸÑ€Ð¾Ð²ÐµÑ€ÑÐµÐ¼: Ð¿Ð¾Ð»Ð¸Ñ‚Ð¸ÐºÐ° INPUT
INPUT_POLICY=$(echo "$IPTABLES_RULES" | grep 'Chain INPUT' | grep -o 'policy [A-Z]*')
if echo "$INPUT_POLICY" | grep -q 'DROP\|REJECT'; then
  log "âœ“ ÐŸÐ¾Ð»Ð¸Ñ‚Ð¸ÐºÐ° INPUT: $INPUT_POLICY (Ð±ÐµÐ·Ð¾Ð¿Ð°ÑÐ½Ð¾)"
else
  queue_alert "IPTABLES: Ð¿Ð¾Ð»Ð¸Ñ‚Ð¸ÐºÐ° INPUT=$INPUT_POLICY" "Ð ÐµÐºÐ¾Ð¼ÐµÐ½Ð´ÑƒÐµÑ‚ÑÑ policy DROP. Ð¢ÐµÐºÑƒÑ‰Ð°Ñ Ð¿Ð¾Ð»Ð¸Ñ‚Ð¸ÐºÐ°: $INPUT_POLICY"
fi

# ÐŸÑ€Ð¾Ð²ÐµÑ€ÑÐµÐ¼: MySQL/MariaDB Ð½Ðµ Ð¾Ñ‚ÐºÑ€Ñ‹Ñ‚ Ð½Ð°Ñ€ÑƒÐ¶Ñƒ (source 0.0.0.0/0)
MYSQL_OPEN=$(iptables -L INPUT -n --line-numbers 2>/dev/null \
  | awk '$2=="ACCEPT" && $5=="0.0.0.0/0"' | grep 'dpt:3306')
if [ -n "$MYSQL_OPEN" ]; then
  queue_alert "IPTABLES: MySQL Ð¾Ñ‚ÐºÑ€Ñ‹Ñ‚ Ð´Ð»Ñ Ð²ÑÐµÐ³Ð¾ Ð¼Ð¸Ñ€Ð°!" "ÐŸÑ€Ð°Ð²Ð¸Ð»Ð¾ Ñ€Ð°Ð·Ñ€ÐµÑˆÐ°ÐµÑ‚ Ð¿Ð¾Ð´ÐºÐ»ÑŽÑ‡ÐµÐ½Ð¸Ðµ Ðº MySQL Ñ 0.0.0.0/0:\n$MYSQL_OPEN"
else
  log "âœ“ MySQL Ð½Ðµ Ð´Ð¾ÑÑ‚ÑƒÐ¿ÐµÐ½ Ð¸Ð·Ð²Ð½Ðµ"
fi

# ÐŸÑ€Ð¾Ð²ÐµÑ€ÑÐµÐ¼: ÐµÑÑ‚ÑŒ Ð»Ð¸ fail2ban Ñ†ÐµÐ¿Ð¾Ñ‡ÐºÐ¸
if iptables -L f2b-sshd -n &>/dev/null; then
  log "âœ“ fail2ban Ð°ÐºÑ‚Ð¸Ð²ÐµÐ½ (Ñ†ÐµÐ¿Ð¾Ñ‡ÐºÐ° f2b-sshd Ð½Ð°Ð¹Ð´ÐµÐ½Ð°)"
else
  queue_alert "fail2ban Ð½Ðµ Ð°ÐºÑ‚Ð¸Ð²ÐµÐ½" "Ð¦ÐµÐ¿Ð¾Ñ‡ÐºÐ° f2b-sshd Ð½Ðµ Ð½Ð°Ð¹Ð´ÐµÐ½Ð° Ð² iptables â€” Ð²Ð¾Ð·Ð¼Ð¾Ð¶Ð½Ð¾ fail2ban Ð½Ðµ Ð·Ð°Ð¿ÑƒÑ‰ÐµÐ½"
fi

# --- 5. CRON-Ð—ÐÐ”ÐÐ§Ð˜ Ð’Ð¡Ð•Ð¥ ÐŸÐžÐ›Ð¬Ð—ÐžÐ’ÐÐ¢Ð•Ð›Ð•Ð™ ---
log "=== 5. CRON-Ð—ÐÐ”ÐÐ§Ð˜ ==="
echo "System cron:"
ls -la /etc/cron* 2>/dev/null
cat /etc/crontab 2>/dev/null

for user in "${USERS[@]}" root www-data; do
  CRON=$(crontab -u "$user" -l 2>/dev/null)
  if [ -n "$CRON" ]; then
    echo "$CRON" | tee -a "$REPORT_DIR/crontabs.txt"
    # Strip comment lines and blank lines, then check what's left
    CRON_REAL=$(echo "$CRON" | grep -v '^\s*#' | grep -v '^\s*$' | \
      grep -v 'MAILTO=' | grep -v 'CONTENT_TYPE=')
    # Skip alert if all real cron entries are safe known-patterns:
    #   artisan schedule:run  â€” standard Laravel scheduler
    #   security-audit        â€” our own audit script
    #   hestiaweb/hestia      â€” HestiaCP system tasks
    CRON_SUSPICIOUS=$(echo "$CRON_REAL" | grep -v 'artisan schedule:run' | \
      grep -v 'server-security\|security-audit' | grep -v 'hestia')
    if [ -n "$CRON_SUSPICIOUS" ]; then
      queue_alert "Cron Ð¿Ð¾Ð»ÑŒÐ·Ð¾Ð²Ð°Ñ‚ÐµÐ»Ñ $user" "$CRON"
    fi
  fi
done

echo "Cron Ð² /var/spool/cron:"
ls -la /var/spool/cron/crontabs/ 2>/dev/null

# --- 6. ÐŸÐžÐ˜Ð¡Ðš ÐœÐžÐ”Ð˜Ð¤Ð˜Ð¦Ð˜Ð ÐžÐ’ÐÐÐÐ«Ð¥ Ð¤ÐÐ™Ð›ÐžÐ’ (Ð¿Ð¾ÑÐ»ÐµÐ´Ð½Ð¸Ðµ 14 Ð´Ð½ÐµÐ¹) ---
log "=== 6. Ð¤ÐÐ™Ð›Ð« Ð˜Ð—ÐœÐ•ÐÐÐÐÐ«Ð• Ð—Ð 14 Ð”ÐÐ•Ð™ ==="
# Ð˜ÑÐºÐ»ÑŽÑ‡Ð°ÐµÐ¼ Ð±ÐµÐ·Ð¾Ð¿Ð°ÑÐ½Ñ‹Ðµ ÑˆÑƒÐ¼Ð½Ñ‹Ðµ Ð¿ÑƒÑ‚Ð¸:
#   storage/framework/views/  â€” ÑÐºÐ¾Ð¼Ð¿Ð¸Ð»Ð¸Ñ€Ð¾Ð²Ð°Ð½Ð½Ñ‹Ðµ Blade-ÑˆÐ°Ð±Ð»Ð¾Ð½Ñ‹
#   storage/framework/cache/  â€” Laravel bootstrap ÐºÑÑˆ
#   document_errors/          â€” ÑÑ‚Ñ€Ð°Ð½Ð¸Ñ†Ñ‹ Ð¾ÑˆÐ¸Ð±Ð¾Ðº HestiaCP (Ð¼ÐµÐ½ÑÑŽÑ‚ÑÑ Ð¿Ñ€Ð¸ hardening)
#   public/js/filament/       â€” Filament JS Ð°ÑÑÐµÑ‚Ñ‹ (npm build output)
#   public/css/filament/      â€” Filament CSS Ð°ÑÑÐµÑ‚Ñ‹
#   public/build/             â€” Vite build output
#   node_modules/vendor/      â€” Ð·Ð°Ð²Ð¸ÑÐ¸Ð¼Ð¾ÑÑ‚Ð¸
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    MODIFIED=$(find "$WEB_DIR" -type f \( -name "*.php" -o -name "*.js" -o -name "*.html" -o -name "*.htaccess" \) \
      -newer /etc/passwd -mtime -14 \
      ! -path "*/vendor/*" \
      ! -path "*/.git/*" \
      ! -path "*/node_modules/*" \
      ! -path "*/storage/framework/views/*" \
      ! -path "*/storage/framework/cache/*" \
      ! -path "*/document_errors/*" \
      ! -path "*/public/js/filament/*" \
      ! -path "*/public/css/filament/*" \
      ! -path "*/public/build/*" \
      ! -path "*/bootstrap/cache/*" \
      -printf "%TY-%Tm-%Td %TH:%TM  %p\n" 2>/dev/null \
      | sort -r | head -50)
    if [ -n "$MODIFIED" ]; then
      warn "Ð˜Ð·Ð¼ÐµÐ½Ñ‘Ð½Ð½Ñ‹Ðµ PHP/JS Ñ„Ð°Ð¹Ð»Ñ‹ Ñƒ Ð¿Ð¾Ð»ÑŒÐ·Ð¾Ð²Ð°Ñ‚ÐµÐ»Ñ $user:"
      echo "$MODIFIED" | tee -a "$REPORT_DIR/modified-files-$user.txt"
    fi
  fi
done

# --- 7. ÐŸÐžÐ˜Ð¡Ðš Ð’Ð•Ð‘-Ð¨Ð•Ð›Ð›ÐžÐ’ Ð˜ Ð‘Ð­ÐšÐ”ÐžÐ ÐžÐ’ ---
log "=== 7. ÐŸÐžÐ˜Ð¡Ðš Ð’Ð•Ð‘-Ð¨Ð•Ð›Ð›ÐžÐ’ Ð˜ Ð‘Ð­ÐšÐ”ÐžÐ ÐžÐ’ ==="
# Ð’ÐÐ–ÐÐž: vendor/, node_modules/ Ð¸ÑÐºÐ»ÑŽÑ‡ÐµÐ½Ñ‹ Ð¸Ð· Ð¿Ð¾Ð¸ÑÐºÐ° â€” Ñ‚Ð°Ð¼ Ð»ÐµÐ³Ð¸Ñ‚Ð¸Ð¼Ð½Ñ‹Ð¹ ÐºÐ¾Ð´.
# Ð˜Ñ‰ÐµÐ¼ Ñ‚Ð¾Ð»ÑŒÐºÐ¾ Ð² public_html ÐºÐ¾Ñ€Ð½Ðµ, public/, storage/, Ð¸ Ð¿Ñ€Ð¾Ñ‡Ð¸Ñ… Ð½Ðµ-vendor Ð¿ÑƒÑ‚ÑÑ….

# ÐŸÐ°Ñ‚Ñ‚ÐµÑ€Ð½Ñ‹ Ð´Ð»Ñ PHP Ñ„Ð°Ð¹Ð»Ð¾Ð² (Ð¸ÑÐºÐ»ÑŽÑ‡Ð°Ñ vendor/ Ð¸ node_modules/)
PHP_WEBSHELL_PATTERNS=(
  'eval(base64_decode'
  'eval(gzinflate'
  'eval(str_rot13'
  'eval(gzuncompress'
  'eval(\$_'
  'assert(\$_'
  'system(\$_'
  'exec(\$_'
  'passthru(\$_'
  'shell_exec(\$_'
  '\$_POST\[.*\].*eval'
  'base64_decode.*eval'
  'FilesMan'
  'WSO\b'
  'c99shell'
  'r57shell'
  'phpspy'
  'preg_replace.*\/e'
  'create_function.*eval'
  '@eval('
  'assert(base64_decode'
  'gzinflate(base64_decode'
  'str_rot13(base64_decode'
  'move_uploaded_file.*\.php'
  '\$_FILES.*eval'
  'ReflectionFunction'
  'pcntl_exec'
)

# ÐŸÐ¾Ð´Ð¾Ð·Ñ€Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ñ‹Ðµ Ð¸Ð¼ÐµÐ½Ð° Ñ„Ð°Ð¹Ð»Ð¾Ð²-ÑˆÐµÐ»Ð»Ð¾Ð² (Ð¸Ñ‰ÐµÐ¼ Ð²ÐµÐ·Ð´Ðµ Ð²ÐºÐ»ÑŽÑ‡Ð°Ñ vendor/)
# Ð¢Ð¾Ð»ÑŒÐºÐ¾ ÑƒÐ½Ð¸ÐºÐ°Ð»ÑŒÐ½Ñ‹Ðµ Ð¸Ð¼ÐµÐ½Ð°, ÑÐ²Ð½Ð¾ Ð½Ðµ Ð²ÑÑ‚Ñ€ÐµÑ‡Ð°ÑŽÑ‰Ð¸ÐµÑÑ Ð² Ð»ÐµÐ³Ð¸Ñ‚Ð¸Ð¼Ð½Ð¾Ð¼ ÐºÐ¾Ð´Ðµ
SHELL_FILENAMES=(
  # Known webshell names
  'c99.php' 'r57.php' 'b374k.php' 'wso.php' 'alfa.php' 'alfacgiapi.php'
  'FilesMan.php' 'indoxploit.php' 'symlink.php' 'cpanel.php'
  'adminfuns.php' 'wp-conffq.php' 'wp-headre.php' 'shc.php'
  # Specific shells found in this incident
  'kozlakola.php' 'b-1.php'
)

# ÐšÐ¾Ñ€Ð¾Ñ‚ÐºÐ¸Ðµ Ð¸Ð¼ÐµÐ½Ð° â€” Ð¿Ð¾Ð´Ð¾Ð·Ñ€Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ñ‹ Ð²Ð½Ðµ vendor/node_modules/storage/framework
SHELL_FILENAMES_SHORT=(
  'b.php' 'c.php' 'x.php' 'z.php' 'a.php' 'k.php'
)

for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  FOUND_FILE="$REPORT_DIR/webshells-$user.txt"
  if [ -d "$WEB_DIR" ]; then
    echo "" > "$FOUND_FILE"

    # 1. ÐŸÐ¾Ð¸ÑÐº Ð²Ñ€ÐµÐ´Ð¾Ð½Ð¾ÑÐ½Ñ‹Ñ… Ð¿Ð°Ñ‚Ñ‚ÐµÑ€Ð½Ð¾Ð² Ð² PHP Ñ„Ð°Ð¹Ð»Ð°Ñ…, Ð¸ÑÐºÐ»ÑŽÑ‡Ð°Ñ vendor/ Ð¸ node_modules/
    for pattern in "${PHP_WEBSHELL_PATTERNS[@]}"; do
      RESULTS=$(grep -rl \
        --include='*.php' --include='*.php5' --include='*.php7' --include='*.phtml' --include='*.phar' \
        --exclude-dir='.git' --exclude-dir='vendor' --exclude-dir='node_modules' \
        "$pattern" "$WEB_DIR" 2>/dev/null)
      if [ -n "$RESULTS" ]; then
        DETAILS=""
        while IFS= read -r fpath; do
          FMETA=$(stat -c "  mtime=%y owner=%U size=%s" "$fpath" 2>/dev/null)
          FPREVIEW=$(grep -m1 "$pattern" "$fpath" 2>/dev/null | head -c 200)
          DETAILS+="FILE: $fpath\n$FMETA\n  Match: $FPREVIEW\n\n"
        done <<< "$RESULTS"
        queue_alert "Ð‘Ð­ÐšÐ”ÐžÐ  Ñƒ $user (Ð¿Ð°Ñ‚Ñ‚ÐµÑ€Ð½: $pattern)" "$DETAILS"
        echo "$RESULTS" | tee -a "$FOUND_FILE"
      fi
    done

    # 2. ÐŸÐ¾Ð¸ÑÐº Ð¿Ð¾ Ð¿Ð¾Ð´Ð¾Ð·Ñ€Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ñ‹Ð¼ Ð¸Ð¼ÐµÐ½Ð°Ð¼ Ñ„Ð°Ð¹Ð»Ð¾Ð² (Ð²ÐµÐ·Ð´Ðµ)
    for fname in "${SHELL_FILENAMES[@]}"; do
      RESULTS=$(find "$WEB_DIR" -name "$fname" 2>/dev/null | grep -v '/.git/')
      if [ -n "$RESULTS" ]; then
        queue_alert "ÐŸÐžÐ”ÐžÐ—Ð Ð˜Ð¢Ð•Ð›Ð¬ÐÐ«Ð™ Ð¤ÐÐ™Ð› Ñƒ $user ($fname)" "$RESULTS"
        echo "$RESULTS" | tee -a "$FOUND_FILE"
      fi
    done

    # 2b. ÐšÐ¾Ñ€Ð¾Ñ‚ÐºÐ¸Ðµ Ð¸Ð¼ÐµÐ½Ð° Ñ„Ð°Ð¹Ð»Ð¾Ð² â€” Ð¿Ð¾Ð´Ð¾Ð·Ñ€Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ñ‹ Ð²Ð½Ðµ vendor/node_modules/storage/framework
    for fname in "${SHELL_FILENAMES_SHORT[@]}"; do
      RESULTS=$(find "$WEB_DIR" -name "$fname" 2>/dev/null \
        | grep -v '/.git/' \
        | grep -v '/vendor/' \
        | grep -v '/node_modules/' \
        | grep -v '/storage/framework/')
      if [ -n "$RESULTS" ]; then
        queue_alert "ÐŸÐžÐ”ÐžÐ—Ð Ð˜Ð¢Ð•Ð›Ð¬ÐÐ«Ð™ Ð¤ÐÐ™Ð› (ÐºÐ¾Ñ€Ð¾Ñ‚ÐºÐ¾Ðµ Ð¸Ð¼Ñ) Ñƒ $user ($fname)" "$RESULTS"
        echo "$RESULTS" | tee -a "$FOUND_FILE"
      fi
    done

    # 3. PHP-Ñ„Ð°Ð¹Ð»Ñ‹ Ñ hex-Ð¸Ð¼ÐµÐ½Ð°Ð¼Ð¸ (8+ hex ÑÐ¸Ð¼Ð²Ð¾Ð»Ð¾Ð²) â€” Ñ…Ð°Ñ€Ð°ÐºÑ‚ÐµÑ€Ð½Ð¾ Ð´Ð»Ñ Ð´Ñ€Ð¾Ð¿Ð¿ÐµÑ€Ð¾Ð²
    # Ð˜ÑÐºÐ»ÑŽÑ‡Ð°ÐµÐ¼ storage/framework/views/ â€” Ñ‚Ð°Ð¼ Ð»ÐµÐ³Ð¸Ñ‚Ð¸Ð¼Ð½Ñ‹Ðµ ÑÐºÐ¾Ð¼Ð¿Ð¸Ð»Ð¸Ñ€Ð¾Ð²Ð°Ð½Ð½Ñ‹Ðµ Blade-ÑˆÐ°Ð±Ð»Ð¾Ð½Ñ‹ Laravel
    RESULTS=$(find "$WEB_DIR" -type f -name "*.php" 2>/dev/null \
      | grep -E '/[0-9a-f]{8,}\.php$' \
      | grep -v '/.git/' \
      | grep -v '/storage/framework/views/' \
      | grep -v '/vendor/')
    if [ -n "$RESULTS" ]; then
      queue_alert "PHP Ð”Ð ÐžÐŸÐŸÐ•Ð  (hex-Ð¸Ð¼Ñ) Ñƒ $user" "$RESULTS"
      echo "$RESULTS" | tee -a "$FOUND_FILE"
    fi

    # 4. cache.php Ð¢ÐžÐ›Ð¬ÐšÐž Ð² Ð¿Ð¾Ð´Ð¾Ð·Ñ€Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ñ‹Ñ… Ð¼ÐµÑÑ‚Ð°Ñ… (Ð½Ðµ Ð² /config/, /wp-includes/, /themes/)
    # Ð›ÐµÐ³Ð¸Ñ‚Ð¸Ð¼Ð½Ñ‹Ðµ Ð¼ÐµÑÑ‚Ð°: /config/cache.php (Laravel), /wp-includes/cache.php (WP core),
    #   /wp-content/themes/*/cache.php (Ñ‚ÐµÐ¼Ñ‹)
    # ÐŸÐ¾Ð´Ð¾Ð·Ñ€Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ñ‹Ðµ: /public/, /storage/, /upload/, /assets/, /build/, /tmp/
    RESULTS=$(find "$WEB_DIR" -name "cache.php" 2>/dev/null \
      | grep -v '/vendor/' \
      | grep -v '/node_modules/' \
      | grep -v '/.git/' \
      | grep -v '/config/cache\.php' \
      | grep -v '/wp-includes/' \
      | grep -v '/wp-content/themes/' \
      | grep -E '/(public|storage|upload|assets|build|tmp|cache|files)/')
    if [ -n "$RESULTS" ]; then
      queue_alert "WEBSHELL cache.php Ñƒ $user" "$RESULTS"
      echo "$RESULTS" | tee -a "$FOUND_FILE"
    fi
  fi
done

# 5. Ð¡Ð¿ÐµÑ†Ð¸Ñ„Ð¸Ñ‡Ð½Ð¾: cron Ñ .X11-linux (Ð¼Ð°Ð¹Ð½ÐµÑ€/Ð±ÑÐºÐ´Ð¾Ñ€)
for user in "${USERS[@]}"; do
  CRON_XLINUX=$(crontab -u "$user" -l 2>/dev/null | grep '\.X11-linux')
  if [ -n "$CRON_XLINUX" ]; then
    queue_alert "ÐœÐÐ™ÐÐ•Ð  Ð’ CRON Ñƒ $user (.X11-linux)" "$CRON_XLINUX"
  fi
done

# --- 7b. ÐÐ£Ð›Ð•Ð’ÐÐ¯ Ð¢Ð•Ð ÐŸÐ˜ÐœÐžÐ¡Ð¢Ð¬: PHP Ð’ Ð”Ð˜Ð Ð•ÐšÐ¢ÐžÐ Ð˜Ð¯Ð¥ Ð—ÐÐ“Ð Ð£Ð—ÐšÐ˜ ---
log "=== 7b. PHP-Ð¤ÐÐ™Ð›Ð« Ð’ Ð”Ð˜Ð Ð•ÐšÐ¢ÐžÐ Ð˜Ð¯Ð¥ Ð—ÐÐ“Ð Ð£Ð—ÐšÐ˜ (Ð½ÑƒÐ»ÐµÐ²Ð°Ñ Ñ‚ÐµÑ€Ð¿Ð¸Ð¼Ð¾ÑÑ‚ÑŒ) ==="
# ÐŸÐ ÐÐ’Ð˜Ð›Ðž: PHP-Ñ„Ð°Ð¹Ð»Ñ‹ Ð² ÑÑ‚Ð¸Ñ… Ð´Ð¸Ñ€ÐµÐºÑ‚Ð¾Ñ€Ð¸ÑÑ… Ð’Ð¡Ð•Ð“Ð”Ð ÑÐ²Ð»ÑÑŽÑ‚ÑÑ Ð²Ñ€ÐµÐ´Ð¾Ð½Ð¾ÑÐ½Ñ‹Ð¼Ð¸.
# Ð›ÐµÐ³Ð¸Ñ‚Ð¸Ð¼Ð½Ñ‹Ð¹ ÐºÐ¾Ð´ Ð½Ð¸ÐºÐ¾Ð³Ð´Ð° Ð½Ðµ Ñ€Ð°Ð·Ð¼ÐµÑ‰Ð°ÐµÑ‚ .php Ñ„Ð°Ð¹Ð»Ñ‹ Ð² upload-Ð´Ð¸Ñ€ÐµÐºÑ‚Ð¾Ñ€Ð¸ÑÑ….
# ÐŸÑ€Ð¾Ð²ÐµÑ€ÑÐµÐ¼ Ð’Ð¡Ð• Ñ„Ð°Ð¹Ð»Ñ‹ Ð½ÐµÐ·Ð°Ð²Ð¸ÑÐ¸Ð¼Ð¾ Ð¾Ñ‚ Ð´Ð°Ñ‚Ñ‹ Ð¸Ð·Ð¼ÐµÐ½ÐµÐ½Ð¸Ñ.

UPLOAD_PATH_PATTERNS=(
  '*/storage/app/public/*'
  '*/storage/app/livewire-tmp/*'
  '*/wp-content/uploads/*'
  '*/wp-content/cache/*'
  '*/public/storage/*'
)

for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ ! -d "$WEB_DIR" ]; then continue; fi

  UPLOAD_FOUND_FILE="$REPORT_DIR/upload-php-$user.txt"
  echo "" > "$UPLOAD_FOUND_FILE"

  for path_pattern in "${UPLOAD_PATH_PATTERNS[@]}"; do
    FOUND=$(find "$WEB_DIR" -type f \
      \( -name "*.php" -o -name "*.php5" -o -name "*.phtml" -o -name "*.phar" \) \
      -path "$path_pattern" 2>/dev/null)

    if [ -n "$FOUND" ]; then
      DETAILS="Pattern: $path_pattern\n"
      while IFS= read -r fpath; do
        FMETA=$(stat -c "  mtime=%y owner=%U size=%s" "$fpath" 2>/dev/null)
        FPREVIEW=$(head -c 300 "$fpath" 2>/dev/null | strings | head -5 | tr '\n' ' ')
        DETAILS+="FILE: $fpath\n$FMETA\n  Preview: $FPREVIEW\n\n"
        echo "$fpath" >> "$UPLOAD_FOUND_FILE"
      done <<< "$FOUND"
      queue_alert "âš  PHP Ð’ UPLOAD-Ð”Ð˜Ð Ð•ÐšÐ¢ÐžÐ Ð˜Ð˜ Ñƒ $user" "$DETAILS"
    fi
  done
done
log "âœ“ Ð¡ÐºÐ°Ð½Ð¸Ñ€Ð¾Ð²Ð°Ð½Ð¸Ðµ upload-Ð´Ð¸Ñ€ÐµÐºÑ‚Ð¾Ñ€Ð¸Ð¹ Ð·Ð°Ð²ÐµÑ€ÑˆÐµÐ½Ð¾"

# --- 8. Ð¤ÐÐ™Ð›Ð« Ð¡ ÐžÐŸÐÐ¡ÐÐ«ÐœÐ˜ ÐŸÐ ÐÐ’ÐÐœÐ˜ ---
log "=== 8. Ð¤ÐÐ™Ð›Ð« Ð¡ 777/SUID ÐŸÐ ÐÐ’ÐÐœÐ˜ ==="
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    FILES_777=$(find "$WEB_DIR" -perm -0777 -type f 2>/dev/null | head -20)
    DIRS_777=$(find "$WEB_DIR" -perm -0777 -type d 2>/dev/null | head -20)
    if [ -n "$FILES_777" ]; then
      warn "777 Ñ„Ð°Ð¹Ð»Ñ‹ Ñƒ $user:"
      echo "$FILES_777" | tee -a "$REPORT_DIR/perms-$user.txt"
      queue_alert "777 Ñ„Ð°Ð¹Ð»Ñ‹ Ñƒ $user" "$FILES_777"
    fi
    if [ -n "$DIRS_777" ]; then
      warn "777 Ð´Ð¸Ñ€ÐµÐºÑ‚Ð¾Ñ€Ð¸Ð¸ Ñƒ $user:"
      echo "$DIRS_777" | tee -a "$REPORT_DIR/perms-$user.txt"
      queue_alert "777 Ð´Ð¸Ñ€ÐµÐºÑ‚Ð¾Ñ€Ð¸Ð¸ Ñƒ $user" "$DIRS_777"
    fi
  fi
done

# SUID Ð²Ð¾ Ð²ÑÐµÐ¹ ÑÐ¸ÑÑ‚ÐµÐ¼Ðµ â€” Ð°Ð»ÐµÑ€Ñ‚Ð¸Ð¼ Ñ‚Ð¾Ð»ÑŒÐºÐ¾ Ð½Ð° Ð½ÐµÑÑ‚Ð°Ð½Ð´Ð°Ñ€Ñ‚Ð½Ñ‹Ðµ Ñ„Ð°Ð¹Ð»Ñ‹
# Ð¡Ñ‚Ð°Ð½Ð´Ð°Ñ€Ñ‚Ð½Ñ‹Ðµ ÑÐ¸ÑÑ‚ÐµÐ¼Ð½Ñ‹Ðµ SUID Ð¿ÑƒÑ‚Ð¸ Ð¸ÑÐºÐ»ÑŽÑ‡Ð°ÐµÐ¼
SUID_STANDARD='/usr/bin|/usr/sbin|/bin|/sbin|/usr/lib/openssh|/usr/lib/dbus|/usr/libexec/polkit|/usr/lib/mysql/plugin/auth_pam'
SUID_SUSPICIOUS=$(find / -perm /4000 -type f 2>/dev/null \
  | grep -vE "$SUID_STANDARD")
find / -perm /4000 -type f 2>/dev/null > "$REPORT_DIR/suid-files.txt"
if [ -n "$SUID_SUSPICIOUS" ]; then
  warn "ÐÐ•Ð¡Ð¢ÐÐÐ”ÐÐ Ð¢ÐÐ«Ð• SUID Ñ„Ð°Ð¹Ð»Ñ‹ (Ñ‚Ñ€ÐµÐ±ÑƒÑŽÑ‚ Ð¿Ñ€Ð¾Ð²ÐµÑ€ÐºÐ¸):"
  echo "$SUID_SUSPICIOUS" | tee -a "$REPORT_DIR/suid-files.txt"
  queue_alert "ÐÐµÑÑ‚Ð°Ð½Ð´Ð°Ñ€Ñ‚Ð½Ñ‹Ðµ SUID Ñ„Ð°Ð¹Ð»Ñ‹" "$SUID_SUSPICIOUS"
else
  log "âœ“ SUID Ñ„Ð°Ð¹Ð»Ñ‹ â€” Ñ‚Ð¾Ð»ÑŒÐºÐ¾ ÑÑ‚Ð°Ð½Ð´Ð°Ñ€Ñ‚Ð½Ñ‹Ðµ ÑÐ¸ÑÑ‚ÐµÐ¼Ð½Ñ‹Ðµ"
fi

# --- 9. Ð›ÐžÐ“Ð˜ WEB-Ð¡Ð•Ð Ð’Ð•Ð Ð â€” Ð¸Ñ‰ÐµÐ¼ Ð¿Ð¾Ð´Ð¾Ð·Ñ€Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ñ‹Ðµ Ð·Ð°Ð¿Ñ€Ð¾ÑÑ‹ ---
log "=== 9. ÐŸÐžÐ”ÐžÐ—Ð Ð˜Ð¢Ð•Ð›Ð¬ÐÐ«Ð• Ð—ÐÐŸÐ ÐžÐ¡Ð« Ð’ NGINX/APACHE Ð›ÐžÐ“ÐÐ¥ ==="
SUSPICIOUS_PATTERNS="(eval|base64_decode|system\(|passthru|shell_exec|union.*select|\.\.\/|etc\/passwd|cmd=|exec=|wget |curl |chmod |/tmp/|/dev/shm)"

for user in "${USERS[@]}"; do
  for logfile in /home/$user/web/*/log/access.log /home/$user/web/*/log/error.log; do
    if [ -f "$logfile" ]; then
      HITS=$(grep -iE "$SUSPICIOUS_PATTERNS" "$logfile" 2>/dev/null | wc -l)
      if [ "$HITS" -gt 0 ]; then
        HITS_SAMPLE=$(grep -iE "$SUSPICIOUS_PATTERNS" "$logfile" 2>/dev/null | tail -20)
        queue_alert "ÐŸÐ¾Ð´Ð¾Ð·Ñ€Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ñ‹Ðµ Ð·Ð°Ð¿Ñ€Ð¾ÑÑ‹ Ð² $logfile ($HITS ÑˆÑ‚ÑƒÐº)" "$HITS_SAMPLE"
        echo "$HITS_SAMPLE" | tee -a "$REPORT_DIR/suspicious-requests-$user.txt"
      fi
    fi
  done
done

# --- 10. PHP ÐšÐžÐÐ¤Ð˜Ð“Ð£Ð ÐÐ¦Ð˜Ð¯ ---
log "=== 10. PHP ÐšÐžÐÐ¤Ð˜Ð“Ð£Ð ÐÐ¦Ð˜Ð¯ ==="
php -i 2>/dev/null | grep -E "(disable_functions|open_basedir|allow_url_fopen|allow_url_include|expose_php|upload_tmp_dir)" \
  | tee "$REPORT_DIR/php-config.txt"

# ÐŸÑ€Ð¾Ð²ÐµÑ€ÐºÐ° PHP-FPM Ð¿ÑƒÐ»Ð¾Ð² â€” Ð°Ð»ÐµÑ€Ñ‚Ð¸Ð¼ Ñ‚Ð¾Ð»ÑŒÐºÐ¾ Ð½Ð° Ð¿ÑƒÐ»Ñ‹ Ð‘Ð•Ð— open_basedir
POOLS_NO_BASEDIR=$(grep -rL "open_basedir" /etc/php/*/fpm/pool.d/*.conf 2>/dev/null \
  | grep -v dummy.conf | grep -v '/www.conf')  # www.conf â€” HestiaCP internal (hestiamail)
if [ -n "$POOLS_NO_BASEDIR" ]; then
  warn "PHP-FPM Ð¿ÑƒÐ»Ñ‹ Ð‘Ð•Ð— open_basedir (Ñ€Ð¸ÑÐº Ð²Ñ‹Ñ…Ð¾Ð´Ð° Ð·Ð° Ð¿Ñ€ÐµÐ´ÐµÐ»Ñ‹ Ð´Ð¾Ð¼Ð°ÑˆÐ½ÐµÐ¹ Ð´Ð¸Ñ€ÐµÐºÑ‚Ð¾Ñ€Ð¸Ð¸):"
  echo "$POOLS_NO_BASEDIR" | tee -a "$REPORT_DIR/php-fpm-pools.txt"
  queue_alert "PHP-FPM Ð¿ÑƒÐ»Ñ‹ Ð±ÐµÐ· open_basedir" "$POOLS_NO_BASEDIR"
else
  log "âœ“ Ð’ÑÐµ PHP-FPM Ð¿ÑƒÐ»Ñ‹ Ð¸Ð¼ÐµÑŽÑ‚ open_basedir"
fi

# --- 11. ÐŸÐ ÐžÐ’Ð•Ð ÐšÐ .htaccess Ð˜ .user.ini ÐÐ Ð˜ÐÐªÐ•ÐšÐ¦Ð˜Ð˜ ---
log "=== 11. ÐŸÐ ÐžÐ’Ð•Ð ÐšÐ .htaccess Ð˜ .user.ini ==="
# Ð˜Ñ‰ÐµÐ¼ Ñ‚Ð¾Ð»ÑŒÐºÐ¾ Ð¿Ð¾Ð´Ð¾Ð·Ñ€Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ñ‹Ðµ Ð¿Ð°Ñ‚Ñ‚ÐµÑ€Ð½Ñ‹, Ð° Ð½Ðµ Ð´Ð°Ð¼Ð¿Ð¸Ð¼ Ð²ÐµÑÑŒ ÐºÐ¾Ð½Ñ‚ÐµÐ½Ñ‚
HTACCESS_BAD_PATTERNS='php_value auto_prepend|SetHandler.*cgi|AddHandler.*php|RewriteRule.*eval|base64_decode|system\(|shell_exec'
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    # Ð¡Ð¾Ñ…Ñ€Ð°Ð½ÑÐµÐ¼ Ð²ÑÐµ htaccess Ð² Ð¾Ñ‚Ñ‡Ñ‘Ñ‚ Ñ‚Ð¸Ñ…Ð¾
    find "$WEB_DIR" -name ".htaccess" -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null \
      >> "$REPORT_DIR/htaccess-$user.txt"
    # ÐÐ»ÐµÑ€Ñ‚Ð¸Ð¼ Ñ‚Ð¾Ð»ÑŒÐºÐ¾ Ð½Ð° Ð¿Ð¾Ð´Ð¾Ð·Ñ€Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ñ‹Ðµ Ð¿Ð°Ñ‚Ñ‚ÐµÑ€Ð½Ñ‹
    HTACCESS_SUSPICIOUS=$(grep -rniE "$HTACCESS_BAD_PATTERNS" \
      $(find "$WEB_DIR" -name ".htaccess" 2>/dev/null) 2>/dev/null)
    if [ -n "$HTACCESS_SUSPICIOUS" ]; then
      warn "ÐŸÐ¾Ð´Ð¾Ð·Ñ€Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ñ‹Ðµ .htaccess Ñƒ $user:"
      echo "$HTACCESS_SUSPICIOUS" | tee -a "$REPORT_DIR/htaccess-$user.txt"
      queue_alert ".htaccess Ð¸Ð½ÑŠÐµÐºÑ†Ð¸Ñ Ñƒ $user" "$HTACCESS_SUSPICIOUS"
    fi
    # .user.ini â€” ÑÐ¾Ñ…Ñ€Ð°Ð½ÑÐµÐ¼ Ñ‚Ð¸Ñ…Ð¾, Ð°Ð»ÐµÑ€Ñ‚Ð¸Ð¼ Ñ‚Ð¾Ð»ÑŒÐºÐ¾ Ð½Ð° Ð¿Ð¾Ð´Ð¾Ð·Ñ€Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ñ‹Ðµ Ð·Ð°Ð¿Ð¸ÑÐ¸
    find "$WEB_DIR" -name ".user.ini" -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null \
      >> "$REPORT_DIR/user-ini-$user.txt"
    USERINI_SUSPICIOUS=$(grep -rniE "auto_prepend_file|auto_append_file|open_basedir\s*=\s*none" \
      $(find "$WEB_DIR" -name ".user.ini" 2>/dev/null) 2>/dev/null)
    if [ -n "$USERINI_SUSPICIOUS" ]; then
      warn "ÐŸÐ¾Ð´Ð¾Ð·Ñ€Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ñ‹Ðµ .user.ini Ñƒ $user:"
      echo "$USERINI_SUSPICIOUS" | tee -a "$REPORT_DIR/user-ini-$user.txt"
      queue_alert ".user.ini Ð¸Ð½ÑŠÐµÐºÑ†Ð¸Ñ Ñƒ $user" "$USERINI_SUSPICIOUS"
    fi
  fi
done

# --- 12. ÐŸÐ ÐžÐ’Ð•Ð ÐšÐ /tmp Ð˜ /dev/shm ÐÐ ÐŸÐžÐ”ÐžÐ—Ð Ð˜Ð¢Ð•Ð›Ð¬ÐÐ«Ð• Ð¤ÐÐ™Ð›Ð« ---
log "=== 12. /tmp Ð˜ /dev/shm ==="
# Ð¡Ð¾Ñ…Ñ€Ð°Ð½ÑÐµÐ¼ Ð»Ð¸ÑÑ‚Ð¸Ð½Ð³ Ð² Ð¾Ñ‚Ñ‡Ñ‘Ñ‚ Ñ‚Ð¸Ñ…Ð¾
ls -la /tmp/ > "$REPORT_DIR/tmp-files.txt" 2>/dev/null
ls -la /dev/shm/ >> "$REPORT_DIR/tmp-files.txt" 2>/dev/null
# ÐÐ»ÐµÑ€Ñ‚Ð¸Ð¼ Ñ‚Ð¾Ð»ÑŒÐºÐ¾ Ð½Ð° Ð¸ÑÐ¿Ð¾Ð»Ð½ÑÐµÐ¼Ñ‹Ðµ Ñ„Ð°Ð¹Ð»Ñ‹ â€” Ñ€ÐµÐ°Ð»ÑŒÐ½Ð°Ñ ÑƒÐ³Ñ€Ð¾Ð·Ð°
TMP_EXEC=$(find /tmp /dev/shm -type f -executable 2>/dev/null)
if [ -n "$TMP_EXEC" ]; then
  warn "Ð˜ÑÐ¿Ð¾Ð»Ð½ÑÐµÐ¼Ñ‹Ðµ Ñ„Ð°Ð¹Ð»Ñ‹ Ð² /tmp Ð¸Ð»Ð¸ /dev/shm:"
  echo "$TMP_EXEC" | tee "$REPORT_DIR/tmp-executables.txt"
  queue_alert "Ð˜ÑÐ¿Ð¾Ð»Ð½ÑÐµÐ¼Ñ‹Ðµ Ñ„Ð°Ð¹Ð»Ñ‹ Ð² /tmp" "$TMP_EXEC"
else
  log "âœ“ ÐÐµÑ‚ Ð¸ÑÐ¿Ð¾Ð»Ð½ÑÐµÐ¼Ñ‹Ñ… Ñ„Ð°Ð¹Ð»Ð¾Ð² Ð² /tmp Ð¸ /dev/shm"
fi

# --- 13. SSH ÐšÐ›Ð®Ð§Ð˜ Ð’Ð¡Ð•Ð¥ ÐŸÐžÐ›Ð¬Ð—ÐžÐ’ÐÐ¢Ð•Ð›Ð•Ð™ ---
log "=== 13. SSH ÐšÐ›Ð®Ð§Ð˜ ==="
for user in "${USERS[@]}" root; do
  HOME_DIR=$(eval echo "~$user")
  AUTH_KEYS="$HOME_DIR/.ssh/authorized_keys"
  if [ -f "$AUTH_KEYS" ]; then
    # Ð¡Ð¾Ñ…Ñ€Ð°Ð½ÑÐµÐ¼ Ð²ÑÐµ ÐºÐ»ÑŽÑ‡Ð¸ Ð² Ð¾Ñ‚Ñ‡Ñ‘Ñ‚ Ñ‚Ð¸Ñ…Ð¾
    echo "=== $user ==" >> "$REPORT_DIR/ssh-keys.txt"
    cat "$AUTH_KEYS" >> "$REPORT_DIR/ssh-keys.txt"
    # ÐÐ»ÐµÑ€Ñ‚Ð¸Ð¼ Ñ‚Ð¾Ð»ÑŒÐºÐ¾ ÐµÑÐ»Ð¸ Ñ„Ð°Ð¹Ð» ÐºÐ»ÑŽÑ‡ÐµÐ¹ Ð¸Ð·Ð¼ÐµÐ½Ð¸Ð»ÑÑ Ð½ÐµÐ´Ð°Ð²Ð½Ð¾ (Ð·Ð° 7 Ð´Ð½ÐµÐ¹)
    if find "$AUTH_KEYS" -mtime -7 2>/dev/null | grep -q .; then
      KEYS_CONTENT=$(cat "$AUTH_KEYS")
      warn "ÐÐµÐ´Ð°Ð²Ð½Ð¾ Ð¸Ð·Ð¼ÐµÐ½Ñ‘Ð½Ð½Ñ‹Ðµ SSH ÐºÐ»ÑŽÑ‡Ð¸ Ð¿Ð¾Ð»ÑŒÐ·Ð¾Ð²Ð°Ñ‚ÐµÐ»Ñ $user:"
      echo "$KEYS_CONTENT"
      queue_alert "Ð˜Ð·Ð¼ÐµÐ½ÐµÐ½Ñ‹ SSH ÐºÐ»ÑŽÑ‡Ð¸ Ñƒ $user" "$KEYS_CONTENT"
    fi
  fi
done
KEY_COUNT=$(grep -c 'ssh-' "$REPORT_DIR/ssh-keys.txt" 2>/dev/null || echo 0)
log "SSH ÐºÐ»ÑŽÑ‡Ð¸ ÑÐ¾Ñ…Ñ€Ð°Ð½ÐµÐ½Ñ‹ Ð² Ð¾Ñ‚Ñ‡Ñ‘Ñ‚ ($KEY_COUNT ÐºÐ»ÑŽÑ‡ÐµÐ¹ Ð²ÑÐµÐ³Ð¾)"

# --- 14. Ð˜Ð—ÐœÐ•ÐÐ•ÐÐ˜Ð¯ Ð’ /etc ---
log "=== 14. ÐÐ•Ð”ÐÐ’ÐÐž Ð˜Ð—ÐœÐ•ÐÐÐÐÐ«Ð• Ð¡Ð˜Ð¡Ð¢Ð•ÐœÐÐ«Ð• Ð¤ÐÐ™Ð›Ð« ==="
find /etc -newer /etc/passwd -mtime -7 -type f 2>/dev/null \
  | grep -vE '(\.db|mtab|resolv|adjtime|machine-id)' \
  | tee "$REPORT_DIR/recently-modified-etc.txt"

# --- Ð˜Ð¢ÐžÐ“ ---
echo ""
echo "============================================================"
log "ÐÐ£Ð”Ð˜Ð¢ Ð—ÐÐ’Ð•Ð Ð¨ÐÐ. Ð ÐµÐ·ÑƒÐ»ÑŒÑ‚Ð°Ñ‚Ñ‹ Ð²: $REPORT_DIR"
echo "============================================================"
echo "ÐžÑÐ½Ð¾Ð²Ð½Ñ‹Ðµ Ñ„Ð°Ð¹Ð»Ñ‹ Ð´Ð»Ñ Ð¿Ñ€Ð¾Ð²ÐµÑ€ÐºÐ¸:"
ls -la "$REPORT_DIR/"

# --- ÐžÐ¢ÐŸÐ ÐÐ’ÐšÐ ÐžÐ¢Ð§ÐÐ¢Ð Ð§Ð•Ð Ð•Ð— RESEND ---
log "=== ÐžÑ‚Ð¿Ñ€Ð°Ð²ÐºÐ° Ð¾Ñ‚Ñ‡Ñ‘Ñ‚Ð° Ð¿Ð¾ email ==="

# Ð¤Ð¾Ñ€Ð¼Ð¸Ñ€ÑƒÐµÐ¼ ÑÐ²Ð¾Ð´Ð½Ñ‹Ð¹ Ð¾Ñ‚Ñ‡Ñ‘Ñ‚
SUMMARY_FILE="$REPORT_DIR/summary.txt"
{
  echo "SECURITY AUDIT REPORT"
  echo "Ð¡ÐµÑ€Ð²ÐµÑ€: $HOSTNAME"
  echo "Ð”Ð°Ñ‚Ð°: $(date)"
  echo "Ð”Ð¸Ñ€ÐµÐºÑ‚Ð¾Ñ€Ð¸Ñ Ð¾Ñ‚Ñ‡Ñ‘Ñ‚Ð°: $REPORT_DIR"
  echo ""
  echo "=============================="
  echo "ÐžÐ‘ÐÐÐ Ð£Ð–Ð•ÐÐÐ«Ð• ÐŸÐ ÐžÐ‘Ð›Ð•ÐœÐ«:"
  echo "=============================="

  if [ "${#ALERT_SUBJECTS[@]}" -eq 0 ]; then
    echo "Ð¯Ð²Ð½Ñ‹Ñ… Ð¿Ñ€Ð¾Ð±Ð»ÐµÐ¼ Ð½Ðµ Ð¾Ð±Ð½Ð°Ñ€ÑƒÐ¶ÐµÐ½Ð¾."
  else
    for i in "${!ALERT_SUBJECTS[@]}"; do
      echo ""
      echo "--- ${ALERT_SUBJECTS[$i]} ---"
      echo "${ALERT_BODIES[$i]}"
    done
  fi

  echo ""
  echo "=============================="
  echo "Ð¡Ð¢ÐÐ¢Ð˜Ð¡Ð¢Ð˜ÐšÐ:"
  echo "=============================="
  for user in "${USERS[@]}"; do
    WEBSHELL_COUNT=$(cat "$REPORT_DIR/webshells-$user.txt" 2>/dev/null | wc -l)
    MOD_COUNT=$(cat "$REPORT_DIR/modified-files-$user.txt" 2>/dev/null | wc -l)
    echo "$user: Ð¸Ð·Ð¼ÐµÐ½Ñ‘Ð½Ð½Ñ‹Ñ… Ñ„Ð°Ð¹Ð»Ð¾Ð²=$MOD_COUNT, Ð¿Ð¾Ð´Ð¾Ð·Ñ€Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ñ‹Ñ…=$WEBSHELL_COUNT"
  done

  echo ""
  echo "ÐŸÐ¾Ð»Ð½Ñ‹Ð¹ Ð¾Ñ‚Ñ‡Ñ‘Ñ‚ Ð²: $REPORT_DIR"
} > "$SUMMARY_FILE"

# ÐžÐ¿Ñ€ÐµÐ´ÐµÐ»ÑÐµÐ¼ Ñ‚ÐµÐ¼Ñƒ Ð¿Ð¸ÑÑŒÐ¼Ð°
if [ "${#ALERT_SUBJECTS[@]}" -gt 0 ]; then
  EMAIL_SUBJECT="[SECURITY ALERT] $HOSTNAME â€” Ð¾Ð±Ð½Ð°Ñ€ÑƒÐ¶ÐµÐ½Ð¾ ${#ALERT_SUBJECTS[@]} Ð¿Ñ€Ð¾Ð±Ð»ÐµÐ¼(Ñ‹)"
else
  EMAIL_SUBJECT="[SECURITY OK] $HOSTNAME â€” Ð°ÑƒÐ´Ð¸Ñ‚ Ð·Ð°Ð²ÐµÑ€ÑˆÑ‘Ð½, Ð¿Ñ€Ð¾Ð±Ð»ÐµÐ¼ Ð½Ðµ Ð¾Ð±Ð½Ð°Ñ€ÑƒÐ¶ÐµÐ½Ð¾"
fi

send_resend_email "$EMAIL_SUBJECT" "$SUMMARY_FILE"
