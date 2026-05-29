#!/bin/bash
# =============================================================================
# SECURITY AUDIT SCRIPT — infection vector detection
# Run as root: sudo bash 01-security-audit.sh 2>&1 | tee audit-report.txt
# =============================================================================

LOCK_FILE="/var/lock/hestia-security-audit.lock"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Another security audit is already running; exiting."
  exit 0
fi

# Auto-detect HestiaCP users (or set manually in /etc/security-audit.env)
# USERS=("user1" "user2")   # uncomment to override
if [ -z "${USERS+x}" ]; then
  if command -v v-list-users &>/dev/null; then
    mapfile -t USERS < <(sudo /usr/local/hestia/bin/v-list-users plain 2>/dev/null | awk 'NR>2 && $1 != "admin" {print $1}' | sort -u)
  else
    mapfile -t USERS < <(ls /home/ | grep -vE '^(admin|lost\+found|ubuntu)$' | sort -u)
  fi
fi

REPORT_DIR="/root/security-audit-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"

# IP from which SSH is allowed (detected from iptables, or set manually)
TRUSTED_SSH_IP=$(iptables -L INPUT -n --line-numbers 2>/dev/null \
  | awk '$3=="ACCEPT" && $5=="tcp" && /dpt:22/' \
  | awk '{print $8}' | grep -v '0.0.0.0' | head -1)
[ -z "$TRUSTED_SSH_IP" ] && TRUSTED_SSH_IP="YOUR.IP.HERE"

# --- RESEND SETTINGS ---
# Replace with your values or move to /etc/security-audit.env
RESEND_API_KEY="re_YOUR_API_KEY"
RESEND_FROM="security@your-domain.com"
RESEND_TO="admin@your-email.com"
HOSTNAME="$(hostname -f)"
ALERT_SUBJECTS=()   # accumulate alert subjects
ALERT_BODIES=()     # accumulate alert bodies

# Load config from file if exists (to avoid storing keys in the script)
[ -f /etc/security-audit.env ] && source /etc/security-audit.env

# Send email via Resend API
# $1 — subject, $2 — path to email body file (plain text)
send_resend_email() {
  local SUBJECT="$1"
  local BODY_FILE="$2"
  local TMPJSON
  TMPJSON=$(mktemp /tmp/resend-body-XXXXXX.json)

  # Use python3 for proper JSON encoding (avoids "Argument list too long")
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
    log "Email sent via Resend: $SUBJECT"
  else
    warn "Email send error (HTTP $HTTP_CODE): $(cat /tmp/resend-response.json 2>/dev/null)"
  fi
}

# Add alert to queue (will be sent as a single email at the end)
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
echo " SECURITY AUDIT — $(date)"
echo "============================================================"

# --- 1. SYSTEM INFORMATION ---
log "=== 1. SYSTEM INFORMATION ==="
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME)"
echo "Kernel: $(uname -r)"
echo "Uptime: $(uptime)"
echo "HestiaCP version: $(cat /usr/local/hestia/conf/hestia.conf 2>/dev/null | grep VERSION || echo 'not found')"

# --- 2. RECENT SERVER LOGINS ---
log "=== 2. RECENT SSH LOGINS (last 50) ==="
last -n 50 | tee "$REPORT_DIR/last-logins.txt"

# Failed SSH logins — show count only (fail2ban protects)
grep "Failed password" /var/log/auth.log 2>/dev/null \
  | tee "$REPORT_DIR/failed-ssh-logins.txt" > /dev/null
FAILED_COUNT=$(wc -l < "$REPORT_DIR/failed-ssh-logins.txt")
if [ "$FAILED_COUNT" -gt 10 ]; then
  warn "Failed SSH login attempts in auth.log: $FAILED_COUNT (fail2ban active)"
else
  log "✓ Failed SSH attempts: $FAILED_COUNT"
fi

# Accepted passwords — alert only for IPs not in the whitelist
grep "Accepted password" /var/log/auth.log 2>/dev/null \
  | tee "$REPORT_DIR/accepted-password-logins.txt" > /dev/null
PASSWD_FROM_UNKNOWN=$(grep "Accepted password" /var/log/auth.log 2>/dev/null \
  | grep -v "$TRUSTED_SSH_IP")
if [ -n "$PASSWD_FROM_UNKNOWN" ]; then
  warn "Accepted passwords from unknown IPs (SUSPICIOUS):"
  echo "$PASSWD_FROM_UNKNOWN" | tee -a "$REPORT_DIR/accepted-password-logins.txt"
  queue_alert "SSH: accepted passwords from unknown IPs" "$PASSWD_FROM_UNKNOWN"
else
  log "✓ No accepted passwords from unknown IPs (only $TRUSTED_SSH_IP or keys)"
fi

# --- 3. ACTIVE SESSIONS AND PROCESSES ---
log "=== 3. ACTIVE SESSIONS ==="
w
echo ""
log "Suspicious processes (PHP/Python/Perl/curl/wget from web users):"
ps aux | grep -E "(php|python|perl|wget|curl|nc |ncat|bash -i|sh -i)" \
  | grep -v grep | tee "$REPORT_DIR/suspicious-processes.txt"

# --- 4. NETWORK CONNECTIONS ---
log "=== 4. NON-STANDARD NETWORK CONNECTIONS ==="
echo "Listening ports:"
ss -tlnp | tee "$REPORT_DIR/listening-ports.txt"

EXT_CONNS=$(ss -tnp | grep ESTAB | grep -vE ':80 |:443 |:22 |:3306 |:8083 ')
if [ -n "$EXT_CONNS" ]; then
  warn "Active external connections (not 80/443/22/3306):"
  echo "$EXT_CONNS" | tee "$REPORT_DIR/external-connections.txt"
else
  log "✓ No non-standard external connections"
fi

# --- 4b. IPTABLES CHECK ---
log "=== 4b. IPTABLES CHECK ==="
IPTABLES_RULES=$(iptables -L INPUT -n --line-numbers 2>/dev/null)
echo "$IPTABLES_RULES" | tee "$REPORT_DIR/iptables-input.txt"

# Check: SSH (port 22) must not be open to 0.0.0.0/0 as SOURCE
# Use awk to check the source column (5), not destination
SSH_OPEN=$(iptables -L INPUT -n --line-numbers 2>/dev/null \
  | awk '$2=="ACCEPT" && $5=="0.0.0.0/0"' | grep 'dpt:22')
if [ -n "$SSH_OPEN" ]; then
  queue_alert "IPTABLES: SSH open to the world!" "Rule allows SSH from 0.0.0.0/0 — should be restricted by IP:\n$SSH_OPEN"
else
  log "✓ SSH restricted by IP (0.0.0.0/0 not allowed as source)"
fi

# Check: INPUT policy
INPUT_POLICY=$(echo "$IPTABLES_RULES" | grep 'Chain INPUT' | grep -o 'policy [A-Z]*')
if echo "$INPUT_POLICY" | grep -q 'DROP\|REJECT'; then
  log "✓ INPUT policy: $INPUT_POLICY (secure)"
else
  queue_alert "IPTABLES: INPUT policy=$INPUT_POLICY" "Recommended policy is DROP. Current policy: $INPUT_POLICY"
fi

# Check: MySQL/MariaDB not exposed externally (source 0.0.0.0/0)
MYSQL_OPEN=$(iptables -L INPUT -n --line-numbers 2>/dev/null \
  | awk '$2=="ACCEPT" && $5=="0.0.0.0/0"' | grep 'dpt:3306')
if [ -n "$MYSQL_OPEN" ]; then
  queue_alert "IPTABLES: MySQL open to the world!" "Rule allows MySQL connections from 0.0.0.0/0:\n$MYSQL_OPEN"
else
  log "✓ MySQL not accessible externally"
fi

# Check: fail2ban is running (supports both iptables and nftables backends)
if systemctl is-active --quiet fail2ban && fail2ban-client status sshd &>/dev/null; then
  log "✓ fail2ban active (sshd jail running)"
else
  queue_alert "fail2ban not active" "fail2ban service not running or sshd jail missing"
fi

# --- 5. CRON JOBS FOR ALL USERS ---
log "=== 5. CRON JOBS ==="
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
    #   artisan schedule:run  — standard Laravel scheduler
    #   security-audit        — our own audit script
    #   hestiaweb/hestia      — HestiaCP system tasks
    CRON_SUSPICIOUS=$(echo "$CRON_REAL" | grep -v 'artisan schedule:run' | \
      grep -v 'server-security\|security-audit' | grep -v 'hestia')
    if [ -n "$CRON_SUSPICIOUS" ]; then
      queue_alert "Cron job for user $user" "$CRON"
    fi
  fi
done

echo "Cron in /var/spool/cron:"
ls -la /var/spool/cron/crontabs/ 2>/dev/null

# --- 6. SEARCH FOR MODIFIED FILES (last 14 days) ---
log "=== 6. FILES MODIFIED IN THE LAST 14 DAYS ==="
# Exclude safe noisy paths:
#   storage/framework/views/  — compiled Blade templates
#   storage/framework/cache/  — Laravel bootstrap cache
#   document_errors/          — HestiaCP error pages (change during hardening)
#   public/js/filament/       — Filament JS assets (npm build output)
#   public/css/filament/      — Filament CSS assets
#   public/build/             — Vite build output
#   node_modules/vendor/      — dependencies
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
      warn "Modified PHP/JS files for user $user:"
      echo "$MODIFIED" | tee -a "$REPORT_DIR/modified-files-$user.txt"
    fi
  fi
done

# --- 7. SEARCH FOR WEBSHELLS AND BACKDOORS ---
log "=== 7. SEARCH FOR WEBSHELLS AND BACKDOORS ==="
# IMPORTANT: vendor/, node_modules/ excluded from search — legitimate code there.
# Searching only in public_html root, public/, storage/, and other non-vendor paths.

# Patterns for PHP files (excluding vendor/ and node_modules/)
# Keep these split so we can scan each tree once with fixed strings and once
# with regexes instead of rescanning the full tree per pattern.
PHP_WEBSHELL_FIXED_PATTERNS=(
  'eval(base64_decode'
  'eval(gzinflate'
  'eval(str_rot13'
  'eval(gzuncompress'
  'FilesMan'
  'c99shell'
  'r57shell'
  'phpspy'
  '/* LP_'
  # LP_ marker without /* prefix (incident 2026-05-28 avtonic.com — Livewire RCE)
  'echo "LP_'
  # GUI shell from same incident: "System Manager" + "Command Executor" + magic key
  'wanna_play_with_me'
  'System Manager'
  'Command Executor'
)

PHP_WEBSHELL_REGEX_PATTERNS=(
  'eval\(\$_'
  'assert\(\$_'
  'system\(\$_'
  'exec\(\$_'
  'passthru\(\$_'
  'shell_exec\(\$_'
  '\$_POST\[.*\].*eval'
  'base64_decode.*eval'
  'WSO\b'
  'HTTP/1\.0 404.*die\(\)'
  # Multi-fallback RCE pattern: tries system/passthru/shell_exec/exec/proc_open/popen in sequence
  '@system\(\$.*@passthru\(\$'
  # 404 + exit + REQUEST shell — typical hidden RCE backdoor
  'HTTP/1\.1 404 Not Found.*exit.*\$_REQUEST'
  # move_uploaded_file driven by user-controlled path (file uploader webshell)
  'move_uploaded_file\(\$_FILES\[.*\$_(GET|POST|REQUEST)'
)

# Suspicious shell filenames (search everywhere including vendor/)
# Only unique names clearly not found in legitimate code
SHELL_FILENAMES=(
  'shc.php'
  'adminfuns.php'
  'wp-conffq.php'
  'wp-headre.php'
)
SHELL_FILENAME_EXPR=( -name 'shc.php' -o -name 'adminfuns.php' -o -name 'wp-conffq.php' -o -name 'wp-headre.php' )

# Suspicious mirror/path-traversal directories created inside a Laravel public/.
# Webshells often live in nested paths that look like public/htdocs/, public/public/, etc.
# A real Laravel app never has these as subdirs of public/.
LARAVEL_MIRROR_DIR_NAMES=(htdocs html httpdocs public public_html www)

is_known_safe_php_file() {
  local file_path="$1"

  case "$file_path" in
    */wp-content/plugins/insert-headers-and-footers/includes/class-wpcode-snippet-execute.php)
      return 0
      ;;
    */wp-content/uploads/wpforms/cache/index.php)
      return 0
      ;;
    */wp-content/uploads/wp-import-export-lite/index.php)
      return 0
      ;;
    */wp-content/uploads/wp-import-export-lite/import/index.php)
      return 0
      ;;
    */wp-content/uploads/wp-import-export-lite/export/index.php)
      return 0
      ;;
    */wp-content/uploads/wp-import-export-lite/temp/index.php)
      return 0
      ;;
    */wp-content/uploads/wp-import-export-lite/upload/index.php)
      return 0
      ;;
    */wp-content/uploads/alm_templates/default.php)
      return 0
      ;;
    */wp-content/uploads/wp-lister/templates/*/*.php)
      return 0
      ;;
    */wp-content/plugins.bak/*/*.asset.php)
      return 0
      ;;
    */wp-content/plugins.old/*/*.asset.php)
      return 0
      ;;
    */wp-content/plugins.bak/wp-mail-smtp/assets/languages/wp-mail-smtp-vue.php)
      return 0
      ;;
  esac

  if [ "$(basename "$file_path")" = "index.php" ] && grep -q "Silence is golden" "$file_path" 2>/dev/null; then
    return 0
  fi

  return 1
}

filter_known_safe_results() {
  while IFS= read -r file_path; do
    [ -n "$file_path" ] || continue
    if ! is_known_safe_php_file "$file_path"; then
      printf '%s\n' "$file_path"
    fi
  done
}

FIXED_PATTERN_FILE="$REPORT_DIR/php-webshell-fixed-patterns.txt"
REGEX_PATTERN_FILE="$REPORT_DIR/php-webshell-regex-patterns.txt"
printf '%s\n' "${PHP_WEBSHELL_FIXED_PATTERNS[@]}" > "$FIXED_PATTERN_FILE"
printf '%s\n' "${PHP_WEBSHELL_REGEX_PATTERNS[@]}" > "$REGEX_PATTERN_FILE"

for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  FOUND_FILE="$REPORT_DIR/webshells-$user.txt"
  if [ -d "$WEB_DIR" ]; then
    echo "" > "$FOUND_FILE"

    # 1. Search for malicious patterns in PHP files, excluding vendor/ and node_modules/
    # Scan each tree once per pattern type to avoid N x pattern full-tree rescans.
    RESULTS_FIXED=$(grep -rIlF -f "$FIXED_PATTERN_FILE" "$WEB_DIR" \
      --include='*.php' \
      --include='*.php5' \
      --include='*.php7' \
      --include='*.phtml' \
      --include='*.phar' \
      --exclude-dir='.git' \
      --exclude-dir='vendor' \
      --exclude-dir='node_modules' 2>/dev/null)
    RESULTS_REGEX=$(grep -rIlE -f "$REGEX_PATTERN_FILE" "$WEB_DIR" \
      --include='*.php' \
      --include='*.php5' \
      --include='*.php7' \
      --include='*.phtml' \
      --include='*.phar' \
      --exclude-dir='.git' \
      --exclude-dir='vendor' \
      --exclude-dir='node_modules' 2>/dev/null)
    RESULTS=$(printf '%s\n%s\n' "$RESULTS_FIXED" "$RESULTS_REGEX" | sed '/^$/d' | sort -u)
    RESULTS=$(printf '%s\n' "$RESULTS" | filter_known_safe_results)
    if [ -n "$RESULTS" ]; then
      queue_alert "BACKDOOR indicators for $user" "$RESULTS"
      echo "$RESULTS" | tee -a "$FOUND_FILE"
    fi

    # 2. Search by suspicious filenames (everywhere)
    RESULTS=$(find "$WEB_DIR" \( "${SHELL_FILENAME_EXPR[@]}" \) 2>/dev/null | grep -v '/.git/')
    RESULTS=$(printf '%s\n' "$RESULTS" | filter_known_safe_results)
    if [ -n "$RESULTS" ]; then
      queue_alert "SUSPICIOUS FILE for $user" "$RESULTS"
      echo "$RESULTS" | tee -a "$FOUND_FILE"
    fi

    # 3. PHP files with hex names (8+ hex chars) — typical for droppers
    # Exclude storage/framework/views/ — legitimate compiled Laravel Blade templates
    RESULTS=$(find "$WEB_DIR" -type f -name "*.php" 2>/dev/null \
      | grep -E '/[0-9a-f]{8,}\.php$' \
      | grep -v '/.git/' \
      | grep -v '/storage/framework/views/' \
      | grep -v '/vendor/')
    RESULTS=$(printf '%s\n' "$RESULTS" | filter_known_safe_results)
    if [ -n "$RESULTS" ]; then
      queue_alert "PHP DROPPER (hex name) for $user" "$RESULTS"
      echo "$RESULTS" | tee -a "$FOUND_FILE"
    fi

    # 4. cache.php ONLY in suspicious locations (not in /config/, /wp-includes/, /themes/)
    # Legitimate locations: /config/cache.php (Laravel), /wp-includes/cache.php (WP core),
    #   /wp-content/themes/*/cache.php (themes)
    # Suspicious: /public/, /storage/, /upload/, /assets/, /build/, /tmp/
    RESULTS=$(find "$WEB_DIR" -name "cache.php" 2>/dev/null \
      | grep -v '/vendor/' \
      | grep -v '/node_modules/' \
      | grep -v '/.git/' \
      | grep -v '/config/cache\.php' \
      | grep -v '/wp-includes/' \
      | grep -v '/wp-content/themes/' \
      | grep -E '/(public|storage|upload|assets|build|tmp|cache|files)/')
    RESULTS=$(printf '%s\n' "$RESULTS" | filter_known_safe_results)
    if [ -n "$RESULTS" ]; then
      queue_alert "WEBSHELL cache.php for $user" "$RESULTS"
      echo "$RESULTS" | tee -a "$FOUND_FILE"
    fi

    # 5. PHP files in directories that should only contain static assets
    # These directories should NEVER contain .php files — any found is suspicious
    # WordPress exclusions: wp-content/plugins/, wp-content/themes/, wp-includes/ legitimately
    # store PHP files inside images/, files/, assets/ subdirs — these are not webshells.
    STATIC_DIRS_REGEX='/(images|img|media|uploads|files|assets|pics|photos|pictures)/'
    RESULTS=$(find "$WEB_DIR" -type f -name "*.php" 2>/dev/null \
      | grep -E "$STATIC_DIRS_REGEX" \
      | grep -v '/vendor/' \
      | grep -v '/node_modules/' \
      | grep -v '/.git/' \
      | grep -v '/wp-content/plugins/' \
      | grep -v '/wp-content/themes/' \
      | grep -v '/wp-includes/')
    RESULTS=$(printf '%s\n' "$RESULTS" | filter_known_safe_results)
    if [ -n "$RESULTS" ]; then
      queue_alert "PHP IN STATIC DIR for $user" "$RESULTS"
      echo "$RESULTS" | tee -a "$FOUND_FILE"
    fi

    # 6. PHP files created in the last 24h inside public/ (excluding index.php and vendor)
    # Legitimate deploys don't create new .php files in the web-served public/ directory
    RESULTS=$(find "$WEB_DIR" -type f -name "*.php" -mmin -1440 2>/dev/null \
      | grep '/public/' \
      | grep -v '/vendor/' \
      | grep -v '/node_modules/' \
      | grep -v '/.git/' \
      | grep -v '/index\.php$')
    RESULTS=$(printf '%s\n' "$RESULTS" | filter_known_safe_results)
    if [ -n "$RESULTS" ]; then
      queue_alert "NEWLY CREATED PHP IN PUBLIC/ for $user (last 24h)" "$RESULTS"
      echo "$RESULTS" | tee -a "$FOUND_FILE"
    fi

    # 7. Backup/config files that should NEVER be publicly accessible
    # wp-config.php.old, config.php.bak, .env.bak, settings.php.old, etc.
    # If found in web root, they can leak DB credentials and secret keys
    BACKUP_FILES=$(find "$WEB_DIR" -maxdepth 4 -type f 2>/dev/null \( \
      -name "wp-config*.old" -o -name "wp-config*.bak" -o -name "wp-config*.save" \
      -o -name "config.php.bak" -o -name "config.php.old" \
      -o -name "settings.php.bak" -o -name "settings.php.old" \
      -o -name "database.php.bak" -o -name "database.php.old" \
      -o -name ".env.bak" -o -name ".env.old" -o -name ".env.save" -o -name ".env.backup" \
      -o -name "*.php.bak" -o -name "*.php.old" -o -name "*.php.save" \
    \) | grep -v '/.git/' | grep -v '/vendor/')
    if [ -n "$BACKUP_FILES" ]; then
      queue_alert "CONFIG BACKUP FILES EXPOSED for $user (may leak credentials!)" "$BACKUP_FILES"
      echo "$BACKUP_FILES" | tee -a "$FOUND_FILE"
    fi
  fi
done

# 5. Specific: cron with .X11-linux or base64-encoded payload (miner/backdoor)
for user in "${USERS[@]}"; do
  CRON_XLINUX=$(crontab -u "$user" -l 2>/dev/null | grep '\.X11-linux')
  if [ -n "$CRON_XLINUX" ]; then
    queue_alert "MINER IN CRON for $user (.X11-linux)" "$CRON_XLINUX"
  fi
  # Detect base64-encoded payloads in cron (attacker evasion technique)
  CRON_BASE64=$(crontab -u "$user" -l 2>/dev/null | grep -E 'echo.*base64.*-d|base64 -d|base64 --decode' | grep -v '^#')
  if [ -n "$CRON_BASE64" ]; then
    queue_alert "BASE64 PAYLOAD IN CRON for $user (possible miner/backdoor)" "$CRON_BASE64"
  fi
done

# 6. PHP files in storage/app/public/ — webshells via file-upload/Livewire RCE
# Laravel framework NEVER writes PHP files to storage/app/public/ — any found = webshell
# Also checks hidden-name files like .cache.php, .bak.php (dot-prefix evasion)
log "Checking for PHP files in storage/app/public/ (upload RCE webshells)..."
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    STORAGE_PHP=$(find "$WEB_DIR" -path "*/storage/app/public/*" 2>/dev/null \
      \( -name "*.php" -o -name "*.phtml" -o -name "*.phar" \
         -o -name ".*.php" -o -name ".*.phtml" -o -name ".*.phar" \) \
      | grep -v 'framework/views' \
      | grep -v 'framework/sessions' \
      | grep -v 'framework/testing')
    if [ -n "$STORAGE_PHP" ]; then
      queue_alert "WEBSHELL IN storage/app/public/ for $user (file-upload/Livewire RCE!)" "$STORAGE_PHP"
      echo "$STORAGE_PHP" | tee -a "$REPORT_DIR/webshells-$user.txt"
    else
      log "✓ No PHP in storage/app/public/ for $user"
    fi
  fi
done

# 7. Laravel storage/framework/maintenance.php — goto-obfuscated SEO cloaker hiding spot
# Legit Laravel writes this file ONLY while `php artisan down` is active. Content is a small
# (~500B) PHP stub that either renders 503 or `return require __DIR__.'/down';`. Anything
# bigger or containing obfuscation markers = malware (auto-required by public/index.php
# BEFORE Laravel bootstrap, so it executes on every request without leaving framework traces).
# Reference: incident 2026-05-25 grinev.studio — 17KB goto-obfuscated cloaker calling out
# to 198.204.224.178 (opboot.icu C&C).
log "Checking Laravel storage/framework/maintenance.php integrity..."
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    while IFS= read -r mfile; do
      [ -n "$mfile" ] || continue
      SIZE=$(stat -c%s "$mfile" 2>/dev/null || echo 0)
      # Legit Laravel maintenance stub is <2KB. Anything bigger = suspicious.
      if [ "$SIZE" -gt 2048 ]; then
        queue_alert "LARAVEL maintenance.php OVERSIZED for $user (likely cloaker, ${SIZE}B)" \
          "$mfile (size: $SIZE bytes — legit is ~500B)"
        echo "$mfile size=$SIZE" >> "$REPORT_DIR/webshells-$user.txt"
      elif [ "$SIZE" -gt 0 ]; then
        # Even small file: alert if it contains obfuscation markers or network calls
        if grep -qE 'goto [A-Za-z0-9_]{10,};|curl_init|file_get_contents.*http|fsockopen|eval\(' "$mfile" 2>/dev/null; then
          queue_alert "LARAVEL maintenance.php WITH SUSPICIOUS CODE for $user" \
            "$mfile contains obfuscation/network calls — investigate"
          echo "$mfile (suspicious content)" >> "$REPORT_DIR/webshells-$user.txt"
        fi
      fi
    done < <(find "$WEB_DIR" -path "*/storage/framework/maintenance.php" 2>/dev/null)
  fi
done

# 8. Unexpected PHP files in bootstrap/cache/ — Laravel autoloads compiled files from here
# Legit files: services.php, packages.php, config.php, routes-v7.php, compiled.php,
#   events.php, container.php (Laravel 11+), plus per-package caches like blade-icons.php,
#   livewire-components.php, filament-*.php — these are written by package service providers.
# Suspicious: digit-prefixed names (e.g., 1index.php), names matching index/loader/cache,
#   or random hex names — staged payloads (incident 2026-05-25 grinev.studio dropped
#   202KB encrypted backdoor as `1index.php` here).
log "Checking Laravel bootstrap/cache/ for unexpected PHP files..."
LARAVEL_CACHE_WHITELIST='^(services|packages|config|routes-v[0-9]+|compiled|events|container|blade-icons|livewire-components|filament-[a-z0-9-]+|[a-z][a-z0-9-]*-components|[a-z][a-z0-9-]*-icons)\.php$'
LARAVEL_CACHE_SUSPICIOUS_NAME='^([0-9]|.*index|.*loader|.*shell|.*cache\.php$|[0-9a-f]{8,}\.php$)'
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    UNEXPECTED=$(find "$WEB_DIR" -path "*/bootstrap/cache/*.php" 2>/dev/null \
      | while IFS= read -r f; do
          bn=$(basename "$f")
          # Skip if matches whitelist
          echo "$bn" | grep -qE "$LARAVEL_CACHE_WHITELIST" && continue
          # Alert if matches suspicious name pattern OR size > 50KB
          # (legit compiled caches rarely exceed 50KB; cloakers are 200KB+)
          sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
          if echo "$bn" | grep -qE "$LARAVEL_CACHE_SUSPICIOUS_NAME" || [ "$sz" -gt 51200 ]; then
            echo "$f (size: $sz)"
          fi
        done)
    if [ -n "$UNEXPECTED" ]; then
      queue_alert "UNEXPECTED PHP IN bootstrap/cache/ for $user (staged payload?)" "$UNEXPECTED"
      echo "$UNEXPECTED" >> "$REPORT_DIR/webshells-$user.txt"
    fi
  fi
done

# 9. Goto-obfuscation density — PHP files outside vendor/ with >20 `goto LABEL;` statements
# Modern legit PHP almost never uses `goto`. Obfuscators (incl. the maintenance.php cloaker)
# rely heavily on goto with random hex/alphanumeric labels to flatten control flow.
log "Checking for goto-obfuscated PHP files..."
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    # Find PHP files outside vendor/node_modules and count `goto <label>;` occurrences
    GOTO_HITS=$(find "$WEB_DIR" -type f -name "*.php" \
      ! -path "*/vendor/*" ! -path "*/node_modules/*" ! -path "*/.git/*" \
      ! -path "*/storage/framework/views/*" 2>/dev/null \
      | while IFS= read -r f; do
          n=$(grep -cE 'goto [A-Za-z0-9_]{10,};' "$f" 2>/dev/null || echo 0)
          [ "$n" -gt 20 ] && echo "$f (goto-count: $n)"
        done)
    if [ -n "$GOTO_HITS" ]; then
      queue_alert "GOTO-OBFUSCATED PHP for $user (likely malware loader)" "$GOTO_HITS"
      echo "$GOTO_HITS" >> "$REPORT_DIR/webshells-$user.txt"
    fi
  fi
done

# 10. Known-bad IOC: hardcoded malware C&C indicators
# Add new indicators here as incidents accumulate.
KNOWN_BAD_IOC='198\.204\.224\.178|opboot\.icu|zs898v13'
log "Checking for known-bad C&C indicators (IOCs)..."
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    IOC_HITS=$(grep -rIlE "$KNOWN_BAD_IOC" "$WEB_DIR" \
      --include='*.php' --include='*.phtml' --include='*.phar' --include='*.inc' \
      --exclude-dir='.git' --exclude-dir='node_modules' 2>/dev/null)
    if [ -n "$IOC_HITS" ]; then
      queue_alert "KNOWN-BAD C&C INDICATOR for $user" "$IOC_HITS"
      echo "$IOC_HITS" >> "$REPORT_DIR/webshells-$user.txt"
    fi
  fi
done

# 11. Mirror/path-traversal dirs inside Laravel public/.
# Webshells often live in nested decoy paths (public/public/, public/htdocs/,
# public/www/, public/public_html/) so SEO crawlers and admins miss them.
# Incident 2026-05-28 avtonic.com dropped 20 vendor.php files this way.
log "Checking for mirror/decoy dirs inside Laravel public/..."
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    MIRROR_HITS=$(find "$WEB_DIR" -maxdepth 6 -type d \
      \( -path "*/public/public" \
         -o -path "*/public/htdocs" \
         -o -path "*/public/html" \
         -o -path "*/public/httpdocs" \
         -o -path "*/public/public_html" \
         -o -path "*/public/www" \
         -o -path "*/storage/app/public/app/public" \) \
      ! -path "*/vendor/*" ! -path "*/node_modules/*" 2>/dev/null)
    if [ -n "$MIRROR_HITS" ]; then
      queue_alert "DECOY MIRROR DIRS in Laravel public/ for $user (webshell hideout)" "$MIRROR_HITS"
      echo "$MIRROR_HITS" >> "$REPORT_DIR/webshells-$user.txt"
    fi
  fi
done

# 12. Livewire CVE check (GHSA-mr5q-7p3c-7mhh / file-upload RCE).
# Vulnerable: Livewire 3.0.0 through 3.5.1. Fixed in 3.5.2.
# Livewire 2.x is EOL and inherently risky for new exploits; warn separately.
log "Checking Livewire versions for known RCE (GHSA-mr5q-7p3c-7mhh)..."
LIVEWIRE_FINDINGS=""
LIVEWIRE_EOL=""
for c in /home/*/web/*/public_html/composer.lock; do
  [ -f "$c" ] || continue
  ver=$(grep -A1 '"name": "livewire/livewire"' "$c" 2>/dev/null \
    | grep -E '"version"' | head -1 | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  [ -z "$ver" ] && continue
  ver_clean="${ver#v}"
  major=$(echo "$ver_clean" | cut -d. -f1)
  minor=$(echo "$ver_clean" | cut -d. -f2)
  patch=$(echo "$ver_clean" | cut -d. -f3)
  site=$(dirname "$c")
  # Livewire 2.x = EOL
  if [ "$major" = "2" ]; then
    LIVEWIRE_EOL+="$site  v$ver_clean (EOL)\n"
    continue
  fi
  # Livewire 3.0.x - 3.5.1 vulnerable
  if [ "$major" = "3" ]; then
    if [ "$minor" -lt 5 ] || { [ "$minor" = "5" ] && [ "$patch" -lt 2 ]; }; then
      LIVEWIRE_FINDINGS+="$site  v$ver_clean (vulnerable, upgrade to >=3.5.2)\n"
    fi
  fi
done
if [ -n "$LIVEWIRE_FINDINGS" ]; then
  queue_alert "LIVEWIRE RCE VULNERABLE (GHSA-mr5q-7p3c-7mhh)" "$(printf "$LIVEWIRE_FINDINGS")"
  echo -e "$LIVEWIRE_FINDINGS" >> "$REPORT_DIR/livewire-vulns.txt"
fi
if [ -n "$LIVEWIRE_EOL" ]; then
  queue_alert "LIVEWIRE 2.x EOL (no security fixes upstream)" "$(printf "$LIVEWIRE_EOL")"
  echo -e "$LIVEWIRE_EOL" >> "$REPORT_DIR/livewire-eol.txt"
fi
if [ -z "$LIVEWIRE_FINDINGS" ] && [ -z "$LIVEWIRE_EOL" ]; then
  log "✓ All Livewire installs are >=3.5.2 (patched against GHSA-mr5q-7p3c-7mhh)"
fi

# --- 8. FILES WITH DANGEROUS PERMISSIONS ---
log "=== 8. FILES WITH 777/SUID PERMISSIONS ==="
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    FILES_777=$(find "$WEB_DIR" -perm -0777 -type f 2>/dev/null | head -20)
    DIRS_777=$(find "$WEB_DIR" -perm -0777 -type d 2>/dev/null | head -20)
    if [ -n "$FILES_777" ]; then
      warn "777 files for $user:"
      echo "$FILES_777" | tee -a "$REPORT_DIR/perms-$user.txt"
      queue_alert "777 files for $user" "$FILES_777"
    fi
    if [ -n "$DIRS_777" ]; then
      warn "777 directories for $user:"
      echo "$DIRS_777" | tee -a "$REPORT_DIR/perms-$user.txt"
      queue_alert "777 directories for $user" "$DIRS_777"
    fi
  fi
done

# SUID system-wide — alert only on non-standard files
# Standard system SUID paths are excluded
SUID_STANDARD='/usr/bin|/usr/sbin|/bin|/sbin|/usr/lib/openssh|/usr/lib/dbus|/usr/libexec/polkit|/usr/lib/mysql/plugin/auth_pam'
# Known legitimate SUID files outside standard paths (whitelist)
SUID_WHITELIST=(
  /usr/lib/policykit-1/polkit-agent-helper-1  # PolicyKit auth agent
  /usr/lib/eject/dmcrypt-get-device            # eject package
  /usr/lib/snapd/snap-confine                  # snap sandbox
)
# Exclude /root/forensics/ — stores seized malware files (SUID bit intentionally removed)
SUID_SUSPICIOUS=$(find / -perm /4000 -type f 2>/dev/null \
  | grep -vE "$SUID_STANDARD" \
  | grep -v '/root/forensics/' \
  | grep -vF "$(printf '%s\n' "${SUID_WHITELIST[@]}")")
find / -perm /4000 -type f 2>/dev/null > "$REPORT_DIR/suid-files.txt"
if [ -n "$SUID_SUSPICIOUS" ]; then
  warn "NON-STANDARD SUID files (require review):"
  echo "$SUID_SUSPICIOUS" | tee -a "$REPORT_DIR/suid-files.txt"
  queue_alert "Non-standard SUID files" "$SUID_SUSPICIOUS"
else
  log "✓ SUID files — standard system only"
fi

# --- 8b. INTEGRITY OF CRITICAL SYSTEM BINARIES ---
log "=== 8b. CRITICAL BINARY INTEGRITY ==="
# Check key SUID binaries for signs of replacement.
# Backdoor indicators (as seen in /usr/bin/su, replaced in May 2026):
#   - statically linked (real Ubuntu binaries are dynamically linked)
#   - "no section header" in file(1) output
#   - file absent from dpkg database (dpkg -S cannot find it)
CRITICAL_BINS=(
  /bin/su
  /usr/bin/su
  /usr/bin/sudo
  /usr/bin/passwd
  /usr/bin/newgrp
  /usr/bin/gpasswd
)
BINARY_REPORT="$REPORT_DIR/binary-integrity.txt"
BINARY_ALERTS=()
CHECKED_INODES=()

for bin in "${CRITICAL_BINS[@]}"; do
  [ -f "$bin" ] || continue
  # Skip if this inode was already checked (usr-merge deduplication)
  BIN_INODE=$(stat -c '%i' "$bin" 2>/dev/null)
  if [[ " ${CHECKED_INODES[*]} " == *" $BIN_INODE "* ]]; then continue; fi
  CHECKED_INODES+=("$BIN_INODE")
  FILE_OUT=$(file "$bin" 2>/dev/null)

  # Indicator 1: statically linked — atypical for Ubuntu system binaries
  if echo "$FILE_OUT" | grep -q "statically linked"; then
    msg="STATICALLY LINKED (suspicious): $bin — $FILE_OUT"
    warn "$msg"
    echo "$msg" >> "$BINARY_REPORT"
    BINARY_ALERTS+=("$msg")
  fi

  # Indicator 2: no ELF sections ("no section header") — typical for packed/trojanized binaries
  if echo "$FILE_OUT" | grep -q "no section header"; then
    msg="NO ELF SECTIONS (backdoor indicator): $bin — $FILE_OUT"
    warn "$msg"
    echo "$msg" >> "$BINARY_REPORT"
    BINARY_ALERTS+=("$msg")
  fi

  # Indicator 3: file absent from dpkg database
  # Ubuntu 20.04+ usr-merge: /bin → /usr/bin symlink, so dpkg may register
  # the binary under either path. Try both, then fall back to inode match.
  DPKG_PATH="$bin"
  PKG=$(dpkg -S "$bin" 2>/dev/null | cut -d: -f1)
  if [ -z "$PKG" ]; then
    ALT_BIN=$(echo "$bin" | sed 's|^/usr/bin/|/bin/|; s|^/usr/sbin/|/sbin/|; s|^/bin/|/usr/bin/|; s|^/sbin/|/usr/sbin/|')
    PKG=$(dpkg -S "$ALT_BIN" 2>/dev/null | cut -d: -f1)
    [ -n "$PKG" ] && DPKG_PATH="$ALT_BIN"
  fi
  if [ -z "$PKG" ]; then
    msg="NOT REGISTERED IN DPKG (file removed from package database): $bin"
    warn "$msg"
    echo "$msg" >> "$BINARY_REPORT"
    BINARY_ALERTS+=("$msg")
  else
    # Indicator 4: dpkg --verify reports checksum mismatch
    # Use the path dpkg actually knows about (DPKG_PATH, not $bin)
    VERIFY_OUT=$(dpkg --verify "$PKG" 2>/dev/null | grep -F "$DPKG_PATH")
    if [ -n "$VERIFY_OUT" ]; then
      msg="DPKG CHECKSUM MISMATCH: $bin — $VERIFY_OUT"
      warn "$msg"
      echo "$msg" >> "$BINARY_REPORT"
      BINARY_ALERTS+=("$msg")
    fi
  fi
done

# Also check all SUID binaries in standard paths for static linking
STATIC_SUID=$(find /usr/bin /usr/sbin /bin /sbin -perm /4000 -type f 2>/dev/null \
  | while read -r f; do
      file "$f" 2>/dev/null | grep -q "statically linked" && echo "$f"
    done)
if [ -n "$STATIC_SUID" ]; then
  msg="SUID binaries with static linking (check manually):\n$STATIC_SUID"
  warn "$msg"
  echo -e "$msg" >> "$BINARY_REPORT"
  BINARY_ALERTS+=("$msg")
fi

if [ "${#BINARY_ALERTS[@]}" -gt 0 ]; then
  queue_alert "BINARY INTEGRITY: suspicious files detected" \
    "$(printf '%s\n' "${BINARY_ALERTS[@]}")"
else
  log "✓ Critical binaries — dynamically linked, present in dpkg"
fi

# --- 9. WEB SERVER LOGS — search for suspicious requests ---
log "=== 9. SUSPICIOUS REQUESTS IN NGINX/APACHE LOGS ==="
SUSPICIOUS_PATTERNS="(eval|base64_decode|system\(|passthru|shell_exec|union.*select|\.\.\/|etc\/passwd|cmd=|exec=|wget |curl |chmod |/tmp/|/dev/shm)"

for user in "${USERS[@]}"; do
  for logfile in /home/$user/web/*/log/access.log /home/$user/web/*/log/error.log; do
    if [ -f "$logfile" ]; then
      HITS=$(grep -iE "$SUSPICIOUS_PATTERNS" "$logfile" 2>/dev/null | wc -l)
      if [ "$HITS" -gt 0 ]; then
        HITS_SAMPLE=$(grep -iE "$SUSPICIOUS_PATTERNS" "$logfile" 2>/dev/null | tail -20)
        queue_alert "Suspicious requests in $logfile ($HITS total)" "$HITS_SAMPLE"
        echo "$HITS_SAMPLE" | tee -a "$REPORT_DIR/suspicious-requests-$user.txt"
      fi
    fi
  done
done

# --- 9b. ACTIVE OUTBOUND CONNECTIONS FROM PHP-FPM ---
# PHP-FPM workers should not be initiating outbound TCP connections except to local
# services (DB, redis, etc.). Outbound to public IPs strongly indicates a cloaker or
# C&C beacon. Skips RFC1918, loopback and link-local destinations.
log "=== 9b. PHP-FPM OUTBOUND CONNECTIONS ==="
if command -v ss >/dev/null 2>&1; then
  PHP_OUT=$(ss -tnpH state established 2>/dev/null \
    | grep -E 'php-fpm|"php"' \
    | awk '{print $4" -> "$5}' \
    | grep -vE '-> (127\.|::1|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|\[::1\]|\[fe80)')
  if [ -n "$PHP_OUT" ]; then
    queue_alert "PHP-FPM OUTBOUND TO PUBLIC IP (possible C&C beacon)" "$PHP_OUT"
    echo "$PHP_OUT" | tee "$REPORT_DIR/php-fpm-outbound.txt"
  else
    log "✓ No PHP-FPM outbound to public IPs"
  fi
fi

# --- 10. PHP CONFIGURATION ---
log "=== 10. PHP CONFIGURATION ==="
php -i 2>/dev/null | grep -E "(disable_functions|open_basedir|allow_url_fopen|allow_url_include|expose_php|upload_tmp_dir)" \
  | tee "$REPORT_DIR/php-config.txt"

# Check PHP-FPM pools — alert only on pools WITHOUT open_basedir
POOLS_NO_BASEDIR=$(grep -rL "open_basedir" /etc/php/*/fpm/pool.d/*.conf 2>/dev/null \
  | grep -v dummy.conf | grep -v '/www.conf')  # www.conf — HestiaCP internal (hestiamail)
if [ -n "$POOLS_NO_BASEDIR" ]; then
  warn "PHP-FPM pools WITHOUT open_basedir (risk of escaping home directory):"
  echo "$POOLS_NO_BASEDIR" | tee -a "$REPORT_DIR/php-fpm-pools.txt"
  queue_alert "PHP-FPM pools without open_basedir" "$POOLS_NO_BASEDIR"
else
  log "✓ All PHP-FPM pools have open_basedir"
fi

# --- 11. CHECK .htaccess AND .user.ini FOR INJECTIONS ---
log "=== 11. CHECK .htaccess AND .user.ini ==="
# Search only for suspicious patterns, not dumping all content
HTACCESS_BAD_PATTERNS='php_value auto_prepend|SetHandler.*cgi|AddHandler.*php|RewriteRule.*eval|base64_decode|system\(|shell_exec'
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    mapfile -t HTACCESS_FILES < <(find "$WEB_DIR" -name ".htaccess" ! -path "*/vendor/*" ! -path "*/node_modules/*" 2>/dev/null)
    # Save all htaccess to report silently
    if [ "${#HTACCESS_FILES[@]}" -gt 0 ]; then
      printf '%s\0' "${HTACCESS_FILES[@]}" | xargs -0 -I{} sh -c 'echo "=== {} ==="; cat "{}"' 2>/dev/null \
        >> "$REPORT_DIR/htaccess-$user.txt"
    fi
    # Alert only on suspicious patterns
    HTACCESS_SUSPICIOUS=""
    if [ "${#HTACCESS_FILES[@]}" -gt 0 ]; then
      HTACCESS_SUSPICIOUS=$(printf '%s\0' "${HTACCESS_FILES[@]}" | xargs -0 grep -nHiE "$HTACCESS_BAD_PATTERNS" 2>/dev/null)
    fi
    if [ -n "$HTACCESS_SUSPICIOUS" ]; then
      warn "Suspicious .htaccess for $user:"
      echo "$HTACCESS_SUSPICIOUS" | tee -a "$REPORT_DIR/htaccess-$user.txt"
      queue_alert ".htaccess injection for $user" "$HTACCESS_SUSPICIOUS"
    fi
    # .user.ini — save silently, alert only on suspicious entries
    mapfile -t USERINI_FILES < <(find "$WEB_DIR" -name ".user.ini" ! -path "*/vendor/*" ! -path "*/node_modules/*" 2>/dev/null)
    if [ "${#USERINI_FILES[@]}" -gt 0 ]; then
      printf '%s\0' "${USERINI_FILES[@]}" | xargs -0 -I{} sh -c 'echo "=== {} ==="; cat "{}"' 2>/dev/null \
        >> "$REPORT_DIR/user-ini-$user.txt"
    fi
    USERINI_SUSPICIOUS=""
    if [ "${#USERINI_FILES[@]}" -gt 0 ]; then
      USERINI_SUSPICIOUS=$(printf '%s\0' "${USERINI_FILES[@]}" | xargs -0 grep -nHiE "auto_prepend_file\s*=\s*[^[:space:]]+|auto_append_file\s*=\s*[^[:space:]]+|open_basedir\s*=\s*none" 2>/dev/null)
    fi
    if [ -n "$USERINI_SUSPICIOUS" ]; then
      warn "Suspicious .user.ini for $user:"
      echo "$USERINI_SUSPICIOUS" | tee -a "$REPORT_DIR/user-ini-$user.txt"
      queue_alert ".user.ini injection for $user" "$USERINI_SUSPICIOUS"
    fi
  fi
done

# --- 12. CHECK /tmp AND /dev/shm FOR SUSPICIOUS FILES ---
log "=== 12. /tmp AND /dev/shm ==="
# Save listing to report silently
ls -la /tmp/ > "$REPORT_DIR/tmp-files.txt" 2>/dev/null
ls -la /dev/shm/ >> "$REPORT_DIR/tmp-files.txt" 2>/dev/null
# Alert only on executable files — real threat
TMP_EXEC=$(find /tmp /dev/shm -type f -executable 2>/dev/null)
if [ -n "$TMP_EXEC" ]; then
  warn "Executable files in /tmp or /dev/shm:"
  echo "$TMP_EXEC" | tee "$REPORT_DIR/tmp-executables.txt"
  queue_alert "Executable files in /tmp" "$TMP_EXEC"
else
  log "✓ No executable files in /tmp and /dev/shm"
fi

# Miner/backdoor detection: hidden executables in user home directories
# Miners commonly hide in ~/.config/htop/, ~/.cache/, ~/.local/bin/ etc.
log "Checking for hidden executables in user home directories (miner/backdoor)..."
HIDDEN_EXEC=$(find /home -type f -executable \
  \( -path "*/.config/*" -o -path "*/.cache/*" -o -path "*/.local/bin/*" \) \
  2>/dev/null \
  | grep -v '/.config/systemd/' \
  | grep -v '/.config/dbus' \
  | grep -v 'gvfs-metadata' \
  | grep -v '/pulse/' \
  | grep -v '/.cache/composer/vcs/.*/hooks/.*\.sample$' \
  | head -30)
if [ -n "$HIDDEN_EXEC" ]; then
  warn "SUSPICIOUS EXECUTABLES IN HIDDEN HOME DIRS:"
  echo "$HIDDEN_EXEC" | tee "$REPORT_DIR/hidden-executables.txt"
  queue_alert "Miner/backdoor: hidden executables in home dirs" "$HIDDEN_EXEC"
else
  log "✓ No suspicious hidden executables in home directories"
fi

# --- 13. SSH KEYS FOR ALL USERS ---
# Alert only when keys actually change (hash-based baseline), not just by mtime.
# To accept current keys as baseline: rm /var/lib/security-audit/ssh-key-baseline.sha256
log "=== 13. SSH KEYS ==="
SSH_BASELINE_DIR="/var/lib/security-audit"
SSH_BASELINE_FILE="$SSH_BASELINE_DIR/ssh-key-baseline.sha256"
mkdir -p "$SSH_BASELINE_DIR"
# Build current hash of all authorized_keys files
CURRENT_SSH_HASH=$(for user in "${USERS[@]}" root; do
  HOME_DIR=$(eval echo "~$user")
  AUTH_KEYS="$HOME_DIR/.ssh/authorized_keys"
  [ -f "$AUTH_KEYS" ] && echo "$user" && cat "$AUTH_KEYS"
done | sha256sum | awk '{print $1}')

for user in "${USERS[@]}" root; do
  HOME_DIR=$(eval echo "~$user")
  AUTH_KEYS="$HOME_DIR/.ssh/authorized_keys"
  if [ -f "$AUTH_KEYS" ]; then
    echo "=== $user ==" >> "$REPORT_DIR/ssh-keys.txt"
    cat "$AUTH_KEYS" >> "$REPORT_DIR/ssh-keys.txt"
  fi
done

if [ ! -f "$SSH_BASELINE_FILE" ]; then
  # First run — save baseline, no alert
  echo "$CURRENT_SSH_HASH" > "$SSH_BASELINE_FILE"
  log "✓ SSH key baseline established ($(grep -c 'ssh-' "$REPORT_DIR/ssh-keys.txt" 2>/dev/null || echo 0) keys)"
else
  SAVED_SSH_HASH=$(cat "$SSH_BASELINE_FILE")
  if [ "$CURRENT_SSH_HASH" != "$SAVED_SSH_HASH" ]; then
    KEYS_DIFF=$(for user in "${USERS[@]}" root; do
      HOME_DIR=$(eval echo "~$user")
      AUTH_KEYS="$HOME_DIR/.ssh/authorized_keys"
      [ -f "$AUTH_KEYS" ] && echo "=== $user ===" && cat "$AUTH_KEYS"
    done)
    warn "SSH authorized_keys changed since last baseline!"
    queue_alert "SSH keys changed" "$KEYS_DIFF"
    # Auto-update baseline after alerting (alert fires once per change)
    echo "$CURRENT_SSH_HASH" > "$SSH_BASELINE_FILE"
  else
    log "✓ SSH keys unchanged since baseline"
  fi
fi
KEY_COUNT=$(grep -c 'ssh-' "$REPORT_DIR/ssh-keys.txt" 2>/dev/null || echo 0)
log "SSH keys saved to report ($KEY_COUNT keys total)"

# --- 14. CHANGES IN /etc ---
log "=== 14. RECENTLY MODIFIED SYSTEM FILES ==="
find /etc -newer /etc/passwd -mtime -7 -type f 2>/dev/null \
  | grep -vE '(\.db|mtab|resolv|adjtime|machine-id)' \
  | tee "$REPORT_DIR/recently-modified-etc.txt"

# --- SUMMARY ---
echo ""
echo "============================================================"
log "AUDIT COMPLETE. Results in: $REPORT_DIR"
echo "============================================================"
echo "Key files to review:"
ls -la "$REPORT_DIR/"

# --- SEND REPORT VIA RESEND ---
log "=== Sending report by email ==="

# Build summary report
SUMMARY_FILE="$REPORT_DIR/summary.txt"
{
  echo "SECURITY AUDIT REPORT"
  echo "Server: $HOSTNAME"
  echo "Date: $(date)"
  echo "Report directory: $REPORT_DIR"
  echo ""
  echo "=============================="
  echo "DETECTED ISSUES:"
  echo "=============================="

  if [ "${#ALERT_SUBJECTS[@]}" -eq 0 ]; then
    echo "No issues detected."
  else
    for i in "${!ALERT_SUBJECTS[@]}"; do
      echo ""
      echo "--- ${ALERT_SUBJECTS[$i]} ---"
      echo "${ALERT_BODIES[$i]}"
    done
  fi

  echo ""
  echo "=============================="
  echo "STATISTICS:"
  echo "=============================="
  for user in "${USERS[@]}"; do
    WEBSHELL_COUNT=$(cat "$REPORT_DIR/webshells-$user.txt" 2>/dev/null | wc -l)
    MOD_COUNT=$(cat "$REPORT_DIR/modified-files-$user.txt" 2>/dev/null | wc -l)
    echo "$user: modified files=$MOD_COUNT, suspicious=$WEBSHELL_COUNT"
  done

  echo ""
  echo "Full report in: $REPORT_DIR"
} > "$SUMMARY_FILE"

# Determine email subject
if [ "${#ALERT_SUBJECTS[@]}" -gt 0 ]; then
  EMAIL_SUBJECT="[SECURITY ALERT] $HOSTNAME — ${#ALERT_SUBJECTS[@]} issue(s) detected"
else
  EMAIL_SUBJECT="[SECURITY OK] $HOSTNAME — audit complete, no issues detected"
fi

send_resend_email "$EMAIL_SUBJECT" "$SUMMARY_FILE"
