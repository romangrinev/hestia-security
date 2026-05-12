#!/bin/bash
# =============================================================================
# SECURITY AUDIT SCRIPT — infection vector detection
# Run as root: sudo bash 01-security-audit.sh 2>&1 | tee audit-report.txt
# =============================================================================

# Auto-detect HestiaCP users (or set manually in /etc/security-audit.env)
# USERS=("user1" "user2")   # uncomment to override
if [ -z "${USERS+x}" ]; then
  if command -v v-list-users &>/dev/null; then
    mapfile -t USERS < <(sudo /usr/local/hestia/bin/v-list-users plain 2>/dev/null | awk 'NR>2 && $1 != "admin" {print $1}')
  else
    mapfile -t USERS < <(ls /home/ | grep -vE '^(admin|lost\+found|ubuntu)$')
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

# Check: fail2ban chains exist
if iptables -L f2b-sshd -n &>/dev/null; then
  log "✓ fail2ban active (f2b-sshd chain found)"
else
  queue_alert "fail2ban not active" "f2b-sshd chain not found in iptables — fail2ban may not be running"
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
)

# Suspicious shell filenames (search everywhere including vendor/)
# Only unique names clearly not found in legitimate code
SHELL_FILENAMES=(
  'shc.php'
  'adminfuns.php'
  'wp-conffq.php'
  'wp-headre.php'
)

for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  FOUND_FILE="$REPORT_DIR/webshells-$user.txt"
  if [ -d "$WEB_DIR" ]; then
    echo "" > "$FOUND_FILE"

    # 1. Search for malicious patterns in PHP files, excluding vendor/ and node_modules/
    for pattern in "${PHP_WEBSHELL_PATTERNS[@]}"; do
      RESULTS=$(grep -rl "$pattern" "$WEB_DIR" 2>/dev/null \
        | grep -E '\.(php|php5|php7|phtml|phar)$' \
        | grep -v '/.git/' \
        | grep -v '/vendor/' \
        | grep -v '/node_modules/')
      if [ -n "$RESULTS" ]; then
        queue_alert "BACKDOOR for $user (pattern: $pattern)" "$RESULTS"
        echo "$RESULTS" | tee -a "$FOUND_FILE"
      fi
    done

    # 2. Search by suspicious filenames (everywhere)
    for fname in "${SHELL_FILENAMES[@]}"; do
      RESULTS=$(find "$WEB_DIR" -name "$fname" 2>/dev/null | grep -v '/.git/')
      if [ -n "$RESULTS" ]; then
        queue_alert "SUSPICIOUS FILE for $user ($fname)" "$RESULTS"
        echo "$RESULTS" | tee -a "$FOUND_FILE"
      fi
    done

    # 3. PHP files with hex names (8+ hex chars) — typical for droppers
    # Exclude storage/framework/views/ — legitimate compiled Laravel Blade templates
    RESULTS=$(find "$WEB_DIR" -type f -name "*.php" 2>/dev/null \
      | grep -E '/[0-9a-f]{8,}\.php$' \
      | grep -v '/.git/' \
      | grep -v '/storage/framework/views/' \
      | grep -v '/vendor/')
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
    if [ -n "$RESULTS" ]; then
      queue_alert "WEBSHELL cache.php for $user" "$RESULTS"
      echo "$RESULTS" | tee -a "$FOUND_FILE"
    fi
  fi
done

# 5. Specific: cron with .X11-linux (miner/backdoor)
for user in "${USERS[@]}"; do
  CRON_XLINUX=$(crontab -u "$user" -l 2>/dev/null | grep '\.X11-linux')
  if [ -n "$CRON_XLINUX" ]; then
    queue_alert "MINER IN CRON for $user (.X11-linux)" "$CRON_XLINUX"
  fi
done

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
# Exclude /root/forensics/ — stores seized malware files (SUID bit intentionally removed)
SUID_SUSPICIOUS=$(find / -perm /4000 -type f 2>/dev/null \
  | grep -vE "$SUID_STANDARD" \
  | grep -v '/root/forensics/')
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

for bin in "${CRITICAL_BINS[@]}"; do
  [ -f "$bin" ] || continue
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
  PKG=$(dpkg -S "$bin" 2>/dev/null | cut -d: -f1)
  if [ -z "$PKG" ]; then
    msg="NOT REGISTERED IN DPKG (file removed from package database): $bin"
    warn "$msg"
    echo "$msg" >> "$BINARY_REPORT"
    BINARY_ALERTS+=("$msg")
  else
    # Indicator 4: dpkg --verify reports checksum mismatch
    VERIFY_OUT=$(dpkg --verify "$PKG" 2>/dev/null | grep "$bin")
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
    # Save all htaccess to report silently
    find "$WEB_DIR" -name ".htaccess" -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null \
      >> "$REPORT_DIR/htaccess-$user.txt"
    # Alert only on suspicious patterns
    HTACCESS_SUSPICIOUS=$(grep -rniE "$HTACCESS_BAD_PATTERNS" \
      $(find "$WEB_DIR" -name ".htaccess" 2>/dev/null) 2>/dev/null)
    if [ -n "$HTACCESS_SUSPICIOUS" ]; then
      warn "Suspicious .htaccess for $user:"
      echo "$HTACCESS_SUSPICIOUS" | tee -a "$REPORT_DIR/htaccess-$user.txt"
      queue_alert ".htaccess injection for $user" "$HTACCESS_SUSPICIOUS"
    fi
    # .user.ini — save silently, alert only on suspicious entries
    find "$WEB_DIR" -name ".user.ini" -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null \
      >> "$REPORT_DIR/user-ini-$user.txt"
    USERINI_SUSPICIOUS=$(grep -rniE "auto_prepend_file|auto_append_file|open_basedir\s*=\s*none" \
      $(find "$WEB_DIR" -name ".user.ini" 2>/dev/null) 2>/dev/null)
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

# --- 13. SSH KEYS FOR ALL USERS ---
log "=== 13. SSH KEYS ==="
for user in "${USERS[@]}" root; do
  HOME_DIR=$(eval echo "~$user")
  AUTH_KEYS="$HOME_DIR/.ssh/authorized_keys"
  if [ -f "$AUTH_KEYS" ]; then
    # Save all keys to report silently
    echo "=== $user ==" >> "$REPORT_DIR/ssh-keys.txt"
    cat "$AUTH_KEYS" >> "$REPORT_DIR/ssh-keys.txt"
    # Alert only if key file was recently modified (within 7 days)
    if find "$AUTH_KEYS" -mtime -7 2>/dev/null | grep -q .; then
      KEYS_CONTENT=$(cat "$AUTH_KEYS")
      warn "Recently modified SSH keys for user $user:"
      echo "$KEYS_CONTENT"
      queue_alert "SSH keys modified for $user" "$KEYS_CONTENT"
    fi
  fi
done
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
