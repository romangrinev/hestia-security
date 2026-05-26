#!/bin/bash
# =============================================================================
# HARDENING SCRIPT — protection measures against reinfection
# Run as root: sudo bash 03-hardening.sh 2>&1 | tee hardening-report.txt
#
# WARNING: Test in staging before applying to production!
# Some settings may break application functionality.
# =============================================================================

# Auto-detect HestiaCP users (or set manually)
# USERS=("user1" "user2")   # uncomment to override
if [ -z "${USERS+x}" ]; then
  if command -v v-list-users &>/dev/null; then
    mapfile -t USERS < <(sudo /usr/local/hestia/bin/v-list-users plain 2>/dev/null | awk 'NR>2 && $1 != "admin" {print $1}')
  else
    mapfile -t USERS < <(ls /home/ | grep -vE '^(admin|lost\+found|ubuntu)$')
  fi
fi

PHP_VERSIONS=$(ls /etc/php/ 2>/dev/null)

RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${GRN}[+]${NC} $1"; }
warn() { echo -e "${YLW}[!]${NC} $1"; }
alert() { echo -e "${RED}[ALERT]${NC} $1"; }

echo "============================================================"
echo " HARDENING — $(date)"
echo "============================================================"

# ============================================================
# 1. PHP — GLOBAL SECURITY SETTINGS
# ============================================================
log "=== 1. PHP Configuration ==="

for phpver in $PHP_VERSIONS; do
  PHP_INI_CLI="/etc/php/$phpver/cli/php.ini"
  PHP_INI_FPM="/etc/php/$phpver/fpm/php.ini"

  for inifile in "$PHP_INI_CLI" "$PHP_INI_FPM"; do
    if [ -f "$inifile" ]; then
      log "Configuring $inifile"

      # Disable remote file inclusion (allow_url_include is off by default;
      # allow_url_fopen is NOT touched — required by Guzzle/cURL/Laravel HTTP client)
      sed -i 's/^allow_url_include\s*=.*/allow_url_include = Off/' "$inifile"

      # Do not expose errors to users
      sed -i 's/^expose_php\s*=.*/expose_php = Off/' "$inifile"
      sed -i 's/^display_errors\s*=.*/display_errors = Off/' "$inifile"

      # Limit upload file size
      sed -i 's/^file_uploads\s*=.*/file_uploads = On/' "$inifile"
      sed -i 's/^upload_max_filesize\s*=.*/upload_max_filesize = 10M/' "$inifile"
      sed -i 's/^post_max_size\s*=.*/post_max_size = 12M/' "$inifile"

      log "✓ $inifile updated"
    fi
  done
done

# ============================================================
# 2. PHP-FPM POOLS — disable dangerous shell functions
# ============================================================
# NOTE: open_basedir is NOT set at the pool level — it breaks Laravel,
# Guzzle (curl_exec), and other legitimate functions. We only disable
# genuinely dangerous shell execution functions.
log "=== 2. PHP-FPM disable shell functions ==="

FPMRESTARTED=()

for phpver in $PHP_VERSIONS; do
  POOL_DIR="/etc/php/$phpver/fpm/pool.d"
  if [ -d "$POOL_DIR" ]; then
    for poolfile in "$POOL_DIR"/*.conf; do
      [ -f "$poolfile" ] || continue

      # Determine pool user
      POOL_USER=$(grep "^user\s*=" "$poolfile" 2>/dev/null | awk '{print $3}')

      if [[ " ${USERS[@]} " =~ " ${POOL_USER} " ]]; then
        warn "Configuring $poolfile (user: $POOL_USER)"

        # Disable only shell execution functions not needed by web apps.
        # curl_exec, exec, proc_open, parse_ini_file — NOT disabled (needed by Laravel/Guzzle/Intervention).
        if ! grep -q "disable_functions" "$poolfile"; then
          echo "" >> "$poolfile"
          echo "; Security: disable shell execution functions (safe subset)" >> "$poolfile"
          echo "php_admin_value[disable_functions] = shell_exec,system,passthru,popen,pcntl_exec,show_source" >> "$poolfile"
          echo "php_admin_flag[allow_url_include] = off" >> "$poolfile"
          log "✓ Security settings added to $poolfile"
        else
          warn "disable_functions already set in $poolfile — skipping"
        fi

        FPMRESTARTED+=("$phpver")
      fi
    done

    # Restart PHP-FPM to apply changes
    if [[ " ${FPMRESTARTED[@]} " =~ " $phpver " ]]; then
      systemctl restart php${phpver}-fpm && log "✓ php${phpver}-fpm restarted" || warn "Failed to restart php${phpver}-fpm"
    fi
  fi
done

# ============================================================
# 3. SSH HARDENING
# ============================================================
log "=== 3. SSH Hardening ==="

SSHD_CONFIG="/etc/ssh/sshd_config"
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup-$(date +%Y%m%d)"

# Disable password login (key auth only)
warn "WARNING: Disabling SSH password login. Make sure your key is in authorized_keys!"
warn "Press Enter to continue or Ctrl+C to abort..."
read -r

if grep -q "^PasswordAuthentication" "$SSHD_CONFIG"; then
  sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
else
  echo "PasswordAuthentication no" >> "$SSHD_CONFIG"
fi

# Disable root password login
if grep -q "^PermitRootLogin" "$SSHD_CONFIG"; then
  sed -i 's/^PermitRootLogin.*/PermitRootLogin prohibit-password/' "$SSHD_CONFIG"
else
  echo "PermitRootLogin prohibit-password" >> "$SSHD_CONFIG"
fi

# Additional SSH settings
grep -q "^MaxAuthTries" "$SSHD_CONFIG" || echo "MaxAuthTries 3" >> "$SSHD_CONFIG"
grep -q "^LoginGraceTime" "$SSHD_CONFIG" || echo "LoginGraceTime 30" >> "$SSHD_CONFIG"
grep -q "^ClientAliveInterval" "$SSHD_CONFIG" || echo "ClientAliveInterval 300" >> "$SSHD_CONFIG"
grep -q "^ClientAliveCountMax" "$SSHD_CONFIG" || echo "ClientAliveCountMax 2" >> "$SSHD_CONFIG"

# Validate config before restarting
sshd -t && systemctl reload sshd && log "✓ SSH restarted"

# ============================================================
# 4. FAIL2BAN
# ============================================================
log "=== 4. Fail2ban ==="

if ! command -v fail2ban-server &>/dev/null; then
  apt-get install -y fail2ban
fi

cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
destemail = root@localhost
action = %(action_mw)s

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
maxretry = 3
bantime = 86400

[nginx-http-auth]
enabled = true

[nginx-botsearch]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/*error.log
maxretry = 2

[php-url-fopen]
enabled = true
port    = http,https
filter  = php-url-fopen
logpath = /var/log/nginx/domains/*.log
maxretry = 2
EOF

# PHP attack filter
cat > /etc/fail2ban/filter.d/php-url-fopen.conf << 'EOF'
[Definition]
failregex = ^<HOST> .*(eval\(|base64_decode|shell_exec|passthru|system\(|cmd=|exec=)
ignoreregex =
EOF

systemctl enable fail2ban
systemctl restart fail2ban
log "✓ Fail2ban configured and started"

# ============================================================
# 5. FILE PERMISSIONS
# ============================================================
log "=== 5. File permissions ==="

for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    # NOTE: chown is intentionally NOT applied globally — HestiaCP manages
    # ownership of conf/ and other system directories.
    # Only restore permissions for each domain public_html.
    for domain_dir in "$WEB_DIR"/*/public_html; do
      [ -d "$domain_dir" ] || continue
      # Directories: 755 (including vendor/ and node_modules/ — execute bit needed for traversal)
      find "$domain_dir" -type d -exec chmod 755 {} \;
      # Files: 644 — EXCLUDE binaries in .bin/ dirs (they would lose execute bit)
      find "$domain_dir" -type f \
        -not -path "*/node_modules/.bin/*" \
        -not -path "*/vendor/bin/*" \
        -exec chmod 644 {} \;
      # Restore execute bit for node_modules/.bin and vendor/bin binaries
      find "$domain_dir/node_modules/.bin" -maxdepth 1 \( -type f -o -type l \) \
        -exec chmod +x {} \; 2>/dev/null || true
      find "$domain_dir/vendor/bin" -maxdepth 1 \( -type f -o -type l \) \
        -exec chmod +x {} \; 2>/dev/null || true
      # Owner — only public_html and below, do not touch conf/
      chown -R "$user:$user" "$domain_dir"
      log "✓ Permissions restored: $domain_dir"
    done
    # storage and bootstrap/cache must be writable
    for storage_dir in "$WEB_DIR"/*/public_html/storage "$WEB_DIR"/*/public_html/bootstrap/cache; do
      [ -d "$storage_dir" ] || continue
      find "$storage_dir" -type d -exec chmod 775 {} \;
      find "$storage_dir" -type f -exec chmod 664 {} \;
    done
  fi
done

# ============================================================
# 6. FILE CHANGE MONITORING (inotifywait)
# ============================================================
log "=== 6. File monitoring ==="

if ! command -v inotifywait &>/dev/null; then
  apt-get install -y inotify-tools
fi

# Detect the package directory (where this script lives)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MONITOR_SCRIPT="$SCRIPT_DIR/05-file-monitor.sh"

if [ ! -f "$MONITOR_SCRIPT" ]; then
  warn "05-file-monitor.sh not found in $SCRIPT_DIR — skipping file monitor setup"
else
  chmod +x "$MONITOR_SCRIPT"

  # Systemd service points directly to the repo script — no copy needed.
  # Updates via git pull automatically take effect on next service restart.
  cat > /etc/systemd/system/file-monitor.service << EOF
[Unit]
Description=Web Files Monitor (hestia-security)
After=network.target

[Service]
Type=simple
ExecStart=$MONITOR_SCRIPT
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable file-monitor
  systemctl restart file-monitor
  log "✓ File monitoring started — running from $MONITOR_SCRIPT"
  log "  Log: /var/log/file-changes.log"
fi

# ============================================================
# 7. NGINX — security headers + per-site conf_security blocks
# ============================================================
log "=== 7. Nginx security ==="

# Global security headers snippet
cat > /etc/nginx/snippets/security-headers.conf << 'EOF'
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
server_tokens off;
EOF

# Block direct .git access snippet
cat > /etc/nginx/snippets/deny-git.conf << 'EOF'
location ~ /\.(git|svn|hg|env) {
    deny all;
    return 404;
}
EOF

# Livewire rate-limit zone (add to nginx.conf http block if not present)
if ! grep -q "zone=livewire" /etc/nginx/nginx.conf 2>/dev/null; then
  sed -i '/http {/a\    limit_req_zone $binary_remote_addr zone=livewire:10m rate=30r/m;' /etc/nginx/nginx.conf
  log "Added livewire rate-limit zone to nginx.conf"
fi

# Generate per-site nginx.ssl.conf_security for every Laravel site
# (HestiaCP includes *.conf_security from the site conf directory automatically)
log "Generating per-site nginx security blocks..."
for user in "${USERS[@]}"; do
  for domain_dir in /home/$user/web/*/public_html; do
    [ -d "$domain_dir" ] || continue
    DOMAIN=$(basename "$(dirname "$domain_dir")")
    CONF_DIR="/home/$user/conf/web/$DOMAIN"
    [ -d "$CONF_DIR" ] || continue

    SSL_SEC="$CONF_DIR/nginx.ssl.conf_security"
    PLAIN_SEC="$CONF_DIR/nginx.conf_security"

    # Detect if this is a Laravel site
    IS_LARAVEL=false
    [ -f "$domain_dir/artisan" ] && IS_LARAVEL=true

    # Base security block (all sites)
    BASE_BLOCK='    # Block PHP/script execution in writable/static content directories
    # Covers .php, .php3-.php8, .phtml, .phar (nginx+PHP-FPM, no Apache needed)
    location ^~ /storage/ {
        try_files $uri $uri/ /index.php?$args;
        location ~* \.(php[3-8]?|phtml|phar)$ { deny all; return 403; }
    }
    location ^~ /build/ {
        try_files $uri $uri/ =404;
        location ~* \.(php[3-8]?|phtml|phar)$ { deny all; return 403; }
    }
    location ^~ /images/ {
        try_files $uri $uri/ =404;
        location ~* \.(php[3-8]?|phtml|phar)$ { deny all; return 403; }
    }
    location ^~ /img/ {
        try_files $uri $uri/ =404;
        location ~* \.(php[3-8]?|phtml|phar)$ { deny all; return 403; }
    }
    location ^~ /media/ {
        try_files $uri $uri/ =404;
        location ~* \.(php[3-8]?|phtml|phar)$ { deny all; return 403; }
    }
    location ^~ /uploads/ {
        try_files $uri $uri/ =404;
        location ~* \.(php[3-8]?|phtml|phar)$ { deny all; return 403; }
    }
    location ^~ /cache/ {
        try_files $uri $uri/ =404;
        location ~* \.(php[3-8]?|phtml|phar)$ { deny all; return 403; }
    }
    location ^~ /files/ {
        try_files $uri $uri/ =404;
        location ~* \.(php[3-8]?|phtml|phar)$ { deny all; return 403; }
    }

    # Block common attack and scanner paths
    location ~* ^/(_ignition|telescope|horizon|laravel-websockets)(/|$) {
        deny all;
        return 403;
    }
    location ~* ^/(vendor/phpunit|phpunit|lib/phpunit)(/|$) {
        deny all;
        return 403;
    }

    # Block sensitive file access (credentials, backups, editor swap files)
    location ~* \.(env|log|sql|bak|old|save|backup|swp|orig|tmp)$ {
        deny all;
        return 403;
    }

    # Block config backup file patterns regardless of extension chain
    location ~* /(wp-config|config|settings|database|credentials|secrets)\.(php|ini|txt|bak|old|save|backup)$ {
        deny all;
        return 403;
    }'

    # Livewire block (Laravel sites only) — must include try_files to pass to PHP-FPM
    LIVEWIRE_BLOCK='# Block bot exploitation of Livewire update endpoint
location = /livewire/update {
    if ($http_user_agent ~* "python-requests|curl|wget|libwww|Go-http") {
        return 403;
    }
    limit_req zone=livewire burst=30 nodelay;
    limit_req_status 429;
    try_files $uri /index.php?$query_string;
}

# Block Livewire file upload from bots (no referer = not a browser form)
location = /livewire/upload-file {
    if ($http_referer = "") {
        return 403;
    }
    try_files $uri /index.php?$query_string;
}'

    if $IS_LARAVEL; then
      printf '%s\n%s\n' "$BASE_BLOCK" "$LIVEWIRE_BLOCK" | sudo tee "$SSL_SEC" > /dev/null
      printf '%s\n%s\n' "$BASE_BLOCK" "$LIVEWIRE_BLOCK" | sudo tee "$PLAIN_SEC" > /dev/null
      log "✓ $DOMAIN — Laravel security block written (with Livewire)"
    else
      printf '%s\n' "$BASE_BLOCK" | sudo tee "$SSL_SEC" > /dev/null
      printf '%s\n' "$BASE_BLOCK" | sudo tee "$PLAIN_SEC" > /dev/null
      log "✓ $DOMAIN — base security block written"
    fi
  done
done

nginx -t && systemctl reload nginx && log "✓ Nginx reloaded"

# ============================================================
# 8. AUTOMATIC SECURITY UPDATES
# ============================================================
log "=== 8. Automatic security updates ==="

apt-get install -y unattended-upgrades apt-listchanges
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF

dpkg-reconfigure -f noninteractive unattended-upgrades
log "✓ Automatic security updates enabled"

# ============================================================
# 9. RESTART PHP-FPM
# ============================================================
log "=== 9. Restart services ==="
for phpver in $PHP_VERSIONS; do
  systemctl restart "php$phpver-fpm" 2>/dev/null && log "✓ php$phpver-fpm restarted"
done

echo ""
echo "============================================================"
log "HARDENING COMPLETE — $(date)"
echo "============================================================"
echo ""
warn "ADDITIONAL MANUAL STEPS:"
echo "1. Add 'include snippets/security-headers.conf;' and 'include snippets/deny-git.conf;'"
echo "   to each site's nginx config at /home/*/conf/web/nginx.conf"
echo ""
echo "2. Configure the backup/restore script (04-git-auto-restore.sh)"
echo ""
echo "3. Change all passwords:"
echo "   - SSH users"
echo "   - HestiaCP admin"
echo "   - FTP users (v-list-web-domain-ftp)"
echo "   - MySQL/PostgreSQL databases"
echo ""
echo "4. Check HestiaCP for updates:"
echo "   apt list --upgradable | grep hestia"
echo "   bash /usr/local/hestia/install/upgrade/upgrade.sh"
echo ""
echo "5. Install ClamAV for malware scanning:"
echo "   apt-get install clamav clamav-daemon"
echo "   freshclam && clamscan -r /home --infected --remove"
