#!/bin/bash
# =============================================================================
# HARDENING SCRIPT — меры защиты от повторного заражения
# Запускать от root: sudo bash 03-hardening.sh 2>&1 | tee hardening-report.txt
#
# ВНИМАНИЕ: Тестируйте в staging перед применением в production!
# Некоторые настройки могут нарушить работу приложений.
# =============================================================================

# Авто-определение пользователей HestiaCP (или задайте вручную)
# USERS=("user1" "user2")   # раскомментируйте чтобы переопределить
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
# 1. PHP — ГЛОБАЛЬНЫЕ НАСТРОЙКИ БЕЗОПАСНОСТИ
# ============================================================
log "=== 1. Настройка PHP ==="

for phpver in $PHP_VERSIONS; do
  PHP_INI_CLI="/etc/php/$phpver/cli/php.ini"
  PHP_INI_FPM="/etc/php/$phpver/fpm/php.ini"

  for inifile in "$PHP_INI_CLI" "$PHP_INI_FPM"; do
    if [ -f "$inifile" ]; then
      log "Настраиваем $inifile"

      # Запрет включения удалённых файлов (allow_url_include выключен по умолчанию;
      # allow_url_fopen НЕ трогаем — он нужен Guzzle/cURL/Laravel HTTP клиенту)
      sed -i 's/^allow_url_include\s*=.*/allow_url_include = Off/' "$inifile"

      # Не показывать ошибки пользователям
      sed -i 's/^expose_php\s*=.*/expose_php = Off/' "$inifile"
      sed -i 's/^display_errors\s*=.*/display_errors = Off/' "$inifile"

      # Ограничение размера загружаемых файлов
      sed -i 's/^file_uploads\s*=.*/file_uploads = On/' "$inifile"
      sed -i 's/^upload_max_filesize\s*=.*/upload_max_filesize = 10M/' "$inifile"
      sed -i 's/^post_max_size\s*=.*/post_max_size = 12M/' "$inifile"

      log "✓ $inifile обновлён"
    fi
  done
done

# ============================================================
# 2. PHP-FPM ПУЛЫ — отключаем shell-функции (безопасный набор)
# ============================================================
# ВАЖНО: open_basedir НЕ применяется на уровне пулов — это ломает Laravel,
# Guzzle (curl_exec), и другие легитимные функции. Ограничиваем только
# реально опасные функции выполнения shell-команд.
log "=== 2. PHP-FPM disable shell functions ==="

FPMRESTARTED=()

for phpver in $PHP_VERSIONS; do
  POOL_DIR="/etc/php/$phpver/fpm/pool.d"
  if [ -d "$POOL_DIR" ]; then
    for poolfile in "$POOL_DIR"/*.conf; do
      [ -f "$poolfile" ] || continue

      # Определяем пользователя пула
      POOL_USER=$(grep "^user\s*=" "$poolfile" 2>/dev/null | awk '{print $3}')

      if [[ " ${USERS[@]} " =~ " ${POOL_USER} " ]]; then
        warn "Настраиваем $poolfile (user: $POOL_USER)"

        # Запрещаем только shell-функции, которые не нужны веб-приложениям.
        # curl_exec, exec, proc_open, parse_ini_file — НЕ отключаем (нужны Laravel/Guzzle/Intervention).
        if ! grep -q "disable_functions" "$poolfile"; then
          echo "" >> "$poolfile"
          echo "; Security: disable shell execution functions (safe subset)" >> "$poolfile"
          echo "php_admin_value[disable_functions] = shell_exec,system,passthru,popen,pcntl_exec,show_source" >> "$poolfile"
          echo "php_admin_flag[allow_url_include] = off" >> "$poolfile"
          log "✓ Защита добавлена в $poolfile"
        else
          warn "disable_functions уже настроен в $poolfile — пропускаем"
        fi

        FPMRESTARTED+=("$phpver")
      fi
    done

    # Перезапускаем PHP-FPM чтобы изменения вступили в силу
    if [[ " ${FPMRESTARTED[@]} " =~ " $phpver " ]]; then
      systemctl restart php${phpver}-fpm && log "✓ php${phpver}-fpm перезапущен" || warn "Не удалось перезапустить php${phpver}-fpm"
    fi
  fi
done

# ============================================================
# 3. SSH HARDENING
# ============================================================
log "=== 3. SSH Hardening ==="

SSHD_CONFIG="/etc/ssh/sshd_config"
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup-$(date +%Y%m%d)"

# Запрет входа по паролю (только по ключу)
warn "ВНИМАНИЕ: Запрет входа по паролю SSH. Убедитесь что ваш ключ добавлен в authorized_keys!"
warn "Нажмите Enter для продолжения или Ctrl+C для отмены..."
read -r

if grep -q "^PasswordAuthentication" "$SSHD_CONFIG"; then
  sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
else
  echo "PasswordAuthentication no" >> "$SSHD_CONFIG"
fi

# Запрет входа root по паролю
if grep -q "^PermitRootLogin" "$SSHD_CONFIG"; then
  sed -i 's/^PermitRootLogin.*/PermitRootLogin prohibit-password/' "$SSHD_CONFIG"
else
  echo "PermitRootLogin prohibit-password" >> "$SSHD_CONFIG"
fi

# Другие SSH настройки
grep -q "^MaxAuthTries" "$SSHD_CONFIG" || echo "MaxAuthTries 3" >> "$SSHD_CONFIG"
grep -q "^LoginGraceTime" "$SSHD_CONFIG" || echo "LoginGraceTime 30" >> "$SSHD_CONFIG"
grep -q "^ClientAliveInterval" "$SSHD_CONFIG" || echo "ClientAliveInterval 300" >> "$SSHD_CONFIG"
grep -q "^ClientAliveCountMax" "$SSHD_CONFIG" || echo "ClientAliveCountMax 2" >> "$SSHD_CONFIG"

# Проверяем конфиг перед перезапуском
sshd -t && systemctl reload sshd && log "✓ SSH перезапущен"

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
logpath = /home/*/web/*/log/access.log
maxretry = 2
EOF

# Фильтр для PHP атак
cat > /etc/fail2ban/filter.d/php-url-fopen.conf << 'EOF'
[Definition]
failregex = ^<HOST> .*(eval\(|base64_decode|shell_exec|passthru|system\(|cmd=|exec=)
ignoreregex =
EOF

systemctl enable fail2ban
systemctl restart fail2ban
log "✓ Fail2ban настроен и запущен"

# ============================================================
# 5. НАСТРОЙКА ПРАВ ФАЙЛОВ
# ============================================================
log "=== 5. Права файлов ==="

for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    # ВАЖНО: chown намеренно НЕ применяется глобально — HestiaCP управляет
    # владельцами conf/ и других системных директорий.
    # Восстанавливаем права только для public_html каждого домена.
    for domain_dir in "$WEB_DIR"/*/public_html; do
      [ -d "$domain_dir" ] || continue
      # Директории: 755 (включая vendor/ и node_modules/ — нужен execute bit для traversal)
      find "$domain_dir" -type d -exec chmod 755 {} \;
      # Файлы: 644 — ИСКЛЮЧАЕМ бинарники в .bin/ директориях (теряют execute bit)
      find "$domain_dir" -type f \
        -not -path "*/node_modules/.bin/*" \
        -not -path "*/vendor/bin/*" \
        -exec chmod 644 {} \;
      # Восстанавливаем execute bit для бинарников node_modules/.bin и vendor/bin
      find "$domain_dir/node_modules/.bin" -maxdepth 1 \( -type f -o -type l \) \
        -exec chmod +x {} \; 2>/dev/null || true
      find "$domain_dir/vendor/bin" -maxdepth 1 \( -type f -o -type l \) \
        -exec chmod +x {} \; 2>/dev/null || true
      # Владелец — только public_html и ниже, не трогаем conf/
      chown -R "$user:$user" "$domain_dir"
      log "✓ Права восстановлены: $domain_dir"
    done
    # storage и bootstrap/cache должны быть writable
    for storage_dir in "$WEB_DIR"/*/public_html/storage "$WEB_DIR"/*/public_html/bootstrap/cache; do
      [ -d "$storage_dir" ] || continue
      find "$storage_dir" -type d -exec chmod 775 {} \;
      find "$storage_dir" -type f -exec chmod 664 {} \;
    done
  fi
done

# ============================================================
# 6. МОНИТОРИНГ ИЗМЕНЕНИЙ ФАЙЛОВ (inotifywait)
# ============================================================
log "=== 6. Мониторинг файлов ==="

if ! command -v inotifywait &>/dev/null; then
  apt-get install -y inotify-tools
fi

# Создаём systemd сервис для мониторинга
cat > /etc/systemd/system/file-monitor.service << 'EOF'
[Unit]
Description=Web Files Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/file-monitor.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > /usr/local/bin/file-monitor.sh << 'SCRIPT'
#!/bin/bash
WATCH_DIRS=""
for user in ridecals grinev alisa vmc; do
  [ -d "/home/$user/web" ] && WATCH_DIRS="$WATCH_DIRS /home/$user/web"
done

inotifywait -m -r -e create,modify,moved_to \
  --include '\.(php|js|html|sh|py|pl|phtml)$' \
  $WATCH_DIRS 2>/dev/null \
  | while read dir event file; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $event: ${dir}${file}" \
      >> /var/log/file-changes.log
    # Алерт если изменён PHP файл не через git
    logger -t "file-monitor" "ALERT: File changed: ${dir}${file} ($event)"
  done
SCRIPT

chmod +x /usr/local/bin/file-monitor.sh
systemctl daemon-reload
systemctl enable file-monitor
systemctl start file-monitor
log "✓ Мониторинг файлов запущен (логи: /var/log/file-changes.log)"

# ============================================================
# 7. НАСТРОЙКА NGINX — блокировка исполнения PHP в upload-директориях
# ============================================================
log "=== 7. Nginx security headers ==="

cat > /etc/nginx/snippets/security-headers.conf << 'EOF'
# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

# Скрываем версию nginx
server_tokens off;

# Блокировка исполнения PHP в папках загрузок
# Добавьте в конфиг каждого сайта:
# location ~* /(?:uploads|files|storage|media)/.*\.php$ {
#     deny all;
# }
EOF

# Блокировка доступа к .git папкам
cat > /etc/nginx/snippets/deny-git.conf << 'EOF'
# Запрет доступа к .git и другим служебным папкам
location ~ /\.(git|svn|hg|env|htaccess|htpasswd) {
    deny all;
    return 404;
}
location ~ /vendor/ {
    deny all;
    return 404;
}
EOF

warn "Добавьте в nginx конфиги сайтов:"
echo "  include snippets/security-headers.conf;"
echo "  include snippets/deny-git.conf;"

nginx -t && systemctl reload nginx && log "✓ Nginx перезапущен"

# ============================================================
# 8. АВТОМАТИЧЕСКОЕ ОБНОВЛЕНИЕ БЕЗОПАСНОСТИ
# ============================================================
log "=== 8. Автообновления безопасности ==="

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
log "✓ Автообновления безопасности включены"

# ============================================================
# 9. ПЕРЕЗАПУСК PHP-FPM
# ============================================================
log "=== 9. Перезапуск сервисов ==="
for phpver in $PHP_VERSIONS; do
  systemctl restart "php$phpver-fpm" 2>/dev/null && log "✓ php$phpver-fpm перезапущен"
done

echo ""
echo "============================================================"
log "HARDENING ЗАВЕРШЁН — $(date)"
echo "============================================================"
echo ""
warn "ДОПОЛНИТЕЛЬНЫЕ РУЧНЫЕ ШАГИ:"
echo "1. Добавьте 'include snippets/security-headers.conf;' и 'include snippets/deny-git.conf;'"
echo "   в конфиги каждого nginx сайта /home/*/conf/web/nginx.conf"
echo ""
echo "2. Настройте backup сценарий (04-git-auto-restore.sh)"
echo ""
echo "3. Смените все пароли:"
echo "   - SSH пользователей"
echo "   - HestiaCP admin"
echo "   - FTP пользователей (v-list-web-domain-ftp)"
echo "   - Базы данных MySQL/PostgreSQL"
echo ""
echo "4. Проверьте Хестию на обновления:"
echo "   apt list --upgradable | grep hestia"
echo "   bash /usr/local/hestia/install/upgrade/upgrade.sh"
echo ""
echo "5. Установите ClamAV для сканирования:"
echo "   apt-get install clamav clamav-daemon"
echo "   freshclam && clamscan -r /home --infected --remove"
