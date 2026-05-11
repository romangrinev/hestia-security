#!/bin/bash
# =============================================================================
# SECURITY AUDIT SCRIPT — обнаружение вектора заражения
# Запускать от root: sudo bash 01-security-audit.sh 2>&1 | tee audit-report.txt
# =============================================================================

# Авто-определение пользователей HestiaCP (или задайте вручную в /etc/security-audit.env)
# USERS=("user1" "user2")   # раскомментируйте чтобы переопределить
if [ -z "${USERS+x}" ]; then
  if command -v v-list-users &>/dev/null; then
    mapfile -t USERS < <(sudo /usr/local/hestia/bin/v-list-users plain 2>/dev/null | awk 'NR>2 && $1 != "admin" {print $1}')
  else
    mapfile -t USERS < <(ls /home/ | grep -vE '^(admin|lost\+found|ubuntu)$')
  fi
fi

REPORT_DIR="/root/security-audit-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"

# IP с которого разрешён SSH (определяем из iptables, или задайте вручную)
TRUSTED_SSH_IP=$(iptables -L INPUT -n --line-numbers 2>/dev/null \
  | awk '$3=="ACCEPT" && $5=="tcp" && /dpt:22/' \
  | awk '{print $8}' | grep -v '0.0.0.0' | head -1)
[ -z "$TRUSTED_SSH_IP" ] && TRUSTED_SSH_IP="67.185.203.213"

# --- RESEND НАСТРОЙКИ ---
# Замените на ваши значения или вынесите в /etc/security-audit.env
RESEND_API_KEY="re_ВАШ_API_КЛЮЧ"
RESEND_FROM="security@ВАШ_ДОМЕН.com"
RESEND_TO="admin@ВАШ_EMAIL.com"
HOSTNAME="$(hostname -f)"
ALERT_SUBJECTS=()   # накапливаем темы алертов
ALERT_BODIES=()     # накапливаем тела алертов

# Загружаем конфиг из файла если есть (чтобы не хранить ключи в скрипте)
[ -f /etc/security-audit.env ] && source /etc/security-audit.env

# Отправка письма через Resend API
# $1 — тема, $2 — путь к файлу с телом письма (plain text)
send_resend_email() {
  local SUBJECT="$1"
  local BODY_FILE="$2"
  local TMPJSON
  TMPJSON=$(mktemp /tmp/resend-body-XXXXXX.json)

  # Используем python3 для корректного JSON-кодирования (избегаем "Argument list too long")
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
    log "Email отправлен через Resend: $SUBJECT"
  else
    warn "Ошибка отправки email (HTTP $HTTP_CODE): $(cat /tmp/resend-response.json 2>/dev/null)"
  fi
}

# Добавить алерт в очередь (будет отправлен одним письмом в конце)
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

# --- 1. СИСТЕМНАЯ ИНФОРМАЦИЯ ---
log "=== 1. СИСТЕМНАЯ ИНФОРМАЦИЯ ==="
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME)"
echo "Kernel: $(uname -r)"
echo "Uptime: $(uptime)"
echo "HestiaCP version: $(cat /usr/local/hestia/conf/hestia.conf 2>/dev/null | grep VERSION || echo 'не найдено')"

# --- 2. ПОСЛЕДНИЕ ВХОДЫ НА СЕРВЕР ---
log "=== 2. ПОСЛЕДНИЕ ВХОДЫ SSH (last 50) ==="
last -n 50 | tee "$REPORT_DIR/last-logins.txt"

# Неудачные SSH входы — показываем только счётчик (fail2ban защищает)
grep "Failed password" /var/log/auth.log 2>/dev/null \
  | tee "$REPORT_DIR/failed-ssh-logins.txt" > /dev/null
FAILED_COUNT=$(wc -l < "$REPORT_DIR/failed-ssh-logins.txt")
if [ "$FAILED_COUNT" -gt 10 ]; then
  warn "Неудачных попыток входа SSH в auth.log: $FAILED_COUNT (fail2ban активен)"
else
  log "✓ Неудачных SSH попыток: $FAILED_COUNT"
fi

# Принятые пароли — алерт только для IP не из вайтлиста
grep "Accepted password" /var/log/auth.log 2>/dev/null \
  | tee "$REPORT_DIR/accepted-password-logins.txt" > /dev/null
PASSWD_FROM_UNKNOWN=$(grep "Accepted password" /var/log/auth.log 2>/dev/null \
  | grep -v "$TRUSTED_SSH_IP")
if [ -n "$PASSWD_FROM_UNKNOWN" ]; then
  warn "Принятые пароли с незнакомых IP (ПОДОЗРИТЕЛЬНО):"
  echo "$PASSWD_FROM_UNKNOWN" | tee -a "$REPORT_DIR/accepted-password-logins.txt"
  queue_alert "SSH: принятые пароли с неизвестных IP" "$PASSWD_FROM_UNKNOWN"
else
  log "✓ Принятых паролей с незнакомых IP нет (только $TRUSTED_SSH_IP или ключи)"
fi

# --- 3. АКТИВНЫЕ СЕССИИ И ПРОЦЕССЫ ---
log "=== 3. АКТИВНЫЕ СЕССИИ ==="
w
echo ""
log "Подозрительные процессы (PHP/Python/Perl/curl/wget от веб-пользователей):"
ps aux | grep -E "(php|python|perl|wget|curl|nc |ncat|bash -i|sh -i)" \
  | grep -v grep | tee "$REPORT_DIR/suspicious-processes.txt"

# --- 4. СЕТЕВЫЕ СОЕДИНЕНИЯ ---
log "=== 4. НЕСТАНДАРТНЫЕ СЕТЕВЫЕ СОЕДИНЕНИЯ ==="
echo "Слушающие порты:"
ss -tlnp | tee "$REPORT_DIR/listening-ports.txt"

EXT_CONNS=$(ss -tnp | grep ESTAB | grep -vE ':80 |:443 |:22 |:3306 |:8083 ')
if [ -n "$EXT_CONNS" ]; then
  warn "Активные внешние соединения (не 80/443/22/3306):"
  echo "$EXT_CONNS" | tee "$REPORT_DIR/external-connections.txt"
else
  log "✓ Нестандартных внешних соединений нет"
fi

# --- 4b. ПРОВЕРКА IPTABLES ---
log "=== 4b. ПРОВЕРКА IPTABLES ==="
IPTABLES_RULES=$(iptables -L INPUT -n --line-numbers 2>/dev/null)
echo "$IPTABLES_RULES" | tee "$REPORT_DIR/iptables-input.txt"

# Проверяем: SSH (порт 22) не должен быть открыт для 0.0.0.0/0 как SOURCE
# Используем awk чтобы проверить именно колонку source (5), а не destination
SSH_OPEN=$(iptables -L INPUT -n --line-numbers 2>/dev/null \
  | awk '$2=="ACCEPT" && $5=="0.0.0.0/0"' | grep 'dpt:22')
if [ -n "$SSH_OPEN" ]; then
  queue_alert "IPTABLES: SSH открыт для всего мира!" "Правило разрешает SSH с 0.0.0.0/0 — следует ограничить по IP:\n$SSH_OPEN"
else
  log "✓ SSH ограничен по IP (0.0.0.0/0 не разрешён как source)"
fi

# Проверяем: политика INPUT
INPUT_POLICY=$(echo "$IPTABLES_RULES" | grep 'Chain INPUT' | grep -o 'policy [A-Z]*')
if echo "$INPUT_POLICY" | grep -q 'DROP\|REJECT'; then
  log "✓ Политика INPUT: $INPUT_POLICY (безопасно)"
else
  queue_alert "IPTABLES: политика INPUT=$INPUT_POLICY" "Рекомендуется policy DROP. Текущая политика: $INPUT_POLICY"
fi

# Проверяем: MySQL/MariaDB не открыт наружу (source 0.0.0.0/0)
MYSQL_OPEN=$(iptables -L INPUT -n --line-numbers 2>/dev/null \
  | awk '$2=="ACCEPT" && $5=="0.0.0.0/0"' | grep 'dpt:3306')
if [ -n "$MYSQL_OPEN" ]; then
  queue_alert "IPTABLES: MySQL открыт для всего мира!" "Правило разрешает подключение к MySQL с 0.0.0.0/0:\n$MYSQL_OPEN"
else
  log "✓ MySQL не доступен извне"
fi

# Проверяем: есть ли fail2ban цепочки
if iptables -L f2b-sshd -n &>/dev/null; then
  log "✓ fail2ban активен (цепочка f2b-sshd найдена)"
else
  queue_alert "fail2ban не активен" "Цепочка f2b-sshd не найдена в iptables — возможно fail2ban не запущен"
fi

# --- 5. CRON-ЗАДАЧИ ВСЕХ ПОЛЬЗОВАТЕЛЕЙ ---
log "=== 5. CRON-ЗАДАЧИ ==="
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
      queue_alert "Cron пользователя $user" "$CRON"
    fi
  fi
done

echo "Cron в /var/spool/cron:"
ls -la /var/spool/cron/crontabs/ 2>/dev/null

# --- 6. ПОИСК МОДИФИЦИРОВАННЫХ ФАЙЛОВ (последние 14 дней) ---
log "=== 6. ФАЙЛЫ ИЗМЕНЁННЫЕ ЗА 14 ДНЕЙ ==="
# Исключаем безопасные шумные пути:
#   storage/framework/views/  — скомпилированные Blade-шаблоны
#   storage/framework/cache/  — Laravel bootstrap кэш
#   document_errors/          — страницы ошибок HestiaCP (меняются при hardening)
#   public/js/filament/       — Filament JS ассеты (npm build output)
#   public/css/filament/      — Filament CSS ассеты
#   public/build/             — Vite build output
#   node_modules/vendor/      — зависимости
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
      warn "Изменённые PHP/JS файлы у пользователя $user:"
      echo "$MODIFIED" | tee -a "$REPORT_DIR/modified-files-$user.txt"
    fi
  fi
done

# --- 7. ПОИСК ВЕБ-ШЕЛЛОВ И БЭКДОРОВ ---
log "=== 7. ПОИСК ВЕБ-ШЕЛЛОВ И БЭКДОРОВ ==="
# ВАЖНО: vendor/, node_modules/ исключены из поиска — там легитимный код.
# Ищем только в public_html корне, public/, storage/, и прочих не-vendor путях.

# Паттерны для PHP файлов (исключая vendor/ и node_modules/)
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

# Подозрительные имена файлов-шеллов (ищем везде включая vendor/)
# Только уникальные имена, явно не встречающиеся в легитимном коде
SHELL_FILENAMES=(
  # Known webshell names
  'c99.php' 'r57.php' 'b374k.php' 'wso.php' 'alfa.php' 'alfacgiapi.php'
  'FilesMan.php' 'indoxploit.php' 'symlink.php' 'cpanel.php'
  'adminfuns.php' 'wp-conffq.php' 'wp-headre.php' 'shc.php'
  # Specific shells found in this incident
  'kozlakola.php' 'b-1.php'
)

# Короткие имена — подозрительны вне vendor/node_modules/storage/framework
SHELL_FILENAMES_SHORT=(
  'b.php' 'c.php' 'x.php' 'z.php' 'a.php' 'k.php'
)

for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  FOUND_FILE="$REPORT_DIR/webshells-$user.txt"
  if [ -d "$WEB_DIR" ]; then
    echo "" > "$FOUND_FILE"

    # 1. Поиск вредоносных паттернов в PHP файлах, исключая vendor/ и node_modules/
    for pattern in "${PHP_WEBSHELL_PATTERNS[@]}"; do
      RESULTS=$(grep -rl "$pattern" "$WEB_DIR" 2>/dev/null \
        | grep -E '\.(php|php5|php7|phtml|phar)$' \
        | grep -v '/.git/' \
        | grep -v '/vendor/' \
        | grep -v '/node_modules/')
      if [ -n "$RESULTS" ]; then
        DETAILS=""
        while IFS= read -r fpath; do
          FMETA=$(stat -c "  mtime=%y owner=%U size=%s" "$fpath" 2>/dev/null)
          FPREVIEW=$(grep -m1 "$pattern" "$fpath" 2>/dev/null | head -c 200)
          DETAILS+="FILE: $fpath\n$FMETA\n  Match: $FPREVIEW\n\n"
        done <<< "$RESULTS"
        queue_alert "БЭКДОР у $user (паттерн: $pattern)" "$DETAILS"
        echo "$RESULTS" | tee -a "$FOUND_FILE"
      fi
    done

    # 2. Поиск по подозрительным именам файлов (везде)
    for fname in "${SHELL_FILENAMES[@]}"; do
      RESULTS=$(find "$WEB_DIR" -name "$fname" 2>/dev/null | grep -v '/.git/')
      if [ -n "$RESULTS" ]; then
        queue_alert "ПОДОЗРИТЕЛЬНЫЙ ФАЙЛ у $user ($fname)" "$RESULTS"
        echo "$RESULTS" | tee -a "$FOUND_FILE"
      fi
    done

    # 2b. Короткие имена файлов — подозрительны вне vendor/node_modules/storage/framework
    for fname in "${SHELL_FILENAMES_SHORT[@]}"; do
      RESULTS=$(find "$WEB_DIR" -name "$fname" 2>/dev/null \
        | grep -v '/.git/' \
        | grep -v '/vendor/' \
        | grep -v '/node_modules/' \
        | grep -v '/storage/framework/')
      if [ -n "$RESULTS" ]; then
        queue_alert "ПОДОЗРИТЕЛЬНЫЙ ФАЙЛ (короткое имя) у $user ($fname)" "$RESULTS"
        echo "$RESULTS" | tee -a "$FOUND_FILE"
      fi
    done

    # 3. PHP-файлы с hex-именами (8+ hex символов) — характерно для дропперов
    # Исключаем storage/framework/views/ — там легитимные скомпилированные Blade-шаблоны Laravel
    RESULTS=$(find "$WEB_DIR" -type f -name "*.php" 2>/dev/null \
      | grep -E '/[0-9a-f]{8,}\.php$' \
      | grep -v '/.git/' \
      | grep -v '/storage/framework/views/' \
      | grep -v '/vendor/')
    if [ -n "$RESULTS" ]; then
      queue_alert "PHP ДРОППЕР (hex-имя) у $user" "$RESULTS"
      echo "$RESULTS" | tee -a "$FOUND_FILE"
    fi

    # 4. cache.php ТОЛЬКО в подозрительных местах (не в /config/, /wp-includes/, /themes/)
    # Легитимные места: /config/cache.php (Laravel), /wp-includes/cache.php (WP core),
    #   /wp-content/themes/*/cache.php (темы)
    # Подозрительные: /public/, /storage/, /upload/, /assets/, /build/, /tmp/
    RESULTS=$(find "$WEB_DIR" -name "cache.php" 2>/dev/null \
      | grep -v '/vendor/' \
      | grep -v '/node_modules/' \
      | grep -v '/.git/' \
      | grep -v '/config/cache\.php' \
      | grep -v '/wp-includes/' \
      | grep -v '/wp-content/themes/' \
      | grep -E '/(public|storage|upload|assets|build|tmp|cache|files)/')
    if [ -n "$RESULTS" ]; then
      queue_alert "WEBSHELL cache.php у $user" "$RESULTS"
      echo "$RESULTS" | tee -a "$FOUND_FILE"
    fi
  fi
done

# 5. Специфично: cron с .X11-linux (майнер/бэкдор)
for user in "${USERS[@]}"; do
  CRON_XLINUX=$(crontab -u "$user" -l 2>/dev/null | grep '\.X11-linux')
  if [ -n "$CRON_XLINUX" ]; then
    queue_alert "МАЙНЕР В CRON у $user (.X11-linux)" "$CRON_XLINUX"
  fi
done

# --- 7b. НУЛЕВАЯ ТЕРПИМОСТЬ: PHP В ДИРЕКТОРИЯХ ЗАГРУЗКИ ---
log "=== 7b. PHP-ФАЙЛЫ В ДИРЕКТОРИЯХ ЗАГРУЗКИ (нулевая терпимость) ==="
# ПРАВИЛО: PHP-файлы в этих директориях ВСЕГДА являются вредоносными.
# Легитимный код никогда не размещает .php файлы в upload-директориях.
# Проверяем ВСЕ файлы независимо от даты изменения.

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
      queue_alert "⚠ PHP В UPLOAD-ДИРЕКТОРИИ у $user" "$DETAILS"
    fi
  done
done
log "✓ Сканирование upload-директорий завершено"

# --- 8. ФАЙЛЫ С ОПАСНЫМИ ПРАВАМИ ---
log "=== 8. ФАЙЛЫ С 777/SUID ПРАВАМИ ==="
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    FILES_777=$(find "$WEB_DIR" -perm -0777 -type f 2>/dev/null | head -20)
    DIRS_777=$(find "$WEB_DIR" -perm -0777 -type d 2>/dev/null | head -20)
    if [ -n "$FILES_777" ]; then
      warn "777 файлы у $user:"
      echo "$FILES_777" | tee -a "$REPORT_DIR/perms-$user.txt"
      queue_alert "777 файлы у $user" "$FILES_777"
    fi
    if [ -n "$DIRS_777" ]; then
      warn "777 директории у $user:"
      echo "$DIRS_777" | tee -a "$REPORT_DIR/perms-$user.txt"
      queue_alert "777 директории у $user" "$DIRS_777"
    fi
  fi
done

# SUID во всей системе — алертим только на нестандартные файлы
# Стандартные системные SUID пути исключаем
SUID_STANDARD='/usr/bin|/usr/sbin|/bin|/sbin|/usr/lib/openssh|/usr/lib/dbus|/usr/libexec/polkit|/usr/lib/mysql/plugin/auth_pam'
SUID_SUSPICIOUS=$(find / -perm /4000 -type f 2>/dev/null \
  | grep -vE "$SUID_STANDARD")
find / -perm /4000 -type f 2>/dev/null > "$REPORT_DIR/suid-files.txt"
if [ -n "$SUID_SUSPICIOUS" ]; then
  warn "НЕСТАНДАРТНЫЕ SUID файлы (требуют проверки):"
  echo "$SUID_SUSPICIOUS" | tee -a "$REPORT_DIR/suid-files.txt"
  queue_alert "Нестандартные SUID файлы" "$SUID_SUSPICIOUS"
else
  log "✓ SUID файлы — только стандартные системные"
fi

# --- 9. ЛОГИ WEB-СЕРВЕРА — ищем подозрительные запросы ---
log "=== 9. ПОДОЗРИТЕЛЬНЫЕ ЗАПРОСЫ В NGINX/APACHE ЛОГАХ ==="
SUSPICIOUS_PATTERNS="(eval|base64_decode|system\(|passthru|shell_exec|union.*select|\.\.\/|etc\/passwd|cmd=|exec=|wget |curl |chmod |/tmp/|/dev/shm)"

for user in "${USERS[@]}"; do
  for logfile in /home/$user/web/*/log/access.log /home/$user/web/*/log/error.log; do
    if [ -f "$logfile" ]; then
      HITS=$(grep -iE "$SUSPICIOUS_PATTERNS" "$logfile" 2>/dev/null | wc -l)
      if [ "$HITS" -gt 0 ]; then
        HITS_SAMPLE=$(grep -iE "$SUSPICIOUS_PATTERNS" "$logfile" 2>/dev/null | tail -20)
        queue_alert "Подозрительные запросы в $logfile ($HITS штук)" "$HITS_SAMPLE"
        echo "$HITS_SAMPLE" | tee -a "$REPORT_DIR/suspicious-requests-$user.txt"
      fi
    fi
  done
done

# --- 10. PHP КОНФИГУРАЦИЯ ---
log "=== 10. PHP КОНФИГУРАЦИЯ ==="
php -i 2>/dev/null | grep -E "(disable_functions|open_basedir|allow_url_fopen|allow_url_include|expose_php|upload_tmp_dir)" \
  | tee "$REPORT_DIR/php-config.txt"

# Проверка PHP-FPM пулов — алертим только на пулы БЕЗ open_basedir
POOLS_NO_BASEDIR=$(grep -rL "open_basedir" /etc/php/*/fpm/pool.d/*.conf 2>/dev/null \
  | grep -v dummy.conf | grep -v '/www.conf')  # www.conf — HestiaCP internal (hestiamail)
if [ -n "$POOLS_NO_BASEDIR" ]; then
  warn "PHP-FPM пулы БЕЗ open_basedir (риск выхода за пределы домашней директории):"
  echo "$POOLS_NO_BASEDIR" | tee -a "$REPORT_DIR/php-fpm-pools.txt"
  queue_alert "PHP-FPM пулы без open_basedir" "$POOLS_NO_BASEDIR"
else
  log "✓ Все PHP-FPM пулы имеют open_basedir"
fi

# --- 11. ПРОВЕРКА .htaccess И .user.ini НА ИНЪЕКЦИИ ---
log "=== 11. ПРОВЕРКА .htaccess И .user.ini ==="
# Ищем только подозрительные паттерны, а не дампим весь контент
HTACCESS_BAD_PATTERNS='php_value auto_prepend|SetHandler.*cgi|AddHandler.*php|RewriteRule.*eval|base64_decode|system\(|shell_exec'
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    # Сохраняем все htaccess в отчёт тихо
    find "$WEB_DIR" -name ".htaccess" -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null \
      >> "$REPORT_DIR/htaccess-$user.txt"
    # Алертим только на подозрительные паттерны
    HTACCESS_SUSPICIOUS=$(grep -rniE "$HTACCESS_BAD_PATTERNS" \
      $(find "$WEB_DIR" -name ".htaccess" 2>/dev/null) 2>/dev/null)
    if [ -n "$HTACCESS_SUSPICIOUS" ]; then
      warn "Подозрительные .htaccess у $user:"
      echo "$HTACCESS_SUSPICIOUS" | tee -a "$REPORT_DIR/htaccess-$user.txt"
      queue_alert ".htaccess инъекция у $user" "$HTACCESS_SUSPICIOUS"
    fi
    # .user.ini — сохраняем тихо, алертим только на подозрительные записи
    find "$WEB_DIR" -name ".user.ini" -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null \
      >> "$REPORT_DIR/user-ini-$user.txt"
    USERINI_SUSPICIOUS=$(grep -rniE "auto_prepend_file|auto_append_file|open_basedir\s*=\s*none" \
      $(find "$WEB_DIR" -name ".user.ini" 2>/dev/null) 2>/dev/null)
    if [ -n "$USERINI_SUSPICIOUS" ]; then
      warn "Подозрительные .user.ini у $user:"
      echo "$USERINI_SUSPICIOUS" | tee -a "$REPORT_DIR/user-ini-$user.txt"
      queue_alert ".user.ini инъекция у $user" "$USERINI_SUSPICIOUS"
    fi
  fi
done

# --- 12. ПРОВЕРКА /tmp И /dev/shm НА ПОДОЗРИТЕЛЬНЫЕ ФАЙЛЫ ---
log "=== 12. /tmp И /dev/shm ==="
# Сохраняем листинг в отчёт тихо
ls -la /tmp/ > "$REPORT_DIR/tmp-files.txt" 2>/dev/null
ls -la /dev/shm/ >> "$REPORT_DIR/tmp-files.txt" 2>/dev/null
# Алертим только на исполняемые файлы — реальная угроза
TMP_EXEC=$(find /tmp /dev/shm -type f -executable 2>/dev/null)
if [ -n "$TMP_EXEC" ]; then
  warn "Исполняемые файлы в /tmp или /dev/shm:"
  echo "$TMP_EXEC" | tee "$REPORT_DIR/tmp-executables.txt"
  queue_alert "Исполняемые файлы в /tmp" "$TMP_EXEC"
else
  log "✓ Нет исполняемых файлов в /tmp и /dev/shm"
fi

# --- 13. SSH КЛЮЧИ ВСЕХ ПОЛЬЗОВАТЕЛЕЙ ---
log "=== 13. SSH КЛЮЧИ ==="
for user in "${USERS[@]}" root; do
  HOME_DIR=$(eval echo "~$user")
  AUTH_KEYS="$HOME_DIR/.ssh/authorized_keys"
  if [ -f "$AUTH_KEYS" ]; then
    # Сохраняем все ключи в отчёт тихо
    echo "=== $user ==" >> "$REPORT_DIR/ssh-keys.txt"
    cat "$AUTH_KEYS" >> "$REPORT_DIR/ssh-keys.txt"
    # Алертим только если файл ключей изменился недавно (за 7 дней)
    if find "$AUTH_KEYS" -mtime -7 2>/dev/null | grep -q .; then
      KEYS_CONTENT=$(cat "$AUTH_KEYS")
      warn "Недавно изменённые SSH ключи пользователя $user:"
      echo "$KEYS_CONTENT"
      queue_alert "Изменены SSH ключи у $user" "$KEYS_CONTENT"
    fi
  fi
done
KEY_COUNT=$(grep -c 'ssh-' "$REPORT_DIR/ssh-keys.txt" 2>/dev/null || echo 0)
log "SSH ключи сохранены в отчёт ($KEY_COUNT ключей всего)"

# --- 14. ИЗМЕНЕНИЯ В /etc ---
log "=== 14. НЕДАВНО ИЗМЕНЁННЫЕ СИСТЕМНЫЕ ФАЙЛЫ ==="
find /etc -newer /etc/passwd -mtime -7 -type f 2>/dev/null \
  | grep -vE '(\.db|mtab|resolv|adjtime|machine-id)' \
  | tee "$REPORT_DIR/recently-modified-etc.txt"

# --- ИТОГ ---
echo ""
echo "============================================================"
log "АУДИТ ЗАВЕРШЁН. Результаты в: $REPORT_DIR"
echo "============================================================"
echo "Основные файлы для проверки:"
ls -la "$REPORT_DIR/"

# --- ОТПРАВКА ОТЧЁТА ЧЕРЕЗ RESEND ---
log "=== Отправка отчёта по email ==="

# Формируем сводный отчёт
SUMMARY_FILE="$REPORT_DIR/summary.txt"
{
  echo "SECURITY AUDIT REPORT"
  echo "Сервер: $HOSTNAME"
  echo "Дата: $(date)"
  echo "Директория отчёта: $REPORT_DIR"
  echo ""
  echo "=============================="
  echo "ОБНАРУЖЕННЫЕ ПРОБЛЕМЫ:"
  echo "=============================="

  if [ "${#ALERT_SUBJECTS[@]}" -eq 0 ]; then
    echo "Явных проблем не обнаружено."
  else
    for i in "${!ALERT_SUBJECTS[@]}"; do
      echo ""
      echo "--- ${ALERT_SUBJECTS[$i]} ---"
      echo "${ALERT_BODIES[$i]}"
    done
  fi

  echo ""
  echo "=============================="
  echo "СТАТИСТИКА:"
  echo "=============================="
  for user in "${USERS[@]}"; do
    WEBSHELL_COUNT=$(cat "$REPORT_DIR/webshells-$user.txt" 2>/dev/null | wc -l)
    MOD_COUNT=$(cat "$REPORT_DIR/modified-files-$user.txt" 2>/dev/null | wc -l)
    echo "$user: изменённых файлов=$MOD_COUNT, подозрительных=$WEBSHELL_COUNT"
  done

  echo ""
  echo "Полный отчёт в: $REPORT_DIR"
} > "$SUMMARY_FILE"

# Определяем тему письма
if [ "${#ALERT_SUBJECTS[@]}" -gt 0 ]; then
  EMAIL_SUBJECT="[SECURITY ALERT] $HOSTNAME — обнаружено ${#ALERT_SUBJECTS[@]} проблем(ы)"
else
  EMAIL_SUBJECT="[SECURITY OK] $HOSTNAME — аудит завершён, проблем не обнаружено"
fi

send_resend_email "$EMAIL_SUBJECT" "$SUMMARY_FILE"
