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

echo ""
warn "Неудачные попытки входа SSH:"
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -30 \
  | tee "$REPORT_DIR/failed-ssh-logins.txt"

echo ""
warn "Успешные входы по паролю (подозрительно — должны быть только по ключу):"
grep "Accepted password" /var/log/auth.log 2>/dev/null | tail -20 \
  | tee "$REPORT_DIR/accepted-password-logins.txt"

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

echo ""
warn "Активные внешние соединения (не 80/443/22/3306):"
ss -tnp | grep ESTAB | grep -vE ':80 |:443 |:22 |:3306 |:8083 ' \
  | tee "$REPORT_DIR/external-connections.txt"

# --- 5. CRON-ЗАДАЧИ ВСЕХ ПОЛЬЗОВАТЕЛЕЙ ---
log "=== 5. CRON-ЗАДАЧИ ==="
echo "System cron:"
ls -la /etc/cron* 2>/dev/null
cat /etc/crontab 2>/dev/null

for user in "${USERS[@]}" root www-data; do
  CRON=$(crontab -u "$user" -l 2>/dev/null)
  if [ -n "$CRON" ]; then
    queue_alert "Cron пользователя $user" "$CRON"
    echo "$CRON" | tee -a "$REPORT_DIR/crontabs.txt"
  fi
done

echo "Cron в /var/spool/cron:"
ls -la /var/spool/cron/crontabs/ 2>/dev/null

# --- 6. ПОИСК МОДИФИЦИРОВАННЫХ ФАЙЛОВ (последние 14 дней) ---
log "=== 6. ФАЙЛЫ ИЗМЕНЁННЫЕ ЗА 14 ДНЕЙ ==="
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    warn "Изменённые PHP/JS файлы у пользователя $user:"
    find "$WEB_DIR" -type f \( -name "*.php" -o -name "*.js" -o -name "*.html" -o -name "*.htaccess" \) \
      -newer /etc/passwd -mtime -14 \
      ! -path "*/vendor/*" ! -path "*/.git/*" \
      -printf "%TY-%Tm-%Td %TH:%TM  %p\n" 2>/dev/null \
      | sort -r | head -50 | tee -a "$REPORT_DIR/modified-files-$user.txt"
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
)

# Подозрительные имена файлов-шеллов (ищем везде включая vendor/)
SHELL_FILENAMES=(
  'shc.php'
  '.cache.php'
  'bootstrap.cache.php'
  'adminfuns.php'
  'wp-conffq.php'
  'wp-headre.php'
  'press.php'
  'radio.php'
  'content.php'
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
        queue_alert "БЭКДОР у $user (паттерн: $pattern)" "$RESULTS"
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

    # 3. PHP-файлы с hex-именами (8+ hex символов) — характерно для дропперов
    RESULTS=$(find "$WEB_DIR" -type f -name "*.php" 2>/dev/null \
      | grep -E '/[0-9a-f]{8,}\.php$' \
      | grep -v '/.git/')
    if [ -n "$RESULTS" ]; then
      queue_alert "PHP ДРОППЕР (hex-имя) у $user" "$RESULTS"
      echo "$RESULTS" | tee -a "$FOUND_FILE"
    fi

    # 4. cache.php в build/assets или storage (вне vendor/)
    RESULTS=$(find "$WEB_DIR" -name "cache.php" 2>/dev/null \
      | grep -v '/vendor/' \
      | grep -v '/node_modules/' \
      | grep -v '/.git/')
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

# --- 8. ФАЙЛЫ С ОПАСНЫМИ ПРАВАМИ ---
log "=== 8. ФАЙЛЫ С 777/SUID ПРАВАМИ ==="
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    warn "777 файлы у $user:"
    find "$WEB_DIR" -perm -0777 -type f 2>/dev/null | head -20 \
      | tee -a "$REPORT_DIR/perms-$user.txt"
    warn "777 директории у $user:"
    find "$WEB_DIR" -perm -0777 -type d 2>/dev/null | head -20 \
      | tee -a "$REPORT_DIR/perms-$user.txt"
  fi
done

# SUID во всей системе
warn "SUID файлы в системе (проверьте на подозрительные):"
find / -perm /4000 -type f 2>/dev/null | grep -vE '(/usr/bin|/usr/sbin|/bin|/sbin)' \
  | tee "$REPORT_DIR/suid-files.txt"

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

# Проверка PHP-FPM пулов
warn "PHP-FPM пулы (проверьте open_basedir в каждом):"
grep -r "open_basedir\|user\|group" /etc/php/*/fpm/pool.d/ 2>/dev/null \
  | tee -a "$REPORT_DIR/php-fpm-pools.txt"

# --- 11. ПРОВЕРКА .htaccess И .user.ini НА ИНЪЕКЦИИ ---
log "=== 11. ПРОВЕРКА .htaccess И .user.ini ==="
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    warn ".htaccess файлы у $user:"
    find "$WEB_DIR" -name ".htaccess" -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null \
      | tee -a "$REPORT_DIR/htaccess-$user.txt"
    warn ".user.ini файлы у $user:"
    find "$WEB_DIR" -name ".user.ini" -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null \
      | tee -a "$REPORT_DIR/user-ini-$user.txt"
  fi
done

# --- 12. ПРОВЕРКА /tmp И /dev/shm НА ПОДОЗРИТЕЛЬНЫЕ ФАЙЛЫ ---
log "=== 12. /tmp И /dev/shm ==="
warn "Файлы в /tmp:"
ls -la /tmp/ | tee "$REPORT_DIR/tmp-files.txt"
warn "Файлы в /dev/shm:"
ls -la /dev/shm/ 2>/dev/null | tee "$REPORT_DIR/shm-files.txt"
warn "Исполняемые файлы в /tmp:"
find /tmp /dev/shm -type f -executable 2>/dev/null | tee -a "$REPORT_DIR/tmp-executables.txt"

# --- 13. SSH КЛЮЧИ ВСЕХ ПОЛЬЗОВАТЕЛЕЙ ---
log "=== 13. SSH КЛЮЧИ ==="
for user in "${USERS[@]}" root; do
  HOME_DIR=$(eval echo "~$user")
  AUTH_KEYS="$HOME_DIR/.ssh/authorized_keys"
  if [ -f "$AUTH_KEYS" ]; then
    warn "SSH ключи пользователя $user:"
    cat "$AUTH_KEYS" | tee -a "$REPORT_DIR/ssh-keys.txt"
  fi
done

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
    WEBSHELL_COUNT=$(wc -l < "$REPORT_DIR/webshells-$user.txt" 2>/dev/null || echo 0)
    MOD_COUNT=$(wc -l < "$REPORT_DIR/modified-files-$user.txt" 2>/dev/null || echo 0)
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
