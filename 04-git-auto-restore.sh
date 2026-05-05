#!/bin/bash
# =============================================================================
# AUTO-RESTORE SCRIPT — автоматическое восстановление через git по расписанию
# Можно добавить в cron: 0 */6 * * * root bash /root/04-git-auto-restore.sh
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

LOG="/var/log/git-auto-restore.log"
HOSTNAME="$(hostname -f)"

# Resend настройки (берём из общего конфига)
RESEND_API_KEY="re_ВАШ_API_КЛЮЧ"
RESEND_FROM="security@ВАШ_ДОМЕН.com"
RESEND_TO="admin@ВАШ_EMAIL.com"
[ -f /etc/security-audit.env ] && source /etc/security-audit.env

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"; }

send_resend_email() {
  local SUBJECT="$1"
  local BODY="$2"
  local ESC_SUBJECT ESC_BODY
  ESC_SUBJECT=$(echo "$SUBJECT" | sed 's/\\/\\\\/g; s/"/\\"/g')
  ESC_BODY=$(echo "$BODY" | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/' | tr -d '\n')
  curl -s -o /dev/null \
    -X POST https://api.resend.com/emails \
    -H "Authorization: Bearer ${RESEND_API_KEY}" \
    -H "Content-Type: application/json" \
    -d "{
      \"from\": \"${RESEND_FROM}\",
      \"to\": [\"${RESEND_TO}\"],
      \"subject\": \"${ESC_SUBJECT}\",
      \"text\": \"${ESC_BODY}\"
    }"
}

log "=== Запуск автоматической проверки git ==="

for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  [ -d "$WEB_DIR" ] || continue

  while IFS= read -r gitdir; do
    REPO=$(dirname "$gitdir")

    # Проверяем есть ли изменения
    CHANGES=$(sudo -u "$user" git -C "$REPO" status --porcelain 2>/dev/null | wc -l)

    if [ "$CHANGES" -gt 0 ]; then
      CHANGED_FILES=$(sudo -u "$user" git -C "$REPO" status --short 2>/dev/null)
      log "ВНИМАНИЕ: Обнаружены изменения в $REPO ($CHANGES файлов)"
      echo "$CHANGED_FILES" | tee -a "$LOG"

      # Откатываем
      sudo -u "$user" git -C "$REPO" checkout -- . 2>/dev/null
      sudo -u "$user" git -C "$REPO" clean -fd 2>/dev/null
      log "✓ Откат выполнен: $REPO"

      # Уведомление через Resend
      send_resend_email \
        "[SECURITY ALERT] $HOSTNAME — файлы изменены и откатаны: $REPO" \
        "Сервер: $HOSTNAME
Репозиторий: $REPO
Изменено файлов: $CHANGES
Время: $(date)

Изменённые файлы:
$CHANGED_FILES

Откат выполнен через git checkout -- . && git clean -fd.
Немедленно проверьте вектор атаки: sudo bash /root/server-security/01-security-audit.sh"
    fi
  done < <(find "$WEB_DIR" -maxdepth 4 -name ".git" -type d 2>/dev/null)
done

log "=== Проверка завершена ==="
