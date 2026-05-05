#!/bin/bash
# =============================================================================
# GIT CLEANUP SCRIPT — очистка всех проектов через git
# Запускать от root: sudo bash 02-git-cleanup.sh 2>&1 | tee cleanup-report.txt
#
# ВНИМАНИЕ: git clean -fd удалит неотслеживаемые файлы!
# Загруженные пользователями медиафайлы должны быть в .gitignore
# Перед запуском убедитесь что storage/, uploads/ и т.д. в .gitignore
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

RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${GRN}[+]${NC} $1"; }
warn() { echo -e "${YLW}[!]${NC} $1"; }
alert() { echo -e "${RED}[ALERT]${NC} $1"; }

echo "============================================================"
echo " GIT CLEANUP — $(date)"
echo "============================================================"

cleanup_git_repo() {
  local REPO_DIR="$1"
  local OWNER="$2"

  if [ ! -d "$REPO_DIR/.git" ]; then
    warn "Не git-репозиторий: $REPO_DIR — пропускаем"
    return
  fi

  log "Очищаем: $REPO_DIR (владелец: $OWNER)"

  # Показываем что изменено перед очисткой
  echo "--- Изменённые файлы:"
  sudo -u "$OWNER" git -C "$REPO_DIR" status --short 2>/dev/null || git -C "$REPO_DIR" status --short

  echo "--- Неотслеживаемые файлы (будут удалены):"
  sudo -u "$OWNER" git -C "$REPO_DIR" clean -nfd 2>/dev/null || git -C "$REPO_DIR" clean -nfd

  # Сброс изменённых файлов к состоянию репозитория
  sudo -u "$OWNER" git -C "$REPO_DIR" checkout -- . 2>/dev/null \
    || git -C "$REPO_DIR" checkout -- .

  # Удаление неотслеживаемых файлов (кроме явно нужных)
  sudo -u "$OWNER" git -C "$REPO_DIR" clean -fd 2>/dev/null \
    || git -C "$REPO_DIR" clean -fd

  log "✓ Очищено: $REPO_DIR"
  echo ""
}

# --- Сначала удаляем явные веб-шеллы из /tmp ---
log "=== Очистка /tmp и /dev/shm ==="
find /tmp -type f \( -name "*.php" -o -name "*.py" -o -name "*.pl" -o -name "*.sh" \) -delete 2>/dev/null
find /dev/shm -type f -delete 2>/dev/null
log "✓ /tmp и /dev/shm очищены"

# --- Обход всех пользователей ---
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"

  if [ ! -d "$WEB_DIR" ]; then
    warn "Директория $WEB_DIR не найдена — пропускаем пользователя $user"
    continue
  fi

  log "=== Обрабатываем пользователя: $user ==="

  # Ищем git-репозитории (на глубину 4 уровня)
  while IFS= read -r repo; do
    REPO_DIR=$(dirname "$repo")
    cleanup_git_repo "$REPO_DIR" "$user"
  done < <(find "$WEB_DIR" -maxdepth 4 -name ".git" -type d 2>/dev/null)

  # Дополнительно: ищем в /home/$user/git или /home/$user/repos если есть bare repos
  for extra in "/home/$user/git" "/home/$user/repos"; do
    if [ -d "$extra" ]; then
      while IFS= read -r repo; do
        REPO_DIR=$(dirname "$repo")
        cleanup_git_repo "$REPO_DIR" "$user"
      done < <(find "$extra" -maxdepth 4 -name ".git" -type d 2>/dev/null)
    fi
  done
done

# --- Фиксируем права после очистки ---
log "=== Восстановление прав доступа ==="
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    # Директории: 755, файлы: 644, PHP файлы: 644
    find "$WEB_DIR" -type d -exec chmod 755 {} \; 2>/dev/null
    find "$WEB_DIR" -type f -exec chmod 644 {} \; 2>/dev/null
    # PHP файлы не должны быть исполняемыми
    find "$WEB_DIR" -name "*.php" -exec chmod 644 {} \; 2>/dev/null
    # Восстанавливаем владельца
    chown -R "$user:$user" "$WEB_DIR" 2>/dev/null
    log "✓ Права восстановлены для $user"
  fi
done

# --- Проверяем .htaccess на инъекции после очистки ---
log "=== Проверка .htaccess после очистки ==="
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    SUSPICIOUS=$(find "$WEB_DIR" -name ".htaccess" -exec grep -l "php_value\|base64\|eval\|RewriteRule.*http" {} \; 2>/dev/null)
    if [ -n "$SUSPICIOUS" ]; then
      alert "Подозрительный .htaccess у $user:"
      echo "$SUSPICIOUS"
    fi
  fi
done

echo ""
echo "============================================================"
log "ОЧИСТКА ЗАВЕРШЕНА — $(date)"
echo "============================================================"
echo ""
warn "СЛЕДУЮЩИЕ ШАГИ:"
echo "1. Перезапустите PHP-FPM: sudo systemctl restart php*-fpm"
echo "2. Очистите кэш opcache: curl http://localhost/opcache-reset.php (если настроен)"
echo "3. Перезапустите nginx: sudo systemctl reload nginx"
echo "4. Запустите скрипт хардинга: sudo bash 03-hardening.sh"
