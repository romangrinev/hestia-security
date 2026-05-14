#!/bin/bash
# =============================================================================
# FILE MONITOR — real-time PHP/script file change detection
# Runs as a systemd service (installed by 03-hardening.sh).
# Watches all HestiaCP user web directories and logs any create/modify events
# for PHP, JS, HTML, shell scripts — useful for catching injected webshells.
#
# Log: /var/log/file-changes.log
# Service: file-monitor.service
# Install: sudo bash 03-hardening.sh  (re-installs this service automatically)
# =============================================================================

WATCH_DIRS=""

# Auto-detect all HestiaCP web users (skips admin)
if command -v /usr/local/hestia/bin/v-list-users &>/dev/null; then
  for user in $(/usr/local/hestia/bin/v-list-users plain 2>/dev/null | awk 'NR>2 && $1 != "admin" {print $1}'); do
    [ -d "/home/$user/web" ] && WATCH_DIRS="$WATCH_DIRS /home/$user/web"
  done
fi

# Fallback: scan /home/*/web if HestiaCP CLI unavailable
if [ -z "$WATCH_DIRS" ]; then
  for d in /home/*/web; do
    [ -d "$d" ] && WATCH_DIRS="$WATCH_DIRS $d"
  done
fi

if [ -z "$WATCH_DIRS" ]; then
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: No web directories found to watch" \
    >> /var/log/file-changes.log
  exit 1
fi

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting file monitor. Watching:$WATCH_DIRS" \
  >> /var/log/file-changes.log

exec inotifywait -m -r -e create,modify,moved_to \
  --include '(artisan|\.(php|phtml|phar|js|html|sh|py|pl))$' \
  $WATCH_DIRS 2>/dev/null \
  | while read dir event file; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $event: ${dir}${file}" \
      >> /var/log/file-changes.log
    logger -t "file-monitor" "ALERT: File changed: ${dir}${file} ($event)"
  done
