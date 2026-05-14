#!/bin/bash
# =============================================================================
# AUTO-RESTORE SCRIPT — automatic restore via git on a schedule
# Can be added to cron: 0 */6 * * * root bash /root/04-git-auto-restore.sh
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

LOG="/var/log/git-auto-restore.log"
HOSTNAME="$(hostname -f)"

# Resend settings (taken from shared config)
RESEND_API_KEY="re_YOUR_API_KEY"
RESEND_FROM="security@your-domain.com"
RESEND_TO="admin@your-email.com"
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

log "=== Starting automatic git check ==="

for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  [ -d "$WEB_DIR" ] || continue

  while IFS= read -r gitdir; do
    REPO=$(dirname "$gitdir")

    # Check if there are changes
    CHANGES=$(sudo -u "$user" git -C "$REPO" status --porcelain 2>/dev/null | wc -l)

    if [ "$CHANGES" -gt 0 ]; then
      CHANGED_FILES=$(sudo -u "$user" git -C "$REPO" status --short 2>/dev/null)
      log "WARNING: Changes detected in $REPO ($CHANGES files)"
      echo "$CHANGED_FILES" | tee -a "$LOG"

      # Save content diff before rollback (so we can review what was changed)
      DIFF_CONTENT=$(sudo -u "$user" git -C "$REPO" diff 2>/dev/null | head -200)

      # Roll back
      sudo -u "$user" git -C "$REPO" checkout -- . 2>/dev/null
      sudo -u "$user" git -C "$REPO" clean -fd 2>/dev/null
      log "✓ Rollback complete: $REPO"

      # Notify via Resend
      send_resend_email \
        "[SECURITY ALERT] $HOSTNAME — files changed and rolled back: $REPO" \
        "Server: $HOSTNAME
Repository: $REPO
Files changed: $CHANGES
Time: $(date)

Changed files:
$CHANGED_FILES

Content diff (first 200 lines):
${DIFF_CONTENT:-'(no tracked content diff — may be untracked files or mode-only change)'}

Rollback performed via git checkout -- . && git clean -fd.
Immediately check attack vector: sudo bash /root/server-security/01-security-audit.sh"
    fi
  done < <(find "$WEB_DIR" -maxdepth 4 -name ".git" -type d 2>/dev/null)
done

log "=== Check complete ==="
