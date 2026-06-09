#!/bin/bash
# =============================================================================
# AUTO-RESTORE SCRIPT — automatic restore via git on a schedule
# Can be added to cron: 0 */6 * * * root bash /root/04-git-auto-restore.sh
# =============================================================================

LOCK_FILE="/var/lock/hestia-git-auto-restore.lock"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Another git auto-restore run is already running; exiting."
  exit 0
fi

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
      # Preserve forensic/quarantine artefacts so incident response workflow
      # is not undone by the next cron tick (chattr +i alone also blocks
      # `git clean`, but excluding the patterns avoids the noisy alert loop).
      sudo -u "$user" git -C "$REPO" clean -fd \
        -e '*.QUARANTINED' \
        -e '*.malware-bak' \
        -e '.malware-quarantine-*' \
        2>/dev/null
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

    # --- Scan gitignored paths for webshells (runs every tick, not only on CHANGES) ---
    # IMPORTANT: use a strict allowlist of dangerous web-accessible/upload paths only.
    # We intentionally DO NOT scan generic gitignored framework/cache paths to avoid
    # false positives on legitimate Laravel compiled files (e.g. storage/framework/views).
    # Incident 2026-06-04: real backdoor survived in public/build/, so keep those paths covered.
    WEBSHELLS_IN_IGNORED=$(sudo -u "$user" git -C "$REPO" \
      ls-files --ignored --exclude-standard --others 2>/dev/null \
      | grep -Ei '\.(php[0-9]?|phtml|phar)$' \
      | grep -E '^(public/|storage/app/public/|bootstrap/cache/|tmp/|uploads?/|assets?/)' \
      | grep -v '^vendor/' \
      | grep -v '^node_modules/' \
      | sort -u \
      | while IFS= read -r f; do
          fp="$REPO/$f"
          [ -f "$fp" ] || continue
          # Alert on hex-named PHP (typical dropper pattern)
          if echo "$f" | grep -qE '[0-9a-f]{8,}\.(php[0-9]?|phtml|phar)$'; then
            echo "$fp"
            continue
          fi
          # Alert if file contains any webshell pattern
          if grep -qE \
            'eval\(base64_decode|eval\(\$_[A-Z]|assert\(\$_|system\(\$_|passthru\(\$_|shell_exec\(\$_|@system\(.*@passthru|HTTP/1\.[01] 404.*exit.*\$_REQUEST|move_uploaded_file\(\$_FILES' \
            "$fp" 2>/dev/null; then
            echo "$fp"
          fi
        done)

    if [ -n "$WEBSHELLS_IN_IGNORED" ]; then
      log "CRITICAL: Webshell(s) in .gitignore-d path(s) in $REPO"
      echo "$WEBSHELLS_IN_IGNORED" | tee -a "$LOG"

      Q_BASE="$REPO/.malware-quarantine-$(date +%Y%m%d-%H%M%S)"
      mkdir -p "$Q_BASE"
      while IFS= read -r wp; do
        [ -n "$wp" ] || continue
        sudo cp "$wp" "$Q_BASE/$(basename "$wp").QUARANTINED" 2>/dev/null
        sudo rm -f "$wp"
        log "Quarantined and removed: $wp"
      done <<< "$WEBSHELLS_IN_IGNORED"

      send_resend_email \
        "[SECURITY ALERT] $HOSTNAME — webshells in .gitignore-d dirs removed: $REPO" \
        "Server: $HOSTNAME
Repository: $REPO
Time: $(date)

Webshell(s) found in .gitignore-d directories (survived git-clean) and auto-removed:
$WEBSHELLS_IN_IGNORED

Quarantined to: $Q_BASE
Run full audit: sudo bash /root/server-security/01-security-audit.sh"
    fi
  done < <(find "$WEB_DIR" -maxdepth 4 -name ".git" -type d 2>/dev/null)
done

log "=== Check complete ==="
