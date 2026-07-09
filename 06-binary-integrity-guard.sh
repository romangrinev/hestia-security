#!/bin/bash
# =============================================================================
# BINARY INTEGRITY GUARD — baseline + drift alert for su/sudo/PAM
# Run manually:
#   sudo bash 06-binary-integrity-guard.sh --init
#   sudo bash 06-binary-integrity-guard.sh
# =============================================================================

set -u

LOCK_FILE="/var/lock/hestia-binary-integrity-guard.lock"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Another binary guard run is active; exiting."
  exit 0
fi

STATE_DIR="/var/lib/hestia-security"
BASELINE_FILE="$STATE_DIR/binary-integrity-baseline.sha256"
LAST_ALERT_SIG_FILE="$STATE_DIR/binary-integrity-last-alert.sig"
LOG_FILE="/var/log/binary-integrity-guard.log"

mkdir -p "$STATE_DIR"

# Shared email config
RESEND_API_KEY="re_YOUR_API_KEY"
RESEND_FROM="security@your-domain.com"
RESEND_TO="admin@your-email.com"
[ -f /etc/security-audit.env ] && source /etc/security-audit.env
HOSTNAME="$(hostname -f 2>/dev/null || hostname)"

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

send_resend_email() {
  local SUBJECT="$1"
  local BODY_FILE="$2"
  local TMPJSON
  TMPJSON=$(mktemp /tmp/binary-guard-mail-XXXXXX.json)

  python3 - "$SUBJECT" "$RESEND_FROM" "$RESEND_TO" "$BODY_FILE" <<'PYEOF' > "$TMPJSON"
import json, sys
subject = sys.argv[1]
from_addr = sys.argv[2]
to_addr = sys.argv[3]
body_file = sys.argv[4]
with open(body_file, 'r', errors='replace') as f:
    body = f.read()
print(json.dumps({
    'from': from_addr,
    'to': [to_addr],
    'subject': subject,
    'text': body,
}))
PYEOF

  curl -s -o /tmp/binary-guard-resend.json -w "%{http_code}" \
    -X POST https://api.resend.com/emails \
    -H "Authorization: Bearer ${RESEND_API_KEY}" \
    -H "Content-Type: application/json" \
    --data "@${TMPJSON}" >/tmp/binary-guard-http-code.txt

  rm -f "$TMPJSON"
}

MONITORED_FILES=(
  /bin/su
  /usr/bin/sudo
  /usr/bin/passwd
  /etc/pam.d/su
  /etc/pam.d/sudo
  /etc/pam.d/common-auth
  /etc/pam.d/common-password
)

build_snapshot() {
  local target_file="$1"
  : > "$target_file"

  for f in "${MONITORED_FILES[@]}"; do
    if [ -f "$f" ]; then
      sha256sum "$f" >> "$target_file"
    else
      echo "MISSING  $f" >> "$target_file"
    fi
  done
}

if [ "${1:-}" = "--init" ]; then
  build_snapshot "$BASELINE_FILE"
  chmod 600 "$BASELINE_FILE"
  log "Baseline initialized: $BASELINE_FILE"
  exit 0
fi

if [ ! -f "$BASELINE_FILE" ]; then
  build_snapshot "$BASELINE_FILE"
  chmod 600 "$BASELINE_FILE"
  log "Baseline was missing, initialized automatically: $BASELINE_FILE"
  exit 0
fi

CURRENT_FILE=$(mktemp /tmp/binary-guard-current-XXXXXX.txt)
DIFF_FILE=$(mktemp /tmp/binary-guard-diff-XXXXXX.txt)
BODY_FILE=$(mktemp /tmp/binary-guard-body-XXXXXX.txt)

build_snapshot "$CURRENT_FILE"

if ! diff -u "$BASELINE_FILE" "$CURRENT_FILE" > "$DIFF_FILE"; then
  ALERT_SIG=$(sha256sum "$DIFF_FILE" | awk '{print $1}')
  LAST_SIG=""
  [ -f "$LAST_ALERT_SIG_FILE" ] && LAST_SIG=$(cat "$LAST_ALERT_SIG_FILE")

  log "ALERT: Critical binary/PAM drift detected"

  # Extra high-signal integrity checks for su binary.
  SU_FILE_OUT=$(file /bin/su 2>/dev/null || true)
  SU_DPKG_VERIFY=$(dpkg -V util-linux 2>/dev/null | grep -F '/bin/su' || true)

  {
    echo "Server: $HOSTNAME"
    echo "Time: $(date)"
    echo
    echo "Critical binary/PAM integrity drift detected."
    echo
    echo "Diff (baseline vs current):"
    cat "$DIFF_FILE"
    echo
    echo "/bin/su file(1):"
    echo "$SU_FILE_OUT"
    echo
    echo "dpkg -V util-linux (su-related):"
    if [ -n "$SU_DPKG_VERIFY" ]; then
      echo "$SU_DPKG_VERIFY"
    else
      echo "clean (no /bin/su mismatch in util-linux)"
    fi
    echo
    echo "Recommended immediate checks:"
    echo "  sudo file /bin/su && ldd /bin/su"
    echo "  sudo dpkg -V util-linux | grep /bin/su"
    echo "  sudo bash /root/server-security/01-security-audit.sh"
  } > "$BODY_FILE"

  # Send only if this alert signature is new.
  if [ "$ALERT_SIG" != "$LAST_SIG" ]; then
    send_resend_email "[SECURITY ALERT] $HOSTNAME — binary/PAM integrity drift" "$BODY_FILE"
    echo "$ALERT_SIG" > "$LAST_ALERT_SIG_FILE"
    log "Alert email sent (new signature)"
  else
    log "Alert signature unchanged; email suppressed"
  fi
else
  log "OK: Binary/PAM integrity matches baseline"
fi

rm -f "$CURRENT_FILE" "$DIFF_FILE" "$BODY_FILE"
