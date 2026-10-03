#!/bin/bash
# =============================================================================
# GUARDS SMOKE CHECK — daily health check for guard cron jobs/logs/baseline.
# Intended to fail loudly when guards stop running.
# =============================================================================

set -u

LOCK_FILE="/var/lock/hestia-guards-smoke-check.lock"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Another guards smoke check is active; exiting."
  exit 0
fi

LOG_FILE="/var/log/guards-smoke-check.log"
CRON_FILE="/etc/cron.d/security-monitoring"
BASELINE_FILE="/var/lib/hestia-security/binary-integrity-baseline.sha256"
BIN_LOG="/var/log/binary-integrity-guard.log"
TMP_LOG="/var/log/tmp-ioc-guard.log"
MAX_BIN_AGE_SEC=10800
MAX_TMP_AGE_SEC=5400

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
  TMPJSON=$(mktemp /tmp/guards-smoke-mail-XXXXXX.json)

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

  curl -s -o /tmp/guards-smoke-resend.json -w "%{http_code}" \
    -X POST https://api.resend.com/emails \
    -H "Authorization: Bearer ${RESEND_API_KEY}" \
    -H "Content-Type: application/json" \
    --data "@${TMPJSON}" >/tmp/guards-smoke-http-code.txt

  rm -f "$TMPJSON"
}

FAILURES=()

assert_file_fresh() {
  local f="$1"
  local max_age="$2"
  local label="$3"

  if [ ! -f "$f" ]; then
    FAILURES+=("$label missing: $f")
    return
  fi

  now_ts=$(date +%s)
  mod_ts=$(stat -c '%Y' "$f" 2>/dev/null || echo 0)
  age=$((now_ts - mod_ts))
  if [ "$age" -gt "$max_age" ]; then
    FAILURES+=("$label stale (${age}s old): $f")
  fi
}

if [ ! -f "$CRON_FILE" ]; then
  FAILURES+=("Cron file missing: $CRON_FILE")
else
  grep -Fq "/06-binary-integrity-guard.sh" "$CRON_FILE" || FAILURES+=("Missing cron entry for 06-binary-integrity-guard.sh")
  grep -Fq "/07-tmp-ioc-guard.sh" "$CRON_FILE" || FAILURES+=("Missing cron entry for 07-tmp-ioc-guard.sh")
fi

if [ ! -s "$BASELINE_FILE" ]; then
  FAILURES+=("Binary integrity baseline missing or empty: $BASELINE_FILE")
fi

assert_file_fresh "$BIN_LOG" "$MAX_BIN_AGE_SEC" "Binary guard log"
assert_file_fresh "$TMP_LOG" "$MAX_TMP_AGE_SEC" "Tmp IOC guard log"

if [ "${#FAILURES[@]}" -gt 0 ]; then
  BODY_FILE=$(mktemp /tmp/guards-smoke-body-XXXXXX.txt)
  {
    echo "Server: $HOSTNAME"
    echo "Time: $(date)"
    echo
    echo "Guards smoke check FAILED."
    echo
    printf '%s\n' "${FAILURES[@]}"
    echo
    echo "Suggested checks:"
    echo "  sudo sed -n '1,200p' /etc/cron.d/security-monitoring"
    echo "  sudo tail -n 100 /var/log/binary-integrity-guard.log"
    echo "  sudo tail -n 100 /var/log/tmp-ioc-guard.log"
  } > "$BODY_FILE"

  send_resend_email "[SECURITY ALERT] $HOSTNAME — guards smoke check failed" "$BODY_FILE"
  log "ALERT: Guards smoke check failed"
  printf '%s\n' "${FAILURES[@]}" | tee -a "$LOG_FILE"
  rm -f "$BODY_FILE"
  exit 1
fi

log "OK: guard cron, baseline, and logs look healthy"
exit 0
