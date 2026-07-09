#!/bin/bash
# =============================================================================
# TMP IOC GUARD — quarantine high-confidence local privesc artifacts in /tmp
# and /dev/shm with minimal false positives.
# =============================================================================

set -u

LOCK_FILE="/var/lock/hestia-tmp-ioc-guard.lock"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Another tmp IOC guard run is active; exiting."
  exit 0
fi

LOG_FILE="/var/log/tmp-ioc-guard.log"
STATE_DIR="/var/lib/hestia-security"
LAST_ALERT_SIG_FILE="$STATE_DIR/tmp-ioc-last-alert.sig"
FORENSICS_BASE="/root/forensics"

mkdir -p "$STATE_DIR" "$FORENSICS_BASE"

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
  TMPJSON=$(mktemp /tmp/tmp-ioc-guard-mail-XXXXXX.json)

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

  curl -s -o /tmp/tmp-ioc-guard-resend.json -w "%{http_code}" \
    -X POST https://api.resend.com/emails \
    -H "Authorization: Bearer ${RESEND_API_KEY}" \
    -H "Content-Type: application/json" \
    --data "@${TMPJSON}" >/tmp/tmp-ioc-guard-http-code.txt

  rm -f "$TMPJSON"
}

is_high_confidence_ioc_file() {
  local f="$1"

  # Incident-specific names (high-confidence markers).
  case "$(basename "$f")" in
    .ab3c90ca|.cd0319cf|.evil_ed.sh|.lpe_fdrace_ok)
      return 0
      ;;
  esac

  # Constrain content scan to executable files only (avoids flagging uploaded scripts).
  if [ ! -x "$f" ]; then
    return 1
  fi

  # Only scan moderate-size files to keep runtime bounded and stable.
  if ! [ -s "$f" ] || [ "$(stat -c%s "$f" 2>/dev/null || echo 0)" -gt 20971520 ]; then
    return 1
  fi

  if head -c 5242880 "$f" 2>/dev/null | strings 2>/dev/null \
    | grep -qE 'NOPASSWD:ALL|r00t::0:0:|ME X 1337 Auto Root agent|trycloudflare\.com'; then
    return 0
  fi

  return 1
}

is_high_confidence_ioc_dir() {
  local d="$1"
  case "$(basename "$d")" in
    ovlcap|.ovl_fuse|.ovl_lower|.ovl_upper|.ovl_merged|.ovl_work|.gcm_fuse|.gcm_lower|.gcm_upper|.gcm_merged|.gcm_work|.fuse_legacy_mnt|.fuse_legacy_work|.cg_escape)
      return 0
      ;;
  esac
  return 1
}

TS="$(date +%Y%m%d_%H%M%S)"
QDIR="$FORENSICS_BASE/tmp-ioc-guard-$TS"
mkdir -p "$QDIR"

IOC_ITEMS_FILE="$QDIR/ioc-items.txt"
: > "$IOC_ITEMS_FILE"

# 1) Find IOC files in /tmp and /dev/shm.
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if is_high_confidence_ioc_file "$f"; then
    echo "$f" >> "$IOC_ITEMS_FILE"
  fi
done < <(find /tmp /dev/shm -maxdepth 2 -type f 2>/dev/null)

# 2) Find IOC exploit-staging dirs in /tmp owned by non-root users.
while IFS= read -r d; do
  [ -n "$d" ] || continue
  owner_uid=$(stat -c '%u' "$d" 2>/dev/null || echo 0)
  if [ "$owner_uid" != "0" ] && is_high_confidence_ioc_dir "$d"; then
    echo "$d" >> "$IOC_ITEMS_FILE"
  fi
done < <(find /tmp -maxdepth 2 -type d 2>/dev/null)

sort -u "$IOC_ITEMS_FILE" -o "$IOC_ITEMS_FILE"

if [ ! -s "$IOC_ITEMS_FILE" ]; then
  rmdir "$QDIR" 2>/dev/null || true
  log "OK: no high-confidence tmp/shm IOC artifacts"
  exit 0
fi

QUARANTINED_FILE="$QDIR/quarantined.txt"
: > "$QUARANTINED_FILE"

while IFS= read -r p; do
  [ -n "$p" ] || continue
  [ -e "$p" ] || continue

  safe_name=$(echo "$p" | sed 's|/|__|g')

  stat -c '%n|%U:%G|%a|%y|%s' "$p" >> "$QDIR/ioc-stat.txt" 2>/dev/null || true
  sha256sum "$p" >> "$QDIR/ioc-hashes.txt" 2>/dev/null || true

  cp -a "$p" "$QDIR/${safe_name}.orig" 2>/dev/null || true
  chmod -R a-rwx "$p" 2>/dev/null || true
  if mv "$p" "$QDIR/${safe_name}.quarantined" 2>/dev/null; then
    echo "$p" >> "$QUARANTINED_FILE"
    log "Quarantined IOC artifact: $p"
  fi
done < "$IOC_ITEMS_FILE"

# Detect passwd backdoor line if present.
PASSWD_BACKDOOR=$(grep -nE '^r00t::0:0:' /etc/passwd 2>/dev/null || true)

ALERT_BODY="$QDIR/alert-body.txt"
{
  echo "Server: $HOSTNAME"
  echo "Time: $(date)"
  echo
  echo "Tmp IOC guard quarantined high-confidence artifacts:"
  cat "$QUARANTINED_FILE" 2>/dev/null
  echo
  echo "Forensics dir: $QDIR"
  echo
  if [ -n "$PASSWD_BACKDOOR" ]; then
    echo "CRITICAL: passwd backdoor account present:"
    echo "$PASSWD_BACKDOOR"
    echo
  fi
  echo "Recommended checks:"
  echo "  sudo bash /root/server-security/01-security-audit.sh"
  echo "  sudo file /bin/su && ldd /bin/su"
  echo "  sudo dpkg -V util-linux | grep /bin/su"
} > "$ALERT_BODY"

ALERT_SIG=$(sha256sum "$ALERT_BODY" | awk '{print $1}')
LAST_SIG=""
[ -f "$LAST_ALERT_SIG_FILE" ] && LAST_SIG=$(cat "$LAST_ALERT_SIG_FILE")

if [ "$ALERT_SIG" != "$LAST_SIG" ]; then
  send_resend_email "[SECURITY ALERT] $HOSTNAME — tmp/shm IOC quarantined" "$ALERT_BODY"
  echo "$ALERT_SIG" > "$LAST_ALERT_SIG_FILE"
  log "Alert email sent (new signature)"
else
  log "Alert signature unchanged; email suppressed"
fi
