#!/bin/bash
# =============================================================================
# GIT CLEANUP SCRIPT — clean all projects via git
# Run as root: sudo bash 02-git-cleanup.sh 2>&1 | tee cleanup-report.txt
#
# WARNING: git clean -fd will delete untracked files!
# User-uploaded media files must be in .gitignore
# Before running, ensure storage/, uploads/, etc. are in .gitignore
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
    warn "Not a git repository: $REPO_DIR — skipping"
    return
  fi

  log "Cleaning: $REPO_DIR (owner: $OWNER)"

  # Show what is modified before cleaning
  echo "--- Modified files:"
  sudo -u "$OWNER" git -C "$REPO_DIR" status --short 2>/dev/null || git -C "$REPO_DIR" status --short

  echo "--- Untracked files (will be deleted):"
  sudo -u "$OWNER" git -C "$REPO_DIR" clean -nfd 2>/dev/null || git -C "$REPO_DIR" clean -nfd

  # Reset modified files to repository state
  sudo -u "$OWNER" git -C "$REPO_DIR" checkout -- . 2>/dev/null \
    || git -C "$REPO_DIR" checkout -- .

  # Delete untracked files (except explicitly needed)
  sudo -u "$OWNER" git -C "$REPO_DIR" clean -fd 2>/dev/null \
    || git -C "$REPO_DIR" clean -fd

  log "✓ Cleaned: $REPO_DIR"
  echo ""
}

# --- First remove explicit webshells from /tmp ---
log "=== Cleaning /tmp and /dev/shm ==="
find /tmp -type f \( -name "*.php" -o -name "*.py" -o -name "*.pl" -o -name "*.sh" \) -delete 2>/dev/null
find /dev/shm -type f -delete 2>/dev/null
log "✓ /tmp and /dev/shm cleaned"

# --- Process all users ---
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"

  if [ ! -d "$WEB_DIR" ]; then
    warn "Directory $WEB_DIR not found — skipping user $user"
    continue
  fi

  log "=== Processing user: $user ==="

  # Search for git repositories (up to 4 levels deep)
  while IFS= read -r repo; do
    REPO_DIR=$(dirname "$repo")
    cleanup_git_repo "$REPO_DIR" "$user"
  done < <(find "$WEB_DIR" -maxdepth 4 -name ".git" -type d 2>/dev/null)

  # Additionally: search in /home/$user/git or /home/$user/repos if bare repos exist
  for extra in "/home/$user/git" "/home/$user/repos"; do
    if [ -d "$extra" ]; then
      while IFS= read -r repo; do
        REPO_DIR=$(dirname "$repo")
        cleanup_git_repo "$REPO_DIR" "$user"
      done < <(find "$extra" -maxdepth 4 -name ".git" -type d 2>/dev/null)
    fi
  done
done

# --- Fix permissions after cleanup ---
log "=== Restoring file permissions ==="
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    # Directories: 755, files: 644, PHP files: 644
    find "$WEB_DIR" -type d -exec chmod 755 {} \; 2>/dev/null
    find "$WEB_DIR" -type f -exec chmod 644 {} \; 2>/dev/null
    # PHP files must not be executable
    find "$WEB_DIR" -name "*.php" -exec chmod 644 {} \; 2>/dev/null
    # Restore ownership
    chown -R "$user:$user" "$WEB_DIR" 2>/dev/null
    log "✓ Permissions restored for $user"
  fi
done

# --- Check .htaccess for injections after cleanup ---
log "=== Checking .htaccess after cleanup ==="
for user in "${USERS[@]}"; do
  WEB_DIR="/home/$user/web"
  if [ -d "$WEB_DIR" ]; then
    SUSPICIOUS=$(find "$WEB_DIR" -name ".htaccess" -exec grep -l "php_value\|base64\|eval\|RewriteRule.*http" {} \; 2>/dev/null)
    if [ -n "$SUSPICIOUS" ]; then
      alert "Suspicious .htaccess for $user:"
      echo "$SUSPICIOUS"
    fi
  fi
done

echo ""
echo "============================================================"
log "CLEANUP COMPLETE — $(date)"
echo "============================================================"
echo ""
warn "NEXT STEPS:"
echo "1. Restart PHP-FPM: sudo systemctl restart php*-fpm"
echo "2. Clear opcache: curl http://localhost/opcache-reset.php (if configured)"
echo "3. Reload nginx: sudo systemctl reload nginx"
echo "4. Run hardening script: sudo bash 03-hardening.sh"
