#!/bin/bash
# Installs Phylode as a system service that starts at boot.
#
# This script needs sudo, but **the installed service does not run as root** — launchd binds
# port 53 and the service runs as the dedicated _phylode account.
#
# Usage:  sudo ./deploy/install.sh
# Remove: sudo ./deploy/uninstall.sh

set -euo pipefail

LABEL="com.Phylode.gatekeeper"
DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
PLIST_SOURCE="${DEPLOY_DIR}/${LABEL}.plist"
PLIST_TARGET="/Library/LaunchDaemons/${LABEL}.plist"
UPDATE_LABEL="com.Phylode.blocklist-update"
UPDATE_PLIST_TARGET="/Library/LaunchDaemons/${UPDATE_LABEL}.plist"
UPDATE_SCRIPT_TARGET="/usr/local/libexec/phylode-update-lists"
ETC_DIR="/usr/local/etc/phylode"
LISTS_DIR="${ETC_DIR}/lists"
BINARY_SOURCE="$(cd "$(dirname "$0")/.." && pwd)/target/release/phylode"
BINARY_TARGET="/usr/local/bin/phylode"
CONFIG_TARGET="/usr/local/etc/phylode.conf"
LOG_DIR="/var/log/phylode"
SERVICE_USER="_phylode"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this with sudo: sudo $0" >&2
  exit 1
fi

if [[ ! -x "$BINARY_SOURCE" ]]; then
  echo "Binary not found at $BINARY_SOURCE" >&2
  echo "Build it first: cargo build --release" >&2
  exit 1
fi

echo "==> Creating the dedicated user ${SERVICE_USER} (the service runs as this, not root)"
if ! dscl . -read "/Users/${SERVICE_USER}" >/dev/null 2>&1; then
  # Pick a system ID free on both the user and group side (the same number is used for both).
  NEXT_ID=$({ dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID; } \
    | awk '$2 < 500 {print $2}' | sort -n | tail -1)
  NEXT_ID=$((NEXT_ID + 1))
  dscl . -create "/Users/${SERVICE_USER}"
  dscl . -create "/Users/${SERVICE_USER}" UserShell /usr/bin/false
  dscl . -create "/Users/${SERVICE_USER}" RealName "Phylode Gatekeeper"
  dscl . -create "/Users/${SERVICE_USER}" UniqueID "$NEXT_ID"
  dscl . -create "/Users/${SERVICE_USER}" PrimaryGroupID "$NEXT_ID"
  dscl . -create "/Users/${SERVICE_USER}" NFSHomeDirectory /var/empty
  dscl . -create "/Groups/${SERVICE_USER}" PrimaryGroupID "$NEXT_ID"
  echo "    created with ID ${NEXT_ID}"
else
  echo "    already exists, skipping"
fi

echo "==> Installing the binary to ${BINARY_TARGET}"
install -m 755 -o root -g wheel "$BINARY_SOURCE" "$BINARY_TARGET"

echo "==> Preparing the journal directory ${LOG_DIR}"
mkdir -p "$LOG_DIR"
# The group is admin: subdirectories and files the service creates inherit it (750/640), so
# phylode report needs no sudo. No other account gets in — the journal is a complete browsing
# history.
chown "${SERVICE_USER}:admin" "$LOG_DIR"
chmod 750 "$LOG_DIR"

if [[ ! -f "$CONFIG_TARGET" ]]; then
  echo "==> Writing the default configuration to ${CONFIG_TARGET}"
  mkdir -p "$(dirname "$CONFIG_TARGET")"
  cat > "$CONFIG_TARGET" <<'CONF'
# Phylode configuration. Changes here need a service restart; changes to the list files the
# paths below point at take effect within seconds.

listen = 127.0.0.1:53

# Upstreams are always encrypted, addressed by IP, with the hostname used only to validate the
# certificate. When they are unreachable there is no fallback to plaintext (RFC 8310 Strict
# Privacy, which is also Apple's default).
# One uses port 853 (DoT) and one port 443 (DoH): some networks block 853, and two upstreams on
# the same port would fail together.
upstream = "tls 1.1.1.1 cloudflare-dns.com"
upstream = "https 9.9.9.9 dns.quad9.net"

# Blocklists, updated daily by com.Phylode.blocklist-update (Hagezi Pro plus Threat Intelligence
# Feeds). If they cannot be read or are empty the service keeps running, but nothing is blocked
# during that window and the weekly summary flags it.
blocklist = /usr/local/etc/phylode/lists/hagezi-pro.txt
blocklist = /usr/local/etc/phylode/lists/hagezi-tif.txt

# These two are maintained by phylode allow / phylode block; it is fine if they do not exist.
allowlist = /usr/local/etc/phylode/allow.txt
user_blocklist = /usr/local/etc/phylode/block.txt

# How many seconds a device caches a blocked answer. Must stay in single digits; larger and
# allowing a domain appears not to work.
block_ttl_secs = 2

journal_dir = /var/log/phylode/queries
journal_retention_days = 10
CONF
  chmod 644 "$CONFIG_TARGET"
else
  echo "==> Configuration already exists, leaving it alone: ${CONFIG_TARGET}"
fi

echo "==> Preparing the list directories"
# The config directory is writable by the admin group so phylode allow/block need no sudo (they
# write a staging file and rename, which needs write permission on the directory).
# The service only reads here. The list subdirectory belongs to the service account and is
# written only by the daily update job.
mkdir -p "$LISTS_DIR"
chown root:admin "$ETC_DIR"
chmod 775 "$ETC_DIR"
chown "${SERVICE_USER}:${SERVICE_USER}" "$LISTS_DIR"
chmod 755 "$LISTS_DIR"

echo "==> Installing the list update schedule (downloads once now, then daily)"
mkdir -p "$(dirname "$UPDATE_SCRIPT_TARGET")"
install -m 755 -o root -g wheel "${DEPLOY_DIR}/update-blocklists.sh" "$UPDATE_SCRIPT_TARGET"
install -m 644 -o root -g wheel "${DEPLOY_DIR}/${UPDATE_LABEL}.plist" "$UPDATE_PLIST_TARGET"
launchctl bootout "system/${UPDATE_LABEL}" 2>/dev/null || true
launchctl bootstrap system "$UPDATE_PLIST_TARGET"

echo "==> Installing the boot service ${PLIST_TARGET}"
install -m 644 -o root -g wheel "$PLIST_SOURCE" "$PLIST_TARGET"

echo "==> Loading the service"
launchctl bootout "system/${LABEL}" 2>/dev/null || true
launchctl bootstrap system "$PLIST_TARGET"

echo "==> Checking the service answers (waiting up to 15 seconds)"
answered=0
for _ in $(seq 1 15); do
  if dig @127.0.0.1 apple.com +short +time=1 +tries=1 2>/dev/null | grep -q .; then
    answered=1
    break
  fi
  sleep 1
done

if [[ $answered -eq 0 ]]; then
  echo
  echo "⚠️ The service is installed but answered nothing within 15 seconds. Do not change your\
 DNS settings yet — doing so would leave this Mac without working name resolution." >&2
  echo "To see why it did not start:" >&2
  echo "  tail -20 ${LOG_DIR}/stderr.log" >&2
  exit 1
fi

echo
echo "Installed, and answering queries. The lists are downloading in the background; in a minute or two, check that blocking is active with:"
echo "  phylode status"
echo
echo "Point this Mac at it (this is the step that actually starts protecting this machine):"
echo "  sudo networksetup -setdnsservers Wi-Fi 127.0.0.1"
echo "To undo that:"
echo "  sudo networksetup -setdnsservers Wi-Fi empty"
