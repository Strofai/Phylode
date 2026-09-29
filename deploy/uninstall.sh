#!/bin/bash
# Removes Phylode from the system and restores the DNS settings.
#
# Usage: sudo ./deploy/uninstall.sh
#
# The journal and the lists are deliberately not deleted — that is your data. The commands to
# remove them are printed at the end.

set -euo pipefail

LABEL="com.Phylode.gatekeeper"
PLIST_TARGET="/Library/LaunchDaemons/${LABEL}.plist"
UPDATE_LABEL="com.Phylode.blocklist-update"
UPDATE_PLIST_TARGET="/Library/LaunchDaemons/${UPDATE_LABEL}.plist"
UPDATE_SCRIPT_TARGET="/usr/local/libexec/phylode-update-lists"
BINARY_TARGET="/usr/local/bin/phylode"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this with sudo: sudo $0" >&2
  exit 1
fi

echo "==> Restoring this Mac's DNS settings to automatic first"
echo "    (without this step, nothing resolves on this machine once the service stops)"
# One service name per line; names often contain spaces ("USB 10/100/1000 LAN"), so they must
# not be word-split by for.
# A leading * marks a disabled service and has to be stripped before querying.
networksetup -listallnetworkservices | tail -n +2 | while IFS= read -r service; do
  service="${service#\*}"
  if networksetup -getdnsservers "$service" 2>/dev/null | grep -q '^127\.0\.0\.1$'; then
    networksetup -setdnsservers "$service" empty
    echo "    restored: ${service}"
  fi
done

echo "==> Stopping and removing the boot service and the update schedule"
launchctl bootout "system/${LABEL}" 2>/dev/null || true
rm -f "$PLIST_TARGET"
launchctl bootout "system/${UPDATE_LABEL}" 2>/dev/null || true
rm -f "$UPDATE_PLIST_TARGET" "$UPDATE_SCRIPT_TARGET"

echo "==> Removing the binary"
rm -f "$BINARY_TARGET"

echo
echo "Removed. The following is your data and was **deliberately left in place**:"
echo "  configuration: /usr/local/etc/phylode.conf"
echo "  lists:         /usr/local/etc/phylode/"
echo "  journal:       /var/log/phylode/"
echo
echo "Delete it yourself once you are sure:"
echo "  sudo rm -rf /usr/local/etc/phylode /usr/local/etc/phylode.conf /var/log/phylode"
echo
echo "The dedicated _phylode user is also left behind. To remove it:"
echo "  sudo dscl . -delete /Users/_phylode"
echo "  sudo dscl . -delete /Groups/_phylode"
