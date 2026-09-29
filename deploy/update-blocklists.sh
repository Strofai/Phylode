#!/bin/bash
# Downloads the blocklists, swaps them in only after validation, and keeps the previous version.
# Run daily by launchd (com.Phylode.blocklist-update).
#
# The service itself never downloads anything: it watches the list files' modification times and
# reloads as soon as one is replaced.
# What breaks if you change it: the swap must be "staging file in the same directory, then mv",
# because mv is atomic within one volume. Writing directly to the live file lets the service read
# a half-written one.
#
# Usage: update-blocklists.sh [list directory] (default /usr/local/etc/phylode/lists)
# Exit codes: 0 if every list succeeded; 1 if any failed (a failed list keeps its previous
# version, so blocking continues).

set -euo pipefail

DIR="${1:-/usr/local/etc/phylode/lists}"

# name filename. The combination Hagezi recommends: one tier (Pro) plus threat intelligence
# (TIF), used as a union.
# TIF uses Medium: the full feed's 2.77 million entries are too large, and Mini covers only the
# few most important sources.
LISTS=(
  "hagezi-pro pro-onlydomains.txt"
  "hagezi-tif tif.medium-onlydomains.txt"
)
# The download links in Hagezi's README point at jsDelivr; GitHub is the fallback.
MIRRORS=(
  "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard"
  "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard"
)
# Fewer entries than this means a corrupt download. Both lists normally exceed 200,000.
MIN_ENTRIES=10000

mkdir -p "$DIR"
status=0

for entry in "${LISTS[@]}"; do
  read -r name file <<<"$entry"
  target="$DIR/$name.txt"
  tmp="$(mktemp "$DIR/.$name.XXXXXX")"

  fetched=0
  for mirror in "${MIRRORS[@]}"; do
    if curl -fsSL --proto '=https' --tlsv1.2 --max-time 300 -o "$tmp" "$mirror/$file"; then
      fetched=1
      break
    fi
    echo "$(date '+%F %T') ${name}: download from $mirror failed, trying the next" >&2
  done

  if [[ $fetched -eq 0 ]]; then
    echo "$(date '+%F %T') ${name}: every source failed, keeping the previous list" >&2
    rm -f "$tmp"
    status=1
    continue
  fi

  # The count declared in the header must match the actual line count: a truncated file, an
  # error page and an empty file all fail this check.
  declared="$(grep -m1 '^# Number of entries:' "$tmp" | awk '{print $NF}' || true)"
  actual="$(grep -vc '^#' "$tmp" || true)"
  if [[ -z "$declared" || "$declared" != "$actual" || "$actual" -lt $MIN_ENTRIES ]]; then
    echo "$(date '+%F %T') ${name}: validation failed (header says ${declared:-none}, actual $actual), keeping the previous list" >&2
    rm -f "$tmp"
    status=1
    continue
  fi

  if [[ -f "$target" ]]; then
    cp -p "$target" "$DIR/$name.prev.txt"
  fi
  chmod 644 "$tmp"
  mv "$tmp" "$target"
  echo "$(date '+%F %T') ${name}: updated, $actual entries"
done

exit $status
