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
# More than this, or a file larger than MAX_BYTES, means a damaged or hostile download: the two
# lists hold about a million entries and under 20 MB each. MAX_BYTES must equal
# MAX_LIST_BYTES in src/policy/blocklist.rs (a test compares them).
MAX_ENTRIES=5000000
MAX_BYTES=67108864

mkdir -p "$DIR"
status=0
tmp=""
# A run stopped part-way (launchd, a shutdown) must not leave a staging file of up to MAX_BYTES
# behind. The handler reads tmp when it runs, so it always removes the current one.
trap 'rm -f "$tmp"' EXIT
trap 'exit 1' INT TERM HUP

# Checks a downloaded list; prints why it is unusable, or nothing when it is fine.
# The service refuses a file that is not UTF-8, so installing one would leave no list at the
# next restart. The count declared in the header must match the actual line count: a
# truncated file, an error page and an empty file all fail this check.
problem_with() {
  local file="$1" declared actual
  if ! iconv -f UTF-8 -t UTF-8 "$file" >/dev/null 2>&1; then
    echo "not valid UTF-8"
    return
  fi
  declared="$(grep -m1 '^# Number of entries:' "$file" | awk '{print $NF}' || true)"
  actual="$(grep -vc '^#' "$file" || true)"
  if [[ -z "$declared" || "$declared" != "$actual" || "$actual" -lt $MIN_ENTRIES || "$actual" -gt $MAX_ENTRIES ]]; then
    echo "header says ${declared:-none}, actual $actual"
  fi
}

for entry in "${LISTS[@]}"; do
  read -r name file <<<"$entry"
  target="$DIR/$name.txt"
  tmp="$(mktemp "$DIR/.$name.XXXXXX")"

  # A mirror that answers with a damaged file is treated like one that does not answer: the
  # next one is tried.
  usable=0
  for mirror in "${MIRRORS[@]}"; do
    if ! curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --max-time 300 \
      --max-filesize "$MAX_BYTES" -o "$tmp" "$mirror/$file"; then
      echo "$(date '+%F %T') ${name}: download from $mirror failed, trying the next" >&2
      continue
    fi
    problem="$(problem_with "$tmp")"
    if [[ -z "$problem" ]]; then
      usable=1
      break
    fi
    echo "$(date '+%F %T') ${name}: download from $mirror failed validation ($problem), trying the next" >&2
  done

  if [[ $usable -eq 0 ]]; then
    echo "$(date '+%F %T') ${name}: no source gave a usable list, keeping the previous one" >&2
    rm -f "$tmp"
    status=1
    continue
  fi
  actual="$(grep -vc '^#' "$tmp" || true)"

  if [[ -f "$target" ]]; then
    cp -p "$target" "$DIR/$name.prev.txt"
  fi
  chmod 644 "$tmp"
  mv "$tmp" "$target"
  echo "$(date '+%F %T') ${name}: updated, $actual entries"
done

exit $status
