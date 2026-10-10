#!/bin/bash
# Checks every commit in a range against "Commits and pushes" in CLAUDE.md, so a message that
# breaks the rules cannot reach main whoever wrote it.
#
# Usage: check-commit-messages.sh <range>   (for example origin/main..HEAD, or one commit id)
# Exit codes: 0 if every commit passes, 1 if any fails; each failure is printed with its commit.
#
# What breaks if you change it: the rules here must match CLAUDE.md. Dependabot's commits are
# skipped because its body and Signed-off-by trailer are written by GitHub, not by us.

set -euo pipefail

range="${1:?usage: check-commit-messages.sh <range>}"
# A single commit id checks only that commit; anything with .. is a range.
if [[ "$range" != *..* ]]; then
  range="$range^!"
fi

failed=0
fail() {
  echo "$1: $2"
  failed=1
}

for commit in $(git rev-list --no-merges "$range"); do
  short="$(git rev-parse --short "$commit")"
  if [[ "$(git log -1 --format=%ae "$commit")" == *"dependabot[bot]"* ]]; then
    continue
  fi
  subject="$(git log -1 --format=%s "$commit")"
  message="$(git log -1 --format=%B "$commit")"

  if [[ ! "$subject" =~ ^(Feat|Fix|Docs|Test|Chore):\ [A-Z] ]]; then
    fail "$short" "the summary must start with Feat:, Fix:, Docs:, Test: or Chore: and a capital letter"
  fi
  if (( ${#subject} > 72 )); then
    fail "$short" "the summary is ${#subject} characters; the limit is 72"
  fi
  if [[ "$subject" == *. ]]; then
    fail "$short" "the summary ends with a full stop"
  fi
  if grep -qiE 'claude\.ai/code|Claude-Session:|Generated with' <<<"$message"; then
    fail "$short" "the message carries a session link or a Generated-with line"
  fi

  trailers="$(git interpret-trailers --parse <<<"$message")"
  count=0
  while IFS= read -r trailer; do
    [[ -z "$trailer" ]] && continue
    count=$((count + 1))
    if [[ ! "$trailer" =~ ^Co-Authored-By:\ Claude\ [^\<]+\ \<noreply@anthropic\.com\>$ ]]; then
      fail "$short" "the only trailer allowed is Co-Authored-By: Claude <model> <noreply@anthropic.com>; found: $trailer"
    fi
  done <<<"$trailers"
  if (( count > 1 )); then
    fail "$short" "the message has $count trailers; at most one is allowed"
  fi
done

exit $failed
