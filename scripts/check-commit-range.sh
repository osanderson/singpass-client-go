#!/usr/bin/env bash
# Checks every non-merge commit in BASE..HEAD with check-commit-msg.sh.
#
# Usage: scripts/check-commit-range.sh <base-sha> <head-sha>
#
# If BASE is empty, all-zeros (a new branch) or unknown (e.g. after a force
# push), only HEAD is checked. Needs full history (actions/checkout
# fetch-depth: 0).
set -euo pipefail

base=${1:-}
head=${2:?usage: check-commit-range.sh <base-sha> <head-sha>}
here=$(dirname -- "${BASH_SOURCE[0]}")

if [[ -z $base || $base =~ ^0+$ ]] || ! git cat-file -e "${base}^{commit}" 2>/dev/null; then
  commits=$(git rev-list --no-merges -1 "$head")
else
  commits=$(git rev-list --no-merges "${base}..${head}")
fi

status=0
for sha in $commits; do
  if git log -1 --format=%B "$sha" | "$here/check-commit-msg.sh" -; then
    echo "✔ ${sha:0:7} $(git log -1 --format=%s "$sha")"
  else
    echo "  in commit ${sha:0:7}" >&2
    status=1
  fi
done
exit $status
