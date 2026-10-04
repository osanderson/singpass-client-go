#!/usr/bin/env bash
# Checks that a commit message (or PR title) follows Conventional Commits:
#
#   type(optional-scope)!: summary
#
# Usage:
#   scripts/check-commit-msg.sh <file>   # message in a file (commit-msg hook)
#   scripts/check-commit-msg.sh -        # message on stdin (CI)
#
# Only the subject line is checked. Used by .githooks/commit-msg and by the
# commit-lint jobs in .github/workflows.
set -euo pipefail

TYPES='build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test'
PATTERN="^(${TYPES})(\([a-z0-9._/-]+\))?!?: [^ ].*$"
MAX_SUBJECT=100

src=${1:--}
if [[ $src == - ]]; then
  msg=$(cat)
else
  msg=$(cat -- "$src")
fi

# First non-comment, non-blank line is the subject (git strips '#' lines).
subject=$(printf '%s\n' "$msg" | grep -v '^#' | sed '/^[[:space:]]*$/d' | head -n 1 || true)

# Let git's autosquash markers through; they never reach main un-squashed.
if [[ $subject =~ ^(fixup|squash|amend)!\  ]]; then
  exit 0
fi

fail() {
  {
    echo "✖ Not a Conventional Commit: \"${subject}\""
    echo "  $1"
    echo "  Expected: <type>(<scope>)?!?: <summary>"
    echo "  Types:    ${TYPES//|/, }"
    echo "  Example:  feat(myinfo): expose container-level source"
  } >&2
  exit 1
}

# A squash merge appends " (#123)" to the PR title. The title was checked
# before the merge, so measure the length without that suffix: otherwise a
# title under the limit fails once it lands on main.
bare=$(printf '%s' "$subject" | sed -E 's/ \(#[0-9]+\)$//')

[[ -n $subject ]] || fail "empty message"
[[ $subject =~ $PATTERN ]] || fail "subject doesn't match the pattern"
(( ${#bare} <= MAX_SUBJECT )) || fail "subject is ${#bare} chars (max ${MAX_SUBJECT}), not counting a trailing (#PR number)"
