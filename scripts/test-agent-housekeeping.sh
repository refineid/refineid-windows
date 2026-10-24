#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Exercise the verdicts of scripts/agent-housekeeping.sh in a throwaway
# repository that is removed on exit:
#
#   - a freshly created worktree whose branch has no commits of its own
#     reports KEEP and survives --clean;
#   - an idle worktree whose branch has no commits of its own is removed;
#   - an idle, clean worktree whose branch is merged into main is removed;
#   - an idle, clean worktree whose branch is not merged reports REVIEW
#     and survives --clean.
#
# Usage:
#
#   scripts/test-agent-housekeeping.sh

set -euo pipefail

housekeeping="$(cd "$(dirname "$0")" && pwd)/agent-housekeeping.sh"

# agent-housekeeping.sh calls a worktree stale after one day; twice that is
# idle beyond any doubt.
stale_after_seconds=86400
idle_seconds=$((2 * stale_after_seconds))

sandbox=$(mktemp -d)
trap 'rm -rf "${sandbox}"' EXIT

# The layout mirrors the policy: the repository beside a wt/ directory under
# a src/ parent, so the housekeeping script raises no placement warning.
repo="${sandbox}/src/repo"
worktrees="${sandbox}/src/wt"
mkdir -p "${repo}" "${worktrees}"

git -C "${repo}" init --quiet --initial-branch=main
git -C "${repo}" config user.name "Housekeeping Test"
git -C "${repo}" config user.email "housekeeping@example.invalid"
git -C "${repo}" commit --quiet --allow-empty -m "Initial commit"

seconds_ago() {
  echo $(( $(date +%s) - $1 ))
}

# Set a path's modification time to a past epoch second on GNU and BSD touch.
set_mtime() {
  local target="$1" when="$2"
  if touch -d "@${when}" "${target}" 2>/dev/null; then
    return
  fi
  touch -t "$(date -r "${when}" +%Y%m%d%H%M.%S)" "${target}"
}

run_housekeeping() {
  (cd "${repo}" && "${housekeeping}" "$@")
}

expect_verdict() {
  local label="$1" expected="$2" output="$3"
  if [[ "${output}" != *"verdict: ${expected}"* ]]; then
    echo "FAIL ${label}: expected 'verdict: ${expected}', got:" >&2
    echo "${output}" >&2
    exit 1
  fi
}

expect_present() {
  local label="$1" path="$2" branch="$3"
  if [[ ! -d "${path}" ]] || ! git -C "${repo}" show-ref --quiet --verify "refs/heads/${branch}"; then
    echo "FAIL ${label}: worktree or branch is gone" >&2
    exit 1
  fi
}

expect_absent() {
  local label="$1" path="$2" branch="$3"
  if [[ -d "${path}" ]] || git -C "${repo}" show-ref --quiet --verify "refs/heads/${branch}"; then
    echo "FAIL ${label}: worktree or branch survived" >&2
    exit 1
  fi
}

# A worktree created moments ago with no commits of its own is a live claim.
label="fresh worktree, no commits"
path="${worktrees}/fresh"
git -C "${repo}" worktree add --quiet "${path}" -b fresh
output=$(run_housekeeping --clean)
expect_verdict "${label}" "KEEP (live claim)" "${output}"
expect_present "${label}" "${path}" fresh
git -C "${repo}" worktree remove "${path}"
git -C "${repo}" branch --quiet -d fresh
echo "ok: ${label}"

# The same worktree left untouched past the stale threshold is removed.
label="idle worktree, no commits"
path="${worktrees}/idle"
git -C "${repo}" worktree add --quiet "${path}" -b idle
set_mtime "${path}" "$(seconds_ago "${idle_seconds}")"
output=$(run_housekeeping --clean)
expect_verdict "${label}" "REMOVED" "${output}"
expect_absent "${label}" "${path}" idle
echo "ok: ${label}"

# A branch whose commit is merged into main, with a clean idle worktree,
# is removed.
label="idle worktree, merged branch"
path="${worktrees}/merged"
git -C "${repo}" worktree add --quiet "${path}" -b merged
echo "merged" >"${path}/merged.txt"
git -C "${path}" add merged.txt
git -C "${path}" commit --quiet -m "Add merged file"
git -C "${repo}" merge --quiet --ff-only merged
set_mtime "${path}" "$(seconds_ago "${idle_seconds}")"
output=$(run_housekeeping --clean)
expect_verdict "${label}" "REMOVED" "${output}"
expect_absent "${label}" "${path}" merged
echo "ok: ${label}"

# A branch with an old, unmerged commit and a clean idle worktree needs an
# owner decision and survives --clean.
label="idle worktree, unmerged branch"
path="${worktrees}/pending"
git -C "${repo}" worktree add --quiet "${path}" -b pending
echo "pending" >"${path}/pending.txt"
git -C "${path}" add pending.txt
commit_time="$(seconds_ago "${idle_seconds}") +0000"
GIT_AUTHOR_DATE="${commit_time}" GIT_COMMITTER_DATE="${commit_time}" \
  git -C "${path}" commit --quiet -m "Add pending file"
set_mtime "${path}" "$(seconds_ago "${idle_seconds}")"
output=$(run_housekeeping --clean)
expect_verdict "${label}" "REVIEW (needs an owner decision)" "${output}"
expect_present "${label}" "${path}" pending
echo "ok: ${label}"

echo "ok: all housekeeping verdicts"
