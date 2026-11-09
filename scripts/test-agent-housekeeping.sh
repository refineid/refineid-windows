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
sandbox=$(cd "${sandbox}" && pwd -P)
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

# A detached checkout must be judged by its own commit and retained even
# when its commit is merged, because it has no upstream to prove publication.
label="detached worktrees and subsequent branch"
unmerged="${worktrees}/detached-unmerged"
merged_detached="${worktrees}/detached-merged"
fresh_detached="${worktrees}/detached-fresh"
dirty_detached="${worktrees}/detached-dirty"
following="${worktrees}/following"
git -C "${repo}" worktree add --quiet --detach "${unmerged}" main
echo "detached work" >"${unmerged}/detached.txt"
git -C "${unmerged}" add detached.txt
commit_time="$(seconds_ago "${idle_seconds}") +0000"
GIT_AUTHOR_DATE="${commit_time}" GIT_COMMITTER_DATE="${commit_time}" \
  git -C "${unmerged}" commit --quiet -m "Unmerged detached work"
git -C "${repo}" worktree add --quiet --detach "${merged_detached}" main
git -C "${repo}" worktree add --quiet --detach "${fresh_detached}" main
git -C "${repo}" worktree add --quiet --detach "${dirty_detached}" main
echo "uncommitted" >"${dirty_detached}/uncommitted.txt"
git -C "${repo}" worktree add --quiet "${following}" -b following
for target in "${unmerged}" "${merged_detached}" "${dirty_detached}" "${following}"; do
  set_mtime "${target}" "$(seconds_ago "${idle_seconds}")"
done
output=$(run_housekeeping --clean)
for target in "${unmerged}" "${merged_detached}" "${fresh_detached}" "${dirty_detached}"; do
  if [[ ! -d "${target}" ]]; then
    echo "FAIL ${label}: detached worktree was removed" >&2
    exit 1
  fi
done
for target in "${unmerged}" "${merged_detached}"; do
  entry=$(awk -v path="${target}" 'index($0, "--- " path " [") == 1 {found=1} found {print} found && /^$/ {exit}' <<<"${output}")
  expect_verdict "${label}" "REVIEW (needs an owner decision)" "${entry}"
  [[ "${entry}" == *"unpushed: ?"* ]] || { echo "FAIL ${label}: detached publication was assumed" >&2; exit 1; }
done
entry=$(awk -v path="${unmerged}" 'index($0, "--- " path " [") == 1 {found=1} found {print} found && /^$/ {exit}' <<<"${output}")
[[ "${entry}" == *"merged: no"* && "${entry}" == *"latest: Unmerged detached work"* ]] || { echo "FAIL ${label}: wrong detached commit assessed" >&2; exit 1; }
entry=$(awk -v path="${merged_detached}" 'index($0, "--- " path " [") == 1 {found=1} found {print} found && /^$/ {exit}' <<<"${output}")
[[ "${entry}" == *"merged: yes (ancestry)"* ]] || { echo "FAIL ${label}: merged checkout not identified" >&2; exit 1; }
for target in "${fresh_detached}" "${dirty_detached}"; do
  entry=$(awk -v path="${target}" 'index($0, "--- " path " [") == 1 {found=1} found {print} found && /^$/ {exit}' <<<"${output}")
  expect_verdict "${label}" "KEEP (live claim)" "${entry}"
done
entry=$(awk -v path="${dirty_detached}" 'index($0, "--- " path " [") == 1 {found=1} found {print} found && /^$/ {exit}' <<<"${output}")
[[ "${entry}" == *"dirty: yes"* && "${entry}" == *"activity: stale"* ]] || { echo "FAIL ${label}: dirty protection not exercised" >&2; exit 1; }
entry=$(awk -v path="${fresh_detached}" 'index($0, "--- " path " [") == 1 {found=1} found {print} found && /^$/ {exit}' <<<"${output}")
[[ "${entry}" == *"dirty: no"* && "${entry}" == *"activity: fresh"* ]] || { echo "FAIL ${label}: fresh protection not exercised" >&2; exit 1; }
expect_absent "${label}" "${following}" following
echo "ok: ${label}"

# Advance a clean candidate after its snapshot, while du reports its size.
label="worktree advances during report"
racing="${worktrees}/racing"
git -C "${repo}" worktree add --quiet "${racing}" -b racing
set_mtime "${racing}" "$(seconds_ago "${idle_seconds}")"
wrapper_dir="${sandbox}/bin"
mkdir -p "${wrapper_dir}"
real_du=$(command -v du)
cat >"${wrapper_dir}/du" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${2:-}" == "${HOUSEKEEPING_TEST_WORKTREE}" ]]; then
  echo "new work" >"${HOUSEKEEPING_TEST_WORKTREE}/new.txt"
  git -C "${HOUSEKEEPING_TEST_WORKTREE}" add new.txt
  git -C "${HOUSEKEEPING_TEST_WORKTREE}" commit --quiet -m "New work during report"
fi
exec "${HOUSEKEEPING_TEST_DU}" "$@"
EOF
chmod +x "${wrapper_dir}/du"
output=$(PATH="${wrapper_dir}:${PATH}" HOUSEKEEPING_TEST_WORKTREE="${racing}" \
  HOUSEKEEPING_TEST_DU="${real_du}" run_housekeeping --clean)
entry=$(awk -v path="${racing}" 'index($0, "--- " path " [") == 1 {found=1} found {print} found && /^$/ {exit}' <<<"${output}")
expect_verdict "${label}" "REVIEW (needs an owner decision)" "${entry}"
expect_present "${label}" "${racing}" racing
[[ "$(git -C "${racing}" log -1 --format=%s)" == "New work during report" ]] || { echo "FAIL ${label}: new commit lost" >&2; exit 1; }
echo "ok: ${label}"

echo "ok: all housekeeping verdicts"
