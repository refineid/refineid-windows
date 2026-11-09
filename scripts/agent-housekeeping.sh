#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Report agent worktree health, and with --clean remove only what is
# provably done. See doc/process/agent-worktrees.md.
#
# Usage (a bash script; run it directly, not with sh):
#
#   scripts/agent-housekeeping.sh [--clean]
#
# Without flags the script only reports. With --clean it removes worktrees
# whose branch is merged into main, whose tree is clean, and that hold no
# unpushed commits, then deletes the merged branch. A branch counts as
# merged when main contains it by ancestry, or when every one of its
# changes is already in main by patch: each commit on its own, or the
# branch's whole diff as one squash. A live claim is tested first, so a
# fresh or dirty worktree is never removed even when its branch is merged.
# Detached worktrees have no upstream to establish publication and are kept.
# Anything else — uncommitted changes, unpushed commits, or an unmerged
# branch — is reported with its latest commit message and never destroyed.

set -euo pipefail

clean=0
if [[ "${1:-}" == "--clean" ]]; then
  clean=1
elif [[ $# -gt 0 ]]; then
  echo "usage: scripts/agent-housekeeping.sh [--clean]" >&2
  exit 2
fi

repo=$(git rev-parse --show-toplevel)
cd "${repo}"
git worktree prune
primary=$(git worktree list --porcelain | sed -n 's/^worktree //p' | head -n 1)
# Worktrees belong in wt/ beside the primary checkout (AGENTS.md).
# Keep Git's path spelling for comparison with worktree list, including on
# Git Bash where pwd and Git may use different forms of the same path.
wt_root="${primary%/*}/wt"

stale_after_seconds=86400
now=$(date +%s)

# Print how main contains the checkout commit, or nothing when it does not.
# Any probe that fails prints nothing, so the worktree is kept.
merged_by() {
  local commit="$1" cherry base squash_id main_ids
  if git merge-base --is-ancestor "${commit}" main 2>/dev/null; then
    echo "ancestry"
    return
  fi
  cherry=$(git cherry main "${commit}" 2>/dev/null) || return 0
  if [[ -n "${cherry}" ]] && ! grep -q '^+' <<<"${cherry}"; then
    echo "patch"
    return
  fi
  # The branch's whole diff as one squash, compared by patch ID against
  # each commit main gained since the branch forked.
  base=$(git merge-base main "${commit}" 2>/dev/null) || return 0
  squash_id=$(git diff --no-color --no-ext-diff "${base}" "${commit}" 2>/dev/null \
    | git patch-id --stable | cut -d ' ' -f 1) || return 0
  [[ -n "${squash_id}" ]] || return 0
  main_ids=$(git log -p --no-merges --no-color --no-ext-diff "${base}..main" 2>/dev/null \
    | git patch-id --stable | cut -d ' ' -f 1) || return 0
  if grep -qxF "${squash_id}" <<<"${main_ids}"; then
    echo "squash"
  fi
}

file_mtime() {
  if stat -c %Y "$1" >/dev/null 2>&1; then
    stat -c %Y "$1"
  else
    stat -f %m "$1"
  fi
}

while IFS= read -r line; do
  if [[ "${line}" == worktree* ]]; then
    path="${line#worktree }"
  elif [[ "${line}" == bare ]]; then
    path=""
  elif [[ -z "${line}" ]]; then
    if [[ -n "${path:-}" ]] && [[ "${path}" != "${primary}" ]]; then
      if ! commit=$(git -C "${path}" rev-parse --verify 'HEAD^{commit}' 2>/dev/null); then
        echo "--- ${path}"
        echo "  verdict: REVIEW (not a readable checkout)"
        echo
        path=""
        continue
      fi
      branch=$(git -C "${path}" symbolic-ref --quiet --short HEAD 2>/dev/null || true)
      branch_label="${branch:-(detached)}"
      merged_test="$(merged_by "${commit}")"
      merged="no"
      if [[ -n "${merged_test}" ]]; then
        merged="yes (${merged_test})"
      fi
      dirty="no"
      if ! status=$(git -C "${path}" status --porcelain 2>/dev/null); then
        dirty="unknown"
      elif [[ -n "${status}" ]]; then
        dirty="yes"
      fi
      branch_commits="$(git rev-list --count "main..${commit}" 2>/dev/null || echo "?")"
      if [[ -z "${branch}" ]]; then
        unpushed="?"
      elif git -C "${path}" rev-parse --abbrev-ref "${branch}@{upstream}" >/dev/null 2>&1; then
        unpushed="$(git rev-list --count "${branch}@{upstream}..${commit}" 2>/dev/null || echo "?")"
      elif [[ -n "${merged_test}" ]]; then
        unpushed="0"
      else
        unpushed="${branch_commits}"
      fi

      tree_mtime=$(file_mtime "${path}")
      last_commit_time=0
      if [[ "${branch_commits}" =~ ^[0-9]+$ && "${branch_commits}" -gt 0 ]]; then
        last_commit_time=$(git log -1 --format=%ct "${commit}" 2>/dev/null || echo "0")
        latest_subject=$(git log -1 --format=%s "${commit}" 2>/dev/null || true)
      else
        latest_subject="(no commits on branch yet)"
      fi

      latest_activity=$(( last_commit_time > tree_mtime ? last_commit_time : tree_mtime ))
      age=$((now - latest_activity))
      if [[ "${age}" -gt "${stale_after_seconds}" ]]; then
        activity="stale (${age}s since activity)"
      else
        activity="fresh (${age}s since activity)"
      fi

      size="$(du -sh "${path}" 2>/dev/null | cut -f1)"
      echo "--- ${path} [${size}]"
      if [[ "${path}" != "${wt_root}/"* ]]; then
        echo "  policy: NON-COMPLIANT (worktree must live under ${wt_root}/)"
      fi
      echo "  branch: ${branch_label} (merged: ${merged}, dirty: ${dirty}, unpushed: ${unpushed})"
      echo "  activity: ${activity}"
      [[ -n "${latest_subject}" ]] && echo "  latest: ${latest_subject}"
      if [[ "${activity}" == fresh* || "${dirty}" == "yes" ]]; then
        echo "  verdict: KEEP (live claim)"
      elif [[ -n "${branch}" && -n "${merged_test}" && "${dirty}" == "no" && "${unpushed}" == "0" && "${branch_commits}" != "?" ]]; then
        if [[ "${clean}" == "1" ]]; then
          # The checkout may have changed while the report was prepared.
          # Recheck its identity, cleanliness and activity immediately before
          # removal; an unreadable or changed checkout needs review.
          if final_commit=$(git -C "${path}" rev-parse --verify 'HEAD^{commit}' 2>/dev/null) &&
            final_branch=$(git -C "${path}" symbolic-ref --quiet --short HEAD 2>/dev/null) &&
            final_status=$(git -C "${path}" status --porcelain 2>/dev/null) &&
            final_mtime=$(file_mtime "${path}") &&
            [[ "${final_commit}" == "${commit}" && "${final_branch}" == "${branch}" &&
              -z "${final_status}" && "${final_mtime}" == "${tree_mtime}" ]]; then
            git worktree remove "${path}"
            # A squash-merged branch is not an ancestor of main, so -d
            # refuses it; merged_by has already shown its content is in main.
            git branch -D "${branch}"
            echo "  verdict: REMOVED (worktree ${path}, branch ${branch})"
          else
            echo "  verdict: REVIEW (needs an owner decision)"
          fi
        else
          echo "  verdict: REMOVE (rerun with --clean)"
        fi
      else
        echo "  verdict: REVIEW (needs an owner decision)"
      fi
      echo
    fi
    path=""
  fi
done < <(git worktree list --porcelain)
