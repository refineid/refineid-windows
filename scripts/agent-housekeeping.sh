#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Report agent worktree health, and with --clean remove only what is
# provably done. See docs/process/agent-worktrees.md.
#
# Usage:
#
#   scripts/agent-housekeeping.sh [--clean]
#
# Without flags the script only reports. With --clean it removes worktrees
# whose branch is merged into main, whose tree is clean, and that hold no
# unpushed commits, then deletes the merged branch. Anything else —
# uncommitted changes, unpushed commits, or an unmerged branch — is
# reported with its latest commit message and never destroyed.

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

stale_after_seconds=86400
now=$(date +%s)

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
  elif [[ "${line}" == branch* ]]; then
    ref="${line#branch }"
    branch="${ref#refs/heads/}"
  elif [[ "${line}" == bare ]]; then
    path=""
  elif [[ -z "${line}" ]]; then
    if [[ -n "${path:-}" ]] && [[ "${path}" != "${primary}" ]]; then
      if ! branch=$(git -C "${path}" rev-parse --abbrev-ref HEAD 2>/dev/null); then
        echo "--- ${path}"
        echo "  verdict: REVIEW (not a readable checkout)"
        echo
        path=""
        continue
      fi
      merged="no"
      if git merge-base --is-ancestor "${branch}" main 2>/dev/null; then
        merged="yes"
      fi
      dirty="no"
      if [[ -n "$(git -C "${path}" status --porcelain 2>/dev/null)" ]]; then
        dirty="yes"
      fi
      unpushed="$(git -C "${path}" rev-list --count "main..${branch}" 2>/dev/null || echo "?")"
      branch_commits="$(git -C "${path}" rev-list --count "main..${branch}" 2>/dev/null || echo "0")"

      tree_mtime=$(file_mtime "${path}")
      last_commit_time=0
      if [[ "${branch_commits}" -gt 0 ]]; then
        last_commit_time=$(git -C "${path}" log -1 --format=%ct 2>/dev/null || echo "0")
        latest_subject=$(git -C "${path}" log -1 --format=%s 2>/dev/null || true)
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
      if [[ "${path}" != *"/src/wt/"* ]]; then
        echo "  policy: NON-COMPLIANT (worktree must live under ~/src/wt/)"
      fi
      echo "  branch: ${branch} (merged: ${merged}, dirty: ${dirty}, unpushed: ${unpushed})"
      echo "  activity: ${activity}"
      [[ -n "${latest_subject}" ]] && echo "  latest: ${latest_subject}"
      if [[ "${merged}" == "yes" && "${dirty}" == "no" && "${unpushed}" == "0" ]]; then
        if [[ "${clean}" == "1" ]]; then
          git worktree remove "${path}"
          git branch -d "${branch}"
          echo "  verdict: REMOVED"
        else
          echo "  verdict: REMOVE (rerun with --clean)"
        fi
      elif [[ "${activity}" == fresh* || "${dirty}" == "yes" ]]; then
        echo "  verdict: KEEP (live claim)"
      else
        echo "  verdict: REVIEW (needs an owner decision)"
      fi
      echo
    fi
    path=""
  fi
done < <(git worktree list --porcelain)
