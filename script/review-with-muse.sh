#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

set -euo pipefail

# review-with-muse.sh - Run automated code review using Muse Code agent (muse exec --yolo)

PROGNAME="review-with-muse"
MUSE_BIN="${MUSE_BIN:-/Users/pk/.local/bin/muse}"
MUSE_MODEL="${MUSE_MODEL:-muse-spark-1.3-contributor}"
MUSE_REASONING_EFFORT="${MUSE_REASONING_EFFORT:-max}"

print_usage() {
  echo "Usage: $PROGNAME [OPTIONS] [GIT_REF_OR_RANGE]"
  echo ""
  echo "Run an automated code review using Muse Code agent against a GitHub PR,"
  echo "a git commit range, or the current working tree diff."
  echo ""
  echo "Options:"
  echo "  --pr <NUM>          Review a GitHub pull request by number"
  echo "  --repo <OWNER/REPO> GitHub repository (default: auto-detected from git remote)"
  echo "  --submit            Submit the review to the GitHub PR (comment/approve)"
  echo "  --approve           When submitting to PR, submit as APPROVE"
  echo "  --request-changes   When submitting to PR, submit as REQUEST_CHANGES"
  echo "  -o, --output <FILE> Write review markdown output to file"
  echo "  -h, --help          Show this help message"
  echo ""
  echo "Examples:"
  echo "  $PROGNAME                         # Review uncommitted working tree changes"
  echo "  $PROGNAME HEAD~1..HEAD            # Review the most recent commit"
  echo "  $PROGNAME main...feature-branch   # Review a branch diff against main"
  echo "  $PROGNAME --pr 65                 # Review GitHub PR #65"
  echo "  $PROGNAME --pr 65 --submit        # Review PR #65 and post review to GitHub"
  exit 1
}

PR_NUM=""
REPO=""
SUBMIT=""
REVIEW_EVENT="COMMENT"
OUTPUT_FILE=""
GIT_RANGE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pr)
      PR_NUM="$2"
      shift 2
      ;;
    --repo)
      REPO="$2"
      shift 2
      ;;
    --submit)
      SUBMIT="1"
      shift
      ;;
    --approve)
      SUBMIT="1"
      REVIEW_EVENT="APPROVE"
      shift
      ;;
    --request-changes)
      SUBMIT="1"
      REVIEW_EVENT="REQUEST_CHANGES"
      shift
      ;;
    -o|--output)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    -h|--help)
      print_usage
      ;;
    -*)
      echo "Unknown option: $1" >&2
      print_usage
      ;;
    *)
      if [[ -z "$GIT_RANGE" ]]; then
        GIT_RANGE="$1"
        shift
      else
        echo "Unexpected argument: $1" >&2
        print_usage
      fi
      ;;
  esac
done

if ! command -v "$MUSE_BIN" >/dev/null 2>&1; then
  echo "Error: muse binary not found at $MUSE_BIN" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d -t review-with-muse-XXXXXX)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

CONTEXT_FILE="$TMP_DIR/context.txt"
DIFF_FILE="$TMP_DIR/diff.patch"
PROMPT_FILE="$TMP_DIR/prompt.md"
REVIEW_FILE="$TMP_DIR/review.md"

if [[ -n "$PR_NUM" ]]; then
  REPO_FLAG=()
  if [[ -n "$REPO" ]]; then
    REPO_FLAG=(--repo "$REPO")
  fi

  echo "==> Fetching PR #$PR_NUM details and diff..." >&2
  gh pr view "$PR_NUM" "${REPO_FLAG[@]}" > "$CONTEXT_FILE" 2>&1 || {
    echo "Error: failed to fetch PR #$PR_NUM metadata with gh" >&2
    exit 1
  }
  gh pr diff "$PR_NUM" "${REPO_FLAG[@]}" > "$DIFF_FILE" 2>&1 || {
    echo "Error: failed to fetch PR #$PR_NUM diff with gh" >&2
    exit 1
  }
elif [[ -n "$GIT_RANGE" ]]; then
  echo "==> Gathering diff for git ref/range: $GIT_RANGE..." >&2
  git log -n 5 "$GIT_RANGE" > "$CONTEXT_FILE" 2>&1 || true
  git diff "$GIT_RANGE" > "$DIFF_FILE" 2>&1 || {
    echo "Error: failed to git diff $GIT_RANGE" >&2
    exit 1
  }
else
  echo "==> Gathering working tree diff (staged and unstaged)..." >&2
  git status --short > "$CONTEXT_FILE" 2>&1 || true
  git diff HEAD > "$DIFF_FILE" 2>&1 || true
  if [[ ! -s "$DIFF_FILE" ]]; then
    git diff --cached > "$DIFF_FILE" 2>&1 || true
  fi
fi

if [[ ! -s "$DIFF_FILE" ]]; then
  echo "Warning: Diff is empty. Nothing to review." >&2
  exit 0
fi

DIFF_LINES=$(wc -l < "$DIFF_FILE" | tr -d ' ')
echo "==> Diff has $DIFF_LINES lines. Generating review prompt..." >&2

cat << 'PROMPT_EOF' > "$PROMPT_FILE"
You are an expert code reviewer conducting a rigorous code review.

Perform a thorough review of the provided code changes, strictly auditing compliance with the following mandatory project and security rules:

### Mandatory Project Quality & Security Rules:
1. **Character Encoding & Special Symbols**:
   - Source files and project prose may use the ISO-8859-15 character repertoire, including meaningful specification symbols such as `§` and `€`.
   - Never degrade specification symbols to ASCII. Rust source files must be valid UTF-8. Protocol fixtures must preserve their exact specified byte encodings.
2. **Zero PIN and PIN-Length Logging**:
   - STRICT ZERO PIN LOGGING across all environments: Never log, trace, display, or format PIN bytes, candidate PIN lengths (e.g. `got {len}`), or development PIN identifiers in log sinks, audit records, or error strings.
   - Never commit test PINs or card secrets.
3. **Memory Safety & Language Boundaries**:
   - Safe Rust must own protocol parsing, secret handling, and state machines.
   - Keep `unsafe` code strictly inside the PC/SC or Windows Card Module boundary.
   - Every Windows ABI pointer access must validate nullability and buffer length before dereferencing.
   - Every slice or index access must be checked for bounds or use safe iterators/patterns.
4. **Clean Code & Conventions**:
   - Use named constants instead of naked protocol or status values.
   - Verify external claims from Microsoft, DVV, ICAO, eIDAS, or primary sources.
   - Zero AI attribution in git commits, commit messages, or PR bodies.

### Required Review Output Format:
Output your review in clear GitHub-flavored Markdown formatted as follows:

## Summary of Changes
Brief concise summary of what this change does.

## Security & Project Rule Compliance Audit
- [ ] ISO-8859-15 encoding & symbol preservation: (Pass / Fail / N/A - explain)
- [ ] Zero PIN / PIN-length logging: (Pass / Fail / N/A - explain)
- [ ] Safe Rust boundary & unsafe containment: (Pass / Fail / N/A - explain)
- [ ] Pointer nullability & length validation: (Pass / Fail / N/A - explain)
- [ ] Named constants & protocol cleanliness: (Pass / Fail / N/A - explain)
- [ ] No AI attribution in commit/PR prose: (Pass / Fail / N/A - explain)

## Findings & Recommendations
Categorize any issues found by severity:
- **Critical / Blocker**: Violations of security rules, memory safety, potential panics/crashes, or regression bugs.
- **Warning**: Code smell, missing boundary check, inadequate error handling.
- **Suggestion**: Non-blocking improvements or cleanups.
(If no issues, state "No blockers or defects identified.")

## Verdict
State clearly: **APPROVE**, **REQUEST_CHANGES**, or **COMMENT**, followed by a one-sentence rationale.

---
Here is the context and diff to review:

PROMPT_EOF

echo "### Context / Metadata:" >> "$PROMPT_FILE"
cat "$CONTEXT_FILE" >> "$PROMPT_FILE"
echo "" >> "$PROMPT_FILE"
echo "### Git Diff:" >> "$PROMPT_FILE"
cat "$DIFF_FILE" >> "$PROMPT_FILE"

echo "==> Invoking Muse Code reviewer ($MUSE_BIN exec --yolo --model $MUSE_MODEL --reasoning-effort $MUSE_REASONING_EFFORT)..." >&2

"$MUSE_BIN" exec --yolo --model "$MUSE_MODEL" --reasoning-effort "$MUSE_REASONING_EFFORT" --prompt-file "$PROMPT_FILE" > "$REVIEW_FILE" 2>&1 || {
  echo "Error: muse exec failed" >&2
  cat "$REVIEW_FILE" >&2
  exit 1
}

# Clean out muse runtime headers if present
sed -e '/^muse: workspace root:/d' -e '/^muse: workspace trust:/d' "$REVIEW_FILE" > "$TMP_DIR/cleaned_review.md"
cp "$TMP_DIR/cleaned_review.md" "$REVIEW_FILE"

if [[ -n "$OUTPUT_FILE" ]]; then
  cp "$REVIEW_FILE" "$OUTPUT_FILE"
  echo "==> Review saved to $OUTPUT_FILE" >&2
fi

cat "$REVIEW_FILE"

if [[ "$SUBMIT" == "1" && -n "$PR_NUM" ]]; then
  echo "" >&2
  echo "==> Submitting review to GitHub PR #$PR_NUM ($REVIEW_EVENT)..." >&2
  REPO_FLAG=()
  if [[ -n "$REPO" ]]; then
    REPO_FLAG=(--repo "$REPO")
  fi

  case "$REVIEW_EVENT" in
    APPROVE)
      gh pr review "$PR_NUM" "${REPO_FLAG[@]}" --approve --body-file "$REVIEW_FILE"
      ;;
    REQUEST_CHANGES)
      gh pr review "$PR_NUM" "${REPO_FLAG[@]}" --request-changes --body-file "$REVIEW_FILE"
      ;;
    *)
      gh pr review "$PR_NUM" "${REPO_FLAG[@]}" --comment --body-file "$REVIEW_FILE"
      ;;
  esac
  echo "==> Review successfully posted to GitHub PR #$PR_NUM!" >&2
fi
