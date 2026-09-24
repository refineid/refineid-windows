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

# discuss-with-muse.sh - Stateful multi-turn code review discussion with Muse Code agent

PROGNAME="discuss-with-muse"
MUSE_BIN="${MUSE_BIN:-/Users/pk/.local/bin/muse}"
MUSE_MODEL="${MUSE_MODEL:-muse-spark-1.3-contributor}"
MUSE_REASONING_EFFORT="${MUSE_REASONING_EFFORT:-max}"
CONTRIBUTOR_NAME="${CONTRIBUTOR_NAME:-Contributor}"
CACHE_DIR="${HOME}/.cache/refineid-muse-discussions"
mkdir -p "$CACHE_DIR"

print_usage() {
  echo "Usage: $PROGNAME <COMMAND> [OPTIONS]"
  echo ""
  echo "Commands:"
  echo "  start --pr <NUM> [--repo <OWNER/REPO>] [--intent <MSG>]"
  echo "      Start a persistent review discussion with Muse on a pull request."
  echo ""
  echo "  reply --pr <NUM> [--repo <OWNER/REPO>] <MESSAGE> | --file <PATH>"
  echo "      Send a follow-up reply, answer, or code update to Muse in the same session."
  echo ""
  echo "  transcript --pr <NUM> [--repo <OWNER/REPO>]"
  echo "      Display the complete multi-turn discussion transcript."
  echo ""
  echo "  submit --pr <NUM> [--repo <OWNER/REPO>] [--approve | --comment]"
  echo "      Submit the discussion transcript to the GitHub PR."
  echo ""
  echo "Examples:"
  echo "  $PROGNAME start --pr 65 --repo refineid/refineid-mono-internal"
  echo "  $PROGNAME reply --pr 65 \"Fixed the clone/cd mismatch in site/beta/index.html.\""
  echo "  $PROGNAME transcript --pr 65"
  exit 1
}

if [[ $# -eq 0 ]]; then
  print_usage
fi

COMMAND="$1"
shift

PR_NUM=""
REPO=""
INTENT=""
MESSAGE=""
MSG_FILE=""
SUBMIT_EVENT="COMMENT"

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
    --intent)
      INTENT="$2"
      shift 2
      ;;
    --file)
      MSG_FILE="$2"
      shift 2
      ;;
    --approve)
      SUBMIT_EVENT="APPROVE"
      shift
      ;;
    --comment)
      SUBMIT_EVENT="COMMENT"
      shift
      ;;
    -h|--help)
      print_usage
      ;;
    *)
      if [[ -z "$MESSAGE" ]]; then
        MESSAGE="$1"
        shift
      else
        echo "Unexpected argument: $1" >&2
        print_usage
      fi
      ;;
  esac
done

if [[ -z "$PR_NUM" ]]; then
  echo "Error: --pr <NUM> is required" >&2
  exit 1
fi

if [[ -z "$REPO" ]]; then
  REPO=$(git config --get remote.origin.url 2>/dev/null | sed -E 's/.*github\.com[:\/]([^\/]+\/[^\/\.]+).*/\1/' || true)
  if [[ -z "$REPO" ]]; then
    echo "Error: Could not auto-detect GitHub repo; please pass --repo <OWNER/REPO>" >&2
    exit 1
  fi
fi

SLUG=$(echo "${REPO}_pr_${PR_NUM}" | tr '/:' '_')
STATE_FILE="${CACHE_DIR}/${SLUG}.json"
TRANSCRIPT_FILE="${CACHE_DIR}/${SLUG}_transcript.md"

case "$COMMAND" in
  start)
    SESSION_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
    echo "==> Initializing persistent discussion session ($SESSION_ID) for $REPO #$PR_NUM..." >&2

    TMP_DIR=$(mktemp -d -t discuss-muse-XXXXXX)
    trap 'rm -rf "$TMP_DIR"' EXIT

    echo "==> Fetching PR metadata and diff..." >&2
    gh pr view "$PR_NUM" --repo "$REPO" > "$TMP_DIR/context.txt"
    gh pr diff "$PR_NUM" --repo "$REPO" > "$TMP_DIR/diff.patch"

    cat << 'EOF' > "$TMP_DIR/prompt.md"
You are the designated code reviewer in a collaborative, iterative review discussion with the author/assistant.
Review the pull request changes below and audit compliance with all mandatory project rules:

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

### Collaboration & Discussion Protocol:
This is a multi-turn conversation. You do not just give a final one-way pass/fail verdict:
- State your specific observations, questions, edge case concerns, and recommendations.
- Highlight anything that needs clarification, justification, or a follow-up commit.
- End your response with clear questions or required action items for the author.
EOF

    {
      if [[ -n "$INTENT" ]]; then
        echo ""
        echo "### Author's Statement of Intent:"
        echo "$INTENT"
      fi
      echo ""
      echo "### Pull Request Context:"
      cat "$TMP_DIR/context.txt"
      echo ""
      echo "### Git Diff:"
      cat "$TMP_DIR/diff.patch"
    } >> "$TMP_DIR/prompt.md"

    echo "==> Sending initial review request to Muse Code agent..." >&2
    "$MUSE_BIN" exec --yolo --allow-workspace-switch --model "$MUSE_MODEL" --reasoning-effort "$MUSE_REASONING_EFFORT" --session-id "$SESSION_ID" --prompt-file "$TMP_DIR/prompt.md" > "$TMP_DIR/muse_reply.txt" 2>&1 || {
      echo "Error: muse exec failed" >&2
      cat "$TMP_DIR/muse_reply.txt" >&2
      exit 1
    }

    sed -e '/^muse: workspace root:/d' -e '/^muse: workspace trust:/d' "$TMP_DIR/muse_reply.txt" > "$TMP_DIR/cleaned_reply.txt"

    cat << EOF > "$STATE_FILE"
{
  "repo": "$REPO",
  "pr": "$PR_NUM",
  "session_id": "$SESSION_ID",
  "turns": 1,
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

    cat << EOF > "$TRANSCRIPT_FILE"
# PR #$PR_NUM Review Discussion: $REPO
*Session ID: $SESSION_ID*
*Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)*

## Turn 1 ($CONTRIBUTOR_NAME -> Muse)
${INTENT:-"Submitted PR #$PR_NUM and diff for rigorous review against ReFineID project rules."}

## Turn 1 (Muse Reviewer)
$(cat "$TMP_DIR/cleaned_reply.txt")

EOF

    cat "$TMP_DIR/cleaned_reply.txt"
    echo ""
    echo "==> Session saved ($SESSION_ID). To reply to Muse, run:" >&2
    echo "    $PROGNAME reply --pr $PR_NUM --repo $REPO \"Your reply or explanation here\"" >&2
    ;;

  reply)
    if [[ ! -f "$STATE_FILE" ]]; then
      echo "Error: No active discussion session found for $REPO PR #$PR_NUM. Run '$PROGNAME start --pr $PR_NUM' first." >&2
      exit 1
    fi

    SESSION_ID=$(jq -r .session_id "$STATE_FILE")
    TURNS=$(jq -r .turns "$STATE_FILE")
    NEXT_TURN=$((TURNS + 1))

    CONTENT=""
    if [[ -n "$MSG_FILE" && -f "$MSG_FILE" ]]; then
      CONTENT=$(cat "$MSG_FILE")
    elif [[ -n "$MESSAGE" ]]; then
      CONTENT="$MESSAGE"
    else
      echo "Error: Specify a message string or --file <PATH>" >&2
      exit 1
    fi

    TMP_DIR=$(mktemp -d -t discuss-muse-reply-XXXXXX)
    trap 'rm -rf "$TMP_DIR"' EXIT

    echo "==> Sending Turn $NEXT_TURN to Muse session $SESSION_ID..." >&2
    cat << EOF > "$TMP_DIR/reply_prompt.md"
$CONTENT

Please review this response / updated status. Does this satisfy your questions and findings?
Provide your assessment, any remaining observations, or your updated review status.
EOF

    "$MUSE_BIN" exec --yolo --allow-workspace-switch --model "$MUSE_MODEL" --reasoning-effort "$MUSE_REASONING_EFFORT" --session-id "$SESSION_ID" --prompt-file "$TMP_DIR/reply_prompt.md" > "$TMP_DIR/muse_reply.txt" 2>&1 || {
      echo "Error: muse exec failed" >&2
      cat "$TMP_DIR/muse_reply.txt" >&2
      exit 1
    }

    sed -e '/^muse: workspace root:/d' -e '/^muse: workspace trust:/d' "$TMP_DIR/muse_reply.txt" > "$TMP_DIR/cleaned_reply.txt"

    jq --arg turns "$NEXT_TURN" '.turns = ($turns | tonumber)' "$STATE_FILE" > "$TMP_DIR/updated_state.json"
    mv "$TMP_DIR/updated_state.json" "$STATE_FILE"

    cat << EOF >> "$TRANSCRIPT_FILE"
---
## Turn $NEXT_TURN ($CONTRIBUTOR_NAME -> Muse)
$CONTENT

## Turn $NEXT_TURN (Muse Reviewer)
$(cat "$TMP_DIR/cleaned_reply.txt")

EOF

    cat "$TMP_DIR/cleaned_reply.txt"
    ;;

  transcript)
    if [[ -f "$TRANSCRIPT_FILE" ]]; then
      cat "$TRANSCRIPT_FILE"
    else
      echo "Error: No transcript found for $REPO PR #$PR_NUM" >&2
      exit 1
    fi
    ;;

  submit)
    if [[ ! -f "$TRANSCRIPT_FILE" ]]; then
      echo "Error: No transcript found for $REPO PR #$PR_NUM" >&2
      exit 1
    fi

    echo "==> Posting discussion transcript to GitHub PR #$PR_NUM ($SUBMIT_EVENT)..." >&2
    case "$SUBMIT_EVENT" in
      APPROVE)
        gh pr review "$PR_NUM" --repo "$REPO" --approve --body-file "$TRANSCRIPT_FILE"
        ;;
      *)
        gh pr review "$PR_NUM" --repo "$REPO" --comment --body-file "$TRANSCRIPT_FILE"
        ;;
    esac
    echo "==> Transcript posted successfully to GitHub PR #$PR_NUM!" >&2
    ;;

  *)
    print_usage
    ;;
esac
