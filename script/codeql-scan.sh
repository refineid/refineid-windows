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

# CodeQL executable path
CODEQL_BIN="${CODEQL_BIN:-/opt/homebrew/bin/codeql}"
if [ ! -x "$CODEQL_BIN" ]; then
    CODEQL_BIN=$(command -v codeql 2>/dev/null || true)
fi

if [ -z "$CODEQL_BIN" ] || [ ! -x "$CODEQL_BIN" ]; then
    echo "error: codeql executable not found at /opt/homebrew/bin/codeql or on PATH" >&2
    echo "install via: brew install --cask codeql" >&2
    exit 1
fi

REPO_TOP=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
REPO_NAME=$(basename "$REPO_TOP")
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/codeql"
mkdir -p "$CACHE_DIR"

THREADS="${CODEQL_THREADS:-0}" # 0 = use all machine cores
TARGET_LANG=""
CHANGED_ONLY=0

usage() {
    echo "Usage: $0 [--lang=<language>] [--changed] [--threads=<N>]"
    echo ""
    echo "Options:"
    echo "  --lang=<lang>   Analyze specific language (rust, swift, cpp, csharp, java, python, javascript, actions)"
    echo "  --changed       Analyze only languages present in uncommitted/staged git changes"
    echo "  --threads=<N>   Number of threads (default: 0 = all cores)"
    echo "  -h, --help      Show this help"
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --lang=*) TARGET_LANG="${1#*=}" ;;
        --changed) CHANGED_ONLY=1 ;;
        --threads=*) THREADS="${1#*=}" ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
    shift
done

# Language to pack mapping
query_pack_for_lang() {
    case "$1" in
        rust) echo "codeql/rust-queries" ;;
        swift) echo "codeql/swift-queries" ;;
        cpp) echo "codeql/cpp-queries" ;;
        csharp) echo "codeql/csharp-queries" ;;
        java) echo "codeql/java-queries" ;;
        python) echo "codeql/python-queries" ;;
        javascript) echo "codeql/javascript-queries" ;;
        actions) echo "codeql/actions-queries" ;;
        *) echo "" ;;
    esac
}

detect_languages() {
    local langs=()
    local files=""

    if [ "$CHANGED_ONLY" -eq 1 ]; then
        files=$(git diff --name-only HEAD 2>/dev/null || git status --porcelain | awk '{print $NF}')
    else
        files=$(git ls-files 2>/dev/null || find . -type f)
    fi

    if printf '%s\n' "$files" | grep -qE '(\.rs$|Cargo\.toml$)'; then
        langs+=("rust")
    fi
    if printf '%s\n' "$files" | grep -qE '\.swift$'; then
        langs+=("swift")
    fi
    if printf '%s\n' "$files" | grep -qE '\.(c|h|cpp|cc|cxx)$'; then
        langs+=("cpp")
    fi
    if printf '%s\n' "$files" | grep -qE '(\.cs$|\.csproj$)'; then
        langs+=("csharp")
    fi
    if printf '%s\n' "$files" | grep -qE '\.(java|kt)$'; then
        langs+=("java")
    fi
    if printf '%s\n' "$files" | grep -qE '\.py$'; then
        langs+=("python")
    fi
    if printf '%s\n' "$files" | grep -qE '\.(js|jsx|ts|tsx)$'; then
        langs+=("javascript")
    fi
    if printf '%s\n' "$files" | grep -qE '^\.github/workflows/.*\.ya?ml$'; then
        langs+=("actions")
    fi

    echo "${langs[@]}"
}

if [ -n "$TARGET_LANG" ]; then
    LANGUAGES=("$TARGET_LANG")
else
    # shellcheck disable=SC2207
    LANGUAGES=($(detect_languages))
fi

if [ "${#LANGUAGES[@]}" -eq 0 ]; then
    echo "No matching languages detected to scan."
    exit 0
fi

TOTAL_FINDINGS=0

for lang in "${LANGUAGES[@]}"; do
    pack=$(query_pack_for_lang "$lang")
    if [ -z "$pack" ]; then
        echo "warning: no known CodeQL query pack for language '$lang', skipping." >&2
        continue
    fi

    db_path="$CACHE_DIR/db-${REPO_NAME}-${lang}"
    sarif_path="$CACHE_DIR/results-${REPO_NAME}-${lang}.sarif"

    echo "==> [$lang] Building CodeQL database at $db_path (threads=$THREADS)..."
    "$CODEQL_BIN" database create "$db_path" \
        --language="$lang" \
        --source-root="$REPO_TOP" \
        --threads="$THREADS" \
        --overwrite >/dev/null

    echo "==> [$lang] Analyzing with $pack..."
    "$CODEQL_BIN" database analyze "$db_path" "$pack" \
        --threads="$THREADS" \
        --format=sarif-latest \
        --output="$sarif_path" >/dev/null

    # Format findings concisely using Python
    findings_count=$(python3 - "$sarif_path" << 'PYEOF'
import json, sys

sarif_file = sys.argv[1]
try:
    with open(sarif_file, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    sys.exit(0)

results = []
for run in data.get("runs", []):
    for r in run.get("results", []):
        rule_id = r.get("ruleId", "unknown")
        msg = r.get("message", {}).get("text", "").splitlines()[0] if r.get("message") else ""
        locs = r.get("locations", [])
        uri = "unknown"
        line = 0
        if locs:
            phys = locs[0].get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "unknown")
            line = phys.get("region", {}).get("startLine", 0)
        results.append((rule_id, uri, line, msg))

for rule_id, uri, line, msg in results:
    print(f"  {uri}:{line}: [{rule_id}] {msg}")

print(f"COUNT:{len(results)}")
PYEOF
)

    count=$(echo "$findings_count" | grep '^COUNT:' | cut -d: -f2 || echo 0)
    findings_output=$(echo "$findings_count" | grep -v '^COUNT:' || true)

    if [ "$count" -gt 0 ]; then
        echo "==> [$lang] Found $count finding(s):"
        printf '%s\n' "$findings_output"
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + count))
    else
        echo "==> [$lang] Zero findings (clean)."
    fi
    echo ""
done

if [ "$TOTAL_FINDINGS" -gt 0 ]; then
    echo "CodeQL analysis completed with $TOTAL_FINDINGS total finding(s)."
    exit 1
else
    echo "CodeQL analysis clean across all scanned languages."
    exit 0
fi
