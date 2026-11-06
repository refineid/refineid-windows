#!/bin/sh
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Stamps the workspace version with the UTC day when it differs, refreshes
# the lock file to match, and prints the change; prints nothing when the
# version already names today.
set -eu
cd "$(dirname "$0")/.."

manifest=Cargo.toml
yy=$(date -u +%y); yy=${yy#0}
mo=$(date -u +%m); mo=${mo#0}
dd=$(date -u +%d); dd=${dd#0}
today="$yy.$mo.$dd"
current=$(awk -F'"' '/^version = / { print $2; exit }' "$manifest")
[ "$current" != "$today" ] || exit 0
sed -i.bak "s|^version = \"$current\"|version = \"$today\"|" "$manifest"
rm -f "$manifest.bak"
cargo check --workspace --quiet
echo "workspace version $current -> $today (UTC day change)"
