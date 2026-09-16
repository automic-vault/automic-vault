#!/bin/bash
# Real packaging regression: an unchanged build must not change signed bytes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
app="$ROOT/target/swift/Automic Vault.app"

/bin/bash "$ROOT/scripts/build.sh" >"$tmp/first.log" 2>&1 || { cat "$tmp/first.log"; exit 1; }
python3 "$ROOT/scripts/build-sign.py" --fingerprint "$app" >"$tmp/first"
cp "$app/Contents/MacOS/av" "$tmp/installed-av"
/bin/bash "$ROOT/scripts/build.sh" >"$tmp/second.log" 2>&1 || { cat "$tmp/second.log"; exit 1; }
python3 "$ROOT/scripts/build-sign.py" --fingerprint "$app" >"$tmp/second"
cmp "$tmp/first" "$tmp/second"
cmp "$tmp/installed-av" "$app/Contents/MacOS/av"
grep -q '^Reused signature: Automic Vault.app$' "$tmp/second.log"
echo "PASS: repeated build preserves the signed bundle and skips CLI replacement"
