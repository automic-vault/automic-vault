#!/bin/sh

set -e

tmp="$(mktemp -d)"
app="$tmp/mnt/Automic Vault.app"
team_id="ZU76A67LGU"

cleanup() {
  set +x
  /usr/bin/hdiutil detach "$tmp/mnt" -quiet 2>/dev/null || true
  /bin/rm -rf "$tmp"
}

trap cleanup EXIT

set -x

/usr/bin/curl -sSfL https://automicvault.com/av.dmg -o "$tmp/av.dmg"

/usr/bin/hdiutil attach "$tmp/av.dmg" \
  -mountpoint "$tmp/mnt" \
  -nobrowse \
  -readonly \
  -quiet

/usr/sbin/spctl -a -vv --type exec "$app"

/usr/bin/codesign --verify --deep --strict "$app"

/usr/bin/codesign -dv --verbose=4 "$app" 2>&1 \
  | /usr/bin/grep -q "^TeamIdentifier=${team_id}$"

/usr/bin/ditto "$app" "/Applications/Automic Vault.app"
if ! /usr/bin/cmp -s "$app/Contents/MacOS/av" /usr/local/bin/av; then
  /usr/bin/sudo /bin/mkdir -p /usr/local/bin
  /usr/bin/sudo /usr/bin/install -m 755 \
    "$app/Contents/MacOS/av" \
    /usr/local/bin/av
fi
