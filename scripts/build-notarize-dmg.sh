#!/bin/sh
set -eu

: "${APPLE_USERNAME:?error: APPLE_USERNAME is required}"
: "${APPLE_PASSWORD:?error: APPLE_PASSWORD is required}"
: "${APPLE_TEAM_ID:?error: APPLE_TEAM_ID is required}"

output="$(/usr/bin/xcrun notarytool submit \
  --apple-id "${APPLE_USERNAME}" \
  --team-id "${APPLE_TEAM_ID}" \
  --password "${APPLE_PASSWORD}" \
  --wait \
  "$1" \
  2>&1)"
printf '%s\n' "$output" >&2
printf '%s\n' "$output" | grep -q "status: Accepted"
/usr/bin/xcrun stapler staple "$1" >&2
/usr/bin/xcrun stapler validate "$1" >&2
