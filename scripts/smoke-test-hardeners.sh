#!/usr/local/bin/av inject -- /bin/bash
# --- automic-vault
# capabilities:
#   brew: trusted
# ---
# shellcheck shell=bash disable=SC1008,SC2016,SC2096
set -euo pipefail

AV=/usr/local/bin/av
APP_AV="/Applications/Automic Vault.app/Contents/MacOS/av"
JQ=/usr/bin/jq
SUDO=/usr/bin/sudo

[[ "$(/usr/bin/uname -s)" == Darwin ]] || { echo "error: macOS is required" >&2; exit 1; }
[[ "$(/usr/bin/id -u)" -ne 0 ]] || {
  echo "error: run this script as your normal user, not with sudo" >&2
  exit 1
}
[[ -x "$AV" && -x "$APP_AV" ]] || {
  echo "error: install and open the current Automic Vault app first" >&2
  exit 1
}
[[ -x "$JQ" ]] || { echo "error: $JQ is required" >&2; exit 1; }
/usr/bin/codesign --verify --strict "$AV"
[[ "$("$AV" __version)" == "$("$APP_AV" __version)" ]] || {
  echo "error: /usr/local/bin/av does not match the installed app revision" >&2
  exit 1
}
/bin/launchctl print "gui/$(/usr/bin/id -u)/com.automicvault.menubar-helper" >/dev/null || {
  echo "error: open Automic Vault before running the smoke test" >&2
  exit 1
}

catalog="$("$AV" hardeners --json)"
printf '%s\n' "$catalog" | "$JQ" -e '(.hardeners | type == "array" and length > 0)' >/dev/null || {
  echo "error: av returned an invalid or empty hardener catalog" >&2
  exit 1
}

HARDENERS=()
while IFS= read -r hardener; do
  HARDENERS+=("$hardener")
done < <(printf '%s\n' "$catalog" | "$JQ" -r '.hardeners[] | select(.applicable) | .name')
[[ ${#HARDENERS[@]} -gt 0 ]] || { echo "error: no applicable hardeners found" >&2; exit 1; }

total="$(printf '%s\n' "$catalog" | "$JQ" '.hardeners | length')"
printf 'Testing %d applicable hardeners (%d catalog entries are not installed)\n' \
  "${#HARDENERS[@]}" "$((total - ${#HARDENERS[@]}))"

echo "Authenticating once for protected Target installation…"
"$SUDO" -v

run_hardener() {
  if [[ "$1" == sudo || "$1" == emudhra ]]; then
    "$SUDO" "$AV" harden "$1" --yes
  else
    "$AV" harden "$1" --yes
  fi
}

for hardener in "${HARDENERS[@]}"; do
  echo
  echo "===== av harden $hardener ====="
  run_hardener "$hardener"
done

echo
echo "Rerunning hardeners to verify idempotence…"
for hardener in "${HARDENERS[@]}"; do
  run_hardener "$hardener" >/dev/null
done

echo
echo "Verifying Hardened State and Doctor checks…"
catalog="$("$AV" hardeners --json)"
for hardener in "${HARDENERS[@]}"; do
  printf '%s\n' "$catalog" | "$JQ" -e --arg name "$hardener" \
    'any(.hardeners[]; .name == $name and .hardened == true)' >/dev/null || {
    echo "error: $hardener did not reach Hardened State" >&2
    exit 1
  }
  printf 'PASS  %s\n' "$hardener"
done

if ! doctor_output="$("$AV" doctor --json)"; then
  printf '%s\n' "$doctor_output" >&2
  exit 1
fi

echo "PASS: all applicable hardeners installed, verified, and remained idempotent"
