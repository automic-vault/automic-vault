#!/bin/bash
set -euo pipefail

run=0
install=0
dmg=0
notarize=0
release_artifact=0
wmo=0
version_supplied=0
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CURRENT_VERSION="$(
  awk -F '"' '
    /^\[package\]/ { package = 1; next }
    /^\[/ { package = 0 }
    package && /^[[:space:]]*version[[:space:]]*=/ { print $2; exit }
  ' "$ROOT/Cargo.toml"
)"
MACOSX_DEPLOYMENT_TARGET=14.0
export MACOSX_DEPLOYMENT_TARGET
VERSION="$CURRENT_VERSION"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run) run=1 ;;
    --install) install=1 ;;
    --dmg) dmg=1 ;;
    --notarize) notarize=1 ;;
    --release-artifact) release_artifact=1; dmg=1; notarize=1 ;;
    --wmo) wmo=1 ;;
    --version)
      if [[ $# -lt 2 || "$2" == --* ]]; then
        echo "error: --version requires a value" >&2
        exit 64
      fi
      VERSION="$2"
      version_supplied=1
      shift
      ;;
    *)
      echo "usage: $0 [--run] [--install] [--dmg] [--notarize] [--release-artifact] [--wmo] [--version VERSION]" >&2
      exit 64
      ;;
  esac
  shift
done
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: version must be in MAJOR.MINOR.PATCH format" >&2
  exit 64
fi
if [[ "$run" -eq 1 && "$install" -ne 1 ]]; then
  echo "error: --run requires --install" >&2
  exit 64
fi
if [[ "$notarize" -eq 1 && "$dmg" -ne 1 ]]; then
  echo "error: --notarize requires --dmg" >&2
  exit 64
fi
if [[ "$release_artifact" -eq 1 ]]; then
  if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
    echo "error: release artifacts may only be built by GitHub Actions" >&2
    exit 64
  fi
  if [[ "$version_supplied" -ne 1 || "$VERSION" != "$CURRENT_VERSION" ]]; then
    echo "error: --release-artifact requires --version to match Cargo.toml ($CURRENT_VERSION)" >&2
    exit 64
  fi
  if [[ -z "${POSTHOG_API_KEY:-}" ]]; then
    echo "error: --release-artifact requires POSTHOG_API_KEY" >&2
    exit 64
  fi
  if [[ -z "${GITHUB_SHA:-}" || "$GITHUB_SHA" != "$(git -C "$ROOT" rev-parse HEAD)" ]]; then
    echo "error: release checkout does not match GITHUB_SHA" >&2
    exit 64
  fi
  if [[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]]; then
    echo "error: release artifacts require a clean checkout" >&2
    exit 64
  fi
fi
if [[ "$notarize" -eq 1 ]]; then
  : "${APPLE_USERNAME:?error: --notarize requires APPLE_USERNAME}"
  : "${APPLE_PASSWORD:?error: --notarize requires APPLE_PASSWORD}"
fi
if [[ "$release_artifact" -eq 1 ]]; then
  APP_VERSION="$VERSION"
else
  APP_VERSION="${APP_VERSION:-$VERSION}"
fi

MENU_HELPER="$ROOT/src/menu-helper"
SWIFT_TARGET="$ROOT/target/swift"
APP="$SWIFT_TARGET/Automic Vault.app"
DMG="$SWIFT_TARGET/Automic-Vault-$VERSION.dmg"
DMG_STAGE="$SWIFT_TARGET/dmg"
DMG_MOUNT="$SWIFT_TARGET/dmg-mount"
ICON_BUILD="$SWIFT_TARGET/icon"
LAUNCHER_ICONSET="$ICON_BUILD/LauncherBundle.iconset"
MENU_HELPER_PROFILE="$HOME/Library/MobileDevice/Provisioning Profiles/Automic_Vault_Developer_ID.provisionprofile"
MENU_HELPER_ENTITLEMENTS="$SWIFT_TARGET/menu-helper.entitlements.plist"
SIGNED_MENU_HELPER_ENTITLEMENTS="$SWIFT_TARGET/signed-menu-helper.entitlements.plist"
PRIVATE_KEYCHAIN_ACCESS_GROUP="ZU76A67LGU.com.automicvault"
APPROVAL_KEYCHAIN_ACCESS_GROUP="ZU76A67LGU.com.automicvault.approval"
PROXY_HELPER_ENTITLEMENTS="$MENU_HELPER/Resources/ProxyHelper.entitlements"
INSTALLED_APP="/Applications/Automic Vault.app"
CONTENTS="$APP/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"
LAUNCH_AGENTS="$CONTENTS/Library/LaunchAgents"
LAUNCH_AGENT_NAME="com.automicvault.menubar-helper"
LAUNCH_AGENT_PLIST="$LAUNCH_AGENTS/$LAUNCH_AGENT_NAME.plist"
INSTALLED_LAUNCH_AGENT="$HOME/Library/LaunchAgents/$LAUNCH_AGENT_NAME.plist"

assert_no_embedded_entitlements() {
  local executable="$1"
  local entitlements
  if ! entitlements="$(codesign -d --entitlements :- "$executable" 2>/dev/null)"; then
    echo "error: failed to inspect signed entitlements for $executable" >&2
    exit 1
  fi
  if [[ -n "$entitlements" ]]; then
    echo "error: Gate Client must not have embedded entitlements: $executable" >&2
    exit 1
  fi
}

assert_private_keychain_entitlement() {
  local application="$1"
  if ! codesign -d --entitlements :- "$application" \
    2>/dev/null >"$SIGNED_MENU_HELPER_ENTITLEMENTS"; then
    echo "error: failed to inspect signed entitlements for $application" >&2
    exit 1
  fi
  if ! plutil -lint "$SIGNED_MENU_HELPER_ENTITLEMENTS" >/dev/null; then
    echo "error: menu bar app has no valid signed entitlements" >&2
    exit 1
  fi
  local groups
  if ! groups="$(
    plutil -extract keychain-access-groups json -o - "$SIGNED_MENU_HELPER_ENTITLEMENTS"
  )"; then
    echo "error: menu bar app has no Keychain access group" >&2
    exit 1
  fi
  if [[ "$groups" == *"*"* ]]; then
    echo "error: menu bar app must not have a wildcard Keychain access group" >&2
    exit 1
  fi
  if [[ "$groups" != "[\"$PRIVATE_KEYCHAIN_ACCESS_GROUP\",\"$APPROVAL_KEYCHAIN_ACCESS_GROUP\"]" ]]; then
    echo "error: menu bar app must have exactly its Secret and Approval Keychain groups; found $groups" >&2
    exit 1
  fi
}

cargo build --release --locked --manifest-path "$ROOT/Cargo.toml"
AV_CLI_REVISION="$("$ROOT/target/release/av" __version)"
if [[ ! "$AV_CLI_REVISION" =~ ^[0-9]+$ ]]; then
  echo "error: invalid av install revision: $AV_CLI_REVISION" >&2
  exit 64
fi
swift_build_args=(
  --build-system xcode
  -c release
  --disable-automatic-resolution
  --package-path "$MENU_HELPER"
  --build-path "$SWIFT_TARGET"
  --arch arm64
)
if [[ "$wmo" -eq 1 ]]; then
  swift_build_args+=(-Xswiftc -whole-module-optimization)
else
  swift_build_args+=(-Xswiftc -no-whole-module-optimization)
fi
swift build "${swift_build_args[@]}"
SWIFT_BIN="$(
  swift build "${swift_build_args[@]}" --show-bin-path
)"

rm -rf "$APP" "$ICON_BUILD"
mkdir -p "$MACOS" "$RESOURCES" "$LAUNCH_AGENTS" "$ICON_BUILD"
cp "$SWIFT_BIN/AutomicVaultMenubar" "$MACOS/AutomicVaultMenubar"
cp "$SWIFT_BIN/AutomicVaultLauncher" "$RESOURCES/AutomicVaultLauncher"
cp "$SWIFT_BIN/AutomicVaultVarlockPlugin" "$RESOURCES/AutomicVaultVarlockPlugin"
ditto "$SWIFT_BIN/AppUpdater_AppUpdater.bundle" "$RESOURCES/AppUpdater_AppUpdater.bundle"
cp "$MENU_HELPER/Info.plist" "$CONTENTS/Info.plist"
plutil -replace CFBundleShortVersionString -string "$APP_VERSION" "$CONTENTS/Info.plist"
plutil -replace CFBundleVersion -string "$APP_VERSION" "$CONTENTS/Info.plist"
plutil -replace AVCLIRevision -integer "$AV_CLI_REVISION" "$CONTENTS/Info.plist"
if [[ "$release_artifact" -eq 1 ]]; then
  plutil -insert PostHogAPIKey -string "$POSTHOG_API_KEY" "$CONTENTS/Info.plist"
fi
cp "$MENU_HELPER/LaunchAgent.plist" "$LAUNCH_AGENT_PLIST"
cp "$MENU_HELPER/Resources/NSMenuItem.png" "$RESOURCES/NSMenuItem.png"
/usr/bin/install -m 0755 "$MENU_HELPER/Resources/install-av-cli.command" "$RESOURCES/install-av-cli.command"
mkdir -p "$LAUNCHER_ICONSET"
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$MENU_HELPER/Resources/LauncherBundleIcon.png" \
    --out "$LAUNCHER_ICONSET/icon_${size}x${size}.png" >/dev/null
  retina_size=$((size * 2))
  sips -z "$retina_size" "$retina_size" "$MENU_HELPER/Resources/LauncherBundleIcon.png" \
    --out "$LAUNCHER_ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$LAUNCHER_ICONSET" -o "$RESOURCES/LauncherBundleIcon.icns"
xcrun actool "$MENU_HELPER/Resources/AppIcon.icon" \
  "$MENU_HELPER/Resources/Assets.xcassets" \
  --compile "$ICON_BUILD" \
  --platform macosx \
  --target-device mac \
  --minimum-deployment-target "$MACOSX_DEPLOYMENT_TARGET" \
  --app-icon AppIcon \
  --accent-color AccentColor \
  --include-all-app-icons \
  --enable-on-demand-resources NO \
  --output-partial-info-plist "$ICON_BUILD/IconInfo.plist" >/dev/null
cp "$ICON_BUILD/Assets.car" "$RESOURCES/Assets.car"

identity="$(
  security find-identity -v -p codesigning |
    awk -F '"' '/Developer ID Application/ { print $2; exit }'
)"
if [[ -z "$identity" ]]; then
  if [[ "$release_artifact" -eq 1 ]]; then
    echo "error: --release-artifact requires a Developer ID Application identity" >&2
    exit 64
  fi
  identity="$(
    security find-identity -v -p codesigning |
      awk -F '"' '/Apple Development/ { print $2; exit }'
  )"
fi
if [[ -z "$identity" ]]; then
  identity="-"
fi
if [[ -z "${APPLE_TEAM_ID:-}" && "$identity" =~ \(([A-Z0-9]+)\)$ ]]; then
  export APPLE_TEAM_ID="${BASH_REMATCH[1]}"
fi
if [[ "$notarize" -eq 1 && -z "${APPLE_TEAM_ID:-}" ]]; then
  echo "error: --notarize requires APPLE_TEAM_ID" >&2
  exit 64
fi
if [[ "$release_artifact" -eq 1 && ! -f "$MENU_HELPER_PROFILE" ]]; then
  echo "error: --release-artifact requires the Developer ID provisioning profile" >&2
  exit 64
fi
codesign_args=(--force --sign "$identity" --options runtime)
if [[ "$identity" != "-" ]]; then
  codesign_args+=(--timestamp)
fi

codesign "${codesign_args[@]}" --identifier com.automicvault.av "$ROOT/target/release/av"
codesign "${codesign_args[@]}" --identifier com.automicvault.av-gpg "$ROOT/target/release/av-gpg"
codesign "${codesign_args[@]}" --identifier com.automicvault.av-brew-stub "$ROOT/target/release/av-brew-stub"
codesign "${codesign_args[@]}" --identifier com.automicvault.launcher-bundle-runner "$RESOURCES/AutomicVaultLauncher"
codesign "${codesign_args[@]}" --identifier com.automicvault.varlock-plugin-helper "$RESOURCES/AutomicVaultVarlockPlugin"
assert_no_embedded_entitlements "$ROOT/target/release/av"
assert_no_embedded_entitlements "$ROOT/target/release/av-gpg"
assert_no_embedded_entitlements "$ROOT/target/release/av-brew-stub"
assert_no_embedded_entitlements "$RESOURCES/AutomicVaultVarlockPlugin"
cp "$ROOT/target/release/av" "$MACOS/av"
cp "$ROOT/target/release/av-gpg" "$MACOS/av-gpg"
cp "$ROOT/target/release/av-brew-stub" "$MACOS/av-brew-stub"
cp "$ROOT/target/release/av-proxy-helper" "$MACOS/av-proxy-helper"
codesign "${codesign_args[@]}" --identifier com.automicvault.av "$MACOS/av"
codesign "${codesign_args[@]}" --identifier com.automicvault.av-gpg "$MACOS/av-gpg"
codesign "${codesign_args[@]}" --identifier com.automicvault.av-brew-stub "$MACOS/av-brew-stub"
codesign "${codesign_args[@]}" \
  --entitlements "$PROXY_HELPER_ENTITLEMENTS" \
  --identifier com.automicvault.av-proxy-helper \
  "$MACOS/av-proxy-helper"
set +e
AV_PROXY_CONTROL=1 "$MACOS/av-proxy-helper" </dev/null >/dev/null 2>&1
proxy_helper_status=$?
set -e
if [[ "$proxy_helper_status" -ne 1 ]]; then
  echo "error: signed sandboxed proxy helper failed its launch probe ($proxy_helper_status)" >&2
  exit 1
fi
assert_no_embedded_entitlements "$MACOS/av"
assert_no_embedded_entitlements "$MACOS/av-gpg"
assert_no_embedded_entitlements "$MACOS/av-brew-stub"
"$MACOS/av" __version >/dev/null
app_codesign_args=("${codesign_args[@]}")
if [[ -f "$MENU_HELPER_PROFILE" && "$identity" != "-" ]]; then
  cp "$MENU_HELPER_PROFILE" "$CONTENTS/embedded.provisionprofile"
  security cms -D -i "$MENU_HELPER_PROFILE" |
    plutil -extract Entitlements xml1 -o "$MENU_HELPER_ENTITLEMENTS" -
  plutil -replace keychain-access-groups -json \
    "[\"$PRIVATE_KEYCHAIN_ACCESS_GROUP\",\"$APPROVAL_KEYCHAIN_ACCESS_GROUP\"]" \
    "$MENU_HELPER_ENTITLEMENTS"
  app_codesign_args+=(--entitlements "$MENU_HELPER_ENTITLEMENTS")
fi
codesign "${app_codesign_args[@]}" "$APP"
codesign --verify --strict "$MACOS/av"
codesign --verify --strict "$MACOS/av-gpg"
codesign --verify --strict "$MACOS/av-brew-stub"
codesign --verify --strict "$MACOS/av-proxy-helper"
codesign --verify --strict "$APP"
if [[ -f "$MENU_HELPER_PROFILE" && "$identity" != "-" ]]; then
  assert_private_keychain_entitlement "$APP"
fi
if [[ "$dmg" -eq 1 ]]; then
  rm -rf "$DMG" "$DMG_STAGE"
  mkdir -p "$DMG_STAGE"
  ditto "$APP" "$DMG_STAGE/Automic Vault.app"
  create-dmg \
    --volname "Automic Vault" \
    --volicon "$ICON_BUILD/AppIcon.icns" \
    --window-size 500 300 \
    --icon "Automic Vault.app" 125 120 \
    --app-drop-link 375 120 \
    --codesign "$identity" \
    --overwrite \
    "$DMG" \
    "$DMG_STAGE"
  codesign --verify "$DMG"
  rm -rf "$DMG_STAGE"
  if [[ "$notarize" -eq 1 ]]; then
    "$ROOT/scripts/build-notarize-dmg.sh" "$DMG"
  fi
fi
if [[ "$install" -eq 1 ]]; then
  install_app="$APP"
  if [[ "$dmg" -eq 1 ]]; then
    rm -rf "$DMG_MOUNT"
    mkdir -p "$DMG_MOUNT"
    hdiutil attach -nobrowse -readonly -mountpoint "$DMG_MOUNT" "$DMG"
    trap 'hdiutil detach "$DMG_MOUNT" >/dev/null 2>&1 || true' EXIT
    install_app="$DMG_MOUNT/Automic Vault.app"
  fi
  rm -rf "$INSTALLED_APP"
  ditto "$install_app" "$INSTALLED_APP"
  if [[ "$dmg" -eq 1 ]]; then
    hdiutil detach "$DMG_MOUNT"
    trap - EXIT
    rm -rf "$DMG_MOUNT"
  fi
  if ! cmp -s "$INSTALLED_APP/Contents/MacOS/av" /usr/local/bin/av; then
    sudo install -m 0755 "$INSTALLED_APP/Contents/MacOS/av" /usr/local/bin/av
  fi
  mkdir -p "$HOME/Library/LaunchAgents"
  cp "$INSTALLED_APP/Contents/Library/LaunchAgents/$LAUNCH_AGENT_NAME.plist" "$INSTALLED_LAUNCH_AGENT"
  plutil -replace ProgramArguments -json \
    "[\"$INSTALLED_APP/Contents/MacOS/AutomicVaultMenubar\"]" \
    "$INSTALLED_LAUNCH_AGENT"
  if [[ "$run" -eq 1 ]]; then
    defaults write com.automicvault pendingMainWindow -bool true
  fi
  launchctl bootout "gui/$(id -u)" "$INSTALLED_LAUNCH_AGENT" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$INSTALLED_LAUNCH_AGENT"
  launchctl enable "gui/$(id -u)/$LAUNCH_AGENT_NAME"
  launchctl kickstart -k "gui/$(id -u)/$LAUNCH_AGENT_NAME"
fi
if [[ "$dmg" -eq 1 ]]; then
  echo "$DMG"
else
  echo "$APP"
fi
