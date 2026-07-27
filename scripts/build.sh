#!/usr/local/bin/av inject --allow-missing-keys +APPLE_PASSWORD -- /bin/bash
# --- automic-vault
# capabilities:
#   gh: trusted
# ---
# shellcheck shell=bash disable=SC1008,SC2096
set -euo pipefail

run=0
install=0
dmg=0
notarize=0
publish=0
release_artifact=0
version_supplied=0
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPOSITORY="automic-vault/automic-vault"
TAP_ROOT="${AUTOMIC_VAULT_REPO_CACHE:-$ROOT/../isotopes}/homebrew-isotopes"
CURRENT_VERSION="$(
  awk -F '"' '
    /^\[package\]/ { package = 1; next }
    /^\[/ { package = 0 }
    package && /^[[:space:]]*version[[:space:]]*=/ { print $2; exit }
  ' "$ROOT/Cargo.toml"
)"
VERSION="$CURRENT_VERSION"
prepare_cask_publish() {
  local branch origin
  if [[ ! -d "$TAP_ROOT/.git" ]]; then
    echo "error: --publish requires the Homebrew tap at $TAP_ROOT" >&2
    exit 64
  fi
  origin="$(git -C "$TAP_ROOT" remote get-url origin)"
  case "$origin" in
    git@github.com:automic-vault/homebrew-isotopes.git | https://github.com/automic-vault/homebrew-isotopes.git) ;;
    *)
      echo "error: unexpected Homebrew tap origin: $origin" >&2
      exit 64
      ;;
  esac
  branch="$(git -C "$TAP_ROOT" branch --show-current)"
  if [[ "$branch" != "main" ]]; then
    echo "error: Homebrew tap must be on main, found ${branch:-detached HEAD}" >&2
    exit 64
  fi
  if [[ -n "$(git -C "$TAP_ROOT" status --porcelain --untracked-files=all)" ]]; then
    echo "error: Homebrew tap must have a clean working tree" >&2
    exit 64
  fi
  git -C "$TAP_ROOT" fetch --quiet origin main
  if [[ "$(git -C "$TAP_ROOT" rev-parse HEAD)" != "$(git -C "$TAP_ROOT" rev-parse origin/main)" ]]; then
    echo "error: Homebrew tap main must match origin/main" >&2
    exit 64
  fi
}

publish_cask() {
  local version="$1"
  local sha256="$2"
  local cask="Casks/automic-vault.rb"
  git -C "$TAP_ROOT" pull --ff-only --quiet origin main
  ruby - "$TAP_ROOT/$cask" "$version" "$sha256" <<'RUBY'
path, version, sha256 = ARGV
contents = File.read(path)
replacements = {
  /^  version "[^"]+"$/ => %(  version "#{version}"),
  /^  sha256 "[0-9a-f]{64}"$/ => %(  sha256 "#{sha256}")
}
replacements.each do |pattern, replacement|
  abort "#{path}: expected exactly one #{pattern.inspect}" unless contents.scan(pattern).one?
  contents.sub!(pattern, replacement)
end
File.write("#{path}.tmp", contents)
File.rename("#{path}.tmp", path)
RUBY
  ruby -c "$TAP_ROOT/$cask"
  git -C "$TAP_ROOT" diff --check -- "$cask"
  if git -C "$TAP_ROOT" diff --quiet -- "$cask"; then
    echo "Homebrew cask is already current."
    return
  fi
  git -C "$TAP_ROOT" add -- "$cask"
  git -C "$TAP_ROOT" commit -m "Update Automic Vault cask to $version"
  git -C "$TAP_ROOT" push origin HEAD:main
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run) run=1 ;;
    --install) install=1 ;;
    --dmg) dmg=1 ;;
    --notarize) notarize=1 ;;
    --publish) publish=1 ;;
    --release-artifact) release_artifact=1; dmg=1; notarize=1 ;;
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
      echo "usage: $0 [--run] [--install] [--dmg] [--notarize] [--publish] [--release-artifact] [--version VERSION]" >&2
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
if [[ "$publish" -eq 1 ]]; then
  if [[ "$run" -eq 1 || "$install" -eq 1 || "$dmg" -eq 1 || "$release_artifact" -eq 1 ]]; then
    echo "error: --publish cannot be combined with build or install options" >&2
    exit 64
  fi
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    echo "error: --publish dispatches GitHub Actions and must run locally" >&2
    exit 64
  fi
  if [[ "$version_supplied" -eq 1 && "$VERSION" != "$CURRENT_VERSION" ]]; then
    echo "error: --publish version must match Cargo.toml ($CURRENT_VERSION)" >&2
    exit 64
  fi
  if ! command -v gh >/dev/null 2>&1; then
    echo "error: --publish requires gh" >&2
    exit 64
  fi
  if [[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]]; then
    echo "error: --publish requires a clean checkout" >&2
    exit 64
  fi
  if [[ "$(git -C "$ROOT" branch --show-current)" != "main" ]]; then
    echo "error: --publish requires the main branch" >&2
    exit 64
  fi
  case "$(git -C "$ROOT" remote get-url origin)" in
    git@github.com:automic-vault/automic-vault.git | https://github.com/automic-vault/automic-vault.git) ;;
    *)
      echo "error: --publish requires the automic-vault/automic-vault origin" >&2
      exit 64
      ;;
  esac
  prepare_cask_publish
  git -C "$ROOT" fetch --quiet origin main
  head="$(git -C "$ROOT" rev-parse HEAD)"
  if [[ "$head" != "$(git -C "$ROOT" rev-parse origin/main)" ]]; then
    echo "error: --publish requires main to match origin/main" >&2
    exit 64
  fi
  if gh release view "$VERSION" --repo "$REPOSITORY" >/dev/null 2>&1 ||
    git -C "$ROOT" ls-remote --exit-code --tags origin "refs/tags/$VERSION" >/dev/null 2>&1; then
    echo "error: release or tag $VERSION already exists; publish a new version" >&2
    exit 64
  fi
  run_url="$(
    gh workflow run release.yml \
      --repo "$REPOSITORY" \
      --ref main \
      -f version="$VERSION" \
      -f commit="$head"
  )"
  run_url="${run_url##*$'\n'}"
  if [[ ! "$run_url" =~ /actions/runs/([0-9]+)$ ]]; then
    echo "error: could not determine dispatched workflow run from: $run_url" >&2
    exit 1
  fi
  run_id="${BASH_REMATCH[1]}"
  echo "Release workflow: $run_url"
  gh run watch "$run_id" --repo "$REPOSITORY" --compact --exit-status
  read -r is_draft target_commitish release_url < <(
    gh release view "$VERSION" \
      --repo "$REPOSITORY" \
      --json isDraft,targetCommitish,url \
      --jq '[.isDraft, .targetCommitish, .url] | @tsv'
  )
  if [[ "$is_draft" != "true" || "$target_commitish" != "$head" ]]; then
    echo "error: workflow did not create the expected draft release" >&2
    exit 1
  fi
  echo "Draft release ready for review and publication:"
  echo "$release_url"
  printf "release y/n? "
  reply=""
  read -r reply || true
  if [[ "$reply" != "y" && "$reply" != "Y" ]]; then
    echo "Draft release left unpublished."
    exit 0
  fi
  gh release edit "$VERSION" \
    --repo "$REPOSITORY" \
    --draft=false \
    --latest
  read -r is_draft is_immutable target_commitish < <(
    gh api \
      -H "X-GitHub-Api-Version: 2026-03-10" \
      "repos/$REPOSITORY/releases/tags/$VERSION" \
      --jq '[.draft, .immutable, .target_commitish] | @tsv'
  )
  if [[ "$is_draft" != "false" || "$is_immutable" != "true" || "$target_commitish" != "$head" ]]; then
    echo "error: published release is not immutable or targets the wrong commit" >&2
    exit 1
  fi
  digest="$(
    gh release view "$VERSION" \
      --repo "$REPOSITORY" \
      --json assets \
      --jq ".assets[] | select(.name == \"Automic-Vault-$VERSION.dmg\") | .digest"
  )"
  if [[ ! "$digest" =~ ^sha256:([0-9a-f]{64})$ ]]; then
    echo "error: release DMG has no valid SHA-256 digest" >&2
    exit 1
  fi
  publish_cask "$VERSION" "${BASH_REMATCH[1]}"
  echo "Published release: $release_url"
  exit 0
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
MENU_HELPER_PROFILE="$HOME/Library/MobileDevice/Provisioning Profiles/Automic_Vault_Developer_ID.provisionprofile"
MENU_HELPER_ENTITLEMENTS="$SWIFT_TARGET/menu-helper.entitlements.plist"
INSTALLED_APP="/Applications/Automic Vault.app"
CONTENTS="$APP/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"
LAUNCH_AGENTS="$CONTENTS/Library/LaunchAgents"
LAUNCH_AGENT_NAME="com.automicvault.menubar-helper"
LAUNCH_AGENT_PLIST="$LAUNCH_AGENTS/$LAUNCH_AGENT_NAME.plist"
INSTALLED_LAUNCH_AGENT="$HOME/Library/LaunchAgents/$LAUNCH_AGENT_NAME.plist"

cargo build --release --locked --manifest-path "$ROOT/Cargo.toml"
AV_CLI_REVISION="$("$ROOT/target/release/av" __version)"
if [[ ! "$AV_CLI_REVISION" =~ ^[0-9]+$ ]]; then
  echo "error: invalid av install revision: $AV_CLI_REVISION" >&2
  exit 64
fi
swift build -c release --disable-automatic-resolution \
  --package-path "$MENU_HELPER" \
  --build-path "$SWIFT_TARGET"
SWIFT_BIN="$(
  swift build -c release --disable-automatic-resolution \
    --package-path "$MENU_HELPER" \
    --build-path "$SWIFT_TARGET" \
    --show-bin-path
)"

rm -rf "$APP" "$ICON_BUILD"
mkdir -p "$MACOS" "$RESOURCES" "$LAUNCH_AGENTS" "$ICON_BUILD"
cp "$SWIFT_BIN/AutomicVaultMenubar" "$MACOS/AutomicVaultMenubar"
cp "$MENU_HELPER/Info.plist" "$CONTENTS/Info.plist"
plutil -replace CFBundleShortVersionString -string "$APP_VERSION" "$CONTENTS/Info.plist"
plutil -replace CFBundleVersion -string "$APP_VERSION" "$CONTENTS/Info.plist"
plutil -replace AVCLIRevision -integer "$AV_CLI_REVISION" "$CONTENTS/Info.plist"
if [[ "$release_artifact" -eq 1 ]]; then
  plutil -insert PostHogAPIKey -string "$POSTHOG_API_KEY" "$CONTENTS/Info.plist"
fi
cp "$MENU_HELPER/LaunchAgent.plist" "$LAUNCH_AGENT_PLIST"
cp "$MENU_HELPER/Resources/NSMenuItem.png" "$RESOURCES/NSMenuItem.png"
xcrun actool "$MENU_HELPER/Resources/AppIcon.icon" \
  --compile "$ICON_BUILD" \
  --platform macosx \
  --target-device mac \
  --minimum-deployment-target 26.0 \
  --app-icon AppIcon \
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
codesign "${codesign_args[@]}" --identifier com.automicvault.av-brew-stub "$ROOT/target/release/av-brew-stub"
cp "$ROOT/target/release/av" "$MACOS/av"
cp "$ROOT/target/release/av-brew-stub" "$MACOS/av-brew-stub"
codesign "${codesign_args[@]}" --identifier com.automicvault.av "$MACOS/av"
codesign "${codesign_args[@]}" --identifier com.automicvault.av-brew-stub "$MACOS/av-brew-stub"
app_codesign_args=("${codesign_args[@]}")
if [[ -f "$MENU_HELPER_PROFILE" && "$identity" != "-" ]]; then
  cp "$MENU_HELPER_PROFILE" "$CONTENTS/embedded.provisionprofile"
  security cms -D -i "$MENU_HELPER_PROFILE" |
    plutil -extract Entitlements xml1 -o "$MENU_HELPER_ENTITLEMENTS" -
  plutil -replace keychain-access-groups -json \
    "[\"${APPLE_TEAM_ID}.com.automicvault\"]" \
    "$MENU_HELPER_ENTITLEMENTS"
  app_codesign_args+=(--entitlements "$MENU_HELPER_ENTITLEMENTS")
fi
codesign "${app_codesign_args[@]}" "$APP"
codesign --verify --deep --strict "$APP"
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
  launchctl bootout "gui/$(id -u)" "$INSTALLED_LAUNCH_AGENT" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$INSTALLED_LAUNCH_AGENT"
  launchctl enable "gui/$(id -u)/$LAUNCH_AGENT_NAME"
  launchctl kickstart -k "gui/$(id -u)/$LAUNCH_AGENT_NAME"
  if [[ "$run" -eq 1 ]]; then
    pkill -x AutomicVaultMenubar || true
    open -n "$INSTALLED_APP"
  fi
fi
if [[ "$dmg" -eq 1 ]]; then
  echo "$DMG"
else
  echo "$APP"
fi
