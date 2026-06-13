#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
GUI_DIR="$ROOT_DIR/src/gui"
GUI_LOCALIZATION_DIR="$GUI_DIR/Resources"
CONFIGURATION="${GUI_BUILD_CONFIGURATION:-debug}"
PUBLISH_BUILD=false
source "$ROOT_DIR/scripts/cli-style.sh"
cli_style_init "Automic Vault"

load_build_env() {
  local env_file="$ROOT_DIR/.env"
  [[ -f "$env_file" ]] || return

  local line key value
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -n "$line" && "$line" != \#* && "$line" =~ '^[A-Za-z_][A-Za-z0-9_]*=' ]] || continue

    key="${line%%=*}"
    value="${line#*=}"
    if (( ! ${+parameters[$key]} )); then
      export "$key=$value"
    fi
  done <"$env_file"
}

unquote_build_env_value() {
  local value="$1"
  case "$value" in
    \"*\")
      value="${value#\"}"
      value="${value%\"}"
      ;;
    \'*\')
      value="${value#\'}"
      value="${value%\'}"
      ;;
  esac
  printf '%s' "$value"
}

normalize_codesign_identity() {
  local identity="$1"
  if [[ "$identity" == "-" || "$identity" == *:* ]]; then
    printf '%s' "$identity"
  else
    printf 'Developer ID Application: %s' "$identity"
  fi
}

configure_codesign_identity() {
  if [[ -n "${CODESIGN_IDENTITY:-}" ]]; then
    CODESIGN_IDENTITY="$(normalize_codesign_identity "$(unquote_build_env_value "$CODESIGN_IDENTITY")")"
    export CODESIGN_IDENTITY
    return
  fi

  if [[ -z "${TEAM_COMMON_NAME:-}" || -z "${TEAM_IDENTIFIER:-}" ]]; then
    return
  fi

  local team_common_name team_identifier
  team_common_name="$(unquote_build_env_value "$TEAM_COMMON_NAME")"
  team_identifier="$(unquote_build_env_value "$TEAM_IDENTIFIER")"
  [[ -n "$team_common_name" && -n "$team_identifier" ]] || return

  CODESIGN_IDENTITY="$(normalize_codesign_identity "${team_common_name} (${team_identifier})")"
  export CODESIGN_IDENTITY
}

team_identifier_from_identity() {
  local identity="$1"
  if [[ "$identity" =~ '\(([A-Z0-9]+)\)[[:space:]]*$' ]]; then
    printf '%s' "$match[1]"
  fi
}

valid_team_identifier() {
  local team_identifier="$1"
  if [[ "$team_identifier" =~ '^[A-Z0-9]+$' ]]; then
    printf '%s' "$team_identifier"
  fi
}

configure_dotenv_keychain_access_group() {
  if [[ -n "${AV_DOTENV_KEYCHAIN_ACCESS_GROUP:-}" ]]; then
    AV_DOTENV_KEYCHAIN_ACCESS_GROUP="$(unquote_build_env_value "$AV_DOTENV_KEYCHAIN_ACCESS_GROUP")"
    export AV_DOTENV_KEYCHAIN_ACCESS_GROUP
    return
  fi

  local team_identifier=""
  if [[ -n "${APPLE_TEAM_ID:-}" ]]; then
    team_identifier="$(valid_team_identifier "$(unquote_build_env_value "$APPLE_TEAM_ID")")"
  fi
  if [[ -z "$team_identifier" && -n "${TEAM_IDENTIFIER:-}" ]]; then
    team_identifier="$(valid_team_identifier "$(unquote_build_env_value "$TEAM_IDENTIFIER")")"
  fi
  if [[ -z "$team_identifier" && -n "${CODESIGN_IDENTITY:-}" ]]; then
    team_identifier="$(team_identifier_from_identity "$CODESIGN_IDENTITY")"
  fi
  [[ -n "$team_identifier" ]] || team_identifier="ZU76A67LGU"

  AV_DOTENV_KEYCHAIN_ACCESS_GROUP="${team_identifier}.com.automicvault.dotenv"
  export AV_DOTENV_KEYCHAIN_ACCESS_GROUP
}

uses_real_codesign_identity() {
  [[ -n "${CODESIGN_IDENTITY:-}" && "$CODESIGN_IDENTITY" != "-" ]]
}

normalize_profile_path() {
  local path="$1"
  path="$(unquote_build_env_value "$path")"
  if [[ "$path" == "~/"* ]]; then
    path="$HOME/${path#~/}"
  fi
  printf '%s' "$path"
}

rust_protocol_version() {
  awk -F'"' '/PROTOCOL_VERSION[[:space:]]*:/ { print $2; exit }' "$ROOT_DIR/src/lib/rs/core.rs"
}

usage() {
  cat <<'EOF'
Usage: scripts/build-app.sh [--debug|--release] [--publish]

Build Automic Vault.app and print the app bundle path.

Options:
  --debug       Build faster local debug binaries. This is the default.
  --release     Build optimized release binaries for packaging.
  --publish     Require a current package database. Use for published builds.
  --help        Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --debug)
      CONFIGURATION="debug"
      shift
      ;;
    --release)
      CONFIGURATION="release"
      shift
      ;;
    --publish)
      PUBLISH_BUILD=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      cli_error "Unknown argument: $1"
      usage >&2
      exit 1
      ;;
  esac
done

load_build_env
configure_codesign_identity
configure_dotenv_keychain_access_group

case "$CONFIGURATION" in
  debug|release)
    ;;
  *)
    cli_error "Unknown GUI_BUILD_CONFIGURATION: $CONFIGURATION"
    usage >&2
    exit 1
    ;;
esac

BUILD_DIR="$ROOT_DIR/target/gui/$CONFIGURATION"
APP_DIR="$BUILD_DIR/Automic Vault.app"
MACOS_DIR="$APP_DIR/Contents/MacOS"
RESOURCES_DIR="$APP_DIR/Contents/Resources"
HELPERS_DIR="$APP_DIR/Contents/Library/LaunchServices"
LOGIN_ITEMS_DIR="$APP_DIR/Contents/Library/LoginItems"
EXECUTABLE="$MACOS_DIR/Automic Vault"
HELPER_EXECUTABLE="$HELPERS_DIR/com.automicvault.nuke-helper"
MENU_APP_DIR="$LOGIN_ITEMS_DIR/Automic Vault Menu.app"
MENU_MACOS_DIR="$MENU_APP_DIR/Contents/MacOS"
MENU_RESOURCES_DIR="$MENU_APP_DIR/Contents/Resources"
MENU_EXECUTABLE="$MENU_MACOS_DIR/Automic Vault Menu"
ICON_PNG="$ROOT_DIR/assets/gui-icon.png"
MENU_APP_ICON_NAME="gui-icon"
MENU_ICON_PNG="$ROOT_DIR/assets/NSMenuItem.png"
MENU_ICON_1X="$BUILD_DIR/NSMenuItem.png"
MENU_ICON_2X="$BUILD_DIR/NSMenuItem@2x.png"
ENRICHMENT_MANIFESTS_JSON="$BUILD_DIR/enrichment-manifests.json"
ICON_NAME="gui-icon"
ICONSET_DIR="$BUILD_DIR/$ICON_NAME.iconset"
ICON_ICNS="$BUILD_DIR/$ICON_NAME.icns"
SERVICE_MANAGEMENT_SHIM_DIR="$GUI_DIR/ServiceManagementShim"
SERVICE_MANAGEMENT_SHIM_INCLUDE_DIR="$SERVICE_MANAGEMENT_SHIM_DIR/include"
SERVICE_MANAGEMENT_SHIM_SOURCE="$SERVICE_MANAGEMENT_SHIM_DIR/ServiceManagementShim.m"
SERVICE_MANAGEMENT_SHIM_HEADER="$SERVICE_MANAGEMENT_SHIM_INCLUDE_DIR/ServiceManagementShim.h"
SERVICE_MANAGEMENT_SHIM_MODULEMAP="$SERVICE_MANAGEMENT_SHIM_INCLUDE_DIR/module.modulemap"
SERVICE_MANAGEMENT_SHIM_OBJECT="$BUILD_DIR/ServiceManagementShim.o"
DOTENV_ENTITLEMENTS="$BUILD_DIR/dotenv-keychain.entitlements"
HELPER_ENTITLEMENTS="$BUILD_DIR/nuke-helper.entitlements"
DOTENV_KEYCHAIN_ENTITLEMENT_ENABLED=false
if uses_real_codesign_identity; then
  DOTENV_KEYCHAIN_ENTITLEMENT_ENABLED=true
fi
[[ -n "${MIN_MACOS_VERSION:-}" ]] || cli_die "Set MIN_MACOS_VERSION in .env"
NUKE_PROTOCOL_VERSION="$(rust_protocol_version)"
[[ -n "$NUKE_PROTOCOL_VERSION" ]] || cli_die "Could not read PROTOCOL_VERSION from src/lib/rs/core.rs"
[[ -n "${NUKE_HELPER_VERSION:-}" ]] || cli_die "Set NUKE_HELPER_VERSION in .env"
APP_VERSION="$(awk -F'\"' '/^version = / { print $2; exit }' "$ROOT_DIR/Cargo.toml")"
APPLE_TEAM_ID="${APPLE_TEAM_ID:-}"

git_build_id() {
  git -C "$ROOT_DIR" rev-parse --short=12 HEAD 2>/dev/null || printf '%s' "$APP_VERSION"
}

if [[ "$CONFIGURATION" == "release" || "$PUBLISH_BUILD" == "true" ]]; then
  # Production builds intentionally let build.rs compute and track the Git ID.
  APP_BUILD_ID="$(git_build_id)"
  unset NUKE_BUILD_ID
elif [[ -n "${NUKE_BUILD_ID:-}" ]]; then
  APP_BUILD_ID="$NUKE_BUILD_ID"
  export NUKE_BUILD_ID
else
  # Local target/gui apps force a fresh daemon at launch, so a stable ID avoids
  # recompiling Rust for Swift-only commits while keeping app and daemon aligned.
  APP_BUILD_ID="local-${APP_VERSION}"
  export NUKE_BUILD_ID="$APP_BUILD_ID"
fi

APP_BUNDLE_ID="com.automicvault"
MENU_BUNDLE_ID="com.automicvault.menu-helper"
HELPER_BUNDLE_ID="com.automicvault.nuke-helper"
APP_PROVISIONING_PROFILE="${AV_APP_PROVISIONING_PROFILE:-}"
MENU_PROVISIONING_PROFILE="${AV_MENU_PROVISIONING_PROFILE:-}"
if [[ -n "$APP_PROVISIONING_PROFILE" ]]; then
  APP_PROVISIONING_PROFILE="$(normalize_profile_path "$APP_PROVISIONING_PROFILE")"
fi
if [[ -n "$MENU_PROVISIONING_PROFILE" ]]; then
  MENU_PROVISIONING_PROFILE="$(normalize_profile_path "$MENU_PROVISIONING_PROFILE")"
fi
COMBINED_DB_PATH="${AV_COMBINED_DB_PATH:-${ROOT_DIR}/../av.db/cache/automic-vault/combined.json}"

cli_step "Locating package database"
if [[ ! -f "$COMBINED_DB_PATH" ]]; then
  cli_die "Missing package database: ${COMBINED_DB_PATH}. Generate it in ../av.db or set AV_COMBINED_DB_PATH."
fi
cli_info "${COMBINED_DB_PATH}"

if [[ -z "$APPLE_TEAM_ID" && -n "${CODESIGN_IDENTITY:-}" ]]; then
  if [[ "${CODESIGN_IDENTITY}" =~ \(([A-Z0-9]+)\)[[:space:]]*$ ]]; then
    APPLE_TEAM_ID="${match[1]}"
  fi
fi

if [[ -n "$APPLE_TEAM_ID" ]]; then
  HELPER_REQUIREMENT="identifier \"$HELPER_BUNDLE_ID\" and anchor apple generic and certificate leaf[subject.OU] = \"$APPLE_TEAM_ID\""
else
  HELPER_REQUIREMENT="identifier \"$HELPER_BUNDLE_ID\" and anchor apple generic"
fi

if [[ "$CONFIGURATION" == "release" ]]; then
  [[ -n "${POSTHOG_API_KEY:-}" ]] || cli_die "Set POSTHOG_API_KEY in the environment for release GUI builds"
fi

if [[ -n "$APPLE_TEAM_ID" ]]; then
  export APPLE_TEAM_ID
else
  unset APPLE_TEAM_ID
fi
DOTENV_KEYCHAIN_BROKER_TEAM_ID="${AV_DOTENV_KEYCHAIN_ACCESS_GROUP%%.*}"
DOTENV_KEYCHAIN_BROKER_AV_REQUIREMENT="identifier \"${APP_BUNDLE_ID}.av\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"${DOTENV_KEYCHAIN_BROKER_TEAM_ID}\""
DOTENV_KEYCHAIN_BROKER_MENU_AV_REQUIREMENT="identifier \"${MENU_BUNDLE_ID}.av\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"${DOTENV_KEYCHAIN_BROKER_TEAM_ID}\""
export NUKE_HELPER_VERSION
SHARED_SWIFT_SOURCES=(
  "$GUI_DIR/Localization.swift"
  "$GUI_DIR/PackageModels.swift"
  "$GUI_DIR/SecurityCatalog.swift"
  "$GUI_DIR/NucleusBridge.swift"
  "$GUI_DIR/NukeHelperBridge.swift"
  "$GUI_DIR/NucleusStatusStore.swift"
  "$GUI_DIR/VaultApprovalStore.swift"
  "$GUI_DIR/ContainmentLogStore.swift"
)
GUI_SWIFT_SOURCES=(
  "$GUI_DIR/AppMain.swift"
  "$GUI_DIR/AppDelegate.swift"
  "$GUI_DIR/PackageNodeHazardEffect.swift"
  "$GUI_DIR/RootViewController.swift"
  "$GUI_DIR/PackageFieldView.swift"
  "$GUI_DIR/DossierView.swift"
  "$GUI_DIR/ExternalSurfaceView.swift"
  "$GUI_DIR/UpdateProgressViewController.swift"
  "$GUI_DIR/ContainmentLogWindowController.swift"
  "$GUI_DIR/UIStyle.swift"
)
MENU_SWIFT_SOURCES=(
  "$GUI_DIR/MenuBarMain.swift"
  "$GUI_DIR/MenuBarAppDelegate.swift"
  "$GUI_DIR/VaultDaemon.swift"
)

if [[ "$CONFIGURATION" == "release" ]]; then
  SWIFT_OPT_FLAGS=(-O)
else
  SWIFT_OPT_FLAGS=(-Onone -g -D DEBUG)
fi

RUST_BIN_DIR="$ROOT_DIR/target/release"
SWIFT_PACKAGE_BIN_DIR=""

is_current() {
  local output_path="$1"
  shift

  if [[ ! -e "$output_path" ]]; then
    return 1
  fi

  local input_path
  for input_path in "$@"; do
    if [[ -e "$input_path" && "$input_path" -nt "$output_path" ]]; then
      return 1
    fi
  done

  return 0
}

sign_binary() {
  local target_path="$1"
  local identifier="$2"
  local entitlements="${3:-}"

  local -a args=(
    --force
    --options runtime
    --sign "$CODESIGN_IDENTITY"
  )

  if [[ -n "$identifier" ]]; then
    args+=(
      --identifier "$identifier"
    )
  fi

  if [[ -n "$entitlements" ]]; then
    args+=(
      --entitlements "$entitlements"
    )
  fi

  codesign "${args[@]}" "$target_path"
}

sign_bundle() {
  local target_path="$1"
  local identifier="$2"
  local entitlements="${3:-}"

  local -a args=(
    --force
    --options runtime
    --sign "$CODESIGN_IDENTITY"
  )

  if [[ -n "$identifier" ]]; then
    args+=(
      --identifier "$identifier"
    )
  fi

  if [[ -n "$entitlements" ]]; then
    args+=(
      --entitlements "$entitlements"
    )
  fi

  codesign "${args[@]}" "$target_path"
}

adhoc_sign_binary() {
  local target_path="$1"
  local entitlements="${2:-}"

  local -a args=(
    --force
    --options runtime
    --sign -
  )

  if [[ -n "$entitlements" ]]; then
    args+=(
      --entitlements "$entitlements"
    )
  fi

  codesign "${args[@]}" "$target_path"
}

adhoc_sign_bundle() {
  local target_path="$1"
  local entitlements="${2:-}"

  local -a args=(
    --force
    --options runtime
    --sign -
  )

  if [[ -n "$entitlements" ]]; then
    args+=(
      --entitlements "$entitlements"
    )
  fi

  codesign "${args[@]}" "$target_path"
}

write_entitlements() {
  local output_path="$1"
  local include_dotenv_group="$2"

  cat >"$output_path" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
PLIST
  if [[ "$include_dotenv_group" == "true" ]]; then
    cat >>"$output_path" <<PLIST
  <key>keychain-access-groups</key>
  <array>
    <string>${AV_DOTENV_KEYCHAIN_ACCESS_GROUP}</string>
  </array>
PLIST
  fi
  cat >>"$output_path" <<PLIST
</dict>
</plist>
PLIST
}

verify_keychain_access_group_entitlement() {
  local target_path="$1"
  local label="$2"
  local output

  if ! output="$(codesign -d --entitlements - "$target_path" 2>/dev/null)"; then
    cli_die "Failed to read entitlements for $label: $target_path"
  fi
  if [[ "$output" != *"${AV_DOTENV_KEYCHAIN_ACCESS_GROUP}"* ]]; then
    cli_error "$output"
    cli_die "$label is missing keychain access group ${AV_DOTENV_KEYCHAIN_ACCESS_GROUP}"
  fi
}

verify_codesign_signature() {
  local target_path="$1"
  local label="$2"

  if ! codesign --verify --strict --verbose=4 "$target_path" >&2; then
    cli_die "$label failed strict codesign verification: $target_path"
  fi
}

decode_provisioning_profile() {
  local profile_path="$1"
  local output_path="$2"

  if /usr/bin/security cms -D -i "$profile_path" >"$output_path" 2>/dev/null; then
    return 0
  fi

  if command -v openssl >/dev/null 2>&1 &&
      openssl smime \
        -inform DER \
        -verify \
        -noverify \
        -in "$profile_path" \
        -out "$output_path" \
        >/dev/null 2>&1; then
    return 0
  fi

  cli_die "Unable to decode provisioning profile: $profile_path"
}

try_decode_provisioning_profile() {
  local profile_path="$1"
  local output_path="$2"

  if /usr/bin/security cms -D -i "$profile_path" >"$output_path" 2>/dev/null; then
    return 0
  fi

  if command -v openssl >/dev/null 2>&1 &&
      openssl smime \
        -inform DER \
        -verify \
        -noverify \
        -in "$profile_path" \
        -out "$output_path" \
        >/dev/null 2>&1; then
    return 0
  fi

  return 1
}

profile_plist_value() {
  local plist_path="$1"
  local key_path="$2"

  /usr/libexec/PlistBuddy -c "Print $key_path" "$plist_path" 2>/dev/null || true
}

profile_matches_bundle() {
  local profile_path="$1"
  local bundle_id="$2"
  local decoded_path app_identifier team_identifier expected_app_identifier keychain_groups

  decoded_path="$(mktemp "${TMPDIR:-/tmp}/automic-vault-profile.XXXXXX.plist")"
  if ! try_decode_provisioning_profile "$profile_path" "$decoded_path"; then
    rm -f "$decoded_path"
    return 1
  fi

  app_identifier="$(profile_plist_value "$decoded_path" ":Entitlements:com.apple.application-identifier")"
  team_identifier="$(profile_plist_value "$decoded_path" ":Entitlements:com.apple.developer.team-identifier")"
  keychain_groups="$(profile_plist_value "$decoded_path" ":Entitlements:keychain-access-groups")"
  rm -f "$decoded_path"

  expected_app_identifier="${team_identifier}.${bundle_id}"
  [[ -n "$team_identifier" ]] || return 1
  [[ "$app_identifier" == "$expected_app_identifier" ]] || return 1
  [[ "$AV_DOTENV_KEYCHAIN_ACCESS_GROUP" == "${team_identifier}."* ]] || return 1
  [[ "$keychain_groups" == *"$AV_DOTENV_KEYCHAIN_ACCESS_GROUP"* ||
     "$keychain_groups" == *"${team_identifier}.*"* ]]
}

describe_provisioning_profile() {
  local profile_path="$1"
  local decoded_path name app_identifier team_identifier keychain_groups

  decoded_path="$(mktemp "${TMPDIR:-/tmp}/automic-vault-profile.XXXXXX.plist")"
  if ! try_decode_provisioning_profile "$profile_path" "$decoded_path"; then
    rm -f "$decoded_path"
    cli_error "  $profile_path: unable to decode"
    return
  fi

  name="$(profile_plist_value "$decoded_path" ":Name")"
  app_identifier="$(profile_plist_value "$decoded_path" ":Entitlements:com.apple.application-identifier")"
  team_identifier="$(profile_plist_value "$decoded_path" ":Entitlements:com.apple.developer.team-identifier")"
  keychain_groups="$(profile_plist_value "$decoded_path" ":Entitlements:keychain-access-groups" | tr '\n' ' ')"
  rm -f "$decoded_path"

  cli_info "$profile_path"
  cli_info "  name: ${name:-unknown}"
  cli_info "  application-identifier: ${app_identifier:-missing}"
  cli_info "  team: ${team_identifier:-missing}"
  cli_info "  keychain-access-groups: ${keychain_groups:-missing}"
}

print_provisioning_profile_diagnostics() {
  local bundle_id="$1"
  local env_var="$2"
  local search_dir="$HOME/Library/MobileDevice/Provisioning Profiles"
  local team_identifier="${AV_DOTENV_KEYCHAIN_ACCESS_GROUP%%.*}"
  local profile found=false

  cli_error "No matching Developer ID provisioning profile found for $bundle_id."
  cli_error "Required application-identifier: ${team_identifier}.${bundle_id}"
  cli_error "Required keychain access group: $AV_DOTENV_KEYCHAIN_ACCESS_GROUP"
  cli_error "Searched: $search_dir"

  if [[ -d "$search_dir" ]]; then
    while IFS= read -r profile; do
      if [[ "$found" == "false" ]]; then
        cli_error "Installed profiles:"
        found=true
      fi
      describe_provisioning_profile "$profile"
    done < <(find "$search_dir" -type f \( -name '*.provisionprofile' -o -name '*.mobileprovision' \) 2>/dev/null | sort)
  fi

  if [[ "$found" == "false" ]]; then
    cli_error "Installed profiles: none"
  fi

  cli_die "Set $env_var to an explicit profile path if it is stored elsewhere."
}

find_provisioning_profile() {
  local bundle_id="$1"
  local search_dir="$HOME/Library/MobileDevice/Provisioning Profiles"
  local profile
  [[ -d "$search_dir" ]] || return 1

  while IFS= read -r profile; do
    if profile_matches_bundle "$profile" "$bundle_id"; then
      printf '%s\n' "$profile"
      return 0
    fi
  done < <(find "$search_dir" -type f \( -name '*.provisionprofile' -o -name '*.mobileprovision' \) 2>/dev/null | sort)

  return 1
}

resolve_provisioning_profile() {
  local current_profile="$1"
  local bundle_id="$2"
  local env_var="$3"
  local label="$4"

  if [[ -n "$current_profile" ]]; then
    current_profile="$(normalize_profile_path "$current_profile")"
    [[ -f "$current_profile" ]] || cli_die "$label provisioning profile not found: $current_profile"
    printf '%s\n' "$current_profile"
    return 0
  fi

  if current_profile="$(find_provisioning_profile "$bundle_id")"; then
    cli_info "Using $label provisioning profile: $current_profile"
    printf '%s\n' "$current_profile"
    return 0
  fi

  print_provisioning_profile_diagnostics "$bundle_id" "$env_var"
}

validate_provisioning_profile() {
  local profile_path="$1"
  local bundle_id="$2"
  local label="$3"
  local decoded_path app_identifier team_identifier expected_app_identifier keychain_groups

  [[ -f "$profile_path" ]] || cli_die "$label provisioning profile not found: $profile_path"

  decoded_path="$(mktemp "$BUILD_DIR/${label//[^A-Za-z0-9]/-}.profile.XXXXXX.plist")"
  decode_provisioning_profile "$profile_path" "$decoded_path"

  app_identifier="$(profile_plist_value "$decoded_path" ":Entitlements:com.apple.application-identifier")"
  team_identifier="$(profile_plist_value "$decoded_path" ":Entitlements:com.apple.developer.team-identifier")"
  keychain_groups="$(profile_plist_value "$decoded_path" ":Entitlements:keychain-access-groups")"
  rm -f "$decoded_path"

  expected_app_identifier="${team_identifier}.${bundle_id}"
  if [[ -z "$team_identifier" || "$app_identifier" != "$expected_app_identifier" ]]; then
    cli_error "Profile application identifier: ${app_identifier:-missing}"
    cli_die "$label provisioning profile must contain application identifier $expected_app_identifier"
  fi

  if [[ "$AV_DOTENV_KEYCHAIN_ACCESS_GROUP" != "${team_identifier}."* ]]; then
    cli_error "Profile team identifier: $team_identifier"
    cli_die "$label provisioning profile team does not match access group $AV_DOTENV_KEYCHAIN_ACCESS_GROUP"
  fi

  if [[ "$keychain_groups" != *"$AV_DOTENV_KEYCHAIN_ACCESS_GROUP"* &&
        "$keychain_groups" != *"${team_identifier}.*"* ]]; then
    cli_error "$keychain_groups"
    cli_die "$label provisioning profile does not cover keychain access group $AV_DOTENV_KEYCHAIN_ACCESS_GROUP"
  fi
}

require_dotenv_provisioning_profiles() {
  [[ "$DOTENV_KEYCHAIN_ENTITLEMENT_ENABLED" == "true" ]] || return 0

  APP_PROVISIONING_PROFILE="$(
    resolve_provisioning_profile \
      "$APP_PROVISIONING_PROFILE" \
      "$APP_BUNDLE_ID" \
      "AV_APP_PROVISIONING_PROFILE" \
      "Automic Vault app"
  )"
  MENU_PROVISIONING_PROFILE="$(
    resolve_provisioning_profile \
      "$MENU_PROVISIONING_PROFILE" \
      "$MENU_BUNDLE_ID" \
      "AV_MENU_PROVISIONING_PROFILE" \
      "menu helper app"
  )"

  validate_provisioning_profile "$APP_PROVISIONING_PROFILE" "$APP_BUNDLE_ID" "Automic Vault app"
  validate_provisioning_profile "$MENU_PROVISIONING_PROFILE" "$MENU_BUNDLE_ID" "menu helper app"
}

embed_provisioning_profile() {
  local profile_path="$1"
  local target_bundle="$2"
  local bundle_id="$3"
  local label="$4"

  validate_provisioning_profile "$profile_path" "$bundle_id" "$label"
  cp "$profile_path" "$target_bundle/Contents/embedded.provisionprofile"
}

build_icon() {
  local source_png="$1"
  local iconset_dir="$2"
  local output_icns="$3"

  if is_current "$output_icns" "$source_png"; then
    return
  fi

  rm -rf "$iconset_dir" "$output_icns"
  mkdir -p "$iconset_dir"

  local -a icon_sizes=(16 32 128 256 512)
  local size
  for size in "${icon_sizes[@]}"; do
    sips -z "$size" "$size" "$source_png" \
      --out "$iconset_dir/icon_${size}x${size}.png" \
      >/dev/null

    local retina_size=$((size * 2))
    sips -z "$retina_size" "$retina_size" "$source_png" \
      --out "$iconset_dir/icon_${size}x${size}@2x.png" \
      >/dev/null
  done

  iconutil -c icns "$iconset_dir" -o "$output_icns"
}

generate_enrichment_manifest_index() {
  local output_path="$1"
  local manifest_dir="$ROOT_DIR/manifests/enrichments"
  local temp_path="${output_path}.tmp"
  local -a manifest_names=()
  local manifest_path

  if [[ -d "$manifest_dir" ]]; then
    for manifest_path in "$manifest_dir"/*.rs(N); do
      manifest_names+=("${${manifest_path:t}:r}")
    done
  fi

  {
    printf '[\n'
    local count="${#manifest_names[@]}"
    local index
    for (( index = 1; index <= count; index++ )); do
      local suffix=','
      if [[ "$index" -eq "$count" ]]; then
        suffix=''
      fi
      printf '  "%s"%s\n' "${manifest_names[$index]}" "$suffix"
    done
    printf ']\n'
  } >"$temp_path"

  if [[ -f "$output_path" ]] && cmp -s "$temp_path" "$output_path"; then
    rm -f "$temp_path"
  else
    mv "$temp_path" "$output_path"
  fi
}

copy_localizations() {
  local destination_dir="$1"
  local localization_dir

  [[ -d "$GUI_LOCALIZATION_DIR" ]] || return 0
  rm -rf "$destination_dir"/*.lproj(N)
  for localization_dir in "$GUI_LOCALIZATION_DIR"/*.lproj(N); do
    cp -R "$localization_dir" "$destination_dir/"
  done
}

copy_pack_images() {
  local destination_dir="$1"
  local source_dir="$GUI_DIR/Resources/PackImages"

  rm -rf "$destination_dir/PackImages"
  [[ -d "$source_dir" ]] || return 0
  cp -R "$source_dir" "$destination_dir/"
}

cli_title "Build Automic Vault.app"
cli_info "Configuration: $CONFIGURATION"
cli_info "Output: $APP_DIR"

mkdir -p "$BUILD_DIR"
if [[ "$DOTENV_KEYCHAIN_ENTITLEMENT_ENABLED" != "true" ]]; then
  cli_warn "Skipping dotenv keychain access-group entitlement for ad-hoc signing"
fi
require_dotenv_provisioning_profiles
write_entitlements "$DOTENV_ENTITLEMENTS" "$DOTENV_KEYCHAIN_ENTITLEMENT_ENABLED"
write_entitlements "$HELPER_ENTITLEMENTS" false
cli_step "Building Rust binaries"
cargo build \
  --release \
  --features packaged-db \
  --bin av \
  --bin nuke-helper \
  --manifest-path "$ROOT_DIR/Cargo.toml"
cli_step "Building Cocoa app"
xcrun swift build \
  --package-path "$GUI_DIR" \
  --configuration "$CONFIGURATION" \
  --product AutomicVaultApp \
  >&2
SWIFT_PACKAGE_BIN_DIR="$(
  xcrun swift build \
    --package-path "$GUI_DIR" \
    --configuration "$CONFIGURATION" \
    --show-bin-path |
    tail -n 1
)"
cli_step "Preparing icons and manifests"
build_icon "$ICON_PNG" "$ICONSET_DIR" "$ICON_ICNS"
if ! is_current "$MENU_ICON_1X" "$MENU_ICON_PNG"; then
  sips -z 27 27 "$MENU_ICON_PNG" --out "$MENU_ICON_1X" >/dev/null
fi
if ! is_current "$MENU_ICON_2X" "$MENU_ICON_PNG"; then
  cp "$MENU_ICON_PNG" "$MENU_ICON_2X"
fi
generate_enrichment_manifest_index "$ENRICHMENT_MANIFESTS_JSON"

if [[ "$CONFIGURATION" == "release" ]]; then
  rm -rf "$APP_DIR"
fi
mkdir -p \
  "$MACOS_DIR" \
  "$RESOURCES_DIR" \
  "$HELPERS_DIR" \
  "$MENU_MACOS_DIR" \
  "$MENU_RESOURCES_DIR"
rm -f \
  "$APP_DIR/Contents/embedded.provisionprofile" \
  "$MENU_APP_DIR/Contents/embedded.provisionprofile"

cp "$SWIFT_PACKAGE_BIN_DIR/AutomicVaultApp" "$EXECUTABLE"

if ! is_current "$MENU_EXECUTABLE" "${SHARED_SWIFT_SOURCES[@]}" "${MENU_SWIFT_SOURCES[@]}" "$SERVICE_MANAGEMENT_SHIM_SOURCE" "$SERVICE_MANAGEMENT_SHIM_HEADER" "$SERVICE_MANAGEMENT_SHIM_MODULEMAP"; then
  cli_step "Building menu bar helper"
  if ! is_current "$SERVICE_MANAGEMENT_SHIM_OBJECT" "$SERVICE_MANAGEMENT_SHIM_SOURCE" "$SERVICE_MANAGEMENT_SHIM_HEADER"; then
    xcrun clang \
      -target "$(uname -m)-apple-macos${MIN_MACOS_VERSION}" \
      -I "$SERVICE_MANAGEMENT_SHIM_INCLUDE_DIR" \
      -c "$SERVICE_MANAGEMENT_SHIM_SOURCE" \
      -o "$SERVICE_MANAGEMENT_SHIM_OBJECT"
  fi
  xcrun swiftc \
    "${SWIFT_OPT_FLAGS[@]}" \
    -target "$(uname -m)-apple-macos${MIN_MACOS_VERSION}" \
    -I "$SERVICE_MANAGEMENT_SHIM_INCLUDE_DIR" \
    -framework AppKit \
    -framework Foundation \
    -framework QuartzCore \
    -framework ServiceManagement \
    -framework UserNotifications \
    -o "$MENU_EXECUTABLE" \
    "$SERVICE_MANAGEMENT_SHIM_OBJECT" \
    "${SHARED_SWIFT_SOURCES[@]}" \
    "${MENU_SWIFT_SOURCES[@]}"
fi

cli_step "Assembling app bundle"
cp "$RUST_BIN_DIR/av" "$RESOURCES_DIR/av"
cp "$COMBINED_DB_PATH" "$RESOURCES_DIR/combined.json"
rm -f "$RESOURCES_DIR/isotopes.json"
cp "$ENRICHMENT_MANIFESTS_JSON" "$RESOURCES_DIR/enrichment-manifests.json"
cp "$RUST_BIN_DIR/nuke-helper" "$HELPER_EXECUTABLE"
cp "$ICON_ICNS" "$RESOURCES_DIR/$ICON_NAME.icns"
copy_localizations "$RESOURCES_DIR"
copy_pack_images "$RESOURCES_DIR"
cp "$ICON_ICNS" "$MENU_RESOURCES_DIR/$MENU_APP_ICON_NAME.icns"
cp "$RUST_BIN_DIR/av" "$MENU_RESOURCES_DIR/av"
cp "$COMBINED_DB_PATH" "$MENU_RESOURCES_DIR/combined.json"
rm -f "$MENU_RESOURCES_DIR/isotopes.json"
cp "$ENRICHMENT_MANIFESTS_JSON" "$MENU_RESOURCES_DIR/enrichment-manifests.json"
copy_localizations "$MENU_RESOURCES_DIR"
cp "$MENU_ICON_1X" "$MENU_RESOURCES_DIR/NSMenuItem.png"
cp "$MENU_ICON_2X" "$MENU_RESOURCES_DIR/NSMenuItem@2x.png"
chmod 755 \
  "$EXECUTABLE" \
  "$RESOURCES_DIR/av" \
  "$HELPER_EXECUTABLE" \
  "$MENU_EXECUTABLE" \
  "$MENU_RESOURCES_DIR/av"

cat >"$APP_DIR/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleLocalizations</key>
  <array>
    <string>en</string>
    <string>ja</string>
    <string>de</string>
    <string>fr</string>
    <string>zh-Hans</string>
  </array>
  <key>CFBundleExecutable</key>
  <string>Automic Vault</string>
  <key>CFBundleIconFile</key>
  <string>gui-icon</string>
  <key>CFBundleIdentifier</key>
  <string>${APP_BUNDLE_ID}</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLName</key>
      <string>Automic Vault package links</string>
      <key>CFBundleURLSchemes</key>
      <array>
        <string>automicvault</string>
      </array>
    </dict>
  </array>
  <key>CFBundleName</key>
  <string>Automic Vault</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>SMPrivilegedExecutables</key>
  <dict>
    <key>${HELPER_BUNDLE_ID}</key>
    <string>${HELPER_REQUIREMENT}</string>
  </dict>
  <key>CFBundleShortVersionString</key>
  <string>${APP_VERSION}</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>NukeBuildID</key>
  <string>${APP_BUILD_ID}</string>
  <key>NukeProtocolVersion</key>
  <string>${NUKE_PROTOCOL_VERSION}</string>
  <key>NukeHelperVersion</key>
  <string>${NUKE_HELPER_VERSION}</string>
  <key>AVDotenvKeychainAccessGroup</key>
  <string>${AV_DOTENV_KEYCHAIN_ACCESS_GROUP}</string>
  <key>AVDotenvKeychainBrokerAuthorizedClients</key>
  <array>
    <string>${DOTENV_KEYCHAIN_BROKER_AV_REQUIREMENT}</string>
    <string>${DOTENV_KEYCHAIN_BROKER_MENU_AV_REQUIREMENT}</string>
  </array>
  <key>LSMinimumSystemVersion</key>
  <string>${MIN_MACOS_VERSION}</string>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsArbitraryLoadsInWebContent</key>
    <true/>
  </dict>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST

if [[ "$CONFIGURATION" == "release" ]]; then
  /usr/bin/plutil \
    -insert PostHogAPIKey \
    -string "$POSTHOG_API_KEY" \
    "$APP_DIR/Contents/Info.plist"
fi

cat >"$MENU_APP_DIR/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleLocalizations</key>
  <array>
    <string>en</string>
    <string>ja</string>
    <string>de</string>
    <string>fr</string>
    <string>zh-Hans</string>
  </array>
  <key>CFBundleExecutable</key>
  <string>Automic Vault Menu</string>
  <key>CFBundleIconFile</key>
  <string>${MENU_APP_ICON_NAME}</string>
  <key>CFBundleIdentifier</key>
  <string>${MENU_BUNDLE_ID}</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>Automic Vault Menu</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${APP_VERSION}</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>${MIN_MACOS_VERSION}</string>
  <key>LSUIElement</key>
  <true/>
  <key>NukeBuildID</key>
  <string>${APP_BUILD_ID}</string>
  <key>NukeProtocolVersion</key>
  <string>${NUKE_PROTOCOL_VERSION}</string>
  <key>AVDotenvKeychainAccessGroup</key>
  <string>${AV_DOTENV_KEYCHAIN_ACCESS_GROUP}</string>
  <key>AVDotenvKeychainBrokerAuthorizedClients</key>
  <array>
    <string>${DOTENV_KEYCHAIN_BROKER_AV_REQUIREMENT}</string>
    <string>${DOTENV_KEYCHAIN_BROKER_MENU_AV_REQUIREMENT}</string>
  </array>
</dict>
</plist>
PLIST

if [[ "$DOTENV_KEYCHAIN_ENTITLEMENT_ENABLED" == "true" ]]; then
  cli_step "Embedding Developer ID provisioning profiles"
  embed_provisioning_profile \
    "$APP_PROVISIONING_PROFILE" \
    "$APP_DIR" \
    "$APP_BUNDLE_ID" \
    "Automic Vault app"
  embed_provisioning_profile \
    "$MENU_PROVISIONING_PROFILE" \
    "$MENU_APP_DIR" \
    "$MENU_BUNDLE_ID" \
    "menu helper app"
fi

if uses_real_codesign_identity; then
  cli_step "Signing bundle with Developer ID"
  sign_binary "$RESOURCES_DIR/av" "${APP_BUNDLE_ID}.av"
  sign_binary "$MENU_RESOURCES_DIR/av" "${MENU_BUNDLE_ID}.av"
  sign_binary \
    "$HELPER_EXECUTABLE" \
    "$HELPER_BUNDLE_ID" \
    "$HELPER_ENTITLEMENTS"
  sign_binary "$MENU_EXECUTABLE" "$MENU_BUNDLE_ID" "$DOTENV_ENTITLEMENTS"
  sign_bundle "$MENU_APP_DIR" "$MENU_BUNDLE_ID" "$DOTENV_ENTITLEMENTS"
  sign_bundle \
    "$APP_DIR" \
    "$APP_BUNDLE_ID" \
    "$DOTENV_ENTITLEMENTS"
else
  cli_step "Signing bundle ad-hoc"
  adhoc_sign_binary "$RESOURCES_DIR/av"
  adhoc_sign_binary "$MENU_RESOURCES_DIR/av"
  adhoc_sign_binary \
    "$HELPER_EXECUTABLE" \
    "$HELPER_ENTITLEMENTS"
  adhoc_sign_binary "$MENU_EXECUTABLE" "$DOTENV_ENTITLEMENTS"
  adhoc_sign_bundle "$MENU_APP_DIR" "$DOTENV_ENTITLEMENTS"
  adhoc_sign_bundle \
    "$APP_DIR" \
    "$DOTENV_ENTITLEMENTS"
fi

verify_codesign_signature "$RESOURCES_DIR/av" "bundled av"
verify_codesign_signature "$MENU_RESOURCES_DIR/av" "menu bundled av"
verify_codesign_signature "$HELPER_EXECUTABLE" "privileged helper"
verify_codesign_signature "$MENU_EXECUTABLE" "menu helper executable"
verify_codesign_signature "$MENU_APP_DIR" "menu helper app"
verify_codesign_signature "$APP_DIR" "Automic Vault app"
if [[ "$DOTENV_KEYCHAIN_ENTITLEMENT_ENABLED" == "true" ]]; then
  verify_keychain_access_group_entitlement "$MENU_APP_DIR" "menu helper app"
  verify_keychain_access_group_entitlement "$APP_DIR" "Automic Vault app"
fi

cli_done "App bundle ready"
echo "$APP_DIR"
