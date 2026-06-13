#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
source "${repo_root}/scripts/cli-style.sh"
cli_style_init "Automic Vault"
build_dir="${repo_root}/target/gui"
target_dir="${repo_root}/target"
default_background="${repo_root}/assets/dmg-bg@2x.png"
release_s3_uri="s3://automicvault.com/Automic Vault.dmg"
scanner_s3_uri="s3://automicvault.com/scanner.gz"
scanner_script_s3_uri="s3://automicvault.com/scanner.sh"
scanner_script_source="${repo_root}/scripts/scanner.sh"
release_cloudfront_alias="${AUTOMIC_VAULT_RELEASE_DOMAIN:-automicvault.com}"
release_cloudfront_path="/Automic%20Vault.dmg"
release_cloudfront_paths=("${release_cloudfront_path}" "/scanner.gz" "/scanner.sh")
finder_left=120
finder_top=120
finder_width=796
finder_height=494
icon_size=128
icon_gap_from_center=155

output_path=""
background_path=""
volume_name=""
notarize=false
install_app=false
publish_release=false
clobber_release=false

load_build_env() {
  local env_file="${repo_root}/.env"
  [[ -f "${env_file}" ]] || return

  local line key value
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line%$'\r'}"
    [[ -n "${line}" && "${line}" != \#* && "${line}" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue

    key="${line%%=*}"
    value="${line#*=}"
    if [[ -z "${!key+x}" ]]; then
      export "${key}=${value}"
    fi
  done <"${env_file}"
}

unquote_build_env_value() {
  local value="$1"
  case "${value}" in
    \"*\")
      value="${value#\"}"
      value="${value%\"}"
      ;;
    \'*\')
      value="${value#\'}"
      value="${value%\'}"
      ;;
  esac
  printf '%s' "${value}"
}

normalize_codesign_identity() {
  local identity="${1}"
  if [[ "${identity}" == "-" || "${identity}" == *:* ]]; then
    printf '%s' "${identity}"
  else
    printf 'Developer ID Application: %s' "${identity}"
  fi
}

configure_codesign_identity() {
  if [[ -n "${CODESIGN_IDENTITY:-}" ]]; then
    CODESIGN_IDENTITY="$(normalize_codesign_identity "$(unquote_build_env_value "${CODESIGN_IDENTITY}")")"
    export CODESIGN_IDENTITY
    return
  fi

  if [[ -z "${TEAM_COMMON_NAME:-}" || -z "${TEAM_IDENTIFIER:-}" ]]; then
    return
  fi

  local team_common_name team_identifier
  team_common_name="$(unquote_build_env_value "${TEAM_COMMON_NAME}")"
  team_identifier="$(unquote_build_env_value "${TEAM_IDENTIFIER}")"
  [[ -n "${team_common_name}" && -n "${team_identifier}" ]] || return

  CODESIGN_IDENTITY="$(normalize_codesign_identity "${team_common_name} (${team_identifier})")"
  export CODESIGN_IDENTITY
}

count_isotope_manifests() {
  local root="$1"

  if [[ ! -d "${root}" ]]; then
    printf '0'
    return
  fi

  find "${root}" \
    -mindepth 2 \
    -maxdepth 2 \
    -type f \
    -name automic-vault.yml \
    -print 2>/dev/null |
    wc -l |
    tr -d '[:space:]'
}

ensure_isotope_sources_present() {
  local av_db_root
  local isotope_root
  local radioisotope_root
  local isotope_count
  local radioisotope_count

  av_db_root="${AV_DB_ROOT:-${repo_root}/../av.db}"
  isotope_root="${AUTOMIC_VAULT_REPO_CACHE:-${av_db_root}/../isotopes}"
  radioisotope_root="${AUTOMIC_VAULT_RADIOISOTOPES_REPO:-${av_db_root}/../radioisotopes}"
  isotope_count="$(count_isotope_manifests "${isotope_root}")"
  radioisotope_count="$(count_isotope_manifests "${radioisotope_root}")"

  if (( isotope_count + radioisotope_count == 0 )); then
    cli_error "No isotope or radioisotope manifests found"
    cli_info "Isotope root: ${isotope_root}"
    cli_info "Radioisotope root: ${radioisotope_root}"
    cli_info "Run scripts/sync-isotope-checkouts.sh or set AUTOMIC_VAULT_REPO_CACHE/AUTOMIC_VAULT_RADIOISOTOPES_REPO"
    exit 1
  fi

  cli_info "Isotope manifests: ${isotope_count}; radioisotope manifests: ${radioisotope_count}"
}

usage() {
  cat <<'EOF'
Usage: scripts/build-dmg.sh [--output PATH] [--background PATH]
                            [--volume-name NAME] [--notarize] [--install]
                            [--publish] [--clobber]

Build the release app bundle and package it into a DMG in target/.

Options:
  --output PATH       Write the final DMG to PATH.
  --background PATH   Use PATH as the Finder window background image.
  --volume-name NAME  Override the mounted DMG volume name.
  --notarize          Submit the DMG for notarization and staple it.
  --notorize          Alias for --notarize.
  --install           Install the built app bundle into /Applications.
  --publish           Ask Codex for release notes and the next semantic
                      version, update Cargo.toml and Cargo.lock, commit
                      vX.Y.Z, push, then create a GitHub release for vX.Y.Z
                      with the DMG.
                      Also uploads /scanner.gz and /scanner.sh to S3.
                      Requires --notarize.
  --clobber           Delete any existing GitHub release for vX.Y.Z before
                      publishing. Requires --publish.
  --help              Show this help.
EOF
}

publish_github_release() {
  local tag="$1"
  local version="$2"
  local dmg_path="$3"
  local release_notes_path="$4"
  local asset_label
  local scanner_gz_path
  local target_ref
  local -a release_args

  asset_label="$(basename "${dmg_path}")"
  target_ref="$(git -C "${repo_root}" rev-parse HEAD)"

  scanner_gz_path="$(build_public_scanner_artifact)"

  if [[ "${clobber_release}" == "true" ]]; then
    clobber_github_release "${tag}"
  fi

  release_args=(
    "${tag}"
    --draft
    --notes-file "${release_notes_path}"
    --target "${target_ref}"
    --title "Automic Vault ${version}"
  )

  cli_require_tool gh
  cli_step "Creating draft GitHub release ${tag}"
  gh release create "${release_args[@]}" >&2

  cli_step "Uploading DMG to GitHub release"
  if ! gh release upload "${tag}" "${dmg_path}#${asset_label}" >&2; then
    cli_error "DMG upload failed"
    cli_die "Draft release remains unpublished: ${tag}"
  fi

  publish_public_dmg "${dmg_path}" "${tag}" "${scanner_gz_path}"

  cli_step "Publishing GitHub release ${tag}"
  if ! gh release edit "${tag}" --draft=false >&2; then
    cli_error "Release publish failed"
    cli_die "Draft release remains unpublished: ${tag}"
  fi
}

build_public_scanner_artifact() {
  if [[ ! -f "${scanner_script_source}" ]]; then
    cli_die "Missing scanner shell script: ${scanner_script_source}"
  fi

  "${repo_root}/scripts/build-scanner.sh"
}

clobber_github_release() {
  local tag="$1"
  local view_error

  cli_require_tool gh
  view_error="$(mktemp "${TMPDIR:-/tmp}/automic-vault-release-view.XXXXXX")"

  if ! gh release view "${tag}" >/dev/null 2>"${view_error}"; then
    if grep -Eiq 'release not found|not found|HTTP 404' "${view_error}"; then
      rm -f "${view_error}"
      return 0
    fi

    cat "${view_error}" >&2
    rm -f "${view_error}"
    cli_die "Unable to check existing GitHub release ${tag}"
  fi

  rm -f "${view_error}"

  cli_step "Clobbering existing GitHub release ${tag}"
  if ! gh release delete "${tag}" --yes --cleanup-tag >&2; then
    cli_die "Unable to clobber existing GitHub release ${tag}"
  fi
}

latest_release_tag() {
  local release_tag

  cli_require_tool gh

  if ! release_tag="$(
    gh release list \
      --exclude-drafts \
      --limit 1 \
      --json tagName \
      --jq '.[0].tagName'
  )"; then
    cli_die "Unable to list GitHub releases"
  fi

  [[ -n "${release_tag}" && "${release_tag}" != "null" ]] || return 1
  printf '%s\n' "${release_tag}"
}

ensure_git_tag_available() {
  local tag="$1"

  if git -C "${repo_root}" rev-parse --verify --quiet "${tag}^{commit}" >/dev/null; then
    return 0
  fi

  cli_step "Fetching release tag ${tag}"
  if ! git -C "${repo_root}" fetch --quiet origin "refs/tags/${tag}:refs/tags/${tag}"; then
    cli_die "Unable to fetch release tag ${tag}"
  fi
}

package_version() {
  local pkgid version

  pkgid="$(cargo pkgid --manifest-path "${repo_root}/Cargo.toml")"
  version="${pkgid##*#}"
  printf '%s\n' "${version##*@}"
}

version_gt() {
  local left="$1"
  local right="$2"
  local left_major left_minor left_patch right_major right_minor right_patch

  IFS=. read -r left_major left_minor left_patch <<<"${left}"
  IFS=. read -r right_major right_minor right_patch <<<"${right}"

  if (( 10#${left_major} != 10#${right_major} )); then
    (( 10#${left_major} > 10#${right_major} ))
  elif (( 10#${left_minor} != 10#${right_minor} )); then
    (( 10#${left_minor} > 10#${right_minor} ))
  else
    (( 10#${left_patch} > 10#${right_patch} ))
  fi
}

ensure_release_worktree_state() {
  git -C "${repo_root}" diff --cached --quiet ||
    cli_die "Index has staged changes; commit or stash them before publishing"
  git -C "${repo_root}" diff --quiet -- Cargo.toml Cargo.lock ||
    cli_die "Cargo.toml or Cargo.lock has unstaged changes; commit or stash them before publishing"
}

generate_release_plan() {
  local current_version="$1"
  local plan_path
  local notes_path
  local version_path
  local previous_tag
  local compare_range
  local prompt
  local target_ref

  target_ref="$(git -C "${repo_root}" rev-parse HEAD)"

  cli_require_tool codex
  cli_require_tool gh

  plan_path="$(mktemp "${TMPDIR:-/tmp}/automic-vault-release-plan.XXXXXX")"
  notes_path="$(mktemp "${TMPDIR:-/tmp}/automic-vault-release-notes.XXXXXX")"
  version_path="$(mktemp "${TMPDIR:-/tmp}/automic-vault-release-version.XXXXXX")"

  if previous_tag="$(latest_release_tag)"; then
    ensure_git_tag_available "${previous_tag}"
    compare_range="${previous_tag}..${target_ref}"
    prompt="Plan the next Automic Vault release.

Repository: ${repo_root}
Previous release tag: ${previous_tag}
Current Cargo package version: ${current_version}
Compare range: ${compare_range}

Inspect the git history and diff for that range. Choose the next SemVer version based on the changes since the previous release.
Use patch for compatible fixes, minor for new user-visible behavior, and major only for intentional breaking changes.
Write concise GitHub release notes in Markdown focused on behavior, fixes, user-visible improvements, packaging, and operational changes.
Do not edit files or create commits.
Output exactly this format, with no code fence, no title, no preamble, no commit hashes, no contributor list, and no GitHub auto-generated notes references:
1. Release Notes
<release notes markdown>
2. New Semantic Version
<X.Y.Z>"
  else
    prompt="Plan the initial Automic Vault release.

Repository: ${repo_root}
Current Cargo package version: ${current_version}
Target ref: ${target_ref}

Inspect the repository and recent git history. Choose the next SemVer version.
Write concise GitHub release notes in Markdown focused on behavior, fixes, user-visible improvements, packaging, and operational changes.
Do not edit files or create commits.
Output exactly this format, with no code fence, no title, no preamble, no commit hashes, no contributor list, and no GitHub auto-generated notes references:
1. Release Notes
<release notes markdown>
2. New Semantic Version
<X.Y.Z>"
  fi

  cli_step "Generating release plan with Codex"
  if ! codex exec \
    --cd "${repo_root}" \
    --sandbox read-only \
    --config approval_policy=\"never\" \
    --color never \
    --ephemeral \
    --output-last-message "${plan_path}" \
    "${prompt}" \
    >&2; then
    cli_die "Codex release planning failed"
  fi

  if [[ ! -s "${plan_path}" ]]; then
    cli_die "Codex generated an empty release plan"
  fi

  awk '
    /^[[:space:]]*(1\.)?[[:space:]]*Release Notes[[:space:]]*$/ { in_notes = 1; next }
    /^[[:space:]]*(2\.)?[[:space:]]*New Semantic Version[[:space:]]*$/ { exit }
    in_notes { print }
  ' "${plan_path}" >"${notes_path}"

  awk '
    /^[[:space:]]*(2\.)?[[:space:]]*New Semantic Version[[:space:]]*$/ { in_version = 1; next }
    in_version && match($0, /[0-9]+\.[0-9]+\.[0-9]+/) {
      print substr($0, RSTART, RLENGTH)
      exit
    }
  ' "${plan_path}" >"${version_path}"

  if [[ ! -s "${notes_path}" ]]; then
    cli_die "Codex release plan did not include release notes"
  fi
  if [[ ! -s "${version_path}" ]]; then
    cli_die "Codex release plan did not include an X.Y.Z version"
  fi

  cli_info "1. Release Notes"
  sed 's/^/  /' "${notes_path}" >&2
  cli_info "2. New Semantic Version"
  sed 's/^/  /' "${version_path}" >&2

  printf '%s\n%s\n' "${notes_path}" "${version_path}"
}

bump_cargo_version() {
  local version="$1"

  [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    cli_die "Release publishing requires an X.Y.Z version, got: ${version}"

  VERSION="${version}" perl -0pi -e '
    my $version = $ENV{VERSION};
    s/(\[package\](?:(?!^\[).)*?^version\s*=\s*")[^"]+(")/$1$version$2/ms
      or die "Unable to update package.version in Cargo.toml\n";
  ' "${repo_root}/Cargo.toml"

  cargo update \
    --manifest-path "${repo_root}/Cargo.toml" \
    -p nucleus \
    --precise "${version}" \
    >/dev/null
}

commit_release_version() {
  local version="$1"
  local tag="v${version}"

  git -C "${repo_root}" add Cargo.toml Cargo.lock

  if git -C "${repo_root}" diff --cached --quiet; then
    cli_die "Cargo.toml and Cargo.lock were unchanged after version bump"
  fi

  cli_step "Committing ${tag}"
  git -C "${repo_root}" commit -m "${tag}" >&2
}

push_current_branch() {
  local branch

  branch="$(git -C "${repo_root}" rev-parse --abbrev-ref HEAD)"
  [[ "${branch}" != "HEAD" ]] || cli_die "Cannot push release commit from detached HEAD"

  cli_step "Pushing ${branch}"
  git -C "${repo_root}" push >&2
}

publish_public_dmg() {
  local dmg_path="$1"
  local tag="$2"
  local scanner_gz_path="$3"
  local distribution_id

  cli_require_tool aws
  cli_step "Uploading DMG to ${release_s3_uri}"
  if ! aws s3 cp \
    "${dmg_path}" \
    "${release_s3_uri}" \
    --content-type application/x-apple-diskimage \
    >&2; then
    cli_error "S3 upload failed"
    cli_die "Draft release remains unpublished: ${tag}"
  fi

  cli_step "Uploading scanner binary to ${scanner_s3_uri}"
  if ! aws s3 cp \
    "${scanner_gz_path}" \
    "${scanner_s3_uri}" \
    --content-type application/gzip \
    --cache-control no-cache \
    >&2; then
    cli_error "Scanner upload failed"
    cli_die "Draft release remains unpublished: ${tag}"
  fi

  cli_step "Uploading scanner shell entrypoint to ${scanner_script_s3_uri}"
  if ! aws s3 cp \
    "${scanner_script_source}" \
    "${scanner_script_s3_uri}" \
    --content-type "text/x-shellscript; charset=utf-8" \
    --cache-control no-cache \
    >&2; then
    cli_error "Scanner script upload failed"
    cli_die "Draft release remains unpublished: ${tag}"
  fi

  distribution_id="${AUTOMIC_VAULT_CLOUDFRONT_DISTRIBUTION_ID:-}"
  if [[ -z "${distribution_id}" ]]; then
    cli_step "Finding CloudFront distribution for ${release_cloudfront_alias}"
    if ! distribution_id="$(
        aws cloudfront list-distributions \
        --query "DistributionList.Items[?Aliases.Items && contains(join(',', Aliases.Items), '${release_cloudfront_alias}')].Id | [0]" \
        --output text
      )"; then
      cli_error "CloudFront distribution lookup failed"
      cli_die "Draft release remains unpublished: ${tag}"
    fi
  fi

  if [[ -z "${distribution_id}" || "${distribution_id}" == "None" ]]; then
    cli_die "Unable to find CloudFront distribution for ${release_cloudfront_alias}"
  fi

  cli_step "Invalidating CloudFront release paths"
  if ! aws cloudfront create-invalidation \
    --distribution-id "${distribution_id}" \
    --paths "${release_cloudfront_paths[@]}" \
    >&2; then
    cli_error "CloudFront invalidation failed"
    cli_die "Draft release remains unpublished: ${tag}"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      output_path="$2"
      shift 2
      ;;
    --background)
      background_path="$2"
      shift 2
      ;;
    --volume-name)
      volume_name="$2"
      shift 2
      ;;
    --notorize|--notarize)
      notarize=true
      shift
      ;;
    --install)
      install_app=true
      shift
      ;;
    --publish)
      publish_release=true
      shift
      ;;
    --clobber)
      clobber_release=true
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
ensure_isotope_sources_present

if [[ "${publish_release}" == "true" && "${notarize}" != "true" ]]; then
  cli_die "--publish requires --notarize"
fi

if [[ "${clobber_release}" == "true" && "${publish_release}" != "true" ]]; then
  cli_die "--clobber requires --publish"
fi

if [[ "${publish_release}" == "true" ]]; then
  cli_require_tool git
  cli_require_tool cargo
  git -C "${repo_root}" rev-parse --is-inside-work-tree >/dev/null ||
    cli_die "scripts/build-dmg.sh must run inside a git repository"
  git -C "${repo_root}" rev-parse --verify HEAD >/dev/null 2>&1 ||
    cli_die "Create an initial commit before publishing"
  if ! git -C "${repo_root}" remote get-url origin >/dev/null 2>&1 && [[ -z "${GH_REPO:-}" ]]; then
    cli_die "Set a git origin remote or GH_REPO before publishing"
  fi

  ensure_release_worktree_state

  current_version="$(package_version)"
  release_plan="$(generate_release_plan "${current_version}")"
  release_notes_path="$(printf '%s\n' "${release_plan}" | sed -n '1p')"
  version_path="$(printf '%s\n' "${release_plan}" | sed -n '2p')"
  planned_version="$(<"${version_path}")"

  if ! version_gt "${planned_version}" "${current_version}"; then
    cli_die "Codex proposed ${planned_version}, which is not newer than current Cargo version ${current_version}"
  fi

  if [[ "${clobber_release}" != "true" ]] &&
      git -C "${repo_root}" rev-parse --verify --quiet "v${planned_version}^{commit}" >/dev/null; then
    cli_die "Tag v${planned_version} already exists"
  fi

  bump_cargo_version "${planned_version}"
  commit_release_version "${planned_version}"
  push_current_branch
fi

if [[ -z "${background_path}" && -f "${default_background}" ]]; then
  background_path="${default_background}"
fi

if [[ -n "${background_path}" && ! -f "${background_path}" ]]; then
  cli_die "Background image not found: ${background_path}"
fi

if [[ -n "${background_path}" ]]; then
  background_width="$(
    sips -g pixelWidth "${background_path}" 2>/dev/null |
      awk '/pixelWidth:/ {print $2; exit}'
  )"
  background_height="$(
    sips -g pixelHeight "${background_path}" 2>/dev/null |
      awk '/pixelHeight:/ {print $2; exit}'
  )"

  if [[ "${background_width}" =~ ^[0-9]+$ && "${background_height}" =~ ^[0-9]+$ ]]; then
    if [[ "$(basename "${background_path}")" == *@2x.* ]]; then
      finder_width=$((background_width / 2))
      finder_height=$((background_height / 2))
    else
      finder_width="${background_width}"
      finder_height="${background_height}"
    fi
  fi
fi

finder_center_x=$((finder_width / 2))
app_icon_x=$((finder_center_x - icon_gap_from_center))
applications_icon_x=$((finder_center_x + icon_gap_from_center))
# Place Finder labels over the lower glow in the background artwork.
applications_icon_y=$(((finder_height * 2 / 3) - 22))
app_icon_y="${applications_icon_y}"

cli_title "Build Automic Vault DMG"
cli_step "Building release app bundle"
build_app_args=(--release)
if [[ "${publish_release}" == "true" ]]; then
  build_app_args+=(--publish)
fi
app_path="$("${repo_root}/scripts/build-app.sh" "${build_app_args[@]}")"
app_name="$(basename "${app_path}")"
app_stem="${app_name%.app}"
plist_path="${app_path}/Contents/Info.plist"
icon_name="$(
  /usr/libexec/PlistBuddy -c 'Print :CFBundleIconFile' "${plist_path}" \
    2>/dev/null || printf 'gui-icon'
)"
volume_icon_path="${app_path}/Contents/Resources/${icon_name}.icns"

version="$(
  /usr/libexec/PlistBuddy -c \
    'Print :CFBundleShortVersionString' \
    "${plist_path}" 2>/dev/null || printf '0.1'
)"

if [[ -z "${volume_name}" ]]; then
  volume_name="${app_stem}"
fi

safe_version="${version// /-}"
default_output="${target_dir}/${app_stem// /-}-${safe_version}.dmg"

if [[ -z "${output_path}" ]]; then
  output_path="${default_output}"
fi

mkdir -p "${build_dir}" "${target_dir}"
mkdir -p "$(dirname "${output_path}")"
output_dir="$(cd "$(dirname "${output_path}")" && pwd)"
output_path="${output_dir}/$(basename "${output_path}")"

final_dmg="${output_path}"
cli_info "Version: ${version}"
cli_info "Output: ${final_dmg}"
if [[ -n "${background_path}" ]]; then
  cli_info "Background: ${background_path}"
fi

rm -f "${final_dmg}"
create_dmg_args=(
  --volname "${volume_name}"
  --window-pos "${finder_left}" "${finder_top}"
  --window-size "${finder_width}" "${finder_height}"
  --icon-size "${icon_size}"
  --icon "${app_name}" "${app_icon_x}" "${app_icon_y}"
  --app-drop-link "${applications_icon_x}" "${applications_icon_y}"
  --format ULFO
  --filesystem HFS+
  --hdiutil-quiet
)

if [[ -n "${background_path}" ]]; then
  create_dmg_args+=(
    --background "${background_path}"
  )
fi

if [[ -f "${volume_icon_path}" ]]; then
  create_dmg_args+=(
    --volicon "${volume_icon_path}"
  )
fi

cli_require_tool create-dmg
cli_step "Composing disk image"
create-dmg \
  "${create_dmg_args[@]}" \
  "${final_dmg}" \
  "${app_path}" \
  >&2

if [[ "${notarize}" == "true" ]]; then
  cli_step "Submitting DMG for notarization"
  if [[ -z "${APPLE_USERNAME:-}" ]]; then
    cli_die "APPLE_USERNAME is required for notarization"
  fi

  if [[ -z "${CODESIGN_IDENTITY:-}" ]]; then
    cli_die "CODESIGN_IDENTITY is required for notarization"
  fi

  if [[ "${CODESIGN_IDENTITY}" =~ \(([A-Z0-9]+)\)[[:space:]]*$ ]]; then
    export team_id="${BASH_REMATCH[1]}"
  else
    cli_error "Unable to extract Apple team ID from CODESIGN_IDENTITY"
    cli_die "Expected an identity like: Developer ID Application: Name (TEAMID)"
  fi

  "${repo_root}/scripts/build-dmg-notarize.sh" "${final_dmg}"

  cli_step "Stapling notarization ticket"
  xcrun stapler staple "${final_dmg}" >&2
fi

if [[ "${install_app}" == "true" ]]; then
  cli_step "Installing app into /Applications"
  install_mount="$(mktemp -d "${TMPDIR:-/tmp}/automic-vault-install.XXXXXX")"
  cleanup_install_mount() {
    hdiutil detach "${install_mount}" >/dev/null 2>&1 || true
    rmdir "${install_mount}" >/dev/null 2>&1 || true
  }
  trap cleanup_install_mount EXIT

  hdiutil attach \
    -nobrowse \
    -readonly \
    -mountpoint "${install_mount}" \
    "${final_dmg}" \
    >/dev/null

  mounted_app_path="${install_mount}/${app_name}"
  install_path="/Applications/${app_name}"
  rm -rf "${install_path}"
  ditto "${mounted_app_path}" "${install_path}"
  sudo cp -f "${mounted_app_path}/Contents/Resources/av" /usr/local/bin/av
  sudo chmod 755 /usr/local/bin/av
fi

if [[ "${publish_release}" == "true" ]]; then
  if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    cli_die "Release publishing requires an X.Y.Z version, got: ${version}"
  fi
  if [[ "${version}" != "${planned_version}" ]]; then
    cli_die "Built app version ${version} does not match planned release version ${planned_version}"
  fi

  publish_github_release "v${version}" "${version}" "${final_dmg}" "${release_notes_path}"
fi

cli_done "DMG ready"
echo "${final_dmg}"
