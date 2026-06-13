#!/usr/bin/env bash

set -euo pipefail

org="automic-vault"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
av_db_root="${AV_DB_ROOT:-${repo_root}/../av.db}"
clone_root="${AUTOMIC_VAULT_REPO_CACHE:-${av_db_root}/../isotopes}"
radioisotopes_dir="${AUTOMIC_VAULT_RADIOISOTOPES_REPO:-${av_db_root}/../radioisotopes}"
depth=1

usage() {
  cat <<'EOF'
Usage: scripts/sync-isotope-checkouts.sh [--clone-root PATH]
                                         [--radioisotopes-dir PATH]
                                         [--depth N]

Clone or fast-forward the isotope repositories that Automic Vault expects
during builds and coverage runs.

Options:
  --clone-root PATH         Directory for isotope fork clones.
                            Defaults to ../isotopes.
  --radioisotopes-dir PATH  Directory for the radioisotopes checkout.
                            Defaults to ../radioisotopes.
  --depth N                 Shallow fetch depth. Defaults to 1.
  --help                    Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clone-root)
      clone_root="$2"
      shift 2
      ;;
    --radioisotopes-dir)
      radioisotopes_dir="$2"
      shift 2
      ;;
    --depth)
      depth="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

for tool in gh git; do
  command -v "${tool}" >/dev/null 2>&1 || {
    echo "Missing required tool: ${tool}" >&2
    exit 1
  }
done

mkdir -p "${clone_root}" "$(dirname "${radioisotopes_dir}")"

default_branch() {
  local repo="$1"
  gh repo view "${repo}" --json defaultBranchRef --jq '.defaultBranchRef.name'
}

checkout_branch() {
  local repo="$1"

  case "${repo}" in
    automic-vault/gh-cli)
      printf '%s\n' "codex/av-gh-cli-env-lock-2026-05-23"
      ;;
    *)
      default_branch "${repo}"
      ;;
  esac
}

sync_checkout() {
  local repo="$1"
  local repo_dir="$2"
  local branch

  branch="$(checkout_branch "${repo}")"
  if [[ -d "${repo_dir}/.git" ]]; then
    if [[ -n "$(git -C "${repo_dir}" status --porcelain)" ]]; then
      echo "Refusing to update dirty checkout: ${repo_dir}" >&2
      return 1
    fi
    git -C "${repo_dir}" fetch --depth "${depth}" origin "${branch}"
    git -C "${repo_dir}" checkout "${branch}"
    git -C "${repo_dir}" reset --hard "origin/${branch}"
    return 0
  fi

  if [[ -e "${repo_dir}" ]]; then
    echo "Clone path exists but is not a git repo: ${repo_dir}" >&2
    return 1
  fi

  git clone --depth "${depth}" "https://github.com/${repo}.git" "${repo_dir}"
}

repo_has_manifest() {
  local repo="$1"
  gh api "repos/${org}/${repo}/contents/automic-vault.yml" >/dev/null 2>&1
}

sync_checkout "${org}/radioisotopes" "${radioisotopes_dir}"

isotope_repos=()
while IFS= read -r repo; do
  isotope_repos+=("${repo}")
done < <(
  gh repo list "${org}" --limit 200 --json name,isArchived,isFork,parent \
    --jq '.[] | select(.isFork and (.isArchived | not) and .parent != null) | .name'
)

for repo in "${isotope_repos[@]}"; do
  if repo_has_manifest "${repo}"; then
    sync_checkout "${org}/${repo}" "${clone_root}/${repo}"
  fi
done
