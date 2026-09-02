#!/bin/bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
package="$repo/src/menu-helper"
signed=0

if [[ "${1:-}" == "--signed" ]]; then
  signed=1
  shift
fi

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [--signed] [menubar-executable]" >&2
  exit 64
fi

if [[ $# -eq 1 ]]; then
  menubar=$1
else
  swift build \
    --package-path "$package" \
    --configuration debug \
    --product AutomicVaultMenubar \
    --disable-automatic-resolution
  bin_dir=$(swift build \
    --package-path "$package" \
    --configuration debug \
    --show-bin-path)
  menubar="$bin_dir/AutomicVaultMenubar"
fi

if [[ ! -x "$menubar" ]]; then
  echo "error: menu helper is not executable: $menubar" >&2
  exit 1
fi

checks=(
  --self-check-approvals
  --self-check-approval-process-execution
  --self-check-standalone-launchers
  --self-check-secret-mutations
  --self-check-gh-read-only
  --self-check-docker-credentials
  --self-check-terraform-credentials
  --self-check-aliyun-credentials
  --self-check-wakatime-credentials
  --self-check-kubectl-credentials
  --self-check-sqlcmd-credentials
  --self-check-oxide-credentials
  --self-check-goat-credentials
  --self-check-railway-credentials
  --self-check-ordercli-credentials
  --self-check-openhue-credentials
  --self-check-plumber-credentials
  --self-check-uaa-credentials
  --self-check-aws-read-only
  --self-check-brew-read-only
  --self-check-transient-approvals
  --self-check-retained-provenance
  --self-check-dashboard-search
  --self-check-update-toolbar
  --self-check-launch-agent-handoff
  --self-check-menu-status
  --self-check-scan-scheduling
  --self-check-text-paste
)

if [[ "$signed" -eq 1 ]]; then
  checks+=(--self-check-keychain-persistence)
fi

for check in "${checks[@]}"; do
  "$menubar" "$check"
done

echo "menu helper self-checks passed (${#checks[@]})"
