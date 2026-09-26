#!/bin/bash
set -euo pipefail

app=${1:?usage: verify-universal-app.sh app-bundle}
# Check every bundled executable, including helpers that are launched separately.
for executable in \
  MacOS/AutomicVaultMenubar MacOS/av MacOS/av-gpg MacOS/av-brew-stub \
  MacOS/av-proxy-helper Resources/AutomicVaultLauncher Resources/AutomicVaultVarlockPlugin; do
  for architecture in arm64 x86_64; do
    lipo "$app/Contents/$executable" -verify_arch "$architecture"
  done
  codesign --verify --strict --all-architectures "$app/Contents/$executable"
done
codesign --verify --strict --all-architectures "$app"
