# podman Detector

## Trigger Conditions

- Podman registry auth file contains credentials.

## Sensitive Files

- `$REGISTRY_AUTH_FILE`
- `$XDG_RUNTIME_DIR/containers/auth.json`
- `$XDG_CONFIG_HOME/containers/auth.json`
- `~/.config/containers/auth.json`

## Hardened State

`av harden podman` migrates supported registry-level credentials into Secret
Custody and selects Automic Vault through containers/image's native global
credential-helper setting. The official Red Hat-signed macOS Podman client is
the verified Target; no plaintext auth file is recreated.
