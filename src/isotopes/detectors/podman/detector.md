# podman

```sh
cat "$HOME/.config/containers/auth.json"
```

This prints the file, including any registry credentials it contains. Software
running as you with read access can copy the same material. Base64-encoded
registry credentials can be decoded; encoding does not restrict access.

> ### What we check
>
> - Podman registry auth file contains credentials.
>
> #### Sensitive Files
>
> - `$REGISTRY_AUTH_FILE`
> - `$XDG_RUNTIME_DIR/containers/auth.json`
> - `$XDG_CONFIG_HOME/containers/auth.json`
> - `~/.config/containers/auth.json`

## Mitigation

`av harden podman` migrates supported registry-level credentials into Secret
Custody and selects Automic Vault through containers/image's native global
credential-helper setting. The official Red Hat-signed macOS Podman client is
the verified Target; no plaintext auth file is recreated.

See the [hardening reference](../../hardeners/podman.md) for setup and coverage.
