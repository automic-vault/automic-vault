# uaa-cli

```sh
cat "$HOME/.uaa/config.json"
```

This prints the file, including any UAA OAuth tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - UAA CLI config contains plaintext OAuth tokens.
>
> #### Sensitive Files
>
> - `~/.uaa/config.json`

## Mitigation

Run `av harden uaa-cli`. The hardener installs the signed UAA CLI Isotope and
migrates saved OAuth tokens into Automic Vault custody while leaving only
non-secret context metadata and `@av` markers on disk.

Upstream UAA CLI has no credential-helper boundary: OAuth tokens are fields in
the same JSON document as target and context metadata. The Isotope therefore
patches config reads and writes to use authenticated XPC operations while the
Detector covers every non-empty access or refresh token in the active
`~/.uaa/config.json` or `UAA_HOME/config.json`.

The residual gap is other users' configs, backups, and inactive alternate
config roots that are not selected by the current `HOME` or `UAA_HOME`.

See the [hardening reference](../../hardeners/uaa_cli.md) for setup and coverage.
