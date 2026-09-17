# dcos-cli Detector

> ### What we check
>
> - dcos-cli cluster config contains a plaintext ACS token.
>
> #### Sensitive Files
>
> - `$DCOS_DIR/clusters/*/dcos.toml`
> - `~/.dcos/clusters/*/dcos.toml`

## Why This is not Yet Hardened

The retired `dcos-cli` hardener moved the detected secret to the macOS Keychain,
then recreated `$DCOS_DIR/clusters/*/dcos.toml` inside a temporary directory for
each run. We no longer consider a temporary plaintext file a sufficient security
boundary, so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
