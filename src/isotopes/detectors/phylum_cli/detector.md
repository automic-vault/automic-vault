# phylum-cli

```sh
cat "$HOME/.config/phylum/settings.yaml"
```

This prints the file, including any Phylum API tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Phylum config contains a plaintext API token.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/phylum/settings.yaml`
> - `~/.config/phylum/settings.yaml`

## Mitigation

The retired `phylum-cli` hardener moved the detected secret to the macOS
Keychain, then recreated `$XDG_CONFIG_HOME/phylum/settings.yaml` inside a
temporary directory for each run. We no longer consider a temporary plaintext
file a sufficient security boundary, so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
