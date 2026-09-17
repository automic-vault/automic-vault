# soracom-cli

```sh
cat "$HOME/.soracom/default.json"
```

This prints the file, including any SORACOM credentials it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - soracom-cli default profile contains plaintext local credentials.
>
> #### Sensitive Files
>
> - `~/.soracom/default.json`

## Mitigation

The retired `soracom-cli` hardener moved the detected secret to the macOS
Keychain, then recreated `~/.soracom/default.json` inside a temporary directory
for each run. We no longer consider a temporary plaintext file a sufficient
security boundary, so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
