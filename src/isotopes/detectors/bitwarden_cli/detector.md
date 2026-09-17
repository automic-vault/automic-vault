# bitwarden-cli

It is trivial for anything on your computer to exfiltrate bitwarden-cli’s secret:

```sh
cat "$HOME/Library/Application Support/Bitwarden CLI/data.json"
```

This prints the file, including any Bitwarden token state it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Bitwarden CLI token state is stored in plaintext data.json.
>
> #### Sensitive Files
>
> - `$BITWARDENCLI_APPDATA_DIR/data.json`
> - `~/Library/Application Support/Bitwarden CLI/data.json`

## Mitigation

The retired `bitwarden-cli` hardener moved the detected secret to the macOS
Keychain, then recreated `$BITWARDENCLI_APPDATA_DIR/data.json` inside a
temporary directory for each run. We no longer consider a temporary plaintext
file a sufficient security boundary, so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
