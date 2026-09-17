# gallery-dl

It is trivial for anything on your computer to exfiltrate gallery-dl’s secret:

```sh
cat "$HOME/.config/gallery-dl/config.json"
```

This prints the file, including any gallery-dl account credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - gallery-dl config contains credentials.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/gallery-dl/config.json`
> - `~/.config/gallery-dl/config.json`
> - `~/.gallery-dl.conf`

## Mitigation

The retired `gallery-dl` hardener moved the detected secret to the macOS
Keychain, then recreated `$XDG_CONFIG_HOME/gallery-dl/config.json` inside a
temporary directory for each run. We no longer consider a temporary plaintext
file a sufficient security boundary, so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
