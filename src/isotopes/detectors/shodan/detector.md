# shodan

It is trivial for anything on your computer to exfiltrate shodan’s secret:

```sh
cat "$HOME/.shodan/api_key"
```

This prints the file, including any Shodan API keys it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Shodan config contains a plaintext API key.
>
> #### Sensitive Files
>
> - `~/.shodan/api_key`
> - `$XDG_CONFIG_HOME/shodan/api_key`
> - `~/.config/shodan/api_key`

## Mitigation

The retired `shodan` hardener moved the detected secret to the macOS Keychain,
then recreated `~/.shodan/api_key` inside a temporary directory for each run. We
no longer consider a temporary plaintext file a sufficient security boundary, so
this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
