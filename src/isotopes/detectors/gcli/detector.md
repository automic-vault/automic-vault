# gcli

It is trivial for anything on your computer to exfiltrate gcli’s secret:

```sh
cat "$HOME/.config/gcli/config"
```

This prints the file, including any gcli API tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - gcli config contains plaintext API tokens.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/gcli/config`
> - `~/.config/gcli/config`

## Mitigation

The retired `gcli` hardener moved the detected secret to the macOS Keychain,
then recreated `$XDG_CONFIG_HOME/gcli/config` inside a temporary directory for
each run. We no longer consider a temporary plaintext file a sufficient security
boundary, so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
