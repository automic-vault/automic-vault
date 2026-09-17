# mercurial

It is trivial for anything on your computer to exfiltrate mercurial’s secret:

```sh
cat "$HOME/.hgrc"
```

This prints the file, including any Mercurial credentials it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Mercurial hgrc contains credentials.
>
> #### Sensitive Files
>
> - `~/.hgrc`
> - `$XDG_CONFIG_HOME/hg/hgrc`
> - `~/.config/hg/hgrc`

## Mitigation

The retired `mercurial` hardener moved the detected secret to the macOS
Keychain, then recreated `~/.hgrc` inside a temporary directory for each run. We
no longer consider a temporary plaintext file a sufficient security boundary, so
this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
