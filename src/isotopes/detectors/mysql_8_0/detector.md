# mysql@8.0

It is trivial for anything on your computer to exfiltrate mysql@8.0’s secret:

```sh
cat "$HOME/.my.cnf"
```

This prints the file, including any database passwords it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - MySQL option file contains plaintext passwords.
>
> #### Sensitive Files
>
> - `~/.my.cnf`

## Mitigation

The retired `mysql@8.0` hardener moved the detected secret to the macOS
Keychain, then recreated `~/.my.cnf` inside a temporary directory for each run.
We no longer consider a temporary plaintext file a sufficient security boundary,
so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
