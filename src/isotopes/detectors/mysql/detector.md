# mysql Detector

> ### What we check
>
> - MySQL option file contains plaintext passwords.
>
> #### Sensitive Files
>
> - `~/.my.cnf`

## Why This is not Yet Hardened

The retired `mysql` hardener moved the detected secret to the macOS Keychain,
then recreated `~/.my.cnf` inside a temporary directory for each run. We no
longer consider a temporary plaintext file a sufficient security boundary, so
this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
