# imap-backup

```sh
cat "$HOME/.imap-backup/config.json"
```

This prints the file, including any IMAP account passwords it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - imap-backup config contains plaintext account passwords.
>
> #### Sensitive Files
>
> - `~/.imap-backup/config.json`

## Mitigation

The retired `imap-backup` hardener moved the detected secret to the macOS
Keychain, then recreated `~/.imap-backup/config.json` inside a temporary
directory for each run. We no longer consider a temporary plaintext file a
sufficient security boundary, so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
