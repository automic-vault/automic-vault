# fauna-shell

```sh
cat "$HOME/.fauna/credentials/account_keys"
```

This prints the file, including any Fauna account or secret keys it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - fauna-shell credential file contains plaintext local credentials.
>
> #### Sensitive Files
>
> - `~/.fauna/credentials/account_keys`
> - `~/.fauna/credentials/secret_keys`

## Mitigation

The retired `fauna-shell` hardener moved the detected secret to the macOS
Keychain, then recreated `~/.fauna/credentials/account_keys` inside a temporary
directory for each run. We no longer consider a temporary plaintext file a
sufficient security boundary, so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
