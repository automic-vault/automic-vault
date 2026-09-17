# opencode

```sh
cat "$HOME/.local/share/opencode/auth.json"
```

This prints the file, including any OpenCode account credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - opencode auth state contains plaintext credentials.
>
> #### Sensitive Files
>
> - `$XDG_DATA_HOME/opencode/auth.json`
> - `$XDG_DATA_HOME/opencode/account.json`
> - `~/.local/share/opencode/auth.json`
> - `~/.local/share/opencode/account.json`
> - `~/Library/Application Support/opencode/auth.json`
> - `~/Library/Application Support/opencode/account.json`

## Mitigation

The auth file is mutable application state and sits beside non-secret opencode
data. A safe fix needs a source isotope or an upstream keychain-backed account
store.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
