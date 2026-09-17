# atuin

```sh
cat "$HOME/.local/share/atuin/key"
```

This prints the file, including any Atuin sync secrets it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Atuin sync secret is stored in plaintext.
>
> #### Sensitive Files
>
> - `$XDG_DATA_HOME/atuin/key`
> - `$XDG_DATA_HOME/atuin/session`
> - `~/.local/share/atuin/key`
> - `~/.local/share/atuin/session`

## Mitigation

Atuin keeps the local sync encryption key and server session under the Atuin
data directory. Until Automic Vault has a write-safe Atuin integration, this
detector reports those plaintext files without changing Atuin behavior.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
