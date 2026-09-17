# todoist-cli

```sh
cat "$HOME/.config/todoist/config.json"
```

This prints the file, including any Todoist API tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Todoist config contains a plaintext API token.
> - Todoist cache contains a plaintext API token.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/todoist/config.json`
> - `$XDG_CACHE_HOME/todoist/cache.json`
> - `~/.config/todoist/config.json`
> - `~/.cache/todoist/cache.json`

## Mitigation

The retired `todoist-cli` hardener moved the detected secret to the macOS
Keychain, then recreated `$XDG_CONFIG_HOME/todoist/config.json` inside a
temporary directory for each run. We no longer consider a temporary plaintext
file a sufficient security boundary, so this detector remains report-only.

If a narrow environment-variable or credential-helper interface can cover this
state without writing the secret back to disk, we can reconsider the hardener.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
