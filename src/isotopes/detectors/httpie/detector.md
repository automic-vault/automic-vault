# httpie

It is trivial for anything on your computer to exfiltrate httpie’s secret:

```sh
cat "$HOME/.config/httpie/sessions/HOST/default.json"
```

Use the path reported by the Scan in place of this example path. This prints the
file, including any HTTPie session credentials it contains. Software running as
you with read access can copy the same material.

> ### What we check
>
> - HTTPie session contains plaintext auth material.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/httpie/sessions/**/default.json`
> - `~/.config/httpie/sessions/**/default.json`
> - `~/.httpie/sessions/**/default.json`

## Mitigation

HTTPie session files are mutable runtime state. A safe fix needs native
session-store integration or a source isotope that preserves session updates.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
