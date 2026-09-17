# httpie Detector

> ### What we check
>
> - HTTPie session contains plaintext auth material.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/httpie/sessions/**/default.json`
> - `~/.config/httpie/sessions/**/default.json`
> - `~/.httpie/sessions/**/default.json`

## Why This is not Yet Hardened

HTTPie session files are mutable runtime state. A safe fix needs native
session-store integration or a source isotope that preserves session updates.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
