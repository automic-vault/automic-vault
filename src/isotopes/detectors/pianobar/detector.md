# pianobar Detector

> ### What we check
>
> - pianobar config contains a plaintext password.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/pianobar/config`
> - `~/.config/pianobar/config`
> - `~/.pianobar/config`

## Why This is not Yet Hardened

pianobar does not expose a narrow credential interface that preserves normal
config behavior.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
