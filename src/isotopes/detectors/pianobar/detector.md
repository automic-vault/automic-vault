# pianobar

It is trivial for anything on your computer to exfiltrate pianobar’s secret:

```sh
cat "$HOME/.config/pianobar/config"
```

This prints the file, including any Pandora passwords it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - pianobar config contains a plaintext password.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/pianobar/config`
> - `~/.config/pianobar/config`
> - `~/.pianobar/config`

## Mitigation

pianobar does not expose a narrow credential interface that preserves normal
config behavior.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
