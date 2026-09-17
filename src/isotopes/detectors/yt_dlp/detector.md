# yt-dlp

It is trivial for anything on your computer to exfiltrate yt-dlp’s secret:

```sh
cat "$HOME/.netrc"
```

This prints the file, including any stored account credentials it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - yt-dlp netrc file contains plaintext credentials.
> - yt-dlp config contains plaintext password options.
>
> #### Sensitive Files
>
> - `~/.netrc`
> - `$XDG_CONFIG_HOME/yt-dlp/config`
> - `$XDG_CONFIG_HOME/yt-dlp.conf`
> - `~/.config/yt-dlp/config`
> - `~/.config/yt-dlp.conf`
> - `~/.yt-dlp.conf`

## Mitigation

These auth inputs are generic request state rather than a narrow package-owned
credential store.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
