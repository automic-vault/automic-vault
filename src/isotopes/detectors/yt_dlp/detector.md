# yt-dlp Detector

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

## Why This is not Yet Hardened

These auth inputs are generic request state rather than a narrow package-owned
credential store.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
