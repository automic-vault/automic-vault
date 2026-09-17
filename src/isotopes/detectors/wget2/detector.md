# wget2 Detector

> ### What we check
>
> - Wget2 netrc file contains plaintext credentials.
> - Wget2 config contains plaintext password options.
>
> #### Sensitive Files
>
> - `~/.netrc`
> - `~/.wget2rc`
> - `$XDG_CONFIG_HOME/wget/wget2rc`
> - `$XDG_CONFIG_HOME/wget2/wget2rc`
> - `~/.config/wget/wget2rc`
> - `~/.config/wget2/wget2rc`

## Why This is not Yet Hardened

Wget2 can consume credentials from `~/.netrc` and from password options in user
configuration files such as `~/.wget2rc`.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
