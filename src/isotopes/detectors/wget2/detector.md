# wget2

It is trivial for anything on your computer to exfiltrate wget2’s secret:

```sh
cat "$HOME/.netrc"
```

This prints the file, including any stored request credentials it contains.
Software running as you with read access can copy the same material.

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

## Mitigation

Wget2 can consume credentials from `~/.netrc` and from password options in user
configuration files such as `~/.wget2rc`.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
