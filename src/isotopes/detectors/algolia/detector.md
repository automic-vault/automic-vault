# algolia

It is trivial for anything on your computer to exfiltrate algolia’s secret:

```sh
cat "${XDG_CONFIG_HOME:-$HOME/.config}/algolia/config.toml"
```

This prints the file, including any Algolia API keys it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - algolia config contains plaintext API keys.
>
> #### Sensitive Files
>
> - `${XDG_CONFIG_HOME:-$HOME/.config}/algolia/config.toml`

## Mitigation

```sh
av harden algolia
```
