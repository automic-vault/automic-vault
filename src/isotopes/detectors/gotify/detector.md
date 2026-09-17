# gotify

It is trivial for anything on your computer to exfiltrate gotify’s secret:

```sh
cat "$HOME/.gotify/cli.json"
```

This prints the file, including any Gotify application tokens it contains.
Software running as you with read access can copy the same material.

> ### What we check
>
> - Gotify config contains a plaintext application token.
>
> #### Sensitive Files
>
> - `$XDG_CONFIG_HOME/gotify/cli.json`
> - `~/.gotify/cli.json`

## Mitigation

```sh
av harden gotify
```
