# gotify Detector

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
