# algolia Detector

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
