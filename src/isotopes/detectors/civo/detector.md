# civo Detector

> ### What we check
>
> - civo config contains plaintext API keys.
>
> #### Sensitive Files
>
> - `$CIVO_CONFIG`
> - `~/.civo.json`

## Mitigation

```sh
av harden civo
```
