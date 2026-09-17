# civo

```sh
cat "$HOME/.civo.json"
```

This prints the file, including any Civo API keys it contains. Software running
as you with read access can copy the same material.

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
