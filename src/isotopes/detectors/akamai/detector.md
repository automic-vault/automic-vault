# akamai

```sh
cat "${AKAMAI_EDGERC:-$HOME/.edgerc}"
```

This prints the file, including any EdgeGrid credentials it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - Akamai CLI .edgerc contains plaintext EdgeGrid credentials.
>
> #### Sensitive Files
>
> - `${AKAMAI_EDGERC:-$HOME/.edgerc}`

## Mitigation

```sh
av harden akamai
```
