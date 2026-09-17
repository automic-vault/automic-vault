# akamai Detector

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
