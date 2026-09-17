# transifex-cli Detector

> ### What we check
>
> - Transifex root config contains plaintext credentials.
>
> #### Sensitive Files
>
> - `~/.transifexrc`

## Mitigation

```sh
av harden transifex-cli
```
