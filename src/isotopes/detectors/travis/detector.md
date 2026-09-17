# travis Detector

> ### What we check
>
> - Travis CLI config contains a plaintext access token.
>
> #### Sensitive Files
>
> - `~/.travis/config.yml`

## Mitigation

```sh
av harden travis
```
