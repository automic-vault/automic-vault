# sentry-cli Detector

> ### What we check
>
> - Sentry CLI config contains a plaintext auth token.
>
> #### Sensitive Files
>
> - `~/.sentryclirc`

## Mitigation

```sh
av harden sentry-cli
```
