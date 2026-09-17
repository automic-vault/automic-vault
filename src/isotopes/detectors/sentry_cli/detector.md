# sentry-cli

```sh
cat "$HOME/.sentryclirc"
```

This prints the file, including any Sentry auth tokens it contains. Software
running as you with read access can copy the same material.

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
