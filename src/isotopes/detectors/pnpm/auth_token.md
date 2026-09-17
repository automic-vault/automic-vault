# pnpm-auth-token

```sh
cat "$HOME/.npmrc"
```

This prints the file, including any npm registry tokens it contains. Software
running as you with read access can copy the same material.

> ### What we check
>
> - npm user config contains a plaintext auth token.
>
> #### Sensitive Files
>
> - `$NPM_CONFIG_USERCONFIG`
> - `~/.npmrc`

## Mitigation

```sh
av harden pnpm
```
