# node Detector

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
av harden node
```
