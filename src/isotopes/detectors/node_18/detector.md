# node@18

It is trivial for anything on your computer to exfiltrate node@18’s secret:

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

The retired hardener moved one npm token to the macOS Keychain, rewrote the
matching npm config entry to reference `NODE_AUTH_TOKEN`, and wrapped only
`npm publish`. The current `node` hardener targets `/opt/node/bin/npm`; it does
not manage the versioned `/opt/node@18/bin/npm` installation.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
