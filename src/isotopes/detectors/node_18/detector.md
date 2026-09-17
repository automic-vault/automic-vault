# node@18 Detector

> ### What we check
>
> - npm user config contains a plaintext auth token.
>
> #### Sensitive Files
>
> - `$NPM_CONFIG_USERCONFIG`
> - `~/.npmrc`

## Why This is not Yet Hardened

The retired hardener moved one npm token to the macOS Keychain, rewrote the
matching npm config entry to reference `NODE_AUTH_TOKEN`, and wrapped only
`npm publish`. The current `node` hardener targets `/opt/node/bin/npm`; it does
not manage the versioned `/opt/node@18/bin/npm` installation.

[Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
