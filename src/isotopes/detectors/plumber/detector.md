# plumber

```sh
cat "$HOME/.batchsh/plumber.json"
```

This prints the file, including any Plumber connection or relay credentials it
contains. Software running as you with read access can copy the same material.

> ### What we check
>
> - Plumber local config contains a non-empty plaintext credential field.
>
> #### Sensitive Files
>
> - `~/.batchsh/plumber.json`

## Mitigation

Run `av harden plumber`. The hardener installs the signed Plumber Isotope and
migrates the complete local config into Automic Vault custody. If
`~/.batchsh/plumber.json` exists, it is replaced with a fixed, non-secret marker.

Upstream Plumber has no credential-helper boundary: local connection and relay
credentials share one JSON document with non-secret configuration. The Isotope
therefore patches local config reads and writes to use authenticated XPC
operations, and the hardener moves that complete local document into custody.

The Detector covers the known local token, password, secret, credential, and
client-key fields under `~/.batchsh/plumber.json`. Cluster-mode KV storage is
unchanged and remains outside both this Detector and hardener; backups and other
users' configs are also residual gaps.

See the [hardening reference](../../hardeners/plumber.md) for setup and coverage.
