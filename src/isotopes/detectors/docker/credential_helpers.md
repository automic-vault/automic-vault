# docker-credential-helpers Detector

> ### What we check
>
> - Docker config uses an ambient credential store.
> - Docker config uses an ambient per-registry credential helper.
>
> #### Sensitive Files
>
> - `$DOCKER_CONFIG/config.json`
> - `~/.docker/config.json`

## Mitigation

Run:

```sh
av harden docker
```

This keeps Docker Desktop's vendor-signed CLI, migrates credentials from its
default helper into Automic Vault, and installs an approval-aware helper.
Non-Automic per-registry helpers fail closed rather than being partly migrated.
