# docker-credential-helper Detector

> ### What we check
>
> - Docker config uses an ambient Docker credential helper.
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

Automic Vault replaces the ambient default helper with its Secret Gate while
retaining Docker Desktop's vendor-signed CLI.
