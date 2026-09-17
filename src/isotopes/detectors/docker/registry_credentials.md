# docker-registry-credentials Detector

> ### What we check
>
> - Docker legacy config contains registry credentials.
> - Docker config contains inline registry credentials.
>
> #### Sensitive Files
>
> - `$DOCKER_CONFIG/config.json`
> - `~/.docker/config.json`
> - `~/.dockercfg`

## Mitigation

Run `docker logout REGISTRY` for each affected registry, then configure a Docker
credential helper before signing in again. Remove obsolete `auths` entries from
the reported config files.
