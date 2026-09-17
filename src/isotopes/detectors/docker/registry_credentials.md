# docker-registry-credentials

It is trivial for anything on your computer to exfiltrate Docker’s secret:

```sh
cat "$HOME/.docker/config.json"
```

This prints the file, including any inline registry credentials it contains.
Software running as you with read access can copy the same material.
Base64-encoded registry credentials can be decoded; encoding does not restrict
access.

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
