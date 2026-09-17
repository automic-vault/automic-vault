# docker-credential-helper

Docker delegates registry credential retrieval to configured helpers. An
ambient helper may return a credential to other software running as you,
without authorizing the complete Docker operation. This Detector inspects the
helper configuration without invoking it.

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

See the [hardening reference](../../hardeners/docker.md) for setup and coverage.
