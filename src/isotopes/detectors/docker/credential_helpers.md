# docker-credential-helpers

Docker delegates registry credential retrieval to configured helpers. An
ambient helper may return a credential to other software running as you,
without authorizing the complete Docker operation. This Detector inspects the
helper configuration without invoking it.

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

See the [hardening reference](../../hardeners/docker.md) for setup and coverage.
