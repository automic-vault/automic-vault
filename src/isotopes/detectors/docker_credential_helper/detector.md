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

With Docker Desktop installed in `/Applications`, run:

```sh
av harden docker
```

Automic Vault replaces the ambient default helper with its Secret Gate while
retaining Docker Desktop's vendor-signed CLI.

See the [hardening reference](../../hardeners/docker.md) for setup and coverage.

The hardener does not support the Homebrew Docker CLI, including installations
used with Colima. Installing Colima does not satisfy the Docker Desktop
requirement. On those setups this Finding still applies: the configured ambient
helper can disclose registry credentials to other software running as you.
Do not replace the helper with plaintext credentials to silence the Finding.
