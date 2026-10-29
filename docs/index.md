# Documentation

## Security model

- [Product Positioning](positioning.md) — canonical product promise, supporting claims, and messaging limits
- [Domain Language](domain-language.md) — canonical product and security terms
- [Architecture](architecture.md) — contexts, invariants, and authorization flow
- [Architecture Decisions](adr/) — accepted security and design decisions
- [Secret Gate Security Audit](secret-gate-security-audit.md) — mediation limits and reviewed risks

## Using Automic Vault

- [Choosing a Mechanism](choosing-a-mechanism.md) — which feature to reach for, starting from your situation
- [Detection and Tool Hardening](tool-hardening.md) — Findings, verification, AWS/Docker handoffs, and terminal permissions
- [Authorization Gates and Approval](authorization.md) — Access Levels, descendant Launcher overrides, denial, Approval, grants, and History
- [Project Secrets](project-secrets.md) — multiline and exact-input saving, Project Values, dotenvx, and mise
- [Direct Secret Access](direct-secret-access.md) — environment delivery, approved FD delivery, and broad per-Secret Launcher access
- [Copying Secrets from v1](migrating-from-v1.md) — selected legacy Keychain Values, import Approval, and migration limits
- [Secret Proxy](secret-proxy.md) — destination-gated HTTP/S Secret Application with bearer references
- [Varlock](varlock.md) — resolver setup and Varlock's separate credential proxy
- [Signed CLI Launchers](signed-cli-launchers.md) — signature requirements and verification
- [Securing Git](securing-git.md) — per-key SSH policies, GPG signing, and protected Git credentials
- [Reentrant Release Script](examples/reentrant-release.sh) — reviewed GitHub, S3, and CloudFront workflow with agent input
- [Agent Skills](../skills/README.md) — teach coding agents to write Blessed Scripts and reentrant Blessed Scripts

## Development

- [Releasing](releasing.md) — release, notarization, and publication process
