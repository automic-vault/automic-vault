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
- [Authorization Gates and Approval](authorization.md) — Access Levels, iPhone and Touch ID setup, Temporary Access Grants, and History
- [Project Secrets](project-secrets.md) — Project Values with dotenvx and mise
- [Direct Secret Access](direct-secret-access.md) — broad per-Secret Launcher access and safer alternatives
- [Secret Proxy](secret-proxy.md) — destination-gated HTTP/S Secret Application with bearer references
- [Varlock](varlock.md) — resolver setup and Varlock's separate credential proxy
- [Signed CLI Launchers](signed-cli-launchers.md) — signature requirements and verification
- [Securing Git](securing-git.md) — protected Git credentials
- [Reentrant Release Script](examples/reentrant-release.sh) — reviewed GitHub, S3, and CloudFront workflow with agent input

## Development

- [Releasing](releasing.md) — release, notarization, and publication process
