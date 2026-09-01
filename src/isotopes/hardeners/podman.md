# Podman

`av harden podman` keeps Red Hat's official Developer ID-signed, Hardened
Runtime client at `/opt/podman/bin/podman`. It migrates supported registry-level
credentials from Podman's macOS `auth.json`, installs Automic Vault's protected
registry credential helper, and selects it through a user
`registries.conf.d` drop-in.

Podman's macOS remote client resolves the credential locally before sending it
to the Linux service. Automic Vault verifies that live client, its complete
arguments, its registry, and its Launcher before releasing the credential.
Docker and Podman share registry credentials but use separate Authorization
Gates. Namespaced credentials and competing helpers fail closed because the
external helper protocol cannot preserve them safely.

Install Podman with the [official macOS installer] before hardening. An Isotope
is unnecessary while Red Hat ships an eligible signed client.

[official macOS installer]: https://podman.io/docs/installation
