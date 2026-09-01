# ADR 0038: Podman registry credential custody

- Status: Accepted
- Date: 2026-09-01

## Context

On macOS, Podman is a remote client for a Linux service. Upstream's remote
client reads the local containers/image authentication configuration and
constructs the registry-auth request header before contacting that service.
containers/image supports the Docker credential-helper protocol through the
global `credential-helpers` setting in `registries.conf`.

The official Podman package installs `/opt/podman/bin/podman` with Red Hat's
Developer ID Application identity, Hardened Runtime, and no entitlements. A
Podman Isotope would replace that upstream identity without narrowing the
credential-helper protocol.

## Decision

The Podman Hardener preserves the official client and requires its canonical
path, Red Hat team `HYSCB8KRL2`, identifier `podman`, Developer ID signature,
Hardened Runtime, timestamp, and safe entitlements. Automic Vault does not
install or relocate the upstream multi-file Podman package.

The Hardener migrates supported registry-level credentials from Podman's
primary macOS `auth.json` into Secret Custody, installs the existing root-owned
`docker-credential-av` Gate Client, writes a final user
`registries.conf.d` drop-in selecting helper `av`, and removes migrated inline
credentials. Namespaced credentials and competing credential helpers fail
closed because external helpers cannot preserve their semantics.

Docker and Podman intentionally share the registry-address-bound Secret format
and helper executable. For every `get`, `store`, and `erase`, the menu helper
derives the Tool from the helper's live parent rather than trusting a client
claim. It accepts Podman only at `/opt/podman/bin/podman` with the expected live
code identity and runtime posture, binds the Authorization Request to the
parent's complete arguments and registry, revalidates the process before Secret
Application, and routes Podman through a distinct Authorization Gate.

## Consequences

No Podman source fork or Automic Vault Isotope is required while Red Hat ships
an eligible client. Podman login, logout, pull, push, search, build, and other
containers/image users can use the native helper without plaintext credential
files. The verified Podman Target necessarily receives a usable credential in
memory and the remote service necessarily receives it in the registry-auth
header; neither boundary is controlled by Automic Vault after Secret
Application.

The optional helper `list` operation remains unsupported because it would
disclose registry and account metadata. Podman operations whose intent cannot
be classified safely remain Unknown and require Approval.
