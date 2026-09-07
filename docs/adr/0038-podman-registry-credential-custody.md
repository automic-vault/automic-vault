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

The Hardener migrates supported registry-level credentials from Podman's macOS
auth files into Secret Custody, installs an exact root-owned
`docker-credential-av-podman` launcher, writes a final user
`registries.conf.d` drop-in selecting helper `av-podman`, and replaces migrated
inline credentials with registry-only helper markers. Namespaced credentials
and competing credential helpers fail closed because external helpers cannot
preserve their semantics.

Docker and Podman intentionally share the registry-address-bound Secret format
but use distinct exact helper launchers. For every `get`, `store`, and `erase`,
the menu helper also verifies the helper's live parent rather than trusting the
client claim. It accepts Podman only at `/opt/podman/bin/podman` with the
expected live code identity and runtime posture, binds the Authorization
Request to the parent's complete arguments and registry, revalidates the
process before Secret Application, and routes Podman through a distinct
Authorization Gate.

The Podman helper implements `list` by reading only the registry markers already
present in the user-readable auth file and returns empty usernames. It does not
enumerate Secret Names or load Secret Values. Upstream Podman then requests each
marked credential and sends the resulting multi-auth header to its Linux
service. Every Podman credential read therefore classifies as a Secret Dump,
regardless of the apparent command operation.

## Consequences

No Podman source fork or Automic Vault Isotope is required while Red Hat ships
an eligible client. Podman login, logout, pull, push, search, build, and other
containers/image users can use the native helper without plaintext credential
files. The verified Podman Target necessarily receives a usable credential in
memory and the remote service necessarily receives it in the registry-auth
header; neither boundary is controlled by Automic Vault after Secret
Application.

Registry locations remain visible in Podman's auth file by necessity; account
names and Secret Values do not. Adding a new registry through `podman login`
stores the credential first and then atomically adds its marker. A failed marker
write leaves the Secret safely stored but undiscoverable until login or
hardening is retried.
