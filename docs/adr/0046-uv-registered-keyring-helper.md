# ADR 0046: Bind uv keyring access to a registered operation

Status: accepted

## Context

Official macOS uv releases now carry Developer ID signatures and Hardened
Runtime. Native Keychain storage still permits the signed `uv auth token`
command to disclose credentials to any invoking process. Signing that Target
cannot authorize its Launcher or distinguish package operations from disclosure.

The reviewed uv 0.12.12 subprocess keyring provider asks an external executable
for one service and optional username. Unlike native authentication, `auth token`
does not consult this provider. This permits an integration without modifying
or re-signing upstream uv and without recreating a plaintext credential store.

## Decision

Install the official arm64 or x86_64 release at `/opt/av/uv/0.12.12/uv`. Pin the
archive and executable SHA-256 and verify the vendor Developer ID signature.
The protected installation preserves Hardened Runtime and empty entitlements.
Install root-owned `uv` and `uvx` stubs through signed `av`, and a private
`/opt/av/uv/bin/keyring` stub through that same Gate Client. Updates require a new
release and command-surface review; `uv self update` cannot replace this prefix
as the user.

Before executing a credential-consuming command from the positive catalog,
`av` registers the complete arguments, initial working directory, and live
process identity with the menu app. `uvx` registers `uv tool run` with its complete
arguments. The menu app verifies these against the live stub invocation and
returns a random 256-bit nonce. Registration is bounded, kept only in memory,
and grants no Secret Use authority.

The launcher executes the pinned Target in the same process and places the
nonce in its environment. When uv invokes keyring, the menu app verifies the
Gate Client and its original parent from kernel process metadata. The parent
must be the reviewed live uv code identity, at the protected path, with matching
PID, start time, effective user, audit session, nonce, and complete arguments.
The first request binds the registration to the live Target's PID version;
subsequent requests must match that execution. The request uses the Target's
live working directory, including uv's directory selection, for Project Value
selection. Identity and working directory are revalidated before release.

Every keyring request is a Secret Application request through the uv Secret
Gate. Existing Launcher verification, operation policy, task context, Approval,
recording, and release checks apply to the full operation. The service and
optional username narrow the request and are included in its credential scope.
The nonce alone conveys no authority. Unregistered helper execution and sibling uv processes cannot satisfy this
binding. A direct child of uv can, however, replace itself with the signed helper
and retain uv as its original parent. The nonce binds an operation, not the
provenance of code running inside it. Even `pip list` can execute a selected
Python interpreter before network access. All Python-capable command families
therefore classify as Unknown and require Approval; they must not gain automic
Read Only or Local Write authorization. `publish` uploads existing distributions
without selecting a Python interpreter and classifies as Remote Write.

Store the imported HTTP Basic credential records as one protected
`UV_CREDENTIALS` Secret. After Authorization, the menu app selects one credential
by HTTPS origin, segment-boundary path prefix, and optional username. The most
specific path wins; ambiguity fails closed. Scheme-less host fallback is denied
because it could otherwise release an HTTPS credential for an HTTP request.
Only the selected credential is returned through XPC and uv's captured helper
stdout. The bundle is never supplied to uv or written back to disk.

The Hardener migrates only the selected plaintext `credentials.toml`, retaining
it on installation failure or a detected concurrent change. Existing protected
values must match exactly. Native Keychain and other credential sources remain
independent Exposures. Private indexes must supply a username or configure
`authenticate = "always"` so upstream uv requests keyring credentials.

## Consequences

The command catalog and classifications are recorded in the
[uv Hardener documentation](../../src/isotopes/hardeners/uv_cli.md), with matching
Rust routing and Swift policy tests. Helper protocol probes use isolated dummy
credentials and a local registry; Detectors do not attempt credential retrieval.

The integration authorizes Secret Application to uv. It does not constrain uv
after release or freeze its configuration. In particular, uv's configured TLS
exceptions, custom certificate roots, proxies, and subsequent credential use
remain under the Target's control. HTTPS scope matching is not a claim that AV
independently verifies uv's transport. This is the existing
[Target boundary](../domain-language.md#target), not a network containment gate.

Auth display, unknown commands, and local inspection receive no registration.
Explicit alternative credentials can satisfy uv without any helper request or
Secret Use. A helper denial is an authentication failure; it does not fall back
to disclosure of the protected bundle. Approvals cover individual credential
requests under the existing cache/grant rules, not an unlimited registration.
