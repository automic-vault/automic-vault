# ADR 0043: Gate SSH authentication through a local SSH agent

Status: accepted

## Context

An encrypted SSH key with a Keychain passphrase protects the file at rest, but
an ordinary agent can make its signing authority ambient to same-user software.
Issue #217 requests Launcher-based authorization, with destination policy left
for later. Unlike GPG signing, SSH uses the same credential for all Launchers.

## Decision

Add an off-by-default SSH Agent setting and a built-in SSH Agent Gate. Keep one
OpenSSH private key and optional passphrase together in `AV_SSH_CREDENTIAL` in
the Data Protection Keychain. Select only its Global Value. Persist the enabled
state and corresponding public key in a separate Keychain configuration item.
Changing credentials or enabling the integration uses the existing authority
Approval surface. Disabling immediately prevents new Secret Application.

The signed bundled `av ssh-agent` serves a mode-0600 Unix socket in a private
mode-0700 directory. It implements bounded identity enumeration and SSH user
authentication signing from RFC 9987. Unsupported operations, including adding
keys, PKCS#11 loading, arbitrary signing and unrecognized flags, fail closed.
Use RustCrypto's SSH key implementation for OpenSSH decoding, decryption and
signatures for Ed25519 and ECDSA keys. RSA is rejected because the available
RustCrypto RSA implementation has the unpatched
[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) timing
advisory; another reviewed implementation is required before enabling RSA.
Never invoke the ambient system agent or write usable keys to disk.

For each signature the helper passes the connected socket over authenticated
XPC, binding the exact bounded payload digest, public key and signature flags.
The menu app obtains the socket peer's kernel audit token, matches the socket's
recorded executable UUID, and verifies that the live process owns the exact
connected endpoint through kernel descriptor information. `LOCAL_PEERTOKEN`
alone is insufficient: macOS resolves the most recent accessor's current task,
including after exec or PID reuse. UUID is corroborating data, not code identity.
Each request retains and revalidates the peer's PID version, start time, user,
audit session, arguments and working directory.

Launcher attribution follows only live original ancestors. Each parent must
match the child's kernel-recorded parent unique ID and original parent PID
version. The peer cannot represent itself as a Launcher, and session-leader or
retained-provenance fallback is unavailable. This prevents a socket sender or
its parent from gaining a different Launcher's authority by executing an
allow-listed app after preparing a request. Kernels that cannot provide original
parent execution versions leave the feature unavailable; Settings explains this.
The long-running helper never supplies Launcher attribution.
A root-owned `/usr/bin/login` may be traversed as a system relay, because Terminal
uses it to start the user's shell. Both original execution links must verify, the
live relay must satisfy `anchor apple and identifier com.apple.login`, and its
parent must have the child's UID and audit session. The relay supplies no Launcher
authority. Its PID version comes from kernel process information when its audit
token is inaccessible; the relay's unknown audit session is not used for attribution.
A Verified Launcher is required even for manual Approval. The signing Target
remains the signed `av` helper, which alone receives usable credential bytes.
The peer and Keychain configuration are rechecked before release. Each use must
persist and verify an Authorization Record before credential bytes leave custody.
No transient decision reuse, script authority, Temporary Access Grants or
Retained Launcher Provenance applies. Policy offers Approval Required and Allow
Authentication; authentication can enable remote writes.

## Consequences

Public keys are deliberately enumerable without Approval, but enumerating them
never loads private material. Private-key copies outside Automic Vault and keys
already loaded into other agents remain independent access paths. Settings must
explain these limits and never silently delete originals or clear another agent.

The socket establishes a live local accessor and its original ancestry, not the
origin of every byte it forwards. Forwarded or shared connections inherit that local client's
attribution. Hostnames and remote command arguments are context, not verified
destination restrictions. A subsequent destination policy requires an additional
review of OpenSSH session binding and forwarding, not trust in client labels.

References: [SSH agent protocol](https://www.rfc-editor.org/rfc/rfc9987.html),
[OpenSSH extensions](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent).
