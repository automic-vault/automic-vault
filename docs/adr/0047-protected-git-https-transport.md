# ADR 0047: Protected Git HTTPS transport

- Status: Implementation under validation; not release-ready until signed E2E checks pass
- Date: 2026-09-10

## Context

An Apple signature does not stop Git from forwarding a password to another
credential helper. Repository configuration can also override generic TLS
settings and change after inspection. See the [confinement experiment](../git-credential-confinement-experiment.md).

## Decision

`av git` accepts four fixed forms: `clone URL DIRECTORY`, `fetch URL`, `pull URL`,
and `push URL`. URL must be an explicit `https://github.com/OWNER/REPO.git`.
Only `main`, full SHA-1 repositories, fast-forward pull, and non-force push are
supported. There are no arbitrary Git flags, remote names, submodules, or LFS.

The network phase uses a root-owned runtime at `/opt/av/git`, containing reviewed
Apple Git 2.50.1 (Apple Git-155), its HTTPS executable, the hardened gh provider,
an empty home directory, and a fixed bare repository with no writable refs or
configuration. The installer verifies protected copies before publishing them;
unverified source material remains inside a root-only staging directory.
It preserves upstream signatures. Copies are necessary because a writable
parent directory can permit replacement of an otherwise root-owned executable.
Both client and service reject extended ACLs on protected paths and unexpected
entries in the fixed repository. Executables are copied as bytes into newly
created files so source ownership and ACLs cannot weaken the installed copy.

The network Git receives an explicitly constructed environment and the user's
object directory. It never reads the user's repository, global, or system Git
configuration. It uses the OpenSSL backend and the protected system CA bundle,
disables redirects and proxies, permits only HTTPS, and installs only the fixed
gh helper. Fetch does not write refs, FETCH_HEAD, or commit graphs, or run
maintenance. Ref advertisement selects one exact object ID before fetching it.
Push resolves HEAD before registration and supplies its exact object ID.

The signed av Gate Client registers each network phase with the approval
service. Registration binds its live execution, original operation, working
directory, object directory, exact transport arguments, and a random nonce.
Registration alone releases no Secret. The service accepts a protected gh
request only through the live original chain
`av → Git operation → Git remote-https dispatcher → HTTPS transport → gh`,
with exact paths, arguments, same user/session, code requirements, and eligible
runtime protections. The root-owned provider prevents an unsigned interceptor
from executing gh after rearranging its credential pipe. A nonce alone conveys
no authority. Every lookup revalidates this chain and the registration, including
around record persistence, before the existing fulfillment transaction releases
the credential.

These requests use the existing gh Authorization Gate. Clone, fetch, and pull
classify as Local Write; push classifies as Remote Write. The complete original
operation and GitHub URL remain bound to the Authorization Request. Project
Value selection uses the original av working directory. Insufficient authority
requires the normal Approval. Decision reuse is disabled for this route.
Direct invocation of the protected provider is denied. Ordinary gh credential
commands retain their existing Secret Disclosure classification.

The av process waits for Git to exit and synchronously unregisters the phase
before updating local refs, checking out a clone, or merging a pull. Those local
operations may use repository configuration and run hooks or filters, but cannot
inherit this credential registration. Failure to unregister prevents that phase
transition. Exiting av also invalidates registration for subsequent lookups.

## Validation and limits

The Rust and Swift positive parsers and classifications have focused checks.
Signed integration testing must additionally establish successful private
repository operations, denial of direct/sibling/replayed helper requests,
resistance to configuration and environment attacks, and authorization records
from the real service. Passing parser or dummy transport tests alone does not
establish that boundary.

Root/kernel compromise, vulnerabilities in the trusted native executables or
TLS stack, and credentials already outside Vault are outside this claim. The
credential necessarily enters gh and the HTTPS transport. Process exit cannot
revoke bytes already applied to a Target. This is a constrained transport, not
a general promise that signed Git cannot disclose credentials.

The runtime currently requires explicit installation and supports only the
reviewed Git build. Distribution, refresh/repair integration, and a broader
command surface must be reviewed before extending this installation.
