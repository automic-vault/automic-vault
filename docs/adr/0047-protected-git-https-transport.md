# ADR 0047: Protected Git HTTPS transport

- Status: Prototype implemented; signed av git E2E verified; transparent workflow and distribution integration pending
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

The shipping workflow must preserve ordinary Git commands, following the
domain model's Zeroconf principle. `av git` is the prototype harness, not the
required user-facing workflow. Configuration-selected remote helpers are under
investigation. A [security review and executable probe](../git-remote-helper-security-review.md)
found that an unrestricted relay to `git-remote-https` can reuse one credential
lookup for a later Remote Write or another HTTPS origin. The transparent route
requires a protocol adapter that enforces immutable operations and destination
bounds. A loopback-only adapter prototype now passes ordinary feature-branch
clone/fetch/pull/push, tracking-ref, dry-run, mutable-source-ref, and adversarial
protocol checks. It uses fixture authorization; production integration is not
implemented or covered by the signed E2E results below.

Verified on macOS 26.6.2 with the installed, signed app and CLI, Apple Git
2.50.1 (Apple Git-155), and hardened gh 2.98.0-2:

- All 329 Swift tests passed, including the positive operation surface, policy
  classifications, and rejection of ACL writes hidden by restrictive mode bits.
  The focused Rust operation-surface and ACL tests also passed.
- The signed app's gh Read Only, Approval, and process-execution self-checks passed.
- Real private GitHub clone, fetch, fast-forward pull, and non-force push passed.
  Push's remote object ID matched the local commit. All four operations produced
  new, persisted Authorization History records through the existing gh Gate;
  this installation authorized them automatically under its existing policy.
- Direct protected gh and an unregistered signed Git/HTTPS/gh chain were denied.
  Copying the actual invocation and nonce while the registered av process was
  stopped did not authorize a sibling chain. Replaying after unregister also
  failed, while the original registered fetch completed successfully.
- An authenticated fetch ignored repository credential-store, URL-scoped TLS
  and proxy overrides, and hostile environment configuration, tracing, proxy,
  TLS, and executable-path settings. No credential-store or trace file appeared.

Repeat the live checks with an installed runtime and a disposable private
repository the Vault-managed credential may update:

```sh
python3 scripts/test-git-credential-e2e.py --run --repository OWNER/PRIVATE_TEST_REPO
```

The fixture is retained when supplied explicitly. The script creates test
commits, checks output without displaying possible credential material, and
requires new authorization records from that run. These checks demonstrate the
implemented boundary for the tested attacks; they are not an exhaustive proof.

Root/kernel compromise, vulnerabilities in the trusted native executables or
TLS stack, and credentials already outside Vault are outside this claim. The
credential necessarily enters gh and the HTTPS transport. Process exit cannot
revoke bytes already applied to a Target. This is a constrained transport, not
a general promise that signed Git cannot disclose credentials.

The runtime currently requires explicit installation and supports only the
reviewed Git build. Distribution, refresh/repair integration, and a broader
command surface must be reviewed before extending this installation.
