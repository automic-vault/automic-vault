# Git credential confinement experiment

Date: 2026-09-10. Status: experiment, not an endorsed integration or security
guarantee. Related: [issue #319](https://github.com/automic-vault/automic-vault/issues/319).

The constrained transport works for the four tested operation forms and blocks
the tested credential escape paths. This does **not** establish that the full
proposed Git/gh integration is secure: the experiment substitutes a dummy
credential provider for gh and does not implement the production registration,
live identity, Authorization Policy, Approval, or recording boundary.

The [domain language](domain-language.md), [architecture](architecture.md), and
[positioning](positioning.md) remain authoritative. In particular, signing
establishes identity and integrity, and the Target controls a Secret after
Application. No production code, policy, or security boundary changes here.

## Reproduce

On macOS with Xcode installed:

```sh
python3 scripts/check-git-credential-confinement.py
```

Observed on Git 2.50.1 (Apple Git-155), arm64. The script verifies the on-disk
Apple signing requirements of Git, its HTTPS transport, and credential-store.
On this installation credential-store resolves to the Git executable itself.
These static checks are prerequisites for the experiment, not live process
identity verification.

The script uses only the Python standard library, Apple Git, and system OpenSSL.
It creates temporary repositories, two temporary TLS identities, a dummy
credential provider, and loopback HTTPS servers. It neither reads real Secrets
nor contacts GitHub. It supplies its own environment and ignores the user's
global/system Git configuration. Temporary artifacts are removed on completion.

Exit zero means all expected observations held, **including the deliberately
vulnerable controls**. The final line explicitly limits the result.

## Candidate and observed results

The initial candidate accepts four fixed operation forms:

- clone one exact HTTPS URL, without templates or recursive submodules;
- fetch that URL's `refs/heads/main`;
- pull the same ref with `--ff-only` and without recursive submodules;
- push `HEAD:refs/heads/main` to that URL, with pre-push hooks disabled.

It reconstructs an environment, pins the executable paths, disables hooks,
resets the helper list, and permits only HTTPS transport. The dummy provider
accepts only the expected HTTPS host and port and the expected repository path
when present. It emits a public dummy password through captured helper stdout.
It does not establish the identity or authority of its parent.

| Check | Observation |
| --- | --- |
| Authenticated clone, fetch, pull, push | Succeed; file contents and remote ref updates match; no credential in captured stdout/stderr |
| Additional Apple credential-store helper | Plain Git writes the dummy password to disk; candidate's helper reset prevents it |
| Ambient credential-helper injection, trace logging, TLS bypass, executable search path, proxy variables | Candidate does not forward them; fetch succeeds without trace/storage files |
| Direct credential command, unknown command, arbitrary leading `-c` | Candidate rejects them before executing Git |
| Untrusted server certificate with clean configuration | Authentication fails without the server receiving the credential |
| Repository-local, URL-scoped `sslVerify=false` | **Bypasses generic command-line `http.sslVerify=true`; untrusted server receives the credential** |
| Exact-URL TLS verification and CA-file overrides | Block that configuration attack; trailing-slash spelling does not bypass them on this Git version |
| Same-user process edits checked repository config before execution | **Attack succeeds despite the containing temporary directory having mode 0700** |
| Replace a user-owned CA file selected by exact-URL configuration | **TLS verification succeeds against the replacement identity and releases the credential** |

The CA-file test models a user-writable trust input. It does not claim that a
same-user process can modify the system trust store. The configuration race
uses a deterministic schedule: inspect, mutate from another process with the
same user ID, execute. It does not measure the probability of winning a live
race. It establishes that checking a pathname or placing it in a mode-0700
directory does not freeze its contents against this adversary.

The stronger candidate adds a server public-key pin as a literal command
argument and forces TLS verification, the CA file, no redirects, and an empty
HTTP proxy at the transport URL's scope. The trusted public key comes from the
test server's generated identity; the test never derives it from the substituted
server certificate.

That stronger candidate:

- rejects the substituted TLS identity even after the CA file is replaced;
- rejects the untrusted server with an additional configured CA directory;
- completes clone/fetch/pull/push despite scoped helper, TLS, and wrong-pin
  configuration in the repository, without creating the credential-store file;
- does not contact a second origin through a redirect, even when repository
  configuration enables redirects;
- releases no credential to a rewritten origin: the helper's exact host/port
  check denies it and authentication fails.

The rewritten-origin test does make an unauthenticated request to that origin.
It demonstrates denial of Secret Disclosure, not complete network containment
or authorization of every network request.

## What this establishes, and what it does not

The original generic configuration overrides are insufficient. There is now a
runnable stronger transport candidate that survives the listed attacks while
performing useful Git operations. Public-key pinning is one tested way to
remove the mutable CA-file dependency; this experiment does not establish it as
the only possible approach or specify GitHub key distribution and rotation.

The evidence remains conditional on the exact operation forms, tested Git
build, trusted expected endpoint/key, and controlled launch arguments and
environment. A finite test matrix is not a proof against every Git/libcurl
configuration feature, implementation vulnerability, or future release.

Before enabling automic Secret Application, the production design still needs
to establish and test:

1. A signed, protected launcher and provider, with a complete registered
   Authorization Request and live Git/transport/helper identity binding.
   A direct invocation, sibling process, wrapper bypass, shell interceptor,
   changed execution, or replay must receive no Secret. A nonce alone cannot
   establish this; see [the uv registration boundary](adr/0046-uv-registered-keyring-helper.md).
2. An integrity-protected source for the effective transport constraints and
   expected endpoint identity. User-owned files and a preflight scan cannot
   supply that boundary. The dummy provider is deliberately mutable and has
   no Vault authority.
3. An exact upstream configuration and command-surface review. The tests do not
   establish support for arbitrary flags, aliases, remote names, tags, force
   pushes, submodules, LFS, custom filters, hooks, or arbitrary pull strategies.
4. The existing policy distinction between Local Write and Remote Write,
   explicit Secret Disclosure handling, live revalidation through Approval,
   and record-before-release behavior. None is replaced by these transport
   checks or exercised by this experiment.

An ADR must define the accepted boundary before implementation. No automatic
Git credential exception should be enabled on the strength of this experiment
alone.

## Upstream references

- [Git v2.50.1 credential.c](https://github.com/git/git/blob/v2.50.1/credential.c):
  helper selection and `credential_approve` forwarding credentials for storage.
- [Git v2.50.1 http.c](https://github.com/git/git/blob/v2.50.1/http.c): URL-matched
  configuration, TLS/proxy settings, environment overrides, and key pinning.
- [Git v2.50.1 remote-curl.c](https://github.com/git/git/blob/v2.50.1/remote-curl.c):
  HTTP transport initialization and helper operation protocol.
- [Git configuration documentation](https://git-scm.com/docs/git-config):
  configuration scopes and URL-specific HTTP matching.

The upstream references explain the mechanisms. The executable observations
come from the installed Apple build, which can differ from upstream v2.50.1.
