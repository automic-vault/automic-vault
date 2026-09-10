# Configuration-selected Git transport: security review

Status: bounded adapter passes loopback workflow/attack checks; signed Vault integration pending.
Date: 2026-09-10

The proposed integration can preserve ordinary Git commands, but a helper that
forwards an arbitrary command stream to credential-bearing `git-remote-https`
does **not** meet our security promises. Two executable counterexamples below
show why controlling configuration and keeping the token off stdout are
insufficient.

This assessment follows the [domain language](domain-language.md),
[architecture](architecture.md), and [positioning](positioning.md). It does not
extend the signed `av git` E2E results in [ADR 0047](adr/0047-protected-git-https-transport.md)
to a different process chain or protocol boundary.

## Executable evidence

```sh
python3 scripts/check-git-credential-confinement.py --remote-helper
```

The probe uses Apple Git 2.50.1 (Apple Git-155), verified on-disk Apple
signatures, temporary repositories, loopback TLS servers, and a public dummy
password. It reuses the original confinement experiment's server and provider.
No real Secret, GitHub repository, Vault policy, or installed runtime changes
participate. Temporary Python helpers are test doubles with no Vault authority;
their files and CA material are user-owned, not a production integrity boundary.

The isolated HTTPS process receives a separate bare repository, selected object
directory, fresh environment, one dummy provider, verified TLS, a literal test
public-key pin, and disabled proxies/redirects. The outer Git configuration
routes the unchanged HTTPS origin through a custom remote helper.

| Check | Observed result |
| --- | --- |
| Ordinary `git ls-remote origin` through URL configuration | Authenticated successfully; saved origin stayed unchanged. |
| Outer credential-store, URL-specific TLS/proxy settings, and curl tracing | No dummy credential in output; no storage or trace file. |
| Longer URL rewrite bypasses custom helper | Connection failed without invoking the dummy provider. This establishes routing behavior, not Vault enforcement. |
| `list`, then `push OID:refs/heads/read-session-write` in one HTTPS process | Created the remote branch after exactly one credential lookup, initially used for the read. |
| `list`, then `get OTHER_URL LOCAL_FILE` in one HTTPS process | Another HTTPS origin received the cached dummy credential without a second provider lookup. |

The other origin uses a different loopback port and the same test certificate
and key. TLS verification and the public-key pin remain enabled. This proves
that a valid TLS peer and even a matching pin do not enforce the authorized
origin. It does not demonstrate bypassing a mismatched TLS pin.

Both counterexamples leave the dummy credential out of parent-facing stdout
and stderr. The first still performs an unintended Remote Write; the second
sends credential bytes outside the original origin. These are general-purpose
Git helper behaviors, not claimed Git vulnerabilities or bypasses of the
existing registered `av git` implementation. No real Read Only policy or
Approval was bypassed: the test demonstrates what would go wrong if an adapter
authorized the initial read and then relayed the remaining stream unchanged.

## Match against our promises

| Promise | Assessment and required boundary |
| --- | --- |
| Existing commands keep working | Configuration routing works for native Git. Full clone/fetch/pull/push, tracking refs, feature branches, hooks, and relevant GUI clients still need workflow tests. Embedded Git implementations may not support this extension. |
| Authorization covers one complete immutable operation | **An unrestricted relay fails.** Parse and bound each semantic request; bind the original command plus the effective destination, object IDs/ref updates, force/lease/dry-run state, and relevant options before using the credential. |
| Read authority cannot authorize Remote Write | **An unrestricted relay fails.** Never carry a read authorization into `list for-push`, `push`, or an unrestricted connection mode. A complete fetch/pull/clone still counts as Local Write even though its network exchange reads remote state. |
| Secret Application does not become Secret Disclosure | **An unrestricted relay fails destination confinement.** The helper must keep credentials in protected processes and constrain every authenticated request's origin, repository path, endpoint, and transport settings. Reject arbitrary `get` requests. |
| Software identity establishes eligibility, not blanket authority | The new helper needs live original-process/Launcher verification and its own complete registered request. PATH selection, a helper name, parent argv, URL configuration, and a nonce are insufficient individually. Test direct calls, wrappers that alter pipes before exec, and sibling/replayed requests. |
| Configuration bypass fails closed | Configuration selects a route; it cannot grant Secret access. Overriding it must leave ordinary Git without the Vault-managed credential except through separately authorized Secret Disclosure. Ambient credentials remain outside this claim. |
| Record before release; no broader fallback | Reuse the service's verified recording and selected-Value checks for the new route. Test record failure, changed Value selection, process replacement/exit, and policy changes while Approval is pending. These are not tested by this dummy probe. |

## Required implementation shape

Prefer a small protocol adapter that constructs one immutable transport plan
and starts a dedicated constrained credential-bearing process for that plan.
It must own the child's input pipe. Only the adapter may generate transport
commands; the outer Git command stream must never become that pipe directly.
Do not expose cached credentials through a general-purpose transport session.
Ending registration alone does not erase a credential already cached in a live
HTTPS process.

Advertise only reviewed capabilities. Validate bounded, complete command
batches and option values; deny malformed/incomplete requests. Do not forward
`get`, arbitrary `connect`/`stateless-connect` service names, or unreviewed
options. Resolving a mutable source ref once is insufficient if a later child
resolves it again: bind an exact object ID and exact destination update. Changes
to destination, force/lease semantics, or dry-run state require a new request.

Keep hooks, filters, local configuration, and local ref bookkeeping outside
the credential-bearing process. The outer Git process can retain those normal
behaviors while the adapter treats all incoming protocol data as untrusted.
Required safety options must fail explicitly when unsupported; silently
discarding a lease, signature, atomic, or dry-run option changes user intent.

Before enabling this route, repeat the signed Vault tests for the new chain and
add live read-to-write escalation, destination change, stdin/pipe interposition,
mutable-ref, option-change, record-failure, and lower-policy Approval tests.
Then exercise ordinary private feature-branch workflows and verify both remote
effects and local tracking refs. Passing the old `av git` tests cannot establish
these new guarantees.

## Bounded adapter experiment

The [prototype adapter](../scripts/git-remote-av-prototype.py) now implements the
fixed-batch approach above. It advertises only fetch, push, and reviewed options.
Each network request starts a fresh Apple HTTPS process with a complete input
batch; subsequent client commands cannot enter that process. Push planning
resolves source refs to exact commit IDs before executing the transport.
Git protocol v0 provides explicit ref lists without exposing an opaque
stateless-connect session. Git still performs local checkout, merge, upstream
configuration, and tracking-ref updates.

Run the authenticated loopback test:

```sh
python3 scripts/check-git-credential-confinement.py --adapter
```

Observed with Apple Git 2.50.1 (Apple Git-155):

- Ordinary `git clone`, feature-branch `git push -u origin feature/workflow`,
  `git fetch origin`, `git pull --ff-only`, and `git push` succeeded. The
  original HTTPS URL stayed unchanged. Remote refs, local files, upstream
  configuration, and `origin/feature/workflow` matched the expected commits.
- `git push --dry-run` left the remote unchanged. Unsupported lease, atomic,
  and signed-push options failed instead of continuing with weaker semantics.
- A deterministic same-user ref change during authenticated push discovery
  did not change the already-planned commit sent to the remote.
- A read-only fixture refused a push after an authenticated read. An arbitrary
  `get` after a read never contacted the second HTTPS origin. Neither attack
  caused another credential lookup after the allowed read.
- Outer credential-store, TLS/proxy configuration, proxy environment, and
  tracing did not capture the dummy credential or affect the isolated transport.
- Unreviewed connection commands/options, mixed or incomplete batches, and
  oversized input failed before credential lookup. Recorded fixture plans
  contained the exact push object IDs, destination refs, URL, and option values.

This is an executable feasibility result, **not production authorization**.
The Python adapter permits only the loopback fixture endpoint, has mutable
test files, and uses a fixture read/write setting and JSON plan log instead of
Vault. The fixture's read/write labels describe network effects; they do not
replace classification of the complete original Git operation. In particular,
fetch, clone, and pull must still require Local Write in the real Gate.
The prototype does not prove live identity binding, Project Value selection,
record-before-release, cancellation, or real Approval behavior for this route.
No real Secret or installed Git configuration changed during these tests.

The tested surface covers full SHA-1 repositories and ordinary branch
operations. Force/deletion, tags, shallow/partial clones, submodules, LFS,
leases, atomic/signed pushes, and GUI compatibility remain outside this
prototype's supported surface. Its controlled test server uses small packs;
large transfers and streaming/resource bounds still need production validation.

The next step is to port the bounded protocol handling into a signed Gate
Client, register its actual transport plans and original-operation context,
and repeat the signed Vault tests against the new process chain. A complete
secure implementation of the configuration-selected route is not yet verified.

## Upstream mechanisms

- [Remote-helper interface](https://git-scm.com/docs/gitremote-helpers): command batches, options, and capabilities.
- [URL routing](https://git-scm.com/docs/git-config#Documentation/git-config.txt-urlltbasegtinsteadOf): longest matching rewrite wins.
- [Git v2.50.1 remote-curl.c](https://github.com/git/git/blob/v2.50.1/remote-curl.c): `cmd_main`, `parse_get`, and `parse_push` accept subsequent commands in one initialized HTTP session.
