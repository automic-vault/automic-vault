# Configuration-selected Git transport: security review

Status: native signed adapter passes private GitHub/Vault E2E; broad workflow and distribution coverage pending.
Date: 2026-09-10

Force/lease follow-up: 2026-09-23; see the assessment below. Production support
remains disabled.

The proposed integration can preserve ordinary Git commands, but a helper that
forwards an arbitrary command stream to credential-bearing `git-remote-https`
does **not** meet our security promises. Two executable counterexamples below
show why controlling configuration and keeping the token off stdout are
insufficient.

This assessment follows the [domain language](domain-language.md),
[architecture](architecture.md), and [positioning](positioning.md). The native adapter now has its own signed E2E evidence in
[ADR 0047](adr/0047-protected-git-https-transport.md); the loopback probes below
remain separate tests of Git behavior and the protocol boundary.

## Force pushes and leases: feasibility assessment

**Conditional go for implementation; not yet ready to enable.** Neither force
pushes nor exact leases inherently needs a broader credential boundary. They
can use the existing fixed destination, isolated configuration, protected
executables, and one complete batch per HTTPS process. This conclusion covers
branch updates through the reviewed smart HTTPS path, not arbitrary Git
options, signed pushes, or unrestricted helper sessions.

The earlier counterexamples concern arbitrary authenticated requests and reuse
of a read-authorized session. A forced branch update can remain one Remote Write
Authorization Request. Its URL, destination, exact new commit, force mode, and
any exact expected remote commit must all be immutable before Secret
Application. The caller must never acquire the credential-bearing input pipe.

Source review used upstream Git v2.50.1 alongside behavioral checks of the
installed Apple Git 2.50.1 (Apple Git-155):

- [transport-helper.c](https://github.com/git/git/blob/v2.50.1/transport-helper.c#L945-L1025)
  encodes unconditional force as `+` on each update and emits one `cas` option
  per lease. Implicit tracking-ref expectations become explicit object IDs
  before crossing the helper interface.
- [remote-curl.c](https://github.com/git/git/blob/v2.50.1/remote-curl.c#L1282-L1344)
  passes leases as `--force-with-lease=REF:OID` arguments to `send-pack`. The
  smart transport continues to use `git-receive-pack` at the fixed destination.
- [remote.c](https://github.com/git/git/blob/v2.50.1/remote.c#L1541-L1626)
  checks the expected old object ID and permits a non-fast-forward update when
  it matches. Explicit force overrides rejection, including a stale lease.
- [receive-pack.c](https://github.com/git/git/blob/v2.50.1/builtin/receive-pack.c#L1523-L1530)
  supplies both new and advertised old IDs to the server ref transaction. This
  rejects a concurrent remote change after discovery.

### Reproducible evidence

```sh
python3 scripts/check-git-credential-confinement.py --force-lease
```

The new probe reuses the loopback TLS fixture and public dummy password. It
verifies the installed transport's Apple signatures and runs that transport
from an isolated bare repository with a fresh environment, fixed helper, and
redirects disabled. It omits the fixture's extra public-key pin, matching the
production transport's reliance on TLS verification. Fixture setup and the
server use the current Xcode Git, observed as Apple Git 2.54.0 (Apple Git-157).
No real Secret, Vault policy, production runtime, or GitHub repository changes.

Observed results:

| Check | Result |
| --- | --- |
| Divergent update without force, then with force | Rejected normally; exact forced update succeeded. |
| Server denies non-fast-forward updates | Force was still rejected. |
| Matching and stale exact leases | Matching lease allowed the rewrite; stale lease prevented it. |
| Lease expects an absent branch (zero OID) | Creation succeeded; an existing branch was rejected. |
| Multiple leases | Each expectation was enforced; ordinary partial success remained possible. |
| Remote changes between discovery and receive-pack | Server rejected the update; concurrent value remained intact. |
| Force and lease dry-runs | Remote refs stayed unchanged. |
| Outer credential-store, TLS/proxy configuration, and ambient tracing | No dummy credential capture or trace file; intended updates succeeded. |
| Authenticated redirect to another origin | Push failed; the second origin received no request. |
| Parent-facing stdout/stderr | No dummy password or Authorization value in any exchange. |

Two executable counterexamples rule out a simple allowlist extension:

1. **Adding `+` to a leased update defeats its stale-lease rejection.** A lease
   permits a rewrite on its own; it must not be implemented by adding an
   unconditional-force marker. Initially reject a lease combined with `+` for
   the same destination, or explicitly model it as unconditional force with no
   lease guarantee. Never display it as lease-protected.
2. **The current option map cannot represent multiple leases.** Rust stores
   options in a `BTreeMap<String, String>`; Swift also requires unique ordered
   option names. Keeping only the last `cas` loses earlier expectations. The
   probe demonstrates an otherwise valid fast-forward proceeding despite a
   stale expectation when its lease is dropped. Current production rejects
   `cas`, so this is a hazard in a proposed extension, not an enabled bypass.

### Conditions for enabling support

Represent each update's destination, fixed new commit, and either unconditional
force or exact lease explicitly. Preserve every lease and bind it to its exact
destination. Bound counts and bytes; reject duplicate destinations, duplicate
or conflicting leases, unmatched leases, malformed refs/OIDs, and arbitrary
revision expressions. Accept the zero OID only as an expected absent ref, not
as permission to delete. Keep tags, deletion, unreviewed options and arbitrary
helper commands outside this extension.

Both native Rust and service-side Swift must validate the same schema before
registration. Generate the complete payload from that frozen plan. Approval
and Authorization History must distinguish unconditional force from a checked
lease and include every exact expectation. Never reread tracking refs or
refresh an expected OID after Approval. Scope lease state to its push batch.
Retain Remote Write classification and the existing policy checks; discovery
approval cannot authorize a later update. A lease protects against a changed
remote value, not malicious intent: the outer Git may choose any expectation,
which must be authorized as part of the complete request.

Before release, add native parser/wire parity and adversarial tests, then run
the signed Vault/GitHub workflow with force and leases: human Approval and
denial, Read Only policy, record failure, plan changes while Approval is
pending, multiple branches, implicit and explicit leases, dry-run, and stale
remote races. Repeat the existing nonce replay, process-chain, credential
confinement, and session-isolation checks. Reject unsupported combinations
instead of dropping their semantics. Update ADR 0047 when adopting the expanded
surface.

These probes establish transport feasibility, not production authorization
correctness or an exhaustive absence of credential leaks. The production
adapter and service were not changed. Signed pushes and atomic pushes require
their own review; this result does not approve them.

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

The native port is implemented in `src/cli/git_remote.rs`. The Gate independently
validates the complete plan and original execution context, checks the shorter
adapter process chain, and uses the existing gh fulfillment transaction. Its
signed private-repository run verifies ordinary feature-branch workflows,
exact authorization records, hostile configuration isolation, malformed-input
denial, and rejection of copied live/expired nonces. Run:

```sh
python3 scripts/test-git-remote-e2e.py --repository OWNER/PRIVATE_TEST_REPO
```

The live run used existing Write Access authority. Human Approval, cancellation,
large transfers and GUI clients remain to be exercised; the loopback results
alone do not establish those properties. The [manual testing guide](git-workflow-testing.md)
provides configuration, workflow, policy and rollback steps.

## Upstream mechanisms

- [Remote-helper interface](https://git-scm.com/docs/gitremote-helpers): command batches, options, and capabilities.
- [URL routing](https://git-scm.com/docs/git-config#Documentation/git-config.txt-urlltbasegtinsteadOf): longest matching rewrite wins.
- [Git v2.50.1 remote-curl.c](https://github.com/git/git/blob/v2.50.1/remote-curl.c): `cmd_main`, `parse_get`, and `parse_push` accept subsequent commands in one initialized HTTP session.
