# av5 security boundaries are versioned separately from av4

Status: accepted for the av5 rewrite; no change to shipped av4 enforcement.

av5 retains the canonical meanings of Secret, Authorization Request, Verified
Launcher, Target, Gate, Policy, Approval, and Local Execution Boundary. Record
these deliberate product differences explicitly rather than weakening av4's
existing documented invariants:

- av5 removes persistent Authorization History and the requirement to persist an
  Authorization Record before Secret release. It retains complete-request binding,
  identity and integrity validation, credential selection, policy evaluation,
  live-request checks, replay defenses, timed grants/denials, provenance, and
  operational state. Durable Blessings retain the contents needed for diffs.
- Enrolled Macs may carry approvals alongside iPhones. The originating Mac owns
  the request, validates the first valid response, and enforces the decision.
  Other devices receive neither stored Secret values nor execution authority.
  Shared-key recovery remains account-wide; key rotation cannot exclude a
  compromised device that retains access to the same iCloud Keychain account.
- av5 omits Varlock integration, Secret Proxies, Homebrew hardening, generic
  Launcher Bundle enrollment, and SHA-based enrollment. Its MVP includes gh,
  aws, SSH Agent Gate, and GPG Signing Gate. npm protections and herdr/pi
  packaging are deferred. Installing a tool grants no credential authority.
- Managed installations use root-owned versioned prefixes with narrow privileged
  publication authority. The main app and engine-owning menu helper are ordinary
  user processes. Root/kernel compromise remains outside the threat model.
- av5 requires an explicit capabilities manifest for Blessed Scripts. Unlike
  av4's compatibility behavior, absence does not mean Capability Inheritance.
  `capabilities: { inherit: true }` remains explicit inheritance; `{}` remains
  an empty ceiling. Its initial runner accepts only verified shell snapshots,
  without the canonical-path exception, and SSH capabilities name exact per-key
  gates. Optional ordinary-shebang re-exec uses `AV_RUN` only as a recursion hint,
  never authority. See [AV5 ADR 0021](../../../av5/docs/adr/0021-local-blessed-scripts.md).
- av5 uses distinct bundle, IPC, launch-agent, and future storage namespaces so
  av4 can run alongside it. No implicit migration or fallback to av4 authority.

The av5 repository's ADRs 0009–0012 and implementation plan specify delivery.
Stage 1 implements only process lifecycle, authenticated management IPC, and
startup configuration. It exposes no credential or approval operation. Later
stages must validate the retained invariants before enabling those operations.

av4 retains its record-before-release requirement, supported integrations, and
existing remote-approval behavior. This decision does not migrate existing
credentials, policies, installations, or relay enrollment.
