# ADR 0066: Use kernel-enforced integrity for live helper executables

Status: accepted

Repeated full executable scans add latency to every Authorization Request from
a Verified Launcher Helper. For an already-running helper, use fresh
`SecCodeCheckValidity` and macOS signed-page enforcement, then compare its
validated CDHash with the selected executable's signature metadata. The disk
metadata is untrusted until this comparison succeeds. Do not independently
rehash the helper solely for this live-to-disk identity comparison.

Bind discovery and parent validation to the same process execution, including
PID version, start time, effective user, and audit session. Missing PID-version
evidence denies helper attribution. Validate the live code and disk identity
again after parent validation. Never retain a `SecCode` between checks: local
tests showed that a warmed object could retain the old identity across `exec`,
while a fresh lookup correctly identified the replacement.

This accepts a deliberate difference from full static integrity: an unread
signed page can be damaged on disk while live validation succeeds. In local
Hardened Runtime fixtures, macOS killed the process when it accessed the damaged
page. The authority boundary is the verified live execution; this check does
not certify all bytes currently on disk or an inactive architecture.

The parent app may not be running. Its static executable and vendor checks
remain required, as does targeted resource-seal membership for in-bundle
helpers. Outside-bundle helpers retain the explicit scope in ADR 0055. Launcher
Bundle enrollment, pre-execution Target verification, runtime eligibility,
current policy, and recording before Secret release remain mandatory.

This refines the extra live helper executable scan in ADR 0033 and ADR 0055,
not ordinary app Launcher validation. Tests exercise the production verifier
against path replacement, `exec`, process exit, and unread-page mutation.
The API benchmark motivating this decision measured 1.267 ms for fresh live
validation versus 15.306 ms for targeted static validation of a 32 MiB Developer
ID-signed fixture on Apple silicon, macOS 27.0.1. These are microbenchmarks, not
an end-to-end tool-call improvement or a claim about Gatekeeper's cache.
