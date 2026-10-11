# ADR 0047: Encrypted Rolling Authorization History

Status: accepted; write-time pruning and cap semantics superseded by [ADR 0067](0067-periodic-history-maintenance.md)

## Context

Authorization History was one Keychain item containing the newest 50 records.
That kept sensitive request metadata inside the Data Protection Keychain, but a
busy developer could lose useful operational context quickly. Increasing the
array bound would make every allowed Secret Use rewrite and verify an
ever-growing Keychain value.

Authorization History remains local operational history. Longer retention must
not imply an append-only audit trail or move readable Secret Names, commands,
working directories, and software identities into an ordinary same-user file.

## Decision

The menu bar app stores Authorization Records as independently authenticated
AES-GCM ciphertext rows in one SQLite database in Application Support. A random 256-bit root key is
stored in the app's Data Protection Keychain access group with After First
Unlock availability. HKDF derives separate encryption and retention-bucket
keys. Record timestamps remain inside the ciphertext; keyed hourly retention
buckets permit expiry without disclosing activity times. Each row's opaque ID
and retention bucket are authenticated with its ciphertext.

The store prunes expired records transactionally on each write and on a
coalesced background maintenance pass after a read. Reads filter expired
records immediately without holding a write transaction. It caps encrypted
record payloads at 25 MiB, deleting the oldest records by authenticated record
date first while preserving a newly appended record. A dormant database may
retain expired ciphertext until its next access. The
database is excluded from backup. SQLite provides synchronous transactions; an
allowed Secret Use succeeds only after
its complete record is committed, read back, authenticated, decoded, and
compared with the expected record. Each write also authenticates retained rows
before pruning; the bounded scan can add latency, but a cleartext date index
would disclose activity times and skipping authentication would weaken
fail-closed storage checks.

On first use and subsequent restarts, the app idempotently imports existing
Keychain and older UserDefaults history,
verifies every imported record and rechecks both legacy sources before committing
the import, then applies retention. A changed source fails closed. Legacy
sources remain in place: an older helper can write between a source comparison
and deletion, and neither Keychain nor UserDefaults provides a conditional
delete of the observed value. Their pre-existing copies therefore do not
acquire the rolling store's retention guarantee. A database without its
encryption key is unavailable
and never receives a replacement key.

The dashboard initially showed the newest 50 records. It now browses all
retained records grouped by day, loading older records in 50-record pages as
they scroll into view. While searching, the user loads older pages explicitly
to extend the search. The cursor uses the store's sequence rather than an
offset, so a new record does not skip an older page. `av history` returns the
newest 50 by default; `--since <duration>` may request a narrower time window up
to 30 days. The original single-reply protocol rejected results over 1 MiB;
[ADR 0058](0058-complete-cli-history-windows.md) supersedes that CLI limitation
with a complete snapshot transferred in bounded chunks. Filtering occurs inside
the menu bar app before disclosure. CLI
formats receive only display-safe commands as defined by ADR 0046.
An explicit window uses the dedicated `history-window` XPC operation with the
signed menu helper. An older helper rejects that operation rather than silently
ignoring `--since` and returning its default 50-record view.

## Consequences

- Longer history does not make Authorization History tamper-proof, complete, or
  suitable as forensic evidence. Same-user software can still damage or delete
  the encrypted database.
- The database exposes its existence, record count, insertion order, and
  approximate storage volume. Equal bucket values reveal which records share a
  retention hour, but not that hour or record contents without the
  Keychain-held key.
- New writes use one durable history store; retained legacy sources are
  read-only to the current helper and may be reimported after a restart.
- Browsing older records changes only the local dashboard view, not the
  Approval or Verified Launcher requirements for `av history`. More metadata
  may be visible to software with access to the open window or its accessibility
  tree; the dashboard already exposes its visible records on that surface.
- GUI export remains unnecessary while the attended, authorized CLI can emit
  JSON for an explicit time window.
