# ADR 0067: Periodic Authorization History maintenance

Status: accepted

## Context

Every append decrypted all historical records and pruned inside its commit. This
made credential handover proportional to retained history. Independently sealed
records do not require validating old ciphertext to verify a new record, and
Authorization History is not a complete or tamper-proof audit trail.

## Decision

Keep AES-GCM, authenticated row identifiers and retention buckets, encrypted dates,
Keychain key custody, and synchronous FULL SQLite commit plus authenticated
readback of the new record before Secret release. Failed new-record persistence
still denies release. Appends and setting changes do not scan historical rows.
Legacy import still verifies imported records and sources before committing.

Run maintenance hourly while active, after startup/wake when overdue, and sooner
when estimated payload usage reaches the retention target, throttled to one
attempt per minute. Coalesce overlapping runs and log failures without record
contents. The setting is a retention target, allowing overshoot between passes,
including prolonged overshoot if maintenance fails. Individual records above
the target are rejected. Disk-full failures continue to deny new persistence.

Scan up to the initial maximum sequence in short reads; authenticate and sort
outside the insertion lock. Authenticate the entire scan before any deletion.
Delete expired/future records and then oldest records until the scanned payload
meets the target. Each deletion uses its own transaction and checks the row ID,
sequence, and digest of the authenticated bucket and ciphertext. Changed or missing
candidates stop maintenance; previously committed deletions remain committed.
New rows are excluded. A changed retention setting stops deletion under the old
selection. Estimates schedule work only and never authorize deletion or release.

Historical corruption fails disclosure and maintenance, but does not block an
unrelated new record. Corrupted rows are not silently discarded as expired.
Reads still filter age immediately. Physical deletion is eventual while the app
runs; sleep, shutdown, or failure can delay it. No plaintext timestamp index or
new encryption format is introduced.

## Consequences

Handover performs work for its new record rather than the full history. A short
maintenance read or deletion can still contend with insertion; authentication
and sorting cannot hold that lock. Temporary payload overshoot and later detection
of old corruption replace the previous strict write-time guarantees deliberately.
