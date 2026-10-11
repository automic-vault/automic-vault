# ADR 0068: Dashboard Authorization History reads

Status: accepted

## Context

After every new Authorization Record, the dashboard decrypted all retained rows
for the first page's day count, then scanned again for 24-hour activity. Both
reads held the same lock used by credential handover to persist its new record.
Moving pruning off handover did not remove this competing work.

## Decision

Build the first 50 records, retained-day count, and 24-hour activity together.
Capture the highest sequence and copy ciphertext in batches of at most 64 rows,
ending a batch once its ciphertext reaches 1 MiB. One record may exceed that byte
threshold. Release the insertion lock before authenticating and decoding each
batch. Concurrent appends beyond the captured sequence belong to the next refresh.

After a commit notification, reuse already authenticated display data and read
only sequences added since the prior snapshot. Keep snapshots scoped to their
store instance and calendar, and rescan after one minute from the original scan,
on clock rollback, or when an expiring page record requires replenishing the
page. Filter activity and retained days against the current retention window on
every refresh. Explicit refreshes and reopening the dashboard perform full scans.

Imports and maintenance deletions invalidate snapshots under the store lock.
SQLite's connection-local `PRAGMA data_version` detects commits through other
connections. A scan overlapping either kind of invalidation fails rather than
publishing mixed results. These counters are cache invalidation hints, never a
substitute for authenticating ciphertext or an authorization input. They do not
make arbitrary file damage detectable immediately; full reads still authenticate
every scanned row.

Keep encryption, durable append/readback before Secret release, and the verified
CLI disclosure path unchanged. Dashboard snapshots cannot grant authority.

## Consequences

Ordinary commit notifications decrypt only new rows. Initial and periodic full
scans still scale with retained history, but decryption does not hold the writer
lock. SQLite reads and existing CLI disclosure can still contend with insertion.
Activity records remain in memory and are filtered each refresh; this is not a
constant-time operation across arbitrary activity volumes. A failed dashboard
read displays the existing unavailable state and drops the reusable snapshot.

SQLite documents the cache invalidation behavior in
[PRAGMA data_version](https://www.sqlite.org/pragma.html#pragma_data_version).
