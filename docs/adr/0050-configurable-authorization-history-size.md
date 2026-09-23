# ADR 0050: Configurable Authorization History Size

Status: accepted

## Decision

The Mac exposes an Authorization History size setting in whole MiB, from 1 to
1024, defaulting to the existing 25 MiB encrypted payload cap. It stores the
preference in UserDefaults; missing or out-of-range values use 25 MiB. This is
an operational retention preference, not Authorization Policy or a grant of
Authorization History Access. SQLite overhead and reusable free pages are not
included in the payload cap, so it is not a maximum database file size.

On the next history access, the cached store applies a changed cap under its
existing lock and transaction, authenticating rows before pruning the oldest
records. A failure rolls back both the pruning and the in-memory cap and makes
the access fail closed. Increasing the cap cannot restore deleted records.

The 30-day limit, encryption, disclosure limits, and synchronous verified record
persistence before Secret release remain unchanged. Same-user software can
already destroy this local operational history; the preference conveys no
additional authority. No new Approval surface is introduced.

## Consequences

Larger caps retain more sensitive metadata within the existing age limit and
increase the cost of authenticated scans. The 1024 MiB ceiling keeps the setting
bounded. Lower caps discard older records sooner. A record larger than the
configured cap still fails persistence and cannot authorize Secret release.
