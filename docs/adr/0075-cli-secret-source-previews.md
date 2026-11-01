# 0075: CLI Secret source previews

Status: accepted

## Context

Users need to inspect which Global Value or Project Value a Secret Name would
select before running a command. Project Directory paths disclose more than
Secret Names; existing Secret Name Access grants must retain their scope.

## Decision

Extend `av list` with `--json` and `--project-directory=DIR`. Terminal output
shows each name and selected source, coloring Project Values cyan when color is
enabled. Labels remain explicit without color. Honor `NO_COLOR` and `TERM=dumb`.
Piped output without options remains one Secret Name per line.

Source previews use a separate `list-sources` wire operation restricted to the
trusted `av` Gate Client. Every request requires human Approval, retains the
existing cancellation and denial checks, and records Approval before release.
Neither Secret Name Access nor Authorization History Access authorizes it.
There is no new durable grant in this change.

The client canonicalizes the selection directory, defaulting to its cwd. The
service validates it and uses the same physical-ancestor selection function as
Secret Use. An attributes-only inventory supplies names and source metadata;
Secret data is never read or returned. Inventory or selection failure fails
closed. A Secret without a matching Value is marked missing. A selected Value
is not read to check availability, so a preview cannot promise later success or
fall back following a Secret read failure.

JSON is a sorted array containing `name`, `source` (`global`, `project`, or
`missing`), and `projectDirectory` for project selections only. Text escapes
terminal control characters; JSON never contains ANSI styling.

## Consequences

Interactive listing now asks for Approval even for a Launcher with names-only
access. Piped names-only discovery retains its existing behavior. Older apps
reject the new request; the CLI asks the user to update instead of downgrading
silently. A preview is a point-in-time selection, not authorization of future
Secret Use. No new dashboard or settings UI is needed.
