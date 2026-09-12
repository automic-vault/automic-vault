# ADR 0046: CLI Authorization History Access

Status: accepted

## Context

Authorization History contains cumulative Secret Names and request metadata.
Although `av list` already gates disclosure of saved Secret Names, its Secret
Name Access grant does not describe or authorize disclosure of other Launchers'
historical activity.

## Decision

`av history` uses the signed `av` Gate Client and the same live Verified Launcher
verification and Approval flow as `av list`. It returns a table by default and
JSON with `--json`.

Automic authorization uses a separate, Data Protection Keychain-backed
Authorization History Access list. Adding a Verified Launcher requires Approval;
removal is immediate. Secret Name Access and Authorization History Access do not
imply one another.

The history read is classified as Secret Disclosure for Approval presentation.
An allowed read must append its own Authorization Record before any records are
returned. Failure to record denies the disclosure. The menu bar app must be
running because the CLI has no direct access to the history store.

## Consequences

- Existing `av list` grants gain no authority.
- Scripts can use `av history --json` only after per-request Approval or an
  explicit Verified Launcher grant.
- The returned bounded history includes the record for the current read.
