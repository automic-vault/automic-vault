# ADR 0043: File Descriptor Secret Delivery

- Status: Accepted
- Date: 2026-09-08

## Context

Some consumers accept credentials through file descriptors and require exact
multiline Values without environment injection or named plaintext files.
Environment injection followed by a pipe would still expose Secrets through the
intermediate environment. A generic retrieval operation would weaken custody.

## Decision

Add `av inject --mode=fd +FOO:3 +BAR:4 -- COMMAND`. Each Secret has its own
anonymous pipe. There is no serialization format or Secret transformation.

Use a distinct `inject-fd` XPC operation restricted to the signed `av` Gate
Client. Older helpers fail closed. Validate all Secret Names, descriptor numbers,
uniqueness, and complete coverage independently on the CLI and app. The app
constructs canonical mapping detail rather than trusting client-provided prose.
That detail participates in the request identity, phone Approval digest, and
Authorization Record. Preserve the ordinary selected-Value custody transaction
and require a persisted, verified record before returning any Secret bytes.
FD replies use XPC data rather than NUL-terminated strings.

Require fresh human Approval for every invocation. Existing Direct Access Rules,
Blessings, Tool-specific rules, and Temporary Access Grants gain no FD authority.
Do not offer FD delivery through shebang declarations in this initial version.

The CLI accepts only unused descriptors above stderr. Reserve pipe read ends
close-on-exec before opening XPC resources and keep write ends close-on-exec.
After Approval, preload pipes with nonblocking writes and close the writers. If
any Value does not fit, close all pipes and fail without starting the Target.
Clear close-on-exec on the selected read ends only when executing the approved
Target. Continue using `exec` so process attribution and lifetime do not change.
Remove the requested Secret Names from the Target's environment.

## Consequences

- Exact stored UTF-8 bytes, including multiline PEMs, reach the Target and then
  EOF. A descriptor can be read repeatedly, but consumed bytes are not replayed.
- Prebuffering bounds Value size at available kernel pipe capacity. A streaming
  writer would introduce another Secret-holding process and needs separate review.
- No Secret enters argv, the supplied environment, a named pipe, or a plaintext
  file through this delivery path. The Target can still leak bytes or descriptors.
- This change provides neither encrypted backups nor recovery of bytes changed
  during an earlier import, and does not claim a 1.x migration or rollback path.
