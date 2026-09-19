# ADR 0049: Administrator-authorized CLI installation

Status: accepted

## Context

Opening the bundled CLI installer as a `.command` document causes Gatekeeper
to assess that unsigned script separately when the app carries quarantine.
The existing installer already uses administrator authority to copy the bundled
CLI into `/usr/local/bin/av`. The replacement must preserve that narrow purpose
without introducing a persistent root helper or arbitrary privileged commands.

## Decision

Run a fixed installation transaction through Apple's `osascript` and its
administrator authorization prompt, off the app's main actor. Serialize install
requests within the app. This is installation authority, not an Authorization
Decision at a Secret Gate or Execution Gate; it grants no Secret Use authority.

Before prompting, reuse the bundled executable validator: require a valid strict
signature, the `com.automicvault.av` identifier, and the running app's Team ID.
Inside the privileged transaction, validate each destination ancestor before
creating children. Require actual root-owned directories, no group/world write
permissions, and no extended ACL entries. Do not repair unsafe existing paths.

Copy into a private root-owned temporary directory beneath the validated
`/usr/local/bin`. Remove extended ACLs copied from the source so they cannot
weaken the installed file's permissions. Verify the staged copy's strict code signature against the CLI
identifier, Apple signing anchor, and app Team ID before atomically renaming it
to the fixed destination. Reject an existing destination directory or symlink.
This second verification prevents a changed source during the administrator
prompt from publishing an unsigned or differently identified executable. It
binds publisher and executable identity, not an exact release or app resource
seal; another valid CLI release with that identity satisfies the requirement.

Cancellation makes no installation change. A failure before publication leaves
the existing CLI intact and removes staging through a shell exit trap. Abrupt
process termination or machine failure may leave a staging directory. Missing
protected parent directories created earlier in the transaction may remain.
After success, refresh both dashboard and menu state. Installed-state detection
also rejects unsafe ancestors, any CLI mode other than `0755` (including
setuid/setgid bits), and any CLI ACL.

## Consequences

Quarantine no longer causes a bundled script document to be launched. The app
retains an attended, one-shot administrator operation; no persistent helper,
policy delegation, or privileged general-purpose execution interface is added.
User-managed or ACL-bearing installation directories fail closed rather than
being silently taken over. Regression tests exercise temporary directories and
ad-hoc signed executables without elevation; the real administrator prompt in a
signed app remains a separate manual verification step.
