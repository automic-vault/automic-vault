# Future Breaking Changes

These are compatibility mistakes we intentionally preserve until a major
version can remove them safely. Each entry states today's behavior and the
breaking correction so new code can opt in early.

## Script capability declarations should default to no inheritance

### Current behavior

A script with no capabilities manifest inherits automic authority already
available from its execution context. This includes an outer Blessed Script,
Verified Launcher policy, Direct Access Rules, and matching Temporary Access
Grants. Existing scripts may depend on that ambient authority, so changing the
default in a minor release could break automation.

Use `capabilities: { inherit: true }` to record an intentional dependency on
this compatibility behavior. Use `capabilities: {}` to opt into the safer empty
capability ceiling now.

### Next major version

Omitting the capabilities manifest should mean `capabilities: {}`. Scripts that
need ambient authority must declare `capabilities: { inherit: true }` explicitly.

## `av save` single-line input should trim surrounding whitespace

### Current behavior

In single-line mode, `av save` removes the line ending from the entered value but
preserves other leading and trailing whitespace. Existing Secrets may depend on
those bytes, so changing this behavior in a minor release could silently alter
their values.

### Next major version

`av save` should trim whitespace from both ends of values entered in single-line
mode before validating and storing them.
