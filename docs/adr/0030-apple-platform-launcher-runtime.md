# ADR 0030: Treat Apple platform Launchers as runtime protected

Status: accepted

## Context

Apple platform code may omit the CodeDirectory Hardened Runtime flag. Static
signing information can carry a platform identifier, while live code reports
the platform status applied by macOS. macOS intrinsically applies the
corresponding runtime protections to these platform binaries. Requiring the
Hardened Runtime flag alone incorrectly made Apple Launchers such as Chess
ineligible for Authorization Gate policy.

## Decision

Launcher runtime classification treats a valid signing-information platform
identifier or live platform status as equivalent to the Hardened Runtime flag.
The same blocked-runtime entitlement checks still apply. Static app selection,
live process inspection, and Launcher Bundle inspection use this shared
classification.

## Consequences

Apple platform apps can become Verified Launchers without a CodeDirectory
Hardened Runtime flag. A merely Apple-issued Developer ID signature is not
enough: macOS must identify the code as platform code, and normal signature,
designated-requirement, entitlement, and live process checks continue to fail
closed.
