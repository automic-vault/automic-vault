# 0078: Recognize sealed application PATH directories

Status: accepted

## Context

The PATH Detector uses Unix write-access checks. These can report directories
inside installed applications as writable without accounting for macOS App
Management. ChatGPT supplies such a directory containing its sealed `rg` to
its command processes. Restarting Automic Vault does not change those processes'
environments.

## Decision

For PATH Findings only, recognize a narrow installed-application exception:

- The absolute directory must resolve to itself, without symlink aliases, under
  `/Applications` and inside an enclosing `.app`'s `Contents` directory.
- The app's executable must pass strict, all-architecture static validation
  with an Apple, Mac App Store, or Developer ID Application signing requirement.
  Ad-hoc, self-signed, and development signatures do not qualify.
- Every immediate directory entry must be a regular file whose seal validates
  against that app. Reject symlinks, subdirectories, special files, empty
  directories, errors, and directories with more than 256 entries.

The Rust scanner uses the same dynamically resolved
`SecStaticCodeValidateResourceWithErrors` SPI as the Swift app-resource
validator. Validate the executable once per app and each distinct PATH directory
once per macOS Detector pass. Do not retain these results across Scans.
If the SPI is unavailable, retain the Finding instead of performing an expensive
complete-bundle scan. Shell PATH checks use the same classifier.

## Security consequences

This is a diagnostic policy that relies on macOS App Management for installed
vendor applications. Signature validation establishes current integrity; it is
not a query of TCC enforcement or the user's existing App Management grants.
Previously authorized app-management access and vendor updates are outside this
PATH Hazard. The exception does not grant Developer Authority, alter Launcher
verification, or change any Authorization Gate.

Only the app executable and files in the PATH directory are validated. Unrelated
bundle resources may be modified without invalidating this diagnostic exception,
matching the targeted scope of the existing Swift validator. Added or modified
files in the PATH directory retain the Finding. Other installation locations
and symlink layouts conservatively retain the existing behavior.

This remains a point-in-time Scan, not a promise about future command lookup.
Per-pass caches can reflect earlier observations within that pass; the next
Scan obtains fresh code objects and revalidates resources.

## Validation

Ad-hoc fixtures exercise the resource-validation path without a private signing
identity, separately asserting that the production vendor requirement rejects
them. Tests cover unsigned bundles, modified executables and resources, added
files, unrelated resources, symlinks, empty and oversized directories, and
ordinary writable PATH entries. An opt-in integration benchmark exercises the
production classifier against installed ChatGPT and repeated observations.

On the development Mac, three fresh release-build macOS Detector scans took
182–287 ms, versus 35 ms before this exception. In the debug integration
benchmark, fresh validation within an initialized process took 19–22 ms;
78 repeated directory checks using the per-pass cache took 1.4 ms total.
These are local measurements, not performance guarantees.
