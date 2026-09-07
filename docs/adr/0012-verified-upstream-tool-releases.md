# ADR 0012: Verified upstream Tool releases

Status: accepted

## Context

The AWS Hardener originally wrapped Homebrew's AWS CLI. That Target is a Python
entry point using a separately packaged interpreter and source tree. Unless the
entire Homebrew installation is hardened, code running with the user's normal
privileges can replace those components before credential application.

AWS publishes a macOS installer package signed with its Developer ID Installer
identity, notarized by Apple, and containing native universal executables signed
with AWS's Developer ID Application identity and Hardened Runtime. Running the
installer is unnecessary and would execute an upstream post-install script with
root authority.

Changing the Target from Homebrew to a privileged direct install changes the
Tool Hardening and Runtime Authorization boundaries. A migration must also keep
already hardened installations working without allowing the legacy Target once
the launcher is upgraded.

## Decision

The AWS Hardener reads recent versions from AWS CLI's upstream changelog,
selects the newest version whose macOS package is published, and downloads only
that version's HTTPS package URL with redirects disabled and a strict size
limit. The requested version crosses the privileged boundary with the package
digest. The privileged phase copies the package through
`O_NOFOLLOW`, rechecks its SHA-256, requires the signed package version to match,
and verifies all of these claims:

- Apple accepts the installer package and its notarization;
- the package has a trusted timestamp and AWS team `94KV3E626L` as Developer ID
  Installer;
- the package identifier is exactly `com.amazon.aws.cli2`;
- declared and expanded payload sizes and entry counts are bounded;
- the payload contains only regular files and directories, no links or special
  files, and every native component has AWS's Developer ID Application
  signature, a secure timestamp, and Hardened Runtime;
- dangerous runtime exceptions are absent.

The package is expanded as the unprivileged `nobody` account. Installer scripts
are never run. Upstream payload files remain unmodified; AV metadata is added
alongside them in a version-and-digest-bound directory under
`/opt/av/aws/versions`. The tree is made root-owned and non-user-writable, given
a complete SHA-256 content manifest, reverified, and activated through an atomic
`current` symlink. Signed downgrades are rejected. Re-hardening the same release
is supported.

The AWS Gate Client protocol has two explicit generations. Protocol v1 accepts
the exact legacy Homebrew launcher and runtime shape. Protocol v2 accepts only
the official native Target. The menu app negotiates v1 for old clients and v2
for new clients, but it also verifies that `/usr/local/bin/aws` exactly matches
the requested generation. Replacing the stub therefore disables legacy
Homebrew registration and helper retrieval without fallback.

Doctor reports exact legacy launchers as requiring re-hardening. For the
official generation it verifies the active release link, release metadata,
ownership, permissions, content manifest, executable signature, Hardened
Runtime, dependencies, and PATH resolution.

## Consequences

AWS credential application no longer depends on a same-user-mutable Homebrew
Python environment. Upstream package identity and executable identity remain
separate verified claims, and package scripts receive no authority.

The Hardener assumes responsibility for AWS CLI updates and performs a network
download during hardening. Existing Homebrew AWS installations remain usable
only through the exact legacy launcher until the user re-hardens. Other direct
AWS executables remain callable, but cannot retrieve Automic Vault credentials
through this helper.
