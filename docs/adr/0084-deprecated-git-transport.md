# ADR 0084: Deprecate protected Git HTTPS transport

- Status: Accepted
- Date: 2026-11-16
- Supersedes: automatic installation and repair in [ADR 0070](0070-independent-gh-hardening.md) and the hardener integration in [ADR 0047](0047-protected-git-https-transport.md)

## Decision

Deprecate `av git` and the `git-remote-av` transport. GitHub CLI hardening
continues to install the `gh` Isotope, migrate credentials, verify custody, and
remove supported legacy credentials. It no longer installs or refreshes the
Git runtime or adapter, or changes Git configuration. The private runtime
installer refuses all requests before filesystem mutation.

Keep `--without-git-configuration` as an accepted compatibility no-op. Leave
existing configuration and legacy preference files untouched. Doctor does not
require the deprecated transport or a reviewed system Git build. It reports
existing `av::` URL rewrites as deprecated without recommending installation.
Both transport entry points warn on stderr so Git protocol stdout stays intact.

## Security boundary

Existing requests retain live process-chain validation, exact operation
binding, runtime integrity and version checks, policy, and recording before
release. Invalid or unavailable runtimes fail closed. Deprecation neither
changes Secret Custody nor grants ordinary helpers Secret Disclosure authority.
No automatic uninstallation, rewrite removal, or fallback occurs: removing a
rewrite could reactivate an ambient credential helper.

Recommend SSH with the Automic Vault SSH agent. Users must review routing and
remote URLs when migrating. The `gh` Isotope and its Secret Gate remain active.

## Validation

Cover default and compatibility-flag hardening without Git configuration
writes, continued credential migration, deprecated routing diagnostics, warnings
on stderr at both entry points, and refusal of the retired installer. Retain
runtime integrity, operation validation, and protocol tests for existing use.
