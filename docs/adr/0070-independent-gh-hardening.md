# ADR 0070: Complete gh hardening independently of Git setup

- Status: Accepted
- Date: 2026-10-16
- Updates: [ADR 0047](0047-protected-git-https-transport.md), hardener integration

## Context

An unreviewed Apple Git build prevents protected transport installation. Making
that failure fatal to `av harden gh` also interrupts credential migration before
legacy credential cleanup, even though the gh Isotope can operate independently.

## Decision

Complete gh Isotope installation, credential storage, legacy credential cleanup,
and migration postcondition verification before attempting automatic Git setup.
Failures in those hardening steps remain fatal. Automatic Git preflight and setup
failures produce a warning without failing completed gh hardening. The explicit
manual-configuration option retains its existing preference and error handling.

An automatic setup failure does not record a manual opt-out or suppress Doctor
diagnostics. Users can retry setup by running `av harden gh` again.

## Security boundary

Git runtime publication, routing validation, and runtime authorization remain
unchanged. No unreviewed runtime is published, no fallback credential helper is
installed, and no Secret Use authority is granted by a successful hardening exit.
Ordinary credential-helper requests retain Secret Disclosure classification.
This change does not endorse another Git build or remove the version check.

## Validation

Regression coverage exercises automatic Git preflight failure with and without
credentials to migrate, checking successful completion, protected fixture
storage, plaintext cleanup, visible warnings, and absence of a manual opt-out.
Existing migration conflict, cleanup postcondition, and Git routing tests remain
required.
