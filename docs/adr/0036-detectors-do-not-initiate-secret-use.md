# ADR 0036: Detectors do not initiate Secret Use

- Status: Accepted
- Date: 2026-08-31

## Context

A Detector that tests credential availability by invoking a configured helper
can itself initiate Secret Use. With an Automic Vault-protected helper, the Scan
then crosses the Authorization Gate, causes Approval, and may receive the Secret
it was meant only to detect. Suppressing Approval for an internal Detector would
weaken the same authority boundary the Detector is validating.

## Decision

Detectors never initiate Secret Use or execute configured credential helpers.
They may inspect files, metadata, and trusted configuration-only plumbing that
cannot apply or disclose a Secret. When runtime behavior cannot be proven from
passive evidence, the Detector reports a configuration-backed Hazard or an
inspection failure instead of performing the operation.

An explicit user diagnostic may exercise a credential path, but it remains
outside Scan and receives the ordinary Authorization Decision for that complete
request.

## Consequences

- Scan cannot cause Approval merely to determine whether a Secret is protected.
- A signed Gate Client or Automic Vault process receives no diagnostic bypass.
- Some Findings describe configured capability or inspection uncertainty rather
  than proving that a helper currently holds a usable credential.
