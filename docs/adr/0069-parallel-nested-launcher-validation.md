# ADR 0069: Parallel validation of nested Launcher Helpers

Status: accepted

## Context

A Verified Launcher Helper packaged as a nested app produces two candidate
Launcher identities: its verified parent app and its own nested app. Verifying
the nested app and verifying the parent app's sealed helper resource are
independent, expensive operations. A local benchmark of the production validators
measured approximately 230 ms sequentially and 117 ms concurrently.

## Decision

Run these two independent checks concurrently when both candidates exist. Use at
most two synchronous workers per resolution and join both before returning any
identities. Each worker creates its own Security-framework code objects; results
cross the boundary as immutable Sendable values protected by a lock. No work
escapes the resolution call. Other cases retain a single worker.

Preserve parent-first identity order regardless of completion order. Preserve
failure and standalone-fallback behavior. Keep all existing signature flags,
resource checks, vendor requirements, runtime checks, fresh live-code lookups,
and the process-identity recheck after the combined resolution. All authorization
checkpoints continue to execute the complete validation. No integrity result is
cached across resolutions or checkpoints.

## Consequences

Parallel hashing reduces elapsed time on multicore machines without reducing the
checks performed. Total hashing work is unchanged; concurrent requests can still
contend for CPU and storage bandwidth. Benefits depend on the machine and bundle.
A rendezvous regression test requires both production lookup branches to execute
before either can finish and checks identity ordering and failure outcomes.
