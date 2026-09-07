# ADR 0033: Validate only authority-bearing app resources

Status: accepted

## Context

Complete static validation traverses every sealed resource in an app bundle.
That work can take several seconds for large development apps even though
Launcher Identity depends on one live executable. Unrelated documentation,
SDKs, plug-ins, and tools neither establish nor inherit that identity.

macOS provides a targeted code-signing operation that validates one exact file
against an app's resource seal. It is private API, so relying on it changes the
product's compatibility boundary and warrants a major version transition.

## Decision

For ordinary app Launchers, Automic Vault validates the app's signed main
executable with strict all-architecture code-signature checks while excluding
unrelated resources, then uses `SecStaticCodeValidateResourceWithErrors` to
validate the exact executable representing the Launcher against the app's
resource seal. The symbol is resolved dynamically. If it is unavailable,
Automic Vault falls back to strict complete-bundle validation.

The same primitive applies to an app's declared main executable and to an
enabled Verified Launcher Helper. Live process identity, designated
requirements, Team IDs, runtime posture, and helper catalog matching remain
separate mandatory checks.

This does not replace strict standalone executable verification, release-time
distribution verification, or Launcher Bundle enrollment. Launcher Bundles are
small security artifacts whose complete bundle, nested payload, digest, and
enrollment remain one invariant.

## Consequences

Launcher verification time depends on the authority-bearing executable rather
than total app size. Modifying that executable, its signature, the app's signed
main executable, or the seal entry fails verification. Modifying an unrelated
sealed resource no longer invalidates Launcher Identity because that resource
does not contribute authority. Removal of the private API degrades performance
by selecting the strict complete-bundle fallback rather than weakening
validation.

Validation evidence and known integration limits are recorded in
[Targeted App Resource Validation](../targeted-app-resource-validation.md).
