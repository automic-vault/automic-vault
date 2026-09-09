# Code-signing Key Access Detector

**Draft — do not ship:** the legacy macOS ACL API can prompt to unlock a
Keychain even when interaction is disabled. This implementation skips known
locked Keychains and reports incomplete inspection. A Keychain can still lock
between that check and the ACL read. Resolving this race without prompting is a
merge blocker; the proposed Detector is not ready for unattended Scans.

## Trigger Conditions

A **medium-severity Hazard** is reported when an accessible file-based Keychain
identity has a certificate with the Code Signing extended key usage and a
private-key signing ACL that trusts either:

- All applications (a nil trusted-application list).
- `/usr/bin/codesign` (an explicit trusted-application entry).

An empty trusted-application list does not grant this access. Decryption-only
ACLs do not authorize signing. Unknown or unreadable identity/ACL metadata
produces an incomplete-inspection finding instead of a claim of protection.

The Detector reads public certificate fields, key references, and ACL metadata.
It requests disabled Keychain interaction while inspecting and restores the prior
setting. The legacy owner-ACL path does not reliably honor that request; see the
merge blocker above.
It never signs, exports or reads private-key bytes, evaluates certificate trust,
executes a credential tool, or makes a network request.

This is passive evidence of an access-control configuration, **not proof that a
key can currently sign without human authentication**. Keychain lock state,
partition lists, prompt requirements, certificate validity, and token-specific
controls may still prevent use. Partition constraints and effective access are
not evaluated. A native signing probe would itself use the credential and is
outside a Detector's read-only boundary.

## Why This Matters

Code running as the user can invoke `codesign`. If that program can use a
Developer ID private key without human approval, it may be able to sign different
code with the same designated requirement as an ordinary Verified Launcher.
Hardened Runtime establishes runtime protections, not the signer's intent.
This finding does not establish that any particular Launcher can be impersonated
or that a Compromise has occurred.

Generated Launcher Bundles also require exact enrolled code identifiers, payload
digests, and generation metadata. Re-signing changed code does not satisfy their
enrollment. See [Launcher Packaging](../../../../docs/architecture.md#launcher-packaging).

## Why This is not Yet Hardened

Automic Vault does not yet provide a Hardener for code-signing keys. Review the
signing identity's Keychain access controls; changing them may interrupt builds.

## Coverage Limits

Only accessible identities in the file-based Keychain search list whose
certificates explicitly contain Code Signing extended key usage are inspected.
Keys without a certificate, other certificate purposes, inaccessible items, and
other applications' Data Protection Keychain items are outside this coverage.
Secure Enclave and token-backed key controls cannot be inferred from a legacy
ACL. Nonexportability does not establish human approval for each signature.
A clean Scan means no supported condition was found, not that every signing key
is protected.

Certificate trust, expiration, and revocation are deliberately not evaluated;
the finding describes the ACL configuration even for an expired or untrusted
certificate. Notarization is an automated malware and signature check, not a
replacement for control over private-key use.

## References

- [Apple TN3161: Inside Code Signing — Certificates](https://developer.apple.com/documentation/technotes/tn3161-inside-code-signing-certificates)
- [Apple: SecACLCopyContents](https://developer.apple.com/documentation/security/secaclcopycontents(_:_:_:_:))
- [Apple: Keychain partition validation](https://github.com/apple-oss-distributions/Security/blob/main/securityd/src/acls.cpp)
- [Apple: Notarizing macOS software](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
