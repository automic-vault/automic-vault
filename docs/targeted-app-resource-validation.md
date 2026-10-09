# Targeted App Resource Validation

Date: 2026-08-31

This report validates the private API selected by [ADR 0033](adr/0033-targeted-app-launcher-validation.md). It records evidence, not a new security boundary.

## Conclusion

`SecStaticCodeValidateResourceWithErrors` behaves as ADR 0033 expects when it is combined with the existing strict, all-architecture `SecStaticCodeCheckValidity` precheck and the expected `SecRequirement`:

- the app's main executable and one exact sealed resource can be validated without traversing unrelated resources;
- changed, missing, added, unsealed, or out-of-bundle targets fail;
- a changed or forged `CodeResources` file cannot bless modified target bytes;
- a valid update signed by the same Developer ID remains the same code-signing identity;
- ad-hoc re-signing does not satisfy a Developer ID requirement or a nested-code seal;
- the public precheck rejects damage in a non-native architecture that the targeted SPI alone does not inspect on the current architecture.

The SPI is suitable for the targeted static validation role. It is not sufficient to bind a live process to the code currently stored at its bundle path.

## Contract evidence

Apple's open-source Security header declares the exact ABI as:

```c
OSStatus SecStaticCodeValidateResourceWithErrors(
    SecStaticCodeRef code,
    CFURLRef resourcePath,
    SecCSFlags flags,
    CFErrorRef *errors
);
```

The header marks the SPI available from macOS 11.3 and documents these relevant results: `errSecParam` for a path outside the code object, `errSecCSResourcesNotFound` or `errSecCSResourcesNotSealed` for unusable seals, and `errSecCSBadResource` or `errSecCSSignatureFailed` for changed targets. The implementation first validates the static code's core signature, then validates only the selected main executable, `Info.plist`, plain resource, symlink, or nested code. See Apple's [private header](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/SecStaticCodePriv.h#L103-L130) and [implementation](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/SecStaticCode.cpp#L162-L187).

The symbol is exported by every SDK locally available during validation: macOS 13.3, 14.4, 15.4, 26.5, and Xcode 26.6's current macOS SDK. Dynamic resolution and the strict complete-bundle fallback remain necessary because this is SPI, not a compatibility guarantee.

## Reproduction

The independent harness builds disposable universal `x86_64`/`arm64e` app bundles and never invokes Automic Vault:

```sh
scripts/validate-targeted-app-resource.swift
scripts/validate-targeted-app-resource.swift \
  --identity "Developer ID Application: Example (TEAMID)"
```

The first command uses ad-hoc signatures. The second additionally verifies Developer ID update and identity-mismatch behavior.

Observed environment:

- macOS 26.6.2 (25G83), Apple silicon
- Xcode 26.6 (17F113)
- 19 ad-hoc checks passed
- 23 Developer ID checks passed
- the existing `MenubarHelperCore` targeted-validation test passed with a macOS 14 deployment target

The matrix covers baseline agreement with `codesign --verify --strict --all-architectures`, correct and incorrect requirements, unrelated and selected resource mutations, deletion, addition, containment, main executable replacement, `Info.plist`, resource-seal corruption and substitution, nested signed code, symlinks, `CFError`, non-native architecture damage, same-identity updates, and ad-hoc re-signing.

## Integration finding: live-to-disk substitution

Priority: high.

The harness launches signed app A, replaces A's bundle path with independently valid signed app B, and confirms all three facts simultaneously:

1. the live PID still has A's code-signing identity;
2. static inspection at the original path now reports B's identity;
3. targeted main-executable validation succeeds for B.

This is correct SPI behavior because `SecStaticCodeValidateResourceWithErrors` accepts static code. The ordinary app Launcher path in `launcherIdentities` currently combines live runtime posture from A with `staticSigningInfo` from B and does not compare the live code identifier with the current main executable's code identifier. If B has an existing Launcher-specific rule, A can be attributed B's Launcher Identity after same-user bundle-path substitution.

Verified Launcher Helpers already make the required live-to-disk code-identifier comparison before accepting app attribution. Ordinary app Launchers should apply the same fail-closed invariant. A mismatch should deny app attribution until the updated app is relaunched. This issue predates targeted validation; complete static bundle validation also validates B rather than the already-running A.

## Limits

This run does not establish future SPI availability or behavior. It did not execute on Intel hardware or older macOS releases, exercise certificate expiry or revocation, or validate root-volume resource exemptions. The dynamically resolved fallback and focused regression tests remain required.
