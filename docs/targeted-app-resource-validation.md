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

## Live-process investigation, 9 October 2026

Follow-up to [issue 387](https://github.com/automic-vault/automic-vault/issues/387).
Fresh live-process validation is substantially cheaper than our targeted static
validation, but the two checks establish different facts. This investigation
changes no runtime authorization code or security invariant.

### Reproduction and timing

```sh
scripts/validate-targeted-app-resource.swift --live
scripts/validate-targeted-app-resource.swift --live \
  --identity "Developer ID Application: Example (TEAMID)"
```

The opt-in mode compiles a native executable with a 32 MiB signed `__TEXT`
payload, signs disposable app bundles with Hardened Runtime, and communicates
with child processes over pipes. It never invokes Vault or reads Secrets.
One test deliberately damages an unread mapped page and expects macOS to kill
the fixture when it accesses that page. Temporary files and child processes are
removed on ordinary completion. The original bundle-substitution test now waits
for the child's initial execution identity before moving its bundle; otherwise
it could race the initial `exec`.

Environment: Apple silicon, macOS 27.0.1 (26A434), Xcode 27.0 (27A266a).
The ad-hoc run passed 29 checks; the Developer ID run passed 33, including the
original static-validation matrix. Ad-hoc signatures are fixture coverage,
not evidence that ordinary ad-hoc Launchers qualify for authorization.

Each timing uses 20 warm pairs after one discarded pair, alternating order.
Both paths construct fresh Security objects and check the stored designated
requirement. The static path uses the existing harness's production-equivalent
strict, all-architecture precheck and targeted SPI. The live path obtains a new
`SecCode` by PID and calls `SecCodeCheckValidity`.

| Signature | Fresh live median | Targeted static median |
| --- | ---: | ---: |
| Ad hoc | 0.299 ms | 14.264 ms |
| Developer ID | 1.267 ms | 15.306 ms |

These are API microbenchmarks, not end-to-end Authorization Request timings.
They exclude process startup, ancestry walking, helper configuration, credential
access, Authorization History, and network requests. They do not establish a
particular improvement to the reported three-second tool call.

### Mutation and execution results

Both signing modes produced the following results. Zero means `errSecSuccess`.

| Change | Fresh live validation | Relevant static check |
| --- | --- | --- |
| Wrong designated requirement | Rejects | Already covered by original matrix |
| Modify an ordinary sealed resource | Accepts | Targeted resource check rejects |
| Modify `Info.plist` | Rejects (-67030) | Rejects (-67030) |
| Modify `CodeResources` | Accepts | Targeted resource check rejects |
| Corrupt the parent seal while its helper runs | Helper accepts | Helper membership check rejects |
| Modify an unread page in the executable, leaving its signature intact | Accepts before the page is accessed | Rejects (-67061) |
| Move running app A aside and put valid app B at its original path | Accepts A's requirement; rejects B's | Accepts B at the original path |
| `exec` `/bin/sleep` in the same PID | Rejects the old requirement; accepts sleep's | Not an on-disk mutation |
| Process exits | Fresh and retained live references reject | Not applicable |

After the changed-page test asks the child to read the damaged page, the child
dies with SIGKILL (termination reason 2, status 9). Live lookup then fails. This
demonstrates lazy enforcement for that mapped page: a successful live check does
not certify every byte currently on disk. It does not show that modified bytes
can execute under the original identity.

A separate result rules out caching live references by PID alone. After warming
a `SecCode` with a successful validation, then asking the same process to `exec`
sleep, checking the retained object against the old requirement still returns
success. A fresh object rejects the old requirement (-67050) and accepts sleep's
requirement. Fresh lookup and binding to the exact process execution must remain
separate from any reuse of static evidence.

### Implications for Vault

Apple's [dynamic validation implementation](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/Code.cpp)
checks signed identity components, dynamic validity, and consistency of the live
and static CDHashes. Its [non-resource validation](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/StaticCode.cpp)
omits the resource envelope. The observed differences are consistent with those
separate validation roles.

The next optimization candidate is the extra full executable validation in
`verifiedLauncherHelperSigningInfo` → `staticCodeIdentity`, particularly for
outside-bundle helpers. `liveSigningInfo` and `liveCodeIdentity` already acquire
fresh live references and validate them. Replacing that extra scan requires an
explicit decision about relying on kernel execution integrity instead of
requiring all executable bytes on disk to validate before each Secret Use.
ADR 0033 and ADR 0055 retain the current static requirements; this report does
not supersede them.

The parent app may not be running, and a valid live helper cannot authenticate
its parent's resource seal. Keep the targeted membership check for in-bundle
helpers and the required parent identity validation. Keep complete Launcher
Bundle enrollment and payload checks, and static validation of Targets that
have not started. Do not replace `executableSigningInfo` globally: callers also
use it for pre-execution Target verification and runtime-posture reporting.

For ordinary app Launchers, deriving identity from the verified live process
deserves a separate design from verifying an arbitrary installed bundle. The
substitution test confirms that the original path can identify a different,
valid app while the original process remains alive; static path identity must
not replace the live identity.

Before changing production checks, record the intended invariant in an ADR,
retain process-generation, current policy, runtime-posture, and release-time
checks, and test the candidate through the real authorization path with
synthetic Secrets. Measure each Launcher walk and history persistence separately.

### Remaining limits

No Intel or older-macOS run, Rosetta live-process test, PID-reuse test,
same-signer `exec` test, JIT/library-validation exception test, certificate
revocation test, or sustained mutation race test was performed. The existing
static matrix covers a damaged non-native architecture; the new live fixture is
native-only. Gatekeeper's current assessment-cache invalidation and App
Management enforcement were not tested. No production speedup or complete
replacement for static verification has been established.
