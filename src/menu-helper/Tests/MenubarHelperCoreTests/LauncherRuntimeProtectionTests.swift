import Security
import Testing
@testable import MenubarHelperCore

@Test func hardenedRuntimeIsRequiredForNewSecretGateLaunchers() {
    #expect(launcherRuntimeProtection(
        signatureFlags: 0,
        enabledEntitlements: []
    ) == .hardenedRuntimeMissing)
    #expect(launcherRuntimeProtection(
        signatureFlags: SecCodeSignatureFlags.runtime.rawValue,
        enabledEntitlements: []
    ) == .hardened)
    #expect(launcherRuntimeProtection(
        signatureFlags: SecCodeSignatureFlags.runtime.rawValue,
        enabledEntitlements: [
            "com.apple.security.cs.allow-jit",
            "com.apple.security.cs.allow-unsigned-executable-memory",
        ]
    ) == .hardened)
    #expect(launcherRuntimeProtection(
        signatureFlags: SecCodeSignatureFlags.runtime.rawValue,
        enabledEntitlements: ["com.apple.security.cs.disable-library-validation"]
    ) == .hardenedWithLibraryValidationDisabled)
}

@Test func applePlatformCodeIsIntrinsicallyRuntimeProtected() {
    #expect(launcherRuntimeProtection(signingInformation: [
        kSecCodeInfoFlags: 0,
        kSecCodeInfoPlatformIdentifier: 26,
    ]) == .hardened)
    #expect(launcherRuntimeProtection(signingInformation: [
        kSecCodeInfoFlags: 0,
        kSecCodeInfoPlatformIdentifier: 26,
        kSecCodeInfoEntitlementsDict: ["com.apple.security.get-task-allow": true],
    ]) == .unsafeEntitlements(["com.apple.security.get-task-allow"]))
}

@Test func liveApplePlatformCodeIsIntrinsicallyRuntimeProtected() {
    #expect(launcherRuntimeProtection(signingInformation: [
        kSecCodeInfoFlags: 0,
        kSecCodeInfoStatus: SecCodeStatus.platform.rawValue,
    ]) == .hardened)
    #expect(launcherRuntimeProtection(signingInformation: [
        kSecCodeInfoFlags: SecCodeStatus.platform.rawValue,
    ]) == .hardenedRuntimeMissing)
}

@Test func injectionAndDebuggingExceptionsPreventSecretGateAdmission() {
    let unsafe: Set<String> = [
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.get-task-allow",
    ]
    #expect(launcherRuntimeProtection(
        signatureFlags: SecCodeSignatureFlags.runtime.rawValue,
        enabledEntitlements: unsafe
    ) == .unsafeEntitlements(unsafe.sorted()))
}

@Test func signingInformationUsesOnlyEnabledRuntimeExceptions() {
    #expect(launcherRuntimeProtection(signingInformation: [
        kSecCodeInfoFlags: SecCodeSignatureFlags.runtime.rawValue,
        kSecCodeInfoEntitlementsDict: [
            "com.apple.security.cs.allow-dyld-environment-variables": false,
            "com.apple.security.cs.disable-library-validation": true,
        ],
    ]) == .hardenedWithLibraryValidationDisabled)
}

@Test func signingInformationPrefersLiveRuntimeStatus() {
    #expect(launcherRuntimeProtection(signingInformation: [
        kSecCodeInfoFlags: 0,
        kSecCodeInfoStatus: SecCodeSignatureFlags.runtime.rawValue,
    ]) == .hardened)
    #expect(launcherRuntimeProtection(signingInformation: [
        kSecCodeInfoFlags: SecCodeSignatureFlags.runtime.rawValue,
        kSecCodeInfoStatus: 0,
    ]) == .hardenedRuntimeMissing)
}

@Test func runtimeRequirementsRejectPostEnrollmentExpansion() {
    #expect(LauncherRuntimeRequirement.hardened.allows(.hardened))
    #expect(!LauncherRuntimeRequirement.hardened.allows(.hardenedWithLibraryValidationDisabled))

    let libraryLoading = LauncherRuntimeRequirement.hardenedAllowingLibraryValidationDisabled
    #expect(libraryLoading.allows(.hardened))
    #expect(libraryLoading.allows(.hardenedWithLibraryValidationDisabled))
    #expect(!libraryLoading.allows(.hardenedRuntimeMissing))
    #expect(!libraryLoading.allows(.unsafeEntitlements([
        "com.apple.security.cs.allow-dyld-environment-variables",
    ])))

    #expect(LauncherRuntimeRequirement.legacyUnchecked.allows(.hardenedRuntimeMissing))
}

@Test func targetRuntimeHistoryExplainsSecretExposure() {
    #expect(
        LauncherRuntimeProtection.hardened.targetAuthorizationHistoryDescription
            == "Hardened Runtime"
    )
    #expect(
        LauncherRuntimeProtection.hardenedRuntimeMissing.targetAuthorizationHistoryDescription
            .contains("Secret may be exposed to debugging or process-memory inspection")
    )
    #expect(
        LauncherRuntimeProtection.unsafeEntitlements([
            "com.apple.security.get-task-allow",
        ]).targetAuthorizationHistoryDescription.contains("debugging code")
    )
}
