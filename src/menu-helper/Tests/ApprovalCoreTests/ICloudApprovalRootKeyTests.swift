import Foundation
import Security
import Testing
@testable import ApprovalCore

private enum RootKeyFixtureError: Error {
    case generationFailed
}

@Test func iCloudAccountAvailabilityRequiresAnIdentityToken() {
    #expect(!ICloudApprovalRootKey.hasActiveICloudAccount(identityToken: nil))
    #expect(ICloudApprovalRootKey.hasActiveICloudAccount(identityToken: Data([1])))
}

@Test func existingRootKeyIsReturnedWithoutMutation() throws {
    let existing = rootKey(1)
    var generated = false
    var added = false

    let result = try loadOrCreateApprovalRootKey(
        read: { .success(existing) },
        generate: {
            generated = true
            return rootKey(2)
        },
        add: { _ in
            added = true
            return errSecSuccess
        }
    )

    #expect(result == existing)
    #expect(!generated)
    #expect(!added)
}

@Test func missingRootKeyIsGeneratedAndStored() throws {
    let generated = rootKey(2)
    var added: Data?

    let result = try loadOrCreateApprovalRootKey(
        read: { .failure(.unavailable(errSecItemNotFound)) },
        generate: { generated },
        add: {
            added = $0
            return errSecSuccess
        }
    )

    #expect(result == generated)
    #expect(added == generated)
}

@Test func concurrentRootKeyCreationUsesTheStoredWinner() throws {
    let generated = rootKey(3)
    let winner = rootKey(4)
    var reads = 0

    let result = try loadOrCreateApprovalRootKey(
        read: {
            reads += 1
            return reads == 1
                ? .failure(.unavailable(errSecItemNotFound))
                : .success(winner)
        },
        generate: { generated },
        add: {
            #expect($0 == generated)
            return errSecDuplicateItem
        }
    )

    #expect(result == winner)
    #expect(reads == 2)
}

@Test(arguments: [errSecAuthFailed, errSecInteractionNotAllowed])
func rootKeyReadErrorsPropagate(_ status: OSStatus) {
    #expect(throws: ICloudApprovalRootKeyError.unavailable(status)) {
        try loadOrCreateApprovalRootKey(
            read: { .failure(.unavailable(status)) },
            generate: { rootKey(5) },
            add: { _ in errSecSuccess }
        )
    }
}

@Test func rootKeyGenerationErrorsPropagateBeforeStorage() {
    var added = false
    #expect(throws: RootKeyFixtureError.generationFailed) {
        try loadOrCreateApprovalRootKey(
            read: { .failure(.unavailable(errSecItemNotFound)) },
            generate: { throw RootKeyFixtureError.generationFailed },
            add: { _ in
                added = true
                return errSecSuccess
            }
        )
    }
    #expect(!added)
}

@Test func failedRootKeyStoragePropagates() {
    #expect(throws: ICloudApprovalRootKeyError.unavailable(errSecAuthFailed)) {
        try loadOrCreateApprovalRootKey(
            read: { .failure(.unavailable(errSecItemNotFound)) },
            generate: { rootKey(6) },
            add: { _ in errSecAuthFailed }
        )
    }
}

@Test func rotationUpdatesAndVerifiesTheStoredKey() throws {
    let replacement = rootKey(7)
    var updated: Data?

    let result = try rotateApprovalRootKey(
        read: { .success(replacement) },
        generate: { replacement },
        update: {
            updated = $0
            return errSecSuccess
        },
        add: { _ in
            Issue.record("rotation unexpectedly attempted an add")
            return errSecSuccess
        }
    )

    #expect(result == replacement)
    #expect(updated == replacement)
}

@Test func rotationCreatesAKeyWhenTheRecordDisappears() throws {
    let replacement = rootKey(8)
    var added: Data?

    let result = try rotateApprovalRootKey(
        read: { .success(replacement) },
        generate: { replacement },
        update: { _ in errSecItemNotFound },
        add: {
            added = $0
            return errSecSuccess
        }
    )

    #expect(result == replacement)
    #expect(added == replacement)
}

@Test(arguments: [errSecAuthFailed, errSecInteractionNotAllowed])
func rotationUpdateErrorsPropagate(_ status: OSStatus) {
    #expect(throws: ICloudApprovalRootKeyError.unavailable(status)) {
        try rotateApprovalRootKey(
            read: { .success(rootKey(9)) },
            generate: { rootKey(9) },
            update: { _ in status },
            add: { _ in errSecSuccess }
        )
    }
}

@Test func rotationAddErrorsPropagate() {
    #expect(throws: ICloudApprovalRootKeyError.unavailable(errSecAuthFailed)) {
        try rotateApprovalRootKey(
            read: { .success(rootKey(10)) },
            generate: { rootKey(10) },
            update: { _ in errSecItemNotFound },
            add: { _ in errSecAuthFailed }
        )
    }
}

@Test func rotationFailsClosedWhenReadbackDiffers() {
    #expect(throws: ICloudApprovalRootKeyError.invalidKey) {
        try rotateApprovalRootKey(
            read: { .success(rootKey(11)) },
            generate: { rootKey(12) },
            update: { _ in errSecSuccess },
            add: { _ in errSecSuccess }
        )
    }
}

private func rootKey(_ byte: UInt8) -> Data {
    Data(repeating: byte, count: ApprovalCrypto.rootKeyByteCount)
}
