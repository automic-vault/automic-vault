import Foundation
import Testing
@testable import MenubarHelperCore

@Test @MainActor func approvalFulfillmentDoesNotRunOnTheMainThread() async {
    await performAuthorizationWork {
        let transaction = AuthorizationFulfillmentTransaction(material: "fixture")
        let committed = transaction.commit(
            record: {
                #expect(!Thread.isMainThread, "History persistence and pruning must not block approval UI")
                return true
            },
            activate: { _ in }, observe: { _ in },
            release: { _ in
                #expect(!Thread.isMainThread, "Final peer validation must not block approval UI")
            }
        )
        #expect(committed)
    }
}

@Test @MainActor func approvalMonitorValidatesOffMainAndStopsOnFailure() async {
    enum InvalidPeer: Error { case changed }
    await #expect(throws: InvalidPeer.changed) {
        try await monitorAuthorizationValidity(interval: .zero) {
            #expect(!Thread.isMainThread, "Pending SSH checks must not block approval UI")
            throw InvalidPeer.changed
        }
    }
}

@Test func approvalMonitorCancellationDuringValidationStopsFurtherChecks() async throws {
    let entered = AsyncStream<Void>.makeStream()
    let finishValidation = DispatchSemaphore(value: 0)
    let monitor = Task {
        do {
            try await monitorAuthorizationValidity(interval: .zero) {
                // Avoid deadlocking the test if the main-thread regression returns.
                guard !Thread.isMainThread else {
                    Issue.record("Validation blocked the main thread")
                    throw CancellationError()
                }
                entered.continuation.yield(())
                #expect(finishValidation.wait(timeout: .now() + 5) == .success)
            }
            Issue.record("Monitor returned without failure or cancellation")
        } catch {
            #expect(error is CancellationError)
        }
        entered.continuation.finish()
    }
    var iterator = entered.stream.makeAsyncIterator()
    _ = try #require(await iterator.next())
    // Coordinate away from the main actor so unrelated UI tests cannot delay cancellation.
    monitor.cancel()
    finishValidation.signal()
    await monitor.value
    #expect(await iterator.next() == nil, "A canceled monitor must not start another validation")
}

@Test func approvalWorkerPreservesRecordBeforeReleaseAndRechecksRevocation() async throws {
    let recording = AsyncStream<Void>.makeStream()
    let finishRecording = DispatchSemaphore(value: 0)
    let revoked = DispatchSemaphore(value: 0)
    let worker = Task {
        await performAuthorizationWork {
            guard !Thread.isMainThread else {
                Issue.record("Recording blocked the main thread")
                recording.continuation.finish()
                return
            }
            enum Revoked: Error { case peer }
            var released = false
            let transaction = AuthorizationFulfillmentTransaction(material: "fixture")
            #expect(throws: Revoked.peer) {
                try transaction.commit(
                    record: {
                        recording.continuation.yield(())
                        #expect(finishRecording.wait(timeout: .now() + 5) == .success)
                        return true
                    },
                    activate: { _ in }, observe: { _ in },
                    release: { _ in
                        // The production transaction revalidates after recording, before delivery.
                        if revoked.wait(timeout: .now()) == .success { throw Revoked.peer }
                        released = true
                    }
                )
            }
            #expect(!released)
            recording.continuation.finish()
        }
    }
    var iterator = recording.stream.makeAsyncIterator()
    _ = try #require(await iterator.next())
    // Revoke while history is persisting, independently of unrelated main-actor work.
    revoked.signal()
    finishRecording.signal()
    await worker.value
}

@Test @MainActor func approvalWorkerDoesNotReleaseWhenHistoryFails() async {
    await performAuthorizationWork {
        let transaction = AuthorizationFulfillmentTransaction(material: "fixture")
        let committed = transaction.commit(
            record: { false },
            activate: { _ in Issue.record("Activated without a record") },
            observe: { _ in Issue.record("Observed without a record") },
            release: { _ in Issue.record("Released without a record") }
        )
        #expect(!committed)
    }
}
