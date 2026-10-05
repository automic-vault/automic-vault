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

@Test @MainActor func approvalMonitorCancellationDuringValidationStopsFurtherChecks() async throws {
    let entered = DispatchSemaphore(value: 0)
    let finishValidation = DispatchSemaphore(value: 0)
    let monitor = Task {
        do {
            try await monitorAuthorizationValidity(interval: .zero) {
                // Avoid deadlocking the test if the main-thread regression returns.
                guard !Thread.isMainThread else {
                    Issue.record("Validation blocked the main thread")
                    throw CancellationError()
                }
                entered.signal()
                #expect(finishValidation.wait(timeout: .now() + 5) == .success)
            }
            Issue.record("Monitor returned without failure or cancellation")
        } catch {
            #expect(error is CancellationError)
        }
    }
    // A blocked synchronous check must not depend on the cooperative executor
    // scheduling another test continuation to release it.
    DispatchQueue(label: "test.authorization-cancellation").async {
        #expect(entered.wait(timeout: .now() + 60) == .success)
        monitor.cancel()
        finishValidation.signal()
    }
    await monitor.value
    await performAuthorizationWork {
        #expect(entered.wait(timeout: .now()) == .timedOut, "A canceled monitor must not start another validation")
    }
}

@Test @MainActor func approvalWorkerPreservesRecordBeforeReleaseAndRechecksRevocation() async throws {
    let recording = DispatchSemaphore(value: 0)
    let finishRecording = DispatchSemaphore(value: 0)
    let revoked = DispatchSemaphore(value: 0)
    let worker = Task {
        await performAuthorizationWork {
            guard !Thread.isMainThread else {
                Issue.record("Recording blocked the main thread")
                return
            }
            enum Revoked: Error { case peer }
            var released = false
            let transaction = AuthorizationFulfillmentTransaction(material: "fixture")
            #expect(throws: Revoked.peer) {
                try transaction.commit(
                    record: {
                        recording.signal()
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
        }
    }
    DispatchQueue(label: "test.authorization-revocation").async {
        #expect(recording.wait(timeout: .now() + 60) == .success)
        revoked.signal()
        finishRecording.signal()
    }
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
