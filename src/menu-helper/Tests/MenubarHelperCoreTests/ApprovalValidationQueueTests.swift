import Foundation
import Testing
@testable import MenubarHelperCore

@Test(arguments: [(2, 1), (8, 2), (12, 3), (16, 4), (32, 4)])
func validationBoundsBurstsAndDiscardsDisconnectedPeers(processors: Int, workers: Int) {
    let executor = DispatchQueue(label: "test.validation", attributes: .initiallyInactive)
    let queue = ApprovalValidationQueue(activeProcessorCount: processors, workers: executor)
    let waiting = UUID()
    for _ in 0..<workers {
        #expect(queue.submit(peer: UUID()) {})
    }
    for _ in 0..<8 {
        #expect(queue.submit(peer: waiting) { Issue.record("Disconnected request ran") })
    }
    for _ in 0..<200 {
        #expect(!queue.submit(peer: UUID()) { Issue.record("Excess request ran") })
    }
    queue.discardWaiting(for: waiting)
    let finished = DispatchSemaphore(value: 0)
    #expect(queue.submit(peer: UUID()) { finished.signal() })
    executor.activate()
    // Drain the workers, then the waiting request scheduled by their completion.
    executor.sync {}
    executor.sync {}
    #expect(finished.wait(timeout: .now()) == .success)
}

@Test func validationSerializesOnePeerWhileOthersCanProceed() {
    let executor = DispatchQueue(label: "test.validation", attributes: .initiallyInactive)
    let queue = ApprovalValidationQueue(activeProcessorCount: 8, workers: executor)
    let peer = UUID()
    let otherFinished = DispatchSemaphore(value: 0)
    let secondFinished = DispatchSemaphore(value: 0)
    #expect(queue.submit(peer: peer) {})
    let accepted = queue.submit(peer: peer) {
        #expect(otherFinished.wait(timeout: .now()) == .success)
        secondFinished.signal()
    }
    #expect(accepted)
    #expect(queue.submit(peer: UUID()) { otherFinished.signal() })
    executor.activate()
    executor.sync {}
    executor.sync {}
    #expect(secondFinished.wait(timeout: .now()) == .success)
}
