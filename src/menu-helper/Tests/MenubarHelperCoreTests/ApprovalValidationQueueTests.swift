import Foundation
import Testing
@testable import MenubarHelperCore

@Test(arguments: [(2, 1), (8, 2), (12, 3), (16, 4), (32, 4)])
func validationBoundsBurstsAndDiscardsDisconnectedPeers(processors: Int, workers: Int) throws {
    let queue = ApprovalValidationQueue(activeProcessorCount: processors)
    let started = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    defer {
        for _ in 0..<workers { release.signal() }
    }
    let waiting = UUID()
    for _ in 0..<workers {
        try #require(queue.submit(peer: UUID()) {
            started.signal()
            _ = release.wait(timeout: .now() + 10)
        })
        try #require(started.wait(timeout: .now() + 2) == .success)
    }
    for _ in 0..<8 {
        try #require(queue.submit(peer: waiting) { Issue.record("Disconnected request ran") })
    }
    for _ in 0..<200 {
        #expect(!queue.submit(peer: UUID()) { Issue.record("Excess request ran") })
    }
    queue.discardWaiting(for: waiting)
    let finished = DispatchSemaphore(value: 0)
    try #require(queue.submit(peer: UUID()) { finished.signal() })
    release.signal()
    #expect(finished.wait(timeout: .now() + 2) == .success)
}

@Test func validationSerializesOnePeerWhileOthersCanProceed() throws {
    let queue = ApprovalValidationQueue(activeProcessorCount: 8)
    let peer = UUID()
    let release = DispatchSemaphore(value: 0)
    defer { release.signal() }
    let firstFinished = DispatchSemaphore(value: 0)
    let secondFinished = DispatchSemaphore(value: 0)
    let otherFinished = DispatchSemaphore(value: 0)
    try #require(queue.submit(peer: peer) {
        _ = release.wait(timeout: .now() + 10)
        firstFinished.signal()
    })
    try #require(queue.submit(peer: peer) {
        #expect(firstFinished.wait(timeout: .now()) == .success)
        secondFinished.signal()
    })
    try #require(queue.submit(peer: UUID()) { otherFinished.signal() })
    try #require(otherFinished.wait(timeout: .now() + 2) == .success)
    #expect(secondFinished.wait(timeout: .now()) == .timedOut)
    release.signal()
    #expect(secondFinished.wait(timeout: .now() + 2) == .success)
}
