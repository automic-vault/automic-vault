import Foundation
import Testing
@testable import MenubarHelperCore

@Test func immediateAcquisitionWhenSlotIsAvailable() async {
    let queue = HumanApprovalQueue()
    #expect(!queue.hasActiveSlot)
    #expect(queue.pendingCount == 0)

    let granted = await queue.acquire()
    #expect(granted)
    #expect(queue.hasActiveSlot)
    #expect(queue.pendingCount == 0)

    queue.release()
    #expect(!queue.hasActiveSlot)
    #expect(queue.pendingCount == 0)
}

@Test func queuesSubsequentRequestsInFIFOOrder() async {
    let queue = HumanApprovalQueue()
    let acquired1 = await queue.acquire()
    #expect(acquired1)
    #expect(queue.hasActiveSlot)

    let executionOrder = LockedState<[Int]>([])

    let task2 = Task {
        let acquired = await queue.acquire()
        #expect(acquired)
        executionOrder.withValue { $0.append(2) }
        queue.release()
    }

    // Ensure task2 has enqueued before starting task3 to eliminate unstructured scheduling races
    let task2Enqueued = await waitUntil { queue.pendingCount >= 1 }
    #expect(task2Enqueued)

    let task3 = Task {
        let acquired = await queue.acquire()
        #expect(acquired)
        executionOrder.withValue { $0.append(3) }
        queue.release()
    }

    // Wait for task3 to enqueue
    let task3Enqueued = await waitUntil { queue.pendingCount >= 2 }
    #expect(task3Enqueued)

    // Release task 1
    executionOrder.withValue { $0.append(1) }
    queue.release()

    _ = await task2.value
    _ = await task3.value

    #expect(executionOrder.get() == [1, 2, 3])
    #expect(!queue.hasActiveSlot)
}

@Test func cancelAllPendingResumesAllWaitersWithFalse() async {
    let queue = HumanApprovalQueue()
    let acquired1 = await queue.acquire()
    #expect(acquired1)

    let task2Acquired = LockedState<Bool?>(nil)
    let task3Acquired = LockedState<Bool?>(nil)

    let task2 = Task {
        let granted = await queue.acquire()
        task2Acquired.set(granted)
    }

    let task2Enqueued = await waitUntil { queue.pendingCount >= 1 }
    #expect(task2Enqueued)

    let task3 = Task {
        let granted = await queue.acquire()
        task3Acquired.set(granted)
    }

    let task3Enqueued = await waitUntil { queue.pendingCount >= 2 }
    #expect(task3Enqueued)

    queue.cancelAllPending()
    #expect(queue.pendingCount == 0)

    _ = await task2.value
    _ = await task3.value

    #expect(task2Acquired.get() == false)
    #expect(task3Acquired.get() == false)
    #expect(queue.hasActiveSlot)
    queue.release()
    #expect(!queue.hasActiveSlot)
}

@Test func queuedRequestCanBeCancelledBeforePresentation() async {
    let queue = HumanApprovalQueue()
    let acquired1 = await queue.acquire()
    #expect(acquired1)

    let id2 = UUID()
    let id3 = UUID()
    let task2Acquired = LockedState<Bool?>(nil)
    let task3Acquired = LockedState<Bool?>(nil)

    let task2 = Task {
        let acquired = await queue.acquire(id: id2)
        task2Acquired.set(acquired)
    }

    let task3 = Task {
        let acquired = await queue.acquire(id: id3)
        task3Acquired.set(acquired)
    }

    let bothEnqueued = await waitUntil { queue.pendingCount >= 2 }
    #expect(bothEnqueued)

    // Cancel task 2 while it is waiting in queue
    queue.cancel(id: id2)

    _ = await task2.value
    #expect(task2Acquired.get() == false)
    #expect(queue.pendingCount == 1)

    // Release task 1 -> task 3 should be promoted immediately
    queue.release()

    _ = await task3.value
    #expect(task3Acquired.get() == true)

    queue.release()
    #expect(!queue.hasActiveSlot)
}

@Test func preCancelledRequestFailsImmediately() async {
    let queue = HumanApprovalQueue()
    let granted = await queue.acquire(isCanceled: { true })
    #expect(!granted)
    #expect(!queue.hasActiveSlot)
    #expect(queue.pendingCount == 0)
}

@Test func stressConcurrencyEnsuresMutualExclusion() async {
    let queue = HumanApprovalQueue()
    let concurrentHolders = LockedState<Int>(0)
    let maxConcurrentHolders = LockedState<Int>(0)
    let completedCount = LockedState<Int>(0)
    let taskCount = 30

    await withTaskGroup(of: Void.self) { group in
        for _ in 0..<taskCount {
            group.addTask {
                let granted = await queue.acquire()
                #expect(granted)

                let current = concurrentHolders.withValue { count -> Int in
                    count += 1
                    return count
                }
                maxConcurrentHolders.withValue { maxCount in
                    if current > maxCount { maxCount = current }
                }

                // Small yield to allow race conditions to emerge if mutual exclusion is broken
                try? await Task.sleep(nanoseconds: 100_000)

                concurrentHolders.withValue { $0 -= 1 }
                completedCount.withValue { $0 += 1 }
                queue.release()
            }
        }
    }

    #expect(completedCount.get() == taskCount)
    #expect(maxConcurrentHolders.get() == 1)
    #expect(!queue.hasActiveSlot)
    #expect(queue.pendingCount == 0)
}

@Test func stressInterleavedCancellationAndRelease() async {
    let queue = HumanApprovalQueue()
    let acquired1 = await queue.acquire()
    #expect(acquired1)

    let totalWaiters = 20
    var ids: [UUID] = []
    let results = LockedState<[UUID: Bool]>([:])

    var tasks: [Task<Void, Never>] = []
    for _ in 0..<totalWaiters {
        let id = UUID()
        ids.append(id)
        tasks.append(Task {
            let granted = await queue.acquire(id: id)
            results.withValue { $0[id] = granted }
            if granted {
                queue.release()
            }
        })
    }

    let allEnqueued = await waitUntil { queue.pendingCount == totalWaiters }
    #expect(allEnqueued)

    // Concurrently cancel half the waiters while releasing the active slot
    let cancelledIDs = Set(ids.prefix(totalWaiters / 2))
    for id in cancelledIDs {
        queue.cancel(id: id)
    }
    queue.release()

    for task in tasks {
        _ = await task.value
    }

    let finalResults = results.get()
    #expect(finalResults.count == totalWaiters)
    for id in ids {
        if cancelledIDs.contains(id) {
            #expect(finalResults[id] == false)
        } else {
            #expect(finalResults[id] == true)
        }
    }
    #expect(!queue.hasActiveSlot)
    #expect(queue.pendingCount == 0)
}

@Test func idempotentAndUnknownCancellationIsSafe() async {
    let queue = HumanApprovalQueue()
    // Cancelling an unknown UUID does not crash or corrupt queue
    queue.cancel(id: UUID())

    let id = UUID()
    let taskResult = LockedState<Bool?>(nil)
    let acquired = await queue.acquire()
    #expect(acquired)

    let task = Task {
        let granted = await queue.acquire(id: id)
        taskResult.set(granted)
    }

    let enqueued = await waitUntil { queue.pendingCount == 1 }
    #expect(enqueued)

    // Multiple cancellations of the same ID
    queue.cancel(id: id)
    queue.cancel(id: id)

    _ = await task.value
    #expect(taskResult.get() == false)
    #expect(queue.pendingCount == 0)

    queue.release()
    #expect(!queue.hasActiveSlot)
}

private final class LockedState<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: T

    init(_ initial: T) {
        self.value = initial
    }

    func withValue<R>(_ body: (inout T) -> R) -> R {
        lock.withLock { body(&value) }
    }

    func get() -> T {
        lock.withLock { value }
    }

    func set(_ newValue: T) {
        lock.withLock { value = newValue }
    }
}

private func waitUntil(
    timeout: Duration = .seconds(3),
    condition: @Sendable () -> Bool
) async -> Bool {
    let start = ContinuousClock.now
    while !condition() {
        if ContinuousClock.now - start > timeout {
            return false
        }
        try? await Task.sleep(nanoseconds: 1_000_000)
    }
    return true
}
