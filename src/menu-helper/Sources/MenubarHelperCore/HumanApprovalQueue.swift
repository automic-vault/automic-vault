import Foundation

/// Manages a FIFO queue for human approval prompts so that only a single
/// prompt occupies the active presentation slot at any given time without blocking
/// the main event loop or delaying unrelated secret access.
public final class HumanApprovalQueue: @unchecked Sendable {
    public static let shared = HumanApprovalQueue()

    private let lock = NSLock()
    private var isSlotActive = false
    private var waiters: [UUID: (Bool) -> Void] = [:]
    private var waiterOrder: [UUID] = []

    public init() {}

    public var pendingCount: Int {
        lock.withLock { waiterOrder.count }
    }

    public var hasActiveSlot: Bool {
        lock.withLock { isSlotActive }
    }

    /// Requests access to the single active human approval slot.
    /// - Parameters:
    ///   - id: A unique identifier for this request.
    ///   - isCanceled: An optional closure returning true if already cancelled.
    ///   - registerCancellation: An optional closure to register a cancellation observer.
    /// - Returns: `true` if access to the slot was granted, or `false` if cancelled.
    public func acquire(
        id: UUID = UUID(),
        isCanceled: (@Sendable () -> Bool)? = nil,
        registerCancellation: (@Sendable (@escaping @Sendable () -> Void) -> Void)? = nil
    ) async -> Bool {
        if isCanceled?() == true { return false }

        let shouldWait: Bool = lock.withLock {
            if !isSlotActive {
                isSlotActive = true
                return false
            } else {
                return true
            }
        }

        if !shouldWait {
            return true
        }

        return await withCheckedContinuation { continuation in
            var resumed = false
            let resumeWith: (Bool) -> Void = { granted in
                guard !resumed else { return }
                resumed = true
                continuation.resume(returning: granted)
            }

            let wasAlreadyCanceled: Bool = lock.withLock {
                if isCanceled?() == true {
                    return true
                }
                waiters[id] = resumeWith
                waiterOrder.append(id)
                return false
            }

            if wasAlreadyCanceled {
                resumeWith(false)
                return
            }

            registerCancellation? { [weak self] in
                self?.cancel(id: id)
            }
        }
    }

    /// Cancels a pending request in the queue. If it was waiting, resumes it with `false`.
    public func cancel(id: UUID) {
        let resume: ((Bool) -> Void)? = lock.withLock {
            guard let index = waiterOrder.firstIndex(of: id) else { return nil }
            waiterOrder.remove(at: index)
            return waiters.removeValue(forKey: id)
        }
        resume?(false)
    }

    /// Releases the active approval slot and promotes the next queued waiter, if any.
    public func release() {
        var nextResume: ((Bool) -> Void)?
        lock.withLock {
            while !waiterOrder.isEmpty {
                let nextID = waiterOrder.removeFirst()
                if let resume = waiters.removeValue(forKey: nextID) {
                    nextResume = resume
                    // Slot remains active for the promoted waiter
                    return
                }
            }
            isSlotActive = false
        }
        nextResume?(true)
    }

    /// Cancels all pending waiters in the queue, resuming them with `false`.
    public func cancelAllPending() {
        let pendingResumes: [(Bool) -> Void] = lock.withLock {
            let list = Array(waiters.values)
            waiters.removeAll()
            waiterOrder.removeAll()
            return list
        }
        for resume in pendingResumes {
            resume(false)
        }
    }

    /// Resets queue state (for test isolation).
    public func resetForTesting() {
        lock.withLock {
            isSlotActive = false
            for resume in waiters.values {
                resume(false)
            }
            waiters.removeAll()
            waiterOrder.removeAll()
        }
    }
}
