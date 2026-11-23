import Foundation

/// Bounds synchronous request processing across XPC peers and preserves each peer's message order.
package final class ApprovalValidationQueue: @unchecked Sendable {
    private struct Request {
        let peer: UUID
        let run: @Sendable () -> Void
    }

    private let workers = DispatchQueue(label: "com.automicvault.validation", qos: .utility, attributes: .concurrent)
    private let workerLimit: Int
    private let lock = NSLock()
    private var active = Set<UUID>()
    private var waiting: [Request] = []

    package init(activeProcessorCount: Int = ProcessInfo.processInfo.activeProcessorCount) {
        workerLimit = min(4, max(1, activeProcessorCount / 4))
    }

    package func submit(peer: UUID, run: @escaping @Sendable () -> Void) -> Bool {
        lock.withLock {
            let request = Request(peer: peer, run: run)
            if active.count < workerLimit && !active.contains(peer) {
                start(request)
            } else {
                guard waiting.count < 8 else { return false }
                waiting.append(request)
            }
            return true
        }
    }

    package func discardWaiting(for peer: UUID) {
        lock.withLock { waiting.removeAll { $0.peer == peer } }
    }

    // Called with the lock held. Human approval presentation runs outside this queue.
    private func start(_ request: Request) {
        active.insert(request.peer)
        workers.async {
            request.run()
            self.lock.withLock {
                self.active.remove(request.peer)
                if let index = self.waiting.firstIndex(where: { !self.active.contains($0.peer) }) {
                    self.start(self.waiting.remove(at: index))
                }
            }
        }
    }
}
