@testable import ApprovalCore
import Foundation
import Testing

private enum PongError: Error { case failed }

@Test
func pingRequiresAConnection() async throws {
    let relay = try ApprovalRelayClient(
        endpoint: URL(string: "https://example.com")!,
        rootKeyData: Data(repeating: 7, count: ApprovalCrypto.rootKeyByteCount)
    )
    await #expect(throws: ApprovalRelayClientError.disconnected) {
        try await relay.ping()
    }
}

@Test
func pongWaitSucceeds() async throws {
    try await ApprovalRelayClient.waitForPong { completion in completion(nil) }
}

@Test
func pongWaitPropagatesFailure() async {
    await #expect(throws: PongError.failed) {
        try await ApprovalRelayClient.waitForPong { completion in completion(PongError.failed) }
    }
}

@Test(.timeLimit(.minutes(1)))
func canceledPongWaitDoesNotHang() async {
    let pingStarted = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
    let wait = Task {
        try await ApprovalRelayClient.waitForPong { _ in
            pingStarted.continuation.yield()
        }
    }
    for await _ in pingStarted.stream.prefix(1) { break }

    wait.cancel()
    await #expect(throws: CancellationError.self) {
        try await wait.value
    }
}
