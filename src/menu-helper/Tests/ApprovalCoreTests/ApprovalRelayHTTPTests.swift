@testable import ApprovalCore
import Foundation
import Testing

@Suite(.serialized)
struct ApprovalRelayHTTPTests {
    private let endpoint = URL(string: "https://relay.example/base")!
    private let rootKey = Data(repeating: 7, count: ApprovalCrypto.rootKeyByteCount)

    @Test func registrationBindsMethodPathAuthorizationAndBody() async throws {
        let recorder = RequestRecorder()
        let client = try makeClient(recorder: recorder, status: 204)

        try await client.register(
            deviceID: "phone-1",
            token: Data([0, 1, 0xfe, 0xff]),
            environment: .production
        )

        let request = try #require(recorder.request)
        let address = try ApprovalCrypto(rootKeyData: rootKey).address
        #expect(request.httpMethod == "PUT")
        #expect(request.url?.path == "/base/v1/register/\(address.room)/phone-1")
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer \(address.credential)")
        #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/json")
        let registration = try JSONDecoder().decode(
            ApprovalDeviceRegistration.self,
            from: try #require(recorder.body)
        )
        #expect(registration.token == "0001feff")
        #expect(registration.environment == .production)
        let expectedProof = try ApprovalCrypto(rootKeyData: rootKey).registrationProof(deviceID: "phone-1")
        #expect(registration.proof == expectedProof)
    }

    @Test func registrationStatusValidatesAndDecodesTheResponse() async throws {
        let recorder = RequestRecorder()
        let response = ApprovalRegistrationStatus(count: 2, mostRecentMilliseconds: 42)
        let client = try makeClient(
            recorder: recorder,
            status: 200,
            body: JSONEncoder().encode(response)
        )

        #expect(try await client.registrationStatus() == response)
        let request = try #require(recorder.request)
        let address = try ApprovalCrypto(rootKeyData: rootKey).address
        #expect(request.httpMethod == "GET")
        #expect(request.url?.path == "/base/v1/registrations/\(address.room)")
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer \(address.credential)")
    }

    @Test func roomRevocationUsesAnAuthorizedDelete() async throws {
        let recorder = RequestRecorder()
        let client = try makeClient(recorder: recorder, status: 204)

        try await client.revokeRoom()

        let request = try #require(recorder.request)
        let address = try ApprovalCrypto(rootKeyData: rootKey).address
        #expect(request.httpMethod == "DELETE")
        #expect(request.url?.path == "/base/v1/room/\(address.room)")
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer \(address.credential)")
    }

    @Test(arguments: [200, 201, 401, 500])
    func unexpectedRegistrationStatusesFailClosed(_ status: Int) async throws {
        let client = try makeClient(recorder: RequestRecorder(), status: status)
        await #expect(throws: ApprovalRelayClientError.invalidResponse(status)) {
            try await client.register(deviceID: "phone", token: Data([1]), environment: .sandbox)
        }
    }

    private func makeClient(
        recorder: RequestRecorder,
        status: Int,
        body: Data = Data()
    ) throws -> ApprovalRelayClient {
        RelayURLProtocol.handler = { request in
            recorder.record(request)
            return (
                HTTPURLResponse(
                    url: try #require(request.url),
                    statusCode: status,
                    httpVersion: "HTTP/1.1",
                    headerFields: nil
                )!,
                body
            )
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RelayURLProtocol.self]
        return try ApprovalRelayClient(
            endpoint: endpoint,
            rootKeyData: rootKey,
            session: URLSession(configuration: configuration)
        )
    }
}

private final class RequestRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: URLRequest?
    private var recordedBody: Data?

    var request: URLRequest? {
        lock.withLock { recorded }
    }

    var body: Data? {
        lock.withLock { recordedBody }
    }

    func record(_ request: URLRequest) {
        let body = request.httpBody ?? request.httpBodyStream.flatMap(readAll)
        lock.withLock {
            recorded = request
            recordedBody = body
        }
    }

    private func readAll(_ stream: InputStream) -> Data? {
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4_096)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            guard count >= 0 else { return nil }
            if count == 0 { break }
            data.append(buffer, count: count)
        }
        return data
    }
}

private final class RelayURLProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var handler: (@Sendable (URLRequest) throws -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        do {
            let (response, data) = try Self.handler?(request)
                ?? { throw ApprovalRelayClientError.unexpectedMessage }()
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            if !data.isEmpty { client?.urlProtocol(self, didLoad: data) }
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
