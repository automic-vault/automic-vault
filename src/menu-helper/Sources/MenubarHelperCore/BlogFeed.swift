import Foundation

public struct BlogPost: Decodable, Identifiable, Sendable {
    public let title: String
    public let url: URL
    public var id: URL { url }
}

public enum BlogFeed {
    private struct Feed: Decodable { let items: [BlogPost] }
    public static let url = URL(string: "https://www.automicvault.com/blog/index.json")!

    public static func posts(from data: Data) throws -> [BlogPost] {
        var seen = Set<URL>()
        return try JSONDecoder().decode(Feed.self, from: data).items.filter {
            !$0.title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                && $0.title.count <= 240
                && $0.url.scheme == "https"
                && $0.url.host == url.host
                && $0.url.port == nil && $0.url.user == nil && $0.url.password == nil
                && $0.url.path.hasPrefix("/blog/")
                && seen.insert($0.url).inserted
        }.prefix(2).map { $0 }
    }

    public static func load() async throws -> [BlogPost] {
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let request = URLRequest(url: url, timeoutInterval: 10)
        let (bytes, response) = try await session.bytes(for: request)
        guard let response = response as? HTTPURLResponse,
              response.statusCode == 200, response.url == url else {
            throw URLError(.badServerResponse)
        }
        var data = Data()
        for try await byte in bytes {
            guard data.count < 65_536 else { throw URLError(.dataLengthExceedsMaximum) }
            data.append(byte)
        }
        return try posts(from: data)
    }
}
