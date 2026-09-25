import Foundation

public enum ReleaseNotes {
    private struct Release: Decodable {
        let tag_name: String
        let body: String?
    }

    public static func notes(from data: Data, version: String) throws -> String {
        let release = try JSONDecoder().decode(Release.self, from: data)
        guard release.tag_name == version else { throw URLError(.badServerResponse) }
        return (release.body ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    public static func load(version: String) async throws -> String {
        let url = URL(string: "https://api.github.com/repos/automic-vault/automic-vault/releases/tags/")!
            .appendingPathComponent(version)
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: url, timeoutInterval: 10)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        let (bytes, response) = try await session.bytes(for: request)
        guard let response = response as? HTTPURLResponse,
              response.statusCode == 200, response.url == url else {
            throw URLError(.badServerResponse)
        }
        var data = Data()
        for try await byte in bytes {
            guard data.count < 262_144 else { throw URLError(.dataLengthExceedsMaximum) }
            data.append(byte)
        }
        return try notes(from: data, version: version)
    }
}
