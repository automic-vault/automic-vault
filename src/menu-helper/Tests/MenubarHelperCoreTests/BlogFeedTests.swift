import XCTest
@testable import MenubarHelperCore

final class BlogFeedTests: XCTestCase {
    func testHeadlinesAreBoundedUniqueAndOnlyLinkToOurBlog() throws {
        let data = Data(#"""
        {"items":[
          {"title":"External", "url":"https://example.com/blog/post/"},
          {"title":"Local", "url":"file:///blog/post/"},
          {"title":"Empty", "url":"https://www.automicvault.com/settings/"},
          {"title":"First", "url":"https://www.automicvault.com/blog/first/"},
          {"title":"Duplicate", "url":"https://www.automicvault.com/blog/first/"},
          {"title":"Second", "url":"https://www.automicvault.com/blog/second/"},
          {"title":"Third", "url":"https://www.automicvault.com/blog/third/"}
        ]}
        """#.utf8)
        XCTAssertEqual(try BlogFeed.posts(from: data).map(\.title), ["First", "Second"])
        XCTAssertThrowsError(try BlogFeed.posts(from: Data("not JSON".utf8)))
    }
}
