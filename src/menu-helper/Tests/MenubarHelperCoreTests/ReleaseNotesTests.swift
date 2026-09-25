import XCTest
@testable import MenubarHelperCore

final class ReleaseNotesTests: XCTestCase {
    func testNotesMustBelongToTheAvailableVersion() throws {
        let data = Data(#"{"tag_name":"2.8.0","body":"  ## Changes\n- A fix\n"}"#.utf8)
        XCTAssertEqual(try ReleaseNotes.notes(from: data, version: "2.8.0"), "## Changes\n- A fix")
        XCTAssertThrowsError(try ReleaseNotes.notes(from: data, version: "2.9.0"))
        XCTAssertThrowsError(try ReleaseNotes.notes(from: Data("invalid".utf8), version: "2.8.0"))
        XCTAssertEqual(try ReleaseNotes.notes(from: Data(#"{"tag_name":"2.8.0","body":null}"#.utf8), version: "2.8.0"), "")
    }
}
