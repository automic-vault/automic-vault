import Foundation
import Testing
@testable import MenubarHelperCore

@Test func markdownDroppingInitialHeadingMarkerStripsLeadingHeading() {
    #expect(markdownDroppingInitialHeadingMarker("# Title\nBody text") == "Body text")
}

@Test func markdownDroppingInitialHeadingMarkerLeavesOtherMarkdownAlone() {
    #expect(markdownDroppingInitialHeadingMarker("Body text") == "Body text")
}

@Test func extractsTrailingLinkOnlyParagraph() {
    let markdown = """
    First paragraph.

    Second paragraph explains things.

    [Open an issue to discuss a safer integration](https://github.com/automic-vault/automic-vault/issues).
    """

    let result = markdownExtractingTrailingLinkParagraph(markdown)

    #expect(result.text == "First paragraph.\n\nSecond paragraph explains things.")
    #expect(result.trailingLink?.title == "Open an issue to discuss a safer integration")
    #expect(result.trailingLink?.url == URL(string: "https://github.com/automic-vault/automic-vault/issues"))
    #expect(result.trailingLink?.trailingText == ".")
}

@Test func extractsTrailingLinkWhenItIsTheOnlyParagraph() {
    let markdown = "[Open an issue](https://example.com/issues)"

    let result = markdownExtractingTrailingLinkParagraph(markdown)

    #expect(result.text == "")
    #expect(result.trailingLink?.title == "Open an issue")
    #expect(result.trailingLink?.url == URL(string: "https://example.com/issues"))
    #expect(result.trailingLink?.trailingText == "")
}

@Test func leavesMarkdownAloneWhenLastParagraphIsNotJustALink() {
    let markdown = """
    Intro.

    See [the issue tracker](https://example.com/issues) for details.
    """

    let result = markdownExtractingTrailingLinkParagraph(markdown)

    #expect(result.text == markdown)
    #expect(result.trailingLink == nil)
}

@Test func leavesPlainMarkdownAlone() {
    let markdown = "Just some prose with no links at all."

    let result = markdownExtractingTrailingLinkParagraph(markdown)

    #expect(result.text == markdown)
    #expect(result.trailingLink == nil)
}
