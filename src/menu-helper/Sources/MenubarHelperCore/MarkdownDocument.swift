import Foundation

public func markdownDroppingInitialHeadingMarker(_ markdown: String) -> String {
    guard markdown.hasPrefix("# ") else { return markdown }
    return markdown.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)
        .dropFirst()
        .first
        .map(String.init) ?? ""
}

public struct MarkdownTrailingLink: Equatable, Sendable {
    public let title: String
    public let url: URL
    /// Any punctuation immediately following the link's closing `)`, e.g. a trailing period.
    public let trailingText: String
}

public struct MarkdownBody: Equatable, Sendable {
    public let text: String
    public let trailingLink: MarkdownTrailingLink?
}

private let trailingLinkParagraphRegex = try! NSRegularExpression(
    pattern: #"^\[([^\]]+)\]\(([^\s)]+)\)([\p{P}]{0,2})$"#
)

/// Splits a standalone `[title](url).`-only paragraph off the end of `markdown`, if present.
///
/// A link rendered by MarkdownUI's `Text`-based inline renderer loses its pointing-hand cursor
/// when the containing view has `.textSelection(.enabled)` applied (an AppKit/SwiftUI limitation).
/// Every detector doc ends its "not yet hardened" explanation with exactly this kind of paragraph,
/// so pulling it out lets the caller render it as a plain, non-selectable `Link`/`Text(.link)`
/// that keeps the correct hover cursor.
public func markdownExtractingTrailingLinkParagraph(_ markdown: String) -> MarkdownBody {
    let trimmed = markdown.trimmingCharacters(in: .whitespacesAndNewlines)

    let bodyEndIndex: String.Index
    let lastParagraph: String
    if let separatorRange = trimmed.range(of: "\n\n", options: .backwards) {
        bodyEndIndex = separatorRange.lowerBound
        lastParagraph = trimmed[separatorRange.upperBound...]
            .trimmingCharacters(in: .whitespacesAndNewlines)
    } else {
        bodyEndIndex = trimmed.startIndex
        lastParagraph = trimmed
    }

    guard let trailingLink = trailingLink(matching: lastParagraph) else {
        return MarkdownBody(text: markdown, trailingLink: nil)
    }

    return MarkdownBody(text: String(trimmed[trimmed.startIndex..<bodyEndIndex]), trailingLink: trailingLink)
}

private func trailingLink(matching paragraph: String) -> MarkdownTrailingLink? {
    let fullRange = NSRange(paragraph.startIndex..., in: paragraph)
    guard
        let match = trailingLinkParagraphRegex.firstMatch(in: paragraph, range: fullRange),
        let titleRange = Range(match.range(at: 1), in: paragraph),
        let urlRange = Range(match.range(at: 2), in: paragraph),
        let url = URL(string: String(paragraph[urlRange]))
    else { return nil }

    let trailingText = Range(match.range(at: 3), in: paragraph).map { String(paragraph[$0]) } ?? ""
    return MarkdownTrailingLink(title: String(paragraph[titleRange]), url: url, trailingText: trailingText)
}
