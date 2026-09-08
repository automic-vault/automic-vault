import MarkdownUI
import MenubarHelperCore
import SwiftUI

struct RenderedMarkdown: View {
    let markdown: String

    private var parsedContent: MarkdownBody {
        markdownExtractingTrailingLinkParagraph(markdownDroppingInitialHeadingMarker(markdown))
    }

    var body: some View {
        let parsed = parsedContent

        VStack(alignment: .leading, spacing: 8) {
            if !parsed.text.isEmpty {
                Markdown(parsed.text)
                    .markdownTheme(.basic.listItem { configuration in
                        configuration.label.markdownMargin(top: .em(0.15))
                    })
                    .textSelection(.enabled)
            }

            if let trailingLink = parsed.trailingLink {
                // .textSelection(.disabled) is explicit, not just "we didn't wrap this one": a
                // selectable ancestor would otherwise flow its environment value down here too,
                // and SwiftUI/AppKit stops showing the pointing-hand cursor over links once their
                // container is selectable.
                trailingLinkText(trailingLink)
                    .textSelection(.disabled)
            }
        }
    }

    private func trailingLinkText(_ link: MarkdownTrailingLink) -> Text {
        var title = AttributedString(link.title)
        title.link = link.url
        return Text(title) + Text(link.trailingText)
    }
}
