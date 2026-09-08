import Testing
@testable import MenubarHelperCore

@Test func fdMappingsBindEverySecretToOneDistinctDescriptor() {
    let detail = fileDescriptorInjectionDetail(keys: ["BAR", "FOO"], mappings: ["FOO:3", "BAR:4"])
    #expect(detail?.contains("BAR → FD 4, FOO → FD 3") == true)
    #expect(detail == fileDescriptorInjectionDetail(keys: ["FOO", "BAR"], mappings: ["BAR:4", "FOO:3"]))
    #expect(detail != fileDescriptorInjectionDetail(keys: ["FOO", "BAR"], mappings: ["BAR:3", "FOO:4"]))
    for mappings in [
        ["FOO:3"], ["FOO:3", "FOO:4"], ["FOO:3", "BAR:3"], ["FOO:3", "OTHER:4"],
        ["FOO:0", "BAR:4"], ["FOO:1", "BAR:4"], ["FOO:2", "BAR:4"],
        ["FOO:03", "BAR:4"], ["FOO:+3", "BAR:4"], ["FOO:2147483647", "BAR:4"],
        ["FOO:3:4", "BAR:4"], ["FOO:3", "BAR: 4"],
    ] {
        #expect(fileDescriptorInjectionDetail(keys: ["FOO", "BAR"], mappings: mappings) == nil)
    }
    #expect(fileDescriptorInjectionDetail(keys: [], mappings: []) == nil)
    #expect(fileDescriptorInjectionDetail(keys: ["FOO", "FOO"], mappings: ["FOO:3", "FOO:4"]) == nil)
    #expect(fileDescriptorInjectionDetail(keys: ["BAD\nNAME"], mappings: ["BAD\nNAME:3"]) == nil)
}
