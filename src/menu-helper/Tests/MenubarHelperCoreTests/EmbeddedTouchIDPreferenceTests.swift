import Foundation
import Testing
@testable import MenubarHelperCore

@Test func embeddedTouchIDPreferenceDefaultsAndFailures() {
    #expect(embeddedTouchIDApprovalIsEnabled(.notFound))
    #expect(embeddedTouchIDApprovalIsEnabled(.success(Data([1]))))
    #expect(!embeddedTouchIDApprovalIsEnabled(.success(Data([0]))))
    #expect(!embeddedTouchIDApprovalIsEnabled(.success(Data())))
    #expect(!embeddedTouchIDApprovalIsEnabled(.success(Data([1, 0]))))
    #expect(!embeddedTouchIDApprovalIsEnabled(.failure(-25308)))
}
