import Testing
@testable import MenubarHelperCore

@Test func approvalServiceRejectsGenericSecretLoad() {
    #expect(ApprovalServiceOperation(rawValue: "load") == nil)
}

@Test func conditionalSaveKeepsItsCompatibleWireValue() {
    #expect(ApprovalServiceOperation.saveIfAbsentOrEqual.rawValue == "save-if-absent")
}

@Test func varlockHasADedicatedWireOperation() {
    #expect(ApprovalServiceOperation.varlock.rawValue == "varlock")
}

@Test func terraformCredentialGetHasADedicatedWireOperation() {
    #expect(ApprovalServiceOperation.terraformGet.rawValue == "terraform-get")
}

@Test func aliyunCredentialGetHasADedicatedWireOperation() {
    #expect(ApprovalServiceOperation.aliyunHelperVersion.rawValue == "aliyun-helper-version")
    #expect(ApprovalServiceOperation.aliyunGet.rawValue == "aliyun-get")
}

@Test func oxideCredentialsHaveDedicatedWireOperations() {
    #expect(ApprovalServiceOperation.oxideGet.rawValue == "oxide-get")
    #expect(ApprovalServiceOperation.oxideSave.rawValue == "oxide-save")
    #expect(ApprovalServiceOperation.oxideDelete.rawValue == "oxide-delete")
}

@Test func goatCredentialsHaveDedicatedWireOperations() {
    #expect(ApprovalServiceOperation.goatGet.rawValue == "goat-get")
    #expect(ApprovalServiceOperation.wakatimeHelperVersion.rawValue == "wakatime-helper-version")
    #expect(ApprovalServiceOperation.wakatimeGet.rawValue == "wakatime-get")
    #expect(ApprovalServiceOperation.goatSave.rawValue == "goat-save")
    #expect(ApprovalServiceOperation.goatDelete.rawValue == "goat-delete")
}

@Test func railwayCredentialsHaveDedicatedWireOperations() {
    #expect(ApprovalServiceOperation.railwayGet.rawValue == "railway-get")
    #expect(ApprovalServiceOperation.railwaySave.rawValue == "railway-save")
    #expect(ApprovalServiceOperation.railwayDelete.rawValue == "railway-delete")
}

@Test func ordercliCredentialsHaveDedicatedWireOperations() {
    #expect(ApprovalServiceOperation.ordercliGet.rawValue == "ordercli-get")
    #expect(ApprovalServiceOperation.ordercliSave.rawValue == "ordercli-save")
    #expect(ApprovalServiceOperation.ordercliDelete.rawValue == "ordercli-delete")
}

@Test func openhueCredentialsHaveDedicatedWireOperations() {
    #expect(ApprovalServiceOperation.openhueGet.rawValue == "openhue-get")
    #expect(ApprovalServiceOperation.openhueSave.rawValue == "openhue-save")
}

@Test func plumberCredentialsHaveDedicatedWireOperations() {
    #expect(ApprovalServiceOperation.plumberGet.rawValue == "plumber-get")
    #expect(ApprovalServiceOperation.plumberSave.rawValue == "plumber-save")
}

@Test func uaaCredentialsHaveDedicatedWireOperations() {
    #expect(ApprovalServiceOperation.uaaGet.rawValue == "uaa-get")
    #expect(ApprovalServiceOperation.uaaSave.rawValue == "uaa-save")
    #expect(ApprovalServiceOperation.uaaDelete.rawValue == "uaa-delete")
}

@Test func approvalServiceOperationValuesAreUnique() {
    let values = ApprovalServiceOperation.allCases.map(\.rawValue)
    #expect(Set(values).count == values.count)
}
