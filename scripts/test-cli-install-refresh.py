#!/usr/bin/env python3
"""Exercise the real history loader; scoped refresh races live in the native self-check."""
from pathlib import Path
import subprocess
import sys
import tempfile

source = (Path(__file__).resolve().parents[1] /
          "src/menu-helper/Sources/MenubarHelper/MainWindow.swift").read_text()
model_source = source.split("final class DashboardModel:", 1)[1]
show_method = "    func showAccessRequest(" + model_source.split(
    "    func showAccessRequest(", 1
)[1].split("    func showSecretGate(", 1)[0]
pending_status = "    var pendingAccessRequestStatus:" + model_source.split(
    "    var pendingAccessRequestStatus:", 1
)[1].split("    var selectedProxySession:", 1)[0]
history_method = "    func reloadAccessRequests(" + model_source.split(
    "    func reloadAccessRequests(", 1
)[1].split("    private func invalidateAuthorizationReload()", 1)[0]

fixture = r"""
import Foundation
import Synchronization

let dashboardDidReload = Notification.Name("AutomicVaultDashboardDidReload")

let (historyStarted, historySignal) = AsyncStream<Void>.makeStream()
let finishHistory = DispatchSemaphore(value: 0)
let blockHistory = Mutex(false)
let historyReads = Mutex(0)
let incrementalReads = Mutex(0)
let historyDayCount = Mutex(30)
let failFirstPage = Mutex(false)
let failOlderPage = Mutex(false)
let fixtureRecordID = UUID()
extension String {
    var id: UUID {
        if self == "latest" { return fixtureRecordID }
        let index = Int(split(separator: "-").last!)! + 1
        return UUID(uuidString: String(format: "00000000-0000-0000-0000-%012d", index))!
    }
}
typealias AccessRequestRecord = String
struct AuthorizationHistoryPage {
    let records: [String]
    let olderPageCursor: Int64?
    let storedDayCount: Int?
}
struct AuthorizationHistoryDashboard {
    let page: AuthorizationHistoryPage
    let activityRecords: [AccessRequestRecord]
}
func loadAuthorizationHistoryDashboard(previous: AuthorizationHistoryDashboard? = nil) -> AuthorizationHistoryDashboard? {
    if previous != nil { incrementalReads.withLock { $0 += 1 } }
    guard let page = loadAccessRequestRecordsPage() else { return nil }
    return AuthorizationHistoryDashboard(page: page, activityRecords: ["latest"])
}
enum DashboardSection { case secretUsage }

struct DashboardSnapshot: Sendable {
    var policy = "loaded"
    var toolStatus = "loaded"
    var accessRequests = [String]()
    var detectorFindings = ["preserved"]

}
func loadAccessRequestRecordsForDisclosure(since: Date? = nil) -> [AccessRequestRecord]? {
    ["latest"]
}
func loadAccessRequestRecordsPage(beforeSequence: Int64? = nil) -> AuthorizationHistoryPage? {
    let dayCount = historyDayCount.withLock { $0 }
    if blockHistory.withLock({ $0 }) {
        historyReads.withLock { $0 += 1 }
        historySignal.yield(())
        finishHistory.wait()
    }
    if beforeSequence == nil && failFirstPage.withLock({ $0 }) { return nil }
    if beforeSequence != nil && failOlderPage.withLock({ $0 }) { return nil }
    if beforeSequence == nil {
        return AuthorizationHistoryPage(
            records: ["latest"] + (0..<49).map { "older-\($0)" },
            olderPageCursor: 50,
            storedDayCount: dayCount)
    }
    return AuthorizationHistoryPage(
        records: (49..<74).map { "older-\($0)" },
        olderPageCursor: nil,
        storedDayCount: dayCount)
}

@MainActor final class Model {
    var accessRequestsReloadTask: Task<Void, Never>?
    var accessRequestsReloadPending = false
    var historyDashboard: AuthorizationHistoryDashboard?
    var accessRequestsGeneration = 0
    var historyOlderPageCursor: Int64?
    var isLoadingOlderHistory = false
    var historyLoadFailed = false
    var authorizationHistoryDayCount = 0
    var pendingAccessRequestID: UUID?
    var selectedSection = DashboardSection.secretUsage
    var selectedItemID: String?
    var searchText = ""
    var overviewHistory: [AccessRequestRecord]?
    var snapshot = DashboardSnapshot()
    var normalizationCount = 0
    var historyRecordsByID = [UUID: String]()
    func normalizeSelection() {
        normalizationCount += 1
        if pendingAccessRequestID != nil {
            selectedItemID = nil
            return
        }
        if selectedItemID.map({ id in snapshot.accessRequests.contains { $0.id.uuidString == id } }) != true {
            selectedItemID = snapshot.accessRequests.first?.id.uuidString
        }
    }
    func setHistoryRecords(_ records: [String], storedDayCount: Int? = nil) {
        historyRecordsByID = Dictionary(records.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        authorizationHistoryDayCount = storedDayCount ?? (records.isEmpty ? 0 : 1)
    }
    func appendHistoryRecords(_ records: [String]) {
        for record in records { historyRecordsByID[record.id] = record }
    }
    struct Loaders {
        var history: (AuthorizationHistoryDashboard?) async -> AuthorizationHistoryDashboard? = { previous in
            await Task.detached { loadAuthorizationHistoryDashboard(previous: previous) }.value
        }
    }
    let loaders = Loaders()
""" + show_method + pending_status + history_method + """
}

DispatchQueue.global().asyncAfter(deadline: .now() + 10) {
    print("FAIL: reload timed out")
    exit(1)
}
let model = Model()
model.reloadAccessRequests()
await model.accessRequestsReloadTask!.value
assert(model.overviewHistory == ["latest"])
assert(model.snapshot.accessRequests.count == 50 && model.snapshot.accessRequests.first == "latest")
assert(model.historyOlderPageCursor == 50)
assert(model.authorizationHistoryDayCount == 30)
blockHistory.withLock { $0 = true }
model.reloadAccessRequests()
for await _ in historyStarted { break }
for _ in 0..<100 { model.reloadAccessRequests() }
assert(historyReads.withLock { $0 == 1 }, "history burst queued duplicate reads")
finishHistory.signal()
for await _ in historyStarted { break }
assert(historyReads.withLock { $0 == 2 }, "history burst did not coalesce")
finishHistory.signal()
await model.accessRequestsReloadTask!.value
assert(historyReads.withLock { $0 == 2 })
blockHistory.withLock { $0 = false }
// Sustained notifications must publish each completed snapshot and reuse it.
model.historyDashboard = nil
incrementalReads.withLock { $0 = 0 }
blockHistory.withLock { $0 = true }
model.reloadAccessRequests(incremental: true)
for await _ in historyStarted { break }
for index in 0..<5 {
    let active = model.accessRequestsReloadTask!
    for _ in 0..<20 { model.reloadAccessRequests(incremental: true) }
    finishHistory.signal()
    await active.value
    assert(model.historyDashboard != nil, "incremental notifications discarded a usable snapshot")
    for await _ in historyStarted { break }
    assert(incrementalReads.withLock { $0 == index + 1 }, "follow-up repeated a full history scan")
}
finishHistory.signal()
await model.accessRequestsReloadTask!.value
blockHistory.withLock { $0 = false }
let missingID = UUID()
model.showAccessRequest(id: missingID)
await model.accessRequestsReloadTask!.value
assert(model.pendingAccessRequestID == missingID)
assert(model.selectedItemID == nil, "missing record selected an unrelated history row")
assert(model.pendingAccessRequestStatus == String(localized:
    "Load older records to find this Authorization History record."))
model.showAccessRequest(id: fixtureRecordID)
assert(model.pendingAccessRequestID == nil)
assert(model.selectedItemID == fixtureRecordID.uuidString)
model.snapshot.accessRequests = []
blockHistory.withLock { $0 = true }
model.showAccessRequest(id: fixtureRecordID)
for await _ in historyStarted { break }
model.searchText = "hide requested record"
finishHistory.signal()
await model.accessRequestsReloadTask!.value
assert(model.searchText.isEmpty && model.selectedItemID == fixtureRecordID.uuidString,
       "resolving a pending request selected a search-hidden row")
blockHistory.withLock { $0 = false }
let normalizationsBeforeOlderPage = model.normalizationCount
model.pendingAccessRequestID = UUID()
model.loadMoreHistory()
assert(model.pendingAccessRequestStatus == String(localized: "Loading Authorization History…"))
for _ in 0..<10_000 {
    if !model.isLoadingOlderHistory { break }
    await Task.yield()
}
assert(model.snapshot.accessRequests.count == 75, "older history page was not appended")
assert(model.historyOlderPageCursor == nil)
assert(model.normalizationCount == normalizationsBeforeOlderPage + 1,
       "older history page did not normalize selection")
assert(model.pendingAccessRequestStatus == String(localized: "Authorization History record unavailable"))
model.reloadAccessRequests()
await model.accessRequestsReloadTask!.value
assert(model.snapshot.accessRequests.count == 50, "refresh retained evicted or older cached records")
assert(model.historyOlderPageCursor == 50, "refresh did not reset the paging cursor")
blockHistory.withLock { $0 = true }
model.reloadAccessRequests()
for await _ in historyStarted { break }
model.loadMoreHistory()
assert(!model.isLoadingOlderHistory, "older page started during first-page refresh")
finishHistory.signal()
await model.accessRequestsReloadTask!.value
blockHistory.withLock { $0 = false }
failFirstPage.withLock { $0 = true }
model.reloadAccessRequests()
await model.accessRequestsReloadTask!.value
assert(model.snapshot.accessRequests.isEmpty && model.historyOlderPageCursor == nil)
assert(model.historyLoadFailed, "failed first-page read looked successful")
assert(model.pendingAccessRequestStatus == String(localized: "Authorization History unavailable"))
failFirstPage.withLock { $0 = false }
blockHistory.withLock { $0 = true }
model.reloadAccessRequests()
for await _ in historyStarted { break }
assert(model.historyLoadFailed && model.accessRequestsReloadTask != nil,
       "first-page retry did not expose a loading state")
finishHistory.signal()
await model.accessRequestsReloadTask!.value
blockHistory.withLock { $0 = false }
assert(model.snapshot.accessRequests.count == 50 && !model.historyLoadFailed)
failOlderPage.withLock { $0 = true }
model.loadMoreHistory()
for _ in 0..<10_000 {
    if !model.isLoadingOlderHistory { break }
    await Task.yield()
}
assert(model.snapshot.accessRequests.count == 50 && model.historyOlderPageCursor == 50)
assert(model.historyLoadFailed, "failed older-page read looked successful")
assert(model.pendingAccessRequestStatus == String(localized: "Older Authorization History unavailable"))
failOlderPage.withLock { $0 = false }
model.loadMoreHistory(retry: true)
for _ in 0..<10_000 {
    if !model.isLoadingOlderHistory { break }
    await Task.yield()
}
assert(model.snapshot.accessRequests.count == 75 && !model.historyLoadFailed)
assert(model.historyDashboard != nil)
print("PASS: coalesced history refreshes, pagination, search selection, and failures")
"""

with tempfile.TemporaryDirectory(prefix="av-cli-refresh-") as directory:
    path = Path(directory) / "main.swift"
    path.write_text(fixture)
    result = subprocess.run(["swift", "-swift-version", "6", str(path)])
    sys.exit(result.returncode)
