#!/usr/bin/env python3
"""Exercise the dashboard's real reload method with a blocked snapshot load."""
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
reload_method, reload_boundary, _ = model_source.split(
    "    func reload() {", 1
)[1].partition("    fileprivate func reloadAuthorizationState()")
assert reload_boundary, "DashboardModel reload extraction boundary not found"

fixture = r"""
import Foundation
import Synchronization

let loads = Mutex((count: 0, active: 0, peak: 0))

let (snapshotStarted, started) = AsyncStream<Void>.makeStream()
let finishSnapshot = DispatchSemaphore(value: 0)
let (historyStarted, historySignal) = AsyncStream<Void>.makeStream()
let finishHistory = DispatchSemaphore(value: 0)
let blockHistory = Mutex(false)
let historyReads = Mutex(0)
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
enum DashboardSection { case secretUsage }

struct DashboardSnapshot: Sendable {
    var policy = "loaded"
    var accessRequests = [String]()
    var detectorFindings = ["preserved"]
    static func load() -> Self {
        loads.withLock {
            $0.count += 1
            $0.active += 1
            $0.peak = max($0.peak, $0.active)
        }
        defer { loads.withLock { $0.active -= 1 } }
        started.yield(())
        finishSnapshot.wait()
        return Self(detectorFindings: [])
    }
}
enum CLIInstallState { case current, outdated }
func currentCLIInstallState() -> CLIInstallState { .current }
func loadLauncherBundleEnrollments() -> [String] { [] }
func loadAccessRequestRecordsForDisclosure(since: Date? = nil) -> [AccessRequestRecord]? {
    ["latest"]
}
func loadAccessRequestRecordsPage(beforeSequence: Int64? = nil) -> AuthorizationHistoryPage? {
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
            storedDayCount: 30)
    }
    return AuthorizationHistoryPage(
        records: (49..<74).map { "older-\($0)" },
        olderPageCursor: nil,
        storedDayCount: 30)
}

@MainActor final class Model {
    var reloadTask: Task<Void, Never>?
    var accessRequestsReloadTask: Task<Void, Never>?
    var accessRequestsReloadPending = false
    var accessRequestsGeneration = 0
    var historyOlderPageCursor: Int64?
    var isLoadingOlderHistory = false
    var historyLoadFailed = false
    var authorizationHistoryDayCount = 0
    var pendingAccessRequestID: UUID?
    var selectedSection = DashboardSection.secretUsage
    var selectedItemID: String?
    var searchText = ""
    var reloadPending = false
    var isReloading = false
    var hasLoadedInitialSnapshot = false
    var overviewHistory: [AccessRequestRecord]?
    var lastHardeningRefresh: Date?
    var snapshot = DashboardSnapshot()
    var cliInstallState = CLIInstallState.outdated
    var launcherBundles: [String] = []
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
    func invalidateForTest() { invalidateReload() }
""" + show_method + pending_status + r"""
    func reload() {
""" + reload_method + """
}

DispatchQueue.global().asyncAfter(deadline: .now() + 10) {
    print("FAIL: reload timed out")
    exit(1)
}
let model = Model()
model.reload()
for await _ in snapshotStarted { break }
model.pendingAccessRequestID = UUID()
assert(model.pendingAccessRequestStatus == String(localized: "Loading Authorization History…"))
model.pendingAccessRequestID = nil
guard model.cliInstallState == .current, model.isReloading else {
    print("FAIL: Update av CLI remains visible while dashboard loading is blocked")
    exit(1)
}
let first = model.reloadTask!
for _ in 0..<100 { model.reload() }
assert(!first.isCancelled, "refresh must not cancel a usable result")
finishSnapshot.signal()
await first.value
assert(model.hasLoadedInitialSnapshot && model.lastHardeningRefresh != nil)
assert(model.overviewHistory == ["latest"])
assert(model.snapshot.accessRequests.count == 50 && model.snapshot.accessRequests.first == "latest")
assert(model.historyOlderPageCursor == 50)
assert(model.authorizationHistoryDayCount == 30)
assert(model.snapshot.detectorFindings == ["preserved"])
// A burst queues exactly one follow-up, after the first load finishes.
for await _ in snapshotStarted { break }
let second = model.reloadTask!
finishSnapshot.signal()
await second.value
assert(!model.isReloading)
assert(model.snapshot.detectorFindings == ["preserved"])
assert(loads.withLock { $0.count == 2 && $0.peak == 1 })
assert(model.reloadTask == nil)

model.reload()
for await _ in snapshotStarted { break }
let invalidated = model.reloadTask!
model.reload() // A pending refresh must also be invalidated by a policy edit.
model.invalidateForTest()
model.snapshot.policy = "edited"
model.reloadAccessRequests()
await model.accessRequestsReloadTask!.value
assert(model.snapshot.accessRequests.count == 50 && model.snapshot.accessRequests.first == "latest")
assert(invalidated.isCancelled)
assert(!model.isReloading)
assert(!model.reloadPending)
assert(loads.withLock { $0.count == 3 })
model.reload() // Wait for the invalidated work instead of overlapping it.
finishSnapshot.signal()
await invalidated.value
assert(model.snapshot.policy == "edited", "stale policy result was applied")
for await _ in snapshotStarted { break }
let replacement = model.reloadTask!
finishSnapshot.signal()
await replacement.value
assert(loads.withLock { $0.count == 4 && $0.peak == 1 })
assert(model.reloadTask == nil && !model.isReloading)
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
print("PASS: early CLI status, coalesced refreshes, fresh history, and stale policy rejection")
"""

with tempfile.TemporaryDirectory(prefix="av-cli-refresh-") as directory:
    path = Path(directory) / "main.swift"
    path.write_text(fixture)
    result = subprocess.run(["swift", "-swift-version", "6", str(path)])
    sys.exit(result.returncode)
