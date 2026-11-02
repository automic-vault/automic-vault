import StoreKit
import SwiftUI

private enum ApprovalRoute: Hashable {
    case pending(UUID)
    case history(UUID)
    case subscription
}

private enum ApprovalTab: Hashable {
    case requests
    case settings
}

struct ApprovalRootView: View {
    @Bindable var model: ApprovalModel
    @Bindable var subscription: ApprovalSubscription
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.openURL) private var openURL
    @State private var selectedTab = ApprovalTab.requests
    @State private var path: [ApprovalRoute] = []
    @State private var showingSubscription = false
    @State private var keepsPendingListVisible = false

    var body: some View {
        TabView(selection: $selectedTab) {
            Tab("Requests", systemImage: "checkmark.shield", value: ApprovalTab.requests) {
                requests
            }
            .badge(model.pending.count)
            Tab("Settings", systemImage: "gear", value: ApprovalTab.settings) {
                NavigationStack {
                    ApprovalSettingsView(model: model, subscription: subscription)
                        .navigationDestination(for: ApprovalRoute.self) { route in
                            destination(for: route)
                        }
                }
            }
        }
        .tabViewStyle(.sidebarAdaptable)
        .alert("Approval Error", isPresented: Binding(
            get: { model.errorMessage != nil },
            set: { if !$0 { model.errorMessage = nil } }
        )) {
            Button("OK") { model.errorMessage = nil }
        } message: {
            Text(model.errorMessage ?? "")
        }
        .alert("Subscription Error", isPresented: Binding(
            get: { subscription.errorMessage != nil },
            set: { if !$0 { subscription.errorMessage = nil } }
        )) {
            Button("OK") { subscription.errorMessage = nil }
        } message: {
            Text(subscription.errorMessage ?? "")
        }
        .sheet(isPresented: $showingSubscription) {
            NavigationStack {
                ApprovalSubscriptionView(subscription: subscription)
            }
        }
        .onChange(of: subscription.state) { _, state in
            guard state == .active, showingSubscription else { return }
            showingSubscription = false
            Task { await model.enable() }
        }
        .onChange(of: model.pending.count, initial: true) { _, count in
            if count > 1 { keepsPendingListVisible = true }
            if count == 0 { keepsPendingListVisible = false }
        }
        .onChange(of: model.notificationReviewSequence, initial: true) { _, sequence in
            guard sequence > 0 else { return }
            selectedTab = .requests
            path.removeAll()
            showingSubscription = false
            keepsPendingListVisible = false
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { Task { await model.refreshNotificationSettings() } }
        }
        .safeAreaInset(edge: .bottom) {
            if model.notificationsAreOff {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Notifications are off", systemImage: "exclamationmark.triangle.fill")
                        .font(.headline)
                    Text("Approval requests may only appear when you open Automic Vault.")
                        .font(.callout)
                    if model.notificationAuthorizationStatus == .notDetermined {
                        Button("Enable Notifications") { Task { await model.enable() } }
                    } else {
                        Button("Open Notification Settings") {
                            if let url = URL(string: UIApplication.openNotificationSettingsURLString) { openURL(url) }
                        }
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.bar)
            }
        }
    }

    private var requests: some View {
        NavigationStack(path: $path) {
            Group {
                if let request = notificationRequest {
                    ApprovalDetailView(request: request, model: model, subscription: subscription)
                } else if let ticket = model.notificationReviewTicket {
                    notificationPreview(ticket)
                } else if model.pending.count == 1, !keepsPendingListVisible, let request = model.pending.first {
                    ApprovalDetailView(request: request, model: model, subscription: subscription)
                } else if !model.pending.isEmpty {
                    list
                } else if model.isStarting || subscription.state == .loading {
                    ProgressView()
                        .controlSize(.large)
                        .accessibilityLabel("Loading")
                } else if model.state == .setup || subscription.state == .inactive {
                    setup
                } else {
                    ApprovalActivityView(model: model)
                }
            }
            .navigationTitle(model.notificationReviewTicket != nil ? "Approval" : showsActivity ? "Request History" : "Approvals")
            .navigationDestination(for: ApprovalRoute.self) { route in
                destination(for: route)
            }
        }
    }

    private func notificationPreview(_ ticket: PhoneApprovalTicket) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(ticket.launcher).font(.title2.bold())
                    Text("on \(ticket.macName)").foregroundStyle(.secondary)
                }
                LabeledContent("Tool", value: ticket.tool)
                Text(ticket.command).font(.body.monospaced())
                Text(ticket.reason).foregroundStyle(.secondary)
                ProgressView().accessibilityLabel("Loading")
                    .frame(maxWidth: .infinity)
                if case .reconnecting(let reason) = model.state {
                    Text(reason).foregroundStyle(.secondary)
                    Button("Refresh", systemImage: "arrow.clockwise") {
                        Task { await model.refresh() }
                    }
                } else if case .unavailable(let reason) = model.state {
                    Text(reason).foregroundStyle(.secondary)
                }
                Button("Done") { model.dismissNotificationReview() }
                    .frame(maxWidth: .infinity)
            }
            .padding(20)
            .frame(maxWidth: 720)
            .frame(maxWidth: .infinity)
        }
        .navigationBarTitleDisplayMode(.inline)
    }

    private var notificationRequest: PhoneApprovalRequest? {
        guard let id = model.notificationReviewRequestID else { return nil }
        return model.pending.first { $0.id == id }
    }

    private var showsActivity: Bool {
        model.pending.isEmpty && (
            model.isStarting || subscription.state == .loading
                || (model.state != .setup && subscription.state == .active)
        )
    }

    @ViewBuilder
    private func destination(for route: ApprovalRoute) -> some View {
        switch route {
        case .pending(let id):
            if let request = model.pending.first(where: { $0.id == id }) {
                ApprovalDetailView(request: request, model: model, subscription: subscription)
            } else {
                ContentUnavailableView("Approval No Longer Pending", systemImage: "checkmark.shield")
            }
        case .history(let id):
            if let item = model.activity.first(where: { $0.id == id }) {
                ApprovalActivityDetailView(item: item)
            } else {
                ContentUnavailableView("History Entry Unavailable", systemImage: "clock.badge.xmark")
            }
        case .subscription:
            ApprovalSubscriptionView(subscription: subscription)
        }
    }

    private var setup: some View {
        ContentUnavailableView {
            Label("Approve Away from Your Mac", systemImage: "iphone.and.arrow.forward")
        } description: {
            Text("Use this device for every human Approval on an enrolled Mac. iCloud Keychain and notifications are required.")
        } actions: {
            Button("Enable iPhone Approval") {
                if subscription.state == .active {
                    Task { await model.enable() }
                } else {
                    showingSubscription = true
                }
            }
                .buttonStyle(.borderedProminent)
        }
    }

    private var list: some View {
        List {
            Section {
                ForEach(model.pending) { request in
                    NavigationLink(value: ApprovalRoute.pending(request.id)) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(request.launcher).font(.headline)
                            Text(request.command).font(.callout.monospaced()).lineLimit(2)
                            Text("\(request.macName) · \(request.secretNames.count) secret\(request.secretNames.count == 1 ? "" : "s")")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                Text("\(model.pending.count) pending")
            } footer: {
                Button("Deny All", role: .destructive) { Task { await model.denyAll() } }
            }
        }
    }
}

struct ApprovalDetailView: View {
    let request: PhoneApprovalRequest
    @Bindable var model: ApprovalModel
    @Bindable var subscription: ApprovalSubscription
    @Environment(\.dismiss) private var dismiss
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @State private var showingSubscription = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(request.launcher).font(.title2.bold())
                    Text("on \(request.macName)").foregroundStyle(.secondary)
                }

                LabeledContent("Tool", value: request.tool)
                VStack(alignment: .leading, spacing: 8) {
                    Text("Command").font(.caption).foregroundStyle(.secondary)
                    Text(request.command)
                        .font(.body.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                        .background(.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 12))
                }
                ApprovalMetadata(label: "Working Directory", value: request.cwd)
                ApprovalMetadata(label: "Secrets", value: request.secretNames.joined(separator: ", "))
                HStack {
                    Text("Requested").foregroundStyle(.secondary)
                    Spacer()
                    Text(Date(timeIntervalSince1970: TimeInterval(request.createdAtMilliseconds) / 1_000), style: .relative)
                }

                Label {
                    Text(request.reason).fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: request.requiresFullReview ? "exclamationmark.shield.fill" : "shield")
                        .foregroundStyle(request.requiresFullReview ? .orange : .primary)
                }

                ForEach(Array(request.details.enumerated()), id: \.offset) { _, section in
                    DisclosureGroup(section.title) {
                        VStack(spacing: 10) {
                            ForEach(Array(section.rows.enumerated()), id: \.offset) { _, row in
                                ApprovalMetadata(label: row.label, value: row.value)
                            }
                        }
                        .padding(.top, 8)
                    }
                }

                Divider()

                if subscription.state == .active {
                    responseLayout {
                        denyButton
                        if isResponding { ProgressView().accessibilityLabel("Responding") }
                        Button { Task { await model.approve(request) } } label: {
                            Text("Approve Once").frame(maxWidth: .infinity, minHeight: 24)
                        }
                        .buttonStyle(.borderedProminent).controlSize(.large)
                    }
                    .disabled(isResponding)
                } else if subscription.state == .loading {
                    HStack(spacing: 12) {
                        denyButton
                        ProgressView().accessibilityLabel("Loading")
                            .frame(maxWidth: .infinity)
                    }
                } else {
                    denyButton
                    Button("Subscribe to Approve") { showingSubscription = true }
                        .buttonStyle(.borderedProminent).controlSize(.large).frame(maxWidth: .infinity)
                }

                if let denial = request.temporaryDenial {
                    Button(denial.actionTitle, role: .destructive) {
                        Task { await model.denyTemporarily(request) }
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                    .disabled(isResponding)
                    .accessibilityLabel("\(denial.actionTitle) for \(denial.scope)")
                    Text("Only \(denial.scope). You can end this early from the Mac’s menu bar.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }

                if subscription.state == .active, let scope = request.temporaryAccessGrantScope {
                    Button {
                        Task { await model.allowTemporaryWriteAccess(request) }
                    } label: {
                        Label {
                            VStack(alignment: .leading) {
                                Text("Allow Write Access")
                                    .font(.body.weight(.medium))
                                Text("for 10 Minutes")
                                    .font(.subheadline)
                            }
                            .fixedSize(horizontal: false, vertical: true)
                        } icon: {
                            Image(systemName: "clock.badge.checkmark")
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .buttonStyle(.bordered)
                    .buttonBorderShape(.roundedRectangle)
                    .controlSize(.large)
                    .disabled(isResponding)
                    .accessibilityLabel("Allow Write Access for 10 minutes for \(scope)")

                    Text("Limited to \(scope).")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: .infinity)
                }
            }
            .padding(24)
            .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 24))
            .padding()
            .frame(maxWidth: 720)
            .frame(maxWidth: .infinity)
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("Approval")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $showingSubscription) {
            NavigationStack {
                ApprovalSubscriptionView(subscription: subscription)
            }
        }
        .onChange(of: subscription.state) { _, state in
            guard state == .active else { return }
            showingSubscription = false
        }
        .onChange(of: model.pending.contains { $0.id == request.id }, initial: true) { _, isPending in
            if !isPending { dismiss() }
        }
    }

    private var isResponding: Bool {
        model.respondingRequestIDs.contains(request.id)
    }

    private var responseLayout: AnyLayout {
        dynamicTypeSize.isAccessibilitySize
            ? AnyLayout(VStackLayout(spacing: 12))
            : AnyLayout(HStackLayout(spacing: 12))
    }

    private var denyButton: some View {
        Button(role: .destructive) { Task { await model.deny(request) } } label: {
            Text("Deny").frame(maxWidth: .infinity, minHeight: 24)
        }
        .buttonStyle(.bordered).controlSize(.large)
        .disabled(isResponding)
    }
}

private struct ApprovalMetadata: View {
    let label: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }
}

struct ApprovalSettingsView: View {
    @Bindable var model: ApprovalModel
    @Bindable var subscription: ApprovalSubscription
    @State private var showingManageSubscriptions = false

    var body: some View {
        Form {
            Section("Protection") {
                Toggle("Require Face ID or Touch ID", isOn: Binding(
                    get: { model.biometricProtectionEnabled },
                    set: { enabled in Task { await model.setBiometricProtection(enabled) } }
                ))
                Text("When enabled, Approve requires biometrics on this device. Passcode, Apple Watch, and a companion Mac cannot substitute.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Section {
                Toggle("Host", isOn: Binding(
                    get: { model.notificationPreferences.showsHost },
                    set: { model.setNotificationHostVisible($0) }
                ))
                Toggle("Approval type", isOn: Binding(
                    get: { model.notificationPreferences.showsApprovalType },
                    set: { model.setNotificationApprovalTypeVisible($0) }
                ))
            } header: {
                Text("Notification Details")
            } footer: {
                Text("Selected details appear in notification text and may be visible on the Lock Screen, Apple Watch, or a mirrored Mac.")
            }
            Section("Physical Separation") {
                Label("iPhone Mirroring and Show on Mac can put Approval controls back onto a Mac when biometric protection is off.", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                Text("Turn off Show on Mac for Automic Vault notifications and revoke iPhone Mirroring access if agents can control your Mac.")
                    .font(.footnote)
            }
            Section("Subscription") {
                LabeledContent("iPhone Approval", value: subscription.state == .active ? "Active" : "Required")
                if subscription.state == .active {
                    Button("Manage Subscription") { showingManageSubscriptions = true }
                } else {
                    NavigationLink("Subscribe", value: ApprovalRoute.subscription)
                }
            }
            Section("Connection") { Text(connectionLabel) }
        }
        .navigationTitle("Settings")
        .manageSubscriptionsSheet(isPresented: $showingManageSubscriptions)
    }

    private var connectionLabel: String {
        switch model.state {
        case .setup: "Not enabled"
        case .connecting: "Connecting…"
        case .connected: "Connected"
        case .unavailable(let reason): reason
        case .reconnecting(let reason): reason
        }
    }
}

struct ApprovalActivityView: View {
    @Bindable var model: ApprovalModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Group {
            if model.activity.isEmpty {
                ContentUnavailableView(
                    "No Request History",
                    systemImage: "clock.arrow.circlepath",
                    description: Text("Responses and canceled requests will appear here.")
                )
            } else {
                List {
                    Section {
                        ForEach(model.activity) { item in
                            NavigationLink(value: ApprovalRoute.history(item.id)) {
                                VStack(alignment: .leading, spacing: 4) {
                                    Label(item.responseTitle, systemImage: item.responseSystemImage)
                                        .font(.headline)
                                        .foregroundStyle(item.responseColor)
                                    Text(item.command)
                                        .font(.callout.monospaced())
                                        .lineLimit(2)
                                    HStack {
                                        Text("\(item.launcher) · \(item.tool) · \(item.macName)")
                                        Spacer()
                                        Text(item.recordedAt, style: .relative)
                                    }
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                }
                            }
                        }
                    } footer: {
                        Text("Up to 50 responses and canceled requests. The Mac's Authorization History is authoritative.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .frame(maxWidth: .infinity)
                    }
                }
            }
        }
        .safeAreaInset(edge: .bottom) {
            ZStack {
                if let message = connectionMessage {
                    HStack(spacing: 12) {
                        if case .unavailable = model.state {
                            Image(systemName: "exclamationmark.triangle")
                                .foregroundStyle(.orange)
                        } else {
                            ProgressView().accessibilityHidden(true)
                        }
                        Text(message).font(.callout)
                        if case .reconnecting = model.state {
                            Button("Retry") { Task { await model.refresh() } }
                                .buttonStyle(.bordered)
                                .controlSize(.large)
                        }
                    }
                    .padding()
                    .background(.bar, ignoresSafeAreaEdges: .bottom)
                    .frame(maxWidth: .infinity)
                    .transition(reduceMotion ? .opacity : .move(edge: .bottom).combined(with: .opacity))
                }
            }
            .frame(maxWidth: .infinity)
            .clipped()
            .animation(reduceMotion ? nil : .easeInOut(duration: 0.25), value: connectionMessage != nil)
        }
    }

    private var connectionMessage: String? {
        switch model.state {
        case .connecting: "Connecting…"
        case .reconnecting(let reason), .unavailable(let reason): reason
        case .setup, .connected: nil
        }
    }
}

struct ApprovalActivityDetailView: View {
    let item: PhoneApprovalActivity

    var body: some View {
        Form {
            Section {
                Label(item.responseTitle, systemImage: item.responseSystemImage)
                    .foregroundStyle(item.responseColor)
                LabeledContent("Recorded") {
                    Text(item.recordedAt, format: .dateTime)
                }
            }

            Section("Request") {
                LabeledContent("Mac", value: item.macName)
                LabeledContent("Launcher", value: item.launcher)
                LabeledContent("Tool", value: item.tool)
            }

            Section("Command") {
                Text(item.command)
                    .font(.body.monospaced())
                    .textSelection(.enabled)
            }

            Section("Request ID") {
                Text(item.id.uuidString)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
            }
        }
        .navigationTitle("Request Details")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private extension PhoneApprovalActivity {
    var recordedAt: Date {
        Date(timeIntervalSince1970: TimeInterval(respondedAtMilliseconds) / 1_000)
    }

    var responseTitle: String {
        switch outcome {
        case .approved: "Approve Once sent"
        case .denied: "Deny sent"
        case .temporaryDenial: "2-minute denial sent"
        case .temporaryWriteAccess: "10-minute Write Access sent"
        case .canceled: "Request canceled"
        }
    }

    var responseSystemImage: String {
        switch outcome {
        case .approved: "checkmark.shield"
        case .denied, .temporaryDenial: "xmark.shield"
        case .temporaryWriteAccess: "clock.badge.checkmark"
        case .canceled: "xmark.circle"
        }
    }

    var responseColor: Color {
        switch outcome {
        case .approved, .temporaryWriteAccess: .green
        case .denied, .temporaryDenial: .red
        case .canceled: .secondary
        }
    }
}

struct ApprovalSubscriptionView: View {
    @Bindable var subscription: ApprovalSubscription
    @Environment(\.dismiss) private var dismiss
    @ScaledMetric(relativeTo: .largeTitle) private var symbolSize = 52

    var body: some View {
        SubscriptionStoreView(productIDs: ApprovalSubscription.productIDs) {
            VStack(spacing: 12) {
                Image(systemName: "iphone.and.arrow.forward")
                    .font(.system(size: symbolSize))
                    .accessibilityHidden(true)
                    .foregroundStyle(.tint)
                Text("iPhone Approval")
                    .font(.largeTitle.bold())
                Text("Keep every human Approval away from agents that can control your Mac.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal)
        }
        .subscriptionStoreControlStyle(.prominentPicker)
        .subscriptionStoreButtonLabel(.multiline)
        .storeButton(.visible, for: .restorePurchases)
        .subscriptionStorePolicyDestination(
            url: URL(string: "https://www.automicvault.com/privacy/")!,
            for: .privacyPolicy
        )
        .subscriptionStorePolicyDestination(
            url: URL(string: "https://www.automicvault.com/terms/")!,
            for: .termsOfService
        )
        .onInAppPurchaseCompletion { _, result in
            await subscription.handlePurchase(result)
        }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Done") { dismiss() }
            }
        }
        .navigationTitle("Subscription")
        .navigationBarTitleDisplayMode(.inline)
    }
}
