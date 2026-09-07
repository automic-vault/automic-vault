import StoreKit
import SwiftUI

private enum ApprovalRoute: Hashable {
    case pending(UUID)
    case history(UUID)
    case settings
    case subscription
}

struct ApprovalRootView: View {
    @Bindable var model: ApprovalModel
    @Bindable var subscription: ApprovalSubscription
    @State private var path: [ApprovalRoute] = []
    @State private var showingSubscription = false
    @State private var keepsPendingListVisible = false

    var body: some View {
        NavigationStack(path: $path) {
            Group {
                if let request = notificationRequest {
                    ApprovalDetailView(request: request, model: model, subscription: subscription)
                } else if model.pending.count == 1, !keepsPendingListVisible, let request = model.pending.first {
                    ApprovalDetailView(request: request, model: model, subscription: subscription)
                } else if !model.pending.isEmpty {
                    list
                } else if subscription.state == .loading {
                    ProgressView("Checking subscription…")
                } else if model.state == .setup || subscription.state == .inactive {
                    setup
                } else if showsActivity {
                    ApprovalActivityView(model: model)
                } else {
                    empty
                }
            }
            .navigationTitle(showsActivity ? "Request History" : "Approvals")
            .navigationDestination(for: ApprovalRoute.self) { route in
                destination(for: route)
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    NavigationLink(value: ApprovalRoute.settings) {
                        Label("Settings", systemImage: "gear")
                    }
                }
            }
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
                path.removeAll()
                showingSubscription = false
                keepsPendingListVisible = false
            }
        }
    }

    private var notificationRequest: PhoneApprovalRequest? {
        guard let id = model.notificationReviewRequestID else { return nil }
        return model.pending.first { $0.id == id }
    }

    private var showsActivity: Bool {
        model.pending.isEmpty && model.state == .connected && subscription.state == .active
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
        case .settings:
            ApprovalSettingsView(model: model, subscription: subscription)
        case .subscription:
            ApprovalSubscriptionView(subscription: subscription)
        }
    }

    private var setup: some View {
        ContentUnavailableView {
            Label("Approve Away from Your Mac", systemImage: "iphone.and.arrow.forward")
        } description: {
            Text("Use this iPhone for every human Approval on an enrolled Mac. iCloud Keychain and notifications are required.")
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

    private var empty: some View {
        ContentUnavailableView {
            Label("No Pending Approvals", systemImage: "checkmark.shield")
        } description: {
            Text(connectionText)
        } actions: {
            if case .reconnecting = model.state {
                Button("Refresh", systemImage: "arrow.clockwise") {
                    Task { await model.refresh() }
                }
                .buttonStyle(.borderedProminent)
            }
        }
    }

    private var connectionText: String {
        switch model.state {
        case .setup: "Enable notifications to receive Approval requests."
        case .connecting: "Connecting…"
        case .connected: "Ready for Approval requests."
        case .unavailable(let reason): reason
        case .reconnecting(let reason): reason
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
                LabeledContent("Working Directory", value: request.cwd)
                LabeledContent("Secrets", value: request.secretNames.joined(separator: ", "))
                HStack {
                    Text("Requested").foregroundStyle(.secondary)
                    Spacer()
                    Text(Date(timeIntervalSince1970: TimeInterval(request.createdAtMilliseconds) / 1_000), style: .relative)
                }

                Label(request.reason, systemImage: request.requiresFullReview ? "exclamationmark.shield.fill" : "shield")
                    .foregroundStyle(request.requiresFullReview ? .orange : .primary)

                ForEach(Array(request.details.enumerated()), id: \.offset) { _, section in
                    DisclosureGroup(section.title) {
                        VStack(spacing: 10) {
                            ForEach(Array(section.rows.enumerated()), id: \.offset) { _, row in
                                LabeledContent(row.label, value: row.value)
                            }
                        }
                        .padding(.top, 8)
                    }
                }

                if subscription.state == .active {
                    HStack(spacing: 12) {
                        denyButton
                        Button("Approve Once") { Task { await model.approve(request) } }
                            .buttonStyle(.borderedProminent).controlSize(.large).frame(maxWidth: .infinity)
                    }
                } else {
                    denyButton
                    Button("Subscribe to Approve") { showingSubscription = true }
                        .buttonStyle(.borderedProminent).controlSize(.large).frame(maxWidth: .infinity)
                }

                if subscription.state == .active, let scope = request.temporaryAccessGrantScope {
                    Button {
                        Task { await model.allowTemporaryWriteAccess(request) }
                    } label: {
                        Label("Allow Write Access for 10 Minutes…", systemImage: "clock.badge.checkmark")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                    .accessibilityLabel("Allow Write Access for 10 minutes for \(scope)")

                    Text("Limited to \(scope).")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: .infinity)
                }
            }
            .padding()
        }
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

    private var denyButton: some View {
        Button("Deny", role: .destructive) { Task { await model.deny(request) } }
            .buttonStyle(.bordered).controlSize(.large).frame(maxWidth: .infinity)
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
                Text("When enabled, Approve requires biometrics on this iPhone. Passcode, Apple Watch, and a companion Mac cannot substitute.")
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

    var body: some View {
        Group {
            if model.activity.isEmpty {
                ContentUnavailableView(
                    "No Request History",
                    systemImage: "clock.arrow.circlepath",
                    description: Text("Responses and canceled requests will appear here.")
                )
            } else {
                List(model.activity) { item in
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
            }
        }
        .safeAreaInset(edge: .bottom) {
            Text("Up to 50 responses and canceled requests. The Mac's Authorization History is authoritative.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding()
                .frame(maxWidth: .infinity)
                .background(.bar)
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
        case .temporaryWriteAccess: "10-minute Write Access sent"
        case .canceled: "Request canceled"
        }
    }

    var responseSystemImage: String {
        switch outcome {
        case .approved: "checkmark.shield"
        case .denied: "xmark.shield"
        case .temporaryWriteAccess: "clock.badge.checkmark"
        case .canceled: "xmark.circle"
        }
    }

    var responseColor: Color {
        switch outcome {
        case .approved, .temporaryWriteAccess: .green
        case .denied: .red
        case .canceled: .secondary
        }
    }
}

struct ApprovalSubscriptionView: View {
    @Bindable var subscription: ApprovalSubscription

    var body: some View {
        SubscriptionStoreView(productIDs: ApprovalSubscription.productIDs) {
            VStack(spacing: 12) {
                Image(systemName: "iphone.and.arrow.forward")
                    .font(.system(size: 52))
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
        .navigationTitle("Subscription")
        .navigationBarTitleDisplayMode(.inline)
    }
}
