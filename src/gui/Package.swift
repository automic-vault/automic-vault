// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AutomicVaultGUI",
    defaultLocalization: "en",
    platforms: [
        .macOS("26.0"),
    ],
    products: [
        .executable(name: "AutomicVaultApp", targets: ["AutomicVaultApp"]),
    ],
    dependencies: [
        .package(
            url: "https://github.com/mxcl/AppUpdater.git",
            from: "2.1.1"
        ),
    ],
    targets: [
        .executableTarget(
            name: "AutomicVaultApp",
            dependencies: [
                .product(name: "AppUpdater", package: "AppUpdater"),
                "ServiceManagementShim",
            ],
            path: ".",
            exclude: [
                "AutomicVault.entitlements",
                "MenuBarAppDelegate.swift",
                "MenuBarMain.swift",
                "ServiceManagementShim",
                "VaultDaemon.swift",
                "Tests",
            ],
            sources: [
                "Localization.swift",
                "PackageModels.swift",
                "SecurityCatalog.swift",
                "NucleusBridge.swift",
                "NukeHelperBridge.swift",
                "NucleusStatusStore.swift",
                "VaultApprovalStore.swift",
                "ContainmentLogStore.swift",
                "PostHogTelemetry.swift",
                "DeepLink.swift",
                "AppMain.swift",
                "AppDelegate.swift",
                "PackagePacks.swift",
                "PackWindowController.swift",
                "MainWindowController.swift",
                "MainWindowModel.swift",
                "MainWindowView.swift",
                "CommandExecutionApprovalView.swift",
                "IsotopeApprovalView.swift",
                "DotenvApprovalView.swift",
                "DotenvFileWatcher.swift",
                "AppUpdateCoordinator.swift",
                "PackageSecurityRules.swift",
                "UpdateProgressViewController.swift",
                "ContainmentLogWindowController.swift",
                "UIStyle.swift",
            ],
            resources: [
                .process("Resources"),
            ]
        ),
        .target(
            name: "ServiceManagementShim",
            path: "ServiceManagementShim",
            publicHeadersPath: "include"
        ),
        .testTarget(
            name: "AutomicVaultGUITests",
            dependencies: ["AutomicVaultApp"],
            path: "Tests",
            sources: [
                "LocalizationResourceTests.swift",
                "DeepLinkTests.swift",
                "MainWindowModelTests.swift",
                "NukeHelperBridgeTests.swift",
                "PackageSecurityStateTests.swift",
                "UpdateProgressViewModelTests.swift",
                "VaultApprovalStoreTests.swift",
            ]
        ),
    ],
    swiftLanguageModes: [.v5]
)
