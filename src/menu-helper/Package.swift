// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "AutomicVaultMenubar",
    platforms: [.macOS("14.0"), .iOS("26.1")],
    products: [
        .executable(name: "AutomicVaultMenubar", targets: ["MenubarHelper"]),
        .executable(name: "AutomicVaultLauncher", targets: ["LauncherBundleRunner"]),
        .executable(name: "AutomicVaultVarlockPlugin", targets: ["VarlockPluginHelper"]),
        .library(name: "ApprovalCore", targets: ["ApprovalCore"]),
    ],
    dependencies: [
        .package(url: "https://github.com/mxcl/AppUpdater.git", from: "4.1.2"),
        .package(url: "https://github.com/GraphQLSwift/GraphQL.git", from: "4.2.0"),
        .package(url: "https://github.com/gonzalezreal/swift-markdown-ui", from: "2.4.1"),
    ],
    targets: [
        .target(name: "ApprovalCore"),
        .target(
            name: "MenubarHelperCore",
            dependencies: [
                .product(name: "GraphQL", package: "GraphQL"),
            ]
        ),
        .target(
            name: "CProcessInfo",
            publicHeadersPath: "include",
            linkerSettings: [.linkedLibrary("bsm")]
        ),
        .executableTarget(
            name: "LauncherBundleRunner",
            linkerSettings: [.linkedFramework("Security")]
        ),
        .executableTarget(name: "VarlockPluginHelper"),
        .executableTarget(
            name: "MenubarHelper",
            dependencies: [
                "ApprovalCore",
                "AppUpdater",
                "CProcessInfo",
                "MenubarHelperCore",
                .product(name: "MarkdownUI", package: "swift-markdown-ui"),
            ]
        ),
        .testTarget(
            name: "MenubarHelperCoreTests",
            dependencies: ["MenubarHelperCore"]
        ),
        .testTarget(
            name: "ApprovalCoreTests",
            dependencies: ["ApprovalCore"]
        ),
    ]
)
