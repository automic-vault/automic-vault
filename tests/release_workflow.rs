const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const BUILD_SCRIPT: &str = include_str!("../scripts/build.sh");
const PUBLISH_SCRIPT: &str = include_str!("../scripts/publish.sh");
const HARDENER_SMOKE_SCRIPT: &str = include_str!("../scripts/smoke-test-hardeners.sh");
const NOTARIZE_SCRIPT: &str = include_str!("../scripts/build-notarize-dmg.sh");
const BUILD_SCANNER_SCRIPT: &str = include_str!("../scripts/build-scanner.sh");
const INSTALL_SCRIPT: &str = include_str!("../scripts/dist/install.sh");
const SCANNER_SCRIPT: &str = include_str!("../scripts/dist/scanner.sh");
const PROXY_HELPER_ENTITLEMENTS: &str =
    include_str!("../src/menu-helper/Resources/ProxyHelper.entitlements");
const MENU_HELPER_INFO_PLIST: &str = include_str!("../src/menu-helper/Info.plist");
const ACCENT_COLOR: &str =
    include_str!("../src/menu-helper/Resources/Assets.xcassets/AccentColor.colorset/Contents.json");
const SECRET_PROXY: &str =
    include_str!("../src/menu-helper/Sources/MenubarHelper/SecretProxy.swift");

#[test]
fn release_workflow_binds_the_dmg_to_reviewed_source() {
    assert!(RELEASE_WORKFLOW.contains("workflow_dispatch:"));
    assert!(RELEASE_WORKFLOW.contains("commit:"));
    assert!(RELEASE_WORKFLOW.contains("notes:"));
    assert!(RELEASE_WORKFLOW.contains("Release notes must not be empty."));
    assert!(RELEASE_WORKFLOW.contains("refs/heads/main"));
    assert!(RELEASE_WORKFLOW.contains("IMMUTABLE_RELEASES_ENABLED"));
    assert!(RELEASE_WORKFLOW.contains("--target \"$GITHUB_SHA\""));
    assert!(RELEASE_WORKFLOW.contains("targetCommitish"));
    assert!(RELEASE_WORKFLOW.contains("actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6"));
    assert_eq!(RELEASE_WORKFLOW.matches("uses: actions/attest@").count(), 2);
    assert!(!RELEASE_WORKFLOW.contains("Isotope-darwin-arm64.tgz"));
    assert!(!RELEASE_WORKFLOW.contains("cosign-installer"));
    assert!(RELEASE_WORKFLOW.contains("sbom-path:"));
    assert!(RELEASE_WORKFLOW.contains("SHA256SUMS"));
    assert!(RELEASE_WORKFLOW.contains("RUST_TOOLCHAIN: 1.96.0"));
    assert!(RELEASE_WORKFLOW.contains("syft-version: v1.49.0"));
    assert!(
        RELEASE_WORKFLOW
            .contains("c50d2bc97c3d6292642bac55f530d247eaf4bf65ee605f26b4caf339383e381c")
    );
}

#[test]
fn release_assets_are_immutable_and_never_replaced() {
    assert!(RELEASE_WORKFLOW.contains("--draft"));
    assert!(PUBLISH_SCRIPT.contains(".immutable"));
    assert!(RELEASE_WORKFLOW.contains("Release $VERSION already exists; publish a new version."));
    assert!(!RELEASE_WORKFLOW.contains("--clobber"));
    assert!(!BUILD_SCRIPT.contains("--publish"));
    assert!(!BUILD_SCRIPT.contains("--clobber"));
    assert!(!PUBLISH_SCRIPT.contains("--clobber"));
    assert!(!PUBLISH_SCRIPT.contains("gh release create"));
    assert!(!RELEASE_WORKFLOW.contains("SCANNER_NAME"));
    assert!(!RELEASE_WORKFLOW.contains("scanner.tgz"));
}

#[test]
fn release_builds_are_actions_only_and_fail_closed() {
    assert!(BUILD_SCRIPT.starts_with("#!/bin/bash\n"));
    assert!(!BUILD_SCRIPT.contains("av inject"));
    assert!(PUBLISH_SCRIPT.starts_with(
        "#!/usr/local/bin/av inject -- /bin/bash\n\
# --- automic-vault\n\
# capabilities:\n\
#   gh: trusted\n\
#   aws: trusted\n\
#   gpg-signing: local-write\n\
# ---\n"
    ));
    assert!(!PUBLISH_SCRIPT.contains("APPLE_PASSWORD"));
    assert!(PUBLISH_SCRIPT.contains("dirname \"${AV_SCRIPT_PATH:-$0}\""));
    assert!(PUBLISH_SCRIPT.contains("Determining release metadata with Codex"));
    assert!(PUBLISH_SCRIPT.contains(
        "Breaking changes confined to the experimental Homebrew stub have at most minor impact"
    ));
    assert!(PUBLISH_SCRIPT.contains("internalVersionReview"));
    assert!(PUBLISH_SCRIPT.contains("INSTALL_REVISION in src/cli/mod.rs"));
    assert!(PUBLISH_SCRIPT.contains("STUB_VERSION in src/isotopes/hardeners/homebrew.rs"));
    assert!(PUBLISH_SCRIPT.contains("bumps-required)"));
    assert!(PUBLISH_SCRIPT.contains("exit 64"));
    assert!(PUBLISH_SCRIPT.contains("update_internal_versions \"$INTERNAL_VERSION_METADATA\""));
    assert!(PUBLISH_SCRIPT.contains("next != current + 1"));
    assert!(PUBLISH_SCRIPT.contains("ls-files --error-unmatch"));
    assert!(PUBLISH_SCRIPT.contains("expected exactly one numeric assignment"));
    assert!(PUBLISH_SCRIPT.contains("--sandbox read-only"));
    assert!(PUBLISH_SCRIPT.contains("approval_policy=\\\"never\\\""));
    assert!(PUBLISH_SCRIPT.contains("shell_environment_policy.inherit=\\\"none\\\""));
    assert!(PUBLISH_SCRIPT.contains("git -C \"$ROOT\" commit -m \"Release $VERSION\""));
    assert!(PUBLISH_SCRIPT.contains("RESUME_RELEASE=1"));
    assert!(PUBLISH_SCRIPT.contains("retry with: $0 --version $VERSION"));
    assert!(PUBLISH_SCRIPT.contains("-f notes=\"$(<\"$RELEASE_NOTES\")\""));
    assert!(
        PUBLISH_SCRIPT
            .contains("APP_VERSION=\"$previous_version\" \"$ROOT/scripts/build.sh\" --wmo")
    );
    assert!(RELEASE_WORKFLOW.contains("--notes-file \"$notes\""));
    assert!(!RELEASE_WORKFLOW.contains("--generate-notes"));
    assert!(RELEASE_WORKFLOW.contains(
        "run: /bin/bash scripts/build.sh --release-artifact --wmo --version \"$VERSION\""
    ));
    assert!(BUILD_SCRIPT.contains("--release-artifact"));
    assert!(BUILD_SCRIPT.contains("release artifacts may only be built by GitHub Actions"));
    assert!(BUILD_SCRIPT.contains("release checkout does not match GITHUB_SHA"));
    assert!(BUILD_SCRIPT.contains("cargo build --release --locked"));
    assert!(BUILD_SCRIPT.contains("--disable-automatic-resolution"));
    assert_eq!(
        BUILD_SCRIPT
            .matches("swift build \"${swift_build_args[@]}\"")
            .count(),
        2
    );
    assert!(
        BUILD_SCRIPT
            .contains("cp \"$SWIFT_BIN/AutomicVaultMenubar\" \"$MACOS/AutomicVaultMenubar\"")
    );
    assert!(BUILD_SCRIPT.contains("--arch arm64"));
    assert!(BUILD_SCRIPT.contains("-no-whole-module-optimization"));
    assert!(!BUILD_SCRIPT.contains("lipo "));
    assert!(BUILD_SCRIPT.contains(
        "ditto \"$SWIFT_BIN/AppUpdater_AppUpdater.bundle\" \"$RESOURCES/AppUpdater_AppUpdater.bundle\""
    ));
    assert!(BUILD_SCRIPT.contains("requires a Developer ID Application identity"));
    assert!(BUILD_SCRIPT.contains("requires the Developer ID provisioning profile"));
    assert!(!BUILD_SCRIPT.contains("build-scanner.sh"));
    assert!(NOTARIZE_SCRIPT.starts_with("#!/bin/sh\n"));
    assert!(!NOTARIZE_SCRIPT.contains("/usr/local/bin/av"));
    for secret in ["APPLE_USERNAME", "APPLE_PASSWORD", "APPLE_TEAM_ID"] {
        assert!(NOTARIZE_SCRIPT.contains(secret));
    }
    for secret in [
        "MACOS_DEVELOPER_ID_P12_BASE64",
        "MACOS_DEVELOPER_ID_P12_PASSWORD",
        "APPLE_PASSWORD",
    ] {
        assert!(RELEASE_WORKFLOW.contains(&format!("secrets.{secret}")));
    }
    for public_value in [
        "MACOS_PROVISIONING_PROFILE_BASE64",
        "APPLE_USERNAME",
        "APPLE_TEAM_ID",
        "POSTHOG_API_KEY",
    ] {
        assert!(RELEASE_WORKFLOW.contains(&format!("vars.{public_value}")));
        assert!(!RELEASE_WORKFLOW.contains(&format!("secrets.{public_value}")));
    }
}

#[test]
fn hardener_smoke_test_is_blessable_and_uses_the_live_catalog() {
    assert!(HARDENER_SMOKE_SCRIPT.starts_with(
        "#!/usr/local/bin/av inject -- /bin/bash\n\
# --- automic-vault\n\
# capabilities:\n\
#   brew: trusted\n\
# ---\n"
    ));
    assert!(HARDENER_SMOKE_SCRIPT.contains(".hardeners[] | select(.applicable) | .name"));
}

#[test]
fn release_build_asserts_secret_custody_entitlements() {
    assert!(BUILD_SCRIPT.contains("PRIVATE_KEYCHAIN_ACCESS_GROUP=\"ZU76A67LGU.com.automicvault\""));
    assert!(
        BUILD_SCRIPT
            .contains("APPROVAL_KEYCHAIN_ACCESS_GROUP=\"ZU76A67LGU.com.automicvault.approval\"")
    );
    assert!(BUILD_SCRIPT.contains("assert_no_embedded_entitlements \"$ROOT/target/release/av\""));
    assert!(
        BUILD_SCRIPT.contains("assert_no_embedded_entitlements \"$ROOT/target/release/av-gpg\"")
    );
    assert!(
        BUILD_SCRIPT
            .contains("assert_no_embedded_entitlements \"$ROOT/target/release/av-brew-stub\"")
    );
    assert!(BUILD_SCRIPT.contains("assert_no_embedded_entitlements \"$MACOS/av\""));
    assert!(BUILD_SCRIPT.contains("assert_no_embedded_entitlements \"$MACOS/av-brew-stub\""));
    assert!(BUILD_SCRIPT.contains("assert_private_keychain_entitlement \"$APP\""));
    assert!(BUILD_SCRIPT.contains("menu bar app must not have a wildcard Keychain access group"));
    assert!(
        BUILD_SCRIPT
            .contains("menu bar app must have exactly its Secret and Approval Keychain groups")
    );
}

#[test]
fn macos_app_uses_its_violet_accent() {
    assert!(MENU_HELPER_INFO_PLIST.contains("<key>NSAccentColorName</key>"));
    assert!(MENU_HELPER_INFO_PLIST.contains("<string>AccentColor</string>"));
    for component in [
        "\"blue\" : \"0.915\"",
        "\"green\" : \"0.253\"",
        "\"red\" : \"0.609\"",
        "\"blue\" : \"0.972\"",
        "\"green\" : \"0.331\"",
        "\"red\" : \"0.665\"",
    ] {
        assert!(ACCENT_COLOR.contains(component));
    }
    assert!(ACCENT_COLOR.contains("\"appearance\" : \"luminosity\""));
    assert!(ACCENT_COLOR.contains("\"value\" : \"dark\""));
    assert!(BUILD_SCRIPT.contains("\"$MENU_HELPER/Resources/Assets.xcassets\""));
    assert!(BUILD_SCRIPT.contains("--accent-color AccentColor"));
}

#[test]
fn git_signing_adapter_is_hardened_and_bundled_without_a_privileged_install() {
    assert!(
        BUILD_SCRIPT
            .contains("--identifier com.automicvault.av-gpg \"$ROOT/target/release/av-gpg\"")
    );
    assert!(BUILD_SCRIPT.contains("cp \"$ROOT/target/release/av-gpg\" \"$MACOS/av-gpg\""));
    assert!(BUILD_SCRIPT.contains("codesign --verify --strict \"$MACOS/av-gpg\""));
    assert!(!INSTALL_SCRIPT.contains("Contents/MacOS/av-gpg"));
}

#[test]
fn proxy_helper_is_sandboxed_signed_inside_out_and_has_no_keychain_authority() {
    assert!(
        BUILD_SCRIPT
            .contains("cp \"$ROOT/target/release/av-proxy-helper\" \"$MACOS/av-proxy-helper\"")
    );
    assert!(BUILD_SCRIPT.contains("--identifier com.automicvault.av-proxy-helper"));
    assert!(BUILD_SCRIPT.contains("--entitlements \"$PROXY_HELPER_ENTITLEMENTS\""));
    assert!(
        BUILD_SCRIPT.contains("codesign_args=(--force --sign \"$identity\" --options runtime)")
    );
    let helper = BUILD_SCRIPT
        .find("--identifier com.automicvault.av-proxy-helper")
        .unwrap();
    let app = BUILD_SCRIPT
        .find("codesign \"${app_codesign_args[@]}\" \"$APP\"")
        .unwrap();
    assert!(helper < app);
    assert!(BUILD_SCRIPT.contains("codesign --verify --strict \"$MACOS/av-proxy-helper\""));
    assert!(
        BUILD_SCRIPT
            .contains("AV_PROXY_CONTROL=1 \"$MACOS/av-proxy-helper\" </dev/null >/dev/null 2>&1")
    );
    assert!(BUILD_SCRIPT.contains("proxy helper failed its launch probe"));
    assert!(!BUILD_SCRIPT.contains("codesign --verify --deep --strict \"$APP\""));

    for entitlement in [
        "com.apple.security.app-sandbox",
        "com.apple.security.network.client",
        "com.apple.security.network.server",
    ] {
        assert!(PROXY_HELPER_ENTITLEMENTS.contains(entitlement));
    }
    assert!(!PROXY_HELPER_ENTITLEMENTS.contains("keychain-access-groups"));
    assert!(!PROXY_HELPER_ENTITLEMENTS.contains("get-task-allow"));
    assert_eq!(PROXY_HELPER_ENTITLEMENTS.matches("<true/>").count(), 3);
}

#[test]
fn proxy_session_certificate_write_uses_supported_options() {
    assert!(!SECRET_PROXY.contains("options: [.atomic, .withoutOverwriting]"));
    assert!(SECRET_PROXY.contains("options: .withoutOverwriting"));
}

#[test]
fn release_actions_delegate_website_publication_to_the_local_script() {
    assert!(!RELEASE_WORKFLOW.contains("aws-actions/"));
    assert!(!RELEASE_WORKFLOW.contains("aws "));
    assert!(!RELEASE_WORKFLOW.contains("AWS_"));
    assert!(!RELEASE_WORKFLOW.contains("homebrew-isotopes"));
    assert!(!RELEASE_WORKFLOW.contains("HOMEBREW_TAP_TOKEN"));
    assert!(PUBLISH_SCRIPT.contains("release y/n?"));
    assert!(PUBLISH_SCRIPT.contains("read -r -s -n 1 -p"));
    assert!(PUBLISH_SCRIPT.contains("gh release edit"));
    assert!(PUBLISH_SCRIPT.contains("Update Automic Vault cask to $version"));
    assert!(PUBLISH_SCRIPT.contains("Homebrew tap main must match origin/main"));
    assert!(PUBLISH_SCRIPT.contains("publish_website_assets \"$head\""));
    assert!(PUBLISH_SCRIPT.contains("resume_published_release"));
    assert!(PUBLISH_SCRIPT.contains("Resuming local publication for immutable release"));
    assert!(PUBLISH_SCRIPT.contains("recovery requires an unmodified publish script"));
    assert!(PUBLISH_SCRIPT.contains("finish_publication \"$VERSION\" \"$head\" \"$release_url\""));
    assert!(PUBLISH_SCRIPT.contains("contains(Aliases.Items, '$WEBSITE_ALIAS')"));
    assert!(!PUBLISH_SCRIPT.contains("contains(join(',', Aliases.Items)"));
    assert!(PUBLISH_SCRIPT.contains("SCANNER_RUST_TOOLCHAIN=\"1.96.0\""));
    assert!(
        PUBLISH_SCRIPT.contains("exactly one Developer ID Application identity for ZU76A67LGU")
    );
    assert!(PUBLISH_SCRIPT.contains("git -C \"$ROOT\" archive \"$expected_head\""));
    assert!(PUBLISH_SCRIPT.contains("$source/scripts/build-scanner.sh"));
    assert!(PUBLISH_SCRIPT.contains("scanner release commit is invalid"));
    assert!(!PUBLISH_SCRIPT.contains("scanner must be built from the clean release commit"));
    assert!(!PUBLISH_SCRIPT.contains("--pattern scanner.tgz"));
    assert!(PUBLISH_SCRIPT.contains("$source/scripts/dist/install.sh"));
    assert!(PUBLISH_SCRIPT.contains("$source/scripts/dist/scanner.sh"));
    assert!(PUBLISH_SCRIPT.contains("s3://$WEBSITE_BUCKET/install.sh"));
    assert!(PUBLISH_SCRIPT.contains("s3://$WEBSITE_BUCKET/scanner.tgz"));
    assert!(PUBLISH_SCRIPT.contains("scanner archive has unexpected contents"));
    assert!(PUBLISH_SCRIPT.contains("codesign --verify --strict -R \"$requirement\" \"$scanner\""));
    assert!(RELEASE_WORKFLOW.contains("DMG_NAME: Automic-Vault-${{ inputs.version }}.dmg"));
    let build = PUBLISH_SCRIPT
        .find("$source/scripts/build-scanner.sh")
        .unwrap();
    let verify = PUBLISH_SCRIPT
        .find("codesign --verify --strict -R \"$requirement\" \"$scanner\"")
        .unwrap();
    let upload = PUBLISH_SCRIPT.find("aws s3 cp \"$archive\"").unwrap();
    assert!(build < verify && verify < upload);
    assert!(PUBLISH_SCRIPT.contains("RECOVERED_RELEASE=1"));
    assert!(PUBLISH_SCRIPT.contains("RESUMED_DRAFT=1"));
    assert!(PUBLISH_SCRIPT.contains("repos/$REPOSITORY/releases?per_page=100"));
    assert!(PUBLISH_SCRIPT.contains(r#"select(.tag_name == \"$REQUESTED_VERSION\")"#));
    assert!(PUBLISH_SCRIPT.contains("multiple GitHub releases exist for $REQUESTED_VERSION"));
    assert!(PUBLISH_SCRIPT.contains("Resuming draft release $VERSION."));
    assert!(PUBLISH_SCRIPT.contains("draft release $VERSION does not target a commit on main"));
    assert!(
        PUBLISH_SCRIPT
            .contains("git -C \"$ROOT\" merge-base --is-ancestor \"$DRAFT_HEAD\" origin/main")
    );
    assert!(PUBLISH_SCRIPT.contains("if [[ \"$RESUMED_DRAFT\" -eq 0 ]] && ! command -v codex"));
    assert!(!PUBLISH_SCRIPT.contains("if resume_published_release; then"));
    let resume = PUBLISH_SCRIPT
        .rfind("\nresume_published_release\n")
        .unwrap();
    let codex = PUBLISH_SCRIPT.rfind("command -v codex").unwrap();
    assert!(resume < codex);
    let resumed_draft = PUBLISH_SCRIPT
        .rfind("if [[ \"$RESUMED_DRAFT\" -eq 1 ]]")
        .unwrap();
    let generate = PUBLISH_SCRIPT
        .rfind("generate_release_metadata \"$source_head\"")
        .unwrap();
    assert!(resumed_draft < generate);
}

#[test]
fn publication_requires_the_previous_app_to_accept_the_draft() {
    let verify = PUBLISH_SCRIPT
        .find("verify_draft_update \"$VERSION\" \"$head\"")
        .unwrap();
    let prompt = PUBLISH_SCRIPT.find("release y/n?").unwrap();
    assert!(verify < prompt);
    assert!(PUBLISH_SCRIPT.contains("gh api \"repos/$REPOSITORY/releases?per_page=30\""));
    assert!(
        PUBLISH_SCRIPT.contains("tmp=\"$(mktemp -d \"$ROOT/target/av-update-preflight.XXXXXX\")\"")
    );
    assert!(PUBLISH_SCRIPT.contains("AVUpdatePreflightVersion"));
    assert!(PUBLISH_SCRIPT.contains("--verify-update \"$version\""));
    assert!(PUBLISH_SCRIPT.contains("APP_VERSION=\"$previous_version\""));
    assert!(
        PUBLISH_SCRIPT
            .contains("\"$previous_version\" == \"2.9.0\" || \"$previous_version\" == \"2.10.0\"")
    );
    assert!(PUBLISH_SCRIPT.contains("lacks the updater preflight"));
    assert!(PUBLISH_SCRIPT.contains("downloaded draft DMG does not match GitHub's digest"));
}

#[test]
fn publication_requires_the_draft_app_to_launch_on_macos_14() {
    let updater = PUBLISH_SCRIPT.find("--verify-update \"$version\"").unwrap();
    let launch = PUBLISH_SCRIPT
        .find("verify_macos_14_launch \"$candidate_dmg\" \"$version\"")
        .unwrap();
    let prompt = PUBLISH_SCRIPT.find("release y/n?").unwrap();
    assert!(updater < launch && launch < prompt);

    assert!(PUBLISH_SCRIPT.contains(
        "ghcr.io/cirruslabs/macos-sonoma-base@sha256:41a4a6eef68363b23f9cfcd520fce5db5523aa90e10c0db70e51974bcc7f058c"
    ));
    for requirement in [
        "tart exec --help",
        "--no-graphics",
        "--no-audio",
        "--no-clipboard",
        "--net-softnet-block=0.0.0.0/0",
        "--dir=\"release:$shared_dir:ro\"",
        "TART_NO_AUTO_PRUNE=1 tart clone",
        "SECONDS + 120",
        "/usr/bin/sw_vers -productVersion",
        "[[ \"$product_version\" != 14.* ]]",
        "open -n \"$app\"",
        "sleep 5",
        "kill -0 \"$app_pid\"",
        "tart stop \"$vm\" --timeout 10",
        "tart delete \"$vm\"",
    ] {
        assert!(
            PUBLISH_SCRIPT.contains(requirement),
            "missing {requirement}"
        );
    }
    assert!(PUBLISH_SCRIPT.contains("candidate_dir=\"$tmp/candidate\""));

    let tart = PUBLISH_SCRIPT.rfind("if ! command -v tart").unwrap();
    let release_commit = PUBLISH_SCRIPT
        .find("git -C \"$ROOT\" commit -m \"Release $VERSION\"")
        .unwrap();
    assert!(tart < release_commit);
}

#[test]
fn scanner_is_small_signed_and_read_only() {
    for setting in [
        "CARGO_PROFILE_RELEASE_OPT_LEVEL=z",
        "CARGO_PROFILE_RELEASE_LTO=fat",
        "CARGO_PROFILE_RELEASE_STRIP=symbols",
    ] {
        assert!(BUILD_SCANNER_SCRIPT.contains(setting));
    }
    assert!(BUILD_SCANNER_SCRIPT.contains("rustup run \"$SCANNER_RUST_TOOLCHAIN\" cargo"));
    assert!(SCANNER_SCRIPT.contains("https://www.automicvault.com/scanner.tgz"));
    assert!(SCANNER_SCRIPT.contains("--proto '=https'"));
    assert!(SCANNER_SCRIPT.contains("--proto-redir '=https'"));
    assert!(SCANNER_SCRIPT.contains("--tlsv1.2"));
    assert!(SCANNER_SCRIPT.contains("team_id=\"ZU76A67LGU\""));
    assert!(SCANNER_SCRIPT.contains("identifier=\"com.automicvault.scanner\""));
    assert!(SCANNER_SCRIPT.contains("certificate leaf[subject.OU] = \\\"$team_id\\\""));
    assert!(SCANNER_SCRIPT.contains("and identifier \\\"$identifier\\\""));
    assert!(SCANNER_SCRIPT.contains("(deny default)"));
    assert!(SCANNER_SCRIPT.contains("(allow file-read*)"));
    assert!(SCANNER_SCRIPT.contains("(allow process-info*)"));
    assert!(SCANNER_SCRIPT.contains("(allow sysctl-read)"));
    assert!(
        SCANNER_SCRIPT.find("codesign --verify").unwrap()
            < SCANNER_SCRIPT.rfind("/usr/bin/sandbox-exec").unwrap()
    );
    assert!(SCANNER_SCRIPT.contains("set +x"));
    assert!(SCANNER_SCRIPT.contains("set -x"));
    assert!(SCANNER_SCRIPT.find("set -x").unwrap() < SCANNER_SCRIPT.find("/usr/bin/curl").unwrap());
}

#[test]
fn website_installer_is_transparent_and_verifies_release() {
    assert!(INSTALL_SCRIPT.contains("https://automicvault.com/av.dmg"));
    assert!(INSTALL_SCRIPT.contains("set +x"));
    assert!(INSTALL_SCRIPT.contains("set -x"));
    assert!(INSTALL_SCRIPT.contains("/usr/sbin/spctl -a -vv --type exec \"$app\""));
    assert!(INSTALL_SCRIPT.contains("/usr/bin/codesign --verify --deep --strict \"$app\""));
    assert!(INSTALL_SCRIPT.contains("^TeamIdentifier=${team_id}$"));
    assert!(INSTALL_SCRIPT.contains("$app/Contents/MacOS/av"));
    assert!(INSTALL_SCRIPT.find("set -x").unwrap() < INSTALL_SCRIPT.find("/usr/bin/curl").unwrap());
}
