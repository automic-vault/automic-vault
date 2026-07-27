const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const BUILD_SCRIPT: &str = include_str!("../scripts/build.sh");
const NOTARIZE_SCRIPT: &str = include_str!("../scripts/build-notarize-dmg.sh");

#[test]
fn release_workflow_binds_the_dmg_to_reviewed_source() {
    assert!(RELEASE_WORKFLOW.contains("workflow_dispatch:"));
    assert!(RELEASE_WORKFLOW.contains("commit:"));
    assert!(RELEASE_WORKFLOW.contains("refs/heads/main"));
    assert!(RELEASE_WORKFLOW.contains("IMMUTABLE_RELEASES_ENABLED"));
    assert!(RELEASE_WORKFLOW.contains("--target \"$GITHUB_SHA\""));
    assert!(RELEASE_WORKFLOW.contains("targetCommitish"));
    assert!(RELEASE_WORKFLOW.contains("actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6"));
    assert_eq!(RELEASE_WORKFLOW.matches("uses: actions/attest@").count(), 2);
    assert!(RELEASE_WORKFLOW.contains("sbom-path:"));
    assert!(RELEASE_WORKFLOW.contains("SHA256SUMS"));
    assert!(RELEASE_WORKFLOW.contains("RUST_TOOLCHAIN: 1.96.0"));
    assert!(
        RELEASE_WORKFLOW
            .contains("c50d2bc97c3d6292642bac55f530d247eaf4bf65ee605f26b4caf339383e381c")
    );
}

#[test]
fn release_assets_are_immutable_and_never_replaced() {
    assert!(RELEASE_WORKFLOW.contains("--draft"));
    assert!(BUILD_SCRIPT.contains(".immutable"));
    assert!(RELEASE_WORKFLOW.contains("Release $VERSION already exists; publish a new version."));
    assert!(!RELEASE_WORKFLOW.contains("--clobber"));
    assert!(BUILD_SCRIPT.contains("--publish"));
    assert!(!BUILD_SCRIPT.contains("--clobber"));
    assert!(!BUILD_SCRIPT.contains("gh release create"));
    assert!(!BUILD_SCRIPT.contains("aws s3"));
}

#[test]
fn release_builds_are_actions_only_and_fail_closed() {
    assert!(BUILD_SCRIPT.starts_with(
        "#!/usr/local/bin/av inject --allow-missing-keys +APPLE_PASSWORD -- /bin/bash\n\
# --- automic-vault\n\
# capabilities:\n\
#   gh: trusted\n\
# ---\n"
    ));
    assert!(
        RELEASE_WORKFLOW
            .contains("run: /bin/bash scripts/build.sh --release-artifact --version \"$VERSION\"")
    );
    assert!(BUILD_SCRIPT.contains("--release-artifact"));
    assert!(BUILD_SCRIPT.contains("release artifacts may only be built by GitHub Actions"));
    assert!(BUILD_SCRIPT.contains("release checkout does not match GITHUB_SHA"));
    assert!(BUILD_SCRIPT.contains("cargo build --release --locked"));
    assert!(BUILD_SCRIPT.contains("--disable-automatic-resolution"));
    assert!(BUILD_SCRIPT.contains("requires a Developer ID Application identity"));
    assert!(BUILD_SCRIPT.contains("requires the Developer ID provisioning profile"));
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
fn publication_is_local_and_release_actions_need_no_aws() {
    assert!(!RELEASE_WORKFLOW.contains("aws-actions/"));
    assert!(!RELEASE_WORKFLOW.contains("aws "));
    assert!(!RELEASE_WORKFLOW.contains("AWS_"));
    assert!(!RELEASE_WORKFLOW.contains("homebrew-isotopes"));
    assert!(!RELEASE_WORKFLOW.contains("HOMEBREW_TAP_TOKEN"));
    assert!(BUILD_SCRIPT.contains("release y/n?"));
    assert!(BUILD_SCRIPT.contains("gh release edit"));
    assert!(BUILD_SCRIPT.contains("Update Automic Vault cask to $version"));
    assert!(BUILD_SCRIPT.contains("Homebrew tap main must match origin/main"));
    assert!(RELEASE_WORKFLOW.contains("DMG_NAME: Automic-Vault-${{ inputs.version }}.dmg"));
}
