const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const BUILD_SCRIPT: &str = include_str!("../scripts/build.sh");
const NOTARIZE_SCRIPT: &str = include_str!("../scripts/build-notarize-dmg.sh");

#[test]
fn release_workflow_binds_the_dmg_to_reviewed_source() {
    assert!(RELEASE_WORKFLOW.contains("workflow_dispatch:"));
    assert!(RELEASE_WORKFLOW.contains("refs/heads/main"));
    assert!(RELEASE_WORKFLOW.contains("IMMUTABLE_RELEASES_ENABLED"));
    assert!(RELEASE_WORKFLOW.contains("--target \"$GITHUB_SHA\""));
    assert!(RELEASE_WORKFLOW.contains(".target_commitish"));
    assert!(RELEASE_WORKFLOW.contains("actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6"));
    assert_eq!(RELEASE_WORKFLOW.matches("uses: actions/attest@").count(), 2);
    assert!(RELEASE_WORKFLOW.contains("sbom-path:"));
    assert!(RELEASE_WORKFLOW.contains("SHA256SUMS"));
    assert!(RELEASE_WORKFLOW.contains("--signer-workflow"));
    assert!(RELEASE_WORKFLOW.contains("--source-digest \"$GITHUB_SHA\""));
    assert!(RELEASE_WORKFLOW.contains("RUST_TOOLCHAIN: 1.96.0"));
    assert!(
        RELEASE_WORKFLOW
            .contains("c50d2bc97c3d6292642bac55f530d247eaf4bf65ee605f26b4caf339383e381c")
    );
}

#[test]
fn release_assets_are_immutable_and_never_replaced() {
    assert!(RELEASE_WORKFLOW.contains("Published release is not immutable."));
    assert!(RELEASE_WORKFLOW.contains("Release $VERSION already exists; publish a new version."));
    assert!(!RELEASE_WORKFLOW.contains("--clobber"));
    assert!(!BUILD_SCRIPT.contains("--publish"));
    assert!(!BUILD_SCRIPT.contains("--clobber"));
    assert!(!BUILD_SCRIPT.contains("gh release"));
    assert!(!BUILD_SCRIPT.contains("aws s3"));
}

#[test]
fn release_builds_are_actions_only_and_fail_closed() {
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
}

#[test]
fn website_receives_the_attested_release_bytes() {
    assert!(RELEASE_WORKFLOW.contains("gh attestation verify"));
    assert!(RELEASE_WORKFLOW.contains("Downloaded release asset digest does not match GitHub."));
    assert!(RELEASE_WORKFLOW.contains("S3 checksum does not match the attested release asset."));
    assert!(RELEASE_WORKFLOW.contains(
        "aws-actions/configure-aws-credentials@61815dcd50bd041e203e49132bacad1fd04d2708"
    ));
    assert!(RELEASE_WORKFLOW.contains("--checksum-algorithm SHA256"));
}
