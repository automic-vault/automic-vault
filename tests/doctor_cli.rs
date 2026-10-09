use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const LEGACY_AWS_STUB: &str = include_str!("../src/isotopes/hardeners/aws.legacy");
const HOMEBREW_AWS_STUB: &str = include_str!("../src/isotopes/hardeners/aws.homebrew");

#[test]
fn gh_doctor_reports_missing_global_routing_for_an_installed_isotope() {
    let root = gh_fixture();
    let output = gh_doctor(&root).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let issue = gh_git_issue(&output).expect("installed gh must diagnose missing Git routing");
    assert_eq!(
        issue["message"],
        "GitHub HTTPS operations are not globally routed through Automic Vault"
    );
    assert_gh_git_repair(&issue);
    assert!(!root.join("home/.gitconfig").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn gh_doctor_reports_unavailable_transport_and_respects_manual_setup() {
    let root = gh_fixture();
    let config = root.join("home/.gitconfig");
    let routing = "[url \"av::https://github.com/\"]\n insteadOf = https://github.com/\n";
    fs::write(&config, routing).unwrap();
    // PATH contains only the fixture gh, so the protected adapter is unavailable.
    // Machines without the signed CLI/runtime may report that earlier failure.
    let output = gh_doctor(&root).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let issue = gh_git_issue(&output).expect("a route without usable transport needs repair");
    assert!(!issue["message"].as_str().unwrap().is_empty());
    assert!(
        !issue["message"]
            .as_str()
            .unwrap()
            .contains("not globally routed")
    );
    assert_gh_git_repair(&issue);

    fs::write(root.join("gh/av-git-configuration"), "manual\n").unwrap();
    let manual = gh_doctor(&root).output().unwrap();
    assert!(
        gh_git_issue(&manual).is_none(),
        "manual setup must suppress Git repair diagnostics"
    );
    assert_eq!(fs::read_to_string(config).unwrap(), routing);
    fs::remove_dir_all(root).unwrap();
}

fn gh_fixture() -> PathBuf {
    let root = temp_dir();
    for directory in ["home", "bin", "gh"] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    executable(&root.join("bin/gh"));
    root
}

fn gh_doctor(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_av"));
    command
        .env_clear()
        .args(["doctor", "gh", "--json"])
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("home/.config"))
        .env("GH_CONFIG_DIR", root.join("gh"))
        .env("PATH", root.join("bin"))
        .env("AUTOMIC_VAULT_TEST_GH_CLI_PATH", root.join("bin/gh"))
        .current_dir(root.join("home"));
    command
}

fn gh_git_issue(output: &Output) -> Option<serde_json::Value> {
    assert!(output.stderr.is_empty(), "{}", stderr(output));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["results"][0]["name"], "gh");
    report["results"][0]["issues"]
        .as_array()
        .unwrap()
        .iter()
        .find(|issue| issue["kind"] == "gh_git_configuration")
        .cloned()
}

fn assert_gh_git_repair(issue: &serde_json::Value) {
    let remediation = issue["remediation"].as_str().unwrap();
    assert!(remediation.contains("Run `av harden gh`"));
    assert!(remediation.contains("av harden gh --without-git-configuration"));
}

#[test]
fn av_doctor_omits_unhardened_tools_and_reports_hardened_stubs() {
    let root = temp_dir();
    let targets = root.join("targets");
    let stubs = root.join("stubs");
    fs::create_dir_all(&targets).unwrap();
    fs::create_dir_all(&stubs).unwrap();
    executable(&targets.join("npm"));

    let aggregate = av(&root).args(["doctor", "--json"]).output().unwrap();
    let aggregate: serde_json::Value = serde_json::from_slice(&aggregate.stdout).unwrap();
    assert!(
        aggregate["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|result| result["name"] != "node")
    );

    let harden = av(&root)
        .args(["harden", "node", "--yes"])
        .output()
        .unwrap();
    assert!(harden.status.success(), "{}", stderr(&harden));

    let healthy = av(&root)
        .args(["doctor", "npm", "--json"])
        .env("PATH", std::env::join_paths([&stubs, &targets]).unwrap())
        .output()
        .unwrap();
    assert!(healthy.status.success(), "{}", stderr(&healthy));
    let healthy: serde_json::Value = serde_json::from_slice(&healthy.stdout).unwrap();
    assert_eq!(healthy["results"][0]["name"], "node");
    assert_eq!(healthy["results"][0]["commands"][0], "npm");
    assert_eq!(healthy["results"][0]["issues"].as_array().unwrap().len(), 0);

    let shadowed = av(&root)
        .args(["doctor", "npm", "--json"])
        .env("PATH", std::env::join_paths([&targets, &stubs]).unwrap())
        .output()
        .unwrap();
    assert_eq!(shadowed.status.code(), Some(1));
    let shadowed: serde_json::Value = serde_json::from_slice(&shadowed.stdout).unwrap();
    assert_eq!(
        shadowed["results"][0]["issues"][0]["kind"],
        "stub_not_first_on_path"
    );
    assert_eq!(
        shadowed["results"][0]["issues"][0]["resolved_path"],
        targets.join("npm").display().to_string()
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn av_doctor_rejects_unknown_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_av"))
        .args(["doctor", "definitely-not-a-hardener"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stderr(&output),
        "av doctor: unknown command `definitely-not-a-hardener`\n"
    );
}

#[test]
fn av_doctor_reports_unsigned_agent_clis() {
    let root = temp_dir();
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    executable(&bin.join("codex"));

    let output = av(&root)
        .args(["doctor", "codex", "--json"])
        .env("PATH", &bin)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["results"][0]["name"], "codex");
    assert_eq!(
        report["results"][0]["issues"][0]["kind"],
        "agent_cli_signature_invalid"
    );
    assert_eq!(
        report["results"][0]["issues"][0]["resolved_path"],
        bin.join("codex").display().to_string()
    );
    assert!(
        report["results"][0]["issues"][0]["remediation"]
            .as_str()
            .unwrap()
            .contains("OpenAI's standalone installer or the Homebrew cask")
    );

    let aggregate = av(&root)
        .args(["doctor", "--json"])
        .env("PATH", &bin)
        .output()
        .unwrap();
    assert_eq!(aggregate.status.code(), Some(1));
    let aggregate: serde_json::Value = serde_json::from_slice(&aggregate.stdout).unwrap();
    assert!(
        aggregate["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|result| {
                result["name"] == "codex"
                    && result["issues"][0]["kind"] == "agent_cli_signature_invalid"
            })
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn av_doctor_requires_rehardening_for_each_exact_legacy_aws_launcher() {
    for launcher in [LEGACY_AWS_STUB, HOMEBREW_AWS_STUB] {
        assert_aws_rehardening_required(launcher);
    }
}

fn assert_aws_rehardening_required(launcher: &str) {
    let root = temp_dir();
    let stub = root.join("aws");
    fs::create_dir_all(&root).unwrap();
    fs::write(&stub, launcher).unwrap();
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_av"))
        .args(["doctor", "aws", "--json"])
        .env("AUTOMIC_VAULT_TEST_AWS_STUB_PATH", &stub)
        .env("PATH", &root)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let issue = report["results"][0]["issues"]
        .as_array()
        .unwrap()
        .iter()
        .find(|issue| issue["kind"] == "stub_upgrade_required")
        .unwrap();
    let remediation = issue["remediation"].as_str().unwrap();
    assert!(!remediation.contains("waiting"));
    assert!(remediation.contains("Run `av harden aws`"));

    let _ = fs::remove_dir_all(root);
}

fn av(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_av"));
    command.env(
        "AUTOMIC_VAULT_TEST_ENV_WRAPPER_TARGET_DIR",
        root.join("targets"),
    );
    command.env(
        "AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR",
        root.join("stubs"),
    );
    command.env("AUTOMIC_VAULT_TEST_EUID", "0");
    command.env("HOME", root.join("home"));
    command.env_remove("NPM_CONFIG_USERCONFIG");
    command
}

fn executable(path: &Path) {
    fs::write(path, "#!/bin/sh\n").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn temp_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("av-doctor-cli-{nanos}"))
}
