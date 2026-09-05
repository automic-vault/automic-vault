use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const LEGACY_AWS_STUB: &str = include_str!("../src/isotopes/hardeners/aws.legacy");
const HOMEBREW_AWS_STUB: &str = include_str!("../src/isotopes/hardeners/aws.homebrew");

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
fn av_doctor_reports_a_target_occupying_its_reserved_launcher_path() {
    let root = temp_dir();
    let stubs = root.join("stubs");
    fs::create_dir_all(&stubs).unwrap();
    let sentry_cli = stubs.join("sentry-cli");
    executable(&sentry_cli);

    let output = av(&root)
        .args(["doctor", "sentry-cli", "--json"])
        .env("PATH", &stubs)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let issues = report["results"][0]["issues"].as_array().unwrap();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0]["kind"], "target_at_launcher_path");
    assert_eq!(issues[0]["stub_path"], sentry_cli.display().to_string());
    assert_eq!(issues[0]["resolved_path"], sentry_cli.display().to_string());
    let remediation = issues[0]["remediation"].as_str().unwrap();
    assert!(remediation.contains("Review and preserve the executable"));
    assert!(remediation.contains("leaving"));
    assert!(!remediation.contains("exec sentry-cli"));

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
