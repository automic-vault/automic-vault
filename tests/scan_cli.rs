use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn av_scan_reports_clean_home() {
    let home = temp_home("clean");
    let output = av_scan(&home);

    assert!(output.status.success());
    let stdout = stdout(&output);
    assert!(stdout.starts_with("╭─ system exposure audit\n│\n"));
    assert!(!stdout.contains("GUI PATH"));
    assert!(stdout.contains("◇ No problems found\n"));
    assert!(stdout.ends_with("╰─ vault sealed\n"));
    assert_eq!(stderr(&output), "");

    let _ = fs::remove_dir_all(home);
}

#[test]
fn av_scan_reports_findings() {
    let home = temp_home("triggered");
    fs::write(
        home.join(".git-credentials"),
        "https://user:token@example.com\n",
    )
    .unwrap();

    let output = av_scan(&home);
    let stdout = stdout(&output);

    assert!(output.status.success());
    assert!(stdout.contains("│  solution\n"));
    assert!(stdout.contains("│  Remove credentials from the reported files"));
    assert!(!stdout.contains("│  homepage\n"));
    assert!(stdout.contains("│  full details & caveats\n"));
    assert!(!stdout.contains("│  read more\n"));
    assert!(stdout.contains(".git-credentials"));
    assert!(stdout.contains("│  affected files\n"));
    assert!(stdout.contains("╰─ scan complete\n"));
    for line in stdout.lines().filter(|line| !line.is_empty()) {
        assert!(
            line.starts_with('╭')
                || line.starts_with('◆')
                || line.starts_with('◇')
                || line.starts_with('└')
                || line.starts_with('├')
                || line.starts_with('╰')
                || line.starts_with('│'),
            "{line}"
        );
        if !line.starts_with("│  https://") {
            assert!(line.chars().count() <= 78, "{line}");
        }
    }
    assert_eq!(stderr(&output), "");

    let _ = fs::remove_dir_all(home);
}

#[test]
fn av_scan_json_reports_findings() {
    let home = temp_home("json");
    fs::write(
        home.join(".git-credentials"),
        "https://user:token@example.com\n",
    )
    .unwrap();

    let output = av_scan_json(&home);
    let stdout = stdout(&output);

    assert!(output.status.success());
    assert!(stdout.starts_with(r#"{"findings":[{"#));
    assert!(!stdout.contains(r#""gui_path""#));
    assert!(stdout.contains(r#""source":"git-credentials-file""#));
    assert!(stdout.contains(".git-credentials"));
    assert_eq!(stderr(&output), "");

    let _ = fs::remove_dir_all(home);
}

#[test]
fn av_scan_json_can_run_one_detector() {
    let home = temp_home("targeted-json");
    fs::write(
        home.join(".git-credentials"),
        "https://user:token@example.com\n",
    )
    .unwrap();
    fs::write(home.join(".npmrc"), "min-release-age=0\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_av"))
        .args(["scan", "--json", "--detector", "git-credentials-file"])
        .env("HOME", &home)
        .output()
        .unwrap();
    let stdout = stdout(&output);

    assert!(output.status.success());
    assert!(stdout.contains(r#""source":"git-credentials-file""#));
    assert!(stdout.contains(r#""detectors":["git-credentials-file"]"#));
    assert!(!stdout.contains(r#""source":"npm""#));
    assert_eq!(stderr(&output), "");

    let _ = fs::remove_dir_all(home);
}

#[test]
fn av_scan_git_credential_fill_does_not_invoke_configured_helpers() {
    let home = temp_home("git-credential-fill-passive");
    let marker = home.join("helper-invoked");
    let helper = home.join("credential-helper");
    fs::write(
        &helper,
        format!("#!/bin/sh\nprintf invoked > {}\n", marker.display()),
    )
    .unwrap();
    let mut permissions = fs::metadata(&helper).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&helper, permissions).unwrap();
    fs::write(
        home.join(".gitconfig"),
        format!(
            "[credential \"https://github.com\"]\nhelper =\nhelper = !{}\n",
            helper.display()
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_av"))
        .args(["scan", "--json", "--detector", "git-credential-fill"])
        .current_dir(&home)
        .env_clear()
        .env("HOME", &home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .output()
        .unwrap();
    let stdout = stdout(&output);
    let helper_was_invoked = marker.exists();
    let _ = fs::remove_dir_all(home);

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout.contains(r#""source":"git-credential-fill""#));
    assert!(stdout.contains("ambient credential helper"));
    assert!(stdout.contains(r#""line":3"#));
    assert!(
        !helper_was_invoked,
        "av scan invoked a configured Git credential helper"
    );
}

#[test]
fn av_scan_json_rejects_an_unknown_detector() {
    let home = temp_home("unknown-detector");
    let output = Command::new(env!("CARGO_BIN_EXE_av"))
        .args(["scan", "--json", "--detector", "not-a-detector"])
        .env("HOME", &home)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("unknown detector: not-a-detector"));

    let _ = fs::remove_dir_all(home);
}

fn av_scan(home: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_av"))
        .arg("scan")
        .env_clear()
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "AUTOMIC_VAULT_TEST_BREW_TARGET",
            home.join("missing-opt-homebrew/bin/brew"),
        )
        .env(
            "AUTOMIC_VAULT_TEST_SIP_STATUS",
            "System Integrity Protection status: enabled.",
        )
        .env("AUTOMIC_VAULT_DISABLE_SUDO_DETECTOR", "1")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .output()
        .unwrap()
}

fn av_scan_json(home: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_av"))
        .args(["scan", "--json"])
        .env_clear()
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "AUTOMIC_VAULT_TEST_BREW_TARGET",
            home.join("missing-opt-homebrew/bin/brew"),
        )
        .env(
            "AUTOMIC_VAULT_TEST_SIP_STATUS",
            "System Integrity Protection status: enabled.",
        )
        .env("AUTOMIC_VAULT_DISABLE_SUDO_DETECTOR", "1")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn temp_home(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("av-cli-{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path).unwrap();
    path
}
