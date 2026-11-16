#![cfg(target_os = "macos")]

use std::process::Command;

#[test]
fn deprecated_transport_entry_points_warn_on_stderr_without_protocol_output() {
    for args in [vec!["git"], vec!["__git-remote", "origin", "invalid-url"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_av"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("Git HTTPS transport is deprecated"));
        assert!(stderr.contains("SSH agent"));
    }
}

#[test]
fn retired_runtime_installer_refuses_before_inspecting_sources() {
    for args in [
        vec!["__install-git-runtime"],
        vec![
            "__install-git-runtime",
            "/missing/git",
            "/missing/https",
            "/missing/gh",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_av"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("installation is disabled"));
        assert!(stderr.contains("deprecated"));
    }
}
