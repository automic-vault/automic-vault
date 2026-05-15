use std::process::{Command, Output};
use std::{fs, path::PathBuf};

#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn pkg_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn run_nuke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_av"))
        .args(args)
        .output()
        .unwrap()
}

fn run_nuke_with_columns(args: &[&str], columns: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_av"))
        .env("COLUMNS", columns)
        .args(args)
        .output()
        .unwrap()
}

fn run_nuke_with_env(args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_av"));
    command.args(args);
    command.env_remove("NO_COLOR");
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().unwrap()
}

fn run_nuke_with_forced_color(args: &[&str], columns: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_av"))
        .env("CLICOLOR_FORCE", "1")
        .env_remove("NO_COLOR")
        .env("COLUMNS", columns)
        .args(args)
        .output()
        .unwrap()
}

fn write_fake_trace_agent(bin_dir: &std::path::Path, name: &str, response: &str) {
    fs::create_dir_all(bin_dir).unwrap();
    let path = bin_dir.join(name);
    fs::write(
        &path,
        format!("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{}'\n", response),
    )
    .unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn debug_opt_root() -> PathBuf {
    PathBuf::from("/tmp/opt")
}

fn write_test_receipt(package_name: &str, version: &str, source: serde_json::Value) -> PathBuf {
    let root = debug_opt_root().join(package_name);
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    fs::create_dir_all(root.join(".pkg")).unwrap();
    fs::write(
        root.join(".pkg/root-receipt.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "package_name": package_name,
            "version": version,
            "source": source,
            "metadata": {},
        }))
        .unwrap(),
    )
    .unwrap();
    root
}

struct PackageRootGuard {
    root: PathBuf,
}

impl PackageRootGuard {
    fn install(package_name: &str, version: &str, source: serde_json::Value) -> Self {
        Self {
            root: write_test_receipt(package_name, version, source),
        }
    }
}

impl Drop for PackageRootGuard {
    fn drop(&mut self) {
        if self.root.exists() {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }
}

#[test]
fn subs_top_level_cli_paths_cover_help_version_and_unknown_subcommands() {
    let output = run_nuke(&[]);
    assert!(!output.status.success());
    assert!(stdout(&output).contains("USAGE"));
    assert!(stdout(&output).contains("av <subcommand> [args...]"));
    assert!(stderr(&output).contains("av: missing subcommand"));

    let output = run_nuke_with_columns(&["--help"], "140");
    assert!(output.status.success());
    assert!(stdout(&output).contains("PACKAGE SYSTEM"));
    assert!(stdout(&output).contains("▪ PACKAGE SYSTEM"));
    assert!(stdout(&output).contains("install (i)"));
    assert!(stdout(&output).contains("list (ls)"));
    assert!(stdout(&output).contains("scan"));
    assert!(stdout(&output).contains("trace"));
    assert!(!stdout(&output).contains("secret-scanner"));
    assert!(stdout(&output).contains("─"));
    assert!(stdout(&output).contains("LEGEND"));

    let output = run_nuke_with_columns(&["--help"], "90");
    assert!(output.status.success());
    assert!(stdout(&output).starts_with("────────────────"));
    assert!(!stdout(&output).contains("LEGEND"));

    let output = run_nuke_with_forced_color(&["--help"], "90");
    let colored_stdout = stdout(&output);
    assert!(output.status.success());
    assert!(!colored_stdout.contains("\x1b[38;2;214;198;165m"));
    assert!(colored_stdout.contains("\x1b[2m"));
    assert!(colored_stdout.contains("\x1b[38;2;224;90;71m"));

    let output = run_nuke(&["--version"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains(&format!("av {}", pkg_version())));

    let output = run_nuke(&["help", "update"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av update"));

    let output = run_nuke(&["help", "i"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av i"));

    let output = run_nuke(&["help", "uninstall"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av uninstall"));

    let output = run_nuke(&["help", "outdated"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av outdated"));

    let output = run_nuke(&["help", "list"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av list"));

    let output = run_nuke(&["help", "info"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av info"));

    let output = run_nuke(&["help", "search"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av search"));

    let output = run_nuke(&["help", "scan"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av scan"));

    let output = run_nuke(&["help", "trace"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av trace"));

    let output = run_nuke(&["help", "secret-scanner"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av scan"));

    let output = run_nuke(&["help", "serve"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av serve"));

    let output = run_nuke(&["help", "inject"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av inject"));

    let output = run_nuke(&["help", "save"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av save"));

    let output = run_nuke(&["help", "gate"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av gate"));

    let output = run_nuke(&["help", "contain"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av contain"));

    let output = run_nuke(&["wat"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("av: unknown subcommand 'wat'"));

    let output = run_nuke(&["x"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("av: unknown subcommand 'x'"));

    let output = run_nuke(&["run"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("av: unknown subcommand 'run'"));
}

#[test]
fn subs_gate_cli_covers_help_version_and_parse_errors() {
    let output = run_nuke(&["gate", "--help"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av gate"));

    let output = run_nuke(&["gate", "--version"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains(&format!("av gate {}", pkg_version())));

    let output = run_nuke(&["gate"]);
    assert!(!output.status.success());
    assert!(stdout(&output).contains("Usage: av gate"));
    assert!(stderr(&output).contains("missing gate message"));

    let output = run_nuke(&["gate", "   "]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("empty gate message"));

    let output = run_nuke(&["gate", "approve", "extra"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("single gate message"));
}

#[test]
fn subs_subcommand_parsing_covers_help_version_and_non_root_failures() {
    let version = pkg_version();
    let cases = [
        (vec!["i", "--help"], true, "Usage: av i".to_string()),
        (vec!["i", "--version"], true, format!("av i {version}")),
        (
            vec!["update", "--help"],
            true,
            "Usage: av update".to_string(),
        ),
        (
            vec!["update", "--version"],
            true,
            format!("av update {version}"),
        ),
        (vec!["list", "--help"], true, "Usage: av list".to_string()),
        (
            vec!["list", "--version"],
            true,
            format!("av list {version}"),
        ),
        (vec!["scan", "--help"], true, "Usage: av scan".to_string()),
        (
            vec!["scan", "--version"],
            true,
            format!("av scan {version}"),
        ),
        (
            vec!["secret-scanner", "--version"],
            true,
            format!("av scan {version}"),
        ),
        (vec!["trace", "--help"], true, "Usage: av trace".to_string()),
        (
            vec!["trace", "--version"],
            true,
            format!("av trace {version}"),
        ),
        (vec!["info", "--help"], true, "Usage: av info".to_string()),
        (
            vec!["info", "--version"],
            true,
            format!("av info {version}"),
        ),
        (
            vec!["outdated", "--help"],
            true,
            "Usage: av outdated".to_string(),
        ),
        (
            vec!["outdated", "--version"],
            true,
            format!("av outdated {version}"),
        ),
        (
            vec!["uninstall", "--help"],
            true,
            "Usage: av uninstall".to_string(),
        ),
        (
            vec!["uninstall", "--version"],
            true,
            format!("av uninstall {version}"),
        ),
    ];

    for (args, success, needle) in cases {
        let output = run_nuke(&args);
        let stdout = stdout(&output);
        assert_eq!(output.status.success(), success, "{args:?}");
        assert!(stdout.contains(&needle), "{args:?}: {stdout}");
    }

    let output = run_nuke(&["info"]);
    assert!(!output.status.success());
    assert!(stdout(&output).contains("Usage: av info"));
    assert!(stderr(&output).contains("av: missing package name"));

    if !cfg!(debug_assertions) && unsafe { libc::geteuid() } != 0 {
        let output = run_nuke(&["i", "bun"]);
        assert!(!output.status.success());
        assert!(stderr(&output).contains("av: must be run as root"));

        let output = run_nuke(&["update"]);
        assert!(!output.status.success());
        assert!(stderr(&output).contains("av: must be run as root"));
    }
}

#[test]
fn subs_query_commands_cover_success_and_output_modes() {
    let output = run_nuke(&["search", "rg"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("ripgrep"));

    let output = run_nuke(&["search", "--json", "rg"]);
    assert!(output.status.success());
    let search: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(search.as_array().unwrap().iter().any(|package| {
        package["package_name"] == "ripgrep" || package["package_name"] == "rg"
    }));

    let output = run_nuke(&["search", "rg", "--jsonl"]);
    assert!(output.status.success());
    assert!(
        stdout(&output)
            .lines()
            .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())
    );

    let output = run_nuke(&["info", "--json", "rg"]);
    assert!(output.status.success());
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(info["package_name"] == "ripgrep" || info["package_name"] == "rg");

    let output = run_nuke(&["info", "rg", "--jsonl"]);
    assert!(output.status.success());
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(info["package_name"] == "ripgrep" || info["package_name"] == "rg");

    let output = run_nuke(&["info", "rg"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("ripgrep"));
    assert!(stdout(&output).contains("Installed"));

    let output = run_nuke(&["list", "--json"]);
    assert!(output.status.success());
    serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap();

    let output = run_nuke(&["list", "--jsonl"]);
    assert!(output.status.success());
    assert!(
        stdout(&output)
            .lines()
            .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())
    );

    let temp = std::env::temp_dir().join(format!("av-secret-scanner-cli-{}", std::process::id()));
    if temp.exists() {
        fs::remove_dir_all(&temp).unwrap();
    }
    let home = temp.join("home");
    let scan = temp.join("scan");
    let aws_credentials = home.join(".aws/credentials");
    let kubeconfig = temp.join("kubeconfig");
    let npm_config = temp.join("empty-npmrc");
    let uv_credentials_dir = temp.join("uv");
    let cargo_home = temp.join("cargo");
    let caroot = temp.join("mkcert");
    let helm_config_home = temp.join("helm");
    let helm_repository_config = temp.join("repositories.yaml");
    fs::create_dir_all(aws_credentials.parent().unwrap()).unwrap();
    fs::create_dir_all(&scan).unwrap();
    fs::create_dir_all(&uv_credentials_dir).unwrap();
    fs::write(&aws_credentials, "").unwrap();
    fs::write(&kubeconfig, "").unwrap();
    fs::write(&npm_config, "").unwrap();
    fs::write(scan.join(".env"), "SERVICE_TOKEN=secret_secret\n").unwrap();

    let output = run_nuke_with_env(
        &["scan", "--path", scan.to_str().unwrap(), "--json"],
        &[
            ("HOME", home.to_str().unwrap()),
            (
                "AWS_SHARED_CREDENTIALS_FILE",
                aws_credentials.to_str().unwrap(),
            ),
            ("CARGO_HOME", cargo_home.to_str().unwrap()),
            ("CAROOT", caroot.to_str().unwrap()),
            ("HELM_CONFIG_HOME", helm_config_home.to_str().unwrap()),
            (
                "HELM_REPOSITORY_CONFIG",
                helm_repository_config.to_str().unwrap(),
            ),
            ("KUBECONFIG", kubeconfig.to_str().unwrap()),
            ("NPM_CONFIG_USERCONFIG", npm_config.to_str().unwrap()),
            ("UV_CREDENTIALS_DIR", uv_credentials_dir.to_str().unwrap()),
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["findings"], 1);
    assert_eq!(report["findings"][0]["source"], "file-probe");

    let output = run_nuke_with_env(
        &[
            "secret-scanner",
            "--path",
            scan.to_str().unwrap(),
            "--jsonl",
        ],
        &[
            ("HOME", home.to_str().unwrap()),
            (
                "AWS_SHARED_CREDENTIALS_FILE",
                aws_credentials.to_str().unwrap(),
            ),
            ("CARGO_HOME", cargo_home.to_str().unwrap()),
            ("CAROOT", caroot.to_str().unwrap()),
            ("HELM_CONFIG_HOME", helm_config_home.to_str().unwrap()),
            (
                "HELM_REPOSITORY_CONFIG",
                helm_repository_config.to_str().unwrap(),
            ),
            ("KUBECONFIG", kubeconfig.to_str().unwrap()),
            ("NPM_CONFIG_USERCONFIG", npm_config.to_str().unwrap()),
            ("UV_CREDENTIALS_DIR", uv_credentials_dir.to_str().unwrap()),
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output)
            .lines()
            .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())
    );

    let output = run_nuke_with_env(
        &["scan", "--path", scan.to_str().unwrap()],
        &[
            ("HOME", home.to_str().unwrap()),
            (
                "AWS_SHARED_CREDENTIALS_FILE",
                aws_credentials.to_str().unwrap(),
            ),
            ("CARGO_HOME", cargo_home.to_str().unwrap()),
            ("CAROOT", caroot.to_str().unwrap()),
            ("HELM_CONFIG_HOME", helm_config_home.to_str().unwrap()),
            (
                "HELM_REPOSITORY_CONFIG",
                helm_repository_config.to_str().unwrap(),
            ),
            ("KUBECONFIG", kubeconfig.to_str().unwrap()),
            ("NPM_CONFIG_USERCONFIG", npm_config.to_str().unwrap()),
            ("UV_CREDENTIALS_DIR", uv_credentials_dir.to_str().unwrap()),
        ],
    );
    let plain_stdout = stdout(&output);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(plain_stdout.contains("Automic Vault scan"));
    assert!(plain_stdout.contains("Findings:"));
    assert!(!plain_stdout.contains("\x1b["));
    assert!(!plain_stdout.contains("╭"));

    let output = run_nuke_with_env(
        &["scan", "--path", scan.to_str().unwrap()],
        &[
            ("CLICOLOR_FORCE", "1"),
            ("HOME", home.to_str().unwrap()),
            (
                "AWS_SHARED_CREDENTIALS_FILE",
                aws_credentials.to_str().unwrap(),
            ),
            ("CARGO_HOME", cargo_home.to_str().unwrap()),
            ("CAROOT", caroot.to_str().unwrap()),
            ("HELM_CONFIG_HOME", helm_config_home.to_str().unwrap()),
            (
                "HELM_REPOSITORY_CONFIG",
                helm_repository_config.to_str().unwrap(),
            ),
            ("KUBECONFIG", kubeconfig.to_str().unwrap()),
            ("NPM_CONFIG_USERCONFIG", npm_config.to_str().unwrap()),
            ("UV_CREDENTIALS_DIR", uv_credentials_dir.to_str().unwrap()),
        ],
    );
    let rich_stdout = stdout(&output);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(rich_stdout.contains("╭─ Automic Vault Scan"));
    assert!(rich_stdout.contains("\x1b["));
    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn subs_trace_command_covers_agent_selection_and_outputs() {
    let temp = std::env::temp_dir().join(format!("av-trace-cli-{}", std::process::id()));
    if temp.exists() {
        fs::remove_dir_all(&temp).unwrap();
    }
    let bin_dir = temp.join("bin");
    let codex_response = r#"{"steps":[{"description":"Downloads the installer from https://foo.com and writes /usr/local/bin/foo with executable permissions.","operation":"install","path":"/usr/local/bin/foo","network":"https://foo.com"}]}"#;
    let claude_response = r#"{"steps":[{"description":"Appends downloaded shell output to ~/.profile.","operation":"append","path":"~/.profile","network":"https://foo.com"}]}"#;
    write_fake_trace_agent(&bin_dir, "codex", codex_response);
    write_fake_trace_agent(&bin_dir, "claude", claude_response);
    let path = bin_dir.to_str().unwrap();

    let output = run_nuke_with_env(
        &["trace", "curl foo.com | sh"],
        &[("PATH", path), ("CODEX_CI", "1")],
    );
    let plain_stdout = stdout(&output);
    let plain_stderr = stderr(&output);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(plain_stdout.contains("1. Downloads the installer from https://foo.com"));
    assert!(plain_stdout.contains("with executable\n   permissions."));
    assert!(plain_stderr.contains("trace: Resolving trace agent"));
    assert!(plain_stderr.contains("trace: Asking codex to trace file-changing actions"));
    assert!(!plain_stdout.contains("2."));

    let output = run_nuke_with_env(
        &["trace", "--json", "curl foo.com | sh"],
        &[("PATH", path), ("CODEX_CI", "1")],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!stderr(&output).contains("trace:"));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["command"], "curl foo.com | sh");
    assert_eq!(report["agent"], "codex");
    assert_eq!(report["steps"][0]["operation"], "install");
    assert_eq!(report["steps"][0]["network"], "https://foo.com");

    fs::remove_file(bin_dir.join("codex")).unwrap();
    let output = run_nuke_with_env(
        &["trace", "--json", "curl foo.com | sh"],
        &[("PATH", path), ("CODEX_CI", "1")],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["agent"], "claude");
    assert_eq!(report["steps"][0]["path"], "~/.profile");

    let output = run_nuke_with_env(
        &["trace", "--agent", "wat", "curl foo.com | sh"],
        &[("PATH", path)],
    );
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unknown trace agent 'wat'"));

    let output = run_nuke_with_env(&["trace"], &[("PATH", path)]);
    assert!(!output.status.success());
    assert!(stdout(&output).contains("Usage: av trace"));
    assert!(stderr(&output).contains("missing shell one-liner"));

    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn subs_help_topics_and_root_gated_commands_cover_dispatch_edges() {
    for topic in [
        "uninstall",
        "outdated",
        "update",
        "list",
        "info",
        "search",
        "scan",
        "trace",
        "serve",
        "inject",
        "save",
        "gate",
        "contain",
        "install",
    ] {
        let output = run_nuke(&["help", topic]);
        assert!(output.status.success(), "topic={topic} stderr={}", stderr(&output));
        assert!(stdout(&output).contains("Usage:"), "topic={topic}");
    }

    let output = run_nuke(&["help", "wat"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("PACKAGE SYSTEM"));

    let output = run_nuke(&["update"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("must be run as root"));

    let output = run_nuke(&["uninstall", "ripgrep"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("package ripgrep is not installed"));

    let _guard = PackageRootGuard::install(
        "coverage-cli-uninstall",
        "0.0.1",
        serde_json::json!({
            "formula": "coverage-cli-uninstall"
        }),
    );
    let output = run_nuke(&["uninstall", "coverage-cli-uninstall"]);
    assert!(output.status.success(), "{}", stderr(&output));
}

#[test]
fn subs_serve_command_covers_non_server_paths() {
    let output = run_nuke(&["serve", "--help"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av serve"));

    let output = run_nuke(&["serve", "--version"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains(&format!("av serve {}", pkg_version())));

    let output = run_nuke(&["serve", "--bad"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unknown argument '--bad'"));
}

#[test]
fn subs_list_and_outdated_commands_cover_requested_outputs() {
    let _installed = PackageRootGuard::install(
        "coverage-cli-status",
        "0.0.1",
        serde_json::json!({
            "kind": "isotope",
            "isotope_name": "gh"
        }),
    );

    let output = run_nuke(&["list", "coverage-cli-status"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("coverage-cli-status 0.0.1"));

    let output = run_nuke(&["list", "coverage-cli-status", "--json"]);
    assert!(output.status.success());
    let listed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["package_name"], "coverage-cli-status");

    let output = run_nuke(&["list", "coverage-cli-status", "--jsonl"]);
    assert!(output.status.success());
    let listed: serde_json::Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(listed["package_name"], "coverage-cli-status");

    let output = run_nuke(&["outdated", "coverage-cli-status"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("coverage-cli-status 0.0.1 ->"));

    let output = run_nuke(&["outdated", "coverage-cli-status", "--json"]);
    assert!(output.status.success());
    let outdated: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(outdated.as_array().unwrap().len(), 1);
    assert_eq!(outdated[0]["package_name"], "coverage-cli-status");

    let output = run_nuke(&["outdated", "coverage-cli-status", "--jsonl"]);
    assert!(output.status.success());
    let outdated: serde_json::Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(outdated["package_name"], "coverage-cli-status");
}

#[test]
fn subs_help_fallback_and_non_utf8_arguments_report_errors() {
    let output = run_nuke(&["help", "wat"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("USAGE"));
    assert!(stdout(&output).contains("av <subcommand> [args...]"));

    #[cfg(unix)]
    {
        let output = Command::new(env!("CARGO_BIN_EXE_av"))
            .arg(std::ffi::OsString::from_vec(vec![0xff]))
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(stderr(&output).contains("av: subcommand must be valid UTF-8"));

        let output = Command::new(env!("CARGO_BIN_EXE_av"))
            .arg("gate")
            .arg(std::ffi::OsString::from_vec(vec![0xff]))
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(stderr(&output).contains("av gate: gate message must be valid UTF-8"));
    }
}
