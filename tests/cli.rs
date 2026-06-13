use std::process::{Command, Output};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

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

fn run_scanner(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_scanner"))
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

fn run_scanner_with_env(args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_scanner"));
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

fn run_shell_with_test_av(shell: &str, script: &str, cwd: &Path) -> Option<Output> {
    let av_dir = Path::new(env!("CARGO_BIN_EXE_av")).parent().unwrap();
    let path = env::join_paths(
        std::iter::once(av_dir.to_path_buf())
            .chain(env::split_paths(&env::var_os("PATH").unwrap_or_default())),
    )
    .unwrap();
    Command::new(shell)
        .arg("-fc")
        .arg(script)
        .current_dir(cwd)
        .env("PATH", path)
        .output()
        .ok()
}

fn write_fake_trace_agent(bin_dir: &std::path::Path, name: &str, response: &str) {
    fs::create_dir_all(bin_dir).unwrap();
    let path = bin_dir.join(name);
    let guard = if name == "codex" {
        "case \" $* \" in *\" --skip-git-repo-check \"*) ;; *) echo 'Not inside a trusted directory and --skip-git-repo-check was not specified.' >&2; exit 1 ;; esac\n"
    } else {
        ""
    };
    fs::write(
        &path,
        format!(
            "#!/bin/sh\n{}cat >/dev/null\nprintf '%s\\n' '{}'\n",
            guard, response
        ),
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
    assert!(stdout(&output).contains("transfer"));
    assert!(stdout(&output).contains("trace"));
    assert!(stdout(&output).contains("open"));
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

    let output = run_nuke(&["help", "open"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av open"));

    let output = run_nuke(&["help", "inject"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av inject"));

    let output = run_nuke(&["help", "save"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av save"));

    let output = run_nuke(&["help", "dotenv"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av dotenv"));

    let output = run_nuke(&["help", "transfer"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av transfer"));

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
fn subs_dotenv_cli_covers_help_version_and_parse_errors() {
    let output = run_nuke(&["dotenv", "--help"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av dotenv"));

    let output = run_nuke(&["dotenv", "--version"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains(&format!("av dotenv {}", pkg_version())));

    let output = run_nuke(&["dotenv"]);
    assert!(!output.status.success());
    assert!(stdout(&output).contains("Usage: av dotenv"));
    assert!(stderr(&output).contains("missing dotenv command"));

    let output = run_nuke(&["dotenv", "wat"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unknown dotenv command 'wat'"));

    let output = run_nuke(&["dotenv", "init", "--help"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av dotenv init"));

    let output = run_nuke(&["dotenv", "set", "--help"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av dotenv set"));

    let output = run_nuke(&["dotenv", "set"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("missing KEY"));

    let output = run_nuke(&["dotenv", "encrypt", "--help"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av dotenv encrypt"));

    let output = run_nuke(&["dotenv", "encrypt", "--key"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("missing value for --key"));

    let output = run_nuke(&["dotenv", "import", "--help"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av dotenv import"));

    let output = run_nuke(&["dotenv", "hook", "--help"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av dotenv hook"));

    let output = run_nuke(&["dotenv", "hook", "zsh"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("add-zsh-hook"));
    assert!(stdout(&output).contains("av dotenv export --shell zsh"));

    let temp = tempfile::tempdir().unwrap();
    if let Some(output) = run_shell_with_test_av("zsh", "eval $(av dotenv hook zsh)", temp.path()) {
        assert!(
            output.status.success(),
            "zsh hook eval failed\nstdout:\n{}\nstderr:\n{}",
            stdout(&output),
            stderr(&output)
        );
    }
    if let Some(output) = run_shell_with_test_av("bash", "eval $(av dotenv hook bash)", temp.path())
    {
        assert!(
            output.status.success(),
            "bash hook eval failed\nstdout:\n{}\nstderr:\n{}",
            stdout(&output),
            stderr(&output)
        );
    }

    let output = run_nuke(&["dotenv", "hook", "powershell"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unsupported shell 'powershell'"));

    let output = run_nuke(&["dotenv", "export", "--help"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av dotenv export"));

    let output = run_nuke(&["dotenv", "export"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("missing --shell"));

    let temp = tempfile::tempdir().unwrap();
    let output = run_nuke_with_env(
        &[
            "dotenv",
            "export",
            "--shell",
            "zsh",
            "--cwd",
            temp.path().to_str().unwrap(),
        ],
        &[
            ("AV_DOTENV_FILE", "/tmp/project/.env"),
            ("AV_DOTENV_KEYS", "FOO:BAR"),
        ],
    );
    assert!(output.status.success());
    assert!(
        stdout(&output)
            .contains("printf '%s\\n' 'av dotenv: unloading /tmp/project/.env (2 keys)' >&2;")
    );
    assert!(stdout(&output).contains("unset FOO;"));

    let output = run_nuke(&["dotenv", "run", "--help"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av dotenv run"));

    let output = run_nuke(&["dotenv", "run"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("missing command"));
}

#[test]
fn subs_transfer_cli_covers_help_version_and_receive_errors() {
    let output = run_nuke(&["transfer", "--help"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av transfer"));

    let output = run_nuke(&["transfer", "--version"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains(&format!("av transfer {}", pkg_version())));

    let output = run_nuke(&["transfer"]);
    assert!(!output.status.success());
    assert!(stdout(&output).contains("Usage: av transfer"));
    assert!(stderr(&output).contains("missing ssh target"));

    let output = run_nuke(&["transfer", "receive"]);
    assert!(!output.status.success());
    assert!(stdout(&output).contains("Usage: av transfer receive"));
    assert!(stderr(&output).contains("transfer receive requires --stdin"));

    let output = run_nuke(&["transfer", "receive", "--stdin"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("failed to decode transfer bundle"));
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
fn subs_contain_cli_covers_help_version_and_vault_subcommands() {
    let output = run_nuke(&["contain", "--help"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av contain <command>"));

    let output = run_nuke(&["contain", "--version"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains(&format!("av contain {}", pkg_version())));

    let output = run_nuke(&["contain"]);
    assert!(!output.status.success());
    assert!(stdout(&output).contains("Usage: av contain <command>"));
    assert!(stderr(&output).contains("av contain: missing command"));

    let output = run_nuke(&["contain", "--proxy"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("av contain: missing proxy stub path"));

    let output = run_nuke(&["contain", "internal-exec"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("restricted to trusted callers"));

    let output = run_nuke(&["contain", "toolchain", "--help"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av contain toolchain"));

    let output = run_nuke(&["contain", "toolchain", "--socket"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("missing value for --socket"));

    let output = run_nuke(&["contain", "toolchain", "--vault-bin"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("missing value for --vault-bin"));

    let output = run_nuke(&["contain", "toolchain", "--bad"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unknown toolchain argument '--bad'"));

    let output = run_nuke(&["contain", "sandbox-profile", "--help"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av contain sandbox-profile"));

    let output = run_nuke(&["contain", "sandbox-profile", "--allow"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("missing value for --allow"));

    let output = run_nuke(&["contain", "sandbox-profile", "--bad"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unknown sandbox-profile argument '--bad'"));
}

#[test]
fn subs_contain_toolchain_and_profile_emit_expected_outputs() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("vault.sock");

    let output = run_nuke_with_env(
        &["contain", "toolchain", "--json"],
        &[
            ("HOME", temp.path().to_str().unwrap()),
            ("VAULT_SOCKET_PATH", socket.to_str().unwrap()),
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let manifest: serde_json::Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(
        manifest["environment"]["socket_path"].as_str(),
        Some(socket.to_str().unwrap())
    );
    assert_eq!(
        manifest["environment"]["initial_executable_path"].as_str(),
        None
    );

    let output = run_nuke_with_env(
        &["contain", "sandbox-profile"],
        &[("HOME", temp.path().to_str().unwrap())],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let profile = stdout(&output);
    assert!(profile.contains("(allow default)"));
    assert!(profile.contains("(deny process-exec)"));
}

#[test]
fn subs_contain_sandboxed_command_exercises_launch_path() {
    let output = run_nuke(&["contain", "/usr/bin/true"]);
    let stderr = stderr(&output);
    assert!(
        output.status.success()
            || stderr.contains("sandbox-exec:")
            || stderr.contains("failed to enter sandbox:"),
        "unexpected stderr: {stderr}"
    );
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

    let output = run_nuke(&["scan", "--help"]);
    assert!(stdout(&output).contains("--skip"));
    assert!(stdout(&output).contains("--isotopes-only"));

    let output = run_scanner(&["--help"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: scanner"));

    let output = run_scanner(&["--version"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains(&format!("scanner {version}")));

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
    assert_eq!(report["scope"], "full");
    assert_eq!(report["summary"]["findings"], 1);
    assert_eq!(report["findings"][0]["source"], "file-probe");

    let output = run_nuke_with_env(
        &[
            "scan",
            "--path",
            scan.to_str().unwrap(),
            "--isotopes-only",
            "--json",
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
    let isotope_only_report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(isotope_only_report["scope"], "isotopes-only");
    assert_eq!(isotope_only_report["summary"]["scanned_files"], 0);
    assert_eq!(isotope_only_report["summary"]["file_probes"], 0);
    assert!(
        isotope_only_report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["source"] != "file-probe")
    );

    let output = run_scanner_with_env(
        &["--path", scan.to_str().unwrap(), "--json"],
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
    let scanner_report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(scanner_report, isotope_only_report);

    let output = run_scanner_with_env(
        &[],
        &[
            ("AUTOMIC_VAULT_SCANNER_WRAPPER_UI", "1"),
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
    assert!(output.status.success(), "{}", stderr(&output));
    let scanner_stdout = stdout(&output);
    assert!(scanner_stdout.contains("│"));
    assert!(!scanner_stdout.contains("\x1b[35"));
    assert!(scanner_stdout.contains("Scope"));
    assert!(scanner_stdout.contains("Checked"));
    assert!(!scanner_stdout.contains("╭─ Automic Vault Scan"));

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
    assert!(plain_stdout.contains("Scope: isotope detectors and file probes"));
    assert!(plain_stdout.contains("Findings:"));
    assert!(!plain_stdout.contains("\x1b["));
    assert!(!plain_stdout.contains("╭"));

    let output = run_nuke_with_env(
        &["scan", "--path", scan.to_str().unwrap(), "--isotopes-only"],
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
    let isotope_only_stdout = stdout(&output);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(isotope_only_stdout.contains("Scope: isotope detectors only"));
    assert!(isotope_only_stdout.contains("file probes skipped"));
    assert!(!isotope_only_stdout.contains("Findings:"));

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
    assert!(rich_stdout.contains("Scope"));
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
        &[
            ("PATH", path),
            ("CODEX_CI", "1"),
            ("NUKE_TEST_BYPASS_TRACE_SANDBOX", "1"),
        ],
    );
    let plain_stdout = stdout(&output);
    let plain_stderr = stderr(&output);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(plain_stdout.contains("Safety: moderate - "));
    assert!(plain_stdout.contains("downloads installer payload"));
    assert!(plain_stdout.contains("installs command"));
    assert!(plain_stdout.contains("1. Downloads the installer from https://foo.com"));
    assert!(plain_stdout.contains("with executable\n   permissions."));
    assert!(plain_stderr.contains("trace: Resolving trace agent"));
    assert!(plain_stderr.contains("trace: Asking codex to trace file-changing actions"));
    assert!(!plain_stdout.contains("2."));

    let output = run_nuke_with_env(
        &["trace", "--json", "curl foo.com | sh"],
        &[
            ("PATH", path),
            ("CODEX_CI", "1"),
            ("NUKE_TEST_BYPASS_TRACE_SANDBOX", "1"),
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!stderr(&output).contains("trace:"));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["command"], "curl foo.com | sh");
    assert_eq!(report["agent"], "codex");
    assert_eq!(report["safetyRating"]["level"], "moderate");
    assert_eq!(
        report["safetyRating"]["reasons"],
        serde_json::json!([
            "downloads installer payload",
            "installs command",
            "changes permissions"
        ])
    );
    assert_eq!(report["steps"][0]["operation"], "install");
    assert_eq!(report["steps"][0]["network"], "https://foo.com");

    fs::remove_file(bin_dir.join("codex")).unwrap();
    let output = run_nuke_with_env(
        &["trace", "--json", "curl foo.com | sh"],
        &[
            ("PATH", path),
            ("CODEX_CI", "1"),
            ("NUKE_TEST_BYPASS_TRACE_SANDBOX", "1"),
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["agent"], "claude");
    assert_eq!(report["safetyRating"]["level"], "moderate");
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
        "open",
        "inject",
        "save",
        "gate",
        "contain",
        "install",
    ] {
        let output = run_nuke(&["help", topic]);
        assert!(
            output.status.success(),
            "topic={topic} stderr={}",
            stderr(&output)
        );
        assert!(stdout(&output).contains("Usage:"), "topic={topic}");
    }

    let output = run_nuke(&["help", "wat"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("PACKAGE SYSTEM"));

    if unsafe { libc::geteuid() } != 0 {
        let output = run_nuke(&["update"]);
        assert!(!output.status.success());
        assert!(stderr(&output).contains("must be run as root"));
    }

    let output = run_nuke(&["uninstall", "coverage-cli-uninstall-missing"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("package coverage-cli-uninstall-missing is not installed"));

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
fn subs_open_command_covers_non_launch_paths() {
    let output = run_nuke(&["open", "--help"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains("Usage: av open"));

    let output = run_nuke(&["open", "--version"]);
    assert!(output.status.success());
    assert!(stdout(&output).contains(&format!("av open {}", pkg_version())));

    let output = run_nuke(&["open", "--bad"]);
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
fn subs_outdated_human_output_reports_empty_result() {
    let info_output = run_nuke(&["info", "cask:codex", "--json"]);
    assert!(info_output.status.success(), "{}", stderr(&info_output));
    let info: serde_json::Value = serde_json::from_slice(&info_output.stdout).unwrap();
    let latest_version = info["latest_version"].as_str().unwrap();

    let _installed = PackageRootGuard::install(
        "codex",
        latest_version,
        serde_json::json!({
            "kind": "cask",
            "cask_name": "codex"
        }),
    );

    let output = run_nuke(&["outdated", "codex"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(output.stdout.is_empty());
    assert_eq!(stderr(&output), "No outdated packages.\n");

    let output = run_nuke(&["outdated", "codex", "--json"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "[]\n");

    let output = run_nuke(&["outdated", "codex", "--jsonl"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(output.stdout.is_empty());
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
