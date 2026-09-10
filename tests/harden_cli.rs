use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn harden_explains_launcher_collisions_without_changing_files() {
    for command in ["sentry-cli", "doctl"] {
        let root = fixture(command);
        prepare(&root, command);
        let launcher = root.join("stubs").join(command);
        let target = root.join("targets").join(command);
        // An executable in the working directory is not a Target unless on PATH.
        fs::rename(&target, root.join(command)).unwrap();
        let config = root.join("doctl.yaml");
        let credentials = "access-token: do_secret\ncontext: default\n";
        fs::write(&config, credentials).unwrap();

        let mut harden = av(&root, command);
        harden
            .env_remove("AUTOMIC_VAULT_TEST_ENV_WRAPPER_TARGET_DIR")
            .env("PATH", root.join("stubs"))
            .env("DIGITALOCEAN_CONFIG", &config)
            .current_dir(&root);

        let missing = harden.output().unwrap();
        assert!(!missing.status.success());
        assert!(stderr(&missing).contains(&format!("{command} is not installed on PATH")));

        fs::copy(root.join(command), &launcher).unwrap();
        let original = fs::read(&launcher).unwrap();
        let collision = harden.output().unwrap();
        assert!(!collision.status.success());
        let error = stderr(&collision);
        assert!(error.starts_with(&format!("av harden: {command}: {}", launcher.display())));
        assert!(error.contains("reserved Automic Vault Launcher path"));
        assert!(error.contains("no separate Target was found on PATH"));
        assert!(error.contains("Review and preserve this executable"));
        assert!(error.contains("leaving"));
        assert!(stdout(&collision).is_empty());
        assert_eq!(fs::read(&launcher).unwrap(), original);
        assert_eq!(fs::read_to_string(&config).unwrap(), credentials);
        assert!(!root.join("keychain").exists());

        // A separate Target still cannot authorize overwriting the occupant.
        fs::copy(root.join(command), &target).unwrap();
        harden.env(
            "PATH",
            std::env::join_paths([root.join("stubs"), root.join("targets")]).unwrap(),
        );
        let occupied = harden.output().unwrap();
        assert!(!occupied.status.success());
        assert!(stderr(&occupied).contains("is not an Automic Vault env-wrapper stub"));
        assert_eq!(fs::read(&launcher).unwrap(), original);
        assert_eq!(fs::read_to_string(&config).unwrap(), credentials);
        assert!(!root.join("keychain").exists());
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn harden_installs_stub_then_migrates_direct_token() {
    let root = fixture("direct");
    let config = root.join("doctl.yaml");
    prepare(&root, "doctl");
    fs::write(&config, "access-token: do_secret\ncontext: default\n").unwrap();

    let output = av(&root, "doctl")
        .env("DIGITALOCEAN_CONFIG", &config)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("◇ next: run `av doctor doctl`"),
        "{}",
        stdout(&output)
    );
    assert!(root.join("stubs/doctl").exists());
    assert_eq!(
        fs::read_to_string(root.join("keychain/DIGITALOCEAN_ACCESS_TOKEN")).unwrap(),
        "do_secret"
    );
    assert_eq!(
        fs::read_to_string(config).unwrap(),
        "access-token: \"\"\ncontext: default\n"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn harden_migrates_assignment_bundle() {
    let root = fixture("assignments");
    let config = root.join("edgerc");
    prepare(&root, "akamai");
    fs::write(
        &config,
        "[default]\nhost = example.invalid\nclient_token = tok\nclient_secret = sec\naccess_token = acc\n",
    )
    .unwrap();

    let output = av(&root, "akamai")
        .env("AKAMAI_EDGERC", &config)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        fs::read_to_string(root.join("keychain/AKAMAI_ENV_ASSIGNMENTS")).unwrap(),
        "AKAMAI_HOST=example.invalid\nAKAMAI_CLIENT_TOKEN=tok\nAKAMAI_CLIENT_SECRET=sec\nAKAMAI_ACCESS_TOKEN=acc"
    );
    assert!(
        !fs::read_to_string(config)
            .unwrap()
            .contains("client_token = tok")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_secret_storage_leaves_plaintext_usable_behind_stub() {
    let root = fixture("store-failure");
    let config = root.join("doctl.yaml");
    prepare(&root, "doctl");
    fs::write(&config, "access-token: do_secret\ncontext: default\n").unwrap();
    fs::write(root.join("keychain"), "not a directory").unwrap();

    let output = av(&root, "doctl")
        .env("DIGITALOCEAN_CONFIG", &config)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(root.join("stubs/doctl").exists());
    assert_eq!(
        fs::read_to_string(config).unwrap(),
        "access-token: do_secret\ncontext: default\n"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_stub_install_does_not_migrate_credentials() {
    let root = fixture("install-failure");
    let config = root.join("doctl.yaml");
    prepare(&root, "doctl");
    fs::write(&config, "access-token: do_secret\ncontext: default\n").unwrap();
    fs::set_permissions(root.join("stubs"), fs::Permissions::from_mode(0o555)).unwrap();

    let output = av(&root, "doctl")
        .env("DIGITALOCEAN_CONFIG", &config)
        .output()
        .unwrap();

    fs::set_permissions(root.join("stubs"), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!output.status.success());
    assert_eq!(
        fs::read_to_string(config).unwrap(),
        "access-token: do_secret\ncontext: default\n"
    );
    assert!(!root.join("keychain/DIGITALOCEAN_ACCESS_TOKEN").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cancelled_hardening_changes_nothing() {
    let root = fixture("cancelled");
    let config = root.join("doctl.yaml");
    prepare(&root, "doctl");
    fs::write(&config, "access-token: do_secret\ncontext: default\n").unwrap();

    let mut command = base_av(&root);
    command.args(["harden", "doctl"]);
    let output = command
        .env("DIGITALOCEAN_CONFIG", &config)
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!root.join("stubs/doctl").exists());
    assert_eq!(
        fs::read_to_string(config).unwrap(),
        "access-token: do_secret\ncontext: default\n"
    );
    fs::remove_dir_all(root).unwrap();
}

fn av(root: &Path, hardener: &str) -> Command {
    let mut command = base_av(root);
    command.args(["harden", hardener, "--yes"]);
    command
}

fn base_av(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_av"));
    command.env("HOME", root.join("home"));
    command.env("AUTOMIC_VAULT_TEST_EUID", "0");
    command.env(
        "AUTOMIC_VAULT_TEST_ENV_WRAPPER_TARGET_DIR",
        root.join("targets"),
    );
    command.env(
        "AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR",
        root.join("stubs"),
    );
    command.env("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", root.join("keychain"));
    command
}

fn prepare(root: &Path, command: &str) {
    fs::create_dir_all(root.join("targets")).unwrap();
    fs::create_dir_all(root.join("stubs")).unwrap();
    fs::create_dir_all(root.join("home")).unwrap();
    fs::write(root.join("targets").join(command), "#!/bin/sh\n").unwrap();
    fs::set_permissions(
        root.join("targets").join(command),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn fixture(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("av-harden-{label}-{}-{nanos}", std::process::id()))
}
