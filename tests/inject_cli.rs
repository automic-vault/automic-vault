use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn av_inject_loads_keychain_secret_into_child_environment() {
    let home = temp_home("inject");
    let keychain = home.join("keychain");
    fs::create_dir_all(&keychain).unwrap();
    fs::write(keychain.join("SOME_SECRET"), "expected").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_av"))
        .args(["inject", "+SOME_SECRET", "--", "env"])
        .env("HOME", &home)
        .env("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain)
        .output()
        .unwrap();

    if unsafe { libc::geteuid() } == 0 {
        assert!(!output.status.success());
        return;
    }

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("SOME_SECRET=expected\n"));
    let _ = fs::remove_dir_all(home);
}

#[test]
fn av_inject_accepts_shebang_dispatch() {
    let home = temp_home("inject-shebang");
    let keychain = home.join("keychain");
    fs::create_dir_all(&keychain).unwrap();
    let script = home.join("tool");
    fs::write(
        &script,
        format!(
            "#!{} inject +SOME_SECRET /bin/echo\n",
            env!("CARGO_BIN_EXE_av")
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).unwrap();

    let output = Command::new(&script)
        .env("HOME", &home)
        .env("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain)
        .env("SOME_SECRET", "expected")
        .output()
        .unwrap();

    if unsafe { libc::geteuid() } == 0 {
        assert!(!output.status.success());
        return;
    }

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("/dev/fd/"));
    let _ = fs::remove_dir_all(home);
}

#[test]
fn av_inject_preserves_existing_env_without_replace() {
    let home = temp_home("inject-existing");
    let keychain = home.join("keychain");
    fs::create_dir_all(&keychain).unwrap();
    fs::write(keychain.join("SOME_SECRET"), "keychain").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_av"))
        .args(["inject", "+SOME_SECRET", "--", "env"])
        .env("HOME", &home)
        .env("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain)
        .env("SOME_SECRET", "ambient")
        .output()
        .unwrap();

    if unsafe { libc::geteuid() } == 0 {
        assert!(!output.status.success());
        return;
    }

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("SOME_SECRET=ambient\n"));
    assert!(stderr(&output).contains("leaving existing value unchanged"));
    let _ = fs::remove_dir_all(home);
}

#[test]
fn relocated_cli_cannot_enable_the_test_keychain_hook() {
    let home = temp_home("inject-relocated");
    let keychain = home.join("keychain");
    let relocated = home.join("av");
    fs::create_dir_all(&keychain).unwrap();
    fs::write(keychain.join("SOME_SECRET"), "must-not-leak").unwrap();
    fs::copy(env!("CARGO_BIN_EXE_av"), &relocated).unwrap();
    fs::set_permissions(&relocated, fs::Permissions::from_mode(0o755)).unwrap();

    let output = Command::new(&relocated)
        .args(["inject", "+SOME_SECRET", "--", "env"])
        .env("HOME", &home)
        .env("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!stdout(&output).contains("must-not-leak"));
    let _ = fs::remove_dir_all(home);
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
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
