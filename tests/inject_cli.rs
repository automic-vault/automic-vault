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
            "#!{} inject +SOME_SECRET /bin/sh\nprintf '%s\\n' \"$0\" \"$AV_SCRIPT_PATH\" \"$AV_SCRIPT_DIR\"\n",
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
        .env("AV_SCRIPT_PATH", "untrusted")
        .env("AV_SCRIPT_DIR", "untrusted")
        .output()
        .unwrap();

    if unsafe { libc::geteuid() } == 0 {
        assert!(!output.status.success());
        return;
    }

    assert!(output.status.success(), "{}", stderr(&output));
    let path = script.canonicalize().unwrap();
    let stdout = stdout(&output);
    let mut lines = stdout.lines();
    assert!(lines.next().unwrap().starts_with("/dev/fd/"));
    assert_eq!(lines.next(), path.to_str());
    assert_eq!(lines.next(), path.parent().unwrap().to_str());
    let _ = fs::remove_dir_all(home);
}

#[test]
fn av_inject_uses_the_script_path_for_uv_and_preserves_stdin() {
    let home = temp_home("inject-uv");
    let keychain = home.join("keychain");
    fs::create_dir_all(&keychain).unwrap();
    let uv = home.join("uv");
    fs::write(&uv, "#!/bin/sh\nprintf 'args:%s\\n' \"$*\"\ncat\n").unwrap();
    fs::set_permissions(&uv, fs::Permissions::from_mode(0o755)).unwrap();
    let dotenvx = home.join("dotenvx");
    fs::write(
        &dotenvx,
        "#!/bin/sh\nwhile [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&dotenvx, fs::Permissions::from_mode(0o755)).unwrap();
    let script = home.join("tool");
    fs::write(
        &script,
        format!(
            "#!{} inject -- {} run -- {} run --script\nprint('UV_STDIN_OK')\n",
            env!("CARGO_BIN_EXE_av"),
            dotenvx.display(),
            uv.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let input = home.join("input");
    fs::write(&input, "CALLER_STDIN\n").unwrap();

    let output = Command::new(&script)
        .env("HOME", &home)
        .env("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain)
        .stdin(fs::File::open(input).unwrap())
        .output()
        .unwrap();

    if unsafe { libc::geteuid() } == 0 {
        assert!(!output.status.success());
        return;
    }

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains(&format!(
        "args:run --script {}\n",
        script.canonicalize().unwrap().display()
    )));
    assert!(stdout(&output).contains("CALLER_STDIN\n"));
    assert!(!stdout(&output).contains("print('UV_STDIN_OK')\n"));
    assert!(stderr(&output).contains(
        "Blessed Script authorization requires a Blessing created with this exception, and another process can change the script between verification and execution"
    ));
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

#[test]
fn fd_injection_preserves_bytes_eof_and_separates_environment() {
    let home = temp_home("inject-fd");
    let keychain = home.join("keychain");
    fs::create_dir_all(&keychain).unwrap();
    let pem = b"  -----BEGIN PRIVATE KEY-----\r\nfixture\0bytes\n-----END PRIVATE KEY-----\n\n";
    fs::write(keychain.join("FOO"), pem).unwrap();
    fs::write(keychain.join("BAR"), "second").unwrap();
    let input = home.join("stdin");
    fs::write(&input, "stdin").unwrap();
    // CI runners can leave these descriptors open. Free them in the child before av starts.
    let output = Command::new("/bin/sh")
        .args([
            "-c",
            "exec 3<&- 4<&-; exec \"$@\"",
            "inject-fd-test",
            env!("CARGO_BIN_EXE_av"),
            "inject",
            "--mode=fd",
            "+FOO:3",
            "+BAR:4",
            "--",
            "/bin/sh",
            "-c",
            "test -z \"${FOO+x}${BAR+x}\" || exit 91; cat <&4; cat <&3; cat <&3; cat",
        ])
        .env("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain)
        .env("FOO", "ambient-foo")
        .env("BAR", "ambient-bar")
        .stdin(fs::File::open(input).unwrap())
        .output()
        .unwrap();
    if unsafe { libc::geteuid() } != 0 {
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(
            output.stdout,
            [b"second".as_slice(), pem, b"stdin"].concat()
        );
        assert!(output.stderr.is_empty(), "{}", stderr(&output));
    } else {
        assert!(!output.status.success());
    }
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn fd_injection_can_use_the_highest_descriptor_under_the_process_limit() {
    let home = temp_home("inject-fd-limit");
    let keychain = home.join("keychain");
    fs::create_dir_all(&keychain).unwrap();
    fs::write(keychain.join("FOO"), "exact value\n").unwrap();
    fs::write(keychain.join("BAR"), "second").unwrap();
    let output = Command::new("/bin/sh")
        .args([
            "-c",
            "ulimit -n 32 || exit; exec 3<&- 4<&- 5<&- 31<&-; exec \"$@\"",
            "inject-fd-limit-test",
            env!("CARGO_BIN_EXE_av"),
            "inject",
            "--mode=fd",
            "+FOO:31",
            "+BAR:5",
            "--",
            "/bin/cat",
            "/dev/fd/31",
            "/dev/fd/5",
        ])
        .env("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain)
        .output()
        .unwrap();
    if unsafe { libc::geteuid() } != 0 {
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(output.stdout, b"exact value\nsecond");
        assert!(output.stderr.is_empty(), "{}", stderr(&output));
    } else {
        assert!(!output.status.success());
    }
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn fd_injection_missing_oversized_or_occupied_descriptors_never_start_target() {
    use std::os::unix::process::CommandExt;
    let home = temp_home("inject-fd-errors");
    let keychain = home.join("keychain");
    fs::create_dir_all(&keychain).unwrap();
    fs::write(keychain.join("LARGE"), vec![b'x'; 1024 * 1024]).unwrap();
    fs::write(keychain.join("SMALL"), "must-not-leak").unwrap();
    for (key, occupied, expected) in [
        ("MISSING", false, "missing Secret"),
        ("LARGE", false, "exceeds the anonymous pipe buffer capacity"),
        ("SMALL", true, "already open"),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_av"));
        command
            .args([
                "inject",
                "--mode=fd",
                &format!("+{key}:100"),
                "--",
                "/bin/echo",
                "TARGET_RAN",
            ])
            .env("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain);
        if occupied {
            unsafe {
                command.pre_exec(|| {
                    if libc::dup2(0, 100) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!stderr(&output).contains("must-not-leak"));
        if unsafe { libc::geteuid() } != 0 {
            assert!(stderr(&output).contains(expected), "{}", stderr(&output));
        }
    }
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn av_inject_rejects_python_that_shares_the_snapshot_offset() {
    let home = temp_home("inject-python-offset");
    let keychain = home.join("keychain");
    fs::create_dir_all(&keychain).unwrap();
    let python = fake_python(&home, "3.9.6");
    let script = home.join("tool");
    fs::write(
        &script,
        format!(
            "#!{} inject +SOME_SECRET {} -I\nprint('x')\n",
            env!("CARGO_BIN_EXE_av"),
            python.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

    let output = Command::new(&script)
        .env("HOME", &home)
        .env("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain)
        .output()
        .unwrap();

    if unsafe { libc::geteuid() } == 0 {
        assert!(!output.status.success());
        return;
    }

    assert!(!output.status.success(), "{}", stdout(&output));
    let stderr = stderr(&output);
    assert!(
        stderr.contains("cannot execute the verified /dev/fd snapshot"),
        "{stderr}"
    );
    assert!(stderr.contains("Python 3.9.6"), "{stderr}");
    assert!(stderr.contains("bless the script again"), "{stderr}");
    assert!(!stdout(&output).contains("RAN"), "{}", stdout(&output));
    let _ = fs::remove_dir_all(home);
}

#[test]
fn av_inject_keeps_the_snapshot_for_fixed_python() {
    let home = temp_home("inject-python-fixed");
    let keychain = home.join("keychain");
    fs::create_dir_all(&keychain).unwrap();
    let python = fake_python(&home, "3.12.0");
    for (shebang_target, extra_env) in [
        (python.display().to_string(), None),
        (
            "/usr/bin/env python3".to_string(),
            Some(format!("{}:/usr/bin:/bin", home.display())),
        ),
    ] {
        let script = home.join("tool");
        fs::write(
            &script,
            format!(
                "#!{} inject +SOME_SECRET {shebang_target} -I\nprint('x')\n",
                env!("CARGO_BIN_EXE_av")
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

        let mut command = Command::new(&script);
        command
            .env("HOME", &home)
            .env("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain)
            .env("SOME_SECRET", "expected");
        if let Some(path) = extra_env {
            command.env("PATH", path);
        }
        let output = command.output().unwrap();

        if unsafe { libc::geteuid() } == 0 {
            assert!(!output.status.success());
            return;
        }

        assert!(output.status.success(), "{}", stderr(&output));
        assert!(
            stdout(&output).contains("RAN -I /dev/fd/"),
            "{}",
            stdout(&output)
        );
    }
    let _ = fs::remove_dir_all(home);
}

#[test]
fn av_inject_passes_through_python_stdout_stderr_and_exit_status() {
    let home = temp_home("inject-python-streams");
    let keychain = home.join("keychain");
    fs::create_dir_all(&keychain).unwrap();
    let python = [
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        "python3",
    ]
    .iter()
    .find_map(|candidate| {
        let version = python_version(candidate)?;
        (version >= (3, 12, 0)).then(|| candidate.to_string())
    });
    let Some(python) = python else {
        eprintln!("skipping: no Python >= 3.12 available");
        return;
    };
    let script = home.join("tool");
    fs::write(
        &script,
        format!(
            "#!{} inject +SOME_SECRET {python} -I\nimport sys\nprint('STDOUT_MARKER')\nprint('STDERR_MARKER', file=sys.stderr)\nraise SystemExit(3)\n",
            env!("CARGO_BIN_EXE_av")
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

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

    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("STDOUT_MARKER"),
        "{}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("STDERR_MARKER"),
        "{}",
        stderr(&output)
    );
    let _ = fs::remove_dir_all(home);
}

#[test]
fn av_inject_rejects_apple_system_python_when_present() {
    let home = temp_home("inject-python-apple");
    let keychain = home.join("keychain");
    fs::create_dir_all(&keychain).unwrap();
    match python_version("/usr/bin/python3") {
        Some(version) if version < (3, 10, 9) || version == (3, 11, 0) => {}
        _ => {
            eprintln!("skipping: no affected /usr/bin/python3 available");
            return;
        }
    }
    let ran = home.join("ran");
    let script = home.join("tool");
    fs::write(
        &script,
        format!(
            "#!{} inject +SOME_SECRET /usr/bin/python3 -I\nopen('{}', 'w').write('x')\n",
            env!("CARGO_BIN_EXE_av"),
            ran.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

    let output = Command::new(&script)
        .env("HOME", &home)
        .env("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain)
        .output()
        .unwrap();

    if unsafe { libc::geteuid() } == 0 {
        assert!(!output.status.success());
        return;
    }

    assert!(!output.status.success(), "{}", stdout(&output));
    assert!(
        stderr(&output).contains("cannot execute the verified /dev/fd snapshot"),
        "{}",
        stderr(&output)
    );
    assert!(!ran.exists());
    let _ = fs::remove_dir_all(home);
}

fn fake_python(home: &std::path::Path, version: &str) -> std::path::PathBuf {
    let python = home.join("python3");
    fs::write(
        &python,
        format!(
            "#!/bin/sh\ncase \"$*\" in\n  *--version*) echo 'Python {version}' ;;\n  *) printf 'RAN %s\\n' \"$*\" ;;\nesac\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&python, fs::Permissions::from_mode(0o755)).unwrap();
    python
}

fn python_version(program: &str) -> Option<(u32, u32, u32)> {
    let output = Command::new(program).arg("--version").output().ok()?;
    let mut combined = output.stdout;
    combined.extend_from_slice(&output.stderr);
    let text = String::from_utf8_lossy(&combined);
    let version = text.split_whitespace().nth(1)?;
    let mut parts = version.split('.');
    let mut part = || {
        parts.next().and_then(|part| {
            let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse().ok()
        })
    };
    Some((part()?, part()?, part().unwrap_or(0)))
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
