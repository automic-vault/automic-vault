#![cfg(target_os = "macos")]
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn imports_encrypted_openssh_keys_and_rejects_wrong_passphrases() {
    let directory = std::env::temp_dir().join(format!(
        "av-ssh-import-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    for algorithm in ["ed25519", "ecdsa", "rsa"] {
        let key = directory.join(algorithm);
        assert!(
            Command::new("/usr/bin/ssh-keygen")
                .args([
                    "-q",
                    "-t",
                    algorithm,
                    "-N",
                    "fixture-passphrase",
                    "-C",
                    "fixture"
                ])
                .arg("-f")
                .arg(&key)
                .status()
                .unwrap()
                .success()
        );
        for passphrase in ["fixture-passphrase", "wrong-passphrase"] {
            let credential = serde_json::json!({
                "private_key": std::fs::read_to_string(&key).unwrap(), "passphrase": passphrase
            });
            let mut child = Command::new(env!("CARGO_BIN_EXE_av"))
                .arg("__ssh-public-key")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(credential.to_string().as_bytes())
                .unwrap();
            let output = child.wait_with_output().unwrap();
            if passphrase == "fixture-passphrase" && algorithm != "rsa" {
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(
                    String::from_utf8(output.stdout).unwrap().trim(),
                    std::fs::read_to_string(key.with_extension("pub"))
                        .unwrap()
                        .trim()
                );
            } else {
                assert!(!output.status.success());
                assert!(output.stdout.is_empty());
                assert!(!String::from_utf8_lossy(&output.stderr).contains(passphrase));
            }
        }
    }
    std::fs::remove_dir_all(directory).unwrap();
}
