use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn aws_version_skips_secret_use() {
    let stub = std::env::temp_dir().join(format!(
        "av-aws-metadata-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::write(&stub, "#!/usr/local/bin/av aws-official\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_av"))
        .arg("aws-official")
        .arg(&stub)
        .arg("--version")
        .env_clear()
        .env("AUTOMIC_VAULT_TEST_AWS_STUB_PATH", &stub)
        .env("AUTOMIC_VAULT_TEST_OFFICIAL_AWS_PATH", "/bin/echo")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(output.stdout, b"--version\n");
    assert!(output.stderr.is_empty());
    fs::remove_file(stub).unwrap();
}
