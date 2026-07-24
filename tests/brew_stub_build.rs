use std::process::Command;

#[test]
fn av_brew_stub_binary_is_built() {
    let output = Command::new(env!("CARGO_BIN_EXE_av-brew-stub"))
        .arg("--automic-vault-brew-stub-marker")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "AUTOMIC_VAULT_BREW_STUB_V4"
    );
}
