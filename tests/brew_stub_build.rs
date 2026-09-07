use std::process::Command;

const HOMEBREW_HARDENER: &str = include_str!("../src/isotopes/hardeners/homebrew.rs");

#[test]
fn av_brew_stub_binary_is_built() {
    let output = Command::new(env!("CARGO_BIN_EXE_av-brew-stub"))
        .arg("--automic-vault-brew-stub-marker")
        .output()
        .unwrap();

    assert!(output.status.success());
    let marker = String::from_utf8_lossy(&output.stdout);
    let stub_version = marker
        .trim()
        .strip_prefix("AUTOMIC_VAULT_BREW_STUB_V")
        .unwrap();
    let required_version = HOMEBREW_HARDENER
        .lines()
        .find_map(|line| {
            line.strip_prefix("const STUB_VERSION: u32 = ")
                .and_then(|line| line.strip_suffix(';'))
        })
        .unwrap();
    assert_eq!(stub_version, required_version);

    let output = Command::new(env!("CARGO_BIN_EXE_av-brew-stub"))
        .args(["--automic-vault-brew-stub-marker", "--version"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}
