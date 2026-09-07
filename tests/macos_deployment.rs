use std::{fs, path::Path};

#[test]
fn macos_deployment_targets_match() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |path| fs::read_to_string(root.join(path)).unwrap();

    let cargo_config = read(".cargo/config.toml");
    assert!(cargo_config.contains("-mmacosx-version-min=14.0"));
    assert!(cargo_config.contains("MACOSX_DEPLOYMENT_TARGET = { value = \"14.0\", force = true }"));
    let build_script = read("scripts/build.sh");
    assert!(build_script.contains("MACOSX_DEPLOYMENT_TARGET=14.0"));
    assert!(build_script.contains("--minimum-deployment-target \"$MACOSX_DEPLOYMENT_TARGET\""));
    assert!(read("src/menu-helper/Package.swift").contains(".macOS(\"14.0\")"));
    assert!(read("src/menu-helper/Info.plist").contains("<string>14.0</string>"));
}
