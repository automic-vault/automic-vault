use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let profile_dir = out.ancestors().nth(3).unwrap();
    println!(
        "cargo:rustc-env=AV_CARGO_PROFILE_DIR={}",
        profile_dir.display()
    );

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    let proxy_info =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("src/proxy_helper/Info.plist");
    println!(
        "cargo:rustc-link-arg-bin=av-proxy-helper=-Wl,-sectcreate,__TEXT,__info_plist,{}",
        proxy_info.display()
    );
    println!("cargo:rerun-if-changed={}", proxy_info.display());

    let architecture = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        other => panic!("unsupported macOS architecture: {other}"),
    };
    let object = out.join("xpc_shim.o");
    let library = out.join("libav_xpc_shim.a");

    assert!(
        Command::new("cc")
            .args([
                "-arch",
                architecture,
                "-fblocks",
                "-c",
                "src/cli/xpc_shim.c",
                "-o"
            ])
            .arg(&object)
            .status()
            .unwrap()
            .success(),
        "failed to compile XPC shim"
    );
    assert!(
        Command::new("ar")
            .args(["crs"])
            .arg(&library)
            .arg(&object)
            .status()
            .unwrap()
            .success(),
        "failed to archive XPC shim"
    );

    println!("cargo:rerun-if-changed=src/cli/xpc_shim.c");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=av_xpc_shim");
    println!("cargo:rustc-link-arg-bin=av-brew-stub=-lav_xpc_shim");
}
