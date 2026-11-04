use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use super::{HardenerDetection, SecretGateDescriptor, SecretGateRoute, isotope};

pub(crate) const TARGET: &str = "/opt/av/gcloud/Gcloud.app/Contents/MacOS/gcloud";
const PREFIX: &str = "/opt/av/gcloud";
// Bound the complete pinned Python and SDK distribution.
pub(super) const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;

pub(crate) fn run(stdout: &mut dyn Write, yes: bool) -> Result<(), String> {
    super::PrivilegeMode::Mixed.require_user("gcloud", false)?;
    let plan = isotope::plan(isotope::GCLOUD)?;
    writeln!(stdout, "╭─ harden gcloud").ok();
    plan.write(stdout, isotope::GCLOUD);
    writeln!(
        stdout,
        "├─ verify and protect the signed Gcloud runtime at {PREFIX}"
    )
    .ok();
    writeln!(
        stdout,
        "├─ revoke existing upstream sessions before gcloud auth login"
    )
    .ok();
    writeln!(stdout, "│").ok();
    if !super::gh_cli::confirm(stdout, yes)? {
        writeln!(stdout, "╰─ cancelled").ok();
        return Ok(());
    }
    plan.apply(isotope::GCLOUD)?;
    writeln!(stdout, "╰─ installed Gcloud Isotope").ok();
    super::write_secret_gate_notice(stdout, "gcloud");
    Ok(())
}

pub(crate) fn detect() -> HardenerDetection {
    isotope::detect(isotope::GCLOUD)
}

fn command(program: &str) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null());
    command
}

pub(crate) fn extract_and_verify(archive: &Path, destination: &Path) -> Result<PathBuf, String> {
    let listing = command("/usr/bin/tar")
        .arg("-tzf")
        .arg(archive)
        .output()
        .map_err(|error| format!("cannot inspect Gcloud archive: {error}"))?;
    if !listing.status.success() {
        return Err("invalid Gcloud archive".into());
    }
    let listing = std::str::from_utf8(&listing.stdout).map_err(|_| "invalid archive paths")?;
    if listing.is_empty() || listing.lines().any(|entry| !safe_archive_path(entry)) {
        return Err("Gcloud archive contains unexpected paths".into());
    }
    // bsdtar's default secure extraction rejects traversal through symlinks and
    // external hard links. Never use -P. Strip archived ownership, ACLs and flags.
    let status = command("/usr/bin/tar")
        .args(["-xzf"])
        .arg(archive)
        .args([
            "--no-same-owner",
            "--no-same-permissions",
            "--no-acls",
            "--no-xattrs",
            "--no-fflags",
            "--safe-writes",
            "-C",
        ])
        .arg(destination)
        .status()
        .map_err(|error| format!("cannot extract Gcloud: {error}"))?;
    if !status.success() {
        return Err("Gcloud archive extraction failed".into());
    }
    let bundle = destination.join("Gcloud.app");
    verify_bundle(&bundle, false)?;
    Ok(bundle)
}

fn safe_archive_path(entry: &str) -> bool {
    let mut components = Path::new(entry).components();
    components.next() == Some(Component::Normal("Gcloud.app".as_ref()))
        && components.all(|part| matches!(part, Component::Normal(_)))
}

fn verify_bundle(bundle: &Path, protected: bool) -> Result<(), String> {
    fn walk(path: &Path, root: &Path, protected: bool) -> Result<(), String> {
        let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        if protected && metadata.uid() != 0 {
            return Err("Gcloud runtime must be root-owned".into());
        }
        if metadata.file_type().is_symlink() {
            if !fs::canonicalize(path)
                .map_err(|error| error.to_string())?
                .starts_with(root)
            {
                return Err("Gcloud resource link escapes bundle".into());
            }
        } else if metadata.is_dir() || metadata.is_file() {
            if metadata.mode() & 0o7022 != 0 {
                return Err("Gcloud resource has unsafe permissions".into());
            }
            if metadata.is_file() {
                let mut magic = [0; 4];
                if fs::File::open(path)
                    .and_then(|mut file| file.read_exact(&mut magic))
                    .is_ok()
                    && matches!(
                        magic,
                        [0xcf, 0xfa, 0xed, 0xfe]
                            | [0xce, 0xfa, 0xed, 0xfe]
                            | [0xca, 0xfe, 0xba, 0xbe]
                            | [0xbe, 0xba, 0xfe, 0xca]
                    )
                {
                    verify_native(path)?;
                }
            }
            if metadata.is_dir() {
                for entry in fs::read_dir(path).map_err(|error| error.to_string())? {
                    walk(
                        &entry.map_err(|error| error.to_string())?.path(),
                        root,
                        protected,
                    )?;
                }
            }
        } else {
            return Err("invalid Gcloud resource type".into());
        }
        Ok(())
    }
    if !fs::symlink_metadata(bundle).is_ok_and(|metadata| metadata.is_dir()) {
        return Err("Gcloud bundle must be a real directory".into());
    }
    let canonical = fs::canonicalize(bundle).map_err(|error| error.to_string())?;
    walk(bundle, &canonical, protected)?;
    let requirement = "=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = ZU76A67LGU and identifier \"com.automicvault.gcloud\"";
    let status = command("/usr/bin/codesign")
        .args([
            "--verify",
            "--deep",
            "--strict",
            "--all-architectures",
            "-R",
            requirement,
        ])
        .arg(bundle)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| error.to_string())?;
    if !status.success() {
        return Err("Gcloud bundle signature is invalid".into());
    }
    Ok(())
}

fn verify_native(path: &Path) -> Result<(), String> {
    let details = command("/usr/bin/codesign")
        .args(["-d", "-vvv"])
        .arg(path)
        .output()
        .map_err(|error| error.to_string())?;
    let details_text = String::from_utf8_lossy(&details.stderr);
    if !details.status.success()
        || !details_text.contains("flags=0x10000(runtime)")
        || !details_text.contains("Authority=Developer ID Application:")
        || !details_text.contains("TeamIdentifier=ZU76A67LGU")
        || !details_text.contains("Timestamp=")
    {
        return Err(
            "Gcloud native resource lacks Developer ID Hardened Runtime protections".into(),
        );
    }
    let entitlements = command("/usr/bin/codesign")
        .args(["-d", "--entitlements", ":-"])
        .arg(path)
        .output()
        .map_err(|error| error.to_string())?;
    let xml = String::from_utf8_lossy(&entitlements.stdout);
    if !entitlements.status.success() || !xml.is_empty() {
        return Err("Gcloud native resource has unexpected entitlements".into());
    }
    Ok(())
}

pub(crate) fn verify_installed() -> Result<(), String> {
    let bundle = Path::new(PREFIX).join("Gcloud.app");
    verify_bundle(&bundle, true)?;
    // The authenticated bootstrap checks every ancestor and effective ACL access
    // before loading any mutable resource. --version never requests a Credential.
    let output = command(TARGET)
        .arg("--version")
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("Gcloud runtime validation failed".into());
    }
    Ok(())
}

pub(crate) fn install_privileged(digest: &str, archive: &Path) -> Result<(), String> {
    if super::effective_uid() != 0 {
        return Err("Gcloud installation requires root".into());
    }
    isotope::validate_sha256(digest)?;
    let prefix = Path::new(PREFIX);
    isotope::prepare_install_directory(prefix)?;
    for directory in prefix.ancestors() {
        let acl = command("/bin/ls")
            .args(["-lde"])
            .arg(directory)
            .output()
            .map_err(|error| error.to_string())?;
        if !acl.status.success() || String::from_utf8_lossy(&acl.stdout).lines().count() != 1 {
            return Err(format!(
                "refusing installation through directory with ACLs: {}",
                directory.display()
            ));
        }
    }
    let temporary = isotope::TemporaryDirectory::new_in(prefix, "gcloud")?;
    let trusted_archive = temporary.path.join("isotope.tgz");
    isotope::copy_new(archive, &trusted_archive)?;
    if isotope::sha256_file(&trusted_archive)? != digest {
        return Err("Gcloud archive changed before installation".into());
    }
    let bundle = extract_and_verify(&trusted_archive, &temporary.path)?;
    verify_bundle(&bundle, true)?;
    let destination = prefix.join("Gcloud.app");
    let previous = temporary.path.join("previous.app");
    let existed = destination.symlink_metadata().is_ok();
    if existed {
        fs::rename(&destination, &previous).map_err(|error| error.to_string())?;
    }
    if let Err(error) = fs::rename(&bundle, &destination) {
        if existed {
            fs::rename(&previous, &destination)
                .map_err(|rollback| format!("{error}; rollback failed: {rollback}"))?;
        }
        return Err(error.to_string());
    }
    // Do not run the network-capable CLI as root during installation.
    let receipt = isotope::receipt_path(isotope::GCLOUD);
    isotope::prepare_install_directory(receipt.parent().unwrap())?;
    let staged_receipt = temporary.path.join("receipt");
    fs::write(&staged_receipt, format!("{digest}\n")).map_err(|error| error.to_string())?;
    fs::set_permissions(&staged_receipt, fs::Permissions::from_mode(0o644))
        .map_err(|error| error.to_string())?;
    fs::rename(staged_receipt, receipt).map_err(|error| error.to_string())?;
    let bin = Path::new("/usr/local/bin");
    isotope::prepare_install_directory(bin)?;
    let link = bin.join(format!(".gcloud-av-{}", isotope::now_nanos()));
    std::os::unix::fs::symlink(TARGET, &link).map_err(|error| error.to_string())?;
    if let Err(error) = fs::rename(&link, bin.join("gcloud")) {
        let _ = fs::remove_file(&link);
        return Err(error.to_string());
    }
    Ok(())
}

pub(crate) fn secret_gate() -> SecretGateDescriptor {
    let keys = vec!["GCLOUD_AUTH_*".to_string()];
    SecretGateDescriptor {
        id: "gcloud",
        key_patterns: keys.clone(),
        routes: vec![SecretGateRoute {
            operation: "keys",
            script_path: None,
            target_path: "/opt/av/gcloud/Gcloud.app/Contents/MacOS/gcloud".to_string(),
            caller_identifiers: vec!["com.automicvault.gcloud"],
            key_patterns: keys,
            replace_existing_env: true,
            allow_missing_keys: false,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extraction_cannot_write_through_external_links() {
        for bytes in [
            include_bytes!("testdata/wrangler-symlink-escape.tgz").as_slice(),
            include_bytes!("testdata/wrangler-hardlink-escape.tgz").as_slice(),
        ] {
            let temp =
                isotope::TemporaryDirectory::new_in(&std::env::temp_dir(), "gcloud-test").unwrap();
            let stage = temp.path.join("stage");
            let outside = temp.path.join("outside");
            fs::create_dir(&stage).unwrap();
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("sentinel"), "original").unwrap();
            let archive = temp.path.join("attack.tgz");
            fs::write(&archive, bytes).unwrap();
            assert!(extract_and_verify(&archive, &stage).is_err());
            assert_eq!(
                fs::read_to_string(outside.join("sentinel")).unwrap(),
                "original"
            );
        }
    }

    #[test]
    #[ignore = "requires a locally signed Gcloud release archive"]
    fn signed_release_extracts_and_verifies() {
        let archive = std::env::var("GCLOUD_TEST_ARCHIVE").unwrap();
        let temp =
            isotope::TemporaryDirectory::new_in(&std::env::temp_dir(), "gcloud-release-test")
                .unwrap();
        extract_and_verify(Path::new(&archive), &temp.path).unwrap();
    }

    #[test]
    fn archive_paths_stay_inside_the_bundle() {
        assert!(safe_archive_path("Gcloud.app/Contents/MacOS/gcloud"));
        assert!(safe_archive_path("Gcloud.app/"));
        for path in [
            "/Gcloud.app/file",
            "Gcloud.app/../escape",
            "bin/gcloud",
            "../Gcloud.app",
            "",
        ] {
            assert!(!safe_archive_path(path), "{path}");
        }
    }
}
