use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use super::{HardenerDetection, RootOnlyOutcome};
use crate::isotopes::detectors::emudhra::{CERT_PATH, cert_path, filtered_bundle, validate_bundle};

pub(crate) fn run(stdout: &mut dyn Write, color: bool) -> Result<RootOnlyOutcome, String> {
    if !cfg!(target_os = "macos") {
        return Err("this hardener requires macOS".into());
    }
    let path = cert_path();
    let contents = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let (_, roots) = filtered_bundle(&contents)?;
    writeln!(stdout, "╭─ harden emudhra").ok();
    if roots.is_empty() {
        let text = "already hardened ✔︎";
        writeln!(
            stdout,
            "╰─ {}",
            if color {
                format!("\x1b[32m{text}\x1b[0m")
            } else {
                text.into()
            }
        )
        .ok();
        return Ok(RootOnlyOutcome::Hardened);
    }
    writeln!(
        stdout,
        "├─ remove emSign ECC Root CA - G3 and AAA Certificate Services from {CERT_PATH}"
    )
    .ok();
    writeln!(
        stdout,
        "├─ sites relying on these roots may fail TLS verification"
    )
    .ok();
    if super::effective_uid() != 0 {
        writeln!(stdout, "╰─ next: sudo av harden emudhra").ok();
        return Ok(RootOnlyOutcome::Previewed);
    }
    harden(&path)?;
    writeln!(stdout, "╰─ hardened emudhra").ok();
    Ok(RootOnlyOutcome::Hardened)
}

pub(crate) fn detect() -> HardenerDetection {
    let hardened = fs::read_to_string(cert_path())
        .ok()
        .and_then(|contents| filtered_bundle(&contents).ok())
        .is_some_and(|(_, roots)| roots.is_empty());
    HardenerDetection::configuration(hardened, cfg!(target_os = "macos"), Some(CERT_PATH.into()))
}

fn trusted(metadata: &fs::Metadata) -> bool {
    let owner = if cfg!(test) {
        unsafe { libc::geteuid() }
    } else {
        0
    };
    (metadata.uid() == 0 || metadata.uid() == owner) && metadata.permissions().mode() & 0o022 == 0
}

fn open_bundle(path: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("failed to open {}: {e}", path.display()))?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.nlink() != 1 || !trusted(&metadata) {
        return Err(format!("refusing untrusted {}", path.display()));
    }
    Ok(file)
}

fn harden(path: &Path) -> Result<(), String> {
    let parent = path.parent().ok_or("missing certificate directory")?;
    if !fs::symlink_metadata(parent)
        .map_err(|e| e.to_string())?
        .is_dir()
    {
        return Err("refusing a symlinked certificate directory".into());
    }
    // /etc itself is Apple's symlink to /private/etc; validate the resolved ancestry.
    let canonical = parent.canonicalize().map_err(|e| e.to_string())?;
    for ancestor in canonical.ancestors() {
        if !trusted(&fs::metadata(ancestor).map_err(|e| e.to_string())?) {
            return Err(format!(
                "refusing untrusted directory {}",
                ancestor.display()
            ));
        }
    }
    let mut original = open_bundle(path)?;
    let metadata = original.metadata().map_err(|e| e.to_string())?;
    let mut contents = String::new();
    original
        .read_to_string(&mut contents)
        .map_err(|e| e.to_string())?;
    let (replacement, roots) = filtered_bundle(&contents)?;
    if roots.is_empty() {
        return Ok(());
    }
    validate_bundle(&replacement)?;

    let backup = path.with_file_name("cert.pem.orig");
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&backup)
    {
        Ok(mut file) => {
            if let Err(error) = file
                .write_all(contents.as_bytes())
                .and_then(|()| file.sync_all())
            {
                let _ = fs::remove_file(&backup);
                return Err(format!("could not back up certificate bundle: {error}"));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut existing = String::new();
            open_bundle(&backup)?
                .read_to_string(&mut existing)
                .map_err(|e| e.to_string())?;
            validate_bundle(&existing)?;
        }
        Err(e) => return Err(format!("could not back up certificate bundle: {e}")),
    }
    let temp = parent.join(format!(".cert.pem.av-{:016x}", rand::random::<u64>()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&temp)
        .map_err(|e| e.to_string())?;
    let result = (|| {
        file.write_all(replacement.as_bytes())
            .map_err(|e| e.to_string())?;
        file.set_permissions(fs::Permissions::from_mode(0o644))
            .map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        let mut current = open_bundle(path)?;
        let current_metadata = current.metadata().map_err(|e| e.to_string())?;
        let mut current_contents = String::new();
        current
            .read_to_string(&mut current_contents)
            .map_err(|e| e.to_string())?;
        if current_metadata.ino() != metadata.ino()
            || current_metadata.dev() != metadata.dev()
            || current_contents != contents
        {
            return Err("certificate bundle changed during hardening; retry".into());
        }
        fs::rename(&temp, path).map_err(|e| e.to_string())?;
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| e.to_string())?;
        let installed = fs::read_to_string(path).map_err(|e| e.to_string())?;
        if installed != replacement || !filtered_bundle(&installed)?.1.is_empty() {
            return Err("failed to verify hardened certificate bundle".into());
        }
        Ok(())
    })();
    let _ = fs::remove_file(temp);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    const EMSIGN: &str = include_str!("../detectors/emudhra/testdata/emsign.pem");
    const AAA: &str = include_str!("../detectors/emudhra/testdata/aaa.pem");
    const SAFE: &str = include_str!("../detectors/emudhra/testdata/unaffected.pem");

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new(contents: &str) -> Self {
            let dir = std::env::current_dir()
                .unwrap()
                .join(format!(".emudhra-test-{:016x}", rand::random::<u64>()));
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("cert.pem"), contents).unwrap();
            Self(dir)
        }
        fn path(&self) -> std::path::PathBuf {
            self.0.join("cert.pem")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn backs_up_replaces_and_is_idempotent() {
        let input = format!("{SAFE}{EMSIGN}{AAA}");
        let fixture = Fixture::new(&input);
        harden(&fixture.path()).unwrap();
        let installed = fs::read_to_string(fixture.path()).unwrap();
        assert!(filtered_bundle(&installed).unwrap().1.is_empty());
        assert!(installed.contains(SAFE.trim()));
        assert_eq!(
            fs::read_to_string(fixture.0.join("cert.pem.orig")).unwrap(),
            input
        );
        assert_eq!(
            fs::metadata(fixture.path()).unwrap().permissions().mode() & 0o777,
            0o644
        );
        harden(&fixture.path()).unwrap();
        assert_eq!(fs::read_to_string(fixture.path()).unwrap(), installed);
        assert_eq!(
            fs::read_to_string(fixture.0.join("cert.pem.orig")).unwrap(),
            input
        );
    }

    #[test]
    fn preserves_existing_backup() {
        let fixture = Fixture::new(&format!("{SAFE}{EMSIGN}"));
        fs::write(fixture.0.join("cert.pem.orig"), SAFE).unwrap();
        harden(&fixture.path()).unwrap();
        assert_eq!(
            fs::read_to_string(fixture.0.join("cert.pem.orig")).unwrap(),
            SAFE
        );
    }

    #[test]
    fn refuses_unsafe_files_without_modifying_them() {
        for attack in [
            "symlink",
            "backup-symlink",
            "hardlink",
            "writable",
            "directory",
            "empty-result",
            "invalid",
        ] {
            let input = match attack {
                "empty-result" => EMSIGN.to_string(),
                "invalid" => {
                    "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----".to_string()
                }
                _ => format!("{SAFE}{EMSIGN}"),
            };
            let fixture = Fixture::new(&input);
            let victim = fixture.0.join("victim");
            fs::write(&victim, "untouched").unwrap();
            match attack {
                "symlink" => {
                    fs::remove_file(fixture.path()).unwrap();
                    symlink(&victim, fixture.path()).unwrap();
                }
                "backup-symlink" => symlink(&victim, fixture.0.join("cert.pem.orig")).unwrap(),
                "hardlink" => fs::hard_link(fixture.path(), fixture.0.join("alias")).unwrap(),
                "writable" => {
                    fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o666)).unwrap()
                }
                "directory" => {
                    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o777)).unwrap()
                }
                _ => {}
            }
            assert!(harden(&fixture.path()).is_err(), "{attack}");
            assert_eq!(fs::read_to_string(victim).unwrap(), "untouched");
            if attack != "symlink" {
                assert_eq!(fs::read_to_string(fixture.path()).unwrap(), input);
            }
        }
    }

    #[test]
    fn previews_without_writing_then_reports_hardened() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let input = format!("{SAFE}{EMSIGN}{AAA}");
        let fixture = Fixture::new(&input);
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_EMUDHRA_CERT_PATH", fixture.path());
            std::env::set_var("AUTOMIC_VAULT_TEST_EUID", "501");
        }
        let mut output = Vec::new();
        let preview = run(&mut output, false);
        let before = detect();
        let findings = crate::isotopes::detectors::emudhra::findings(&fixture.0);
        let unchanged = fs::read_to_string(fixture.path()).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_EUID", "0");
        }
        let applied = run(&mut Vec::new(), false);
        let after = detect();
        let clean = crate::isotopes::detectors::emudhra::findings(&fixture.0);
        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_EMUDHRA_CERT_PATH");
            std::env::remove_var("AUTOMIC_VAULT_TEST_EUID");
        }
        assert_eq!(preview.unwrap(), RootOnlyOutcome::Previewed);
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("sudo av harden emudhra")
        );
        assert_eq!(unchanged, input);
        assert!(!before.hardened);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|finding| finding.severity == "high"));
        assert_eq!(applied.unwrap(), RootOnlyOutcome::Hardened);
        assert!(after.hardened);
        assert!(clean.is_empty());
    }

    #[test]
    fn unreadable_or_invalid_bundle_is_not_reported_as_hardened() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let fixture = Fixture::new("not a certificate");
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_EMUDHRA_CERT_PATH", fixture.path());
        }
        let hardened = detect().hardened;
        let findings = crate::isotopes::detectors::emudhra::findings(&fixture.0);
        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_EMUDHRA_CERT_PATH");
        }
        assert!(!hardened);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].explanation.contains("Could not check"));
    }
}
