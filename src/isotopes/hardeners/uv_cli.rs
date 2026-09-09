use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use zeroize::Zeroizing;

use super::{
    HardenerDetection, HardenerDiagnostic, RequiredExecutable, RequiredIdentity,
    SecretGateDescriptor, SecretGateRoute, StubRequirements, isotope,
};
use crate::uv::*;

const MAX_ARCHIVE: u64 = 64 * 1024 * 1024;
const MAX_BINARY: u64 = 128 * 1024 * 1024;
const ROOT: &str = "/opt/av/uv";

fn release() -> Result<(&'static str, &'static str, &'static str, &'static str), String> {
    match std::env::consts::ARCH {
        "aarch64" => Ok((
            "aarch64",
            "46740540b63fdee9a6cb2e19baf3f1f475b850c440a33e63455087a6871263f1",
            "53cf843c2eed12d1cafdaab7a1ba95e53496f7df280fc2be4fa8f3d7c32a1496",
            "uv-924a20a6cc8daa66",
        )),
        "x86_64" => Ok((
            "x86_64",
            "0dc8cd6c961582b0d140b5398f96b23502885277fb3464241456a2435e460dfa",
            "e4ae6d0f64373f52071f20ddfa493f943e6b40983fcb71cccaeb3ed54380bf84",
            "uv",
        )),
        _ => Err("official uv is supported only on macOS arm64 and x86_64".into()),
    }
}

pub(crate) fn run(stdout: &mut dyn Write, yes: bool) -> Result<(), String> {
    super::PrivilegeMode::Mixed.require_user("uv", false)?;
    crate::cli::ensure_uv_helper_ready()?;
    let path = credentials_path()?;
    let source = read_credentials(&path)?;
    let imported = source
        .as_ref()
        .map(|v| Credentials::from_toml(v))
        .transpose()?;
    writeln!(stdout, "╭─ harden uv\n│\n◆ Install official signed uv {VERSION} under /opt/av/uv and register uv/uvx operations with Automic Vault.").ok();
    if let Some(credentials) = &imported {
        writeln!(
            stdout,
            "├─ move {} HTTP credentials from {} into {SECRET}",
            credentials.credential.len(),
            path.display()
        )
        .ok();
    } else {
        writeln!(
            stdout,
            "├─ no plaintext credential store found; existing {SECRET} remains unchanged"
        )
        .ok();
    }
    writeln!(stdout, "├─ private indexes must configure a username or authenticate = \"always\" for keyring lookup").ok();
    writeln!(stdout, "├─ use a process-bound keyring helper; native Keychain and other ambient credentials are not migrated\n│").ok();
    if !yes {
        write!(stdout, "◇ Continue? [y/N] ").map_err(|e| e.to_string())?;
        stdout.flush().map_err(|e| e.to_string())?;
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| e.to_string())?;
        if !matches!(input.trim(), "y" | "Y" | "yes") {
            return Ok(());
        }
    }
    let temporary = isotope::TemporaryDirectory::new_in(&std::env::temp_dir(), "uv-release")?;
    let archive = temporary.path.join("uv.tar.gz");
    download(&archive)?;
    if let Some(credentials) = imported {
        let encoded =
            Zeroizing::new(serde_json::to_string(&credentials).map_err(|e| e.to_string())?);
        if encoded.len() > 1024 * 1024 {
            return Err("encoded uv credential bundle exceeds 1 MiB".into());
        }
        crate::secrets::store_secret_if_absent_or_equal(SECRET, &encoded)?;
    }
    let status = Command::new("/usr/bin/sudo")
        .args(["--", "/usr/local/bin/av", "__install-uv-release"])
        .arg(&archive)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("official uv installation failed; original credentials retained".into());
    }
    verify_installation()?;
    if let Some(original) = source {
        // Coordinate with uv's credentials.toml.lock before comparing and removing.
        let lock_path = path.with_extension("toml.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&lock_path)
            .map_err(|e| e.to_string())?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("uv credentials are in use; plaintext retained; retry hardening".into());
        }
        if read_credentials(&path)?.as_ref().map(|v| v.as_str()) != Some(original.as_str()) {
            return Err("uv credentials changed during hardening; plaintext retained".into());
        }
        fs::remove_file(&path)
            .map_err(|e| format!("failed to remove plaintext uv credentials: {e}"))?;
    }
    writeln!(stdout, "╰─ hardened uv").ok();
    super::write_secret_gate_notice(stdout, "uv");
    Ok(())
}

fn read_credentials(path: &Path) -> Result<Option<Zeroizing<String>>, String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read uv credentials: {e}")),
    };
    if !file
        .metadata()
        .is_ok_and(|m| m.is_file() && m.len() <= 1024 * 1024)
    {
        return Err("uv credential store must be a regular file at most 1 MiB".into());
    }
    let mut value = Zeroizing::new(String::new());
    file.take(1024 * 1024 + 1)
        .read_to_string(&mut value)
        .map_err(|e| e.to_string())?;
    if value.len() > 1024 * 1024 {
        return Err("uv credential store exceeds 1 MiB".into());
    }
    Ok(Some(value))
}

fn download(destination: &Path) -> Result<(), String> {
    let (arch, hash, _, _) = release()?;
    let url = format!(
        "https://github.com/astral-sh/uv/releases/download/{VERSION}/uv-{arch}-apple-darwin.tar.gz"
    );
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(5)
        .timeout_global(Some(Duration::from_secs(180)))
        .build()
        .into();
    let mut body = agent
        .get(&url)
        .call()
        .map_err(|e| format!("uv download failed: {e}"))?
        .into_body()
        .into_reader()
        .take(MAX_ARCHIVE + 1);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .map_err(|e| e.to_string())?;
    if std::io::copy(&mut body, &mut file).map_err(|e| e.to_string())? > MAX_ARCHIVE {
        return Err("uv archive exceeds 64 MiB".into());
    }
    file.sync_all().map_err(|e| e.to_string())?;
    if isotope::sha256_file(destination)? != hash {
        return Err("official uv archive checksum mismatch".into());
    }
    Ok(())
}

pub(crate) fn install_privileged(archive: &Path) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("uv installation requires root".into());
    }
    if std::env::var_os("AUTOMIC_VAULT_TEST_ISOTOPE_DIRECT_DIR").is_some() {
        return Err("test path overrides are forbidden during privileged uv installation".into());
    }
    isotope::prepare_install_directory(Path::new(ROOT))?;
    let staging = isotope::TemporaryDirectory::new_in(Path::new(ROOT), "install")?;
    let trusted = staging.path.join("archive.tar.gz");
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(archive)
        .map_err(|e| e.to_string())?;
    if !input
        .metadata()
        .is_ok_and(|m| m.is_file() && m.len() <= MAX_ARCHIVE)
    {
        return Err("invalid uv archive file".into());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&trusted)
        .map_err(|e| e.to_string())?;
    if std::io::copy(
        &mut Read::by_ref(&mut input).take(MAX_ARCHIVE + 1),
        &mut output,
    )
    .map_err(|e| e.to_string())?
        > MAX_ARCHIVE
    {
        return Err("uv archive grew during copy".into());
    }
    output.sync_all().map_err(|e| e.to_string())?;
    if isotope::sha256_file(&trusted)? != release()?.1 {
        return Err("privileged uv archive checksum mismatch".into());
    }
    let staged_binary = staging.path.join("uv");
    extract_binary(&trusted, &staged_binary, true)?;
    fs::set_permissions(&staged_binary, fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    verify_binary(&staged_binary)?;
    isotope::prepare_install_directory(Path::new(TARGET).parent().unwrap())?;
    isotope::prepare_install_directory(Path::new(HELPER).parent().unwrap())?;
    isotope::prepare_install_directory(Path::new("/usr/local/bin"))?;
    fs::rename(&staged_binary, TARGET).map_err(|e| e.to_string())?;
    for (path, contents) in [
        (HELPER, HELPER_STUB),
        ("/usr/local/bin/uv", STUB),
        ("/usr/local/bin/uvx", UVX_STUB),
    ] {
        let destination = Path::new(path);
        let temporary = destination.with_extension(format!("av-{}", isotope::now_nanos()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        file.write_all(contents.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| e.to_string())?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
        fs::rename(&temporary, destination).map_err(|e| e.to_string())?;
    }
    verify_installation()
}

fn extract_binary(archive: &Path, destination: &Path, drop_privileges: bool) -> Result<(), String> {
    let member = format!("uv-{}-apple-darwin/uv", release()?.0);
    let mut command = Command::new("/usr/bin/tar");
    command
        .args(["-xzOf", "-", &member])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(File::open(archive).map_err(|e| e.to_string())?)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if drop_privileges {
        command.uid(65534).gid(65534);
    }
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(destination)
            .map_err(|e| e.to_string())?;
        let size = std::io::copy(
            &mut child.stdout.take().unwrap().take(MAX_BINARY + 1),
            &mut file,
        )
        .map_err(|e| e.to_string())?;
        if size == 0 || size > MAX_BINARY {
            return Err("invalid uv binary size".into());
        }
        file.sync_all().map_err(|e| e.to_string())?;
        if !child.wait().map_err(|e| e.to_string())?.success() {
            return Err("uv extraction failed".into());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

pub(crate) fn verify_binary(path: &Path) -> Result<(), String> {
    let (_, _, hash, identifier) = release()?;
    if isotope::sha256_file(path)? != hash {
        return Err("uv binary does not match the reviewed release".into());
    }
    let requirement = format!(
        "=identifier \"{identifier}\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"2DC432GLL2\""
    );
    let status = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "-R", &requirement])
        .arg(path)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("official uv Developer ID signature is invalid".into());
    }
    // The pinned digest also binds the reviewed Hardened Runtime flags and empty entitlements.
    Ok(())
}

fn protected(path: &Path, mode: u32, directory: bool) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != mode
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file() || metadata.nlink() != 1
        }
    {
        return Err(format!("unsafe uv installation entry: {}", path.display()));
    }
    Ok(())
}

pub(crate) fn verify_stub(path: &Path, contents: &str) -> Result<(), String> {
    protected(path, 0o755, false)?;
    if fs::read(path).ok().as_deref() != Some(contents.as_bytes()) {
        return Err("uv launcher contents changed".into());
    }
    Ok(())
}

pub(crate) fn verify_installation() -> Result<(), String> {
    for directory in [
        "/opt",
        "/opt/av",
        ROOT,
        "/opt/av/uv/0.12.12",
        "/opt/av/uv/bin",
        "/usr/local",
        "/usr/local/bin",
    ] {
        let metadata = fs::symlink_metadata(directory).map_err(|e| e.to_string())?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(format!("unsafe uv installation directory: {directory}"));
        }
    }
    protected(Path::new(TARGET), 0o755, false)?;
    verify_binary(Path::new(TARGET))?;
    for (path, stub) in [
        (HELPER, HELPER_STUB),
        ("/usr/local/bin/uv", STUB),
        ("/usr/local/bin/uvx", UVX_STUB),
    ] {
        verify_stub(Path::new(path), stub)?;
    }
    Ok(())
}

pub(crate) fn detect() -> HardenerDetection {
    let installed = verify_stub(Path::new("/usr/local/bin/uv"), STUB).is_ok();
    let mut detection = HardenerDetection::command(
        installed,
        "uv",
        Some("/usr/local/bin/uv".into()),
        TARGET.into(),
    );
    detection.commands[0].injected_keys = vec![SECRET.into()];
    detection.commands[0].required_paths = vec![
        RequiredExecutable {
            name: "Automic Vault CLI",
            path: "/usr/local/bin/av".into(),
        },
        RequiredExecutable {
            name: "uv keyring helper",
            path: HELPER.into(),
        },
    ];
    detection.commands[0].stub_requirements = Some(StubRequirements {
        mode: 0o755,
        owner: RequiredIdentity {
            name: "root",
            id: Some(0),
        },
        group: RequiredIdentity {
            name: "wheel",
            id: Some(0),
        },
    });
    if installed && let Err(error) = verify_installation() {
        detection.commands[0].stub_valid = false;
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "uv_release_invalid",
            message: error,
            remediation:
                "Run `av harden uv` to reinstall the reviewed official release and helpers.".into(),
            path: Some(TARGET.into()),
        });
    }
    let mut uvx = detection.commands[0].clone();
    uvx.name = "uvx".into();
    uvx.stub_path = Some("/usr/local/bin/uvx".into());
    uvx.hardened = verify_stub(Path::new("/usr/local/bin/uvx"), UVX_STUB).is_ok();
    uvx.stub_valid = uvx.hardened && detection.commands[0].stub_valid;
    detection.commands.push(uvx);
    detection
}

pub(crate) fn secret_gate() -> SecretGateDescriptor {
    SecretGateDescriptor {
        id: "uv",
        key_patterns: vec![SECRET.into()],
        routes: vec![SecretGateRoute {
            operation: "uv-get",
            script_path: None,
            target_path: TARGET.into(),
            caller_identifiers: vec!["com.automicvault.av"],
            key_patterns: vec![SECRET.into()],
            replace_existing_env: false,
            allow_missing_keys: false,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn release_pins_and_migration_input_are_bounded() {
        let (_, archive, binary, _) = release().unwrap();
        isotope::validate_sha256(archive).unwrap();
        isotope::validate_sha256(binary).unwrap();
        assert_ne!(archive, binary);
        let root = isotope::TemporaryDirectory::new_in(&std::env::temp_dir(), "uv-test").unwrap();
        assert!(read_credentials(&root.path).is_err());
        let path = root.path.join("credentials.toml");
        assert!(read_credentials(&path).unwrap().is_none());
        std::os::unix::fs::symlink("/dev/null", &path).unwrap();
        assert!(read_credentials(&path).is_err());
    }
}
