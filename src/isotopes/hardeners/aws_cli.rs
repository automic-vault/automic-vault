use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    HardenerDetection, HardenerDiagnostic, RequiredExecutable, RequiredIdentity,
    SecretGateDescriptor, SecretGateRoute, StubRequirements, aws_release,
};

const AWS_ACCESS_KEY_ID: &str = "AWS_ACCESS_KEY_ID";
const AWS_SECRET_ACCESS_KEY: &str = "AWS_SECRET_ACCESS_KEY";
const AWS_HARDEN_PROFILE: &str = "default";
const AWS_STUB: &str = include_str!("aws");
// Exact native-helper launcher used before the official AWS distribution migration.
const HOMEBREW_AWS_STUB: &str = include_str!("aws.homebrew");
// Exact previously released launcher: any edit must remain an invalid stub.
const LEGACY_AWS_STUB: &str = include_str!("aws.legacy");
const AWS_STUB_PATH: &str = "/usr/local/bin/aws";
const AWS_HOMEBREW_TARGET_PATH: &str = "/opt/homebrew/bin/aws";
const AV_PATH: &str = "/usr/local/bin/av";
const SUDO_PATH: &str = "/usr/bin/sudo";
const PRIVILEGE_MODE: super::PrivilegeMode = super::PrivilegeMode::Mixed;

unsafe extern "C" {
    fn geteuid() -> u32;
}

pub(crate) fn run_aws(stdout: &mut dyn Write, yes: bool) -> Result<(), String> {
    let has_test_stub = crate::test_env_var("AUTOMIC_VAULT_TEST_AWS_STUB_PATH").is_some();
    PRIVILEGE_MODE.require_user("aws", has_test_stub)?;
    let is_root = super::effective_uid() == 0;
    if !has_test_stub {
        crate::cli::ensure_aws_helper_ready()?;
    }
    let has_test_keychain = crate::test_keychain_dir().is_some();
    let should_import_credentials = should_import_aws_credentials(is_root, has_test_keychain);
    let credentials_path = if should_import_credentials {
        Some(aws_credentials_path()?)
    } else {
        None
    };
    let credentials = if let Some(credentials_path) = &credentials_path {
        read_aws_credentials(credentials_path, AWS_HARDEN_PROFILE)?
    } else {
        None
    };

    writeln!(stdout, "╭─ harden aws").ok();
    writeln!(stdout, "│").ok();
    writeln!(
        stdout,
        "◆ This will install AWS's official CLI release and use Automic Vault for temporary AWS credentials."
    )
    .ok();
    writeln!(stdout, "│").ok();
    if !has_test_stub {
        writeln!(
            stdout,
            "├─ download AWS's latest available versioned package from {}",
            aws_release::DOWNLOAD_ROOT
        )
        .ok();
        writeln!(
            stdout,
            "├─ verify Amazon's Apple-issued installer identity, notarization, timestamp, package identity, signed native payload, Hardened Runtime, and safe extraction limits"
        )
        .ok();
        writeln!(
            stdout,
            "├─ extract the payload to /opt/av/aws without running the package installer or its scripts"
        )
        .ok();
        writeln!(
            stdout,
            "├─ replace the Homebrew-backed Target because Homebrew's Python runtime is independently mutable and may lag AWS releases"
        )
        .ok();
    }
    if let Some(credentials_path) = &credentials_path {
        if credentials.is_some() {
            writeln!(
                stdout,
                "├─ import {AWS_HARDEN_PROFILE} keys from {} into the login keychain",
                credentials_path.display()
            )
            .ok();
            writeln!(
                stdout,
                "├─ delete {AWS_HARDEN_PROFILE} plaintext keys from {}",
                credentials_path.display()
            )
            .ok();
        } else {
            writeln!(
                stdout,
                "├─ no {AWS_HARDEN_PROFILE} plaintext keys found in {}",
                credentials_path.display()
            )
            .ok();
        }
    }

    writeln!(
        stdout,
        "├─ run sudo to install the verified AWS release and launcher"
    )
    .ok();
    writeln!(stdout, "│").ok();
    if !confirm(stdout, yes)? {
        writeln!(stdout, "╰─ cancelled").ok();
        return Ok(());
    }

    let download = if has_test_stub {
        None
    } else {
        let temporary = TemporaryDirectory::new("aws-release")?;
        let package = temporary.path.join("AWSCLIV2.pkg");
        let (version, digest) = aws_release::download(&package)?;
        Some((temporary, version, digest))
    };
    if let Some(credentials) = &credentials {
        import_aws_credentials(credentials)?;
        writeln!(stdout, "├─ imported keys").ok();
    }
    install_privileged(download.as_ref().map(|(directory, version, digest)| {
        (
            directory.path.join("AWSCLIV2.pkg"),
            version.as_str(),
            digest.as_str(),
        )
    }))?;
    if credentials.is_some() {
        let credentials_path = credentials_path.as_ref().unwrap();
        delete_aws_credentials(credentials_path, AWS_HARDEN_PROFILE)?;
        writeln!(stdout, "├─ deleted plaintext keys").ok();
    }
    if !is_aws_stub(&aws_stub_path()) {
        return Err(format!(
            "installed AWS launcher at {AWS_STUB_PATH} failed verification"
        ));
    }
    writeln!(stdout, "╰─ hardened aws").ok();
    super::write_secret_gate_notice(stdout, "aws");
    Ok(())
}

pub(crate) fn install_aws_release(
    version: &str,
    sha256: &str,
    package: &Path,
) -> Result<(), String> {
    if crate::test_env_var("AUTOMIC_VAULT_TEST_AWS_STUB_PATH").is_some()
        || crate::test_env_var("AUTOMIC_VAULT_TEST_AWS_INSTALL_ROOT").is_some()
    {
        return Err("test path overrides are forbidden during privileged installation".into());
    }
    if actual_uid() != 0 {
        return Err("official AWS CLI installation requires root".into());
    }
    aws_release::install_privileged(version, sha256, package)?;
    install_aws_stub(Path::new(AWS_STUB_PATH))
}

pub(crate) fn detect() -> HardenerDetection {
    let path = aws_stub_path();
    let state = aws_stub_state(&path);
    let hardened = state != AwsStubState::Unknown;
    let official = state == AwsStubState::Official;
    let target = if official {
        aws_release::target_path().display().to_string()
    } else {
        AWS_HOMEBREW_TARGET_PATH.to_string()
    };
    let mut detection =
        HardenerDetection::command(hardened, "aws", Some(path.display().to_string()), target);
    detection.commands[0].stub_valid = official;
    if crate::test_env_var("AUTOMIC_VAULT_TEST_AWS_STUB_PATH").is_none() {
        detection.commands[0]
            .required_paths
            .push(RequiredExecutable {
                name: "Automic Vault CLI",
                path: "/usr/local/bin/av".to_string(),
            });
    }
    detection.commands[0].stub_requirements = Some(root_stub_requirements(&path));
    detection.commands[0].injected_keys = vec![
        AWS_ACCESS_KEY_ID.to_string(),
        AWS_SECRET_ACCESS_KEY.to_string(),
    ];
    if official
        && crate::test_env_var("AUTOMIC_VAULT_TEST_AWS_STUB_PATH").is_none()
        && let Err(error) = aws_release::current_release_valid()
    {
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "aws_official_release_invalid",
            message: error,
            remediation:
                "Run `av harden aws` to download and reinstall a verified official AWS CLI release."
                    .into(),
            path: Some(aws_release::target_path().display().to_string()),
        });
    }
    detection
}

fn root_stub_requirements(path: &Path) -> StubRequirements {
    let test_ids = crate::test_env_var("AUTOMIC_VAULT_TEST_AWS_STUB_PATH").and_then(|_| {
        path.parent()
            .and_then(|parent| parent.metadata().ok())
            .map(|metadata| (metadata.uid(), metadata.gid()))
    });
    let (uid, gid) = test_ids.unwrap_or((0, 0));
    StubRequirements {
        mode: 0o755,
        owner: RequiredIdentity {
            name: if test_ids.is_some() {
                "test user"
            } else {
                "root"
            },
            id: Some(uid),
        },
        group: RequiredIdentity {
            name: if test_ids.is_some() {
                "test group"
            } else {
                "wheel"
            },
            id: Some(gid),
        },
    }
}

pub(crate) fn secret_gate() -> SecretGateDescriptor {
    let keys = vec![
        AWS_ACCESS_KEY_ID.to_string(),
        AWS_SECRET_ACCESS_KEY.to_string(),
    ];
    SecretGateDescriptor {
        id: "aws",
        key_patterns: keys.clone(),
        routes: [aws_release::TARGET_PATH, AWS_HOMEBREW_TARGET_PATH]
            .into_iter()
            .map(|target| SecretGateRoute {
                operation: "inject",
                script_path: None,
                target_path: target.to_string(),
                caller_identifiers: vec!["com.automicvault.av"],
                key_patterns: keys.clone(),
                replace_existing_env: false,
                allow_missing_keys: false,
            })
            .collect(),
    }
}

fn confirm(stdout: &mut dyn Write, yes: bool) -> Result<bool, String> {
    if yes {
        writeln!(stdout, "◇ Continue? yes (--yes)").ok();
        return Ok(true);
    }

    write!(stdout, "◇ Continue? [y/N] ").ok();
    stdout
        .flush()
        .map_err(|err| format!("failed to flush prompt: {err}"))?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|err| format!("failed to read confirmation: {err}"))?;
    if !io::stdin().is_terminal() {
        writeln!(stdout).ok();
    }
    Ok(matches!(
        input.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn should_import_aws_credentials(is_root: bool, has_test_keychain: bool) -> bool {
    !is_root || has_test_keychain
}

fn is_aws_stub(path: &Path) -> bool {
    aws_stub_state(path) == AwsStubState::Official
}

fn actual_uid() -> u32 {
    unsafe { geteuid() }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AwsStubState {
    Official,
    HomebrewHelper,
    Legacy,
    Unknown,
}

fn aws_stub_state(path: &Path) -> AwsStubState {
    match fs::read_to_string(path).as_deref() {
        Ok(AWS_STUB) => AwsStubState::Official,
        Ok(HOMEBREW_AWS_STUB) => AwsStubState::HomebrewHelper,
        Ok(LEGACY_AWS_STUB) => AwsStubState::Legacy,
        _ => AwsStubState::Unknown,
    }
}

fn aws_stub_path() -> PathBuf {
    crate::test_env_var("AUTOMIC_VAULT_TEST_AWS_STUB_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(AWS_STUB_PATH))
}

fn install_aws_stub(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("AWS launcher has no parent directory: {}", path.display()))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let staging = parent.join(format!(
        ".aws.automic-vault.{}.{nonce}.tmp",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&staging)
            .map_err(|err| format!("failed to create {}: {err}", staging.display()))?;
        file.write_all(AWS_STUB.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|err| format!("failed to write {}: {err}", staging.display()))?;
        file.set_permissions(fs::Permissions::from_mode(0o755))
            .map_err(|err| format!("failed to chmod {}: {err}", staging.display()))?;
        fs::rename(&staging, path)
            .map_err(|err| format!("failed to replace {}: {err}", path.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(staging);
    }
    result
}

fn install_privileged(package: Option<(PathBuf, &str, &str)>) -> Result<(), String> {
    if crate::test_env_var("AUTOMIC_VAULT_TEST_AWS_STUB_PATH").is_some() {
        return install_aws_stub(&aws_stub_path());
    }
    let (package, version, digest) =
        package.ok_or_else(|| "AWS release download is missing".to_string())?;
    super::env_wrapper::validate_privileged_av(Path::new(AV_PATH))?;
    let installed_revision = Command::new(AV_PATH)
        .arg("__version")
        .output()
        .map_err(|err| format!("failed to check {AV_PATH}: {err}"))?;
    if !installed_revision.status.success()
        || parse_cli_revision(&installed_revision.stdout) != Some(crate::cli::INSTALL_REVISION)
    {
        return Err("update the av CLI from the Automic Vault app before rehardening AWS".into());
    }
    let status = Command::new(SUDO_PATH)
        .args([AV_PATH, "__install-aws-release", version, digest])
        .arg(package)
        .status()
        .map_err(|err| format!("failed to run sudo: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("AWS launcher installation failed: {status}"))
    }
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(label: &str) -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "automic-vault-{label}.{}.{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir(&path)
            .map_err(|err| format!("failed to create {}: {err}", path.display()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|err| format!("failed to protect {}: {err}", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn parse_cli_revision(output: &[u8]) -> Option<u32> {
    std::str::from_utf8(output).ok()?.trim().parse().ok()
}

#[derive(Debug, PartialEq, Eq)]
struct AwsCredentials {
    access_key_id: String,
    secret_access_key: String,
}

fn aws_credentials_path() -> Result<PathBuf, String> {
    if let Some(path) =
        std::env::var_os("AWS_SHARED_CREDENTIALS_FILE").filter(|path| !path.is_empty())
    {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| "HOME is not set".to_string())?;
    Ok(PathBuf::from(home).join(".aws/credentials"))
}

fn read_aws_credentials(path: &Path, profile: &str) -> Result<Option<AwsCredentials>, String> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };
    parse_aws_credentials(&contents, profile)
}

fn parse_aws_credentials(contents: &str, profile: &str) -> Result<Option<AwsCredentials>, String> {
    let mut in_profile = false;
    let mut access_key_id = None;
    let mut secret_access_key = None;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(section) = section_name(trimmed) {
            in_profile = section == profile;
            continue;
        }
        if !in_profile {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "aws_access_key_id" if !value.is_empty() => access_key_id = Some(value.to_string()),
            "aws_secret_access_key" if !value.is_empty() => {
                secret_access_key = Some(value.to_string())
            }
            _ => {}
        }
    }

    match (access_key_id, secret_access_key) {
        (Some(access_key_id), Some(secret_access_key)) => Ok(Some(AwsCredentials {
            access_key_id,
            secret_access_key,
        })),
        (None, None) => Ok(None),
        _ => Err(format!(
            "AWS shared credentials file has incomplete AWS keys for profile {profile}"
        )),
    }
}

fn delete_aws_credentials(path: &Path, profile: &str) -> Result<(), String> {
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let cleaned = remove_aws_credentials(&contents, profile);
    fs::write(path, cleaned).map_err(|err| format!("failed to write {}: {err}", path.display()))
}

fn remove_aws_credentials(contents: &str, profile: &str) -> String {
    let mut in_profile = false;
    let mut out = String::new();
    for line in contents.split_inclusive('\n') {
        let trimmed = line.trim();
        if let Some(section) = section_name(trimmed) {
            in_profile = section == profile;
        }
        if in_profile
            && trimmed.split_once('=').is_some_and(|(key, _)| {
                matches!(key.trim(), "aws_access_key_id" | "aws_secret_access_key")
            })
        {
            continue;
        }
        out.push_str(line);
    }
    out
}

fn section_name(line: &str) -> Option<&str> {
    line.strip_prefix('[')
        .and_then(|line| line.strip_suffix(']'))
        .map(str::trim)
}

fn import_aws_credentials(credentials: &AwsCredentials) -> Result<(), String> {
    store_keychain_secret(AWS_ACCESS_KEY_ID, &credentials.access_key_id)?;
    store_keychain_secret(AWS_SECRET_ACCESS_KEY, &credentials.secret_access_key)
}

pub(crate) fn store_keychain_secret(account: &str, value: &str) -> Result<(), String> {
    crate::secrets::store_secret(account, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn aws_stub_delegates_directly_to_av() {
        let path = temp_path("aws-stub");
        install_aws_stub(&path).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), AWS_STUB);
        assert_eq!(AWS_STUB, "#!/usr/local/bin/av aws-official\n");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn aws_stub_install_replaces_a_symlink_without_following_it() {
        let dir = temp_path("aws-stub-symlink");
        let victim = dir.join("victim");
        let path = dir.join("aws");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&victim, "do not overwrite").unwrap();
        symlink(&victim, &path).unwrap();

        install_aws_stub(&path).unwrap();

        assert_eq!(fs::read_to_string(&victim).unwrap(), "do not overwrite");
        assert_eq!(fs::read_to_string(&path).unwrap(), AWS_STUB);
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_file());
        assert_eq!(
            path.metadata().unwrap().permissions().mode() & 0o7777,
            0o755
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn aws_stub_validation_requires_exact_contents() {
        let path = temp_path("aws-stub-exact");
        fs::write(&path, AWS_STUB).unwrap();
        assert!(is_aws_stub(&path));
        assert!(aws_stub_state(&path) == AwsStubState::Official);

        fs::write(&path, HOMEBREW_AWS_STUB).unwrap();
        assert!(aws_stub_state(&path) == AwsStubState::HomebrewHelper);
        assert!(!is_aws_stub(&path));

        fs::write(&path, LEGACY_AWS_STUB).unwrap();
        assert!(aws_stub_state(&path) == AwsStubState::Legacy);
        assert!(!is_aws_stub(&path));

        fs::write(&path, format!("{AWS_STUB}\n# modified\n")).unwrap();
        assert!(aws_stub_state(&path) == AwsStubState::Unknown);
        assert!(!is_aws_stub(&path));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn legacy_aws_stub_is_hardened_but_requires_upgrade() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_path("aws-legacy-detection");
        let aws_stub = dir.join("aws");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&aws_stub, LEGACY_AWS_STUB).unwrap();
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_AWS_STUB_PATH", &aws_stub) };

        let detection = detect();

        assert!(detection.hardened);
        assert!(detection.commands[0].hardened);
        assert!(!detection.commands[0].stub_valid);

        fs::write(&aws_stub, format!("{LEGACY_AWS_STUB}\n# modified\n")).unwrap();
        let modified = detect();
        assert!(!modified.commands[0].hardened);
        assert!(!modified.commands[0].stub_valid);
        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_AWS_STUB_PATH") };
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn harden_replaces_each_exact_legacy_stub() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_path("aws-legacy-upgrade");
        let aws_stub = dir.join("aws");
        let credentials = dir.join("credentials");
        fs::create_dir_all(&dir).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_EUID", "501");
            std::env::set_var("AUTOMIC_VAULT_TEST_AWS_STUB_PATH", &aws_stub);
            std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", &credentials);
        }

        for launcher in [LEGACY_AWS_STUB, HOMEBREW_AWS_STUB] {
            fs::write(&aws_stub, launcher).unwrap();
            let mut stdout = Vec::new();
            run_aws(&mut stdout, true).unwrap();
            assert_eq!(fs::read_to_string(&aws_stub).unwrap(), AWS_STUB);
            let stdout = String::from_utf8(stdout).unwrap();
            assert!(stdout.contains("run sudo to install the verified AWS release and launcher"));
            assert!(stdout.contains("╰─ hardened aws"));
        }

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_EUID");
            std::env::remove_var("AUTOMIC_VAULT_TEST_AWS_STUB_PATH");
            std::env::remove_var("AWS_SHARED_CREDENTIALS_FILE");
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn root_skips_aws_credential_import_without_test_keychain() {
        assert!(!should_import_aws_credentials(true, false));
        assert!(should_import_aws_credentials(true, true));
        assert!(should_import_aws_credentials(false, false));
    }

    #[test]
    fn installed_cli_revision_must_be_an_exact_integer() {
        assert_eq!(parse_cli_revision(b"13\n"), Some(13));
        assert_eq!(parse_cli_revision(b"av 13\n"), None);
        assert_eq!(parse_cli_revision(b"13 extra\n"), None);
    }

    #[test]
    fn root_hardening_skips_credentials_and_installs_stub() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_path("aws-root");
        let aws_stub = dir.join("aws");
        fs::create_dir_all(&dir).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_EUID", "0");
            std::env::set_var("AUTOMIC_VAULT_TEST_AWS_STUB_PATH", &aws_stub);
        }

        let mut stdout = Vec::new();
        run_aws(&mut stdout, true).unwrap();

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_EUID");
            std::env::remove_var("AUTOMIC_VAULT_TEST_AWS_STUB_PATH");
        }
        assert_eq!(fs::read_to_string(&aws_stub).unwrap(), AWS_STUB);
        let stdout = String::from_utf8(stdout).unwrap();
        assert!(!stdout.contains("plaintext keys"));
        assert!(stdout.contains(
            "`aws` defaults to Read Only, adjust this in the app: `av open --secret-gate aws`"
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn parses_profile_credentials() {
        assert_eq!(
            parse_aws_credentials(
                "[default]\naws_access_key_id = AKIA\naws_secret_access_key= secret\n",
                "default"
            )
            .unwrap(),
            Some(AwsCredentials {
                access_key_id: "AKIA".to_string(),
                secret_access_key: "secret".to_string()
            })
        );
    }

    #[test]
    fn removes_only_selected_profile_keys() {
        assert_eq!(
            remove_aws_credentials(
                "[default]\naws_access_key_id = AKIA\nregion = us-east-1\naws_secret_access_key = secret\n[dev]\naws_access_key_id = keep\n",
                "default"
            ),
            "[default]\nregion = us-east-1\n[dev]\naws_access_key_id = keep\n"
        );
    }

    #[test]
    fn harden_imports_keys_and_deletes_plaintext_credentials() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_path("aws-import");
        let credentials_path = dir.join("credentials");
        let keychain_dir = dir.join("keychain");
        let aws_vault = dir.join("aws-vault");
        let aws_stub = dir.join("aws");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&aws_vault, "").unwrap();
        fs::write(
            &credentials_path,
            "[default]\naws_access_key_id = AKIA\nregion = us-east-1\naws_secret_access_key = secret\n[dev]\naws_access_key_id = DEV\naws_secret_access_key = dev-secret\n",
        )
        .unwrap();
        unsafe {
            std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", &credentials_path);
            std::env::set_var("AWS_PROFILE", "dev");
            std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain_dir);
            std::env::set_var("AUTOMIC_VAULT_TEST_AWS_VAULT_PATH", &aws_vault);
            std::env::set_var("AUTOMIC_VAULT_TEST_AWS_STUB_PATH", &aws_stub);
        }

        run_aws(&mut Vec::new(), true).unwrap();

        unsafe {
            std::env::remove_var("AWS_SHARED_CREDENTIALS_FILE");
            std::env::remove_var("AWS_PROFILE");
            std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR");
            std::env::remove_var("AUTOMIC_VAULT_TEST_AWS_VAULT_PATH");
            std::env::remove_var("AUTOMIC_VAULT_TEST_AWS_STUB_PATH");
        }
        assert_eq!(
            fs::read_to_string(keychain_dir.join(AWS_ACCESS_KEY_ID)).unwrap(),
            "AKIA"
        );
        assert_eq!(
            fs::read_to_string(keychain_dir.join(AWS_SECRET_ACCESS_KEY)).unwrap(),
            "secret"
        );
        assert_eq!(
            fs::read_to_string(credentials_path).unwrap(),
            "[default]\nregion = us-east-1\n[dev]\naws_access_key_id = DEV\naws_secret_access_key = dev-secret\n"
        );
        let _ = fs::remove_dir_all(dir);
    }

    fn temp_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("av-{label}-{}-{nanos}", std::process::id()))
    }
}
