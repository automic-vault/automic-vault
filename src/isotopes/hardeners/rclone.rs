use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};

use super::{
    HardenerCommand, HardenerDetection, HardenerDiagnostic, RequiredExecutable,
    SecretGateDescriptor, SecretGateRoute,
};

const AV_PATH: &str = "/usr/local/bin/av";
const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;
const TEAM_IDENTIFIER: &str = "ZU76A67LGU";

pub(crate) fn run(stdout: &mut dyn Write, yes: bool) -> Result<(), String> {
    let testing = test_config_path().is_some();
    super::PrivilegeMode::Mixed.require_user("rclone", testing)?;
    reject_competing_password_sources()?;
    if !testing {
        crate::secrets::ensure_rclone_helper_ready()?;
    }
    let config = config_path()?;
    let encrypted = encrypted_state(&read_config(&config)?)?;
    let target = target();
    let plan = super::isotope::plan(super::isotope::RCLONE)?;

    writeln!(stdout, "╭─ harden rclone").ok();
    writeln!(stdout, "│").ok();
    plan.write(stdout, super::isotope::RCLONE);
    writeln!(stdout, "├─ encrypt {}", config.display()).ok();
    writeln!(stdout, "├─ keep its wrapping password in Automic Vault").ok();
    writeln!(
        stdout,
        "├─ authorize one rclone process for every configured remote"
    )
    .ok();
    writeln!(stdout, "│").ok();
    if !super::gh_cli::confirm(stdout, yes)? {
        writeln!(stdout, "╰─ cancelled").ok();
        return Ok(());
    }

    plan.apply(super::isotope::RCLONE)?;
    verify_target(&target)?;
    if encrypted {
        encryption_set(&target, &config)?.require_success()?;
    } else {
        let first = encryption_set(&target, &config)?;
        if !encrypted_state(&read_config(&config)?)? {
            if !first.secret_was_missing() {
                return Err(first.failure("rclone could not encrypt its configuration"));
            }
            let password = generate_password()?;
            crate::secrets::store_secret(crate::cli::rclone_password::SECRET_NAME, &password)?;
            encryption_set(&target, &config)?.require_success()?;
        }
    }
    if !encrypted_state(&read_config(&config)?)? {
        return Err("rclone reported success but its configuration remains plaintext".into());
    }

    writeln!(stdout, "╰─ hardened rclone").ok();
    super::write_secret_gate_notice(stdout, "rclone");
    Ok(())
}

pub(crate) fn detect() -> HardenerDetection {
    let testing = test_config_path().is_some();
    let target = target();
    let target_valid = verify_target(&target).is_ok();
    let config = config_path().ok();
    let config_valid = config.as_deref().is_some_and(|path| {
        read_config(path)
            .and_then(|contents| encrypted_state(&contents))
            .unwrap_or(false)
    });
    let hardened = target_valid && config_valid;
    let isotope = super::isotope::detect(super::isotope::RCLONE)
        .commands
        .into_iter()
        .next()
        .and_then(|command| command.isotope);
    let command = HardenerCommand {
        name: "rclone".into(),
        hardened,
        stub_valid: true,
        stub_path: None,
        target_path: target.display().to_string(),
        required_paths: if testing {
            Vec::new()
        } else {
            vec![RequiredExecutable {
                name: "Automic Vault CLI",
                path: AV_PATH.into(),
            }]
        },
        stub_requirements: None,
        injected_keys: Vec::new(),
        assignment_keys: Vec::new(),
        isotope,
    };
    let mut detection = HardenerDetection::commands(hardened, vec![command]);
    detection.applicable = config.as_deref().is_some_and(Path::exists) || target.exists();
    if target.exists() && !target_valid && !testing {
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "rclone_target_invalid",
            message: verify_target(&target).unwrap_err(),
            remediation: "Rerun `av harden rclone` to install the signed rclone Isotope.".into(),
            path: Some(target.display().to_string()),
        });
    }
    if config.as_deref().is_some_and(Path::exists) && !config_valid {
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "rclone_config_not_encrypted",
            message: "rclone configuration is not encrypted with its native config encryption."
                .into(),
            remediation: "Rerun `av harden rclone`.".into(),
            path: config.map(|path| path.display().to_string()),
        });
    }
    detection
}

pub(crate) fn secret_gate() -> SecretGateDescriptor {
    SecretGateDescriptor {
        id: "rclone",
        key_patterns: vec![crate::cli::rclone_password::SECRET_NAME.into()],
        routes: vec![SecretGateRoute {
            operation: "rclone-get",
            script_path: None,
            target_path: target().display().to_string(),
            caller_identifiers: vec!["com.automicvault.av"],
            key_patterns: vec![crate::cli::rclone_password::SECRET_NAME.into()],
            replace_existing_env: false,
            allow_missing_keys: false,
        }],
    }
}

fn reject_competing_password_sources() -> Result<(), String> {
    for name in [
        "RCLONE_CONFIG_PASS",
        "RCLONE_PASSWORD_COMMAND",
        "_RCLONE_CONFIG_KEY_FILE",
    ] {
        if std::env::var_os(name).is_some_and(|value| !value.is_empty()) {
            return Err(format!("unset {name} before hardening rclone"));
        }
    }
    Ok(())
}

fn config_path() -> Result<PathBuf, String> {
    if let Some(path) = test_config_path() {
        return Ok(path);
    }
    if let Some(path) = std::env::var_os("RCLONE_CONFIG").filter(|value| !value.is_empty()) {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err("RCLONE_CONFIG must be an absolute path".into());
        }
        return Ok(path);
    }
    if let Some(parent) = target().parent() {
        let local = parent.join("rclone.conf");
        if local.exists() {
            return Ok(local);
        }
    }
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())?;
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
        let path = PathBuf::from(xdg).join("rclone/rclone.conf");
        if path.exists() {
            return Ok(path);
        }
    }
    for path in [
        home.join(".config/rclone/rclone.conf"),
        home.join(".rclone.conf"),
    ] {
        if path.exists() {
            return Ok(path);
        }
    }
    Err("configure rclone before hardening it; no rclone.conf was found".into())
}

fn test_config_path() -> Option<PathBuf> {
    crate::test_env_var("AUTOMIC_VAULT_TEST_RCLONE_CONFIG").map(PathBuf::from)
}

fn target() -> PathBuf {
    super::isotope::target(super::isotope::RCLONE)
}

fn read_config(path: &Path) -> Result<String, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.len() > MAX_CONFIG_BYTES
        || metadata.uid() != super::effective_uid()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(format!(
            "refusing unsafe rclone configuration: {}",
            path.display()
        ));
    }
    let mut contents = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    if contents.len() as u64 > MAX_CONFIG_BYTES {
        return Err(format!(
            "rclone configuration is too large: {}",
            path.display()
        ));
    }
    Ok(contents)
}

fn encrypted_state(contents: &str) -> Result<bool, String> {
    let Some(first) = contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with(';'))
    else {
        return Ok(false);
    };
    if first == "RCLONE_ENCRYPT_V0:" {
        return Ok(true);
    }
    if first.starts_with("RCLONE_ENCRYPT_V") {
        return Err("unsupported rclone configuration encryption version".into());
    }
    Ok(false)
}

struct EncryptionResult {
    status: std::process::ExitStatus,
    output: String,
}

impl EncryptionResult {
    fn secret_was_missing(&self) -> bool {
        output_reports_missing_secret(&self.output)
    }

    fn failure(&self, prefix: &str) -> String {
        format!("{prefix}: {}", self.status)
    }

    fn require_success(self) -> Result<(), String> {
        self.status
            .success()
            .then_some(())
            .ok_or_else(|| self.failure("rclone config encryption failed"))
    }
}

fn output_reports_missing_secret(output: &str) -> bool {
    output.contains("failed to load secret RCLONE_CONFIG_PASSWORD: -25300")
}

fn encryption_set(target: &Path, config: &Path) -> Result<EncryptionResult, String> {
    let output = Command::new(target)
        .arg("--config")
        .arg(config)
        .args(["config", "encryption", "set"])
        .env_remove("RCLONE_CONFIG")
        .env_remove("RCLONE_CONFIG_PASS")
        .env_remove("RCLONE_PASSWORD_COMMAND")
        .env_remove("_RCLONE_CONFIG_KEY_FILE")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("failed to run {}: {error}", target.display()))?;
    Ok(EncryptionResult {
        status: output.status,
        output: format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    })
}

fn generate_password() -> Result<String, String> {
    let mut bytes = [0_u8; 48];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "failed to generate rclone config password".to_string())?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn verify_target(path: &Path) -> Result<(), String> {
    if test_config_path().is_some() {
        return path
            .exists()
            .then_some(())
            .ok_or_else(|| format!("test rclone Target is missing: {}", path.display()));
    }
    let requirement = format!(
        "=identifier \"rclone\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"{TEAM_IDENTIFIER}\""
    );
    let status = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "-R", &requirement])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("failed to verify {}: {error}", path.display()))?;
    if !status.success() {
        return Err(format!(
            "rclone Target signature is invalid: {}",
            path.display()
        ));
    }
    let output = Command::new("/usr/bin/codesign")
        .args(["-d", "-vvv"])
        .arg(path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .output()
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    let details = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success()
        || !details.contains("flags=0x10000(runtime)")
        || !details.contains(&format!("TeamIdentifier={TEAM_IDENTIFIER}"))
        || !details.contains("Timestamp=")
    {
        return Err(
            "rclone Target lacks the required Developer ID Hardened Runtime identity".into(),
        );
    }
    let entitlements = Command::new("/usr/bin/codesign")
        .args(["-d", "--entitlements", ":-"])
        .arg(path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .output()
        .map_err(|error| format!("failed to inspect rclone entitlements: {error}"))?;
    if !entitlements.status.success() || !entitlements.stdout.is_empty() {
        return Err("rclone Target has unexpected code-signing entitlements".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn recognizes_only_supported_native_encryption() {
        assert!(encrypted_state("# rclone\n\nRCLONE_ENCRYPT_V0:\ndata").unwrap());
        assert!(!encrypted_state("[remote]\ntoken = secret\n").unwrap());
        assert!(encrypted_state("RCLONE_ENCRYPT_V1:\ndata").is_err());
    }

    #[test]
    fn generated_password_is_a_single_high_entropy_line() {
        let password = generate_password().unwrap();
        assert_eq!(password.len(), 64);
        assert!(crate::cli::rclone_password::validate_password(&password).is_ok());
    }

    #[test]
    fn only_the_exact_missing_secret_error_allows_password_creation() {
        assert!(output_reports_missing_secret(
            "rclone-password: failed to load secret RCLONE_CONFIG_PASSWORD: -25300"
        ));
        assert!(!output_reports_missing_secret(
            "another failure for RCLONE_CONFIG_PASSWORD also mentioned -25300"
        ));
    }

    #[test]
    fn hardener_creates_password_only_after_the_target_reports_it_missing() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root = std::env::temp_dir().join(format!("av-rclone-hardener-{}", std::process::id()));
        let config = root.join("rclone.conf");
        let target = root.join("rclone");
        let keychain = root.join("keychain");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&keychain).unwrap();
        std::fs::write(&config, "[remote]\ntoken = plaintext\n").unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(
            &target,
            "#!/bin/sh\nset -eu\ntest \"$1\" = --config\ntest \"$3 $4 $5\" = 'config encryption set'\nif test -f \"$AUTOMIC_VAULT_TEST_KEYCHAIN_DIR/RCLONE_CONFIG_PASSWORD\"; then\n  printf '# encrypted\\n\\nRCLONE_ENCRYPT_V0:\\ndata\\n' > \"$2\"\nelse\n  echo 'failed to load secret RCLONE_CONFIG_PASSWORD: -25300' >&2\nfi\n",
        )
        .unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_RCLONE_CONFIG", &config);
            std::env::set_var("AUTOMIC_VAULT_TEST_RCLONE_TARGET", &target);
            std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain);
        }

        let mut output = Vec::new();
        let result = run(&mut output, true);

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_RCLONE_CONFIG");
            std::env::remove_var("AUTOMIC_VAULT_TEST_RCLONE_TARGET");
            std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR");
        }
        assert!(result.is_ok(), "{result:?}");
        assert!(encrypted_state(&std::fs::read_to_string(&config).unwrap()).unwrap());
        assert!(
            keychain
                .join(crate::cli::rclone_password::SECRET_NAME)
                .exists()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
