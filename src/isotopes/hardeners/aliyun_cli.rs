use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

use super::{
    HardenerCommand, HardenerDetection, HardenerDiagnostic, RequiredExecutable,
    SecretGateDescriptor, SecretGateRoute,
};

const AV_PATH: &str = "/usr/local/bin/av";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const PRIVILEGE_MODE: super::PrivilegeMode = super::PrivilegeMode::Mixed;
const TEAM_IDENTIFIER: &str = "ZU76A67LGU";

#[derive(Debug, PartialEq, Eq)]
struct Credential {
    profile: String,
    value: String,
}

pub(crate) fn run(stdout: &mut dyn Write, yes: bool) -> Result<(), String> {
    let testing = test_config_path().is_some();
    PRIVILEGE_MODE.require_user("aliyun-cli", testing)?;
    if !testing {
        crate::secrets::ensure_aliyun_helper_ready()?;
    }
    let path = config_path()?;
    let original = read_config(&path)?;
    let (sanitized, credentials, managed) = sanitize_config(&original)?;
    let existing = crate::secrets::list_global_secret_names()?;
    if let Some(name) = managed.iter().find(|name| !existing.contains(name)) {
        return Err(format!(
            "Alibaba Cloud External profile has no matching Secret Value: {name}"
        ));
    }
    let plan = super::isotope::plan(super::isotope::ALIYUN)?;

    writeln!(stdout, "╭─ harden aliyun-cli").ok();
    writeln!(stdout, "│").ok();
    plan.write(stdout, super::isotope::ALIYUN);
    writeln!(
        stdout,
        "├─ migrate {} AccessKey/STS profile{} without printing them",
        credentials.len(),
        if credentials.len() == 1 { "" } else { "s" }
    )
    .ok();
    writeln!(
        stdout,
        "├─ configure Alibaba Cloud's External credential provider"
    )
    .ok();
    writeln!(stdout, "│").ok();
    if !confirm(stdout, yes)? {
        writeln!(stdout, "╰─ cancelled").ok();
        return Ok(());
    }

    plan.apply(super::isotope::ALIYUN)?;
    verify_target(&target())?;
    if !testing {
        verify_command_resolution()?;
    }
    for credential in &credentials {
        crate::secrets::store_secret_if_absent_or_equal(
            &crate::cli::aliyun_credential::secret_name(&credential.profile),
            &credential.value,
        )?;
    }
    if original != sanitized {
        write_config(&path, &sanitized)?;
    }
    writeln!(stdout, "╰─ hardened aliyun-cli").ok();
    super::write_secret_gate_notice(stdout, "aliyun-cli");
    Ok(())
}

pub(crate) fn detect() -> HardenerDetection {
    let target = target();
    let target_valid = verify_target(&target).is_ok();
    let command_resolves = test_config_path().is_some() || verify_command_resolution().is_ok();
    let config = config_path().ok();
    let config_valid = config.as_deref().is_some_and(|path| {
        read_config(path).is_ok_and(|contents| {
            sanitize_config(&contents).is_ok_and(|(sanitized, credentials, managed)| {
                credentials.is_empty() && !managed.is_empty() && sanitized == contents
            })
        })
    });
    let hardened = target_valid && command_resolves && config_valid;
    let isotope = super::isotope::detect(super::isotope::ALIYUN)
        .commands
        .into_iter()
        .next()
        .and_then(|command| command.isotope);
    let command = HardenerCommand {
        name: "aliyun".into(),
        hardened,
        stub_valid: true,
        stub_path: None,
        target_path: target.display().to_string(),
        required_paths: if test_config_path().is_some() {
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
    if target.exists() && !target_valid && test_config_path().is_none() {
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "aliyun_target_invalid",
            message: verify_target(&target).unwrap_err(),
            remediation: "Rerun `av harden aliyun-cli` to install the signed Isotope.".into(),
            path: Some(target.display().to_string()),
        });
    }
    if let Some(path) = config
        && path.exists()
        && read_config(&path)
            .and_then(|contents| sanitize_config(&contents).map(|_| ()))
            .is_err()
    {
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "aliyun_config_unsupported",
            message: "Alibaba Cloud config contains unsupported or malformed credential state"
                .into(),
            remediation:
                "Rerun `av harden aliyun-cli`; unsupported profiles must be resolved manually."
                    .into(),
            path: Some(path.display().to_string()),
        });
    }
    detection
}

pub(crate) fn secret_gate() -> SecretGateDescriptor {
    SecretGateDescriptor {
        id: "aliyun-cli",
        key_patterns: vec!["ALIYUN_PROFILE_CREDENTIAL_*".into()],
        routes: vec![SecretGateRoute {
            operation: "aliyun-get",
            script_path: None,
            target_path: target().display().to_string(),
            caller_identifiers: vec!["com.automicvault.av"],
            key_patterns: vec!["ALIYUN_PROFILE_CREDENTIAL_*".into()],
            replace_existing_env: false,
            allow_missing_keys: false,
        }],
    }
}

fn sanitize_config(contents: &str) -> Result<(String, Vec<Credential>, Vec<String>), String> {
    let mut document: Value = serde_json::from_str(contents)
        .map_err(|error| format!("invalid Alibaba Cloud config JSON: {error}"))?;
    let root = document
        .as_object_mut()
        .ok_or_else(|| "Alibaba Cloud config must be a JSON object".to_string())?;
    let profiles = root
        .get_mut("profiles")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "Alibaba Cloud config requires a `profiles` array".to_string())?;
    let mut credentials = Vec::new();
    let mut managed = Vec::new();
    let mut names = BTreeSet::new();
    for value in profiles {
        let profile = value
            .as_object_mut()
            .ok_or_else(|| "Alibaba Cloud profiles must be JSON objects".to_string())?;
        let name = profile
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "Alibaba Cloud profile requires string field `name`".to_string())?;
        let name = crate::cli::aliyun_credential::normalize_profile(name)?;
        if !names.insert(name.clone()) {
            return Err(format!("duplicate Alibaba Cloud profile {name:?}"));
        }
        let mode = profile
            .get("mode")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Alibaba Cloud profile {name:?} requires string field `mode`"))?
            .to_string();
        for key in [
            "private_key",
            "access_token",
            "oauth_access_token",
            "oauth_refresh_token",
            "bearer_token",
        ] {
            if nonempty_string(profile.get(key)) {
                return Err(format!(
                    "Alibaba Cloud profile {name:?} contains unsupported secret field {key:?}"
                ));
            }
        }
        let access_key_id = string_field(profile, "access_key_id")?;
        let access_key_secret = string_field(profile, "access_key_secret")?;
        let sts_token = string_field(profile, "sts_token")?;
        let has_credential = [access_key_id, access_key_secret, sts_token]
            .into_iter()
            .any(|value| value.is_some_and(|value| !value.is_empty()));
        if mode == "External" {
            if has_credential {
                return Err(format!(
                    "Alibaba Cloud External profile {name:?} still contains inline credentials"
                ));
            }
            let expected_command = crate::cli::aliyun_credential::process_command(&name);
            if profile.get("process_command").and_then(Value::as_str)
                != Some(expected_command.as_str())
            {
                return Err(format!(
                    "Alibaba Cloud profile {name:?} uses a non-Automic External credential provider"
                ));
            }
            managed.push(crate::cli::aliyun_credential::secret_name(&name));
            continue;
        }
        if !matches!(mode.as_str(), "AK" | "StsToken") {
            if has_credential {
                return Err(format!(
                    "Alibaba Cloud profile {name:?} uses unsupported credential mode {mode:?}"
                ));
            }
            continue;
        }
        let access_key_id = access_key_id
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("Alibaba Cloud profile {name:?} requires `access_key_id`"))?;
        let access_key_secret = access_key_secret
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                format!("Alibaba Cloud profile {name:?} requires `access_key_secret`")
            })?;
        let sts_token = sts_token.filter(|value| !value.is_empty());
        let credential = crate::cli::aliyun_credential::credential(
            &mode,
            access_key_id,
            access_key_secret,
            sts_token,
        )?;
        credentials.push(Credential {
            profile: name.clone(),
            value: credential,
        });
        for key in ["access_key_id", "access_key_secret", "sts_token"] {
            profile.remove(key);
        }
        profile.insert("mode".into(), Value::String("External".into()));
        profile.insert(
            "process_command".into(),
            Value::String(crate::cli::aliyun_credential::process_command(&name)),
        );
    }
    let mut sanitized = serde_json::to_string_pretty(&document)
        .map_err(|error| format!("failed to serialize Alibaba Cloud config: {error}"))?;
    sanitized.push('\n');
    Ok((sanitized, credentials, managed))
}

fn string_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<Option<&'a str>, String> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(format!("Alibaba Cloud field {name:?} must be a string")),
    }
}

fn nonempty_string(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
}

fn config_path() -> Result<PathBuf, String> {
    if let Some(path) = test_config_path() {
        return Ok(path);
    }
    let home = std::env::var_os("HOME").ok_or_else(|| "HOME is not set".to_string())?;
    Ok(PathBuf::from(home).join(".aliyun/config.json"))
}

fn test_config_path() -> Option<PathBuf> {
    crate::test_env_var("AUTOMIC_VAULT_TEST_ALIYUN_CONFIG").map(PathBuf::from)
}

fn target() -> PathBuf {
    super::isotope::target(super::isotope::ALIYUN)
}

fn read_config(path: &Path) -> Result<String, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    if !file
        .metadata()
        .is_ok_and(|metadata| metadata.file_type().is_file() && metadata.len() <= MAX_CONFIG_BYTES)
    {
        return Err(format!(
            "refusing unsafe Alibaba Cloud config {}",
            path.display()
        ));
    }
    let mut contents = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    if contents.len() as u64 > MAX_CONFIG_BYTES {
        return Err("Alibaba Cloud config exceeds 1 MiB".into());
    }
    Ok(contents)
}

fn write_config(path: &Path, contents: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("Alibaba Cloud config has no parent: {}", path.display()))?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("failed to inspect {}: {error}", parent.display()))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != super::effective_uid()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(format!(
            "refusing unsafe Alibaba Cloud directory {}",
            parent.display()
        ));
    }
    let staging = parent.join(format!(
        ".config.json.av-{}.tmp",
        super::isotope::now_nanos()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&staging)
            .map_err(|error| format!("failed to create {}: {error}", staging.display()))?;
        file.write_all(contents.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("failed to write {}: {error}", staging.display()))?;
        fs::rename(&staging, path)
            .map_err(|error| format!("failed to replace {}: {error}", path.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(staging);
    }
    result
}

fn verify_command_resolution() -> Result<(), String> {
    let output = Command::new("/usr/bin/which")
        .arg("aliyun")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("failed to resolve aliyun: {error}"))?;
    let resolved = String::from_utf8(output.stdout)
        .ok()
        .filter(|_| output.status.success())
        .map(|path| PathBuf::from(path.trim()))
        .and_then(|path| path.canonicalize().ok());
    if resolved.is_some() && resolved == target().canonicalize().ok() {
        Ok(())
    } else {
        Err(format!(
            "your PATH does not resolve `aliyun` to {}; unlink competing installations or adjust PATH",
            target().display()
        ))
    }
}

pub(crate) fn verify_target(path: &Path) -> Result<(), String> {
    if test_config_path().is_some() {
        return path
            .exists()
            .then_some(())
            .ok_or_else(|| format!("test Alibaba Cloud Target is missing: {}", path.display()));
    }
    if !super::isotope::signature_valid(path, "aliyun") {
        return Err(format!(
            "Alibaba Cloud Target signature is invalid: {}",
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
            "Alibaba Cloud Target lacks the required Developer ID Hardened Runtime identity".into(),
        );
    }
    let entitlements = Command::new("/usr/bin/codesign")
        .args(["-d", "--entitlements", ":-"])
        .arg(path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .output()
        .map_err(|error| format!("failed to inspect {} entitlements: {error}", path.display()))?;
    if !entitlements.status.success() || !entitlements.stdout.is_empty() {
        return Err("Alibaba Cloud Target has unexpected code-signing entitlements".into());
    }
    Ok(())
}

fn confirm(stdout: &mut dyn Write, yes: bool) -> Result<bool, String> {
    if yes {
        writeln!(stdout, "◇ Continue? yes (--yes)").ok();
        return Ok(true);
    }
    write!(stdout, "◇ Continue? [y/N] ").ok();
    stdout
        .flush()
        .map_err(|error| format!("failed to flush prompt: {error}"))?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|error| format!("failed to read confirmation: {error}"))?;
    if !io::stdin().is_terminal() {
        writeln!(stdout).ok();
    }
    Ok(matches!(
        input.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_preserves_profile_metadata_and_rejects_unsupported_secrets() {
        let input = r#"{
  "current": "prod",
  "profiles": [{
    "name": "prod",
    "mode": "StsToken",
    "access_key_id": "id",
    "access_key_secret": "secret",
    "sts_token": "session",
    "region_id": "cn-hangzhou"
  }]
}"#;
        let (sanitized, credentials, managed) = sanitize_config(input).unwrap();
        assert_eq!(credentials.len(), 1);
        assert!(managed.is_empty());
        assert!(sanitized.contains(r#""mode": "External""#));
        assert!(sanitized.contains("aliyun-credential 'prod'"));
        assert!(sanitized.contains(r#""region_id": "cn-hangzhou""#));
        assert!(!sanitized.contains("session"));
        let (_, second, managed) = sanitize_config(&sanitized).unwrap();
        assert!(second.is_empty());
        assert_eq!(
            managed,
            [crate::cli::aliyun_credential::secret_name("prod")]
        );
        assert!(
            sanitize_config(&input.replace(
                r#""access_key_secret": "secret","#,
                r#""access_key_secret": "secret", "oauth_refresh_token": "refresh","#
            ))
            .is_err()
        );
        assert!(sanitize_config(
            r#"{"profiles":[{"name":"prod","mode":"External","process_command":"other-helper"}]}"#
        )
        .is_err());
    }

    #[test]
    fn hardener_migrates_without_installing_in_test_mode() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root = std::env::temp_dir().join(format!("av-aliyun-hardener-{}", std::process::id()));
        let config = root.join("config.json");
        let target = root.join("aliyun");
        let keychain = root.join("keychain");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(&target, "target").unwrap();
        fs::write(
            &config,
            r#"{"profiles":[{"name":"prod","mode":"AK","access_key_id":"id","access_key_secret":"secret","region_id":"cn-hangzhou"}]}"#,
        )
        .unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ALIYUN_CONFIG", &config);
            std::env::set_var("AUTOMIC_VAULT_TEST_ALIYUN_TARGET", &target);
            std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain);
        }
        let mut output = Vec::new();
        run(&mut output, true).unwrap();
        assert!(detect().hardened);
        assert!(!fs::read_to_string(&config).unwrap().contains("secret"));
        assert!(
            keychain
                .join(crate::cli::aliyun_credential::secret_name("prod"))
                .exists()
        );
        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_ALIYUN_CONFIG");
            std::env::remove_var("AUTOMIC_VAULT_TEST_ALIYUN_TARGET");
            std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR");
        }
        let _ = fs::remove_dir_all(root);
    }
}
