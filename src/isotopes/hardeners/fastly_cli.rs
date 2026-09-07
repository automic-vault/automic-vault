use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use toml::Value;

use super::{
    HardenerCommand, HardenerDetection, HardenerDiagnostic, RequiredExecutable,
    SecretGateDescriptor, SecretGateRoute,
};

const API_ENDPOINT: &str = "https://api.fastly.com";
const AV_PATH: &str = "/usr/local/bin/av";
const CREDENTIAL_MARKER: &str = "@av";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const PRIVILEGE_MODE: super::PrivilegeMode = super::PrivilegeMode::Mixed;
const TEAM_IDENTIFIER: &str = "ZU76A67LGU";

#[derive(Debug, PartialEq, Eq)]
struct Credential {
    name: String,
    token: String,
}

pub(crate) fn run(stdout: &mut dyn Write, yes: bool) -> Result<(), String> {
    let testing = test_config_path().is_some();
    PRIVILEGE_MODE.require_user("fastly-cli", testing)?;
    if !testing {
        crate::secrets::ensure_fastly_helper_ready()?;
    }
    if std::env::var_os("FASTLY_API_TOKEN").is_some() {
        return Err("unset FASTLY_API_TOKEN before hardening Fastly CLI".into());
    }
    if std::env::var_os("FASTLY_API_ENDPOINT").is_some() {
        return Err("unset FASTLY_API_ENDPOINT before hardening Fastly CLI".into());
    }
    let path = config_path()?;
    let original = read_config(&path)?;
    let (sanitized, credentials, managed_secret_names) = sanitize_config(&original)?;
    if !managed_secret_names.is_empty() {
        let existing_secret_names = crate::secrets::list_global_secret_names()?;
        if let Some(name) = managed_secret_names
            .iter()
            .find(|name| !existing_secret_names.contains(name))
        {
            return Err(format!(
                "Fastly credential marker has no matching Secret Value: {name}"
            ));
        }
    }
    let target = target();
    let plan = super::isotope::plan(super::isotope::FASTLY)?;

    writeln!(stdout, "╭─ harden fastly-cli").ok();
    writeln!(stdout, "│").ok();
    plan.write(stdout, super::isotope::FASTLY);
    writeln!(
        stdout,
        "├─ migrate {} named static token{} without printing them",
        credentials.len(),
        if credentials.len() == 1 { "" } else { "s" }
    )
    .ok();
    writeln!(stdout, "├─ keep only Fastly token metadata on disk").ok();
    writeln!(stdout, "│").ok();
    if !confirm(stdout, yes)? {
        writeln!(stdout, "╰─ cancelled").ok();
        return Ok(());
    }

    plan.apply(super::isotope::FASTLY)?;
    verify_target(&target)?;
    if !testing {
        verify_command_resolution()?;
    }
    for credential in &credentials {
        crate::secrets::store_secret_if_absent_or_equal(
            &crate::cli::fastly_credential::secret_name(&credential.name, API_ENDPOINT),
            &credential.token,
        )?;
    }
    if original != sanitized {
        write_config(&path, &sanitized)?;
    }
    writeln!(stdout, "╰─ hardened fastly-cli").ok();
    super::write_secret_gate_notice(stdout, "fastly-cli");
    Ok(())
}

pub(crate) fn detect() -> HardenerDetection {
    let target = target();
    let target_valid = verify_target(&target).is_ok();
    let command_resolves = test_config_path().is_some() || verify_command_resolution().is_ok();
    let config = config_path().ok();
    let config_valid = config.as_deref().is_some_and(|path| {
        read_config(path).is_ok_and(|contents| {
            sanitize_config(&contents).is_ok_and(|(sanitized, credentials, _)| {
                credentials.is_empty() && sanitized == contents
            })
        })
    });
    let hardened = target_valid && command_resolves && config_valid;
    let isotope = super::isotope::detect(super::isotope::FASTLY)
        .commands
        .into_iter()
        .next()
        .and_then(|command| command.isotope);
    let command = HardenerCommand {
        name: "fastly".into(),
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
            kind: "fastly_target_invalid",
            message: verify_target(&target).unwrap_err(),
            remediation: "Rerun `av harden fastly-cli` to install the signed Fastly Isotope."
                .into(),
            path: Some(target.display().to_string()),
        });
    }
    if target_valid && !command_resolves && test_config_path().is_none() {
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "fastly_command_shadowed",
            message: verify_command_resolution().unwrap_err(),
            remediation: "Rerun `av harden fastly-cli` after correcting PATH.".into(),
            path: Some(target.display().to_string()),
        });
    }
    if let Some(path) = config
        && path.exists()
        && !config_valid
    {
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "fastly_plaintext_or_unsupported_config",
            message: "Fastly credential configuration is not in the supported Hardened State."
                .into(),
            remediation:
                "Rerun `av harden fastly-cli`; SSO, alternate endpoints, and unsupported auth fields must be resolved manually."
                    .into(),
            path: Some(path.display().to_string()),
        });
    }
    detection
}

pub(crate) fn secret_gate() -> SecretGateDescriptor {
    SecretGateDescriptor {
        id: "fastly-cli",
        key_patterns: vec!["FASTLY_API_TOKEN_*".into()],
        routes: vec![SecretGateRoute {
            operation: "fastly-get",
            script_path: None,
            target_path: target().display().to_string(),
            caller_identifiers: vec!["com.automicvault.av"],
            key_patterns: vec!["FASTLY_API_TOKEN_*".into()],
            replace_existing_env: false,
            allow_missing_keys: false,
        }],
    }
}

fn sanitize_config(contents: &str) -> Result<(String, Vec<Credential>, Vec<String>), String> {
    if contents.is_empty() {
        return Ok((String::new(), Vec::new(), Vec::new()));
    }
    let mut document = toml::from_str::<Value>(contents)
        .map_err(|error| format!("invalid Fastly config TOML: {error}"))?;
    let root = document
        .as_table_mut()
        .ok_or_else(|| "Fastly config must be a TOML table".to_string())?;
    if root.get("user").is_some() || root.get("profile").is_some() {
        return Err("Fastly legacy user/profile credentials are unsupported; migrate them to named static auth tokens first".into());
    }
    if let Some(fastly) = root.get("fastly") {
        let table = fastly
            .as_table()
            .ok_or_else(|| "Fastly `fastly` config must be a table".to_string())?;
        if let Some(endpoint) = table.get("api_endpoint") {
            let endpoint = endpoint
                .as_str()
                .ok_or_else(|| "Fastly API endpoint must be a string".to_string())?;
            if !endpoint.is_empty() && endpoint != API_ENDPOINT {
                return Err(format!("Fastly API endpoint must be {API_ENDPOINT}"));
            }
        }
    }
    let Some(auth) = root.get_mut("auth") else {
        return Ok((contents.to_string(), Vec::new(), Vec::new()));
    };
    let auth = auth
        .as_table_mut()
        .ok_or_else(|| "Fastly `auth` config must be a table".to_string())?;
    if auth
        .keys()
        .any(|key| !["default", "tokens"].contains(&key.as_str()))
    {
        return Err("Fastly auth config contains unsupported fields".into());
    }
    if auth.get("default").is_some_and(|value| !value.is_str()) {
        return Err("Fastly default token name must be a string".into());
    }
    let default = auth
        .get("default")
        .and_then(Value::as_str)
        .map(str::to_string);
    let Some(tokens) = auth.get_mut("tokens") else {
        return Ok((contents.to_string(), Vec::new(), Vec::new()));
    };
    let tokens = tokens
        .as_table_mut()
        .ok_or_else(|| "Fastly auth tokens must be a table".to_string())?;
    let allowed = [
        "type",
        "token",
        "label",
        "account_id",
        "email",
        "api_token_name",
        "api_token_scope",
        "api_token_expires_at",
        "api_token_id",
    ];
    let mut credentials = Vec::new();
    let mut managed_secret_names = Vec::new();
    for (name, value) in tokens.iter_mut() {
        let name = crate::cli::fastly_credential::normalize_name(name)?;
        let table = value
            .as_table_mut()
            .ok_or_else(|| format!("Fastly token {name:?} must be a table"))?;
        if table.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(format!(
                "Fastly token {name:?} contains unsupported or SSO fields"
            ));
        }
        if table.get("type").and_then(Value::as_str) != Some("static") {
            return Err(format!("Fastly token {name:?} must have type `static`"));
        }
        for field in table.keys() {
            if !table[field].is_str() {
                return Err(format!(
                    "Fastly token {name:?} field {field:?} must be a string"
                ));
            }
        }
        let token = table
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Fastly token {name:?} requires string field `token`"))?;
        if token == CREDENTIAL_MARKER {
            managed_secret_names.push(crate::cli::fastly_credential::secret_name(
                &name,
                API_ENDPOINT,
            ));
        } else {
            credentials.push(Credential {
                name: name.clone(),
                token: crate::cli::fastly_credential::parse_token(token)?,
            });
        }
        table.insert("token".into(), Value::String(CREDENTIAL_MARKER.into()));
    }
    if let Some(default) = default.as_deref()
        && !default.is_empty()
        && !tokens.contains_key(default)
    {
        return Err(format!("Fastly default token {default:?} does not exist"));
    }
    let sanitized = toml::to_string_pretty(&document)
        .map_err(|error| format!("failed to serialize Fastly config: {error}"))?;
    Ok((sanitized, credentials, managed_secret_names))
}

fn config_path() -> Result<PathBuf, String> {
    if let Some(path) = test_config_path() {
        return Ok(path);
    }
    let candidates = config_path_candidates()?;
    let active = candidates[0].clone();
    if let Some(secondary) = candidates
        .iter()
        .skip(1)
        .find(|path| path.as_path() != active && path.exists())
    {
        return Err(format!(
            "Fastly config exists outside the active path: {}; move or merge it into {} before hardening",
            secondary.display(),
            active.display()
        ));
    }
    Ok(active)
}

/// The first path is Fastly CLI's actual `os.UserConfigDir` selection on
/// Darwin: `$HOME/Library/Application Support`, unconditionally. Go's
/// `os.UserConfigDir` only consults `$XDG_CONFIG_HOME` on non-Darwin Unix
/// targets, so the live Fastly Target never reads that variable on the
/// macOS-only platform this Hardener runs on. Remaining paths are
/// detector-only legacy locations and must not silently win.
fn config_path_candidates() -> Result<Vec<PathBuf>, String> {
    let mut candidates = Vec::new();
    let home = std::env::var_os("HOME").ok_or_else(|| "HOME is not set".to_string())?;
    let home = PathBuf::from(home);
    candidates.push(home.join("Library/Application Support/fastly/config.toml"));
    if let Some(root) = std::env::var_os("XDG_CONFIG_HOME") {
        let root = PathBuf::from(root);
        if !root.is_absolute() {
            return Err("XDG_CONFIG_HOME must be an absolute path".into());
        }
        candidates.push(root.join("fastly/config.toml"));
    }
    candidates.push(home.join(".fastly/config.toml"));
    Ok(candidates)
}

fn test_config_path() -> Option<PathBuf> {
    crate::test_env_var("AUTOMIC_VAULT_TEST_FASTLY_CONFIG").map(PathBuf::from)
}

fn target() -> PathBuf {
    super::isotope::target(super::isotope::FASTLY)
}

fn read_config(path: &Path) -> Result<String, String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(format!("failed to read {}: {error}", path.display())),
    };
    if !file
        .metadata()
        .is_ok_and(|metadata| metadata.file_type().is_file() && metadata.len() <= MAX_CONFIG_BYTES)
    {
        return Err(format!("refusing unsafe Fastly config {}", path.display()));
    }
    let mut contents = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    if contents.len() as u64 > MAX_CONFIG_BYTES {
        return Err("Fastly config exceeds 1 MiB".into());
    }
    Ok(contents)
}

fn write_config(path: &Path, contents: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("Fastly config has no parent: {}", path.display()))?;
    secure_directory(parent)?;
    let staging = parent.join(format!(
        ".config.toml.av-{}.tmp",
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
            .map_err(|error| format!("failed to replace {}: {error}", path.display()))?;
        OpenOptions::new()
            .read(true)
            .open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("failed to sync {}: {error}", parent.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(staging);
    }
    result
}

fn secure_directory(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        secure_directory(parent)?;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_dir()
                && metadata.uid() == super::effective_uid()
                && metadata.permissions().mode() & 0o022 == 0 =>
        {
            Ok(())
        }
        Ok(_) => Err(format!(
            "refusing unsafe Fastly directory {}",
            path.display()
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .map_err(|error| format!("failed to create {}: {error}", path.display()))?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("failed to protect {}: {error}", path.display()))
        }
        Err(error) => Err(format!("failed to inspect {}: {error}", path.display())),
    }
}

fn verify_command_resolution() -> Result<(), String> {
    let output = Command::new("/usr/bin/which")
        .arg("fastly")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("failed to resolve fastly: {error}"))?;
    let resolved = String::from_utf8(output.stdout)
        .ok()
        .filter(|_| output.status.success())
        .map(|path| PathBuf::from(path.trim()))
        .and_then(|path| path.canonicalize().ok());
    let expected = target().canonicalize().ok();
    if resolved.is_some() && resolved == expected {
        Ok(())
    } else {
        Err(format!(
            "your PATH does not resolve `fastly` to {}; remove version-manager shims or adjust PATH",
            target().display()
        ))
    }
}

pub(crate) fn verify_target(path: &Path) -> Result<(), String> {
    if test_config_path().is_some() {
        return path
            .exists()
            .then_some(())
            .ok_or_else(|| format!("test Fastly Target is missing: {}", path.display()));
    }
    let requirement = format!(
        "=identifier \"fastly\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"{TEAM_IDENTIFIER}\""
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
            "Fastly Target signature is invalid: {}",
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
            "Fastly Target lacks the required Developer ID Hardened Runtime identity".into(),
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
        return Err("Fastly Target has unexpected code-signing entitlements".into());
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
    fn migration_preserves_static_metadata_and_rejects_sso() {
        let input = r#"[fastly]
api_endpoint = "https://api.fastly.com"

[auth]
default = "production"

[auth.tokens.production]
type = "static"
token = "secret"
label = "Production"
api_token_scope = "global"
"#;
        let (sanitized, credentials, managed) = sanitize_config(input).unwrap();
        assert_eq!(
            credentials,
            [Credential {
                name: "production".into(),
                token: "secret".into()
            }]
        );
        assert!(sanitized.contains("token = \"@av\""));
        assert!(sanitized.contains("label = \"Production\""));
        assert!(managed.is_empty());
        assert_eq!(
            sanitize_config(&input.replace("secret", "@av"))
                .unwrap()
                .2
                .len(),
            1
        );
        assert!(sanitize_config(&input.replace("static", "sso")).is_err());
        assert!(
            sanitize_config(&input.replace("label =", "refresh_token = \"secret\"\nlabel ="))
                .is_err()
        );
        assert!(sanitize_config(&input.replace(API_ENDPOINT, "https://example.invalid")).is_err());
    }

    #[test]
    fn hardener_migrates_without_recreating_plaintext() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root = std::env::temp_dir().join(format!("av-fastly-hardener-{}", std::process::id()));
        let config = root.join("config.toml");
        let target = root.join("fastly");
        let keychain = root.join("keychain");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(&config, "[auth]\ndefault = \"prod\"\n[auth.tokens.prod]\ntype = \"static\"\ntoken = \"secret\"\n").unwrap();
        fs::write(&target, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_FASTLY_CONFIG", &config);
            std::env::set_var("AUTOMIC_VAULT_TEST_FASTLY_TARGET", &target);
            std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain);
        }
        run(&mut Vec::new(), true).unwrap();
        let hardened = fs::read_to_string(&config).unwrap();
        assert!(hardened.contains("token = \"@av\""));
        assert!(!hardened.contains("secret"));
        let secret = keychain.join(crate::cli::fastly_credential::secret_name(
            "prod",
            API_ENDPOINT,
        ));
        assert_eq!(fs::read_to_string(&secret).unwrap(), "secret");
        assert!(detect().hardened);
        fs::remove_file(secret).unwrap();
        assert!(detect().hardened);
        assert!(
            run(&mut Vec::new(), true)
                .unwrap_err()
                .contains("credential marker has no matching Secret Value")
        );
        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_FASTLY_CONFIG");
            std::env::remove_var("AUTOMIC_VAULT_TEST_FASTLY_TARGET");
            std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR");
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn config_path_rejects_legacy_dotfastly_instead_of_claiming_it_is_active() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root =
            std::env::temp_dir().join(format!("av-fastly-config-path-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let dot_fastly = root.join(".fastly");
        fs::create_dir_all(&dot_fastly).unwrap();
        fs::write(dot_fastly.join("config.toml"), "[fastly]\n").unwrap();
        let previous_home = std::env::var_os("HOME");
        let previous_xdg = std::env::var_os("XDG_CONFIG_HOME");
        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_FASTLY_CONFIG");
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::set_var("HOME", &root);
        }
        let error = config_path().unwrap_err();
        assert!(error.contains("outside the active path"));
        assert!(error.contains("Library/Application Support/fastly/config.toml"));
        unsafe {
            match previous_home {
                Some(home) => std::env::set_var("HOME", home),
                None => std::env::remove_var("HOME"),
            }
            match previous_xdg {
                Some(xdg) => std::env::set_var("XDG_CONFIG_HOME", xdg),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn config_path_ignores_xdg_config_home_as_authoritative_on_macos() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root =
            std::env::temp_dir().join(format!("av-fastly-config-path-xdg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let xdg = root.join("xdg-config");
        fs::create_dir_all(xdg.join("fastly")).unwrap();
        fs::write(xdg.join("fastly/config.toml"), "[fastly]\n").unwrap();
        let previous_home = std::env::var_os("HOME");
        let previous_xdg = std::env::var_os("XDG_CONFIG_HOME");
        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_FASTLY_CONFIG");
            std::env::set_var("HOME", &root);
            std::env::set_var("XDG_CONFIG_HOME", &xdg);
        }
        // Go's `os.UserConfigDir` never consults `$XDG_CONFIG_HOME` on
        // Darwin, so the live Fastly Target always reads
        // `~/Library/Application Support/fastly/config.toml` regardless of
        // this variable. A config that exists only under
        // `$XDG_CONFIG_HOME` must be rejected as an inactive/legacy file,
        // never treated as the authoritative one to harden.
        let error = config_path().unwrap_err();
        assert!(error.contains("outside the active path"));
        assert!(error.contains("xdg-config/fastly/config.toml"));
        assert!(error.contains("Library/Application Support/fastly/config.toml"));
        unsafe {
            match previous_home {
                Some(home) => std::env::set_var("HOME", home),
                None => std::env::remove_var("HOME"),
            }
            match previous_xdg {
                Some(xdg) => std::env::set_var("XDG_CONFIG_HOME", xdg),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
        let _ = fs::remove_dir_all(root);
    }
}
