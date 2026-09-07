use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::{
    HardenerCommand, HardenerDetection, HardenerDiagnostic, RequiredExecutable,
    SecretGateDescriptor, SecretGateRoute,
};

const AV_PATH: &str = "/usr/local/bin/av";
const HELPER: &str = "/usr/local/bin/av wakatime-credential";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const TEAM_IDENTIFIER: &str = "ZU76A67LGU";

pub(crate) fn run(stdout: &mut dyn Write, yes: bool) -> Result<(), String> {
    let testing = test_config_path().is_some();
    super::PrivilegeMode::Mixed.require_user("wakatime-cli", testing)?;
    if std::env::var_os("WAKATIME_API_KEY").is_some_and(|value| !value.is_empty()) {
        return Err("unset WAKATIME_API_KEY before hardening WakaTime CLI".into());
    }
    if !testing {
        crate::secrets::ensure_wakatime_helper_ready()?;
    }
    let config_path = config_path()?;
    let original = read_config(&config_path)?;
    let (sanitized, api_key) = sanitize_config(&original)?;
    let target = target();
    let command_path = plugin_command_path()?;
    let plan = super::isotope::plan(super::isotope::WAKATIME)?;

    writeln!(stdout, "╭─ harden wakatime-cli").ok();
    writeln!(stdout, "│").ok();
    plan.write(stdout, super::isotope::WAKATIME);
    writeln!(
        stdout,
        "├─ point {} at the verified Target",
        command_path.display()
    )
    .ok();
    if api_key.is_some() {
        writeln!(
            stdout,
            "├─ migrate the global WakaTime API key without printing it"
        )
        .ok();
    }
    writeln!(
        stdout,
        "├─ restrict credential use to WakaTime's official API endpoint"
    )
    .ok();
    writeln!(stdout, "│").ok();
    if !confirm(stdout, yes)? {
        writeln!(stdout, "╰─ cancelled").ok();
        return Ok(());
    }

    plan.apply(super::isotope::WAKATIME)?;
    verify_target(&target)?;
    if let Some(api_key) = api_key {
        crate::secrets::store_secret_if_absent_or_equal(
            crate::cli::wakatime_credential::SECRET_NAME,
            &api_key,
        )?;
    }
    install_plugin_link(&command_path, &target)?;
    if original != sanitized {
        write_config(&config_path, &sanitized)?;
    }
    writeln!(stdout, "╰─ hardened wakatime-cli").ok();
    super::write_secret_gate_notice(stdout, "wakatime-cli");
    Ok(())
}

pub(crate) fn detect() -> HardenerDetection {
    let testing = test_config_path().is_some();
    let target = target();
    let target_valid = verify_target(&target).is_ok();
    let command = plugin_command_path().ok();
    let command_valid = command
        .as_deref()
        .is_some_and(|path| plugin_link_valid(path, &target));
    let config = config_path().ok();
    let config_valid = config.as_deref().is_some_and(|path| {
        read_config(path).is_ok_and(|contents| {
            sanitize_config(&contents).is_ok_and(|(sanitized, key)| {
                key.is_none() && sanitized == contents && helper_configured(&contents)
            })
        })
    });
    let hardened = target_valid && command_valid && config_valid;
    let isotope = super::isotope::detect(super::isotope::WAKATIME)
        .commands
        .into_iter()
        .next()
        .and_then(|command| command.isotope);
    let hardener_command = HardenerCommand {
        name: "wakatime-cli".into(),
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
    let mut detection = HardenerDetection::commands(hardened, vec![hardener_command]);
    detection.applicable = config.as_deref().is_some_and(Path::exists)
        || command.as_deref().is_some_and(Path::exists)
        || target.exists();
    if target.exists() && !target_valid && !testing {
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "wakatime_target_invalid",
            message: verify_target(&target).unwrap_err(),
            remediation:
                "Rerun `av harden wakatime-cli` to install the signed WakaTime CLI Isotope.".into(),
            path: Some(target.display().to_string()),
        });
    }
    if target_valid && !command_valid {
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "wakatime_plugin_command_invalid",
            message: "the WakaTime editor-plugin command does not resolve to the verified Target."
                .into(),
            remediation: "Rerun `av harden wakatime-cli`.".into(),
            path: command.map(|path| path.display().to_string()),
        });
    }
    if config.as_deref().is_some_and(Path::exists) && !config_valid {
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "wakatime_plaintext_or_unsupported_config",
            message: "WakaTime configuration is not in the supported Hardened State.".into(),
            remediation: "Rerun `av harden wakatime-cli`; unsupported credential routes must be removed manually."
                .into(),
            path: config.map(|path| path.display().to_string()),
        });
    }
    detection
}

pub(crate) fn secret_gate() -> SecretGateDescriptor {
    SecretGateDescriptor {
        id: "wakatime-cli",
        key_patterns: vec![crate::cli::wakatime_credential::SECRET_NAME.into()],
        routes: vec![SecretGateRoute {
            operation: "wakatime-get",
            script_path: None,
            target_path: target().display().to_string(),
            caller_identifiers: vec!["com.automicvault.av"],
            key_patterns: vec![crate::cli::wakatime_credential::SECRET_NAME.into()],
            replace_existing_env: false,
            allow_missing_keys: false,
        }],
    }
}

fn sanitize_config(contents: &str) -> Result<(String, Option<String>), String> {
    let mut section = String::new();
    let mut output = Vec::new();
    let mut key = None;
    let mut helper_seen = false;
    let mut settings_seen = false;

    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            if section == "settings" && !helper_seen {
                output.push(format!("api_key_vault_cmd = {HELPER}"));
                helper_seen = true;
            }
            section = name.trim().to_ascii_lowercase();
            settings_seen |= section == "settings";
            output.push(line.to_string());
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            output.push(line.to_string());
            continue;
        }
        let Some((raw_name, raw_value)) = line.split_once('=') else {
            return Err("invalid WakaTime config line".into());
        };
        let name = raw_name.trim().to_ascii_lowercase().replace('-', "_");
        let value = raw_value.trim().trim_matches(['\'', '"']);
        if section == "project_api_key" && !value.is_empty() {
            return Err("project-specific WakaTime API keys are not supported".into());
        }
        if section == "api_urls" && !value.is_empty() {
            return Err("per-project WakaTime API routes are not supported".into());
        }
        if section.is_empty() || section == "settings" {
            match name.as_str() {
                "api_key" | "apikey" | "key" => {
                    if !value.is_empty() {
                        crate::cli::wakatime_credential::validate_api_key(value)?;
                        if key.replace(value.to_string()).is_some() {
                            return Err("multiple WakaTime API keys are configured".into());
                        }
                    }
                    continue;
                }
                "api_key_vault_cmd" => {
                    if helper_seen || !value.is_empty() && value != HELPER {
                        return Err("WakaTime uses a competing credential helper".into());
                    }
                    if section != "settings" {
                        return Err("WakaTime credential helper must be in [settings]".into());
                    }
                    output.push(format!("api_key_vault_cmd = {HELPER}"));
                    helper_seen = true;
                    continue;
                }
                "api_url" | "apiurl"
                    if !value.is_empty()
                        && value.trim_end_matches('/')
                            != crate::cli::wakatime_credential::API_URL =>
                {
                    return Err("WakaTime alternate API URLs are not supported".into());
                }
                "proxy" | "https_proxy" | "ssl_certs_file" | "import_cfg" if !value.is_empty() => {
                    return Err(format!(
                        "WakaTime `{name}` is not supported by this hardener"
                    ));
                }
                "no_ssl_verify"
                    if matches!(
                        value.to_ascii_lowercase().as_str(),
                        "true" | "yes" | "1" | "on"
                    ) =>
                {
                    return Err("WakaTime TLS verification cannot be disabled".into());
                }
                _ => {}
            }
        }
        output.push(line.to_string());
    }
    if !helper_seen {
        if !contents.is_empty() && !contents.ends_with('\n') {
            output.push(String::new());
        }
        if !settings_seen {
            output.push("[settings]".into());
        }
        output.push(format!("api_key_vault_cmd = {HELPER}"));
    }
    let mut sanitized = output.join("\n");
    if contents.ends_with('\n') || contents.is_empty() {
        sanitized.push('\n');
    }
    Ok((sanitized, key))
}

fn helper_configured(contents: &str) -> bool {
    contents
        .lines()
        .any(|line| line.trim() == format!("api_key_vault_cmd = {HELPER}"))
}

fn waka_home() -> Result<(PathBuf, bool), String> {
    if let Some(value) = std::env::var_os("WAKATIME_HOME").filter(|value| !value.is_empty()) {
        let path = PathBuf::from(value);
        let path = if let Ok(rest) = path.strip_prefix("~") {
            home()?.join(rest)
        } else {
            path
        };
        if !path.is_absolute() {
            return Err("WAKATIME_HOME must resolve to an absolute path".into());
        }
        return Ok((path, true));
    }
    Ok((home()?, false))
}

fn home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".into())
}

fn config_path() -> Result<PathBuf, String> {
    test_config_path().map_or_else(
        || waka_home().map(|(home, _)| home.join(".wakatime.cfg")),
        Ok,
    )
}

fn plugin_command_path() -> Result<PathBuf, String> {
    if let Some(path) = crate::test_env_var("AUTOMIC_VAULT_TEST_WAKATIME_COMMAND") {
        return Ok(path.into());
    }
    let (home, custom) = waka_home()?;
    Ok(if custom {
        home.join("wakatime-cli")
    } else {
        home.join(".wakatime/wakatime-cli")
    })
}

fn test_config_path() -> Option<PathBuf> {
    crate::test_env_var("AUTOMIC_VAULT_TEST_WAKATIME_CONFIG").map(PathBuf::from)
}

fn target() -> PathBuf {
    super::isotope::target(super::isotope::WAKATIME)
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
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.len() > MAX_CONFIG_BYTES
        || metadata.uid() != super::effective_uid()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(format!(
            "refusing unsafe WakaTime config {}",
            path.display()
        ));
    }
    let mut contents = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    if contents.len() as u64 > MAX_CONFIG_BYTES {
        return Err("WakaTime config exceeds 1 MiB".into());
    }
    Ok(contents)
}

fn write_config(path: &Path, contents: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "WakaTime config has no parent".to_string())?;
    secure_directory(parent)?;
    let staging = parent.join(format!(
        ".wakatime.cfg.av-{}.tmp",
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
            .and_then(|dir| dir.sync_all())
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
            "refusing unsafe WakaTime directory {}",
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

fn plugin_link_valid(path: &Path, target: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
        && path.canonicalize().ok() == target.canonicalize().ok()
}

fn install_plugin_link(path: &Path, target: &Path) -> Result<(), String> {
    if plugin_link_valid(path, target) {
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "WakaTime command has no parent".to_string())?;
    secure_directory(parent)?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("failed to inspect {}: {error}", path.display())),
    };
    if let Some(metadata) = &metadata
        && !metadata.file_type().is_symlink()
        && !(metadata.file_type().is_file() && metadata.uid() == super::effective_uid())
    {
        return Err(format!(
            "refusing unsafe WakaTime command {}",
            path.display()
        ));
    }
    let staging = parent.join(format!(
        ".wakatime-cli.av-{}.tmp",
        super::isotope::now_nanos()
    ));
    symlink(target, &staging)
        .map_err(|error| format!("failed to create {}: {error}", staging.display()))?;
    let mut backup_path = None;
    if let Some(metadata) = metadata {
        if metadata.file_type().is_file() {
            let backup = path.with_extension("av-backup");
            if backup.exists() {
                let _ = fs::remove_file(&staging);
                return Err(format!(
                    "refusing to overwrite existing backup {}",
                    backup.display()
                ));
            }
            if let Err(error) = fs::rename(path, &backup) {
                let _ = fs::remove_file(&staging);
                return Err(format!("failed to back up {}: {error}", path.display()));
            }
            backup_path = Some(backup);
        }
    }
    if let Err(error) = fs::rename(&staging, path) {
        let _ = fs::remove_file(&staging);
        if let Some(backup) = backup_path
            && let Err(rollback) = fs::rename(&backup, path)
        {
            return Err(format!(
                "failed to install {}: {error}; failed to restore {}: {rollback}",
                path.display(),
                backup.display()
            ));
        }
        return Err(format!("failed to install {}: {error}", path.display()));
    }
    Ok(())
}

pub(crate) fn verify_target(path: &Path) -> Result<(), String> {
    if test_config_path().is_some() {
        return path
            .exists()
            .then_some(())
            .ok_or_else(|| format!("test WakaTime Target is missing: {}", path.display()));
    }
    let requirement = format!(
        "=identifier \"wakatime-cli\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"{TEAM_IDENTIFIER}\""
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
            "WakaTime Target signature is invalid: {}",
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
            "WakaTime Target lacks the required Developer ID Hardened Runtime identity".into(),
        );
    }
    let entitlements = Command::new("/usr/bin/codesign")
        .args(["-d", "--entitlements", ":-"])
        .arg(path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .output()
        .map_err(|error| format!("failed to inspect WakaTime entitlements: {error}"))?;
    if !entitlements.status.success() || !entitlements.stdout.is_empty() {
        return Err("WakaTime Target has unexpected code-signing entitlements".into());
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
    fn migrates_only_the_supported_global_key() {
        let api_key = ["waka_01234567", "89ab", "4cde", "8fab", "0123456789ab"].join("-");
        let input = format!("[settings]\napi_key = {api_key}\ndebug = true\n");
        let (sanitized, key) = sanitize_config(&input).unwrap();
        assert_eq!(key.as_deref(), Some(api_key.as_str()));
        assert_eq!(
            sanitized,
            format!("[settings]\ndebug = true\napi_key_vault_cmd = {HELPER}\n")
        );
        assert_eq!(sanitize_config(&sanitized).unwrap(), (sanitized, None));
        assert!(sanitize_config("[settings]\napi_url = https://example.com\n").is_err());
        assert!(sanitize_config(&format!("[project_api_key]\n/work = {api_key}\n")).is_err());
        assert!(sanitize_config("[settings]\nproxy = https://user:pass@example.com\n").is_err());
    }

    #[test]
    fn editor_plugin_binary_is_backed_up_and_replaced_by_a_target_link() {
        let directory = std::env::temp_dir().join(format!(
            "av-wakatime-link-{}-{}",
            std::process::id(),
            super::super::isotope::now_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let target = directory.join("target");
        let command = directory.join("wakatime-cli");
        fs::write(&target, "target").unwrap();
        fs::write(&command, "upstream").unwrap();

        install_plugin_link(&command, &target).unwrap();

        assert!(plugin_link_valid(&command, &target));
        assert_eq!(
            fs::read_to_string(command.with_extension("av-backup")).unwrap(),
            "upstream"
        );
        install_plugin_link(&command, &target).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }
}
