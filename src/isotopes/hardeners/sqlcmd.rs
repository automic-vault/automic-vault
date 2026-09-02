use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;

use super::{
    HardenerCommand, HardenerDetection, HardenerDiagnostic, RequiredExecutable,
    SecretGateDescriptor, SecretGateRoute,
};

const AV_PATH: &str = "/usr/local/bin/av";
const PRIVILEGE_MODE: super::PrivilegeMode = super::PrivilegeMode::Mixed;
const TEAM_IDENTIFIER: &str = "ZU76A67LGU";

#[derive(Deserialize)]
struct Status {
    profiles: Vec<String>,
    total_users: usize,
    hardened: bool,
}

pub(crate) fn run(stdout: &mut dyn Write, yes: bool) -> Result<(), String> {
    let testing = test_target().is_some();
    PRIVILEGE_MODE.require_user("sqlcmd", testing)?;
    if !testing {
        crate::secrets::ensure_sqlcmd_helper_ready()?;
    }
    for name in ["SQLCMD_PASSWORD", "SQLCMDPASSWORD"] {
        if std::env::var_os(name).is_some() {
            return Err(format!("unset {name} before hardening sqlcmd"));
        }
    }
    let target = target();
    let plan = super::isotope::plan(super::isotope::SQLCMD)?;

    writeln!(stdout, "╭─ harden sqlcmd").ok();
    writeln!(stdout, "│").ok();
    plan.write(stdout, super::isotope::SQLCMD);
    writeln!(
        stdout,
        "├─ move basic-auth passwords into Automic Vault custody"
    )
    .ok();
    writeln!(
        stdout,
        "├─ keep only sqlcmd user, context, and endpoint metadata on disk"
    )
    .ok();
    writeln!(stdout, "│").ok();
    if !confirm(stdout, yes)? {
        writeln!(stdout, "╰─ cancelled").ok();
        return Ok(());
    }

    plan.apply(super::isotope::SQLCMD)?;
    verify_target(&target)?;
    if !testing {
        verify_command_resolution()?;
    }
    let before = status(&target, true)?;
    ensure_managed_secrets_exist(&before.profiles)?;
    let after = if before.hardened {
        before
    } else {
        status(&target, false)?
    };
    if !after.hardened || after.profiles.len() != after.total_users {
        return Err("sqlcmd did not reach the supported Hardened State".into());
    }
    ensure_managed_secrets_exist(&after.profiles)?;
    writeln!(stdout, "╰─ hardened sqlcmd").ok();
    super::write_secret_gate_notice(stdout, "sqlcmd");
    Ok(())
}

pub(crate) fn detect() -> HardenerDetection {
    let target = target();
    let target_valid = verify_target(&target).is_ok();
    let command_resolves = test_target().is_some() || verify_command_resolution().is_ok();
    let config = config_path();
    let config_valid = target_valid
        && (!config.exists() || status(&target, true).is_ok_and(|value| value.hardened));
    let hardened = target_valid && command_resolves && config_valid;
    let isotope = super::isotope::detect(super::isotope::SQLCMD)
        .commands
        .into_iter()
        .next()
        .and_then(|command| command.isotope);
    let command = HardenerCommand {
        name: "sqlcmd".into(),
        hardened,
        stub_valid: true,
        stub_path: None,
        target_path: target.display().to_string(),
        required_paths: if test_target().is_some() {
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
    detection.applicable = config.exists() || target.exists();
    if target.exists() && !target_valid && test_target().is_none() {
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "sqlcmd_target_invalid",
            message: verify_target(&target).unwrap_err(),
            remediation: "Rerun `av harden sqlcmd` to install the signed sqlcmd Isotope.".into(),
            path: Some(target.display().to_string()),
        });
    }
    if target_valid && !command_resolves && test_target().is_none() {
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "sqlcmd_command_shadowed",
            message: verify_command_resolution().unwrap_err(),
            remediation: "Rerun `av harden sqlcmd` after correcting PATH.".into(),
            path: Some(target.display().to_string()),
        });
    }
    if config.exists() && !config_valid {
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "sqlcmd_plaintext_or_unsupported_config",
            message: "sqlcmd configuration is not in the supported Hardened State.".into(),
            remediation: "Rerun `av harden sqlcmd`; custom sqlconfig paths and unsupported authentication must be resolved manually.".into(),
            path: Some(config.display().to_string()),
        });
    }
    detection
}

pub(crate) fn secret_gate() -> SecretGateDescriptor {
    SecretGateDescriptor {
        id: "sqlcmd",
        key_patterns: vec!["SQLCMD_PASSWORD_*".into()],
        routes: vec![SecretGateRoute {
            operation: "sqlcmd-get",
            script_path: None,
            target_path: target().display().to_string(),
            caller_identifiers: vec!["com.automicvault.av"],
            key_patterns: vec!["SQLCMD_PASSWORD_*".into()],
            replace_existing_env: false,
            allow_missing_keys: false,
        }],
    }
}

fn status(target: &Path, read_only: bool) -> Result<Status, String> {
    let home = std::env::var_os("HOME").ok_or_else(|| "HOME is not set".to_string())?;
    let mut command = Command::new(target);
    command.args(["config", "automic-vault"]);
    if read_only {
        command.arg("--status");
    }
    let output = command
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("failed to inspect sqlcmd configuration: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "sqlcmd configuration check failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("sqlcmd returned invalid Automic Vault status: {error}"))
}

fn ensure_managed_secrets_exist(profiles: &[String]) -> Result<(), String> {
    if profiles.is_empty() {
        return Ok(());
    }
    let names = crate::secrets::list_global_secret_names()?;
    for profile in profiles {
        let profile = crate::cli::sqlcmd_credential::normalize_profile(profile)?;
        let name = crate::cli::sqlcmd_credential::secret_name(&profile);
        if !names.contains(&name) {
            return Err(format!(
                "sqlcmd credential marker has no matching Secret Value: {name}"
            ));
        }
    }
    Ok(())
}

fn config_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join(".sqlcmd/sqlconfig")
}

fn test_target() -> Option<PathBuf> {
    crate::test_env_var("AUTOMIC_VAULT_TEST_SQLCMD_TARGET").map(PathBuf::from)
}

fn target() -> PathBuf {
    super::isotope::target(super::isotope::SQLCMD)
}

fn verify_command_resolution() -> Result<(), String> {
    let output = Command::new("/usr/bin/which")
        .arg("sqlcmd")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("failed to resolve sqlcmd: {error}"))?;
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
            "your PATH does not resolve `sqlcmd` to {}; remove version-manager shims or adjust PATH",
            target().display()
        ))
    }
}

pub(crate) fn verify_target(path: &Path) -> Result<(), String> {
    if test_target().is_some() {
        return path
            .exists()
            .then_some(())
            .ok_or_else(|| format!("test sqlcmd Target is missing: {}", path.display()));
    }
    let requirement = format!(
        "=identifier \"sqlcmd\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"{TEAM_IDENTIFIER}\""
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
            "sqlcmd Target signature is invalid: {}",
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
            "sqlcmd Target lacks the required Developer ID Hardened Runtime identity".into(),
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
        return Err("sqlcmd Target has unexpected code-signing entitlements".into());
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
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn hardener_migrates_through_the_signed_target_boundary() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root = std::env::temp_dir().join(format!("av-sqlcmd-hardener-{}", std::process::id()));
        let home = root.join("home");
        let original_home = std::env::var_os("HOME");
        let target = root.join("sqlcmd");
        let keychain = root.join("keychain");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(home.join(".sqlcmd")).unwrap();
        fs::create_dir_all(&keychain).unwrap();
        fs::write(home.join(".sqlcmd/sqlconfig"), "password: cGFzc3dvcmQ=\n").unwrap();
        fs::write(
            &target,
            "#!/bin/sh\nif test \"$3\" = --status && ! test -f \"$HOME/.migrated\"; then echo '{\"profiles\":[],\"total_users\":1,\"hardened\":false}'; else touch \"$HOME/.migrated\"; echo '{\"profiles\":[\"prod\"],\"total_users\":1,\"hardened\":true}'; fi\n",
        ).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            keychain.join(crate::cli::sqlcmd_credential::secret_name("prod")),
            "password",
        )
        .unwrap();
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("AUTOMIC_VAULT_TEST_SQLCMD_TARGET", &target);
            std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain);
        }
        run(&mut Vec::new(), true).unwrap();
        assert!(detect().hardened);
        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_SQLCMD_TARGET");
            std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR");
            if let Some(home) = original_home {
                std::env::set_var("HOME", home);
            } else {
                std::env::remove_var("HOME");
            }
        }
        let _ = fs::remove_dir_all(root);
    }
}
