use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{HardenerDetection, SecretGateDescriptor, SecretGateRoute, isotope};

const PRIVILEGE_MODE: super::PrivilegeMode = super::PrivilegeMode::UserOnly;
const VAULT_KEY: &str = "SUPABASE_ACCESS_TOKEN";
const KEYCHAIN_SERVICE: &str = "Supabase CLI";
const KEYCHAIN_ACCOUNTS: &[&str] = &["supabase", "access-token"];

pub(crate) fn run(stdout: &mut dyn Write, yes: bool) -> Result<(), String> {
    PRIVILEGE_MODE.require_user("supabase", false)?;
    let install = isotope::plan(isotope::SUPABASE)?;

    let token_paths = supabase_token_paths()?;
    let mut tokens = read_plaintext_tokens(&token_paths)?;

    writeln!(stdout, "╭─ harden supabase")
        .map_err(|err| format!("failed to show Keychain notice: {err}"))?;
    writeln!(stdout, "│").map_err(|err| format!("failed to show Keychain notice: {err}"))?;
    writeln!(
        stdout,
        "├─ macOS may show a Keychain request from `security` while migrating a legacy Supabase token"
    )
    .map_err(|err| format!("failed to show Keychain notice: {err}"))?;
    writeln!(
        stdout,
        "├─ Automic Vault initiated that request; choose Allow, not Always Allow"
    )
    .and_then(|()| stdout.flush())
    .map_err(|err| format!("failed to show Keychain notice: {err}"))?;

    tokens.extend(read_legacy_keychain_tokens()?);
    tokens.sort();
    tokens.dedup();

    install.write(stdout, isotope::SUPABASE);
    if tokens.is_empty() && !install.needed() {
        writeln!(stdout, "╰─ no legacy Supabase credentials found").ok();
        super::write_secret_gate_notice(stdout, "supabase");
        return Ok(());
    }
    if tokens.len() > 1 {
        return Err(
            "multiple distinct Supabase access tokens found; remove the stale one and retry".into(),
        );
    }

    if tokens.is_empty() {
        writeln!(stdout, "├─ no legacy Supabase credentials found").ok();
    } else {
        writeln!(
            stdout,
            "├─ migrate Supabase access token into Automic Vault"
        )
        .ok();
        writeln!(stdout, "├─ remove plaintext fallback access-token files").ok();
    }
    writeln!(stdout, "│").ok();
    if !confirm(stdout, yes)? {
        writeln!(stdout, "╰─ cancelled").ok();
        return Ok(());
    }

    install.apply(isotope::SUPABASE)?;
    if tokens.is_empty() {
        writeln!(stdout, "╰─ installed supabase isotope").ok();
        super::write_secret_gate_notice(stdout, "supabase");
        return Ok(());
    }
    crate::secrets::store_secret(VAULT_KEY, &tokens[0])?;
    for path in &token_paths {
        remove_plaintext_token(path)?;
    }
    for account in KEYCHAIN_ACCOUNTS {
        delete_legacy_keychain_token(account)?;
    }
    writeln!(stdout, "╰─ migrated Supabase credentials").ok();
    super::write_secret_gate_notice(stdout, "supabase");
    Ok(())
}

pub(crate) fn detect() -> HardenerDetection {
    isotope::detect(isotope::SUPABASE)
}

pub(crate) fn secret_gate() -> SecretGateDescriptor {
    SecretGateDescriptor {
        id: "supabase",
        key_patterns: vec![VAULT_KEY.to_string()],
        routes: vec![SecretGateRoute {
            operation: "keys",
            script_path: None,
            target_path: isotope::target(isotope::SUPABASE).display().to_string(),
            caller_identifiers: vec!["supabase", "supabase-go", "com.supabase.cli"],
            key_patterns: vec![VAULT_KEY.to_string()],
            replace_existing_env: true,
            allow_missing_keys: false,
        }],
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

fn supabase_token_paths() -> Result<Vec<PathBuf>, String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())?;
    let mut paths = vec![home.join(".supabase/access-token")];
    if let Some(supabase_home) = std::env::var_os("SUPABASE_HOME").filter(|value| !value.is_empty())
    {
        paths.push(PathBuf::from(supabase_home).join("access-token"));
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn read_plaintext_tokens(paths: &[PathBuf]) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    for path in paths {
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
        };
        let token = contents.trim();
        if is_supabase_access_token(token) {
            tokens.push(token.to_string());
        }
    }
    Ok(tokens)
}

fn read_legacy_keychain_tokens() -> Result<Vec<String>, String> {
    if let Some(token) = crate::test_env_string("AUTOMIC_VAULT_TEST_SUPABASE_LEGACY_TOKEN") {
        return validate_legacy_keychain_token("test", token).map(|token| vec![token]);
    }
    if crate::test_keychain_dir().is_some() {
        return Ok(Vec::new());
    }
    let mut tokens = Vec::new();
    for account in KEYCHAIN_ACCOUNTS {
        if let Some(token) = security_find_generic_password(KEYCHAIN_SERVICE, account)? {
            tokens.push(token);
        }
    }
    Ok(tokens)
}

fn security_find_generic_password(service: &str, account: &str) -> Result<Option<String>, String> {
    super::gh_cli::security_find_generic_password_result(service, Some(account))?
        .map(|token| validate_legacy_keychain_token(account, token))
        .transpose()
}

fn validate_legacy_keychain_token(account: &str, token: String) -> Result<String, String> {
    is_supabase_access_token(&token).then_some(token).ok_or_else(|| {
        format!("legacy Supabase Keychain item for account {account:?} is not a supported access token")
    })
}

fn remove_plaintext_token(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("failed to remove {}: {err}", path.display())),
    }
}

fn delete_legacy_keychain_token(account: &str) -> Result<(), String> {
    if crate::test_env_var("AUTOMIC_VAULT_TEST_SUPABASE_LEGACY_TOKEN").is_some() {
        return Ok(());
    }
    let output = Command::new("/usr/bin/security")
        .args([
            "delete-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            account,
        ])
        .output()
        .map_err(|err| format!("failed to run security: {err}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("could not be found")
        || stderr.contains("The specified item could not be found")
    {
        return Ok(());
    }
    Err(format!(
        "failed to delete legacy Supabase keychain item: {}",
        stderr.trim()
    ))
}

fn is_supabase_access_token(value: &str) -> bool {
    let suffix = value
        .strip_prefix("sbp_oauth_")
        .or_else(|| value.strip_prefix("sbp_"));
    suffix.is_some_and(|rest| rest.len() == 40 && rest.chars().all(|ch| ch.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn harden_imports_plaintext_access_token() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_path("supabase-import");
        let home = dir.join("home");
        let keychain = dir.join("keychain");
        let supabase = dir.join("supabase");
        let token_dir = home.join(".supabase");
        fs::create_dir_all(&token_dir).unwrap();
        fs::write(&supabase, "").unwrap();
        fs::write(
            token_dir.join("access-token"),
            "sbp_0123456789abcdef0123456789abcdef01234567\n",
        )
        .unwrap();
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain);
            std::env::set_var("AUTOMIC_VAULT_TEST_SUPABASE_CLI_PATH", &supabase);
        }

        let mut output = Vec::new();
        run(&mut output, true).unwrap();

        unsafe {
            std::env::remove_var("HOME");
            std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR");
            std::env::remove_var("AUTOMIC_VAULT_TEST_SUPABASE_CLI_PATH");
        }
        assert_eq!(
            fs::read_to_string(keychain.join(VAULT_KEY)).unwrap(),
            "sbp_0123456789abcdef0123456789abcdef01234567"
        );
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Automic Vault initiated that request"));
        assert!(output.contains("choose Allow, not Always Allow"));
        assert!(!token_dir.join("access-token").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn detect_reports_full_supabase_path() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let missing = temp_path("missing-supabase-cli-detect");
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_SUPABASE_CLI_PATH", &missing);
        }

        let detection = detect();

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_SUPABASE_CLI_PATH");
        }
        assert_eq!(detection.target_path, Some(missing.display().to_string()));
    }

    #[test]
    fn validates_supabase_access_tokens() {
        assert!(is_supabase_access_token(
            "sbp_0123456789abcdef0123456789abcdef01234567"
        ));
        assert!(is_supabase_access_token(
            "sbp_oauth_0123456789abcdef0123456789abcdef01234567"
        ));
        assert!(!is_supabase_access_token("sbp_short"));
        assert!(!is_supabase_access_token("not-a-token"));
    }

    #[test]
    fn normalizes_go_keyring_wrapped_keychain_tokens() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let security = fake_security(
            "wrapped-supabase-keychain",
            "printf '%s\\n' 'go-keyring-base64:c2JwXzAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc='\n",
        );
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_SECURITY_PATH", &security);
        }

        let token = security_find_generic_password(KEYCHAIN_SERVICE, "supabase").unwrap();

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_SECURITY_PATH");
        }
        assert_eq!(
            token.as_deref(),
            Some("sbp_0123456789abcdef0123456789abcdef01234567")
        );
        let _ = fs::remove_file(security);
    }

    #[test]
    fn treats_only_item_not_found_as_keychain_absence() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let security = fake_security(
            "missing-supabase-keychain",
            "printf '%s\\n' 'The specified item could not be found in the keychain.' >&2\nexit 44\n",
        );
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_SECURITY_PATH", &security);
        }

        let token = security_find_generic_password(KEYCHAIN_SERVICE, "supabase").unwrap();

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_SECURITY_PATH");
        }
        assert_eq!(token, None);
        let _ = fs::remove_file(security);
    }

    #[test]
    fn keychain_read_errors_fail_closed() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_path("denied-supabase-migration");
        let home = dir.join("home");
        let supabase = dir.join("supabase");
        let token_path = home.join(".supabase/access-token");
        fs::create_dir_all(token_path.parent().unwrap()).unwrap();
        fs::write(&supabase, "original").unwrap();
        fs::write(
            &token_path,
            "sbp_0123456789abcdef0123456789abcdef01234567\n",
        )
        .unwrap();
        let security = fake_security(
            "denied-supabase-keychain",
            "printf '%s\\n' 'user interaction is not allowed' >&2\nexit 1\n",
        );
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("AUTOMIC_VAULT_TEST_SUPABASE_CLI_PATH", &supabase);
            std::env::set_var("AUTOMIC_VAULT_TEST_SECURITY_PATH", &security);
        }

        let error = run(&mut Vec::new(), true).unwrap_err();

        unsafe {
            std::env::remove_var("HOME");
            std::env::remove_var("AUTOMIC_VAULT_TEST_SUPABASE_CLI_PATH");
            std::env::remove_var("AUTOMIC_VAULT_TEST_SECURITY_PATH");
        }
        assert!(error.contains("failed to read legacy keychain item"));
        assert!(error.contains("user interaction is not allowed"));
        assert!(token_path.exists());
        assert_eq!(fs::read_to_string(supabase).unwrap(), "original");
        let _ = fs::remove_file(security);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn malformed_keychain_values_fail_closed() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let security = fake_security(
            "malformed-supabase-keychain",
            "printf '%s\\n' 'go-keyring-base64:not-base64'\n",
        );
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_SECURITY_PATH", &security);
        }

        let error = security_find_generic_password(KEYCHAIN_SERVICE, "supabase").unwrap_err();

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_SECURITY_PATH");
        }
        assert!(error.contains("unsupported or malformed value"));
        let _ = fs::remove_file(security);
    }

    fn fake_security(label: &str, body: &str) -> PathBuf {
        let path = temp_path(label);
        fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn temp_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("av-{label}-{}-{nanos}", std::process::id()))
    }
}
