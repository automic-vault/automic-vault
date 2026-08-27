use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use super::{HardenerDetection, SecretGateDescriptor, SecretGateRoute, isotope};

const PRIVILEGE_MODE: super::PrivilegeMode = super::PrivilegeMode::UserOnly;
const KEYCHAIN_SERVICE: &str = "StripeCLI";
const API_KEY_FIELDS: [&str; 2] = ["test_mode_api_key", "live_mode_api_key"];

#[derive(Clone)]
struct Credential {
    value: String,
    legacy_accounts: BTreeSet<String>,
}

pub(crate) fn run(stdout: &mut dyn Write, yes: bool) -> Result<(), String> {
    PRIVILEGE_MODE.require_user("stripe", false)?;
    let install = isotope::plan(isotope::STRIPE)?;

    let config_dir = stripe_config_dir()?;
    let config_path = config_dir.join("config.toml");
    let credentials_path = config_dir.join("credentials.json");
    let config = match fs::read_to_string(&config_path) {
        Ok(config) => config,
        Err(err) if err.kind() == io::ErrorKind::NotFound => String::new(),
        Err(err) => {
            return Err(format!("failed to read {}: {err}", config_path.display()));
        }
    };
    let profiles = parse_profiles(&config);
    let mut credentials = BTreeMap::<String, Credential>::new();

    for (profile, account_id) in &profiles {
        for field in API_KEY_FIELDS {
            let legacy_key = format!("{profile}.{field}");
            let key = vault_key(&logical_api_key(profile, account_id, field));
            if let Some(value) =
                config_value(&config, profile, field).filter(|value| is_api_key(value))
            {
                add_credential(&mut credentials, key.clone(), value, None)?;
            }
            if let Some(value) = legacy_keychain_value(&legacy_key)? {
                add_credential(&mut credentials, key, value, Some(legacy_key))?;
            }
        }
        let session_key = format!("{profile}.stripe_cli_session");
        if let Some(value) = legacy_keychain_value(&session_key)? {
            add_credential(
                &mut credentials,
                vault_key(&session_key),
                value,
                Some(session_key),
            )?;
        }
    }
    if let Some(value) = legacy_keychain_value("uat")? {
        add_credential(
            &mut credentials,
            vault_key("uat"),
            value,
            Some("uat".to_string()),
        )?;
    }

    let fallback = read_fallback(&credentials_path)?;
    for (legacy_key, value) in &fallback {
        let logical_key = remap_api_key(legacy_key, &profiles);
        add_credential(
            &mut credentials,
            vault_key(&logical_key),
            value.clone(),
            None,
        )?;
    }

    writeln!(stdout, "╭─ harden stripe").ok();
    writeln!(stdout, "│").ok();
    install.write(stdout, isotope::STRIPE);
    if credentials.is_empty() && !install.needed() {
        remove_fallback(&credentials_path)?;
        writeln!(stdout, "╰─ no legacy Stripe credentials found").ok();
        super::write_secret_gate_notice(stdout, "stripe");
        return Ok(());
    }
    if credentials.is_empty() {
        writeln!(stdout, "├─ no legacy Stripe credentials found").ok();
    } else {
        writeln!(
            stdout,
            "├─ migrate {} Stripe credential(s) into Automic Vault",
            credentials.len()
        )
        .ok();
        writeln!(stdout, "├─ remove legacy Keychain and plaintext copies").ok();
    }
    writeln!(stdout, "│").ok();
    if !super::gh_cli::confirm(stdout, yes)? {
        writeln!(stdout, "╰─ cancelled").ok();
        return Ok(());
    }

    install.apply(isotope::STRIPE)?;
    if credentials.is_empty() {
        remove_fallback(&credentials_path)?;
        writeln!(stdout, "╰─ installed stripe isotope").ok();
        super::write_secret_gate_notice(stdout, "stripe");
        return Ok(());
    }
    for (key, credential) in &credentials {
        crate::secrets::store_secret(key, &credential.value)?;
    }
    rewrite_config(&config_path, &config, &credentials)?;
    remove_fallback(&credentials_path)?;
    for credential in credentials.values() {
        for account in &credential.legacy_accounts {
            delete_legacy_keychain_value(account)?;
        }
    }
    writeln!(stdout, "╰─ migrated Stripe credentials").ok();
    super::write_secret_gate_notice(stdout, "stripe");
    Ok(())
}

pub(crate) fn detect() -> HardenerDetection {
    isotope::detect(isotope::STRIPE)
}

pub(crate) fn secret_gate() -> SecretGateDescriptor {
    SecretGateDescriptor {
        id: "stripe",
        key_patterns: vec!["STRIPE_CLI_*".to_string()],
        routes: vec![SecretGateRoute {
            operation: "keys",
            script_path: None,
            target_path: isotope::target(isotope::STRIPE).display().to_string(),
            caller_identifiers: vec!["stripe"],
            key_patterns: vec!["STRIPE_CLI_*".to_string()],
            replace_existing_env: true,
            allow_missing_keys: false,
        }],
    }
}

fn stripe_config_dir() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path).join("stripe"));
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|path| path.join(".config/stripe"))
        .ok_or_else(|| "HOME is not set".to_string())
}

fn parse_profiles(config: &str) -> BTreeMap<String, String> {
    let mut profiles = BTreeMap::new();
    let mut section = None;
    for line in config.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            section = Some(name.trim_matches('"').to_string());
            continue;
        }
        if let Some(section) = section.as_ref() {
            if let Some(account_id) = toml_value(trimmed, "account_id") {
                profiles.insert(section.clone(), account_id);
            } else if toml_value(trimmed, "display_name").is_some()
                || API_KEY_FIELDS
                    .iter()
                    .any(|field| toml_value(trimmed, field).is_some())
            {
                profiles.entry(section.clone()).or_default();
            }
        }
    }
    profiles
}

fn config_value(config: &str, wanted_section: &str, wanted_key: &str) -> Option<String> {
    let mut section = None;
    for line in config.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            section = Some(name.trim_matches('"'));
            continue;
        }
        if section == Some(wanted_section)
            && let Some(value) = toml_value(trimmed, wanted_key)
        {
            return Some(value);
        }
    }
    None
}

fn toml_value(line: &str, wanted_key: &str) -> Option<String> {
    let (key, value) = line.split_once('=')?;
    (key.trim() == wanted_key).then(|| {
        value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string()
    })
}

fn is_api_key(value: &str) -> bool {
    value.len() >= 12
        && !value.contains('*')
        && (value.starts_with("sk_") || value.starts_with("rk_"))
}

fn read_fallback(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };
    serde_json::from_slice(&data)
        .map_err(|err| format!("failed to parse {}: {err}", path.display()))
}

fn remove_fallback(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("failed to remove {}: {err}", path.display())),
    }
}

fn remap_api_key(key: &str, profiles: &BTreeMap<String, String>) -> String {
    for (profile, account_id) in profiles {
        for field in API_KEY_FIELDS {
            if key == format!("{profile}.{field}") {
                return logical_api_key(profile, account_id, field);
            }
        }
    }
    key.to_string()
}

fn logical_api_key(profile: &str, account_id: &str, field: &str) -> String {
    if account_id.trim().is_empty() {
        format!("{profile}.{field}")
    } else {
        format!("account.{}.{field}", account_id.trim())
    }
}

fn vault_key(logical_key: &str) -> String {
    let mut key = String::from("STRIPE_CLI_");
    for byte in logical_key.as_bytes() {
        use std::fmt::Write as _;
        write!(key, "{byte:02X}").unwrap();
    }
    key
}

fn add_credential(
    credentials: &mut BTreeMap<String, Credential>,
    key: String,
    value: String,
    legacy_account: Option<String>,
) -> Result<(), String> {
    let credential = credentials
        .entry(key.clone())
        .or_insert_with(|| Credential {
            value: value.clone(),
            legacy_accounts: BTreeSet::new(),
        });
    if credential.value != value {
        return Err(format!("conflicting legacy Stripe credentials for {key}"));
    }
    if let Some(account) = legacy_account {
        credential.legacy_accounts.insert(account);
    }
    Ok(())
}

fn legacy_keychain_value(account: &str) -> Result<Option<String>, String> {
    if let Some(json) = crate::test_env_string("AUTOMIC_VAULT_TEST_STRIPE_LEGACY_KEYS") {
        return serde_json::from_str::<BTreeMap<String, String>>(&json)
            .map(|mut values| values.remove(account))
            .map_err(|err| format!("failed to parse test Stripe Keychain values: {err}"));
    }
    super::gh_cli::security_find_generic_password(KEYCHAIN_SERVICE, Some(account))
}

fn delete_legacy_keychain_value(account: &str) -> Result<(), String> {
    if crate::test_env_var("AUTOMIC_VAULT_TEST_STRIPE_LEGACY_KEYS").is_some() {
        return Ok(());
    }
    super::gh_cli::security_delete_generic_password(KEYCHAIN_SERVICE, Some(account))
}

fn rewrite_config(
    path: &Path,
    config: &str,
    credentials: &BTreeMap<String, Credential>,
) -> Result<(), String> {
    if config.is_empty() {
        return Ok(());
    }
    let profiles = parse_profiles(config);
    let mut section = None;
    let mut changed = false;
    let mut lines = Vec::new();
    for line in config.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            section = Some(name.trim_matches('"').to_string());
        }
        let replacement = section.as_ref().and_then(|profile| {
            let account_id = profiles.get(profile)?;
            API_KEY_FIELDS.iter().find_map(|field| {
                toml_value(trimmed, field).and_then(|value| {
                    let key = vault_key(&logical_api_key(profile, account_id, field));
                    credentials
                        .get(&key)
                        .filter(|_| is_api_key(&value))
                        .map(|credential| format!("{field} = '{}'", redact(&credential.value)))
                })
            })
        });
        if let Some(replacement) = replacement {
            lines.push(replacement);
            changed = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if changed {
        let mut rewritten = lines.join("\n");
        if config.ends_with('\n') {
            rewritten.push('\n');
        }
        fs::write(path, rewritten)
            .map_err(|err| format!("failed to rewrite {}: {err}", path.display()))?;
    }
    Ok(())
}

fn redact(value: &str) -> String {
    format!(
        "{}{}{}",
        &value[..8],
        "*".repeat(value.len() - 12),
        &value[value.len() - 4..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn harden_migrates_keychain_and_plaintext_credentials() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_path("stripe-import");
        let config_dir = dir.join("stripe");
        let keychain = dir.join("keychain");
        let stripe = dir.join("stripe-cli");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(&stripe, "").unwrap();
        fs::write(
            config_dir.join("config.toml"),
            "[default]\naccount_id = 'acct_123'\ntest_mode_api_key = 'sk_test_1234567890'\nlive_mode_api_key = 'rk_live_********0000'\n",
        )
        .unwrap();
        fs::write(
            config_dir.join("credentials.json"),
            r#"{"uat":"uat_secret"}"#,
        )
        .unwrap();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &dir);
            std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain);
            std::env::set_var("AUTOMIC_VAULT_TEST_STRIPE_CLI_PATH", &stripe);
            std::env::set_var(
                "AUTOMIC_VAULT_TEST_STRIPE_LEGACY_KEYS",
                r#"{"default.live_mode_api_key":"rk_live_1234567890"}"#,
            );
        }

        run(&mut Vec::new(), true).unwrap();

        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR");
            std::env::remove_var("AUTOMIC_VAULT_TEST_STRIPE_CLI_PATH");
            std::env::remove_var("AUTOMIC_VAULT_TEST_STRIPE_LEGACY_KEYS");
        }
        assert_eq!(
            fs::read_to_string(keychain.join(vault_key("account.acct_123.test_mode_api_key")))
                .unwrap(),
            "sk_test_1234567890"
        );
        assert_eq!(
            fs::read_to_string(keychain.join(vault_key("account.acct_123.live_mode_api_key")))
                .unwrap(),
            "rk_live_1234567890"
        );
        assert_eq!(
            fs::read_to_string(keychain.join(vault_key("uat"))).unwrap(),
            "uat_secret"
        );
        let config = fs::read_to_string(config_dir.join("config.toml")).unwrap();
        assert!(!config.contains("sk_test_1234567890"));
        assert!(!config_dir.join("credentials.json").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn harden_removes_empty_fallback() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_path("stripe-empty-fallback");
        let config_dir = dir.join("stripe");
        let fallback = config_dir.join("credentials.json");
        let stripe = dir.join("stripe-cli");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(&fallback, "{}").unwrap();
        fs::write(&stripe, "").unwrap();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &dir);
            std::env::set_var("AUTOMIC_VAULT_TEST_STRIPE_CLI_PATH", &stripe);
            std::env::set_var("AUTOMIC_VAULT_TEST_STRIPE_LEGACY_KEYS", "{}");
        }

        run(&mut Vec::new(), true).unwrap();

        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var("AUTOMIC_VAULT_TEST_STRIPE_CLI_PATH");
            std::env::remove_var("AUTOMIC_VAULT_TEST_STRIPE_LEGACY_KEYS");
        }
        assert!(!fallback.exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn stripe_gate_matches_the_signed_isotope() {
        let gate = secret_gate();
        assert_eq!(gate.id, "stripe");
        assert_eq!(gate.key_patterns, ["STRIPE_CLI_*"]);
        assert_eq!(gate.routes[0].caller_identifiers, ["stripe"]);
        assert_eq!(gate.routes[0].key_patterns, ["STRIPE_CLI_*"]);
    }

    #[test]
    fn keychain_read_errors_fail_closed() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let security = temp_path("denied-stripe-keychain");
        fs::write(
            &security,
            "#!/bin/sh\nprintf '%s\\n' 'user interaction is not allowed' >&2\nexit 1\n",
        )
        .unwrap();
        fs::set_permissions(&security, fs::Permissions::from_mode(0o700)).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_SECURITY_PATH", &security);
        }

        let error = legacy_keychain_value("uat").unwrap_err();

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_SECURITY_PATH");
        }
        assert!(error.contains("failed to read legacy keychain item"));
        let _ = fs::remove_file(security);
    }

    fn temp_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("av-{name}-{}-{nonce}", std::process::id()))
    }
}
