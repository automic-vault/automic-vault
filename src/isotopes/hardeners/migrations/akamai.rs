#[cfg(all(target_os = "macos", not(test), not(coverage)))]
use std::ffi::{CString, c_char};
use std::fs;
use std::path::{Path, PathBuf};

const KEYCHAIN_SERVICE: &str = "com.automicvault.isotope";
const AKAMAI_ENV_ASSIGNMENTS_KEY: &str = "AKAMAI_ENV_ASSIGNMENTS";

pub trait CredentialStore {
    fn store_secret(&self, key: &str, value: &str) -> Result<(), String>;
}

pub struct KeychainCredentialStore;

pub fn keys() -> &'static [&'static str] {
    &[AKAMAI_ENV_ASSIGNMENTS_KEY]
}

pub fn migrate_credentials() -> Result<(), String> {
    migrate_credentials_file(&edgerc_path()?, &KeychainCredentialStore).map(|_| ())
}

pub fn migrate_credentials_file(path: &Path, store: &dyn CredentialStore) -> Result<bool, String> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };

    let migration = edgerc_migration(&contents)?;
    if !migration.changed {
        return Ok(false);
    }

    store.store_secret(
        AKAMAI_ENV_ASSIGNMENTS_KEY,
        &migration.assignments.join("\n"),
    )?;
    fs::write(path, migration.sanitized)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    Ok(true)
}

fn edgerc_path() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("AKAMAI_EDGERC").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path));
    }

    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())?;
    Ok(home.join(".edgerc"))
}

pub(super) fn caller_has_credentials(edgerc: Option<&Path>, section: &str) -> bool {
    let prefix = match env_section_prefix(section) {
        Ok(prefix) => format!("AKAMAI_{prefix}"),
        Err(_) => return false,
    };
    if ["CLIENT_TOKEN", "CLIENT_SECRET", "ACCESS_TOKEN"]
        .iter()
        .all(|key| {
            std::env::var_os(format!("{prefix}{key}")).is_some_and(|value| !value.is_empty())
        })
    {
        return true;
    }

    let path = edgerc
        .map(Path::to_path_buf)
        .or_else(|| {
            std::env::var_os("AKAMAI_EDGERC")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".edgerc")));
    let Some(path) = path else { return false };
    let Ok(contents) = fs::read_to_string(path) else {
        return false;
    };
    edgerc_section_has_credentials(&contents, section)
}

pub(super) fn command_is_installed(command: &str) -> bool {
    let Some(home) = std::env::var_os("AKAMAI_CLI_HOME")
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var_os("HOME"))
    else {
        return false;
    };
    let Ok(packages) = fs::read_dir(PathBuf::from(home).join(".akamai-cli/src")) else {
        return false;
    };
    packages.filter_map(Result::ok).any(|package| {
        let path = package.path();
        let package_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("cli-"));
        let Ok(contents) = fs::read(path.join("cli.json")) else {
            return false;
        };
        let Ok(metadata) = serde_json::from_slice::<serde_json::Value>(&contents) else {
            return false;
        };
        metadata["commands"].as_array().is_some_and(|commands| {
            commands.iter().any(|candidate| {
                let Some(name) = candidate["name"].as_str() else {
                    return false;
                };
                let name = name.to_ascii_lowercase();
                command == name
                    || candidate["aliases"].as_array().is_some_and(|aliases| {
                        aliases.iter().any(|alias| alias.as_str() == Some(command))
                    })
                    || package_name.is_some_and(|package| command == format!("{package}/{name}"))
            })
        })
    })
}

fn edgerc_section_has_credentials(contents: &str, wanted: &str) -> bool {
    let mut section = String::new();
    let mut values = Vec::new();
    for line in contents.lines() {
        if let Some(name) = section_name(line) {
            section = name.to_string();
            continue;
        }
        if (section == wanted || section.is_empty() && wanted == "default")
            && let Some((key, value)) = config_value(line)
        {
            values.push((key.to_ascii_lowercase(), value));
        }
    }
    ["host", "client_token", "client_secret", "access_token"]
        .iter()
        .all(|key| {
            values
                .iter()
                .rev()
                .find(|(candidate, _)| candidate == key)
                .is_some_and(|(_, value)| !value.is_empty())
        })
}

fn config_has_edgegrid_secrets(contents: &str) -> bool {
    config_values(contents).any(|(key, value)| {
        matches!(
            key.as_str(),
            "client_token" | "client_secret" | "access_token"
        ) && !value.is_empty()
    })
}

#[derive(Debug)]
struct EdgeRcMigration {
    sanitized: String,
    assignments: Vec<String>,
    changed: bool,
}

#[derive(Debug, Default)]
struct EdgeRcSection {
    name: String,
    values: Vec<(String, String)>,
    has_secret: bool,
}

fn edgerc_migration(contents: &str) -> Result<EdgeRcMigration, String> {
    let mut output = Vec::new();
    let mut sections = Vec::new();
    let mut current = EdgeRcSection::default();
    let mut changed = false;

    for line in contents.lines() {
        if let Some(name) = section_name(line) {
            sections.push(current);
            current = EdgeRcSection {
                name: name.to_string(),
                values: Vec::new(),
                has_secret: false,
            };
            output.push(line.to_string());
            continue;
        }

        if let Some((key, value)) = config_value(line) {
            let normalized = key.to_ascii_lowercase();
            if is_edgegrid_secret_key(&normalized) && !value.is_empty() {
                current.has_secret = true;
                changed = true;
                current.values.push((normalized, value));
                output.push(format!("{key} = \"\""));
                continue;
            }
            current.values.push((normalized, value));
        }
        output.push(line.to_string());
    }
    sections.push(current);

    if !changed {
        return Ok(EdgeRcMigration {
            sanitized: contents.to_string(),
            assignments: Vec::new(),
            changed,
        });
    }

    let mut assignments = Vec::new();
    for section in sections.iter().filter(|section| section.has_secret) {
        section_assignments(section, &mut assignments)?;
    }

    let mut sanitized = output.join("\n");
    if contents.ends_with('\n') {
        sanitized.push('\n');
    }
    Ok(EdgeRcMigration {
        sanitized,
        assignments,
        changed,
    })
}

fn section_name(line: &str) -> Option<&str> {
    line.trim()
        .strip_prefix('[')?
        .strip_suffix(']')
        .map(str::trim)
}

fn config_value(line: &str) -> Option<(String, String)> {
    let line = line.split(['#', ';']).next().unwrap_or("").trim();
    let (key, value) = line.split_once('=')?;
    Some((key.trim().to_string(), unquote_ini_value(value.trim())))
}

fn unquote_ini_value(value: &str) -> String {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
        {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

fn section_assignments(
    section: &EdgeRcSection,
    assignments: &mut Vec<String>,
) -> Result<(), String> {
    let prefix = env_section_prefix(&section.name)?;
    for key in ["host", "client_token", "client_secret", "access_token"] {
        let value = section_value(section, key).ok_or_else(|| {
            let section = if section.name.is_empty() {
                "default".to_string()
            } else {
                section.name.clone()
            };
            format!("Akamai [{section}] is missing required EdgeGrid key {key}")
        })?;
        let variable = format!("AKAMAI_{prefix}{}", key.to_ascii_uppercase());
        push_assignment(assignments, variable, value)?;
    }
    if let Some(account_key) = section_value(section, "account_key") {
        push_assignment(assignments, "AKAMAI_ACCOUNT_KEY".to_string(), account_key)?;
    }
    Ok(())
}

fn env_section_prefix(section: &str) -> Result<String, String> {
    if section.is_empty() || section == "default" {
        return Ok(String::new());
    }
    if !section
        .chars()
        .all(|character| character == '_' || character.is_ascii_alphanumeric())
    {
        return Err(format!(
            "Akamai section [{section}] cannot be represented as a safe environment variable"
        ));
    }
    Ok(format!("{}_", section.to_ascii_uppercase()))
}

fn section_value(section: &EdgeRcSection, key: &str) -> Option<String> {
    section
        .values
        .iter()
        .rev()
        .find(|(candidate, value)| candidate == key && !value.is_empty())
        .map(|(_, value)| value.clone())
}

fn push_assignment(
    assignments: &mut Vec<String>,
    variable: String,
    value: String,
) -> Result<(), String> {
    if value.contains('\n') || value.contains('\r') {
        return Err(format!("{variable} cannot contain line breaks"));
    }
    let assignment = format!("{variable}={value}");
    let prefix = format!("{variable}=");
    if assignments
        .iter()
        .any(|existing| existing.starts_with(&prefix) && existing != &assignment)
    {
        return Err(format!(
            "Akamai variable {variable} has conflicting values across sections"
        ));
    }
    if !assignments.iter().any(|existing| existing == &assignment) {
        assignments.push(assignment);
    }
    Ok(())
}

fn is_edgegrid_secret_key(key: &str) -> bool {
    matches!(key, "client_token" | "client_secret" | "access_token")
}

fn config_values(contents: &str) -> impl Iterator<Item = (String, String)> + '_ {
    contents.lines().filter_map(|line| config_value(line))
}

impl CredentialStore for KeychainCredentialStore {
    fn store_secret(&self, key: &str, value: &str) -> Result<(), String> {
        keychain_store_secret(KEYCHAIN_SERVICE, key, value)
    }
}

#[cfg(all(target_os = "macos", not(test), not(coverage)))]
fn keychain_store_secret(service: &str, account: &str, value: &str) -> Result<(), String> {
    unsafe extern "C" {
        fn isotope_store_generic_password_json(
            service_cstr: *const c_char,
            account_cstr: *const c_char,
            value_cstr: *const c_char,
            error_cstr: *mut *mut c_char,
        ) -> bool;
    }

    let service_cstr =
        CString::new(service).map_err(|_| "invalid keychain service name".to_string())?;
    let account_cstr =
        CString::new(account).map_err(|_| "invalid keychain account name".to_string())?;
    let value_cstr =
        CString::new(value).map_err(|_| "invalid keychain secret value".to_string())?;
    let mut error = std::ptr::null_mut();
    if unsafe {
        isotope_store_generic_password_json(
            service_cstr.as_ptr(),
            account_cstr.as_ptr(),
            value_cstr.as_ptr(),
            &mut error,
        )
    } {
        return Ok(());
    }

    let message =
        unsafe { take_bridge_string(error) }.unwrap_or_else(|| "keychain write failed".to_string());
    Err(format!("failed to store secret {account}: {message}"))
}

#[cfg(any(not(target_os = "macos"), test, coverage))]
fn keychain_store_secret(_service: &str, _account: &str, _value: &str) -> Result<(), String> {
    Err("Automic Vault secret storage is only available on macOS".to_string())
}

#[cfg(all(target_os = "macos", not(test), not(coverage)))]
unsafe fn take_bridge_string(value: *mut c_char) -> Option<String> {
    if value.is_null() {
        return None;
    }

    unsafe extern "C" {
        fn isotope_free_c_string(value: *mut c_char);
    }

    let bytes = unsafe { std::ffi::CStr::from_ptr(value) }
        .to_str()
        .ok()
        .map(str::to_owned);
    unsafe { isotope_free_c_string(value) };
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::fs;

    #[derive(Default)]
    struct TestCredentialStore {
        values: RefCell<Vec<(String, String)>>,
    }

    struct FailingStore;

    impl CredentialStore for TestCredentialStore {
        fn store_secret(&self, key: &str, value: &str) -> Result<(), String> {
            self.values
                .borrow_mut()
                .push((key.to_string(), value.to_string()));
            Ok(())
        }
    }

    impl CredentialStore for FailingStore {
        fn store_secret(&self, _key: &str, _value: &str) -> Result<(), String> {
            Err("store failed".to_string())
        }
    }

    #[test]
    fn migrates_edgerc_to_env_assignments() {
        let path = std::env::temp_dir().join(format!("akamai-edgerc-{}", std::process::id()));
        let contents = "[default]\nhost = example.luna.akamaiapis.net\nclient_token = tok\nclient_secret = sec\naccess_token = acc\n";
        fs::write(&path, contents).unwrap();
        let store = TestCredentialStore::default();

        assert!(migrate_credentials_file(&path, &store).unwrap());
        assert_eq!(
            store.values.borrow().as_slice(),
            &[(
                AKAMAI_ENV_ASSIGNMENTS_KEY.to_string(),
                "AKAMAI_HOST=example.luna.akamaiapis.net\nAKAMAI_CLIENT_TOKEN=tok\nAKAMAI_CLIENT_SECRET=sec\nAKAMAI_ACCESS_TOKEN=acc".to_string()
            )]
        );
        let sanitized = fs::read_to_string(&path).unwrap();
        assert!(sanitized.contains("host = example.luna.akamaiapis.net"));
        assert!(sanitized.contains("client_token = \"\""));
        assert!(sanitized.contains("client_secret = \"\""));
        assert!(sanitized.contains("access_token = \"\""));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn maps_named_sections_to_prefixed_env_assignments() {
        let migration = edgerc_migration(
            "[papi]\nhost = example.luna.akamaiapis.net\nclient_token = tok\nclient_secret = sec\naccess_token = acc\n",
        )
        .unwrap();

        assert_eq!(
            migration.assignments,
            vec![
                "AKAMAI_PAPI_HOST=example.luna.akamaiapis.net",
                "AKAMAI_PAPI_CLIENT_TOKEN=tok",
                "AKAMAI_PAPI_CLIENT_SECRET=sec",
                "AKAMAI_PAPI_ACCESS_TOKEN=acc",
            ]
        );
    }

    #[test]
    fn rejects_incomplete_or_unsafe_sections() {
        let missing = edgerc_migration("[default]\nclient_token = tok\n").unwrap_err();
        assert!(missing.contains("missing required EdgeGrid key"));

        let unsafe_section = edgerc_migration(
            "[prod-west]\nhost = example.luna.akamaiapis.net\nclient_token = tok\nclient_secret = sec\naccess_token = acc\n",
        )
        .unwrap_err();
        assert!(unsafe_section.contains("environment variable"));
    }

    #[test]
    fn does_not_migrate_secretless_edgerc() {
        let path = std::env::temp_dir().join(format!("akamai-edgerc-empty-{}", std::process::id()));
        fs::write(&path, "[default]\nhost = example\n").unwrap();
        let store = TestCredentialStore::default();

        assert!(!migrate_credentials_file(&path, &store).unwrap());
        assert!(store.values.borrow().is_empty());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn edgerc_path_prefers_env_and_requires_home() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let expected =
            std::env::temp_dir().join(format!("akamai-migrate-{}.edgerc", std::process::id()));
        let previous_home = std::env::var_os("HOME");
        let previous_edgerc = std::env::var_os("AKAMAI_EDGERC");

        unsafe {
            std::env::set_var("AKAMAI_EDGERC", &expected);
            std::env::remove_var("HOME");
        }
        assert_eq!(edgerc_path().unwrap(), expected);

        unsafe {
            std::env::remove_var("AKAMAI_EDGERC");
        }
        assert_eq!(edgerc_path().unwrap_err(), "HOME is not set");

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match previous_edgerc {
                Some(value) => std::env::set_var("AKAMAI_EDGERC", value),
                None => std::env::remove_var("AKAMAI_EDGERC"),
            }
        }
    }

    #[test]
    fn migrate_credentials_file_propagates_store_and_read_errors() {
        let temp =
            std::env::temp_dir().join(format!("akamai-migrate-errors-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();
        let secret_file = temp.join("secret.edgerc");
        fs::write(
            &secret_file,
            "[default]\nhost = example.luna.akamaiapis.net\nclient_token = tok\nclient_secret = sec\naccess_token = acc\n",
        )
        .unwrap();

        assert_eq!(
            migrate_credentials_file(&secret_file, &FailingStore).unwrap_err(),
            "store failed"
        );
        assert_eq!(
            migrate_credentials_file(&temp, &TestCredentialStore::default()).unwrap_err(),
            format!(
                "failed to read {}: Is a directory (os error 21)",
                temp.display()
            )
        );

        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn test_build_keychain_store_secret_is_stubbed() {
        assert_eq!(
            keychain_store_secret(KEYCHAIN_SERVICE, AKAMAI_ENV_ASSIGNMENTS_KEY, "value")
                .unwrap_err(),
            "Automic Vault secret storage is only available on macOS"
        );
    }
}
