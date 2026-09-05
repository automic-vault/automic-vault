#[cfg(all(target_os = "macos", not(test), not(coverage)))]
use std::ffi::{CString, c_char};
use std::fs;
use std::path::{Path, PathBuf};

const KEYCHAIN_SERVICE: &str = "com.automicvault.isotope";
const TRAVIS_TOKEN_ENV_KEY: &str = "TRAVIS_TOKEN";
const TRAVIS_COM_ENDPOINT: &str = "https://api.travis-ci.com/";

pub trait CredentialStore {
    fn store_secret(&self, key: &str, value: &str) -> Result<(), String>;
}

pub struct KeychainCredentialStore;

pub fn keys() -> &'static [&'static str] {
    &[TRAVIS_TOKEN_ENV_KEY]
}

pub fn migrate_credentials() -> Result<(), String> {
    migrate_credentials_file(&travis_config_path()?, &KeychainCredentialStore).map(|_| ())
}

pub fn migrate_credentials_file(path: &Path, store: &dyn CredentialStore) -> Result<bool, String> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };

    let tokens = config_access_tokens(&contents);
    if tokens.len() > 1 {
        return Err("multiple Travis access tokens found; migrate them manually".to_string());
    }
    let (guarded, has_endpoints) = guard_token_storage(&contents);
    if !config_access_tokens(&guarded).is_empty() {
        return Err("Travis access token is outside the supported endpoints config".to_string());
    }
    if tokens.is_empty() {
        if !has_endpoints || guarded == contents {
            return Ok(false);
        }
        fs::write(path, guarded)
            .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
        return Ok(true);
    }

    store.store_secret(TRAVIS_TOKEN_ENV_KEY, &tokens[0])?;
    fs::write(path, guarded).map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    Ok(true)
}

pub(super) fn default_config_is_safe_for_token() -> bool {
    uses_default_config_path()
        && travis_config_path()
            .ok()
            .and_then(|path| fs::read_to_string(path).ok())
            .is_some_and(|contents| {
                let (guarded, has_endpoints) = guard_token_storage(&contents);
                has_endpoints && guarded == contents && config_uses_official_authority(&contents)
            })
}

fn uses_default_config_path() -> bool {
    std::env::var_os("TRAVIS_CONFIG_PATH").is_none_or(|value| value.is_empty())
}

fn travis_config_path() -> Result<PathBuf, String> {
    let home = user_home()?;
    Ok(home.join(".travis/config.yml"))
}

fn user_home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())
}

fn config_contains_access_token(contents: &str) -> bool {
    !config_access_tokens(contents).is_empty()
}

fn config_access_tokens(contents: &str) -> Vec<String> {
    contents.lines().filter_map(line_access_token).collect()
}

fn line_access_token(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (key, value) = line.split_once(':')?;
    if key.trim() != "access_token" {
        return None;
    }
    let value = yaml_scalar_value(value)?;
    if value.is_empty() {
        return None;
    }
    Some(value.to_string())
}

fn line_is_access_token(line: &str) -> bool {
    line.trim()
        .split_once(':')
        .is_some_and(|(key, _)| key.trim() == "access_token")
}

fn yaml_scalar_value(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.trim_matches('"').trim_matches('\'').trim())
}

fn guard_token_storage(contents: &str) -> (String, bool) {
    let mut output = String::new();
    let mut in_endpoints = false;
    let mut active_endpoint = false;
    let mut endpoint_guarded = false;
    let mut has_endpoints = false;

    for line in contents.lines() {
        let trimmed = line.trim();
        let indentation = line.len() - line.trim_start_matches(' ').len();
        let structural = !trimmed.is_empty() && !trimmed.starts_with('#');

        if in_endpoints && structural && indentation == 2 && trimmed.ends_with(':') {
            if active_endpoint && !endpoint_guarded {
                output.push_str("    access_token: ''\n");
            }
            active_endpoint = true;
            endpoint_guarded = false;
            has_endpoints = true;
        } else if in_endpoints && structural && indentation == 0 {
            if active_endpoint && !endpoint_guarded {
                output.push_str("    access_token: ''\n");
            }
            in_endpoints = false;
            active_endpoint = false;
        } else if in_endpoints && active_endpoint && line_is_access_token(line) {
            output.push_str(&" ".repeat(indentation));
            output.push_str("access_token: ''\n");
            endpoint_guarded = true;
            continue;
        }

        output.push_str(line);
        output.push('\n');
        if !in_endpoints && indentation == 0 && trimmed == "endpoints:" {
            in_endpoints = true;
        }
    }
    if in_endpoints && active_endpoint && !endpoint_guarded {
        output.push_str("    access_token: ''\n");
    }
    if !contents.ends_with('\n') {
        output.pop();
    }
    (output, has_endpoints)
}

fn config_uses_official_authority(contents: &str) -> bool {
    let mut in_endpoints = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indentation = line.len() - line.trim_start_matches(' ').len();
        if indentation == 0 {
            in_endpoints = trimmed == "endpoints:";
        }
        if in_endpoints && indentation == 2 && trimmed.ends_with(':') {
            if trimmed.trim_end_matches(':').trim_matches(['\'', '"']) != TRAVIS_COM_ENDPOINT {
                return false;
            }
            continue;
        }
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = yaml_scalar_value(value).unwrap_or_default();
        if key == "enterprise"
            || key == "insecure" && !matches!(value, "" | "false")
            || matches!(key, "default_endpoint" | "endpoint") && value != TRAVIS_COM_ENDPOINT
        {
            return false;
        }
    }
    true
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

    #[derive(Default)]
    struct TestCredentialStore {
        values: RefCell<Vec<(String, String)>>,
    }

    impl CredentialStore for TestCredentialStore {
        fn store_secret(&self, key: &str, value: &str) -> Result<(), String> {
            self.values
                .borrow_mut()
                .push((key.to_string(), value.to_string()));
            Ok(())
        }
    }

    #[test]
    fn migrates_single_travis_token() {
        let path = std::env::temp_dir().join(format!("travis-config-{}", std::process::id()));
        let contents = concat!(
            "endpoints:\n",
            "  https://api.travis-ci.com/:\n",
            "    access_token: fake-travis-token\n",
            "    insecure: false\n",
        );
        fs::write(&path, contents).unwrap();
        let store = TestCredentialStore::default();

        assert!(migrate_credentials_file(&path, &store).unwrap());

        assert_eq!(
            store.values.borrow().as_slice(),
            &[(
                TRAVIS_TOKEN_ENV_KEY.to_string(),
                "fake-travis-token".to_string()
            )]
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "endpoints:\n  https://api.travis-ci.com/:\n    access_token: ''\n    insecure: false\n"
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn refuses_multiple_travis_tokens() {
        let path =
            std::env::temp_dir().join(format!("travis-multiple-tokens-{}", std::process::id()));
        let contents = concat!(
            "endpoints:\n",
            "  https://api.travis-ci.com/:\n",
            "    access_token: one\n",
            "  https://api.travis-ci.org/:\n",
            "    access_token: two\n",
        );
        fs::write(&path, contents).unwrap();
        let store = TestCredentialStore::default();

        assert_eq!(
            migrate_credentials_file(&path, &store).unwrap_err(),
            "multiple Travis access tokens found; migrate them manually"
        );
        assert!(store.values.borrow().is_empty());
        assert_eq!(fs::read_to_string(&path).unwrap(), contents);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn does_not_migrate_without_access_token() {
        let path = std::env::temp_dir().join(format!("travis-no-token-{}", std::process::id()));
        fs::write(&path, "endpoints: {}\n").unwrap();
        let store = TestCredentialStore::default();

        assert!(!migrate_credentials_file(&path, &store).unwrap());
        assert!(store.values.borrow().is_empty());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn guards_every_endpoint_without_storing_a_secret() {
        let path = std::env::temp_dir().join(format!("travis-guard-{}", std::process::id()));
        fs::write(
            &path,
            "endpoints:\n  https://one.example/:\n    insecure: false\n  https://two.example/:\n    enterprise: true\nrepos: {}\n",
        )
        .unwrap();
        let store = TestCredentialStore::default();

        assert!(migrate_credentials_file(&path, &store).unwrap());
        assert!(store.values.borrow().is_empty());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "endpoints:\n  https://one.example/:\n    insecure: false\n    access_token: ''\n  https://two.example/:\n    enterprise: true\n    access_token: ''\nrepos: {}\n"
        );
        assert!(!migrate_credentials_file(&path, &store).unwrap());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn only_the_guarded_official_config_is_safe_for_token_routing() {
        let official = "endpoints:\n  https://api.travis-ci.com/:\n    access_token: ''\n";
        let (guarded, has_endpoints) = guard_token_storage(official);
        assert!(has_endpoints);
        assert_eq!(guarded, official);
        assert!(config_uses_official_authority(official));

        assert!(!config_uses_official_authority(
            "default_endpoint: https://enterprise.example/api\nendpoints:\n  https://api.travis-ci.com/:\n    access_token: ''\n"
        ));
        assert!(!config_uses_official_authority(
            "endpoints:\n  https://enterprise.example/api:\n    access_token: ''\n"
        ));
        assert!(!config_uses_official_authority(
            "endpoints:\n  https://api.travis-ci.com/:\n    access_token: ''\nrepos:\n  owner/repo:\n    endpoint: https://enterprise.example/api\n"
        ));
        assert!(!config_uses_official_authority(
            "endpoints:\n  https://api.travis-ci.com/:\n    access_token: ''\nenterprise: {}\n"
        ));
        assert!(!config_uses_official_authority(
            "endpoints:\n  https://api.travis-ci.com/:\n    access_token: ''\n    insecure: true\n"
        ));
    }

    #[test]
    fn top_level_migrate_credentials_ignores_missing_default_location() {
        let home = std::env::temp_dir().join(format!(
            "{}-migrate-missing-{}",
            module_path!().replace(':', "_"),
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();

        let previous_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", &home);
        }

        migrate_credentials().unwrap();

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }

        std::fs::remove_dir_all(home).unwrap();
    }
}
