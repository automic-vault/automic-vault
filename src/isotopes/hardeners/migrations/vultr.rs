#[cfg(all(target_os = "macos", not(test), not(coverage)))]
use std::ffi::{CString, c_char};
use std::fs;
use std::path::{Path, PathBuf};

const KEYCHAIN_SERVICE: &str = "com.automicvault.isotope";
const VULTR_API_KEY_ENV_KEY: &str = "VULTR_API_KEY";

pub trait CredentialStore {
    fn store_secret(&self, key: &str, value: &str) -> Result<(), String>;
}

pub struct KeychainCredentialStore;

pub fn keys() -> &'static [&'static str] {
    &[VULTR_API_KEY_ENV_KEY]
}

pub fn migrate_credentials() -> Result<(), String> {
    let store = KeychainCredentialStore;
    for path in vultr_config_paths()? {
        if migrate_credentials_file(&path, &store)? {
            return Ok(());
        }
    }
    Ok(())
}

pub fn migrate_credentials_file(path: &Path, store: &dyn CredentialStore) -> Result<bool, String> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };

    let Some(api_key) = config_api_key(&contents) else {
        return Ok(false);
    };

    store.store_secret(VULTR_API_KEY_ENV_KEY, &api_key)?;
    fs::write(path, remove_api_key(&contents))
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    Ok(true)
}

fn vultr_config_paths() -> Result<Vec<PathBuf>, String> {
    let home = user_home()?;
    Ok(vec![
        home.join("Library/Application Support/vultr-cli.yaml"),
        home.join(".vultr-cli.yaml"),
    ])
}

fn user_home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())
}

pub(super) fn config_has_api_key(path: Option<&Path>) -> bool {
    let path = match path {
        Some(path) => path.to_path_buf(),
        None => {
            let Ok(paths) = vultr_config_paths() else {
                return false;
            };
            if fs::metadata(&paths[0]).is_ok() {
                paths[0].clone()
            } else {
                paths[1].clone()
            }
        }
    };
    fs::read_to_string(path).is_ok_and(|contents| config_contains_api_key(&contents))
}

fn config_api_key(contents: &str) -> Option<String> {
    contents.lines().find_map(line_api_key)
}

fn line_api_key(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (key, value) = line.split_once(':')?;
    if key.trim() != "api-key" {
        return None;
    }
    let value = yaml_scalar_value(value)?;
    if value.is_empty() {
        return None;
    }
    Some(value.to_string())
}

fn config_contains_api_key(contents: &str) -> bool {
    config_api_key(contents).is_some()
}

fn line_has_api_key(line: &str) -> bool {
    line_api_key(line).is_some()
}

fn remove_api_key(contents: &str) -> String {
    let mut output = String::new();
    for line in contents.lines() {
        if line_api_key(line).is_some() {
            continue;
        }
        output.push_str(line);
        output.push('\n');
    }
    output
}

fn yaml_scalar_value(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.trim_matches('"').trim_matches('\'').trim())
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
    fn migrates_vultr_api_key() {
        let path = std::env::temp_dir().join(format!("vultr-config-{}", std::process::id()));
        let contents = "api-key: fake-vultr-key\noutput: json\n";
        fs::write(&path, contents).unwrap();
        let store = TestCredentialStore::default();

        assert!(migrate_credentials_file(&path, &store).unwrap());

        assert_eq!(
            store.values.borrow().as_slice(),
            &[(
                VULTR_API_KEY_ENV_KEY.to_string(),
                "fake-vultr-key".to_string()
            )]
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "output: json\n");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn does_not_migrate_without_api_key() {
        let path = std::env::temp_dir().join(format!("vultr-no-key-{}", std::process::id()));
        fs::write(&path, "output: json\n").unwrap();
        let store = TestCredentialStore::default();

        assert!(!migrate_credentials_file(&path, &store).unwrap());
        assert!(store.values.borrow().is_empty());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn top_level_migrate_credentials_ignores_missing_default_locations() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
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

    #[test]
    fn migrate_credentials_file_propagates_store_and_read_errors() {
        let temp =
            std::env::temp_dir().join(format!("vultr-migrate-errors-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();
        let config = temp.join("vultr-cli.yaml");
        fs::write(&config, "api-key: fake-vultr-key\n").unwrap();

        assert_eq!(
            migrate_credentials_file(&config, &FailingStore).unwrap_err(),
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
    fn path_and_keychain_helpers_cover_edge_cases() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let home = std::env::temp_dir().join(format!("vultr-migrate-home-{}", std::process::id()));
        let previous_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", &home);
        }
        let paths = vultr_config_paths().unwrap();
        assert_eq!(
            paths[0],
            home.join("Library/Application Support/vultr-cli.yaml")
        );
        assert_eq!(paths[1], home.join(".vultr-cli.yaml"));
        unsafe {
            std::env::remove_var("HOME");
        }
        assert_eq!(vultr_config_paths().unwrap_err(), "HOME is not set");
        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }

        assert_eq!(
            keychain_store_secret(KEYCHAIN_SERVICE, VULTR_API_KEY_ENV_KEY, "value").unwrap_err(),
            "Automic Vault secret storage is only available on macOS"
        );
    }

    #[test]
    fn token_routing_honors_the_selected_caller_config() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let home = std::env::temp_dir().join(format!("vultr-routing-{}", std::process::id()));
        let app_support = home.join("Library/Application Support/vultr-cli.yaml");
        let legacy = home.join(".vultr-cli.yaml");
        let explicit = home.join("explicit.yaml");
        let previous_home = std::env::var_os("HOME");
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(app_support.parent().unwrap()).unwrap();
        unsafe { std::env::set_var("HOME", &home) };

        assert!(!config_has_api_key(None));
        fs::write(&legacy, "api-key: caller-key\n").unwrap();
        assert!(config_has_api_key(None));
        fs::write(&app_support, "output: json\n").unwrap();
        assert!(!config_has_api_key(None));
        fs::write(&app_support, "api-key: app-support-key\n").unwrap();
        assert!(config_has_api_key(None));
        fs::write(&explicit, "api-key: explicit-key\n").unwrap();
        assert!(config_has_api_key(Some(&explicit)));

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
        fs::remove_dir_all(home).unwrap();
    }
}
