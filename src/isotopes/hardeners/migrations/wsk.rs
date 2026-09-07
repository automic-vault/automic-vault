#[cfg(all(target_os = "macos", not(test), not(coverage)))]
use std::ffi::{CString, c_char};
use std::fs;
use std::path::{Path, PathBuf};

const KEYCHAIN_SERVICE: &str = "com.automicvault.isotope";
const WHISK_AUTH_ENV_KEY: &str = "WHISK_AUTH";

pub trait CredentialStore {
    fn store_secret(&self, key: &str, value: &str) -> Result<(), String>;
}

pub struct KeychainCredentialStore;

pub fn keys() -> &'static [&'static str] {
    &[WHISK_AUTH_ENV_KEY]
}

pub fn migrate_credentials() -> Result<(), String> {
    migrate_props_file(&wsk_props_path()?, &KeychainCredentialStore).map(|_| ())
}

pub fn migrate_props_file(path: &Path, store: &dyn CredentialStore) -> Result<bool, String> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };
    let Some(migration) = wsk_props_migration(&contents) else {
        return Ok(false);
    };

    store.store_secret(WHISK_AUTH_ENV_KEY, &migration.auth)?;
    fs::write(path, migration.rewritten)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    Ok(true)
}

#[derive(Debug)]
struct WskPropsMigration {
    auth: String,
    rewritten: String,
}

fn wsk_props_migration(contents: &str) -> Option<WskPropsMigration> {
    let mut auth = None;
    let mut rewritten = String::new();
    let mut changed = false;

    for line in contents.lines() {
        if let Some(value) = parse_auth_line(line) {
            auth = Some(value);
            changed = true;
            continue;
        }
        push_line(&mut rewritten, line);
    }

    if !changed {
        return None;
    }

    Some(WskPropsMigration {
        auth: auth.expect("changed OpenWhisk props without auth"),
        rewritten,
    })
}

fn wsk_props_path() -> Result<PathBuf, String> {
    Ok(user_home()?.join(".wskprops"))
}

pub(super) fn selected_props_have_auth() -> bool {
    let path = match std::env::var_os("WSK_CONFIG_FILE") {
        Some(path) => PathBuf::from(path),
        None => match wsk_props_path() {
            Ok(path) => path,
            Err(_) => return false,
        },
    };
    fs::read_to_string(path)
        .is_ok_and(|contents| contents.lines().any(|line| parse_auth_line(line).is_some()))
}

fn user_home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())
}

fn parse_auth_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let (key, value) = trimmed.split_once('=')?;
    if key.trim() != "AUTH" {
        return None;
    }

    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn push_line(output: &mut String, line: &str) {
    output.push_str(line);
    output.push('\n');
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
    fn keys_include_whisk_auth() {
        assert_eq!(keys(), &[WHISK_AUTH_ENV_KEY]);
    }

    #[test]
    fn migration_removes_auth_and_preserves_other_properties() {
        let migration = wsk_props_migration(
            "APIHOST=https://openwhisk.example\nAUTH=fake-uuid:fake-secret\nNAMESPACE=demo\n",
        )
        .unwrap();

        assert_eq!(migration.auth, "fake-uuid:fake-secret");
        assert_eq!(
            migration.rewritten,
            "APIHOST=https://openwhisk.example\nNAMESPACE=demo\n"
        );
    }

    #[test]
    fn migrates_props_file() {
        let path = std::env::temp_dir().join(format!("wskprops-{}", std::process::id()));
        fs::write(
            &path,
            "APIHOST=https://openwhisk.example\nAUTH=fake-uuid:fake-secret\n",
        )
        .unwrap();
        let store = TestCredentialStore::default();

        assert!(migrate_props_file(&path, &store).unwrap());

        assert_eq!(
            store.values.borrow().as_slice(),
            &[(
                WHISK_AUTH_ENV_KEY.to_string(),
                "fake-uuid:fake-secret".to_string()
            )]
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "APIHOST=https://openwhisk.example\n"
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn does_not_migrate_missing_or_empty_auth() {
        let missing = std::env::temp_dir().join(format!("missing-wskprops-{}", std::process::id()));
        let empty = std::env::temp_dir().join(format!("empty-wskprops-{}", std::process::id()));
        fs::write(&empty, "AUTH=\nAPIHOST=https://openwhisk.example\n").unwrap();
        let store = TestCredentialStore::default();

        assert!(!migrate_props_file(&missing, &store).unwrap());
        assert!(!migrate_props_file(&empty, &store).unwrap());
        assert!(store.values.borrow().is_empty());
        fs::remove_file(empty).unwrap();
    }

    #[test]
    fn migrate_props_file_propagates_store_and_read_errors() {
        let temp = std::env::temp_dir().join(format!("wsk-migrate-errors-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();
        let path = temp.join(".wskprops");
        fs::write(&path, "AUTH=fake-uuid:fake-secret\n").unwrap();

        assert_eq!(
            migrate_props_file(&path, &FailingStore).unwrap_err(),
            "store failed"
        );
        assert_eq!(
            migrate_props_file(&temp, &TestCredentialStore::default()).unwrap_err(),
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
        let home = std::env::temp_dir().join(format!("wsk-migrate-home-{}", std::process::id()));
        let previous_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", &home);
        }
        assert_eq!(wsk_props_path().unwrap(), home.join(".wskprops"));
        unsafe {
            std::env::remove_var("HOME");
        }
        assert_eq!(wsk_props_path().unwrap_err(), "HOME is not set");
        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }

        assert_eq!(
            keychain_store_secret(KEYCHAIN_SERVICE, WHISK_AUTH_ENV_KEY, "value").unwrap_err(),
            "Automic Vault secret storage is only available on macOS"
        );
    }

    #[test]
    fn token_routing_honors_only_the_selected_properties_file() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let home = std::env::temp_dir().join(format!("wsk-routing-{}", std::process::id()));
        let default = home.join(".wskprops");
        let selected = home.join("selected.wskprops");
        let previous_home = std::env::var_os("HOME");
        let previous_config = std::env::var_os("WSK_CONFIG_FILE");
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::remove_var("WSK_CONFIG_FILE");
        }

        assert!(!selected_props_have_auth());
        fs::write(&default, "AUTH=caller-default\n").unwrap();
        assert!(selected_props_have_auth());
        fs::write(&selected, "APIHOST=https://openwhisk.example\n").unwrap();
        unsafe { std::env::set_var("WSK_CONFIG_FILE", &selected) };
        assert!(!selected_props_have_auth());
        fs::write(&selected, "AUTH=caller-selected\n").unwrap();
        assert!(selected_props_have_auth());

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match previous_config {
                Some(value) => std::env::set_var("WSK_CONFIG_FILE", value),
                None => std::env::remove_var("WSK_CONFIG_FILE"),
            }
        }
        fs::remove_dir_all(home).unwrap();
    }
}
