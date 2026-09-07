#[cfg(all(target_os = "macos", not(test), not(coverage)))]
use std::ffi::{CString, c_char};
use std::fs;
use std::path::{Path, PathBuf};

const KEYCHAIN_SERVICE: &str = "com.automicvault.isotope";
const VTCLI_APIKEY_ENV_KEY: &str = "VTCLI_APIKEY";
const OFFICIAL_HOST: &str = "www.virustotal.com";
const VIPER_CONFIG_EXTENSIONS: &[&str] = &[
    "json",
    "toml",
    "yaml",
    "yml",
    "properties",
    "props",
    "prop",
    "hcl",
    "tfvars",
    "dotenv",
    "env",
    "ini",
];

pub trait CredentialStore {
    fn store_secret(&self, key: &str, value: &str) -> Result<(), String>;
}

pub struct KeychainCredentialStore;

pub fn keys() -> &'static [&'static str] {
    &[VTCLI_APIKEY_ENV_KEY]
}

pub fn migrate_credentials() -> Result<(), String> {
    migrate_config_file(&vt_config_path()?, &KeychainCredentialStore).map(|_| ())
}

pub fn migrate_config_file(path: &Path, store: &dyn CredentialStore) -> Result<bool, String> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };
    let Some(api_key) =
        toml_string_value_for_key(&contents, "apikey").filter(|value| !value.is_empty())
    else {
        return Ok(false);
    };

    store.store_secret(VTCLI_APIKEY_ENV_KEY, api_key)?;
    fs::write(path, remove_toml_key_lines(&contents, "apikey"))
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    Ok(true)
}

fn vt_config_path() -> Result<PathBuf, String> {
    Ok(user_home()?.join(".vt.toml"))
}

fn user_home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())
}

pub(super) fn default_config_is_safe_for_api_key() -> bool {
    let Ok(home) = user_home() else {
        return false;
    };
    let Ok(cwd) = std::env::current_dir() else {
        return false;
    };
    active_vt_config(&home, &cwd).is_none_or(|path| safe_vt_config(&path))
}

fn active_vt_config(home: &Path, cwd: &Path) -> Option<PathBuf> {
    [home, cwd].iter().find_map(|directory| {
        VIPER_CONFIG_EXTENSIONS.iter().find_map(|extension| {
            let path = directory.join(format!(".vt.{extension}"));
            fs::metadata(&path)
                .ok()
                .filter(|metadata| metadata.is_file())
                .map(|_| path)
        })
    })
}

fn safe_vt_config(path: &Path) -> bool {
    path.extension().and_then(|value| value.to_str()) == Some("toml")
        && fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
        && fs::read_to_string(path).is_ok_and(|contents| toml_config_is_safe_for_api_key(&contents))
}

fn toml_config_is_safe_for_api_key(contents: &str) -> bool {
    let Ok(config) = contents.parse::<toml::Table>() else {
        return false;
    };
    config.iter().all(|(key, value)| {
        if key.eq_ignore_ascii_case("apikey") {
            value.as_str() == Some("")
        } else if key.eq_ignore_ascii_case("host") {
            value
                .as_str()
                .is_some_and(|host| host.is_empty() || host.eq_ignore_ascii_case(OFFICIAL_HOST))
        } else {
            true
        }
    })
}

fn toml_string_value_for_key<'a>(contents: &'a str, key: &str) -> Option<&'a str> {
    contents.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let (line_key, value) = line.split_once('=')?;
        if line_key.trim() != key {
            return None;
        }
        toml_string_value(value)
    })
}

fn toml_string_value(value: &str) -> Option<&str> {
    value
        .trim()
        .strip_prefix('"')
        .and_then(|value| value.split_once('"').map(|(value, _)| value))
}

fn remove_toml_key_lines(contents: &str, key: &str) -> String {
    let mut output = String::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        let should_remove = !trimmed.starts_with('#')
            && trimmed
                .split_once('=')
                .is_some_and(|(line_key, _)| line_key.trim() == key);
        if should_remove {
            continue;
        }
        output.push_str(line);
        output.push('\n');
    }
    output
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
    fn migrates_api_key_and_preserves_other_config() {
        let path = std::env::temp_dir().join(format!("vt-config-{}", std::process::id()));
        fs::write(&path, "apikey=\"fake-vt-key\"\nproxy=\"http://proxy\"\n").unwrap();
        let store = TestCredentialStore::default();

        assert!(migrate_config_file(&path, &store).unwrap());

        assert_eq!(
            store.values.borrow().as_slice(),
            &[(VTCLI_APIKEY_ENV_KEY.to_string(), "fake-vt-key".to_string())]
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "proxy=\"http://proxy\"\n"
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn ignores_missing_or_empty_api_key() {
        let missing = std::env::temp_dir().join(format!("missing-vt-{}", std::process::id()));
        let empty = std::env::temp_dir().join(format!("empty-vt-{}", std::process::id()));
        fs::write(&empty, "apikey=\"\"\n").unwrap();
        let store = TestCredentialStore::default();

        assert!(!migrate_config_file(&missing, &store).unwrap());
        assert!(!migrate_config_file(&empty, &store).unwrap());
        assert!(store.values.borrow().is_empty());
        fs::remove_file(empty).unwrap();
    }

    #[test]
    fn migrate_config_file_propagates_store_and_read_errors() {
        let temp = std::env::temp_dir().join(format!("vt-migrate-errors-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();
        let config = temp.join(".vt.toml");
        fs::write(&config, "apikey=\"fake-vt-key\"\n").unwrap();

        assert_eq!(
            migrate_config_file(&config, &FailingStore).unwrap_err(),
            "store failed"
        );
        assert_eq!(
            migrate_config_file(&temp, &TestCredentialStore::default()).unwrap_err(),
            format!(
                "failed to read {}: Is a directory (os error 21)",
                temp.display()
            )
        );

        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn path_and_toml_helpers_cover_edge_cases() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let home = std::env::temp_dir().join(format!("vt-migrate-home-{}", std::process::id()));
        let previous_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", &home);
        }
        assert_eq!(vt_config_path().unwrap(), home.join(".vt.toml"));
        unsafe {
            std::env::remove_var("HOME");
        }
        assert_eq!(vt_config_path().unwrap_err(), "HOME is not set");
        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }

        assert_eq!(toml_string_value_for_key("apikey = 1\n", "apikey"), None);
        assert_eq!(
            remove_toml_key_lines("apikey=\"x\"\nproxy=\"http://proxy\"\n", "apikey"),
            "proxy=\"http://proxy\"\n"
        );
    }

    #[test]
    fn test_build_keychain_store_secret_is_stubbed() {
        assert_eq!(
            keychain_store_secret(KEYCHAIN_SERVICE, VTCLI_APIKEY_ENV_KEY, "value").unwrap_err(),
            "Automic Vault secret storage is only available on macOS"
        );
    }

    #[test]
    fn token_routing_requires_the_active_config_to_use_the_official_host() {
        let dir = std::env::temp_dir().join(format!("vt-config-safety-{}", std::process::id()));
        let home = dir.join("home");
        let cwd = dir.join("cwd");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&cwd).unwrap();

        assert!(active_vt_config(&home, &cwd).is_none());
        fs::write(home.join(".vt.toml"), "host=\"www.virustotal.com\"\n").unwrap();
        assert!(safe_vt_config(&active_vt_config(&home, &cwd).unwrap()));

        fs::write(home.join(".vt.toml"), "host=\"evil.example\"\n").unwrap();
        assert!(!safe_vt_config(&active_vt_config(&home, &cwd).unwrap()));
        fs::write(home.join(".vt.toml"), "apikey=\"caller-key\"\n").unwrap();
        assert!(!safe_vt_config(&active_vt_config(&home, &cwd).unwrap()));
        fs::write(home.join(".vt.toml"), "apikey=\"\"\n").unwrap();
        assert!(safe_vt_config(&active_vt_config(&home, &cwd).unwrap()));
        fs::write(home.join(".vt.toml"), "\"host\"=\"evil.example\"\n").unwrap();
        assert!(!safe_vt_config(&active_vt_config(&home, &cwd).unwrap()));
        fs::write(home.join(".vt.toml"), "host=[\n").unwrap();
        assert!(!safe_vt_config(&active_vt_config(&home, &cwd).unwrap()));

        fs::write(home.join(".vt.toml"), "host=\"www.virustotal.com\"\n").unwrap();
        fs::write(home.join(".vt.json"), "{}\n").unwrap();
        assert_eq!(active_vt_config(&home, &cwd), Some(home.join(".vt.json")));
        assert!(!safe_vt_config(&active_vt_config(&home, &cwd).unwrap()));

        fs::remove_file(home.join(".vt.json")).unwrap();
        fs::remove_file(home.join(".vt.toml")).unwrap();
        fs::write(cwd.join(".vt.toml"), "host=\"www.virustotal.com\"\n").unwrap();
        assert!(safe_vt_config(&active_vt_config(&home, &cwd).unwrap()));

        fs::remove_dir_all(dir).unwrap();
    }
}
