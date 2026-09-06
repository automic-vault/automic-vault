#![allow(dead_code)]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

pub fn install_is_insecure() -> Result<bool, String> {
    install_insecurity_reasons().map(|reasons| !reasons.is_empty())
}

pub fn install_insecurity_reasons() -> Result<Vec<String>, String> {
    let cockpit = cockpit_credentials_path()?;
    Ok(cockpit_insecurity_reasons_for(&cockpit))
}

fn cockpit_insecurity_reasons_for(path: &Path) -> Vec<String> {
    match path.try_exists() {
        Ok(false) => return Vec::new(),
        Ok(true) => match std::fs::read_to_string(path) {
            Ok(contents) => match cockpit_file_has_credentials(&contents) {
                Ok(true) => vec![format!(
                    "Antigravity Cockpit credentials contain plaintext tokens: {}",
                    path.display()
                )],
                Ok(false) => Vec::new(),
                Err(_) => vec![format!(
                    "Antigravity Cockpit credentials could not be parsed and may contain plaintext credentials: {}",
                    path.display()
                )],
            },
            Err(_) => vec![format!(
                "Antigravity Cockpit credentials could not be read and may contain plaintext credentials: {}",
                path.display()
            )],
        },
        Err(_) => vec![format!(
            "Antigravity Cockpit credentials could not be read and may contain plaintext credentials: {}",
            path.display()
        )],
    }
}

pub(crate) fn cockpit_credentials_path() -> Result<PathBuf, String> {
    cockpit_credentials_path_in(std::env::var_os("HOME").as_deref())
}

fn cockpit_credentials_path_in(home: Option<&OsStr>) -> Result<PathBuf, String> {
    home.filter(|value| !value.is_empty())
        .map(|home| PathBuf::from(home).join(".antigravity_cockpit/credentials.json"))
        .ok_or_else(|| "HOME is not set".to_string())
}

fn cockpit_file_has_credentials(contents: &str) -> Result<bool, String> {
    let value: serde_json::Value = serde_json::from_str(contents)
        .map_err(|err| format!("failed to parse Antigravity Cockpit JSON: {err}"))?;
    let Some(object) = value.as_object() else {
        return Ok(false);
    };

    if let Some(accounts) = object.get("accounts") {
        if let Some(accounts_obj) = accounts.as_object() {
            for account in accounts_obj.values() {
                if account_has_tokens(account) {
                    return Ok(true);
                }
            }
        } else if let Some(accounts_arr) = accounts.as_array() {
            for account in accounts_arr {
                if account_has_tokens(account) {
                    return Ok(true);
                }
            }
        }
    }

    if account_has_tokens(&value) {
        return Ok(true);
    }

    Ok(false)
}

fn account_has_tokens(value: &serde_json::Value) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };
    [
        "accessToken",
        "refreshToken",
        "access_token",
        "refresh_token",
        "token",
        "id_token",
    ]
    .iter()
    .any(|field| is_nonempty_string(obj.get(*field)))
}

fn is_nonempty_string(value: Option<&serde_json::Value>) -> bool {
    value
        .and_then(serde_json::Value::as_str)
        .is_some_and(|text| !text.trim().is_empty())
}

pub(crate) fn findings(home: &std::path::Path) -> Vec<crate::Finding> {
    super::radioisotope::findings("antigravity-cockpit", install_insecurity_reasons, home)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "{}-{label}-{}",
            module_path!().replace(':', "_"),
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn detects_cockpit_credentials() {
        let contents = r#"{
            "accounts": {
                "dev@example.com": {
                    "email": "dev@example.com",
                    "accessToken": "ya29.sample-token",
                    "refreshToken": "1//sample-refresh",
                    "expiresAt": "2026-09-06T00:00:00.000Z",
                    "projectId": "sample-project"
                }
            }
        }"#;
        assert!(cockpit_file_has_credentials(contents).unwrap());
    }

    #[test]
    fn detects_cockpit_credentials_with_multiple_accounts() {
        let contents = r#"{
            "accounts": {
                "empty@example.com": {
                    "email": "empty@example.com",
                    "accessToken": "",
                    "refreshToken": ""
                },
                "active@example.com": {
                    "email": "active@example.com",
                    "accessToken": "ya29.sample-token",
                    "refreshToken": "1//sample-refresh"
                }
            }
        }"#;
        assert!(cockpit_file_has_credentials(contents).unwrap());
    }

    #[test]
    fn detects_cockpit_credentials_with_array_of_accounts() {
        let contents = r#"{
            "accounts": [
                {
                    "email": "user@example.com",
                    "accessToken": "ya29.sample-token",
                    "refreshToken": "1//sample-refresh"
                }
            ]
        }"#;
        assert!(cockpit_file_has_credentials(contents).unwrap());
    }

    #[test]
    fn detects_cockpit_single_account_credentials() {
        let contents = r#"{
            "accessToken": "ya29.sample-token",
            "refreshToken": "1//sample-refresh"
        }"#;
        assert!(cockpit_file_has_credentials(contents).unwrap());
    }

    #[test]
    fn ignores_empty_cockpit_credentials() {
        assert!(!cockpit_file_has_credentials("{}").unwrap());
        assert!(!cockpit_file_has_credentials(r#"{"accounts": {}}"#).unwrap());
        let contents = r#"{
            "accounts": {
                "user@example.com": {
                    "email": "user@example.com",
                    "accessToken": "",
                    "refreshToken": "   "
                }
            }
        }"#;
        assert!(!cockpit_file_has_credentials(contents).unwrap());
    }

    #[test]
    fn reports_cockpit_file_holding_secrets() {
        let dir = temporary_directory("cockpit-creds");
        let path = dir.join("credentials.json");
        std::fs::write(
            &path,
            r#"{"accounts":{"user@example.com":{"refreshToken":"1//live-refresh-token"}}}"#,
        )
        .unwrap();

        let reasons = cockpit_insecurity_reasons_for(&path);
        assert_eq!(reasons.len(), 1);
        assert!(
            reasons[0].starts_with("Antigravity Cockpit credentials contain plaintext tokens: ")
        );
        assert!(reasons[0].ends_with(&path.display().to_string()));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reports_unparseable_files() {
        let dir = temporary_directory("unparseable");
        let cockpit_path = dir.join("credentials.json");
        std::fs::write(&cockpit_path, "not json").unwrap();

        let cockpit_reasons = cockpit_insecurity_reasons_for(&cockpit_path);
        assert_eq!(cockpit_reasons.len(), 1);
        assert!(cockpit_reasons[0].contains("could not be parsed"));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reports_unreadable_files() {
        let dir = temporary_directory("unreadable");
        let cockpit_path = dir.join("credentials.json");
        std::fs::create_dir(&cockpit_path).unwrap();

        let cockpit_reasons = cockpit_insecurity_reasons_for(&cockpit_path);
        assert_eq!(cockpit_reasons.len(), 1);
        assert!(cockpit_reasons[0].contains("could not be read"));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn reports_when_parent_directory_is_unsearchable() {
        use std::os::unix::fs::PermissionsExt;

        let directory = temporary_directory("unsearchable-parent");
        let cockpit_dir = directory.join(".antigravity_cockpit");
        std::fs::create_dir_all(&cockpit_dir).unwrap();
        let path = cockpit_dir.join("credentials.json");
        std::fs::write(&path, r#"{"accessToken":"sample"}"#).unwrap();

        let original_perms = std::fs::metadata(&cockpit_dir).unwrap().permissions();
        std::fs::set_permissions(&cockpit_dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let reasons = cockpit_insecurity_reasons_for(&path);

        let _ = std::fs::set_permissions(&cockpit_dir, original_perms);
        let _ = std::fs::remove_dir_all(&directory);

        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains("could not be read"));
        assert!(reasons[0].ends_with(&path.display().to_string()));
    }

    #[test]
    fn scan_discovers_cockpit_credential_file() {
        let home = temporary_directory("scan-cockpit");
        let cockpit_dir = home.join(".antigravity_cockpit");
        std::fs::create_dir_all(&cockpit_dir).unwrap();
        std::fs::write(
            cockpit_dir.join("credentials.json"),
            r#"{"accounts":{"u":{"accessToken":"ya29.sample","refreshToken":"1//sample"}}}"#,
        )
        .unwrap();

        let findings = findings(&home);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source, "antigravity-cockpit");
        assert_eq!(findings[0].affected.len(), 1);
        assert_eq!(
            findings[0].affected[0].path,
            cockpit_dir.join("credentials.json").display().to_string()
        );

        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn scan_stays_quiet_without_credential_files() {
        let home = temporary_directory("scan-missing");
        assert!(findings(&home).is_empty());
        std::fs::remove_dir_all(home).unwrap();
    }
}
