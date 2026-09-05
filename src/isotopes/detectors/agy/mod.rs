#![allow(dead_code)]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

pub fn install_is_insecure() -> Result<bool, String> {
    install_insecurity_reasons().map(|reasons| !reasons.is_empty())
}

pub fn install_insecurity_reasons() -> Result<Vec<String>, String> {
    let oauth = oauth_path()?;
    Ok(oauth_insecurity_reasons_for(&oauth))
}

fn oauth_insecurity_reasons_for(path: &Path) -> Vec<String> {
    if !path.exists() {
        return Vec::new();
    }
    match std::fs::read_to_string(path) {
        Ok(contents) => match oauth_file_has_credentials(&contents) {
            Ok(true) => vec![format!(
                "agy OAuth credentials contain plaintext tokens: {}",
                path.display()
            )],
            Ok(false) => Vec::new(),
            Err(_) => vec![format!(
                "agy OAuth credentials could not be parsed and may contain plaintext credentials: {}",
                path.display()
            )],
        },
        Err(_) => vec![format!(
            "agy OAuth credentials could not be read and may contain plaintext credentials: {}",
            path.display()
        )],
    }
}

pub(crate) fn oauth_path() -> Result<PathBuf, String> {
    oauth_path_in(std::env::var_os("HOME").as_deref())
}

fn oauth_path_in(home: Option<&OsStr>) -> Result<PathBuf, String> {
    home.filter(|value| !value.is_empty())
        .map(|home| PathBuf::from(home).join(".gemini/oauth_creds.json"))
        .ok_or_else(|| "HOME is not set".to_string())
}

fn oauth_file_has_credentials(contents: &str) -> Result<bool, String> {
    let value: serde_json::Value = serde_json::from_str(contents)
        .map_err(|err| format!("failed to parse agy OAuth JSON: {err}"))?;
    let Some(object) = value.as_object() else {
        return Ok(false);
    };

    if ["access_token", "refresh_token", "id_token", "token"]
        .iter()
        .any(|field| is_nonempty_string(object.get(*field)))
    {
        return Ok(true);
    }

    if let Some(tokens) = object.get("tokens").and_then(serde_json::Value::as_object)
        && ["access_token", "refresh_token", "id_token", "token"]
            .iter()
            .any(|field| is_nonempty_string(tokens.get(*field)))
    {
        return Ok(true);
    }

    Ok(false)
}

fn is_nonempty_string(value: Option<&serde_json::Value>) -> bool {
    value
        .and_then(serde_json::Value::as_str)
        .is_some_and(|text| !text.trim().is_empty())
}

pub(crate) fn findings(home: &std::path::Path) -> Vec<crate::Finding> {
    super::radioisotope::findings("agy", install_insecurity_reasons, home)
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
    fn detects_oauth_credentials() {
        let contents = r#"{
            "access_token": "ya29.sample-token",
            "refresh_token": "1//sample-refresh",
            "scope": "openid email",
            "token_type": "Bearer",
            "id_token": "eyJsample",
            "expiry_date": 1234567890
        }"#;
        assert!(oauth_file_has_credentials(contents).unwrap());
    }

    #[test]
    fn detects_oauth_credentials_with_only_refresh_token() {
        let contents = r#"{"refresh_token": "1//sample-refresh"}"#;
        assert!(oauth_file_has_credentials(contents).unwrap());
    }

    #[test]
    fn detects_oauth_credentials_with_only_access_token() {
        let contents = r#"{"access_token": "ya29.sample-token"}"#;
        assert!(oauth_file_has_credentials(contents).unwrap());
    }

    #[test]
    fn detects_oauth_credentials_with_only_id_token() {
        let contents = r#"{"id_token": "eyJsample"}"#;
        assert!(oauth_file_has_credentials(contents).unwrap());
    }

    #[test]
    fn ignores_empty_oauth_credentials() {
        assert!(!oauth_file_has_credentials("{}").unwrap());
        let contents = r#"{
            "access_token": "",
            "refresh_token": "   ",
            "id_token": null,
            "expiry_date": 0
        }"#;
        assert!(!oauth_file_has_credentials(contents).unwrap());
    }

    #[test]
    fn reports_oauth_file_holding_secrets() {
        let dir = temporary_directory("oauth-creds");
        let path = dir.join("oauth_creds.json");
        std::fs::write(&path, r#"{"refresh_token":"1//live-refresh-token"}"#).unwrap();

        let reasons = oauth_insecurity_reasons_for(&path);
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].starts_with("agy OAuth credentials contain plaintext tokens: "));
        assert!(reasons[0].ends_with(&path.display().to_string()));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reports_unparseable_files() {
        let dir = temporary_directory("unparseable");
        let oauth_path = dir.join("oauth_creds.json");
        std::fs::write(&oauth_path, "not json").unwrap();

        let oauth_reasons = oauth_insecurity_reasons_for(&oauth_path);
        assert_eq!(oauth_reasons.len(), 1);
        assert!(oauth_reasons[0].contains("could not be parsed"));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reports_unreadable_files() {
        let dir = temporary_directory("unreadable");
        let oauth_path = dir.join("oauth_creds.json");
        std::fs::create_dir(&oauth_path).unwrap();

        let oauth_reasons = oauth_insecurity_reasons_for(&oauth_path);
        assert_eq!(oauth_reasons.len(), 1);
        assert!(oauth_reasons[0].contains("could not be read"));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn scan_discovers_oauth_credential_file() {
        let home = temporary_directory("scan-oauth");
        let gemini_dir = home.join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        std::fs::write(
            gemini_dir.join("oauth_creds.json"),
            r#"{"access_token":"ya29.sample","refresh_token":"1//sample"}"#,
        )
        .unwrap();

        let findings = findings(&home);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source, "agy");
        assert_eq!(findings[0].affected.len(), 1);
        assert_eq!(
            findings[0].affected[0].path,
            gemini_dir.join("oauth_creds.json").display().to_string()
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
