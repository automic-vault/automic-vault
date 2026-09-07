#![allow(dead_code)]

use std::path::PathBuf;

pub fn install_is_insecure() -> Result<bool, String> {
    install_insecurity_reasons().map(|reasons| !reasons.is_empty())
}

pub fn install_insecurity_reasons() -> Result<Vec<String>, String> {
    let path = aliyun_config_path()?;
    if path.exists() && config_has_sensitive_profile_data(&read_to_string(&path)?)? {
        return Ok(vec![format!(
            "Alibaba Cloud CLI config contains plaintext credentials: {}",
            path.display()
        )]);
    }
    Ok(Vec::new())
}

fn aliyun_config_path() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())?;
    Ok(home.join(".aliyun/config.json"))
}

fn read_to_string(path: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|err| format!("failed to read {}: {err}", path.display()))
}

fn config_has_sensitive_profile_data(contents: &str) -> Result<bool, String> {
    let value: serde_json::Value = serde_json::from_str(contents)
        .map_err(|err| format!("failed to parse aliyun config JSON: {err}"))?;
    Ok(profile_objects(&value)
        .iter()
        .any(|profile| profile_has_sensitive_fields(profile)))
}

fn profile_objects(value: &serde_json::Value) -> Vec<&serde_json::Map<String, serde_json::Value>> {
    value
        .get("profiles")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_object)
        .collect()
}

fn profile_has_sensitive_fields(profile: &serde_json::Map<String, serde_json::Value>) -> bool {
    sensitive_field_names().iter().any(|key| {
        profile
            .get(*key)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| !value.is_empty())
    })
}

fn sensitive_field_names() -> &'static [&'static str] {
    &[
        "access_key_secret",
        "sts_token",
        "private_key",
        "access_token",
        "oauth_access_token",
        "oauth_refresh_token",
        "bearer_token",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_access_key_secret_and_oauth_tokens() {
        let contents = r#"{
          "current": "default",
          "profiles": [
            {
              "name": "default",
              "access_key_id": "ak",
              "access_key_secret": "secret",
              "oauth_refresh_token": "refresh"
            }
          ]
        }"#;
        assert!(config_has_sensitive_profile_data(contents).unwrap());
    }

    #[test]
    fn ignores_profiles_without_inline_secrets() {
        let contents = r#"{
          "current": "default",
          "profiles": [
            {
              "name": "default",
              "mode": "External",
              "region_id": "cn-hangzhou",
              "process_command": "credential-helper"
            }
          ]
        }"#;
        assert!(!config_has_sensitive_profile_data(contents).unwrap());
    }

    #[test]
    fn detects_bearer_tokens() {
        assert!(
            config_has_sensitive_profile_data(
                r#"{"profiles":[{"name":"default","bearer_token":"secret"}]}"#
            )
            .unwrap()
        );
    }
}

pub(crate) fn findings(home: &std::path::Path) -> Vec<crate::Finding> {
    super::radioisotope::findings("aliyun-cli", install_insecurity_reasons, home)
}
