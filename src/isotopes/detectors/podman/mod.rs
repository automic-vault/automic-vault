#![allow(dead_code)]

use std::path::PathBuf;

pub fn install_is_insecure() -> Result<bool, String> {
    install_insecurity_reasons().map(|reasons| !reasons.is_empty())
}

pub fn install_insecurity_reasons() -> Result<Vec<String>, String> {
    for path in candidate_auth_paths()? {
        if path.exists() && auth_json_contains_secret(&read_to_string(&path)?) {
            return Ok(vec![format!(
                "Podman registry auth file contains credentials: {}",
                path.display()
            )]);
        }
    }
    Ok(Vec::new())
}

pub(crate) fn candidate_auth_paths() -> Result<Vec<PathBuf>, String> {
    if let Some(path) = std::env::var_os("REGISTRY_AUTH_FILE").filter(|value| !value.is_empty()) {
        return Ok(vec![PathBuf::from(path)]);
    }

    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())?;
    let mut paths = Vec::new();
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR").filter(|value| !value.is_empty()) {
        paths.push(PathBuf::from(runtime).join("containers/auth.json"));
    }
    if let Some(config) = std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
        paths.push(PathBuf::from(config).join("containers/auth.json"));
    }
    paths.push(home.join(".config/containers/auth.json"));
    Ok(paths)
}

fn read_to_string(path: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|err| format!("failed to read {}: {err}", path.display()))
}

fn auth_json_contains_secret(contents: &str) -> bool {
    contents.contains("\"auths\"")
        && ["\"auth\"", "\"identitytoken\"", "\"identityToken\""]
            .iter()
            .any(|key| json_key_has_non_empty_string(contents, key))
}

fn json_key_has_non_empty_string(contents: &str, key: &str) -> bool {
    let mut remaining = contents;
    while let Some(index) = remaining.find(key) {
        let Some(after_key) = remaining[index..].split_once(':').map(|(_, value)| value) else {
            return false;
        };
        if json_string_value(after_key).is_some_and(|value| !value.is_empty()) {
            return true;
        }
        remaining = &after_key[1..];
    }
    false
}

fn json_string_value(value: &str) -> Option<&str> {
    value
        .trim_start()
        .strip_prefix('"')
        .and_then(|value| value.split_once('"').map(|(value, _)| value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_registry_auth() {
        assert!(auth_json_contains_secret(
            r#"{"auths":{"registry.example":{"auth":"base64"}}}"#
        ));
    }

    #[test]
    fn detects_identity_token() {
        assert!(auth_json_contains_secret(
            r#"{"auths":{"registry.example":{"identitytoken":"token"}}}"#
        ));
    }

    #[test]
    fn ignores_empty_auths() {
        assert!(!auth_json_contains_secret(r#"{"auths":{}}"#));
    }

    #[test]
    fn top_level_install_is_insecure_returns_false_when_default_locations_are_missing() {
        let home = std::env::temp_dir().join(format!(
            "{}-detect-missing-{}",
            module_path!().replace(':', "_"),
            std::process::id()
        ));
        let xdg = home.join("xdg");
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&xdg).unwrap();

        let previous_home = std::env::var_os("HOME");
        let previous_xdg = std::env::var_os("XDG_CONFIG_HOME");
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("XDG_CONFIG_HOME", &xdg);
        }

        let result = install_is_insecure().unwrap();

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match previous_xdg {
                Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }

        assert!(!result);
        std::fs::remove_dir_all(home).unwrap();
    }
}

pub(crate) fn findings(home: &std::path::Path) -> Vec<crate::Finding> {
    super::radioisotope::findings("podman", install_insecurity_reasons, home)
}
