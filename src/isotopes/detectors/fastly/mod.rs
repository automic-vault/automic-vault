#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub fn install_is_insecure() -> Result<bool, String> {
    install_insecurity_reasons().map(|reasons| !reasons.is_empty())
}

pub fn install_insecurity_reasons() -> Result<Vec<String>, String> {
    let mut reasons = Vec::new();
    for path in fastly_config_paths()? {
        if path.exists() && config_contains_secret(&read_to_string(&path)?) {
            reasons.push(format!(
                "Fastly config contains plaintext credentials: {}",
                path.display()
            ));
        }
    }
    Ok(reasons)
}

fn fastly_config_paths() -> Result<Vec<PathBuf>, String> {
    let home = user_home()?;
    let mut paths = Vec::new();
    if let Some(config_home) = std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty())
    {
        paths.push(PathBuf::from(config_home).join("fastly/config.toml"));
    }
    paths.push(home.join("Library/Application Support/fastly/config.toml"));
    paths.push(home.join(".fastly/config.toml"));
    Ok(paths)
}

fn user_home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())
}

fn read_to_string(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|err| format!("failed to read {}: {err}", path.display()))
}

fn config_contains_secret(contents: &str) -> bool {
    contents.lines().any(line_contains_secret)
}

fn line_contains_secret(line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return false;
    }
    let Some((key, value)) = line.split_once('=') else {
        return false;
    };
    matches!(key.trim(), "token" | "access_token" | "refresh_token")
        && !matches!(toml_string_value(value).unwrap_or_default(), "" | "@av")
}

fn toml_string_value(value: &str) -> Option<&str> {
    value
        .trim()
        .strip_prefix('"')
        .and_then(|value| value.split_once('"').map(|(value, _)| value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_fastly_auth_tokens() {
        assert!(config_contains_secret(
            "[auth.tokens.prod]\ntoken = \"fake-fastly-token\"\n"
        ));
        assert!(config_contains_secret(
            "[auth.tokens.sso]\nrefresh_token = \"fake-refresh-token\"\n"
        ));
        assert!(config_contains_secret(
            "[profile.user]\naccess_token = \"fake-access-token\"\n"
        ));
        assert!(!config_contains_secret("token = \"\"\n"));
        assert!(!config_contains_secret("token = \"@av\"\n"));
        assert!(!config_contains_secret("# token = \"fake-token\"\n"));
    }

    #[test]
    fn top_level_install_is_insecure_returns_false_when_default_locations_are_missing() {
        let home = std::env::temp_dir().join(format!(
            "{}-detect-missing-{}",
            module_path!().replace(':', "_"),
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();

        let previous_home = std::env::var_os("HOME");
        let previous_xdg = std::env::var_os("XDG_CONFIG_HOME");
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::remove_var("XDG_CONFIG_HOME");
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
    super::radioisotope::findings("fastly", install_insecurity_reasons, home)
}
