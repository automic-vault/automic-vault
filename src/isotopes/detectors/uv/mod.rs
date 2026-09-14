#![allow(dead_code)]

use crate::uv::credentials_path as uv_credentials_path;

pub fn install_is_insecure() -> Result<bool, String> {
    install_insecurity_reasons().map(|reasons| !reasons.is_empty())
}

pub fn install_insecurity_reasons() -> Result<Vec<String>, String> {
    let mut reasons = Vec::new();
    let path = uv_credentials_path()?;
    if path.exists() && credentials_toml_contains_secret(&read_to_string(&path)?) {
        reasons.push(format!(
            "uv credentials store contains plaintext credentials: {}",
            path.display()
        ));
    }
    Ok(reasons)
}

fn read_to_string(path: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|err| format!("failed to read {}: {err}", path.display()))
}

fn credentials_toml_contains_secret(contents: &str) -> bool {
    contents.lines().any(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return false;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            return false;
        };
        let key = key.trim();
        matches!(key, "password" | "token")
            && quoted_value(value.trim()).is_some_and(|value| !value.is_empty())
    })
}

fn quoted_value(value: &str) -> Option<&str> {
    value
        .strip_prefix('"')
        .and_then(|value| value.split_once('"').map(|(value, _)| value))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.split_once('\'').map(|(value, _)| value))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_password_entries() {
        assert!(credentials_toml_contains_secret(
            "[[credentials]]\nusername = \"user\"\npassword = \"secret\"\n"
        ));
    }

    #[test]
    fn ignores_empty_and_commented_entries() {
        assert!(!credentials_toml_contains_secret(
            "# password = \"secret\"\npassword = \"\"\n"
        ));
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
    super::radioisotope::findings("uv", install_insecurity_reasons, home)
        .into_iter().map(|mut finding| {
            finding.solution = "Run `av harden uv` to move supported HTTP Basic credentials into Automic Vault and install the official uv credential helper.".into();
            finding
        }).collect()
}
