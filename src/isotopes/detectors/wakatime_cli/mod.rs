#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub fn install_is_insecure() -> Result<bool, String> {
    install_insecurity_reasons().map(|reasons| !reasons.is_empty())
}

pub fn install_insecurity_reasons() -> Result<Vec<String>, String> {
    let path = wakatime_config_path()?;
    if path.exists() && config_contains_api_key(&read_to_string(&path)?) {
        return Ok(vec![format!(
            "WakaTime config contains plaintext API keys: {}",
            path.display()
        )]);
    }
    Ok(Vec::new())
}

fn wakatime_config_path() -> Result<PathBuf, String> {
    let home = std::env::var_os("WAKATIME_HOME")
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())?;
    Ok(home.join(".wakatime.cfg"))
}

fn read_to_string(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|err| format!("failed to read {}: {err}", path.display()))
}

fn config_contains_api_key(contents: &str) -> bool {
    let mut section = String::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        if let Some(name) = trimmed
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            section = name.trim().to_ascii_lowercase();
            continue;
        }

        if line_has_secret(trimmed, &section) {
            return true;
        }
    }

    false
}

fn line_has_secret(line: &str, section: &str) -> bool {
    let Some((key, value)) = line.split_once('=') else {
        return false;
    };
    let key = key.trim().to_ascii_lowercase();
    let value = value.trim();
    if value.is_empty() {
        return false;
    }

    matches!(key.as_str(), "api_key" | "apikey" | "key")
        || (section == "project_api_key" && !key.is_empty())
        || (section == "api_urls"
            && value
                .split_once('|')
                .is_some_and(|(_, key)| !key.trim().is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detects_default_project_and_api_url_keys() {
        assert!(config_contains_api_key("[settings]\napi_key = fake-key\n"));
        assert!(config_contains_api_key(
            "[project_api_key]\nprojects/foo = fake-project-key\n"
        ));
        assert!(config_contains_api_key(
            "[api_urls]\n^/work = https://example.invalid/api/v1|fake-work-key\n"
        ));
        assert!(config_contains_api_key("[settings]\napikey = fake-key\n"));
    }

    #[test]
    fn ignores_comments_and_empty_values() {
        assert!(!config_contains_api_key(
            "# api_key = fake-key\n[settings]\napi_key =\n[api_urls]\n.* = https://example.invalid|\n"
        ));
    }

    #[test]
    fn top_level_install_is_insecure_returns_false_when_default_location_is_missing() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let home = std::env::temp_dir().join(format!(
            "{}-detect-missing-{}",
            module_path!().replace(':', "_"),
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();

        let previous_home = std::env::var_os("HOME");
        let previous_wakatime_home = std::env::var_os("WAKATIME_HOME");
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::remove_var("WAKATIME_HOME");
        }

        let result = install_is_insecure().unwrap();

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match previous_wakatime_home {
                Some(value) => std::env::set_var("WAKATIME_HOME", value),
                None => std::env::remove_var("WAKATIME_HOME"),
            }
        }

        assert!(!result);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn path_and_line_helpers_cover_edge_cases() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let home =
            std::env::temp_dir().join(format!("wakatime-detect-home-{}", std::process::id()));
        let previous_home = std::env::var_os("HOME");
        let previous_wakatime_home = std::env::var_os("WAKATIME_HOME");
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::remove_var("WAKATIME_HOME");
        }
        assert_eq!(wakatime_config_path().unwrap(), home.join(".wakatime.cfg"));
        unsafe {
            std::env::set_var("WAKATIME_HOME", home.join("custom"));
        }
        assert_eq!(
            wakatime_config_path().unwrap(),
            home.join("custom/.wakatime.cfg")
        );
        unsafe {
            std::env::remove_var("WAKATIME_HOME");
        }
        unsafe {
            std::env::remove_var("HOME");
        }
        assert_eq!(wakatime_config_path().unwrap_err(), "HOME is not set");
        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match previous_wakatime_home {
                Some(value) => std::env::set_var("WAKATIME_HOME", value),
                None => std::env::remove_var("WAKATIME_HOME"),
            }
        }

        assert!(!line_has_secret("api_key =", "settings"));
        assert!(!line_has_secret("broken", "settings"));
    }

    #[test]
    fn install_insecurity_reasons_reports_wakatime_config_path() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let home =
            std::env::temp_dir().join(format!("wakatime-detect-report-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).unwrap();
        let config = home.join(".wakatime.cfg");
        fs::write(&config, "[settings]\napi_key = fake-key\n").unwrap();
        let previous_home = std::env::var_os("HOME");
        let previous_wakatime_home = std::env::var_os("WAKATIME_HOME");
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::remove_var("WAKATIME_HOME");
        }

        let reasons = install_insecurity_reasons().unwrap();

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match previous_wakatime_home {
                Some(value) => std::env::set_var("WAKATIME_HOME", value),
                None => std::env::remove_var("WAKATIME_HOME"),
            }
        }

        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains(config.to_str().unwrap()));
        fs::remove_dir_all(home).unwrap();
    }
}

pub(crate) fn findings(home: &std::path::Path) -> Vec<crate::Finding> {
    super::radioisotope::findings("wakatime-cli", install_insecurity_reasons, home)
}
