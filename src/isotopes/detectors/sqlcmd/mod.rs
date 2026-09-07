#![allow(dead_code)]

use std::path::PathBuf;

pub fn install_is_insecure() -> Result<bool, String> {
    install_insecurity_reasons().map(|reasons| !reasons.is_empty())
}

pub fn install_insecurity_reasons() -> Result<Vec<String>, String> {
    let path = sqlconfig_path()?;
    if path.exists() && sqlconfig_has_password(&read_to_string(&path)?) {
        return Ok(vec![format!(
            "sqlcmd sqlconfig contains stored passwords: {}",
            path.display()
        )]);
    }
    Ok(Vec::new())
}

fn sqlconfig_path() -> Result<PathBuf, String> {
    Ok(user_home()?.join(".sqlcmd/sqlconfig"))
}

fn user_home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())
}

fn read_to_string(path: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|err| format!("failed to read {}: {err}", path.display()))
}

fn sqlconfig_has_password(contents: &str) -> bool {
    contents.lines().any(line_has_password_value)
}

fn line_has_password_value(line: &str) -> bool {
    let trimmed = line.trim();
    if !trimmed.starts_with("password:") || trimmed.starts_with("password-encryption:") {
        return false;
    }
    let value = trimmed["password:".len()..].trim();
    !value.is_empty()
        && value != "\"\""
        && value != "''"
        && value != "@av"
        && value != "\"@av\""
        && value != "'@av'"
        && !value.eq_ignore_ascii_case("null")
        && !value.eq_ignore_ascii_case("redacted")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_password_field() {
        assert!(sqlconfig_has_password(
            "users:\n- user:\n    username: sa\n    password: c2VjcmV0\n"
        ));
    }

    #[test]
    fn ignores_password_encryption_setting() {
        assert!(!sqlconfig_has_password(
            "users:\n- user:\n    password-encryption: none\n"
        ));
    }

    #[test]
    fn ignores_empty_or_redacted_passwords() {
        assert!(!sqlconfig_has_password("password: \"\"\n"));
        assert!(!sqlconfig_has_password("password: REDACTED\n"));
        assert!(!sqlconfig_has_password("password: '@av'\n"));
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
    super::radioisotope::findings("sqlcmd", install_insecurity_reasons, home)
}
