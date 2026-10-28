#![allow(dead_code)]

use std::path::{Path, PathBuf};

const KEYCHAIN_SERVICE: &str = "cloudflare";

pub fn install_is_insecure() -> Result<bool, String> {
    install_insecurity_reasons().map(|reasons| !reasons.is_empty())
}

pub fn install_insecurity_reasons() -> Result<Vec<String>, String> {
    let profiles = candidate_auth_files()?;
    let mut reasons = profiles.uncertainties;
    for path in profiles.plaintext {
        if !path.exists() {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(contents) => match auth_profile_contains_secret(&contents) {
                Some(true) => reasons.push(format!(
                    "cf auth profile contains plaintext Cloudflare tokens: {}",
                    path.display()
                )),
                Some(false) => {}
                None => reasons.push(format!(
                    "cf auth profile could not be inspected (invalid JSON): {}",
                    path.display()
                )),
            },
            Err(error) => reasons.push(format!(
                "cf auth profile could not be inspected ({error}): {}",
                path.display()
            )),
        }
    }
    for path in profiles.encrypted {
        if !path.exists() {
            continue;
        }
        let Some((service, account)) = keychain_item_for(&path) else {
            continue;
        };
        if let Some(reason) = encrypted_auth_file_reason(
            &path,
            super::gh_cli::keychain_item_allows_security_tool(service, &account),
        ) {
            reasons.push(reason);
        }
    }
    reasons.sort();
    reasons.dedup();
    Ok(reasons)
}

#[derive(Debug, Default, PartialEq)]
struct AuthFiles {
    plaintext: Vec<PathBuf>,
    encrypted: Vec<PathBuf>,
    uncertainties: Vec<String>,
}

fn candidate_auth_files() -> Result<AuthFiles, String> {
    let home = home_dir()?;
    let mut roots = vec![
        home.join("Library/Preferences/cloudflare"),
        home.join(".config/cloudflare"),
    ];
    if let Some(config_home) = xdg_config_home() {
        roots.push(config_home.join("cloudflare"));
    }

    let mut files = AuthFiles::default();
    for root in roots {
        let directory = root.join("config");
        files.plaintext.push(directory.join("default.json"));
        files.encrypted.push(directory.join("default.enc"));
        match std::fs::read_dir(&directory) {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(entry) => files.add_named_profile(entry.path()),
                        Err(error) => files
                            .uncertainties
                            .push(directory_uncertainty(&directory, &error)),
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => files
                .uncertainties
                .push(directory_uncertainty(&directory, &error)),
        }
    }
    files.plaintext.sort();
    files.plaintext.dedup();
    files.encrypted.sort();
    files.encrypted.dedup();
    files.uncertainties.sort();
    files.uncertainties.dedup();
    Ok(files)
}

impl AuthFiles {
    fn add_named_profile(&mut self, path: PathBuf) {
        let bucket = match path.extension().and_then(|value| value.to_str()) {
            Some("json") => &mut self.plaintext,
            Some("enc") => &mut self.encrypted,
            _ => return,
        };
        match std::fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => bucket.push(path),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => self.uncertainties.push(format!(
                "cf auth profile could not be inspected ({error}): {}",
                path.display()
            )),
        }
    }
}

fn directory_uncertainty(directory: &Path, error: &std::io::Error) -> String {
    format!(
        "cf auth profile directory could not be inspected ({error}): {}",
        directory.display()
    )
}

fn keychain_item_for(encrypted_path: &Path) -> Option<(&'static str, String)> {
    let account = encrypted_path.file_stem()?.to_str()?;
    Some((KEYCHAIN_SERVICE, account.to_string()))
}

fn encrypted_auth_file_reason(path: &Path, key_access: Result<bool, String>) -> Option<String> {
    match key_access {
        Ok(true) => Some(format!(
            "cf encrypted auth profile uses a Keychain encryption key retrievable non-interactively through /usr/bin/security: {}",
            path.display()
        )),
        Ok(false) => None,
        Err(error) => Some(format!(
            "cf encrypted auth profile Keychain access could not be inspected ({error}): {}",
            path.display()
        )),
    }
}

fn home_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())
}

fn xdg_config_home() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn auth_profile_contains_secret(contents: &str) -> Option<bool> {
    let Ok(serde_json::Value::Object(profile)) = serde_json::from_str(contents) else {
        return None;
    };
    Some(
        ["oauth_token", "refresh_token", "api_token"]
            .iter()
            .any(|key| profile.get(*key).is_some_and(secret_value)),
    )
}

fn secret_value(value: &serde_json::Value) -> bool {
    value
        .as_str()
        .is_some_and(|value| !value.trim().is_empty() && value != "null")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EnvGuard {
        previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl EnvGuard {
        fn set(values: &[(&'static str, &Path)]) -> Self {
            let previous = values
                .iter()
                .map(|(key, value)| {
                    let previous = std::env::var_os(key);
                    unsafe { std::env::set_var(key, value) };
                    (*key, previous)
                })
                .collect();
            Self { previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, previous) in self.previous.drain(..).rev() {
                match previous {
                    Some(value) => unsafe { std::env::set_var(key, value) },
                    None => unsafe { std::env::remove_var(key) },
                }
            }
        }
    }

    fn temp_home(label: &str) -> PathBuf {
        let home = std::env::temp_dir().join(format!(
            "{}-{label}-{}",
            module_path!().replace(':', "_"),
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        home
    }

    #[test]
    fn detects_oauth_and_api_tokens() {
        assert_eq!(
            auth_profile_contains_secret(
                r#"{"oauth_token":"access","expiration_time":"2026-01-01T00:00:00Z","refresh_token":"refresh","scopes":["account:read"]}"#
            ),
            Some(true)
        );
        assert_eq!(
            auth_profile_contains_secret(r#"{"api_token":"token"}"#),
            Some(true)
        );
        assert_eq!(
            auth_profile_contains_secret(r#"{"refresh_token":"refresh"}"#),
            Some(true)
        );
    }

    #[test]
    fn ignores_profiles_without_token_values() {
        for clean in [
            r#"{"scopes":["account:read"]}"#,
            r#"{"oauth_token":"","refresh_token":""}"#,
            r#"{"oauth_token":null,"api_token":"null"}"#,
            r#"{"oauth_token":42}"#,
        ] {
            assert_eq!(auth_profile_contains_secret(clean), Some(false), "{clean}");
        }
    }

    #[test]
    fn profiles_that_are_not_json_objects_are_not_inspectable() {
        for opaque in ["[]", "oauth_token = \"access\"\n", r#"{"oauth_token":"acc"#] {
            assert_eq!(auth_profile_contains_secret(opaque), None, "{opaque}");
        }
    }

    #[test]
    fn encrypted_profile_maps_to_its_keychain_item_without_reading_it() {
        // Oracle: npm package `cf` 1.0.0-beta.23, dist/chunk-3PJ54H4K-C8sxQzhB.mjs.
        // `MacSecurityKeyProvider` runs `security add-generic-password -s cloudflare -a <profile>`
        // with `getKeyringAccountName`; `getEncryptedAuthConfigFilePath` writes `config/<profile>.enc`.
        assert_eq!(
            keychain_item_for(Path::new("/tmp/cloudflare/config/default.enc")),
            Some(("cloudflare", "default".to_string()))
        );
        assert_eq!(
            keychain_item_for(Path::new("/tmp/cloudflare/config/work-account.enc")),
            Some(("cloudflare", "work-account".to_string()))
        );
    }

    #[test]
    fn unparseable_profiles_are_reported_without_hiding_other_findings() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let home = temp_home("unparseable");
        let xdg = home.join("xdg");
        let preferences = home.join("Library/Preferences/cloudflare/config");
        std::fs::create_dir_all(&xdg).unwrap();
        std::fs::create_dir_all(&preferences).unwrap();
        std::fs::write(
            preferences.join("default.json"),
            r#"{"oauth_token":"fixture-trunc"#,
        )
        .unwrap();
        std::fs::write(preferences.join("array.json"), "[]").unwrap();
        std::fs::write(
            preferences.join("work-account.json"),
            r#"{"api_token":"fixture-api-token"}"#,
        )
        .unwrap();
        let _env = EnvGuard::set(&[("HOME", &home), ("XDG_CONFIG_HOME", &xdg)]);

        let reasons = install_insecurity_reasons().unwrap();

        let invalid = |name: &str| {
            format!(
                "cf auth profile could not be inspected (invalid JSON): {}",
                preferences.join(name).display()
            )
        };
        assert_eq!(reasons.len(), 3, "{reasons:?}");
        assert!(reasons.contains(&invalid("default.json")), "{reasons:?}");
        assert!(reasons.contains(&invalid("array.json")), "{reasons:?}");
        assert!(reasons.contains(&format!(
            "cf auth profile contains plaintext Cloudflare tokens: {}",
            preferences.join("work-account.json").display()
        )));
        assert!(reasons.iter().all(|reason| !reason.contains("fixture-")));
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn reports_encrypted_profile_only_when_key_access_is_exposed_or_unknown() {
        let path = Path::new("/tmp/cloudflare/config/default.enc");
        assert!(encrypted_auth_file_reason(path, Ok(false)).is_none());
        let exposed = encrypted_auth_file_reason(path, Ok(true)).unwrap();
        assert!(exposed.contains("retrievable non-interactively"));
        assert!(exposed.ends_with(": /tmp/cloudflare/config/default.enc"));
        let unknown =
            encrypted_auth_file_reason(path, Err("copy keychain ACL list".to_string())).unwrap();
        assert!(unknown.contains("could not be inspected (copy keychain ACL list)"));
        assert!(unknown.ends_with(": /tmp/cloudflare/config/default.enc"));
    }

    #[test]
    fn scans_default_and_named_profiles_under_every_config_root() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let home = temp_home("profiles");
        let xdg = home.join("xdg");
        let preferences = home.join("Library/Preferences/cloudflare/config");
        let xdg_config = xdg.join("cloudflare/config");
        std::fs::create_dir_all(&preferences).unwrap();
        std::fs::create_dir_all(&xdg_config).unwrap();
        std::fs::write(
            preferences.join("default.json"),
            r#"{"oauth_token":"fixture-access","expiration_time":"2026-01-01T00:00:00Z","refresh_token":"fixture-refresh","scopes":["account:read"]}"#,
        )
        .unwrap();
        std::fs::write(
            preferences.join("work-account.json"),
            r#"{"api_token":"fixture-api-token"}"#,
        )
        .unwrap();
        std::fs::write(
            preferences.join("logged-out.json"),
            r#"{"scopes":["account:read"]}"#,
        )
        .unwrap();
        std::fs::write(
            xdg_config.join("staging.json"),
            r#"{"oauth_token":"fixture-staging"}"#,
        )
        .unwrap();
        let _env = EnvGuard::set(&[("HOME", &home), ("XDG_CONFIG_HOME", &xdg)]);

        let reasons = install_insecurity_reasons().unwrap();

        let expected = [
            preferences.join("default.json"),
            preferences.join("work-account.json"),
            xdg_config.join("staging.json"),
        ];
        assert_eq!(reasons.len(), expected.len(), "{reasons:?}");
        for path in &expected {
            assert!(
                reasons.iter().any(|reason| reason
                    == &format!(
                        "cf auth profile contains plaintext Cloudflare tokens: {}",
                        path.display()
                    )),
                "{reasons:?}"
            );
        }
        assert!(reasons.iter().all(|reason| !reason.contains("fixture-")));
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn unreadable_profile_is_reported_without_hiding_other_findings() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let home = temp_home("unreadable");
        let xdg = home.join("xdg");
        let preferences = home.join("Library/Preferences/cloudflare/config");
        std::fs::create_dir_all(&xdg).unwrap();
        std::fs::create_dir_all(preferences.join("default.json")).unwrap();
        std::fs::write(
            preferences.join("work-account.json"),
            r#"{"api_token":"fixture-api-token"}"#,
        )
        .unwrap();
        let _env = EnvGuard::set(&[("HOME", &home), ("XDG_CONFIG_HOME", &xdg)]);

        let reasons = install_insecurity_reasons().unwrap();

        assert_eq!(reasons.len(), 2, "{reasons:?}");
        assert!(reasons.iter().any(|reason| {
            reason.starts_with("cf auth profile could not be inspected (")
                && reason.ends_with(&format!(": {}", preferences.join("default.json").display()))
        }));
        assert!(reasons.contains(&format!(
            "cf auth profile contains plaintext Cloudflare tokens: {}",
            preferences.join("work-account.json").display()
        )));
        assert!(reasons.iter().all(|reason| !reason.contains("fixture-")));
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn top_level_install_is_insecure_returns_false_when_default_locations_are_missing() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let home = temp_home("missing");
        let xdg = home.join("xdg");
        std::fs::create_dir_all(&xdg).unwrap();
        let _env = EnvGuard::set(&[("HOME", &home), ("XDG_CONFIG_HOME", &xdg)]);

        assert!(!install_is_insecure().unwrap());
        std::fs::remove_dir_all(home).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unlistable_profile_directory_is_reported_without_hiding_other_roots() {
        use std::os::unix::fs::PermissionsExt;

        let _lock = crate::global_test_env_lock().lock().unwrap();
        let home = temp_home("unlistable");
        let xdg = home.join("xdg");
        let preferences = home.join("Library/Preferences/cloudflare/config");
        let xdg_config = xdg.join("cloudflare/config");
        std::fs::create_dir_all(&preferences).unwrap();
        std::fs::create_dir_all(&xdg_config).unwrap();
        std::fs::write(
            preferences.join("default.json"),
            r#"{"scopes":["account:read"]}"#,
        )
        .unwrap();
        std::fs::write(
            preferences.join("work-account.json"),
            r#"{"api_token":"fixture-api-token"}"#,
        )
        .unwrap();
        std::fs::write(
            xdg_config.join("staging.json"),
            r#"{"oauth_token":"fixture-staging"}"#,
        )
        .unwrap();
        std::fs::set_permissions(&preferences, std::fs::Permissions::from_mode(0o311)).unwrap();
        let _env = EnvGuard::set(&[("HOME", &home), ("XDG_CONFIG_HOME", &xdg)]);

        let reasons = install_insecurity_reasons().unwrap();

        std::fs::set_permissions(&preferences, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(reasons.len(), 2, "{reasons:?}");
        assert!(reasons.iter().any(|reason| {
            reason.starts_with("cf auth profile directory could not be inspected (")
                && reason.ends_with(&format!(": {}", preferences.display()))
        }));
        assert!(reasons.contains(&format!(
            "cf auth profile contains plaintext Cloudflare tokens: {}",
            xdg_config.join("staging.json").display()
        )));
        assert!(reasons.iter().all(|reason| !reason.contains("fixture-")));
        std::fs::remove_dir_all(home).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_named_profiles_are_inspected_like_the_default_profile() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let home = temp_home("symlinks");
        let xdg = home.join("xdg");
        let preferences = home.join("Library/Preferences/cloudflare/config");
        let targets = home.join("targets");
        std::fs::create_dir_all(&xdg).unwrap();
        std::fs::create_dir_all(&preferences).unwrap();
        std::fs::create_dir_all(&targets).unwrap();
        std::fs::write(
            targets.join("work.json"),
            r#"{"api_token":"fixture-api-token"}"#,
        )
        .unwrap();
        std::fs::write(targets.join("staging.enc"), "fixture-ciphertext").unwrap();
        std::fs::create_dir_all(targets.join("tree.json")).unwrap();
        std::os::unix::fs::symlink(
            targets.join("work.json"),
            preferences.join("work-account.json"),
        )
        .unwrap();
        std::os::unix::fs::symlink(targets.join("staging.enc"), preferences.join("staging.enc"))
            .unwrap();
        std::os::unix::fs::symlink(targets.join("tree.json"), preferences.join("tree.json"))
            .unwrap();
        std::os::unix::fs::symlink(targets.join("missing.json"), preferences.join("ghost.json"))
            .unwrap();
        let _env = EnvGuard::set(&[("HOME", &home), ("XDG_CONFIG_HOME", &xdg)]);

        let files = candidate_auth_files().unwrap();
        let reasons = install_insecurity_reasons().unwrap();

        assert!(
            files
                .plaintext
                .contains(&preferences.join("work-account.json")),
            "{files:?}"
        );
        assert!(
            files.encrypted.contains(&preferences.join("staging.enc")),
            "{files:?}"
        );
        assert!(
            !files.plaintext.contains(&preferences.join("tree.json")),
            "{files:?}"
        );
        assert!(
            !files.plaintext.contains(&preferences.join("ghost.json")),
            "{files:?}"
        );
        assert_eq!(files.uncertainties, Vec::<String>::new());
        assert!(
            reasons.contains(&format!(
                "cf auth profile contains plaintext Cloudflare tokens: {}",
                preferences.join("work-account.json").display()
            )),
            "{reasons:?}"
        );
        assert!(reasons.iter().all(|reason| !reason.contains("fixture-")));
        std::fs::remove_dir_all(home).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn named_profile_whose_target_cannot_be_examined_is_reported() {
        use std::os::unix::fs::PermissionsExt;

        let _lock = crate::global_test_env_lock().lock().unwrap();
        let home = temp_home("unexaminable");
        let xdg = home.join("xdg");
        let preferences = home.join("Library/Preferences/cloudflare/config");
        let locked = home.join("locked");
        std::fs::create_dir_all(&xdg).unwrap();
        std::fs::create_dir_all(&preferences).unwrap();
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::write(
            locked.join("work.json"),
            r#"{"api_token":"fixture-api-token"}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(
            locked.join("work.json"),
            preferences.join("work-account.json"),
        )
        .unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let _env = EnvGuard::set(&[("HOME", &home), ("XDG_CONFIG_HOME", &xdg)]);

        let reasons = install_insecurity_reasons().unwrap();

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(reasons.len(), 1, "{reasons:?}");
        assert!(reasons[0].starts_with("cf auth profile could not be inspected ("));
        assert!(reasons[0].ends_with(&format!(
            ": {}",
            preferences.join("work-account.json").display()
        )));
        assert!(!reasons[0].contains("fixture-"));
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn documentation_explains_why_cf_keyring_is_not_hardened() {
        let documentation = include_str!("detector.md");
        assert!(documentation.contains("cf auth login --use-keyring"));
        assert!(documentation.contains("`/usr/bin/security`"));
        assert!(documentation.contains("Authorization Gate"));
        assert!(documentation.contains("Secret Custody"));
        assert!(documentation.contains("`cf auth logout` removes the default profile"));
        assert!(documentation.contains("`cf auth delete <name>` removes the named"));
    }
}

pub(crate) fn findings(home: &std::path::Path) -> Vec<crate::Finding> {
    super::radioisotope::findings("cloudflare-cf", install_insecurity_reasons, home)
}
