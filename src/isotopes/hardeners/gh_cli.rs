use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{HardenerDetection, SecretGateDescriptor, SecretGateRoute, isotope};

const PRIVILEGE_MODE: super::PrivilegeMode = super::PrivilegeMode::UserOnly;

#[derive(Debug, Clone, PartialEq, Eq)]
struct GhCredential {
    host: String,
    user: Option<String>,
    token: String,
}

pub(crate) fn run(stdout: &mut dyn Write, yes: bool) -> Result<(), String> {
    PRIVILEGE_MODE.require_user("gh", false)?;
    let install = isotope::plan(isotope::GH)?;

    let hosts_paths = gh_hosts_paths()?;
    let configured_hosts = configured_hosts(&hosts_paths);
    let mut plaintext_credentials = Vec::new();
    for path in &hosts_paths {
        plaintext_credentials.extend(read_plaintext_credentials(path)?);
    }
    let legacy_credentials = read_legacy_keychain_credentials(&configured_hosts)?;
    let mut credentials = plaintext_credentials.clone();
    credentials.extend(
        legacy_credentials
            .iter()
            .map(|credential| credential.credential.clone()),
    );

    writeln!(stdout, "╭─ harden gh").ok();
    writeln!(stdout, "│").ok();
    install.write(stdout, isotope::GH);
    if credentials.is_empty() && !install.needed() {
        writeln!(stdout, "╰─ no legacy gh credentials found").ok();
        super::write_secret_gate_notice(stdout, "gh");
        return Ok(());
    }

    let destinations = migration_destinations(&credentials, &configured_hosts)?;

    if credentials.is_empty() {
        writeln!(stdout, "├─ no legacy gh credentials found").ok();
    } else {
        writeln!(
            stdout,
            "├─ migrate {} GitHub token(s) into Automic Vault",
            credentials.len()
        )
        .ok();
    }
    if !plaintext_credentials.is_empty() {
        writeln!(
            stdout,
            "├─ delete plaintext oauth_token entries from hosts.yml"
        )
        .ok();
    }
    if !legacy_credentials.is_empty() {
        writeln!(
            stdout,
            "├─ delete {} exact legacy GitHub Keychain item(s)",
            legacy_credentials.len()
        )
        .ok();
    }
    writeln!(stdout, "│").ok();
    if !confirm(stdout, yes)? {
        writeln!(stdout, "╰─ cancelled").ok();
        return Ok(());
    }

    if credentials.is_empty() {
        install.apply(isotope::GH)?;
        writeln!(stdout, "╰─ installed gh isotope").ok();
        super::write_secret_gate_notice(stdout, "gh");
        return Ok(());
    }
    store_destinations(&destinations)?;
    install.apply(isotope::GH)?;
    for path in &hosts_paths {
        remove_plaintext_tokens(path)?;
    }
    for credential in legacy_credentials {
        credential.delete()?;
    }
    verify_postconditions()?;
    writeln!(stdout, "╰─ migrated gh credentials").ok();
    super::write_secret_gate_notice(stdout, "gh");
    Ok(())
}

pub(crate) fn detect() -> HardenerDetection {
    isotope::detect(isotope::GH)
}

pub(crate) fn secret_gate() -> SecretGateDescriptor {
    SecretGateDescriptor {
        id: "gh",
        key_patterns: vec!["GH_TOKEN_*".to_string()],
        routes: vec![SecretGateRoute {
            operation: "keys",
            script_path: None,
            target_path: isotope::target(isotope::GH).display().to_string(),
            caller_identifiers: vec!["gh", "com.github.cli"],
            key_patterns: vec!["GH_TOKEN_*".to_string()],
            replace_existing_env: true,
            allow_missing_keys: false,
        }],
    }
}

pub(super) fn confirm(stdout: &mut dyn Write, yes: bool) -> Result<bool, String> {
    if yes {
        writeln!(stdout, "◇ Continue? yes (--yes)").ok();
        return Ok(true);
    }

    write!(stdout, "◇ Continue? [y/N] ").ok();
    stdout
        .flush()
        .map_err(|err| format!("failed to flush prompt: {err}"))?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|err| format!("failed to read confirmation: {err}"))?;
    if !io::stdin().is_terminal() {
        writeln!(stdout).ok();
    }
    Ok(matches!(
        input.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn gh_hosts_paths() -> Result<Vec<PathBuf>, String> {
    if let Some(config_dir) = std::env::var_os("GH_CONFIG_DIR").filter(|value| !value.is_empty()) {
        return Ok(vec![PathBuf::from(config_dir).join("hosts.yml")]);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())?;
    let mut paths = Vec::new();
    if let Some(config_home) = std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty())
    {
        paths.push(PathBuf::from(config_home).join("gh/hosts.yml"));
    }
    paths.push(home.join(".config/gh/hosts.yml"));
    Ok(paths)
}

fn read_plaintext_credentials(path: &Path) -> Result<Vec<GhCredential>, String> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };
    Ok(parse_hosts_credentials(&contents))
}

fn parse_hosts_credentials(contents: &str) -> Vec<GhCredential> {
    let mut credentials = Vec::new();
    let mut host = None::<String>;
    let mut active_user = None::<String>;
    let mut user_context = None::<String>;

    for line in contents.lines() {
        let indent = line.chars().take_while(|ch| ch.is_whitespace()).count();
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if indent == 0 {
            host = trimmed.strip_suffix(':').map(str::to_string);
            active_user = None;
            user_context = None;
            continue;
        }
        if indent <= 4 {
            user_context = None;
        }
        if indent == 4
            && let Some(value) = yaml_string_value(trimmed, "user")
        {
            active_user = Some(value.to_string());
            continue;
        }
        if indent >= 8 && trimmed.ends_with(':') {
            user_context = trimmed.strip_suffix(':').map(str::to_string);
            continue;
        }
        if let Some(token) = yaml_string_value(trimmed, "oauth_token") {
            if token.is_empty() || token == "null" {
                continue;
            }
            let Some(host) = &host else { continue };
            credentials.push(GhCredential {
                host: host.clone(),
                user: user_context.clone().or_else(|| active_user.clone()),
                token: token.to_string(),
            });
        }
    }
    credentials
}

fn yaml_string_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let (got_key, value) = line.split_once(':')?;
    if got_key.trim() != key {
        return None;
    }
    Some(value.trim().trim_matches('"').trim_matches('\''))
}

struct LegacyCredential {
    credential: GhCredential,
    item: Option<crate::isotopes::detectors::gh_cli::LegacyKeychainItem>,
}

impl LegacyCredential {
    fn delete(self) -> Result<(), String> {
        self.item.map_or(Ok(()), |item| item.delete())
    }
}

fn read_legacy_keychain_credentials(
    hosts: &BTreeMap<String, Option<String>>,
) -> Result<Vec<LegacyCredential>, String> {
    if let Some(token) = crate::test_env_string("AUTOMIC_VAULT_TEST_GH_LEGACY_TOKEN") {
        return Ok(hosts
            .iter()
            .map(|(host, user)| LegacyCredential {
                credential: GhCredential {
                    host: host.clone(),
                    user: user.clone(),
                    token: token.clone(),
                },
                item: None,
            })
            .collect());
    }
    if crate::test_keychain_dir().is_some() {
        return Ok(Vec::new());
    }

    let services = hosts
        .keys()
        .map(|host| format!("gh:{host}"))
        .collect::<Vec<_>>();
    let items = crate::isotopes::detectors::gh_cli::legacy_keychain_items(&services)?;
    let mut identities = BTreeSet::new();
    let mut credentials = Vec::new();
    for item in items {
        if !identities.insert((item.service.clone(), item.account.clone())) {
            return Err(format!(
                "refusing ambiguous duplicate legacy keychain items (service {:?}, account {:?})",
                item.service, item.account
            ));
        }
        let token = security_find_generic_password_result(&item.service, Some(&item.account))?
            .ok_or_else(|| {
                format!(
                    "failed to read legacy keychain item (service {:?}, account {:?})",
                    item.service, item.account
                )
            })?;
        credentials.push(LegacyCredential {
            credential: GhCredential {
                host: item.service.trim_start_matches("gh:").to_string(),
                user: (!item.account.is_empty()).then(|| item.account.clone()),
                token,
            },
            item: Some(item),
        });
    }
    Ok(credentials)
}

fn configured_hosts(hosts_paths: &[PathBuf]) -> BTreeMap<String, Option<String>> {
    let mut hosts = BTreeMap::from([("github.com".to_string(), None)]);
    for path in hosts_paths {
        let Ok(contents) = fs::read_to_string(path) else {
            continue;
        };
        let mut host = None::<String>;
        let mut active_user = None::<String>;
        for line in contents.lines() {
            let indent = line.chars().take_while(|ch| ch.is_whitespace()).count();
            let trimmed = line.trim();
            if indent == 0 {
                if let Some(previous) = host.take() {
                    hosts.insert(previous, active_user.take());
                }
                host = trimmed.strip_suffix(':').map(str::to_string);
            } else if indent == 4
                && let Some(value) = yaml_string_value(trimmed, "user")
            {
                active_user = Some(value.to_string());
            }
        }
        if let Some(previous) = host {
            hosts.insert(previous, active_user);
        }
    }
    hosts
}

pub(super) fn security_find_generic_password(
    service: &str,
    account: Option<&str>,
) -> Result<Option<String>, String> {
    security_find_generic_password_result(service, account)
}

pub(super) fn security_find_generic_password_result(
    service: &str,
    account: Option<&str>,
) -> Result<Option<String>, String> {
    let mut command = Command::new(security_path());
    command.args(["find-generic-password", "-s", service]);
    if let Some(account) = account {
        command.args(["-a", account]);
    }
    command.arg("-w");
    let output = command
        .output()
        .map_err(|err| format!("failed to run security: {err}"))?;
    if !output.status.success() {
        if output.status.code() == Some(44) {
            return Ok(None);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "failed to read legacy keychain item (service {service:?}, account {account:?}): {}",
            stderr.trim()
        ));
    }
    decode_legacy_keychain_password(String::from_utf8_lossy(&output.stdout).trim())
        .map(Some)
        .ok_or_else(|| {
            format!(
                "legacy keychain item (service {service:?}, account {account:?}) contained an unsupported or malformed value"
            )
        })
}

fn decode_legacy_keychain_password(value: &str) -> Option<String> {
    // zalando/go-keyring wraps macOS Keychain passwords so arbitrary bytes
    // survive `/usr/bin/security -w`. Decode its two published legacy forms
    // before moving the credential into Automic Vault.
    const BASE64_PREFIX: &str = "go-keyring-base64:";
    const HEX_PREFIX: &str = "go-keyring-encoded:";

    let decoded = if let Some(value) = value.strip_prefix(BASE64_PREFIX) {
        decode_base64(value)?
    } else if let Some(value) = value.strip_prefix(HEX_PREFIX) {
        decode_hex(value)?
    } else {
        return (!value.is_empty()).then(|| value.to_string());
    };
    let decoded = String::from_utf8(decoded).ok()?;
    (!decoded.is_empty()).then_some(decoded)
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(4) {
        return None;
    }

    fn sextet(byte: u8) -> Option<u8> {
        Some(match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }

    let chunks = value.as_bytes().chunks_exact(4);
    let chunk_count = chunks.len();
    let mut decoded = Vec::with_capacity(value.len() / 4 * 3);
    for (index, chunk) in chunks.enumerate() {
        let last = index + 1 == chunk_count;
        let a = sextet(chunk[0])?;
        let b = sextet(chunk[1])?;
        decoded.push((a << 2) | (b >> 4));

        if chunk[2] == b'=' {
            if !last || chunk[3] != b'=' || b & 0x0f != 0 {
                return None;
            }
            continue;
        }
        let c = sextet(chunk[2])?;
        decoded.push(((b & 0x0f) << 4) | (c >> 2));

        if chunk[3] == b'=' {
            if !last || c & 0x03 != 0 {
                return None;
            }
            continue;
        }
        let d = sextet(chunk[3])?;
        decoded.push(((c & 0x03) << 6) | d);
    }
    Some(decoded)
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)? as u8;
            let low = (pair[1] as char).to_digit(16)? as u8;
            Some((high << 4) | low)
        })
        .collect()
}

fn migration_destinations(
    credentials: &[GhCredential],
    active_users: &BTreeMap<String, Option<String>>,
) -> Result<BTreeMap<String, String>, String> {
    let mut destinations = BTreeMap::new();
    for credential in credentials {
        if let Some(user) = credential.user.as_deref().filter(|user| !user.is_empty()) {
            insert_destination(
                &mut destinations,
                vault_key(&credential.host, Some(user)),
                &credential.token,
            )?;
        } else {
            insert_destination(
                &mut destinations,
                vault_key(&credential.host, None),
                &credential.token,
            )?;
        }

        if active_users
            .get(&credential.host)
            .and_then(|user| user.as_deref())
            == credential.user.as_deref()
        {
            insert_destination(
                &mut destinations,
                vault_key(&credential.host, None),
                &credential.token,
            )?;
        }
    }

    for (host, active_user) in active_users {
        if active_user.is_some() || destinations.contains_key(&vault_key(host, None)) {
            continue;
        }
        let mut tokens = credentials
            .iter()
            .filter(|credential| credential.host == *host)
            .map(|credential| credential.token.as_str());
        if let Some(token) = tokens
            .next()
            .filter(|token| tokens.all(|other| other == *token))
        {
            insert_destination(&mut destinations, vault_key(host, None), token)?;
        }
    }
    Ok(destinations)
}

fn insert_destination(
    destinations: &mut BTreeMap<String, String>,
    key: String,
    token: &str,
) -> Result<(), String> {
    if let Some(existing) = destinations.get(&key) {
        if existing != token {
            return Err(format!(
                "refusing ambiguous GitHub credential destination {key}"
            ));
        }
    } else {
        destinations.insert(key, token.to_string());
    }
    Ok(())
}

fn store_destinations(destinations: &BTreeMap<String, String>) -> Result<(), String> {
    for (key, token) in destinations {
        crate::secrets::store_secret_if_absent_or_equal(key, token)?;
    }
    Ok(())
}

fn verify_postconditions() -> Result<(), String> {
    let hosts_token =
        crate::isotopes::detectors::gh_cli::hosts_token::install_insecurity_reasons()?;
    let keychain_access = if crate::test_keychain_dir().is_some() {
        Vec::new()
    } else {
        crate::isotopes::detectors::gh_cli::keychain_access::install_insecurity_reasons()?
    };
    ensure_postconditions(&hosts_token, &keychain_access)
}

fn ensure_postconditions(hosts_token: &[String], keychain_access: &[String]) -> Result<(), String> {
    let mut failed = Vec::new();
    if !hosts_token.is_empty() {
        failed.push("gh-cli-hosts-token");
    }
    if !keychain_access.is_empty() {
        failed.push("gh-cli-keychain-access");
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "GitHub migration postcondition failed: {}",
            failed.join(", ")
        ))
    }
}

fn remove_plaintext_tokens(path: &Path) -> Result<(), String> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };
    let cleaned = contents
        .split_inclusive('\n')
        .filter(|line| yaml_string_value(line.trim(), "oauth_token").is_none())
        .collect::<String>();
    if cleaned != contents {
        fs::write(path, cleaned)
            .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    }
    Ok(())
}

pub(super) fn security_delete_generic_password(
    service: &str,
    account: Option<&str>,
) -> Result<(), String> {
    let mut command = Command::new(security_path());
    command.args(["delete-generic-password", "-s", service]);
    if let Some(account) = account {
        command.args(["-a", account]);
    }
    let output = command
        .output()
        .map_err(|err| format!("failed to run security: {err}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("could not be found")
        || stderr.contains("The specified item could not be found")
    {
        return Ok(());
    }
    Err(format!(
        "failed to delete legacy keychain item (service {service:?}, account {account:?}): {}",
        stderr.trim()
    ))
}

fn security_path() -> PathBuf {
    crate::test_env_var("AUTOMIC_VAULT_TEST_SECURITY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/bin/security"))
}

fn vault_key(host: &str, user: Option<&str>) -> String {
    let mut key = format!("GH_TOKEN_{}", sanitize_key_part(host));
    if let Some(user) = user {
        key.push('_');
        key.push_str(&sanitize_key_part(user));
    }
    key
}

fn sanitize_key_part(value: &str) -> String {
    let mut out = String::new();
    let mut last_underscore = false;
    for ch in value.chars().flat_map(char::to_uppercase) {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_underscore = false;
        } else if !last_underscore {
            out.push('_');
            last_underscore = true;
        }
    }
    out.trim_matches('_').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn detect_reports_full_gh_path() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let missing = temp_path("missing-gh-cli-detect");
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_GH_CLI_PATH", &missing);
        }

        let detection = detect();

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_GH_CLI_PATH");
        }
        assert_eq!(detection.target_path, Some(missing.display().to_string()));
    }

    #[test]
    fn parses_plaintext_hosts_tokens() {
        assert_eq!(
            parse_hosts_credentials(
                "github.com:\n    user: monalisa\n    oauth_token: ghp_secret\n    users:\n        hubot:\n            oauth_token: gho_bot\n"
            ),
            vec![
                GhCredential {
                    host: "github.com".into(),
                    user: Some("monalisa".into()),
                    token: "ghp_secret".into(),
                },
                GhCredential {
                    host: "github.com".into(),
                    user: Some("hubot".into()),
                    token: "gho_bot".into(),
                }
            ]
        );
    }

    #[test]
    fn harden_imports_plaintext_hosts_tokens() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_path("gh-import");
        let config = dir.join("config");
        let keychain = dir.join("keychain");
        let gh = dir.join("gh");
        fs::create_dir_all(&config).unwrap();
        fs::write(&gh, "").unwrap();
        fs::write(
            config.join("hosts.yml"),
            "github.com:\n    user: monalisa\n    oauth_token: ghp_secret\n",
        )
        .unwrap();
        unsafe {
            std::env::set_var("GH_CONFIG_DIR", &config);
            std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain);
            std::env::set_var("AUTOMIC_VAULT_TEST_GH_CLI_PATH", &gh);
        }

        run(&mut Vec::new(), true).unwrap();

        unsafe {
            std::env::remove_var("GH_CONFIG_DIR");
            std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR");
            std::env::remove_var("AUTOMIC_VAULT_TEST_GH_CLI_PATH");
        }
        assert_eq!(
            fs::read_to_string(keychain.join("GH_TOKEN_GITHUB_COM")).unwrap(),
            "ghp_secret"
        );
        assert_eq!(
            fs::read_to_string(keychain.join("GH_TOKEN_GITHUB_COM_MONALISA")).unwrap(),
            "ghp_secret"
        );
        assert!(
            !fs::read_to_string(config.join("hosts.yml"))
                .unwrap()
                .contains("oauth_token")
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn harden_imports_legacy_keychain_token() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_path("gh-keychain-import");
        let config = dir.join("config");
        let keychain = dir.join("keychain");
        let gh = dir.join("gh");
        fs::create_dir_all(&config).unwrap();
        fs::write(&gh, "").unwrap();
        fs::write(
            config.join("hosts.yml"),
            "github.com:\n    users:\n        mxcl:\n    user: mxcl\n",
        )
        .unwrap();
        unsafe {
            std::env::set_var("GH_CONFIG_DIR", &config);
            std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain);
            std::env::set_var("AUTOMIC_VAULT_TEST_GH_CLI_PATH", &gh);
            std::env::set_var("AUTOMIC_VAULT_TEST_GH_LEGACY_TOKEN", "gho_secret");
        }

        let mut output = Vec::new();
        run(&mut output, true).unwrap();

        unsafe {
            std::env::remove_var("GH_CONFIG_DIR");
            std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR");
            std::env::remove_var("AUTOMIC_VAULT_TEST_GH_CLI_PATH");
            std::env::remove_var("AUTOMIC_VAULT_TEST_GH_LEGACY_TOKEN");
        }
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("delete 1 exact legacy")
        );
        assert_eq!(
            fs::read_to_string(keychain.join("GH_TOKEN_GITHUB_COM")).unwrap(),
            "gho_secret"
        );
        assert_eq!(
            fs::read_to_string(keychain.join("GH_TOKEN_GITHUB_COM_MXCL")).unwrap(),
            "gho_secret"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn migration_destinations_union_multiple_accounts() {
        let credentials = vec![
            GhCredential {
                host: "github.com".into(),
                user: Some("monalisa".into()),
                token: "active-token".into(),
            },
            GhCredential {
                host: "github.com".into(),
                user: Some("hubot".into()),
                token: "other-token".into(),
            },
        ];
        let active_users =
            BTreeMap::from([("github.com".to_string(), Some("monalisa".to_string()))]);

        assert_eq!(
            migration_destinations(&credentials, &active_users).unwrap(),
            BTreeMap::from([
                (
                    "GH_TOKEN_GITHUB_COM".to_string(),
                    "active-token".to_string()
                ),
                (
                    "GH_TOKEN_GITHUB_COM_HUBOT".to_string(),
                    "other-token".to_string(),
                ),
                (
                    "GH_TOKEN_GITHUB_COM_MONALISA".to_string(),
                    "active-token".to_string(),
                ),
            ])
        );
    }

    #[test]
    fn migration_rejects_ambiguous_destination() {
        let credentials = vec![
            GhCredential {
                host: "github.com".into(),
                user: Some("mona-lisa".into()),
                token: "first".into(),
            },
            GhCredential {
                host: "github.com".into(),
                user: Some("mona_lisa".into()),
                token: "second".into(),
            },
        ];

        let error = migration_destinations(
            &credentials,
            &BTreeMap::from([("github.com".to_string(), None)]),
        )
        .unwrap_err();

        assert!(error.contains("refusing ambiguous GitHub credential destination"));
    }

    #[test]
    fn harden_preserves_sources_and_destination_on_conflict() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_path("gh-destination-conflict");
        let config = dir.join("config");
        let keychain = dir.join("keychain");
        let gh = dir.join("gh");
        fs::create_dir_all(&config).unwrap();
        fs::create_dir_all(&keychain).unwrap();
        fs::write(&gh, "").unwrap();
        fs::write(
            config.join("hosts.yml"),
            "github.com:\n    user: monalisa\n    oauth_token: incoming\n",
        )
        .unwrap();
        fs::write(keychain.join("GH_TOKEN_GITHUB_COM"), "working").unwrap();
        unsafe {
            std::env::set_var("GH_CONFIG_DIR", &config);
            std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain);
            std::env::set_var("AUTOMIC_VAULT_TEST_GH_CLI_PATH", &gh);
        }

        let error = run(&mut Vec::new(), true).unwrap_err();

        unsafe {
            std::env::remove_var("GH_CONFIG_DIR");
            std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR");
            std::env::remove_var("AUTOMIC_VAULT_TEST_GH_CLI_PATH");
        }
        assert!(error.contains("refusing to replace"));
        assert_eq!(
            fs::read_to_string(keychain.join("GH_TOKEN_GITHUB_COM")).unwrap(),
            "working"
        );
        assert!(
            fs::read_to_string(config.join("hosts.yml"))
                .unwrap()
                .contains("oauth_token: incoming")
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn harden_preserves_sources_and_skips_install_after_partial_store_failure() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_path("gh-partial-store-failure");
        let config = dir.join("config");
        let keychain = dir.join("keychain");
        let gh = dir.join("gh");
        fs::create_dir_all(&config).unwrap();
        fs::create_dir_all(&keychain).unwrap();
        fs::write(&gh, "original").unwrap();
        fs::write(
            config.join("hosts.yml"),
            "github.com:\n    user: monalisa\n    oauth_token: incoming\n",
        )
        .unwrap();
        fs::write(keychain.join("GH_TOKEN_GITHUB_COM_MONALISA"), "existing").unwrap();
        unsafe {
            std::env::set_var("GH_CONFIG_DIR", &config);
            std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain);
            std::env::set_var("AUTOMIC_VAULT_TEST_GH_CLI_PATH", &gh);
        }

        let error = run(&mut Vec::new(), true).unwrap_err();

        unsafe {
            std::env::remove_var("GH_CONFIG_DIR");
            std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR");
            std::env::remove_var("AUTOMIC_VAULT_TEST_GH_CLI_PATH");
        }
        assert!(error.contains("refusing to replace"));
        assert_eq!(
            fs::read_to_string(keychain.join("GH_TOKEN_GITHUB_COM")).unwrap(),
            "incoming"
        );
        assert_eq!(
            fs::read_to_string(keychain.join("GH_TOKEN_GITHUB_COM_MONALISA")).unwrap(),
            "existing"
        );
        assert!(
            fs::read_to_string(config.join("hosts.yml"))
                .unwrap()
                .contains("oauth_token: incoming")
        );
        assert_eq!(fs::read_to_string(&gh).unwrap(), "original");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn verifies_both_detector_postconditions() {
        assert!(ensure_postconditions(&[], &[]).is_ok());
        assert!(
            ensure_postconditions(&["plaintext".into()], &[])
                .unwrap_err()
                .contains("gh-cli-hosts-token")
        );
        assert!(
            ensure_postconditions(&[], &["keychain".into()])
                .unwrap_err()
                .contains("gh-cli-keychain-access")
        );
    }

    #[test]
    fn keychain_delete_error_identifies_item() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let security = temp_path("failing-security");
        fs::write(&security, "#!/bin/sh\nprintf denied >&2\nexit 1\n").unwrap();
        fs::set_permissions(&security, fs::Permissions::from_mode(0o700)).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_SECURITY_PATH", &security);
        }

        let err = security_delete_generic_password("StripeCLI", Some("uat")).unwrap_err();

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_SECURITY_PATH");
        }
        assert!(err.contains("service \"StripeCLI\", account Some(\"uat\")"));
        let _ = fs::remove_file(security);
    }

    #[test]
    fn vault_key_matches_gh_isotope() {
        assert_eq!(vault_key("github.com", None), "GH_TOKEN_GITHUB_COM");
        assert_eq!(
            vault_key("github.com", Some("mona-lisa")),
            "GH_TOKEN_GITHUB_COM_MONA_LISA"
        );
    }

    #[test]
    fn decodes_go_keyring_wrapped_tokens() {
        assert_eq!(
            decode_legacy_keychain_password("go-keyring-base64:Z2hvX3NlY3JldA==").as_deref(),
            Some("gho_secret")
        );
        assert_eq!(
            decode_legacy_keychain_password("go-keyring-encoded:67686f5f736563726574").as_deref(),
            Some("gho_secret")
        );
    }

    #[test]
    fn rejects_malformed_go_keyring_wrappers() {
        assert_eq!(
            decode_legacy_keychain_password("go-keyring-base64:not-base64"),
            None
        );
        assert_eq!(
            decode_legacy_keychain_password("go-keyring-encoded:not-hex"),
            None
        );
        assert_eq!(
            decode_legacy_keychain_password("go-keyring-base64:Z===x"),
            None
        );
        assert_eq!(
            decode_legacy_keychain_password("go-keyring-base64:/w=="),
            None
        );
        assert_eq!(
            decode_legacy_keychain_password("go-keyring-encoded:ff"),
            None
        );
    }

    #[test]
    fn preserves_unwrapped_legacy_tokens() {
        assert_eq!(
            decode_legacy_keychain_password("gho_secret").as_deref(),
            Some("gho_secret")
        );
    }

    fn temp_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("av-{label}-{}-{nanos}", std::process::id()))
    }
}
