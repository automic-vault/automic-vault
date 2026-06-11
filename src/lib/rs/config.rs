use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

const DEFAULT_AUDIT_MAX_BYTES: u64 = 8 * 1024 * 1024;
const AUDIT_LOG_RELATIVE: &str = "Library/Logs/av/audit.jsonl";
const AUDIT_CONFIG_RELATIVE: &str = "Library/Application Support/Automic Vault/audit-config.json";

const DEBUG_OPT_ROOT: &str = "/tmp/opt";
const DEBUG_BIN_ROOT: &str = "/tmp/usr/local/bin";
const RELEASE_OPT_ROOT: &str = "/opt";
const RELEASE_BIN_ROOT: &str = "/usr/local/bin";
const FORMULA_API_ROOT: &str = "https://formulae.brew.sh/api/formula";
const PYPI_ROOT: &str = "https://pypi.org/pypi";
const GITHUB_API_ROOT: &str = "https://api.github.com";
const NPM_REGISTRY_ROOT: &str = "https://registry.npmjs.org";

pub(crate) fn opt_pkg_root() -> PathBuf {
    if cfg!(debug_assertions) {
        return PathBuf::from(DEBUG_OPT_ROOT);
    }
    PathBuf::from(RELEASE_OPT_ROOT)
}

pub(crate) fn opt_npm_root() -> PathBuf {
    opt_pkg_root().join("npm")
}

pub(crate) fn opt_pip_root() -> PathBuf {
    opt_pkg_root().join("pip")
}

pub(crate) fn managed_bin_root() -> PathBuf {
    if cfg!(debug_assertions) {
        return PathBuf::from(DEBUG_BIN_ROOT);
    }
    PathBuf::from(RELEASE_BIN_ROOT)
}

pub(crate) fn install_requires_root() -> bool {
    !cfg!(debug_assertions)
}

pub(crate) fn homebrew_debug_allowance_enabled() -> bool {
    cfg!(debug_assertions)
}

pub(crate) fn formula_api_root() -> String {
    endpoint_overrides()
        .formula_api_root
        .clone()
        .unwrap_or_else(|| FORMULA_API_ROOT.to_string())
}

pub(crate) fn pypi_root() -> String {
    endpoint_overrides()
        .pypi_root
        .clone()
        .unwrap_or_else(|| PYPI_ROOT.to_string())
}

pub(crate) fn github_api_root() -> String {
    endpoint_overrides()
        .github_api_root
        .clone()
        .unwrap_or_else(|| GITHUB_API_ROOT.to_string())
}

pub(crate) fn npm_registry_root() -> String {
    endpoint_overrides()
        .npm_registry_root
        .clone()
        .unwrap_or_else(|| NPM_REGISTRY_ROOT.to_string())
}

/// Whether the audit log is enabled. Default OFF (opt-in). `AV_AUDIT=1|on|true`
/// or `=0|off|false` overrides everything; otherwise a test override applies.
pub(crate) fn audit_enabled() -> bool {
    // Precedence: AV_AUDIT env (one-shot / CI override) > test override >
    // persisted config file (`av audit enable`/`disable`) > default OFF.
    if let Some(flag) = env_flag("AV_AUDIT") {
        return flag;
    }
    if let Some(enabled) = audit_overrides().enabled {
        return enabled;
    }
    read_audit_config().enabled.unwrap_or(false)
}

/// Resolved path to the active audit log. Honors `AV_AUDIT_PATH`, then a test
/// override, then `~/Library/Logs/av/audit.jsonl`.
pub(crate) fn audit_log_path() -> Result<PathBuf, String> {
    if let Some(value) = env::var_os("AV_AUDIT_PATH") {
        if !value.is_empty() {
            return Ok(PathBuf::from(value));
        }
    }
    if let Some(path) = audit_overrides().path {
        return Ok(path);
    }
    let home = env::var_os("HOME").ok_or_else(|| "HOME is not set".to_string())?;
    Ok(PathBuf::from(home).join(AUDIT_LOG_RELATIVE))
}

/// Whether to enable the Keychain-backed HMAC tamper-evidence layer.
pub(crate) fn audit_hmac_enabled() -> bool {
    env_flag("AV_AUDIT_HMAC").unwrap_or(false)
}

/// Whether to drop argv/cwd from records (they can carry a user-supplied secret
/// on the command line, e.g. `--token=...`).
pub(crate) fn audit_redact_argv() -> bool {
    env_flag("AV_AUDIT_NO_ARGV").unwrap_or(false)
}

/// Rotation threshold in bytes (0 disables rotation).
pub(crate) fn audit_max_bytes() -> u64 {
    env::var("AV_AUDIT_MAX_BYTES")
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(DEFAULT_AUDIT_MAX_BYTES)
}

/// On-disk audit config. Extensible; only the on/off toggle is wired today.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
struct AuditFileConfig {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    enabled: Option<bool>,
}

/// Path to the persisted audit config file. Honors `AV_AUDIT_CONFIG_PATH`, then
/// a test override, then `~/Library/Application Support/Automic Vault/audit-config.json`.
pub(crate) fn audit_config_path() -> Result<PathBuf, String> {
    if let Some(value) = env::var_os("AV_AUDIT_CONFIG_PATH") {
        if !value.is_empty() {
            return Ok(PathBuf::from(value));
        }
    }
    if let Some(path) = audit_overrides().config_path {
        return Ok(path);
    }
    let home = env::var_os("HOME").ok_or_else(|| "HOME is not set".to_string())?;
    Ok(PathBuf::from(home).join(AUDIT_CONFIG_RELATIVE))
}

/// Best-effort read of the audit config file (missing/invalid -> defaults).
fn read_audit_config() -> AuditFileConfig {
    let Ok(path) = audit_config_path() else {
        return AuditFileConfig::default();
    };
    match fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => AuditFileConfig::default(),
    }
}

/// Persist the on/off toggle to the audit config file (file mode 0600). Returns
/// the path written. Used by `av audit enable`/`disable`.
pub(crate) fn set_persisted_audit_enabled(enabled: bool) -> Result<PathBuf, String> {
    let path = audit_config_path()?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|err| format!("failed to create {}: {err}", dir.display()))?;
    }
    let mut config = read_audit_config();
    config.enabled = Some(enabled);
    let json = serde_json::to_string_pretty(&config)
        .map_err(|err| format!("failed to serialize audit config: {err}"))?;
    fs::write(&path, format!("{json}\n"))
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    Ok(path)
}

fn env_flag(key: &str) -> Option<bool> {
    let value = env::var(key).ok()?;
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "on" | "true" | "yes" => Some(true),
        "0" | "off" | "false" | "no" => Some(false),
        _ => None,
    }
}

#[derive(Clone, Default)]
struct AuditOverrides {
    enabled: Option<bool>,
    path: Option<PathBuf>,
    config_path: Option<PathBuf>,
}

static AUDIT_OVERRIDES: OnceLock<Mutex<AuditOverrides>> = OnceLock::new();

fn audit_overrides() -> AuditOverrides {
    AUDIT_OVERRIDES
        .get_or_init(|| Mutex::new(AuditOverrides::default()))
        .lock()
        .unwrap()
        .clone()
}

#[cfg(test)]
pub(crate) fn set_test_audit_overrides(
    enabled: Option<bool>,
    path: Option<PathBuf>,
    config_path: Option<PathBuf>,
) {
    *AUDIT_OVERRIDES
        .get_or_init(|| Mutex::new(AuditOverrides::default()))
        .lock()
        .unwrap() = AuditOverrides {
        enabled,
        path,
        config_path,
    };
}

#[cfg(test)]
pub(crate) fn clear_test_audit_overrides() {
    *AUDIT_OVERRIDES
        .get_or_init(|| Mutex::new(AuditOverrides::default()))
        .lock()
        .unwrap() = AuditOverrides::default();
}

#[derive(Clone, Default)]
struct EndpointOverrides {
    formula_api_root: Option<String>,
    pypi_root: Option<String>,
    github_api_root: Option<String>,
    npm_registry_root: Option<String>,
}

static ENDPOINT_OVERRIDES: OnceLock<Mutex<EndpointOverrides>> = OnceLock::new();

fn endpoint_overrides() -> EndpointOverrides {
    ENDPOINT_OVERRIDES
        .get_or_init(|| Mutex::new(EndpointOverrides::default()))
        .lock()
        .unwrap()
        .clone()
}

#[cfg(test)]
pub(crate) fn set_test_endpoint_overrides(overrides: TestEndpointOverrides) {
    *ENDPOINT_OVERRIDES
        .get_or_init(|| Mutex::new(EndpointOverrides::default()))
        .lock()
        .unwrap() = EndpointOverrides {
        formula_api_root: overrides.formula_api_root,
        pypi_root: overrides.pypi_root,
        github_api_root: overrides.github_api_root,
        npm_registry_root: overrides.npm_registry_root,
    };
}

#[cfg(test)]
pub(crate) fn clear_test_endpoint_overrides() {
    *ENDPOINT_OVERRIDES
        .get_or_init(|| Mutex::new(EndpointOverrides::default()))
        .lock()
        .unwrap() = EndpointOverrides::default();
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestEndpointOverrides {
    pub(crate) formula_api_root: Option<String>,
    pub(crate) pypi_root: Option<String>,
    pub(crate) github_api_root: Option<String>,
    pub(crate) npm_registry_root: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct OverrideGuard;

    impl OverrideGuard {
        fn set(overrides: TestEndpointOverrides) -> Self {
            set_test_endpoint_overrides(overrides);
            Self
        }
    }

    impl Drop for OverrideGuard {
        fn drop(&mut self) {
            clear_test_endpoint_overrides();
        }
    }

    #[test]
    fn config_debug_roots_match_expected_layout() {
        assert_eq!(opt_pkg_root(), PathBuf::from("/tmp/opt"));
        assert_eq!(opt_npm_root(), PathBuf::from("/tmp/opt/npm"));
        assert_eq!(opt_pip_root(), PathBuf::from("/tmp/opt/pip"));
        assert_eq!(managed_bin_root(), PathBuf::from("/tmp/usr/local/bin"));
        assert!(!install_requires_root());
        assert!(homebrew_debug_allowance_enabled());
    }

    #[test]
    fn config_endpoint_overrides_replace_default_roots() {
        let _guard = OverrideGuard::set(TestEndpointOverrides {
            formula_api_root: Some("https://formula.example.test".to_string()),
            pypi_root: Some("https://pypi.example.test".to_string()),
            github_api_root: Some("https://github.example.test".to_string()),
            npm_registry_root: Some("https://npm.example.test".to_string()),
        });

        assert_eq!(formula_api_root(), "https://formula.example.test");
        assert_eq!(pypi_root(), "https://pypi.example.test");
        assert_eq!(github_api_root(), "https://github.example.test");
        assert_eq!(npm_registry_root(), "https://npm.example.test");
    }
}
