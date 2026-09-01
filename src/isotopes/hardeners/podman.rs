use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::{Map, Value, json};

use super::{
    HardenerCommand, HardenerDetection, HardenerDiagnostic, RequiredExecutable,
    SecretGateDescriptor, SecretGateRoute,
};

const AV_PATH: &str = "/usr/local/bin/av";
const TARGET_PATH: &str = "/opt/podman/bin/podman";
const TEAM_IDENTIFIER: &str = "HYSCB8KRL2";
const DROP_IN: &str = "credential-helpers = [\"av-podman\"]\n";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

struct AuthState {
    path: PathBuf,
    existed: bool,
    original: Value,
    sanitized: Value,
    credentials: Vec<crate::cli::docker_credential::DockerCredential>,
}

pub(crate) fn run(stdout: &mut dyn Write, yes: bool) -> Result<(), String> {
    let testing = test_auth_path().is_some();
    super::PrivilegeMode::Mixed.require_user("podman", testing)?;
    reject_competing_config()?;
    reject_fallback_auth_sources()?;
    if !testing {
        crate::secrets::ensure_registry_helper_ready()?;
        verify_target(&target())?;
        super::docker::validate_helper_install_path(&helper_path())?;
    }

    let states = auth_states()?;
    let credentials = merge_credentials(&states)?;
    let markers = auth_markers(&states);
    let drop_in = drop_in_path()?;

    writeln!(stdout, "╭─ harden podman").ok();
    writeln!(stdout, "│").ok();
    writeln!(stdout, "├─ keep Red Hat's signed Podman client").ok();
    writeln!(stdout, "├─ install {}", helper_path().display()).ok();
    writeln!(
        stdout,
        "├─ select Automic Vault as Podman's registry credential helper"
    )
    .ok();
    writeln!(
        stdout,
        "├─ treat every remote registry request as a Secret Dump (upstream sends all credentials)"
    )
    .ok();
    if !credentials.is_empty() {
        writeln!(
            stdout,
            "├─ migrate {} registry credential{} without printing them",
            credentials.len(),
            if credentials.len() == 1 { "" } else { "s" }
        )
        .ok();
    }
    writeln!(stdout, "│").ok();
    if !super::gh_cli::confirm(stdout, yes)? {
        writeln!(stdout, "╰─ cancelled").ok();
        return Ok(());
    }

    for credential in credentials.values() {
        crate::secrets::store_secret_if_absent_or_equal(
            &crate::cli::docker_credential::secret_name(&credential.server_url),
            &credential.storage_json(),
        )?;
    }
    install_helper(testing)?;
    write_drop_in(&drop_in)?;
    for state in &states {
        if state.existed && state.original != state.sanitized {
            write_json(&state.path, &state.sanitized)?;
        }
    }
    for registry in &markers {
        add_helper_marker(registry)?;
    }
    verify_hardened_state()?;

    writeln!(stdout, "╰─ hardened podman").ok();
    super::write_secret_gate_notice(stdout, "podman");
    Ok(())
}

pub(crate) fn detect() -> HardenerDetection {
    let testing = test_auth_path().is_some();
    let target = target();
    let target_valid = testing || verify_target(&target).is_ok();
    let helper = helper_path();
    let helper_valid = podman_helper_valid(&helper, testing);
    let config_valid = reject_competing_config().is_ok()
        && reject_fallback_auth_sources().is_ok()
        && drop_in_path().is_ok_and(|path| drop_in_is_effective(&path))
        && auth_states().is_ok_and(|states| {
            states
                .iter()
                .all(|state| state.credentials.is_empty() && state.original == state.sanitized)
                && markers_are_discoverable(&states)
        });
    let hardened = target_valid && helper_valid && config_valid;
    let command = HardenerCommand {
        name: "podman".into(),
        hardened,
        stub_valid: helper_valid,
        stub_path: Some(helper.display().to_string()),
        target_path: target.display().to_string(),
        required_paths: if testing {
            Vec::new()
        } else {
            vec![RequiredExecutable {
                name: "Automic Vault CLI",
                path: AV_PATH.into(),
            }]
        },
        stub_requirements: Some(super::docker::stub_requirements(&helper, testing)),
        injected_keys: Vec::new(),
        assignment_keys: Vec::new(),
        isotope: None,
    };
    let mut detection = HardenerDetection::commands(hardened, vec![command]);
    detection.applicable =
        target.exists() || auth_paths().is_ok_and(|paths| paths.iter().any(|path| path.exists()));
    if target.exists() && !target_valid && !testing {
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "podman_vendor_cli_invalid",
            message: verify_target(&target).unwrap_err(),
            remediation: "Install or update Podman using Red Hat's official macOS installer, then rerun `av harden podman`.".into(),
            path: Some(target.display().to_string()),
        });
    }
    if detection.applicable && !config_valid {
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "podman_config_not_hardened",
            message: "Podman registry authentication is not in the supported Hardened State."
                .into(),
            remediation: "Rerun `av harden podman`; competing helpers and namespaced credentials must be resolved manually.".into(),
            path: drop_in_path().ok().map(|path| path.display().to_string()),
        });
    }
    detection
}

pub(crate) fn secret_gate() -> SecretGateDescriptor {
    SecretGateDescriptor {
        id: "podman",
        key_patterns: vec!["DOCKER_REGISTRY_CREDENTIAL_*".into()],
        routes: vec![SecretGateRoute {
            operation: "docker-get",
            script_path: None,
            target_path: target().display().to_string(),
            caller_identifiers: vec!["com.automicvault.av"],
            key_patterns: vec!["DOCKER_REGISTRY_CREDENTIAL_*".into()],
            replace_existing_env: false,
            allow_missing_keys: false,
        }],
    }
}

fn auth_states() -> Result<Vec<AuthState>, String> {
    auth_paths()?
        .into_iter()
        .map(|path| {
            let (existed, original) = read_json(&path)?;
            let (sanitized, credentials) = sanitize_auth(original.clone())?;
            Ok(AuthState {
                path,
                existed,
                original,
                sanitized,
                credentials,
            })
        })
        .collect()
}

fn merge_credentials(
    states: &[AuthState],
) -> Result<BTreeMap<String, crate::cli::docker_credential::DockerCredential>, String> {
    let mut merged = BTreeMap::new();
    for credential in states.iter().flat_map(|state| &state.credentials) {
        match merged.get(&credential.server_url) {
            Some(existing) if existing != credential => {
                return Err(format!(
                    "conflicting Podman credentials exist for {}",
                    credential.server_url
                ));
            }
            _ => {
                merged.insert(credential.server_url.clone(), credential.clone());
            }
        }
    }
    Ok(merged)
}

fn auth_markers(states: &[AuthState]) -> BTreeSet<String> {
    states
        .iter()
        .filter_map(|state| state.sanitized.get("credHelpers")?.as_object())
        .flat_map(|helpers| helpers.keys().cloned())
        .collect()
}

fn markers_are_discoverable(states: &[AuthState]) -> bool {
    helper_markers().is_ok_and(|primary| {
        auth_markers(states)
            .iter()
            .all(|registry| primary.contains_key(registry))
    })
}

fn sanitize_auth(
    mut value: Value,
) -> Result<(Value, Vec<crate::cli::docker_credential::DockerCredential>), String> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| "registry auth config must be a JSON object".to_string())?;
    let mut markers = match object.get("credHelpers") {
        Some(Value::Object(helpers)) => {
            let mut markers = Map::new();
            for (registry, helper) in helpers {
                if helper.as_str() != Some("av-podman") {
                    return Err(
                        "competing registry credential helpers are not supported yet".into(),
                    );
                }
                markers.insert(
                    normalize_registry(registry)?,
                    Value::String("av-podman".into()),
                );
            }
            markers
        }
        Some(_) => return Err("registry `credHelpers` must be an object".into()),
        None => Map::new(),
    };
    if !object.contains_key("auths") {
        if markers.is_empty() {
            object.remove("credHelpers");
        } else {
            object.insert("credHelpers".into(), Value::Object(markers));
        }
        return Ok((value, Vec::new()));
    }
    let auths = object.get_mut("auths").expect("checked above");
    let auths = auths
        .as_object_mut()
        .ok_or_else(|| "Podman `auths` must be an object".to_string())?;
    let mut credentials = Vec::new();
    for (registry, entry) in auths.iter() {
        let entry = entry
            .as_object()
            .ok_or_else(|| format!("Podman credential for {registry} must be an object"))?;
        if entry
            .keys()
            .any(|key| !["auth", "identitytoken", "identityToken"].contains(&key.as_str()))
        {
            return Err(format!(
                "Podman credential for {registry} contains unsupported fields"
            ));
        }
        let auth = optional_string(entry, "auth")?;
        let identity =
            optional_string(entry, "identitytoken")?.or(optional_string(entry, "identityToken")?);
        if auth.is_some() && identity.is_some() {
            return Err(format!(
                "Podman credential for {registry} contains both basic and identity credentials"
            ));
        }
        let Some((username, secret)) = auth
            .map(decode_auth)
            .transpose()?
            .or_else(|| identity.map(|secret| ("<token>".into(), secret)))
        else {
            continue;
        };
        let server_url = normalize_registry(registry)?;
        markers.insert(server_url.clone(), Value::String("av-podman".into()));
        credentials.push(crate::cli::docker_credential::DockerCredential {
            server_url,
            username,
            secret,
        });
    }
    auths.clear();
    object.remove("auths");
    if !markers.is_empty() {
        object.insert("credHelpers".into(), Value::Object(markers));
    }
    Ok((value, credentials))
}

fn optional_string(entry: &Map<String, Value>, key: &str) -> Result<Option<String>, String> {
    match entry.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(format!("Podman credential field `{key}` must be a string")),
    }
}

fn decode_auth(encoded: String) -> Result<(String, String), String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "Podman credential contains invalid base64".to_string())?;
    let decoded = String::from_utf8(decoded)
        .map_err(|_| "Podman credential is not valid UTF-8".to_string())?;
    let (username, secret) = decoded
        .split_once(':')
        .ok_or_else(|| "Podman credential has no username/password separator".to_string())?;
    if username.is_empty() || secret.is_empty() || username.contains('\0') || secret.contains('\0')
    {
        return Err("Podman credential has an empty or invalid username/password".into());
    }
    Ok((username.into(), secret.into()))
}

fn normalize_registry(value: &str) -> Result<String, String> {
    let (registry, had_scheme) = value
        .strip_prefix("https://")
        .map(|value| (value, true))
        .or_else(|| value.strip_prefix("http://").map(|value| (value, true)))
        .unwrap_or((value, false));
    let registry = if had_scheme {
        let (authority, path) = registry.split_once('/').unwrap_or((registry, ""));
        let legacy_docker_path = matches!(
            (authority, path),
            (
                "docker.io" | "index.docker.io" | "registry-1.docker.io",
                "v1" | "v1/"
            )
        );
        if !path.is_empty() && !legacy_docker_path {
            return Err(format!(
                "namespaced Podman credential `{value}` cannot be preserved by an external helper"
            ));
        }
        authority
    } else {
        if registry.contains('/') {
            return Err(format!(
                "namespaced Podman credential `{value}` cannot be preserved by an external helper"
            ));
        }
        registry
    };
    let registry = match registry {
        "docker.io" | "registry-1.docker.io" => "index.docker.io",
        registry => registry,
    };
    if registry.is_empty()
        || registry.len() > 2048
        || registry
            .bytes()
            .any(|byte| matches!(byte, 0 | b'\r' | b'\n' | b'?' | b'#' | b'@'))
    {
        return Err("invalid Podman registry address".into());
    }
    Ok(registry.into())
}

fn auth_paths() -> Result<Vec<PathBuf>, String> {
    if let Some(path) = test_auth_path() {
        return Ok(vec![path]);
    }
    let mut unique = BTreeSet::new();
    let paths = crate::isotopes::detectors::podman_auth_paths()?
        .into_iter()
        .filter(|path| unique.insert(path.clone()))
        .collect::<Vec<_>>();
    if let Some(path) = paths.iter().find(|path| !path.is_absolute()) {
        return Err(format!(
            "Podman auth path must be absolute: {}",
            path.display()
        ));
    }
    Ok(paths)
}

fn test_auth_path() -> Option<PathBuf> {
    crate::test_env_var("AUTOMIC_VAULT_TEST_PODMAN_AUTH").map(PathBuf::from)
}

fn target() -> PathBuf {
    crate::test_env_var("AUTOMIC_VAULT_TEST_PODMAN_TARGET")
        .map(PathBuf::from)
        .unwrap_or_else(|| TARGET_PATH.into())
}

fn helper_path() -> PathBuf {
    crate::cli::docker_credential::podman_helper_path()
}

fn podman_helper_valid(path: &Path, testing: bool) -> bool {
    let metadata = fs::symlink_metadata(path).ok();
    crate::cli::docker_credential::podman_helper_stub_valid(path)
        && metadata.as_ref().is_some_and(|metadata| {
            metadata.permissions().mode() & 0o777 == 0o755
                && (testing
                    || (metadata.uid() == 0
                        && super::docker::validate_helper_install_path(path).is_ok()))
        })
}

fn install_helper(testing: bool) -> Result<(), String> {
    if testing {
        return super::docker::install_stub(
            &helper_path(),
            crate::cli::docker_credential::podman_helper_stub(),
        );
    }
    super::env_wrapper::validate_privileged_av(Path::new(AV_PATH))?;
    let revision = Command::new(AV_PATH)
        .arg("__version")
        .output()
        .map_err(|error| format!("failed to check {AV_PATH}: {error}"))?;
    if !revision.status.success()
        || std::str::from_utf8(&revision.stdout)
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
            != Some(crate::cli::INSTALL_REVISION)
    {
        return Err("update the av CLI from the Automic Vault app before hardening Podman".into());
    }
    let status = Command::new("/usr/bin/sudo")
        .args([AV_PATH, "__install-podman-helper"])
        .status()
        .map_err(|error| format!("failed to run sudo: {error}"))?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| format!("Podman helper installation failed: {status}"))
}

pub(crate) fn install_privileged() -> Result<(), String> {
    if test_auth_path().is_some()
        || crate::test_env_var("AUTOMIC_VAULT_TEST_PODMAN_HELPER_PATH").is_some()
    {
        return Err("test path overrides are forbidden during privileged installation".into());
    }
    if super::effective_uid() != 0 {
        return Err("Podman helper installation requires root".into());
    }
    let path = helper_path();
    super::docker::validate_helper_install_path(&path)?;
    super::docker::install_stub(&path, crate::cli::docker_credential::podman_helper_stub())
}

pub(crate) fn helper_markers() -> Result<BTreeMap<String, String>, String> {
    let (_, value) = read_json(&primary_auth_path()?)?;
    let (value, credentials) = sanitize_auth(value)?;
    if !credentials.is_empty() {
        return Err("Podman auth file contains unmigrated credentials".into());
    }
    Ok(value
        .get("credHelpers")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .map(|(registry, _)| (registry.clone(), String::new()))
        .collect())
}

pub(crate) fn add_helper_marker(registry: &str) -> Result<(), String> {
    update_helper_marker(registry, true)
}

pub(crate) fn remove_helper_marker(registry: &str) -> Result<(), String> {
    update_helper_marker(registry, false)
}

fn update_helper_marker(registry: &str, add: bool) -> Result<(), String> {
    if normalize_registry(registry)? != registry {
        return Err("Podman helper received a non-canonical registry".into());
    }
    let path = primary_auth_path()?;
    let (_, value) = read_json(&path)?;
    let (mut value, credentials) = sanitize_auth(value)?;
    if !credentials.is_empty() {
        return Err("Podman auth file contains unmigrated credentials".into());
    }
    let object = value.as_object_mut().expect("sanitized object");
    let helpers = object
        .entry("credHelpers")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .expect("sanitized helpers");
    if add {
        helpers.insert(registry.into(), Value::String("av-podman".into()));
    } else {
        helpers.remove(registry);
        if helpers.is_empty() {
            object.remove("credHelpers");
        }
    }
    write_json(&path, &value)
}

fn primary_auth_path() -> Result<PathBuf, String> {
    if let Some(path) = test_auth_path() {
        return Ok(path);
    }
    auth_paths()?
        .into_iter()
        .next()
        .ok_or_else(|| "Podman has no registry auth path".into())
}

fn drop_in_path() -> Result<PathBuf, String> {
    if let Some(path) = crate::test_env_var("AUTOMIC_VAULT_TEST_PODMAN_DROP_IN") {
        return Ok(path.into());
    }
    let root = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .map(|home| home.join(".config"))
        })
        .ok_or_else(|| "HOME is not set".to_string())?;
    if !root.is_absolute() {
        return Err(format!(
            "Podman config path must be absolute: {}",
            root.display()
        ));
    }
    Ok(root.join("containers/registries.conf.d/999-automic-vault.conf"))
}

fn reject_competing_config() -> Result<(), String> {
    if std::env::var_os("CONTAINERS_REGISTRIES_CONF").is_some_and(|value| !value.is_empty()) {
        return Err("CONTAINERS_REGISTRIES_CONF bypasses the Podman hardener configuration".into());
    }
    Ok(())
}

fn reject_fallback_auth_sources() -> Result<(), String> {
    if test_auth_path().is_some()
        || std::env::var_os("REGISTRY_AUTH_FILE").is_some_and(|value| !value.is_empty())
    {
        return Ok(());
    }
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())?;
    let docker = std::env::var_os("DOCKER_CONFIG")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".docker"))
        .join("config.json");
    let (exists, value) = read_json(&docker)?;
    if exists {
        let (_, credentials) = sanitize_auth(value).map_err(|error| {
            format!("Docker's fallback auth config must be hardened before Podman: {error}")
        })?;
        if !credentials.is_empty() {
            return Err(
                "Docker's fallback auth config contains credentials; harden or remove that fallback before Podman"
                    .into(),
            );
        }
    }
    let legacy = home.join(".dockercfg");
    let (exists, value) = read_json(&legacy)?;
    if exists && value.as_object().is_some_and(|object| !object.is_empty()) {
        return Err(format!(
            "legacy Docker fallback {} must be removed before hardening Podman",
            legacy.display()
        ));
    }
    Ok(())
}

fn drop_in_is_effective(path: &Path) -> bool {
    if fs::read_to_string(path).ok().as_deref() != Some(DROP_IN) {
        return false;
    }
    let Some(directory) = path.parent() else {
        return false;
    };
    let Ok(entries) = fs::read_dir(directory) else {
        return false;
    };
    !entries.filter_map(Result::ok).any(|entry| {
        let candidate = entry.path();
        candidate.extension().and_then(|value| value.to_str()) == Some("conf")
            && candidate.file_name() > path.file_name()
            && fs::read_to_string(candidate).map_or(true, |contents| {
                toml::from_str::<toml::Value>(&contents).map_or(true, |value| {
                    value
                        .as_table()
                        .is_some_and(|table| table.contains_key("credential-helpers"))
                })
            })
    })
}

fn write_drop_in(path: &Path) -> Result<(), String> {
    if path.exists() && fs::read_to_string(path).ok().as_deref() != Some(DROP_IN) {
        return Err(format!(
            "refusing to replace unexpected Podman config {}",
            path.display()
        ));
    }
    write_bytes(path, DROP_IN.as_bytes())?;
    if !drop_in_is_effective(path) {
        return Err("a later Podman registry config overrides Automic Vault's helper".into());
    }
    Ok(())
}

fn read_json(path: &Path) -> Result<(bool, Value), String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((false, json!({})));
        }
        Err(error) => return Err(format!("failed to open {}: {error}", path.display())),
    };
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.len() > MAX_CONFIG_BYTES
        || metadata.uid() != super::effective_uid()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(format!(
            "refusing unsafe registry auth file {}",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err("registry auth file exceeds 1 MiB".into());
    }
    serde_json::from_slice(&bytes)
        .map(|value| (true, value))
        .map_err(|error| format!("invalid registry auth file {}: {error}", path.display()))
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to encode Podman auth config: {error}"))?;
    bytes.push(b'\n');
    write_bytes(path, &bytes)
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("config path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    let staging = parent.join(format!(
        ".{}.av.{}.{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config"),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&staging)
            .map_err(|error| format!("failed to create {}: {error}", staging.display()))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("failed to write {}: {error}", staging.display()))?;
        fs::rename(&staging, path)
            .map_err(|error| format!("failed to replace {}: {error}", path.display()))?;
        OpenOptions::new()
            .read(true)
            .open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("failed to sync {}: {error}", parent.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(staging);
    }
    result
}

fn verify_hardened_state() -> Result<(), String> {
    let path = drop_in_path()?;
    let states = auth_states()?;
    if !drop_in_is_effective(&path)
        || states
            .iter()
            .any(|state| !state.credentials.is_empty() || state.original != state.sanitized)
        || !markers_are_discoverable(&states)
    {
        return Err("Podman hardening postcondition failed".into());
    }
    Ok(())
}

fn verify_target(path: &Path) -> Result<(), String> {
    if path != Path::new(TARGET_PATH) {
        return Err(format!("Podman must be installed at {TARGET_PATH}"));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err("official Podman executable is not a protected root-owned file".into());
    }
    for ancestor in path.parent().into_iter().flat_map(Path::ancestors) {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|error| format!("failed to inspect {}: {error}", ancestor.display()))?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(format!(
                "official Podman path crosses unsafe directory {}",
                ancestor.display()
            ));
        }
    }
    let requirement = format!(
        "=identifier \"podman\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"{TEAM_IDENTIFIER}\""
    );
    let status = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "-R", &requirement])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("failed to verify Podman: {error}"))?;
    if !status.success() {
        return Err("Podman Developer ID signature is invalid".into());
    }
    let details = codesign_output(&["-d", "-vvv"], path)?;
    for required in [
        "flags=0x10000(runtime)",
        "Authority=Developer ID Application: Red Hat, Inc. (HYSCB8KRL2)",
        "TeamIdentifier=HYSCB8KRL2",
        "Timestamp=",
    ] {
        if !details.contains(required) {
            return Err(format!("Podman signature did not confirm {required:?}"));
        }
    }
    let entitlements = codesign_output(&["-d", "--entitlements", ":-"], path)?;
    if entitlements.contains("<key>") {
        return Err("Podman executable has unexpected entitlements".into());
    }
    Ok(())
}

fn codesign_output(args: &[&str], path: &Path) -> Result<String, String> {
    let output = Command::new("/usr/bin/codesign")
        .args(args)
        .arg(path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(text)
    } else {
        Err(format!(
            "failed to inspect Podman signature: {}",
            text.trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_registry_credentials_and_rejects_lossy_cases() {
        let (sanitized, credentials) = sanitize_auth(json!({
            "auths": {
                "docker.io": {"auth": "dXNlcjp0b2tlbg=="},
                "quay.io": {"identitytoken": "identity"}
            }
        }))
        .unwrap();
        assert_eq!(
            sanitized,
            json!({"credHelpers": {
                "index.docker.io": "av-podman",
                "quay.io": "av-podman"
            }})
        );
        assert_eq!(credentials.len(), 2);
        assert_eq!(credentials[0].server_url, "index.docker.io");
        assert_eq!(credentials[0].username, "user");
        assert_eq!(credentials[1].username, "<token>");
        assert!(
            sanitize_auth(json!({
                "auths": {"quay.io/team": {"auth": "dXNlcjp0b2tlbg=="}}
            }))
            .is_err()
        );
        assert!(normalize_registry("https://quay.io/team").is_err());
        assert!(normalize_registry("https://quay.io?scope=team").is_err());
        assert_eq!(
            normalize_registry("https://index.docker.io/v1/").unwrap(),
            "index.docker.io"
        );
        assert!(
            sanitize_auth(json!({
                "credHelpers": {"quay.io": "osxkeychain"}
            }))
            .is_err()
        );
        assert!(decode_auth("dXNlcjp0b2tlbgA=".into()).is_err());
    }

    #[test]
    fn normalizes_existing_helper_markers() {
        let (sanitized, credentials) = sanitize_auth(json!({
            "credHelpers": {
                "docker.io": "av-podman",
                "index.docker.io": "av-podman"
            }
        }))
        .unwrap();

        assert!(credentials.is_empty());
        assert_eq!(
            sanitized,
            json!({"credHelpers": {"index.docker.io": "av-podman"}})
        );
    }

    #[test]
    fn later_helper_override_is_not_hardened() {
        let root = std::env::temp_dir().join(format!("av-podman-drop-in-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let ours = root.join("999-automic-vault.conf");
        fs::write(&ours, DROP_IN).unwrap();
        assert!(drop_in_is_effective(&ours));
        fs::write(root.join("zzz.conf"), "credential-helpers = [\"other\"]\n").unwrap();
        assert!(!drop_in_is_effective(&ours));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn xdg_paths_are_selected_and_relative_paths_fail_closed() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let names = [
            "HOME",
            "XDG_RUNTIME_DIR",
            "XDG_CONFIG_HOME",
            "REGISTRY_AUTH_FILE",
            "AUTOMIC_VAULT_TEST_PODMAN_AUTH",
            "AUTOMIC_VAULT_TEST_PODMAN_DROP_IN",
        ];
        let previous = names.map(|name| std::env::var_os(name));
        unsafe {
            std::env::set_var("HOME", "/tmp/av-podman-home");
            std::env::set_var("XDG_RUNTIME_DIR", "/tmp/av-podman-runtime");
            std::env::set_var("XDG_CONFIG_HOME", "/tmp/av-podman-config");
            for name in &names[3..] {
                std::env::remove_var(name);
            }
        }
        assert_eq!(
            primary_auth_path().unwrap(),
            Path::new("/tmp/av-podman-runtime/containers/auth.json")
        );
        assert_eq!(
            drop_in_path().unwrap(),
            Path::new("/tmp/av-podman-config/containers/registries.conf.d/999-automic-vault.conf")
        );
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", "relative") };
        assert!(primary_auth_path().is_err());
        unsafe {
            std::env::set_var("XDG_RUNTIME_DIR", "/tmp/av-podman-runtime");
            std::env::set_var("XDG_CONFIG_HOME", "relative");
        }
        assert!(drop_in_path().is_err());

        unsafe {
            for (name, value) in names.into_iter().zip(previous) {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    #[test]
    fn hardening_migrates_auth_and_configures_shared_helper() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root = std::env::temp_dir().join(format!("av-podman-hardener-{}", std::process::id()));
        let auth = root.join("auth.json");
        let drop_in = root.join("registries.conf.d/999-automic-vault.conf");
        let helper = root.join("docker-credential-av-podman");
        let keychain = root.join("keychain");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(
            &auth,
            r#"{"auths":{"quay.io":{"auth":"dXNlcjp0b2tlbg=="}}}"#,
        )
        .unwrap();
        let previous_registries_conf = std::env::var_os("CONTAINERS_REGISTRIES_CONF");
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_PODMAN_AUTH", &auth);
            std::env::set_var("AUTOMIC_VAULT_TEST_PODMAN_DROP_IN", &drop_in);
            std::env::set_var("AUTOMIC_VAULT_TEST_PODMAN_HELPER_PATH", &helper);
            std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain);
            std::env::remove_var("CONTAINERS_REGISTRIES_CONF");
        }

        run(&mut Vec::new(), true).unwrap();

        assert_eq!(fs::read_to_string(&drop_in).unwrap(), DROP_IN);
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&auth).unwrap()).unwrap(),
            json!({"credHelpers": {"quay.io": "av-podman"}})
        );
        let saved = fs::read_to_string(
            keychain.join(crate::cli::docker_credential::secret_name("quay.io")),
        )
        .unwrap();
        assert_eq!(
            crate::cli::docker_credential::parse_credential(&saved)
                .unwrap()
                .secret,
            "token"
        );
        assert!(super::detect().hardened);

        unsafe {
            for name in [
                "AUTOMIC_VAULT_TEST_PODMAN_AUTH",
                "AUTOMIC_VAULT_TEST_PODMAN_DROP_IN",
                "AUTOMIC_VAULT_TEST_PODMAN_HELPER_PATH",
                "AUTOMIC_VAULT_TEST_KEYCHAIN_DIR",
            ] {
                std::env::remove_var(name);
            }
            if let Some(value) = previous_registries_conf {
                std::env::set_var("CONTAINERS_REGISTRIES_CONF", value);
            }
        }
        let _ = fs::remove_dir_all(root);
    }
}
