use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

use super::{
    HardenerCommand, HardenerDetection, HardenerDiagnostic, RequiredExecutable, RequiredIdentity,
    SecretGateDescriptor, SecretGateRoute, StubRequirements,
};

const AV_PATH: &str = "/usr/local/bin/av";
const SUDO_PATH: &str = "/usr/bin/sudo";
const DOCKER_APP: &str = "/Applications/Docker.app";
const DOCKER_TEAM: &str = "9BNSXJN65R";
const MAX_CONFIG: u64 = 1024 * 1024;
const MAX_HELPER_OUTPUT: u64 = 1024 * 1024;
const PRIVILEGE_MODE: super::PrivilegeMode = super::PrivilegeMode::Mixed;

const TARGETS: [(&str, &str, &str); 3] = [
    (
        "docker",
        "/Applications/Docker.app/Contents/Resources/bin/docker",
        "docker",
    ),
    (
        "docker-compose",
        "/Applications/Docker.app/Contents/Resources/cli-plugins/docker-compose",
        "docker-compose",
    ),
    (
        "docker-buildx",
        "/Applications/Docker.app/Contents/Resources/cli-plugins/docker-buildx",
        "docker-buildx",
    ),
];

pub(crate) fn run(stdout: &mut dyn Write, yes: bool) -> Result<(), String> {
    let testing = test_config_path().is_some();
    PRIVILEGE_MODE.require_user("docker", testing)?;
    if !testing {
        crate::secrets::ensure_registry_helper_ready()?;
        verify_vendor_install()?;
        validate_helper_install_path(&helper_path())?;
    }
    let path = config_path()?;
    let mut config = read_config(&path)?;
    let old_store = validate_config(&config)?;
    let credentials = match old_store.as_deref() {
        Some("av") | None => Vec::new(),
        Some(store) => read_legacy_credentials(store)?,
    };

    writeln!(stdout, "╭─ harden docker").ok();
    writeln!(stdout, "│").ok();
    writeln!(stdout, "├─ keep Docker Desktop's vendor-signed CLI").ok();
    writeln!(stdout, "├─ install {}", helper_path().display()).ok();
    if let Some(store) = old_store.as_deref().filter(|store| *store != "av") {
        writeln!(
            stdout,
            "├─ migrate {} credential{} from `{store}` without printing them",
            credentials.len(),
            if credentials.len() == 1 { "" } else { "s" }
        )
        .ok();
    }
    writeln!(stdout, "├─ set Docker's credential store to `av`").ok();
    writeln!(stdout, "│").ok();
    if !confirm(stdout, yes)? {
        writeln!(stdout, "╰─ cancelled").ok();
        return Ok(());
    }

    for credential in &credentials {
        crate::secrets::store_secret_if_absent_or_equal(
            &crate::cli::docker_credential::secret_name(&credential.server_url),
            &credential.storage_json(),
        )?;
    }
    install_shared_helper(testing)?;
    let source = old_store
        .as_deref()
        .filter(|store| *store != "av")
        .map(source_helper)
        .transpose()?;
    let mut erased = Vec::new();
    if let Some(source) = source.as_deref() {
        for credential in &credentials {
            erased.push(credential);
            if let Err(error) = helper_action(source, "erase", &credential.server_url) {
                return Err(with_rollback(
                    "legacy Docker credential deletion failed",
                    error,
                    restore_legacy(source, &erased),
                ));
            }
        }
    }
    config
        .as_object_mut()
        .expect("validated config")
        .insert("credsStore".into(), Value::String("av".into()));
    if let Err(error) = write_config(&path, &config) {
        if let Some(source) = source.as_deref() {
            return Err(with_rollback(
                "Docker configuration update failed",
                error,
                restore_legacy(source, &erased),
            ));
        }
        return Err(format!("Docker configuration update failed: {error}"));
    }
    writeln!(stdout, "╰─ hardened docker").ok();
    super::write_secret_gate_notice(stdout, "docker");
    Ok(())
}

pub(crate) fn install_privileged() -> Result<(), String> {
    if test_config_path().is_some()
        || crate::test_env_var("AUTOMIC_VAULT_TEST_DOCKER_HELPER_PATH").is_some()
    {
        return Err("test path overrides are forbidden during privileged installation".into());
    }
    if super::effective_uid() != 0 {
        return Err("Docker helper installation requires root".into());
    }
    let helper = helper_path();
    validate_helper_install_path(&helper)?;
    install_stub(&helper, crate::cli::docker_credential::helper_stub())
}

pub(crate) fn detect() -> HardenerDetection {
    let helper = helper_path();
    let config = config_path().ok();
    let config_valid = config
        .as_deref()
        .and_then(|path| read_config(path).ok())
        .is_some_and(|value| validate_config(&value).ok().flatten().as_deref() == Some("av"));
    let stub_valid = helper_valid(&helper, test_config_path().is_some());
    let vendor = test_config_path().is_some() || verify_vendor_install().is_ok();
    let hardened = config_valid && stub_valid && vendor;
    let commands = TARGETS
        .iter()
        .map(|(name, target, _)| HardenerCommand {
            name: (*name).into(),
            hardened,
            stub_valid,
            stub_path: Some(helper.display().to_string()),
            target_path: (*target).into(),
            required_paths: if test_config_path().is_some() {
                Vec::new()
            } else {
                vec![RequiredExecutable {
                    name: "Automic Vault CLI",
                    path: AV_PATH.into(),
                }]
            },
            stub_requirements: Some(stub_requirements(&helper, test_config_path().is_some())),
            injected_keys: Vec::new(),
            assignment_keys: Vec::new(),
            isotope: None,
        })
        .collect();
    let mut detection = HardenerDetection::commands(hardened, commands);
    detection.applicable =
        config.as_deref().is_some_and(Path::exists) || Path::new(TARGETS[0].1).exists();
    if !vendor && test_config_path().is_none() {
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "docker_vendor_cli_invalid",
            message: verify_vendor_install().unwrap_err(),
            remediation: "Reinstall or update Docker Desktop, then rerun `av harden docker`."
                .into(),
            path: Some(DOCKER_APP.into()),
        });
    }
    detection
}

pub(crate) fn secret_gate() -> SecretGateDescriptor {
    SecretGateDescriptor {
        id: "docker",
        key_patterns: vec!["DOCKER_REGISTRY_CREDENTIAL_*".into()],
        routes: TARGETS
            .iter()
            .map(|(_, target, _)| SecretGateRoute {
                operation: "docker-get",
                script_path: None,
                target_path: (*target).into(),
                caller_identifiers: vec!["com.automicvault.av"],
                key_patterns: vec!["DOCKER_REGISTRY_CREDENTIAL_*".into()],
                replace_existing_env: false,
                allow_missing_keys: false,
            })
            .collect(),
    }
}

fn validate_config(config: &Value) -> Result<Option<String>, String> {
    let object = config
        .as_object()
        .ok_or_else(|| "Docker config must be a JSON object".to_string())?;
    if let Some(helpers) = object.get("credHelpers") {
        let helpers = helpers
            .as_object()
            .ok_or_else(|| "Docker `credHelpers` must be an object".to_string())?;
        if helpers.values().any(|helper| helper.as_str() != Some("av")) {
            return Err(
                "non-Automic per-registry Docker credential helpers are not supported yet".into(),
            );
        }
    }
    if object.get("auths").is_some_and(|value| !value.is_object()) {
        return Err("Docker `auths` must be an object".into());
    }
    if object
        .get("auths")
        .and_then(Value::as_object)
        .is_some_and(|auths| {
            auths.values().any(|entry| {
                entry.as_object().is_some_and(|entry| {
                    ["auth", "identitytoken", "identityToken"]
                        .iter()
                        .any(|key| {
                            entry
                                .get(*key)
                                .and_then(Value::as_str)
                                .is_some_and(|value| !value.trim().is_empty())
                        })
                })
            })
        })
    {
        return Err("inline Docker credentials must be removed before hardening".into());
    }
    match object.get("credsStore") {
        None => Ok(None),
        Some(Value::String(store)) if !store.is_empty() => Ok(Some(store.clone())),
        Some(_) => Err("Docker `credsStore` must be a non-empty string".into()),
    }
}

fn read_legacy_credentials(
    store: &str,
) -> Result<Vec<crate::cli::docker_credential::DockerCredential>, String> {
    let helper = source_helper(store)?;
    let output = helper_output(&helper, "list", "")?;
    let list: Map<String, Value> = serde_json::from_str(&output)
        .map_err(|error| format!("legacy Docker helper returned invalid list JSON: {error}"))?;
    let mut servers = list
        .into_iter()
        .map(|(server, username)| {
            username.as_str().ok_or_else(|| {
                "legacy Docker helper list contains a non-string username".to_string()
            })?;
            Ok(server)
        })
        .collect::<Result<Vec<_>, String>>()?;
    servers.sort();
    servers.dedup();
    servers
        .into_iter()
        .map(|server| {
            let output = helper_output(&helper, "get", &server)?;
            let credential = crate::cli::docker_credential::parse_credential(&output)?;
            (credential.server_url == server)
                .then_some(credential)
                .ok_or_else(|| {
                    "legacy Docker helper returned a credential for another registry".into()
                })
        })
        .collect()
}

fn source_helper(store: &str) -> Result<PathBuf, String> {
    if let Some(path) = crate::test_env_var("AUTOMIC_VAULT_TEST_DOCKER_SOURCE_HELPER") {
        return Ok(path.into());
    }
    let name = match store {
        "desktop" => "docker-credential-desktop",
        "osxkeychain" => "docker-credential-osxkeychain",
        _ => return Err(format!("unsupported Docker credential store `{store}`")),
    };
    let path = PathBuf::from(DOCKER_APP)
        .join("Contents/Resources/bin")
        .join(name);
    verify_signed_executable(&path, name)?;
    Ok(path)
}

fn helper_output(path: &Path, action: &str, input: &str) -> Result<String, String> {
    let mut child = helper_command(path, action)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("failed to start {}: {error}", path.display()))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input.as_bytes())
            .map_err(|error| format!("failed to write to {}: {error}", path.display()))?;
    }
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .take(MAX_HELPER_OUTPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read from {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_HELPER_OUTPUT {
        let _ = child.kill();
        let _ = child.wait();
        return Err("legacy Docker helper output exceeded 1 MiB".into());
    }
    let status = child
        .wait()
        .map_err(|error| format!("failed to wait for {}: {error}", path.display()))?;
    if !status.success() {
        return Err(format!(
            "legacy Docker helper `{action}` failed ({status}); open Docker Desktop and retry"
        ));
    }
    String::from_utf8(bytes).map_err(|_| "legacy Docker helper returned non-UTF-8 output".into())
}

fn helper_action(path: &Path, action: &str, input: &str) -> Result<(), String> {
    let mut child = helper_command(path, action)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("failed to start {}: {error}", path.display()))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input.as_bytes())
            .map_err(|error| format!("failed to write to {}: {error}", path.display()))?;
    }
    let status = child
        .wait()
        .map_err(|error| format!("failed to wait for {}: {error}", path.display()))?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| format!("legacy Docker helper `{action}` failed ({status})"))
}

fn helper_command(path: &Path, action: &str) -> Command {
    let mut command = Command::new(path);
    command
        .arg(action)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", std::env::var_os("HOME").unwrap_or_default());
    command
}

fn restore_legacy(
    path: &Path,
    credentials: &[&crate::cli::docker_credential::DockerCredential],
) -> Result<(), String> {
    for credential in credentials {
        helper_action(path, "store", &credential.storage_json())?;
    }
    Ok(())
}

fn with_rollback(context: &str, error: String, rollback: Result<(), String>) -> String {
    match rollback {
        Ok(()) => format!("{context}: {error}; restored legacy credentials"),
        Err(rollback) => format!(
            "{context}: {error}; legacy credential restoration also failed: {rollback}; Automic Vault retains the migrated copies"
        ),
    }
}

fn config_path() -> Result<PathBuf, String> {
    if let Some(path) = test_config_path() {
        return Ok(path);
    }
    if let Some(directory) = std::env::var_os("DOCKER_CONFIG").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(directory).join("config.json"));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| "HOME is not set".to_string())?;
    Ok(PathBuf::from(home).join(".docker/config.json"))
}

fn test_config_path() -> Option<PathBuf> {
    crate::test_env_var("AUTOMIC_VAULT_TEST_DOCKER_CONFIG").map(PathBuf::from)
}

fn read_config(path: &Path) -> Result<Value, String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(json!({})),
        Err(error) => return Err(format!("failed to open {}: {error}", path.display())),
    };
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG {
        return Err(format!("refusing unsafe Docker config: {}", path.display()));
    }
    let mut contents = String::new();
    file.take(MAX_CONFIG + 1)
        .read_to_string(&mut contents)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    if contents.len() as u64 > MAX_CONFIG {
        return Err("Docker config exceeds 1 MiB".into());
    }
    serde_json::from_str(&contents)
        .map_err(|error| format!("invalid Docker config {}: {error}", path.display()))
}

fn write_config(path: &Path, value: &Value) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("Docker config has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    let staging = parent.join(format!(
        ".config.json.av.{}.{}",
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
        serde_json::to_writer_pretty(&mut file, value)
            .map_err(|error| format!("failed to encode Docker config: {error}"))?;
        file.write_all(b"\n")
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

pub(super) fn install_shared_helper(testing: bool) -> Result<(), String> {
    if testing {
        return install_stub(&helper_path(), crate::cli::docker_credential::helper_stub());
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
        return Err("update the av CLI from the Automic Vault app before hardening Docker".into());
    }
    let status = Command::new(SUDO_PATH)
        .args([AV_PATH, "__install-docker-helper"])
        .status()
        .map_err(|error| format!("failed to run sudo: {error}"))?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| format!("Docker helper installation failed: {status}"))
}

pub(super) fn install_stub(path: &Path, contents: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("registry helper has no parent: {}", path.display()))?;
    let staging = parent.join(format!(
        ".registry-credential-helper.{}.{}.tmp",
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
        file.write_all(contents.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("failed to write {}: {error}", staging.display()))?;
        file.set_permissions(fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("failed to chmod {}: {error}", staging.display()))?;
        fs::rename(&staging, path)
            .map_err(|error| format!("failed to replace {}: {error}", path.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(staging);
    }
    result
}

pub(super) fn helper_path() -> PathBuf {
    crate::cli::docker_credential::helper_path()
}

pub(super) fn validate_helper_install_path(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("registry helper has no parent: {}", path.display()))?;
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|error| format!("failed to inspect {}: {error}", ancestor.display()))?;
        if !secure_install_directory(&metadata, 0) {
            return Err(format!(
                "refusing registry helper path through unsafe directory {}: every containing directory must be root-owned and protected from group/world writes",
                ancestor.display()
            ));
        }
    }
    Ok(())
}

fn secure_install_directory(metadata: &fs::Metadata, owner_uid: u32) -> bool {
    metadata.file_type().is_dir()
        && metadata.uid() == owner_uid
        && metadata.permissions().mode() & 0o022 == 0
}

pub(super) fn helper_valid(path: &Path, testing: bool) -> bool {
    let metadata = fs::symlink_metadata(path).ok();
    crate::cli::docker_credential::helper_stub_valid(path)
        && metadata.as_ref().is_some_and(|metadata| {
            metadata.permissions().mode() & 0o777 == 0o755
                && (testing || (metadata.uid() == 0 && validate_helper_install_path(path).is_ok()))
        })
}

pub(super) fn stub_requirements(path: &Path, testing: bool) -> StubRequirements {
    let test_ids = testing
        .then(|| {
            path.parent()
                .and_then(|parent| parent.metadata().ok())
                .map(|metadata| (metadata.uid(), metadata.gid()))
        })
        .flatten();
    StubRequirements {
        mode: 0o755,
        owner: RequiredIdentity {
            name: if test_ids.is_some() {
                "test user"
            } else {
                "root"
            },
            id: Some(test_ids.map_or(0, |ids| ids.0)),
        },
        group: RequiredIdentity {
            name: if test_ids.is_some() {
                "test group"
            } else {
                "wheel"
            },
            id: Some(test_ids.map_or(0, |ids| ids.1)),
        },
    }
}

fn confirm(stdout: &mut dyn Write, yes: bool) -> Result<bool, String> {
    if yes {
        writeln!(stdout, "◇ Continue? yes (--yes)").ok();
        return Ok(true);
    }
    write!(stdout, "◇ Continue? [y/N] ").ok();
    stdout
        .flush()
        .map_err(|error| format!("failed to flush prompt: {error}"))?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|error| format!("failed to read confirmation: {error}"))?;
    if !io::stdin().is_terminal() {
        writeln!(stdout).ok();
    }
    Ok(matches!(
        input.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn verify_vendor_install() -> Result<(), String> {
    if !Path::new(DOCKER_APP).is_dir() {
        return Err("Docker Desktop is not installed in /Applications".into());
    }
    let status = Command::new("/usr/sbin/spctl")
        .args(["--assess", "--type", "execute"])
        .arg(DOCKER_APP)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("failed to assess Docker Desktop notarization: {error}"))?;
    if !status.success() {
        return Err("Docker Desktop failed Apple's execution policy assessment".into());
    }
    for (_, path, identifier) in TARGETS {
        if Path::new(path).exists() || identifier == "docker" {
            verify_signed_executable(Path::new(path), identifier)?;
        }
    }
    Ok(())
}

fn verify_signed_executable(path: &Path, identifier: &str) -> Result<(), String> {
    let requirement = format!(
        "=identifier \"{identifier}\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"{DOCKER_TEAM}\""
    );
    let status = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "-R", &requirement])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("failed to verify {}: {error}", path.display()))?;
    if !status.success() {
        return Err(format!("Docker signature is invalid: {}", path.display()));
    }
    let details = codesign_output(&["-d", "-vvv"], path)?;
    for required in [
        "flags=0x10000(runtime)",
        "Authority=Developer ID Application: Docker Inc (9BNSXJN65R)",
        "TeamIdentifier=9BNSXJN65R",
        "Timestamp=",
    ] {
        if !details.contains(required) {
            return Err(format!(
                "Docker signature for {} did not confirm {required:?}",
                path.display()
            ));
        }
    }
    let entitlements = codesign_output(&["-d", "--entitlements", ":-"], path)?;
    for blocked in [
        "com.apple.security.get-task-allow",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.cs.debugger",
    ] {
        if entitlements.contains(blocked) {
            return Err(format!(
                "Docker executable enables unsafe entitlement {blocked}"
            ));
        }
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
            "failed to inspect Docker signature: {}",
            text.trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_validation_fails_closed_and_accepts_av() {
        assert_eq!(
            validate_config(&json!({"credsStore":"av"})).unwrap(),
            Some("av".into())
        );
        assert!(validate_config(&json!({"credHelpers":{"ghcr.io":"desktop"}})).is_err());
        assert!(validate_config(&json!({"auths":{"ghcr.io":{"auth":"plaintext-ish"}}})).is_err());
    }

    #[test]
    fn helper_install_directories_reject_writes_and_symlinks() {
        let root =
            std::env::temp_dir().join(format!("av-docker-helper-path-{}", std::process::id()));
        let directory = root.join("bin");
        let link = root.join("link");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        let metadata = fs::symlink_metadata(&directory).unwrap();
        assert!(secure_install_directory(&metadata, metadata.uid()));
        assert!(!secure_install_directory(&metadata, metadata.uid() + 1));

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o775)).unwrap();
        let metadata = fs::symlink_metadata(&directory).unwrap();
        assert!(!secure_install_directory(&metadata, metadata.uid()));

        std::os::unix::fs::symlink(&directory, &link).unwrap();
        let metadata = fs::symlink_metadata(&link).unwrap();
        assert!(!secure_install_directory(&metadata, metadata.uid()));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn hardening_migrates_before_switching_helpers() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root = std::env::temp_dir().join(format!("av-docker-hardener-{}", std::process::id()));
        let config = root.join("config.json");
        let installed = root.join("docker-credential-av");
        let source = root.join("docker-credential-desktop");
        let legacy = root.join("legacy.json");
        let keychain = root.join("keychain");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(&config, r#"{"auths":{},"credsStore":"desktop"}"#).unwrap();
        fs::write(
            &legacy,
            r#"{"ServerURL":"registry.example","Username":"user","Secret":"token"}"#,
        )
        .unwrap();
        fs::write(&source, format!("#!/bin/sh\ncase \"$1\" in\nlist) [ -f '{0}' ] && printf '%s' '{{\"registry.example\":\"user\"}}' || printf '%s' '{{}}' ;;\nget) cat '{0}' ;;\nerase) cat >/dev/null; rm -f '{0}' ;;\nstore) cat >'{0}' ;;\n*) exit 2 ;;\nesac\n", legacy.display())).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_DOCKER_CONFIG", &config);
            std::env::set_var("AUTOMIC_VAULT_TEST_DOCKER_HELPER_PATH", &installed);
            std::env::set_var("AUTOMIC_VAULT_TEST_DOCKER_SOURCE_HELPER", &source);
            std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain);
        }
        run(&mut Vec::new(), true).unwrap();
        let updated: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
        assert_eq!(updated["credsStore"], "av");
        assert!(!legacy.exists());
        let saved = fs::read_to_string(keychain.join(crate::cli::docker_credential::secret_name(
            "registry.example",
        )))
        .unwrap();
        assert_eq!(
            crate::cli::docker_credential::parse_credential(&saved)
                .unwrap()
                .secret,
            "token"
        );
        assert!(helper_valid(&installed, true));
        unsafe {
            for name in [
                "AUTOMIC_VAULT_TEST_DOCKER_CONFIG",
                "AUTOMIC_VAULT_TEST_DOCKER_HELPER_PATH",
                "AUTOMIC_VAULT_TEST_DOCKER_SOURCE_HELPER",
                "AUTOMIC_VAULT_TEST_KEYCHAIN_DIR",
            ] {
                std::env::remove_var(name);
            }
        }
        let _ = fs::remove_dir_all(root);
    }
}
