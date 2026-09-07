use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine;
use serde_json::{Map, Value, json};

use super::{
    HardenerCommand, HardenerDetection, HardenerDiagnostic, RequiredExecutable,
    SecretGateDescriptor, SecretGateRoute,
};

const AV_PATH: &str = "/usr/local/bin/av";
const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;
const TEAM_IDENTIFIER: &str = "ZU76A67LGU";

struct Migration {
    key: String,
    value: String,
}

struct SanitizedConfig {
    value: Value,
    migrations: Vec<Migration>,
    has_helper: bool,
}

pub(crate) fn run(stdout: &mut dyn Write, yes: bool) -> Result<(), String> {
    let testing = test_config_path().is_some();
    super::PrivilegeMode::Mixed.require_user("kubectl", testing)?;
    reject_competing_config()?;
    if !testing {
        crate::secrets::ensure_kubectl_helper_ready()?;
    }
    let config = config_path()?;
    validate_config_file(&config)?;
    let plan = super::isotope::plan(super::isotope::KUBECTL)?;

    writeln!(stdout, "╭─ harden kubectl").ok();
    writeln!(stdout, "│").ok();
    plan.write(stdout, super::isotope::KUBECTL);
    writeln!(
        stdout,
        "├─ migrate supported kubeconfig credentials without printing them"
    )
    .ok();
    writeln!(
        stdout,
        "├─ configure kubectl's native ExecCredential protocol"
    )
    .ok();
    writeln!(stdout, "├─ require approval for every credential use").ok();
    writeln!(stdout, "│").ok();
    if !super::gh_cli::confirm(stdout, yes)? {
        writeln!(stdout, "╰─ cancelled").ok();
        return Ok(());
    }

    plan.apply(super::isotope::KUBECTL)?;
    let target = target();
    verify_target(&target)?;
    let original = render_config(&target, &config)?;
    let sanitized = sanitize_config(original)?;
    if !sanitized.has_helper && sanitized.migrations.is_empty() {
        return Err("kubeconfig has no supported inline credentials to harden".into());
    }
    for migration in &sanitized.migrations {
        crate::secrets::store_secret_if_absent_or_equal(&migration.key, &migration.value)?;
    }
    if !sanitized.migrations.is_empty() {
        write_config(&config, &sanitized.value)?;
    }
    let verified = sanitize_config(render_config(&target, &config)?)?;
    if !verified.has_helper || !verified.migrations.is_empty() {
        return Err("kubectl reported success but kubeconfig is not hardened".into());
    }

    writeln!(stdout, "╰─ hardened kubectl").ok();
    super::write_secret_gate_notice(stdout, "kubectl");
    Ok(())
}

pub(crate) fn detect() -> HardenerDetection {
    let testing = test_config_path().is_some();
    let target = target();
    let target_valid = verify_target(&target).is_ok();
    let config = config_path().ok();
    let config_valid = config.as_deref().is_some_and(|path| {
        validate_config_file(path).is_ok()
            && target_valid
            && render_config(&target, path)
                .and_then(sanitize_config)
                .is_ok_and(|state| state.has_helper && state.migrations.is_empty())
    });
    let hardened = target_valid && config_valid;
    let isotope = super::isotope::detect(super::isotope::KUBECTL)
        .commands
        .into_iter()
        .next()
        .and_then(|command| command.isotope);
    let command = HardenerCommand {
        name: "kubectl".into(),
        hardened,
        stub_valid: true,
        stub_path: None,
        target_path: target.display().to_string(),
        required_paths: if testing {
            Vec::new()
        } else {
            vec![RequiredExecutable {
                name: "Automic Vault CLI",
                path: AV_PATH.into(),
            }]
        },
        stub_requirements: None,
        injected_keys: Vec::new(),
        assignment_keys: Vec::new(),
        isotope,
    };
    let mut detection = HardenerDetection::commands(hardened, vec![command]);
    detection.applicable = config.as_deref().is_some_and(Path::exists) || target.exists();
    if target.exists() && !target_valid && !testing {
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "kubectl_target_invalid",
            message: verify_target(&target).unwrap_err(),
            remediation: "Rerun `av harden kubectl` to install the signed kubectl Isotope.".into(),
            path: Some(target.display().to_string()),
        });
    }
    if config.as_deref().is_some_and(Path::exists) && !config_valid {
        detection.diagnostics.push(HardenerDiagnostic {
            kind: "kubectl_config_not_hardened",
            message: "kubeconfig is not in the supported Hardened State.".into(),
            remediation:
                "Rerun `av harden kubectl`; unsupported credential routes must be removed manually."
                    .into(),
            path: config.map(|path| path.display().to_string()),
        });
    }
    detection
}

pub(crate) fn secret_gate() -> SecretGateDescriptor {
    SecretGateDescriptor {
        id: "kubectl",
        key_patterns: vec!["KUBECTL_USER_CREDENTIAL_*".into()],
        routes: vec![SecretGateRoute {
            operation: "kubectl-get",
            script_path: None,
            target_path: target().display().to_string(),
            caller_identifiers: vec!["com.automicvault.av"],
            key_patterns: vec!["KUBECTL_USER_CREDENTIAL_*".into()],
            replace_existing_env: false,
            allow_missing_keys: false,
        }],
    }
}

fn reject_competing_config() -> Result<(), String> {
    let Some(value) = std::env::var_os("KUBECONFIG").filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let paths = std::env::split_paths(&value).collect::<Vec<_>>();
    if paths.len() != 1 || !paths[0].is_absolute() {
        return Err("KUBECONFIG must name exactly one absolute kubeconfig before hardening".into());
    }
    Ok(())
}

fn config_path() -> Result<PathBuf, String> {
    if let Some(path) = test_config_path() {
        return Ok(path);
    }
    if let Some(value) = std::env::var_os("KUBECONFIG").filter(|value| !value.is_empty()) {
        reject_competing_config()?;
        return Ok(PathBuf::from(value));
    }
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())?;
    Ok(home.join(".kube/config"))
}

fn test_config_path() -> Option<PathBuf> {
    crate::test_env_var("AUTOMIC_VAULT_TEST_KUBECTL_CONFIG").map(PathBuf::from)
}

fn target() -> PathBuf {
    super::isotope::target(super::isotope::KUBECTL)
}

fn validate_config_file(path: &Path) -> Result<(), String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.len() > MAX_CONFIG_BYTES
        || metadata.uid() != super::effective_uid()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(format!("refusing unsafe kubeconfig {}", path.display()));
    }
    Ok(())
}

fn render_config(target: &Path, config: &Path) -> Result<Value, String> {
    let output = Command::new(target)
        .arg(format!("--kubeconfig={}", config.display()))
        .args(["config", "view", "--raw", "-o", "json"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("failed to run {}: {error}", target.display()))?;
    if !output.status.success() {
        return Err(format!(
            "kubectl could not parse {}: {}",
            config.display(),
            output.status
        ));
    }
    if output.stdout.len() as u64 > MAX_CONFIG_BYTES {
        return Err("rendered kubeconfig exceeds 16 MiB".into());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("kubectl returned invalid kubeconfig JSON: {error}"))
}

fn sanitize_config(mut root: Value) -> Result<SanitizedConfig, String> {
    validate_clusters(&root)?;
    let users = root
        .as_object_mut()
        .and_then(|root| root.get_mut("users"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "kubeconfig has no users array".to_string())?;
    let mut names = BTreeSet::new();
    let mut migrations = Vec::new();
    let mut has_helper = false;
    for entry in users {
        let entry = entry
            .as_object_mut()
            .ok_or_else(|| "kubeconfig contains an invalid user entry".to_string())?;
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "kubeconfig contains a user without a name".to_string())?
            .to_string();
        crate::cli::kubectl_credential::validate_user(&name)?;
        if !names.insert(name.clone()) {
            return Err(format!("kubeconfig contains duplicate user {name:?}"));
        }
        let auth = entry
            .get_mut("user")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| format!("kubeconfig user {name:?} has invalid authentication data"))?;
        if exact_helper(auth, &name) {
            has_helper = true;
            continue;
        }
        reject_unsupported_auth(auth, &name)?;
        let token = auth
            .get("token")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        let certificate = auth
            .get("client-certificate-data")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        let key = auth
            .get("client-key-data")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        if certificate.is_some() != key.is_some() {
            return Err(format!(
                "kubeconfig user {name:?} has an incomplete client certificate"
            ));
        }
        if token.is_some() && certificate.is_some() {
            return Err(format!(
                "kubeconfig user {name:?} has ambiguous credentials"
            ));
        }
        let (kind, stored) = if let Some(token) = token {
            if token.len() > 1024 * 1024 || token.contains('\0') {
                return Err(format!("kubeconfig user {name:?} has an invalid token"));
            }
            ("token", json!({"token": token}))
        } else if let (Some(certificate), Some(key)) = (certificate, key) {
            let certificate = decode_pem(certificate, "certificate", &name)?;
            let key = decode_pem(key, "private key", &name)?;
            if !certificate.contains("-----BEGIN CERTIFICATE-----")
                || !key.contains("-----BEGIN")
                || !key.contains("PRIVATE KEY-----")
            {
                return Err(format!(
                    "kubeconfig user {name:?} has invalid PEM credentials"
                ));
            }
            (
                "client-certificate",
                json!({"clientCertificateData": certificate, "clientKeyData": key}),
            )
        } else {
            continue;
        };
        let stored = serde_json::to_string(&stored)
            .map_err(|error| format!("failed to encode kubectl credential: {error}"))?;
        migrations.push(Migration {
            key: crate::cli::kubectl_credential::secret_name(&name),
            value: stored,
        });
        auth.remove("token");
        auth.remove("client-certificate-data");
        auth.remove("client-key-data");
        auth.insert("exec".into(), helper_config(kind, &name));
        has_helper = true;
    }
    Ok(SanitizedConfig {
        value: root,
        migrations,
        has_helper,
    })
}

fn validate_clusters(root: &Value) -> Result<(), String> {
    let clusters = root
        .as_object()
        .and_then(|root| root.get("clusters"))
        .and_then(Value::as_array)
        .ok_or_else(|| "kubeconfig has no clusters array".to_string())?;
    for entry in clusters {
        let cluster = entry
            .as_object()
            .and_then(|entry| entry.get("cluster"))
            .and_then(Value::as_object)
            .ok_or_else(|| "kubeconfig contains an invalid cluster entry".to_string())?;
        let server = cluster
            .get("server")
            .and_then(Value::as_str)
            .ok_or_else(|| "kubeconfig contains a cluster without a server".to_string())?;
        if server.is_empty() || server.len() > 4096 || !server.is_ascii() {
            return Err("kubeconfig contains an invalid Kubernetes API server".into());
        }
        let url = url::Url::parse(server)
            .map_err(|_| "kubeconfig contains an invalid Kubernetes API server")?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("kubeconfig contains an unsafe Kubernetes API server".into());
        }
        if cluster
            .get("insecure-skip-tls-verify")
            .and_then(Value::as_bool)
            == Some(true)
        {
            return Err("kubeconfig disables Kubernetes API certificate verification".into());
        }
    }
    Ok(())
}

fn reject_unsupported_auth(auth: &Map<String, Value>, name: &str) -> Result<(), String> {
    let safe = BTreeSet::from([
        "token",
        "client-certificate-data",
        "client-key-data",
        "impersonate",
        "impersonate-uid",
        "impersonate-groups",
        "impersonate-user-extra",
        "extensions",
    ]);
    if let Some(field) = auth
        .iter()
        .find(|(field, value)| !safe.contains(field.as_str()) && !value.is_null())
        .map(|(field, _)| field)
    {
        return Err(format!(
            "kubeconfig user {name:?} uses unsupported authentication field {field:?}"
        ));
    }
    Ok(())
}

fn decode_pem(value: &str, label: &str, user: &str) -> Result<String, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| format!("kubeconfig user {user:?} has invalid base64 {label}"))?;
    if bytes.is_empty() || bytes.len() > 2 * 1024 * 1024 {
        return Err(format!("kubeconfig user {user:?} has invalid {label}"));
    }
    String::from_utf8(bytes).map_err(|_| format!("kubeconfig user {user:?} has non-UTF-8 {label}"))
}

fn helper_config(kind: &str, user: &str) -> Value {
    json!({
        "apiVersion": "client.authentication.k8s.io/v1",
        "command": AV_PATH,
        "args": ["kubectl-credential", "1", kind, user],
        "provideClusterInfo": true,
        "interactiveMode": "Never",
    })
}

fn exact_helper(auth: &Map<String, Value>, user: &str) -> bool {
    auth.get("exec")
        == Some(&helper_config(
            auth.get("exec")
                .and_then(Value::as_object)
                .and_then(|exec| exec.get("args"))
                .and_then(Value::as_array)
                .and_then(|args| args.get(2))
                .and_then(Value::as_str)
                .unwrap_or_default(),
            user,
        ))
        && auth
            .get("exec")
            .and_then(Value::as_object)
            .and_then(|exec| exec.get("args"))
            .and_then(Value::as_array)
            .and_then(|args| args.get(2))
            .and_then(Value::as_str)
            .is_some_and(|kind| matches!(kind, "token" | "client-certificate"))
        && auth.keys().all(|field| {
            matches!(
                field.as_str(),
                "exec"
                    | "impersonate"
                    | "impersonate-uid"
                    | "impersonate-groups"
                    | "impersonate-user-extra"
                    | "extensions"
            )
        })
}

fn write_config(path: &Path, value: &Value) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "kubeconfig has no parent directory".to_string())?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("failed to inspect {}: {error}", parent.display()))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != super::effective_uid()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(format!(
            "refusing unsafe kubeconfig directory {}",
            parent.display()
        ));
    }
    let staging = parent.join(format!(".config.av-{}.tmp", super::isotope::now_nanos()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&staging)
            .map_err(|error| format!("failed to create {}: {error}", staging.display()))?;
        serde_json::to_writer_pretty(&mut file, value)
            .map_err(|error| format!("failed to write {}: {error}", staging.display()))?;
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

pub(crate) fn verify_target(path: &Path) -> Result<(), String> {
    if test_config_path().is_some() {
        return path
            .exists()
            .then_some(())
            .ok_or_else(|| format!("test kubectl Target is missing: {}", path.display()));
    }
    let requirement = format!(
        "=identifier \"kubectl\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"{TEAM_IDENTIFIER}\""
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
        return Err(format!(
            "kubectl Target signature is invalid: {}",
            path.display()
        ));
    }
    let output = Command::new("/usr/bin/codesign")
        .args(["-d", "-vvv"])
        .arg(path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .output()
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    let details = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success()
        || !details.contains("flags=0x10000(runtime)")
        || !details.contains(&format!("TeamIdentifier={TEAM_IDENTIFIER}"))
        || !details.contains("Timestamp=")
    {
        return Err(
            "kubectl Target lacks the required Developer ID Hardened Runtime identity".into(),
        );
    }
    let entitlements = Command::new("/usr/bin/codesign")
        .args(["-d", "--entitlements", ":-"])
        .arg(path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .output()
        .map_err(|error| format!("failed to inspect kubectl entitlements: {error}"))?;
    if !entitlements.status.success() || !entitlements.stdout.is_empty() {
        return Err("kubectl Target has unexpected code-signing entitlements".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn migrates_only_supported_unambiguous_credentials() {
        let input = json!({
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [{"name": "prod", "cluster": {"server": "https://example.com"}}],
            "users": [{"name": "prod", "user": {"token": "secret"}}]
        });
        let sanitized = sanitize_config(input).unwrap();
        assert!(sanitized.has_helper);
        assert_eq!(sanitized.migrations.len(), 1);
        assert_eq!(
            sanitized.migrations[0].key,
            crate::cli::kubectl_credential::secret_name("prod")
        );
        assert!(
            sanitize_config(json!({
                "clusters": [{"name": "prod", "cluster": {"server": "https://example.com"}}],
                "users": [{"name": "prod", "user": {"username": "u", "password": "p"}}]
            }))
            .is_err()
        );
        assert!(
            sanitize_config(json!({
                "clusters": [{"name": "prod", "cluster": {"server": "https://example.com"}}],
                "users": [{"name": "prod", "user": {"exec": {"command": "other"}}}]
            }))
            .is_err()
        );
        assert!(
            sanitize_config(json!({
                "clusters": [{"name": "prod", "cluster": {
                    "server": "https://example.com",
                    "insecure-skip-tls-verify": true
                }}],
                "users": [{"name": "prod", "user": {"token": "secret"}}]
            }))
            .is_err()
        );
    }

    #[test]
    fn recognizes_the_exact_generated_helper_only() {
        let mut auth = Map::new();
        auth.insert("exec".into(), helper_config("token", "prod"));
        assert!(exact_helper(&auth, "prod"));
        auth.get_mut("exec").unwrap()["command"] = json!("av");
        assert!(!exact_helper(&auth, "prod"));
    }

    #[test]
    fn hardener_migrates_a_token_and_installs_the_exact_exec_helper() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root = std::env::temp_dir().join(format!(
            "av-kubectl-hardener-test-{}-{}",
            std::process::id(),
            super::super::isotope::now_nanos()
        ));
        let config = root.join("config");
        let target = root.join("kubectl");
        let keychain = root.join("keychain");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            &config,
            r#"{"apiVersion":"v1","kind":"Config","clusters":[{"name":"prod","cluster":{"server":"https://example.com"}}],"users":[{"name":"prod","user":{"token":"secret"}}]}"#,
        )
        .unwrap();
        fs::write(
            &target,
            "#!/bin/sh\nfile=${1#--kubeconfig=}\n/bin/cat \"$file\"\n",
        )
        .unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        let previous_kubeconfig = std::env::var_os("KUBECONFIG");
        unsafe {
            std::env::remove_var("KUBECONFIG");
            std::env::set_var("AUTOMIC_VAULT_TEST_KUBECTL_CONFIG", &config);
            std::env::set_var("AUTOMIC_VAULT_TEST_KUBECTL_TARGET", &target);
            std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain);
        }

        run(&mut Vec::new(), true).unwrap();

        let hardened: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
        assert!(hardened.to_string().contains("kubectl-credential"));
        assert!(!hardened.to_string().contains("secret"));
        assert_eq!(
            fs::read_to_string(keychain.join(crate::cli::kubectl_credential::secret_name("prod")))
                .unwrap(),
            r#"{"token":"secret"}"#
        );
        assert!(detect().hardened);

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_KUBECTL_CONFIG");
            std::env::remove_var("AUTOMIC_VAULT_TEST_KUBECTL_TARGET");
            std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR");
            if let Some(value) = previous_kubeconfig {
                std::env::set_var("KUBECONFIG", value);
            }
        }
        let _ = fs::remove_dir_all(root);
    }
}
