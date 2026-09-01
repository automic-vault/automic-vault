use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ring::digest::{SHA256, digest};
use serde_json::{Value, json};

use super::inject;

const HELPER_STUB: &str = "#!/usr/local/bin/av docker-credential\n";
const HELPER_PATH: &str = "/usr/local/bin/docker-credential-av";
const PODMAN_HELPER_STUB: &str = "#!/usr/local/bin/av podman-credential\n";
const PODMAN_HELPER_PATH: &str = "/usr/local/bin/docker-credential-av-podman";
const MAX_INPUT_BYTES: u64 = 64 * 1024;
const MAX_SERVER_URL_BYTES: usize = 2048;
const SECRET_PREFIX: &str = "DOCKER_REGISTRY_CREDENTIAL_";
const CREDENTIALS_NOT_FOUND: &str = "credentials not found in native keychain";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DockerCredential {
    pub(crate) server_url: String,
    pub(crate) username: String,
    pub(crate) secret: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flavor {
    Docker,
    Podman,
}

pub(crate) fn run(mut args: Vec<OsString>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    run_flavor(Flavor::Docker, &mut args, stdout, stderr)
}

pub(crate) fn run_podman(
    mut args: Vec<OsString>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    run_flavor(Flavor::Podman, &mut args, stdout, stderr)
}

fn run_flavor(
    flavor: Flavor,
    args: &mut Vec<OsString>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let mut stdin = std::io::stdin().lock();
    match run_with_io(flavor, args, &mut stdin, stdout) {
        Ok(()) => 0,
        Err(error) => {
            write_error(flavor, &error, stdout, stderr);
            1
        }
    }
}

fn write_error(flavor: Flavor, error: &str, stdout: &mut dyn Write, stderr: &mut dyn Write) {
    if error == CREDENTIALS_NOT_FOUND {
        let _ = writeln!(stdout, "{error}");
    } else {
        let helper = match flavor {
            Flavor::Docker => "docker-credential-av",
            Flavor::Podman => "docker-credential-av-podman",
        };
        let _ = writeln!(stderr, "{helper}: {error}");
    }
}

fn run_with_io(
    flavor: Flavor,
    args: &mut Vec<OsString>,
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<(), String> {
    if !args
        .first()
        .is_some_and(|arg| is_helper_stub_arg(flavor, arg))
    {
        return Err(
            "refusing invocation without the installed Automic Vault helper launcher".into(),
        );
    }
    args.remove(0);
    let [action] = args.as_slice() else {
        return Err(match flavor {
            Flavor::Docker => "usage: docker-credential-av <store|get|erase>",
            Flavor::Podman => "usage: docker-credential-av-podman <store|get|erase|list>",
        }
        .into());
    };
    let action = action
        .to_str()
        .ok_or_else(|| "credential-helper action must be valid UTF-8".to_string())?;
    if matches!(action, "store" | "get" | "erase") {
        crate::secrets::ensure_registry_helper_ready()?;
    }
    match action {
        "store" => {
            let credential = parse_credential(&read_limited(input)?)?;
            crate::secrets::store_registry_credential(
                &secret_name(&credential.server_url),
                &credential.storage_json(),
            )?;
            if flavor == Flavor::Podman {
                crate::isotopes::hardeners::podman::add_helper_marker(&credential.server_url)?;
            }
            Ok(())
        }
        "get" => {
            let server_url = parse_server_url(&read_limited(input)?)?;
            let key = secret_name(&server_url);
            let stored = inject::docker_credential(
                key.clone(),
                server_url.clone(),
                if flavor == Flavor::Podman {
                    "podman"
                } else {
                    "docker"
                },
            )
            .map_err(|error| {
                if error == format!("failed to load secret {key}: -25300") {
                    CREDENTIALS_NOT_FOUND.into()
                } else {
                    error
                }
            })?;
            let credential = parse_credential(&stored)?;
            if credential.server_url != server_url {
                return Err("stored credential does not match the requested registry".into());
            }
            writeln!(
                output,
                "{}",
                json!({"Username": credential.username, "Secret": credential.secret})
            )
            .map_err(|error| format!("failed to return registry credential: {error}"))
        }
        "erase" => {
            let server_url = parse_server_url(&read_limited(input)?)?;
            if flavor == Flavor::Podman {
                crate::isotopes::hardeners::podman::remove_helper_marker(&server_url)?;
                if let Err(error) = crate::secrets::delete_registry_credential(
                    &secret_name(&server_url),
                    &server_url,
                ) {
                    return match crate::isotopes::hardeners::podman::add_helper_marker(&server_url)
                    {
                        Ok(()) => Err(error),
                        Err(rollback) => Err(format!(
                            "{error}; additionally failed to restore Podman registry marker: {rollback}"
                        )),
                    };
                }
            } else {
                crate::secrets::delete_registry_credential(&secret_name(&server_url), &server_url)?;
            }
            Ok(())
        }
        "list" if flavor == Flavor::Podman => writeln!(
            output,
            "{}",
            serde_json::to_string(&crate::isotopes::hardeners::podman::helper_markers()?)
                .map_err(|error| format!("failed to encode Podman registry markers: {error}"))?
        )
        .map_err(|error| format!("failed to return Podman registry markers: {error}")),
        "list" => Err(
            "list is intentionally unsupported because it discloses registry account metadata"
                .into(),
        ),
        _ => Err(format!("unknown credential-helper action: {action}")),
    }
}

pub(crate) fn secret_name(server_url: &str) -> String {
    let hash = digest(&SHA256, server_url.as_bytes());
    let hex = hash
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    format!("{SECRET_PREFIX}{hex}")
}

pub(crate) fn parse_credential(input: &str) -> Result<DockerCredential, String> {
    let value: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid registry credential JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "registry credential must be a JSON object".to_string())?;
    if object
        .keys()
        .any(|key| !["ServerURL", "Username", "Secret"].contains(&key.as_str()))
    {
        return Err("registry credential contains an unknown field".into());
    }
    let string = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("registry credential has no {name}"))
    };
    let credential = DockerCredential {
        server_url: string("ServerURL")?,
        username: string("Username")?,
        secret: string("Secret")?,
    };
    validate_server_url(&credential.server_url)?;
    if credential.username.as_bytes().contains(&0) || credential.secret.as_bytes().contains(&0) {
        return Err("registry credential contains NUL".into());
    }
    Ok(credential)
}

impl DockerCredential {
    pub(crate) fn storage_json(&self) -> String {
        json!({
            "ServerURL": self.server_url,
            "Username": self.username,
            "Secret": self.secret,
        })
        .to_string()
    }
}

fn parse_server_url(input: &str) -> Result<String, String> {
    let server_url = input.trim_end_matches(['\r', '\n']);
    validate_server_url(server_url)?;
    Ok(server_url.to_string())
}

fn validate_server_url(server_url: &str) -> Result<(), String> {
    if server_url.is_empty()
        || server_url.len() > MAX_SERVER_URL_BYTES
        || server_url
            .bytes()
            .any(|byte| byte == 0 || byte == b'\r' || byte == b'\n')
    {
        return Err("invalid registry address".into());
    }
    Ok(())
}

fn read_limited(input: &mut dyn Read) -> Result<String, String> {
    let mut bytes = Vec::new();
    input
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read credential-helper input: {error}"))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!(
            "credential-helper input exceeds {MAX_INPUT_BYTES} bytes"
        ));
    }
    String::from_utf8(bytes).map_err(|_| "credential-helper input must be valid UTF-8".into())
}

fn is_helper_stub_arg(flavor: Flavor, arg: &OsString) -> bool {
    let path = PathBuf::from(arg);
    let (expected_path, stub) = match flavor {
        Flavor::Docker => (helper_path(), HELPER_STUB),
        Flavor::Podman => (podman_helper_path(), PODMAN_HELPER_STUB),
    };
    path == expected_path
        && std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_file())
        && std::fs::read_to_string(path).is_ok_and(|contents| contents == stub)
}

pub(crate) fn helper_path() -> PathBuf {
    crate::test_env_var("AUTOMIC_VAULT_TEST_DOCKER_HELPER_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(HELPER_PATH))
}

pub(crate) fn helper_stub_valid(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|contents| contents == HELPER_STUB)
        && std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

pub(crate) const fn helper_stub() -> &'static str {
    HELPER_STUB
}

pub(crate) fn podman_helper_path() -> PathBuf {
    crate::test_env_var("AUTOMIC_VAULT_TEST_PODMAN_HELPER_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(PODMAN_HELPER_PATH))
}

pub(crate) fn podman_helper_stub_valid(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|contents| contents == PODMAN_HELPER_STUB)
        && std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

pub(crate) const fn podman_helper_stub() -> &'static str {
    PODMAN_HELPER_STUB
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn credential_round_trip_uses_registry_bound_secret_name() {
        let credential = parse_credential(
            r#"{"ServerURL":"https://ghcr.io","Username":"octocat","Secret":"token"}"#,
        )
        .unwrap();
        assert_eq!(
            parse_credential(&credential.storage_json()).unwrap(),
            credential
        );
        assert_eq!(
            secret_name("https://ghcr.io").len(),
            SECRET_PREFIX.len() + 64
        );
        assert_ne!(secret_name("ghcr.io"), secret_name("https://ghcr.io"));
    }

    #[test]
    fn helper_store_get_and_erase_use_test_secret_custody() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root = std::env::temp_dir().join(format!("av-docker-helper-{}", std::process::id()));
        let helper = root.join("docker-credential-av");
        let keychain = root.join("keychain");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(&helper, HELPER_STUB).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_DOCKER_HELPER_PATH", &helper);
            std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain);
        }
        let mut args = vec![helper.clone().into_os_string(), "store".into()];
        run_with_io(
            Flavor::Docker,
            &mut args,
            &mut r#"{"ServerURL":"registry.example","Username":"user","Secret":"secret"}"#
                .as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        let mut args = vec![helper.clone().into_os_string(), "get".into()];
        let mut output = Vec::new();
        run_with_io(
            Flavor::Docker,
            &mut args,
            &mut "registry.example\n".as_bytes(),
            &mut output,
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&output).unwrap(),
            json!({"Username":"user", "Secret":"secret"})
        );
        let mut args = vec![helper.clone().into_os_string(), "erase".into()];
        run_with_io(
            Flavor::Docker,
            &mut args,
            &mut "registry.example\n".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        assert!(!keychain.join(secret_name("registry.example")).exists());
        let mut args = vec![helper.clone().into_os_string(), "get".into()];
        let error = run_with_io(
            Flavor::Docker,
            &mut args,
            &mut "registry.example\n".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error, CREDENTIALS_NOT_FOUND);
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        write_error(Flavor::Docker, &error, &mut stdout, &mut stderr);
        assert_eq!(stdout, b"credentials not found in native keychain\n");
        assert!(stderr.is_empty());
        stdout.clear();
        write_error(Flavor::Docker, "approval denied", &mut stdout, &mut stderr);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"docker-credential-av: approval denied\n");
        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_DOCKER_HELPER_PATH");
            std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR");
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn podman_helper_tracks_non_secret_registry_markers_for_list() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root = std::env::temp_dir().join(format!("av-podman-helper-{}", std::process::id()));
        let helper = root.join("docker-credential-av-podman");
        let auth = root.join("auth.json");
        let keychain = root.join("keychain");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(&helper, PODMAN_HELPER_STUB).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_PODMAN_HELPER_PATH", &helper);
            std::env::set_var("AUTOMIC_VAULT_TEST_PODMAN_AUTH", &auth);
            std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain);
        }
        let mut args = vec![helper.clone().into_os_string(), "store".into()];
        run_with_io(
            Flavor::Podman,
            &mut args,
            &mut r#"{"ServerURL":"registry.example","Username":"user","Secret":"secret"}"#
                .as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        let mut args = vec![helper.clone().into_os_string(), "list".into()];
        let mut output = Vec::new();
        run_with_io(Flavor::Podman, &mut args, &mut "".as_bytes(), &mut output).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&output).unwrap(),
            json!({"registry.example": ""})
        );
        let secret = keychain.join(secret_name("registry.example"));
        let backup = keychain.join("credential-backup");
        fs::rename(&secret, &backup).unwrap();
        fs::create_dir(&secret).unwrap();
        let mut args = vec![helper.clone().into_os_string(), "erase".into()];
        assert!(
            run_with_io(
                Flavor::Podman,
                &mut args,
                &mut "registry.example\n".as_bytes(),
                &mut Vec::new(),
            )
            .is_err()
        );
        assert_eq!(
            crate::isotopes::hardeners::podman::helper_markers().unwrap(),
            std::iter::once(("registry.example".into(), String::new())).collect()
        );
        fs::remove_dir(&secret).unwrap();
        fs::rename(&backup, &secret).unwrap();
        let mut args = vec![helper.clone().into_os_string(), "erase".into()];
        run_with_io(
            Flavor::Podman,
            &mut args,
            &mut "registry.example\n".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&auth).unwrap()).unwrap(),
            json!({})
        );
        unsafe {
            for name in [
                "AUTOMIC_VAULT_TEST_PODMAN_HELPER_PATH",
                "AUTOMIC_VAULT_TEST_PODMAN_AUTH",
                "AUTOMIC_VAULT_TEST_KEYCHAIN_DIR",
            ] {
                std::env::remove_var(name);
            }
        }
        let _ = fs::remove_dir_all(root);
    }
}
