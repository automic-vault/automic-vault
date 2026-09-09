//! Reviewed upstream uv 0.12.12 command routing and credential storage.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;

pub(crate) const SECRET: &str = "UV_CREDENTIALS";
pub(crate) const VERSION: &str = "0.12.12";
pub(crate) const TARGET: &str = "/opt/av/uv/0.12.12/uv";
pub(crate) const HELPER: &str = "/opt/av/uv/bin/keyring";
pub(crate) const STUB: &str = "#!/usr/local/bin/av uv\n";
pub(crate) const UVX_STUB: &str = "#!/usr/local/bin/av uvx\n";
pub(crate) const HELPER_STUB: &str = "#!/usr/local/bin/av uv-keyring\n";

/// Registration grants no Secret Use. Only these commands can later use the helper.
pub(crate) fn credential_command(args: &[String]) -> Option<&'static str> {
    // Help/version output cannot consume the protected credential. Conservatively
    // keep passthrough help forms tokenless too.
    if args
        .iter()
        .any(|v| matches!(v.as_str(), "-h" | "--help" | "-V" | "--version"))
    {
        return None;
    }
    let i = command_offset(args, false)?;
    match args.get(i)?.as_str() {
        "add" => Some("add"),
        "remove" => Some("remove"),
        "sync" => Some("sync"),
        "lock" => Some("lock"),
        "upgrade" => Some("upgrade"),
        "tree" => Some("tree"),
        "export" => Some("export"),
        "audit" => Some("audit"),
        "check" => Some("check"),
        "run" => Some("run"),
        "build" => Some("build"),
        "publish" => Some("publish"),
        "version" => Some("version"),
        "venv" | "virtualenv" | "v" => Some("venv"),
        "pip" => match args
            .get(i + 1 + command_offset(&args[i + 1..], true)?)?
            .as_str()
        {
            "compile" => Some("pip compile"),
            "install" => Some("pip install"),
            "sync" => Some("pip sync"),
            "uninstall" => Some("pip uninstall"),
            "list" | "ls" => Some("pip list"),
            "tree" => Some("pip tree"),
            _ => None,
        },
        "tool" => match args
            .get(i + 1 + command_offset(&args[i + 1..], false)?)?
            .as_str()
        {
            "run" | "uvx" => Some("tool run"),
            "install" => Some("tool install"),
            "upgrade" | "update" => Some("tool upgrade"),
            "list" | "ls" => Some("tool list"),
            _ => None,
        },
        _ => None,
    }
}

fn command_offset(args: &[String], pip: bool) -> Option<usize> {
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        let flag = arg.split('=').next()?;
        match flag {
            "--cert" if pip => {
                if !arg.contains('=') {
                    i += 1;
                    if args
                        .get(i)
                        .is_none_or(|v| v.is_empty() || v.starts_with('-'))
                    {
                        return None;
                    }
                } else if arg.ends_with('=') {
                    return None;
                }
            }
            "--color"
            | "--cache-dir"
            | "--directory"
            | "--project"
            | "--config-file"
            | "--trusted-host"
            | "--allow-insecure-host"
            | "--preview-feature"
            | "--preview-features"
            | "--no-preview-features" => {
                if !arg.contains('=') {
                    i += 1;
                    if args
                        .get(i)
                        .is_none_or(|v| v.is_empty() || v.starts_with('-'))
                    {
                        return None;
                    }
                } else if arg.ends_with('=') {
                    return None;
                }
            }
            "-q"
            | "--quiet"
            | "-v"
            | "--verbose"
            | "-n"
            | "--no-cache"
            | "--no-config"
            | "--no-offline"
            | "--no-system-certs"
            | "--no-native-tls"
            | "--offline"
            | "--no-progress"
            | "--system-certs"
            | "--native-tls"
            | "--managed-python"
            | "--no-managed-python"
            | "--no-python-downloads"
            | "--preview"
            | "--no-preview" => {
                if arg.contains('=') {
                    return None;
                }
            }
            value
                if value.starts_with('-')
                    && value.len() > 1
                    && value[1..].bytes().all(|v| matches!(v, b'q' | b'v')) => {}
            value if value.starts_with('-') => return None,
            _ => break,
        }
        i += 1;
    }
    Some(i)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Credential {
    pub service: String,
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scheme: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Credentials {
    pub credential: Vec<Credential>,
}

pub(crate) fn https_service(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| "invalid uv credential service URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || value.len() > 8192
        || value.chars().any(char::is_control)
    {
        return Err(
            "uv credentials require an HTTPS URL without userinfo, query, or fragment".into(),
        );
    }
    Ok(url)
}

impl Credentials {
    pub(crate) fn from_toml(value: &str) -> Result<Self, String> {
        let mut credentials: Self = toml::from_str(value).map_err(|_| {
            "unsupported uv credential store; expected HTTP Basic credentials".to_string()
        })?;
        if credentials.credential.is_empty() || credentials.credential.len() > 256 {
            return Err("uv credential store must contain 1–256 credentials".into());
        }
        let mut seen = std::collections::HashSet::new();
        for credential in &mut credentials.credential {
            credential.service = https_service(&credential.service)?.to_string();
            if !seen.insert((credential.service.clone(), credential.username.clone()))
                || credential.scheme.as_deref().is_some_and(|v| v != "basic")
                || credential.username.is_empty()
                || credential.username.len() > 1024
                || credential.password.trim_end() != credential.password
                || credential.password.is_empty()
                || credential.username.chars().any(char::is_control)
                || credential.password.chars().any(char::is_control)
            {
                return Err("unsupported, duplicate, or malformed uv credential".into());
            }
            credential.scheme = None;
        }
        credentials
            .credential
            .sort_by(|a, b| (&a.service, &a.username).cmp(&(&b.service, &b.username)));
        Ok(credentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn positive_command_routing() {
        for command in [
            "add",
            "remove",
            "sync",
            "lock",
            "upgrade",
            "tree",
            "export",
            "audit",
            "check",
            "run",
            "build",
            "publish",
            "version",
            "venv",
            "virtualenv",
            "v",
            "pip ls",
            "tool ls",
            "tool update",
            "pip --offline install",
            "tool --directory=auth run",
            "-qvv pip --cert bundle.pem install",
            "pip compile",
            "pip install",
            "pip sync",
            "pip uninstall",
            "pip list",
            "pip tree",
            "tool run",
            "tool uvx",
            "tool install",
            "tool upgrade",
            "tool list",
        ] {
            let args = command.split(' ').map(String::from).collect::<Vec<_>>();
            assert!(credential_command(&args).is_some(), "{command}");
            let mut prefixed = vec!["--directory".into(), "auth".into()];
            prefixed.extend(args);
            assert!(credential_command(&prefixed).is_some(), "{command}");
        }
        for command in [
            "",
            "--help",
            "pip install --help",
            "run -V",
            "--version",
            "help",
            "auth token",
            "auth helper get",
            "auth login",
            "init",
            "format",
            "python install",
            "self update",
            "pip show",
            "pip freeze",
            "pip check",
            "tool uninstall",
            "tool audit",
            "workspace list",
            "future",
            "--future run",
            "--directory",
            "--directory= run",
            "-- run",
            "--project publish auth token",
        ] {
            assert!(
                credential_command(
                    &command
                        .split_whitespace()
                        .map(String::from)
                        .collect::<Vec<_>>()
                )
                .is_none(),
                "{command}"
            );
        }
    }
    #[test]
    fn migration_preserves_scope_and_rejects_unsupported_auth() {
        let fixture = "[[credential]]\nservice = 'https://example.com/private/'\nusername = 'alice'\npassword = 'dummy'\n";
        let parsed = Credentials::from_toml(fixture).unwrap();
        assert_eq!(parsed.credential[0].service, "https://example.com/private/");
        for bad in [
            fixture.replace("https:", "http:"),
            fixture.replace("password", "token"),
            fixture.replace("dummy", ""),
            format!("{fixture}{fixture}"),
            format!("{fixture}future = true\n"),
        ] {
            assert!(Credentials::from_toml(&bad).is_err());
        }
        assert!(https_service("example.com").is_err());
        assert!(https_service("https://alice@example.com").is_err());
    }
}

pub(crate) fn credentials_path() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("UV_CREDENTIALS_DIR").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(path).join("credentials.toml"));
    }
    if let Some(path) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(path).join("uv/credentials/credentials.toml"));
    }
    std::env::var_os("HOME")
        .map(|p| PathBuf::from(p).join(".local/share/uv/credentials/credentials.toml"))
        .ok_or_else(|| "HOME is not set".into())
}
