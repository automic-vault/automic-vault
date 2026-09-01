use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;

use ring::digest::{SHA256, digest};
use serde_json::{Value, json};

const MAX_EXEC_INFO_BYTES: usize = 64 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 4 * 1024 * 1024;

pub(crate) fn run(args: Vec<OsString>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    match run_inner(&args, stdout) {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "kubectl-credential: {error}");
            1
        }
    }
}

fn run_inner(args: &[OsString], stdout: &mut dyn Write) -> Result<(), String> {
    let [version, kind, user] = args else {
        return Err("usage: av kubectl-credential 1 <token|client-certificate> <user>".into());
    };
    if version != "1" {
        return Err("unsupported kubectl credential request".into());
    }
    let kind = kind
        .to_str()
        .ok_or_else(|| "kubectl credential kind must be UTF-8".to_string())?;
    let user = user
        .to_str()
        .ok_or_else(|| "kubectl user name must be UTF-8".to_string())?;
    validate_user(user)?;
    if !matches!(kind, "token" | "client-certificate") {
        return Err("unsupported kubectl credential kind".into());
    }
    let info = std::env::var("KUBERNETES_EXEC_INFO")
        .map_err(|_| "KUBERNETES_EXEC_INFO is missing or is not UTF-8".to_string())?;
    let server = exec_server(&info)?;
    let scope = credential_scope(kind, &server, user)?;
    let key = secret_name(user);
    crate::secrets::ensure_kubectl_helper_ready()?;
    let stored = super::inject::kubectl_credential(key, scope)?;
    let status = credential_status(kind, &stored)?;
    let response = json!({
        "apiVersion": "client.authentication.k8s.io/v1",
        "kind": "ExecCredential",
        "status": status,
    });
    serde_json::to_writer(&mut *stdout, &response)
        .map_err(|error| format!("failed to return kubectl credential: {error}"))?;
    writeln!(stdout).map_err(|error| format!("failed to return kubectl credential: {error}"))
}

pub(crate) fn secret_name(user: &str) -> String {
    let hash = digest(&SHA256, user.as_bytes());
    let suffix = hash
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    format!("KUBECTL_USER_CREDENTIAL_{suffix}")
}

pub(crate) fn validate_user(user: &str) -> Result<(), String> {
    if user.is_empty()
        || user.len() > 1024
        || user.trim() != user
        || user.chars().any(|ch| ch.is_control())
    {
        return Err("invalid kubectl user name".into());
    }
    Ok(())
}

pub(crate) fn credential_scope(kind: &str, server: &str, user: &str) -> Result<String, String> {
    validate_user(user)?;
    if !matches!(kind, "token" | "client-certificate") {
        return Err("unsupported kubectl credential kind".into());
    }
    let server = normalize_server(server)?;
    let fields = BTreeMap::from([("kind", kind), ("server", server.as_str()), ("user", user)]);
    serde_json::to_string(&fields)
        .map_err(|error| format!("failed to encode kubectl scope: {error}"))
}

fn normalize_server(server: &str) -> Result<String, String> {
    if server.is_empty() || server.len() > 4096 || !server.is_ascii() {
        return Err("invalid Kubernetes API server".into());
    }
    let url = url::Url::parse(server).map_err(|_| "invalid Kubernetes API server")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("invalid Kubernetes API server".into());
    }
    Ok(url.to_string())
}

fn exec_server(input: &str) -> Result<String, String> {
    if input.len() > MAX_EXEC_INFO_BYTES {
        return Err("KUBERNETES_EXEC_INFO exceeds 64 KiB".into());
    }
    let value: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid KUBERNETES_EXEC_INFO: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "invalid KUBERNETES_EXEC_INFO".to_string())?;
    if object.get("apiVersion").and_then(Value::as_str) != Some("client.authentication.k8s.io/v1")
        || object.get("kind").and_then(Value::as_str) != Some("ExecCredential")
    {
        return Err("unsupported kubectl ExecCredential request".into());
    }
    let spec = object
        .get("spec")
        .and_then(Value::as_object)
        .ok_or_else(|| "kubectl ExecCredential request has no spec".to_string())?;
    if spec.get("interactive").and_then(Value::as_bool) != Some(false) {
        return Err("interactive kubectl credential requests are not supported".into());
    }
    let server = spec
        .get("cluster")
        .and_then(Value::as_object)
        .and_then(|cluster| cluster.get("server"))
        .and_then(Value::as_str)
        .ok_or_else(|| "kubectl ExecCredential request has no API server".to_string())?;
    normalize_server(server)
}

pub(crate) fn credential_status(kind: &str, stored: &str) -> Result<Value, String> {
    if stored.len() > MAX_CREDENTIAL_BYTES {
        return Err("stored kubectl credential exceeds 4 MiB".into());
    }
    let object = serde_json::from_str::<Value>(stored)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or_else(|| "stored kubectl credential is invalid".to_string())?;
    match kind {
        "token" => {
            if object.len() != 1 {
                return Err("stored kubectl token is invalid".into());
            }
            let token = object
                .get("token")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if token.is_empty() || token.len() > 1024 * 1024 || token.contains('\0') {
                return Err("stored kubectl token is invalid".into());
            }
            Ok(json!({"token": token}))
        }
        "client-certificate" => {
            if object.len() != 2 {
                return Err("stored kubectl client certificate is invalid".into());
            }
            let certificate = object
                .get("clientCertificateData")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let key = object
                .get("clientKeyData")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !certificate.contains("-----BEGIN CERTIFICATE-----")
                || !key.contains("-----BEGIN")
                || !key.contains("PRIVATE KEY-----")
                || certificate.contains('\0')
                || key.contains('\0')
            {
                return Err("stored kubectl client certificate is invalid".into());
            }
            Ok(json!({"clientCertificateData": certificate, "clientKeyData": key}))
        }
        _ => Err("unsupported kubectl credential kind".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_are_canonical_and_bound_to_the_user_and_server() {
        assert_eq!(
            credential_scope("token", "https://EXAMPLE.com:443", "prod").unwrap(),
            r#"{"kind":"token","server":"https://example.com/","user":"prod"}"#
        );
        assert!(credential_scope("token", "https://user@example.com", "prod").is_err());
        assert!(credential_scope("token", "http://example.com", "prod").is_err());
        assert!(credential_scope("token", "file:///tmp/socket", "prod").is_err());
    }

    #[test]
    fn validates_exec_info_and_stored_credential_shape() {
        let info = r#"{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","spec":{"interactive":false,"cluster":{"server":"https://example.com"}}}"#;
        assert_eq!(exec_server(info).unwrap(), "https://example.com/");
        assert_eq!(
            credential_status("token", r#"{"token":"secret"}"#).unwrap(),
            json!({"token": "secret"})
        );
        assert!(credential_status("token", r#"{"token":"secret","future":true}"#).is_err());
    }
}
