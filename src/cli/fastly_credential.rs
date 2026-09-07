use std::ffi::OsString;
use std::io::{Read, Write};

use ring::digest::{SHA256, digest};
use serde_json::{Value, json};

use super::inject;

const ENDPOINT: &str = "https://api.fastly.com";
const MAX_INPUT_BYTES: u64 = 64 * 1024;
const MAX_NAME_BYTES: usize = 128;
const SECRET_PREFIX: &str = "FASTLY_API_TOKEN_";

pub(crate) fn run(args: Vec<OsString>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let mut stdin = std::io::stdin().lock();
    match run_with_io(&args, &mut stdin, stdout) {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "fastly-credential: {error}");
            1
        }
    }
}

fn run_with_io(
    args: &[OsString],
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<(), String> {
    let [action, name, endpoint] = args else {
        return Err(
            "usage: av fastly-credential <get|store|forget> <name> https://api.fastly.com".into(),
        );
    };
    let action = action
        .to_str()
        .ok_or_else(|| "credential action must be valid UTF-8".to_string())?;
    let name = normalize_name(
        name.to_str()
            .ok_or_else(|| "Fastly token name must be valid UTF-8".to_string())?,
    )?;
    let endpoint = normalize_endpoint(
        endpoint
            .to_str()
            .ok_or_else(|| "Fastly endpoint must be valid UTF-8".to_string())?,
    )?;
    let scope = scope(&name, &endpoint);
    let account = secret_name(&name, &endpoint);
    crate::secrets::ensure_fastly_helper_ready()?;
    match action {
        "get" => {
            let token = match inject::fastly_credential(account.clone(), scope) {
                Ok(value) => parse_token(&value)?,
                Err(error) if error == format!("failed to load secret {account}: -25300") => {
                    return Err(format!("no Fastly credential is stored for token {name:?}"));
                }
                Err(error) => return Err(error),
            };
            writeln!(output, "{token}")
                .map_err(|error| format!("failed to return Fastly credential: {error}"))
        }
        "store" => {
            let token = parse_token(&read_limited(input)?)?;
            crate::secrets::store_fastly_credential(&scope, &token)
        }
        "forget" => crate::secrets::delete_fastly_credential(&scope, &account),
        _ => Err(format!("unsupported Fastly credential action: {action}")),
    }
}

pub(crate) fn normalize_name(name: &str) -> Result<String, String> {
    if name.is_empty()
        || name.len() > MAX_NAME_BYTES
        || name.trim() != name
        || !name.is_ascii()
        || name.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err("invalid Fastly token name".into());
    }
    Ok(name.to_string())
}

pub(crate) fn normalize_endpoint(endpoint: &str) -> Result<String, String> {
    if endpoint != ENDPOINT {
        return Err(format!("Fastly endpoint must be {ENDPOINT}"));
    }
    Ok(endpoint.to_string())
}

pub(crate) fn parse_token(token: &str) -> Result<String, String> {
    if token.is_empty()
        || token.len() > MAX_INPUT_BYTES as usize
        || token.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
    {
        return Err("Fastly token must be non-empty and contain no NUL or line breaks".into());
    }
    Ok(token.to_string())
}

pub(crate) fn scope(name: &str, endpoint: &str) -> String {
    json!({"endpoint": endpoint, "name": name}).to_string()
}

pub(crate) fn parse_scope(input: &str) -> Result<(String, String), String> {
    let value: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid Fastly credential scope: {error}"))?;
    let object = value
        .as_object()
        .filter(|object| object.len() == 2)
        .ok_or_else(|| {
            "Fastly credential scope must contain only `name` and `endpoint`".to_string()
        })?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "Fastly credential scope is missing `name`".to_string())?;
    let endpoint = object
        .get("endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| "Fastly credential scope is missing `endpoint`".to_string())?;
    let name = normalize_name(name)?;
    let endpoint = normalize_endpoint(endpoint)?;
    if input != scope(&name, &endpoint) {
        return Err("Fastly credential scope is not canonical".into());
    }
    Ok((name, endpoint))
}

pub(crate) fn secret_name(name: &str, endpoint: &str) -> String {
    let hash = digest(&SHA256, format!("{name}\0{endpoint}").as_bytes());
    let hex = hash
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    format!("{SECRET_PREFIX}{hex}")
}

fn read_limited(input: &mut dyn Read) -> Result<String, String> {
    let mut bytes = Vec::new();
    input
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read Fastly credential: {error}"))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!("Fastly credential exceeds {MAX_INPUT_BYTES} bytes"));
    }
    String::from_utf8(bytes).map_err(|_| "Fastly credential must be valid UTF-8".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn scope_is_canonical_and_name_bound() {
        assert!(normalize_endpoint("https://api.fastly.com/").is_err());
        assert_ne!(secret_name("prod", ENDPOINT), secret_name("dev", ENDPOINT));
        let value = scope("prod", ENDPOINT);
        assert_eq!(
            parse_scope(&value).unwrap(),
            ("prod".into(), ENDPOINT.into())
        );
        assert!(
            parse_scope(r#"{"name":"prod","endpoint":"https://api.fastly.com","extra":true}"#)
                .is_err()
        );
    }

    #[test]
    fn helper_store_get_and_forget_use_test_secret_custody() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root = std::env::temp_dir().join(format!("av-fastly-helper-{}", std::process::id()));
        let keychain = root.join("keychain");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain) };
        let invoke = |action: &str| vec![action.into(), "prod".into(), ENDPOINT.into()];
        run_with_io(&invoke("store"), &mut "token".as_bytes(), &mut Vec::new()).unwrap();
        let mut output = Vec::new();
        run_with_io(&invoke("get"), &mut "".as_bytes(), &mut output).unwrap();
        assert_eq!(output, b"token\n");
        run_with_io(&invoke("forget"), &mut "".as_bytes(), &mut Vec::new()).unwrap();
        assert!(run_with_io(&invoke("get"), &mut "".as_bytes(), &mut Vec::new()).is_err());
        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR") };
        let _ = fs::remove_dir_all(root);
    }
}
