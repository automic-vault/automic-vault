use std::ffi::OsString;
use std::io::{Read, Write};

use ring::digest::{SHA256, digest};
use serde_json::{Value, json};

use super::inject;

const MAX_INPUT_BYTES: u64 = 64 * 1024;
const MAX_PROFILE_BYTES: usize = 128;
const SECRET_PREFIX: &str = "SQLCMD_PASSWORD_";

pub(crate) fn run(args: Vec<OsString>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let mut stdin = std::io::stdin().lock();
    match run_with_io(&args, &mut stdin, stdout) {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "sqlcmd-credential: {error}");
            1
        }
    }
}

fn run_with_io(
    args: &[OsString],
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<(), String> {
    let action = args
        .first()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            "usage: av sqlcmd-credential <get|store|forget> <profile> [address port]".to_string()
        })?;
    let profile = normalize_profile(
        args.get(1)
            .and_then(|value| value.to_str())
            .ok_or_else(|| "sqlcmd user profile must be valid UTF-8".to_string())?,
    )?;
    let account = secret_name(&profile);
    crate::secrets::ensure_sqlcmd_helper_ready()?;
    match action {
        "get" => {
            if args.len() != 4 {
                return Err("get requires profile, address, and port".into());
            }
            let address = normalize_address(
                args[2]
                    .to_str()
                    .ok_or_else(|| "sqlcmd address must be valid UTF-8".to_string())?,
            )?;
            let port = normalize_port(
                args[3]
                    .to_str()
                    .ok_or_else(|| "sqlcmd port must be valid UTF-8".to_string())?,
                address.is_empty(),
            )?;
            let scope = scope(&profile, &address, port);
            let password = match inject::sqlcmd_credential(account.clone(), scope) {
                Ok(value) => parse_password(&value)?,
                Err(error) if error == format!("failed to load secret {account}: -25300") => {
                    return Err(format!(
                        "no sqlcmd credential is stored for profile {profile:?}"
                    ));
                }
                Err(error) => return Err(error),
            };
            writeln!(output, "{password}")
                .map_err(|error| format!("failed to return sqlcmd credential: {error}"))
        }
        "store" if args.len() == 2 => {
            let password = parse_password(&read_limited(input)?)?;
            crate::secrets::store_sqlcmd_credential(&scope(&profile, "", 0), &password)
        }
        "forget" if args.len() == 2 => {
            crate::secrets::delete_sqlcmd_credential(&scope(&profile, "", 0), &account)
        }
        _ => Err(format!("unsupported sqlcmd credential action: {action}")),
    }
}

pub(crate) fn normalize_profile(profile: &str) -> Result<String, String> {
    if profile.is_empty()
        || profile.len() > MAX_PROFILE_BYTES
        || profile.trim() != profile
        || !profile.is_ascii()
        || profile.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err("invalid sqlcmd user profile".into());
    }
    Ok(profile.to_string())
}

fn normalize_address(address: &str) -> Result<String, String> {
    if address.len() > 253
        || address.trim() != address
        || !address.is_ascii()
        || address.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err("invalid sqlcmd endpoint address".into());
    }
    Ok(address.to_string())
}

fn normalize_port(port: &str, empty_address: bool) -> Result<u16, String> {
    if empty_address && port == "0" {
        return Ok(0);
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| "invalid sqlcmd endpoint port".to_string())?;
    if empty_address || port == 0 {
        return Err("sqlcmd endpoint address and port must be provided together".into());
    }
    Ok(port)
}

pub(crate) fn parse_password(password: &str) -> Result<String, String> {
    if password.is_empty()
        || password.len() > MAX_INPUT_BYTES as usize
        || password
            .bytes()
            .any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
    {
        return Err("sqlcmd password must be non-empty and contain no NUL or line breaks".into());
    }
    Ok(password.to_string())
}

pub(crate) fn scope(profile: &str, address: &str, port: u16) -> String {
    json!({"address": address, "port": port, "profile": profile}).to_string()
}

pub(crate) fn parse_scope(input: &str) -> Result<(String, String, u16), String> {
    let value: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid sqlcmd credential scope: {error}"))?;
    let object = value
        .as_object()
        .filter(|object| object.len() == 3)
        .ok_or_else(|| {
            "sqlcmd credential scope must contain only `profile`, `address`, and `port`".to_string()
        })?;
    let profile = normalize_profile(
        object
            .get("profile")
            .and_then(Value::as_str)
            .ok_or_else(|| "sqlcmd credential scope is missing `profile`".to_string())?,
    )?;
    let address = normalize_address(
        object
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| "sqlcmd credential scope is missing `address`".to_string())?,
    )?;
    let raw_port = object
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| "sqlcmd credential scope has invalid `port`".to_string())?;
    let port = normalize_port(&raw_port.to_string(), address.is_empty())?;
    if input != scope(&profile, &address, port) {
        return Err("sqlcmd credential scope is not canonical".into());
    }
    Ok((profile, address, port))
}

pub(crate) fn secret_name(profile: &str) -> String {
    let hash = digest(&SHA256, profile.as_bytes());
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
        .map_err(|error| format!("failed to read sqlcmd credential: {error}"))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!("sqlcmd credential exceeds {MAX_INPUT_BYTES} bytes"));
    }
    String::from_utf8(bytes).map_err(|_| "sqlcmd credential must be valid UTF-8".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn scopes_are_canonical_and_profile_bound() {
        let value = scope("prod", "db.example.com", 1433);
        assert_eq!(
            parse_scope(&value).unwrap(),
            ("prod".into(), "db.example.com".into(), 1433)
        );
        assert_ne!(secret_name("prod"), secret_name("dev"));
        assert!(
            parse_scope(r#"{"address":"db","port":1433,"profile":"prod","extra":true}"#).is_err()
        );
        assert!(parse_scope(&scope("prod", "", 0)).is_ok());
    }

    #[test]
    fn helper_store_get_and_forget_use_test_secret_custody() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root = std::env::temp_dir().join(format!("av-sqlcmd-helper-{}", std::process::id()));
        let keychain = root.join("keychain");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain) };
        run_with_io(
            &["store".into(), "prod".into()],
            &mut "password".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        let mut output = Vec::new();
        run_with_io(
            &[
                "get".into(),
                "prod".into(),
                "db.example.com".into(),
                "1433".into(),
            ],
            &mut "".as_bytes(),
            &mut output,
        )
        .unwrap();
        assert_eq!(output, b"password\n");
        run_with_io(
            &["forget".into(), "prod".into()],
            &mut "".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR") };
        let _ = fs::remove_dir_all(root);
    }
}
