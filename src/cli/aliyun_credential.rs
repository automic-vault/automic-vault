use std::ffi::OsString;
use std::io::Write;

use ring::digest::{SHA256, digest};
use serde_json::{Map, Value};

use super::inject;

const MAX_PROFILE_BYTES: usize = 128;
const MAX_VALUE_BYTES: usize = 64 * 1024;
const SECRET_PREFIX: &str = "ALIYUN_PROFILE_CREDENTIAL_";

pub(crate) fn run(args: Vec<OsString>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    match run_with_io(&args, stdout) {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "aliyun-credential: {error}");
            1
        }
    }
}

fn run_with_io(args: &[OsString], output: &mut dyn Write) -> Result<(), String> {
    let [profile] = args else {
        return Err("usage: av aliyun-credential <profile>".into());
    };
    let profile = normalize_profile(
        profile
            .to_str()
            .ok_or_else(|| "Alibaba Cloud profile must be valid UTF-8".to_string())?,
    )?;
    crate::secrets::ensure_aliyun_helper_ready()?;
    let account = secret_name(&profile);
    let value = match inject::aliyun_credential(account.clone(), profile.clone()) {
        Ok(value) => parse_credential(&value)?,
        Err(error) if error == format!("failed to load secret {account}: -25300") => {
            return Err(format!(
                "no Alibaba Cloud credential is stored for profile {profile:?}"
            ));
        }
        Err(error) => return Err(error),
    };
    writeln!(output, "{value}")
        .map_err(|error| format!("failed to return Alibaba Cloud credential: {error}"))
}

pub(crate) fn normalize_profile(profile: &str) -> Result<String, String> {
    if profile.is_empty()
        || profile.len() > MAX_PROFILE_BYTES
        || profile.trim() != profile
        || !profile.is_ascii()
        || profile.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err("invalid Alibaba Cloud profile name".into());
    }
    Ok(profile.to_string())
}

pub(crate) fn process_command(profile: &str) -> String {
    format!(
        "/usr/local/bin/av aliyun-credential '{}'",
        profile.replace('\'', "'\\''")
    )
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

pub(crate) fn credential(
    mode: &str,
    access_key_id: &str,
    access_key_secret: &str,
    sts_token: Option<&str>,
) -> Result<String, String> {
    let mut object = Map::new();
    object.insert("mode".into(), Value::String(mode.into()));
    object.insert(
        "access_key_id".into(),
        Value::String(validate_value("AccessKey ID", access_key_id)?),
    );
    object.insert(
        "access_key_secret".into(),
        Value::String(validate_value("AccessKey secret", access_key_secret)?),
    );
    match (mode, sts_token) {
        ("AK", None) => {}
        ("StsToken", Some(token)) => {
            object.insert(
                "sts_token".into(),
                Value::String(validate_value("STS token", token)?),
            );
        }
        ("AK", Some(_)) => return Err("AK profile must not contain an STS token".into()),
        ("StsToken", None) => return Err("StsToken profile requires an STS token".into()),
        _ => return Err("unsupported Alibaba Cloud credential mode".into()),
    }
    Ok(Value::Object(object).to_string())
}

pub(crate) fn parse_credential(input: &str) -> Result<String, String> {
    if input.len() > MAX_VALUE_BYTES {
        return Err("Alibaba Cloud credential exceeds 64 KiB".into());
    }
    let value: Value = serde_json::from_str(input)
        .map_err(|error| format!("invalid Alibaba Cloud credential JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "Alibaba Cloud credential must be a JSON object".to_string())?;
    let mode = object
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| "Alibaba Cloud credential requires string field `mode`".to_string())?;
    let access_key_id = field(object, "access_key_id")?;
    let access_key_secret = field(object, "access_key_secret")?;
    let sts_token = object
        .get("sts_token")
        .map(|_| field(object, "sts_token"))
        .transpose()?;
    let expected = if mode == "StsToken" { 4 } else { 3 };
    if object.len() != expected {
        return Err("Alibaba Cloud credential contains unsupported fields".into());
    }
    credential(mode, access_key_id, access_key_secret, sts_token)
}

fn field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Alibaba Cloud credential requires string field `{name}`"))
}

fn validate_value(label: &str, value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > MAX_VALUE_BYTES
        || value.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
    {
        return Err(format!(
            "{label} must be non-empty and contain no NUL or line breaks"
        ));
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn credential_is_profile_bound_and_strict() {
        assert_ne!(secret_name("prod"), secret_name("dev"));
        assert_eq!(
            process_command("team's prod"),
            "/usr/local/bin/av aliyun-credential 'team'\\''s prod'"
        );
        let value = credential("StsToken", "id", "secret", Some("session")).unwrap();
        assert_eq!(parse_credential(&value).unwrap(), value);
        assert!(
            parse_credential(
                r#"{"mode":"AK","access_key_id":"id","access_key_secret":"secret","future":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn helper_reads_only_the_selected_profile_secret() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root = std::env::temp_dir().join(format!("av-aliyun-helper-{}", std::process::id()));
        let keychain = root.join("keychain");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&keychain).unwrap();
        let value = credential("AK", "id", "secret", None).unwrap();
        fs::write(keychain.join(secret_name("prod")), &value).unwrap();
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &keychain) };
        let mut output = Vec::new();
        run_with_io(&["prod".into()], &mut output).unwrap();
        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR") };
        assert_eq!(String::from_utf8(output).unwrap(), format!("{value}\n"));
        let _ = fs::remove_dir_all(root);
    }
}
