use std::ffi::OsString;
use std::io::Write;

use super::inject;

pub(crate) const API_URL: &str = "https://api.wakatime.com/api/v1";
pub(crate) const SECRET_NAME: &str = "WAKATIME_API_KEY";

pub(crate) fn run(args: Vec<OsString>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    match run_inner(&args, stdout) {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "wakatime-credential: {error}");
            1
        }
    }
}

fn run_inner(args: &[OsString], stdout: &mut dyn Write) -> Result<(), String> {
    let [version, api_url] = args else {
        return Err("usage: av wakatime-credential 1 https://api.wakatime.com/api/v1".into());
    };
    if version != "1" || api_url != API_URL {
        return Err("unsupported WakaTime credential request".into());
    }
    crate::secrets::ensure_wakatime_helper_ready()?;
    let key = inject::wakatime_credential(SECRET_NAME.into(), API_URL.into())?;
    validate_api_key(&key)?;
    writeln!(stdout, "{key}").map_err(|error| format!("failed to return WakaTime API key: {error}"))
}

pub(crate) fn validate_api_key(value: &str) -> Result<(), String> {
    let key = value.strip_prefix("waka_").unwrap_or(value);
    let bytes = key.as_bytes();
    let hyphens = [8, 13, 18, 23];
    if bytes.len() != 36
        || bytes[14] != b'4'
        || !matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        || bytes.iter().enumerate().any(|(index, byte)| {
            if hyphens.contains(&index) {
                *byte != b'-'
            } else {
                !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase()
            }
        })
    {
        return Err("invalid WakaTime API key".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_wakatime_v4_api_keys() {
        let valid = ["waka_01234567", "89ab", "4cde", "8fab", "0123456789ab"].join("-");
        let bare = ["01234567", "89ab", "4cde", "bfab", "0123456789ab"].join("-");
        let wrong_version = ["01234567", "89ab", "3cde", "8fab", "0123456789ab"].join("-");
        let uppercase = ["01234567", "89AB", "4cde", "8fab", "0123456789ab"].join("-");
        assert!(validate_api_key(&valid).is_ok());
        assert!(validate_api_key(&bare).is_ok());
        assert!(validate_api_key(&wrong_version).is_err());
        assert!(validate_api_key(&uppercase).is_err());
    }
}
