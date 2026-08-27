use std::ffi::OsString;
use std::io::Write;

use super::inject;

pub(crate) const SECRET_NAME: &str = "RCLONE_CONFIG_PASSWORD";

pub(crate) fn run(args: Vec<OsString>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    match run_inner(&args, stdout) {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "rclone-password: {error}");
            1
        }
    }
}

fn run_inner(args: &[OsString], stdout: &mut dyn Write) -> Result<(), String> {
    let [version] = args else {
        return Err("usage: av rclone-password 1".into());
    };
    if version != "1" {
        return Err("unsupported rclone password request".into());
    }
    crate::secrets::ensure_rclone_helper_ready()?;
    let password = inject::rclone_password(SECRET_NAME.into())?;
    validate_password(&password)?;
    writeln!(stdout, "{password}")
        .map_err(|error| format!("failed to return rclone config password: {error}"))
}

pub(crate) fn validate_password(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 1024
        || value.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
    {
        return Err("invalid rclone config password".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_passwords_that_cannot_be_returned_as_one_line() {
        assert!(validate_password("correct horse battery staple").is_ok());
        assert!(validate_password("").is_err());
        assert!(validate_password("line\nbreak").is_err());
        assert!(validate_password("nul\0byte").is_err());
    }
}
