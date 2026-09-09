use std::ffi::OsString;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use super::credential_xpc::*;
use crate::uv::*;

pub(crate) fn ensure_helper_ready() -> Result<(), String> {
    let version = xpc_request("uv-helper-version", |message| unsafe {
        xpc_set_u64(message, "requested_version", 1);
        Ok(())
    })?;
    (version == "1")
        .then_some(())
        .ok_or_else(|| "update and reopen Automic Vault before hardening uv".into())
}

pub(crate) fn run(mut args: Vec<OsString>, uvx: bool, stderr: &mut dyn Write) -> i32 {
    let result = (|| {
        if unsafe { libc::geteuid() } == 0 {
            return Err("uv launcher must not run as root".into());
        }
        let stub_path = if uvx {
            "/usr/local/bin/uvx"
        } else {
            "/usr/local/bin/uv"
        };
        let expected = if uvx { UVX_STUB } else { STUB };
        if args.first().and_then(|s| s.to_str()) != Some(stub_path) {
            return Err("uv requires its installed Automic Vault launcher".into());
        }
        crate::isotopes::hardeners::uv_cli::verify_stub(Path::new(stub_path), expected)?;
        args.remove(0);
        if uvx {
            args.splice(0..0, ["tool".into(), "run".into()]);
        }
        crate::isotopes::hardeners::uv_cli::verify_installation()?;
        let words = args
            .iter()
            .map(|v| v.to_str().map(str::to_string))
            .collect::<Option<Vec<_>>>();
        let nonce = if let Some(words) = words
            .as_ref()
            .filter(|words| credential_command(words).is_some())
        {
            let cwd = crate::path_security::current_working_directory_utf8()?;
            Some(xpc_request("uv-register", |message| unsafe {
                xpc_set_string(message, "target", TARGET)?;
                xpc_set_string(message, "cwd", &cwd)?;
                xpc_set_string(message, "entry", if uvx { "uvx" } else { "uv" })?;
                xpc_set_array(message, "args", words)?;
                Ok(())
            })?)
        } else {
            None
        };
        let mut command = Command::new(TARGET);
        command
            .args(&args)
            .env_remove("AV_UV_NONCE")
            .env_remove(SECRET);
        // The private PATH entry contains only the root-owned keyring stub. Children
        // may inherit the nonce, but cannot satisfy the helper's live-parent binding.
        let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
        let mut search = OsString::from("/opt/av/uv/bin:");
        search.push(path);
        command
            .env("PATH", search)
            .env("UV_KEYRING_PROVIDER", "subprocess");
        if let Some(nonce) = nonce {
            command.env("AV_UV_NONCE", nonce);
        }
        Err(format!("failed to execute official uv: {}", command.exec()))
    })();
    if let Err(error) = result as Result<(), String> {
        let _ = writeln!(stderr, "uv: {error}");
    }
    1
}

pub(crate) fn keyring(args: Vec<OsString>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let result = (|| {
        if args.first().and_then(|s| s.to_str()) != Some(HELPER) {
            return Err("uv keyring requires its installed helper".into());
        }
        crate::isotopes::hardeners::uv_cli::verify_stub(Path::new(HELPER), HELPER_STUB)?;
        let words = args
            .iter()
            .map(|v| v.to_str())
            .collect::<Option<Vec<_>>>()
            .ok_or("uv keyring arguments must be UTF-8")?;
        let (service, username) = match words.as_slice() {
            [_, "get", service, "--mode", "creds"] => (*service, None),
            [_, "get", service, username] if !username.is_empty() && !username.starts_with('-') => {
                (*service, Some(*username))
            }
            _ => return Err("unsupported uv keyring invocation".into()),
        };
        https_service(service)?; // Never accept the scheme-less host fallback.
        let nonce =
            std::env::var("AV_UV_NONCE").map_err(|_| "uv keyring has no registered invocation")?;
        if nonce.len() != 64 || !nonce.bytes().all(|v| v.is_ascii_hexdigit()) {
            return Err("invalid uv registration nonce".into());
        }
        let value = xpc_request("uv-get", |message| unsafe {
            xpc_set_string(message, "target", "")?;
            xpc_set_string(message, "cwd", "")?;
            xpc_set_string(message, "tool", "uv")?;
            xpc_set_string(message, "uv_nonce", &nonce)?;
            xpc_set_string(message, "uv_service", service)?;
            if let Some(username) = username {
                xpc_set_string(message, "uv_username", username)?;
            }
            xpc_set_array(message, "keys", &[SECRET.into()])?;
            xpc_set_array(message, "args", &[])?;
            xpc_set_array(message, "env_conflicts", &[])?;
            Ok(())
        })?;
        writeln!(stdout, "{value}").map_err(|e| e.to_string())
    })();
    match result {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "uv keyring: {error}");
            1
        }
    }
}
