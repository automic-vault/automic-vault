//! Native remote-helper adapter. Only frozen, validated batches cross the Gate.
use super::credential_xpc::*;
use crate::git_transport::*;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

fn line(input: &mut impl BufRead) -> Result<Option<String>, String> {
    let mut bytes = Vec::new();
    input
        .take(8193)
        .read_until(b'\n', &mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > 8192
        || bytes.last() != Some(&b'\n')
        || bytes.contains(&0)
        || bytes.contains(&b'\r')
    {
        return Err("malformed remote-helper input".into());
    }
    bytes.pop();
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| "helper input must be UTF-8".into())
}

fn local(args: &[&str]) -> Result<String, String> {
    let mut command = Command::new(GIT);
    command
        .env_clear()
        .envs(environment("/opt/av/git/repository/objects", ""));
    // Local object/ref resolution has no credential registration. Use only Git's
    // repository selection, never its incoming config, trace, proxy or loader env.
    command
        .env_remove("GIT_DIR")
        .env_remove("GIT_OBJECT_DIRECTORY");
    if let Some(directory) = std::env::var_os("GIT_DIR") {
        command.env("GIT_DIR", directory);
    }
    let output = command
        .args(["--no-replace-objects"])
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("cannot resolve local Git repository or object".into());
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim().to_owned())
        .map_err(|_| "Git returned invalid UTF-8".into())
}

fn network(
    plan: &RemotePlan,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<(), String> {
    plan.validate()?;
    let objects = if plan.phase.starts_with("list") {
        format!("{REPOSITORY}/objects")
    } else {
        if local(&["rev-parse", "--show-object-format"])? != "sha1"
            || local(&["rev-parse", "--is-shallow-repository"])? != "false"
        {
            return Err("protected Git requires a full SHA-1 repository".into());
        }
        Path::new(&local(&["rev-parse", "--git-path", "objects"])?)
            .canonicalize()
            .map_err(|e| e.to_string())?
            .to_str()
            .ok_or("object directory must be UTF-8")?
            .to_owned()
    };
    let cwd = std::env::current_dir()
        .map_err(|e| e.to_string())?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let payload = plan.payload();
    let nonce = xpc_request("git-register", |message| unsafe {
        xpc_set_string(
            message,
            "cwd",
            cwd.to_str().ok_or("working directory must be UTF-8")?,
        )?;
        xpc_set_string(message, "objects", &objects)?;
        xpc_set_string(message, "phase", "remote-helper")?;
        xpc_set_string(message, "oid", "")?;
        xpc_set_array(message, "args", &plan.wire())
    })?;
    let result = (|| {
        let mut child = Command::new(GIT)
            .current_dir(ROOT)
            .env_clear()
            .envs(environment(&objects, &nonce))
            .args(plan.arguments())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        let mut input = child.stdin.take().ok_or("transport stdin unavailable")?;
        // Drain output while feeding a bounded batch, avoiding pipe-buffer deadlock.
        std::thread::scope(|scope| {
            let writer = scope.spawn(move || input.write_all(&payload));
            let output = child.wait_with_output().map_err(|e| e.to_string());
            writer
                .join()
                .map_err(|_| "transport writer failed")?
                .map_err(|e| e.to_string())?;
            output
        })
    })();
    // The child is gone before registration is removed or another request is read.
    xpc_request("git-unregister", |message| unsafe {
        xpc_set_string(message, "nonce", &nonce)
    })?;
    let output = result?;
    if !output.status.success() {
        // Network diagnostics from the confined runtime have no enabled trace or
        // alternate credential helper. Preserve useful GitHub/policy error messages.
        stderr
            .write_all(&output.stderr)
            .map_err(|e| e.to_string())?;
        return Err("protected HTTPS request failed".into());
    }
    let mut response = output.stdout.as_slice();
    for _ in &plan.options {
        let Some(rest) = response.strip_prefix(b"ok\n") else {
            return Err("HTTPS transport rejected a required option".into());
        };
        response = rest;
    }
    stderr
        .write_all(&output.stderr)
        .map_err(|e| e.to_string())?;
    stdout
        .write_all(response)
        .and_then(|_| stdout.flush())
        .map_err(|e| e.to_string())
}

pub(super) fn run(args: &[OsString], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let result = (|| {
        let [_, url] = args else {
            return Err("expected remote name and GitHub HTTPS URL".into());
        };
        let url = url
            .to_str()
            .filter(|s| valid_url(s))
            .ok_or("only https://github.com/OWNER/REPO.git is supported")?;
        if unsafe { libc::geteuid() } == 0 {
            return Err("must not run Git operations as root".into());
        }
        xpc_request("git-helper-version", |message| unsafe {
            xpc_set_u64(message, "requested_version", 2);
            Ok(())
        })?;
        super::git::verify_runtime()?;
        let mut input = std::io::stdin().lock();
        let mut options = BTreeMap::new();
        while let Some(value) = line(&mut input)? {
            if value.is_empty() {
                break;
            }
            if value == "capabilities" {
                stdout
                    .write_all(b"fetch\npush\noption\n\n")
                    .and_then(|_| stdout.flush())
                    .map_err(|e| e.to_string())?;
            } else if let Some(setting) = value.strip_prefix("option ") {
                let (key, value) = setting.split_once(' ').ok_or("malformed option")?;
                if !valid_option(key, value) {
                    return Err(format!("unsupported Git option: {key}"));
                }
                options.insert(key.to_owned(), value.to_owned());
                stdout
                    .write_all(b"ok\n")
                    .and_then(|_| stdout.flush())
                    .map_err(|e| e.to_string())?;
            } else {
                let phase = match value.as_str() {
                    "list" | "list for-push" => value.clone(),
                    s if s.starts_with("fetch ") => "fetch".into(),
                    s if s.starts_with("push ") => "push".into(),
                    _ => return Err("unsupported Git helper command".into()),
                };
                let mut commands = vec![value];
                let mut size = commands[0].len();
                if matches!(phase.as_str(), "fetch" | "push") {
                    loop {
                        let next = line(&mut input)?.ok_or("incomplete Git batch")?;
                        if next.is_empty() {
                            break;
                        }
                        size += next.len();
                        if !next.starts_with(&format!("{phase} "))
                            || commands.len() >= 4096
                            || size > 1024 * 1024
                        {
                            return Err("mixed or oversized Git batch".into());
                        }
                        commands.push(next);
                    }
                }
                if phase == "push" {
                    for command in &mut commands {
                        let (source, destination) = command
                            .strip_prefix("push ")
                            .and_then(|s| s.split_once(':'))
                            .ok_or("malformed push")?;
                        if !(source == "HEAD" || valid_oid(source) || valid_branch(source))
                            || !valid_branch(destination)
                        {
                            return Err("only non-forced branch updates are supported".into());
                        }
                        let oid = local(&[
                            "rev-parse",
                            "--verify",
                            "--end-of-options",
                            &format!("{source}^{{commit}}"),
                        ])?;
                        if !valid_oid(&oid) {
                            return Err("invalid push object ID".into());
                        }
                        *command = format!("push {oid}:{destination}");
                    }
                }
                network(
                    &RemotePlan {
                        url: url.into(),
                        phase,
                        options: options.clone(),
                        commands,
                    },
                    stdout,
                    stderr,
                )?;
            }
        }
        Ok::<_, String>(())
    })();
    match result {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "av Git: {error}");
            1
        }
    }
}

#[test]
fn helper_lines_require_bounded_complete_utf8_frames() {
    for bytes in [
        b"list".as_slice(),
        b"list\r\n",
        b"list\0\n",
        b"\xff\n",
        &vec![b'x'; 8193],
    ] {
        assert!(line(&mut std::io::Cursor::new(bytes)).is_err());
    }
    let mut input = std::io::Cursor::new(b"list\n\n");
    assert_eq!(line(&mut input).unwrap(), Some("list".into()));
    assert_eq!(line(&mut input).unwrap(), Some(String::new()));
    assert_eq!(line(&mut input).unwrap(), None);
}
