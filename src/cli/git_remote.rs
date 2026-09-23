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
    for _ in 0..plan.options.len() + plan.leases.len() {
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
            xpc_set_u64(message, "requested_version", 3);
            Ok(())
        })?;
        super::git::verify_runtime()?;
        session(
            &mut std::io::stdin().lock(),
            url,
            stdout,
            &mut |source| {
                local(&[
                    "rev-parse",
                    "--verify",
                    "--end-of-options",
                    &format!("{source}^{{commit}}"),
                ])
            },
            &mut |plan, output| network(plan, output, stderr),
        )?;
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

fn session(
    input: &mut impl BufRead,
    url: &str,
    stdout: &mut dyn Write,
    resolve: &mut impl FnMut(&str) -> Result<String, String>,
    execute: &mut impl FnMut(&RemotePlan, &mut dyn Write) -> Result<(), String>,
) -> Result<(), String> {
    let mut options = BTreeMap::new();
    let mut leases = BTreeMap::new();
    let mut lease_bytes = 0;
    while let Some(value) = line(input)? {
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
            if key == "cas" {
                let (reference, oid) = value.split_once(':').ok_or("malformed Git lease")?;
                lease_bytes += value.len();
                if !valid_branch(reference)
                    || !valid_oid(oid)
                    || leases.len() >= 4096
                    || lease_bytes > 1024 * 1024
                    || leases.contains_key(reference)
                {
                    return Err("invalid, duplicate, or oversized Git lease".into());
                }
                leases.insert(reference.to_owned(), oid.to_owned());
            } else if !valid_option(key, value) {
                return Err(format!(
                    "unsupported Git option: {key}; protected HTTPS transport does not support \
                         --atomic or --signed pushes.\n\
                         See https://github.com/automic-vault/automic-vault/blob/main/docs/adr/0047-protected-git-https-transport.md#validation-and-limits"
                ));
            } else {
                options.insert(key.to_owned(), value.to_owned());
            }
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
                    let next = line(input)?.ok_or("incomplete Git batch")?;
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
                    let (force, source) = source
                        .strip_prefix('+')
                        .map_or((false, source), |s| (true, s));
                    if force && leases.contains_key(destination) {
                        return Err(
                            "cannot combine unconditional force and a lease for the same branch"
                                .into(),
                        );
                    }
                    if !(source == "HEAD" || valid_oid(source) || valid_branch(source))
                        || !valid_branch(destination)
                    {
                        return Err(
                            "only branch updates are supported; tags and deletion are unsupported"
                                .into(),
                        );
                    }
                    let oid = resolve(source)?;
                    if !valid_oid(&oid) {
                        return Err("invalid push object ID".into());
                    }
                    *command = format!("push {}{oid}:{destination}", if force { "+" } else { "" });
                }
            }
            let plan = RemotePlan {
                url: url.into(),
                phase,
                options: options.clone(),
                leases: std::mem::take(&mut leases),
                commands,
            };
            plan.validate()?;
            execute(&plan, stdout)?;
            lease_bytes = 0;
        }
    }
    if !leases.is_empty() {
        return Err("incomplete Git lease request".into());
    }
    Ok(())
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

#[test]
fn force_and_leases_freeze_complete_batches_before_execution() {
    let old = "a".repeat(40);
    let new = "b".repeat(40);
    let input = format!(
        "option cas refs/heads/z:{old}\noption cas refs/heads/a:{}\noption dry-run true\n\
         push HEAD:refs/heads/z\npush refs/heads/topic:refs/heads/a\n\n\
         push +HEAD:refs/heads/z\n\n\n",
        "0".repeat(40)
    );
    let mut plans = Vec::new();
    let mut sources = Vec::new();
    session(
        &mut std::io::Cursor::new(input),
        "https://github.com/a/b.git",
        &mut Vec::new(),
        &mut |source| {
            sources.push(source.to_owned());
            Ok(new.clone())
        },
        &mut |plan, _| {
            plans.push((plan.wire(), plan.payload()));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(sources, ["HEAD", "refs/heads/topic", "HEAD"]);
    let expected = vec![
        "remote-helper".to_owned(),
        "https://github.com/a/b.git".into(),
        "push".into(),
        format!("option cas refs/heads/a:{}", "0".repeat(40)),
        format!("option cas refs/heads/z:{old}"),
        "option dry-run true".into(),
        "".into(),
        format!("push {new}:refs/heads/z"),
        format!("push {new}:refs/heads/a"),
    ];
    assert_eq!(plans[0].0, expected);
    assert_eq!(
        String::from_utf8(plans[0].1.clone()).unwrap(),
        format!(
            "option cas refs/heads/a:{}\noption cas refs/heads/z:{old}\noption dry-run true\npush {new}:refs/heads/z\npush {new}:refs/heads/a\n\n\n",
            "0".repeat(40)
        )
    );
    assert_eq!(
        plans[1].0,
        [
            "remote-helper",
            "https://github.com/a/b.git",
            "push",
            "option dry-run true",
            "",
            &format!("push +{new}:refs/heads/z")
        ]
    );
}

#[test]
fn invalid_force_and_lease_requests_never_execute() {
    let oid = "a".repeat(40);
    let lease = format!("option cas refs/heads/main:{oid}\n");
    for input in [
        format!("{lease}push +HEAD:refs/heads/main\n\n"),
        format!("{lease}{lease}push HEAD:refs/heads/main\n\n"),
        format!("{lease}push HEAD:refs/heads/other\n\n"),
        format!("{lease}list for-push\n"),
        format!("{lease}fetch {oid} HEAD\n\n"),
        format!("{lease}push HEAD:refs/heads/main\n"),
        lease,
        "option cas refs/heads/main:HEAD\n".into(),
        "option cas refs/heads/main:\n".into(),
        format!("option cas refs/tags/v1:{oid}\n"),
        "push ++HEAD:refs/heads/main\n\n".into(),
        "push :refs/heads/main\n\n".into(),
        "push +HEAD:refs/tags/v1\n\n".into(),
        "push HEAD:refs/heads/main\npush +HEAD:refs/heads/main\n\n".into(),
        "push HEAD:refs/heads/main\nget https://evil /tmp/token\n\n".into(),
    ] {
        let mut executions = 0;
        let result = session(
            &mut std::io::Cursor::new(&input),
            "https://github.com/a/b.git",
            &mut Vec::new(),
            &mut |_| Ok(oid.clone()),
            &mut |_, _| {
                executions += 1;
                Ok(())
            },
        );
        assert!(result.is_err(), "{input:?}");
        assert_eq!(executions, 0, "{input:?}");
    }
    // A denied execution terminates the session; no fallback or next request.
    let input = "push +HEAD:refs/heads/main\n\npush HEAD:refs/heads/other\n\n";
    let mut executions = 0;
    assert!(
        session(
            &mut std::io::Cursor::new(input),
            "https://github.com/a/b.git",
            &mut Vec::new(),
            &mut |_| Ok(oid.clone()),
            &mut |_, _| {
                executions += 1;
                Err("denied".into())
            }
        )
        .is_err()
    );
    assert_eq!(executions, 1);
}
