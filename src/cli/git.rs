use super::credential_xpc::*;
use crate::git_transport::*;
use std::ffi::{CString, OsString, c_char, c_void};
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

pub(crate) const DEPRECATION_WARNING: &str = "Automic Vault's Git HTTPS transport is deprecated. Use SSH with the Automic Vault SSH agent; see https://github.com/automic-vault/automic-vault/blob/main/docs/securing-git.md.";
const REVIEWED_GIT_VERSION: &[u8] = b"git version 2.50.1 (Apple Git-155)\n";

fn reviewed_git_version(version: &[u8]) -> Result<(), String> {
    if version != REVIEWED_GIT_VERSION {
        return Err("this Git build has not been reviewed for the protected transport".into());
    }
    Ok(())
}

#[test]
fn rejects_acl_writes_even_when_mode_is_private() {
    let file = std::env::temp_dir().join(format!("av-git-acl-{:016x}", rand::random::<u64>()));
    let path = file.as_path();
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    assert!(
        Command::new("/bin/chmod")
            .arg("-N")
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
    assert!(no_extended_acl(path));
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", "everyone allow write"])
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o600);
    assert!(!no_extended_acl(path));
    fs::remove_file(path).unwrap();
}

fn checked(mut command: Command) -> Result<Output, String> {
    let output = command
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if error.is_empty() {
            format!(
                "{} exited with {}",
                command.get_program().to_string_lossy(),
                output.status
            )
        } else {
            error
        });
    }
    Ok(output)
}

fn signing(path: &Path, requirement: &str) -> Result<(), String> {
    let mut command = Command::new("/usr/bin/codesign");
    command
        .env_clear()
        .args(["--verify", "--strict", &format!("-R={requirement}")])
        .arg(path);
    checked(command).map(|_| ())
}

fn protected(path: &Path, directory: bool) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || !no_extended_acl(path)
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file() || metadata.nlink() != 1
        }
    {
        return Err(format!(
            "{} must be root-owned and protected from replacement",
            path.display()
        ));
    }
    Ok(())
}

pub(crate) fn no_extended_acl(path: &Path) -> bool {
    unsafe extern "C" {
        fn acl_get_link_np(path: *const c_char, kind: i32) -> *mut c_void;
        fn acl_valid(acl: *mut c_void) -> i32;
        fn acl_get_entry(acl: *mut c_void, entry: i32, out: *mut *mut c_void) -> i32;
        fn acl_free(acl: *mut c_void) -> i32;
    }
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // Darwin sys/acl.h: ACL_TYPE_EXTENDED = 0x100, ACL_FIRST_ENTRY = 0.
    unsafe {
        let acl = acl_get_link_np(path.as_ptr(), 0x100);
        if acl.is_null() {
            // Darwin also reports ENOENT for an existing file with no ACL.
            // protected() separately requires valid lstat metadata.
            return std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT);
        }
        let mut entry = std::ptr::null_mut();
        let empty = acl_valid(acl) == 0
            && acl_get_entry(acl, 0, &mut entry) == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL);
        acl_free(acl);
        empty
    }
}

pub(super) fn verify_runtime() -> Result<(), String> {
    verify_runtime_at(Path::new(ROOT))
}

fn verify_runtime_at(root: &Path) -> Result<(), String> {
    let runtime_path = |path: &str| {
        Path::new(path)
            .strip_prefix(ROOT)
            .map(|relative| root.join(relative))
            .unwrap_or_else(|_| PathBuf::from(path))
    };
    for path in [
        "/opt",
        "/opt/av",
        ROOT,
        "/opt/av/git/bin",
        "/opt/av/git/empty",
        REPOSITORY,
        "/opt/av/git/repository/refs",
        "/opt/av/git/repository/refs/heads",
        "/opt/av/git/repository/objects",
        "/private",
        "/private/etc",
        "/private/etc/ssl",
    ] {
        protected(&runtime_path(path), true)?;
    }
    for path in [
        GIT,
        HTTPS,
        GH,
        "/opt/av/git/repository/config",
        "/opt/av/git/repository/HEAD",
        "/private/etc/ssl/cert.pem",
    ] {
        protected(&runtime_path(path), false)?;
    }
    for path in [GIT, HTTPS, GH] {
        if fs::metadata(runtime_path(path))
            .map_err(|error| error.to_string())?
            .mode()
            & 0o555
            != 0o555
        {
            return Err(format!("protected Git executable is unavailable: {path}"));
        }
    }
    if fs::read_to_string(root.join("repository/config")).map_err(|e| e.to_string())? != CONFIG
        || fs::read_to_string(root.join("repository/HEAD")).map_err(|e| e.to_string())?
            != "ref: refs/heads/main\n"
        || fs::read_dir(root.join("empty"))
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
    {
        return Err("protected Git runtime configuration changed".into());
    }
    for (directory, expected) in [
        (REPOSITORY, vec!["HEAD", "config", "objects", "refs"]),
        ("/opt/av/git/repository/refs", vec!["heads"]),
        ("/opt/av/git/repository/refs/heads", vec![]),
        ("/opt/av/git/repository/objects", vec![]),
    ] {
        let mut names = fs::read_dir(runtime_path(directory))
            .map_err(|e| e.to_string())?
            .map(|entry| entry.map(|e| e.file_name()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        names.sort();
        if names != expected.into_iter().map(OsString::from).collect::<Vec<_>>() {
            return Err("unexpected files in protected Git repository".into());
        }
    }
    signing(
        &root.join("bin/git"),
        "anchor apple and identifier com.apple.git",
    )?;
    signing(
        &root.join("bin/git-remote-https"),
        "anchor apple and identifier \"com.apple.git-remote-http\"",
    )?;
    signing(
        &root.join("bin/gh"),
        "anchor apple generic and certificate leaf[subject.OU] = ZU76A67LGU and identifier gh",
    )?;
    let mut version = Command::new(root.join("bin/git"));
    version.env_clear().arg("--version");
    reviewed_git_version(&checked(version)?.stdout)
}

pub(super) fn install(_args: &[OsString], stderr: &mut dyn Write) -> i32 {
    let _ = writeln!(
        stderr,
        "av git: installation is disabled. {DEPRECATION_WARNING}"
    );
    1
}

pub(super) fn run(args: &[OsString], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let _ = writeln!(stderr, "av git: warning: {DEPRECATION_WARNING}");
    match execute(args, stdout, stderr) {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "av git: {error}");
            1
        }
    }
}

fn local(repo: &Path, args: &[&str]) -> Result<Output, String> {
    let mut command = Command::new(GIT);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
    command
        .current_dir(repo)
        .env_remove("AV_GIT_NONCE")
        .args(args);
    checked(command)
}

fn text_output(output: Output) -> Result<String, String> {
    String::from_utf8(output.stdout)
        .map(|s| s.trim().into())
        .map_err(|_| "Git returned invalid UTF-8".into())
}

fn execute(
    args: &[OsString],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 {
        return Err("must not run Git operations as root".into());
    }
    let args = args
        .iter()
        .map(|v| {
            v.to_str()
                .map(String::from)
                .ok_or("arguments must be UTF-8")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let operation = Operation::parse(&args)?;
    xpc_request("git-helper-version", |message| unsafe {
        xpc_set_u64(message, "requested_version", 1);
        Ok(())
    })?;
    verify_runtime()?;
    let cwd = std::env::current_dir()
        .map_err(|e| e.to_string())?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let repo = if let Some(destination) = &operation.destination {
        let destination = cwd.join(destination);
        fs::create_dir(&destination).map_err(|e| format!("new clone destination: {e}"))?;
        local(
            &destination,
            &["init", "--template=", "--initial-branch=main", "."],
        )?;
        local(&destination, &["remote", "add", "origin", &operation.url])?;
        destination.canonicalize().map_err(|e| e.to_string())?
    } else {
        cwd.clone()
    };
    if text_output(local(&repo, &["rev-parse", "--show-object-format"])?)? != "sha1"
        || text_output(local(&repo, &["rev-parse", "--is-shallow-repository"])?)? != "false"
    {
        return Err("protected Git currently requires a full SHA-1 repository".into());
    }
    let objects = repo
        .join(text_output(local(
            &repo,
            &["rev-parse", "--git-path", "objects"],
        )?)?)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let objects = objects.to_str().ok_or("object directory must be UTF-8")?;
    let cwd = cwd.to_str().ok_or("working directory must be UTF-8")?;
    let mut transport = |phase: &str, oid: &str| -> Result<Output, String> {
        let git_args = operation.arguments(phase, oid)?;
        let nonce = xpc_request("git-register", |message| unsafe {
            xpc_set_string(message, "cwd", cwd)?;
            xpc_set_string(message, "objects", objects)?;
            xpc_set_string(message, "phase", phase)?;
            xpc_set_string(message, "oid", oid)?;
            xpc_set_array(message, "args", &args)
        })?;
        let mut command = Command::new(GIT);
        command
            .current_dir(ROOT)
            .env_clear()
            .envs(environment(objects, &nonce))
            .args(git_args);
        let result = checked(command);
        // This must succeed before any repository hook/filter/local update runs.
        xpc_request("git-unregister", |message| unsafe {
            xpc_set_string(message, "nonce", &nonce)
        })?;
        if let Ok(output) = &result {
            stderr
                .write_all(&output.stderr)
                .map_err(|e| e.to_string())?;
        }
        result
    };
    if operation.command == "push" {
        let oid = text_output(local(&repo, &["rev-parse", "--verify", "HEAD^{commit}"])?)?;
        stdout
            .write_all(&transport("push", &oid)?.stdout)
            .map_err(|e| e.to_string())?;
    } else {
        let advertisement = text_output(transport("advertise", "")?)?;
        let Some((oid, reference)) = advertisement.split_once('\t') else {
            return Err("invalid Git advertisement".into());
        };
        if !valid_oid(oid) || reference != "refs/heads/main" {
            return Err("unexpected Git advertisement".into());
        }
        transport("fetch", oid)?;
        let fetch_head = repo.join(text_output(local(
            &repo,
            &["rev-parse", "--git-path", "FETCH_HEAD"],
        )?)?);
        let lock = fetch_head.with_extension("lock");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock)
            .map_err(|e| format!("cannot lock FETCH_HEAD: {e}"))?;
        let written = (|| {
            writeln!(file, "{oid}\t\tbranch 'main' of {}", operation.url)?;
            file.sync_all()?;
            fs::rename(&lock, &fetch_head)
        })();
        if let Err(error) = written {
            let _ = fs::remove_file(&lock);
            return Err(format!("cannot write FETCH_HEAD: {error}"));
        }
        let output = match operation.command.as_str() {
            "clone" => Some(local(&repo, &["reset", "--hard", oid])?),
            "pull" => Some(local(&repo, &["merge", "--ff-only", "--no-edit", oid])?),
            _ => None,
        };
        if let Some(output) = output {
            stdout
                .write_all(&output.stdout)
                .map_err(|e| e.to_string())?;
            stderr
                .write_all(&output.stderr)
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
