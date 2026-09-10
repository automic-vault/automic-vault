use super::credential_xpc::*;
use crate::git_transport::*;
use std::ffi::{CString, OsString, c_char, c_void};
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

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

fn no_extended_acl(path: &Path) -> bool {
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
        protected(Path::new(path), true)?;
    }
    for path in [
        GIT,
        HTTPS,
        GH,
        "/opt/av/git/repository/config",
        "/opt/av/git/repository/HEAD",
        "/private/etc/ssl/cert.pem",
    ] {
        protected(Path::new(path), false)?;
    }
    if fs::read_to_string(format!("{REPOSITORY}/config")).map_err(|e| e.to_string())? != CONFIG
        || fs::read_to_string(format!("{REPOSITORY}/HEAD")).map_err(|e| e.to_string())?
            != "ref: refs/heads/main\n"
        || fs::read_dir("/opt/av/git/empty")
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
        let mut names = fs::read_dir(directory)
            .map_err(|e| e.to_string())?
            .map(|entry| entry.map(|e| e.file_name()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        names.sort();
        if names != expected.into_iter().map(OsString::from).collect::<Vec<_>>() {
            return Err("unexpected files in protected Git repository".into());
        }
    }
    signing(Path::new(GIT), "anchor apple and identifier com.apple.git")?;
    signing(
        Path::new(HTTPS),
        "anchor apple and identifier \"com.apple.git-remote-http\"",
    )?;
    signing(
        Path::new(GH),
        "anchor apple generic and certificate leaf[subject.OU] = ZU76A67LGU and identifier gh",
    )?;
    Ok(())
}

pub(super) fn install(args: &[OsString], stderr: &mut dyn Write) -> i32 {
    let result = (|| {
        if unsafe { libc::geteuid() } != 0 || args.len() != 3 {
            return Err(
                "usage (as root): av __install-git-runtime APPLE_GIT APPLE_HTTPS HARDENED_GH"
                    .into(),
            );
        }
        for path in ["/opt", "/opt/av"] {
            if !Path::new(path).exists() {
                fs::create_dir(path).map_err(|e| e.to_string())?;
            }
            protected(Path::new(path), true)?;
        }
        if Path::new(ROOT).exists() {
            return Err("Git runtime is already installed".into());
        }
        let stage = PathBuf::from(format!("/opt/av/.git-install-{}", std::process::id()));
        fs::create_dir(&stage).map_err(|e| e.to_string())?;
        let result = (|| {
            for directory in [
                "",
                "bin",
                "empty",
                "repository",
                "repository/objects",
                "repository/refs",
                "repository/refs/heads",
            ] {
                let path = stage.join(directory);
                if !directory.is_empty() {
                    fs::create_dir(&path).map_err(|e| e.to_string())?;
                }
                // Keep unverified input inaccessible even if a supplied source
                // points at a file only root could read.
                fs::set_permissions(
                    path,
                    fs::Permissions::from_mode(if directory.is_empty() { 0o700 } else { 0o755 }),
                )
                .map_err(|e| e.to_string())?;
            }
            for (source, name, requirement) in [
                (&args[0], "git", "anchor apple and identifier com.apple.git"),
                (
                    &args[1],
                    "git-remote-https",
                    "anchor apple and identifier \"com.apple.git-remote-http\"",
                ),
                (
                    &args[2],
                    "gh",
                    "anchor apple generic and certificate leaf[subject.OU] = ZU76A67LGU and identifier gh",
                ),
            ] {
                let path = stage.join("bin").join(name);
                // Copy bytes only: macOS copyfile can preserve ownership and ACLs.
                let mut input = fs::File::open(source).map_err(|e| e.to_string())?;
                let mut output = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .map_err(|e| e.to_string())?;
                std::io::copy(&mut input, &mut output).map_err(|e| e.to_string())?;
                output.sync_all().map_err(|e| e.to_string())?;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                    .map_err(|e| e.to_string())?;
                // Verify the protected copy, never a mutable source before copying.
                signing(&path, requirement)?;
            }
            fs::write(stage.join("repository/config"), CONFIG).map_err(|e| e.to_string())?;
            fs::write(stage.join("repository/HEAD"), "ref: refs/heads/main\n")
                .map_err(|e| e.to_string())?;
            for path in ["repository/config", "repository/HEAD"] {
                fs::set_permissions(stage.join(path), fs::Permissions::from_mode(0o644))
                    .map_err(|e| e.to_string())?;
            }
            let mut version = Command::new(stage.join("bin/git"));
            version.env_clear().arg("--version");
            if checked(version)?.stdout != b"git version 2.50.1 (Apple Git-155)\n" {
                return Err(
                    "this Git build has not been reviewed for the protected transport".into(),
                );
            }
            fs::set_permissions(&stage, fs::Permissions::from_mode(0o755))
                .map_err(|e| e.to_string())?;
            fs::rename(&stage, ROOT).map_err(|e| e.to_string())?;
            if let Err(error) = verify_runtime() {
                fs::remove_dir_all(ROOT)
                    .map_err(|cleanup| format!("{error}; runtime cleanup failed: {cleanup}"))?;
                return Err(error);
            }
            Ok(())
        })();
        if stage.exists() {
            let _ = fs::remove_dir_all(stage);
        }
        result
    })();
    match result {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "av git: {error}");
            1
        }
    }
}

pub(super) fn run(args: &[OsString], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
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
