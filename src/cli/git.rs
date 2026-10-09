use super::credential_xpc::*;
use crate::git_transport::*;
use std::ffi::{CString, OsString, c_char, c_void};
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const ADAPTER: &str = "/usr/local/bin/git-remote-av";
const ADAPTER_SCRIPT: &str = "#!/bin/sh\nexec /usr/local/bin/av __git-remote \"$@\"\n";
const AV: &str = "/usr/local/bin/av";
const REVIEWED_GIT_VERSION: &[u8] = b"git version 2.50.1 (Apple Git-155)\n";

#[test]
fn runtime_publication_preserves_old_installation_until_swap() {
    let directory =
        std::env::temp_dir().join(format!("av-git-swap-{:016x}", rand::random::<u64>()));
    let stage = directory.join("stage");
    let installed = directory.join("installed");
    fs::create_dir_all(&stage).unwrap();
    fs::write(stage.join("generation"), "old").unwrap();
    publish_runtime(&stage, &installed).unwrap();
    assert!(!stage.exists());
    assert!(publish_runtime(&stage, &installed).is_err());
    assert_eq!(
        fs::read_to_string(installed.join("generation")).unwrap(),
        "old"
    );
    fs::create_dir(&stage).unwrap();
    fs::write(stage.join("generation"), "new").unwrap();
    assert!(rename_with_flags(&stage, &installed, libc::RENAME_EXCL).is_err());
    assert_eq!(
        fs::read_to_string(installed.join("generation")).unwrap(),
        "old"
    );
    publish_runtime(&stage, &installed).unwrap();
    assert_eq!(
        fs::read_to_string(installed.join("generation")).unwrap(),
        "new"
    );
    assert_eq!(fs::read_to_string(stage.join("generation")).unwrap(), "old");
    assert!(verify_runtime_at(&installed).is_err());
    fs::remove_dir_all(directory).unwrap();
}

pub(crate) fn verify_installed_cli() -> Result<(), String> {
    for path in ["/usr", "/usr/local", "/usr/local/bin"] {
        protected(Path::new(path), true)?;
    }
    protected(Path::new(AV), false)?;
    signing(
        Path::new(AV),
        "anchor apple generic and certificate leaf[subject.OU] = ZU76A67LGU and identifier com.automicvault.av",
    )?;
    let mut command = Command::new(AV);
    command.env_clear().arg("__version");
    if checked(command)?.stdout != format!("{}\n", super::INSTALL_REVISION).as_bytes() {
        return Err("update the installed Automic Vault CLI before configuring Git".into());
    }
    Ok(())
}

fn verify_adapter() -> Result<(), String> {
    verify_installed_cli()?;
    protected(Path::new(ADAPTER), false)?;
    if fs::metadata(ADAPTER)
        .map_err(|error| error.to_string())?
        .mode()
        & 0o555
        != 0o555
    {
        return Err("Automic Vault's Git adapter is not executable".into());
    }
    if fs::read(ADAPTER).map_err(|error| error.to_string())? != ADAPTER_SCRIPT.as_bytes() {
        return Err("the installed Git adapter is not Automic Vault's adapter".into());
    }
    verify_adapter_resolution()
}

pub(crate) fn verify_adapter_resolution() -> Result<(), String> {
    let mut git = Command::new("/usr/bin/git");
    git.env_clear().arg("--exec-path");
    let exec_path = text_output(checked(git)?)?;
    let search = std::iter::once(PathBuf::from(exec_path)).chain(
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect::<Vec<_>>(),
    );
    let resolved = search
        .map(|path| path.join("git-remote-av"))
        .find(|path| path == Path::new(ADAPTER) || crate::isotopes::hardeners::executable(path));
    if resolved.as_deref() != Some(Path::new(ADAPTER)) {
        return Err("Git cannot find Automic Vault's adapter first; put /usr/local/bin on PATH before other Git adapters".into());
    }
    Ok(())
}

pub(crate) fn verify_transport(gh: &Path) -> Result<(), String> {
    verify_adapter()?;
    verify_runtime()?;
    let digest = crate::isotopes::hardeners::isotope::sha256_file;
    if digest(Path::new(GH))? != digest(gh)? {
        return Err("the protected Git runtime contains an outdated gh Isotope".into());
    }
    Ok(())
}

pub(crate) fn ensure_transport(gh: &Path) -> Result<(), String> {
    verify_installed_cli()?;
    xpc_request("git-helper-version", |message| unsafe {
        xpc_set_u64(message, "requested_version", 3);
        Ok(())
    })?;
    if verify_transport(gh).is_ok() {
        return Ok(());
    }
    let (git, https) = if verify_runtime().is_ok() {
        (PathBuf::from(GIT), PathBuf::from(HTTPS))
    } else {
        let mut find_git = Command::new("/usr/bin/xcrun");
        find_git.env_clear().args(["--find", "git"]);
        let git = text_output(checked(find_git)?)?;
        let mut exec_path = Command::new(&git);
        exec_path.env_clear().arg("--exec-path");
        let https = PathBuf::from(text_output(checked(exec_path)?)?).join("git-remote-https");
        (PathBuf::from(git), https)
    };
    let status = Command::new("/usr/bin/sudo")
        .arg(AV)
        .arg("__install-git-runtime")
        .arg(git)
        .arg(https)
        .arg(gh)
        .status()
        .map_err(|error| format!("could not install protected Git transport: {error}"))?;
    if !status.success() {
        return Err("protected Git transport installation failed".into());
    }
    verify_transport(gh)
}

fn install_adapter() -> Result<(), String> {
    verify_installed_cli()?;
    if Path::new(ADAPTER).exists() {
        protected(Path::new(ADAPTER), false)?;
        if fs::read(ADAPTER).map_err(|error| error.to_string())? != ADAPTER_SCRIPT.as_bytes() {
            return Err("refusing to replace an unrelated git-remote-av executable".into());
        }
        return fs::set_permissions(ADAPTER, fs::Permissions::from_mode(0o755))
            .map_err(|error| error.to_string());
    }
    let stage = format!(
        "/usr/local/bin/.git-remote-av-{:016x}",
        rand::random::<u64>()
    );
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(&stage)
        .map_err(|error| error.to_string())?;
    let result = (|| {
        output
            .write_all(ADAPTER_SCRIPT.as_bytes())
            .map_err(|error| error.to_string())?;
        output.sync_all().map_err(|error| error.to_string())?;
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o755))
            .map_err(|error| error.to_string())?;
        rename_with_flags(Path::new(&stage), Path::new(ADAPTER), libc::RENAME_EXCL)
    })();
    if Path::new(&stage).exists() {
        let _ = fs::remove_file(stage);
    }
    result
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
    if checked(version)?.stdout != REVIEWED_GIT_VERSION {
        return Err("this Git build has not been reviewed for the protected transport".into());
    }
    Ok(())
}

fn publish_runtime(stage: &Path, destination: &Path) -> Result<(), String> {
    if fs::symlink_metadata(destination)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        return rename_with_flags(stage, destination, libc::RENAME_EXCL);
    }
    // Swap atomically: interruption never leaves an existing route without its runtime.
    rename_with_flags(stage, destination, libc::RENAME_SWAP)
}

fn rename_with_flags(stage: &Path, destination: &Path, flags: libc::c_uint) -> Result<(), String> {
    let stage = CString::new(stage.as_os_str().as_bytes()).map_err(|error| error.to_string())?;
    let destination =
        CString::new(destination.as_os_str().as_bytes()).map_err(|error| error.to_string())?;
    if unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            stage.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            flags,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

pub(super) fn install(args: &[OsString], stderr: &mut dyn Write) -> i32 {
    let result: Result<(), String> = (|| {
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
        if fs::symlink_metadata(ROOT).is_ok() {
            protected(Path::new(ROOT), true)?;
        }
        let stage = PathBuf::from(format!(
            "/opt/av/.git-install-{:016x}",
            rand::random::<u64>()
        ));
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
            fs::set_permissions(&stage, fs::Permissions::from_mode(0o755))
                .map_err(|e| e.to_string())?;
            verify_runtime_at(&stage)?;
            install_adapter()?;
            publish_runtime(&stage, Path::new(ROOT))?;
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
