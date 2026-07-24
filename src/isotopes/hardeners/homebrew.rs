use std::ffi::CString;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, lchown};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::{
    HardenerDetection, HardenerDiagnostic, RequiredIdentity, SecretGateDescriptor, SecretGateRoute,
    StubRequirements,
};

const AUTOMIC_USER: &str = "automic";
const VAULT_GROUP: &str = "vault";
const BREW_PREFIX: &str = "/opt/homebrew";
const BREW_TARGET: &str = "/opt/homebrew/bin/brew";
const BREW_STUB: &str = "/usr/local/bin/brew";
const APP_BREW_STUB: &str = "/Applications/Automic Vault.app/Contents/MacOS/av-brew-stub";
const CASK_USER_UID_FILE: &str = "var/automic/cask-user-uid";
const STUB_MARKER_PREFIX: &[u8] = b"AUTOMIC_VAULT_BREW_STUB_V";
#[cfg(test)]
const STUB_MARKER: &[u8] = b"AUTOMIC_VAULT_BREW_STUB_V4";
const STUB_VERSION: u32 = 4;
const ID_RANGE: std::ops::RangeInclusive<u32> = 550..=599;

unsafe extern "C" {
    fn geteuid() -> u32;
}

#[derive(Debug, PartialEq, Eq)]
struct SourceUser {
    name: String,
    uid: u32,
    home: PathBuf,
}

pub(crate) fn run(stdout: &mut dyn Write, yes: bool) -> Result<(), String> {
    let prefix = brew_prefix();
    let target = brew_target_path();
    let stub = brew_stub_path();
    let source = brew_stub_source_path()?;
    let automic_home = prefix.join("var/automic");
    let automic_cache = automic_home.join("cache");

    if !target.exists() {
        return Err(format!("Homebrew is not installed at {}", target.display()));
    }
    if effective_uid() != 0 {
        return Err("run `sudo av harden brew`".to_string());
    }
    if stub.exists() && !is_managed_stub_file(&stub) {
        return Err(format!(
            "{} already exists and is not an Automic Vault brew stub",
            stub.display()
        ));
    }
    if !is_managed_stub_file(&source) {
        return Err(format!(
            "{} is not an Automic Vault brew stub",
            source.display()
        ));
    }
    let source_user = source_user()?;

    writeln!(stdout, "╭─ harden brew").ok();
    writeln!(stdout, "│").ok();
    writeln!(
        stdout,
        "├─ ensure {AUTOMIC_USER} user and {VAULT_GROUP} group"
    )
    .ok();
    {
        let home = &source_user.home;
        let config = home.join(".homebrew");
        if config.is_dir() {
            writeln!(
                stdout,
                "├─ migrate {} to {}",
                config.display(),
                automic_home.join(".homebrew").display()
            )
            .ok();
        }
        let cache = home.join("Library/Caches/Homebrew");
        if cache.is_dir() {
            writeln!(
                stdout,
                "├─ move {} to {}",
                cache.display(),
                automic_cache.display()
            )
            .ok();
        }
    }
    writeln!(stdout, "├─ prepare {}", automic_home.display()).ok();
    writeln!(
        stdout,
        "├─ repair {AUTOMIC_USER}:{VAULT_GROUP} ownership under {}",
        prefix.display()
    )
    .ok();
    writeln!(
        stdout,
        "├─ record {} for cask app ownership",
        source_user.name
    )
    .ok();
    writeln!(stdout, "├─ install {}", stub.display()).ok();
    writeln!(stdout, "│").ok();
    if !confirm(stdout, yes)? {
        writeln!(stdout, "╰─ cancelled").ok();
        return Ok(());
    }

    let gid = ensure_group()?;
    let uid = ensure_user(gid)?;
    fs::create_dir_all(automic_home.join("tmp"))
        .map_err(|err| format!("failed to create Homebrew automic state dir: {err}"))?;
    fs::create_dir_all(&automic_cache)
        .map_err(|err| format!("failed to create Homebrew automic cache dir: {err}"))?;
    let migration = (|| {
        {
            let home = &source_user.home;
            let config = home.join(".homebrew");
            if config.is_dir() {
                let count = copy_missing_tree(&config, &automic_home.join(".homebrew"))?;
                writeln!(
                    stdout,
                    "├─ migrated {count} new Homebrew configuration file(s)"
                )
                .ok();
            }
            let cache = home.join("Library/Caches/Homebrew");
            if cache.is_dir() {
                let count = move_cache_contents(&cache, &automic_cache)?;
                writeln!(stdout, "├─ moved {count} Homebrew cache item(s)").ok();
            }
        }
        Ok::<_, String>(())
    })();
    write_cask_user_uid(&prefix.join(CASK_USER_UID_FILE), source_user.uid)?;
    remove_legacy_cask_access(&prefix, &source_user.name)?;
    chown_recursive(&prefix, uid, gid)?;
    migration?;
    install_stub(&source, &stub, uid, gid)?;
    writeln!(
        stdout,
        "╰─ hardened brew; run `hash -r` (or start a new shell) before using brew"
    )
    .ok();
    super::write_secret_gate_notice(stdout, "brew");
    Ok(())
}

pub(crate) fn detect() -> HardenerDetection {
    let prefix = brew_prefix();
    let stub = brew_stub_path();
    let target = brew_target_path();
    let uid = automic_uid();
    let gid = vault_gid();
    let hardened = if let (Some(uid), Some(gid)) = (uid, gid) {
        is_hardened_stub(&stub, uid, gid)
    } else {
        false
    };
    let mut detection = HardenerDetection::command(
        hardened,
        "brew",
        Some(stub.display().to_string()),
        target.display().to_string(),
    );
    detection.commands[0].stub_valid = stub_is_current(&stub);
    detection.commands[0].stub_requirements = Some(StubRequirements {
        mode: 0o6755,
        owner: RequiredIdentity {
            name: AUTOMIC_USER,
            id: uid,
        },
        group: RequiredIdentity {
            name: VAULT_GROUP,
            id: gid,
        },
    });
    detection.diagnostics = doctor_diagnostics(&prefix, uid, gid);
    detection
}

pub(crate) fn secret_gate() -> SecretGateDescriptor {
    SecretGateDescriptor {
        id: "brew",
        key_patterns: Vec::new(),
        routes: vec![SecretGateRoute {
            operation: "authorize",
            script_path: None,
            target_path: brew_target_path().display().to_string(),
            caller_identifiers: vec!["com.automicvault.av-brew-stub"],
            key_patterns: Vec::new(),
            replace_existing_env: false,
            allow_missing_keys: false,
        }],
    }
}

fn doctor_diagnostics(
    prefix: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Vec<HardenerDiagnostic> {
    let mut diagnostics = match (uid, gid) {
        (Some(uid), Some(gid)) => state_directory_diagnostics(prefix, uid, gid),
        _ => Vec::new(),
    };
    if crate::test_env_var("AUTOMIC_VAULT_TEST_AUTOMIC_UID").is_none()
        && let Some(gid) = gid
    {
        diagnostics.extend(account_diagnostics(gid));
    }
    diagnostics.extend(cask_access_diagnostics(prefix, uid, gid));
    diagnostics
}

fn cask_access_diagnostics(
    prefix: &Path,
    automic_uid: Option<u32>,
    vault_gid: Option<u32>,
) -> Vec<HardenerDiagnostic> {
    let uid_file = prefix.join(CASK_USER_UID_FILE);
    let mut uid_file_handle = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&uid_file)
    {
        Ok(file) => file,
        Err(_) if fs::symlink_metadata(&uid_file).is_ok() => {
            return vec![HardenerDiagnostic {
                kind: "cask_user_file_permissions_invalid",
                message: "Homebrew's configured cask user file is not protected".into(),
                remediation: "Run `sudo av harden brew` to restore its ownership and permissions."
                    .into(),
                path: Some(uid_file.display().to_string()),
            }];
        }
        Err(_) => {
            return vec![HardenerDiagnostic {
                kind: "cask_user_missing",
                message: "Homebrew hardening has no configured cask user".into(),
                remediation:
                    "Run `sudo av harden brew` as the desktop user who should install casks.".into(),
                path: Some(uid_file.display().to_string()),
            }];
        }
    };
    let Ok(metadata) = uid_file_handle.metadata() else {
        return vec![HardenerDiagnostic {
            kind: "cask_user_file_permissions_invalid",
            message: "Homebrew's configured cask user file is not protected".into(),
            remediation: "Run `sudo av harden brew` to restore its ownership and permissions."
                .into(),
            path: Some(uid_file.display().to_string()),
        }];
    };
    if !metadata.file_type().is_file()
        || automic_uid.is_some_and(|uid| metadata.uid() != uid)
        || vault_gid.is_some_and(|gid| metadata.gid() != gid)
        || metadata.mode() & 0o022 != 0
    {
        return vec![HardenerDiagnostic {
            kind: "cask_user_file_permissions_invalid",
            message: "Homebrew's configured cask user file is not protected".into(),
            remediation: "Run `sudo av harden brew` to restore its ownership and permissions."
                .into(),
            path: Some(uid_file.display().to_string()),
        }];
    }
    let mut configured_uid = String::new();
    let Ok(_) = uid_file_handle.read_to_string(&mut configured_uid) else {
        return vec![HardenerDiagnostic {
            kind: "cask_user_unreadable",
            message: "Homebrew's configured cask user file could not be read".into(),
            remediation: "Run `sudo av harden brew` to restore the cask-user configuration.".into(),
            path: Some(uid_file.display().to_string()),
        }];
    };
    let Ok(configured_uid) = configured_uid.trim().parse::<u32>() else {
        return vec![HardenerDiagnostic {
            kind: "cask_user_invalid",
            message: "Homebrew's configured cask user UID is invalid".into(),
            remediation: "Run `sudo av harden brew` to recreate the cask-user configuration."
                .into(),
            path: Some(uid_file.display().to_string()),
        }];
    };
    let Some(user) = user_name_for_uid(configured_uid) else {
        return vec![HardenerDiagnostic {
            kind: "cask_user_unresolvable",
            message: format!("configured cask user UID {configured_uid} cannot be resolved"),
            remediation: "Run `sudo av harden brew` from the intended desktop account.".into(),
            path: Some(uid_file.display().to_string()),
        }];
    };

    let mut diagnostics = Vec::new();
    let caskroom = prefix.join("Caskroom");
    match fs::symlink_metadata(&caskroom) {
        Ok(metadata)
            if !metadata.file_type().is_dir()
                || automic_uid.is_some_and(|uid| metadata.uid() != uid)
                || vault_gid.is_some_and(|gid| metadata.gid() != gid) =>
        {
            diagnostics.push(HardenerDiagnostic {
                kind: "caskroom_owner_invalid",
                message: format!(
                    "{} must remain owned by {AUTOMIC_USER}:{VAULT_GROUP}",
                    caskroom.display()
                ),
                remediation: "Run `sudo av harden brew` to restore Caskroom ownership.".into(),
                path: Some(caskroom.display().to_string()),
            });
        }
        Err(_) => diagnostics.push(HardenerDiagnostic {
            kind: "caskroom_missing",
            message: format!("Homebrew Caskroom {} is missing", caskroom.display()),
            remediation: "Run `sudo av harden brew` to recreate it.".into(),
            path: Some(caskroom.display().to_string()),
        }),
        _ => {}
    }
    if acl_mentions(&caskroom, &user) {
        diagnostics.push(HardenerDiagnostic {
            kind: "legacy_caskroom_acl_present",
            message: format!("Homebrew Caskroom still grants configured user `{user}` access"),
            remediation: "Run `sudo av harden brew` to remove the obsolete Caskroom ACL.".into(),
            path: Some(caskroom.display().to_string()),
        });
    }
    let config = prefix.join("var/automic/.homebrew");
    if acl_mentions(&config, &user) {
        diagnostics.push(HardenerDiagnostic {
            kind: "legacy_cask_trust_acl_present",
            message: format!("Homebrew trust configuration still grants `{user}` direct access"),
            remediation: "Run `sudo av harden brew` to remove the obsolete trust-store ACL.".into(),
            path: Some(config.display().to_string()),
        });
    }
    for path in [
        prefix.to_path_buf(),
        prefix.join("Cellar"),
        prefix.join("bin"),
    ] {
        if acl_mentions(&path, &user) {
            diagnostics.push(HardenerDiagnostic {
                kind: "cask_user_acl_too_broad",
                message: format!(
                    "configured cask user `{user}` has an unexpected ACL on {}",
                    path.display()
                ),
                remediation: format!(
                    "Remove that ACL with `sudo chmod -a 'user:{user} allow ...' {}`, then rerun `sudo av harden brew`.",
                    path.display()
                ),
                path: Some(path.display().to_string()),
            });
        }
    }
    diagnostics
}

fn write_cask_user_uid(path: &Path, uid: u32) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|err| format!("failed to record Homebrew cask user: {err}"))?;
    file.set_permissions(fs::Permissions::from_mode(0o644))
        .and_then(|()| writeln!(file, "{uid}"))
        .map_err(|err| format!("failed to record Homebrew cask user: {err}"))
}

fn state_directory_diagnostics(prefix: &Path, uid: u32, gid: u32) -> Vec<HardenerDiagnostic> {
    [
        prefix.join("var/automic"),
        prefix.join("var/automic/tmp"),
        prefix.join("var/automic/cache"),
    ]
    .into_iter()
    .filter_map(|path| {
        let path_text = path.display().to_string();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_dir() => metadata,
            Ok(metadata) => {
                let actual = if metadata.file_type().is_symlink() {
                    "a symbolic link"
                } else {
                    "not a directory"
                };
                return Some(HardenerDiagnostic {
                    kind: "state_directory_wrong_type",
                    message: format!(
                        "Homebrew hardening state path {path_text} is {actual}; expected a directory"
                    ),
                    remediation: format!(
                        "Review and remove {path_text}, then run `sudo install -d -o {AUTOMIC_USER} -g {VAULT_GROUP} -m 0755 {path_text}`."
                    ),
                    path: Some(path_text),
                });
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Some(HardenerDiagnostic {
                    kind: "state_directory_missing",
                    message: format!(
                        "Homebrew's hardened launcher requires state directory {path_text}, but it is missing"
                    ),
                    remediation: format!(
                        "Create it with `sudo install -d -o {AUTOMIC_USER} -g {VAULT_GROUP} -m 0755 {path_text}`, then rerun `av doctor brew`."
                    ),
                    path: Some(path_text),
                });
            }
            Err(err) => {
                return Some(HardenerDiagnostic {
                    kind: "state_directory_unreadable",
                    message: format!("cannot inspect Homebrew state directory {path_text}: {err}"),
                    remediation: format!(
                        "Check metadata and parent-directory permissions for {path_text}, then rerun `av doctor brew`."
                    ),
                    path: Some(path_text),
                });
            }
        };
        let mode = metadata.permissions().mode() & 0o7777;
        if metadata.uid() != uid
            || metadata.gid() != gid
            || mode & 0o700 != 0o700
        {
            return Some(HardenerDiagnostic {
                kind: "state_directory_permissions_invalid",
                message: format!(
                    "Homebrew state directory {path_text} has uid {}, gid {}, and mode {mode:#06o}; expected {AUTOMIC_USER} ({uid}), {VAULT_GROUP} ({gid}), with owner read/write/search access",
                    metadata.uid(), metadata.gid()
                ),
                remediation: format!(
                    "Run `sudo chown {AUTOMIC_USER}:{VAULT_GROUP} {path_text} && sudo chmod u+rwx {path_text}`, then rerun `av doctor brew`."
                ),
                path: Some(path_text),
            });
        }
        None
    })
    .collect()
}

fn account_diagnostics(expected_gid: u32) -> Vec<HardenerDiagnostic> {
    let actual_gid = dscl_read("/Users/automic", "PrimaryGroupID");
    let home = dscl_read("/Users/automic", "NFSHomeDirectory");
    let shell = dscl_read("/Users/automic", "UserShell");
    let errors = [&actual_gid, &home, &shell]
        .into_iter()
        .filter_map(|result| result.as_ref().err())
        .cloned()
        .collect::<Vec<_>>();
    if !errors.is_empty() {
        return vec![HardenerDiagnostic {
            kind: "account_unreadable",
            message: format!(
                "cannot inspect the local `automic` account with dscl: {}",
                errors.join("; ")
            ),
            remediation: "Run `dscl . -read /Users/automic PrimaryGroupID NFSHomeDirectory UserShell` to inspect the failure, then rerun `sudo av harden brew`.".to_string(),
            path: None,
        }];
    }
    let (Ok(actual_gid), Ok(home), Ok(shell)) = (actual_gid, home, shell) else {
        unreachable!();
    };
    let expected_gid = expected_gid.to_string();
    if actual_gid.as_deref() == Some(expected_gid.as_str())
        && home.as_deref() == Some("/opt/homebrew/var/automic")
        && shell.as_deref() == Some("/usr/bin/false")
    {
        return Vec::new();
    }
    vec![HardenerDiagnostic {
        kind: "account_configuration_invalid",
        message: format!(
            "local `automic` account has PrimaryGroupID {}, NFSHomeDirectory {}, and UserShell {}; expected {expected_gid}, /opt/homebrew/var/automic, and /usr/bin/false",
            actual_gid.as_deref().unwrap_or("missing"),
            home.as_deref().unwrap_or("missing"),
            shell.as_deref().unwrap_or("missing"),
        ),
        remediation: format!(
            "Repair it with `sudo dscl . -create /Users/automic PrimaryGroupID {expected_gid}`, `sudo dscl . -create /Users/automic NFSHomeDirectory /opt/homebrew/var/automic`, and `sudo dscl . -create /Users/automic UserShell /usr/bin/false`, then rerun `av doctor brew`."
        ),
        path: None,
    }]
}

fn confirm(stdout: &mut dyn Write, yes: bool) -> Result<bool, String> {
    if yes {
        writeln!(stdout, "◇ Continue? yes (--yes)").ok();
        return Ok(true);
    }

    write!(stdout, "◇ Continue? [y/N] ").ok();
    stdout
        .flush()
        .map_err(|err| format!("failed to flush prompt: {err}"))?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|err| format!("failed to read confirmation: {err}"))?;
    if !io::stdin().is_terminal() {
        writeln!(stdout).ok();
    }
    Ok(matches!(
        input.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn ensure_group() -> Result<u32, String> {
    if let Some(gid) = vault_gid() {
        return Ok(gid);
    }
    let gid = first_unused_id("/Groups", "PrimaryGroupID")?;
    dscl([".", "-create", "/Groups/vault"])?;
    dscl([".", "-create", "/Groups/vault", "RealName", "Automic Vault"])?;
    dscl([
        ".",
        "-create",
        "/Groups/vault",
        "PrimaryGroupID",
        &gid.to_string(),
    ])?;
    Ok(gid)
}

fn ensure_user(gid: u32) -> Result<u32, String> {
    if let Some(uid) = automic_uid() {
        let got_gid = dscl_read("/Users/automic", "PrimaryGroupID")?
            .and_then(|value| value.parse::<u32>().ok());
        let home = dscl_read("/Users/automic", "NFSHomeDirectory")?;
        let shell = dscl_read("/Users/automic", "UserShell")?;
        if got_gid != Some(gid)
            || home.as_deref() != Some("/opt/homebrew/var/automic")
            || shell.as_deref() != Some("/usr/bin/false")
        {
            return Err("existing automic user is not compatible".to_string());
        }
        return Ok(uid);
    }

    let uid = first_unused_id("/Users", "UniqueID")?;
    dscl([".", "-create", "/Users/automic"])?;
    dscl([
        ".",
        "-create",
        "/Users/automic",
        "RealName",
        "Automic Vault Homebrew",
    ])?;
    dscl([
        ".",
        "-create",
        "/Users/automic",
        "UserShell",
        "/usr/bin/false",
    ])?;
    dscl([
        ".",
        "-create",
        "/Users/automic",
        "NFSHomeDirectory",
        "/opt/homebrew/var/automic",
    ])?;
    dscl([
        ".",
        "-create",
        "/Users/automic",
        "UniqueID",
        &uid.to_string(),
    ])?;
    dscl([
        ".",
        "-create",
        "/Users/automic",
        "PrimaryGroupID",
        &gid.to_string(),
    ])?;
    dscl([".", "-create", "/Users/automic", "Password", "*"])?;
    Ok(uid)
}

fn first_unused_id(record_type: &str, attribute: &str) -> Result<u32, String> {
    let output = Command::new("/usr/bin/dscl")
        .args([".", "-list", record_type, attribute])
        .output()
        .map_err(|err| format!("failed to run dscl: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "failed to list {record_type} ids: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let used = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().last()?.parse::<u32>().ok())
        .collect::<std::collections::BTreeSet<_>>();
    ID_RANGE
        .clone()
        .find(|id| !used.contains(id))
        .ok_or_else(|| "no free local user/group ids in 550-599".to_string())
}

fn dscl<const N: usize>(args: [&str; N]) -> Result<(), String> {
    let output = Command::new("/usr/bin/dscl")
        .args(args)
        .output()
        .map_err(|err| format!("failed to run dscl: {err}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "dscl failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn dscl_read(record: &str, attribute: &str) -> Result<Option<String>, String> {
    let output = Command::new("/usr/bin/dscl")
        .args([".", "-read", record, attribute])
        .output()
        .map_err(|err| format!("failed to run dscl: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("eDSRecordNotFound") || stderr.contains("No such key") {
            return Ok(None);
        }
        return Err(format!("dscl failed: {}", stderr.trim()));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .split_once(':')
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty()))
}

fn chown_recursive(prefix: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let skipped = prefix.join("var/automic/Library");
    chown_tree(prefix, &skipped, uid, gid)
}

fn chown_tree(path: &Path, skipped: &Path, uid: u32, gid: u32) -> Result<(), String> {
    if path == skipped {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to inspect {}: {err}", path.display()))?;
    if metadata.uid() != uid || metadata.gid() != gid {
        lchown(path, Some(uid), Some(gid))
            .map_err(|err| format!("failed to chown {}: {err}", path.display()))?;
    }
    if metadata.file_type().is_dir() {
        for entry in
            fs::read_dir(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?
        {
            let entry = entry
                .map_err(|err| format!("failed to read entry in {}: {err}", path.display()))?;
            chown_tree(&entry.path(), skipped, uid, gid)?;
        }
    }
    Ok(())
}

fn source_user() -> Result<SourceUser, String> {
    let user = crate::test_env_string("AUTOMIC_VAULT_TEST_BREW_USER")
        .or_else(|| std::env::var("SUDO_USER").ok())
        .ok_or_else(|| "run `sudo av harden brew` from the desktop account".to_string())?;
    if user == "root" {
        return Err("cannot configure root as the Homebrew cask user".into());
    }
    if user.is_empty() || user.contains('/') {
        return Err("Homebrew cask user account name is invalid".into());
    }
    let uid = test_u32("AUTOMIC_VAULT_TEST_BREW_USER_UID")
        .or_else(|| {
            dscl_read(&format!("/Users/{user}"), "UniqueID")
                .ok()
                .flatten()?
                .parse()
                .ok()
        })
        .ok_or_else(|| format!("cannot resolve UID for cask user `{user}`"))?;
    let home = crate::test_env_var("AUTOMIC_VAULT_TEST_BREW_USER_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            dscl_read(&format!("/Users/{user}"), "NFSHomeDirectory")
                .ok()
                .flatten()
                .map(PathBuf::from)
        })
        .ok_or_else(|| format!("cannot resolve home for cask user `{user}`"))?;
    if uid == 0 || !home.is_absolute() {
        return Err("cask user must be a non-root account with an absolute home".into());
    }
    Ok(SourceUser {
        name: user,
        uid,
        home,
    })
}

fn remove_legacy_cask_access(prefix: &Path, user: &str) -> Result<(), String> {
    let caskroom = prefix.join("Caskroom");
    fs::create_dir_all(&caskroom)
        .map_err(|err| format!("failed to create {}: {err}", caskroom.display()))?;
    let cask_acl = format!(
        "{user} allow read,write,execute,delete,append,readattr,writeattr,readextattr,writeextattr,readsecurity,file_inherit,directory_inherit"
    );
    let config = prefix.join("var/automic/.homebrew");
    fs::create_dir_all(&config)
        .map_err(|err| format!("failed to create {}: {err}", config.display()))?;
    let config_acl = format!(
        "{user} allow read,execute,readattr,readextattr,readsecurity,file_inherit,directory_inherit"
    );
    for (path, acl) in [(&caskroom, &cask_acl), (&config, &config_acl)] {
        let _ = acl_tree_command(path, "-a", acl)
            .stderr(Stdio::null())
            .status();
        if acl_mentions(path, user) {
            return Err(format!(
                "failed to remove obsolete ACL from {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn acl_tree_command(path: &Path, operation: &str, acl: &str) -> Command {
    const PROTECTED_BUNDLES: &[&str] = &[
        "*.app",
        "*.appex",
        "*.bundle",
        "*.component",
        "*.driver",
        "*.framework",
        "*.kext",
        "*.mdimporter",
        "*.plugin",
        "*.prefPane",
        "*.qlgenerator",
        "*.saver",
        "*.systemextension",
        "*.vst",
        "*.vst3",
        "*.xpc",
    ];
    let mut command = Command::new("/usr/bin/find");
    command.arg("-x").arg(path).args(["(", "-type", "l"]);
    for pattern in PROTECTED_BUNDLES {
        command.args(["-o", "-name", pattern]);
    }
    command.args([
        ")",
        "-prune",
        "-o",
        "-exec",
        "/bin/chmod",
        "-h",
        operation,
        acl,
        "{}",
        "+",
    ]);
    command
}

fn acl_mentions(path: &Path, user: &str) -> bool {
    Command::new("/bin/ls")
        .args(["-lde"])
        .arg(path)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| {
            String::from_utf8_lossy(&output.stdout).contains(&format!("user:{user} allow"))
        })
}

fn user_name_for_uid(uid: u32) -> Option<String> {
    if let Some(user) = crate::test_env_string("AUTOMIC_VAULT_TEST_BREW_USER") {
        return Some(user);
    }
    let output = Command::new("/usr/bin/dscl")
        .args([".", "-search", "/Users", "UniqueID", &uid.to_string()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .map(str::to_string)
}

fn copy_missing_tree(source: &Path, destination: &Path) -> Result<usize, String> {
    if !source.exists() {
        return Ok(0);
    }
    if !source.is_dir() {
        return Err(format!(
            "Homebrew configuration path is not a directory: {}",
            source.display()
        ));
    }
    fs::create_dir_all(destination)
        .map_err(|err| format!("failed to create {}: {err}", destination.display()))?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700))
        .map_err(|err| format!("failed to chmod {}: {err}", destination.display()))?;
    let mut copied = 0;
    for entry in
        fs::read_dir(source).map_err(|err| format!("failed to read {}: {err}", source.display()))?
    {
        let entry = entry.map_err(|err| format!("failed to read {}: {err}", source.display()))?;
        let from = entry.path();
        let to = destination.join(entry.file_name());
        let kind = entry
            .file_type()
            .map_err(|err| format!("failed to inspect {}: {err}", from.display()))?;
        if kind.is_dir() {
            copied += copy_missing_tree(&from, &to)?;
        } else if kind.is_file() && !to.exists() {
            fs::copy(&from, &to).map_err(|err| {
                format!(
                    "failed to copy {} to {}: {err}",
                    from.display(),
                    to.display()
                )
            })?;
            copied += 1;
        }
    }
    Ok(copied)
}

fn move_cache_contents(source: &Path, destination: &Path) -> Result<usize, String> {
    if !source.exists() {
        return Ok(0);
    }
    if !source.is_dir() {
        return Err(format!(
            "Homebrew cache path is not a directory: {}",
            source.display()
        ));
    }
    fs::create_dir_all(destination)
        .map_err(|err| format!("failed to create {}: {err}", destination.display()))?;
    let mut moved = 0;
    for entry in
        fs::read_dir(source).map_err(|err| format!("failed to read {}: {err}", source.display()))?
    {
        let entry = entry.map_err(|err| format!("failed to read {}: {err}", source.display()))?;
        let from = entry.path();
        let to = destination.join(entry.file_name());
        let kind = entry
            .file_type()
            .map_err(|err| format!("failed to inspect {}: {err}", from.display()))?;
        if !to.exists() {
            match fs::rename(&from, &to) {
                Ok(()) => {
                    moved += 1;
                    continue;
                }
                Err(_) if kind.is_file() => {
                    fs::copy(&from, &to).map_err(|err| {
                        format!(
                            "failed to move {} to {}: {err}",
                            from.display(),
                            to.display()
                        )
                    })?;
                    fs::remove_file(&from)
                        .map_err(|err| format!("failed to remove {}: {err}", from.display()))?;
                    moved += 1;
                    continue;
                }
                Err(_) if kind.is_dir() => {}
                Err(err) => {
                    return Err(format!(
                        "failed to move {} to {}: {err}",
                        from.display(),
                        to.display()
                    ));
                }
            }
        }
        if kind.is_dir() && to.is_dir() {
            moved += move_cache_contents(&from, &to)?;
        } else if kind.is_dir() {
            fs::remove_dir_all(&from).map_err(|err| {
                format!("failed to remove duplicate cache {}: {err}", from.display())
            })?;
        } else {
            fs::remove_file(&from).map_err(|err| {
                format!("failed to remove duplicate cache {}: {err}", from.display())
            })?;
        }
    }
    fs::remove_dir(source)
        .map_err(|err| format!("failed to remove {}: {err}", source.display()))?;
    Ok(moved)
}

fn install_stub(source: &Path, stub: &Path, uid: u32, gid: u32) -> Result<(), String> {
    if let Some(parent) = stub.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    fs::copy(source, stub).map_err(|err| {
        format!(
            "failed to copy {} to {}: {err}",
            source.display(),
            stub.display()
        )
    })?;
    chown(stub, uid, gid)?;
    fs::set_permissions(stub, fs::Permissions::from_mode(0o6755))
        .map_err(|err| format!("failed to chmod {}: {err}", stub.display()))
}

fn chown(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| "path contains NUL byte".to_string())?;
    if unsafe { libc::chown(path.as_ptr(), uid, gid) } == 0 {
        return Ok(());
    }
    Err(format!(
        "failed to chown stub: {}",
        std::io::Error::last_os_error()
    ))
}

fn is_hardened_stub(path: &Path, uid: u32, gid: u32) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    metadata.uid() == uid
        && metadata.gid() == gid
        && metadata.mode() & 0o7777 == 0o6755
        && is_managed_stub_file(path)
}

fn stub_is_current(path: &Path) -> bool {
    stub_version(path).is_some_and(|version| version >= STUB_VERSION)
}

fn is_managed_stub_file(path: &Path) -> bool {
    stub_version(path).is_some()
}

fn stub_version(path: &Path) -> Option<u32> {
    let bytes = fs::read(path).ok()?;
    bytes
        .windows(STUB_MARKER_PREFIX.len())
        .enumerate()
        .filter(|(_, window)| *window == STUB_MARKER_PREFIX)
        .find_map(|(offset, _)| {
            let digits = bytes[offset + STUB_MARKER_PREFIX.len()..]
                .iter()
                .copied()
                .take_while(u8::is_ascii_digit)
                .collect::<Vec<_>>();
            std::str::from_utf8(&digits).ok()?.parse().ok()
        })
}

fn automic_uid() -> Option<u32> {
    test_u32("AUTOMIC_VAULT_TEST_AUTOMIC_UID").or_else(|| {
        dscl_read("/Users/automic", "UniqueID")
            .ok()
            .flatten()?
            .parse()
            .ok()
    })
}

fn vault_gid() -> Option<u32> {
    test_u32("AUTOMIC_VAULT_TEST_VAULT_GID").or_else(|| {
        dscl_read("/Groups/vault", "PrimaryGroupID")
            .ok()
            .flatten()?
            .parse()
            .ok()
    })
}

fn effective_uid() -> u32 {
    test_u32("AUTOMIC_VAULT_TEST_EUID").unwrap_or_else(|| unsafe { geteuid() })
}

fn test_u32(name: &str) -> Option<u32> {
    crate::test_env_string(name)?.parse().ok()
}

fn brew_prefix() -> PathBuf {
    crate::test_env_var("AUTOMIC_VAULT_TEST_BREW_PREFIX")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(BREW_PREFIX))
}

fn brew_target_path() -> PathBuf {
    crate::test_env_var("AUTOMIC_VAULT_TEST_BREW_TARGET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(BREW_TARGET))
}

fn brew_stub_path() -> PathBuf {
    crate::test_env_var("AUTOMIC_VAULT_TEST_BREW_STUB")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(BREW_STUB))
}

fn brew_stub_source_path() -> Result<PathBuf, String> {
    if let Some(path) = crate::test_env_var("AUTOMIC_VAULT_TEST_BREW_STUB_SOURCE") {
        return Ok(PathBuf::from(path));
    }
    let app_stub = PathBuf::from(APP_BREW_STUB);
    if app_stub.exists() {
        return Ok(app_stub);
    }
    let exe = std::env::current_exe().map_err(|err| format!("failed to locate av: {err}"))?;
    Ok(exe
        .parent()
        .ok_or_else(|| "failed to locate av directory".to_string())?
        .join("av-brew-stub"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn detects_stub_marker_owner_group_and_mode() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let path = temp_path("brew-stub-detect");
        fs::write(&path, STUB_MARKER).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o6755)).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_STUB", &path);
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_TARGET", "/tmp/brew-target");
            std::env::set_var("AUTOMIC_VAULT_TEST_AUTOMIC_UID", libc::getuid().to_string());
            std::env::set_var("AUTOMIC_VAULT_TEST_VAULT_GID", libc::getgid().to_string());
        }

        let detection = detect();

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_BREW_STUB");
            std::env::remove_var("AUTOMIC_VAULT_TEST_BREW_TARGET");
            std::env::remove_var("AUTOMIC_VAULT_TEST_AUTOMIC_UID");
            std::env::remove_var("AUTOMIC_VAULT_TEST_VAULT_GID");
        }
        assert!(detection.hardened);
        assert_eq!(detection.stub_path, Some(path.display().to_string()));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn diagnoses_homebrew_state_directories() {
        let prefix = temp_path("brew-doctor-state");
        let home = prefix.join("var/automic");
        let tmp = home.join("tmp");
        let cache = home.join("cache");
        fs::create_dir_all(&tmp).unwrap();
        fs::create_dir_all(&cache).unwrap();
        let metadata = home.metadata().unwrap();

        assert!(state_directory_diagnostics(&prefix, metadata.uid(), metadata.gid()).is_empty());

        fs::remove_dir(&cache).unwrap();
        let diagnostics = state_directory_diagnostics(&prefix, metadata.uid(), metadata.gid());
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].kind, "state_directory_missing");
        assert!(diagnostics[0].remediation.contains("sudo install -d"));

        fs::create_dir(&cache).unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600)).unwrap();
        let diagnostics = state_directory_diagnostics(&prefix, metadata.uid(), metadata.gid());
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].kind, "state_directory_permissions_invalid");
        assert!(diagnostics[0].message.contains("mode 0o0600"));

        let _ = fs::remove_dir_all(prefix);
    }

    #[test]
    fn stub_version_determines_when_an_upgrade_is_required() {
        let path = temp_path("brew-stub-version");

        fs::write(&path, [STUB_MARKER, b" different build"].concat()).unwrap();
        assert!(stub_is_current(&path));

        fs::write(&path, b"AUTOMIC_VAULT_BREW_STUB_V0 old").unwrap();
        assert!(is_managed_stub_file(&path));
        assert!(!stub_is_current(&path));

        fs::write(&path, b"AUTOMIC_VAULT_BREW_STUB_V4 future").unwrap();
        assert!(stub_is_current(&path));

        for invalid in [
            b"ordinary executable".as_slice(),
            b"AUTOMIC_VAULT_BREW_STUB_V",
            b"AUTOMIC_VAULT_BREW_STUB_Vnope",
        ] {
            fs::write(&path, invalid).unwrap();
            assert!(!is_managed_stub_file(&path));
            assert!(!stub_is_current(&path));
        }

        let _ = fs::remove_file(path);
    }

    #[test]
    fn managed_outdated_stub_remains_hardened() {
        let path = temp_path("brew-stub-outdated");
        fs::write(&path, b"AUTOMIC_VAULT_BREW_STUB_V0 old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o6755)).unwrap();
        let metadata = path.metadata().unwrap();

        assert!(is_hardened_stub(&path, metadata.uid(), metadata.gid()));
        assert!(!stub_is_current(&path));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn ports_missing_homebrew_configuration_without_overwriting_hardened_state() {
        let dir = temp_path("brew-config-migration");
        let source = dir.join("source");
        let destination = dir.join("destination");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&destination).unwrap();
        fs::write(source.join("trust.json"), "user trust").unwrap();
        fs::write(source.join("Brewfile"), "brew config").unwrap();
        fs::write(destination.join("trust.json"), "hardened trust").unwrap();

        assert_eq!(copy_missing_tree(&source, &destination).unwrap(), 1);
        assert_eq!(
            fs::read_to_string(destination.join("trust.json")).unwrap(),
            "hardened trust"
        );
        assert_eq!(
            fs::read_to_string(destination.join("Brewfile")).unwrap(),
            "brew config"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn merges_and_removes_the_original_homebrew_cache() {
        use std::os::unix::fs::symlink;

        let dir = temp_path("brew-cache-migration");
        let source = dir.join("source");
        let destination = dir.join("destination");
        fs::create_dir_all(source.join("downloads")).unwrap();
        fs::create_dir_all(destination.join("downloads")).unwrap();
        fs::write(source.join("downloads/new"), "new").unwrap();
        symlink("downloads/new", source.join("formula--1.0")).unwrap();
        fs::write(source.join("downloads/existing"), "old").unwrap();
        fs::write(destination.join("downloads/existing"), "current").unwrap();

        assert_eq!(move_cache_contents(&source, &destination).unwrap(), 2);
        assert!(!source.exists());
        assert_eq!(
            fs::read_to_string(destination.join("formula--1.0")).unwrap(),
            "new"
        );
        assert_eq!(
            fs::read_to_string(destination.join("downloads/new")).unwrap(),
            "new"
        );
        assert_eq!(
            fs::read_to_string(destination.join("downloads/existing")).unwrap(),
            "current"
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn run_requires_root() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_path("brew-root");
        let target = dir.join("bin/brew");
        let source = dir.join("av-brew-stub");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, "").unwrap();
        fs::write(&source, STUB_MARKER).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_PREFIX", &dir);
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_TARGET", &target);
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_STUB_SOURCE", &source);
            std::env::set_var("AUTOMIC_VAULT_TEST_EUID", "501");
        }

        let err = run(&mut Vec::new(), true).unwrap_err();

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_BREW_PREFIX");
            std::env::remove_var("AUTOMIC_VAULT_TEST_BREW_TARGET");
            std::env::remove_var("AUTOMIC_VAULT_TEST_BREW_STUB_SOURCE");
            std::env::remove_var("AUTOMIC_VAULT_TEST_EUID");
        }
        assert_eq!(err, "run `sudo av harden brew`");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_homebrew_reports_target_path() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let missing = temp_path("missing-brew");
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_TARGET", &missing);
            std::env::set_var("AUTOMIC_VAULT_TEST_EUID", "0");
        }

        let err = run(&mut Vec::new(), true).unwrap_err();

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_BREW_TARGET");
            std::env::remove_var("AUTOMIC_VAULT_TEST_EUID");
        }
        assert_eq!(
            err,
            format!("Homebrew is not installed at {}", missing.display())
        );
    }

    #[test]
    fn test_stub_source_override_wins() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let source = temp_path("brew-source");
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_STUB_SOURCE", &source);
        }

        let got = brew_stub_source_path().unwrap();

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_BREW_STUB_SOURCE");
        }
        assert_eq!(got, source);
    }

    #[test]
    fn source_user_requires_a_non_root_resolvable_account() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_USER", "alice");
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_USER_UID", "501");
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_USER_HOME", "/Users/alice");
        }

        assert_eq!(
            source_user().unwrap(),
            SourceUser {
                name: "alice".into(),
                uid: 501,
                home: "/Users/alice".into(),
            }
        );

        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_USER", "root");
        }
        assert_eq!(
            source_user().unwrap_err(),
            "cannot configure root as the Homebrew cask user"
        );
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_USER", "not/a/user");
        }
        assert_eq!(
            source_user().unwrap_err(),
            "Homebrew cask user account name is invalid"
        );
        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_BREW_USER");
            std::env::remove_var("AUTOMIC_VAULT_TEST_BREW_USER_UID");
            std::env::remove_var("AUTOMIC_VAULT_TEST_BREW_USER_HOME");
        }
    }

    #[test]
    fn cask_user_file_is_protected() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root = temp_path("brew-cask-user");
        fs::create_dir_all(root.join("var/automic")).unwrap();
        let path = root.join(CASK_USER_UID_FILE);
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();

        write_cask_user_uid(&path, 501).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "501\n");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o644);

        let target = root.join("target");
        fs::write(&target, "unchanged").unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(write_cask_user_uid(&path, 502).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "unchanged");
        assert_eq!(
            cask_access_diagnostics(&root, None, None)[0].kind,
            "cask_user_file_permissions_invalid"
        );

        fs::remove_file(&path).unwrap();
        write_cask_user_uid(&path, unsafe { libc::getuid() }).unwrap();
        let caskroom = root.join("Caskroom");
        fs::create_dir(root.join("real-caskroom")).unwrap();
        std::os::unix::fs::symlink(root.join("real-caskroom"), &caskroom).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_USER", "alice");
        }
        assert!(
            cask_access_diagnostics(&root, None, None)
                .iter()
                .any(|diagnostic| diagnostic.kind == "caskroom_owner_invalid")
        );
        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_BREW_USER");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn obsolete_cask_acls_are_removed() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let prefix = temp_path("brew-cask-acl");
        fs::create_dir_all(prefix.join("Cellar")).unwrap();
        fs::create_dir_all(prefix.join("bin")).unwrap();
        fs::create_dir_all(prefix.join("var/automic/.homebrew")).unwrap();
        let protected_app = prefix.join("Caskroom/example/1/Protected.app");
        fs::create_dir_all(&protected_app).unwrap();
        std::os::unix::fs::symlink(
            "missing",
            prefix.join("Caskroom/example/1/Dangling.qlgenerator"),
        )
        .unwrap();
        assert!(
            Command::new("/usr/bin/chflags")
                .arg("uchg")
                .arg(&protected_app)
                .status()
                .unwrap()
                .success()
        );
        fs::write(
            prefix.join(CASK_USER_UID_FILE),
            unsafe { libc::getuid() }.to_string(),
        )
        .unwrap();
        let user = std::env::var("USER").unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_USER", &user);
        }
        let cask_acl = format!(
            "{user} allow read,write,execute,delete,append,readattr,writeattr,readextattr,writeextattr,readsecurity,file_inherit,directory_inherit"
        );
        let config_acl = format!(
            "{user} allow read,execute,readattr,readextattr,readsecurity,file_inherit,directory_inherit"
        );
        for (path, acl) in [
            (prefix.join("Caskroom"), &cask_acl),
            (prefix.join("Caskroom/example/1"), &cask_acl),
            (prefix.join("var/automic/.homebrew"), &config_acl),
        ] {
            assert!(
                Command::new("/bin/chmod")
                    .args(["+a", acl])
                    .arg(path)
                    .status()
                    .unwrap()
                    .success()
            );
        }

        remove_legacy_cask_access(&prefix, &user).unwrap();

        assert!(!acl_mentions(&prefix.join("Caskroom"), &user));
        assert!(!acl_mentions(&prefix.join("Caskroom/example/1"), &user));
        assert!(!acl_mentions(&protected_app, &user));
        assert!(!acl_mentions(&prefix.join("var/automic/.homebrew"), &user));
        assert!(!acl_mentions(&prefix, &user));
        assert!(!acl_mentions(&prefix.join("Cellar"), &user));
        assert!(!acl_mentions(&prefix.join("bin"), &user));
        let metadata = prefix.join(CASK_USER_UID_FILE).metadata().unwrap();
        assert!(
            cask_access_diagnostics(&prefix, Some(metadata.uid()), Some(metadata.gid())).is_empty()
        );

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_BREW_USER");
        }
        assert!(
            Command::new("/usr/bin/chflags")
                .arg("nouchg")
                .arg(&protected_app)
                .status()
                .unwrap()
                .success()
        );
        fs::remove_dir_all(prefix).unwrap();
    }

    #[test]
    fn ownership_repair_skips_macos_managed_automic_library() {
        let prefix = temp_path("brew-protected-library");
        let library = prefix.join("var/automic/Library");
        fs::create_dir_all(library.join("Mail")).unwrap();
        fs::set_permissions(&library, fs::Permissions::from_mode(0o000)).unwrap();

        chown_recursive(&prefix, unsafe { libc::getuid() }, unsafe {
            libc::getgid()
        })
        .unwrap();

        fs::set_permissions(&library, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(prefix).unwrap();
    }

    fn temp_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("av-{label}-{}-{nanos}", std::process::id()))
    }
}
