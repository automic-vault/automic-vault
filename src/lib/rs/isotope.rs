use super::*;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
#[cfg(target_os = "macos")]
use std::ffi::{c_char, c_int};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;

const KEYCHAIN_SERVICE: &str = "com.automicvault.isotope";
#[cfg(target_os = "macos")]
const ERR_SEC_ITEM_NOT_FOUND: c_int = -25300;
const APP_BUNDLE_IDENTIFIER: &str = "com.automicvault";
const APPROVAL_NOTIFICATION: &str = "com.automicvault.isotope-approval.pending-changed";
const AUTOMATIC_APPROVAL_NOTIFICATION: &str = "com.automicvault.isotope-approval.automatic-granted";
const USER_APPROVAL_SUBDIR: &str = "isotope";
const ALWAYS_ALLOW_PATH: &str =
    "/Library/Application Support/Automic Vault/isotope/always-allow.json";
pub(crate) const CREDENTIAL_HELPER_TOKEN_ENV: &str = "AUTOMIC_VAULT_CREDENTIAL_HELPER_TOKEN";

#[derive(Debug)]
struct IsotopeOptions {
    replace_existing_env: bool,
    allow_missing_keys: bool,
    keys: Vec<String>,
    target: PathBuf,
    args: Vec<OsString>,
}

#[derive(Debug)]
struct SaveSecretOptions {
    key: String,
}

#[derive(Debug)]
pub(crate) struct CredentialHelperCallerContext {
    pub(crate) token: Option<String>,
    pub(crate) parent_executable_path: Option<String>,
    pub(crate) parent_command: Option<String>,
}

pub(crate) struct CredentialHelperInvocation<'a> {
    pub(crate) args: Vec<OsString>,
    pub(crate) caller: CredentialHelperCallerContext,
    pub(crate) store: &'a dyn CredentialHelperSecretStore,
}

#[derive(Debug)]
struct IsotopePreparedExecution {
    exec_fd: i32,
    exec_path: String,
    argv: Vec<OsString>,
    env: BTreeMap<OsString, OsString>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct IsotopeApprovalRequestSnapshot {
    id: String,
    keys: Vec<String>,
    executable_path: String,
    executable_root_controlled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    script_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    script_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_script_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    script_root_controlled: Option<bool>,
    requested_executable_path: String,
    argv: Vec<String>,
    cwd: String,
    parent_process: ParentProcessSnapshot,
    can_always_allow: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ParentProcessSnapshot {
    pid: i32,
    executable_path: Option<String>,
    display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct IsotopeApprovalDecision {
    id: String,
    approved: bool,
    always_allow: bool,
    reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct IsotopeAlwaysAllowEntry {
    executable_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    script_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    script_sha256: Option<String>,
    keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IsotopeAlwaysAllowScope {
    executable_path: String,
    script_path: Option<String>,
    script_sha256: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct IsotopeAlwaysAllowStore {
    entries: Vec<IsotopeAlwaysAllowEntry>,
}

impl IsotopeAlwaysAllowStore {
    fn always_allows_keys(&self, scope: &IsotopeAlwaysAllowScope, keys: &[String]) -> bool {
        let allowed_keys = self
            .entries
            .iter()
            .filter(|entry| {
                entry.executable_path == scope.executable_path
                    && entry.script_path == scope.script_path
                    && entry.script_sha256 == scope.script_sha256
            })
            .flat_map(|entry| entry.keys.iter())
            .collect::<BTreeSet<_>>();
        keys.iter().all(|key| allowed_keys.contains(key))
    }
}

pub(crate) trait CredentialHelperSecretStore {
    fn load_secret(&self, key: &str) -> Result<String, String>;

    fn load_secret_if_present(&self, key: &str) -> Result<Option<String>, String> {
        self.load_secret(key).map(Some)
    }

    fn secret_exists(&self, key: &str) -> Result<bool, String> {
        self.load_secret_if_present(key)
            .map(|value| value.is_some())
    }

    fn store_secret(&self, _key: &str, _value: &str) -> Result<(), String> {
        Err("credential helper store is read-only".to_string())
    }
}

trait CredentialStore: CredentialHelperSecretStore {
    fn store_secret(&self, key: &str, value: &str) -> Result<(), String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissingCredentialPolicy {
    Required,
    SkipMissing,
}

struct KeychainCredentialStore;

pub fn isotope_main_entry() {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_else(|| OsString::from("isotope"));
    let program_name = Path::new(&program)
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("isotope");
    let result = run_isotope_entry(program_name, args);
    if let Err(err) = result {
        eprintln!("{program_name}: {err}");
        process::exit(1);
    }
}

pub(crate) fn run_isotope_entry(
    program_name: &str,
    args: impl Iterator<Item = OsString>,
) -> Result<(), String> {
    dispatch_isotope(program_name, args, &KeychainCredentialStore)
}

pub(crate) fn run_save_entry(program_name: &str, args: env::ArgsOs) -> Result<(), String> {
    dispatch_save(program_name, args, &KeychainCredentialStore)
}

pub(crate) fn run_credential_helper_entry(
    program_name: &str,
    args: env::ArgsOs,
) -> Result<(), String> {
    dispatch_credential_helper(program_name, args, &KeychainCredentialStore)
}

fn dispatch_isotope(
    program_name: &str,
    mut args: impl Iterator<Item = OsString>,
    store: &dyn CredentialStore,
) -> Result<(), String> {
    let Some(first_arg) = args.next() else {
        print_isotope_usage(program_name);
        return Err("missing key and target binary".to_string());
    };

    if is_help_flag(&first_arg) {
        print_isotope_usage(program_name);
        return Ok(());
    }

    if is_version_flag(&first_arg) {
        println!("{program_name} {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let options = parse_isotope_options(program_name, first_arg, args)?;
    if is_root() {
        return Err("must not be run as root".to_string());
    }
    run_isotope(&options, store)
}

fn dispatch_save(
    program_name: &str,
    args: impl Iterator<Item = OsString>,
    store: &dyn CredentialStore,
) -> Result<(), String> {
    let Some(options) = parse_save_options(program_name, args)? else {
        return Ok(());
    };
    let value = read_save_secret()?;
    run_save(&options, &value, store)
}

fn dispatch_credential_helper(
    program_name: &str,
    mut args: impl Iterator<Item = OsString>,
    store: &dyn CredentialHelperSecretStore,
) -> Result<(), String> {
    let Some(protocol) = args.next() else {
        print_credential_helper_usage(program_name);
        return Err("missing credential helper protocol".to_string());
    };

    if is_help_flag(&protocol) {
        print_credential_helper_usage(program_name);
        return Ok(());
    }
    if is_version_flag(&protocol) {
        println!("{program_name} {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let protocol = protocol
        .to_str()
        .ok_or_else(|| "credential helper protocol must be valid UTF-8".to_string())?;
    let Some(integration) = credential_helper_integration(protocol) else {
        return Err(format!("unknown credential helper protocol '{protocol}'"));
    };
    let credential_helper = integration
        .credential_helper
        .ok_or_else(|| format!("credential helper protocol '{protocol}' is not callable"))?;
    disable_core_dumps()?;
    let caller = current_credential_helper_caller_context();
    let parent = parent_process_snapshot();
    crate::audit::record(
        crate::audit::Event::new(
            crate::audit::EVENT_SECRET_PULL,
            crate::audit::DECISION_OBSERVED,
        )
        .mode(protocol.to_string())
        .token_present(caller.token.is_some())
        .parent(parent.pid as i64, parent.executable_path, parent.display_name),
    );
    credential_helper(CredentialHelperInvocation {
        args: args.collect(),
        caller,
        store,
    })
}

fn parse_isotope_options(
    program_name: &str,
    first_arg: OsString,
    args: impl Iterator<Item = OsString>,
) -> Result<IsotopeOptions, String> {
    let mut replace_existing_env = false;
    let mut allow_missing_keys = false;
    let mut keys = Vec::new();
    let mut seen_keys = BTreeSet::new();
    let mut iter = std::iter::once(first_arg).chain(args);

    while let Some(arg) = iter.next() {
        if arg == "--replace-existing-env" {
            replace_existing_env = true;
            continue;
        }
        if arg == "--allow-missing-keys" {
            allow_missing_keys = true;
            continue;
        }
        if arg == "--allow-existing-env" {
            return Err(
                "--allow-existing-env has been replaced by --replace-existing-env".to_string(),
            );
        }
        if arg == "--force" {
            return Err("--force has been replaced by --replace-existing-env".to_string());
        }
        if arg == "--import" || arg == "--migrate" {
            return Err("credential import and migration are no longer supported".to_string());
        }

        let value = arg
            .to_str()
            .ok_or_else(|| "isotope arguments must be valid UTF-8".to_string())?;
        if let Some(key) = value.strip_prefix('+') {
            validate_key_name(key)?;
            if !seen_keys.insert(key.to_string()) {
                return Err(format!("duplicate key requested: {key}"));
            }
            keys.push(key.to_string());
            continue;
        }

        if keys.is_empty() {
            return Err("at least one +KEY must be provided before the target".to_string());
        }

        keys.sort();
        let target = PathBuf::from(arg);
        if !target.is_absolute() {
            return Err("target binary path must be absolute".to_string());
        }
        return Ok(IsotopeOptions {
            replace_existing_env,
            allow_missing_keys,
            keys,
            target,
            args: iter.collect(),
        });
    }

    print_isotope_usage(program_name);
    Err("missing target binary".to_string())
}

fn parse_save_options<I>(program_name: &str, args: I) -> Result<Option<SaveSecretOptions>, String>
where
    I: Iterator<Item = OsString>,
{
    let mut positionals = Vec::new();

    for arg in args {
        if is_help_flag(&arg) {
            print_save_usage(program_name);
            return Ok(None);
        }
        if is_version_flag(&arg) {
            println!("{program_name} {}", env!("CARGO_PKG_VERSION"));
            return Ok(None);
        }

        if arg == "--allow" || arg == "--allow-path" {
            return Err(
                "--allow/--allow-path have been removed; approve injection with av inject"
                    .to_string(),
            );
        }

        positionals.push(arg);
        if positionals.len() > 1 {
            return Err("supports KEY only; provide the secret on stdin".to_string());
        }
    }

    let key = parse_save_key(program_name, &positionals)?;
    validate_key_name(&key)?;
    Ok(Some(SaveSecretOptions { key }))
}

fn parse_save_key(program_name: &str, positionals: &[OsString]) -> Result<String, String> {
    if positionals.is_empty() {
        print_save_usage(program_name);
        return Err("missing KEY".to_string());
    }
    let [key] = positionals else {
        return Err("supports KEY only; provide the secret on stdin".to_string());
    };
    let key = key
        .to_str()
        .ok_or_else(|| "secret key must be valid UTF-8".to_string())?;
    if key.contains('=') {
        return Err("supports KEY only; provide the secret on stdin".to_string());
    }
    let key = key.trim();
    Ok(key.to_string())
}

fn read_save_secret() -> Result<String, String> {
    let mut stdin = io::stdin();
    let mut value = String::new();

    if stdin.is_terminal() {
        eprint!("Secret: ");
        io::stderr()
            .flush()
            .map_err(|err| format!("failed to flush prompt: {err}"))?;
        read_secret_line_no_echo(&mut stdin, &mut value)?;
        eprintln!();
    } else {
        stdin
            .read_to_string(&mut value)
            .map_err(|err| format!("failed to read secret from stdin: {err}"))?;
    }

    let value = value.trim().to_string();
    if value.is_empty() {
        return Err("empty isotope secret value".to_string());
    }
    Ok(value)
}

fn read_secret_line_no_echo(stdin: &mut io::Stdin, value: &mut String) -> Result<(), String> {
    let fd = stdin.as_raw_fd();
    let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: tcgetattr initializes termios when it succeeds for a valid fd.
    if unsafe { libc::tcgetattr(fd, termios.as_mut_ptr()) } != 0 {
        return Err(format!(
            "failed to read terminal settings: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: tcgetattr succeeded above, so termios is initialized.
    let original = unsafe { termios.assume_init() };
    let mut hidden = original;
    hidden.c_lflag &= !libc::ECHO;
    // SAFETY: fd is stdin and hidden is a valid termios value derived from tcgetattr.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
        return Err(format!(
            "failed to disable terminal echo: {}",
            io::Error::last_os_error()
        ));
    }

    let read_result = stdin.read_line(value);
    // SAFETY: original is the termios value returned by tcgetattr for this fd.
    let restore_result = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &original) };
    if restore_result != 0 {
        return Err(format!(
            "failed to restore terminal echo: {}",
            io::Error::last_os_error()
        ));
    }

    read_result.map_err(|err| format!("failed to read secret: {err}"))?;
    Ok(())
}

fn validate_key_name(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("empty isotope key name".to_string());
    }
    let mut chars = key.chars();
    let first = chars.next().unwrap();
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return Err(format!("invalid isotope key name: {key}"));
    }
    if chars.any(|ch| !(ch == '_' || ch.is_ascii_alphanumeric())) {
        return Err(format!("invalid isotope key name: {key}"));
    }
    Ok(())
}

pub(crate) fn validate_isotope_key_name_for_transfer(key: &str) -> Result<(), String> {
    validate_key_name(key)
}

pub(crate) fn load_isotope_secret_for_transfer(key: &str) -> Result<String, String> {
    validate_key_name(key)?;
    KeychainCredentialStore.load_secret(key)
}

#[cfg(test)]
pub(crate) fn load_existing_isotope_secret_for_transfer(
    key: &str,
) -> Result<Option<String>, String> {
    validate_key_name(key)?;
    KeychainCredentialStore.load_secret_if_present(key)
}

#[cfg(test)]
pub(crate) fn store_isotope_secret_for_transfer(key: &str, value: &str) -> Result<(), String> {
    validate_key_name(key)?;
    CredentialStore::store_secret(&KeychainCredentialStore, key, value)
}

fn run_save(
    options: &SaveSecretOptions,
    value: &str,
    store: &dyn CredentialStore,
) -> Result<(), String> {
    CredentialStore::store_secret(store, &options.key, value)?;
    println!("saved {}", options.key);
    Ok(())
}

fn run_isotope(options: &IsotopeOptions, store: &dyn CredentialStore) -> Result<(), String> {
    disable_core_dumps()?;

    let resolved_target = fs::canonicalize(&options.target)
        .map_err(|err| format!("failed to resolve {}: {err}", options.target.display()))?;
    let resolved_target_string = resolved_target
        .to_str()
        .ok_or_else(|| "resolved target path must be valid UTF-8".to_string())?
        .to_string();

    let existing_env_keys = check_environment_conflicts(&options.keys);
    let mut credential_keys = credential_keys_to_load(
        &options.keys,
        &existing_env_keys,
        options.replace_existing_env,
    );

    let file = File::open(&resolved_target)
        .map_err(|err| format!("failed to open {}: {err}", resolved_target.display()))?;
    validate_regular_target(&resolved_target, &file)?;
    validate_parent_directories(&options.target)?;
    let always_allow_scope = always_allow_scope(
        &resolved_target_string,
        &resolved_target,
        &file,
        &options.args,
    );
    let executable_path_for_approval = always_allow_scope
        .as_ref()
        .ok()
        .map(|scope| scope.executable_path.as_str())
        .unwrap_or(&resolved_target_string);
    let executable_root_controlled = if executable_path_for_approval == resolved_target_string {
        validate_target_root_installation(&resolved_target, &file).is_ok()
    } else {
        true
    };
    let requested_script_path = script_path_for_display(
        &resolved_target,
        always_allow_scope.as_ref().ok(),
        &options.args,
    );
    let script_root_controlled = requested_script_path
        .as_deref()
        .map(|path| validate_root_controlled_path(path).is_ok());
    let can_always_allow = always_allow_scope.is_ok();

    if options.allow_missing_keys {
        credential_keys = credential_keys_present(store, &credential_keys)?;
    }

    let automatically_approved = if !credential_keys.is_empty() && can_always_allow {
        match always_allows_usage(
            always_allow_scope
                .as_ref()
                .expect("validated always-allow scope"),
            &credential_keys,
        ) {
            Ok(value) => value,
            Err(err) => return Err(err),
        }
    } else {
        false
    };

    if !credential_keys.is_empty() && !automatically_approved {
        if let Err(err) = request_isotope_approval(
            executable_path_for_approval,
            always_allow_scope.as_ref().ok(),
            options,
            &credential_keys,
            executable_root_controlled,
            requested_script_path,
            script_root_controlled,
            can_always_allow,
        ) {
            crate::audit::record(
                crate::audit::Event::new(
                    crate::audit::EVENT_APPROVAL_DECISION,
                    crate::audit::DECISION_DENIED,
                )
                .keys(credential_keys.iter().cloned())
                .exec(resolved_target_string.clone(), Vec::new())
                .reason(Some(err.clone())),
            );
            return Err(err);
        }
    } else if automatically_approved {
        let _ = post_distributed_notification_with_object(
            AUTOMATIC_APPROVAL_NOTIFICATION,
            &credential_keys.join(", "),
        );
    }

    let mut env_map = env::vars_os().collect::<BTreeMap<_, _>>();
    let missing_policy = if options.allow_missing_keys {
        MissingCredentialPolicy::SkipMissing
    } else {
        MissingCredentialPolicy::Required
    };
    let mut credentials = load_credentials_with_policy(store, &credential_keys, missing_policy)?;
    for (key, value) in &credentials {
        env_map.insert(OsString::from(key), OsString::from(value));
    }

    let prepared = match prepare_execution(&file, options, env_map) {
        Ok(prepared) => prepared,
        Err(err) => {
            zeroize_credentials(&mut credentials);
            return Err(err);
        }
    };
    // Pre-exec audit: `exec_prepared` replaces the process image, so this must
    // be the last thing recorded. Best-effort; never blocks the exec.
    if !credential_keys.is_empty() {
        let parent = parent_process_snapshot();
        crate::audit::record(
            crate::audit::Event::new(
                crate::audit::EVENT_SECRET_INJECT,
                if automatically_approved {
                    crate::audit::DECISION_AUTO_GRANT
                } else {
                    crate::audit::DECISION_APPROVED
                },
            )
            .keys(credential_keys.iter().cloned())
            .exec(
                prepared.exec_path.clone(),
                prepared
                    .argv
                    .iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect(),
            )
            .cwd(
                env::current_dir()
                    .map(|dir| dir.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            )
            .parent(parent.pid as i64, parent.executable_path, parent.display_name)
            .outcome("exec"),
        );
    }

    let result = exec_prepared(prepared);
    zeroize_credentials(&mut credentials);
    result
}

fn check_environment_conflicts(keys: &[String]) -> BTreeSet<String> {
    let mut existing_env_keys = BTreeSet::new();
    for key in keys {
        if env::var_os(key).is_some() {
            existing_env_keys.insert(key.clone());
        }
    }

    for key in &existing_env_keys {
        eprintln!(
            "isotope: warning: environment variable {key} is already set; \
             leaving existing value unchanged \
             (replace with: --replace-existing-env)"
        );
    }

    existing_env_keys
}

fn credential_keys_to_load(
    keys: &[String],
    existing_env_keys: &BTreeSet<String>,
    replace_existing_env: bool,
) -> Vec<String> {
    keys.iter()
        .filter(|key| replace_existing_env || !existing_env_keys.contains(*key))
        .cloned()
        .collect()
}

fn credential_keys_present(
    store: &dyn CredentialHelperSecretStore,
    keys: &[String],
) -> Result<Vec<String>, String> {
    let mut present = Vec::new();
    for key in keys {
        if store.secret_exists(key)? {
            present.push(key.clone());
        }
    }
    Ok(present)
}

pub(crate) fn load_credentials(
    store: &dyn CredentialHelperSecretStore,
    keys: &[String],
) -> Result<BTreeMap<String, String>, String> {
    load_credentials_with_policy(store, keys, MissingCredentialPolicy::Required)
}

fn load_credentials_with_policy(
    store: &dyn CredentialHelperSecretStore,
    keys: &[String],
    missing_policy: MissingCredentialPolicy,
) -> Result<BTreeMap<String, String>, String> {
    let mut credentials = BTreeMap::new();
    for key in keys {
        match missing_policy {
            MissingCredentialPolicy::Required => {
                credentials.insert(key.clone(), store.load_secret(key)?);
            }
            MissingCredentialPolicy::SkipMissing => {
                if let Some(value) = store.load_secret_if_present(key)? {
                    credentials.insert(key.clone(), value);
                }
            }
        }
    }
    Ok(credentials)
}

fn credential_helper_integration(
    name: &str,
) -> Option<&'static isotope_integrations::IsotopeIntegration> {
    isotope_integrations::INTEGRATIONS
        .iter()
        .find(|integration| integration.credential_helper_name == Some(name))
}

fn current_credential_helper_caller_context() -> CredentialHelperCallerContext {
    let parent_pid = unsafe { libc::getppid() };
    CredentialHelperCallerContext {
        token: env::var(CREDENTIAL_HELPER_TOKEN_ENV).ok(),
        parent_executable_path: parent_process_path(parent_pid),
        parent_command: parent_process_command(parent_pid),
    }
}

fn validate_regular_target(path: &Path, file: &File) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
    if !metadata.is_file() {
        return Err("target binary must be a regular file".to_string());
    }
    Ok(())
}

fn validate_target_root_installation(path: &Path, file: &File) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
    validate_target_file_metadata(metadata.uid(), metadata.mode())?;
    validate_parent_directories(path)
}

pub(crate) fn validate_root_controlled_path(path: &Path) -> Result<(), String> {
    let file =
        File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    validate_regular_target(path, &file)?;
    validate_target_root_installation(path, &file)
}

fn validate_target_file_metadata(uid: u32, mode: u32) -> Result<(), String> {
    if uid != 0 {
        return Err("target binary must be owned by root".to_string());
    }
    if mode & ((libc::S_IWGRP | libc::S_IWOTH) as u32) != 0 {
        return Err("target binary must not be writable by group or others".to_string());
    }
    if mode & 0o111 == 0 {
        return Err("target binary must be executable".to_string());
    }
    Ok(())
}

fn validate_parent_directories(path: &Path) -> Result<(), String> {
    for directory in path.ancestors().skip(1) {
        let metadata = fs::metadata(directory)
            .map_err(|err| format!("failed to stat {}: {err}", directory.display()))?;
        validate_directory_mode(directory, metadata.mode())?;
    }
    Ok(())
}

fn validate_directory_mode(path: &Path, mode: u32) -> Result<(), String> {
    if mode & ((libc::S_IWGRP | libc::S_IWOTH) as u32) != 0 {
        return Err(format!(
            "directory must not be writable by group or others: {}",
            path.display()
        ));
    }
    Ok(())
}

fn always_allow_scope(
    executable_path: &str,
    resolved_executable_path: &Path,
    file: &File,
    args: &[OsString],
) -> Result<IsotopeAlwaysAllowScope, String> {
    if let Some(script) = direct_shebang_script_for_always_allow(resolved_executable_path, file)? {
        return Ok(IsotopeAlwaysAllowScope {
            executable_path: script.interpreter_path,
            script_path: Some(
                script
                    .path
                    .to_str()
                    .map(str::to_string)
                    .ok_or_else(|| "script path must be valid UTF-8".to_string())?,
            ),
            script_sha256: script.sha256,
        });
    }

    validate_target_root_installation(resolved_executable_path, file)?;
    let script = interpreter_script_for_always_allow(resolved_executable_path, args)?;
    Ok(IsotopeAlwaysAllowScope {
        executable_path: executable_path.to_string(),
        script_path: script
            .as_ref()
            .map(|path| {
                path.path
                    .to_str()
                    .map(str::to_string)
                    .ok_or_else(|| "script path must be valid UTF-8".to_string())
            })
            .transpose()?,
        script_sha256: script.and_then(|script| script.sha256),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IsotopeAlwaysAllowScript {
    path: PathBuf,
    interpreter_path: String,
    sha256: Option<String>,
}

fn direct_shebang_script_for_always_allow(
    script_path: &Path,
    file: &File,
) -> Result<Option<IsotopeAlwaysAllowScript>, String> {
    let Some(interpreter_path) = shebang_interpreter_path(script_path)? else {
        return Ok(None);
    };
    if executable_file_name(&interpreter_path) == Some("env") {
        return Err("env shebang always-allow is not supported".to_string());
    }

    let interpreter_file = File::open(&interpreter_path).map_err(|err| {
        format!(
            "failed to open shebang interpreter {}: {err}",
            interpreter_path.display()
        )
    })?;
    validate_regular_target(&interpreter_path, &interpreter_file)?;
    validate_target_root_installation(&interpreter_path, &interpreter_file)?;

    let interpreter_path = interpreter_path
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| "shebang interpreter path must be valid UTF-8".to_string())?;
    if validate_target_root_installation(script_path, file).is_ok() {
        return Ok(Some(IsotopeAlwaysAllowScript {
            path: script_path.to_path_buf(),
            interpreter_path,
            sha256: None,
        }));
    }

    Ok(Some(IsotopeAlwaysAllowScript {
        path: script_path.to_path_buf(),
        interpreter_path,
        sha256: Some(sha256_file(script_path)?),
    }))
}

fn interpreter_script_for_always_allow(
    executable_path: &Path,
    args: &[OsString],
) -> Result<Option<IsotopeAlwaysAllowScript>, String> {
    if executable_file_name(executable_path) == Some("env") {
        return Err("env always-allow is not supported".to_string());
    }
    if !is_script_interpreter(executable_path) {
        return Ok(None);
    }
    let script_operand = interpreter_script_operand(args)
        .ok_or_else(|| "interpreter always-allow requires a root-owned script file".to_string())?;
    let script_path = resolve_script_operand(script_operand)?;
    let file = File::open(&script_path)
        .map_err(|err| format!("failed to open {}: {err}", script_path.display()))?;
    validate_regular_target(&script_path, &file)?;
    if validate_target_root_installation(&script_path, &file).is_ok() {
        return Ok(Some(IsotopeAlwaysAllowScript {
            path: script_path,
            interpreter_path: path_to_display_string(executable_path)?,
            sha256: None,
        }));
    }
    let sha256 = sha256_file(&script_path)?;
    Ok(Some(IsotopeAlwaysAllowScript {
        path: script_path,
        interpreter_path: path_to_display_string(executable_path)?,
        sha256: Some(sha256),
    }))
}

fn script_path_for_display(
    executable_path: &Path,
    always_allow_scope: Option<&IsotopeAlwaysAllowScope>,
    args: &[OsString],
) -> Option<PathBuf> {
    if let Some(scope) = always_allow_scope
        && let Some(script_path) = scope.script_path.as_deref()
    {
        let display_path = PathBuf::from(script_path);
        if display_path == executable_path {
            return Some(display_path);
        }
    }

    interpreter_script_path_for_display(executable_path, args)
}

fn interpreter_script_path_for_display(
    executable_path: &Path,
    args: &[OsString],
) -> Option<PathBuf> {
    if !is_script_interpreter(executable_path)
        || executable_file_name(executable_path) == Some("env")
    {
        return None;
    }
    let script_path = interpreter_script_operand(args)?;
    let path = if script_path.is_absolute() {
        script_path.to_path_buf()
    } else {
        env::current_dir().ok()?.join(script_path)
    };
    Some(fs::canonicalize(&path).unwrap_or(path))
}

fn shebang_interpreter_path(path: &Path) -> Result<Option<PathBuf>, String> {
    let file = File::open(path).map_err(|err| {
        format!(
            "failed to open {} for shebang inspection: {err}",
            path.display()
        )
    })?;
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    reader
        .read_until(b'\n', &mut line)
        .map_err(|err| format!("failed to read shebang from {}: {err}", path.display()))?;
    if !line.starts_with(b"#!") {
        return Ok(None);
    }
    let line = String::from_utf8_lossy(&line[2..]);
    let Some(interpreter) = line.split_whitespace().next() else {
        return Err("script shebang must name an interpreter".to_string());
    };
    let interpreter = Path::new(interpreter);
    if !interpreter.is_absolute() {
        return Err("script shebang interpreter must be absolute".to_string());
    }
    fs::canonicalize(interpreter).map(Some).map_err(|err| {
        format!(
            "failed to resolve shebang interpreter {}: {err}",
            interpreter.display()
        )
    })
}

fn path_to_display_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| "path must be valid UTF-8".to_string())
}

fn is_script_interpreter(path: &Path) -> bool {
    let Some(file_name) = executable_file_name(path) else {
        return false;
    };
    matches!(
        file_name,
        "bash"
            | "dash"
            | "env"
            | "ksh"
            | "node"
            | "osascript"
            | "perl"
            | "python"
            | "python3"
            | "ruby"
            | "sh"
            | "zsh"
    ) || is_versioned_python_name(file_name)
}

fn is_versioned_python_name(file_name: &str) -> bool {
    let Some(suffix) = file_name.strip_prefix("python") else {
        return false;
    };
    !suffix.is_empty() && suffix.chars().all(|ch| ch == '.' || ch.is_ascii_digit())
}

fn executable_file_name(path: &Path) -> Option<&str> {
    path.file_name().and_then(|value| value.to_str())
}

fn interpreter_script_operand(args: &[OsString]) -> Option<&Path> {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].to_str()?;
        if arg == "--" {
            return args.get(index + 1).map(Path::new);
        }
        if !arg.starts_with('-') || arg == "-" {
            return args.get(index).map(Path::new);
        }
        if interpreter_option_takes_value(arg) {
            index += 2;
        } else {
            index += 1;
        }
    }
    None
}

fn interpreter_option_takes_value(arg: &str) -> bool {
    matches!(
        arg,
        "-c" | "-m" | "-S" | "-e" | "-I" | "-l" | "-x" | "-C" | "-M" | "-d" | "-r"
    )
}

fn resolve_script_operand(path: &Path) -> Result<PathBuf, String> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|err| format!("failed to resolve current directory: {err}"))?
            .join(path)
    };
    fs::canonicalize(&path).map_err(|err| format!("failed to resolve {}: {err}", path.display()))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn always_allows_usage(scope: &IsotopeAlwaysAllowScope, keys: &[String]) -> Result<bool, String> {
    let store = load_always_allow_store()?;
    Ok(store.always_allows_keys(scope, keys))
}

#[cfg(test)]
fn always_allows_usage_at_path(
    path: &Path,
    scope: &IsotopeAlwaysAllowScope,
    keys: &[String],
) -> Result<bool, String> {
    let store = load_always_allow_store_at_path(path)?;
    Ok(store.always_allows_keys(scope, keys))
}

fn load_always_allow_store() -> Result<IsotopeAlwaysAllowStore, String> {
    load_root_controlled_always_allow_store_at_path(Path::new(ALWAYS_ALLOW_PATH))
}

fn load_always_allow_store_at_path(path: &Path) -> Result<IsotopeAlwaysAllowStore, String> {
    if !path.exists() {
        return Ok(IsotopeAlwaysAllowStore::default());
    }
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&contents)
        .map_err(|err| format!("failed to decode {}: {err}", path.display()))
}

fn load_root_controlled_always_allow_store_at_path(
    path: &Path,
) -> Result<IsotopeAlwaysAllowStore, String> {
    if !path.exists() {
        return Ok(IsotopeAlwaysAllowStore::default());
    }
    if !is_root_controlled_always_allow_file(path)? {
        return Ok(IsotopeAlwaysAllowStore::default());
    }
    load_always_allow_store_at_path(path)
}

fn is_root_controlled_always_allow_file(path: &Path) -> Result<bool, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Ok(false);
    }
    let Some(parent) = path.parent() else {
        return Ok(false);
    };
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|err| format!("failed to stat {}: {err}", parent.display()))?;
    Ok(parent_metadata.is_dir()
        && parent_metadata.uid() == 0
        && parent_metadata.mode() & 0o022 == 0)
}

fn request_isotope_approval(
    executable_path: &str,
    always_allow_scope: Option<&IsotopeAlwaysAllowScope>,
    options: &IsotopeOptions,
    credential_keys: &[String],
    executable_root_controlled: bool,
    requested_script_path: Option<PathBuf>,
    script_root_controlled: Option<bool>,
    can_always_allow: bool,
) -> Result<(), String> {
    let request_id = format!(
        "{}-{}",
        process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|err| format!("failed to compute request timestamp: {err}"))?
            .as_millis()
    );
    let request = IsotopeApprovalRequestSnapshot {
        id: request_id.clone(),
        keys: credential_keys.to_vec(),
        executable_path: executable_path.to_string(),
        executable_root_controlled,
        script_path: always_allow_scope.and_then(|scope| scope.script_path.clone()),
        script_sha256: always_allow_scope.and_then(|scope| scope.script_sha256.clone()),
        requested_script_path: requested_script_path
            .as_deref()
            .map(path_to_display_string)
            .transpose()?,
        script_root_controlled,
        requested_executable_path: options
            .target
            .to_str()
            .ok_or_else(|| "target path must be valid UTF-8".to_string())?
            .to_string(),
        argv: options
            .args
            .iter()
            .map(|arg| {
                arg.to_str()
                    .ok_or_else(|| "arguments must be valid UTF-8".to_string())
                    .map(str::to_string)
            })
            .collect::<Result<Vec<_>, _>>()?,
        cwd: env::current_dir()
            .map_err(|err| format!("failed to resolve current directory: {err}"))?
            .to_string_lossy()
            .into_owned(),
        parent_process: parent_process_snapshot(),
        can_always_allow,
    };

    let pending_url = pending_approval_path()?;
    write_json(&pending_url, &request)?;
    if let Err(err) = ping_isotope_approval_app() {
        let _ = fs::remove_file(&pending_url);
        return Err(err);
    }
    wait_for_isotope_decision(&request_id)
}

fn parent_process_snapshot() -> ParentProcessSnapshot {
    let pid = unsafe { libc::getppid() };
    let executable_path = parent_process_path(pid);
    let display_name = executable_path
        .as_deref()
        .and_then(|path| Path::new(path).file_name())
        .and_then(|name| name.to_str())
        .map(str::to_string);

    ParentProcessSnapshot {
        pid,
        executable_path,
        display_name,
    }
}

#[cfg(target_os = "macos")]
fn parent_process_path(pid: i32) -> Option<String> {
    let output = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if path.is_empty() { None } else { Some(path) }
}

#[cfg(not(target_os = "macos"))]
fn parent_process_path(_pid: i32) -> Option<String> {
    None
}

#[cfg(target_os = "macos")]
fn parent_process_command(pid: i32) -> Option<String> {
    let output = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let command = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if command.is_empty() {
        None
    } else {
        Some(command)
    }
}

#[cfg(not(target_os = "macos"))]
fn parent_process_command(_pid: i32) -> Option<String> {
    None
}

fn wait_for_isotope_decision(id: &str) -> Result<(), String> {
    let decision_url = decision_path(id)?;
    let pending_url = pending_approval_path()?;
    wait_for_isotope_decision_at(id, &pending_url, &decision_url)
}

fn wait_for_isotope_decision_at(
    id: &str,
    pending_url: &Path,
    decision_url: &Path,
) -> Result<(), String> {
    loop {
        if let Ok(contents) = fs::read_to_string(decision_url) {
            let decision: IsotopeApprovalDecision = serde_json::from_str(&contents)
                .map_err(|err| format!("failed to decode isotope approval decision: {err}"))?;
            if decision.id != id {
                return Err("isotope approval decision id mismatch".to_string());
            }
            clear_approval_files_at(pending_url, decision_url);
            if decision.approved {
                return Ok(());
            }
            return Err(decision
                .reason
                .unwrap_or_else(|| "key injection denied".to_string()));
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn clear_approval_files_at(pending_url: &Path, decision_url: &Path) {
    let _ = fs::remove_file(pending_url);
    let _ = fs::remove_file(decision_url);
}

fn user_approval_root() -> Result<PathBuf, String> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())?;
    Ok(home
        .join("Library")
        .join("Application Support")
        .join("Automic Vault")
        .join(USER_APPROVAL_SUBDIR))
}

fn pending_approval_path() -> Result<PathBuf, String> {
    Ok(user_approval_root()?.join("pending-approval.json"))
}

fn decision_path(id: &str) -> Result<PathBuf, String> {
    Ok(user_approval_root()?
        .join("decisions")
        .join(format!("{id}.json")))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("invalid approval path {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    let payload = serde_json::to_vec_pretty(value)
        .map_err(|err| format!("failed to encode approval request: {err}"))?;
    fs::write(path, payload).map_err(|err| format!("failed to write {}: {err}", path.display()))
}

#[cfg(target_os = "macos")]
fn ping_isotope_approval_app() -> Result<(), String> {
    let status = Command::new("/usr/bin/open")
        .args(["-b", APP_BUNDLE_IDENTIFIER])
        .status()
        .map_err(|err| format!("failed to ping Automic Vault.app: {err}"))?;
    if !status.success() {
        return Err("failed to ping Automic Vault.app for isotope approval".to_string());
    }
    post_distributed_notification(APPROVAL_NOTIFICATION)
}

#[cfg(not(target_os = "macos"))]
fn ping_isotope_approval_app() -> Result<(), String> {
    Err("isotope approvals are only available on macOS".to_string())
}

fn prepare_execution(
    file: &File,
    options: &IsotopeOptions,
    env: BTreeMap<OsString, OsString>,
) -> Result<IsotopePreparedExecution, String> {
    let fd = file.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags == -1 {
            return Err(format!(
                "failed to inspect file descriptor flags: {}",
                io::Error::last_os_error()
            ));
        }
        if libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
            return Err(format!(
                "failed to clear close-on-exec flag: {}",
                io::Error::last_os_error()
            ));
        }
    }

    let exec_path = options
        .target
        .to_str()
        .ok_or_else(|| "target path must be valid UTF-8".to_string())?
        .to_string();
    let mut argv = Vec::with_capacity(options.args.len() + 1);
    argv.push(OsString::from(&exec_path));
    for arg in &options.args {
        argv.push(arg.clone());
    }

    Ok(IsotopePreparedExecution {
        exec_fd: fd,
        exec_path,
        argv,
        env,
    })
}

fn exec_prepared(prepared: IsotopePreparedExecution) -> Result<(), String> {
    validate_exec_path_for_prepared_execution(prepared.exec_fd, &prepared.exec_path)?;
    let path = prepared.exec_path;
    let path_cstr = CString::new(path.clone())
        .map_err(|_| "validated execution path contains interior NUL".to_string())?;
    let argv = build_exec_cstrings(&prepared.argv)?;
    let env = build_exec_environment(&prepared.env)?;
    let argv_ptrs = argv
        .iter()
        .map(|value| value.as_ptr())
        .chain([std::ptr::null()])
        .collect::<Vec<_>>();
    let env_ptrs = env
        .iter()
        .map(|value| value.as_ptr())
        .chain([std::ptr::null()])
        .collect::<Vec<_>>();

    unsafe {
        libc::execve(path_cstr.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
    }

    Err(format!(
        "failed to execute {}: {}",
        path,
        io::Error::last_os_error()
    ))
}

#[cfg(target_os = "macos")]
fn validate_exec_path_for_prepared_execution(fd: i32, path: &str) -> Result<(), String> {
    verify_fd_matches_path(fd, path)
}

#[cfg(not(target_os = "macos"))]
fn validate_exec_path_for_prepared_execution(_fd: i32, _path: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "macos")]
#[cfg(test)]
fn path_for_open_fd(fd: i32) -> Result<String, String> {
    let mut buffer = vec![0_u8; libc::MAXPATHLEN as usize];
    let rc = unsafe { libc::fcntl(fd, libc::F_GETPATH, buffer.as_mut_ptr()) };
    if rc == -1 {
        return Err(format!(
            "failed to resolve executable path from validated descriptor: {}",
            io::Error::last_os_error()
        ));
    }
    let nul = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    String::from_utf8(buffer[..nul].to_vec())
        .map_err(|_| "validated descriptor path is not valid UTF-8".to_string())
}

#[cfg(target_os = "macos")]
fn verify_fd_matches_path(fd: i32, path: &str) -> Result<(), String> {
    let mut fd_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let mut path_stat = std::mem::MaybeUninit::<libc::stat>::uninit();

    let fstat_rc = unsafe { libc::fstat(fd, fd_stat.as_mut_ptr()) };
    if fstat_rc == -1 {
        return Err(format!(
            "failed to stat validated descriptor before exec: {}",
            io::Error::last_os_error()
        ));
    }

    let path_cstr = CString::new(path)
        .map_err(|_| "validated descriptor path contains interior NUL".to_string())?;
    let stat_rc = unsafe { libc::stat(path_cstr.as_ptr(), path_stat.as_mut_ptr()) };
    if stat_rc == -1 {
        return Err(format!(
            "failed to stat executable path before exec: {}",
            io::Error::last_os_error()
        ));
    }

    let fd_stat = unsafe { fd_stat.assume_init() };
    let path_stat = unsafe { path_stat.assume_init() };
    if fd_stat.st_dev != path_stat.st_dev || fd_stat.st_ino != path_stat.st_ino {
        return Err("validated executable changed before exec".to_string());
    }

    Ok(())
}

fn build_exec_cstrings(values: &[OsString]) -> Result<Vec<CString>, String> {
    values
        .iter()
        .map(|value| {
            CString::new(value.as_os_str().as_bytes())
                .map_err(|_| "argument contains interior NUL".to_string())
        })
        .collect()
}

fn build_exec_environment(env: &BTreeMap<OsString, OsString>) -> Result<Vec<CString>, String> {
    env.iter()
        .map(|(key, value)| {
            let mut entry = Vec::with_capacity(
                key.as_os_str().as_bytes().len() + 1 + value.as_os_str().as_bytes().len(),
            );
            entry.extend_from_slice(key.as_os_str().as_bytes());
            entry.push(b'=');
            entry.extend_from_slice(value.as_os_str().as_bytes());
            CString::new(entry).map_err(|_| {
                format!(
                    "environment entry contains interior NUL: {}",
                    key.to_string_lossy()
                )
            })
        })
        .collect()
}

fn disable_core_dumps() -> Result<(), String> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if rc == 0 {
        return Ok(());
    }
    Err(format!(
        "failed to disable core dumps: {}",
        io::Error::last_os_error()
    ))
}

pub(crate) fn zeroize_credentials(credentials: &mut BTreeMap<String, String>) {
    for value in credentials.values_mut() {
        unsafe {
            value.as_mut_vec().fill(0);
        }
        value.clear();
    }
    credentials.clear();
}

impl CredentialHelperSecretStore for KeychainCredentialStore {
    fn load_secret(&self, key: &str) -> Result<String, String> {
        keychain_read_secret(KEYCHAIN_SERVICE, key)
    }

    fn load_secret_if_present(&self, key: &str) -> Result<Option<String>, String> {
        keychain_read_secret_if_present(KEYCHAIN_SERVICE, key)
    }

    fn secret_exists(&self, key: &str) -> Result<bool, String> {
        keychain_secret_exists(KEYCHAIN_SERVICE, key)
    }

    fn store_secret(&self, key: &str, value: &str) -> Result<(), String> {
        keychain_write_secret(KEYCHAIN_SERVICE, key, value)
    }
}

impl CredentialStore for KeychainCredentialStore {
    fn store_secret(&self, key: &str, value: &str) -> Result<(), String> {
        keychain_write_secret(KEYCHAIN_SERVICE, key, value)
    }
}

#[cfg(target_os = "macos")]
fn keychain_read_secret(service: &str, account: &str) -> Result<String, String> {
    keychain_read_secret_if_present(service, account)?
        .ok_or_else(|| missing_keychain_item_error(account))
}

#[cfg(not(target_os = "macos"))]
fn keychain_read_secret(_service: &str, _account: &str) -> Result<String, String> {
    Err("isotope keychain integration is only available on macOS".to_string())
}

#[cfg(target_os = "macos")]
fn keychain_read_secret_if_present(service: &str, account: &str) -> Result<Option<String>, String> {
    unsafe extern "C" {
        fn isotope_copy_generic_password_json_with_status(
            service_cstr: *const c_char,
            account_cstr: *const c_char,
            error_cstr: *mut *mut c_char,
            status_out: *mut c_int,
        ) -> *mut c_char;
    }

    let service_cstr =
        CString::new(service).map_err(|_| "invalid keychain service name".to_string())?;
    let account_cstr =
        CString::new(account).map_err(|_| "invalid keychain account name".to_string())?;
    let mut error = std::ptr::null_mut();
    let mut status = 0;
    let value = unsafe {
        isotope_copy_generic_password_json_with_status(
            service_cstr.as_ptr(),
            account_cstr.as_ptr(),
            &mut error,
            &mut status,
        )
    };
    if value.is_null() {
        if status == ERR_SEC_ITEM_NOT_FOUND {
            unsafe {
                let _ = take_bridge_string(error);
            }
            return Ok(None);
        }
        let message = unsafe { take_bridge_string(error) }
            .unwrap_or_else(|| "keychain lookup failed".to_string());
        return Err(format!("failed to load isotope key {account}: {message}"));
    }

    unsafe { take_bridge_string(value) }
        .map(Some)
        .ok_or_else(|| "keychain returned invalid UTF-8".to_string())
}

#[cfg(not(target_os = "macos"))]
fn keychain_read_secret_if_present(
    _service: &str,
    _account: &str,
) -> Result<Option<String>, String> {
    Err("isotope keychain integration is only available on macOS".to_string())
}

/// Crate-internal accessors so the audit module can store/read its optional
/// HMAC signing key in the same Keychain backend used for isotope secrets.
pub(crate) fn keychain_read_audit_secret(
    service: &str,
    account: &str,
) -> Result<Option<String>, String> {
    keychain_read_secret_if_present(service, account)
}

pub(crate) fn keychain_write_audit_secret(
    service: &str,
    account: &str,
    value: &str,
) -> Result<(), String> {
    keychain_write_secret(service, account, value)
}

#[cfg(target_os = "macos")]
fn keychain_secret_exists(service: &str, account: &str) -> Result<bool, String> {
    unsafe extern "C" {
        fn isotope_generic_password_exists(
            service_cstr: *const c_char,
            account_cstr: *const c_char,
            error_cstr: *mut *mut c_char,
            status_out: *mut c_int,
        ) -> bool;
    }

    let service_cstr =
        CString::new(service).map_err(|_| "invalid keychain service name".to_string())?;
    let account_cstr =
        CString::new(account).map_err(|_| "invalid keychain account name".to_string())?;
    let mut error = std::ptr::null_mut();
    let mut status = 0;
    if unsafe {
        isotope_generic_password_exists(
            service_cstr.as_ptr(),
            account_cstr.as_ptr(),
            &mut error,
            &mut status,
        )
    } {
        return Ok(true);
    }
    if status == ERR_SEC_ITEM_NOT_FOUND {
        unsafe {
            let _ = take_bridge_string(error);
        }
        return Ok(false);
    }

    let message = unsafe { take_bridge_string(error) }
        .unwrap_or_else(|| "keychain lookup failed".to_string());
    Err(format!("failed to load isotope key {account}: {message}"))
}

#[cfg(not(target_os = "macos"))]
fn keychain_secret_exists(_service: &str, _account: &str) -> Result<bool, String> {
    Err("isotope keychain integration is only available on macOS".to_string())
}

#[cfg(target_os = "macos")]
fn missing_keychain_item_error(account: &str) -> String {
    format!(
        "failed to load isotope key {account}: The specified item could not be found in the keychain."
    )
}

#[cfg(target_os = "macos")]
fn keychain_write_secret(service: &str, account: &str, value: &str) -> Result<(), String> {
    unsafe extern "C" {
        fn isotope_store_generic_password_json(
            service_cstr: *const c_char,
            account_cstr: *const c_char,
            value_cstr: *const c_char,
            error_cstr: *mut *mut c_char,
        ) -> bool;
    }

    let service_cstr =
        CString::new(service).map_err(|_| "invalid keychain service name".to_string())?;
    let account_cstr =
        CString::new(account).map_err(|_| "invalid keychain account name".to_string())?;
    let value_cstr =
        CString::new(value).map_err(|_| "invalid keychain secret value".to_string())?;
    let mut error = std::ptr::null_mut();
    if unsafe {
        isotope_store_generic_password_json(
            service_cstr.as_ptr(),
            account_cstr.as_ptr(),
            value_cstr.as_ptr(),
            &mut error,
        )
    } {
        return Ok(());
    }

    let message =
        unsafe { take_bridge_string(error) }.unwrap_or_else(|| "keychain write failed".to_string());
    Err(format!("failed to store isotope key {account}: {message}"))
}

#[cfg(not(target_os = "macos"))]
fn keychain_write_secret(_service: &str, _account: &str, _value: &str) -> Result<(), String> {
    Err("isotope keychain integration is only available on macOS".to_string())
}

#[cfg(target_os = "macos")]
fn post_distributed_notification(name: &str) -> Result<(), String> {
    unsafe extern "C" {
        fn isotope_post_distributed_notification(
            name_cstr: *const c_char,
            error_cstr: *mut *mut c_char,
        ) -> bool;
    }

    let name_cstr =
        CString::new(name).map_err(|_| "invalid distributed notification name".to_string())?;
    let mut error = std::ptr::null_mut();
    if unsafe { isotope_post_distributed_notification(name_cstr.as_ptr(), &mut error) } {
        return Ok(());
    }
    Err(unsafe { take_bridge_string(error) }
        .unwrap_or_else(|| "failed to post isotope approval notification".to_string()))
}

#[cfg(target_os = "macos")]
fn post_distributed_notification_with_object(name: &str, object: &str) -> Result<(), String> {
    unsafe extern "C" {
        fn isotope_post_distributed_notification_with_object(
            name_cstr: *const c_char,
            object_cstr: *const c_char,
            error_cstr: *mut *mut c_char,
        ) -> bool;
    }

    let name_cstr =
        CString::new(name).map_err(|_| "invalid distributed notification name".to_string())?;
    let object_cstr =
        CString::new(object).map_err(|_| "invalid distributed notification object".to_string())?;
    let mut error = std::ptr::null_mut();
    if unsafe {
        isotope_post_distributed_notification_with_object(
            name_cstr.as_ptr(),
            object_cstr.as_ptr(),
            &mut error,
        )
    } {
        return Ok(());
    }
    Err(unsafe { take_bridge_string(error) }
        .unwrap_or_else(|| "failed to post isotope approval notification".to_string()))
}

#[cfg(not(target_os = "macos"))]
fn post_distributed_notification(_name: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn post_distributed_notification_with_object(_name: &str, _object: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "macos")]
unsafe fn take_bridge_string(value: *mut c_char) -> Option<String> {
    if value.is_null() {
        return None;
    }

    unsafe extern "C" {
        fn isotope_free_c_string(value: *mut c_char);
    }

    let bytes = unsafe { std::ffi::CStr::from_ptr(value) }
        .to_str()
        .ok()
        .map(str::to_owned);
    unsafe { isotope_free_c_string(value) };
    bytes
}

pub fn print_isotope_usage(program_name: &str) {
    println!(
        "\
Usage: {program_name} [--replace-existing-env] [--allow-missing-keys] +KEY [+KEY...] /absolute/path/to/executable-or-script [args...]

Asks Automic Vault to approve injecting the named keys into the target process.
--allow-missing-keys skips absent keychain items without a warning."
    );
}

pub fn print_save_usage(program_name: &str) {
    println!(
        "\
Usage: {program_name} KEY

Stores a trimmed secret in the Automic Vault keychain. Feed the secret on stdin,
or run from an interactive terminal to be prompted without echo. Empty trimmed
keys or values are rejected."
    );
}

pub fn print_credential_helper_usage(program_name: &str) {
    let helpers = credential_helper_names();
    let protocol_lines = if helpers.is_empty() {
        "  none".to_string()
    } else {
        helpers
            .into_iter()
            .map(|helper| format!("  {helper}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    println!(
        "\
Usage: {program_name} <protocol>

Runs a credential helper protocol adapter.

Protocols:
{protocol_lines}"
    );
}

fn credential_helper_names() -> Vec<&'static str> {
    let mut names = isotope_integrations::INTEGRATIONS
        .iter()
        .filter_map(|integration| integration.credential_helper_name)
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStringExt;
    use std::sync::Mutex;

    #[derive(Default)]
    struct StubCredentialStore {
        secrets: BTreeMap<String, Result<String, String>>,
        saved: Mutex<Vec<(String, String)>>,
    }

    impl CredentialHelperSecretStore for StubCredentialStore {
        fn load_secret(&self, key: &str) -> Result<String, String> {
            self.secrets
                .get(key)
                .cloned()
                .unwrap_or_else(|| Err("missing stub credential".to_string()))
        }

        fn load_secret_if_present(&self, key: &str) -> Result<Option<String>, String> {
            match self.secrets.get(key).cloned() {
                Some(Ok(value)) => Ok(Some(value)),
                Some(Err(err)) => Err(err),
                None => Ok(None),
            }
        }

        fn secret_exists(&self, key: &str) -> Result<bool, String> {
            match self.secrets.get(key) {
                Some(Ok(_)) => Ok(true),
                Some(Err(err)) => Err(err.clone()),
                None => Ok(false),
            }
        }
    }

    impl CredentialStore for StubCredentialStore {
        fn store_secret(&self, key: &str, value: &str) -> Result<(), String> {
            self.saved
                .lock()
                .unwrap()
                .push((key.to_string(), value.to_string()));
            Ok(())
        }
    }

    struct ReadOnlyCredentialStore;

    impl CredentialHelperSecretStore for ReadOnlyCredentialStore {
        fn load_secret(&self, key: &str) -> Result<String, String> {
            Ok(format!("secret:{key}"))
        }
    }

    struct FdGuard {
        fd: i32,
    }

    impl FdGuard {
        fn new(fd: i32) -> Self {
            Self { fd }
        }

        fn raw(&self) -> i32 {
            self.fd
        }

        fn close(&mut self) {
            if self.fd >= 0 {
                unsafe {
                    libc::close(self.fd);
                }
                self.fd = -1;
            }
        }
    }

    impl Drop for FdGuard {
        fn drop(&mut self) {
            self.close();
        }
    }

    struct StdinRestoreGuard {
        stdin_fd: i32,
        saved_stdin: i32,
    }

    impl Drop for StdinRestoreGuard {
        fn drop(&mut self) {
            if self.saved_stdin >= 0 {
                unsafe {
                    libc::dup2(self.saved_stdin, self.stdin_fd);
                    libc::close(self.saved_stdin);
                }
                self.saved_stdin = -1;
            }
        }
    }

    fn with_fake_stdin<R>(input: &[u8], f: impl FnOnce() -> R) -> R {
        let mut pipe_fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        let mut read_fd = FdGuard::new(pipe_fds[0]);
        let mut write_fd = FdGuard::new(pipe_fds[1]);
        let stdin_fd = io::stdin().as_raw_fd();
        let saved_stdin = unsafe { libc::dup(stdin_fd) };
        assert!(saved_stdin >= 0);
        let restore_stdin = StdinRestoreGuard {
            stdin_fd,
            saved_stdin,
        };

        let write_result =
            unsafe { libc::write(write_fd.raw(), input.as_ptr().cast(), input.len()) };
        assert_eq!(write_result, input.len() as isize);
        write_fd.close();
        assert_eq!(unsafe { libc::dup2(read_fd.raw(), stdin_fd) }, stdin_fd);
        read_fd.close();

        let result = f();

        drop(restore_stdin);
        result
    }

    fn with_fake_tty_stdin<R>(input: &[u8], f: impl FnOnce() -> R) -> R {
        let mut master_fd = -1;
        let mut slave_fd = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master_fd,
                    &mut slave_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let mut master = FdGuard::new(master_fd);
        let mut slave = FdGuard::new(slave_fd);
        let stdin_fd = io::stdin().as_raw_fd();
        let saved_stdin = unsafe { libc::dup(stdin_fd) };
        assert!(saved_stdin >= 0);
        let restore_stdin = StdinRestoreGuard {
            stdin_fd,
            saved_stdin,
        };

        assert_eq!(unsafe { libc::dup2(slave.raw(), stdin_fd) }, stdin_fd);
        slave.close();
        let writer_fd = unsafe { libc::dup(master.raw()) };
        assert!(writer_fd >= 0);
        let input = input.to_vec();
        let writer = std::thread::spawn(move || {
            let write_result =
                unsafe { libc::write(writer_fd, input.as_ptr().cast(), input.len()) };
            assert_eq!(write_result, input.len() as isize);
            unsafe { libc::close(writer_fd) };
        });

        let result = f();

        writer.join().unwrap();
        drop(restore_stdin);
        master.close();
        result
    }

    #[test]
    fn isotopes_parse_options_accepts_explicit_keys() {
        let options = parse_isotope_options(
            "av inject",
            OsString::from("+APPLE_USERNAME"),
            vec![
                OsString::from("+APPLE_PASSWORD"),
                OsString::from("/bin/bash"),
                OsString::from("script.sh"),
            ]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(
            options.keys,
            vec!["APPLE_PASSWORD".to_string(), "APPLE_USERNAME".to_string()]
        );
        assert_eq!(options.target, PathBuf::from("/bin/bash"));
        assert_eq!(options.args, vec![OsString::from("script.sh")]);
    }

    #[test]
    fn isotopes_parse_options_rejects_import_and_migrate() {
        let err = parse_isotope_options(
            "av inject",
            OsString::from("--import"),
            vec![OsString::from("/bin/bash")].into_iter(),
        )
        .unwrap_err();
        assert!(err.contains("no longer supported"));

        let err = parse_isotope_options(
            "av inject",
            OsString::from("--migrate"),
            vec![OsString::from("/bin/bash")].into_iter(),
        )
        .unwrap_err();
        assert!(err.contains("no longer supported"));
    }

    #[test]
    fn isotopes_parse_options_requires_keys_before_target() {
        let err = parse_isotope_options(
            "av inject",
            OsString::from("/bin/bash"),
            Vec::<OsString>::new().into_iter(),
        )
        .unwrap_err();
        assert!(err.contains("at least one +KEY"));
    }

    #[test]
    fn isotopes_validate_key_name_rejects_invalid_environment_names() {
        assert!(validate_key_name("TOKEN").is_ok());
        assert!(validate_key_name("_TOKEN_1").is_ok());
        assert!(validate_key_name("1TOKEN").is_err());
        assert!(validate_key_name("TOKEN-NAME").is_err());
    }

    #[test]
    fn isotopes_parse_options_accepts_replace_existing_env_flag() {
        let options = parse_isotope_options(
            "av inject",
            OsString::from("--replace-existing-env"),
            vec![OsString::from("+TOKEN"), OsString::from("/bin/bash")].into_iter(),
        )
        .unwrap();
        assert!(options.replace_existing_env);
    }

    #[test]
    fn isotopes_parse_options_accepts_allow_missing_keys_flag() {
        let options = parse_isotope_options(
            "av inject",
            OsString::from("--allow-missing-keys"),
            vec![OsString::from("+TOKEN"), OsString::from("/bin/bash")].into_iter(),
        )
        .unwrap();
        assert!(options.allow_missing_keys);
    }

    #[test]
    fn isotopes_parse_options_rejects_removed_allow_existing_env_flag() {
        let err = parse_isotope_options(
            "av inject",
            OsString::from("--allow-existing-env"),
            vec![OsString::from("+TOKEN"), OsString::from("/bin/bash")].into_iter(),
        )
        .unwrap_err();
        assert!(err.contains("--replace-existing-env"));
    }

    #[test]
    fn isotopes_parse_options_rejects_removed_force_flag() {
        let err = parse_isotope_options(
            "av inject",
            OsString::from("--force"),
            vec![OsString::from("+TOKEN"), OsString::from("/bin/bash")].into_iter(),
        )
        .unwrap_err();
        assert!(err.contains("--replace-existing-env"));
    }

    #[test]
    fn isotopes_parse_options_rejects_duplicate_keys_and_missing_target() {
        let err = parse_isotope_options(
            "av inject",
            OsString::from("+TOKEN"),
            vec![OsString::from("+TOKEN"), OsString::from("/bin/bash")].into_iter(),
        )
        .unwrap_err();
        assert!(err.contains("duplicate key requested"));

        let err = parse_isotope_options(
            "av inject",
            OsString::from("+TOKEN"),
            Vec::<OsString>::new().into_iter(),
        )
        .unwrap_err();
        assert!(err.contains("missing target binary"));
    }

    #[test]
    fn isotopes_parse_save_options_accepts_key_only() {
        let options = parse_save_options("av save", vec![OsString::from("FOO")].into_iter())
            .unwrap()
            .unwrap();
        assert_eq!(options.key, "FOO");
    }

    #[test]
    fn isotopes_parse_save_options_trims_key() {
        let options = parse_save_options("av save", vec![OsString::from(" FOO ")].into_iter())
            .unwrap()
            .unwrap();
        assert_eq!(options.key, "FOO");
    }

    #[test]
    fn isotopes_parse_save_options_rejects_invalid_assignment() {
        let err =
            parse_save_options("av save", vec![OsString::from("FOO=bar")].into_iter()).unwrap_err();
        assert!(err.contains("KEY only"));

        let err =
            parse_save_options("av save", vec![OsString::from("1FOO")].into_iter()).unwrap_err();
        assert!(err.contains("invalid isotope key name"));

        let err = parse_save_options("av save", vec![OsString::from(" ")].into_iter()).unwrap_err();
        assert!(err.contains("empty isotope key name"));

        let err = parse_save_options(
            "av save",
            vec![OsString::from("FOO"), OsString::from("bar")].into_iter(),
        )
        .unwrap_err();
        assert!(err.contains("KEY only"));
    }

    #[test]
    fn isotopes_parse_save_options_rejects_removed_allow_path() {
        let err = parse_save_options(
            "av save",
            vec![
                OsString::from("--allow"),
                OsString::from("/usr/bin/env"),
                OsString::from("FOO"),
            ]
            .into_iter(),
        )
        .unwrap_err();
        assert!(err.contains("removed"));

        let err = parse_save_options(
            "av save",
            vec![
                OsString::from("--allow-path"),
                OsString::from("/usr/bin/env"),
                OsString::from("FOO"),
            ]
            .into_iter(),
        )
        .unwrap_err();
        assert!(err.contains("removed"));
    }

    #[test]
    fn isotopes_dispatch_cli_paths_cover_help_version_and_save_stdin() {
        let save_store = StubCredentialStore::default();

        assert!(
            dispatch_isotope(
                "av inject",
                vec![OsString::from("--help")].into_iter(),
                &save_store,
            )
            .is_ok()
        );
        assert!(
            dispatch_isotope(
                "av inject",
                vec![OsString::from("--version")].into_iter(),
                &save_store,
            )
            .is_ok()
        );
        assert_eq!(
            dispatch_isotope("av inject", Vec::<OsString>::new().into_iter(), &save_store)
                .unwrap_err(),
            "missing key and target binary"
        );

        assert!(
            dispatch_save(
                "av save",
                vec![OsString::from("--help")].into_iter(),
                &save_store,
            )
            .is_ok()
        );
        assert!(
            dispatch_save(
                "av save",
                vec![OsString::from("--version")].into_iter(),
                &save_store,
            )
            .is_ok()
        );

        let _guard = crate::global_test_env_lock().lock().unwrap();
        with_fake_stdin(b"  secret-value  \n", || {
            dispatch_save(
                "av save",
                vec![OsString::from("TOKEN")].into_iter(),
                &save_store,
            )
        })
        .unwrap();

        assert_eq!(
            save_store.saved.lock().unwrap().as_slice(),
            &[("TOKEN".to_string(), "secret-value".to_string())]
        );
    }

    #[test]
    fn isotopes_credential_helper_dispatch_accepts_aws_protocol() {
        let store = StubCredentialStore::default();
        assert!(credential_helper_names().contains(&"aws"));

        assert!(
            dispatch_credential_helper(
                "av credential-helper",
                vec![OsString::from("--help")].into_iter(),
                &store,
            )
            .is_ok()
        );
        assert_eq!(
            dispatch_credential_helper(
                "av credential-helper",
                Vec::<OsString>::new().into_iter(),
                &store,
            )
            .unwrap_err(),
            "missing credential helper protocol"
        );
        assert_eq!(
            dispatch_credential_helper(
                "av credential-helper",
                vec![OsString::from("git")].into_iter(),
                &store,
            )
            .unwrap_err(),
            "unknown credential helper protocol 'git'"
        );
        assert!(
            dispatch_credential_helper(
                "av credential-helper",
                vec![OsString::from("aws"), OsString::from("--help")].into_iter(),
                &store,
            )
            .is_ok()
        );
    }

    #[test]
    fn isotopes_dispatch_cli_runs_injection_path_until_exec_failure() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let tool = temp.path().join("tool");
        fs::write(&tool, b"plain text\n").unwrap();
        let mut permissions = fs::metadata(&tool).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&tool, permissions).unwrap();
        unsafe { env::set_var("TOKEN", "already-set") };

        let err = dispatch_isotope(
            "av inject",
            vec![
                OsString::from("+TOKEN"),
                tool.as_os_str().to_os_string(),
                OsString::from("--flag"),
            ]
            .into_iter(),
            &StubCredentialStore::default(),
        )
        .unwrap_err();

        unsafe { env::remove_var("TOKEN") };
        assert!(err.contains("failed to execute"));
    }

    #[test]
    fn isotopes_read_save_secret_rejects_empty_piped_value() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let err = with_fake_stdin(b" \n\t", read_save_secret).unwrap_err();
        assert_eq!(err, "empty isotope secret value");
    }

    #[test]
    fn isotopes_read_save_secret_accepts_interactive_tty_input() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let value = with_fake_tty_stdin(b"  secret-value  \n", read_save_secret).unwrap();
        assert_eq!(value, "secret-value");
    }

    #[test]
    fn isotopes_parse_helpers_reject_non_utf8_inputs() {
        let err = parse_isotope_options(
            "av inject",
            OsString::from_vec(vec![0xff]),
            Vec::<OsString>::new().into_iter(),
        )
        .unwrap_err();
        assert_eq!(err, "isotope arguments must be valid UTF-8");

        let err = parse_save_key("av save", &[OsString::from_vec(vec![0xff])]).unwrap_err();
        assert_eq!(err, "secret key must be valid UTF-8");
    }

    #[test]
    fn credential_helper_secret_store_defaults_are_read_only() {
        let store = ReadOnlyCredentialStore;

        assert_eq!(
            store.load_secret_if_present("TOKEN").unwrap(),
            Some("secret:TOKEN".to_string())
        );
        assert!(store.secret_exists("TOKEN").unwrap());
        assert!(
            store
                .store_secret("TOKEN", "value")
                .unwrap_err()
                .contains("read-only")
        );
    }

    #[test]
    fn isotopes_read_secret_line_no_echo_rejects_non_tty_stdin() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let err = with_fake_stdin(b"secret\n", || {
            let mut value = String::new();
            read_secret_line_no_echo(&mut io::stdin(), &mut value)
        })
        .unwrap_err();
        assert!(err.contains("failed to read terminal settings"));
    }

    #[test]
    fn isotopes_check_environment_conflicts_warns_on_existing_env() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        unsafe { env::set_var("APPLE_USERNAME", "existing") };
        let existing = check_environment_conflicts(&["APPLE_USERNAME".to_string()]);
        assert!(existing.contains("APPLE_USERNAME"));
        unsafe { env::remove_var("APPLE_USERNAME") };
    }

    #[test]
    fn isotopes_skip_loading_credentials_for_existing_env() {
        let existing_env_keys = BTreeSet::from(["APPLE_USERNAME".to_string()]);
        let keys = vec!["APPLE_PASSWORD".to_string(), "APPLE_USERNAME".to_string()];
        let credential_keys = credential_keys_to_load(&keys, &existing_env_keys, false);
        assert_eq!(credential_keys, vec!["APPLE_PASSWORD".to_string()]);
    }

    #[test]
    fn isotopes_skip_approval_when_existing_env_covers_requested_keys() {
        let existing_env_keys = BTreeSet::from(["AWS_ACCESS_KEY_ID".to_string()]);
        let keys = vec!["AWS_ACCESS_KEY_ID".to_string()];
        let credential_keys = credential_keys_to_load(&keys, &existing_env_keys, false);
        assert!(credential_keys.is_empty());
    }

    #[test]
    fn isotopes_replace_existing_env_loads_all_credentials() {
        let existing_env_keys = BTreeSet::from(["APPLE_USERNAME".to_string()]);
        let keys = vec!["APPLE_PASSWORD".to_string(), "APPLE_USERNAME".to_string()];
        let credential_keys = credential_keys_to_load(&keys, &existing_env_keys, true);
        assert_eq!(credential_keys, keys);
    }

    #[test]
    fn isotopes_approval_files_and_decisions_cover_success_and_errors() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let previous_home = env::var_os("HOME");
        unsafe { env::set_var("HOME", temp.path()) };

        let root = user_approval_root().unwrap();
        assert!(root.ends_with("Library/Application Support/Automic Vault/isotope"));
        let pending = pending_approval_path().unwrap();
        let decision = decision_path("request-1").unwrap();
        write_json(
            &pending,
            &IsotopeApprovalRequestSnapshot {
                id: "request-1".to_string(),
                keys: vec!["TOKEN".to_string()],
                executable_path: "/bin/sh".to_string(),
                executable_root_controlled: true,
                script_path: None,
                script_sha256: None,
                requested_script_path: None,
                script_root_controlled: None,
                requested_executable_path: "/bin/sh".to_string(),
                argv: vec!["/bin/sh".to_string()],
                cwd: "/tmp".to_string(),
                parent_process: ParentProcessSnapshot {
                    pid: 1,
                    executable_path: Some("/sbin/launchd".to_string()),
                    display_name: Some("launchd".to_string()),
                },
                can_always_allow: true,
            },
        )
        .unwrap();
        assert!(pending.is_file());
        write_json(
            &decision,
            &IsotopeApprovalDecision {
                id: "request-1".to_string(),
                approved: true,
                always_allow: false,
                reason: None,
            },
        )
        .unwrap();
        wait_for_isotope_decision_at("request-1", &pending, &decision).unwrap();
        assert!(!pending.exists());
        assert!(!decision.exists());

        let denied = decision_path("request-2").unwrap();
        write_json(
            &denied,
            &IsotopeApprovalDecision {
                id: "request-2".to_string(),
                approved: false,
                always_allow: false,
                reason: Some("no".to_string()),
            },
        )
        .unwrap();
        assert_eq!(
            wait_for_isotope_decision_at("request-2", &pending, &denied).unwrap_err(),
            "no"
        );

        let mismatched = decision_path("request-3").unwrap();
        write_json(
            &mismatched,
            &IsotopeApprovalDecision {
                id: "other".to_string(),
                approved: true,
                always_allow: false,
                reason: None,
            },
        )
        .unwrap();
        assert!(
            wait_for_isotope_decision_at("request-3", &pending, &mismatched)
                .unwrap_err()
                .contains("id mismatch")
        );

        match previous_home {
            Some(value) => unsafe { env::set_var("HOME", value) },
            None => unsafe { env::remove_var("HOME") },
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn keychain_and_notification_bridges_reject_invalid_c_strings_before_ffi() {
        assert_eq!(
            keychain_read_secret_if_present("bad\0service", "TOKEN").unwrap_err(),
            "invalid keychain service name"
        );
        assert_eq!(
            keychain_read_secret("service", "bad\0account").unwrap_err(),
            "invalid keychain account name"
        );
        assert_eq!(
            keychain_secret_exists("bad\0service", "TOKEN").unwrap_err(),
            "invalid keychain service name"
        );
        assert_eq!(
            keychain_secret_exists("service", "bad\0account").unwrap_err(),
            "invalid keychain account name"
        );
        assert_eq!(
            keychain_write_secret("bad\0service", "TOKEN", "value").unwrap_err(),
            "invalid keychain service name"
        );
        assert_eq!(
            keychain_write_secret("service", "bad\0account", "value").unwrap_err(),
            "invalid keychain account name"
        );
        assert_eq!(
            keychain_write_secret("service", "TOKEN", "bad\0value").unwrap_err(),
            "invalid keychain secret value"
        );
        assert_eq!(
            post_distributed_notification("bad\0name").unwrap_err(),
            "invalid distributed notification name"
        );
        assert_eq!(
            post_distributed_notification_with_object("bad\0name", "object").unwrap_err(),
            "invalid distributed notification name"
        );
        assert_eq!(
            post_distributed_notification_with_object("name", "bad\0object").unwrap_err(),
            "invalid distributed notification object"
        );
        unsafe {
            assert!(take_bridge_string(std::ptr::null_mut()).is_none());
        }
    }

    #[test]
    fn isotopes_exec_environment_and_zeroize_helpers_cover_errors() {
        assert!(build_exec_cstrings(&[OsString::from("ok")]).is_ok());
        assert!(
            build_exec_cstrings(&[OsString::from("bad\0arg")])
                .unwrap_err()
                .contains("interior NUL")
        );

        let mut env_map = BTreeMap::new();
        env_map.insert(OsString::from("GOOD"), OsString::from("value"));
        let built = build_exec_environment(&env_map).unwrap();
        assert_eq!(built[0].as_bytes(), b"GOOD=value");

        env_map.insert(
            OsString::from("RAW"),
            OsString::from_vec(b"/tmp/v\xffrp/script".to_vec()),
        );
        let built = build_exec_environment(&env_map).unwrap();
        assert!(
            built
                .iter()
                .any(|entry| entry.as_bytes() == b"RAW=/tmp/v\xffrp/script")
        );

        env_map.insert(OsString::from("BAD"), OsString::from("bad\0value"));
        assert!(
            build_exec_environment(&env_map)
                .unwrap_err()
                .contains("environment entry")
        );

        let mut credentials = BTreeMap::new();
        credentials.insert("TOKEN".to_string(), "secret".to_string());
        zeroize_credentials(&mut credentials);
        assert!(credentials.is_empty());
        assert!(disable_core_dumps().is_ok());
        let snapshot = parent_process_snapshot();
        assert!(snapshot.pid > 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn isotopes_fd_path_validation_covers_success_and_error_edges() {
        use std::os::fd::AsRawFd;

        let temp = tempfile::tempdir().unwrap();
        let tool = temp.path().join("tool");
        let other = temp.path().join("other-tool");
        fs::write(&tool, b"tool").unwrap();
        fs::write(&other, b"other").unwrap();
        let file = File::open(&tool).unwrap();
        let fd = file.as_raw_fd();
        let open_path = path_for_open_fd(fd).unwrap();
        let canonical_tool = fs::canonicalize(&tool).unwrap();

        assert_eq!(Path::new(&open_path), canonical_tool);
        verify_fd_matches_path(fd, &open_path).unwrap();
        assert!(
            path_for_open_fd(-1)
                .unwrap_err()
                .contains("failed to resolve executable path")
        );
        assert!(
            verify_fd_matches_path(-1, &open_path)
                .unwrap_err()
                .contains("failed to stat validated descriptor")
        );
        assert_eq!(
            verify_fd_matches_path(fd, "bad\0path").unwrap_err(),
            "validated descriptor path contains interior NUL"
        );
        assert!(
            verify_fd_matches_path(fd, temp.path().join("missing").to_str().unwrap())
                .unwrap_err()
                .contains("failed to stat executable path")
        );
        assert_eq!(
            verify_fd_matches_path(fd, other.to_str().unwrap()).unwrap_err(),
            "validated executable changed before exec"
        );
    }

    #[test]
    fn isotopes_exec_helpers_cover_prepare_and_exec_failures() {
        let temp = tempfile::tempdir().unwrap();
        let invalid_target = PathBuf::from(OsString::from_vec(b"/tmp/isotope-\xff".to_vec()));
        let file = File::open("/bin/sh").unwrap();
        let err = prepare_execution(
            &file,
            &IsotopeOptions {
                replace_existing_env: false,
                allow_missing_keys: false,
                keys: Vec::new(),
                target: invalid_target,
                args: Vec::new(),
            },
            BTreeMap::new(),
        )
        .unwrap_err();
        assert!(err.contains("target path must be valid UTF-8"));

        let script = temp.path().join("not-executable");
        fs::write(&script, b"plain text\n").unwrap();
        let file = File::open(&script).unwrap();
        let err = exec_prepared(IsotopePreparedExecution {
            exec_fd: file.as_raw_fd(),
            exec_path: script.to_string_lossy().into_owned(),
            argv: vec![OsString::from(script.to_string_lossy().as_ref())],
            env: BTreeMap::new(),
        })
        .unwrap_err();
        assert!(err.contains("failed to execute"));
    }

    #[test]
    fn isotopes_save_and_load_credentials_cover_store_paths() {
        let mut store = StubCredentialStore::default();
        store
            .secrets
            .insert("TOKEN".to_string(), Ok("secret".to_string()));
        store
            .secrets
            .insert("BROKEN".to_string(), Err("missing".to_string()));

        let options = SaveSecretOptions {
            key: "TOKEN".to_string(),
        };
        run_save(&options, "stored", &store).unwrap();
        assert_eq!(
            load_credentials(&store, &["TOKEN".to_string()])
                .unwrap()
                .get("TOKEN")
                .cloned(),
            Some("secret".to_string())
        );
        assert_eq!(
            load_credentials(&store, &["BROKEN".to_string()]).unwrap_err(),
            "missing"
        );
        assert_eq!(
            parse_save_key("av save", &[OsString::from(" TOKEN ")]).unwrap(),
            "TOKEN"
        );
        assert!(
            parse_save_key("av save", &[])
                .unwrap_err()
                .contains("missing")
        );
    }

    #[test]
    fn isotopes_load_credentials_uses_explicit_key_names() {
        let mut store = StubCredentialStore::default();
        store
            .secrets
            .insert("TOKEN".to_string(), Ok("secret".to_string()));
        let loaded = load_credentials(&store, &["TOKEN".to_string()]).unwrap();
        assert_eq!(loaded["TOKEN"], "secret");
    }

    #[test]
    fn isotopes_load_credentials_can_skip_missing_optional_keys() {
        let mut store = StubCredentialStore::default();
        store
            .secrets
            .insert("TOKEN".to_string(), Ok("secret".to_string()));
        let loaded = load_credentials_with_policy(
            &store,
            &["MISSING".to_string(), "TOKEN".to_string()],
            MissingCredentialPolicy::SkipMissing,
        )
        .unwrap();

        assert_eq!(
            loaded.keys().cloned().collect::<Vec<_>>(),
            vec!["TOKEN".to_string()]
        );
        assert_eq!(loaded["TOKEN"], "secret");
    }

    #[test]
    fn isotopes_always_allow_accepts_keys_split_across_entries() {
        let store = IsotopeAlwaysAllowStore {
            entries: vec![
                IsotopeAlwaysAllowEntry {
                    executable_path: "/bin/tool".to_string(),
                    script_path: None,
                    script_sha256: None,
                    keys: vec!["A".to_string()],
                },
                IsotopeAlwaysAllowEntry {
                    executable_path: "/bin/tool".to_string(),
                    script_path: None,
                    script_sha256: None,
                    keys: vec!["B".to_string()],
                },
            ],
        };
        let scope = IsotopeAlwaysAllowScope {
            executable_path: "/bin/tool".to_string(),
            script_path: None,
            script_sha256: None,
        };
        let other_scope = IsotopeAlwaysAllowScope {
            executable_path: "/bin/other".to_string(),
            script_path: None,
            script_sha256: None,
        };
        assert!(store.always_allows_keys(&scope, &["A".to_string(), "B".to_string()]));
        assert!(!store.always_allows_keys(&scope, &["A".to_string(), "C".to_string()]));
        assert!(!store.always_allows_keys(&other_scope, &["A".to_string()]));
    }

    #[test]
    fn isotopes_always_allow_requires_matching_script_scope() {
        let store = IsotopeAlwaysAllowStore {
            entries: vec![IsotopeAlwaysAllowEntry {
                executable_path: "/opt/python/bin/python3.14".to_string(),
                script_path: Some("/opt/awscli/bin/aws".to_string()),
                script_sha256: None,
                keys: vec!["AWS_ACCESS_KEY_ID".to_string()],
            }],
        };
        let aws_scope = IsotopeAlwaysAllowScope {
            executable_path: "/opt/python/bin/python3.14".to_string(),
            script_path: Some("/opt/awscli/bin/aws".to_string()),
            script_sha256: None,
        };
        let other_script_scope = IsotopeAlwaysAllowScope {
            executable_path: "/opt/python/bin/python3.14".to_string(),
            script_path: Some("/opt/awscli/bin/other".to_string()),
            script_sha256: None,
        };
        let missing_script_scope = IsotopeAlwaysAllowScope {
            executable_path: "/opt/python/bin/python3.14".to_string(),
            script_path: None,
            script_sha256: None,
        };

        assert!(store.always_allows_keys(&aws_scope, &["AWS_ACCESS_KEY_ID".to_string()]));
        assert!(!store.always_allows_keys(&other_script_scope, &["AWS_ACCESS_KEY_ID".to_string()]));
        assert!(
            !store.always_allows_keys(&missing_script_scope, &["AWS_ACCESS_KEY_ID".to_string()])
        );
    }

    #[test]
    fn isotopes_always_allow_requires_matching_script_sha_when_present() {
        let old_sha = "a".repeat(64);
        let new_sha = "b".repeat(64);
        let store = IsotopeAlwaysAllowStore {
            entries: vec![IsotopeAlwaysAllowEntry {
                executable_path: "/bin/sh".to_string(),
                script_path: Some("/Users/example/tool.sh".to_string()),
                script_sha256: Some(old_sha.clone()),
                keys: vec!["TOKEN".to_string()],
            }],
        };
        let matching_scope = IsotopeAlwaysAllowScope {
            executable_path: "/bin/sh".to_string(),
            script_path: Some("/Users/example/tool.sh".to_string()),
            script_sha256: Some(old_sha),
        };
        let changed_scope = IsotopeAlwaysAllowScope {
            executable_path: "/bin/sh".to_string(),
            script_path: Some("/Users/example/tool.sh".to_string()),
            script_sha256: Some(new_sha),
        };
        let root_owned_scope = IsotopeAlwaysAllowScope {
            executable_path: "/bin/sh".to_string(),
            script_path: Some("/Users/example/tool.sh".to_string()),
            script_sha256: None,
        };

        assert!(store.always_allows_keys(&matching_scope, &["TOKEN".to_string()]));
        assert!(!store.always_allows_keys(&changed_scope, &["TOKEN".to_string()]));
        assert!(!store.always_allows_keys(&root_owned_scope, &["TOKEN".to_string()]));
    }

    #[test]
    fn isotopes_validate_target_file_metadata_rejects_non_root_or_writable_targets() {
        let err = validate_target_file_metadata(501, 0o755).unwrap_err();
        assert!(err.contains("owned by root"));

        let err = validate_target_file_metadata(0, 0o775).unwrap_err();
        assert!(err.contains("writable by group or others"));

        let err = validate_target_file_metadata(0, 0o644).unwrap_err();
        assert!(err.contains("executable"));
    }

    #[test]
    fn isotopes_always_allow_hashes_relative_non_root_interpreter_scripts() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }

        let _guard = crate::global_test_env_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let script = temp.path().join("script.sh");
        fs::write(&script, b"#!/bin/sh\n").unwrap();
        let previous_cwd = env::current_dir().unwrap();
        env::set_current_dir(temp.path()).unwrap();
        let result = interpreter_script_for_always_allow(
            Path::new("/bin/bash"),
            &[OsString::from("script.sh")],
        );
        env::set_current_dir(previous_cwd).unwrap();
        let detected = result.unwrap().unwrap();
        assert_eq!(detected.path, fs::canonicalize(&script).unwrap());
        assert_eq!(detected.sha256, Some(sha256_file(&script).unwrap()));
    }

    #[test]
    fn isotopes_always_allow_hashes_absolute_non_root_interpreter_scripts() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        let script = temp.path().join("script.sh");
        fs::write(&script, b"#!/bin/sh\necho hi\n").unwrap();

        let detected = interpreter_script_for_always_allow(
            Path::new("/bin/bash"),
            &[OsString::from(script.as_os_str())],
        )
        .unwrap()
        .unwrap();

        assert_eq!(detected.path, fs::canonicalize(&script).unwrap());
        assert_eq!(detected.sha256, Some(sha256_file(&script).unwrap()));
    }

    #[test]
    fn isotopes_always_allow_hashes_direct_shebang_scripts() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        let script = temp.path().join("script.sh");
        fs::write(&script, b"#!/bin/sh\necho hi\n").unwrap();
        let script = fs::canonicalize(&script).unwrap();
        let file = File::open(&script).unwrap();

        let scope = always_allow_scope(script.to_str().unwrap(), &script, &file, &[]).unwrap();

        assert_eq!(
            scope.executable_path,
            fs::canonicalize("/bin/sh")
                .unwrap()
                .to_string_lossy()
                .into_owned()
        );
        assert_eq!(scope.script_path.as_deref(), script.to_str());
        assert_eq!(scope.script_sha256, Some(sha256_file(&script).unwrap()));
        assert_eq!(
            script_path_for_display(&script, Some(&scope), &[]).unwrap(),
            script
        );
    }

    #[test]
    fn isotopes_always_allow_rejects_env_shebang_scripts() {
        let temp = tempfile::tempdir().unwrap();
        let script = temp.path().join("script.sh");
        fs::write(&script, b"#!/usr/bin/env bash\necho hi\n").unwrap();
        let script = fs::canonicalize(&script).unwrap();
        let file = File::open(&script).unwrap();

        let err = always_allow_scope(script.to_str().unwrap(), &script, &file, &[]).unwrap_err();

        assert!(err.contains("env shebang always-allow"));
    }

    #[test]
    fn isotopes_always_allow_rejects_inline_interpreter_commands() {
        let err = interpreter_script_for_always_allow(
            Path::new("/bin/bash"),
            &[OsString::from("-c"), OsString::from("echo hi")],
        )
        .unwrap_err();
        assert!(err.contains("root-owned script file"));
    }

    #[test]
    fn isotopes_detect_display_script_for_interpreter_approvals() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let previous_cwd = env::current_dir().unwrap();
        env::set_current_dir(temp.path()).unwrap();
        let script = temp.path().join("deploy.sh");
        fs::write(&script, b"#!/bin/sh\n").unwrap();

        let detected = interpreter_script_path_for_display(
            Path::new("/bin/bash"),
            &[OsString::from("deploy.sh")],
        )
        .unwrap();
        let expected = fs::canonicalize(&script).unwrap();
        let inline_command = interpreter_script_path_for_display(
            Path::new("/bin/bash"),
            &[OsString::from("-c"), OsString::from("echo hi")],
        );
        env::set_current_dir(previous_cwd).unwrap();

        assert_eq!(detected, expected);
        assert_eq!(inline_command, None);
    }

    #[test]
    fn isotopes_always_allow_rejects_env_launchers() {
        let err = interpreter_script_for_always_allow(
            Path::new("/usr/bin/env"),
            &[OsString::from("bash"), OsString::from("script.sh")],
        )
        .unwrap_err();
        assert!(err.contains("env always-allow"));
    }

    #[test]
    fn isotopes_detect_versioned_python_as_interpreter() {
        assert!(is_script_interpreter(Path::new(
            "/opt/awscli/bin/python3.14"
        )));
        assert!(is_script_interpreter(Path::new("/bin/python3")));
        assert!(!is_script_interpreter(Path::new("/bin/python-config")));
    }

    #[test]
    fn isotopes_interpreter_helpers_cover_option_and_path_branches() {
        assert!(interpreter_option_takes_value("-c"));
        assert!(interpreter_option_takes_value("-M"));
        assert!(!interpreter_option_takes_value("--"));

        let args = vec![
            OsString::from("-c"),
            OsString::from("print('hi')"),
            OsString::from("--"),
            OsString::from("script.py"),
        ];
        assert_eq!(
            interpreter_script_operand(&args),
            Some(Path::new("script.py"))
        );

        let args = vec![
            OsString::from("-m"),
            OsString::from("pkg"),
            OsString::from("tool.py"),
        ];
        assert_eq!(
            interpreter_script_operand(&args),
            Some(Path::new("tool.py"))
        );

        assert_eq!(
            interpreter_script_path_for_display(Path::new("/usr/bin/env"), &args),
            None
        );

        let _guard = crate::global_test_env_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let previous_cwd = env::current_dir().unwrap();
        env::set_current_dir(temp.path()).unwrap();
        let missing = resolve_script_operand(Path::new("missing.sh")).unwrap_err();
        env::set_current_dir(previous_cwd).unwrap();
        assert!(missing.contains("failed to resolve"));
    }

    #[test]
    fn isotopes_always_allow_scope_and_path_helpers_cover_expected_paths() {
        let executable = Path::new("/bin/sh");
        let file = File::open(executable).unwrap();
        let scope =
            always_allow_scope("/bin/sh", executable, &file, &[OsString::from("/bin/sh")]).unwrap();
        assert_eq!(scope.executable_path, "/bin/sh");
        assert_eq!(scope.script_path.as_deref(), Some("/bin/sh"));

        let display = path_to_display_string(Path::new("/etc/profile")).unwrap();
        assert_eq!(display, "/etc/profile");
        assert!(
            resolve_script_operand(Path::new("/etc/profile"))
                .unwrap()
                .ends_with("etc/profile")
        );

        let temp = tempfile::tempdir().unwrap();
        let store_path = temp.path().join("always-allow.json");
        fs::write(
            &store_path,
            serde_json::to_vec(&IsotopeAlwaysAllowStore {
                entries: vec![IsotopeAlwaysAllowEntry {
                    executable_path: "/bin/sh".to_string(),
                    script_path: Some("/bin/sh".to_string()),
                    script_sha256: None,
                    keys: vec!["TOKEN".to_string()],
                }],
            })
            .unwrap(),
        )
        .unwrap();
        assert!(always_allows_usage_at_path(&store_path, &scope, &["TOKEN".to_string()]).unwrap());
        assert!(!always_allows_usage_at_path(&store_path, &scope, &["OTHER".to_string()]).unwrap());
        assert_eq!(
            load_always_allow_store_at_path(&temp.path().join("missing.json")).unwrap(),
            IsotopeAlwaysAllowStore::default()
        );
    }

    #[test]
    fn isotopes_always_allow_global_wrappers_match_global_store_contents() {
        let scope = IsotopeAlwaysAllowScope {
            executable_path: "/bin/sh".to_string(),
            script_path: Some("/bin/sh".to_string()),
            script_sha256: None,
        };
        assert!(!always_allows_usage(&scope, &["TOKEN".to_string()]).unwrap());
        assert_eq!(
            load_always_allow_store().unwrap(),
            load_always_allow_store_at_path(Path::new(ALWAYS_ALLOW_PATH)).unwrap()
        );
    }

    #[test]
    fn isotopes_validation_helpers_cover_directory_and_non_file_targets() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("dir");
        fs::create_dir(&dir).unwrap();
        let dir_file = File::open(&dir).unwrap();
        let err = validate_regular_target(&dir, &dir_file).unwrap_err();
        assert!(err.contains("regular file"));

        assert!(validate_directory_mode(Path::new("/tmp"), 0o755).is_ok());
        let err = validate_directory_mode(Path::new("/tmp/open"), 0o777).unwrap_err();
        assert!(err.contains("must not be writable"));

        let err = validate_root_controlled_path(&temp.path().join("missing")).unwrap_err();
        assert!(err.contains("failed to open"));
    }

    #[test]
    fn isotopes_root_controlled_validation_accepts_system_shell_paths() {
        let file = File::open("/bin/sh").unwrap();
        assert!(validate_regular_target(Path::new("/bin/sh"), &file).is_ok());
        assert!(validate_target_root_installation(Path::new("/bin/sh"), &file).is_ok());
        assert!(validate_root_controlled_path(Path::new("/bin/sh")).is_ok());
        assert_eq!(
            interpreter_script_for_always_allow(
                Path::new("/bin/bash"),
                &[OsString::from("/bin/sh")]
            )
            .unwrap(),
            Some(IsotopeAlwaysAllowScript {
                path: PathBuf::from("/bin/sh"),
                interpreter_path: "/bin/bash".to_string(),
                sha256: None,
            })
        );
    }

    #[test]
    fn isotopes_resolve_script_operand_uses_current_directory_for_relative_paths() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let previous_cwd = env::current_dir().unwrap();
        env::set_current_dir(temp.path()).unwrap();
        let script = temp.path().join("tool.sh");
        fs::write(&script, b"#!/bin/sh\n").unwrap();

        let resolved = resolve_script_operand(Path::new("tool.sh")).unwrap();

        env::set_current_dir(previous_cwd).unwrap();
        assert_eq!(resolved, fs::canonicalize(&script).unwrap());
    }

    #[test]
    fn isotopes_request_and_bridge_helpers_reject_invalid_utf8_inputs() {
        let options = IsotopeOptions {
            replace_existing_env: false,
            allow_missing_keys: false,
            keys: vec!["TOKEN".to_string()],
            target: PathBuf::from("/bin/sh"),
            args: vec![OsString::from_vec(b"bad-\xff".to_vec())],
        };
        let err = request_isotope_approval(
            "/bin/sh",
            None,
            &options,
            &["TOKEN".to_string()],
            true,
            None,
            None,
            false,
        )
        .unwrap_err();
        assert!(err.contains("arguments must be valid UTF-8"));

        #[cfg(target_os = "macos")]
        {
            assert!(keychain_read_secret("svc\0bad", "account").is_err());
            assert!(keychain_read_secret_if_present("svc\0bad", "account").is_err());
            assert!(keychain_secret_exists("svc", "account\0bad").is_err());
            assert!(keychain_write_secret("svc", "account\0bad", "value").is_err());
            assert!(keychain_write_secret("svc", "account", "value\0bad").is_err());
            assert!(post_distributed_notification("bad\0notice").is_err());
            assert!(post_distributed_notification_with_object("bad\0notice", "object").is_err());
            assert!(post_distributed_notification_with_object("notice", "bad\0object").is_err());
            assert_eq!(unsafe { take_bridge_string(std::ptr::null_mut()) }, None);

            let missing_account = format!(
                "coverage-missing-{}-{}",
                std::process::id(),
                OffsetDateTime::now_utc().unix_timestamp_nanos()
            );
            assert_eq!(
                keychain_read_secret_if_present(KEYCHAIN_SERVICE, &missing_account).unwrap(),
                None
            );
            assert!(!keychain_secret_exists(KEYCHAIN_SERVICE, &missing_account).unwrap());
            assert!(
                keychain_read_secret(KEYCHAIN_SERVICE, &missing_account)
                    .unwrap_err()
                    .contains("could not be found")
            );

            let store = KeychainCredentialStore;
            assert!(CredentialHelperSecretStore::load_secret(&store, "bad\0key").is_err());
            assert!(
                CredentialHelperSecretStore::load_secret_if_present(&store, "bad\0key").is_err()
            );
            assert!(CredentialHelperSecretStore::secret_exists(&store, "bad\0key").is_err());
            assert!(
                CredentialHelperSecretStore::store_secret(&store, "bad\0key", "value").is_err()
            );
            assert!(CredentialStore::store_secret(&store, "bad\0key", "value").is_err());
        }
    }

    #[test]
    fn isotopes_request_helpers_reject_non_utf8_requested_paths() {
        let bad_path = PathBuf::from(OsString::from_vec(b"/tmp/isotope-\xff".to_vec()));
        let options = IsotopeOptions {
            replace_existing_env: false,
            allow_missing_keys: false,
            keys: vec!["TOKEN".to_string()],
            target: bad_path.clone(),
            args: vec![OsString::from("--version")],
        };
        let err = request_isotope_approval(
            "/bin/sh",
            None,
            &options,
            &["TOKEN".to_string()],
            true,
            None,
            None,
            false,
        )
        .unwrap_err();
        assert!(err.contains("target path must be valid UTF-8"));

        let options = IsotopeOptions {
            replace_existing_env: false,
            allow_missing_keys: false,
            keys: vec!["TOKEN".to_string()],
            target: PathBuf::from("/bin/sh"),
            args: vec![OsString::from("--version")],
        };
        let err = request_isotope_approval(
            "/bin/sh",
            None,
            &options,
            &["TOKEN".to_string()],
            true,
            Some(bad_path),
            None,
            false,
        )
        .unwrap_err();
        assert!(err.contains("path must be valid UTF-8"));
    }

    #[test]
    fn isotopes_validate_parent_directories_rejects_group_writable_directory() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("safe");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).unwrap();
        let target = nested.join("tool");
        fs::write(&target, b"#!/bin/sh\n").unwrap();

        let mut permissions = fs::metadata(&nested).unwrap().permissions();
        permissions.set_mode(0o777);
        fs::set_permissions(&nested, permissions).unwrap();

        let err = validate_parent_directories(&target).unwrap_err();
        assert!(err.contains("directory must not be writable"));
    }

    #[test]
    fn isotopes_run_skips_missing_store_when_existing_env_already_satisfies_keys() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let tool = temp.path().join("tool");
        fs::write(&tool, b"plain text\n").unwrap();
        let mut permissions = fs::metadata(&tool).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&tool, permissions).unwrap();
        unsafe { env::set_var("TOKEN", "already-set") };

        let result = run_isotope(
            &IsotopeOptions {
                replace_existing_env: false,
                allow_missing_keys: false,
                keys: vec!["TOKEN".to_string()],
                target: tool.clone(),
                args: vec![OsString::from("--flag")],
            },
            &StubCredentialStore::default(),
        );

        unsafe { env::remove_var("TOKEN") };
        let err = result.unwrap_err();
        assert!(err.contains("failed to execute"));
    }

    #[test]
    fn isotopes_run_without_credentials_reaches_exec_failure_after_validation() {
        let temp = tempfile::tempdir().unwrap();
        let tool = temp.path().join("tool");
        fs::write(&tool, b"plain text\n").unwrap();
        let mut permissions = fs::metadata(&tool).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&tool, permissions).unwrap();

        let err = run_isotope(
            &IsotopeOptions {
                replace_existing_env: false,
                allow_missing_keys: false,
                keys: Vec::new(),
                target: tool,
                args: vec![OsString::from("--verbose"), OsString::from("value")],
            },
            &StubCredentialStore::default(),
        )
        .unwrap_err();

        assert!(err.contains("failed to execute"));
    }

    #[test]
    fn isotopes_run_allows_missing_keys_without_warning_or_store_error() {
        let temp = tempfile::tempdir().unwrap();
        let tool = temp.path().join("tool");
        fs::write(&tool, b"plain text\n").unwrap();
        let mut permissions = fs::metadata(&tool).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&tool, permissions).unwrap();

        let err = run_isotope(
            &IsotopeOptions {
                replace_existing_env: false,
                allow_missing_keys: true,
                keys: vec!["TOKEN".to_string()],
                target: tool,
                args: Vec::new(),
            },
            &StubCredentialStore::default(),
        )
        .unwrap_err();

        assert!(err.contains("failed to execute"));
        assert!(!err.contains("missing stub credential"));
    }

    #[test]
    fn isotopes_prepare_execution_preserves_argv_zero_and_env() {
        let temp = tempfile::tempdir().unwrap();
        let tool = temp.path().join("tool");
        fs::write(&tool, b"#!/bin/sh\n").unwrap();
        let file = File::open(&tool).unwrap();
        let options = IsotopeOptions {
            replace_existing_env: false,
            allow_missing_keys: false,
            keys: vec!["TOKEN".to_string()],
            target: tool.clone(),
            args: vec![OsString::from("--flag"), OsString::from("value")],
        };
        let prepared = prepare_execution(
            &file,
            &options,
            BTreeMap::from([(OsString::from("TOKEN"), OsString::from("secret"))]),
        )
        .unwrap();
        assert_eq!(prepared.exec_fd, file.as_raw_fd());
        assert_eq!(prepared.exec_path, tool.to_string_lossy().into_owned());
        assert_eq!(
            prepared.argv,
            vec![
                OsString::from(tool.to_string_lossy().as_ref()),
                OsString::from("--flag"),
                OsString::from("value")
            ]
        );
        assert_eq!(prepared.env[OsStr::new("TOKEN")], OsString::from("secret"));
    }

    #[test]
    fn isotopes_prepare_execution_uses_requested_symlink_for_exec() {
        let temp = tempfile::tempdir().unwrap();
        let real_tool = temp.path().join("real-tool");
        let requested_tool = temp.path().join("requested-tool");
        fs::write(&real_tool, b"#!/bin/sh\n").unwrap();
        std::os::unix::fs::symlink(&real_tool, &requested_tool).unwrap();
        let file = File::open(fs::canonicalize(&requested_tool).unwrap()).unwrap();
        let options = IsotopeOptions {
            replace_existing_env: false,
            allow_missing_keys: false,
            keys: vec!["TOKEN".to_string()],
            target: requested_tool.clone(),
            args: Vec::new(),
        };

        let prepared = prepare_execution(&file, &options, BTreeMap::new()).unwrap();

        assert_eq!(
            prepared.exec_path,
            requested_tool.to_string_lossy().into_owned()
        );
        assert_eq!(
            prepared.argv,
            vec![OsString::from(requested_tool.to_string_lossy().as_ref())]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn isotopes_path_for_open_fd_returns_opened_path() {
        let temp = tempfile::tempdir().unwrap();
        let tool = temp.path().join("tool");
        fs::write(&tool, b"#!/bin/sh\n").unwrap();
        let file = File::open(&tool).unwrap();
        let resolved = path_for_open_fd(file.as_raw_fd()).unwrap();
        let expected = fs::canonicalize(&tool).unwrap();
        assert_eq!(resolved, expected.to_string_lossy());
        verify_fd_matches_path(file.as_raw_fd(), &resolved).unwrap();
    }
}
