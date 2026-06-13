use super::*;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Read};

#[cfg(target_os = "macos")]
use std::ffi::{CString, c_char, c_int};

const DOTENV_KEYCHAIN_SERVICE: &str = "com.automicvault.dotenv";
const DOTENV_DEFAULT_KEYCHAIN_ACCESS_GROUP: &str = "ZU76A67LGU.com.automicvault.dotenv";
const ENCRYPTED_PREFIX: &str = "encrypted:";
const DOTENV_PUBLIC_KEY_PREFIX: &str = "DOTENV_PUBLIC_KEY";
const DOTENV_PRIVATE_KEY_PREFIX: &str = "DOTENV_PRIVATE_KEY";
const DOTENV_USER_APPROVAL_SUBDIR: &str = "dotenv";
const DOTENV_APPROVAL_NOTIFICATION: &str = "com.automicvault.dotenv-approval.pending-changed";
const DOTENV_AUTOMATIC_EXPORT_REJECTION_NOTIFICATION: &str =
    "com.automicvault.dotenv-approval.automatic-export-rejected";
const DOTENV_SYSTEM_POLICY_PATH: &str =
    "/Library/Application Support/Automic Vault/dotenv/policy.json";
const DOTENV_SYSTEM_REMEMBERED_APPROVALS_PATH: &str =
    "/Library/Application Support/Automic Vault/dotenv/remembered-approvals.json";
#[cfg(test)]
const AV_TEST_DOTENV_POLICY_PATH_ENV: &str = "AV_TEST_DOTENV_POLICY_PATH";
#[cfg(test)]
const AV_TEST_DOTENV_REMEMBERED_APPROVALS_PATH_ENV: &str =
    "AV_TEST_DOTENV_REMEMBERED_APPROVALS_PATH";
const AV_DOTENV_FILE_ENV: &str = "AV_DOTENV_FILE";
const AV_DOTENV_DIGEST_ENV: &str = "AV_DOTENV_DIGEST";
const AV_DOTENV_KEYS_ENV: &str = "AV_DOTENV_KEYS";
const DOTENV_EXPORT_DENIED_HINT: &str =
    "hint: use `av dotenv run` to run commands with this project's environment";
const DOTENV_AGENT_EXPORT_ENV_MARKERS: &[(&str, &str)] = &[
    ("CODEX_SHELL", "Codex"),
    ("CODEX_THREAD_ID", "Codex"),
    ("CODEX_INTERNAL_ORIGINATOR_OVERRIDE", "Codex"),
    ("CODEX_SANDBOX", "Codex"),
];

#[cfg(target_os = "macos")]
const ERR_SEC_ITEM_NOT_FOUND: c_int = -25300;
#[cfg(target_os = "macos")]
const ERR_SEC_MISSING_ENTITLEMENT: c_int = -34018;

#[cfg(test)]
thread_local! {
    static TEST_DOTENV_PROCESS_CONTEXT: std::cell::RefCell<
        Option<(DotenvParentProcessSnapshot, Vec<DotenvProcessSnapshot>)>
    > = const { std::cell::RefCell::new(None) };
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DotenvCommand {
    Init(DotenvFileOption),
    Set(DotenvSetOptions),
    Encrypt(DotenvEncryptOptions),
    Import(DotenvImportOptions),
    Keychain(DotenvKeychainCommand),
    Hook(DotenvShell),
    Export(DotenvExportOptions),
    Run(DotenvRunOptions),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DotenvKeychainCommand {
    Migrate(DotenvKeychainMigrateOptions),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DotenvFileOption {
    file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DotenvSetOptions {
    file: PathBuf,
    key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DotenvEncryptOptions {
    file: PathBuf,
    include_keys: Vec<String>,
    exclude_keys: Vec<String>,
    check: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DotenvImportOptions {
    file: PathBuf,
    keys_file: PathBuf,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DotenvKeychainMigrateOptions {
    replace: bool,
    delete_legacy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DotenvExportOptions {
    shell: DotenvShell,
    cwd: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DotenvRunOptions {
    file: PathBuf,
    command: OsString,
    args: Vec<OsString>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DotenvShell {
    Bash,
    Fish,
    Zsh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DotenvApprovalMode {
    Export,
    Run,
}

impl DotenvApprovalMode {
    pub fn raw_value(self) -> &'static str {
        match self {
            DotenvApprovalMode::Export => "export",
            DotenvApprovalMode::Run => "run",
        }
    }

    pub fn from_raw_value(value: &str) -> Result<Self, String> {
        match value {
            "export" => Ok(DotenvApprovalMode::Export),
            "run" => Ok(DotenvApprovalMode::Run),
            other => Err(format!("unknown dotenv approval mode: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DotenvApprovalRequestSnapshot {
    id: String,
    approval_token: String,
    mode: DotenvApprovalMode,
    env_file_path: String,
    project_root: String,
    env_sha256: String,
    public_key_fingerprint: String,
    keys: Vec<String>,
    cwd: String,
    parent_process: DotenvParentProcessSnapshot,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    process_ancestry: Vec<DotenvProcessSnapshot>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    command: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DotenvParentProcessSnapshot {
    pid: i32,
    executable_path: Option<String>,
    display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DotenvProcessSnapshot {
    pid: i32,
    parent_pid: i32,
    executable_path: Option<String>,
    display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DotenvApprovalDecision {
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approval_token: Option<String>,
    approved: bool,
    reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DotenvRememberedApprovalEntry {
    mode: DotenvApprovalMode,
    env_file_path: String,
    project_root: String,
    env_sha256: String,
    public_key_fingerprint: String,
    keys: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct DotenvRememberedApprovalStore {
    entries: Vec<DotenvRememberedApprovalEntry>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum DotenvApprovalPolicy {
    #[default]
    #[serde(rename = "approve_every_time")]
    ApproveEveryTime,
    #[serde(rename = "remember_approved")]
    RememberApproved,
}

impl DotenvApprovalPolicy {
    pub fn raw_value(self) -> &'static str {
        match self {
            DotenvApprovalPolicy::ApproveEveryTime => "approve_every_time",
            DotenvApprovalPolicy::RememberApproved => "remember_approved",
        }
    }

    pub fn from_raw_value(value: &str) -> Result<Self, String> {
        match value {
            "approve_every_time" => Ok(DotenvApprovalPolicy::ApproveEveryTime),
            "remember_approved" => Ok(DotenvApprovalPolicy::RememberApproved),
            other => Err(format!("unknown dotenv approval policy: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DotenvPolicyFile {
    approval_policy: DotenvApprovalPolicy,
}

impl DotenvRememberedApprovalStore {
    fn contains(&self, entry: &DotenvRememberedApprovalEntry) -> bool {
        self.entries.iter().any(|candidate| candidate == entry)
    }

    fn remember(&mut self, entry: DotenvRememberedApprovalEntry) {
        if !self.contains(&entry) {
            self.entries.push(entry);
        }
    }
}

trait DotenvPrivateKeyStore {
    fn load_private_key(&self, public_key: &str) -> Result<String, String>;
    fn store_private_key(&self, public_key: &str, private_key: &str) -> Result<(), String>;
}

struct KeychainDotenvPrivateKeyStore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DotenvPrivateKeyTransferMaterial {
    pub(crate) env_file_path: PathBuf,
    pub(crate) public_key_name: String,
    pub(crate) public_key: String,
    pub(crate) public_key_fingerprint: String,
    pub(crate) private_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DotenvLine {
    raw: String,
    assignment: Option<DotenvAssignment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DotenvAssignment {
    key: String,
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DotenvDocument {
    path: PathBuf,
    lines: Vec<DotenvLine>,
    had_trailing_newline: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DotenvKeypair {
    public_key_name: String,
    public_key: String,
    private_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DotenvLoadedSecrets {
    env_path: PathBuf,
    project_root: PathBuf,
    env_sha256: String,
    public_key_fingerprint: String,
    values: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PreviousDotenvState {
    env_path: Option<String>,
    keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DotenvRedactor {
    secrets: Vec<Vec<u8>>,
    pending: Vec<u8>,
    redacted: usize,
    hold_len: usize,
}

pub(crate) fn run_dotenv_entry(
    program_name: &str,
    args: impl Iterator<Item = OsString>,
) -> Result<(), String> {
    dispatch_dotenv(program_name, args, &KeychainDotenvPrivateKeyStore)
}

fn dispatch_dotenv(
    program_name: &str,
    args: impl Iterator<Item = OsString>,
    store: &dyn DotenvPrivateKeyStore,
) -> Result<(), String> {
    let Some(command) = parse_dotenv_command(program_name, args)? else {
        return Ok(());
    };
    match command {
        DotenvCommand::Init(options) => run_dotenv_init(&options, store),
        DotenvCommand::Set(options) => {
            let value = read_dotenv_secret()?;
            run_dotenv_set(&options, &value, store)
        }
        DotenvCommand::Encrypt(options) => run_dotenv_encrypt(&options, store),
        DotenvCommand::Import(options) => run_dotenv_import(&options, store),
        DotenvCommand::Keychain(DotenvKeychainCommand::Migrate(options)) => {
            run_dotenv_keychain_migrate(&options)
        }
        DotenvCommand::Hook(shell) => {
            print_dotenv_hook(program_name, shell);
            Ok(())
        }
        DotenvCommand::Export(options) => run_dotenv_export(&options, store),
        DotenvCommand::Run(options) => run_dotenv_run(&options, store),
    }
}

fn parse_dotenv_command(
    program_name: &str,
    mut args: impl Iterator<Item = OsString>,
) -> Result<Option<DotenvCommand>, String> {
    let Some(first_arg) = args.next() else {
        print_dotenv_usage(program_name);
        return Err("missing dotenv command".to_string());
    };
    if is_help_flag(&first_arg) {
        print_dotenv_usage(program_name);
        return Ok(None);
    }
    if is_version_flag(&first_arg) {
        println!("{program_name} {}", env!("CARGO_PKG_VERSION"));
        return Ok(None);
    }

    let subcommand = first_arg
        .to_str()
        .ok_or_else(|| "dotenv command must be valid UTF-8".to_string())?;
    match subcommand {
        "init" => parse_dotenv_init(program_name, args).map(|value| value.map(DotenvCommand::Init)),
        "set" => parse_dotenv_set(program_name, args).map(|value| value.map(DotenvCommand::Set)),
        "encrypt" => {
            parse_dotenv_encrypt(program_name, args).map(|value| value.map(DotenvCommand::Encrypt))
        }
        "import" => {
            parse_dotenv_import(program_name, args).map(|value| value.map(DotenvCommand::Import))
        }
        "keychain" => parse_dotenv_keychain(program_name, args)
            .map(|value| value.map(DotenvCommand::Keychain)),
        "hook" => parse_dotenv_hook(program_name, args).map(|value| value.map(DotenvCommand::Hook)),
        "export" => {
            parse_dotenv_export(program_name, args).map(|value| value.map(DotenvCommand::Export))
        }
        "run" => parse_dotenv_run(program_name, args).map(|value| value.map(DotenvCommand::Run)),
        other => Err(format!("unknown dotenv command '{other}'")),
    }
}

fn parse_dotenv_init(
    program_name: &str,
    args: impl Iterator<Item = OsString>,
) -> Result<Option<DotenvFileOption>, String> {
    parse_file_only_options(program_name, "init", args, print_dotenv_init_usage)
}

fn parse_dotenv_set(
    program_name: &str,
    args: impl Iterator<Item = OsString>,
) -> Result<Option<DotenvSetOptions>, String> {
    let mut file = PathBuf::from(".env");
    let mut key: Option<String> = None;
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        if is_help_flag(&arg) {
            print_dotenv_set_usage(program_name);
            return Ok(None);
        }
        if is_version_flag(&arg) {
            println!("{program_name} {}", env!("CARGO_PKG_VERSION"));
            return Ok(None);
        }
        if arg == "--file" || arg == "-f" {
            file = next_path_value(&mut args, "--file")?;
            continue;
        }
        if key.is_some() {
            return Err("dotenv set supports one KEY".to_string());
        }
        let value = arg
            .to_str()
            .ok_or_else(|| "dotenv set key must be valid UTF-8".to_string())?;
        validate_dotenv_key_name(value)?;
        key = Some(value.to_string());
    }

    let Some(key) = key else {
        print_dotenv_set_usage(program_name);
        return Err("missing KEY".to_string());
    };
    Ok(Some(DotenvSetOptions { file, key }))
}

fn parse_dotenv_encrypt(
    program_name: &str,
    args: impl Iterator<Item = OsString>,
) -> Result<Option<DotenvEncryptOptions>, String> {
    let mut file = PathBuf::from(".env");
    let mut include_keys = Vec::new();
    let mut exclude_keys = Vec::new();
    let mut check = false;
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        if is_help_flag(&arg) {
            print_dotenv_encrypt_usage(program_name);
            return Ok(None);
        }
        if is_version_flag(&arg) {
            println!("{program_name} {}", env!("CARGO_PKG_VERSION"));
            return Ok(None);
        }
        if arg == "--file" || arg == "-f" {
            file = next_path_value(&mut args, "--file")?;
            continue;
        }
        if arg == "--check" {
            check = true;
            continue;
        }
        if arg == "--key" || arg == "-k" {
            collect_key_values(&mut args, &mut include_keys, "--key")?;
            continue;
        }
        if arg == "--exclude-key" || arg == "-ek" {
            collect_key_values(&mut args, &mut exclude_keys, "--exclude-key")?;
            continue;
        }
        return Err(format!(
            "unknown dotenv encrypt argument '{}'",
            arg.to_string_lossy()
        ));
    }
    include_keys.sort();
    include_keys.dedup();
    exclude_keys.sort();
    exclude_keys.dedup();
    Ok(Some(DotenvEncryptOptions {
        file,
        include_keys,
        exclude_keys,
        check,
    }))
}

fn parse_dotenv_import(
    program_name: &str,
    args: impl Iterator<Item = OsString>,
) -> Result<Option<DotenvImportOptions>, String> {
    let mut file = PathBuf::from(".env");
    let mut keys_file: Option<PathBuf> = None;
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        if is_help_flag(&arg) {
            print_dotenv_import_usage(program_name);
            return Ok(None);
        }
        if is_version_flag(&arg) {
            println!("{program_name} {}", env!("CARGO_PKG_VERSION"));
            return Ok(None);
        }
        if arg == "--file" || arg == "-f" {
            file = next_path_value(&mut args, "--file")?;
            continue;
        }
        if arg == "--keys-file" {
            keys_file = Some(next_path_value(&mut args, "--keys-file")?);
            continue;
        }
        return Err(format!(
            "unknown dotenv import argument '{}'",
            arg.to_string_lossy()
        ));
    }
    let keys_file = keys_file.unwrap_or_else(|| {
        file.parent()
            .map(|parent| parent.join(".env.keys"))
            .unwrap_or_else(|| PathBuf::from(".env.keys"))
    });
    Ok(Some(DotenvImportOptions { file, keys_file }))
}

fn parse_dotenv_keychain(
    program_name: &str,
    mut args: impl Iterator<Item = OsString>,
) -> Result<Option<DotenvKeychainCommand>, String> {
    let nested_program_name = format!("{program_name} keychain");
    let Some(command) = args.next() else {
        print_dotenv_keychain_usage(&nested_program_name);
        return Err("missing dotenv keychain command".to_string());
    };
    if is_help_flag(&command) {
        print_dotenv_keychain_usage(&nested_program_name);
        return Ok(None);
    }
    if is_version_flag(&command) {
        println!("{program_name} {}", env!("CARGO_PKG_VERSION"));
        return Ok(None);
    }

    let command = command
        .to_str()
        .ok_or_else(|| "dotenv keychain command must be valid UTF-8".to_string())?;
    match command {
        "migrate" => parse_dotenv_keychain_migrate(&nested_program_name, args)
            .map(|value| value.map(DotenvKeychainCommand::Migrate)),
        other => Err(format!("unknown dotenv keychain command '{other}'")),
    }
}

fn parse_dotenv_keychain_migrate(
    program_name: &str,
    args: impl Iterator<Item = OsString>,
) -> Result<Option<DotenvKeychainMigrateOptions>, String> {
    let mut options = DotenvKeychainMigrateOptions::default();
    for arg in args {
        if is_help_flag(&arg) {
            print_dotenv_keychain_migrate_usage(program_name);
            return Ok(None);
        }
        if is_version_flag(&arg) {
            println!("{program_name} {}", env!("CARGO_PKG_VERSION"));
            return Ok(None);
        }
        if arg == "--replace" {
            options.replace = true;
            continue;
        }
        if arg == "--delete-legacy" {
            options.delete_legacy = true;
            continue;
        }
        return Err(format!(
            "unknown dotenv keychain migrate argument '{}'",
            arg.to_string_lossy()
        ));
    }
    Ok(Some(options))
}

fn parse_dotenv_hook(
    program_name: &str,
    mut args: impl Iterator<Item = OsString>,
) -> Result<Option<DotenvShell>, String> {
    let Some(shell) = args.next() else {
        print_dotenv_hook_usage(program_name);
        return Err("missing shell".to_string());
    };
    if is_help_flag(&shell) {
        print_dotenv_hook_usage(program_name);
        return Ok(None);
    }
    if is_version_flag(&shell) {
        println!("{program_name} {}", env!("CARGO_PKG_VERSION"));
        return Ok(None);
    }
    if args.next().is_some() {
        return Err("dotenv hook supports one shell".to_string());
    }
    let shell = parse_dotenv_shell(&shell)?;
    Ok(Some(shell))
}

fn parse_dotenv_export(
    program_name: &str,
    args: impl Iterator<Item = OsString>,
) -> Result<Option<DotenvExportOptions>, String> {
    let mut shell: Option<DotenvShell> = None;
    let mut cwd: Option<PathBuf> = None;
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        if is_help_flag(&arg) {
            print_dotenv_export_usage(program_name);
            return Ok(None);
        }
        if is_version_flag(&arg) {
            println!("{program_name} {}", env!("CARGO_PKG_VERSION"));
            return Ok(None);
        }
        if arg == "--shell" {
            let value = args
                .next()
                .ok_or_else(|| "missing value for --shell".to_string())?;
            shell = Some(parse_dotenv_shell(&value)?);
            continue;
        }
        if arg == "--cwd" {
            cwd = Some(next_path_value(&mut args, "--cwd")?);
            continue;
        }
        return Err(format!(
            "unknown dotenv export argument '{}'",
            arg.to_string_lossy()
        ));
    }
    let shell = shell.ok_or_else(|| "missing --shell".to_string())?;
    let cwd =
        cwd.unwrap_or(env::current_dir().map_err(|err| format!("failed to resolve cwd: {err}"))?);
    Ok(Some(DotenvExportOptions { shell, cwd }))
}

fn parse_dotenv_run(
    program_name: &str,
    args: impl Iterator<Item = OsString>,
) -> Result<Option<DotenvRunOptions>, String> {
    let mut file = PathBuf::from(".env");
    let mut positionals = Vec::new();
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        if positionals.is_empty() {
            if is_help_flag(&arg) {
                print_dotenv_run_usage(program_name);
                return Ok(None);
            }
            if is_version_flag(&arg) {
                println!("{program_name} {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            if arg == "--file" || arg == "-f" {
                file = next_path_value(&mut args, "--file")?;
                continue;
            }
            if arg == "--" {
                positionals.extend(args);
                break;
            }
        }
        positionals.push(arg);
    }
    if positionals.is_empty() {
        print_dotenv_run_usage(program_name);
        return Err("missing command".to_string());
    }
    let command = positionals.remove(0);
    Ok(Some(DotenvRunOptions {
        file,
        command,
        args: positionals,
    }))
}

fn parse_file_only_options<I>(
    program_name: &str,
    command_name: &str,
    args: I,
    print_usage: fn(&str),
) -> Result<Option<DotenvFileOption>, String>
where
    I: Iterator<Item = OsString>,
{
    let mut file = PathBuf::from(".env");
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        if is_help_flag(&arg) {
            print_usage(program_name);
            return Ok(None);
        }
        if is_version_flag(&arg) {
            println!("{program_name} {}", env!("CARGO_PKG_VERSION"));
            return Ok(None);
        }
        if arg == "--file" || arg == "-f" {
            file = next_path_value(&mut args, "--file")?;
            continue;
        }
        return Err(format!(
            "unknown dotenv {command_name} argument '{}'",
            arg.to_string_lossy()
        ));
    }
    Ok(Some(DotenvFileOption { file }))
}

fn next_path_value<I>(args: &mut std::iter::Peekable<I>, flag: &str) -> Result<PathBuf, String>
where
    I: Iterator<Item = OsString>,
{
    args.next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn collect_key_values<I>(
    args: &mut std::iter::Peekable<I>,
    keys: &mut Vec<String>,
    flag: &str,
) -> Result<(), String>
where
    I: Iterator<Item = OsString>,
{
    let mut collected = 0;
    while let Some(next) = args.peek() {
        if next.to_string_lossy().starts_with('-') {
            break;
        }
        let value = args.next().unwrap();
        let key = value
            .to_str()
            .ok_or_else(|| format!("{flag} value must be valid UTF-8"))?;
        validate_dotenv_key_name(key)?;
        keys.push(key.to_string());
        collected += 1;
    }
    if collected == 0 {
        return Err(format!("missing value for {flag}"));
    }
    Ok(())
}

fn parse_dotenv_shell(value: &OsStr) -> Result<DotenvShell, String> {
    match value.to_str() {
        Some("bash") => Ok(DotenvShell::Bash),
        Some("fish") => Ok(DotenvShell::Fish),
        Some("zsh") => Ok(DotenvShell::Zsh),
        Some(other) => Err(format!("unsupported shell '{other}'")),
        None => Err("shell must be valid UTF-8".to_string()),
    }
}

fn run_dotenv_init(
    options: &DotenvFileOption,
    store: &dyn DotenvPrivateKeyStore,
) -> Result<(), String> {
    let mut document = DotenvDocument::load_or_empty(&options.file)?;
    if document.public_key().is_some() {
        return Err(format!(
            "{} already has a DOTENV_PUBLIC_KEY",
            document.path.display()
        ));
    }
    let keypair = generate_dotenv_keypair(&document.path);
    document.ensure_public_key(&keypair.public_key_name, &keypair.public_key);
    document.write()?;
    store.store_private_key(&keypair.public_key, &keypair.private_key)?;
    println!("initialized {}", document.path.display());
    Ok(())
}

fn run_dotenv_set(
    options: &DotenvSetOptions,
    value: &str,
    store: &dyn DotenvPrivateKeyStore,
) -> Result<(), String> {
    let mut document = DotenvDocument::load_or_empty(&options.file)?;
    let public_key = ensure_document_public_key(&mut document, store)?;
    let encrypted = encrypt_dotenv_value(value, &public_key)?;
    document.set_value(&options.key, &encrypted);
    document.write()?;
    println!("set {}", options.key);
    Ok(())
}

fn run_dotenv_encrypt(
    options: &DotenvEncryptOptions,
    store: &dyn DotenvPrivateKeyStore,
) -> Result<(), String> {
    let mut document = DotenvDocument::load_or_empty(&options.file)?;
    let keys = document.encryptable_keys(&options.include_keys, &options.exclude_keys);
    if options.check {
        if keys.is_empty() {
            return Ok(());
        }
        let description = if options.include_keys.is_empty() {
            "secret-shaped plaintext dotenv values"
        } else {
            "plaintext dotenv values"
        };
        return Err(format!(
            "{} has {}: {}",
            document.path.display(),
            description,
            keys.join(", ")
        ));
    }
    let public_key = ensure_document_public_key(&mut document, store)?;
    if keys.is_empty() {
        document.write()?;
        if options.include_keys.is_empty() {
            println!("no secret-shaped plaintext values to encrypt");
        } else {
            println!("no plaintext values to encrypt");
        }
        return Ok(());
    }
    for key in &keys {
        let value = document
            .value(key)
            .ok_or_else(|| format!("missing key during encryption: {key}"))?;
        let encrypted = encrypt_dotenv_value(&value, &public_key)?;
        document.set_value(key, &encrypted);
    }
    document.write()?;
    println!("encrypted {}", keys.join(", "));
    Ok(())
}

fn run_dotenv_import(
    options: &DotenvImportOptions,
    store: &dyn DotenvPrivateKeyStore,
) -> Result<(), String> {
    let document = DotenvDocument::load(&options.file)?;
    let (public_key_name, public_key) = document
        .public_key()
        .ok_or_else(|| format!("{} is missing DOTENV_PUBLIC_KEY", document.path.display()))?;
    let private_key_name = private_key_name_for_public_key_name(&public_key_name);
    let keys_document = DotenvDocument::load(&options.keys_file)?;
    let private_key = keys_document.value(&private_key_name).ok_or_else(|| {
        format!(
            "{} is missing {}",
            keys_document.path.display(),
            private_key_name
        )
    })?;
    validate_private_key_list(&private_key)?;
    store.store_private_key(&public_key, &private_key)?;
    println!("imported {}", private_key_name);
    Ok(())
}

fn run_dotenv_export(
    options: &DotenvExportOptions,
    store: &dyn DotenvPrivateKeyStore,
) -> Result<(), String> {
    let previous = previous_dotenv_state();
    let Some(env_path) = nearest_dotenv_file(&options.cwd) else {
        print_shell_unload(options.shell, &previous);
        return Ok(());
    };

    let env_digest = sha256_file_hex(&env_path)?;
    if env::var(AV_DOTENV_FILE_ENV).ok().as_deref() == env_path.to_str()
        && env::var(AV_DOTENV_DIGEST_ENV).ok().as_deref() == Some(env_digest.as_str())
    {
        return Ok(());
    }

    let loaded = load_dotenv_secrets(
        &env_path,
        DotenvApprovalMode::Export,
        &[],
        store,
        Some(&previous.keys),
    )?;
    crate::audit::record(
        crate::audit::Event::new(
            crate::audit::EVENT_SECRET_INJECT,
            crate::audit::DECISION_APPROVED,
        )
        .mode("export")
        .keys(loaded.values.keys().cloned())
        .dotenv(
            loaded.env_path.to_string_lossy().into_owned(),
            loaded.project_root.to_string_lossy().into_owned(),
            loaded.env_sha256.clone(),
            loaded.public_key_fingerprint.clone(),
        )
        .outcome("print"),
    );
    print_shell_exports(options.shell, &previous, &loaded);
    Ok(())
}

fn run_dotenv_run(
    options: &DotenvRunOptions,
    store: &dyn DotenvPrivateKeyStore,
) -> Result<(), String> {
    disable_dotenv_core_dumps()?;
    let command_line = std::iter::once(options.command.clone())
        .chain(options.args.clone())
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let loaded = load_dotenv_secrets(
        &options.file,
        DotenvApprovalMode::Run,
        &command_line,
        store,
        None,
    )?;
    crate::audit::record(
        crate::audit::Event::new(
            crate::audit::EVENT_SECRET_INJECT,
            crate::audit::DECISION_APPROVED,
        )
        .mode("run")
        .keys(loaded.values.keys().cloned())
        .exec(
            options.command.to_string_lossy().into_owned(),
            command_line.clone(),
        )
        .cwd(
            env::current_dir()
                .map(|dir| dir.to_string_lossy().into_owned())
                .unwrap_or_default(),
        )
        .dotenv(
            loaded.env_path.to_string_lossy().into_owned(),
            loaded.project_root.to_string_lossy().into_owned(),
            loaded.env_sha256.clone(),
            loaded.public_key_fingerprint.clone(),
        )
        .outcome("spawn"),
    );

    let mut command = Command::new(&options.command);
    command.args(&options.args);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    for (key, value) in &loaded.values {
        if env::var_os(key).is_none() {
            command.env(key, value);
        }
    }
    let mut child = command.spawn().map_err(|err| {
        format!(
            "failed to execute {}: {err}",
            options.command.to_string_lossy()
        )
    })?;
    let secrets = loaded
        .values
        .values()
        .filter(|value| !value.is_empty())
        .map(|value| value.as_bytes().to_vec())
        .collect::<Vec<_>>();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_secrets = secrets.clone();
    let stdout_thread = stdout.map(|stream| {
        thread::spawn(move || stream_redacted_output(stream, io::stdout(), stdout_secrets))
    });
    let stderr_thread = stderr
        .map(|stream| thread::spawn(move || stream_redacted_output(stream, io::stderr(), secrets)));
    let status = child
        .wait()
        .map_err(|err| format!("failed to wait for dotenv command: {err}"))?;
    let mut redactions = 0;
    if let Some(handle) = stdout_thread {
        redactions += handle
            .join()
            .map_err(|_| "stdout redaction thread panicked".to_string())??;
    }
    if let Some(handle) = stderr_thread {
        redactions += handle
            .join()
            .map_err(|_| "stderr redaction thread panicked".to_string())??;
    }
    if redactions > 0 {
        eprintln!("av dotenv: redacted secret output");
    }
    if status.success() {
        Ok(())
    } else if let Some(code) = status.code() {
        process::exit(code);
    } else {
        Err("dotenv command terminated by signal".to_string())
    }
}

pub(crate) fn load_dotenv_private_key_for_transfer(
    file: &Path,
) -> Result<DotenvPrivateKeyTransferMaterial, String> {
    let document = DotenvDocument::load(file)?;
    let (public_key_name, public_key) = document
        .public_key()
        .ok_or_else(|| format!("{} is missing DOTENV_PUBLIC_KEY", document.path.display()))?;
    validate_dotenv_public_key_for_transfer(&public_key)?;
    let private_key = KeychainDotenvPrivateKeyStore.load_private_key(&public_key)?;
    validate_private_key_list(&private_key)?;
    Ok(DotenvPrivateKeyTransferMaterial {
        env_file_path: document.path,
        public_key_name,
        public_key_fingerprint: public_key_fingerprint(&public_key),
        public_key,
        private_key,
    })
}

pub(crate) fn validate_dotenv_public_key_name_for_transfer(name: &str) -> Result<(), String> {
    if is_public_key_name(name) {
        Ok(())
    } else {
        Err(format!("invalid dotenv public key name: {name}"))
    }
}

pub(crate) fn validate_dotenv_public_key_for_transfer(public_key: &str) -> Result<(), String> {
    let decoded = decode_hex(public_key)?;
    if decoded.len() == 33 {
        Ok(())
    } else {
        Err("dotenv public key must be 33 bytes".to_string())
    }
}

pub(crate) fn validate_dotenv_private_key_for_transfer(private_key: &str) -> Result<(), String> {
    validate_private_key_list(private_key)
}

pub(crate) fn dotenv_public_key_fingerprint_for_transfer(public_key: &str) -> String {
    public_key_fingerprint(public_key)
}

#[cfg(test)]
pub(crate) fn load_existing_dotenv_private_key_for_transfer(
    public_key: &str,
) -> Result<Option<String>, String> {
    validate_dotenv_public_key_for_transfer(public_key)?;
    let account = keychain_account_for_public_key(public_key);
    keychain_read_dotenv_private_key_if_present(DOTENV_KEYCHAIN_SERVICE, &account)
}

#[cfg(test)]
pub(crate) fn store_dotenv_private_key_for_transfer(
    public_key: &str,
    private_key: &str,
) -> Result<(), String> {
    validate_dotenv_public_key_for_transfer(public_key)?;
    validate_dotenv_private_key_for_transfer(private_key)?;
    KeychainDotenvPrivateKeyStore.store_private_key(public_key, private_key)
}

fn ensure_document_public_key(
    document: &mut DotenvDocument,
    store: &dyn DotenvPrivateKeyStore,
) -> Result<String, String> {
    if let Some((_name, public_key)) = document.public_key() {
        return Ok(public_key);
    }
    let keypair = generate_dotenv_keypair(&document.path);
    document.ensure_public_key(&keypair.public_key_name, &keypair.public_key);
    store.store_private_key(&keypair.public_key, &keypair.private_key)?;
    Ok(keypair.public_key)
}

fn load_dotenv_secrets(
    file: &Path,
    mode: DotenvApprovalMode,
    command: &[String],
    store: &dyn DotenvPrivateKeyStore,
    previous_av_keys: Option<&[String]>,
) -> Result<DotenvLoadedSecrets, String> {
    let document = DotenvDocument::load(file)?;
    let (_public_key_name, public_key) = document
        .public_key()
        .ok_or_else(|| format!("{} is missing DOTENV_PUBLIC_KEY", document.path.display()))?;
    let env_sha256 = sha256_file_hex(&document.path)?;
    let public_key_fingerprint = public_key_fingerprint(&public_key);
    let mut assignments = BTreeMap::new();
    for line in &document.lines {
        let Some(assignment) = &line.assignment else {
            continue;
        };
        if is_public_key_name(&assignment.key) || !is_valid_dotenv_key_name(&assignment.key) {
            continue;
        }
        if env_key_is_preexisting(&assignment.key, previous_av_keys) {
            continue;
        }
        assignments.insert(assignment.key.clone(), assignment.value.clone());
    }
    let keys = assignments.keys().cloned().collect::<Vec<_>>();
    let project_root = document
        .path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    request_dotenv_approval_if_needed(
        mode,
        &document.path,
        &project_root,
        &env_sha256,
        &public_key_fingerprint,
        &keys,
        command,
    )?;
    let private_key = store.load_private_key(&public_key)?;
    validate_private_key_list(&private_key)?;
    let mut values = BTreeMap::new();
    for (key, value) in assignments {
        values.insert(
            key.clone(),
            decrypt_dotenv_value(&key, &value, &private_key)?,
        );
    }
    Ok(DotenvLoadedSecrets {
        env_path: document.path,
        project_root,
        env_sha256,
        public_key_fingerprint,
        values,
    })
}

fn env_key_is_preexisting(key: &str, previous_av_keys: Option<&[String]>) -> bool {
    if env::var_os(key).is_none() {
        return false;
    }
    !previous_av_keys
        .map(|keys| keys.iter().any(|previous| previous == key))
        .unwrap_or(false)
}

impl DotenvDocument {
    fn load(path: &Path) -> Result<Self, String> {
        let path = resolve_dotenv_path(path)?;
        let contents = fs::read_to_string(&path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        Ok(Self::parse(path, &contents))
    }

    fn load_or_empty(path: &Path) -> Result<Self, String> {
        let path = resolve_dotenv_path(path)?;
        match fs::read_to_string(&path) {
            Ok(contents) => Ok(Self::parse(path, &contents)),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(Self {
                path,
                lines: Vec::new(),
                had_trailing_newline: true,
            }),
            Err(err) => Err(format!("failed to read {}: {err}", path.display())),
        }
    }

    fn parse(path: PathBuf, contents: &str) -> Self {
        let normalized = contents.replace("\r\n", "\n").replace('\r', "\n");
        let had_trailing_newline = normalized.ends_with('\n');
        let mut lines = normalized
            .lines()
            .map(|raw| DotenvLine {
                raw: raw.to_string(),
                assignment: parse_dotenv_assignment(raw),
            })
            .collect::<Vec<_>>();
        if normalized.is_empty() {
            lines.clear();
        }
        Self {
            path,
            lines,
            had_trailing_newline,
        }
    }

    fn write(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
        }
        fs::write(&self.path, self.render())
            .map_err(|err| format!("failed to write {}: {err}", self.path.display()))
    }

    fn render(&self) -> String {
        let mut output = self
            .lines
            .iter()
            .map(|line| line.raw.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        if self.had_trailing_newline || !output.is_empty() {
            output.push('\n');
        }
        output
    }

    fn public_key(&self) -> Option<(String, String)> {
        self.lines.iter().find_map(|line| {
            let assignment = line.assignment.as_ref()?;
            if is_public_key_name(&assignment.key) && !assignment.value.is_empty() {
                Some((assignment.key.clone(), assignment.value.clone()))
            } else {
                None
            }
        })
    }

    fn value(&self, key: &str) -> Option<String> {
        self.lines.iter().find_map(|line| {
            let assignment = line.assignment.as_ref()?;
            if assignment.key == key {
                Some(assignment.value.clone())
            } else {
                None
            }
        })
    }

    fn ensure_public_key(&mut self, key: &str, value: &str) {
        let line = format_assignment(key, value);
        if self.lines.is_empty() {
            self.lines.extend(dotenv_header_lines());
            self.lines.push(DotenvLine {
                assignment: parse_dotenv_assignment(&line),
                raw: line,
            });
            return;
        }
        self.lines.insert(
            0,
            DotenvLine {
                assignment: parse_dotenv_assignment(&line),
                raw: line,
            },
        );
        for header in dotenv_header_lines().into_iter().rev() {
            self.lines.insert(0, header);
        }
    }

    fn set_value(&mut self, key: &str, value: &str) {
        let raw = format_assignment(key, value);
        for line in &mut self.lines {
            if line
                .assignment
                .as_ref()
                .is_some_and(|assignment| assignment.key == key)
            {
                line.raw = raw.clone();
                line.assignment = parse_dotenv_assignment(&raw);
                return;
            }
        }
        if !self.lines.is_empty()
            && self
                .lines
                .last()
                .is_some_and(|line| !line.raw.trim().is_empty())
        {
            self.lines.push(DotenvLine {
                raw: String::new(),
                assignment: None,
            });
        }
        self.lines.push(DotenvLine {
            assignment: parse_dotenv_assignment(&raw),
            raw,
        });
    }

    fn encryptable_keys(&self, include_keys: &[String], exclude_keys: &[String]) -> Vec<String> {
        let include = include_keys.iter().collect::<HashSet<_>>();
        let exclude = exclude_keys.iter().collect::<HashSet<_>>();
        let explicit_includes = !include.is_empty();
        let mut keys = Vec::new();
        for line in &self.lines {
            let Some(assignment) = &line.assignment else {
                continue;
            };
            if is_public_key_name(&assignment.key) || !is_valid_dotenv_key_name(&assignment.key) {
                continue;
            }
            if !include.is_empty() && !include.contains(&assignment.key) {
                continue;
            }
            if exclude.contains(&assignment.key) || is_encrypted_value(&assignment.value) {
                continue;
            }
            if !explicit_includes
                && !is_secret_shaped_dotenv_assignment(&assignment.key, &assignment.value)
            {
                continue;
            }
            push_unique_string(&mut keys, assignment.key.clone());
        }
        keys
    }
}

fn resolve_dotenv_path(path: &Path) -> Result<PathBuf, String> {
    if path.exists() {
        fs::canonicalize(path).map_err(|err| format!("failed to resolve {}: {err}", path.display()))
    } else if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(env::current_dir()
            .map_err(|err| format!("failed to resolve current directory: {err}"))?
            .join(path))
    }
}

fn parse_dotenv_assignment(raw: &str) -> Option<DotenvAssignment> {
    let trimmed = raw.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let assignment = trimmed.strip_prefix("export ").unwrap_or(trimmed);
    let equals = assignment.find('=');
    let colon = assignment.find(':').filter(|index| {
        assignment[*index + 1..]
            .chars()
            .next()
            .is_some_and(char::is_whitespace)
    });
    let sep = match (equals, colon) {
        (Some(eq), Some(col)) => Some(eq.min(col)),
        (Some(eq), None) => Some(eq),
        (None, Some(col)) => Some(col),
        (None, None) => None,
    }?;
    let key = assignment[..sep].trim();
    if key.is_empty() {
        return None;
    }
    let value_start = sep + 1;
    let value = parse_dotenv_value(&assignment[value_start..]);
    Some(DotenvAssignment {
        key: key.to_string(),
        value,
    })
}

fn parse_dotenv_value(value: &str) -> String {
    let trimmed = value.trim();
    let Some(first) = trimmed.chars().next() else {
        return String::new();
    };
    if matches!(first, '\'' | '"' | '`') {
        return parse_quoted_dotenv_value(trimmed, first);
    }
    trimmed
        .split_once('#')
        .map(|(head, _)| head.trim_end())
        .unwrap_or(trimmed)
        .to_string()
}

fn parse_quoted_dotenv_value(value: &str, quote: char) -> String {
    let mut escaped = false;
    let mut end = None;
    for (index, ch) in value.char_indices().skip(1) {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && quote != '\'' {
            escaped = true;
            continue;
        }
        if ch == quote {
            end = Some(index);
            break;
        }
    }
    let inner = match end {
        Some(index) => &value[1..index],
        None => &value[1..],
    };
    if quote == '"' {
        inner
            .replace("\\n", "\n")
            .replace("\\r", "\r")
            .replace("\\t", "\t")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    } else {
        inner.to_string()
    }
}

fn format_assignment(key: &str, value: &str) -> String {
    format!("{key}=\"{}\"", dotenv_double_quote_escape(value))
}

fn dotenv_double_quote_escape(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn dotenv_header_lines() -> Vec<DotenvLine> {
    [
        "# You can use these keys by running `av dotenv run SCRIPT.ext`.",
        "# The human operator will be prompted to allow it.",
        "# Output will be monitored to occlude secrets.",
        "",
    ]
    .into_iter()
    .map(|raw| DotenvLine {
        raw: raw.to_string(),
        assignment: None,
    })
    .collect()
}

fn generate_dotenv_keypair(path: &Path) -> DotenvKeypair {
    let (private_key, public_key) = ecies::utils::generate_keypair();
    DotenvKeypair {
        public_key_name: public_key_name_for_file(path),
        public_key: encode_hex(&public_key.serialize_compressed()),
        private_key: encode_hex(&private_key.serialize()),
    }
}

fn public_key_name_for_file(path: &Path) -> String {
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(".env")
        .to_ascii_lowercase();
    let filename = filename.strip_suffix(".txt").unwrap_or(&filename);
    if filename == ".env" {
        return DOTENV_PUBLIC_KEY_PREFIX.to_string();
    }
    let parts = filename.split('.').collect::<Vec<_>>();
    let environment = match parts.get(2..) {
        Some([]) | None => filename.replacen(".env", "development", 1),
        Some([one]) => (*one).to_string(),
        Some([one, two]) => format!("{one}_{two}"),
        Some(rest) => rest[..2].join("_"),
    };
    format!(
        "{}_{}",
        DOTENV_PUBLIC_KEY_PREFIX,
        environment.to_ascii_uppercase()
    )
}

fn private_key_name_for_public_key_name(public_key_name: &str) -> String {
    public_key_name.replacen(DOTENV_PUBLIC_KEY_PREFIX, DOTENV_PRIVATE_KEY_PREFIX, 1)
}

fn encrypt_dotenv_value(value: &str, public_key: &str) -> Result<String, String> {
    let public_key = decode_hex(public_key)?;
    let encrypted = ecies::encrypt(&public_key, value.as_bytes())
        .map_err(|err| format!("failed to encrypt dotenv value: {err}"))?;
    Ok(format!("{ENCRYPTED_PREFIX}{}", BASE64.encode(encrypted)))
}

fn decrypt_dotenv_value(key: &str, value: &str, private_keys: &str) -> Result<String, String> {
    if !is_encrypted_value(value) {
        return Ok(value.to_string());
    }
    let encoded = value
        .strip_prefix(ENCRYPTED_PREFIX)
        .expect("checked encrypted prefix");
    let ciphertext = BASE64
        .decode(encoded)
        .map_err(|err| format!("could not decrypt {key}: malformed encrypted data: {err}"))?;
    let mut last_error = None;
    for private_key in private_keys
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let private_key = match decode_hex(private_key) {
            Ok(value) => value,
            Err(err) => {
                last_error = Some(err);
                continue;
            }
        };
        match ecies::decrypt(&private_key, &ciphertext) {
            Ok(value) => {
                return String::from_utf8(value)
                    .map_err(|_| format!("could not decrypt {key}: plaintext is not UTF-8"));
            }
            Err(err) => last_error = Some(err.to_string()),
        }
    }
    Err(format!(
        "could not decrypt {key}: {}",
        last_error.unwrap_or_else(|| "missing private key".to_string())
    ))
}

fn is_encrypted_value(value: &str) -> bool {
    value.starts_with(ENCRYPTED_PREFIX) && value.len() > ENCRYPTED_PREFIX.len()
}

fn is_public_key_name(key: &str) -> bool {
    key == DOTENV_PUBLIC_KEY_PREFIX
        || key
            .strip_prefix(DOTENV_PUBLIC_KEY_PREFIX)
            .is_some_and(|suffix| suffix.starts_with('_'))
}

fn validate_dotenv_key_name(key: &str) -> Result<(), String> {
    if is_valid_dotenv_key_name(key) {
        Ok(())
    } else {
        Err(format!("invalid dotenv key name: {key}"))
    }
}

fn validate_sha256_hex(value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("dotenv sha256 must be a 64-character hex digest".to_string());
    }
    Ok(())
}

fn is_valid_dotenv_key_name(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(first) if first == '_' || first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn is_secret_shaped_dotenv_assignment(key: &str, value: &str) -> bool {
    dotenv_key_looks_secret(key, value) || dotenv_value_looks_secret(value)
}

fn dotenv_key_looks_secret(key: &str, value: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    if upper.starts_with("NEXT_PUBLIC_")
        || upper.starts_with("NUXT_PUBLIC_")
        || upper.starts_with("PUBLIC_")
        || upper.starts_with("VITE_")
        || upper.contains("PUBLISHABLE")
        || upper.contains("PUBLIC_KEY")
    {
        return false;
    }
    if [
        "_ENDPOINT",
        "_HOST",
        "_PORT",
        "_URI",
        "_URL",
        "_VERSION",
        "_ENABLED",
    ]
    .iter()
    .any(|suffix| upper.ends_with(suffix))
    {
        return dotenv_value_looks_secret(value);
    }

    let tokens = upper
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if tokens
        .iter()
        .any(|token| matches!(*token, "SECRET" | "TOKEN" | "PASSWORD" | "PASSWD"))
    {
        return true;
    }
    if tokens.contains(&"KEY")
        && tokens.iter().any(|token| {
            matches!(
                *token,
                "ACCESS"
                    | "API"
                    | "AWS"
                    | "GITHUB"
                    | "GITLAB"
                    | "NPM"
                    | "OPENAI"
                    | "PRIVATE"
                    | "SECRET"
                    | "STRIPE"
            )
        })
    {
        return true;
    }

    let compact = upper
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();
    [
        "APIKEY",
        "ACCESSTOKEN",
        "AUTHTOKEN",
        "BEARERTOKEN",
        "CLIENTSECRET",
        "PRIVATEKEY",
        "REFRESHTOKEN",
        "SECRETKEY",
        "SESSIONSECRET",
        "SIGNINGSECRET",
        "WEBHOOKSECRET",
    ]
    .iter()
    .any(|needle| compact.contains(needle))
        || ((upper.ends_with("_URL") || upper.ends_with("_DSN"))
            && dotenv_value_looks_credential_url(value))
}

fn dotenv_value_looks_secret(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || is_encrypted_value(trimmed) {
        return false;
    }
    if trimmed.contains("-----BEGIN ") && trimmed.contains("PRIVATE KEY-----") {
        return true;
    }
    if dotenv_value_looks_credential_url(trimmed) || dotenv_value_looks_jwt(trimmed) {
        return true;
    }
    if [
        "sk-",
        "sk_live_",
        "sk_test_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "github_pat_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "xapp-",
    ]
    .iter()
    .any(|prefix| trimmed.starts_with(prefix))
    {
        return true;
    }
    if dotenv_value_looks_aws_access_key(trimmed) {
        return true;
    }
    dotenv_value_has_high_entropy_secret_shape(trimmed)
}

fn dotenv_value_looks_credential_url(value: &str) -> bool {
    let Some(scheme_end) = value.find("://") else {
        return false;
    };
    if !value[..scheme_end].chars().enumerate().all(|(index, ch)| {
        if index == 0 {
            ch.is_ascii_alphabetic()
        } else {
            ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-')
        }
    }) {
        return false;
    }
    let authority = value[scheme_end + 3..]
        .split(|ch: char| ch == '/' || ch.is_whitespace())
        .next()
        .unwrap_or_default();
    let Some(at) = authority.rfind('@') else {
        return false;
    };
    authority[..at].contains(':')
}

fn dotenv_value_looks_jwt(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts[0].starts_with("eyJ")
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(is_base64url_byte))
}

fn is_base64url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn dotenv_value_looks_aws_access_key(value: &str) -> bool {
    value.len() == 20
        && (value.starts_with("AKIA") || value.starts_with("ASIA"))
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn dotenv_value_has_high_entropy_secret_shape(value: &str) -> bool {
    if value.len() < 32
        || value.chars().any(char::is_whitespace)
        || value.starts_with('/')
        || value.starts_with("~/")
        || value.contains("://")
        || value.chars().all(|ch| ch.is_ascii_hexdigit() || ch == '-')
    {
        return false;
    }
    let has_lower = value.chars().any(|ch| ch.is_ascii_lowercase());
    let has_upper = value.chars().any(|ch| ch.is_ascii_uppercase());
    let has_digit = value.chars().any(|ch| ch.is_ascii_digit());
    let has_symbol = value.chars().any(|ch| !ch.is_ascii_alphanumeric());
    let class_count = [has_lower, has_upper, has_digit, has_symbol]
        .into_iter()
        .filter(|present| *present)
        .count();
    let unique_count = value.chars().collect::<HashSet<_>>().len();
    class_count >= 3 && unique_count >= 16
}

fn validate_private_key_list(value: &str) -> Result<(), String> {
    for key in value
        .split(',')
        .map(str::trim)
        .filter(|key| !key.is_empty())
    {
        let decoded = decode_hex(key)?;
        if decoded.len() != 32 {
            return Err("dotenv private key must be 32 bytes".to_string());
        }
    }
    Ok(())
}

fn public_key_fingerprint(public_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key.as_bytes());
    encode_hex(&hasher.finalize())
}

fn keychain_account_for_public_key(public_key: &str) -> String {
    format!("DOTENV_PRIVATE_KEY:{}", public_key_fingerprint(public_key))
}

fn sha256_file_hex(path: &Path) -> Result<String, String> {
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
    Ok(encode_hex(&hasher.finalize()))
}

fn encode_hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(TABLE[(byte >> 4) as usize] as char);
        output.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if !value.len().is_multiple_of(2) {
        return Err("hex value must have an even number of characters".to_string());
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let raw = value.as_bytes();
    for chunk in raw.chunks(2) {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("hex value contains non-hex characters".to_string()),
    }
}

fn nearest_dotenv_file(cwd: &Path) -> Option<PathBuf> {
    let mut current = fs::canonicalize(cwd).ok()?;
    loop {
        let candidate = current.join(".env");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !current.pop() {
            return None;
        }
    }
}

fn previous_dotenv_state() -> PreviousDotenvState {
    PreviousDotenvState {
        env_path: env::var(AV_DOTENV_FILE_ENV)
            .ok()
            .filter(|value| !value.is_empty()),
        keys: previous_dotenv_keys(),
    }
}

fn previous_dotenv_keys() -> Vec<String> {
    env::var(AV_DOTENV_KEYS_ENV)
        .ok()
        .map(|value| {
            value
                .split(':')
                .filter(|key| is_valid_dotenv_key_name(key))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn print_shell_unload(shell: DotenvShell, previous: &PreviousDotenvState) {
    if previous.env_path.is_some() || !previous.keys.is_empty() {
        print_shell_status_message(
            shell,
            &dotenv_unloading_status_message(
                "unloading",
                previous.env_path.as_deref(),
                previous.keys.len(),
            ),
        );
    }
    match shell {
        DotenvShell::Bash | DotenvShell::Zsh => {
            for key in &previous.keys {
                println!("unset {key};");
            }
            println!("unset {AV_DOTENV_FILE_ENV};");
            println!("unset {AV_DOTENV_DIGEST_ENV};");
            println!("unset {AV_DOTENV_KEYS_ENV};");
        }
        DotenvShell::Fish => {
            for key in &previous.keys {
                println!("set -e {key};");
            }
            println!("set -e {AV_DOTENV_FILE_ENV};");
            println!("set -e {AV_DOTENV_DIGEST_ENV};");
            println!("set -e {AV_DOTENV_KEYS_ENV};");
        }
    }
}

fn print_shell_exports(
    shell: DotenvShell,
    previous: &PreviousDotenvState,
    loaded: &DotenvLoadedSecrets,
) {
    print_shell_unload(shell, previous);
    let keys = loaded.values.keys().cloned().collect::<Vec<_>>();
    print_shell_status_message(
        shell,
        &dotenv_loading_status_message(&loaded.env_path, &keys),
    );
    match shell {
        DotenvShell::Bash | DotenvShell::Zsh => {
            for (key, value) in &loaded.values {
                println!("export {key}={};", shell_quote(value));
            }
            println!(
                "export {AV_DOTENV_FILE_ENV}={};",
                shell_quote(loaded.env_path.to_string_lossy().as_ref())
            );
            println!(
                "export {AV_DOTENV_DIGEST_ENV}={};",
                shell_quote(&loaded.env_sha256)
            );
            println!(
                "export {AV_DOTENV_KEYS_ENV}={};",
                shell_quote(&keys.join(":"))
            );
        }
        DotenvShell::Fish => {
            for (key, value) in &loaded.values {
                println!("set -gx {key} {};", shell_quote(value));
            }
            println!(
                "set -gx {AV_DOTENV_FILE_ENV} {};",
                shell_quote(loaded.env_path.to_string_lossy().as_ref())
            );
            println!(
                "set -gx {AV_DOTENV_DIGEST_ENV} {};",
                shell_quote(&loaded.env_sha256)
            );
            println!(
                "set -gx {AV_DOTENV_KEYS_ENV} {};",
                shell_quote(&keys.join(":"))
            );
        }
    }
}

fn print_shell_status_message(shell: DotenvShell, message: &str) {
    match shell {
        DotenvShell::Bash | DotenvShell::Zsh | DotenvShell::Fish => {
            println!("printf '%s\\n' {} >&2;", shell_quote(message));
        }
    }
}

fn dotenv_loading_status_message(env_path: &Path, keys: &[String]) -> String {
    let key_list = keys
        .iter()
        .map(|key| format!("+{key}"))
        .collect::<Vec<_>>()
        .join(" ");
    let path = dotenv_display_path(env_path);
    if key_list.is_empty() {
        format!("av dotenv: loading {path}")
    } else {
        format!("av dotenv: loading {path} {key_list}")
    }
}

fn dotenv_unloading_status_message(
    action: &str,
    env_path: Option<&str>,
    key_count: usize,
) -> String {
    let subject = env_path.unwrap_or("dotenv keys");
    format!(
        "av dotenv: {action} {subject} ({key_count} {})",
        if key_count == 1 { "key" } else { "keys" }
    )
}

fn dotenv_display_path(path: &Path) -> String {
    let Some(home) = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    else {
        return path.to_string_lossy().into_owned();
    };

    if path == home {
        return "~".to_string();
    }

    path.strip_prefix(&home)
        .ok()
        .filter(|relative| !relative.as_os_str().is_empty())
        .map(|relative| format!("~/{}", relative.to_string_lossy()))
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}

fn request_dotenv_approval_if_needed(
    mode: DotenvApprovalMode,
    env_path: &Path,
    project_root: &Path,
    env_sha256: &str,
    public_key_fingerprint: &str,
    keys: &[String],
    command: &[String],
) -> Result<(), String> {
    let entry = DotenvRememberedApprovalEntry {
        mode,
        env_file_path: env_path.to_string_lossy().into_owned(),
        project_root: project_root.to_string_lossy().into_owned(),
        env_sha256: env_sha256.to_string(),
        public_key_fingerprint: public_key_fingerprint.to_string(),
        keys: keys.to_vec(),
    };
    let (parent_process, process_ancestry) = dotenv_approval_process_context();
    if let Some(source) = dotenv_agent_export_rejection_source(mode)
        .or_else(|| dotenv_codex_export_rejection_source(mode, &parent_process, &process_ancestry))
    {
        let _ = dotenv_post_distributed_notification_with_object(
            DOTENV_AUTOMATIC_EXPORT_REJECTION_NOTIFICATION,
            &source,
        );
        return Err(dotenv_approval_denied_message(
            mode,
            &dotenv_codex_export_rejection_reason(&source),
        ));
    }
    let policy = load_dotenv_approval_policy().unwrap_or_default();
    if dotenv_remembered_approval_applies_to_mode(mode)
        && policy == DotenvApprovalPolicy::RememberApproved
        && load_dotenv_remembered_approvals()?.contains(&entry)
    {
        return Ok(());
    }
    request_dotenv_approval(&entry, command, parent_process, process_ancestry)?;
    Ok(())
}

fn dotenv_remembered_approval_applies_to_mode(mode: DotenvApprovalMode) -> bool {
    mode == DotenvApprovalMode::Run
}

fn dotenv_approval_process_context() -> (DotenvParentProcessSnapshot, Vec<DotenvProcessSnapshot>) {
    #[cfg(test)]
    if let Some(context) = test_dotenv_process_context() {
        return context;
    }

    let parent_process = dotenv_parent_process_snapshot();
    let process_ancestry = dotenv_process_ancestry_snapshot(parent_process.pid);
    (parent_process, process_ancestry)
}

#[cfg(test)]
fn test_dotenv_process_context() -> Option<(DotenvParentProcessSnapshot, Vec<DotenvProcessSnapshot>)>
{
    TEST_DOTENV_PROCESS_CONTEXT.with(|context| context.borrow().clone())
}

fn request_dotenv_approval(
    entry: &DotenvRememberedApprovalEntry,
    command: &[String],
    parent_process: DotenvParentProcessSnapshot,
    process_ancestry: Vec<DotenvProcessSnapshot>,
) -> Result<(), String> {
    let request_id = new_dotenv_approval_request_id()?;
    let approval_token = new_dotenv_approval_token()?;
    let request = DotenvApprovalRequestSnapshot {
        id: request_id.clone(),
        approval_token: approval_token.clone(),
        mode: entry.mode,
        env_file_path: entry.env_file_path.clone(),
        project_root: entry.project_root.clone(),
        env_sha256: entry.env_sha256.clone(),
        public_key_fingerprint: entry.public_key_fingerprint.clone(),
        keys: entry.keys.clone(),
        cwd: env::current_dir()
            .map_err(|err| format!("failed to resolve current directory: {err}"))?
            .to_string_lossy()
            .into_owned(),
        process_ancestry,
        parent_process,
        command: command.to_vec(),
    };
    let pending_url = prepare_dotenv_approval_request_files(&request_id)?;
    write_dotenv_json(&pending_url, &request)?;
    if let Err(err) = ping_dotenv_approval_app() {
        let _ = fs::remove_file(&pending_url);
        return Err(err);
    }
    wait_for_dotenv_decision(&request_id, &approval_token, entry.mode)
}

fn new_dotenv_approval_request_id() -> Result<String, String> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| format!("failed to compute request timestamp: {err}"))?
        .as_nanos();
    let mut random = [0_u8; 16];
    fill_dotenv_random_bytes(&mut random)?;
    Ok(format!(
        "{}-{timestamp}-{}",
        process::id(),
        encode_hex(&random)
    ))
}

fn new_dotenv_approval_token() -> Result<String, String> {
    let mut random = [0_u8; 32];
    fill_dotenv_random_bytes(&mut random)?;
    Ok(encode_hex(&random))
}

#[cfg(unix)]
fn fill_dotenv_random_bytes(bytes: &mut [u8]) -> Result<(), String> {
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(bytes))
        .map_err(|err| format!("failed to read random bytes for dotenv approval: {err}"))
}

#[cfg(not(unix))]
fn fill_dotenv_random_bytes(bytes: &mut [u8]) -> Result<(), String> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| format!("failed to compute request timestamp: {err}"))?
        .as_nanos();
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (timestamp.rotate_left((index % 8) as u32) as u8)
            ^ (process::id().rotate_left((index % 4) as u32) as u8);
    }
    Ok(())
}

fn prepare_dotenv_approval_request_files(id: &str) -> Result<PathBuf, String> {
    let decision_url = dotenv_decision_path(id)?;
    match fs::remove_file(&decision_url) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "failed to remove stale dotenv approval decision {}: {err}",
                decision_url.display()
            ));
        }
    }
    dotenv_pending_approval_path()
}

fn wait_for_dotenv_decision(
    id: &str,
    approval_token: &str,
    mode: DotenvApprovalMode,
) -> Result<(), String> {
    let decision_url = dotenv_decision_path(id)?;
    let pending_url = dotenv_pending_approval_path()?;
    loop {
        if let Ok(contents) = fs::read_to_string(&decision_url) {
            let decision: DotenvApprovalDecision = serde_json::from_str(&contents)
                .map_err(|err| format!("failed to decode dotenv approval decision: {err}"))?;
            if decision.id != id {
                return Err("dotenv approval decision id mismatch".to_string());
            }
            match decision.approval_token.as_deref() {
                Some(token) if token == approval_token => {}
                Some(_) => return Err("dotenv approval token mismatch".to_string()),
                None => {
                    return Err(
                        "dotenv approval decision missing token; update the approval client"
                            .to_string(),
                    );
                }
            }
            let _ = fs::remove_file(&pending_url);
            let _ = fs::remove_file(&decision_url);
            if decision.approved {
                return Ok(());
            }
            let reason = decision
                .reason
                .unwrap_or_else(|| "dotenv approval denied".to_string());
            return Err(dotenv_approval_denied_message(mode, &reason));
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn dotenv_agent_export_rejection_source(mode: DotenvApprovalMode) -> Option<String> {
    if mode != DotenvApprovalMode::Export {
        return None;
    }
    DOTENV_AGENT_EXPORT_ENV_MARKERS
        .iter()
        .find_map(|(name, source)| {
            env::var_os(name)
                .filter(|value| !value.is_empty())
                .map(|_| (*source).to_string())
        })
}

fn dotenv_codex_export_rejection_source(
    mode: DotenvApprovalMode,
    parent_process: &DotenvParentProcessSnapshot,
    process_ancestry: &[DotenvProcessSnapshot],
) -> Option<String> {
    if mode != DotenvApprovalMode::Export {
        return None;
    }
    dotenv_codex_process_source_name(
        parent_process.executable_path.as_deref(),
        parent_process.display_name.as_deref(),
    )
    .or_else(|| {
        process_ancestry.iter().find_map(|process| {
            dotenv_codex_process_source_name(
                process.executable_path.as_deref(),
                process.display_name.as_deref(),
            )
        })
    })
}

fn dotenv_codex_process_source_name(
    executable_path: Option<&str>,
    display_name: Option<&str>,
) -> Option<String> {
    if let Some(app_name) = executable_path.and_then(dotenv_codex_app_component_name) {
        return Some(app_name);
    }
    if let Some(display_name) = display_name
        && dotenv_codex_name_matches(display_name)
    {
        return Some(display_name.to_string());
    }
    executable_path
        .and_then(|path| Path::new(path).file_name())
        .and_then(|name| name.to_str())
        .filter(|name| dotenv_codex_name_matches(name))
        .map(str::to_string)
}

fn dotenv_codex_app_component_name(executable_path: &str) -> Option<String> {
    Path::new(executable_path)
        .components()
        .find_map(|component| {
            let name = component.as_os_str().to_str()?;
            let lower = name.to_ascii_lowercase();
            let app_name = lower.strip_suffix(".app")?;
            dotenv_codex_name_matches(app_name).then(|| name.to_string())
        })
}

fn dotenv_codex_name_matches(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    let normalized = lower.strip_suffix(".app").unwrap_or(&lower);
    matches!(normalized, "codex" | "openai codex")
}

fn dotenv_codex_export_rejection_reason(source: &str) -> String {
    format!("av dotenv export was auto-rejected because it was requested by {source}")
}

fn dotenv_approval_denied_message(mode: DotenvApprovalMode, reason: &str) -> String {
    if mode == DotenvApprovalMode::Export {
        format!("{reason}\n{DOTENV_EXPORT_DENIED_HINT}")
    } else {
        reason.to_string()
    }
}

fn load_dotenv_remembered_approvals() -> Result<DotenvRememberedApprovalStore, String> {
    let path = dotenv_system_remembered_approvals_path();
    load_dotenv_remembered_approvals_at_path(
        &path,
        dotenv_system_remembered_approvals_requires_root_control(),
    )
}

#[cfg(test)]
fn load_dotenv_remembered_approvals_for_test(
    path: &Path,
) -> Result<DotenvRememberedApprovalStore, String> {
    load_dotenv_remembered_approvals_at_path(path, false)
}

fn load_dotenv_remembered_approvals_at_path(
    path: &Path,
    require_root_controlled: bool,
) -> Result<DotenvRememberedApprovalStore, String> {
    if !path.exists() {
        return Ok(DotenvRememberedApprovalStore::default());
    }
    if require_root_controlled && !dotenv_system_file_is_trusted(path)? {
        return Ok(DotenvRememberedApprovalStore::default());
    }
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&contents)
        .map_err(|err| format!("failed to decode {}: {err}", path.display()))
}

fn remember_dotenv_approval(entry: DotenvRememberedApprovalEntry) -> Result<(), String> {
    let path = dotenv_system_remembered_approvals_path();
    remember_dotenv_approval_at_path(
        &path,
        entry,
        dotenv_system_remembered_approvals_requires_root_control(),
    )
}

pub(crate) fn clear_dotenv_remembered_approvals() -> Result<(), String> {
    let path = dotenv_system_remembered_approvals_path();
    clear_dotenv_remembered_approvals_at_path(
        &path,
        dotenv_system_remembered_approvals_requires_root_control(),
    )
}

#[cfg(test)]
fn remember_dotenv_approval_for_test(
    path: &Path,
    entry: DotenvRememberedApprovalEntry,
) -> Result<(), String> {
    remember_dotenv_approval_at_path(path, entry, false)
}

#[cfg(test)]
fn clear_dotenv_remembered_approvals_for_test(path: &Path) -> Result<(), String> {
    clear_dotenv_remembered_approvals_at_path(path, false)
}

fn remember_dotenv_approval_at_path(
    path: &Path,
    entry: DotenvRememberedApprovalEntry,
    require_root_controlled_parent: bool,
) -> Result<(), String> {
    let mut store = load_dotenv_remembered_approvals_at_path(path, require_root_controlled_parent)?;
    store.remember(entry);
    write_dotenv_system_json(path, &store, require_root_controlled_parent)
}

fn clear_dotenv_remembered_approvals_at_path(
    path: &Path,
    require_root_controlled_parent: bool,
) -> Result<(), String> {
    write_dotenv_system_json(
        path,
        &DotenvRememberedApprovalStore::default(),
        require_root_controlled_parent,
    )
}

pub(crate) fn remember_dotenv_approval_from_helper(
    mode: DotenvApprovalMode,
    env_file_path: &str,
    project_root: &str,
    env_sha256: &str,
    public_key_fingerprint: &str,
    mut keys: Vec<String>,
) -> Result<(), String> {
    if !dotenv_remembered_approval_applies_to_mode(mode) {
        return Ok(());
    }
    if load_dotenv_approval_policy()? != DotenvApprovalPolicy::RememberApproved {
        return Ok(());
    }
    validate_dotenv_approval_entry(
        mode,
        env_file_path,
        project_root,
        env_sha256,
        public_key_fingerprint,
        &mut keys,
    )
    .and_then(remember_dotenv_approval)
}

fn validate_dotenv_approval_entry(
    mode: DotenvApprovalMode,
    env_file_path: &str,
    project_root: &str,
    env_sha256: &str,
    public_key_fingerprint: &str,
    keys: &mut Vec<String>,
) -> Result<DotenvRememberedApprovalEntry, String> {
    validate_sha256_hex(env_sha256)?;
    if public_key_fingerprint.is_empty() {
        return Err("dotenv public key fingerprint is empty".to_string());
    }
    for key in keys.iter() {
        validate_dotenv_key_name(key)?;
    }
    keys.sort();
    keys.dedup();

    let env_path = resolve_dotenv_path(Path::new(env_file_path))?;
    let project_root_path = resolve_dotenv_path(Path::new(project_root))?;
    let expected_project_root = env_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    if project_root_path != expected_project_root {
        return Err("dotenv approval project root does not match env file".to_string());
    }
    let actual_sha256 = sha256_file_hex(&env_path)?;
    if actual_sha256 != env_sha256 {
        return Err("dotenv file changed before approval could be remembered".to_string());
    }
    let document = DotenvDocument::load(&env_path)?;
    let (_public_key_name, public_key) = document
        .public_key()
        .ok_or_else(|| format!("{} is missing DOTENV_PUBLIC_KEY", document.path.display()))?;
    if self::public_key_fingerprint(&public_key) != public_key_fingerprint {
        return Err("dotenv public key fingerprint mismatch".to_string());
    }
    let available_keys = document
        .lines
        .iter()
        .filter_map(|line| line.assignment.as_ref())
        .filter(|assignment| {
            !is_public_key_name(&assignment.key) && is_valid_dotenv_key_name(&assignment.key)
        })
        .map(|assignment| assignment.key.clone())
        .collect::<HashSet<_>>();
    if keys.iter().any(|key| !available_keys.contains(key)) {
        return Err("dotenv approval includes keys that are not in the env file".to_string());
    }

    Ok(DotenvRememberedApprovalEntry {
        mode,
        env_file_path: env_path.to_string_lossy().into_owned(),
        project_root: expected_project_root.to_string_lossy().into_owned(),
        env_sha256: actual_sha256,
        public_key_fingerprint: public_key_fingerprint.to_string(),
        keys: keys.clone(),
    })
}

pub(crate) fn load_dotenv_approval_policy() -> Result<DotenvApprovalPolicy, String> {
    let path = dotenv_system_policy_path();
    load_dotenv_approval_policy_at_path(&path, dotenv_system_policy_requires_root_control())
}

#[cfg(test)]
fn load_dotenv_approval_policy_for_test(path: &Path) -> Result<DotenvApprovalPolicy, String> {
    load_dotenv_approval_policy_at_path(path, false)
}

fn load_dotenv_approval_policy_at_path(
    path: &Path,
    require_root_controlled: bool,
) -> Result<DotenvApprovalPolicy, String> {
    if !path.exists() {
        return Ok(DotenvApprovalPolicy::ApproveEveryTime);
    }
    if require_root_controlled && !dotenv_system_file_is_trusted(path)? {
        return Ok(DotenvApprovalPolicy::ApproveEveryTime);
    }
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let policy_file: DotenvPolicyFile = serde_json::from_str(&contents)
        .map_err(|err| format!("failed to decode {}: {err}", path.display()))?;
    Ok(policy_file.approval_policy)
}

pub(crate) fn write_dotenv_approval_policy(policy: DotenvApprovalPolicy) -> Result<(), String> {
    let path = dotenv_system_policy_path();
    write_dotenv_approval_policy_at_path(
        &path,
        policy,
        dotenv_system_policy_requires_root_control(),
    )
}

#[cfg(test)]
fn write_dotenv_approval_policy_for_test(
    path: &Path,
    policy: DotenvApprovalPolicy,
) -> Result<(), String> {
    write_dotenv_approval_policy_at_path(path, policy, false)
}

fn write_dotenv_approval_policy_at_path(
    path: &Path,
    policy: DotenvApprovalPolicy,
    require_root_controlled_parent: bool,
) -> Result<(), String> {
    write_dotenv_system_json(
        path,
        &DotenvPolicyFile {
            approval_policy: policy,
        },
        require_root_controlled_parent,
    )
}

fn write_dotenv_system_json<T: Serialize>(
    path: &Path,
    value: &T,
    require_root_controlled_parent: bool,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("invalid dotenv system path {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
        .map_err(|err| format!("failed to chmod {}: {err}", parent.display()))?;
    if require_root_controlled_parent && !dotenv_system_directory_is_trusted(parent)? {
        return Err(format!(
            "dotenv approval policy directory is not root-controlled: {}",
            parent.display()
        ));
    }

    let temp_dir = TempDir::new_in(parent)
        .map_err(|err| format!("failed to create temp dir in {}: {err}", parent.display()))?;
    let temp_path = temp_dir.path().join(
        path.file_name()
            .unwrap_or_else(|| OsStr::new("dotenv-system.json")),
    );
    let payload = serde_json::to_vec_pretty(value)
        .map_err(|err| format!("failed to encode dotenv system JSON: {err}"))?;
    fs::write(&temp_path, payload)
        .map_err(|err| format!("failed to write {}: {err}", temp_path.display()))?;
    fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o644))
        .map_err(|err| format!("failed to chmod {}: {err}", temp_path.display()))?;
    fs::rename(&temp_path, path)
        .map_err(|err| format!("failed to install {}: {err}", path.display()))?;
    Ok(())
}

fn dotenv_system_file_is_trusted(path: &Path) -> Result<bool, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Ok(false);
    }
    let Some(parent) = path.parent() else {
        return Ok(false);
    };
    dotenv_system_directory_is_trusted(parent)
}

fn dotenv_system_directory_is_trusted(path: &Path) -> Result<bool, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
    Ok(metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
}

fn dotenv_system_policy_path() -> PathBuf {
    #[cfg(test)]
    if let Some(path) =
        env::var_os(AV_TEST_DOTENV_POLICY_PATH_ENV).filter(|value| !value.is_empty())
    {
        return PathBuf::from(path);
    }
    PathBuf::from(DOTENV_SYSTEM_POLICY_PATH)
}

fn dotenv_system_remembered_approvals_path() -> PathBuf {
    #[cfg(test)]
    if let Some(path) =
        env::var_os(AV_TEST_DOTENV_REMEMBERED_APPROVALS_PATH_ENV).filter(|value| !value.is_empty())
    {
        return PathBuf::from(path);
    }
    PathBuf::from(DOTENV_SYSTEM_REMEMBERED_APPROVALS_PATH)
}

fn dotenv_system_policy_requires_root_control() -> bool {
    #[cfg(test)]
    if env::var_os(AV_TEST_DOTENV_POLICY_PATH_ENV).is_some_and(|value| !value.is_empty()) {
        return false;
    }
    true
}

fn dotenv_system_remembered_approvals_requires_root_control() -> bool {
    #[cfg(test)]
    if env::var_os(AV_TEST_DOTENV_REMEMBERED_APPROVALS_PATH_ENV)
        .is_some_and(|value| !value.is_empty())
    {
        return false;
    }
    true
}

fn dotenv_parent_process_snapshot() -> DotenvParentProcessSnapshot {
    let pid = unsafe { libc::getppid() };
    let executable_path = dotenv_parent_process_path(pid);
    let display_name = dotenv_process_display_name(executable_path.as_deref());
    DotenvParentProcessSnapshot {
        pid,
        executable_path,
        display_name,
    }
}

fn dotenv_process_display_name(executable_path: Option<&str>) -> Option<String> {
    executable_path
        .and_then(|path| Path::new(path).file_name())
        .and_then(|name| name.to_str())
        .map(str::to_string)
}

#[cfg(target_os = "macos")]
fn dotenv_parent_process_path(pid: i32) -> Option<String> {
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
fn dotenv_parent_process_path(_pid: i32) -> Option<String> {
    None
}

fn dotenv_process_ancestry_snapshot(start_pid: i32) -> Vec<DotenvProcessSnapshot> {
    let mut ancestry = Vec::new();
    let mut seen = HashSet::new();
    let mut pid = start_pid;

    for _ in 0..16 {
        if pid <= 0 || !seen.insert(pid) {
            break;
        }
        let Some(snapshot) = dotenv_process_snapshot(pid) else {
            break;
        };
        let parent_pid = snapshot.parent_pid;
        ancestry.push(snapshot);
        if parent_pid <= 1 || parent_pid == pid {
            break;
        }
        pid = parent_pid;
    }

    ancestry
}

#[cfg(target_os = "macos")]
fn dotenv_process_snapshot(pid: i32) -> Option<DotenvProcessSnapshot> {
    let output = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "ppid=", "-o", "comm="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let line = String::from_utf8(output.stdout).ok()?;
    let (parent_pid, executable_path) = parse_dotenv_process_info_line(line.trim())?;
    let display_name = dotenv_process_display_name(executable_path.as_deref());
    Some(DotenvProcessSnapshot {
        pid,
        parent_pid,
        executable_path,
        display_name,
    })
}

#[cfg(not(target_os = "macos"))]
fn dotenv_process_snapshot(_pid: i32) -> Option<DotenvProcessSnapshot> {
    None
}

fn parse_dotenv_process_info_line(line: &str) -> Option<(i32, Option<String>)> {
    let line = line.trim_start();
    let split_at = line
        .char_indices()
        .find_map(|(index, character)| character.is_whitespace().then_some(index))?;
    let parent_pid = line[..split_at].trim().parse().ok()?;
    let executable_path = line[split_at..].trim();
    let executable_path = if executable_path.is_empty() {
        None
    } else {
        Some(executable_path.to_string())
    };
    Some((parent_pid, executable_path))
}

fn dotenv_user_approval_root() -> Result<PathBuf, String> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())?;
    Ok(home
        .join("Library")
        .join("Application Support")
        .join("Automic Vault")
        .join(DOTENV_USER_APPROVAL_SUBDIR))
}

fn dotenv_pending_approval_path() -> Result<PathBuf, String> {
    Ok(dotenv_user_approval_root()?.join("pending-approval.json"))
}

fn dotenv_decision_path(id: &str) -> Result<PathBuf, String> {
    Ok(dotenv_user_approval_root()?
        .join("decisions")
        .join(format!("{id}.json")))
}

fn write_dotenv_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("invalid dotenv approval path {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    secure_dotenv_approval_directory(parent)?;
    let payload = serde_json::to_vec_pretty(value)
        .map_err(|err| format!("failed to encode dotenv approval JSON: {err}"))?;
    fs::write(path, payload).map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    secure_dotenv_approval_file(path)?;
    Ok(())
}

fn secure_dotenv_approval_directory(path: &Path) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|err| format!("failed to chmod {}: {err}", path.display()))?;
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "decisions")
        && let Some(parent) = path.parent()
    {
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|err| format!("failed to chmod {}: {err}", parent.display()))?;
    }
    Ok(())
}

fn secure_dotenv_approval_file(path: &Path) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("failed to chmod {}: {err}", path.display()))
}

#[cfg(target_os = "macos")]
fn ping_dotenv_approval_app() -> Result<(), String> {
    let status = Command::new("/usr/bin/open")
        .args(["-b", GUI_APP_BUNDLE_IDENTIFIER])
        .status()
        .map_err(|err| format!("failed to ping Automic Vault.app: {err}"))?;
    if !status.success() {
        return Err("failed to ping Automic Vault.app for dotenv approval".to_string());
    }
    dotenv_post_distributed_notification(DOTENV_APPROVAL_NOTIFICATION)
}

#[cfg(not(target_os = "macos"))]
fn ping_dotenv_approval_app() -> Result<(), String> {
    Err("dotenv approvals are only available on macOS".to_string())
}

fn stream_redacted_output<R, W>(
    mut reader: R,
    mut writer: W,
    secrets: Vec<Vec<u8>>,
) -> Result<usize, String>
where
    R: Read,
    W: Write,
{
    let mut redactor = DotenvRedactor::new(secrets);
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|err| format!("failed to read process output: {err}"))?;
        if count == 0 {
            break;
        }
        let chunk = redactor.feed(&buffer[..count], false);
        writer
            .write_all(&chunk)
            .and_then(|_| writer.flush())
            .map_err(|err| format!("failed to write redacted output: {err}"))?;
    }
    let chunk = redactor.feed(&[], true);
    writer
        .write_all(&chunk)
        .and_then(|_| writer.flush())
        .map_err(|err| format!("failed to write redacted output: {err}"))?;
    Ok(redactor.redacted)
}

impl DotenvRedactor {
    fn new(mut secrets: Vec<Vec<u8>>) -> Self {
        secrets.retain(|secret| !secret.is_empty());
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        secrets.dedup();
        let hold_len = secrets
            .iter()
            .map(Vec::len)
            .max()
            .unwrap_or(1)
            .saturating_sub(1);
        Self {
            secrets,
            pending: Vec::new(),
            redacted: 0,
            hold_len,
        }
    }

    fn feed(&mut self, chunk: &[u8], final_chunk: bool) -> Vec<u8> {
        self.pending.extend_from_slice(chunk);
        let process_len = if final_chunk {
            self.pending.len()
        } else {
            self.pending.len().saturating_sub(self.hold_len)
        };
        let process = self.pending[..process_len].to_vec();
        self.pending = self.pending[process_len..].to_vec();
        self.redact_bytes(&process)
    }

    fn redact_bytes(&mut self, input: &[u8]) -> Vec<u8> {
        if self.secrets.is_empty() {
            return input.to_vec();
        }
        let mut output = Vec::with_capacity(input.len());
        let mut index = 0;
        while index < input.len() {
            if let Some(secret) = self
                .secrets
                .iter()
                .find(|secret| input[index..].starts_with(secret.as_slice()))
            {
                output.extend_from_slice(b"[REDACTED]");
                index += secret.len();
                self.redacted += 1;
            } else {
                output.push(input[index]);
                index += 1;
            }
        }
        output
    }
}

fn read_dotenv_secret() -> Result<String, String> {
    let mut stdin = io::stdin();
    let mut value = String::new();
    if stdin.is_terminal() {
        eprint!("Secret: ");
        io::stderr()
            .flush()
            .map_err(|err| format!("failed to flush prompt: {err}"))?;
        read_dotenv_secret_line_no_echo(&mut stdin, &mut value)?;
        eprintln!();
    } else {
        stdin
            .read_to_string(&mut value)
            .map_err(|err| format!("failed to read secret from stdin: {err}"))?;
    }
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err("empty dotenv secret value".to_string());
    }
    Ok(value)
}

fn read_dotenv_secret_line_no_echo(
    stdin: &mut io::Stdin,
    value: &mut String,
) -> Result<(), String> {
    let fd = stdin.as_raw_fd();
    let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
    if unsafe { libc::tcgetattr(fd, termios.as_mut_ptr()) } != 0 {
        return Err(format!(
            "failed to read terminal settings: {}",
            io::Error::last_os_error()
        ));
    }
    let original = unsafe { termios.assume_init() };
    let mut hidden = original;
    hidden.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
        return Err(format!(
            "failed to disable terminal echo: {}",
            io::Error::last_os_error()
        ));
    }
    let read_result = stdin.read_line(value);
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

fn disable_dotenv_core_dumps() -> Result<(), String> {
    let mut original = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, original.as_mut_ptr()) } != 0 {
        return Err(format!(
            "failed to read core dump limit: {}",
            io::Error::last_os_error()
        ));
    }
    let original = unsafe { original.assume_init() };
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: original.rlim_max,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0 {
        Ok(())
    } else {
        Err(format!(
            "failed to disable core dumps: {}",
            io::Error::last_os_error()
        ))
    }
}

fn print_dotenv_hook(program_name: &str, shell: DotenvShell) {
    match shell {
        DotenvShell::Bash => println!(
            r#"__av_dotenv_hook() {{
  local __av_dotenv;
  __av_dotenv="$({program_name} export --shell bash --cwd "$PWD")" || return $?;
  eval "$__av_dotenv";
}};
if [[ -n "${{PROMPT_COMMAND:-}}" ]]; then
  PROMPT_COMMAND="__av_dotenv_hook; $PROMPT_COMMAND";
else
  PROMPT_COMMAND="__av_dotenv_hook";
fi;
__av_dotenv_hook;"#
        ),
        DotenvShell::Zsh => println!(
            r#"__av_dotenv_hook() {{
  local __av_dotenv;
  __av_dotenv="$({program_name} export --shell zsh --cwd "$PWD")" || return $?;
  eval "$__av_dotenv";
}};
autoload -Uz add-zsh-hook;
add-zsh-hook chpwd __av_dotenv_hook;
__av_dotenv_hook;"#
        ),
        DotenvShell::Fish => println!(
            r#"function __av_dotenv_hook --on-variable PWD;
  {program_name} export --shell fish --cwd "$PWD" | source;
end;
__av_dotenv_hook;"#
        ),
    }
}

pub(crate) fn print_dotenv_usage(program_name: &str) {
    println!(
        "\
Usage: {program_name} <init|set|encrypt|import|keychain|hook|export|run> [options]

Loads encrypted dotenvx-compatible .env files with Automic Vault approval."
    );
}

fn print_dotenv_init_usage(program_name: &str) {
    println!("Usage: {program_name} init [--file .env]");
}

fn print_dotenv_set_usage(program_name: &str) {
    println!("Usage: {program_name} set [--file .env] KEY");
}

fn print_dotenv_encrypt_usage(program_name: &str) {
    println!(
        "Usage: {program_name} encrypt [--file .env] [--key KEY...] [--exclude-key KEY...] [--check]"
    );
}

fn print_dotenv_import_usage(program_name: &str) {
    println!("Usage: {program_name} import [--file .env] [--keys-file .env.keys]");
}

fn print_dotenv_keychain_usage(program_name: &str) {
    println!("Usage: {program_name} migrate [--replace] [--delete-legacy]");
}

fn print_dotenv_keychain_migrate_usage(program_name: &str) {
    println!("Usage: {program_name} migrate [--replace] [--delete-legacy]");
}

fn print_dotenv_hook_usage(program_name: &str) {
    println!("Usage: {program_name} hook zsh|bash|fish");
}

fn print_dotenv_export_usage(program_name: &str) {
    println!("Usage: {program_name} export --shell zsh|bash|fish [--cwd <path>]");
}

fn print_dotenv_run_usage(program_name: &str) {
    println!("Usage: {program_name} run [--file .env] [--] <command> [args...]");
}

impl DotenvPrivateKeyStore for KeychainDotenvPrivateKeyStore {
    fn load_private_key(&self, public_key: &str) -> Result<String, String> {
        let account = keychain_account_for_public_key(public_key);
        keychain_read_dotenv_private_key(DOTENV_KEYCHAIN_SERVICE, &account)
    }

    fn store_private_key(&self, public_key: &str, private_key: &str) -> Result<(), String> {
        let account = keychain_account_for_public_key(public_key);
        keychain_write_dotenv_private_key(DOTENV_KEYCHAIN_SERVICE, &account, private_key)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DotenvKeychainMigrationReport {
    discovered: usize,
    migrated: usize,
    skipped_existing: usize,
    missing_legacy: usize,
    deleted_legacy: usize,
}

trait DotenvKeychainBackend {
    fn read_new_if_present(
        &self,
        service: &str,
        account: &str,
        access_group: &str,
    ) -> Result<Option<String>, String>;
    fn write_new(
        &self,
        service: &str,
        account: &str,
        access_group: &str,
        value: &str,
    ) -> Result<(), String>;
    #[allow(dead_code)]
    fn delete_new(&self, service: &str, account: &str, access_group: &str) -> Result<bool, String>;
    fn read_legacy_if_present(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<String>, String>;
    fn enumerate_legacy_accounts(&self, service: &str) -> Result<Vec<String>, String>;
    fn delete_legacy(&self, service: &str, account: &str) -> Result<bool, String>;
}

struct SystemDotenvKeychainBackend;

fn dotenv_keychain_access_group() -> &'static str {
    option_env!("AV_DOTENV_KEYCHAIN_ACCESS_GROUP")
        .filter(|value| !value.is_empty())
        .unwrap_or(DOTENV_DEFAULT_KEYCHAIN_ACCESS_GROUP)
}

fn run_dotenv_keychain_migrate(options: &DotenvKeychainMigrateOptions) -> Result<(), String> {
    let report = migrate_dotenv_keychain(
        &SystemDotenvKeychainBackend,
        DOTENV_KEYCHAIN_SERVICE,
        dotenv_keychain_access_group(),
        options,
    )?;
    println!(
        "av dotenv keychain migrate: discovered {} legacy dotenv private keys; migrated {}; skipped existing {}; missing legacy {}; deleted legacy {}",
        report.discovered,
        report.migrated,
        report.skipped_existing,
        report.missing_legacy,
        report.deleted_legacy
    );
    Ok(())
}

fn migrate_dotenv_keychain(
    backend: &dyn DotenvKeychainBackend,
    service: &str,
    access_group: &str,
    options: &DotenvKeychainMigrateOptions,
) -> Result<DotenvKeychainMigrationReport, String> {
    let mut accounts = backend.enumerate_legacy_accounts(service)?;
    accounts.retain(|account| account.starts_with("DOTENV_PRIVATE_KEY:"));
    accounts.sort();
    accounts.dedup();

    let mut report = DotenvKeychainMigrationReport {
        discovered: accounts.len(),
        ..DotenvKeychainMigrationReport::default()
    };

    for account in accounts {
        if !options.replace
            && backend
                .read_new_if_present(service, &account, access_group)?
                .is_some()
        {
            report.skipped_existing += 1;
            continue;
        }

        let Some(legacy_value) = backend.read_legacy_if_present(service, &account)? else {
            report.missing_legacy += 1;
            continue;
        };
        validate_private_key_list(&legacy_value)
            .map_err(|err| format!("legacy dotenv private key {account} is invalid: {err}"))?;

        backend.write_new(service, &account, access_group, &legacy_value)?;
        match backend.read_new_if_present(service, &account, access_group)? {
            Some(value) if value == legacy_value => {}
            Some(_) => {
                return Err(format!(
                    "failed to verify migrated dotenv private key {account}: new keychain value differed"
                ));
            }
            None => {
                return Err(format!(
                    "failed to verify migrated dotenv private key {account}: new keychain item was not found"
                ));
            }
        }
        report.migrated += 1;

        if options.delete_legacy && backend.delete_legacy(service, &account)? {
            report.deleted_legacy += 1;
        }
    }

    Ok(report)
}

#[cfg(target_os = "macos")]
fn keychain_read_dotenv_private_key(service: &str, account: &str) -> Result<String, String> {
    keychain_read_dotenv_private_key_if_present(service, account)?.ok_or_else(|| {
        "failed to load dotenv private key: The specified item could not be found in the keychain. Run av dotenv import or av dotenv init.".to_string()
    })
}

#[cfg(target_os = "macos")]
fn keychain_read_dotenv_private_key_if_present(
    service: &str,
    account: &str,
) -> Result<Option<String>, String> {
    keychain_read_dotenv_private_key_if_present_with_backend(
        &SystemDotenvKeychainBackend,
        service,
        account,
        dotenv_keychain_access_group(),
    )
}

fn keychain_read_dotenv_private_key_if_present_with_backend(
    backend: &dyn DotenvKeychainBackend,
    service: &str,
    account: &str,
    access_group: &str,
) -> Result<Option<String>, String> {
    match backend.read_new_if_present(service, account, access_group) {
        Ok(Some(value)) => Ok(Some(value)),
        Ok(None) => backend.read_legacy_if_present(service, account),
        Err(new_error) => match backend.read_legacy_if_present(service, account) {
            Ok(Some(value)) => Ok(Some(value)),
            Ok(None) | Err(_) => Err(new_error),
        },
    }
}

#[cfg(target_os = "macos")]
impl DotenvKeychainBackend for SystemDotenvKeychainBackend {
    fn read_new_if_present(
        &self,
        _service: &str,
        account: &str,
        _access_group: &str,
    ) -> Result<Option<String>, String> {
        crate::vault::request_dotenv_keychain_load(account)
    }

    fn write_new(
        &self,
        _service: &str,
        account: &str,
        _access_group: &str,
        value: &str,
    ) -> Result<(), String> {
        crate::vault::request_dotenv_keychain_store(account, value)
    }

    fn delete_new(
        &self,
        _service: &str,
        account: &str,
        _access_group: &str,
    ) -> Result<bool, String> {
        crate::vault::request_dotenv_keychain_delete(account)
    }

    fn read_legacy_if_present(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<String>, String> {
        bridge_read_legacy_dotenv_private_key_if_present(service, account)
    }

    fn enumerate_legacy_accounts(&self, service: &str) -> Result<Vec<String>, String> {
        bridge_enumerate_legacy_dotenv_private_key_accounts(service)
    }

    fn delete_legacy(&self, service: &str, account: &str) -> Result<bool, String> {
        bridge_delete_legacy_dotenv_private_key(service, account)
    }
}

#[cfg(not(target_os = "macos"))]
impl DotenvKeychainBackend for SystemDotenvKeychainBackend {
    fn read_new_if_present(
        &self,
        _service: &str,
        _account: &str,
        _access_group: &str,
    ) -> Result<Option<String>, String> {
        Err("dotenv keychain integration is only available on macOS".to_string())
    }

    fn write_new(
        &self,
        _service: &str,
        _account: &str,
        _access_group: &str,
        _value: &str,
    ) -> Result<(), String> {
        Err("dotenv keychain integration is only available on macOS".to_string())
    }

    fn delete_new(
        &self,
        _service: &str,
        _account: &str,
        _access_group: &str,
    ) -> Result<bool, String> {
        Err("dotenv keychain integration is only available on macOS".to_string())
    }

    fn read_legacy_if_present(
        &self,
        _service: &str,
        _account: &str,
    ) -> Result<Option<String>, String> {
        Err("dotenv keychain integration is only available on macOS".to_string())
    }

    fn enumerate_legacy_accounts(&self, _service: &str) -> Result<Vec<String>, String> {
        Err("dotenv keychain integration is only available on macOS".to_string())
    }

    fn delete_legacy(&self, _service: &str, _account: &str) -> Result<bool, String> {
        Err("dotenv keychain integration is only available on macOS".to_string())
    }
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
fn bridge_read_dotenv_private_key_from_new_store_if_present(
    service: &str,
    account: &str,
    access_group: &str,
) -> Result<Option<String>, String> {
    unsafe extern "C" {
        fn isotope_copy_dotenv_private_key_with_status(
            service_cstr: *const c_char,
            account_cstr: *const c_char,
            access_group_cstr: *const c_char,
            error_cstr: *mut *mut c_char,
            status_out: *mut c_int,
        ) -> *mut c_char;
    }
    let service_cstr =
        CString::new(service).map_err(|_| "invalid keychain service name".to_string())?;
    let account_cstr =
        CString::new(account).map_err(|_| "invalid keychain account name".to_string())?;
    let access_group_cstr =
        CString::new(access_group).map_err(|_| "invalid keychain access group".to_string())?;
    let mut error = std::ptr::null_mut();
    let mut status = 0;
    let value = unsafe {
        isotope_copy_dotenv_private_key_with_status(
            service_cstr.as_ptr(),
            account_cstr.as_ptr(),
            access_group_cstr.as_ptr(),
            &mut error,
            &mut status,
        )
    };
    if value.is_null() {
        let message = unsafe { take_dotenv_bridge_string(error) }
            .unwrap_or_else(|| "keychain lookup failed".to_string());
        if status == ERR_SEC_ITEM_NOT_FOUND {
            return Ok(None);
        }
        return Err(dotenv_data_protection_keychain_error(
            "load",
            access_group,
            status,
            &message,
        ));
    }
    unsafe { take_dotenv_bridge_string(value) }
        .map(Some)
        .ok_or_else(|| "keychain returned invalid UTF-8".to_string())
}

#[cfg(target_os = "macos")]
fn bridge_read_legacy_dotenv_private_key_if_present(
    service: &str,
    account: &str,
) -> Result<Option<String>, String> {
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
        let message = unsafe { take_dotenv_bridge_string(error) }
            .unwrap_or_else(|| "keychain lookup failed".to_string());
        if status == ERR_SEC_ITEM_NOT_FOUND {
            return Ok(None);
        }
        return Err(format!("failed to load dotenv private key: {message}"));
    }
    unsafe { take_dotenv_bridge_string(value) }
        .map(Some)
        .ok_or_else(|| "keychain returned invalid UTF-8".to_string())
}

#[cfg(not(target_os = "macos"))]
fn keychain_read_dotenv_private_key(_service: &str, _account: &str) -> Result<String, String> {
    Err("dotenv keychain integration is only available on macOS".to_string())
}

#[cfg(not(target_os = "macos"))]
fn keychain_read_dotenv_private_key_if_present(
    _service: &str,
    _account: &str,
) -> Result<Option<String>, String> {
    Err("dotenv keychain integration is only available on macOS".to_string())
}

#[cfg(target_os = "macos")]
fn keychain_write_dotenv_private_key(
    service: &str,
    account: &str,
    value: &str,
) -> Result<(), String> {
    keychain_write_dotenv_private_key_with_backend(
        &SystemDotenvKeychainBackend,
        service,
        account,
        dotenv_keychain_access_group(),
        value,
    )
}

fn keychain_write_dotenv_private_key_with_backend(
    backend: &dyn DotenvKeychainBackend,
    service: &str,
    account: &str,
    access_group: &str,
    value: &str,
) -> Result<(), String> {
    backend.write_new(service, account, access_group, value)
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
fn bridge_write_dotenv_private_key_to_new_store(
    service: &str,
    account: &str,
    access_group: &str,
    value: &str,
) -> Result<(), String> {
    unsafe extern "C" {
        fn isotope_store_dotenv_private_key(
            service_cstr: *const c_char,
            account_cstr: *const c_char,
            access_group_cstr: *const c_char,
            value_cstr: *const c_char,
            error_cstr: *mut *mut c_char,
            status_out: *mut c_int,
        ) -> bool;
    }
    let service_cstr =
        CString::new(service).map_err(|_| "invalid keychain service name".to_string())?;
    let account_cstr =
        CString::new(account).map_err(|_| "invalid keychain account name".to_string())?;
    let access_group_cstr =
        CString::new(access_group).map_err(|_| "invalid keychain access group".to_string())?;
    let value_cstr = CString::new(value).map_err(|_| "invalid keychain private key".to_string())?;
    let mut error = std::ptr::null_mut();
    let mut status = 0;
    if unsafe {
        isotope_store_dotenv_private_key(
            service_cstr.as_ptr(),
            account_cstr.as_ptr(),
            access_group_cstr.as_ptr(),
            value_cstr.as_ptr(),
            &mut error,
            &mut status,
        )
    } {
        return Ok(());
    }
    let message = unsafe { take_dotenv_bridge_string(error) }
        .unwrap_or_else(|| "keychain write failed".to_string());
    Err(dotenv_data_protection_keychain_error(
        "store",
        access_group,
        status,
        &message,
    ))
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
fn bridge_delete_dotenv_private_key_from_new_store(
    service: &str,
    account: &str,
    access_group: &str,
) -> Result<bool, String> {
    unsafe extern "C" {
        fn isotope_delete_dotenv_private_key_with_status(
            service_cstr: *const c_char,
            account_cstr: *const c_char,
            access_group_cstr: *const c_char,
            error_cstr: *mut *mut c_char,
            status_out: *mut c_int,
        ) -> bool;
    }
    let service_cstr =
        CString::new(service).map_err(|_| "invalid keychain service name".to_string())?;
    let account_cstr =
        CString::new(account).map_err(|_| "invalid keychain account name".to_string())?;
    let access_group_cstr =
        CString::new(access_group).map_err(|_| "invalid keychain access group".to_string())?;
    let mut error = std::ptr::null_mut();
    let mut status = 0;
    if unsafe {
        isotope_delete_dotenv_private_key_with_status(
            service_cstr.as_ptr(),
            account_cstr.as_ptr(),
            access_group_cstr.as_ptr(),
            &mut error,
            &mut status,
        )
    } {
        return Ok(status != ERR_SEC_ITEM_NOT_FOUND);
    }
    let message = unsafe { take_dotenv_bridge_string(error) }
        .unwrap_or_else(|| "keychain delete failed".to_string());
    Err(dotenv_data_protection_keychain_error(
        "delete",
        access_group,
        status,
        &message,
    ))
}

#[cfg(target_os = "macos")]
fn bridge_enumerate_legacy_dotenv_private_key_accounts(
    service: &str,
) -> Result<Vec<String>, String> {
    unsafe extern "C" {
        fn isotope_copy_legacy_dotenv_private_key_accounts_json_with_status(
            service_cstr: *const c_char,
            error_cstr: *mut *mut c_char,
            status_out: *mut c_int,
        ) -> *mut c_char;
    }
    let service_cstr =
        CString::new(service).map_err(|_| "invalid keychain service name".to_string())?;
    let mut error = std::ptr::null_mut();
    let mut status = 0;
    let value = unsafe {
        isotope_copy_legacy_dotenv_private_key_accounts_json_with_status(
            service_cstr.as_ptr(),
            &mut error,
            &mut status,
        )
    };
    if value.is_null() {
        let message = unsafe { take_dotenv_bridge_string(error) }
            .unwrap_or_else(|| "keychain enumeration failed".to_string());
        return Err(format!(
            "failed to enumerate legacy dotenv private keys: {message}"
        ));
    }
    let json = unsafe { take_dotenv_bridge_string(value) }
        .ok_or_else(|| "legacy keychain account list returned invalid UTF-8".to_string())?;
    serde_json::from_str::<Vec<String>>(&json)
        .map_err(|err| format!("failed to parse legacy keychain account list: {err}"))
}

#[cfg(target_os = "macos")]
fn bridge_delete_legacy_dotenv_private_key(service: &str, account: &str) -> Result<bool, String> {
    unsafe extern "C" {
        fn isotope_delete_legacy_generic_password_with_status(
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
        isotope_delete_legacy_generic_password_with_status(
            service_cstr.as_ptr(),
            account_cstr.as_ptr(),
            &mut error,
            &mut status,
        )
    } {
        return Ok(status != ERR_SEC_ITEM_NOT_FOUND);
    }
    let message = unsafe { take_dotenv_bridge_string(error) }
        .unwrap_or_else(|| "keychain delete failed".to_string());
    Err(format!(
        "failed to delete legacy dotenv private key {account}: {message}"
    ))
}

#[cfg(target_os = "macos")]
fn dotenv_data_protection_keychain_error(
    action: &str,
    access_group: &str,
    status: c_int,
    message: &str,
) -> String {
    let mut error = format!(
        "failed to {action} dotenv private key in Data Protection keychain access group {access_group}: {message}"
    );
    if status == ERR_SEC_MISSING_ENTITLEMENT
        || message.to_ascii_lowercase().contains("entitlement")
        || message.to_ascii_lowercase().contains("access group")
    {
        error.push_str(
            "; ensure this binary is signed with a keychain-access-groups entitlement containing ",
        );
        error.push_str(access_group);
        error.push_str("; verify with `codesign -d --entitlements - <path>`");
    }
    error
}

#[cfg(not(target_os = "macos"))]
fn keychain_write_dotenv_private_key(
    _service: &str,
    _account: &str,
    _value: &str,
) -> Result<(), String> {
    Err("dotenv keychain integration is only available on macOS".to_string())
}

#[cfg(target_os = "macos")]
fn dotenv_post_distributed_notification(name: &str) -> Result<(), String> {
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
    Err(unsafe { take_dotenv_bridge_string(error) }
        .unwrap_or_else(|| "failed to post dotenv approval notification".to_string()))
}

#[cfg(target_os = "macos")]
fn dotenv_post_distributed_notification_with_object(
    name: &str,
    object: &str,
) -> Result<(), String> {
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
    Err(unsafe { take_dotenv_bridge_string(error) }
        .unwrap_or_else(|| "failed to post dotenv approval notification".to_string()))
}

#[cfg(not(target_os = "macos"))]
fn dotenv_post_distributed_notification_with_object(
    _name: &str,
    _object: &str,
) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "macos")]
unsafe fn take_dotenv_bridge_string(value: *mut c_char) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    use std::sync::Mutex;

    #[derive(Default)]
    struct StubDotenvPrivateKeyStore {
        private_keys: Mutex<BTreeMap<String, String>>,
    }

    impl DotenvPrivateKeyStore for StubDotenvPrivateKeyStore {
        fn load_private_key(&self, public_key: &str) -> Result<String, String> {
            self.private_keys
                .lock()
                .unwrap()
                .get(public_key)
                .cloned()
                .ok_or_else(|| "missing private key".to_string())
        }

        fn store_private_key(&self, public_key: &str, private_key: &str) -> Result<(), String> {
            self.private_keys
                .lock()
                .unwrap()
                .insert(public_key.to_string(), private_key.to_string());
            Ok(())
        }
    }

    #[derive(Default)]
    struct StubDotenvKeychainBackend {
        new_values: Mutex<BTreeMap<String, String>>,
        legacy_values: Mutex<BTreeMap<String, String>>,
        legacy_accounts: Mutex<Vec<String>>,
        new_writes: Mutex<Vec<String>>,
        legacy_deletes: Mutex<Vec<String>>,
        new_read_error: Mutex<Option<String>>,
    }

    impl StubDotenvKeychainBackend {
        fn with_legacy(account: &str, value: &str) -> Self {
            let backend = Self::default();
            backend
                .legacy_values
                .lock()
                .unwrap()
                .insert(account.to_string(), value.to_string());
            backend
                .legacy_accounts
                .lock()
                .unwrap()
                .push(account.to_string());
            backend
        }

        fn insert_new(&self, account: &str, value: &str) {
            self.new_values
                .lock()
                .unwrap()
                .insert(account.to_string(), value.to_string());
        }

        fn set_legacy_accounts(&self, accounts: Vec<&str>) {
            *self.legacy_accounts.lock().unwrap() =
                accounts.into_iter().map(str::to_string).collect();
        }

        fn set_new_read_error(&self, message: &str) {
            *self.new_read_error.lock().unwrap() = Some(message.to_string());
        }
    }

    impl DotenvKeychainBackend for StubDotenvKeychainBackend {
        fn read_new_if_present(
            &self,
            _service: &str,
            account: &str,
            _access_group: &str,
        ) -> Result<Option<String>, String> {
            if let Some(message) = self.new_read_error.lock().unwrap().clone() {
                return Err(message);
            }
            Ok(self.new_values.lock().unwrap().get(account).cloned())
        }

        fn write_new(
            &self,
            _service: &str,
            account: &str,
            _access_group: &str,
            value: &str,
        ) -> Result<(), String> {
            self.new_values
                .lock()
                .unwrap()
                .insert(account.to_string(), value.to_string());
            self.new_writes.lock().unwrap().push(account.to_string());
            Ok(())
        }

        fn delete_new(
            &self,
            _service: &str,
            account: &str,
            _access_group: &str,
        ) -> Result<bool, String> {
            Ok(self.new_values.lock().unwrap().remove(account).is_some())
        }

        fn read_legacy_if_present(
            &self,
            _service: &str,
            account: &str,
        ) -> Result<Option<String>, String> {
            Ok(self.legacy_values.lock().unwrap().get(account).cloned())
        }

        fn enumerate_legacy_accounts(&self, _service: &str) -> Result<Vec<String>, String> {
            Ok(self.legacy_accounts.lock().unwrap().clone())
        }

        fn delete_legacy(&self, _service: &str, account: &str) -> Result<bool, String> {
            self.legacy_deletes
                .lock()
                .unwrap()
                .push(account.to_string());
            Ok(self.legacy_values.lock().unwrap().remove(account).is_some())
        }
    }

    struct VerifyFailingDotenvKeychainBackend {
        account: String,
        legacy_value: String,
        new_value_after_write: Option<String>,
        wrote: Mutex<bool>,
    }

    impl VerifyFailingDotenvKeychainBackend {
        fn new(account: &str, legacy_value: &str, new_value_after_write: Option<String>) -> Self {
            Self {
                account: account.to_string(),
                legacy_value: legacy_value.to_string(),
                new_value_after_write,
                wrote: Mutex::new(false),
            }
        }
    }

    impl DotenvKeychainBackend for VerifyFailingDotenvKeychainBackend {
        fn read_new_if_present(
            &self,
            _service: &str,
            _account: &str,
            _access_group: &str,
        ) -> Result<Option<String>, String> {
            if *self.wrote.lock().unwrap() {
                Ok(self.new_value_after_write.clone())
            } else {
                Ok(None)
            }
        }

        fn write_new(
            &self,
            _service: &str,
            _account: &str,
            _access_group: &str,
            _value: &str,
        ) -> Result<(), String> {
            *self.wrote.lock().unwrap() = true;
            Ok(())
        }

        fn delete_new(
            &self,
            _service: &str,
            _account: &str,
            _access_group: &str,
        ) -> Result<bool, String> {
            Ok(false)
        }

        fn read_legacy_if_present(
            &self,
            _service: &str,
            account: &str,
        ) -> Result<Option<String>, String> {
            Ok((account == self.account).then(|| self.legacy_value.clone()))
        }

        fn enumerate_legacy_accounts(&self, _service: &str) -> Result<Vec<String>, String> {
            Ok(vec![self.account.clone()])
        }

        fn delete_legacy(&self, _service: &str, _account: &str) -> Result<bool, String> {
            Ok(false)
        }
    }

    fn dotenv_test_private_key(byte: u8) -> String {
        format!("{byte:064x}")
    }

    struct DotenvEnvGuard {
        previous: Vec<(String, Option<OsString>)>,
    }

    struct CoreDumpLimitGuard {
        original: Option<libc::rlimit>,
    }

    impl CoreDumpLimitGuard {
        fn capture() -> Self {
            let mut original = std::mem::MaybeUninit::<libc::rlimit>::uninit();
            let original =
                if unsafe { libc::getrlimit(libc::RLIMIT_CORE, original.as_mut_ptr()) } == 0 {
                    Some(unsafe { original.assume_init() })
                } else {
                    None
                };
            Self { original }
        }
    }

    impl Drop for CoreDumpLimitGuard {
        fn drop(&mut self) {
            if let Some(original) = self.original {
                unsafe {
                    libc::setrlimit(libc::RLIMIT_CORE, &original);
                }
            }
        }
    }

    fn with_core_dump_limit_restored(action: impl FnOnce()) {
        let core_dump_limit = CoreDumpLimitGuard::capture();
        action();
        drop(core_dump_limit);
    }

    #[test]
    fn dotenv_keychain_read_prefers_new_store_and_falls_back_to_legacy() {
        let account =
            "DOTENV_PRIVATE_KEY:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let legacy_value = dotenv_test_private_key(1);
        let new_value = dotenv_test_private_key(2);
        let backend = StubDotenvKeychainBackend::with_legacy(account, &legacy_value);

        assert_eq!(
            keychain_read_dotenv_private_key_if_present_with_backend(
                &backend,
                "service",
                account,
                "TEAM.group"
            )
            .unwrap(),
            Some(legacy_value.clone())
        );

        backend.insert_new(account, &new_value);
        assert_eq!(
            keychain_read_dotenv_private_key_if_present_with_backend(
                &backend,
                "service",
                account,
                "TEAM.group"
            )
            .unwrap(),
            Some(new_value)
        );
    }

    #[test]
    fn dotenv_keychain_read_falls_back_to_legacy_when_new_store_errors() {
        let account =
            "DOTENV_PRIVATE_KEY:abababababababababababababababababababababababababababababababab";
        let legacy_value = dotenv_test_private_key(9);
        let backend = StubDotenvKeychainBackend::with_legacy(account, &legacy_value);
        backend.set_new_read_error("broker unavailable");

        assert_eq!(
            keychain_read_dotenv_private_key_if_present_with_backend(
                &backend,
                "service",
                account,
                "TEAM.group"
            )
            .unwrap(),
            Some(legacy_value)
        );

        let missing_account =
            "DOTENV_PRIVATE_KEY:acacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac";
        assert_eq!(
            keychain_read_dotenv_private_key_if_present_with_backend(
                &backend,
                "service",
                missing_account,
                "TEAM.group"
            )
            .unwrap_err(),
            "broker unavailable"
        );
    }

    #[test]
    fn dotenv_keychain_write_uses_new_store_only() {
        let account =
            "DOTENV_PRIVATE_KEY:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let value = dotenv_test_private_key(3);
        let backend = StubDotenvKeychainBackend::default();

        keychain_write_dotenv_private_key_with_backend(
            &backend,
            "service",
            account,
            "TEAM.group",
            &value,
        )
        .unwrap();

        assert_eq!(
            backend.new_values.lock().unwrap().get(account),
            Some(&value)
        );
        assert!(backend.legacy_values.lock().unwrap().is_empty());
        assert_eq!(backend.new_writes.lock().unwrap().as_slice(), [account]);
    }

    #[test]
    fn dotenv_keychain_migration_counts_and_skips_existing_without_secrets() {
        let migrate_account =
            "DOTENV_PRIVATE_KEY:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let existing_account =
            "DOTENV_PRIVATE_KEY:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let missing_account =
            "DOTENV_PRIVATE_KEY:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let ignored_account =
            "OTHER:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let migrated_value = dotenv_test_private_key(4);
        let existing_value = dotenv_test_private_key(5);
        let backend = StubDotenvKeychainBackend::default();
        backend.set_legacy_accounts(vec![
            migrate_account,
            existing_account,
            missing_account,
            ignored_account,
            migrate_account,
        ]);
        backend
            .legacy_values
            .lock()
            .unwrap()
            .insert(migrate_account.to_string(), migrated_value.clone());
        backend
            .legacy_values
            .lock()
            .unwrap()
            .insert(existing_account.to_string(), existing_value.clone());
        backend.insert_new(existing_account, &existing_value);

        let report = migrate_dotenv_keychain(
            &backend,
            "service",
            "TEAM.group",
            &DotenvKeychainMigrateOptions::default(),
        )
        .unwrap();

        assert_eq!(
            report,
            DotenvKeychainMigrationReport {
                discovered: 3,
                migrated: 1,
                skipped_existing: 1,
                missing_legacy: 1,
                deleted_legacy: 0,
            }
        );
        assert_eq!(
            backend.new_values.lock().unwrap().get(migrate_account),
            Some(&migrated_value)
        );
        let report_debug = format!("{report:?}");
        assert!(!report_debug.contains(&migrated_value));
        assert!(!report_debug.contains(&existing_value));
    }

    #[test]
    fn dotenv_keychain_migration_replace_and_delete_legacy_after_verify() {
        let account =
            "DOTENV_PRIVATE_KEY:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let legacy_value = dotenv_test_private_key(6);
        let backend = StubDotenvKeychainBackend::with_legacy(account, &legacy_value);
        backend.insert_new(account, &dotenv_test_private_key(7));

        let report = migrate_dotenv_keychain(
            &backend,
            "service",
            "TEAM.group",
            &DotenvKeychainMigrateOptions {
                replace: true,
                delete_legacy: true,
            },
        )
        .unwrap();

        assert_eq!(
            report,
            DotenvKeychainMigrationReport {
                discovered: 1,
                migrated: 1,
                skipped_existing: 0,
                missing_legacy: 0,
                deleted_legacy: 1,
            }
        );
        assert_eq!(
            backend.new_values.lock().unwrap().get(account),
            Some(&legacy_value)
        );
        assert!(!backend.legacy_values.lock().unwrap().contains_key(account));
        assert_eq!(backend.legacy_deletes.lock().unwrap().as_slice(), [account]);
    }

    #[test]
    fn dotenv_keychain_migration_reports_verify_failures() {
        assert_eq!(
            dotenv_keychain_access_group(),
            DOTENV_DEFAULT_KEYCHAIN_ACCESS_GROUP
        );
        let account =
            "DOTENV_PRIVATE_KEY:1111111111111111111111111111111111111111111111111111111111111111";
        let legacy_value = dotenv_test_private_key(10);
        let mismatch_backend = VerifyFailingDotenvKeychainBackend::new(
            account,
            &legacy_value,
            Some(dotenv_test_private_key(11)),
        );
        assert!(
            migrate_dotenv_keychain(
                &mismatch_backend,
                "service",
                "TEAM.group",
                &DotenvKeychainMigrateOptions::default(),
            )
            .unwrap_err()
            .contains("new keychain value differed")
        );

        let missing_backend = VerifyFailingDotenvKeychainBackend::new(account, &legacy_value, None);
        assert!(
            migrate_dotenv_keychain(
                &missing_backend,
                "service",
                "TEAM.group",
                &DotenvKeychainMigrateOptions::default(),
            )
            .unwrap_err()
            .contains("new keychain item was not found")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn dotenv_data_protection_keychain_bridge_roundtrips_when_opted_in_and_entitled() {
        if std::env::var_os("AV_TEST_DOTENV_DP_KEYCHAIN").is_none() {
            eprintln!(
                "skipping dotenv DP keychain integration test; set AV_TEST_DOTENV_DP_KEYCHAIN=1 to run"
            );
            return;
        }

        let access_group = dotenv_keychain_access_group();
        let current_exe = std::env::current_exe().expect("current test executable");
        let entitlements = std::process::Command::new("/usr/bin/codesign")
            .args(["-d", "--entitlements", "-"])
            .arg(&current_exe)
            .output();
        let Ok(entitlements) = entitlements else {
            eprintln!("skipping dotenv DP keychain integration test; codesign is unavailable");
            return;
        };
        let entitlement_text = String::from_utf8_lossy(&entitlements.stdout);
        if !entitlement_text.contains(access_group) {
            eprintln!(
                "skipping dotenv DP keychain integration test; {} lacks keychain group {}",
                current_exe.display(),
                access_group
            );
            return;
        }

        let account = format!("DOTENV_PRIVATE_KEY:{:064x}", std::process::id());
        let value = dotenv_test_private_key(8);
        let _ = bridge_delete_dotenv_private_key_from_new_store(
            DOTENV_KEYCHAIN_SERVICE,
            &account,
            access_group,
        );
        bridge_write_dotenv_private_key_to_new_store(
            DOTENV_KEYCHAIN_SERVICE,
            &account,
            access_group,
            &value,
        )
        .unwrap();
        assert_eq!(
            bridge_read_dotenv_private_key_from_new_store_if_present(
                DOTENV_KEYCHAIN_SERVICE,
                &account,
                access_group
            )
            .unwrap(),
            Some(value)
        );
        assert!(
            bridge_delete_dotenv_private_key_from_new_store(
                DOTENV_KEYCHAIN_SERVICE,
                &account,
                access_group
            )
            .unwrap()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn dotenv_keychain_and_notification_bridges_reject_invalid_c_strings_before_ffi() {
        assert_eq!(
            bridge_read_dotenv_private_key_from_new_store_if_present(
                "bad\0service",
                "account",
                "TEAM.group"
            )
            .unwrap_err(),
            "invalid keychain service name"
        );
        assert_eq!(
            bridge_read_dotenv_private_key_from_new_store_if_present(
                "service",
                "bad\0account",
                "TEAM.group"
            )
            .unwrap_err(),
            "invalid keychain account name"
        );
        assert_eq!(
            bridge_write_dotenv_private_key_to_new_store(
                "bad\0service",
                "account",
                "TEAM.group",
                "value"
            )
            .unwrap_err(),
            "invalid keychain service name"
        );
        assert_eq!(
            bridge_write_dotenv_private_key_to_new_store(
                "service",
                "bad\0account",
                "TEAM.group",
                "value"
            )
            .unwrap_err(),
            "invalid keychain account name"
        );
        assert_eq!(
            bridge_write_dotenv_private_key_to_new_store(
                "service",
                "account",
                "TEAM.group",
                "bad\0value"
            )
            .unwrap_err(),
            "invalid keychain private key"
        );
        assert_eq!(
            dotenv_post_distributed_notification("bad\0name").unwrap_err(),
            "invalid distributed notification name"
        );
        assert_eq!(
            dotenv_post_distributed_notification_with_object("bad\0name", "object").unwrap_err(),
            "invalid distributed notification name"
        );
        assert_eq!(
            dotenv_post_distributed_notification_with_object("name", "bad\0object").unwrap_err(),
            "invalid distributed notification object"
        );
        unsafe {
            assert!(take_dotenv_bridge_string(std::ptr::null_mut()).is_none());
        }
    }

    impl DotenvEnvGuard {
        fn set(values: &[(&str, &str)]) -> Self {
            let previous = values
                .iter()
                .map(|(key, value)| {
                    let previous = env::var_os(key);
                    unsafe {
                        env::set_var(key, value);
                    }
                    ((*key).to_string(), previous)
                })
                .collect();
            Self { previous }
        }

        fn unset(keys: &[&str]) -> Self {
            let previous = keys
                .iter()
                .map(|key| {
                    let previous = env::var_os(key);
                    unsafe {
                        env::remove_var(key);
                    }
                    ((*key).to_string(), previous)
                })
                .collect();
            Self { previous }
        }
    }

    impl Drop for DotenvEnvGuard {
        fn drop(&mut self) {
            for (key, previous) in self.previous.drain(..).rev() {
                match previous {
                    Some(value) => unsafe {
                        env::set_var(&key, value);
                    },
                    None => unsafe {
                        env::remove_var(&key);
                    },
                }
            }
        }
    }

    struct DotenvProcessContextGuard {
        previous: Option<(DotenvParentProcessSnapshot, Vec<DotenvProcessSnapshot>)>,
    }

    impl DotenvProcessContextGuard {
        fn set(parent: DotenvParentProcessSnapshot, ancestry: Vec<DotenvProcessSnapshot>) -> Self {
            let previous = TEST_DOTENV_PROCESS_CONTEXT
                .with(|context| context.replace(Some((parent, ancestry))));
            Self { previous }
        }

        fn non_codex_shell() -> Self {
            Self::set(
                DotenvParentProcessSnapshot {
                    pid: 100,
                    executable_path: Some("/bin/zsh".to_string()),
                    display_name: Some("zsh".to_string()),
                },
                vec![DotenvProcessSnapshot {
                    pid: 100,
                    parent_pid: 1,
                    executable_path: Some("/bin/zsh".to_string()),
                    display_name: Some("zsh".to_string()),
                }],
            )
        }

        fn codex_shell() -> Self {
            Self::set(
                DotenvParentProcessSnapshot {
                    pid: 100,
                    executable_path: Some("/bin/zsh".to_string()),
                    display_name: Some("zsh".to_string()),
                },
                vec![
                    DotenvProcessSnapshot {
                        pid: 100,
                        parent_pid: 200,
                        executable_path: Some("/bin/zsh".to_string()),
                        display_name: Some("zsh".to_string()),
                    },
                    DotenvProcessSnapshot {
                        pid: 200,
                        parent_pid: 1,
                        executable_path: Some(
                            "/Applications/Codex.app/Contents/MacOS/Codex".to_string(),
                        ),
                        display_name: Some("Codex".to_string()),
                    },
                ],
            )
        }
    }

    impl Drop for DotenvProcessContextGuard {
        fn drop(&mut self) {
            TEST_DOTENV_PROCESS_CONTEXT.with(|context| {
                context.replace(self.previous.take());
            });
        }
    }

    fn remembered_entry_for(
        env_path: &Path,
        mode: DotenvApprovalMode,
        public_key: &str,
        keys: &[&str],
    ) -> DotenvRememberedApprovalEntry {
        let env_path = fs::canonicalize(env_path).unwrap();
        DotenvRememberedApprovalEntry {
            mode,
            env_file_path: env_path.to_string_lossy().into_owned(),
            project_root: env_path.parent().unwrap().to_string_lossy().into_owned(),
            env_sha256: sha256_file_hex(&env_path).unwrap(),
            public_key_fingerprint: public_key_fingerprint(public_key),
            keys: keys.iter().map(|key| (*key).to_string()).collect(),
        }
    }

    fn dotenv_agent_export_env_marker_names() -> Vec<&'static str> {
        DOTENV_AGENT_EXPORT_ENV_MARKERS
            .iter()
            .map(|(name, _source)| *name)
            .collect()
    }

    #[test]
    fn dotenv_parse_handles_comments_quotes_and_public_key() {
        let doc = DotenvDocument::parse(
            PathBuf::from(".env"),
            "DOTENV_PUBLIC_KEY=abc\nFOO=\"bar\\n baz\" # comment\nexport BAR='literal#x'\n",
        );
        assert_eq!(
            doc.public_key(),
            Some(("DOTENV_PUBLIC_KEY".to_string(), "abc".to_string()))
        );
        assert_eq!(doc.value("FOO").unwrap(), "bar\n baz");
        assert_eq!(doc.value("BAR").unwrap(), "literal#x");
    }

    #[test]
    fn dotenv_document_preserves_comments_when_setting() {
        let mut doc =
            DotenvDocument::parse(PathBuf::from(".env"), "# hello\nFOO=old\n\nBAR=keep\n");
        doc.set_value("FOO", "new");
        doc.set_value("BAZ", "space value");
        let rendered = doc.render();
        assert!(rendered.contains("# hello\n"));
        assert!(rendered.contains("FOO=\"new\"\n"));
        assert!(rendered.contains("BAR=keep\n"));
        assert!(rendered.contains("BAZ=\"space value\"\n"));
    }

    #[test]
    fn dotenv_crypto_roundtrips_with_generated_keypair() {
        let keypair = generate_dotenv_keypair(Path::new(".env"));
        let encrypted = encrypt_dotenv_value("secret value", &keypair.public_key).unwrap();
        assert!(encrypted.starts_with(ENCRYPTED_PREFIX));
        let decrypted = decrypt_dotenv_value("FOO", &encrypted, &keypair.private_key).unwrap();
        assert_eq!(decrypted, "secret value");
    }

    #[test]
    fn dotenv_known_eciesjs_fixture_decrypts() {
        let private_key = "e520872701d9ec44dbac2eab85512ad14ad0c42e01de56d7b528abd8524fcb47";
        let encrypted = "encrypted:BHvhiFrrSNTU2wyZKZZyXTJkeE/viMW2B4L40PlAwhMif8P5BPhG1ew9D7pmU3VFAejrrcQhqjiSog/vM8/wIGBHBYpM+0776ulrLQGbSrLtzjMyh0ig0AimnI9YFrctRb2bWkG7bqASerIwV+xvzQ==";
        let decrypted = decrypt_dotenv_value("HELLO", encrypted, private_key).unwrap();
        assert_eq!(decrypted, "hello world\u{1f30d}");
    }

    #[test]
    fn dotenv_redactor_catches_chunk_boundaries() {
        let mut redactor = DotenvRedactor::new(vec![b"secret-token".to_vec()]);
        let mut out = redactor.feed(b"before secret", false);
        out.extend(redactor.feed(b"-token after", true));
        assert_eq!(String::from_utf8(out).unwrap(), "before [REDACTED] after");
        assert_eq!(redactor.redacted, 1);

        let mut redactor = DotenvRedactor::new(vec![b"secret-token".to_vec()]);
        let mut out = redactor.feed(b"secret", false);
        out.extend(redactor.feed(b"-token", true));
        assert_eq!(String::from_utf8(out).unwrap(), "[REDACTED]");
        assert_eq!(redactor.redacted, 1);
    }

    #[test]
    fn dotenv_shell_exports_unset_previous_keys() {
        let _lock = global_test_env_lock().lock().unwrap();
        let _env = DotenvEnvGuard::set(&[("HOME", "/tmp")]);
        let loaded = DotenvLoadedSecrets {
            env_path: PathBuf::from("/tmp/project/.env"),
            project_root: PathBuf::from("/tmp/project"),
            env_sha256: "abc".to_string(),
            public_key_fingerprint: "def".to_string(),
            values: BTreeMap::from([("FOO".to_string(), "bar baz".to_string())]),
        };
        assert_eq!(shell_quote("bar baz"), "'bar baz'");
        assert_eq!(loaded.values["FOO"], "bar baz");
        assert_eq!(
            dotenv_loading_status_message(
                Path::new("/tmp/project/.env"),
                &["FOO".to_string(), "BAR".to_string()]
            ),
            "av dotenv: loading ~/project/.env +FOO +BAR"
        );
        assert_eq!(
            dotenv_unloading_status_message("unloading", None, 2),
            "av dotenv: unloading dotenv keys (2 keys)"
        );
        assert_eq!(
            dotenv_display_path(Path::new("/var/tmp/project/.env")),
            "/var/tmp/project/.env"
        );
    }

    #[test]
    fn dotenv_parse_encrypt_options_collects_multiple_keys() {
        let options = parse_dotenv_encrypt(
            "av dotenv",
            vec![
                OsString::from("--key"),
                OsString::from("FOO"),
                OsString::from("BAR"),
                OsString::from("--exclude-key"),
                OsString::from("BAZ"),
                OsString::from("--check"),
            ]
            .into_iter(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(options.include_keys, vec!["BAR", "FOO"]);
        assert_eq!(options.exclude_keys, vec!["BAZ"]);
        assert!(options.check);
    }

    #[test]
    #[cfg(unix)]
    fn dotenv_approval_modes_and_parser_edges_cover_raw_values() {
        assert_eq!(DotenvApprovalMode::Export.raw_value(), "export");
        assert_eq!(DotenvApprovalMode::Run.raw_value(), "run");
        assert_eq!(
            DotenvApprovalMode::from_raw_value("export").unwrap(),
            DotenvApprovalMode::Export
        );
        assert_eq!(
            DotenvApprovalMode::from_raw_value("run").unwrap(),
            DotenvApprovalMode::Run
        );
        assert_eq!(
            DotenvApprovalMode::from_raw_value("bogus").unwrap_err(),
            "unknown dotenv approval mode: bogus"
        );
        assert!(!dotenv_remembered_approval_applies_to_mode(
            DotenvApprovalMode::Export
        ));
        assert!(dotenv_remembered_approval_applies_to_mode(
            DotenvApprovalMode::Run
        ));
        assert_eq!(
            DotenvApprovalPolicy::ApproveEveryTime.raw_value(),
            "approve_every_time"
        );
        assert_eq!(
            DotenvApprovalPolicy::RememberApproved.raw_value(),
            "remember_approved"
        );
        assert_eq!(
            DotenvApprovalPolicy::from_raw_value("approve_every_time").unwrap(),
            DotenvApprovalPolicy::ApproveEveryTime
        );
        assert_eq!(
            DotenvApprovalPolicy::from_raw_value("remember_approved").unwrap(),
            DotenvApprovalPolicy::RememberApproved
        );
        assert_eq!(
            DotenvApprovalPolicy::from_raw_value("bogus").unwrap_err(),
            "unknown dotenv approval policy: bogus"
        );

        assert!(
            parse_dotenv_init("av dotenv", [OsString::from("--help")].into_iter())
                .unwrap()
                .is_none()
        );
        assert!(
            parse_dotenv_init("av dotenv", [OsString::from("--version")].into_iter())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            parse_dotenv_init("av dotenv", [OsString::from("--bogus")].into_iter()).unwrap_err(),
            "unknown dotenv init argument '--bogus'"
        );
        assert_eq!(
            parse_dotenv_init("av dotenv", [OsString::from("--file")].into_iter()).unwrap_err(),
            "missing value for --file"
        );
        assert_eq!(
            parse_dotenv_init(
                "av dotenv",
                [OsString::from("--file"), OsString::from(".env.test")].into_iter()
            )
            .unwrap()
            .unwrap()
            .file,
            PathBuf::from(".env.test")
        );

        assert_eq!(
            parse_dotenv_export("av dotenv", [OsString::from("--cwd")].into_iter()).unwrap_err(),
            "missing value for --cwd"
        );
        let export = parse_dotenv_export(
            "av dotenv",
            [OsString::from("--shell"), OsString::from("bash")].into_iter(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(export.shell, DotenvShell::Bash);
        assert!(export.cwd.is_absolute());

        let run = parse_dotenv_run(
            "av dotenv",
            [
                OsString::from("/bin/echo"),
                OsString::from("--file"),
                OsString::from("literal"),
            ]
            .into_iter(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(run.command, OsString::from("/bin/echo"));
        assert_eq!(
            run.args,
            vec![OsString::from("--file"), OsString::from("literal")]
        );

        assert_eq!(
            parse_dotenv_encrypt(
                "av dotenv",
                [OsString::from("--key"), OsString::from_vec(vec![0xff])].into_iter()
            )
            .unwrap_err(),
            "--key value must be valid UTF-8"
        );
    }

    #[test]
    fn dotenv_init_and_encrypt_use_stub_store() {
        let temp = TempDir::new().unwrap();
        let env_path = temp.path().join(".env");
        fs::write(&env_path, "API_KEY=sk-test-secret\n").unwrap();
        let store = StubDotenvPrivateKeyStore::default();
        run_dotenv_encrypt(
            &DotenvEncryptOptions {
                file: env_path.clone(),
                include_keys: Vec::new(),
                exclude_keys: Vec::new(),
                check: false,
            },
            &store,
        )
        .unwrap();
        let output = fs::read_to_string(env_path).unwrap();
        assert!(output.starts_with(
            "# You can use these keys by running `av dotenv run SCRIPT.ext`.\n\
             # The human operator will be prompted to allow it.\n\
             # Output will be monitored to occlude secrets.\n\n"
        ));
        assert!(output.contains("DOTENV_PUBLIC_KEY"));
        assert!(output.contains("API_KEY=\"encrypted:"));
    }

    #[test]
    fn dotenv_init_check_and_runtime_helpers_cover_edges() {
        let _lock = global_test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let env_path = temp.path().join(".env");
        let store = StubDotenvPrivateKeyStore::default();

        run_dotenv_init(
            &DotenvFileOption {
                file: env_path.clone(),
            },
            &store,
        )
        .unwrap();
        let initialized = fs::read_to_string(&env_path).unwrap();
        assert!(initialized.contains("DOTENV_PUBLIC_KEY"));
        assert!(
            run_dotenv_init(
                &DotenvFileOption {
                    file: env_path.clone(),
                },
                &store,
            )
            .unwrap_err()
            .contains("already has a DOTENV_PUBLIC_KEY")
        );

        run_dotenv_encrypt(
            &DotenvEncryptOptions {
                file: env_path.clone(),
                include_keys: Vec::new(),
                exclude_keys: Vec::new(),
                check: true,
            },
            &store,
        )
        .unwrap();

        let dispatch_env = temp.path().join("dispatch.env");
        dispatch_dotenv(
            "av dotenv",
            [
                OsString::from("init"),
                OsString::from("--file"),
                OsString::from(dispatch_env.as_os_str()),
            ]
            .into_iter(),
            &store,
        )
        .unwrap();
        dispatch_dotenv(
            "av dotenv",
            [OsString::from("hook"), OsString::from("fish")].into_iter(),
            &store,
        )
        .unwrap();
        dispatch_dotenv(
            "av dotenv",
            [
                OsString::from("encrypt"),
                OsString::from("--file"),
                OsString::from(dispatch_env.as_os_str()),
                OsString::from("--check"),
            ]
            .into_iter(),
            &store,
        )
        .unwrap();

        let mut stdin = io::stdin();
        if !stdin.is_terminal() {
            let mut secret = String::new();
            assert!(
                read_dotenv_secret_line_no_echo(&mut stdin, &mut secret)
                    .unwrap_err()
                    .contains("failed to read terminal settings")
            );
        }
        with_core_dump_limit_restored(|| disable_dotenv_core_dumps().unwrap());

        let parent = dotenv_parent_process_snapshot();
        assert!(parent.pid > 0);
        assert_eq!(
            dotenv_process_display_name(Some(
                "/Applications/Automic Vault.app/Contents/MacOS/Automic Vault"
            ))
            .as_deref(),
            Some("Automic Vault")
        );
        assert!(dotenv_process_display_name(None).is_none());
        let _snapshot = dotenv_process_snapshot(process::id() as i32);
        let ancestry = dotenv_process_ancestry_snapshot(process::id() as i32);
        if let Some(first) = ancestry.first() {
            assert!(first.pid > 0);
        }

        let home = temp.path().join("home");
        let home_str = home.to_str().unwrap();
        let _home_env = DotenvEnvGuard::set(&[("HOME", home_str)]);
        assert_eq!(dotenv_display_path(&home), "~");
        drop(_home_env);
        let _no_home = DotenvEnvGuard::unset(&["HOME"]);
        assert_eq!(
            dotenv_display_path(Path::new("/var/tmp/project/.env")),
            "/var/tmp/project/.env"
        );
    }

    #[test]
    fn dotenv_codex_export_auto_rejection_matches_process_tree() {
        let shell_parent = DotenvParentProcessSnapshot {
            pid: 100,
            executable_path: Some("/bin/zsh".to_string()),
            display_name: Some("zsh".to_string()),
        };
        let codex_ancestry = vec![
            DotenvProcessSnapshot {
                pid: 100,
                parent_pid: 200,
                executable_path: Some("/bin/zsh".to_string()),
                display_name: Some("zsh".to_string()),
            },
            DotenvProcessSnapshot {
                pid: 200,
                parent_pid: 1,
                executable_path: Some("/Applications/Codex.app/Contents/MacOS/Codex".to_string()),
                display_name: Some("Codex".to_string()),
            },
        ];
        assert_eq!(
            dotenv_codex_export_rejection_source(
                DotenvApprovalMode::Export,
                &shell_parent,
                &codex_ancestry,
            )
            .as_deref(),
            Some("Codex.app")
        );
        assert!(
            dotenv_codex_export_rejection_source(
                DotenvApprovalMode::Run,
                &shell_parent,
                &codex_ancestry,
            )
            .is_none()
        );

        let codex_parent = DotenvParentProcessSnapshot {
            pid: 201,
            executable_path: Some("/usr/local/bin/codex".to_string()),
            display_name: Some("codex".to_string()),
        };
        assert_eq!(
            dotenv_codex_export_rejection_source(DotenvApprovalMode::Export, &codex_parent, &[])
                .as_deref(),
            Some("codex")
        );
        let vscode_ancestry = vec![DotenvProcessSnapshot {
            pid: 202,
            parent_pid: 1,
            executable_path: Some("/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)".to_string()),
            display_name: Some("Code Helper (Plugin)".to_string()),
        }];
        assert!(
            dotenv_codex_export_rejection_source(
                DotenvApprovalMode::Export,
                &shell_parent,
                &vscode_ancestry,
            )
            .is_none()
        );
        assert!(dotenv_codex_export_rejection_reason("Codex.app").contains("Codex.app"));
    }

    #[test]
    fn dotenv_codex_export_auto_rejection_preempts_remembered_approval() {
        let _lock = global_test_env_lock().lock().unwrap();
        let agent_env_markers = dotenv_agent_export_env_marker_names();
        let _agent_env = DotenvEnvGuard::unset(&agent_env_markers);
        let _process_context = DotenvProcessContextGuard::codex_shell();
        let temp = TempDir::new().unwrap();
        let policy_path = temp.path().join("policy.json");
        let remembered_path = temp.path().join("remembered-approvals.json");
        let policy_path_str = policy_path.to_str().unwrap();
        let remembered_path_str = remembered_path.to_str().unwrap();
        let _env = DotenvEnvGuard::set(&[
            (AV_TEST_DOTENV_POLICY_PATH_ENV, policy_path_str),
            (
                AV_TEST_DOTENV_REMEMBERED_APPROVALS_PATH_ENV,
                remembered_path_str,
            ),
        ]);
        write_dotenv_approval_policy(DotenvApprovalPolicy::RememberApproved).unwrap();
        let entry = DotenvRememberedApprovalEntry {
            mode: DotenvApprovalMode::Export,
            env_file_path: "/tmp/project/.env".to_string(),
            project_root: "/tmp/project".to_string(),
            env_sha256: "sha".to_string(),
            public_key_fingerprint: "fingerprint".to_string(),
            keys: vec!["FOO".to_string()],
        };
        remember_dotenv_approval(entry.clone()).unwrap();

        let error = request_dotenv_approval_if_needed(
            entry.mode,
            Path::new(&entry.env_file_path),
            Path::new(&entry.project_root),
            &entry.env_sha256,
            &entry.public_key_fingerprint,
            &entry.keys,
            &[],
        )
        .unwrap_err();

        assert!(error.contains("auto-rejected"), "{error}");
        assert!(error.contains("Codex.app"), "{error}");
        assert!(error.contains("hint: use `av dotenv run`"), "{error}");
    }

    #[test]
    fn dotenv_agent_env_export_auto_rejection_preempts_remembered_approval() {
        let _lock = global_test_env_lock().lock().unwrap();
        let _process_context = DotenvProcessContextGuard::non_codex_shell();
        let temp = TempDir::new().unwrap();
        let policy_path = temp.path().join("policy.json");
        let remembered_path = temp.path().join("remembered-approvals.json");
        let policy_path_str = policy_path.to_str().unwrap();
        let remembered_path_str = remembered_path.to_str().unwrap();
        let _env = DotenvEnvGuard::set(&[
            (AV_TEST_DOTENV_POLICY_PATH_ENV, policy_path_str),
            (
                AV_TEST_DOTENV_REMEMBERED_APPROVALS_PATH_ENV,
                remembered_path_str,
            ),
            ("CODEX_SHELL", "1"),
        ]);
        write_dotenv_approval_policy(DotenvApprovalPolicy::RememberApproved).unwrap();
        let entry = DotenvRememberedApprovalEntry {
            mode: DotenvApprovalMode::Export,
            env_file_path: "/tmp/project/.env".to_string(),
            project_root: "/tmp/project".to_string(),
            env_sha256: "sha".to_string(),
            public_key_fingerprint: "fingerprint".to_string(),
            keys: vec!["FOO".to_string()],
        };
        remember_dotenv_approval(entry.clone()).unwrap();

        let error = request_dotenv_approval_if_needed(
            entry.mode,
            Path::new(&entry.env_file_path),
            Path::new(&entry.project_root),
            &entry.env_sha256,
            &entry.public_key_fingerprint,
            &entry.keys,
            &[],
        )
        .unwrap_err();

        assert!(error.contains("auto-rejected"), "{error}");
        assert!(error.contains("Codex"), "{error}");
        assert!(error.contains("hint: use `av dotenv run`"), "{error}");
    }

    #[test]
    fn dotenv_agent_export_rejects_before_private_key_lookup() {
        let _lock = global_test_env_lock().lock().unwrap();
        let _process_context = DotenvProcessContextGuard::non_codex_shell();
        let temp = TempDir::new().unwrap();
        let env_path = temp.path().join(".env");
        let keypair = generate_dotenv_keypair(&env_path);
        fs::write(
            &env_path,
            format!("DOTENV_PUBLIC_KEY={}\nFOO=plain\n", keypair.public_key),
        )
        .unwrap();
        let _env = DotenvEnvGuard::set(&[("CODEX_SHELL", "1")]);
        let store = StubDotenvPrivateKeyStore::default();

        let error = load_dotenv_secrets(&env_path, DotenvApprovalMode::Export, &[], &store, None)
            .unwrap_err();

        assert!(error.contains("auto-rejected"), "{error}");
        assert!(!error.contains("stub private key"), "{error}");
    }

    #[test]
    fn dotenv_encryptable_keys_auto_select_secret_shaped_plaintext() {
        let ordinary = DotenvDocument::parse(
            PathBuf::from(".env"),
            "DOTENV_PUBLIC_KEY=abc\nMIN_MACOS_VERSION=26.0\nNUKE_HELPER_VERSION=12\nTEAM_COMMON_NAME=\"Developer ID Application: Example\"\nTEAM_IDENTIFIER=ZU76A67LGU\nAWS_ACCOUNT_ID=123456789012\nAPI_BASE_URL=https://api.example.test\nAUTH_TOKEN_URL=https://auth.example.test/oauth/token\nNEXT_PUBLIC_TOKEN=visible\nSTRIPE_PUBLISHABLE_KEY=pk_live_abcdefghijklmnopqrstuvwxyz\nVITE_API_KEY=public-browser-config\nALREADY_SECRET=encrypted:abc\n",
        );
        assert!(ordinary.encryptable_keys(&[], &[]).is_empty());
        assert_eq!(
            ordinary.encryptable_keys(&["AWS_ACCOUNT_ID".to_string()], &[]),
            vec!["AWS_ACCOUNT_ID"]
        );

        let secrets = DotenvDocument::parse(
            PathBuf::from(".env"),
            "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz123456\nexport NPM_TOKEN=\"npm_abcdefghijklmnopqrstuvwxyz\"\nSTRIPE_SECRET_KEY='sk_live_abcdefghijklmnopqrstuvwxyz'\nDATABASE_URL=postgres://user:password@example.test/app\nPLAIN_VALUE=github_pat_1234567890abcdefghijklmnopqrstuvwxyz\nPRIVATE_MATERIAL=\"-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----\"\nJWT_VALUE=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature123\n",
        );
        assert_eq!(
            secrets.encryptable_keys(&[], &[]),
            vec![
                "OPENAI_API_KEY",
                "NPM_TOKEN",
                "STRIPE_SECRET_KEY",
                "DATABASE_URL",
                "PLAIN_VALUE",
                "PRIVATE_MATERIAL",
                "JWT_VALUE",
            ]
        );

        let colon = DotenvDocument::parse(
            PathBuf::from(".env"),
            "DB_PASSWORD: password # comment\nFEATURE_FLAG: enabled\nBAD-NAME=secret\n# COMMENTED_TOKEN=secret\n",
        );
        assert_eq!(colon.encryptable_keys(&[], &[]), vec!["DB_PASSWORD"]);
    }

    #[test]
    fn dotenv_parser_crypto_and_secret_shape_helpers_cover_more_edges() {
        let relative = PathBuf::from("coverage-missing.env");
        assert!(
            resolve_dotenv_path(&relative)
                .unwrap()
                .ends_with(relative.as_path())
        );
        assert!(parse_dotenv_assignment(": value").is_none());
        assert_eq!(parse_dotenv_value(" \t "), "");
        assert_eq!(
            parse_dotenv_value("\"unterminated\\r\\t"),
            "unterminated\r\t"
        );
        assert_eq!(dotenv_double_quote_escape("a\r"), "a\\r");
        assert_eq!(
            public_key_name_for_file(Path::new(".env.production")),
            "DOTENV_PUBLIC_KEY_PRODUCTION"
        );
        assert_eq!(
            public_key_name_for_file(Path::new(".env.prod.local.extra.txt")),
            "DOTENV_PUBLIC_KEY_PROD_LOCAL"
        );

        let keypair = generate_dotenv_keypair(Path::new(".env"));
        let encrypted = encrypt_dotenv_value("secret", &keypair.public_key).unwrap();
        assert_eq!(
            decrypt_dotenv_value(
                "API_KEY",
                &encrypted,
                &format!("bad-key,{}", keypair.private_key)
            )
            .unwrap(),
            "secret"
        );
        assert!(
            decrypt_dotenv_value("API_KEY", "encrypted:not-base64", &keypair.private_key)
                .unwrap_err()
                .contains("malformed encrypted data")
        );
        assert_eq!(
            decrypt_dotenv_value("API_KEY", "plain", &keypair.private_key).unwrap(),
            "plain"
        );
        assert_eq!(
            validate_sha256_hex("bad").unwrap_err(),
            "dotenv sha256 must be a 64-character hex digest"
        );
        assert!(is_public_key_name("DOTENV_PUBLIC_KEY_CI"));
        assert!(validate_dotenv_key_name("1BAD").is_err());

        assert!(dotenv_key_looks_secret("PRIVATE_KEY", "plain"));
        assert!(dotenv_key_looks_secret(
            "DATABASE_URL",
            "postgres://user:pass@example.com/db"
        ));
        assert!(dotenv_key_looks_secret("SECRET_KEY", "plain"));
        assert!(dotenv_key_looks_secret("STRIPE_KEY", "plain"));
        assert!(dotenv_key_looks_secret(
            "DATABASE_DSN",
            "postgres://user:pass@example.com/db"
        ));
        assert!(!dotenv_value_looks_secret(""));
        assert!(!dotenv_value_looks_secret("encrypted:abc"));
        assert!(dotenv_value_looks_secret(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----"
        ));
        assert!(dotenv_value_looks_secret("AKIA1234567890ABCDEF"));
        assert!(!dotenv_value_looks_credential_url(
            "1ttp://user:pass@example.com"
        ));
        assert!(dotenv_value_looks_jwt("eyJhbGciOiJIUzI1NiJ9.e30.signature"));
        assert!(!dotenv_value_looks_jwt("eyJ.bad"));
        assert!(dotenv_value_has_high_entropy_secret_shape(
            "Abcdefghijklmnopqrstuvwx12345!@#$"
        ));
        assert!(!dotenv_value_has_high_entropy_secret_shape(
            "/Users/me/token-with-enough-chars-ABC123!"
        ));

        let mut redacted = Vec::new();
        assert_eq!(
            stream_redacted_output(io::Cursor::new(b"plain output"), &mut redacted, Vec::new())
                .unwrap(),
            0
        );
        assert_eq!(redacted, b"plain output");
    }

    #[test]
    fn dotenv_system_policy_trust_and_approval_helpers_cover_edges() {
        let _lock = global_test_env_lock().lock().unwrap();
        let agent_env_markers = dotenv_agent_export_env_marker_names();
        let _agent_env = DotenvEnvGuard::unset(&agent_env_markers);
        let _process_context = DotenvProcessContextGuard::non_codex_shell();
        let temp = TempDir::new().unwrap();
        let policy_path = temp.path().join("policy.json");
        let remembered_path = temp.path().join("remembered.json");
        fs::write(
            &policy_path,
            serde_json::to_vec(&DotenvPolicyFile {
                approval_policy: DotenvApprovalPolicy::RememberApproved,
            })
            .unwrap(),
        )
        .unwrap();
        fs::write(
            &remembered_path,
            serde_json::to_vec(&DotenvRememberedApprovalStore::default()).unwrap(),
        )
        .unwrap();

        assert_eq!(
            load_dotenv_approval_policy_at_path(&policy_path, true).unwrap(),
            DotenvApprovalPolicy::ApproveEveryTime
        );
        assert!(
            load_dotenv_remembered_approvals_at_path(&remembered_path, true)
                .unwrap()
                .entries
                .is_empty()
        );
        assert!(!dotenv_system_file_is_trusted(&policy_path).unwrap());
        assert!(!dotenv_system_directory_is_trusted(temp.path()).unwrap());
        assert!(
            write_dotenv_system_json(
                &temp.path().join("untrusted/policy.json"),
                &DotenvPolicyFile {
                    approval_policy: DotenvApprovalPolicy::RememberApproved,
                },
                true,
            )
            .unwrap_err()
            .contains("not root-controlled")
        );

        let _env = DotenvEnvGuard::set(&[
            (
                AV_TEST_DOTENV_POLICY_PATH_ENV,
                policy_path.to_str().unwrap(),
            ),
            (
                AV_TEST_DOTENV_REMEMBERED_APPROVALS_PATH_ENV,
                remembered_path.to_str().unwrap(),
            ),
        ]);
        assert_eq!(dotenv_system_policy_path(), policy_path);
        assert_eq!(dotenv_system_remembered_approvals_path(), remembered_path);
        assert!(!dotenv_system_policy_requires_root_control());
        assert!(!dotenv_system_remembered_approvals_requires_root_control());
        write_dotenv_approval_policy(DotenvApprovalPolicy::RememberApproved).unwrap();

        let project = temp.path().join("project");
        fs::create_dir_all(&project).unwrap();
        let env_path = project.join(".env");
        let keypair = generate_dotenv_keypair(&env_path);
        fs::write(
            &env_path,
            format!("DOTENV_PUBLIC_KEY={}\nFOO=plain\n", keypair.public_key),
        )
        .unwrap();
        let digest = sha256_file_hex(&env_path).unwrap();
        let fingerprint = public_key_fingerprint(&keypair.public_key);
        let mut keys = vec!["FOO".to_string(), "FOO".to_string()];
        let entry = validate_dotenv_approval_entry(
            DotenvApprovalMode::Run,
            env_path.to_str().unwrap(),
            project.to_str().unwrap(),
            &digest,
            &fingerprint,
            &mut keys,
        )
        .unwrap();
        assert_eq!(entry.keys, vec!["FOO".to_string()]);

        let mut bad_keys = vec!["BAD-NAME".to_string()];
        assert!(
            validate_dotenv_approval_entry(
                DotenvApprovalMode::Run,
                env_path.to_str().unwrap(),
                project.to_str().unwrap(),
                &digest,
                &fingerprint,
                &mut bad_keys,
            )
            .unwrap_err()
            .contains("invalid dotenv key name")
        );
        let mut good_keys = vec!["FOO".to_string()];
        assert_eq!(
            validate_dotenv_approval_entry(
                DotenvApprovalMode::Run,
                env_path.to_str().unwrap(),
                project.to_str().unwrap(),
                &digest,
                "",
                &mut good_keys,
            )
            .unwrap_err(),
            "dotenv public key fingerprint is empty"
        );
        let mut good_keys = vec!["FOO".to_string()];
        assert_eq!(
            validate_dotenv_approval_entry(
                DotenvApprovalMode::Run,
                env_path.to_str().unwrap(),
                project.to_str().unwrap(),
                &digest,
                &"f".repeat(64),
                &mut good_keys,
            )
            .unwrap_err(),
            "dotenv public key fingerprint mismatch"
        );

        remember_dotenv_approval(entry.clone()).unwrap();
        request_dotenv_approval_if_needed(
            entry.mode,
            Path::new(&entry.env_file_path),
            Path::new(&entry.project_root),
            &entry.env_sha256,
            &entry.public_key_fingerprint,
            &entry.keys,
            &["/bin/echo".to_string()],
        )
        .unwrap();
    }

    #[test]
    fn dotenv_encrypt_provisions_key_without_plaintext() {
        let temp = TempDir::new().unwrap();
        let env_path = temp.path().join(".env");
        fs::write(&env_path, "# comments only\n").unwrap();
        let store = StubDotenvPrivateKeyStore::default();

        run_dotenv_encrypt(
            &DotenvEncryptOptions {
                file: env_path.clone(),
                include_keys: Vec::new(),
                exclude_keys: Vec::new(),
                check: false,
            },
            &store,
        )
        .unwrap();

        let output = fs::read_to_string(env_path).unwrap();
        assert!(output.contains("DOTENV_PUBLIC_KEY"));
        assert!(output.contains("# comments only"));
    }

    #[test]
    #[cfg(unix)]
    fn dotenv_command_parsers_cover_help_version_and_error_edges() {
        assert_eq!(
            parse_dotenv_command("av dotenv", Vec::<OsString>::new().into_iter()).unwrap_err(),
            "missing dotenv command"
        );
        assert!(
            parse_dotenv_command("av dotenv", [OsString::from("--help")].into_iter())
                .unwrap()
                .is_none()
        );
        assert!(
            parse_dotenv_command("av dotenv", [OsString::from("--version")].into_iter())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            parse_dotenv_command("av dotenv", [OsString::from_vec(vec![0xff])].into_iter())
                .unwrap_err(),
            "dotenv command must be valid UTF-8"
        );
        assert_eq!(
            parse_dotenv_command("av dotenv", [OsString::from("bogus")].into_iter()).unwrap_err(),
            "unknown dotenv command 'bogus'"
        );
        assert_eq!(
            parse_dotenv_command(
                "av dotenv",
                [
                    OsString::from("keychain"),
                    OsString::from("migrate"),
                    OsString::from("--replace"),
                    OsString::from("--delete-legacy"),
                ]
                .into_iter()
            )
            .unwrap(),
            Some(DotenvCommand::Keychain(DotenvKeychainCommand::Migrate(
                DotenvKeychainMigrateOptions {
                    replace: true,
                    delete_legacy: true,
                }
            )))
        );
        assert_eq!(
            parse_dotenv_command("av dotenv", [OsString::from("keychain")].into_iter())
                .unwrap_err(),
            "missing dotenv keychain command"
        );
        assert!(
            parse_dotenv_command(
                "av dotenv",
                [OsString::from("keychain"), OsString::from("--help")].into_iter()
            )
            .unwrap()
            .is_none()
        );
        assert!(
            parse_dotenv_command(
                "av dotenv",
                [OsString::from("keychain"), OsString::from("--version")].into_iter()
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(
            parse_dotenv_command(
                "av dotenv",
                [OsString::from("keychain"), OsString::from("bogus")].into_iter()
            )
            .unwrap_err(),
            "unknown dotenv keychain command 'bogus'"
        );
        assert_eq!(
            parse_dotenv_command(
                "av dotenv",
                [
                    OsString::from("keychain"),
                    OsString::from("migrate"),
                    OsString::from("--bogus"),
                ]
                .into_iter()
            )
            .unwrap_err(),
            "unknown dotenv keychain migrate argument '--bogus'"
        );
        assert!(
            parse_dotenv_command(
                "av dotenv",
                [
                    OsString::from("keychain"),
                    OsString::from("migrate"),
                    OsString::from("--help"),
                ]
                .into_iter()
            )
            .unwrap()
            .is_none()
        );
        assert!(
            parse_dotenv_command(
                "av dotenv",
                [
                    OsString::from("keychain"),
                    OsString::from("migrate"),
                    OsString::from("--version"),
                ]
                .into_iter()
            )
            .unwrap()
            .is_none()
        );

        assert!(
            parse_dotenv_set("av dotenv", [OsString::from("--help")].into_iter())
                .unwrap()
                .is_none()
        );
        assert!(
            parse_dotenv_set("av dotenv", [OsString::from("--version")].into_iter())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            parse_dotenv_set("av dotenv", Vec::<OsString>::new().into_iter()).unwrap_err(),
            "missing KEY"
        );
        assert_eq!(
            parse_dotenv_set(
                "av dotenv",
                [OsString::from("FOO"), OsString::from("BAR")].into_iter(),
            )
            .unwrap_err(),
            "dotenv set supports one KEY"
        );
        assert_eq!(
            parse_dotenv_set("av dotenv", [OsString::from("1BAD")].into_iter()).unwrap_err(),
            "invalid dotenv key name: 1BAD"
        );
        assert_eq!(
            parse_dotenv_set("av dotenv", [OsString::from_vec(vec![0xff])].into_iter())
                .unwrap_err(),
            "dotenv set key must be valid UTF-8"
        );
        let set = parse_dotenv_set(
            "av dotenv",
            [
                OsString::from("-f"),
                OsString::from("custom.env"),
                OsString::from("FOO"),
            ]
            .into_iter(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(set.file, PathBuf::from("custom.env"));
        assert_eq!(set.key, "FOO");

        assert!(
            parse_dotenv_encrypt("av dotenv", [OsString::from("--help")].into_iter())
                .unwrap()
                .is_none()
        );
        assert!(
            parse_dotenv_encrypt("av dotenv", [OsString::from("--version")].into_iter())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            parse_dotenv_encrypt("av dotenv", [OsString::from("--key")].into_iter()).unwrap_err(),
            "missing value for --key"
        );
        assert_eq!(
            parse_dotenv_encrypt("av dotenv", [OsString::from("--exclude-key")].into_iter())
                .unwrap_err(),
            "missing value for --exclude-key"
        );
        assert_eq!(
            parse_dotenv_encrypt(
                "av dotenv",
                [OsString::from("--key"), OsString::from("BAD-NAME")].into_iter(),
            )
            .unwrap_err(),
            "invalid dotenv key name: BAD-NAME"
        );
        assert_eq!(
            parse_dotenv_encrypt("av dotenv", [OsString::from("--unknown")].into_iter())
                .unwrap_err(),
            "unknown dotenv encrypt argument '--unknown'"
        );
        assert_eq!(
            parse_dotenv_encrypt("av dotenv", [OsString::from("--file")].into_iter()).unwrap_err(),
            "missing value for --file"
        );

        assert!(
            parse_dotenv_import("av dotenv", [OsString::from("--help")].into_iter())
                .unwrap()
                .is_none()
        );
        assert!(
            parse_dotenv_import("av dotenv", [OsString::from("--version")].into_iter())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            parse_dotenv_import("av dotenv", [OsString::from("--unknown")].into_iter())
                .unwrap_err(),
            "unknown dotenv import argument '--unknown'"
        );
        let import = parse_dotenv_import(
            "av dotenv",
            [OsString::from("--file"), OsString::from("dir/.env.prod")].into_iter(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(import.keys_file, PathBuf::from("dir/.env.keys"));
        let import = parse_dotenv_import(
            "av dotenv",
            [
                OsString::from("--file"),
                OsString::from(".env"),
                OsString::from("--keys-file"),
                OsString::from("keys.env"),
            ]
            .into_iter(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(import.keys_file, PathBuf::from("keys.env"));

        assert_eq!(
            parse_dotenv_hook("av dotenv", Vec::<OsString>::new().into_iter()).unwrap_err(),
            "missing shell"
        );
        assert!(
            parse_dotenv_hook("av dotenv", [OsString::from("--help")].into_iter())
                .unwrap()
                .is_none()
        );
        assert!(
            parse_dotenv_hook("av dotenv", [OsString::from("--version")].into_iter())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            parse_dotenv_hook(
                "av dotenv",
                [OsString::from("bash"), OsString::from("extra")].into_iter(),
            )
            .unwrap_err(),
            "dotenv hook supports one shell"
        );
        assert_eq!(
            parse_dotenv_hook("av dotenv", [OsString::from("tcsh")].into_iter()).unwrap_err(),
            "unsupported shell 'tcsh'"
        );
        assert_eq!(
            parse_dotenv_hook("av dotenv", [OsString::from_vec(vec![0xff])].into_iter())
                .unwrap_err(),
            "shell must be valid UTF-8"
        );

        assert!(
            parse_dotenv_export("av dotenv", [OsString::from("--help")].into_iter())
                .unwrap()
                .is_none()
        );
        assert!(
            parse_dotenv_export("av dotenv", [OsString::from("--version")].into_iter())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            parse_dotenv_export("av dotenv", Vec::<OsString>::new().into_iter()).unwrap_err(),
            "missing --shell"
        );
        assert_eq!(
            parse_dotenv_export("av dotenv", [OsString::from("--shell")].into_iter()).unwrap_err(),
            "missing value for --shell"
        );
        assert_eq!(
            parse_dotenv_export("av dotenv", [OsString::from("--unknown")].into_iter())
                .unwrap_err(),
            "unknown dotenv export argument '--unknown'"
        );
        let export = parse_dotenv_export(
            "av dotenv",
            [
                OsString::from("--shell"),
                OsString::from("fish"),
                OsString::from("--cwd"),
                OsString::from("/tmp"),
            ]
            .into_iter(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(export.shell, DotenvShell::Fish);
        assert_eq!(export.cwd, PathBuf::from("/tmp"));

        assert_eq!(
            parse_dotenv_run("av dotenv", Vec::<OsString>::new().into_iter()).unwrap_err(),
            "missing command"
        );
        assert!(
            parse_dotenv_run("av dotenv", [OsString::from("--help")].into_iter())
                .unwrap()
                .is_none()
        );
        assert!(
            parse_dotenv_run("av dotenv", [OsString::from("--version")].into_iter())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            parse_dotenv_run("av dotenv", [OsString::from("--file")].into_iter()).unwrap_err(),
            "missing value for --file"
        );
        let run = parse_dotenv_run(
            "av dotenv",
            [
                OsString::from("-f"),
                OsString::from("custom.env"),
                OsString::from("--"),
                OsString::from("/bin/echo"),
                OsString::from("hello"),
            ]
            .into_iter(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(run.file, PathBuf::from("custom.env"));
        assert_eq!(run.command, OsString::from("/bin/echo"));
        assert_eq!(run.args, vec![OsString::from("hello")]);
    }

    #[test]
    fn dotenv_document_helpers_cover_rendering_selection_and_paths() {
        let temp = TempDir::new().unwrap();
        let missing = temp.path().join("nested/.env");
        let empty = DotenvDocument::load_or_empty(&missing).unwrap();
        assert!(empty.lines.is_empty());
        assert!(empty.had_trailing_newline);
        assert_eq!(empty.path, missing);

        let mut doc = DotenvDocument::parse(
            PathBuf::from(".env.local.txt"),
            "export FOO: value # comment\r\nBAR=`raw value`\rBAZ=\"line\\nnext\"\nAPI_KEY=sk-test-secret\nNO_SEP\n",
        );
        assert_eq!(doc.value("FOO").unwrap(), "value");
        assert_eq!(doc.value("BAR").unwrap(), "raw value");
        assert_eq!(doc.value("BAZ").unwrap(), "line\nnext");
        assert_eq!(doc.value("API_KEY").unwrap(), "sk-test-secret");
        assert!(doc.value("NO_SEP").is_none());
        assert!(doc.render().ends_with('\n'));

        doc.ensure_public_key("DOTENV_PUBLIC_KEY_LOCAL", "abc123");
        assert_eq!(
            doc.public_key(),
            Some(("DOTENV_PUBLIC_KEY_LOCAL".to_string(), "abc123".to_string()))
        );
        doc.set_value("QUOTED", "tabs\tand\nlines\"\\");
        assert!(
            doc.render()
                .contains("QUOTED=\"tabs\\tand\\nlines\\\"\\\\\"")
        );

        let selected = doc.encryptable_keys(
            &["FOO".to_string(), "API_KEY".to_string()],
            &["FOO".to_string()],
        );
        assert_eq!(selected, vec!["API_KEY"]);
        doc.set_value("API_KEY", "encrypted:abc");
        assert!(!doc.encryptable_keys(&[], &[]).contains(&"FOO".to_string()));
        assert!(
            !doc.encryptable_keys(&[], &[])
                .contains(&"API_KEY".to_string())
        );

        let mut empty_doc = DotenvDocument::parse(PathBuf::from(".env"), "");
        empty_doc.ensure_public_key("DOTENV_PUBLIC_KEY", "public");
        assert!(empty_doc.render().contains("DOTENV_PUBLIC_KEY=\"public\""));

        let write_path = temp.path().join("write/.env");
        let writable = DotenvDocument::parse(write_path.clone(), "FOO=bar");
        writable.write().unwrap();
        let loaded = DotenvDocument::load(&write_path).unwrap();
        assert_eq!(loaded.path, fs::canonicalize(&write_path).unwrap());
        assert_eq!(loaded.value("FOO").unwrap(), "bar");

        assert_eq!(
            resolve_dotenv_path(&temp.path().join("absent.env")).unwrap(),
            temp.path().join("absent.env")
        );
        assert_eq!(
            public_key_name_for_file(Path::new(".env")),
            "DOTENV_PUBLIC_KEY"
        );
        assert_eq!(
            public_key_name_for_file(Path::new(".env.production.local.txt")),
            "DOTENV_PUBLIC_KEY_PRODUCTION_LOCAL"
        );
        assert_eq!(
            private_key_name_for_public_key_name("DOTENV_PUBLIC_KEY_PRODUCTION"),
            "DOTENV_PRIVATE_KEY_PRODUCTION"
        );
    }

    #[test]
    fn dotenv_crypto_helpers_cover_validation_and_decryption_errors() {
        assert_eq!(decode_hex("0x0A").unwrap(), vec![10]);
        assert_eq!(
            decode_hex("abc").unwrap_err(),
            "hex value must have an even number of characters"
        );
        assert_eq!(
            decode_hex("zz").unwrap_err(),
            "hex value contains non-hex characters"
        );
        assert!(validate_private_key_list("").is_ok());
        assert_eq!(
            validate_private_key_list("aa").unwrap_err(),
            "dotenv private key must be 32 bytes"
        );
        assert_eq!(
            validate_private_key_list("not-hex").unwrap_err(),
            "hex value must have an even number of characters"
        );

        assert_eq!(
            decrypt_dotenv_value("PLAIN", "not encrypted", "").unwrap(),
            "not encrypted"
        );
        assert!(
            decrypt_dotenv_value("BAD", "encrypted:not-base64", "")
                .unwrap_err()
                .contains("malformed encrypted data")
        );
        assert_eq!(
            decrypt_dotenv_value("EMPTY", "encrypted:abcd", "").unwrap_err(),
            "could not decrypt EMPTY: missing private key"
        );

        let good = generate_dotenv_keypair(Path::new(".env"));
        let wrong = generate_dotenv_keypair(Path::new(".env"));
        let encrypted = encrypt_dotenv_value("secret", &good.public_key).unwrap();
        assert!(
            decrypt_dotenv_value("FOO", &encrypted, &wrong.private_key)
                .unwrap_err()
                .contains("could not decrypt FOO")
        );
        assert!(public_key_fingerprint(&good.public_key).len() == 64);
        assert!(
            keychain_account_for_public_key(&good.public_key).starts_with("DOTENV_PRIVATE_KEY:")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn dotenv_keychain_bridges_reject_invalid_c_strings() {
        assert_eq!(
            bridge_read_dotenv_private_key_from_new_store_if_present(
                "bad\0service",
                "account",
                "TEAM.group"
            )
            .unwrap_err(),
            "invalid keychain service name"
        );
        assert_eq!(
            bridge_read_dotenv_private_key_from_new_store_if_present(
                "service",
                "bad\0account",
                "TEAM.group"
            )
            .unwrap_err(),
            "invalid keychain account name"
        );
        assert_eq!(
            bridge_write_dotenv_private_key_to_new_store(
                "service",
                "account",
                "TEAM.group",
                "bad\0value"
            )
            .unwrap_err(),
            "invalid keychain private key"
        );
        assert_eq!(
            dotenv_post_distributed_notification("bad\0notification").unwrap_err(),
            "invalid distributed notification name"
        );
        assert_eq!(
            dotenv_post_distributed_notification_with_object("notification", "bad\0object")
                .unwrap_err(),
            "invalid distributed notification object"
        );
    }

    #[test]
    fn dotenv_approval_store_paths_and_decisions_cover_json_edges() {
        let _lock = global_test_env_lock().lock().unwrap();
        let agent_env_markers = dotenv_agent_export_env_marker_names();
        let _agent_env = DotenvEnvGuard::unset(&agent_env_markers);
        let temp = TempDir::new().unwrap();
        let home = temp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let policy_path = temp.path().join("policy.json");
        let remembered_path = temp.path().join("remembered-approvals.json");
        let home_str = home.to_str().unwrap();
        let policy_path_str = policy_path.to_str().unwrap();
        let remembered_path_str = remembered_path.to_str().unwrap();
        let _env = DotenvEnvGuard::set(&[
            ("HOME", home_str),
            (AV_TEST_DOTENV_POLICY_PATH_ENV, policy_path_str),
            (
                AV_TEST_DOTENV_REMEMBERED_APPROVALS_PATH_ENV,
                remembered_path_str,
            ),
        ]);

        assert_eq!(
            dotenv_user_approval_root().unwrap(),
            home.join("Library/Application Support/Automic Vault/dotenv")
        );
        assert_eq!(
            load_dotenv_approval_policy().unwrap(),
            DotenvApprovalPolicy::ApproveEveryTime
        );
        write_dotenv_approval_policy(DotenvApprovalPolicy::RememberApproved).unwrap();
        assert_eq!(
            load_dotenv_approval_policy().unwrap(),
            DotenvApprovalPolicy::RememberApproved
        );
        assert_eq!(
            load_dotenv_approval_policy_for_test(&policy_path).unwrap(),
            DotenvApprovalPolicy::RememberApproved
        );
        let direct_policy_path = temp.path().join("direct-policy.json");
        write_dotenv_approval_policy_for_test(
            &direct_policy_path,
            DotenvApprovalPolicy::ApproveEveryTime,
        )
        .unwrap();
        assert_eq!(
            load_dotenv_approval_policy_for_test(&direct_policy_path).unwrap(),
            DotenvApprovalPolicy::ApproveEveryTime
        );
        assert!(
            load_dotenv_remembered_approvals()
                .unwrap()
                .entries
                .is_empty()
        );

        let entry = DotenvRememberedApprovalEntry {
            mode: DotenvApprovalMode::Export,
            env_file_path: "/tmp/project/.env".to_string(),
            project_root: "/tmp/project".to_string(),
            env_sha256: "sha".to_string(),
            public_key_fingerprint: "fingerprint".to_string(),
            keys: vec!["FOO".to_string()],
        };
        remember_dotenv_approval(entry.clone()).unwrap();
        remember_dotenv_approval(entry.clone()).unwrap();
        let store = load_dotenv_remembered_approvals().unwrap();
        assert_eq!(store.entries, vec![entry.clone()]);
        assert_eq!(
            load_dotenv_remembered_approvals_for_test(&remembered_path)
                .unwrap()
                .entries,
            vec![entry.clone()]
        );
        let direct_remembered_path = temp.path().join("direct-remembered.json");
        remember_dotenv_approval_for_test(&direct_remembered_path, entry.clone()).unwrap();
        assert_eq!(
            load_dotenv_remembered_approvals_for_test(&direct_remembered_path)
                .unwrap()
                .entries,
            vec![entry.clone()]
        );
        clear_dotenv_remembered_approvals_for_test(&direct_remembered_path).unwrap();
        assert!(
            load_dotenv_remembered_approvals_for_test(&direct_remembered_path)
                .unwrap()
                .entries
                .is_empty()
        );

        let generated_id = new_dotenv_approval_request_id().unwrap();
        let id_parts = generated_id.split('-').collect::<Vec<_>>();
        assert_eq!(id_parts.len(), 3);
        assert_eq!(id_parts[0], process::id().to_string());
        assert_eq!(id_parts[2].len(), 32);
        assert!(id_parts[2].chars().all(|ch| ch.is_ascii_hexdigit()));

        let stale_decision_path = dotenv_decision_path("stale").unwrap();
        write_dotenv_json(
            &stale_decision_path,
            &DotenvApprovalDecision {
                id: "stale".to_string(),
                approval_token: Some("stale-token".to_string()),
                approved: true,
                reason: None,
            },
        )
        .unwrap();
        assert!(stale_decision_path.is_file());
        assert_eq!(
            prepare_dotenv_approval_request_files("stale").unwrap(),
            dotenv_pending_approval_path().unwrap()
        );
        assert!(!stale_decision_path.exists());

        let pending = dotenv_pending_approval_path().unwrap();
        write_dotenv_json(&pending, &entry).unwrap();
        assert!(pending.is_file());
        assert_eq!(
            fs::metadata(&pending).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(pending.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        let approval_token = "approval-token";
        let decision_path = dotenv_decision_path("approved").unwrap();
        write_dotenv_json(
            &decision_path,
            &DotenvApprovalDecision {
                id: "approved".to_string(),
                approval_token: Some(approval_token.to_string()),
                approved: true,
                reason: None,
            },
        )
        .unwrap();
        assert_eq!(
            fs::metadata(decision_path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        wait_for_dotenv_decision("approved", approval_token, DotenvApprovalMode::Export).unwrap();
        assert!(!pending.exists());
        assert!(!decision_path.exists());

        write_dotenv_json(&dotenv_pending_approval_path().unwrap(), &entry).unwrap();
        write_dotenv_json(
            &dotenv_decision_path("denied").unwrap(),
            &DotenvApprovalDecision {
                id: "denied".to_string(),
                approval_token: Some(approval_token.to_string()),
                approved: false,
                reason: None,
            },
        )
        .unwrap();
        assert_eq!(
            wait_for_dotenv_decision("denied", approval_token, DotenvApprovalMode::Export)
                .unwrap_err(),
            "dotenv approval denied\nhint: use `av dotenv run` to run commands with this project's environment"
        );

        write_dotenv_json(&dotenv_pending_approval_path().unwrap(), &entry).unwrap();
        write_dotenv_json(
            &dotenv_decision_path("run-denied").unwrap(),
            &DotenvApprovalDecision {
                id: "run-denied".to_string(),
                approval_token: Some(approval_token.to_string()),
                approved: false,
                reason: Some("Denied by operator".to_string()),
            },
        )
        .unwrap();
        assert_eq!(
            wait_for_dotenv_decision("run-denied", approval_token, DotenvApprovalMode::Run)
                .unwrap_err(),
            "Denied by operator"
        );

        write_dotenv_json(&dotenv_pending_approval_path().unwrap(), &entry).unwrap();
        write_dotenv_json(
            &dotenv_decision_path("mismatch").unwrap(),
            &DotenvApprovalDecision {
                id: "other".to_string(),
                approval_token: Some(approval_token.to_string()),
                approved: true,
                reason: None,
            },
        )
        .unwrap();
        assert_eq!(
            wait_for_dotenv_decision("mismatch", approval_token, DotenvApprovalMode::Export)
                .unwrap_err(),
            "dotenv approval decision id mismatch"
        );

        write_dotenv_json(&dotenv_pending_approval_path().unwrap(), &entry).unwrap();
        write_dotenv_json(
            &dotenv_decision_path("token-mismatch").unwrap(),
            &DotenvApprovalDecision {
                id: "token-mismatch".to_string(),
                approval_token: Some("wrong-token".to_string()),
                approved: true,
                reason: None,
            },
        )
        .unwrap();
        assert_eq!(
            wait_for_dotenv_decision("token-mismatch", approval_token, DotenvApprovalMode::Export)
                .unwrap_err(),
            "dotenv approval token mismatch"
        );

        write_dotenv_json(&dotenv_pending_approval_path().unwrap(), &entry).unwrap();
        write_dotenv_json(
            &dotenv_decision_path("missing-token").unwrap(),
            &DotenvApprovalDecision {
                id: "missing-token".to_string(),
                approval_token: None,
                approved: true,
                reason: None,
            },
        )
        .unwrap();
        assert_eq!(
            wait_for_dotenv_decision("missing-token", approval_token, DotenvApprovalMode::Export)
                .unwrap_err(),
            "dotenv approval decision missing token; update the approval client"
        );

        fs::write(&remembered_path, "not json").unwrap();
        assert!(
            load_dotenv_remembered_approvals()
                .unwrap_err()
                .contains("failed to decode")
        );
        drop(_env);
        let _env = DotenvEnvGuard::unset(&["HOME"]);
        assert_eq!(dotenv_user_approval_root().unwrap_err(), "HOME is not set");
    }

    #[test]
    fn dotenv_process_info_parser_preserves_paths_with_spaces() {
        let (parent_pid, executable_path) = parse_dotenv_process_info_line(
            "   42 /Applications/Visual Studio Code.app/Contents/MacOS/Electron",
        )
        .unwrap();

        assert_eq!(parent_pid, 42);
        assert_eq!(
            executable_path.as_deref(),
            Some("/Applications/Visual Studio Code.app/Contents/MacOS/Electron")
        );
        assert_eq!(
            parse_dotenv_process_info_line("  42   ").unwrap(),
            (42, None)
        );
        assert!(parse_dotenv_process_info_line("not-a-pid /bin/zsh").is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn dotenv_process_snapshot_helpers_cover_missing_processes() {
        assert!(dotenv_parent_process_path(0).is_none());
        assert!(dotenv_process_snapshot(0).is_none());
        assert!(dotenv_process_ancestry_snapshot(0).is_empty());
    }

    #[test]
    fn dotenv_helper_remember_validates_policy_and_snapshot() {
        let _lock = global_test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("project");
        fs::create_dir_all(&project).unwrap();
        let policy_path = temp.path().join("policy.json");
        let remembered_path = temp.path().join("remembered-approvals.json");
        let policy_path_str = policy_path.to_str().unwrap();
        let remembered_path_str = remembered_path.to_str().unwrap();
        let _env = DotenvEnvGuard::set(&[
            (AV_TEST_DOTENV_POLICY_PATH_ENV, policy_path_str),
            (
                AV_TEST_DOTENV_REMEMBERED_APPROVALS_PATH_ENV,
                remembered_path_str,
            ),
        ]);

        let keypair = generate_dotenv_keypair(Path::new(".env"));
        let env_path = project.join(".env");
        fs::write(
            &env_path,
            format!(
                "DOTENV_PUBLIC_KEY={}\nFOO=plain\nBAR=plain\n",
                keypair.public_key
            ),
        )
        .unwrap();
        let digest = sha256_file_hex(&env_path).unwrap();
        let fingerprint = public_key_fingerprint(&keypair.public_key);
        let env_path_str = env_path.to_str().unwrap();
        let project_str = project.to_str().unwrap();

        remember_dotenv_approval_from_helper(
            DotenvApprovalMode::Export,
            env_path_str,
            project_str,
            &digest,
            &fingerprint,
            vec!["FOO".to_string()],
        )
        .unwrap();
        assert!(
            load_dotenv_remembered_approvals()
                .unwrap()
                .entries
                .is_empty()
        );

        write_dotenv_approval_policy(DotenvApprovalPolicy::RememberApproved).unwrap();
        remember_dotenv_approval_from_helper(
            DotenvApprovalMode::Export,
            env_path_str,
            temp.path().to_str().unwrap(),
            &digest,
            &fingerprint,
            vec!["FOO".to_string()],
        )
        .unwrap();
        assert!(
            load_dotenv_remembered_approvals()
                .unwrap()
                .entries
                .is_empty()
        );
        assert_eq!(
            remember_dotenv_approval_from_helper(
                DotenvApprovalMode::Run,
                env_path_str,
                temp.path().to_str().unwrap(),
                &digest,
                &fingerprint,
                vec!["FOO".to_string()],
            )
            .unwrap_err(),
            "dotenv approval project root does not match env file"
        );
        assert_eq!(
            remember_dotenv_approval_from_helper(
                DotenvApprovalMode::Run,
                env_path_str,
                project_str,
                &"0".repeat(64),
                &fingerprint,
                vec!["FOO".to_string()],
            )
            .unwrap_err(),
            "dotenv file changed before approval could be remembered"
        );
        assert_eq!(
            remember_dotenv_approval_from_helper(
                DotenvApprovalMode::Run,
                env_path_str,
                project_str,
                &digest,
                &fingerprint,
                vec!["MISSING".to_string()],
            )
            .unwrap_err(),
            "dotenv approval includes keys that are not in the env file"
        );

        remember_dotenv_approval_from_helper(
            DotenvApprovalMode::Run,
            env_path_str,
            project_str,
            &digest,
            &fingerprint,
            vec!["FOO".to_string(), "BAR".to_string(), "FOO".to_string()],
        )
        .unwrap();
        let store = load_dotenv_remembered_approvals().unwrap();
        assert_eq!(store.entries.len(), 1);
        assert_eq!(
            store.entries[0].keys,
            vec!["BAR".to_string(), "FOO".to_string()]
        );
    }

    #[cfg(unix)]
    #[test]
    fn dotenv_load_export_and_run_cover_approval_bypass_paths() {
        let _lock = global_test_env_lock().lock().unwrap();
        let agent_env_markers = dotenv_agent_export_env_marker_names();
        let _agent_env = DotenvEnvGuard::unset(&agent_env_markers);
        let _process_context = DotenvProcessContextGuard::non_codex_shell();
        let temp = TempDir::new().unwrap();
        let home = temp.path().join("home");
        let project = temp.path().join("project");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(project.join("child")).unwrap();
        let policy_path = temp.path().join("policy.json");
        let remembered_path = temp.path().join("remembered-approvals.json");
        let home_str = home.to_str().unwrap();
        let policy_path_str = policy_path.to_str().unwrap();
        let remembered_path_str = remembered_path.to_str().unwrap();
        let _env = DotenvEnvGuard::set(&[
            ("HOME", home_str),
            (AV_DOTENV_KEYS_ENV, "FOO:BAD-NAME"),
            (AV_TEST_DOTENV_POLICY_PATH_ENV, policy_path_str),
            (
                AV_TEST_DOTENV_REMEMBERED_APPROVALS_PATH_ENV,
                remembered_path_str,
            ),
        ]);
        let _unset = DotenvEnvGuard::unset(&["FOO", "BAR", "EXTERNAL"]);
        write_dotenv_approval_policy(DotenvApprovalPolicy::RememberApproved).unwrap();

        let keypair = generate_dotenv_keypair(Path::new(".env"));
        let encrypted_bar = encrypt_dotenv_value("bar secret", &keypair.public_key).unwrap();
        let env_path = project.join(".env");
        fs::write(
            &env_path,
            format!(
                "DOTENV_PUBLIC_KEY={}\nFOO=plain secret\nBAR={}\nBAD-NAME=skip\n",
                keypair.public_key, encrypted_bar
            ),
        )
        .unwrap();
        let store = StubDotenvPrivateKeyStore::default();
        store
            .store_private_key(&keypair.public_key, &keypair.private_key)
            .unwrap();

        remember_dotenv_approval(remembered_entry_for(
            &env_path,
            DotenvApprovalMode::Run,
            &keypair.public_key,
            &["BAR", "FOO"],
        ))
        .unwrap();
        let loaded = load_dotenv_secrets(
            &env_path,
            DotenvApprovalMode::Run,
            &["/bin/echo".to_string()],
            &store,
            Some(&["FOO".to_string()]),
        )
        .unwrap();
        assert_eq!(loaded.values["FOO"], "plain secret");
        assert_eq!(loaded.values["BAR"], "bar secret");
        assert_eq!(
            nearest_dotenv_file(&project.join("child")).unwrap(),
            loaded.env_path
        );

        let previous = PreviousDotenvState {
            env_path: Some("/tmp/old/.env".to_string()),
            keys: vec!["OLD".to_string()],
        };
        print_shell_unload(DotenvShell::Bash, &previous);
        print_shell_unload(DotenvShell::Fish, &previous);
        print_shell_exports(DotenvShell::Zsh, &previous, &loaded);
        print_shell_exports(DotenvShell::Fish, &previous, &loaded);
        print_dotenv_hook("av dotenv", DotenvShell::Bash);
        print_dotenv_hook("av dotenv", DotenvShell::Zsh);
        print_dotenv_hook("av dotenv", DotenvShell::Fish);

        run_dotenv_export(
            &DotenvExportOptions {
                shell: DotenvShell::Bash,
                cwd: temp.path().join("missing"),
            },
            &store,
        )
        .unwrap();

        let digest = sha256_file_hex(&env_path).unwrap();
        let loaded_env_path = loaded.env_path.to_string_lossy().into_owned();
        let _current = DotenvEnvGuard::set(&[
            (AV_DOTENV_FILE_ENV, &loaded_env_path),
            (AV_DOTENV_DIGEST_ENV, &digest),
        ]);
        run_dotenv_export(
            &DotenvExportOptions {
                shell: DotenvShell::Bash,
                cwd: project.clone(),
            },
            &store,
        )
        .unwrap();
        drop(_current);

        remember_dotenv_approval(remembered_entry_for(
            &env_path,
            DotenvApprovalMode::Run,
            &keypair.public_key,
            &["BAR", "FOO"],
        ))
        .unwrap();
        assert!(
            run_dotenv_run(
                &DotenvRunOptions {
                    file: env_path.clone(),
                    command: OsString::from("/definitely/missing-av-dotenv-command"),
                    args: Vec::new(),
                },
                &store,
            )
            .unwrap_err()
            .contains("failed to execute")
        );

        run_dotenv_run(
            &DotenvRunOptions {
                file: env_path,
                command: OsString::from("/bin/sh"),
                args: vec![
                    OsString::from("-c"),
                    OsString::from("printf '%s\\n' \"$FOO:$BAR\""),
                ],
            },
            &store,
        )
        .unwrap();

        unsafe {
            env::set_var("EXTERNAL", "already set");
        }
        assert!(env_key_is_preexisting("EXTERNAL", None));
        assert!(!env_key_is_preexisting(
            "EXTERNAL",
            Some(&["EXTERNAL".to_string()])
        ));
        assert!(!env_key_is_preexisting("MISSING", None));
        assert_eq!(previous_dotenv_keys(), vec!["FOO".to_string()]);
    }

    #[test]
    fn dotenv_import_set_encrypt_and_store_cover_success_and_errors() {
        let temp = TempDir::new().unwrap();
        let env_path = temp.path().join(".env");
        let keys_path = temp.path().join(".env.keys");
        let keypair = generate_dotenv_keypair(&env_path);
        fs::write(
            &env_path,
            format!(
                "DOTENV_PUBLIC_KEY={}\nFOO=plain\nAPI_KEY=sk-test-secret\nBAR=encrypted:abc\n",
                keypair.public_key
            ),
        )
        .unwrap();
        fs::write(
            &keys_path,
            format!(
                "{}={}\n",
                private_key_name_for_public_key_name("DOTENV_PUBLIC_KEY"),
                keypair.private_key
            ),
        )
        .unwrap();

        let store = StubDotenvPrivateKeyStore::default();
        run_dotenv_import(
            &DotenvImportOptions {
                file: env_path.clone(),
                keys_file: keys_path.clone(),
            },
            &store,
        )
        .unwrap();
        assert_eq!(
            store.load_private_key(&keypair.public_key).unwrap(),
            keypair.private_key
        );

        let dispatch_env_path = temp.path().join("dispatch.env");
        let dispatch_keys_path = temp.path().join("dispatch.env.keys");
        let dispatch_keypair = generate_dotenv_keypair(&dispatch_env_path);
        fs::write(
            &dispatch_env_path,
            format!("DOTENV_PUBLIC_KEY={}\n", dispatch_keypair.public_key),
        )
        .unwrap();
        fs::write(
            &dispatch_keys_path,
            format!(
                "{}={}\n",
                private_key_name_for_public_key_name("DOTENV_PUBLIC_KEY"),
                dispatch_keypair.private_key
            ),
        )
        .unwrap();
        dispatch_dotenv(
            "av dotenv",
            [
                OsString::from("import"),
                OsString::from("--file"),
                OsString::from(dispatch_env_path.as_os_str()),
                OsString::from("--keys-file"),
                OsString::from(dispatch_keys_path.as_os_str()),
            ]
            .into_iter(),
            &store,
        )
        .unwrap();

        run_dotenv_set(
            &DotenvSetOptions {
                file: env_path.clone(),
                key: "NEW_SECRET".to_string(),
            },
            "new value",
            &store,
        )
        .unwrap();
        assert!(
            fs::read_to_string(&env_path)
                .unwrap()
                .contains("NEW_SECRET=\"encrypted:")
        );

        assert!(
            run_dotenv_encrypt(
                &DotenvEncryptOptions {
                    file: env_path.clone(),
                    include_keys: vec!["API_KEY".to_string()],
                    exclude_keys: Vec::new(),
                    check: true,
                },
                &store,
            )
            .unwrap_err()
            .contains("plaintext dotenv values: API_KEY")
        );

        run_dotenv_encrypt(
            &DotenvEncryptOptions {
                file: env_path.clone(),
                include_keys: vec!["FOO".to_string(), "API_KEY".to_string()],
                exclude_keys: Vec::new(),
                check: false,
            },
            &store,
        )
        .unwrap();
        let encrypted_env = fs::read_to_string(&env_path).unwrap();
        assert!(encrypted_env.contains("FOO=\"encrypted:"));
        assert!(encrypted_env.contains("API_KEY=\"encrypted:"));

        run_dotenv_encrypt(
            &DotenvEncryptOptions {
                file: env_path.clone(),
                include_keys: vec!["MISSING".to_string()],
                exclude_keys: Vec::new(),
                check: false,
            },
            &store,
        )
        .unwrap();

        let missing_public = temp.path().join("missing-public.env");
        fs::write(&missing_public, "FOO=bar\n").unwrap();
        assert!(
            run_dotenv_import(
                &DotenvImportOptions {
                    file: missing_public,
                    keys_file: keys_path.clone(),
                },
                &store,
            )
            .unwrap_err()
            .contains("is missing DOTENV_PUBLIC_KEY")
        );

        let missing_private = temp.path().join("missing-private.keys");
        fs::write(&missing_private, "OTHER=value\n").unwrap();
        assert!(
            run_dotenv_import(
                &DotenvImportOptions {
                    file: env_path.clone(),
                    keys_file: missing_private,
                },
                &store,
            )
            .unwrap_err()
            .contains("is missing DOTENV_PRIVATE_KEY")
        );

        let invalid_private = temp.path().join("invalid-private.keys");
        fs::write(&invalid_private, "DOTENV_PRIVATE_KEY=abc\n").unwrap();
        assert_eq!(
            run_dotenv_import(
                &DotenvImportOptions {
                    file: env_path,
                    keys_file: invalid_private,
                },
                &store,
            )
            .unwrap_err(),
            "hex value must have an even number of characters"
        );
    }

    #[test]
    fn dotenv_transfer_helpers_validate_error_edges() {
        let temp = TempDir::new().unwrap();
        let missing_public = temp.path().join("missing-public.env");
        fs::write(&missing_public, "FOO=bar\n").unwrap();
        assert!(
            load_dotenv_private_key_for_transfer(&missing_public)
                .unwrap_err()
                .contains("is missing DOTENV_PUBLIC_KEY")
        );

        let invalid_public = temp.path().join("invalid-public.env");
        fs::write(&invalid_public, "DOTENV_PUBLIC_KEY=abc\n").unwrap();
        assert!(
            load_dotenv_private_key_for_transfer(&invalid_public)
                .unwrap_err()
                .contains("hex value")
        );

        assert_eq!(
            validate_dotenv_public_key_name_for_transfer("PRIVATE_KEY").unwrap_err(),
            "invalid dotenv public key name: PRIVATE_KEY"
        );
        assert_eq!(
            validate_dotenv_public_key_for_transfer("aa").unwrap_err(),
            "dotenv public key must be 33 bytes"
        );
        assert_eq!(
            validate_dotenv_private_key_for_transfer("abc").unwrap_err(),
            "hex value must have an even number of characters"
        );
        let public_key = format!("02{}", "11".repeat(32));
        assert_eq!(
            dotenv_public_key_fingerprint_for_transfer(&public_key).len(),
            64
        );
        assert!(
            load_existing_dotenv_private_key_for_transfer("abc")
                .unwrap_err()
                .contains("hex value")
        );
        assert!(
            store_dotenv_private_key_for_transfer("abc", &dotenv_test_private_key(12))
                .unwrap_err()
                .contains("hex value")
        );
        assert_eq!(
            store_dotenv_private_key_for_transfer(&public_key, "abc").unwrap_err(),
            "hex value must have an even number of characters"
        );
    }

    #[test]
    fn dotenv_renderers_and_default_paths_cover_remaining_branches() {
        let _lock = global_test_env_lock().lock().unwrap();
        let mut env_names = vec![
            AV_TEST_DOTENV_POLICY_PATH_ENV,
            AV_TEST_DOTENV_REMEMBERED_APPROVALS_PATH_ENV,
        ];
        env_names.extend(dotenv_agent_export_env_marker_names());
        let _guard = DotenvEnvGuard::unset(&env_names);

        print_dotenv_hook("av", DotenvShell::Bash);
        print_dotenv_hook("av", DotenvShell::Zsh);
        print_dotenv_hook("av", DotenvShell::Fish);
        print_dotenv_usage("av");
        print_dotenv_init_usage("av");
        print_dotenv_set_usage("av");
        print_dotenv_encrypt_usage("av");
        print_dotenv_import_usage("av");
        print_dotenv_hook_usage("av");
        print_dotenv_export_usage("av");
        print_dotenv_run_usage("av");

        assert_eq!(
            dotenv_system_policy_path(),
            PathBuf::from(DOTENV_SYSTEM_POLICY_PATH)
        );
        assert_eq!(
            dotenv_system_remembered_approvals_path(),
            PathBuf::from(DOTENV_SYSTEM_REMEMBERED_APPROVALS_PATH)
        );
        assert!(dotenv_system_policy_requires_root_control());
        assert!(dotenv_system_remembered_approvals_requires_root_control());

        let parent = dotenv_parent_process_snapshot();
        assert!(parent.pid > 0);
        assert_eq!(dotenv_process_display_name(None), None);
        assert_eq!(
            dotenv_process_display_name(Some(
                "/Applications/Automic Vault.app/Contents/MacOS/Automic Vault"
            )),
            Some("Automic Vault".to_string())
        );
        assert!(dotenv_process_ancestry_snapshot(0).is_empty());
        assert!(dotenv_process_ancestry_snapshot(-1).is_empty());
        assert_eq!(
            parse_dotenv_process_info_line("  12 /usr/bin/zsh"),
            Some((12, Some("/usr/bin/zsh".to_string())))
        );
        assert_eq!(parse_dotenv_process_info_line("not-a-pid zsh"), None);
    }
}
