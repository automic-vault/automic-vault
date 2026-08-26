use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const USAGE: &str = "\
Usage: av inject [--replace-existing-env] [--allow-missing-keys] +KEY [+KEY...] [--] COMMAND [args...]
       av inject [--replace-existing-env] [--allow-missing-keys] -- COMMAND [args...]

Injects named Keychain secrets into COMMAND's environment.";

const APPROVAL_SERVICE: &str = "com.automicvault.av2.approval";
const PATH_SCRIPT_INTERPRETERS: &[&str] = &["uv"];
type SecretValues = BTreeMap<String, String>;

#[derive(Debug, PartialEq, Eq)]
struct Options {
    replace_existing_env: bool,
    allow_missing_keys: bool,
    keys: Vec<String>,
    target: OsString,
    args: Vec<OsString>,
    shebang_script: Option<OsString>,
}

#[derive(Debug, PartialEq, Eq)]
struct ApprovalRequest {
    op: &'static str,
    keys: Vec<String>,
    target: String,
    args: Vec<String>,
    cwd: String,
    replace_existing_env: bool,
    allow_missing_keys: bool,
    env_conflicts: Vec<String>,
    shebang_script: Option<String>,
    script_data: Option<Vec<u8>>,
    snapshot_incompatible_interpreter: Option<&'static str>,
    tool: Option<&'static str>,
    docker_server_url: Option<String>,
    terraform_hostname: Option<String>,
    aliyun_profile: Option<String>,
    oxide_scope: Option<String>,
    goat_scope: Option<String>,
    ordercli_scope: Option<String>,
    openhue_scope: Option<String>,
    uaa_scope: Option<String>,
    railway_scope: Option<String>,
    wakatime_api_url: Option<String>,
}

unsafe extern "C" {
    fn geteuid() -> u32;
}

pub(crate) fn run(
    args: Vec<OsString>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    shebang_script: Option<OsString>,
) -> i32 {
    match dispatch(args, stdout, shebang_script) {
        Ok(Some(options)) => exec(options, stderr),
        Ok(None) => 0,
        Err(err) => {
            let _ = writeln!(stderr, "av inject: {err}");
            1
        }
    }
}

fn dispatch(
    args: Vec<OsString>,
    stdout: &mut dyn Write,
    shebang_script: Option<OsString>,
) -> Result<Option<Options>, String> {
    if args
        .first()
        .is_some_and(|arg| arg == "--help" || arg == "-h")
    {
        writeln!(stdout, "{USAGE}").ok();
        return Ok(None);
    }
    if args
        .first()
        .is_some_and(|arg| arg == "--version" || arg == "-V")
    {
        writeln!(stdout, "av inject {}", env!("CARGO_PKG_VERSION")).ok();
        return Ok(None);
    }
    match parse(args) {
        Ok(mut options) => {
            options.shebang_script = shebang_script.or_else(|| infer_shebang_script(&options));
            Ok(Some(options))
        }
        Err(err) => {
            if err.starts_with("missing ") {
                writeln!(stdout, "{USAGE}").ok();
            }
            Err(err)
        }
    }
}

fn parse(args: Vec<OsString>) -> Result<Options, String> {
    let mut replace_existing_env = false;
    let mut allow_missing_keys = false;
    let mut keys = Vec::new();
    let mut seen_keys = BTreeSet::new();
    let mut iter = args.into_iter();

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
            return Err("--allow-existing-env has been replaced by --replace-existing-env".into());
        }
        if arg == "--force" {
            return Err("--force has been replaced by --replace-existing-env".into());
        }
        if arg == "--import" || arg == "--migrate" {
            return Err("credential import and migration are no longer supported".into());
        }

        let value = arg
            .to_str()
            .ok_or_else(|| "inject arguments must be valid UTF-8".to_string())?;
        if let Some(key) = value.strip_prefix('+') {
            validate_key_name(key)?;
            if !seen_keys.insert(key.to_string()) {
                return Err(format!("duplicate key requested: {key}"));
            }
            keys.push(key.to_string());
            continue;
        }

        if arg == "--" {
            let target = iter
                .next()
                .ok_or_else(|| "missing target command".to_string())?;
            keys.sort();
            return Ok(Options {
                replace_existing_env,
                allow_missing_keys,
                keys,
                target,
                args: iter.collect(),
                shebang_script: None,
            });
        }

        if keys.is_empty() {
            return Err("at least one +KEY must be provided before the target".into());
        }
        keys.sort();
        return Ok(Options {
            replace_existing_env,
            allow_missing_keys,
            keys,
            target: arg,
            args: iter.collect(),
            shebang_script: None,
        });
    }

    if keys.is_empty() {
        Err("missing key and target command".into())
    } else {
        Err("missing target command".into())
    }
}

fn exec(mut options: Options, stderr: &mut dyn Write) -> i32 {
    if unsafe { geteuid() } == 0 {
        let _ = writeln!(stderr, "av inject: must not be run as root");
        return 1;
    }

    let verified_script = match options
        .shebang_script
        .as_ref()
        .map(VerifiedScript::open)
        .transpose()
    {
        Ok(script) => script,
        Err(err) => {
            let _ = writeln!(stderr, "av inject: {err}");
            return 1;
        }
    };
    let original_script = options.shebang_script.clone();
    let mut path_interpreter = None;
    if let Some(script) = &verified_script {
        if let Some(index) = options.args.iter().position(|arg| {
            original_script
                .as_ref()
                .is_some_and(|original| arg == original)
                || std::fs::canonicalize(arg).is_ok_and(|path| path == script.path)
        }) {
            path_interpreter =
                path_script_interpreter(Path::new(&options.target), &options.args[..index]);
            if path_interpreter.is_some() {
                options.args[index] = script.path.clone().into_os_string();
            }
        }
        options.shebang_script = Some(script.path.clone().into_os_string());
    }
    if let Some(interpreter) = path_interpreter {
        let _ = writeln!(
            stderr,
            "av inject: warning: {interpreter} cannot execute the verified /dev/fd snapshot; using the canonical script path instead; Blessed Script authorization requires a Blessing created with this exception, and another process can change the script between verification and execution"
        );
    }

    let secretless = verified_script.as_ref().is_some_and(|script| {
        crate::isotopes::hardeners::env_wrapper::invocation_is_secretless(
            &script.path,
            &script.data,
            &options.args,
        )
    });
    let prepared = if secretless {
        resolve_target(&options.target).map(|target| (target, secretless_environment(&options)))
    } else {
        prepare_injection(
            &options,
            stderr,
            verified_script
                .as_ref()
                .map(|script| script.data.as_slice()),
            path_interpreter,
            approve_injection,
            build_env,
        )
    };
    let (target, mut env) = match prepared {
        Ok(prepared) => prepared,
        Err(err) => {
            let _ = writeln!(stderr, "av inject: {err}");
            return 1;
        }
    };

    let mut args = options.args.clone();
    if let (Some(script), Some(original)) = (&verified_script, original_script) {
        if path_interpreter.is_none()
            && let Some(index) = args.iter().position(|arg| {
                arg == &original || std::fs::canonicalize(arg).is_ok_and(|path| path == script.path)
            })
        {
            args[index] = OsString::from(format!("/dev/fd/{}", script.file.as_raw_fd()));
        }
        env.insert(
            OsString::from("AV_SCRIPT_PATH"),
            script.path.clone().into_os_string(),
        );
        env.insert(
            OsString::from("AV_SCRIPT_DIR"),
            script.path.parent().unwrap().as_os_str().to_os_string(),
        );
    }

    let err = Command::new(&target)
        .args(args)
        .env_clear()
        .envs(env)
        .exec();
    let _ = writeln!(
        stderr,
        "av inject: failed to execute {}: {err}",
        target.display()
    );
    1
}

fn secretless_environment(options: &Options) -> BTreeMap<OsString, OsString> {
    let mut env = std::env::vars_os().collect::<BTreeMap<_, _>>();
    for key in &options.keys {
        env.remove(std::ffi::OsStr::new(key));
    }
    env
}

fn path_script_interpreter(target: &Path, args_before_script: &[OsString]) -> Option<&'static str> {
    std::iter::once(target.as_os_str())
        .chain(args_before_script.iter().map(OsString::as_os_str))
        .filter_map(|arg| Path::new(arg).file_name()?.to_str())
        .find_map(|name| {
            PATH_SCRIPT_INTERPRETERS
                .iter()
                .copied()
                .find(|interpreter| name == *interpreter)
        })
}

fn prepare_injection<A, B>(
    options: &Options,
    stderr: &mut dyn Write,
    script_data: Option<&[u8]>,
    snapshot_incompatible_interpreter: Option<&'static str>,
    approve: A,
    build: B,
) -> Result<(PathBuf, BTreeMap<OsString, OsString>), String>
where
    A: FnOnce(&ApprovalRequest) -> Result<SecretValues, String>,
    B: FnOnce(
        &Options,
        &mut dyn Write,
        SecretValues,
    ) -> Result<BTreeMap<OsString, OsString>, String>,
{
    let target = resolve_target(&options.target)?;
    let request = approval_request(
        options,
        &target,
        script_data,
        snapshot_incompatible_interpreter,
    )?;
    let secrets = approve(&request)?;
    let env = build(options, stderr, secrets)?;
    Ok((target, env))
}

fn approval_request(
    options: &Options,
    target: &Path,
    script_data: Option<&[u8]>,
    snapshot_incompatible_interpreter: Option<&'static str>,
) -> Result<ApprovalRequest, String> {
    let current_env = std::env::vars_os().collect::<BTreeMap<_, _>>();
    let env_conflicts = options
        .keys
        .iter()
        .filter(|key| current_env.contains_key(std::ffi::OsStr::new(key.as_str())))
        .cloned()
        .collect();
    Ok(ApprovalRequest {
        op: "inject",
        keys: options.keys.clone(),
        target: target.display().to_string(),
        args: options.args.iter().map(os_display).collect(),
        cwd: crate::path_security::current_working_directory_utf8()?,
        replace_existing_env: options.replace_existing_env,
        allow_missing_keys: options.allow_missing_keys,
        env_conflicts,
        shebang_script: options.shebang_script.as_ref().map(os_display),
        script_data: script_data.map(<[u8]>::to_vec),
        snapshot_incompatible_interpreter,
        tool: None,
        docker_server_url: None,
        terraform_hostname: None,
        aliyun_profile: None,
        oxide_scope: None,
        goat_scope: None,
        ordercli_scope: None,
        openhue_scope: None,
        uaa_scope: None,
        railway_scope: None,
        wakatime_api_url: None,
    })
}

pub(super) fn docker_credential(key: String, server_url: String) -> Result<String, String> {
    validate_key_name(&key)?;
    let request = ApprovalRequest {
        op: "docker-get",
        keys: vec![key.clone()],
        target: String::new(),
        args: Vec::new(),
        cwd: crate::path_security::current_working_directory_utf8()?,
        replace_existing_env: false,
        allow_missing_keys: false,
        env_conflicts: Vec::new(),
        shebang_script: None,
        script_data: None,
        snapshot_incompatible_interpreter: None,
        tool: Some("docker"),
        docker_server_url: Some(server_url),
        terraform_hostname: None,
        aliyun_profile: None,
        oxide_scope: None,
        goat_scope: None,
        ordercli_scope: None,
        openhue_scope: None,
        uaa_scope: None,
        railway_scope: None,
        wakatime_api_url: None,
    };
    if crate::test_keychain_dir().is_some() {
        return load_test_secret_if_present(&key)?
            .ok_or_else(|| format!("failed to load secret {key}: -25300"));
    }
    xpc_approve_injection(&request)?
        .remove(&key)
        .ok_or_else(|| format!("Automic Vault returned no Docker credential for {key}"))
}

pub(super) fn terraform_credential(key: String, hostname: String) -> Result<String, String> {
    validate_key_name(&key)?;
    let request = ApprovalRequest {
        op: "terraform-get",
        keys: vec![key.clone()],
        target: String::new(),
        args: Vec::new(),
        cwd: crate::path_security::current_working_directory_utf8()?,
        replace_existing_env: false,
        allow_missing_keys: false,
        env_conflicts: Vec::new(),
        shebang_script: None,
        script_data: None,
        snapshot_incompatible_interpreter: None,
        tool: Some("terraform"),
        docker_server_url: None,
        terraform_hostname: Some(hostname),
        aliyun_profile: None,
        oxide_scope: None,
        goat_scope: None,
        ordercli_scope: None,
        openhue_scope: None,
        uaa_scope: None,
        railway_scope: None,
        wakatime_api_url: None,
    };
    if crate::test_keychain_dir().is_some() {
        return load_test_secret_if_present(&key)?
            .ok_or_else(|| format!("failed to load secret {key}: -25300"));
    }
    xpc_approve_injection(&request)?
        .remove(&key)
        .ok_or_else(|| format!("Automic Vault returned no Terraform credential for {key}"))
}

pub(super) fn aliyun_credential(key: String, profile: String) -> Result<String, String> {
    validate_key_name(&key)?;
    let request = ApprovalRequest {
        op: "aliyun-get",
        keys: vec![key.clone()],
        target: String::new(),
        args: Vec::new(),
        cwd: crate::path_security::current_working_directory_utf8()?,
        replace_existing_env: false,
        allow_missing_keys: false,
        env_conflicts: Vec::new(),
        shebang_script: None,
        script_data: None,
        snapshot_incompatible_interpreter: None,
        tool: Some("aliyun-cli"),
        docker_server_url: None,
        terraform_hostname: None,
        aliyun_profile: Some(profile),
        oxide_scope: None,
        goat_scope: None,
        ordercli_scope: None,
        openhue_scope: None,
        uaa_scope: None,
        railway_scope: None,
        wakatime_api_url: None,
    };
    if crate::test_keychain_dir().is_some() {
        return load_test_secret_if_present(&key)?
            .ok_or_else(|| format!("failed to load secret {key}: -25300"));
    }
    xpc_approve_injection(&request)?
        .remove(&key)
        .ok_or_else(|| format!("Automic Vault returned no Alibaba Cloud credential for {key}"))
}

pub(super) fn wakatime_credential(key: String, api_url: String) -> Result<String, String> {
    validate_key_name(&key)?;
    let request = ApprovalRequest {
        op: "wakatime-get",
        keys: vec![key.clone()],
        target: String::new(),
        args: Vec::new(),
        cwd: crate::path_security::current_working_directory_utf8()?,
        replace_existing_env: false,
        allow_missing_keys: false,
        env_conflicts: Vec::new(),
        shebang_script: None,
        script_data: None,
        snapshot_incompatible_interpreter: None,
        tool: Some("wakatime-cli"),
        docker_server_url: None,
        terraform_hostname: None,
        aliyun_profile: None,
        oxide_scope: None,
        goat_scope: None,
        ordercli_scope: None,
        openhue_scope: None,
        uaa_scope: None,
        railway_scope: None,
        wakatime_api_url: Some(api_url),
    };
    if crate::test_keychain_dir().is_some() {
        return load_test_secret_if_present(&key)?
            .ok_or_else(|| format!("failed to load secret {key}: -25300"));
    }
    xpc_approve_injection(&request)?
        .remove(&key)
        .ok_or_else(|| format!("Automic Vault returned no WakaTime credential for {key}"))
}

pub(super) fn oxide_credential(key: String, scope: String) -> Result<String, String> {
    validate_key_name(&key)?;
    let request = ApprovalRequest {
        op: "oxide-get",
        keys: vec![key.clone()],
        target: String::new(),
        args: Vec::new(),
        cwd: crate::path_security::current_working_directory_utf8()?,
        replace_existing_env: false,
        allow_missing_keys: false,
        env_conflicts: Vec::new(),
        shebang_script: None,
        script_data: None,
        snapshot_incompatible_interpreter: None,
        tool: Some("oxide-cli"),
        docker_server_url: None,
        terraform_hostname: None,
        aliyun_profile: None,
        oxide_scope: Some(scope),
        goat_scope: None,
        ordercli_scope: None,
        openhue_scope: None,
        uaa_scope: None,
        railway_scope: None,
        wakatime_api_url: None,
    };
    if crate::test_keychain_dir().is_some() {
        return load_test_secret_if_present(&key)?
            .ok_or_else(|| format!("failed to load secret {key}: -25300"));
    }
    xpc_approve_injection(&request)?
        .remove(&key)
        .ok_or_else(|| format!("Automic Vault returned no Oxide credential for {key}"))
}

pub(super) fn goat_credential(key: String, scope: String) -> Result<String, String> {
    validate_key_name(&key)?;
    let request = ApprovalRequest {
        op: "goat-get",
        keys: vec![key.clone()],
        target: String::new(),
        args: Vec::new(),
        cwd: crate::path_security::current_working_directory_utf8()?,
        replace_existing_env: false,
        allow_missing_keys: false,
        env_conflicts: Vec::new(),
        shebang_script: None,
        script_data: None,
        snapshot_incompatible_interpreter: None,
        tool: Some("goat"),
        docker_server_url: None,
        terraform_hostname: None,
        aliyun_profile: None,
        oxide_scope: None,
        goat_scope: Some(scope),
        ordercli_scope: None,
        openhue_scope: None,
        uaa_scope: None,
        railway_scope: None,
        wakatime_api_url: None,
    };
    if crate::test_keychain_dir().is_some() {
        return load_test_secret_if_present(&key)?
            .ok_or_else(|| format!("failed to load secret {key}: -25300"));
    }
    xpc_approve_injection(&request)?
        .remove(&key)
        .ok_or_else(|| format!("Automic Vault returned no goat credential for {key}"))
}

pub(super) fn railway_credential(key: String, scope: String) -> Result<String, String> {
    validate_key_name(&key)?;
    let request = ApprovalRequest {
        op: "railway-get",
        keys: vec![key.clone()],
        target: String::new(),
        args: Vec::new(),
        cwd: crate::path_security::current_working_directory_utf8()?,
        replace_existing_env: false,
        allow_missing_keys: false,
        env_conflicts: Vec::new(),
        shebang_script: None,
        script_data: None,
        snapshot_incompatible_interpreter: None,
        tool: Some("railway"),
        docker_server_url: None,
        terraform_hostname: None,
        aliyun_profile: None,
        oxide_scope: None,
        goat_scope: None,
        ordercli_scope: None,
        openhue_scope: None,
        uaa_scope: None,
        railway_scope: Some(scope),
        wakatime_api_url: None,
    };
    if crate::test_keychain_dir().is_some() {
        return load_test_secret_if_present(&key)?
            .ok_or_else(|| format!("failed to load secret {key}: -25300"));
    }
    xpc_approve_injection(&request)?
        .remove(&key)
        .ok_or_else(|| format!("Automic Vault returned no Railway credential for {key}"))
}

pub(super) fn ordercli_credential(key: String, scope: String) -> Result<String, String> {
    validate_key_name(&key)?;
    let request = ApprovalRequest {
        op: "ordercli-get",
        keys: vec![key.clone()],
        target: String::new(),
        args: Vec::new(),
        cwd: crate::path_security::current_working_directory_utf8()?,
        replace_existing_env: false,
        allow_missing_keys: false,
        env_conflicts: Vec::new(),
        shebang_script: None,
        script_data: None,
        snapshot_incompatible_interpreter: None,
        tool: Some("ordercli"),
        docker_server_url: None,
        terraform_hostname: None,
        aliyun_profile: None,
        oxide_scope: None,
        goat_scope: None,
        ordercli_scope: Some(scope),
        openhue_scope: None,
        uaa_scope: None,
        railway_scope: None,
        wakatime_api_url: None,
    };
    if crate::test_keychain_dir().is_some() {
        return load_test_secret_if_present(&key)?
            .ok_or_else(|| format!("failed to load secret {key}: -25300"));
    }
    xpc_approve_injection(&request)?
        .remove(&key)
        .ok_or_else(|| format!("Automic Vault returned no ordercli credential for {key}"))
}

pub(super) fn uaa_credential(key: String, scope: String) -> Result<String, String> {
    validate_key_name(&key)?;
    let request = ApprovalRequest {
        op: "uaa-get",
        keys: vec![key.clone()],
        target: String::new(),
        args: Vec::new(),
        cwd: crate::path_security::current_working_directory_utf8()?,
        replace_existing_env: false,
        allow_missing_keys: false,
        env_conflicts: Vec::new(),
        shebang_script: None,
        script_data: None,
        snapshot_incompatible_interpreter: None,
        tool: Some("uaa-cli"),
        docker_server_url: None,
        terraform_hostname: None,
        aliyun_profile: None,
        oxide_scope: None,
        goat_scope: None,
        ordercli_scope: None,
        openhue_scope: None,
        uaa_scope: Some(scope),
        railway_scope: None,
        wakatime_api_url: None,
    };
    if crate::test_keychain_dir().is_some() {
        return load_test_secret_if_present(&key)?
            .ok_or_else(|| format!("failed to load secret {key}: -25300"));
    }
    xpc_approve_injection(&request)?
        .remove(&key)
        .ok_or_else(|| format!("Automic Vault returned no UAA credential for {key}"))
}

pub(super) fn openhue_credential(key: String, scope: String) -> Result<String, String> {
    validate_key_name(&key)?;
    let request = ApprovalRequest {
        op: "openhue-get",
        keys: vec![key.clone()],
        target: String::new(),
        args: Vec::new(),
        cwd: crate::path_security::current_working_directory_utf8()?,
        replace_existing_env: false,
        allow_missing_keys: false,
        env_conflicts: Vec::new(),
        shebang_script: None,
        script_data: None,
        snapshot_incompatible_interpreter: None,
        tool: Some("openhue-cli"),
        docker_server_url: None,
        terraform_hostname: None,
        aliyun_profile: None,
        oxide_scope: None,
        goat_scope: None,
        ordercli_scope: None,
        openhue_scope: Some(scope),
        uaa_scope: None,
        railway_scope: None,
        wakatime_api_url: None,
    };
    if crate::test_keychain_dir().is_some() {
        return load_test_secret_if_present(&key)?
            .ok_or_else(|| format!("failed to load secret {key}: -25300"));
    }
    xpc_approve_injection(&request)?
        .remove(&key)
        .ok_or_else(|| format!("Automic Vault returned no OpenHue credential for {key}"))
}

pub(super) fn plumber_credential(key: String, scope: String) -> Result<String, String> {
    validate_key_name(&key)?;
    crate::cli::plumber_credential::parse_scope(&scope)?;
    let request = ApprovalRequest {
        op: "plumber-get",
        keys: vec![key.clone()],
        target: String::new(),
        args: Vec::new(),
        cwd: crate::path_security::current_working_directory_utf8()?,
        replace_existing_env: false,
        allow_missing_keys: false,
        env_conflicts: Vec::new(),
        shebang_script: None,
        script_data: None,
        snapshot_incompatible_interpreter: None,
        tool: Some("plumber"),
        docker_server_url: None,
        terraform_hostname: None,
        aliyun_profile: None,
        oxide_scope: None,
        goat_scope: None,
        ordercli_scope: None,
        openhue_scope: None,
        uaa_scope: None,
        railway_scope: None,
        wakatime_api_url: None,
    };
    if crate::test_keychain_dir().is_some() {
        return load_test_secret_if_present(&key)?
            .ok_or_else(|| format!("failed to load secret {key}: -25300"));
    }
    xpc_approve_injection(&request)?
        .remove(&key)
        .ok_or_else(|| format!("Automic Vault returned no Plumber config for {key}"))
}

struct VerifiedScript {
    file: File,
    path: PathBuf,
    data: Vec<u8>,
}

impl VerifiedScript {
    fn open(path: &OsString) -> Result<Self, String> {
        let path = std::fs::canonicalize(path)
            .map_err(|err| format!("failed to resolve script {}: {err}", path.to_string_lossy()))?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|err| format!("failed to open script {}: {err}", path.display()))?;
        if !file
            .metadata()
            .map_err(|err| format!("failed to inspect script {}: {err}", path.display()))?
            .is_file()
        {
            return Err(format!("script is not a regular file: {}", path.display()));
        }
        let mut data = Vec::new();
        Read::by_ref(&mut file)
            .take(1024 * 1024 + 1)
            .read_to_end(&mut data)
            .map_err(|err| format!("failed to read script {}: {err}", path.display()))?;
        if data.len() > 1024 * 1024 {
            return Err("script exceeds the 1 MiB blessing limit".into());
        }
        let mut template = CString::new("/tmp/automic-vault-script.XXXXXX")
            .unwrap()
            .into_bytes_with_nul();
        let descriptor = unsafe { libc::mkstemp(template.as_mut_ptr().cast()) };
        if descriptor == -1 {
            return Err(format!(
                "failed to snapshot verified script: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        if unsafe { libc::unlink(template.as_ptr().cast()) } == -1 {
            return Err(format!(
                "failed to unlink verified script snapshot: {}",
                std::io::Error::last_os_error()
            ));
        }
        file.write_all(&data)
            .and_then(|()| file.rewind())
            .map_err(|err| format!("failed to snapshot verified script: {err}"))?;
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) } == -1 {
            return Err(format!(
                "failed to preserve verified script descriptor: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self { file, path, data })
    }
}

fn os_display(value: &OsString) -> String {
    value.to_string_lossy().into_owned()
}

fn infer_shebang_script(options: &Options) -> Option<OsString> {
    options.args.iter().find_map(|script| {
        let contents = std::fs::read_to_string(script).ok()?;
        let first_line = contents.lines().next()?;
        (first_line.starts_with("#!") && first_line.contains("av inject")).then(|| script.clone())
    })
}

fn build_env(
    options: &Options,
    stderr: &mut dyn Write,
    secrets: SecretValues,
) -> Result<BTreeMap<OsString, OsString>, String> {
    let mut env = std::env::vars_os().collect::<BTreeMap<_, _>>();
    for key in &options.keys {
        if env.contains_key(std::ffi::OsStr::new(key)) && !options.replace_existing_env {
            writeln!(
                stderr,
                "av inject: warning: environment variable {key} is already set; leaving existing value unchanged (replace with: --replace-existing-env)"
            )
            .ok();
            continue;
        }
        let value = if let Some(value) = secrets.get(key) {
            Some(value.clone())
        } else {
            load_test_secret_if_present(key)?
        };
        match value {
            Some(value) => {
                env.insert(OsString::from(key), OsString::from(value));
            }
            None if options.allow_missing_keys => {}
            None => return Err(format!("failed to load secret {key}: -25300")),
        }
    }
    Ok(env)
}

fn load_test_secret_if_present(key: &str) -> Result<Option<String>, String> {
    if let Some(dir) = crate::test_keychain_dir() {
        let current = std::env::current_dir()
            .map_err(|err| format!("failed to determine working directory: {err}"))?;
        if let Some(value) = load_test_project_secret(&dir, &current, key)? {
            return Ok(Some(value));
        }
        let path = std::path::PathBuf::from(dir).join(key);
        return match std::fs::read_to_string(&path) {
            Ok(value) => Ok(Some(value)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(format!("failed to read {}: {err}", path.display())),
        };
    }
    if let Some(value) = crate::test_env_string(&format!("AUTOMIC_VAULT_TEST_{key}")) {
        return Ok(Some(value));
    }
    Ok(None)
}

fn load_test_project_secret(
    keychain_directory: &Path,
    working_directory: &Path,
    key: &str,
) -> Result<Option<String>, String> {
    let mut current = std::fs::canonicalize(working_directory).map_err(|err| {
        format!(
            "failed to resolve working directory {}: {err}",
            working_directory.display()
        )
    })?;
    let device = current
        .metadata()
        .map_err(|err| format!("failed to inspect working directory: {err}"))?
        .dev();
    loop {
        let project = current
            .to_str()
            .ok_or("working directory must be valid UTF-8")?;
        let path = crate::secrets::test_project_secret_path(keychain_directory, project, key);
        match std::fs::read_to_string(&path) {
            Ok(value) => return Ok(Some(value)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
        }
        let Some(parent) = current.parent() else {
            break;
        };
        let parent = parent.to_path_buf();
        if parent == current
            || parent
                .metadata()
                .map_err(|err| format!("failed to inspect working directory parent: {err}"))?
                .dev()
                != device
        {
            break;
        }
        current = parent;
    }
    Ok(None)
}

pub(super) fn resolve_target(target: &OsString) -> Result<PathBuf, String> {
    let path = Path::new(target);
    if path.components().count() > 1 {
        if !path.is_absolute() {
            return Err("target binary path must be absolute".into());
        }
        return Ok(path.to_path_buf());
    }
    let paths = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(path);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "target command not found on PATH: {}",
        path.display()
    ))
}

pub(super) fn validate_key_name(key: &str) -> Result<(), String> {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return Err("empty secret name".into());
    };
    if !(first == '_' || first.is_ascii_alphabetic())
        || chars.any(|ch| !(ch == '_' || ch.is_ascii_alphanumeric()))
    {
        return Err(format!("invalid secret name: {key}"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn approve_injection(request: &ApprovalRequest) -> Result<SecretValues, String> {
    if crate::test_keychain_dir().is_some() {
        return Ok(SecretValues::new());
    }
    xpc_approve_injection(request)
}

#[cfg(not(target_os = "macos"))]
fn approve_injection(_request: &ApprovalRequest) -> Result<SecretValues, String> {
    Err("menu bar approval is only available on macOS".into())
}

#[cfg(target_os = "macos")]
fn xpc_approve_injection(request: &ApprovalRequest) -> Result<SecretValues, String> {
    xpc_approve_request(request, &request.keys)
}

#[cfg(target_os = "macos")]
pub(super) fn approve_gpg_signing(
    target: String,
    args: Vec<String>,
    cwd: String,
    response_keys: &[String],
) -> Result<SecretValues, String> {
    xpc_approve_request(
        &ApprovalRequest {
            op: "gpg-sign",
            keys: Vec::new(),
            target,
            args,
            cwd,
            replace_existing_env: false,
            allow_missing_keys: false,
            env_conflicts: Vec::new(),
            shebang_script: None,
            script_data: None,
            snapshot_incompatible_interpreter: None,
            tool: Some("gpg-signing"),
            docker_server_url: None,
            terraform_hostname: None,
            aliyun_profile: None,
            oxide_scope: None,
            goat_scope: None,
            ordercli_scope: None,
            openhue_scope: None,
            uaa_scope: None,
            railway_scope: None,
            wakatime_api_url: None,
        },
        response_keys,
    )
}

#[cfg(not(target_os = "macos"))]
pub(super) fn approve_gpg_signing(
    _target: String,
    _args: Vec<String>,
    _cwd: String,
    _response_keys: &[String],
) -> Result<SecretValues, String> {
    Err("GPG signing approval is only available on macOS".into())
}

#[cfg(target_os = "macos")]
fn xpc_approve_request(
    request: &ApprovalRequest,
    response_keys: &[String],
) -> Result<SecretValues, String> {
    use std::os::raw::{c_char, c_int, c_void};

    type XpcObject = *mut c_void;

    unsafe extern "C" {
        static _xpc_type_error: u8;
        static _xpc_error_key_description: *const c_char;

        fn xpc_connection_create_mach_service(
            name: *const c_char,
            targetq: *mut c_void,
            flags: u64,
        ) -> XpcObject;
        fn xpc_connection_activate(connection: XpcObject);
        fn xpc_connection_cancel(connection: XpcObject);
        fn xpc_connection_send_message_with_reply_sync(
            connection: XpcObject,
            message: XpcObject,
        ) -> XpcObject;
        fn xpc_dictionary_create_empty() -> XpcObject;
        fn xpc_dictionary_set_bool(xdict: XpcObject, key: *const c_char, value: bool);
        fn xpc_dictionary_get_bool(xdict: XpcObject, key: *const c_char) -> bool;
        fn xpc_dictionary_set_string(xdict: XpcObject, key: *const c_char, value: *const c_char);
        fn xpc_dictionary_set_data(
            xdict: XpcObject,
            key: *const c_char,
            bytes: *const c_void,
            length: usize,
        );
        fn xpc_dictionary_get_string(xdict: XpcObject, key: *const c_char) -> *const c_char;
        fn xpc_dictionary_get_dictionary(xdict: XpcObject, key: *const c_char) -> XpcObject;
        fn xpc_dictionary_set_value(xdict: XpcObject, key: *const c_char, value: XpcObject);
        fn xpc_array_create_empty() -> XpcObject;
        fn xpc_array_append_value(xarray: XpcObject, value: XpcObject);
        fn xpc_string_create(string: *const c_char) -> XpcObject;
        fn xpc_get_type(object: XpcObject) -> *const c_void;
        fn xpc_release(object: XpcObject);
        fn xpc_connection_set_peer_code_signing_requirement(
            connection: XpcObject,
            requirement: *const c_char,
        ) -> c_int;
        fn av_xpc_connection_set_empty_event_handler(connection: XpcObject);
    }

    unsafe fn set_string(dict: XpcObject, key: &[u8], value: &str) -> Result<(), String> {
        let value =
            CString::new(value).map_err(|_| format!("XPC field contains NUL: {value:?}"))?;
        unsafe { xpc_dictionary_set_string(dict, key.as_ptr().cast(), value.as_ptr()) };
        Ok(())
    }

    unsafe fn string_array(values: &[String]) -> Result<XpcObject, String> {
        let array = unsafe { xpc_array_create_empty() };
        for value in values {
            let value = CString::new(value.as_str())
                .map_err(|_| format!("XPC array contains NUL: {value:?}"))?;
            let string = unsafe { xpc_string_create(value.as_ptr()) };
            unsafe {
                xpc_array_append_value(array, string);
                xpc_release(string);
            }
        }
        Ok(array)
    }

    let service = CString::new(APPROVAL_SERVICE).unwrap();
    let connection =
        unsafe { xpc_connection_create_mach_service(service.as_ptr(), std::ptr::null_mut(), 0) };
    if connection.is_null() {
        return Err("failed to create approval XPC connection".into());
    }

    let menu_requirement = CString::new(crate::MENU_HELPER_CODE_SIGNING_REQUIREMENT).unwrap();
    let requirement_status = unsafe {
        xpc_connection_set_peer_code_signing_requirement(connection, menu_requirement.as_ptr())
    };
    if requirement_status != 0 {
        unsafe { xpc_release(connection) };
        return Err("failed to configure approval XPC signing requirement".into());
    }

    unsafe {
        av_xpc_connection_set_empty_event_handler(connection);
        xpc_connection_activate(connection);
    }

    let message = unsafe { xpc_dictionary_create_empty() };
    if message.is_null() {
        unsafe { xpc_connection_cancel(connection) };
        unsafe { xpc_release(connection) };
        return Err("failed to create approval XPC message".into());
    }

    unsafe {
        set_string(message, b"op\0", request.op)?;
        set_string(message, b"target\0", &request.target)?;
        set_string(message, b"cwd\0", &request.cwd)?;
        if let Some(script) = &request.shebang_script {
            set_string(message, b"shebang_script\0", script)?;
        }
        if let Some(data) = &request.script_data {
            xpc_dictionary_set_data(
                message,
                b"script_data\0".as_ptr().cast(),
                data.as_ptr().cast(),
                data.len(),
            );
        }
        if let Some(interpreter) = request.snapshot_incompatible_interpreter {
            set_string(message, b"snapshot_incompatible_interpreter\0", interpreter)?;
        }
        if let Some(tool) = request.tool {
            set_string(message, b"tool\0", tool)?;
        }
        if let Some(server_url) = &request.docker_server_url {
            set_string(message, b"docker_server_url\0", server_url)?;
        }
        if let Some(hostname) = &request.terraform_hostname {
            set_string(message, b"terraform_hostname\0", hostname)?;
        }
        if let Some(profile) = &request.aliyun_profile {
            set_string(message, b"aliyun_profile\0", profile)?;
        }
        if let Some(scope) = &request.oxide_scope {
            set_string(message, b"oxide_scope\0", scope)?;
        }
        if let Some(scope) = &request.goat_scope {
            set_string(message, b"goat_scope\0", scope)?;
        }
        if let Some(scope) = &request.ordercli_scope {
            set_string(message, b"ordercli_scope\0", scope)?;
        }
        if let Some(scope) = &request.openhue_scope {
            set_string(message, b"openhue_scope\0", scope)?;
        }
        if let Some(scope) = &request.uaa_scope {
            set_string(message, b"uaa_scope\0", scope)?;
        }
        if let Some(scope) = &request.railway_scope {
            set_string(message, b"railway_scope\0", scope)?;
        }
        if let Some(api_url) = &request.wakatime_api_url {
            set_string(message, b"wakatime_api_url\0", api_url)?;
        }
        xpc_dictionary_set_bool(
            message,
            b"replace_existing_env\0".as_ptr().cast(),
            request.replace_existing_env,
        );
        xpc_dictionary_set_bool(
            message,
            b"allow_missing_keys\0".as_ptr().cast(),
            request.allow_missing_keys,
        );

        let keys = string_array(&request.keys)?;
        xpc_dictionary_set_value(message, b"keys\0".as_ptr().cast(), keys);
        xpc_release(keys);

        let args = string_array(&request.args)?;
        xpc_dictionary_set_value(message, b"args\0".as_ptr().cast(), args);
        xpc_release(args);

        let conflicts = string_array(&request.env_conflicts)?;
        xpc_dictionary_set_value(message, b"env_conflicts\0".as_ptr().cast(), conflicts);
        xpc_release(conflicts);
    }

    let reply = unsafe { xpc_connection_send_message_with_reply_sync(connection, message) };
    unsafe {
        xpc_release(message);
        xpc_connection_cancel(connection);
        xpc_release(connection);
    }
    if reply.is_null() {
        return Err("Automic Vault approval did not reply".into());
    }

    let result = unsafe {
        if xpc_get_type(reply) == std::ptr::addr_of!(_xpc_type_error).cast() {
            let error = xpc_dictionary_get_string(reply, _xpc_error_key_description);
            let error = if error.is_null() {
                "approval XPC connection failed".into()
            } else {
                std::ffi::CStr::from_ptr(error)
                    .to_string_lossy()
                    .into_owned()
            };
            if error == "Connection invalid" {
                Err(
                    approval_service_unavailable_message(sandbox_denies_mach_lookup(&service))
                        .into(),
                )
            } else {
                Err(error)
            }
        } else {
            let decision =
                xpc_dictionary_get_string(reply, b"human_approval_decision\0".as_ptr().cast());
            if !decision.is_null() {
                if let Some(decision) =
                    human_approval_message(std::ffi::CStr::from_ptr(decision).to_bytes())
                {
                    eprintln!("automic vault: {decision}");
                }
            }
            if xpc_dictionary_get_bool(reply, b"ok\0".as_ptr().cast()) {
                let mut secrets = SecretValues::new();
                let values = xpc_dictionary_get_dictionary(reply, b"secrets\0".as_ptr().cast());
                if !values.is_null() {
                    for key in response_keys {
                        let key_cstr = CString::new(key.as_str())
                            .map_err(|_| format!("invalid key returned by approval: {key:?}"))?;
                        let value = xpc_dictionary_get_string(values, key_cstr.as_ptr());
                        if !value.is_null() {
                            secrets.insert(
                                key.clone(),
                                std::ffi::CStr::from_ptr(value)
                                    .to_string_lossy()
                                    .into_owned(),
                            );
                        }
                    }
                }
                Ok(secrets)
            } else {
                let error = xpc_dictionary_get_string(reply, b"error\0".as_ptr().cast());
                Err(if error.is_null() {
                    "injection denied".into()
                } else {
                    std::ffi::CStr::from_ptr(error)
                        .to_string_lossy()
                        .into_owned()
                })
            }
        }
    };
    unsafe { xpc_release(reply) };
    result
}

#[cfg(target_os = "macos")]
fn sandbox_denies_mach_lookup(service: &std::ffi::CStr) -> bool {
    use std::os::raw::{c_char, c_int};

    #[link(name = "sandbox")]
    unsafe extern "C" {
        fn sandbox_check(pid: libc::pid_t, operation: *const c_char, filter: c_int, ...) -> c_int;
    }

    const SANDBOX_FILTER_GLOBAL_NAME: c_int = 2;
    unsafe {
        sandbox_check(
            libc::getpid(),
            c"mach-lookup".as_ptr(),
            SANDBOX_FILTER_GLOBAL_NAME,
            service.as_ptr(),
        ) != 0
    }
}

fn approval_service_unavailable_message(sandbox_denied: bool) -> &'static str {
    if sandbox_denied {
        "Automic Vault approval service is blocked by this process's sandbox; retry with elevated permissions"
    } else {
        "Automic Vault approval service is not running; open the menu bar app"
    }
}

fn human_approval_message(decision: &[u8]) -> Option<&'static str> {
    match decision {
        b"approved" => Some("approved"),
        b"denied" => Some("denied"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_only_known_human_approval_decisions() {
        assert_eq!(human_approval_message(b"approved"), Some("approved"));
        assert_eq!(human_approval_message(b"denied"), Some("denied"));
        assert_eq!(human_approval_message(b"unexpected"), None);
    }

    #[test]
    fn connection_error_explains_sandbox_denial() {
        assert_eq!(
            approval_service_unavailable_message(true),
            "Automic Vault approval service is blocked by this process's sandbox; retry with elevated permissions"
        );
    }

    fn os(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn temp_script(contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "av-inject-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn parses_old_and_separator_forms() {
        assert_eq!(
            parse(os(&["+B", "+A", "/bin/echo", "hi"])).unwrap(),
            Options {
                replace_existing_env: false,
                allow_missing_keys: false,
                keys: vec!["A".into(), "B".into()],
                target: "/bin/echo".into(),
                args: os(&["hi"]),
                shebang_script: None,
            }
        );
        assert_eq!(
            parse(os(&["--allow-missing-keys", "+A", "--", "env"]))
                .unwrap()
                .target,
            OsString::from("env")
        );
        assert_eq!(
            parse(os(&["--", "/bin/echo"])).unwrap().keys,
            Vec::<String>::new()
        );
    }

    #[test]
    fn denied_approval_does_not_load_secrets() {
        let options = Options {
            replace_existing_env: false,
            allow_missing_keys: false,
            keys: vec!["SOME_SECRET".into()],
            target: "/bin/echo".into(),
            args: os(&["hi"]),
            shebang_script: None,
        };
        let mut stderr = Vec::new();
        let err = prepare_injection(
            &options,
            &mut stderr,
            None,
            None,
            |_| Err("user denied injection".into()),
            |_, _, _| panic!("approval denial must happen before loading secrets"),
        )
        .unwrap_err();

        assert_eq!(err, "user denied injection");
    }

    #[test]
    fn builds_approval_request_without_secret_values() {
        let options = Options {
            replace_existing_env: true,
            allow_missing_keys: true,
            keys: vec!["A".into(), "B".into()],
            target: "/bin/echo".into(),
            args: os(&["hi"]),
            shebang_script: Some("/tmp/tool".into()),
        };
        let request = approval_request(
            &options,
            Path::new("/bin/echo"),
            Some(b"script"),
            Some("uv"),
        )
        .unwrap();

        assert_eq!(request.keys, ["A", "B"]);
        assert_eq!(request.target, "/bin/echo");
        assert_eq!(request.args, ["hi"]);
        assert!(request.replace_existing_env);
        assert!(request.allow_missing_keys);
        assert_eq!(request.shebang_script.as_deref(), Some("/tmp/tool"));
        assert_eq!(request.script_data.as_deref(), Some(b"script".as_slice()));
        assert_eq!(request.snapshot_incompatible_interpreter, Some("uv"));
    }

    #[test]
    fn secretless_environment_removes_requested_secrets() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        unsafe { std::env::set_var("SOME_SECRET", "ambient") };
        let options = Options {
            replace_existing_env: false,
            allow_missing_keys: true,
            keys: vec!["SOME_SECRET".into()],
            target: "/bin/echo".into(),
            args: Vec::new(),
            shebang_script: None,
        };

        let env = secretless_environment(&options);

        unsafe { std::env::remove_var("SOME_SECRET") };
        assert!(!env.contains_key(std::ffi::OsStr::new("SOME_SECRET")));
        assert!(env.contains_key(std::ffi::OsStr::new("PATH")));
    }

    #[test]
    fn verified_script_executes_the_approved_snapshot() {
        let path = temp_script("approved");
        let mut script = VerifiedScript::open(&path.clone().into_os_string()).unwrap();
        std::fs::write(&path, "changed").unwrap();
        let mut executed = String::new();

        script.file.read_to_string(&mut executed).unwrap();

        assert_eq!(script.data, b"approved");
        assert_eq!(executed, "approved");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn uv_uses_the_canonical_script_path() {
        assert_eq!(
            path_script_interpreter(Path::new("/opt/homebrew/bin/uv"), &[]),
            Some("uv")
        );
        assert_eq!(
            path_script_interpreter(
                Path::new("/usr/local/bin/dotenvx"),
                &os(&["run", "--", "/opt/homebrew/bin/uv", "run", "--script"])
            ),
            Some("uv")
        );
        assert_eq!(
            path_script_interpreter(Path::new("/opt/homebrew/bin/python3"), &[]),
            None
        );
    }

    #[test]
    fn build_env_uses_approved_secret_values() {
        let options = Options {
            replace_existing_env: true,
            allow_missing_keys: false,
            keys: vec!["APPROVED_SECRET".into()],
            target: "/bin/echo".into(),
            args: vec![],
            shebang_script: None,
        };
        let mut secrets = SecretValues::new();
        secrets.insert("APPROVED_SECRET".into(), "expected".into());
        let mut stderr = Vec::new();

        let env = build_env(&options, &mut stderr, secrets).unwrap();

        assert_eq!(
            env.get(std::ffi::OsStr::new("APPROVED_SECRET")),
            Some(&OsString::from("expected"))
        );
    }

    #[test]
    fn test_project_secret_lookup_resolves_symlinked_working_directory() {
        use std::os::unix::fs::symlink;

        let root = PathBuf::from("/tmp").join(format!(
            "av-project-value-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let keychain = root.join("keychain");
        let project = root.join("physical/project");
        let nested = project.join("nested");
        let alias = root.join("alias");
        std::fs::create_dir_all(&nested).unwrap();
        symlink(&project, &alias).unwrap();

        let project = project.canonicalize().unwrap();
        let stored = crate::secrets::test_project_secret_path(
            &keychain,
            project.to_str().unwrap(),
            "PROJECT_SECRET",
        );
        std::fs::create_dir_all(stored.parent().unwrap()).unwrap();
        std::fs::write(stored, "expected").unwrap();

        assert_eq!(
            load_test_project_secret(&keychain, &alias.join("nested"), "PROJECT_SECRET").unwrap(),
            Some("expected".into())
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn infers_split_shebang_script_argument() {
        let script = temp_script("#!/usr/local/bin/av inject +A /bin/zsh\n");
        let options = Options {
            replace_existing_env: false,
            allow_missing_keys: false,
            keys: vec!["A".into()],
            target: "/bin/zsh".into(),
            args: vec![script.clone().into_os_string()],
            shebang_script: None,
        };

        assert_eq!(
            infer_shebang_script(&options),
            Some(script.into_os_string())
        );
    }

    #[test]
    fn infers_split_shebang_script_after_interpreter_options() {
        let script = temp_script("#!/usr/local/bin/av inject +A /bin/zsh -f\n");
        let options = Options {
            replace_existing_env: false,
            allow_missing_keys: false,
            keys: vec!["A".into()],
            target: "/bin/zsh".into(),
            args: vec!["-f".into(), script.clone().into_os_string(), "s3".into()],
            shebang_script: None,
        };

        assert_eq!(
            infer_shebang_script(&options),
            Some(script.into_os_string())
        );
    }
}
