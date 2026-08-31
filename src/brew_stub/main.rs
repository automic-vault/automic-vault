use std::ffi::{CString, OsString};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const MARKER: &str = "AUTOMIC_VAULT_BREW_STUB_V19";
const TARGET: &str = "/opt/homebrew/bin/brew";
const PREFIX: &str = "/opt/homebrew";
const SHELLENV_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
const APPROVAL_SERVICE: &str = "com.automicvault.av2.approval";
const BREW_USER_UID: &str = "/opt/homebrew/var/automic/user-uid";
const FORBIDDEN_CASK_ARTIFACTS: &str = "app appimage artifact audiounitplugin bashcompletion colorpicker commandwrapper dictionary fishcompletion font generatedscript inputmethod installer internetplugin keyboardlayout manpage mdimporter pkg postflight postflightblock postflightsteps preflight preflightblock preflightsteps prefpane qlplugin screensaver service stageonly suite uninstall uninstallpostflightsteps uninstallpreflightsteps vst3plugin vstplugin zshcompletion";

#[derive(Debug, PartialEq, Eq)]
struct AuthorizationRequest {
    target: String,
    args: Vec<String>,
    cwd: String,
}

#[derive(Debug, PartialEq, Eq)]
struct CaskMutation {
    command: String,
    names: Vec<String>,
}

fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && args[0] == "--automic-vault-brew-stub-marker" {
        println!("{MARKER}");
        return;
    }

    validate_caller().unwrap_or_else(|err| fail(err));
    let cwd = effective_cwd(std::env::current_dir());
    let mut command = approved_command(
        args,
        std::env::vars_os(),
        &cwd,
        validate_cask_mutation,
        xpc_authorize,
    )
    .unwrap_or_else(|err| fail(err));
    let status = command
        .status()
        .unwrap_or_else(|err| fail(format!("failed to run {TARGET}: {err}")));
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn fail(message: String) -> ! {
    eprintln!("av-brew-stub: {message}");
    std::process::exit(1);
}

fn approved_command<I, V, F>(
    args: Vec<OsString>,
    source_env: I,
    cwd: &Path,
    validate_cask: V,
    approve: F,
) -> Result<Command, String>
where
    I: IntoIterator<Item = (OsString, OsString)>,
    V: FnOnce(&CaskMutation, &Path) -> Result<(), String>,
    F: FnOnce(&AuthorizationRequest) -> Result<(), String>,
{
    let mut request = authorization_request(&args, cwd)?;
    let shellenv =
        command_index(&request.args).is_some_and(|index| request.args[index] == "shellenv");
    let (args, cask) = governed_args(&request.args)?;
    request.args = args;
    if let Some(cask) = &cask {
        validate_cask(cask, cwd)?;
    }
    approve(&request)?;
    let mut command = Command::new(TARGET);
    command
        .args(request.args)
        .current_dir(cwd)
        .env_clear()
        .envs(stub_env(source_env));
    if shellenv {
        command.env("PATH", SHELLENV_PATH);
    }
    if cask.is_some() {
        command.env("HOMEBREW_NO_AUTO_UPDATE", "1");
    }
    unsafe {
        command.pre_exec(drop_to_effective_identity);
    }
    Ok(command)
}

fn effective_cwd(cwd: io::Result<PathBuf>) -> PathBuf {
    cwd.ok()
        .filter(|cwd| fs::read_dir(cwd).is_ok())
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn drop_to_effective_identity() -> io::Result<()> {
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    if unsafe { libc::setregid(gid, gid) } != 0 || unsafe { libc::setreuid(uid, uid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn governed_args(args: &[String]) -> Result<(Vec<String>, Option<CaskMutation>), String> {
    if args.iter().any(|arg| arg == "--") {
        return Err("`--` is unavailable in hardened Homebrew commands".into());
    }
    let Some(command_index) = command_index(args) else {
        return Ok((args.to_vec(), None));
    };
    let command = args[command_index].as_str();
    if command == "shellenv" {
        let mut args = args.to_vec();
        if let Some(shell) = args[command_index + 1..]
            .iter_mut()
            .find(|arg| !arg.starts_with('-'))
            && shell == "zsh"
        {
            *shell = "sh".into();
        }
        return Ok((args, None));
    }
    if !matches!(
        command,
        "install" | "reinstall" | "upgrade" | "uninstall" | "remove" | "rm" | "bundle"
    ) {
        return Ok((args.to_vec(), None));
    }
    if command == "bundle" {
        return Err("`brew bundle` is unavailable because Brewfiles may contain casks; run formula commands directly".into());
    }
    let cask = args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--cask" | "--casks"));
    let formula = args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--formula" | "--formulae"));
    if cask && formula {
        return Err("brew command cannot select both formulae and casks".into());
    }
    if cask {
        let names = cask_operands(args, command_index)?;
        if names.is_empty() {
            return Err("CLI-only cask mutations must name each cask explicitly".into());
        }
        return Ok((
            args.to_vec(),
            Some(CaskMutation {
                command: command.to_string(),
                names,
            }),
        ));
    }

    let mut args = args.to_vec();
    if !formula {
        args.insert(command_index + 1, "--formula".into());
    }
    Ok((args, None))
}

fn command_index(args: &[String]) -> Option<usize> {
    args.iter().position(|arg| !arg.starts_with('-'))
}

fn cask_operands(args: &[String], command_index: usize) -> Result<Vec<String>, String> {
    const ALLOWED_FLAGS: &[&str] = &[
        "--cask",
        "--casks",
        "--debug",
        "--display-times",
        "--dry-run",
        "--force",
        "--greedy",
        "--greedy-auto-updates",
        "--greedy-latest",
        "--quiet",
        "--verbose",
    ];
    for flag in &args[..command_index] {
        if !matches!(flag.as_str(), "--debug" | "--quiet" | "--verbose") {
            return Err(format!(
                "unsupported option `{flag}` for a CLI-only cask mutation"
            ));
        }
    }
    let mut names = Vec::new();
    for arg in &args[command_index + 1..] {
        if arg == "--" {
            continue;
        }
        if arg.starts_with('-') {
            if !ALLOWED_FLAGS.contains(&arg.as_str()) {
                return Err(format!(
                    "unsupported option `{arg}` for a CLI-only cask mutation"
                ));
            }
            continue;
        }
        if !safe_cask_name(arg) {
            return Err(format!("unsupported cask name `{arg}`"));
        }
        names.push(arg.clone());
    }
    Ok(names)
}

fn safe_cask_name(name: &str) -> bool {
    let token = name.strip_prefix("homebrew/cask/").unwrap_or(name);
    !token.is_empty()
        && !token.starts_with('.')
        && !token.contains('/')
        && token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+' | b'@')
        })
}

fn validate_cask_mutation(cask: &CaskMutation, cwd: &Path) -> Result<(), String> {
    let installs = matches!(cask.command.as_str(), "install" | "reinstall" | "upgrade");
    let removes = matches!(
        cask.command.as_str(),
        "reinstall" | "upgrade" | "uninstall" | "remove" | "rm"
    );
    for name in &cask.names {
        if installs {
            let info = cask_info(name, cwd)?;
            av::brew_cask_policy::validate_info_cask(name, &info)?;
        }
        if removes {
            let receipt = installed_cask_receipt(name)?;
            av::brew_cask_policy::validate_install_receipt(name, &receipt)?;
        }
    }
    Ok(())
}

fn cask_info(name: &str, cwd: &Path) -> Result<serde_json::Value, String> {
    let output = brew_output(&["info", "--json=v2", "--cask", "--", name], cwd)?;
    let mut info: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("Homebrew returned malformed JSON: {err}"))?;
    let casks = info["casks"]
        .as_array_mut()
        .ok_or_else(|| format!("Homebrew returned malformed cask metadata for `{name}`"))?;
    if casks.len() != 1 {
        return Err(format!(
            "Homebrew returned ambiguous cask metadata for `{name}`"
        ));
    }
    Ok(casks.remove(0))
}

fn brew_output(args: &[&str], cwd: &Path) -> Result<std::process::Output, String> {
    let mut command = Command::new(TARGET);
    command
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(stub_env([]))
        .env("HOMEBREW_NO_AUTO_UPDATE", "1");
    unsafe {
        command.pre_exec(drop_to_effective_identity);
    }
    let output = command
        .output()
        .map_err(|err| format!("failed to inspect cask metadata: {err}"))?;
    if output.status.success() {
        return Ok(output);
    }
    Err(format!(
        "Homebrew cask inspection failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn installed_cask_receipt(name: &str) -> Result<serde_json::Value, String> {
    let token = name.rsplit('/').next().unwrap_or(name);
    let cask = Path::new(PREFIX).join("Caskroom").join(token);
    let metadata = fs::symlink_metadata(&cask)
        .map_err(|err| format!("failed to inspect installed cask `{name}`: {err}"))?;
    if !metadata.file_type().is_dir() {
        return Err(format!(
            "installed cask `{name}` is not a protected directory"
        ));
    }
    let path = cask.join(".metadata/INSTALL_RECEIPT.json");
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|err| format!("failed to read installed cask `{name}` receipt: {err}"))?;
    let metadata = file
        .metadata()
        .map_err(|err| format!("failed to inspect installed cask `{name}` receipt: {err}"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 1024 * 1024
    {
        return Err(format!("installed cask `{name}` receipt is not protected"));
    }
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut contents)
        .map_err(|err| format!("failed to read installed cask `{name}` receipt: {err}"))?;
    serde_json::from_slice(&contents)
        .map_err(|err| format!("installed cask `{name}` receipt is malformed: {err}"))
}

fn validate_caller() -> Result<(), String> {
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    validate_invoker(uid, euid)?;
    let configured =
        configured_user_uid(Path::new(BREW_USER_UID), euid, unsafe { libc::getegid() })?;
    if uid != configured {
        return Err(
            "brew must be invoked directly by the user configured by `av harden brew`".into(),
        );
    }
    Ok(())
}

fn validate_invoker(uid: u32, euid: u32) -> Result<(), String> {
    if uid == 0 {
        return Err("brew cannot be invoked as root".into());
    }
    if uid == euid {
        return Err("brew stub is not installed setuid; run `av harden brew`".into());
    }
    Ok(())
}

fn configured_user_uid(path: &Path, owner: u32, group: u32) -> Result<u32, String> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|err| format!("failed to read configured Homebrew user: {err}"))?;
    let metadata = file
        .metadata()
        .map_err(|err| format!("failed to inspect configured Homebrew user: {err}"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner
        || metadata.gid() != group
        || metadata.mode() & 0o022 != 0
    {
        return Err("configured Homebrew user file is not protected".into());
    }
    let mut configured = String::new();
    file.read_to_string(&mut configured)
        .map_err(|err| format!("failed to read configured Homebrew user: {err}"))?;
    configured
        .trim()
        .parse::<u32>()
        .map_err(|_| "configured Homebrew user UID is invalid".to_string())
}

fn authorization_request(args: &[OsString], cwd: &Path) -> Result<AuthorizationRequest, String> {
    let args = args
        .iter()
        .map(|arg| {
            arg.to_str()
                .map(str::to_string)
                .ok_or_else(|| "brew arguments must be valid UTF-8".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cwd = cwd
        .to_str()
        .ok_or_else(|| "current directory must be valid UTF-8".to_string())?;
    Ok(AuthorizationRequest {
        target: TARGET.to_string(),
        args,
        cwd: cwd.to_string(),
    })
}

#[cfg(target_os = "macos")]
fn xpc_authorize(request: &AuthorizationRequest) -> Result<(), String> {
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
        fn xpc_dictionary_get_string(xdict: XpcObject, key: *const c_char) -> *const c_char;
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
        let value = CString::new(value).map_err(|_| "XPC field contains NUL".to_string())?;
        unsafe { xpc_dictionary_set_string(dict, key.as_ptr().cast(), value.as_ptr()) };
        Ok(())
    }

    unsafe fn string_array(values: &[String]) -> Result<XpcObject, String> {
        let array = unsafe { xpc_array_create_empty() };
        if array.is_null() {
            return Err("failed to create approval XPC array".into());
        }
        for value in values {
            let value =
                CString::new(value.as_str()).map_err(|_| "XPC array contains NUL".to_string())?;
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

    let menu_requirement = CString::new(av::MENU_HELPER_CODE_SIGNING_REQUIREMENT).unwrap();
    if unsafe {
        xpc_connection_set_peer_code_signing_requirement(connection, menu_requirement.as_ptr())
    } != 0
    {
        unsafe { xpc_release(connection) };
        return Err("failed to configure approval XPC signing requirement".into());
    }

    unsafe {
        av_xpc_connection_set_empty_event_handler(connection);
        xpc_connection_activate(connection);
    }

    let message = unsafe { xpc_dictionary_create_empty() };
    if message.is_null() {
        unsafe {
            xpc_connection_cancel(connection);
            xpc_release(connection);
        }
        return Err("failed to create approval XPC message".into());
    }

    let empty = unsafe { string_array(&[]) }?;
    let args = unsafe { string_array(&request.args) }?;
    unsafe {
        set_string(message, b"op\0", "authorize")?;
        set_string(message, b"target\0", &request.target)?;
        set_string(message, b"cwd\0", &request.cwd)?;
        set_string(message, b"tool\0", "brew")?;
        xpc_dictionary_set_bool(message, b"replace_existing_env\0".as_ptr().cast(), false);
        xpc_dictionary_set_bool(message, b"allow_missing_keys\0".as_ptr().cast(), false);
        xpc_dictionary_set_value(message, b"keys\0".as_ptr().cast(), empty);
        xpc_dictionary_set_value(message, b"args\0".as_ptr().cast(), args);
        xpc_dictionary_set_value(message, b"env_conflicts\0".as_ptr().cast(), empty);
        xpc_release(empty);
        xpc_release(args);
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
            if av::approval_service_connection_invalid(reply) {
                Err(av::approval_service_unavailable_message(&service).into())
            } else {
                let error = xpc_dictionary_get_string(reply, _xpc_error_key_description);
                let error = if error.is_null() {
                    "approval XPC connection failed".into()
                } else {
                    std::ffi::CStr::from_ptr(error)
                        .to_string_lossy()
                        .into_owned()
                };
                Err(error)
            }
        } else if xpc_dictionary_get_bool(reply, b"ok\0".as_ptr().cast()) {
            Ok(())
        } else {
            let error = xpc_dictionary_get_string(reply, b"error\0".as_ptr().cast());
            Err(if error.is_null() {
                "brew authorization denied".into()
            } else {
                std::ffi::CStr::from_ptr(error)
                    .to_string_lossy()
                    .into_owned()
            })
        }
    };
    unsafe { xpc_release(reply) };
    result
}

#[cfg(not(target_os = "macos"))]
fn xpc_authorize(_request: &AuthorizationRequest) -> Result<(), String> {
    Err("menu bar approval is only available on macOS".into())
}

fn stub_env<I>(source: I) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut env = vec![
        (
            "PATH".into(),
            "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/bin:/bin:/usr/sbin:/sbin".into(),
        ),
        ("HOME".into(), "/opt/homebrew/var/automic".into()),
        ("USER".into(), "automic".into()),
        ("LOGNAME".into(), "automic".into()),
        ("TMPDIR".into(), "/opt/homebrew/var/automic/tmp".into()),
        (
            "HOMEBREW_CACHE".into(),
            "/opt/homebrew/var/automic/cache".into(),
        ),
        ("HOMEBREW_FORBID_PACKAGES_FROM_PATHS".into(), "1".into()),
        (
            "HOMEBREW_FORBIDDEN_CASK_ARTIFACTS".into(),
            FORBIDDEN_CASK_ARTIFACTS.into(),
        ),
        ("HOMEBREW_FORBIDDEN_OWNER".into(), "Automic Vault".into()),
    ];

    for (key, value) in source {
        let Some(key_str) = key.to_str() else {
            continue;
        };
        if key_str == "TERM"
            || key_str == "LANG"
            || key_str == "NO_COLOR"
            || key_str.starts_with("LC_")
        {
            env.push((key, value));
        }
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn authorization_request_keeps_exact_args_and_cwd() {
        let request = authorization_request(
            &[
                "install".into(),
                "--cask".into(),
                "Visual Studio Code".into(),
            ],
            Path::new("/tmp/a project"),
        )
        .unwrap();

        assert_eq!(request.target, TARGET);
        assert_eq!(request.args, ["install", "--cask", "Visual Studio Code"]);
        assert_eq!(request.cwd, "/tmp/a project");
    }

    #[test]
    fn unreadable_working_directory_falls_back_to_root() {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            effective_cwd(Err(io::Error::from(io::ErrorKind::PermissionDenied))),
            Path::new("/")
        );
        let unreadable = temp_path("unreadable-cwd");
        fs::create_dir(&unreadable).unwrap();
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(effective_cwd(Ok(unreadable.clone())), Path::new("/"));
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir(unreadable).unwrap();

        let command = approved_command(
            vec!["--version".into()],
            [],
            Path::new("/"),
            |_, _| Ok(()),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(command.get_current_dir(), Some(Path::new("/")));
    }

    #[test]
    fn denial_prevents_command_creation() {
        let result = approved_command(
            vec!["install".into(), "ack".into()],
            [],
            Path::new("/tmp"),
            |_, _| Ok(()),
            |_| Err("denied".into()),
        );

        assert_eq!(result.unwrap_err().to_string(), "denied");
    }

    #[test]
    fn approval_sees_the_formula_pinned_command() {
        let command = approved_command(
            vec!["install".into(), "tree".into()],
            [],
            Path::new("/tmp"),
            |_, _| Ok(()),
            |request| {
                assert_eq!(request.args, ["install", "--formula", "tree"]);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            ["install", "--formula", "tree"]
        );
    }

    #[test]
    fn child_identity_is_normalized() {
        drop_to_effective_identity().unwrap();
        assert_eq!(unsafe { libc::getuid() }, unsafe { libc::geteuid() });
        assert_eq!(unsafe { libc::getgid() }, unsafe { libc::getegid() });
    }

    #[test]
    fn approved_command_has_sanitized_env() {
        let command = approved_command(
            vec!["info".into(), "ack".into()],
            [
                ("TERM".into(), "xterm-256color".into()),
                ("SECRET".into(), "nope".into()),
            ],
            Path::new("/tmp"),
            |_, _| Ok(()),
            |_| Ok(()),
        )
        .unwrap();
        let env = command
            .get_envs()
            .map(|(key, value)| (key.to_owned(), value.unwrap().to_owned()))
            .collect::<Vec<_>>();

        assert!(env.contains(&("HOME".into(), "/opt/homebrew/var/automic".into())));
        assert!(env.contains(&("TERM".into(), "xterm-256color".into())));
        assert!(!env.iter().any(|(key, _)| key == "SECRET"));
    }

    #[test]
    fn shellenv_child_path_does_not_look_already_configured() {
        let command = approved_command(
            vec!["shellenv".into()],
            [],
            Path::new("/tmp"),
            |_, _| Ok(()),
            |_| Ok(()),
        )
        .unwrap();
        let path = command
            .get_envs()
            .find(|(key, _)| *key == "PATH")
            .and_then(|(_, value)| value)
            .unwrap();

        assert_eq!(path, SHELLENV_PATH);
    }

    #[test]
    fn unsupported_cask_is_rejected_before_authorization() {
        let mut authorized = false;
        let expected = "Hardened Homebrew does not support cask `zed`: its `uninstall` artifact is outside Automic Vault's CLI-only cask support";
        let error = approved_command(
            vec!["install".into(), "--cask".into(), "zed".into()],
            [],
            Path::new("/tmp"),
            |cask, _| {
                av::brew_cask_policy::validate_info_cask(
                    &cask.names[0],
                    &serde_json::json!({
                        "tap": "homebrew/cask",
                        "artifacts": [{"uninstall": [{"quit": "dev.zed.Zed"}]}]
                    }),
                )
            },
            |_| {
                authorized = true;
                Ok(())
            },
        )
        .unwrap_err();

        assert_eq!(error, expected);
        assert!(!authorized);
    }

    #[test]
    fn stub_env_keeps_only_safe_user_env() {
        let env = stub_env([
            ("TERM".into(), "xterm-256color".into()),
            ("LANG".into(), "en_US.UTF-8".into()),
            ("LC_ALL".into(), "C".into()),
            ("NO_COLOR".into(), "1".into()),
            ("HOMEBREW_PREFIX".into(), "/tmp/bad".into()),
            ("PATH".into(), "/tmp/bad".into()),
        ]);

        assert!(env.contains(&("HOME".into(), "/opt/homebrew/var/automic".into())));
        assert!(env.contains(&("USER".into(), "automic".into())));
        assert!(env.contains(&("LOGNAME".into(), "automic".into())));
        assert!(env.contains(&("TERM".into(), "xterm-256color".into())));
        assert!(env.contains(&("LC_ALL".into(), "C".into())));
        assert!(!env.contains(&("HOMEBREW_PREFIX".into(), "/tmp/bad".into())));
        assert!(!env.contains(&("PATH".into(), "/tmp/bad".into())));
    }

    #[test]
    fn mutations_are_pinned_to_formulae() {
        assert_eq!(
            governed_args(&["install".into(), "tree".into()]).unwrap(),
            (
                vec!["install".into(), "--formula".into(), "tree".into()],
                None
            )
        );
        assert_eq!(
            governed_args(&["upgrade".into(), "--formula".into()]).unwrap(),
            (vec!["upgrade".into(), "--formula".into()], None)
        );
        assert_eq!(
            governed_args(&["info".into(), "install".into()]).unwrap(),
            (vec!["info".into(), "install".into()], None)
        );
        assert_eq!(
            governed_args(&[
                "--".into(),
                "install".into(),
                "--cask".into(),
                "codex".into(),
            ])
            .unwrap_err(),
            "`--` is unavailable in hardened Homebrew commands"
        );
    }

    #[test]
    fn zsh_shellenv_does_not_enable_protected_completions() {
        assert_eq!(
            governed_args(&["shellenv".into(), "zsh".into()]).unwrap(),
            (vec!["shellenv".into(), "sh".into()], None)
        );
        assert_eq!(
            governed_args(&["shellenv".into(), "fish".into()]).unwrap(),
            (vec!["shellenv".into(), "fish".into()], None)
        );
    }

    #[test]
    fn cli_cask_mutations_are_explicit_and_restricted() {
        assert_eq!(
            governed_args(&["install".into(), "--cask".into(), "codex".into()]).unwrap(),
            (
                vec!["install".into(), "--cask".into(), "codex".into()],
                Some(CaskMutation {
                    command: "install".into(),
                    names: vec!["codex".into()]
                })
            )
        );
        assert!(
            governed_args(&[
                "install".into(),
                "--cask".into(),
                "homebrew/cask/codex".into()
            ])
            .is_ok()
        );
        for args in [
            vec!["upgrade".into(), "--cask".into()],
            vec![
                "uninstall".into(),
                "--cask".into(),
                "--zap".into(),
                "codex".into(),
            ],
            vec!["install".into(), "--cask".into(), "./codex.rb".into()],
            vec!["install".into(), "--cask".into(), "other/tap/codex".into()],
            vec![
                "install".into(),
                "--cask".into(),
                "--formula".into(),
                "codex".into(),
            ],
        ] {
            assert!(governed_args(&args).is_err());
        }
        assert!(
            governed_args(&["bundle".into()])
                .unwrap_err()
                .contains("Brewfiles may contain casks")
        );
        assert_eq!(
            governed_args(&["list".into(), "--cask".into()]).unwrap(),
            (vec!["list".into(), "--cask".into()], None)
        );
    }

    #[test]
    fn configured_user_must_come_from_a_protected_file() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_path("user");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("uid");
        fs::write(&path, "501\n").unwrap();
        let metadata = fs::metadata(&path).unwrap();

        assert_eq!(
            configured_user_uid(&path, metadata.uid(), metadata.gid()),
            Ok(501)
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(configured_user_uid(&path, metadata.uid(), metadata.gid()).is_err());

        let link = root.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(configured_user_uid(&link, metadata.uid(), metadata.gid()).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invoker_errors_identify_root_and_missing_setuid() {
        assert_eq!(
            validate_invoker(0, 550).unwrap_err(),
            "brew cannot be invoked as root"
        );
        assert_eq!(
            validate_invoker(501, 501).unwrap_err(),
            "brew stub is not installed setuid; run `av harden brew`"
        );
        assert!(validate_invoker(501, 550).is_ok());
    }

    fn temp_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("av-brew-stub-{label}-{nanos}"))
    }
}
