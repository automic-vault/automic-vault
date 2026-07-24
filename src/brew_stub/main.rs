use std::ffi::{CStr, CString, OsString};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const MARKER: &str = "AUTOMIC_VAULT_BREW_STUB_V4";
const TARGET: &str = "/opt/homebrew/bin/brew";
const APPROVAL_SERVICE: &str = "com.automicvault.av2.approval";
const CASK_USER_UID: &str = "/opt/homebrew/var/automic/cask-user-uid";

#[derive(Debug, PartialEq, Eq)]
struct AuthorizationRequest {
    target: String,
    args: Vec<String>,
    cwd: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Caller {
    uid: u32,
    gid: u32,
}

#[derive(Debug, PartialEq, Eq)]
struct CaskPostInstall {
    caller: Caller,
    apps: Vec<PathBuf>,
}

fn main() {
    if std::env::args().any(|arg| arg == "--automic-vault-brew-stub-marker") {
        println!("{MARKER}");
        return;
    }

    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(err) => fail(format!("failed to read current directory: {err}")),
    };
    let (mut command, post_install) =
        approved_command(args, std::env::vars_os(), &cwd, xpc_authorize)
            .unwrap_or_else(|err| fail(err));
    if let Some(post_install) = post_install {
        let status = command
            .status()
            .unwrap_or_else(|err| fail(format!("failed to run {TARGET}: {err}")));
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
        transfer_app_ownership(&post_install).unwrap_or_else(|err| fail(err));
        return;
    }
    let err = command.exec();
    fail(format!("failed to exec {TARGET}: {err}"));
}

fn fail(message: String) -> ! {
    eprintln!("av-brew-stub: {message}");
    std::process::exit(1);
}

fn approved_command<I, F>(
    args: Vec<OsString>,
    source_env: I,
    cwd: &Path,
    approve: F,
) -> Result<(Command, Option<CaskPostInstall>), String>
where
    I: IntoIterator<Item = (OsString, OsString)>,
    F: FnOnce(&AuthorizationRequest) -> Result<(), String>,
{
    let request = authorization_request(&args, cwd)?;
    approve(&request)?;
    let (args, post_install) = prepare_args(&request.args, cwd)?;
    let mut command = Command::new(TARGET);
    command.args(args).env_clear().envs(stub_env(source_env));
    if command
        .get_args()
        .any(|arg| matches!(arg.to_str(), Some("--cask" | "--casks")))
    {
        command.env("HOMEBREW_NO_AUTO_UPDATE", "1");
    }
    Ok((command, post_install))
}

fn prepare_args(
    args: &[String],
    cwd: &Path,
) -> Result<(Vec<String>, Option<CaskPostInstall>), String> {
    let Some((command_index, command)) = mutation_command(args) else {
        return Ok((args.to_vec(), None));
    };

    let options = args[command_index + 1..]
        .iter()
        .take_while(|arg| arg.as_str() != "--")
        .collect::<Vec<_>>();
    let cask_flag = options
        .iter()
        .any(|arg| matches!(arg.as_str(), "--cask" | "--casks"));
    let formula_flag = options
        .iter()
        .any(|arg| matches!(arg.as_str(), "--formula" | "--formulae"));
    if cask_flag && formula_flag {
        return Err("brew command cannot select both formulae and casks".into());
    }

    let mut operands = named_operands(args, command_index);
    if operands.is_empty() {
        if command == "upgrade" && cask_flag {
            operands = brew_lines(&["list", "--cask", "--full-name"], cwd)?;
        } else if command == "upgrade" && !formula_flag {
            return Err(
                "unqualified `brew upgrade` may mix formulae and casks; run `brew upgrade --formula` and `brew upgrade --cask` separately".into(),
            );
        } else {
            return Ok((args.to_vec(), None));
        }
    }

    let is_cask = if cask_flag {
        true
    } else if formula_flag {
        false
    } else {
        let kinds = operands
            .iter()
            .map(|operand| resolve_package(operand, cwd))
            .collect::<Result<Vec<_>, _>>()?;
        if kinds.iter().all(|kind| *kind == PackageKind::Cask) {
            true
        } else if kinds.iter().all(|kind| *kind == PackageKind::Formula) {
            false
        } else {
            return Err(
                "brew command mixes formulae and casks; split it into separate `--formula` and `--cask` commands".into(),
            );
        }
    };

    let mut pinned = args.to_vec();
    if !cask_flag && !formula_flag {
        pinned.insert(
            command_index + 1,
            if is_cask { "--cask" } else { "--formula" }.into(),
        );
    }
    if !is_cask {
        return Ok((pinned, None));
    }

    let infos = operands
        .iter()
        .map(|operand| cask_info(operand, cwd))
        .collect::<Result<Vec<_>, _>>()?;
    for (operand, info) in operands.iter().zip(&infos) {
        reject_unsafe_artifacts(operand, info)?;
    }
    let installs = matches!(command, "install" | "reinstall" | "upgrade")
        && !options.iter().any(|arg| arg.as_str() == "--dry-run");
    if installs
        && options
            .iter()
            .any(|arg| arg.as_str() == "--appdir" || arg.starts_with("--appdir="))
    {
        return Err(
            "custom cask app destinations are not supported by the hardened launcher".into(),
        );
    }
    if installs {
        let mut dep_args = vec!["deps", "--cask", "--missing", "--union", "--"];
        dep_args.extend(operands.iter().map(String::as_str));
        let missing = brew_lines(&dep_args, cwd)?;
        if !missing.is_empty() {
            return Err(format!(
                "cask dependencies must be installed as automic first: {}",
                missing
                    .iter()
                    .map(|dep| format!("`brew install --formula {dep}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }

    let caller = caller()?;
    let apps = if installs {
        infos
            .iter()
            .zip(&operands)
            .map(|(info, operand)| app_targets(operand, info))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect()
    } else {
        Vec::new()
    };
    let post_install = installs.then_some(CaskPostInstall { caller, apps });
    Ok((pinned, post_install))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PackageKind {
    Formula,
    Cask,
}

fn mutation_command(args: &[String]) -> Option<(usize, &str)> {
    let index = args
        .iter()
        .position(|arg| arg == "--" || !arg.starts_with('-'))?;
    let command = args[index].as_str();
    matches!(
        command,
        "install" | "reinstall" | "upgrade" | "uninstall" | "remove" | "rm"
    )
    .then_some((index, command))
}

fn named_operands(args: &[String], command_index: usize) -> Vec<String> {
    const VALUE_FLAGS: &[&str] = &[
        "--appdir",
        "--appimagedir",
        "--audio-unit-plugindir",
        "--bottle-arch",
        "--cc",
        "--colorpickerdir",
        "--dictionarydir",
        "--fontdir",
        "--input-methoddir",
        "--internet-plugindir",
        "--keyboard-layoutdir",
        "--language",
        "--mdimporterdir",
        "--minimum-version",
        "--prefpanedir",
        "--qlplugindir",
        "--screen-saverdir",
        "--servicedir",
        "--vst-plugindir",
        "--vst3-plugindir",
    ];
    let mut operands = Vec::new();
    let mut skip = false;
    let mut options_done = false;
    for arg in args.iter().skip(command_index + 1) {
        if skip {
            skip = false;
            continue;
        }
        if !options_done && arg == "--" {
            options_done = true;
        } else if !options_done && arg.starts_with('-') {
            skip = !arg.contains('=') && VALUE_FLAGS.contains(&arg.as_str());
        } else {
            operands.push(arg.clone());
        }
    }
    operands
}

fn resolve_package(name: &str, cwd: &Path) -> Result<PackageKind, String> {
    let info = brew_json(&["info", "--json=v2", "--", name], cwd)?;
    package_kind(&info, name)
}

fn package_kind(info: &serde_json::Value, name: &str) -> Result<PackageKind, String> {
    let formulae = info["formulae"].as_array().map_or(0, Vec::len);
    let casks = info["casks"].as_array().map_or(0, Vec::len);
    match (formulae, casks) {
        (1, 0) => Ok(PackageKind::Formula),
        (0, 1) => Ok(PackageKind::Cask),
        _ => Err(format!("Homebrew could not safely classify `{name}`")),
    }
}

fn cask_info(name: &str, cwd: &Path) -> Result<serde_json::Value, String> {
    let mut info = brew_json(&["info", "--json=v2", "--cask", "--", name], cwd)?;
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

fn brew_json(args: &[&str], cwd: &Path) -> Result<serde_json::Value, String> {
    let output = brew_output(args, cwd)?;
    serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("Homebrew returned malformed JSON: {err}"))
}

fn brew_lines(args: &[&str], cwd: &Path) -> Result<Vec<String>, String> {
    let output = brew_output(args, cwd)?;
    Ok(String::from_utf8(output.stdout)
        .map_err(|_| "Homebrew output was not valid UTF-8".to_string())?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

fn brew_output(args: &[&str], cwd: &Path) -> Result<std::process::Output, String> {
    let output = Command::new(TARGET)
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(stub_env([]))
        .env("HOMEBREW_NO_AUTO_UPDATE", "1")
        .output()
        .map_err(|err| format!("failed to run Homebrew resolver: {err}"))?;
    if output.status.success() {
        return Ok(output);
    }
    Err(format!(
        "Homebrew resolver failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn reject_unsafe_artifacts(name: &str, info: &serde_json::Value) -> Result<(), String> {
    const KNOWN_KEYS: &[&str] = &[
        "app",
        "appimage",
        "artifact",
        "audio_unit_plugin",
        "bashcompletion",
        "binary",
        "colorpicker",
        "command_wrapper",
        "dictionary",
        "fishcompletion",
        "font",
        "generated_completion",
        "generated_script",
        "input_method",
        "installer",
        "internet_plugin",
        "keyboard_layout",
        "manpage",
        "mdimporter",
        "pkg",
        "postflight",
        "preflight",
        "prefpane",
        "qlplugin",
        "screen_saver",
        "service",
        "stage_only",
        "suite",
        "target",
        "uninstall",
        "uninstall_postflight",
        "uninstall_preflight",
        "vst3_plugin",
        "vst_plugin",
        "zap",
        "zshcompletion",
    ];
    let artifacts = info["artifacts"]
        .as_array()
        .ok_or_else(|| format!("Homebrew returned malformed artifacts for `{name}`"))?;
    for artifact in artifacts {
        let object = artifact
            .as_object()
            .ok_or_else(|| format!("Homebrew returned malformed artifact for `{name}`"))?;
        if let Some(kind) = object
            .keys()
            .find(|kind| !KNOWN_KEYS.contains(&kind.as_str()))
        {
            return Err(format!(
                "Homebrew returned unknown artifact type `{kind}` for `{name}`"
            ));
        }
        for kind in [
            "bashcompletion",
            "binary",
            "command_wrapper",
            "fishcompletion",
            "generated_completion",
            "generated_script",
            "service",
            "zshcompletion",
        ] {
            if object.get(kind).is_some_and(|value| {
                value
                    .as_array()
                    .and_then(|values| values.first())
                    .and_then(serde_json::Value::as_str)
                    .is_none()
            }) {
                return Err(format!(
                    "Homebrew returned malformed {kind} artifact for `{name}`"
                ));
            }
        }
    }
    Ok(())
}

fn app_targets(name: &str, info: &serde_json::Value) -> Result<Vec<PathBuf>, String> {
    const METADATA_KEYS: &[&str] = &[
        "app",
        "bashcompletion",
        "binary",
        "command_wrapper",
        "fishcompletion",
        "generated_completion",
        "generated_script",
        "postflight",
        "preflight",
        "service",
        "target",
        "uninstall",
        "uninstall_postflight",
        "uninstall_preflight",
        "zap",
        "zshcompletion",
    ];
    let artifacts = info["artifacts"]
        .as_array()
        .ok_or_else(|| format!("Homebrew returned malformed artifacts for `{name}`"))?;
    let mut targets = Vec::new();
    for artifact in artifacts {
        let object = artifact
            .as_object()
            .ok_or_else(|| format!("Homebrew returned malformed artifact for `{name}`"))?;
        if let Some(kind) = object
            .keys()
            .find(|kind| !METADATA_KEYS.contains(&kind.as_str()))
        {
            return Err(format!(
                "cask `{name}` installs unsupported `{kind}` artifacts outside an app bundle"
            ));
        }
        if object.contains_key("app") {
            let target = object
                .get("target")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("Homebrew returned no app target for `{name}`"))?;
            let target = PathBuf::from(target);
            if target.parent() != Some(Path::new("/Applications"))
                || target.extension().and_then(|value| value.to_str()) != Some("app")
            {
                return Err(format!(
                    "cask `{name}` app target must be directly inside /Applications"
                ));
            }
            targets.push(target);
        }
    }
    if targets.is_empty() {
        return Err(format!(
            "cask `{name}` has no app bundle whose ownership can be transferred safely"
        ));
    }
    Ok(targets)
}

fn caller() -> Result<Caller, String> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let euid = unsafe { libc::geteuid() };
    validate_invoker(uid, euid)?;
    let configured =
        configured_cask_uid(Path::new(CASK_USER_UID), euid, unsafe { libc::getegid() })?;
    if uid != configured {
        return Err(
            "casks must be invoked directly by the user configured by `sudo av harden brew`".into(),
        );
    }
    let entry = unsafe { libc::getpwuid(uid) };
    if entry.is_null() {
        return Err(format!("cannot resolve local account for UID {uid}"));
    }
    let entry = unsafe { &*entry };
    if entry.pw_gid != gid {
        return Err("caller's real GID does not match the account primary group".into());
    }
    if entry.pw_name.is_null()
        || unsafe { CStr::from_ptr(entry.pw_name) }
            .to_bytes()
            .is_empty()
    {
        return Err("caller's account name is missing".into());
    }
    Ok(Caller { uid, gid })
}

fn validate_invoker(uid: u32, euid: u32) -> Result<(), String> {
    if uid == 0 {
        return Err("casks cannot be invoked as root".into());
    }
    if uid == euid {
        return Err("brew stub is not installed setuid; run `sudo av harden brew`".into());
    }
    Ok(())
}

fn configured_cask_uid(path: &Path, owner: u32, group: u32) -> Result<u32, String> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|err| format!("failed to read configured cask user: {err}"))?;
    let metadata = file
        .metadata()
        .map_err(|err| format!("failed to inspect configured cask user: {err}"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner
        || metadata.gid() != group
        || metadata.mode() & 0o022 != 0
    {
        return Err("configured cask user file is not protected".into());
    }
    let mut configured = String::new();
    file.read_to_string(&mut configured)
        .map_err(|err| format!("failed to read configured cask user: {err}"))?;
    configured
        .trim()
        .parse::<u32>()
        .map_err(|_| "configured cask user UID is invalid".to_string())
}

fn transfer_app_ownership(post_install: &CaskPostInstall) -> Result<(), String> {
    for app in &post_install.apps {
        validate_installed_app(app)?;
        verify_app(app)?;
    }
    eprintln!(
        "av-brew-stub: sudo is required to make the verified app bundle owned by your account"
    );
    let output = ownership_command(post_install)
        .output()
        .map_err(|err| format!("failed to transfer app ownership: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "failed to transfer app ownership: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    for app in &post_install.apps {
        validate_installed_app(app)?;
        let metadata = fs::symlink_metadata(app)
            .map_err(|err| format!("failed to inspect {}: {err}", app.display()))?;
        if metadata.uid() != post_install.caller.uid || metadata.gid() != post_install.caller.gid {
            return Err(format!(
                "{} ownership was not transferred to {}:{}",
                app.display(),
                post_install.caller.uid,
                post_install.caller.gid
            ));
        }
        verify_app(app)?;
    }
    Ok(())
}

fn ownership_command(post_install: &CaskPostInstall) -> Command {
    let owner = format!("{}:{}", post_install.caller.uid, post_install.caller.gid);
    let mut command = Command::new("/usr/bin/sudo");
    command
        .args([
            "--",
            "/usr/sbin/chown",
            "-R",
            "-P",
            "-h",
            "-x",
            "-n",
            "--",
            &owner,
        ])
        .args(&post_install.apps)
        .env_clear()
        .envs(stub_env([]));
    command
}

fn validate_installed_app(app: &Path) -> Result<(), String> {
    if app.parent() != Some(Path::new("/Applications"))
        || app.extension().and_then(|value| value.to_str()) != Some("app")
    {
        return Err(format!("unsafe app ownership target {}", app.display()));
    }
    let metadata = fs::symlink_metadata(app)
        .map_err(|err| format!("failed to inspect installed app {}: {err}", app.display()))?;
    if !metadata.file_type().is_dir() {
        return Err(format!(
            "installed app target {} is not a directory",
            app.display()
        ));
    }
    Ok(())
}

fn verify_app(app: &Path) -> Result<(), String> {
    let output = Command::new("/usr/sbin/spctl")
        .args(["--assess", "--type", "execute", "--"])
        .arg(app)
        .env_clear()
        .envs(stub_env([]))
        .output()
        .map_err(|err| format!("failed to verify {}: {err}", app.display()))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} failed Gatekeeper verification: {}",
            app.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
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
            let error = xpc_dictionary_get_string(reply, _xpc_error_key_description);
            let error = if error.is_null() {
                "approval XPC connection failed".into()
            } else {
                std::ffi::CStr::from_ptr(error)
                    .to_string_lossy()
                    .into_owned()
            };
            if error == "Connection invalid" {
                Err("Automic Vault approval service is not running; open the menu bar app".into())
            } else {
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
        ("AUTOMIC_VAULT_BREW_STUB".into(), MARKER.into()),
        ("HOME".into(), "/opt/homebrew/var/automic".into()),
        ("USER".into(), "automic".into()),
        ("LOGNAME".into(), "automic".into()),
        ("TMPDIR".into(), "/opt/homebrew/var/automic/tmp".into()),
        (
            "HOMEBREW_CACHE".into(),
            "/opt/homebrew/var/automic/cache".into(),
        ),
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
    fn denial_prevents_command_creation() {
        let result = approved_command(
            vec!["install".into(), "ack".into()],
            [],
            Path::new("/tmp"),
            |_| Err("denied".into()),
        );

        assert_eq!(result.unwrap_err().to_string(), "denied");
    }

    #[test]
    fn approved_command_has_sanitized_env() {
        let (command, caller) = approved_command(
            vec!["info".into(), "ack".into()],
            [
                ("TERM".into(), "xterm-256color".into()),
                ("SECRET".into(), "nope".into()),
            ],
            Path::new("/tmp"),
            |_| Ok(()),
        )
        .unwrap();
        assert!(caller.is_none());
        let env = command
            .get_envs()
            .map(|(key, value)| (key.to_owned(), value.unwrap().to_owned()))
            .collect::<Vec<_>>();

        assert!(env.contains(&("HOME".into(), "/opt/homebrew/var/automic".into())));
        assert!(env.contains(&("TERM".into(), "xterm-256color".into())));
        assert!(!env.iter().any(|(key, _)| key == "SECRET"));
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
    fn mutation_operands_skip_options_and_their_values() {
        assert_eq!(
            named_operands(
                &[
                    "install".into(),
                    "--appdir".into(),
                    "/Applications".into(),
                    "--language=en".into(),
                    "--verbose".into(),
                    "firefox".into(),
                ],
                0
            ),
            ["firefox"]
        );
        assert_eq!(
            named_operands(
                &[
                    "upgrade".into(),
                    "--cask".into(),
                    "--".into(),
                    "-odd-cask".into(),
                ],
                0
            ),
            ["-odd-cask"]
        );
        assert_eq!(
            mutation_command(&[
                "--verbose".into(),
                "install".into(),
                "--cask".into(),
                "firefox".into(),
            ]),
            Some((1, "install"))
        );
        assert_eq!(mutation_command(&["info".into(), "install".into()]), None);
        assert_eq!(mutation_command(&["--".into(), "install".into()]), None);
        assert_eq!(
            named_operands(
                &[
                    "--verbose".into(),
                    "install".into(),
                    "--cask".into(),
                    "firefox".into(),
                ],
                1,
            ),
            ["firefox"]
        );
    }

    #[test]
    fn package_json_must_resolve_to_exactly_one_kind() {
        assert_eq!(
            package_kind(
                &serde_json::json!({"formulae": [], "casks": [{"token": "firefox"}]}),
                "firefox"
            ),
            Ok(PackageKind::Cask)
        );
        assert_eq!(
            package_kind(
                &serde_json::json!({"formulae": [{"name": "tree"}], "casks": []}),
                "tree"
            ),
            Ok(PackageKind::Formula)
        );
        assert!(
            package_kind(
                &serde_json::json!({"formulae": [{"name": "same"}], "casks": [{"token": "same"}]}),
                "same"
            )
            .is_err()
        );
        assert!(
            package_kind(&serde_json::json!({"formulae": [], "casks": []}), "missing").is_err()
        );
    }

    #[test]
    fn configured_cask_user_must_come_from_a_protected_file() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_path("cask-user");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("uid");
        fs::write(&path, "501\n").unwrap();
        let metadata = fs::metadata(&path).unwrap();

        assert_eq!(
            configured_cask_uid(&path, metadata.uid(), metadata.gid()),
            Ok(501)
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(configured_cask_uid(&path, metadata.uid(), metadata.gid()).is_err());

        let link = root.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(configured_cask_uid(&link, metadata.uid(), metadata.gid()).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cask_invoker_errors_identify_root_and_missing_setuid() {
        assert_eq!(
            validate_invoker(0, 550).unwrap_err(),
            "casks cannot be invoked as root"
        );
        assert_eq!(
            validate_invoker(501, 501).unwrap_err(),
            "brew stub is not installed setuid; run `sudo av harden brew`"
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

    #[test]
    fn artifact_metadata_must_use_known_formats() {
        let vscode = serde_json::json!({
            "artifacts": [
                {"app": ["Visual Studio Code.app"], "target": "/Applications/Visual Studio Code.app"},
                {"binary": ["/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"], "target": "/opt/homebrew/bin/code"}
            ]
        });
        assert!(reject_unsafe_artifacts("visual-studio-code", &vscode).is_ok());

        let firefox = serde_json::json!({
            "artifacts": [
                {"app": ["Firefox.app"], "target": "/Applications/Firefox.app"},
                {"binary": ["/opt/homebrew/Caskroom/firefox/1/firefox.wrapper.sh"], "target": "/opt/homebrew/bin/firefox"}
            ]
        });
        assert!(reject_unsafe_artifacts("firefox", &firefox).is_ok());
        assert!(
            reject_unsafe_artifacts(
                "broken",
                &serde_json::json!({"artifacts": [{"binary": "bad"}]})
            )
            .is_err()
        );
        assert!(
            reject_unsafe_artifacts(
                "future",
                &serde_json::json!({"artifacts": [{"new_artifact": ["payload"]}]})
            )
            .is_err()
        );
    }

    #[test]
    fn only_declared_app_targets_are_transferred() {
        let spotify = serde_json::json!({
            "artifacts": [
                {"uninstall": [{"quit": "com.spotify.client"}]},
                {"app": ["Spotify.app"], "target": "/Applications/Spotify.app"},
                {"zap": [{"trash": "~/Library/Application Support/Spotify"}]}
            ]
        });
        assert_eq!(
            app_targets("spotify", &spotify).unwrap(),
            [PathBuf::from("/Applications/Spotify.app")]
        );
        assert!(
            app_targets(
                "installer",
                &serde_json::json!({"artifacts": [{"pkg": ["Installer.pkg"]}]})
            )
            .is_err()
        );
        assert!(
            app_targets(
                "elsewhere",
                &serde_json::json!({
                    "artifacts": [{"app": ["Foo.app"], "target": "/tmp/Foo.app"}]
                })
            )
            .is_err()
        );

        let command = ownership_command(&CaskPostInstall {
            caller: Caller { uid: 501, gid: 20 },
            apps: vec![PathBuf::from("/Applications/Spotify.app")],
        });
        assert_eq!(command.get_program(), "/usr/bin/sudo");
        assert_eq!(
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            [
                "--",
                "/usr/sbin/chown",
                "-R",
                "-P",
                "-h",
                "-x",
                "-n",
                "--",
                "501:20",
                "/Applications/Spotify.app"
            ]
        );
    }
}
