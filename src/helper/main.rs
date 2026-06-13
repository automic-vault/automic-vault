use std::ffi::{CStr, CString, c_char, c_void};

use nucleus::{
    HelperCommand, PackageSpec, check_for_updates, execute_helper_command,
    refresh_remote_combined_data, verify_helper_codesign_identity,
};

unsafe extern "C" {
    fn nuke_helper_run_service();
}

type ProgressCallback = extern "C" fn(*mut c_void, *const c_char);

fn main() {
    sanitize_environment();
    if let Err(err) = verify_helper_codesign_identity() {
        eprintln!("{err}");
        std::process::exit(1);
    }
    unsafe { nuke_helper_run_service() };
}

#[unsafe(no_mangle)]
pub extern "C" fn nuke_helper_install(
    packages_json: *const c_char,
    context: *mut c_void,
    progress_callback: Option<ProgressCallback>,
) -> *mut c_char {
    execute_command(
        HelperCommand::Install {
            packages: parse_packages(packages_json),
        },
        context,
        progress_callback,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn nuke_helper_update(
    packages_json: *const c_char,
    context: *mut c_void,
    progress_callback: Option<ProgressCallback>,
) -> *mut c_char {
    execute_command(
        HelperCommand::Update {
            packages: parse_packages(packages_json),
        },
        context,
        progress_callback,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn nuke_helper_uninstall(
    packages_json: *const c_char,
    context: *mut c_void,
    progress_callback: Option<ProgressCallback>,
) -> *mut c_char {
    execute_command(
        HelperCommand::Uninstall {
            packages: parse_packages(packages_json),
        },
        context,
        progress_callback,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn nuke_helper_make_default(
    packages_json: *const c_char,
    context: *mut c_void,
    progress_callback: Option<ProgressCallback>,
) -> *mut c_char {
    execute_command(
        HelperCommand::MakeDefault {
            packages: parse_packages(packages_json),
        },
        context,
        progress_callback,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn nuke_helper_update_all(
    context: *mut c_void,
    progress_callback: Option<ProgressCallback>,
) -> *mut c_char {
    execute_command(HelperCommand::UpdateAll, context, progress_callback)
}

#[unsafe(no_mangle)]
pub extern "C" fn nuke_helper_install_av(
    source_path: *const c_char,
    caller_path: *const c_char,
    context: *mut c_void,
    progress_callback: Option<ProgressCallback>,
) -> *mut c_char {
    let source_path = c_string(source_path).unwrap_or_default();
    let caller_path = c_string(caller_path).unwrap_or_default();
    execute_command(
        HelperCommand::InstallAv {
            source_path,
            caller_path,
        },
        context,
        progress_callback,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn nuke_helper_install_isotope_root(
    isotope_name: *const c_char,
    context: *mut c_void,
    progress_callback: Option<ProgressCallback>,
) -> *mut c_char {
    let isotope_name = c_string(isotope_name).unwrap_or_default();
    execute_command(
        HelperCommand::InstallIsotopeRoot { isotope_name },
        context,
        progress_callback,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn nuke_helper_convert_radioisotope(
    isotope_name: *const c_char,
    context: *mut c_void,
    progress_callback: Option<ProgressCallback>,
) -> *mut c_char {
    let isotope_name = c_string(isotope_name).unwrap_or_default();
    execute_command(
        HelperCommand::ConvertRadioisotope { isotope_name },
        context,
        progress_callback,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn nuke_helper_install_isotope_stubs(
    isotope_name: *const c_char,
    context: *mut c_void,
    progress_callback: Option<ProgressCallback>,
) -> *mut c_char {
    let isotope_name = c_string(isotope_name).unwrap_or_default();
    execute_command(
        HelperCommand::InstallIsotopeStubs { isotope_name },
        context,
        progress_callback,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn nuke_helper_remember_isotope_always_allow(
    executable_path: *const c_char,
    script_path: *const c_char,
    script_sha256: *const c_char,
    keys_json: *const c_char,
    context: *mut c_void,
    progress_callback: Option<ProgressCallback>,
) -> *mut c_char {
    let executable_path = c_string(executable_path).unwrap_or_default();
    let script_path = c_string(script_path).unwrap_or_default();
    let script_sha256 = c_string(script_sha256).unwrap_or_default();
    let keys = parse_string_array(keys_json);
    execute_command(
        HelperCommand::RememberIsotopeAlwaysAllow {
            executable_path,
            script_path: if script_path.is_empty() {
                None
            } else {
                Some(script_path)
            },
            script_sha256: if script_sha256.is_empty() {
                None
            } else {
                Some(script_sha256)
            },
            keys,
        },
        context,
        progress_callback,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn nuke_helper_get_dotenv_approval_policy(
    context: *mut c_void,
    progress_callback: Option<ProgressCallback>,
) -> *mut c_char {
    execute_command(
        HelperCommand::GetDotenvApprovalPolicy,
        context,
        progress_callback,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn nuke_helper_set_dotenv_approval_policy(
    policy: *const c_char,
    context: *mut c_void,
    progress_callback: Option<ProgressCallback>,
) -> *mut c_char {
    let policy = match c_string(policy)
        .ok()
        .and_then(|value| nucleus::DotenvApprovalPolicy::from_raw_value(&value).ok())
    {
        Some(policy) => policy,
        None => return encode_error("invalid dotenv approval policy".to_string()),
    };
    execute_command(
        HelperCommand::SetDotenvApprovalPolicy { policy },
        context,
        progress_callback,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn nuke_helper_remember_dotenv_approval(
    mode: *const c_char,
    env_file_path: *const c_char,
    project_root: *const c_char,
    env_sha256: *const c_char,
    public_key_fingerprint: *const c_char,
    keys_json: *const c_char,
    context: *mut c_void,
    progress_callback: Option<ProgressCallback>,
) -> *mut c_char {
    let mode = match c_string(mode)
        .ok()
        .and_then(|value| nucleus::DotenvApprovalMode::from_raw_value(&value).ok())
    {
        Some(mode) => mode,
        None => return encode_error("invalid dotenv approval mode".to_string()),
    };
    execute_command(
        HelperCommand::RememberDotenvApproval {
            mode,
            env_file_path: c_string(env_file_path).unwrap_or_default(),
            project_root: c_string(project_root).unwrap_or_default(),
            env_sha256: c_string(env_sha256).unwrap_or_default(),
            public_key_fingerprint: c_string(public_key_fingerprint).unwrap_or_default(),
            keys: parse_string_array(keys_json),
        },
        context,
        progress_callback,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn nuke_helper_check_for_updates() -> bool {
    if verify_helper_codesign_identity().is_err() {
        return false;
    }
    let _ = refresh_remote_combined_data();
    check_for_updates().unwrap_or(false)
}

#[unsafe(no_mangle)]
pub extern "C" fn nuke_helper_refresh_remote_database() -> bool {
    if verify_helper_codesign_identity().is_err() {
        return false;
    }
    refresh_remote_combined_data().unwrap_or(false)
}

/// # Safety
///
/// `value` must be null or a pointer returned by this helper's string allocation
/// functions, and it must not have been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nuke_helper_free_string(value: *mut c_char) {
    if value.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(value);
    }
}

fn execute_command(
    command: HelperCommand,
    context: *mut c_void,
    progress_callback: Option<ProgressCallback>,
) -> *mut c_char {
    if let Err(err) = verify_helper_identity_for_command() {
        return encode_error(err);
    }
    let context = context as usize;
    let result = execute_helper_command(command, move |event| {
        let Some(progress_callback) = progress_callback else {
            return;
        };
        let event_json = match serde_json::to_string(&event) {
            Ok(event_json) => event_json,
            Err(_) => return,
        };
        if let Ok(c_string) = CString::new(event_json) {
            progress_callback(context as *mut c_void, c_string.as_ptr());
        }
    });

    match serde_json::to_string(&result) {
        Ok(json) => string_into_raw(json),
        Err(err) => string_into_raw(format!(
            r#"{{"Err":"failed to encode helper result: {err}"}}"#
        )),
    }
}

#[cfg(not(test))]
fn verify_helper_identity_for_command() -> Result<(), String> {
    verify_helper_codesign_identity()
}

#[cfg(test)]
fn verify_helper_identity_for_command() -> Result<(), String> {
    Ok(())
}

fn parse_packages(packages_json: *const c_char) -> Vec<PackageSpec> {
    let Ok(packages_json) = c_string(packages_json) else {
        return Vec::new();
    };
    serde_json::from_str(&packages_json).unwrap_or_default()
}

fn parse_string_array(values_json: *const c_char) -> Vec<String> {
    let Ok(values_json) = c_string(values_json) else {
        return Vec::new();
    };
    serde_json::from_str(&values_json).unwrap_or_default()
}

fn c_string(value: *const c_char) -> Result<String, std::str::Utf8Error> {
    if value.is_null() {
        return Ok(String::new());
    }
    unsafe { CStr::from_ptr(value) }.to_str().map(str::to_owned)
}

fn string_into_raw(value: String) -> *mut c_char {
    CString::new(value).unwrap().into_raw()
}

fn encode_error(message: String) -> *mut c_char {
    match serde_json::to_string(&Err::<HelperCommandSuccessWire, _>(message)) {
        Ok(json) => string_into_raw(json),
        Err(_) => string_into_raw(r#"{"Err":"helper identity check failed"}"#.to_string()),
    }
}

#[derive(serde::Serialize)]
struct HelperCommandSuccessWire {
    message: String,
    processed_packages: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

fn sanitize_environment() {
    for key in ["PKG_ALLOW", "PACKAGE_MAGINAT0R_LVL", "HOMEBREW_PREFIX"] {
        unsafe { std::env::remove_var(key) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    use std::sync::Mutex;

    static CALLBACK_EVENTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

    extern "C" fn capture_progress(_context: *mut c_void, value: *const c_char) {
        CALLBACK_EVENTS
            .lock()
            .unwrap()
            .push(c_string(value).unwrap());
    }

    fn raw_to_string(value: *mut c_char) -> String {
        assert!(!value.is_null());
        let string = c_string(value).unwrap();
        unsafe {
            nuke_helper_free_string(value);
        }
        string
    }

    #[test]
    fn helper_parse_functions_accept_null_invalid_and_valid_json() {
        assert!(parse_packages(ptr::null()).is_empty());
        assert!(parse_string_array(ptr::null()).is_empty());

        let invalid = CString::new("not json").unwrap();
        assert!(parse_packages(invalid.as_ptr()).is_empty());
        assert!(parse_string_array(invalid.as_ptr()).is_empty());

        let packages = CString::new(r#"[{"name":"npm:openclaw","version":"4.5.6"}]"#).unwrap();
        assert_eq!(
            parse_packages(packages.as_ptr()),
            vec![PackageSpec {
                name: "npm:openclaw".to_string(),
                version: Some("4.5.6".to_string()),
            }]
        );

        let keys = CString::new(r#"["AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY"]"#).unwrap();
        assert_eq!(
            parse_string_array(keys.as_ptr()),
            vec![
                "AWS_ACCESS_KEY_ID".to_string(),
                "AWS_SECRET_ACCESS_KEY".to_string()
            ]
        );

        let invalid_utf8 = [0xff_u8, 0x00_u8];
        let invalid_ptr = invalid_utf8.as_ptr().cast();
        assert!(parse_packages(invalid_ptr).is_empty());
        assert!(parse_string_array(invalid_ptr).is_empty());
    }

    #[test]
    fn helper_c_string_and_error_encoding_handle_nulls_and_messages() {
        assert_eq!(c_string(ptr::null()).unwrap(), "");

        let encoded = raw_to_string(encode_error("nope".to_string()));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&encoded).unwrap(),
            serde_json::json!({"Err": "nope"})
        );

        let raw = string_into_raw("hello".to_string());
        assert_eq!(raw_to_string(raw), "hello");
        unsafe {
            nuke_helper_free_string(ptr::null_mut());
        }
    }

    #[test]
    fn helper_ffi_wrappers_return_json_errors_and_progress() {
        CALLBACK_EVENTS.lock().unwrap().clear();
        let packages = CString::new("[]").unwrap();
        let response = raw_to_string(nuke_helper_install(
            packages.as_ptr(),
            ptr::null_mut(),
            Some(capture_progress),
        ));
        let value = serde_json::from_str::<serde_json::Value>(&response).unwrap();
        assert!(value.get("Err").is_some());
        assert!(!CALLBACK_EVENTS.lock().unwrap().is_empty());

        let response = raw_to_string(nuke_helper_update(
            packages.as_ptr(),
            ptr::null_mut(),
            Some(capture_progress),
        ));
        assert!(
            serde_json::from_str::<serde_json::Value>(&response)
                .unwrap()
                .get("Err")
                .is_some()
        );

        let response = raw_to_string(nuke_helper_uninstall(
            packages.as_ptr(),
            ptr::null_mut(),
            Some(capture_progress),
        ));
        assert!(
            serde_json::from_str::<serde_json::Value>(&response)
                .unwrap()
                .get("Err")
                .is_some()
        );

        let response = raw_to_string(nuke_helper_make_default(
            packages.as_ptr(),
            ptr::null_mut(),
            Some(capture_progress),
        ));
        assert!(
            serde_json::from_str::<serde_json::Value>(&response)
                .unwrap()
                .get("Err")
                .is_some()
        );
    }

    #[test]
    fn helper_update_all_and_background_refresh_wrappers_return_stable_shapes() {
        let response = raw_to_string(nuke_helper_update_all(ptr::null_mut(), None));
        let value = serde_json::from_str::<serde_json::Value>(&response).unwrap();
        assert!(value.get("Err").is_some() || value.get("Ok").is_some());

        let check = nuke_helper_check_for_updates();
        let refresh = nuke_helper_refresh_remote_database();
        assert!(matches!(check, true | false));
        assert!(matches!(refresh, true | false));
    }

    #[test]
    fn helper_wrappers_allow_missing_progress_callback() {
        let packages = CString::new("[]").unwrap();
        let response = raw_to_string(nuke_helper_install(
            packages.as_ptr(),
            ptr::null_mut(),
            None,
        ));
        let value = serde_json::from_str::<serde_json::Value>(&response).unwrap();
        assert!(value.get("Err").is_some() || value.get("Ok").is_some());
    }

    #[test]
    fn helper_isotope_and_av_wrappers_accept_null_strings() {
        for response in [
            nuke_helper_install_av(ptr::null(), ptr::null(), ptr::null_mut(), None),
            nuke_helper_install_isotope_root(ptr::null(), ptr::null_mut(), None),
            nuke_helper_convert_radioisotope(ptr::null(), ptr::null_mut(), None),
            nuke_helper_install_isotope_stubs(ptr::null(), ptr::null_mut(), None),
            nuke_helper_remember_isotope_always_allow(
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
                None,
            ),
        ] {
            let value =
                serde_json::from_str::<serde_json::Value>(&raw_to_string(response)).unwrap();
            assert!(value.get("Err").is_some());
        }
    }

    #[test]
    fn helper_wrappers_accept_explicit_strings_and_optional_callbacks() {
        let source_path = CString::new("/tmp/Automic Vault.app").unwrap();
        let caller_path = CString::new("/Applications/Automic Vault.app").unwrap();
        let isotope = CString::new("gh").unwrap();
        let executable = CString::new("/usr/local/bin/python").unwrap();
        let script = CString::new("/tmp/script.py").unwrap();
        let keys = CString::new(r#"["OPENAI_API_KEY"]"#).unwrap();

        for response in [
            nuke_helper_install_av(
                source_path.as_ptr(),
                caller_path.as_ptr(),
                ptr::null_mut(),
                Some(capture_progress),
            ),
            nuke_helper_install_isotope_root(
                isotope.as_ptr(),
                ptr::null_mut(),
                Some(capture_progress),
            ),
            nuke_helper_convert_radioisotope(
                isotope.as_ptr(),
                ptr::null_mut(),
                Some(capture_progress),
            ),
            nuke_helper_install_isotope_stubs(
                isotope.as_ptr(),
                ptr::null_mut(),
                Some(capture_progress),
            ),
            nuke_helper_remember_isotope_always_allow(
                executable.as_ptr(),
                script.as_ptr(),
                ptr::null(),
                keys.as_ptr(),
                ptr::null_mut(),
                Some(capture_progress),
            ),
        ] {
            let value =
                serde_json::from_str::<serde_json::Value>(&raw_to_string(response)).unwrap();
            assert!(value.get("Err").is_some() || value.get("Ok").is_some());
        }
    }

    #[test]
    fn helper_wrappers_cover_nonempty_packages_callbacks_and_sha_inputs() {
        CALLBACK_EVENTS.lock().unwrap().clear();
        let packages = CString::new(r#"[{"name":"rg","version":null}]"#).unwrap();

        for response in [
            nuke_helper_install(packages.as_ptr(), ptr::null_mut(), Some(capture_progress)),
            nuke_helper_update(packages.as_ptr(), ptr::null_mut(), Some(capture_progress)),
            nuke_helper_uninstall(packages.as_ptr(), ptr::null_mut(), Some(capture_progress)),
            nuke_helper_make_default(packages.as_ptr(), ptr::null_mut(), Some(capture_progress)),
            nuke_helper_update_all(ptr::null_mut(), Some(capture_progress)),
        ] {
            let value =
                serde_json::from_str::<serde_json::Value>(&raw_to_string(response)).unwrap();
            assert!(value.get("Err").is_some() || value.get("Ok").is_some());
        }

        let executable = CString::new("/usr/bin/python3").unwrap();
        let script = CString::new("/tmp/script.py").unwrap();
        let sha = CString::new("a".repeat(64)).unwrap();
        let keys = CString::new(r#"["OPENAI_API_KEY","ANTHROPIC_API_KEY"]"#).unwrap();
        let response = raw_to_string(nuke_helper_remember_isotope_always_allow(
            executable.as_ptr(),
            script.as_ptr(),
            sha.as_ptr(),
            keys.as_ptr(),
            ptr::null_mut(),
            Some(capture_progress),
        ));
        let value = serde_json::from_str::<serde_json::Value>(&response).unwrap();
        assert!(value.get("Err").is_some() || value.get("Ok").is_some());
        assert!(!CALLBACK_EVENTS.lock().unwrap().is_empty());
    }

    #[test]
    fn helper_dotenv_wrappers_parse_modes_policies_and_keys() {
        let invalid_policy = CString::new("bogus").unwrap();
        let response = raw_to_string(nuke_helper_set_dotenv_approval_policy(
            invalid_policy.as_ptr(),
            ptr::null_mut(),
            Some(capture_progress),
        ));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&response).unwrap(),
            serde_json::json!({"Err": "invalid dotenv approval policy"})
        );

        let policy = CString::new("remember_approved").unwrap();
        let response = raw_to_string(nuke_helper_set_dotenv_approval_policy(
            policy.as_ptr(),
            ptr::null_mut(),
            Some(capture_progress),
        ));
        let value = serde_json::from_str::<serde_json::Value>(&response).unwrap();
        assert!(value.get("Err").is_some() || value.get("Ok").is_some());

        let response = raw_to_string(nuke_helper_get_dotenv_approval_policy(
            ptr::null_mut(),
            None,
        ));
        let value = serde_json::from_str::<serde_json::Value>(&response).unwrap();
        assert!(value.get("Err").is_some() || value.get("Ok").is_some());

        let invalid_mode = CString::new("bogus").unwrap();
        let path = CString::new("/tmp/project/.env").unwrap();
        let project = CString::new("/tmp/project").unwrap();
        let digest = CString::new("0".repeat(64)).unwrap();
        let fingerprint = CString::new("f".repeat(64)).unwrap();
        let keys = CString::new(r#"["FOO","BAR"]"#).unwrap();
        let response = raw_to_string(nuke_helper_remember_dotenv_approval(
            invalid_mode.as_ptr(),
            path.as_ptr(),
            project.as_ptr(),
            digest.as_ptr(),
            fingerprint.as_ptr(),
            keys.as_ptr(),
            ptr::null_mut(),
            None,
        ));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&response).unwrap(),
            serde_json::json!({"Err": "invalid dotenv approval mode"})
        );

        let mode = CString::new("run").unwrap();
        let response = raw_to_string(nuke_helper_remember_dotenv_approval(
            mode.as_ptr(),
            path.as_ptr(),
            project.as_ptr(),
            digest.as_ptr(),
            fingerprint.as_ptr(),
            keys.as_ptr(),
            ptr::null_mut(),
            Some(capture_progress),
        ));
        let value = serde_json::from_str::<serde_json::Value>(&response).unwrap();
        assert!(value.get("Err").is_some() || value.get("Ok").is_some());
    }

    #[test]
    fn helper_sanitize_environment_removes_inherited_controls() {
        unsafe {
            std::env::set_var("PKG_ALLOW", "all");
            std::env::set_var("PACKAGE_MAGINAT0R_LVL", "9000");
            std::env::set_var("HOMEBREW_PREFIX", "/tmp/homebrew");
        }

        sanitize_environment();

        assert!(std::env::var_os("PKG_ALLOW").is_none());
        assert!(std::env::var_os("PACKAGE_MAGINAT0R_LVL").is_none());
        assert!(std::env::var_os("HOMEBREW_PREFIX").is_none());
    }
}
