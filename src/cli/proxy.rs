use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

const USAGE: &str = "\
Usage: av proxy [--replace-existing-env] +KEY [+KEY...] [--] COMMAND [args...]

Runs COMMAND with random secret references and an explicitly authorized HTTP/S proxy.
Secret values are released to the proxy only when an authorized request needs them.";

const MANAGED_ENVIRONMENT: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "AWS_CA_BUNDLE",
];

#[derive(Debug, PartialEq, Eq)]
struct Options {
    replace_existing_env: bool,
    keys: Vec<String>,
    target: OsString,
    args: Vec<OsString>,
}

#[derive(Debug, PartialEq, Eq)]
struct StartRequest {
    keys: Vec<String>,
    target: String,
    args: Vec<String>,
    cwd: String,
    replace_existing_env: bool,
    env_conflicts: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct SessionEnvironment {
    proxy_url: String,
    ca_certificate_path: PathBuf,
    references: BTreeMap<String, String>,
}

pub(crate) fn run(args: Vec<OsString>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    match dispatch(args, stdout) {
        Ok(Some(options)) => exec(options, stderr),
        Ok(None) => 0,
        Err(err) => {
            let _ = writeln!(stderr, "av proxy: {err}");
            1
        }
    }
}

fn dispatch(args: Vec<OsString>, stdout: &mut dyn Write) -> Result<Option<Options>, String> {
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
        writeln!(stdout, "av proxy {}", env!("CARGO_PKG_VERSION")).ok();
        return Ok(None);
    }
    match parse(args) {
        Ok(options) => Ok(Some(options)),
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
    let mut keys = Vec::new();
    let mut seen_keys = BTreeSet::new();
    let mut iter = args.into_iter();

    while let Some(arg) = iter.next() {
        if arg == "--replace-existing-env" {
            if replace_existing_env {
                return Err("duplicate option: --replace-existing-env".into());
            }
            replace_existing_env = true;
            continue;
        }
        let value = arg
            .to_str()
            .ok_or_else(|| "proxy arguments must be valid UTF-8".to_string())?;
        if let Some(key) = value.strip_prefix('+') {
            super::inject::validate_key_name(key)?;
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
            if keys.is_empty() {
                return Err("missing secret reference".into());
            }
            keys.sort();
            return Ok(Options {
                replace_existing_env,
                keys,
                target,
                args: iter.collect(),
            });
        }
        if value.starts_with('-') {
            return Err(format!("unknown option: {value}"));
        }
        if keys.is_empty() {
            return Err("at least one +KEY must be provided before the target".into());
        }
        keys.sort();
        return Ok(Options {
            replace_existing_env,
            keys,
            target: arg,
            args: iter.collect(),
        });
    }

    if keys.is_empty() {
        Err("missing secret reference and target command".into())
    } else {
        Err("missing target command".into())
    }
}

fn exec(options: Options, stderr: &mut dyn Write) -> i32 {
    if unsafe { libc::geteuid() } == 0 {
        let _ = writeln!(stderr, "av proxy: must not be run as root");
        return 1;
    }
    let target = match super::inject::resolve_target(&options.target).and_then(|target| {
        std::fs::canonicalize(&target)
            .map_err(|err| format!("failed to resolve target {}: {err}", target.display()))
    }) {
        Ok(target) => target,
        Err(err) => {
            let _ = writeln!(stderr, "av proxy: {err}");
            return 1;
        }
    };
    let request = match start_request(&options, &target) {
        Ok(request) => request,
        Err(err) => {
            let _ = writeln!(stderr, "av proxy: {err}");
            return 1;
        }
    };
    if !request.env_conflicts.is_empty() && !options.replace_existing_env {
        let _ = writeln!(
            stderr,
            "av proxy: existing proxy or CA environment would make interception ambiguous: {} (replace with: --replace-existing-env)",
            request.env_conflicts.join(", ")
        );
        return 1;
    }
    let session = match start_session(&request) {
        Ok(session) => session,
        Err(err) => {
            let _ = writeln!(stderr, "av proxy: {err}");
            return 1;
        }
    };
    let environment = match build_environment(&options, session) {
        Ok(environment) => environment,
        Err(err) => {
            let _ = writeln!(stderr, "av proxy: {err}");
            return 1;
        }
    };

    let err = Command::new(&target)
        .args(&options.args)
        .env_clear()
        .envs(environment)
        .exec();
    let _ = writeln!(
        stderr,
        "av proxy: failed to execute {}: {err}",
        target.display()
    );
    1
}

fn start_request(options: &Options, target: &PathBuf) -> Result<StartRequest, String> {
    let current_env = std::env::vars_os().collect::<BTreeMap<_, _>>();
    let env_conflicts = MANAGED_ENVIRONMENT
        .iter()
        .filter(|name| current_env.contains_key(std::ffi::OsStr::new(name)))
        .map(|name| (*name).to_string())
        .collect();
    Ok(StartRequest {
        keys: options.keys.clone(),
        target: target.display().to_string(),
        args: options
            .args
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect(),
        cwd: std::env::current_dir()
            .map_err(|err| format!("failed to read current directory: {err}"))?
            .display()
            .to_string(),
        replace_existing_env: options.replace_existing_env,
        env_conflicts,
    })
}

fn build_environment(
    options: &Options,
    session: SessionEnvironment,
) -> Result<BTreeMap<OsString, OsString>, String> {
    if session.proxy_url.is_empty() {
        return Err("approval returned an empty proxy URL".into());
    }
    if !session.ca_certificate_path.is_absolute() {
        return Err("approval returned a non-absolute CA certificate path".into());
    }
    if session.references.len() != options.keys.len()
        || options
            .keys
            .iter()
            .any(|key| session.references.get(key).is_none_or(String::is_empty))
    {
        return Err("approval returned an incomplete set of secret references".into());
    }

    let mut environment = std::env::vars_os().collect::<BTreeMap<_, _>>();
    for name in MANAGED_ENVIRONMENT {
        environment.remove(std::ffi::OsStr::new(name));
    }
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        environment.insert(name.into(), session.proxy_url.clone().into());
    }
    environment.insert("NO_PROXY".into(), OsString::new());
    environment.insert("no_proxy".into(), OsString::new());
    for name in [
        "SSL_CERT_FILE",
        "NODE_EXTRA_CA_CERTS",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
        "AWS_CA_BUNDLE",
    ] {
        environment.insert(
            name.into(),
            session.ca_certificate_path.clone().into_os_string(),
        );
    }
    for (key, reference) in session.references {
        environment.insert(key.into(), reference.into());
    }
    Ok(environment)
}

#[cfg(target_os = "macos")]
fn start_session(request: &StartRequest) -> Result<SessionEnvironment, String> {
    use std::ffi::{CStr, CString};
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
        fn xpc_connection_set_peer_code_signing_requirement(
            connection: XpcObject,
            requirement: *const c_char,
        ) -> c_int;
        fn xpc_dictionary_create_empty() -> XpcObject;
        fn xpc_dictionary_set_bool(object: XpcObject, key: *const c_char, value: bool);
        fn xpc_dictionary_get_bool(object: XpcObject, key: *const c_char) -> bool;
        fn xpc_dictionary_set_string(object: XpcObject, key: *const c_char, value: *const c_char);
        fn xpc_dictionary_get_string(object: XpcObject, key: *const c_char) -> *const c_char;
        fn xpc_dictionary_get_dictionary(object: XpcObject, key: *const c_char) -> XpcObject;
        fn xpc_dictionary_set_value(object: XpcObject, key: *const c_char, value: XpcObject);
        fn xpc_array_create_empty() -> XpcObject;
        fn xpc_array_append_value(array: XpcObject, value: XpcObject);
        fn xpc_string_create(value: *const c_char) -> XpcObject;
        fn xpc_get_type(object: XpcObject) -> *const c_void;
        fn xpc_release(object: XpcObject);
        fn av_xpc_connection_set_empty_event_handler(connection: XpcObject);
    }

    unsafe fn set_string(object: XpcObject, key: &[u8], value: &str) -> Result<(), String> {
        let value = CString::new(value).map_err(|_| "XPC field contains NUL".to_string())?;
        unsafe { xpc_dictionary_set_string(object, key.as_ptr().cast(), value.as_ptr()) };
        Ok(())
    }

    unsafe fn set_array(object: XpcObject, key: &[u8], values: &[String]) -> Result<(), String> {
        let values = values
            .iter()
            .map(|value| {
                CString::new(value.as_str()).map_err(|_| "XPC array value contains NUL".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let array = unsafe { xpc_array_create_empty() };
        for value in values {
            let string = unsafe { xpc_string_create(value.as_ptr()) };
            unsafe {
                xpc_array_append_value(array, string);
                xpc_release(string);
            }
        }
        unsafe {
            xpc_dictionary_set_value(object, key.as_ptr().cast(), array);
            xpc_release(array);
        }
        Ok(())
    }

    unsafe fn get_string(object: XpcObject, key: &[u8]) -> Option<String> {
        let value = unsafe { xpc_dictionary_get_string(object, key.as_ptr().cast()) };
        (!value.is_null()).then(|| {
            unsafe { CStr::from_ptr(value) }
                .to_string_lossy()
                .into_owned()
        })
    }

    let service = c"com.automicvault.av2.approval";
    let connection =
        unsafe { xpc_connection_create_mach_service(service.as_ptr(), std::ptr::null_mut(), 0) };
    if connection.is_null() {
        return Err("failed to create approval XPC connection".into());
    }
    let requirement = CString::new(crate::MENU_HELPER_CODE_SIGNING_REQUIREMENT).unwrap();
    if unsafe { xpc_connection_set_peer_code_signing_requirement(connection, requirement.as_ptr()) }
        != 0
    {
        unsafe { xpc_release(connection) };
        return Err("failed to pin the Automic Vault app identity".into());
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
        return Err("failed to create Proxy Session request".into());
    }
    let encoded = (|| -> Result<(), String> {
        unsafe {
            set_string(message, b"op\0", "proxy-start")?;
            set_string(message, b"target\0", &request.target)?;
            set_string(message, b"cwd\0", &request.cwd)?;
            xpc_dictionary_set_bool(
                message,
                b"replace_existing_env\0".as_ptr().cast(),
                request.replace_existing_env,
            );
            set_array(message, b"keys\0", &request.keys)?;
            set_array(message, b"args\0", &request.args)?;
            set_array(message, b"env_conflicts\0", &request.env_conflicts)
        }
    })();
    if let Err(error) = encoded {
        unsafe {
            xpc_release(message);
            xpc_connection_cancel(connection);
            xpc_release(connection);
        }
        return Err(error);
    }

    let reply = unsafe { xpc_connection_send_message_with_reply_sync(connection, message) };
    unsafe {
        xpc_release(message);
        xpc_connection_cancel(connection);
        xpc_release(connection);
    }
    if reply.is_null() {
        return Err("Automic Vault did not reply to the Proxy Session request".into());
    }
    let result = (|| -> Result<SessionEnvironment, String> {
        unsafe {
            if xpc_get_type(reply) == std::ptr::addr_of!(_xpc_type_error).cast() {
                if crate::approval_service_connection_invalid(reply) {
                    Err(crate::approval_service_unavailable_message(service).into())
                } else {
                    let value = xpc_dictionary_get_string(reply, _xpc_error_key_description);
                    let error = if value.is_null() {
                        "Proxy Session XPC connection failed".into()
                    } else {
                        CStr::from_ptr(value).to_string_lossy().into_owned()
                    };
                    Err(error)
                }
            } else if !xpc_dictionary_get_bool(reply, b"ok\0".as_ptr().cast()) {
                Err(get_string(reply, b"error\0").unwrap_or_else(|| "Proxy Session denied".into()))
            } else {
                let proxy_url = get_string(reply, b"proxy_url\0")
                    .ok_or_else(|| "Proxy Session reply omitted the proxy URL".to_string())?;
                let ca_certificate_path = get_string(reply, b"ca_certificate_path\0")
                    .ok_or_else(|| "Proxy Session reply omitted the CA certificate".to_string())?;
                let values = xpc_dictionary_get_dictionary(reply, b"references\0".as_ptr().cast());
                if values.is_null() {
                    Err("Proxy Session reply omitted Secret References".into())
                } else {
                    let mut references = BTreeMap::new();
                    let mut missing = None;
                    for key in &request.keys {
                        let key_c = CString::new(key.as_str()).unwrap();
                        let value = xpc_dictionary_get_string(values, key_c.as_ptr());
                        if value.is_null() {
                            missing = Some(key);
                            break;
                        }
                        references.insert(
                            key.clone(),
                            CStr::from_ptr(value).to_string_lossy().into_owned(),
                        );
                    }
                    if let Some(key) = missing {
                        Err(format!(
                            "Proxy Session reply omitted Secret Reference {key}"
                        ))
                    } else {
                        Ok(SessionEnvironment {
                            proxy_url,
                            ca_certificate_path: PathBuf::from(ca_certificate_path),
                            references,
                        })
                    }
                }
            }
        }
    })();
    unsafe { xpc_release(reply) };
    result
}

#[cfg(not(target_os = "macos"))]
fn start_session(_request: &StartRequest) -> Result<SessionEnvironment, String> {
    Err("Secret Proxy sessions are only available on macOS".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn options() -> Options {
        Options {
            replace_existing_env: false,
            keys: vec!["API_TOKEN".into()],
            target: "/usr/bin/true".into(),
            args: Vec::new(),
        }
    }

    #[test]
    fn parses_and_sorts_secret_references() {
        assert_eq!(
            parse(os(&["+Z_TOKEN", "+A_TOKEN", "--", "node", "server.js"])).unwrap(),
            Options {
                replace_existing_env: false,
                keys: vec!["A_TOKEN".into(), "Z_TOKEN".into()],
                target: "node".into(),
                args: os(&["server.js"]),
            }
        );
    }

    #[test]
    fn rejects_missing_duplicate_and_invalid_references() {
        assert!(parse(os(&["--", "node"])).is_err());
        assert!(parse(os(&["+TOKEN", "+TOKEN", "node"])).is_err());
        assert!(parse(os(&["+BAD-NAME", "node"])).is_err());
        assert!(
            parse(os(&[
                "--replace-existing-env",
                "--replace-existing-env",
                "+TOKEN",
                "node"
            ]))
            .is_err()
        );
    }

    #[test]
    fn builds_reference_only_environment() {
        let environment = build_environment(
            &options(),
            SessionEnvironment {
                proxy_url: "http://av:credential@127.0.0.1:1234".into(),
                ca_certificate_path: "/tmp/session-ca.pem".into(),
                references: BTreeMap::from([("API_TOKEN".into(), "avref_random".into())]),
            },
        )
        .unwrap();
        assert_eq!(
            environment.get(std::ffi::OsStr::new("API_TOKEN")),
            Some(&OsString::from("avref_random"))
        );
        assert_eq!(
            environment.get(std::ffi::OsStr::new("HTTPS_PROXY")),
            Some(&OsString::from("http://av:credential@127.0.0.1:1234"))
        );
        assert_eq!(
            environment.get(std::ffi::OsStr::new("NO_PROXY")),
            Some(&OsString::new())
        );
    }

    #[test]
    fn rejects_incomplete_session_material() {
        assert!(
            build_environment(
                &options(),
                SessionEnvironment {
                    proxy_url: "http://127.0.0.1:1234".into(),
                    ca_certificate_path: "/tmp/session-ca.pem".into(),
                    references: BTreeMap::new(),
                }
            )
            .is_err()
        );
    }
}
