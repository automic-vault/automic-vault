use super::*;

#[cfg(target_os = "macos")]
use std::ffi::{CString, c_char};

const APP_BUNDLE_IDENTIFIER: &str = "com.automicvault";
const APPROVAL_NOTIFICATION: &str = "com.automicvault.gate-approval.pending-changed";
const USER_APPROVAL_SUBDIR: &str = "gate";

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateOptions {
    message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct GateApprovalRequestSnapshot {
    id: String,
    message: String,
    cwd: String,
    parent_process: ParentProcessSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ParentProcessSnapshot {
    pid: i32,
    executable_path: Option<String>,
    display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct GateApprovalDecision {
    id: String,
    approved: bool,
    reason: Option<String>,
}

pub(crate) fn run_gate_entry(program_name: &str, args: env::ArgsOs) -> Result<(), String> {
    let Some(options) = parse_gate_options(program_name, args)? else {
        return Ok(());
    };
    request_gate_approval(&options)
}

fn parse_gate_options<I>(program_name: &str, mut args: I) -> Result<Option<GateOptions>, String>
where
    I: Iterator<Item = OsString>,
{
    let Some(first_arg) = args.next() else {
        print_gate_usage(program_name);
        return Err("missing gate message".to_string());
    };

    if is_help_flag(&first_arg) {
        print_gate_usage(program_name);
        return Ok(None);
    }

    if is_version_flag(&first_arg) {
        println!("{program_name} {}", env!("CARGO_PKG_VERSION"));
        return Ok(None);
    }

    if args.next().is_some() {
        return Err("supports a single gate message".to_string());
    }

    let message = first_arg
        .to_str()
        .ok_or_else(|| "gate message must be valid UTF-8".to_string())?
        .trim()
        .to_string();
    if message.is_empty() {
        return Err("empty gate message".to_string());
    }

    Ok(Some(GateOptions { message }))
}

fn request_gate_approval(options: &GateOptions) -> Result<(), String> {
    request_gate_approval_with(options, ping_gate_approval_app, wait_for_gate_decision)
}

fn request_gate_approval_with<P, W>(
    options: &GateOptions,
    ping_gate_approval_app: P,
    wait_for_gate_decision: W,
) -> Result<(), String>
where
    P: FnOnce() -> Result<(), String>,
    W: FnOnce(&str) -> Result<(), String>,
{
    let request_id = format!(
        "{}-{}",
        process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|err| format!("failed to compute request timestamp: {err}"))?
            .as_millis()
    );
    let request = GateApprovalRequestSnapshot {
        id: request_id.clone(),
        message: options.message.clone(),
        cwd: env::current_dir()
            .map_err(|err| format!("failed to resolve current directory: {err}"))?
            .to_string_lossy()
            .into_owned(),
        parent_process: parent_process_snapshot(),
    };

    let pending_url = pending_approval_path()?;
    write_json(&pending_url, &request)?;
    if let Err(err) = ping_gate_approval_app() {
        let _ = fs::remove_file(&pending_url);
        return Err(err);
    }
    let outcome = wait_for_gate_decision(&request_id);
    crate::audit::record(
        crate::audit::Event::new(
            crate::audit::EVENT_COMMAND_GATE,
            if outcome.is_ok() {
                crate::audit::DECISION_APPROVED
            } else {
                crate::audit::DECISION_DENIED
            },
        )
        .message(request.message.clone())
        .cwd(request.cwd.clone())
        .parent(
            request.parent_process.pid as i64,
            request.parent_process.executable_path.clone(),
            request.parent_process.display_name.clone(),
        )
        .request_id(request_id.clone())
        .reason(outcome.as_ref().err().cloned()),
    );
    outcome
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

fn wait_for_gate_decision(id: &str) -> Result<(), String> {
    let decision_url = decision_path(id)?;
    let pending_url = pending_approval_path()?;
    wait_for_gate_decision_at(id, &pending_url, &decision_url)
}

fn wait_for_gate_decision_at(
    id: &str,
    pending_url: &Path,
    decision_url: &Path,
) -> Result<(), String> {
    loop {
        if let Ok(contents) = fs::read_to_string(decision_url) {
            let decision: GateApprovalDecision = serde_json::from_str(&contents)
                .map_err(|err| format!("failed to decode gate approval decision: {err}"))?;
            if decision.id != id {
                return Err("gate approval decision id mismatch".to_string());
            }
            clear_approval_files_at(pending_url, decision_url);
            if decision.approved {
                return Ok(());
            }
            return Err(decision.reason.unwrap_or_else(|| "gate denied".to_string()));
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
        .map_err(|err| format!("failed to encode gate approval request: {err}"))?;
    fs::write(path, payload).map_err(|err| format!("failed to write {}: {err}", path.display()))
}

#[cfg(target_os = "macos")]
fn ping_gate_approval_app() -> Result<(), String> {
    let status = Command::new("/usr/bin/open")
        .args(["-b", APP_BUNDLE_IDENTIFIER])
        .status()
        .map_err(|err| format!("failed to ping Automic Vault.app: {err}"))?;
    if !status.success() {
        return Err("failed to ping Automic Vault.app for gate approval".to_string());
    }
    post_distributed_notification(APPROVAL_NOTIFICATION)
}

#[cfg(not(target_os = "macos"))]
fn ping_gate_approval_app() -> Result<(), String> {
    Err("gate approvals are only available on macOS".to_string())
}

pub fn print_gate_usage(program_name: &str) {
    println!(
        "\
Usage: {program_name} <message>

Asks Automic Vault to approve a manual gate and blocks until a decision is made."
    );
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

#[cfg(target_os = "macos")]
fn post_distributed_notification(name: &str) -> Result<(), String> {
    let name = CString::new(name).map_err(|_| "invalid notification name".to_string())?;
    let mut error = std::ptr::null_mut();
    unsafe extern "C" {
        fn isotope_post_distributed_notification(
            name_cstr: *const c_char,
            error_cstr: *mut *mut c_char,
        ) -> bool;
    }
    if unsafe { isotope_post_distributed_notification(name.as_ptr(), &mut error) } {
        return Ok(());
    }
    Err(unsafe { take_bridge_string(error) }
        .unwrap_or_else(|| "failed to post gate approval notification".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    use std::sync::{Arc, Mutex};

    struct EnvGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = env::var_os(key);
            unsafe { env::set_var(key, value) };
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => unsafe { env::set_var(self.key, value) },
                None => unsafe { env::remove_var(self.key) },
            }
        }
    }

    #[test]
    fn gate_parse_options_accepts_message() {
        let options = parse_gate_options(
            "av gate",
            vec![OsString::from("Approve aws config export-credentials")].into_iter(),
        )
        .unwrap()
        .unwrap();

        assert_eq!(options.message, "Approve aws config export-credentials");
    }

    #[test]
    fn gate_parse_options_trims_message() {
        let options = parse_gate_options("av gate", vec![OsString::from(" approve ")].into_iter())
            .unwrap()
            .unwrap();

        assert_eq!(options.message, "approve");
    }

    #[test]
    fn gate_parse_options_rejects_empty_message() {
        let err =
            parse_gate_options("av gate", vec![OsString::from("   ")].into_iter()).unwrap_err();

        assert!(err.contains("empty gate message"));
    }

    #[test]
    fn gate_parse_options_rejects_extra_arguments() {
        let err = parse_gate_options(
            "av gate",
            vec![OsString::from("approve"), OsString::from("extra")].into_iter(),
        )
        .unwrap_err();

        assert!(err.contains("single gate message"));
    }

    #[test]
    fn gate_parse_options_cover_help_version_and_non_utf8() {
        assert_eq!(
            parse_gate_options("av gate", vec![OsString::from("--help")].into_iter()).unwrap(),
            None
        );
        assert_eq!(
            parse_gate_options("av gate", vec![OsString::from("--version")].into_iter()).unwrap(),
            None
        );

        #[cfg(unix)]
        assert_eq!(
            parse_gate_options("av gate", vec![OsString::from_vec(vec![0xff])].into_iter())
                .unwrap_err(),
            "gate message must be valid UTF-8".to_string()
        );
    }

    #[test]
    fn gate_dispatch_reports_help_and_missing_message() {
        assert_eq!(
            parse_gate_options("av gate", vec![OsString::from("--help")].into_iter()).unwrap(),
            None
        );
        assert_eq!(
            parse_gate_options("av gate", Vec::<OsString>::new().into_iter()).unwrap_err(),
            "missing gate message"
        );
    }

    #[test]
    fn gate_parent_snapshot_covers_display_name_derivation() {
        let snapshot = parent_process_snapshot();
        assert!(snapshot.pid > 0);
        assert_eq!(
            snapshot.display_name.as_deref(),
            snapshot
                .executable_path
                .as_deref()
                .and_then(|path| Path::new(path).file_name())
                .and_then(|name| name.to_str())
        );
    }

    #[test]
    fn gate_wait_for_decision_wrapper_uses_default_paths() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let _env = EnvGuard::set("HOME", temp.path().to_str().unwrap());

        let pending = pending_approval_path().unwrap();
        write_json(
            &pending,
            &GateApprovalRequestSnapshot {
                id: "wrapper-approved".to_string(),
                message: "approve".to_string(),
                cwd: "/tmp".to_string(),
                parent_process: parent_process_snapshot(),
            },
        )
        .unwrap();
        let approved = decision_path("wrapper-approved").unwrap();
        write_json(
            &approved,
            &GateApprovalDecision {
                id: "wrapper-approved".to_string(),
                approved: true,
                reason: None,
            },
        )
        .unwrap();

        wait_for_gate_decision("wrapper-approved").unwrap();
    }

    #[test]
    fn gate_paths_are_derived_from_home() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let _env = EnvGuard::set("HOME", temp.path().to_str().unwrap());

        assert_eq!(
            user_approval_root().unwrap(),
            temp.path()
                .join("Library/Application Support/Automic Vault/gate")
        );
        assert_eq!(
            pending_approval_path().unwrap(),
            temp.path()
                .join("Library/Application Support/Automic Vault/gate/pending-approval.json")
        );
        assert_eq!(
            decision_path("abc").unwrap(),
            temp.path()
                .join("Library/Application Support/Automic Vault/gate/decisions/abc.json")
        );
    }

    #[test]
    fn gate_user_approval_root_requires_home() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let _env = EnvGuard::set("HOME", "/tmp/gate-home");
        unsafe { env::remove_var("HOME") };

        assert_eq!(user_approval_root(), Err("HOME is not set".to_string()));
    }

    #[test]
    fn gate_write_json_and_clear_approval_files() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let _env = EnvGuard::set("HOME", temp.path().to_str().unwrap());
        let pending = pending_approval_path().unwrap();
        let decision = decision_path("request-1").unwrap();

        write_json(
            &pending,
            &GateApprovalRequestSnapshot {
                id: "request-1".to_string(),
                message: "approve".to_string(),
                cwd: "/tmp".to_string(),
                parent_process: ParentProcessSnapshot {
                    pid: 123,
                    executable_path: Some("/bin/sh".to_string()),
                    display_name: Some("sh".to_string()),
                },
            },
        )
        .unwrap();
        write_json(
            &decision,
            &GateApprovalDecision {
                id: "request-1".to_string(),
                approved: true,
                reason: None,
            },
        )
        .unwrap();

        assert!(pending.exists());
        assert!(decision.exists());
        clear_approval_files_at(&pending, &decision);
        assert!(!pending.exists());
        assert!(!decision.exists());
    }

    #[test]
    fn gate_wait_for_decision_handles_approval_denial_and_bad_files() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let _env = EnvGuard::set("HOME", temp.path().to_str().unwrap());
        let pending = pending_approval_path().unwrap();
        write_json(
            &pending,
            &GateApprovalRequestSnapshot {
                id: "approved".to_string(),
                message: "approve".to_string(),
                cwd: "/tmp".to_string(),
                parent_process: parent_process_snapshot(),
            },
        )
        .unwrap();

        let approved = decision_path("approved").unwrap();
        write_json(
            &approved,
            &GateApprovalDecision {
                id: "approved".to_string(),
                approved: true,
                reason: None,
            },
        )
        .unwrap();
        wait_for_gate_decision_at("approved", &pending, &approved).unwrap();

        let denied = decision_path("denied").unwrap();
        write_json(
            &denied,
            &GateApprovalDecision {
                id: "denied".to_string(),
                approved: false,
                reason: Some("not now".to_string()),
            },
        )
        .unwrap();
        assert_eq!(
            wait_for_gate_decision_at("denied", &pending, &denied).unwrap_err(),
            "not now"
        );

        let mismatch = decision_path("mismatch").unwrap();
        write_json(
            &mismatch,
            &GateApprovalDecision {
                id: "other".to_string(),
                approved: true,
                reason: None,
            },
        )
        .unwrap();
        assert_eq!(
            wait_for_gate_decision_at("mismatch", &pending, &mismatch).unwrap_err(),
            "gate approval decision id mismatch"
        );

        let bad = decision_path("bad").unwrap();
        fs::create_dir_all(bad.parent().unwrap()).unwrap();
        fs::write(&bad, b"not json").unwrap();
        assert!(
            wait_for_gate_decision_at("bad", &pending, &bad)
                .unwrap_err()
                .contains("failed to decode gate approval decision")
        );
    }

    #[test]
    fn gate_request_flow_writes_snapshot_and_removes_pending_on_ping_failure() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let _env = EnvGuard::set("HOME", temp.path().to_str().unwrap());

        let err = request_gate_approval_with(
            &GateOptions {
                message: "approve".to_string(),
            },
            || Err("ping failed".to_string()),
            |_| Ok(()),
        )
        .unwrap_err();

        assert_eq!(err, "ping failed");
        assert!(!pending_approval_path().unwrap().exists());
    }

    #[test]
    fn gate_request_flow_persists_snapshot_and_waits_with_generated_id() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let _env = EnvGuard::set("HOME", temp.path().to_str().unwrap());
        let seen_request_id = Arc::new(Mutex::new(None::<String>));
        let seen_request_id_for_wait = Arc::clone(&seen_request_id);

        request_gate_approval_with(
            &GateOptions {
                message: "approve access".to_string(),
            },
            || Ok(()),
            move |request_id| {
                let pending = pending_approval_path().unwrap();
                let snapshot: GateApprovalRequestSnapshot =
                    serde_json::from_slice(&fs::read(&pending).unwrap()).unwrap();
                assert_eq!(snapshot.message, "approve access");
                assert_eq!(
                    snapshot.cwd,
                    env::current_dir().unwrap().display().to_string()
                );
                assert_eq!(snapshot.id, request_id);
                *seen_request_id_for_wait.lock().unwrap() = Some(request_id.to_string());
                Ok(())
            },
        )
        .unwrap();

        let request_id = seen_request_id.lock().unwrap().clone().unwrap();
        assert!(request_id.starts_with(&format!("{}-", process::id())));
        assert!(pending_approval_path().unwrap().exists());
    }
}
