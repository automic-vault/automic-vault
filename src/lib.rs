#![cfg(target_os = "macos")]

mod approval_service;
pub mod brew_cask_policy;
mod cli;
mod gpg;
mod isotopes;
mod path_security;
mod secrets;

pub use cli::{run, run_scanner_terminal, run_terminal};
pub use gpg::run_git_program;

#[doc(hidden)]
pub fn approval_service_unavailable_message(service: &std::ffi::CStr) -> &'static str {
    approval_service::unavailable_message(service)
}

/// # Safety
///
/// `reply` must be a valid XPC object.
#[doc(hidden)]
pub unsafe fn approval_service_connection_invalid(reply: *mut std::ffi::c_void) -> bool {
    unsafe { approval_service::connection_invalid(reply) }
}

pub const MENU_HELPER_CODE_SIGNING_REQUIREMENT: &str = r#"anchor apple generic and certificate leaf[subject.OU] = ZU76A67LGU and identifier "com.automicvault""#;

fn test_env_var(name: &str) -> Option<std::ffi::OsString> {
    if !cfg!(debug_assertions) {
        return None;
    }
    let executable = std::env::current_exe().ok()?.canonicalize().ok()?;
    let cargo_profile = std::path::Path::new(env!("AV_CARGO_PROFILE_DIR"))
        .canonicalize()
        .ok()?;
    executable
        .starts_with(cargo_profile)
        .then(|| std::env::var_os(name))
        .flatten()
}

fn test_env_string(name: &str) -> Option<String> {
    test_env_var(name)?.into_string().ok()
}

fn test_keychain_dir() -> Option<std::path::PathBuf> {
    test_env_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR").map(Into::into)
}

pub(crate) fn bash_shell_secret_insecurity_reasons() -> Result<Vec<String>, String> {
    cli::bash_shell_secret_insecurity_reasons()
}

pub(crate) fn zsh_shell_secret_insecurity_reasons() -> Result<Vec<String>, String> {
    cli::zsh_shell_secret_insecurity_reasons()
}

#[cfg(test)]
pub fn global_test_env_lock() -> &'static std::sync::Mutex<()> {
    &cli::ENV_LOCK
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Finding {
    source: &'static str,
    homepage: &'static str,
    severity: &'static str,
    explanation: String,
    solution: String,
    affected: Vec<AffectedFile>,
    docs_url: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AffectedFile {
    path: String,
    line: Option<usize>,
}
