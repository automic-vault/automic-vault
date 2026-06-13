use std::collections::{HashMap, HashSet};
use std::env;
#[cfg(target_os = "macos")]
use std::ffi::CString;
use std::ffi::OsStr;
#[cfg(target_os = "macos")]
use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::io::ErrorKind;
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{self, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use flate2::read::GzDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::Archive;
use tempfile::TempDir;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use ureq::Error as UreqError;
use walkdir::WalkDir;

mod audit;
mod brew;
mod cask;
mod cli_help;
mod config;
mod core;
mod dotenv;
mod gate;
mod npm;
mod ops;
mod pip;
mod protocol;
mod state;
mod transfer;
#[path = "../../../manifests/packages.rs"]
pub mod vendor;

mod cli;
mod info;
mod install;
mod isotope;
mod trace;
#[allow(clippy::all, dead_code, unused_parens, unused_variables)]
mod isotope_integrations {
    include!(concat!(env!("OUT_DIR"), "/isotope_integrations.rs"));
}
mod stubs;
mod vault;

#[cfg(test)]
static GLOBAL_TEST_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(test)]
pub(crate) fn global_test_env_lock() -> &'static Mutex<()> {
    GLOBAL_TEST_ENV_LOCK.get_or_init(|| Mutex::new(()))
}

pub(crate) use cli::*;
pub use cli::{main_entry, scanner_main_entry};
pub(crate) use cli_help::*;
pub use dotenv::{DotenvApprovalMode, DotenvApprovalPolicy};
pub(crate) use info::*;
pub(crate) use install::*;
pub use isotope::isotope_main_entry;
pub use ops::{
    HelperCommand, HelperCommandResult, HelperCommandSuccess, PackageSpec, ProgressEvent,
    check_for_updates, execute_helper_command, verify_helper_codesign_identity,
};
pub(crate) use stubs::*;
pub(crate) use trace::*;
pub use vault::vault_main_entry;
pub use vault::{
    DotenvKeychainDeleteRequest, DotenvKeychainDeleteResponse, DotenvKeychainLoadRequest,
    DotenvKeychainLoadResponse, DotenvKeychainStoreRequest, DotenvKeychainStoreResponse,
    ExecutionIntent, KeyTransferApprovalItem, KeyTransferApprovalRequest,
    KeyTransferApprovalSource, KeyTransferImportItem, KeyTransferImportRequest,
    KeyTransferImportResponse, VaultApprovalRequest, VaultApprovalResponse, VaultClientRequest,
    VaultContainmentSession, VaultDaemonEvent, VaultExecChunk, VaultExecCompletion,
    VaultExecutionEnvironment, VaultProcessSnapshot, VaultToolAlias, VaultToolchainManifest,
};

mod post_install_hooks {
    use super::*;

    #[derive(Debug, Default, PartialEq, Eq)]
    pub(crate) struct PostInstallOutcome {
        pub(crate) managed_stubs: Vec<String>,
    }

    mod python {
        include!("../post-install/python.rs");
    }

    mod openssl {
        include!("../post-install/openssl.rs");
    }

    pub(crate) fn supports(formula: &str) -> bool {
        python::supports(formula) || openssl::supports(formula)
    }

    pub(crate) fn supports_dependency(formula: &str) -> bool {
        openssl::supports(formula)
    }

    pub(crate) fn run(
        formula: &str,
        prefix: &Path,
        bin_dir: &Path,
    ) -> Result<PostInstallOutcome, String> {
        if python::supports(formula) {
            return python::post_install(prefix, bin_dir);
        }
        if openssl::supports(formula) {
            openssl::post_install(prefix)?;
            return Ok(PostInstallOutcome::default());
        }
        Ok(PostInstallOutcome::default())
    }
}

const DB_SCHEMA_VERSION: u32 = 7;
#[cfg(all(not(test), feature = "packaged-db"))]
const EMBEDDED_COMBINED_DATA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/combined.json"));
#[cfg(any(test, not(feature = "packaged-db")))]
const EMBEDDED_COMBINED_DATA: &[u8] = include_bytes!("fixtures/coverage-combined.json");
const EMBEDDED_POST_INSTALL_CHECK_SKIP: &str =
    include_str!("../../../data/post_install_check_skip.jsonc");
const REMOTE_COMBINED_DATA_URL: &str = "https://automicvault.com/db.json";
const REMOTE_COMBINED_DATA_DIR: &str = "/var/db/automic-vault";
const REMOTE_COMBINED_DATA_PATH: &str = "/var/db/automic-vault/db.json";
const REMOTE_COMBINED_DATA_META_PATH: &str = "/var/db/automic-vault/db.meta.json";
const REMOTE_COMBINED_DATA_CHECK_INTERVAL_SECONDS: u64 = 60 * 60;
const BREW_PACKAGE_PREFIX: &str = "brew:";
const CASK_PACKAGE_PREFIX: &str = "cask:";
const ISOTOPE_PACKAGE_PREFIX: &str = "isotope:";
const VENDOR_PACKAGE_PREFIX: &str = "av:";
const ISOTOPE_INSTALL_ROOT_DIR: &str = "iso";
const PKG_DISPLAY_NAME: &str = "av";
const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
const RELOCATABLE_HOMEBREW_PREFIX: &str = "/opt/homebrew";
const HOMEBREW_PREFIX_PLACEHOLDER: &str = "@@HOMEBREW_PREFIX@@";
const HOMEBREW_CELLAR_PLACEHOLDER: &str = "@@HOMEBREW_CELLAR@@";
const HOMEBREW_REPOSITORY_PLACEHOLDER: &str = "@@HOMEBREW_REPOSITORY@@";
const HOMEBREW_LIBRARY_PLACEHOLDER: &str = "@@HOMEBREW_LIBRARY@@";
const HOMEBREW_PERL_PLACEHOLDER: &str = "@@HOMEBREW_PERL@@";
const HOMEBREW_JAVA_PLACEHOLDER: &str = "@@HOMEBREW_JAVA@@";
const SYSTEM_TMP_ROOT: &str = "/tmp";
const OPENSSL_CA_CERTIFICATES_DIR: &str = "share/ca-certificates";
const OPENSSL_CA_CERTIFICATES_CERT: &str = "share/ca-certificates/cacert.pem";
const OPENSSL_CERT_PEM_PATH: &str = "/etc/openssl@3/cert.pem";
const OPENSSL_CERT_PEM_DESTINATION_DIR: &str = "ssl";
const OPENSSL_CERT_PEM_DESTINATION: &str = "ssl/cert.pem";
const HOMEBREW_NEEDLES: [&[u8]; 6] = [
    b"@@HOMEBREW_PREFIX@@",
    b"@@HOMEBREW_CELLAR@@",
    b"@@HOMEBREW_REPOSITORY@@",
    b"@@HOMEBREW_LIBRARY@@",
    b"@@HOMEBREW_PERL@@",
    b"@@HOMEBREW_JAVA@@",
];
const TMP_TOOL_ROOT: &str = "/tmp/nucleus";
const PKG_STATE_LOCK: &str = ".pkg.lock";
#[cfg(feature = "gold-release")]
const SELF_UPDATE_TARGET: &str = "/usr/local/bin/av";
const SELF_UPDATE_DISABLE_FLAG: &str = "--no-self-update";
#[cfg(feature = "gold-release")]
const SELF_UPDATE_REPO: &str = "mxcl/nucleus";
const ROOT_RECEIPT: &str = ".pkg/root-receipt.json";
const RECEIPTS_DIR: &str = ".pkg/receipts";
const ROOT_EXECUTABLES_MANIFEST: &str = ".pkg/root-executables.json";
const ROOT_OWNERSHIP_MANIFEST: &str = ".pkg/root-owned-paths.json";
const STUB_MANIFEST: &str = ".pkg/stubs.json";
const STUB_HEADER: &str = "# generated by av";
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const SCANNER_WRAPPER_UI_ENV: &str = "AUTOMIC_VAULT_SCANNER_WRAPPER_UI";
const RENDERED_ERROR_PREFIX: &str = "__SUBS_RENDERED_ERROR__\n";
const GUI_APP_BUNDLE_IDENTIFIER: &str = "com.automicvault";
const GUI_APP_BUNDLE_NAME: &str = "Automic Vault.app";
const SAFE_BINARY_PATH_BYTES: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-/@";
static POST_INSTALL_CHECK_SKIP: OnceLock<HashSet<String>> = OnceLock::new();
static NPM_PACKAGE_DATA: OnceLock<HashMap<String, PackageInstallData>> = OnceLock::new();
static PIP_PACKAGE_DATA: OnceLock<HashMap<String, PackageInstallData>> = OnceLock::new();
static ISOTOPE_DATA: OnceLock<HashMap<String, IsotopePackageData>> = OnceLock::new();
static VIRTUAL_ISOTOPE_DATA: OnceLock<Mutex<HashMap<String, &'static IsotopePackageData>>> =
    OnceLock::new();
static SECURITY_RECOMMENDATIONS: OnceLock<SecurityRecommendationsData> = OnceLock::new();
static COMBINED_DATA: OnceLock<CombinedData> = OnceLock::new();
static FORMULA_INDEX: OnceLock<Result<Vec<FormulaIndexEntry>, String>> = OnceLock::new();
static FORMULA_ALIAS_INDEX: OnceLock<Result<HashMap<String, String>, String>> = OnceLock::new();
static CASK_ALIAS_INDEX: OnceLock<HashMap<String, String>> = OnceLock::new();
static STUB_EXCLUSIONS: OnceLock<HashMap<String, HashSet<String>>> = OnceLock::new();

fn formula_api_root() -> String {
    config::formula_api_root()
}

fn pypi_root() -> String {
    config::pypi_root()
}

pub(crate) fn opt_pkg_root() -> PathBuf {
    config::opt_pkg_root()
}

pub(crate) fn opt_npm_root() -> PathBuf {
    config::opt_npm_root()
}

pub(crate) fn opt_pip_root() -> PathBuf {
    config::opt_pip_root()
}

pub(crate) fn managed_bin_root() -> PathBuf {
    config::managed_bin_root()
}

pub(crate) fn install_requires_root() -> bool {
    config::install_requires_root()
}

fn homebrew_debug_allowance_enabled() -> bool {
    config::homebrew_debug_allowance_enabled()
}

pub(crate) fn configure_debug_install_environment() {
    if !homebrew_debug_allowance_enabled() {
        return;
    }

    let mut flags = env::var("PKG_ALLOW").unwrap_or_default();
    for flag in ["unsupported-formulas", "relocation-failures"] {
        if pkg_allow_value_contains(&flags, flag) {
            continue;
        }
        if !flags.is_empty() {
            flags.push(':');
        }
        flags.push_str(flag);
    }
    // SAFETY: This runs during process startup before any worker threads are
    // spawned, so mutating the process environment here is well-defined.
    unsafe { env::set_var("PKG_ALLOW", flags) };
}

#[derive(Debug, Deserialize)]
struct CombinedData {
    #[allow(dead_code)]
    schema: u32,
    #[allow(dead_code)]
    generated_at: String,
    sources: CombinedDataSources,
}

#[derive(Debug, Deserialize)]
struct CombinedDataSources {
    db: Db,
    isotopes: HashMap<String, IsotopePackageData>,
    npm: HashMap<String, PackageInstallData>,
    pip: HashMap<String, PackageInstallData>,
    #[serde(default, rename = "security-recommendations")]
    security_recommendations: SecurityRecommendationsData,
    stub_exclusions: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct RemoteCombinedDataMetadata {
    etag: Option<String>,
    checked_at: Option<u64>,
}

fn embedded_combined_data() -> &'static CombinedData {
    COMBINED_DATA.get_or_init(|| {
        #[cfg(all(not(test), feature = "packaged-db"))]
        {
            let embedded = serde_json::from_slice(EMBEDDED_COMBINED_DATA)
                .expect("failed to parse embedded combined package data JSON");
            match load_trusted_remote_combined_data() {
                Some(remote) if combined_data_is_at_least_as_new(&remote, &embedded) => remote,
                _ => embedded,
            }
        }
        #[cfg(any(test, not(feature = "packaged-db")))]
        {
            serde_json::from_slice(EMBEDDED_COMBINED_DATA)
                .expect("failed to parse embedded combined package data JSON")
        }
    })
}

#[cfg(any(test, feature = "packaged-db"))]
fn combined_data_is_at_least_as_new(candidate: &CombinedData, baseline: &CombinedData) -> bool {
    let Ok(candidate_time) = OffsetDateTime::parse(&candidate.generated_at, &Rfc3339) else {
        return false;
    };
    let Ok(baseline_time) = OffsetDateTime::parse(&baseline.generated_at, &Rfc3339) else {
        return true;
    };
    candidate_time >= baseline_time
}

#[cfg(all(not(test), feature = "packaged-db"))]
fn load_trusted_remote_combined_data() -> Option<CombinedData> {
    load_trusted_remote_combined_data_from(
        Path::new(REMOTE_COMBINED_DATA_DIR),
        Path::new(REMOTE_COMBINED_DATA_PATH),
        true,
    )
}

#[cfg(any(test, feature = "packaged-db"))]
fn load_trusted_remote_combined_data_from(
    dir: &Path,
    path: &Path,
    require_root_owner: bool,
) -> Option<CombinedData> {
    if !trusted_remote_data_path(dir, path, require_root_owner) {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let data = serde_json::from_slice::<CombinedData>(&bytes).ok()?;
    ensure_combined_data_schema(&data).ok()?;
    Some(data)
}

fn ensure_combined_data_schema(data: &CombinedData) -> Result<(), String> {
    ensure_db_schema(&data.sources.db)
}

#[cfg(any(test, feature = "packaged-db"))]
fn trusted_remote_data_path(dir: &Path, path: &Path, require_root_owner: bool) -> bool {
    let Ok(dir_metadata) = fs::metadata(dir) else {
        return false;
    };
    if !dir_metadata.is_dir() || !trusted_remote_data_metadata(&dir_metadata, require_root_owner) {
        return false;
    }
    let Ok(file_metadata) = fs::metadata(path) else {
        return false;
    };
    file_metadata.is_file() && trusted_remote_data_metadata(&file_metadata, require_root_owner)
}

#[cfg(any(test, feature = "packaged-db"))]
fn trusted_remote_data_metadata(metadata: &fs::Metadata, require_root_owner: bool) -> bool {
    if require_root_owner && metadata.uid() != 0 {
        return false;
    }
    metadata.mode() & 0o022 == 0
}

pub fn refresh_remote_combined_data() -> Result<bool, String> {
    refresh_remote_combined_data_with(
        REMOTE_COMBINED_DATA_URL,
        Path::new(REMOTE_COMBINED_DATA_DIR),
        Path::new(REMOTE_COMBINED_DATA_PATH),
        Path::new(REMOTE_COMBINED_DATA_META_PATH),
        REMOTE_COMBINED_DATA_CHECK_INTERVAL_SECONDS,
    )
}

fn refresh_remote_combined_data_with(
    url: &str,
    dir: &Path,
    data_path: &Path,
    meta_path: &Path,
    interval_seconds: u64,
) -> Result<bool, String> {
    let mut metadata = read_remote_combined_data_metadata(meta_path);
    let now = current_unix_timestamp()?;
    if metadata
        .checked_at
        .is_some_and(|checked_at| now.saturating_sub(checked_at) < interval_seconds)
    {
        return Ok(false);
    }

    let mut request = ureq::get(url).set("User-Agent", USER_AGENT);
    if let Some(etag) = metadata.etag.as_deref() {
        request = request.set("If-None-Match", etag);
    }

    let response = match request.call() {
        Ok(response) => response,
        Err(UreqError::Status(304, response)) => {
            metadata.checked_at = Some(now);
            if let Some(etag) = response.header("ETag") {
                metadata.etag = Some(etag.to_string());
            }
            write_remote_combined_data_metadata(dir, meta_path, &metadata)?;
            return Ok(false);
        }
        Err(UreqError::Status(code, _)) => {
            return Err(format!("failed to fetch {url}: http {code}"));
        }
        Err(UreqError::Transport(err)) => {
            return Err(format!("failed to fetch {url}: {err}"));
        }
    };

    if response.status() == 304 {
        metadata.checked_at = Some(now);
        if let Some(etag) = response.header("ETag") {
            metadata.etag = Some(etag.to_string());
        }
        write_remote_combined_data_metadata(dir, meta_path, &metadata)?;
        return Ok(false);
    }

    let etag = response.header("ETag").map(str::to_string);
    let mut bytes = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut bytes)
        .map_err(|err| format!("failed to read {url}: {err}"))?;
    let data = serde_json::from_slice::<CombinedData>(&bytes)
        .map_err(|err| format!("failed to parse {url}: {err}"))?;
    ensure_combined_data_schema(&data)
        .map_err(|err| format!("unsupported remote database {url}: {err}"))?;
    write_remote_combined_data(dir, data_path, &bytes)?;
    metadata.etag = etag.or(metadata.etag);
    metadata.checked_at = Some(now);
    write_remote_combined_data_metadata(dir, meta_path, &metadata)?;
    Ok(true)
}

fn read_remote_combined_data_metadata(path: &Path) -> RemoteCombinedDataMetadata {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn write_remote_combined_data(dir: &Path, path: &Path, bytes: &[u8]) -> Result<(), String> {
    ensure_remote_combined_data_dir(dir)?;
    let temp_path = path.with_extension("json.tmp");
    fs::write(&temp_path, bytes)
        .map_err(|err| format!("failed to write {}: {err}", temp_path.display()))?;
    set_root_readable_permissions(&temp_path, 0o644)?;
    fs::rename(&temp_path, path)
        .map_err(|err| format!("failed to replace {}: {err}", path.display()))?;
    set_root_readable_permissions(path, 0o644)
}

fn write_remote_combined_data_metadata(
    dir: &Path,
    path: &Path,
    metadata: &RemoteCombinedDataMetadata,
) -> Result<(), String> {
    ensure_remote_combined_data_dir(dir)?;
    let bytes = serde_json::to_vec(metadata)
        .map_err(|err| format!("failed to encode {}: {err}", path.display()))?;
    let temp_path = path.with_extension("json.tmp");
    fs::write(&temp_path, bytes)
        .map_err(|err| format!("failed to write {}: {err}", temp_path.display()))?;
    set_root_readable_permissions(&temp_path, 0o644)?;
    fs::rename(&temp_path, path)
        .map_err(|err| format!("failed to replace {}: {err}", path.display()))?;
    set_root_readable_permissions(path, 0o644)
}

fn ensure_remote_combined_data_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|err| format!("failed to create {}: {err}", path.display()))?;
    set_root_readable_permissions(path, 0o755)
}

fn set_root_readable_permissions(path: &Path, mode: u32) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|err| format!("failed to chmod {}: {err}", path.display()))?;
    set_root_owner(path)
}

fn set_root_owner(path: &Path) -> Result<(), String> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("path contains interior nul: {}", path.display()))?;
    let result = unsafe { libc::chown(c_path.as_ptr(), 0, 0) };
    if result == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.kind() == ErrorKind::PermissionDenied && cfg!(debug_assertions) {
        return Ok(());
    }
    Err(format!("failed to chown {}: {err}", path.display()))
}

fn current_unix_timestamp() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| format!("system clock is before unix epoch: {err}"))
}

#[derive(Debug, Clone, Deserialize)]
struct Db {
    schema: u32,
    #[allow(dead_code)]
    generated_at: String,
    entries: HashMap<String, String>,
    #[serde(default)]
    formulas: HashMap<String, EmbeddedFormulaMetadata>,
    #[serde(default)]
    casks: HashMap<String, EmbeddedCaskMetadata>,
    #[serde(default)]
    npms: HashMap<String, EmbeddedNpmMetadata>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct EmbeddedFormulaMetadata {
    #[serde(default)]
    summary: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    oldnames: Vec<String>,
    #[serde(default)]
    category: String,
    #[serde(default)]
    homepage: String,
    #[serde(default, alias = "repo")]
    repository: String,
    #[serde(default, rename = "upstreamDocs")]
    upstream_docs: String,
    #[serde(default)]
    docs: Vec<String>,
    popularity: Option<EmbeddedPackagePopularity>,
    last_updated_at: Option<String>,
    pulse_kind: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct EmbeddedCaskMetadata {
    #[serde(default)]
    summary: String,
    #[serde(default)]
    homepage: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    url: String,
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default)]
    binaries: Vec<EmbeddedCaskBinary>,
    popularity: Option<EmbeddedPackagePopularity>,
    last_updated_at: Option<String>,
    pulse_kind: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct EmbeddedCaskBinary {
    source: String,
    target: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, Serialize, PartialEq, Eq)]
struct EmbeddedPackagePopularity {
    installs_per_365_days: u64,
    rank: u32,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct EmbeddedNpmMetadata {
    #[serde(default)]
    summary: String,
    #[serde(default)]
    homepage: String,
    version: String,
    executable: String,
    popularity: Option<EmbeddedNpmPopularity>,
    last_updated_at: Option<String>,
    pulse_kind: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct EmbeddedNpmPopularity {
    #[allow(dead_code)]
    downloads_per_30_days: u64,
    rank: u32,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct PackageInstallData {
    #[serde(default, rename = "homebrewDeps")]
    homebrew_dependencies: Vec<String>,
    #[serde(default, rename = "pythonFormula")]
    python_formula: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct SecurityRecommendationsData {
    #[serde(default)]
    packages: HashMap<String, SecurityRecommendationPackage>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct SecurityRecommendationPackage {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "installPackageName")]
    install_package_name: String,
    #[serde(default)]
    priority: u32,
    #[serde(default)]
    signals: Vec<String>,
    #[serde(default)]
    reasons: Vec<String>,
    #[serde(default)]
    isotope: Option<String>,
    #[serde(default, rename = "isotopePackage")]
    isotope_package: Option<String>,
    #[serde(default, rename = "approvalGate")]
    approval_gate: bool,
    #[serde(default, rename = "geigerLevel")]
    geiger_level: Option<String>,
    #[serde(default, rename = "geigerConfidence")]
    geiger_confidence: Option<String>,
    #[serde(default, rename = "geigerCategory")]
    geiger_category: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct IsotopePackageData {
    name: String,
    #[serde(default)]
    replaces: Option<String>,
    #[serde(default)]
    modifies: Option<String>,
    #[serde(default)]
    migrate: Option<String>,
    #[serde(default)]
    _repository: Option<String>,
    #[serde(default, rename = "upstreamRepository")]
    _upstream_repository: Option<String>,
    version: String,
    #[serde(default, rename = "releaseUrl")]
    release_url: Option<String>,
    #[serde(default, rename = "archiveUrl")]
    archive_url: Option<String>,
    #[serde(default, rename = "publishedAt")]
    published_at: Option<String>,
    #[serde(default, rename = "appliesToVersionedFormulae")]
    applies_to_versioned_formulae: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PackageSecurityState {
    #[serde(rename = "isotopeName")]
    isotope_name: String,
    #[serde(rename = "installIsInsecure")]
    install_is_insecure: bool,
    #[serde(rename = "remediationAvailable")]
    remediation_available: bool,
    reasons: Vec<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FormulaInfo {
    #[serde(default)]
    desc: String,
    #[serde(default)]
    homepage: String,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    versions: FormulaVersions,
    #[serde(default)]
    revision: u32,
    #[serde(default)]
    dependencies: Vec<String>,
    bottle: Bottle,
    disabled: bool,
    #[serde(default)]
    post_install_defined: bool,
}

#[derive(Debug, Deserialize)]
struct PypiPackageInfoResponse {
    info: PypiPackageInfo,
}

#[derive(Debug, Deserialize)]
struct PypiPackageInfo {
    version: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    home_page: String,
}

#[derive(Debug, Deserialize)]
struct NpmPackageMetadata {
    description: Option<String>,
    homepage: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct FormulaIndexEntry {
    name: String,
    #[serde(default, alias = "desc")]
    summary: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    oldnames: Vec<String>,
    #[serde(default)]
    category: String,
    #[serde(default)]
    homepage: String,
    #[serde(default, alias = "repo")]
    repository: String,
    #[serde(default, rename = "upstreamDocs")]
    upstream_docs: String,
    #[serde(default)]
    docs: Vec<String>,
    popularity: Option<EmbeddedPackagePopularity>,
    last_updated_at: Option<String>,
    pulse_kind: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct FormulaVersions {
    #[serde(default)]
    stable: String,
}

#[derive(Debug, Deserialize)]
struct GitHubCommitListEntry {
    commit: GitHubCommit,
}

#[derive(Debug, Deserialize)]
struct GitHubCommit {
    committer: Option<GitHubCommitIdentity>,
    author: Option<GitHubCommitIdentity>,
}

#[derive(Debug, Deserialize)]
struct GitHubCommitIdentity {
    date: String,
}

#[derive(Debug, Deserialize)]
struct Bottle {
    stable: Option<BottleStable>,
}

#[derive(Debug, Deserialize)]
struct BottleStable {
    files: HashMap<String, BottleFile>,
}

#[derive(Debug, Deserialize)]
struct BottleFile {
    sha256: String,
    url: String,
}

#[derive(Debug, Clone)]
struct FormulaSpec {
    name: String,
    bottle_sha256: String,
    bottle_url: String,
}

#[derive(Debug)]
struct DownloadedBottle {
    path: PathBuf,
    _tmp_dir: TempDir,
}

#[derive(Debug, Deserialize)]
struct GhcrTokenResponse {
    token: String,
}

#[cfg(feature = "gold-release")]
#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubReleaseAsset>,
}

#[cfg(feature = "gold-release")]
#[derive(Debug, Deserialize)]
struct GithubReleaseAsset {
    name: String,
    browser_download_url: String,
}

#[cfg(feature = "gold-release")]
#[derive(Debug)]
struct SelfUpdateRelease {
    version: semver::Version,
    asset_name: String,
    download_url: String,
}

#[derive(Debug, Clone)]
struct InstalledFormula {
    spec: FormulaSpec,
    keg_dir_name: String,
    archive_path: PathBuf,
}

#[derive(Debug, Clone)]
struct RewriteRule {
    source: String,
    destination: String,
}

#[derive(Debug)]
struct Config {
    bottle_tag: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    I,
}

#[derive(Debug)]
struct Invocation {
    binary_name: String,
    name: String,
    mode: Option<Mode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EmbeddedPackage {
    Formula(String),
    Cask(String),
    NpmPackage(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PackageAliasTarget {
    HomebrewFormula(String),
    HomebrewCask(String),
    VendorPackage(String),
    NpmPackage(String),
    PipPackage(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestedPackage {
    Auto(String),
    HomebrewFormula(String),
    HomebrewCask(String),
    VendorPackage(String),
    Isotope(String),
    NpmPackage {
        package: String,
        version: Option<String>,
    },
    PipPackage(String),
}

type ProgressCallback = dyn FnMut(ProgressEvent) + Send;

#[derive(Debug, PartialEq, Eq)]
struct IRequest {
    packages: Vec<RequestedPackage>,
    force: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct UninstallRequest {
    packages: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct UpdateRequest {
    selection: PackageSelection,
    no_self_update: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct PackageStatusRequest {
    selection: PackageSelection,
    output: OutputMode,
}

#[derive(Debug, PartialEq, Eq)]
struct InfoRequest {
    package: RequestedPackage,
    output: OutputMode,
}

#[derive(Debug, PartialEq, Eq)]
struct SearchRequest {
    query: String,
    output: OutputMode,
}

#[derive(Debug, PartialEq, Eq)]
struct SecretScannerRequest {
    path: Option<PathBuf>,
    skip_paths: Vec<PathBuf>,
    output: OutputMode,
    isotopes_only: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct TraceRequest {
    command: String,
    agent: TraceAgent,
    output: OutputMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraceAgent {
    Auto,
    Codex,
    Claude,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct TraceReport {
    command: String,
    agent: String,
    #[serde(rename = "safetyRating")]
    safety_rating: TraceSafetyRating,
    steps: Vec<TraceStep>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct TraceSafetyRating {
    level: String,
    reasons: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
struct TraceStep {
    description: String,
    operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TraceAgentOutput {
    steps: Vec<TraceStep>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    Human,
    Json,
    Jsonl,
}

#[derive(Debug, PartialEq, Eq)]
enum PackageSelection {
    AllInstalled,
    Requested(Vec<RequestedPackage>),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SecretScannerReport {
    scope: SecretScannerScope,
    findings: Vec<SecretScannerFinding>,
    errors: Vec<SecretScannerError>,
    summary: SecretScannerSummary,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum SecretScannerScope {
    Full,
    IsotopesOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ShellSecretFlavor {
    Bash,
    Zsh,
}

impl ShellSecretFlavor {
    fn display_name(self) -> &'static str {
        match self {
            ShellSecretFlavor::Bash => "Bash",
            ShellSecretFlavor::Zsh => "Zsh",
        }
    }

    fn source_label(self) -> &'static str {
        match self {
            ShellSecretFlavor::Bash => "file-probe:bash",
            ShellSecretFlavor::Zsh => "file-probe:zsh",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
struct SecretScannerFinding {
    source: String,
    kind: String,
    severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<usize>,
    message: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
struct SecretScannerError {
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    message: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SecretScannerSummary {
    scanned_files: usize,
    findings: usize,
    errors: usize,
    isotope_detectors: usize,
    file_probes: usize,
}

#[derive(Debug, Clone, Copy)]
enum SecretScannerEvent<'a> {
    Finding(&'a SecretScannerFinding),
    Error(&'a SecretScannerError),
}

#[derive(Debug, Clone)]
struct InstallPlan {
    mode: Mode,
    package_name: String,
    root_formula: String,
    stable_root: PathBuf,
    install_root: PathBuf,
    tmp_root: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct InstallReceipt {
    formula: String,
    version: String,
    bottle_sha256: String,
    bottle_tag: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    owned_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PackageReceipt {
    package_name: String,
    version: String,
    source: PackageReceiptSource,
    #[serde(default)]
    metadata: PackageMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PackageReceiptSource {
    Formula { root_formula: String },
    Cask { cask_name: String },
    Isotope { isotope_name: String },
    Vendor { vendor_name: String },
    Npm { package_name: String },
    Pip { package_name: String },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct PackageMetadata {
    description: Option<String>,
    homepage: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct InstalledPackageRecord {
    package_name: String,
    source: PackageReceiptSource,
    installed_version: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PackageStatus {
    package_name: String,
    source: PackageReceiptSource,
    installed_version: String,
    latest_version: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PackageInfo {
    package_name: String,
    qualified_name: String,
    install_root: PathBuf,
    installed: bool,
    source: Option<PackageReceiptSource>,
    source_error: Option<String>,
    aliases: Vec<String>,
    aliases_error: Option<String>,
    installed_version: Option<String>,
    latest_version: Option<String>,
    latest_version_error: Option<String>,
    executable_paths: Vec<String>,
    executable_paths_error: Option<String>,
    popularity: Option<EmbeddedPackagePopularity>,
    last_updated_at: Option<String>,
    homebrew_info: Option<HomebrewPackageInfo>,
    homebrew_info_error: Option<String>,
    npm_homepage: Option<String>,
    npm_package_info_error: Option<String>,
    security_state: Option<PackageSecurityState>,
    #[serde(rename = "versionOptions", skip_serializing_if = "Vec::is_empty")]
    version_options: Vec<FormulaVersionOption>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct FormulaVersionOption {
    #[serde(rename = "displayName")]
    display_name: String,
    #[serde(rename = "aliasName")]
    alias_name: Option<String>,
    #[serde(rename = "packageName")]
    package_name: String,
    #[serde(rename = "installPackageName")]
    install_package_name: String,
    #[serde(rename = "rootFormula")]
    root_formula: String,
    version: Option<String>,
    #[serde(rename = "installRoot")]
    install_root: PathBuf,
    installed: bool,
    #[serde(rename = "stubActive")]
    stub_active: bool,
    #[serde(rename = "isLatest")]
    is_latest: bool,
    #[serde(rename = "isRecommended")]
    is_recommended: bool,
    #[serde(rename = "supportsSideBySideStubs")]
    supports_side_by_side_stubs: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct HomebrewPackageInfo {
    formula: String,
    description: Option<String>,
    homepage: Option<String>,
    repository: Option<String>,
    #[serde(rename = "upstreamDocs", skip_serializing_if = "Option::is_none")]
    upstream_docs: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    docs: Vec<String>,
    license: Option<String>,
    dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PackageSearchResult {
    package_name: String,
    source: PackageReceiptSource,
    summary: Option<String>,
    latest_version: Option<String>,
    homepage: Option<String>,
    repository: Option<String>,
    upstream_docs: Option<String>,
    docs: Vec<String>,
    category: Option<String>,
    dependencies: Vec<String>,
    install_package_names: Vec<String>,
    security_state: Option<PackageSecurityState>,
    rank: Option<u32>,
    last_updated_at: Option<String>,
    pulse_kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstalledPackageRef {
    package_name: String,
    install_root: PathBuf,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct StubManifest {
    stubs: Vec<String>,
}

struct VendorInstall {
    package: vendor::VendorPackage,
    version: semver::Version,
}

struct ResolvedVendorDependencies {
    formula_graph: Vec<FormulaSpec>,
    vendor_installs: Vec<VendorInstall>,
}

#[derive(Debug)]
struct DependencyInstallState {
    _downloads: HashMap<String, DownloadedBottle>,
    installs: Vec<InstalledFormula>,
    changed_installs: Vec<InstalledFormula>,
}

struct PreparedInstallPlan {
    plan: InstallPlan,
    workspace: Option<TempDir>,
}

#[derive(Clone)]
struct InstallProgress {
    enabled: bool,
    bar: Option<ProgressBar>,
    state: Arc<Mutex<InstallProgressState>>,
    callback: Option<Arc<Mutex<Box<ProgressCallback>>>>,
    package_name: String,
    bytes_downloaded: Arc<Mutex<u64>>,
    total_bytes: Arc<Mutex<Option<u64>>>,
    download_started_at: Arc<Mutex<Option<Instant>>>,
    package_downloads: Arc<Mutex<HashMap<String, PackageDownloadProgress>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallProgressPhase {
    Download,
    Install,
}

#[derive(Debug)]
struct InstallProgressState {
    phase: InstallProgressPhase,
}

#[derive(Debug, Clone, Copy)]
struct PackageDownloadProgress {
    bytes_downloaded: u64,
    total_bytes: Option<u64>,
    started_at: Option<Instant>,
}

impl PackageDownloadProgress {
    fn started() -> Self {
        Self {
            bytes_downloaded: 0,
            total_bytes: None,
            started_at: Some(Instant::now()),
        }
    }
}

struct LoggedCommandOutput {
    status: ExitStatus,
    lines: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum BinaryRewriteMode<'a> {
    Slash,
    #[allow(dead_code)]
    Nul,
    Macho {
        path: &'a Path,
        root: &'a Path,
        future_root: &'a Path,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InstallOptions {
    intent: InstallIntent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallIntent {
    Install,
    Reinstall,
    Update,
}

struct PackageMutationLock {
    file: File,
}

impl InstallPlan {
    fn for_i(package_name: String, root_formula: String) -> Self {
        let opt_root = opt_pkg_root();
        let stable_root = opt_root.join(&package_name);
        let install_root = opt_root.join(&package_name);
        Self {
            mode: Mode::I,
            package_name,
            root_formula,
            stable_root,
            install_root,
            tmp_root: temp_root_for_target_root(
                &opt_root,
                Path::new(SYSTEM_TMP_ROOT),
                Path::new(TMP_TOOL_ROOT),
            ),
        }
    }

    fn for_i_npm(package_name: String, root_formula: String, npm_package: &str) -> Self {
        let npm_root = opt_npm_root();
        let stable_root = npm_root.join(npm_package_install_relative_path(npm_package));
        let install_root = stable_root.clone();
        Self {
            mode: Mode::I,
            package_name,
            root_formula,
            stable_root,
            install_root,
            tmp_root: temp_root_for_target_root(
                &npm_root,
                Path::new(SYSTEM_TMP_ROOT),
                Path::new(TMP_TOOL_ROOT),
            ),
        }
    }

    fn for_i_pip(package_name: String, root_formula: String, pip_package: &str) -> Self {
        let pip_root = opt_pip_root();
        let stable_root = pip_root.join(pip_package_install_leaf_name(pip_package));
        let install_root = stable_root.clone();
        Self {
            mode: Mode::I,
            package_name,
            root_formula,
            stable_root,
            install_root,
            tmp_root: temp_root_for_target_root(
                &pip_root,
                Path::new(SYSTEM_TMP_ROOT),
                Path::new(TMP_TOOL_ROOT),
            ),
        }
    }

    fn for_i_isotope(package_name: String, isotope_name: &str) -> Self {
        let isotope_root = opt_pkg_root().join(ISOTOPE_INSTALL_ROOT_DIR);
        let stable_root = isotope_root.join(isotope_name);
        let install_root = stable_root.clone();
        Self {
            mode: Mode::I,
            package_name: package_name.clone(),
            root_formula: package_name,
            stable_root,
            install_root,
            tmp_root: temp_root_for_target_root(
                &isotope_root,
                Path::new(SYSTEM_TMP_ROOT),
                Path::new(TMP_TOOL_ROOT),
            ),
        }
    }

    fn for_i_radioisotope(package_name: String, root_formula: String) -> Self {
        let opt_root = opt_pkg_root();
        let stable_root = opt_root.join(&root_formula);
        let install_root = stable_root.clone();
        Self {
            mode: Mode::I,
            package_name,
            root_formula,
            stable_root,
            install_root,
            tmp_root: temp_root_for_target_root(
                &opt_root,
                Path::new(SYSTEM_TMP_ROOT),
                Path::new(TMP_TOOL_ROOT),
            ),
        }
    }

    fn actual_target_dir(&self, _formula: &str) -> PathBuf {
        self.install_root.clone()
    }

    fn stable_target_dir(&self, _formula: &str) -> PathBuf {
        self.stable_root.clone()
    }

    fn receipt_path(&self, formula: &str) -> PathBuf {
        self.install_root
            .join(RECEIPTS_DIR)
            .join(format!("{formula}.json"))
    }

    fn package_manifest_path(&self) -> PathBuf {
        self.install_root.join(STUB_MANIFEST)
    }

    fn root_receipt_path(&self) -> PathBuf {
        self.install_root.join(ROOT_RECEIPT)
    }

    fn root_executables_manifest_path(&self) -> PathBuf {
        self.install_root.join(ROOT_EXECUTABLES_MANIFEST)
    }

    fn root_ownership_manifest_path(&self) -> PathBuf {
        self.install_root.join(ROOT_OWNERSHIP_MANIFEST)
    }
}

fn temp_root_for_target_root(
    target_root: &Path,
    system_tmp_root: &Path,
    shared_tmp_root: &Path,
) -> PathBuf {
    match paths_share_device(target_root, system_tmp_root) {
        Ok(true) if shared_tmp_root_is_writable(shared_tmp_root) => shared_tmp_root.to_path_buf(),
        Ok(false) | Err(_) => target_root.join(".tmp"),
        Ok(true) => target_root.join(".tmp"),
    }
}

fn shared_tmp_root_is_writable(path: &Path) -> bool {
    if fs::create_dir_all(path).is_err() {
        return false;
    }
    TempDir::new_in(path).is_ok()
}

fn paths_share_device(left: &Path, right: &Path) -> Result<bool, String> {
    Ok(device_id(left)? == device_id(right)?)
}

fn device_id(path: &Path) -> Result<u64, String> {
    let metadata_path = metadata_probe_path(path)?;
    let metadata = fs::metadata(metadata_path)
        .map_err(|err| format!("failed to stat {}: {err}", metadata_path.display()))?;
    Ok(metadata.dev())
}

fn metadata_probe_path(path: &Path) -> Result<&Path, String> {
    path.ancestors()
        .find(|ancestor| ancestor.exists())
        .ok_or_else(|| format!("no existing ancestor for {}", path.display()))
}

fn prepare_i_install_plan(
    plan: &InstallPlan,
    intent: InstallIntent,
) -> Result<PreparedInstallPlan, String> {
    fs::create_dir_all(&plan.tmp_root)
        .map_err(|err| format!("failed to create {}: {err}", plan.tmp_root.display()))?;
    let workspace = TempDir::new_in(&plan.tmp_root).map_err(|err| {
        format!(
            "failed to create staging dir in {}: {err}",
            plan.tmp_root.display()
        )
    })?;
    let staged_plan = InstallPlan {
        install_root: workspace.path().join("install"),
        ..plan.clone()
    };
    if intent == InstallIntent::Update {
        seed_incremental_update_root(plan, &staged_plan)?;
    }
    Ok(PreparedInstallPlan {
        plan: staged_plan,
        workspace: Some(workspace),
    })
}

fn preserve_temp_dir_in_debug(workspace: TempDir) {
    if !cfg!(debug_assertions) {
        return;
    }

    let path = workspace.path().to_path_buf();
    let _ = workspace.keep();
    eprintln!("info: preserved temp dir {}", path.display());
}

fn preserve_optional_temp_dir_on_failure(workspace: Option<TempDir>) {
    if let Some(workspace) = workspace {
        preserve_temp_dir_in_debug(workspace);
    }
}

fn seed_incremental_update_root(
    source_plan: &InstallPlan,
    staged_plan: &InstallPlan,
) -> Result<bool, String> {
    if !source_plan.install_root.is_dir() {
        return Ok(false);
    }
    if !install_root_supports_incremental_update(source_plan)? {
        return Ok(false);
    }
    copy_tree_contents(&source_plan.install_root, &staged_plan.install_root)?;
    Ok(true)
}

fn install_root_supports_incremental_update(plan: &InstallPlan) -> Result<bool, String> {
    let Some(package_receipt) = load_package_receipt(&plan.root_receipt_path())? else {
        return Ok(false);
    };

    if !formula_receipts_support_incremental_update(plan)? {
        return Ok(false);
    }

    if !matches!(package_receipt.source, PackageReceiptSource::Formula { .. })
        && load_root_ownership_manifest(&plan.root_ownership_manifest_path())?.is_none()
    {
        return Ok(false);
    }

    Ok(true)
}

fn formula_receipts_support_incremental_update(plan: &InstallPlan) -> Result<bool, String> {
    let receipts_dir = plan.install_root.join(RECEIPTS_DIR);
    let entries = match fs::read_dir(&receipts_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(err) => return Err(format!("failed to read {}: {err}", receipts_dir.display())),
    };

    for entry in entries {
        let entry =
            entry.map_err(|err| format!("failed to read {}: {err}", receipts_dir.display()))?;
        if entry.path().extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }
        let Some(receipt) = load_install_receipt(&entry.path())? else {
            return Ok(false);
        };
        if receipt.owned_paths.is_empty() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn copy_tree_contents(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination)
        .map_err(|err| format!("failed to create {}: {err}", destination.display()))?;
    for entry in
        fs::read_dir(source).map_err(|err| format!("failed to read {}: {err}", source.display()))?
    {
        let entry = entry.map_err(|err| format!("failed to read {}: {err}", source.display()))?;
        copy_path(&entry.path(), &destination.join(entry.file_name()))?;
    }
    Ok(())
}

fn copy_path(source: &Path, destination: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|err| format!("failed to stat {}: {err}", source.display()))?;
    if metadata.file_type().is_symlink() {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
        }
        let target = fs::read_link(source)
            .map_err(|err| format!("failed to read symlink {}: {err}", source.display()))?;
        symlink(&target, destination).map_err(|err| {
            format!(
                "failed to link {} -> {}: {err}",
                destination.display(),
                target.display()
            )
        })?;
        return Ok(());
    }
    if metadata.is_dir() {
        fs::create_dir_all(destination)
            .map_err(|err| format!("failed to create {}: {err}", destination.display()))?;
        fs::set_permissions(destination, metadata.permissions())
            .map_err(|err| format!("failed to chmod {}: {err}", destination.display()))?;
        for entry in fs::read_dir(source)
            .map_err(|err| format!("failed to read {}: {err}", source.display()))?
        {
            let entry =
                entry.map_err(|err| format!("failed to read {}: {err}", source.display()))?;
            copy_path(&entry.path(), &destination.join(entry.file_name()))?;
        }
        return Ok(());
    }
    copy_file_preserving_metadata(source, destination, &metadata)
}

fn copy_file_preserving_metadata(
    source: &Path,
    destination: &Path,
    metadata: &fs::Metadata,
) -> Result<(), String> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    clone_file_or_copy(source, destination)?;
    fs::set_permissions(destination, metadata.permissions())
        .map_err(|err| format!("failed to chmod {}: {err}", destination.display()))
}

#[cfg(target_os = "macos")]
fn clone_file_or_copy(source: &Path, destination: &Path) -> Result<(), String> {
    unsafe extern "C" {
        fn clonefile(src: *const libc::c_char, dst: *const libc::c_char, flags: u32)
        -> libc::c_int;
    }

    let source_c = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| format!("path contains NUL byte: {}", source.display()))?;
    let destination_c = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| format!("path contains NUL byte: {}", destination.display()))?;
    let cloned = unsafe { clonefile(source_c.as_ptr(), destination_c.as_ptr(), 0) == 0 };
    if cloned {
        return Ok(());
    }
    fs::copy(source, destination).map(|_| ()).map_err(|err| {
        format!(
            "failed to copy {} to {}: {err}",
            source.display(),
            destination.display()
        )
    })
}

#[cfg(not(target_os = "macos"))]
fn clone_file_or_copy(source: &Path, destination: &Path) -> Result<(), String> {
    fs::copy(source, destination).map(|_| ()).map_err(|err| {
        format!(
            "failed to copy {} to {}: {err}",
            source.display(),
            destination.display()
        )
    })
}

fn acquire_package_mutation_lock() -> Result<PackageMutationLock, String> {
    acquire_package_mutation_lock_at(&opt_pkg_root())
}

fn acquire_package_mutation_lock_at(root: &Path) -> Result<PackageMutationLock, String> {
    fs::create_dir_all(root)
        .map_err(|err| format!("failed to create {}: {err}", root.display()))?;
    let path = root.join(PKG_STATE_LOCK);
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if result != 0 {
        return Err(format!(
            "failed to lock {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(PackageMutationLock { file })
}

impl Drop for PackageMutationLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl InstallProgress {
    fn with_callback(label: &str, callback: Option<Arc<Mutex<Box<ProgressCallback>>>>) -> Self {
        if std::io::stderr().is_terminal() {
            let bar = ProgressBar::new(0);
            bar.set_prefix(label.to_string());
            bar.set_style(download_progress_style());
            bar.enable_steady_tick(Duration::from_millis(120));
            return Self {
                enabled: true,
                bar: Some(bar),
                state: Arc::new(Mutex::new(InstallProgressState {
                    phase: InstallProgressPhase::Download,
                })),
                callback,
                package_name: label.to_string(),
                bytes_downloaded: Arc::new(Mutex::new(0)),
                total_bytes: Arc::new(Mutex::new(None)),
                download_started_at: Arc::new(Mutex::new(None)),
                package_downloads: Arc::new(Mutex::new(HashMap::new())),
            };
        }

        Self {
            enabled: false,
            bar: None,
            state: Arc::new(Mutex::new(InstallProgressState {
                phase: InstallProgressPhase::Download,
            })),
            callback,
            package_name: label.to_string(),
            bytes_downloaded: Arc::new(Mutex::new(0)),
            total_bytes: Arc::new(Mutex::new(None)),
            download_started_at: Arc::new(Mutex::new(None)),
            package_downloads: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn begin_download_phase(&self) {
        let mut state = self.state.lock().unwrap();
        state.phase = InstallProgressPhase::Download;
        drop(state);
        *self.bytes_downloaded.lock().unwrap() = 0;
        *self.total_bytes.lock().unwrap() = None;
        *self.download_started_at.lock().unwrap() = Some(Instant::now());
        self.package_downloads.lock().unwrap().clear();
        if let Some(bar) = &self.bar {
            bar.set_style(download_progress_style());
            bar.set_position(0);
            bar.set_length(0);
            bar.set_message(String::new());
        }
        self.emit(ProgressEvent::Resolving);
    }

    fn add_download_total(&self, total: Option<u64>) {
        self.add_download_total_for(&self.package_name, total);
    }

    fn add_download_total_for(&self, package: &str, total: Option<u64>) {
        let Some(total) = total else {
            return;
        };
        if total == 0 {
            return;
        }
        {
            let mut total_bytes = self.total_bytes.lock().unwrap();
            *total_bytes = Some(total_bytes.unwrap_or(0) + total);
        }
        {
            let mut package_downloads = self.package_downloads.lock().unwrap();
            let state = package_downloads
                .entry(package.to_string())
                .or_insert_with(PackageDownloadProgress::started);
            state.total_bytes = Some(state.total_bytes.unwrap_or(0) + total);
        }
        if let Some(bar) = &self.bar {
            bar.inc_length(total);
        }
        self.emit_downloading_for(package);
    }

    fn advance_download(&self, amount: u64) {
        self.advance_download_for(&self.package_name, amount);
    }

    fn begin_download_for(&self, package: &str) {
        let mut package_downloads = self.package_downloads.lock().unwrap();
        package_downloads
            .entry(package.to_string())
            .or_insert_with(PackageDownloadProgress::started);
        drop(package_downloads);
        self.emit_downloading_for(package);
    }

    fn advance_download_for(&self, package: &str, amount: u64) {
        if amount == 0 {
            return;
        }
        {
            let mut bytes_downloaded = self.bytes_downloaded.lock().unwrap();
            *bytes_downloaded += amount;
        }
        {
            let mut package_downloads = self.package_downloads.lock().unwrap();
            let state = package_downloads
                .entry(package.to_string())
                .or_insert_with(PackageDownloadProgress::started);
            state.bytes_downloaded += amount;
        }
        self.emit_downloading_for(package);
        if !self.enabled {
            return;
        }
        if let Some(bar) = &self.bar {
            bar.inc(amount);
        }
    }

    fn begin_install_phase(&self) {
        self.begin_install_phase_for(&self.package_name);
    }

    fn begin_install_phase_for(&self, package: &str) {
        let mut state = self.state.lock().unwrap();
        let already_installing = state.phase == InstallProgressPhase::Install;
        if !already_installing {
            state.phase = InstallProgressPhase::Install;
        }
        drop(state);
        if already_installing && package == self.package_name {
            return;
        }
        if let Some(bar) = &self.bar {
            bar.set_style(install_progress_style());
            bar.set_message("staging files".to_string());
        }
        self.emit(ProgressEvent::Installing {
            package: package.to_string(),
        });
    }

    fn log<S: AsRef<str>>(&self, message: S) {
        let message = sanitize_progress_message(message.as_ref());
        if message.is_empty() {
            return;
        }
        self.begin_install_phase();
        if let Some(bar) = &self.bar {
            bar.set_message(message.clone());
        }
        self.emit(ProgressEvent::Log {
            package: self.package_name.clone(),
            message,
        });
    }

    fn finish_with_paths(&self, paths: &[String]) {
        let message = format_installed_paths(paths);
        self.emit(ProgressEvent::Completed {
            package: self.package_name.clone(),
        });
        if let Some(bar) = &self.bar {
            bar.set_style(final_progress_style());
            bar.finish_with_message(message);
        } else {
            eprintln!("{message}");
        }
    }

    fn clear(&self) {
        if let Some(bar) = &self.bar {
            bar.finish_and_clear();
        }
    }

    fn emit_downloading_for(&self, package: &str) {
        if let Some(package_state) = self.package_downloads.lock().unwrap().get(package).copied() {
            let progress = package_state
                .total_bytes
                .filter(|total| *total > 0)
                .map(|total| package_state.bytes_downloaded as f32 / total as f32)
                .unwrap_or(0.0)
                .clamp(0.0, 1.0);
            let bytes_per_sec = package_state
                .started_at
                .map(|started| started.elapsed())
                .filter(|elapsed| elapsed.as_secs_f32() > 0.0)
                .map(|elapsed| {
                    (package_state.bytes_downloaded as f32 / elapsed.as_secs_f32()) as u64
                })
                .unwrap_or(0);
            self.emit(ProgressEvent::Downloading {
                package: package.to_string(),
                bytes_per_sec,
                progress,
            });
            return;
        }

        let bytes_downloaded = *self.bytes_downloaded.lock().unwrap();
        let total_bytes = *self.total_bytes.lock().unwrap();
        let started_at = *self.download_started_at.lock().unwrap();
        let progress = total_bytes
            .filter(|total| *total > 0)
            .map(|total| bytes_downloaded as f32 / total as f32)
            .unwrap_or(0.0)
            .clamp(0.0, 1.0);
        let bytes_per_sec = started_at
            .map(|started| started.elapsed())
            .filter(|elapsed| elapsed.as_secs_f32() > 0.0)
            .map(|elapsed| (bytes_downloaded as f32 / elapsed.as_secs_f32()) as u64)
            .unwrap_or(0);
        self.emit(ProgressEvent::Downloading {
            package: package.to_string(),
            bytes_per_sec,
            progress,
        });
    }

    fn emit(&self, event: ProgressEvent) {
        let Some(callback) = &self.callback else {
            return;
        };
        if let Ok(mut callback) = callback.lock() {
            callback(event);
        }
    }
}

fn download_progress_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "{spinner:.cyan} {prefix:.bold} [{bar:28.cyan/blue}] {percent:>3}% {bytes}/{total_bytes}",
    )
    .unwrap()
    .progress_chars("=> ")
}

fn install_progress_style() -> ProgressStyle {
    ProgressStyle::with_template("{spinner:.cyan} {prefix:.bold} {msg}").unwrap()
}

fn final_progress_style() -> ProgressStyle {
    ProgressStyle::with_template("{msg}").unwrap()
}

fn sanitize_progress_message(message: &str) -> String {
    message
        .split(['\n', '\r'])
        .map(str::trim)
        .rfind(|line| !line.is_empty())
        .map(|line| {
            line.chars()
                .filter(|ch| !ch.is_control())
                .collect::<String>()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

fn format_installed_paths(paths: &[String]) -> String {
    if paths.is_empty() {
        "installed".to_string()
    } else {
        paths.join("\n")
    }
}

fn run_i(invocation: &Invocation, mut args: env::ArgsOs) -> Result<(), String> {
    let request = match parse_i_request(invocation, &mut args)? {
        Some(request) => request,
        None => return Ok(()),
    };

    if install_requires_root() && !is_root() {
        return Err("must be run as root".to_string());
    }

    let _lock = acquire_package_mutation_lock()?;
    let config = load_config()?;
    for package in request.packages {
        run_i_package_with_progress(
            &config,
            package,
            InstallOptions {
                intent: if request.force {
                    InstallIntent::Reinstall
                } else {
                    InstallIntent::Install
                },
            },
            None,
        )?;
    }
    Ok(())
}

fn run_i_package(
    config: &Config,
    requested: RequestedPackage,
    options: InstallOptions,
) -> Result<(), String> {
    run_i_package_with_progress(config, requested, options, None)
}

fn run_i_package_with_progress(
    config: &Config,
    requested: RequestedPackage,
    options: InstallOptions,
    progress_callback: Option<Arc<Mutex<Box<ProgressCallback>>>>,
) -> Result<(), String> {
    let mut rollback_name = requested_package_name(&requested);
    let result = match requested {
        RequestedPackage::Auto(package_name) => {
            if let Some(isotope_name) = preferred_auto_isotope_name(&package_name)? {
                let package_name = isotope_qualified_name(&isotope_name);
                rollback_name = package_name.clone();
                if isotope_has_post_install(&package_name) {
                    run_i_radioisotope(
                        config,
                        package_name,
                        isotope_name,
                        options.intent,
                        progress_callback.clone(),
                    )
                } else {
                    prepare_install_target(
                        &opt_pkg_root(),
                        &package_name,
                        options.intent,
                        &managed_bin_root(),
                    )?;
                    run_i_isotope(
                        config,
                        package_name,
                        isotope_name,
                        true,
                        options.intent,
                        progress_callback.clone(),
                    )
                }
            } else if let Some(package) = vendor::get(&package_name) {
                prepare_install_target(
                    &opt_pkg_root(),
                    &package_name,
                    options.intent,
                    &managed_bin_root(),
                )?;
                run_i_vendor(
                    config,
                    package_name.clone(),
                    package,
                    options.intent,
                    progress_callback.clone(),
                )
            } else {
                match resolve_i_root_package(&package_name)? {
                    EmbeddedPackage::Formula(root_formula) => {
                        let install_package_name = formula_install_package_name(&root_formula)?;
                        rollback_name = install_package_name.clone();
                        prepare_install_target(
                            &opt_pkg_root(),
                            &install_package_name,
                            options.intent,
                            &managed_bin_root(),
                        )?;
                        run_i_formula(
                            config,
                            install_package_name,
                            root_formula,
                            options.intent,
                            progress_callback.clone(),
                        )
                    }
                    EmbeddedPackage::Cask(cask_name) => {
                        prepare_install_target(
                            &opt_pkg_root(),
                            &package_name,
                            options.intent,
                            &managed_bin_root(),
                        )?;
                        run_i_cask(
                            config,
                            package_name.clone(),
                            cask_name,
                            options.intent,
                            progress_callback.clone(),
                        )
                    }
                    EmbeddedPackage::NpmPackage(npm_package) => run_i_package_with_progress(
                        config,
                        RequestedPackage::NpmPackage {
                            package: npm_package,
                            version: None,
                        },
                        options,
                        progress_callback.clone(),
                    ),
                }
            }
        }
        RequestedPackage::VendorPackage(package_name) => {
            let package = vendor::get(&package_name)
                .ok_or_else(|| format!("vendor package {package_name} is not registered"))?;
            prepare_install_target(
                &opt_pkg_root(),
                &package_name,
                options.intent,
                &managed_bin_root(),
            )?;
            run_i_vendor(
                config,
                package_name.clone(),
                package,
                options.intent,
                progress_callback.clone(),
            )
        }
        RequestedPackage::HomebrewFormula(formula) => {
            let package_name = formula_install_package_name(&formula)?;
            rollback_name = package_name.clone();
            if let Some(isotope_name) = radioisotope_name_for_homebrew_formula_install(&formula)? {
                run_i_radioisotope(
                    config,
                    isotope_qualified_name(&isotope_name),
                    isotope_name,
                    options.intent,
                    progress_callback.clone(),
                )
            } else {
                prepare_install_target(
                    &opt_pkg_root(),
                    &package_name,
                    options.intent,
                    &managed_bin_root(),
                )?;
                run_i_formula(
                    config,
                    package_name,
                    formula,
                    options.intent,
                    progress_callback.clone(),
                )
            }
        }
        RequestedPackage::HomebrewCask(cask) => {
            prepare_install_target(&opt_pkg_root(), &cask, options.intent, &managed_bin_root())?;
            run_i_cask(
                config,
                cask.clone(),
                cask,
                options.intent,
                progress_callback.clone(),
            )
        }
        RequestedPackage::Isotope(isotope) => {
            let package_name = isotope_qualified_name(&isotope);
            if isotope_has_post_install(&package_name) {
                run_i_radioisotope(
                    config,
                    package_name,
                    isotope,
                    options.intent,
                    progress_callback.clone(),
                )
            } else {
                prepare_install_target(
                    &opt_pkg_root(),
                    &package_name,
                    options.intent,
                    &managed_bin_root(),
                )?;
                run_i_isotope(
                    config,
                    package_name,
                    isotope,
                    true,
                    options.intent,
                    progress_callback.clone(),
                )
            }
        }
        RequestedPackage::NpmPackage {
            package: npm_package,
            version,
        } => {
            let package_name = npm_package_display_name(&npm_package);
            prepare_install_target(
                &opt_pkg_root(),
                &package_name,
                options.intent,
                &managed_bin_root(),
            )?;
            run_i_npm(
                config,
                package_name.clone(),
                npm_package,
                version,
                options,
                options.intent,
                progress_callback.clone(),
            )
        }
        RequestedPackage::PipPackage(pip_package) => {
            let package_name = pip_package_display_name(&pip_package);
            prepare_install_target(
                &opt_pkg_root(),
                &package_name,
                options.intent,
                &managed_bin_root(),
            )?;
            run_i_pip(
                config,
                package_name.clone(),
                pip_package,
                options.intent,
                progress_callback.clone(),
            )
        }
    };
    if let Err(err) = result {
        if options.intent == InstallIntent::Update {
            return Err(err);
        }
        rollback_failed_install(&opt_pkg_root(), &rollback_name, &managed_bin_root())
            .map_err(|cleanup_err| format!("{err}\ncleanup failed: {cleanup_err}"))?;
        return Err(err);
    }
    Ok(())
}

fn run_i_formula(
    config: &Config,
    package_name: String,
    root_formula: String,
    intent: InstallIntent,
    progress_callback: Option<Arc<Mutex<Box<ProgressCallback>>>>,
) -> Result<(), String> {
    print_full_formula_recommendation(&root_formula)?;
    let progress = InstallProgress::with_callback(&package_name, progress_callback);
    let result = (|| {
        let graph = resolve_formula_specs(std::slice::from_ref(&root_formula), config, true)?;
        let root_formula = graph
            .last()
            .map(|spec| spec.name.clone())
            .ok_or_else(|| "no formula resolved".to_string())?;
        let plan = InstallPlan::for_i(package_name.clone(), root_formula);
        let previous_stubs = load_stub_manifest(&plan.package_manifest_path())?.stubs;
        let prepared = prepare_i_install_plan(&plan, intent)?;
        let staged_plan = prepared.plan;
        let staging_workspace = prepared.workspace;
        let install_result = (|| {
            let dependency_state = resolve_dependency_install_state(
                &graph,
                &staged_plan,
                &config.bottle_tag,
                &staged_plan.tmp_root,
                Some(&progress),
            )?;
            progress.begin_install_phase();
            let installs = &dependency_state.installs;
            let changed_installs = &dependency_state.changed_installs;
            let root_install = installs
                .iter()
                .find(|install| install.spec.name == plan.root_formula)
                .ok_or_else(|| {
                    format!(
                        "root formula {} not present in install graph",
                        plan.root_formula
                    )
                })?;

            ensure_plan_parent_dirs(&staged_plan)?;
            let rewrite_rules = build_rewrite_rules(&staged_plan, installs);
            install_package(
                config,
                &staged_plan,
                installs,
                changed_installs,
                &rewrite_rules,
                Some(&progress),
            )?;
            activate_install(&staged_plan)?;
            let metadata = formula_package_metadata(&plan.root_formula)?;
            write_package_receipt(
                &plan.root_receipt_path(),
                &PackageReceipt {
                    package_name: package_name.clone(),
                    version: root_install.keg_dir_name.clone(),
                    source: PackageReceiptSource::Formula {
                        root_formula: plan.root_formula.clone(),
                    },
                    metadata,
                },
            )?;
            sync_stubs(&plan, &graph, &previous_stubs)?;
            run_package_post_install(&plan, installs, &managed_bin_root())?;
            installed_stub_paths(&plan)
        })();
        if install_result.is_err() {
            preserve_optional_temp_dir_on_failure(staging_workspace);
        }
        install_result
    })();

    match result {
        Ok(paths) => {
            progress.finish_with_paths(&paths);
            Ok(())
        }
        Err(err) => {
            progress.clear();
            Err(err)
        }
    }
}

fn run_i_cask(
    config: &Config,
    package_name: String,
    cask_name: String,
    intent: InstallIntent,
    progress_callback: Option<Arc<Mutex<Box<ProgressCallback>>>>,
) -> Result<(), String> {
    let progress = InstallProgress::with_callback(&package_name, progress_callback);
    let result = (|| {
        let cask = embedded_cask(&cask_name)?;
        ensure_cask_install_metadata(&cask_name, &cask)?;
        let dependency_graph = resolve_formula_specs(&cask.dependencies, config, true)?;
        let plan = InstallPlan::for_i(package_name.clone(), cask_name.clone());
        let previous_stubs = load_stub_manifest(&plan.package_manifest_path())?.stubs;
        let prepared = prepare_i_install_plan(&plan, intent)?;
        let staged_plan = prepared.plan;
        let staging_workspace = prepared.workspace;
        let install_result = (|| {
            let dependency_state = resolve_dependency_install_state(
                &dependency_graph,
                &staged_plan,
                &config.bottle_tag,
                &staged_plan.tmp_root,
                Some(&progress),
            )?;
            ensure_plan_parent_dirs(&staged_plan)?;

            let dependency_current =
                dependencies_are_current(&staged_plan, &dependency_state.installs, &[], config)?;
            let mut dependencies_reinstalled = false;
            if !dependency_current {
                progress.begin_install_phase();
                install_dependency_formulas(
                    config,
                    &staged_plan,
                    &dependency_state.installs,
                    &dependency_state.changed_installs,
                    Some(&progress),
                )?;
                dependencies_reinstalled = true;
            }

            if !cask_root_is_current(
                &staged_plan,
                &cask,
                &dependency_state.installs,
                &config.bottle_tag,
            )? {
                if !dependencies_reinstalled {
                    if dependency_graph.is_empty() {
                        prepare_vendor_root_area(&staged_plan)?;
                    } else {
                        reinstall_vendor_dependency_tree(
                            config,
                            &staged_plan,
                            &dependency_state.installs,
                            &dependency_graph,
                            &[],
                            Some(&progress),
                        )?;
                    }
                }
                let root_payload_before = prepare_root_payload_install(&staged_plan)?;
                install_cask_root(&staged_plan, &cask_name, &cask, Some(&progress))?;
                finish_root_payload_install(&staged_plan, root_payload_before)?;
            }

            activate_install(&staged_plan)?;
            write_package_receipt(
                &plan.root_receipt_path(),
                &PackageReceipt {
                    package_name: package_name.clone(),
                    version: cask.version.clone(),
                    source: PackageReceiptSource::Cask {
                        cask_name: cask_name.clone(),
                    },
                    metadata: PackageMetadata {
                        description: string_or_none(&cask.summary),
                        homepage: string_or_none(&cask.homepage),
                    },
                },
            )?;
            sync_declared_stubs(
                &plan,
                &dependency_graph,
                cask_binary_names(&cask),
                &package_stub_exclusions(&plan.package_name),
                &previous_stubs,
            )?;
            installed_stub_paths(&plan)
        })();
        if install_result.is_err() {
            preserve_optional_temp_dir_on_failure(staging_workspace);
        }
        install_result
    })();

    match result {
        Ok(paths) => {
            progress.finish_with_paths(&paths);
            Ok(())
        }
        Err(err) => {
            progress.clear();
            Err(err)
        }
    }
}

fn run_i_isotope(
    config: &Config,
    package_name: String,
    isotope_name: String,
    install_stubs: bool,
    intent: InstallIntent,
    progress_callback: Option<Arc<Mutex<Box<ProgressCallback>>>>,
) -> Result<(), String> {
    let progress = InstallProgress::with_callback(&package_name, progress_callback);
    let result = (|| {
        let record = isotope_package_data(&isotope_name)?.clone();
        let dependency_graph = isotope_dependency_graph(&record, config)?;
        let plan = InstallPlan::for_i_isotope(package_name.clone(), &isotope_name);
        let previous_stubs = load_stub_manifest(&plan.package_manifest_path())?.stubs;
        let prepared = prepare_i_install_plan(&plan, intent)?;
        let staged_plan = prepared.plan;
        let staging_workspace = prepared.workspace;
        let install_result = (|| {
            let dependency_state = resolve_dependency_install_state(
                &dependency_graph,
                &staged_plan,
                &config.bottle_tag,
                &staged_plan.tmp_root,
                Some(&progress),
            )?;
            ensure_plan_parent_dirs(&staged_plan)?;
            let dependency_current =
                dependencies_are_current(&staged_plan, &dependency_state.installs, &[], config)?;
            let mut dependencies_reinstalled = false;
            if !dependency_current {
                progress.begin_install_phase();
                install_dependency_formulas(
                    config,
                    &staged_plan,
                    &dependency_state.installs,
                    &dependency_state.changed_installs,
                    Some(&progress),
                )?;
                dependencies_reinstalled = true;
            }

            if !isotope_root_is_current(&staged_plan, &record)? {
                if !dependencies_reinstalled && dependency_graph.is_empty() {
                    prepare_vendor_root_area(&staged_plan)?;
                }
                let root_payload_before = prepare_root_payload_install(&staged_plan)?;
                install_isotope_root(
                    &staged_plan,
                    &record,
                    &dependency_state.installs,
                    Some(&progress),
                )?;
                finish_root_payload_install(&staged_plan, root_payload_before)?;
            }
            let executables = collect_root_executables(&staged_plan.install_root)?;
            let stub_executables = isotope_stub_executables(&record, &executables)?;
            write_root_executable_manifest(
                &staged_plan.root_executables_manifest_path(),
                &stub_executables,
            )?;
            activate_install(&staged_plan)?;
            write_package_receipt(
                &plan.root_receipt_path(),
                &PackageReceipt {
                    package_name: package_name.clone(),
                    version: record.version.clone(),
                    source: PackageReceiptSource::Isotope {
                        isotope_name: isotope_name.clone(),
                    },
                    metadata: PackageMetadata {
                        description: record
                            .replaces
                            .as_deref()
                            .map(|replaces| format!("Isotope mirror replacing {replaces}")),
                        homepage: record.release_url.clone(),
                    },
                },
            )?;
            if install_stubs {
                sync_declared_stubs(
                    &plan,
                    &dependency_graph,
                    stub_executables.iter().map(String::as_str),
                    &isotope_stub_exclusions(&plan.package_name, &record),
                    &previous_stubs,
                )?;
            }
            installed_stub_paths(&plan)
        })();
        if install_result.is_err() {
            preserve_optional_temp_dir_on_failure(staging_workspace);
        }
        install_result
    })();

    match result {
        Ok(paths) => {
            progress.finish_with_paths(&paths);
            Ok(())
        }
        Err(err) => {
            progress.clear();
            Err(err)
        }
    }
}

fn run_i_isotope_root_only(
    config: &Config,
    package_name: String,
    isotope_name: String,
    progress_callback: Option<Arc<Mutex<Box<ProgressCallback>>>>,
) -> Result<(), String> {
    run_i_isotope(
        config,
        package_name,
        isotope_name,
        false,
        InstallIntent::Install,
        progress_callback,
    )
}

fn run_i_radioisotope(
    config: &Config,
    package_name: String,
    isotope_name: String,
    intent: InstallIntent,
    progress_callback: Option<Arc<Mutex<Box<ProgressCallback>>>>,
) -> Result<(), String> {
    let progress = InstallProgress::with_callback(&package_name, progress_callback.clone());
    let result = (|| {
        let record = isotope_package_data(&isotope_name)?.clone();
        if !isotope_has_post_install(&record.name) {
            return Err(format!("isotope:{} is not a radioisotope", isotope_name));
        }
        let modified_target = isotope_modified_package_target(&record)?
            .ok_or_else(|| format!("radioisotope:{} does not declare modifies", isotope_name))?;
        let modified_package = radioisotope_modified_install_name(&modified_target)?;
        let plan = InstallPlan::for_i_radioisotope(package_name.clone(), modified_package.clone());

        match radioisotope_modified_formula_intent(intent) {
            Some(InstallIntent::Reinstall) => {
                prepare_install_target(
                    &opt_pkg_root(),
                    &modified_package,
                    InstallIntent::Reinstall,
                    &managed_bin_root(),
                )?;
                run_i_modified_package(
                    config,
                    modified_package.clone(),
                    &modified_target,
                    InstallIntent::Reinstall,
                    progress_callback.clone(),
                )?;
            }
            Some(InstallIntent::Update) => {
                run_i_modified_package(
                    config,
                    modified_package.clone(),
                    &modified_target,
                    InstallIntent::Update,
                    progress_callback.clone(),
                )?;
            }
            Some(InstallIntent::Install) => unreachable!("install intent is handled as None"),
            None => {
                let modified_root = package_install_root(&opt_pkg_root(), &modified_package)?;
                if !modified_root.exists() {
                    prepare_install_target(
                        &opt_pkg_root(),
                        &modified_package,
                        InstallIntent::Install,
                        &managed_bin_root(),
                    )?;
                    run_i_modified_package(
                        config,
                        modified_package.clone(),
                        &modified_target,
                        InstallIntent::Install,
                        progress_callback.clone(),
                    )?;
                }
                ensure_package_installed(&opt_pkg_root(), &modified_package)?;
            }
        }

        let previous_stubs = load_stub_manifest(&plan.package_manifest_path())?.stubs;
        let formula_receipt = load_package_receipt(&plan.root_receipt_path())?
            .ok_or_else(|| format!("missing receipt for modified package {modified_package}"))?;
        progress.log("converting Homebrew install to isotope");
        match run_generated_isotope_post_install(&record.name) {
            Some(result) => result?,
            None => return Err(format!("isotope:{} has no post-install step", isotope_name)),
        }
        write_package_receipt(
            &plan.root_receipt_path(),
            &PackageReceipt {
                package_name: package_name.clone(),
                version: formula_receipt.version,
                source: PackageReceiptSource::Isotope {
                    isotope_name: isotope_name.clone(),
                },
                metadata: PackageMetadata {
                    description: record
                        .modifies
                        .as_deref()
                        .map(|modifies| format!("Radioisotope modifying {modifies}")),
                    homepage: record.release_url.clone(),
                },
            },
        )?;
        sync_stubs(&plan, &[], &previous_stubs)?;
        installed_stub_paths(&plan)
    })();

    match result {
        Ok(paths) => {
            progress.finish_with_paths(&paths);
            Ok(())
        }
        Err(err) => {
            progress.clear();
            Err(err)
        }
    }
}

fn run_i_modified_package(
    config: &Config,
    package_name: String,
    target: &PackageAliasTarget,
    intent: InstallIntent,
    progress_callback: Option<Arc<Mutex<Box<ProgressCallback>>>>,
) -> Result<(), String> {
    match target {
        PackageAliasTarget::HomebrewFormula(formula) => run_i_formula(
            config,
            package_name,
            formula.clone(),
            intent,
            progress_callback,
        ),
        PackageAliasTarget::VendorPackage(vendor_name) => {
            let package = vendor::get(vendor_name)
                .ok_or_else(|| format!("vendor package {vendor_name} is not registered"))?;
            run_i_vendor(config, package_name, package, intent, progress_callback)
        }
        _ => Err(format!(
            "invalid isotope modification {}: radioisotopes may only modify Homebrew formulae or vendor packages",
            target.display_name()
        )),
    }
}

fn radioisotope_modified_formula_intent(intent: InstallIntent) -> Option<InstallIntent> {
    match intent {
        InstallIntent::Install => None,
        InstallIntent::Reinstall => Some(InstallIntent::Reinstall),
        InstallIntent::Update => Some(InstallIntent::Update),
    }
}

fn install_isotope_stubs(
    isotope_name: &str,
    progress_callback: Option<Arc<Mutex<Box<ProgressCallback>>>>,
) -> Result<Vec<String>, String> {
    let package_name = isotope_qualified_name(isotope_name);
    let progress = InstallProgress::with_callback(&package_name, progress_callback);
    let record = isotope_package_data(isotope_name)?.clone();
    let plan = InstallPlan::for_i_isotope(package_name, isotope_name);
    if let Some(replaced_package) = isotope_replaced_package_name(&record)?
        && package_install_root(&opt_pkg_root(), &replaced_package)?.exists()
    {
        return Err(format!(
            "cannot install isotope stubs while replacement package is installed: \
                 {replaced_package}"
        ));
    }
    let previous_stubs = load_stub_manifest(&plan.package_manifest_path())?.stubs;
    let executables_manifest =
        load_root_executable_manifest(&plan.root_executables_manifest_path())?;
    let executables = collect_declared_root_executables(
        &plan.install_root,
        executables_manifest.stubs.iter().map(String::as_str),
    )?;
    progress.log("installing isotope stubs");
    sync_declared_stubs(
        &plan,
        &[],
        executables.iter().map(|(name, _)| name.as_str()),
        &isotope_stub_exclusions(&plan.package_name, &record),
        &previous_stubs,
    )?;
    installed_stub_paths(&plan)
}

fn isotope_stub_executables(
    isotope: &IsotopePackageData,
    discovered: &[(String, PathBuf)],
) -> Result<Vec<String>, String> {
    if let Some(formula) = isotope_modified_or_replaced_package_name(isotope)? {
        let executables = predicted_homebrew_executables(&formula)?;
        if !executables.is_empty() {
            return Ok(executables);
        }
    }

    Ok(discovered.iter().map(|(name, _)| name.clone()).collect())
}

fn isotope_stub_exclusions(package_name: &str, isotope: &IsotopePackageData) -> HashSet<String> {
    let mut exclusions = package_stub_exclusions(package_name);
    if let Ok(Some(formula)) = isotope_modified_or_replaced_package_name(isotope) {
        exclusions.extend(formula_stub_exclusions(&formula));
    }
    exclusions
}

fn embedded_post_install_check_skip() -> &'static HashSet<String> {
    POST_INSTALL_CHECK_SKIP.get_or_init(|| {
        json5::from_str::<Vec<String>>(EMBEDDED_POST_INSTALL_CHECK_SKIP)
            .expect("failed to parse embedded post-install check skip list JSONC")
            .into_iter()
            .collect()
    })
}

fn embedded_stub_exclusions() -> &'static HashMap<String, HashSet<String>> {
    STUB_EXCLUSIONS.get_or_init(|| {
        embedded_combined_data()
            .sources
            .stub_exclusions
            .clone()
            .into_iter()
            .map(|(package, executables)| (package, executables.into_iter().collect()))
            .collect()
    })
}

fn formula_stub_exclusions(formula: &str) -> HashSet<String> {
    let mut exclusions = embedded_stub_exclusions()
        .get(&format!("{BREW_PACKAGE_PREFIX}{formula}"))
        .cloned()
        .unwrap_or_default();
    exclusions.extend(versioned_python_stub_exclusions(formula));
    exclusions
}

fn vendor_stub_exclusions(package: &vendor::VendorPackage) -> HashSet<String> {
    embedded_stub_exclusions()
        .get(&format!("vendor:{}", package.name))
        .cloned()
        .unwrap_or_default()
}

fn package_stub_exclusions(package_name: &str) -> HashSet<String> {
    embedded_stub_exclusions()
        .get(package_name)
        .cloned()
        .unwrap_or_default()
}

fn imagemagick_stub_exclusions(
    plan: &InstallPlan,
    current: &[(String, PathBuf)],
) -> HashSet<String> {
    if !should_only_stub_magick(plan) {
        return HashSet::new();
    }

    current
        .iter()
        .filter_map(|(name, _)| (name != "magick").then_some(name.clone()))
        .collect()
}

fn should_only_stub_magick(plan: &InstallPlan) -> bool {
    match plan.root_formula.as_str() {
        "imagemagick-full" => true,
        "imagemagick" => installed_formula_major_version(plan).is_some_and(|major| major >= 7),
        _ => false,
    }
}

fn installed_formula_major_version(plan: &InstallPlan) -> Option<u64> {
    let receipt = load_package_receipt(&plan.root_receipt_path())
        .ok()
        .flatten()?;
    let PackageReceiptSource::Formula { root_formula } = receipt.source else {
        return None;
    };
    if root_formula != plan.root_formula {
        return None;
    }
    parse_homebrew_major_version(&receipt.version)
}

fn parse_homebrew_major_version(version: &str) -> Option<u64> {
    let trimmed = version.strip_prefix('v').unwrap_or(version);
    trimmed
        .split(|ch: char| !ch.is_ascii_digit())
        .find(|part| !part.is_empty())
        .and_then(|major| major.parse().ok())
}

fn versioned_python_stub_exclusions(formula: &str) -> HashSet<String> {
    let Some((major, minor)) = parse_python_formula_version(formula) else {
        return HashSet::new();
    };

    [
        "2to3".to_string(),
        format!("2to3-{major}.{minor}"),
        format!("idle{major}"),
        format!("idle{major}.{minor}"),
        format!("pydoc{major}"),
        format!("pydoc{major}.{minor}"),
        "wheel".to_string(),
        format!("wheel{major}"),
        format!("wheel{major}.{minor}"),
        format!("python{major}-config"),
        format!("python{major}.{minor}-config"),
    ]
    .into_iter()
    .collect()
}

fn parse_python_formula_version(formula: &str) -> Option<(u64, u64)> {
    let version = formula.strip_prefix("python@")?;
    let (major, minor) = version.split_once('.')?;
    if minor.contains('.') {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

fn embedded_npm_package_data() -> &'static HashMap<String, PackageInstallData> {
    NPM_PACKAGE_DATA.get_or_init(|| embedded_combined_data().sources.npm.clone())
}

fn npm_package_homebrew_dependencies(package: &str) -> Vec<String> {
    let data = embedded_npm_package_data();
    if let Some(entry) = data.get(package) {
        return entry.homebrew_dependencies.clone();
    }
    if let Some((_, leaf_name)) = package.rsplit_once('/')
        && let Some(entry) = data.get(leaf_name)
    {
        return entry.homebrew_dependencies.clone();
    }
    Vec::new()
}

fn append_npm_package_homebrew_dependencies(formula_names: &mut Vec<String>, package: &str) {
    for dependency in npm_package_homebrew_dependencies(package) {
        push_unique_string(formula_names, dependency);
    }
}

fn embedded_pip_package_data() -> &'static HashMap<String, PackageInstallData> {
    PIP_PACKAGE_DATA.get_or_init(|| embedded_combined_data().sources.pip.clone())
}

fn embedded_isotope_data() -> &'static HashMap<String, IsotopePackageData> {
    ISOTOPE_DATA.get_or_init(|| {
        embedded_combined_data()
            .sources
            .isotopes
            .clone()
            .into_values()
            .map(|record| (record.name.clone(), record))
            .collect()
    })
}

fn embedded_security_recommendations() -> &'static SecurityRecommendationsData {
    SECURITY_RECOMMENDATIONS.get_or_init(|| {
        embedded_combined_data()
            .sources
            .security_recommendations
            .clone()
    })
}

fn isotope_package_data(name: &str) -> Result<&'static IsotopePackageData, String> {
    let name = isotope_unqualified_name(name);
    if let Some(record) = embedded_isotope_data().get(&isotope_qualified_name(name)) {
        return Ok(record);
    }
    if let Some(record) = virtual_versioned_isotope_package_data(name) {
        return Ok(record);
    }
    Err(format!("unknown isotope {ISOTOPE_PACKAGE_PREFIX}{name}"))
}

fn virtual_versioned_isotope_package_data(name: &str) -> Option<&'static IsotopePackageData> {
    let base = versioned_isotope_base(name)?;
    let cache = VIRTUAL_ISOTOPE_DATA.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(record) = cache.lock().unwrap().get(name).copied() {
        return Some(record);
    }

    let base_record = embedded_isotope_data()
        .get(&isotope_qualified_name(base))?
        .clone();
    let mut record = base_record;
    record.name = isotope_qualified_name(name);
    record.modifies = Some(format!("brew:{name}"));
    record.replaces = None;
    record.release_url = Some(format!("https://formulae.brew.sh/formula/{name}"));
    record.applies_to_versioned_formulae = false;

    let record: &'static IsotopePackageData = Box::leak(Box::new(record));
    let mut cache = cache.lock().unwrap();
    Some(*cache.entry(name.to_string()).or_insert(record))
}

fn versioned_isotope_base(name: &str) -> Option<&str> {
    let name = isotope_unqualified_name(name);
    let base = formula_versioned_base(name)?;
    let version = name.rsplit_once('@')?.1;
    if version.is_empty() || !version.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }

    let record = embedded_isotope_data().get(&isotope_qualified_name(base))?;
    if !record.applies_to_versioned_formulae {
        return None;
    }
    let modified_formula = record.modifies.as_deref()?.strip_prefix("brew:")?;
    (modified_formula == base).then_some(base)
}

fn preferred_auto_isotope_name(package_name: &str) -> Result<Option<String>, String> {
    let target = if vendor::get(package_name).is_some() {
        Some(PackageAliasTarget::VendorPackage(package_name.to_string()))
    } else {
        preferred_auto_homebrew_formula_target(package_name)?
    };

    let Some(target) = target else {
        return Ok(None);
    };
    installable_isotope_name_for_target(&target)
}

fn radioisotope_name_for_homebrew_formula_install(formula: &str) -> Result<Option<String>, String> {
    let formula = formula_install_package_name(formula)?;
    let target = PackageAliasTarget::HomebrewFormula(formula);
    Ok(installable_isotope_name_for_target(&target)?
        .filter(|isotope_name| isotope_has_post_install(&isotope_qualified_name(isotope_name))))
}

fn preferred_auto_homebrew_formula_target(
    package_name: &str,
) -> Result<Option<PackageAliasTarget>, String> {
    let db = crate::cli::load_db()?;
    crate::cli::ensure_db_schema(&db)?;
    if let Some(provider) = db.entries.get(package_name) {
        return Ok(match crate::cli::parse_embedded_provider(provider)? {
            Some(EmbeddedPackage::Formula(formula)) => Some(PackageAliasTarget::HomebrewFormula(
                formula_install_package_name(&formula)?,
            )),
            Some(EmbeddedPackage::Cask(_) | EmbeddedPackage::NpmPackage(_)) => None,
            None => Some(PackageAliasTarget::HomebrewFormula(
                formula_install_package_name(package_name)?,
            )),
        });
    }

    Ok(Some(PackageAliasTarget::HomebrewFormula(
        formula_install_package_name(package_name)?,
    )))
}

fn installable_isotope_name_for_target(
    target: &PackageAliasTarget,
) -> Result<Option<String>, String> {
    let mut isotopes = embedded_isotope_data().values().collect::<Vec<_>>();
    isotopes.sort_by(|left, right| left.name.cmp(&right.name));

    for isotope in isotopes {
        if !isotope_is_installable(isotope) {
            continue;
        }
        if let Ok(true) = isotope_targets_package(isotope, target) {
            return Ok(Some(isotope_unqualified_name(&isotope.name).to_string()));
        }
    }

    if let PackageAliasTarget::HomebrewFormula(formula) = target
        && versioned_isotope_base(formula).is_some()
        && let Ok(record) = isotope_package_data(formula)
        && isotope_is_installable(record)
    {
        return Ok(Some(formula.clone()));
    }

    Ok(None)
}

fn isotope_is_installable(record: &IsotopePackageData) -> bool {
    record
        .archive_url
        .as_deref()
        .is_some_and(|url| !url.trim().is_empty())
        || isotope_has_post_install(&record.name)
}

fn isotope_targets_package(
    record: &IsotopePackageData,
    target: &PackageAliasTarget,
) -> Result<bool, String> {
    if isotope_replaced_package_target(record)?.as_ref() == Some(target) {
        return Ok(true);
    }
    if isotope_modified_package_target(record)?.as_ref() == Some(target) {
        return Ok(true);
    }
    Ok(false)
}

fn isotope_qualified_name(name: &str) -> String {
    format!("{ISOTOPE_PACKAGE_PREFIX}{name}")
}

fn isotope_unqualified_name(name: &str) -> &str {
    name.strip_prefix(ISOTOPE_PACKAGE_PREFIX).unwrap_or(name)
}

fn exact_isotope_integration(
    name: &str,
) -> Option<&'static isotope_integrations::IsotopeIntegration> {
    let name = isotope_unqualified_name(name);
    isotope_integrations::INTEGRATIONS
        .iter()
        .find(|integration| integration.name == name)
}

fn isotope_integration(name: &str) -> Option<&'static isotope_integrations::IsotopeIntegration> {
    exact_isotope_integration(name)
        .or_else(|| versioned_isotope_base(name).and_then(exact_isotope_integration))
}

fn isotope_has_migration(name: &str) -> bool {
    isotope_integration(name).is_some_and(|integration| integration.has_migration)
}

fn isotope_has_post_install(name: &str) -> bool {
    isotope_integration(name).is_some_and(|integration| integration.has_install_remediation)
}

fn isotope_has_remediation(name: &str) -> bool {
    isotope_package_data(isotope_unqualified_name(name))
        .is_ok_and(|record| record.migrate.is_some())
        || isotope_integration(name).is_some_and(|integration| {
            integration.has_migration || integration.has_install_remediation
        })
}

fn run_generated_isotope_migration(name: &str) -> Option<Result<(), String>> {
    let migrate = isotope_integration(name)?.migrate?;
    Some(migrate())
}

fn run_generated_isotope_post_install(name: &str) -> Option<Result<(), String>> {
    if let Some(integration) = exact_isotope_integration(name)
        && let Some(post_install) = integration.post_install
    {
        return Some(post_install());
    }
    let formula = isotope_unqualified_name(name);
    let base = versioned_isotope_base(formula)?;
    let post_install = exact_isotope_integration(base)?.post_install_for_formula?;
    Some(post_install(formula))
}

fn detect_isotope_install_reasons(name: &str) -> Option<Result<Vec<String>, String>> {
    let integration = isotope_integration(name)?;
    if !integration.has_detect {
        return None;
    }
    if let Some(detect_reasons) = integration.detect_reasons {
        return Some(detect_reasons());
    }
    let detect = integration.detect?;
    Some(detect().map(|install_is_insecure| {
        if install_is_insecure {
            vec![format!("isotope:{name} detector triggered")]
        } else {
            Vec::new()
        }
    }))
}

fn package_security_state(info: &PackageInfo) -> Option<PackageSecurityState> {
    let mut identifiers = vec![info.package_name.clone(), info.qualified_name.clone()];
    if let Some(source) = info.source.as_ref() {
        identifiers.push(package_source_qualified_name(source));
    }
    identifiers.extend(info.aliases.iter().cloned());
    package_security_state_for_identifiers(identifiers)
}

fn package_security_state_for_identifiers<I>(identifiers: I) -> Option<PackageSecurityState>
where
    I: IntoIterator<Item = String>,
{
    let mut identifiers = identifiers
        .into_iter()
        .map(|identifier| identifier.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    identifiers.extend(
        identifiers
            .iter()
            .filter_map(|identifier| {
                identifier
                    .split_once(':')
                    .map(|(_, suffix)| suffix)
                    .filter(|suffix| !suffix.is_empty())
                    .map(str::to_string)
            })
            .collect::<Vec<_>>(),
    );
    let versioned_identifiers = identifiers
        .iter()
        .filter(|identifier| formula_versioned_base(identifier).is_some())
        .cloned()
        .collect::<Vec<_>>();
    for identifier in &versioned_identifiers {
        if embedded_isotope_data().contains_key(&isotope_qualified_name(identifier))
            && let Some(state) = package_security_state_for_isotope(identifier)
        {
            return Some(state);
        }
    }
    for identifier in &versioned_identifiers {
        if versioned_isotope_base(identifier).is_some()
            && let Some(state) = package_security_state_for_isotope(identifier)
        {
            return Some(state);
        }
    }

    let mut isotopes = embedded_isotope_data().values().collect::<Vec<_>>();
    isotopes.sort_by(|left, right| left.name.cmp(&right.name));

    for isotope in isotopes {
        let isotope_name = isotope_unqualified_name(&isotope.name).to_string();
        if identifiers.contains(&isotope.name.to_ascii_lowercase())
            || identifiers.contains(&isotope_name.to_ascii_lowercase())
        {
            return package_security_state_for_isotope(&isotope_name);
        }

        let Ok(Some(replaces)) = isotope_modified_or_replaced_package_name(isotope) else {
            continue;
        };
        if !identifiers.contains(&replaces.to_ascii_lowercase()) {
            continue;
        }

        return package_security_state_for_isotope(&isotope_name);
    }

    let mut integrations = isotope_integrations::INTEGRATIONS
        .iter()
        .collect::<Vec<_>>();
    integrations.sort_by(|left, right| left.name.cmp(right.name));
    for integration in integrations {
        let isotope_name = integration.name.to_ascii_lowercase();
        if identifiers.contains(&isotope_name)
            || identifiers.contains(&format!("{ISOTOPE_PACKAGE_PREFIX}{isotope_name}"))
            || identifiers.contains(&format!("{BREW_PACKAGE_PREFIX}{isotope_name}"))
        {
            return package_security_state_for_isotope(integration.name);
        }
    }

    None
}

fn package_security_state_for_isotope(isotope_name: &str) -> Option<PackageSecurityState> {
    let result = detect_isotope_install_reasons(isotope_name)?;
    let remediation_available = isotope_has_remediation(isotope_name);
    Some(match result {
        Ok(reasons) => PackageSecurityState {
            isotope_name: isotope_name.to_string(),
            install_is_insecure: !reasons.is_empty(),
            remediation_available,
            reasons,
            error: None,
        },
        Err(err) => PackageSecurityState {
            isotope_name: isotope_name.to_string(),
            install_is_insecure: false,
            remediation_available,
            reasons: Vec::new(),
            error: Some(err),
        },
    })
}

fn run_secret_scan(request: &SecretScannerRequest) -> Result<SecretScannerReport, String> {
    run_secret_scan_with_events(request, |_| Ok(()))
}

fn run_secret_scan_with_events<F>(
    request: &SecretScannerRequest,
    mut on_event: F,
) -> Result<SecretScannerReport, String>
where
    F: for<'a> FnMut(SecretScannerEvent<'a>) -> Result<(), String>,
{
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let mut seen_findings = HashSet::new();
    let mut seen_errors = HashSet::new();
    let mut isotope_detectors = 0;

    if secret_scan_should_run_isotope_detectors(request) {
        for integration in isotope_integrations::INTEGRATIONS {
            let detector = integration
                .detect_reasons
                .map(|detect_reasons| detect_reasons())
                .or_else(|| {
                    integration.detect.map(|detect| {
                        detect().map(|install_is_insecure| {
                            if install_is_insecure {
                                vec![format!(
                                    "isotope:{} detector found plaintext credential exposure",
                                    integration.name
                                )]
                            } else {
                                Vec::new()
                            }
                        })
                    })
                });

            let Some(result) = detector else {
                continue;
            };
            isotope_detectors += 1;

            match result {
                Ok(reasons) => {
                    for reason in reasons {
                        record_secret_scanner_finding(
                            &mut findings,
                            &mut seen_findings,
                            SecretScannerFinding {
                                source: format!("isotope:{}", integration.name),
                                kind: "detector".to_string(),
                                severity: "high".to_string(),
                                path: None,
                                line: None,
                                message: reason,
                            },
                            &mut on_event,
                        )?;
                    }
                }
                Err(err) => record_secret_scanner_error(
                    &mut errors,
                    &mut seen_errors,
                    SecretScannerError {
                        source: format!("isotope:{}", integration.name),
                        path: None,
                        message: err,
                    },
                    &mut on_event,
                )?,
            }
        }
    }

    let mut scanned_files = 0;
    let mut file_probes = 0;
    if !request.isotopes_only {
        (scanned_files, file_probes) = scan_secret_file_probes(
            request.path.as_deref(),
            &request.skip_paths,
            &mut findings,
            &mut errors,
            &mut seen_findings,
            &mut seen_errors,
            &mut on_event,
        )?;
    }

    findings.sort_by(|left, right| {
        left.source
            .cmp(&right.source)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.line.cmp(&right.line))
            .then_with(|| left.message.cmp(&right.message))
    });
    findings.dedup();
    errors.sort_by(|left, right| {
        left.source
            .cmp(&right.source)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.message.cmp(&right.message))
    });
    errors.dedup();

    Ok(SecretScannerReport {
        scope: if request.isotopes_only {
            SecretScannerScope::IsotopesOnly
        } else {
            SecretScannerScope::Full
        },
        summary: SecretScannerSummary {
            scanned_files,
            findings: findings.len(),
            errors: errors.len(),
            isotope_detectors,
            file_probes,
        },
        findings,
        errors,
    })
}

fn secret_scan_should_run_isotope_detectors(request: &SecretScannerRequest) -> bool {
    request.path.is_none()
}

fn record_secret_scanner_finding<F>(
    findings: &mut Vec<SecretScannerFinding>,
    seen_findings: &mut HashSet<SecretScannerFinding>,
    finding: SecretScannerFinding,
    on_event: &mut F,
) -> Result<(), String>
where
    F: for<'a> FnMut(SecretScannerEvent<'a>) -> Result<(), String>,
{
    if seen_findings.insert(finding.clone()) {
        on_event(SecretScannerEvent::Finding(&finding))?;
        findings.push(finding);
    }
    Ok(())
}

fn record_secret_scanner_error<F>(
    errors: &mut Vec<SecretScannerError>,
    seen_errors: &mut HashSet<SecretScannerError>,
    error: SecretScannerError,
    on_event: &mut F,
) -> Result<(), String>
where
    F: for<'a> FnMut(SecretScannerEvent<'a>) -> Result<(), String>,
{
    if seen_errors.insert(error.clone()) {
        on_event(SecretScannerEvent::Error(&error))?;
        errors.push(error);
    }
    Ok(())
}

fn print_secret_scanner_report_streaming(request: &SecretScannerRequest) -> Result<(), String> {
    let mut printer = SecretScannerStreamPrinter::new(request);
    printer.begin()?;
    let report = run_secret_scan_with_events(request, |event| printer.print_event(event))?;
    printer.finish(&report)?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum SecretScannerStreamFormat {
    Plain,
    Rich,
    Wrapped,
}

struct SecretScannerStreamPrinter {
    format: SecretScannerStreamFormat,
    color: bool,
    scope: SecretScannerScope,
    finding_count: usize,
    printed_findings_header: bool,
    printed_warnings_header: bool,
}

impl SecretScannerStreamPrinter {
    fn new(request: &SecretScannerRequest) -> Self {
        let stdout_is_rich = scan_stdout_is_rich();
        let format = if scanner_wrapper_ui_enabled() && stdout_is_rich {
            SecretScannerStreamFormat::Wrapped
        } else if stdout_is_rich {
            SecretScannerStreamFormat::Rich
        } else {
            SecretScannerStreamFormat::Plain
        };
        Self {
            format,
            color: !matches!(format, SecretScannerStreamFormat::Plain)
                && scan_stdout_supports_ansi(),
            scope: if request.isotopes_only {
                SecretScannerScope::IsotopesOnly
            } else {
                SecretScannerScope::Full
            },
            finding_count: 0,
            printed_findings_header: false,
            printed_warnings_header: false,
        }
    }

    fn begin(&mut self) -> Result<(), String> {
        match self.format {
            SecretScannerStreamFormat::Plain => {
                println!("Automic Vault scan");
                println!("Scope: {}", secret_scanner_scope_label(self.scope));
            }
            SecretScannerStreamFormat::Rich => {
                let status = scan_paint(">", ScanStyle::Heading, self.color);
                let scope = format!(
                    "{}: {}",
                    scan_paint("Scope", ScanStyle::Dim, self.color),
                    secret_scanner_scope_label(self.scope)
                );
                print_scan_box(
                    "Automic Vault Scan",
                    &[
                        format!("{status} Scanning plaintext credential exposure"),
                        scope,
                    ],
                    self.color,
                );
            }
            SecretScannerStreamFormat::Wrapped => {
                let rail = scan_rail(ScanStyle::Dim, self.color);
                println!("{rail}");
                let rail = scan_rail(ScanStyle::Heading, self.color);
                println!(
                    "{rail} {} Scanning plaintext credential exposure",
                    scan_paint(">", ScanStyle::Heading, self.color)
                );
                let rail = scan_rail(ScanStyle::Dim, self.color);
                println!(
                    "{rail}   {}     {}",
                    scan_paint("Scope", ScanStyle::Dim, self.color),
                    secret_scanner_scope_label(self.scope)
                );
            }
        }
        flush_secret_scanner_stdout()
    }

    fn print_event(&mut self, event: SecretScannerEvent<'_>) -> Result<(), String> {
        match event {
            SecretScannerEvent::Finding(finding) => self.print_finding(finding),
            SecretScannerEvent::Error(error) => self.print_error(error),
        }
    }

    fn print_finding(&mut self, finding: &SecretScannerFinding) -> Result<(), String> {
        self.finding_count += 1;
        match self.format {
            SecretScannerStreamFormat::Plain => {
                if !self.printed_findings_header {
                    println!();
                    println!("Findings:");
                    self.printed_findings_header = true;
                }
                println!(
                    "{}. {} {} - {}",
                    self.finding_count, finding.severity, finding.source, finding.message
                );
                if let Some(location) = secret_scanner_finding_location(finding) {
                    println!("   {location}");
                }
            }
            SecretScannerStreamFormat::Rich => {
                if !self.printed_findings_header {
                    println!();
                    println!("{}", scan_paint("Findings", ScanStyle::Heading, self.color));
                    self.printed_findings_header = true;
                }
                let severity =
                    scan_paint(&finding.severity, scan_severity_style(finding), self.color);
                println!(
                    "  {}. {} {}",
                    self.finding_count,
                    severity,
                    scan_paint(&finding.source, ScanStyle::Dim, self.color)
                );
                if let Some(location) = secret_scanner_finding_location(finding) {
                    println!(
                        "     {}",
                        scan_paint(&location, ScanStyle::Path, self.color)
                    );
                }
                println!("     {}", finding.message);
            }
            SecretScannerStreamFormat::Wrapped => {
                if !self.printed_findings_header {
                    let rail = scan_rail(ScanStyle::Dim, self.color);
                    println!("{rail}");
                    let rail = scan_rail(ScanStyle::Heading, self.color);
                    println!(
                        "{rail} {}",
                        scan_paint("Findings", ScanStyle::Heading, self.color)
                    );
                    self.printed_findings_header = true;
                }
                let severity =
                    scan_paint(&finding.severity, scan_severity_style(finding), self.color);
                let rail = scan_rail(scan_severity_style(finding), self.color);
                println!(
                    "{rail}   {}. {} {}",
                    self.finding_count,
                    severity,
                    scan_paint(&finding.source, ScanStyle::Dim, self.color)
                );
                if let Some(location) = secret_scanner_finding_location(finding) {
                    let rail = scan_rail(ScanStyle::Path, self.color);
                    println!(
                        "{rail}      {}",
                        scan_paint(&location, ScanStyle::Path, self.color)
                    );
                }
                let rail = scan_rail(ScanStyle::Dim, self.color);
                println!("{rail}      {}", finding.message);
            }
        }
        flush_secret_scanner_stdout()
    }

    fn print_error(&mut self, error: &SecretScannerError) -> Result<(), String> {
        match self.format {
            SecretScannerStreamFormat::Plain => {
                if !self.printed_warnings_header {
                    eprintln!();
                    eprintln!("Warnings");
                    self.printed_warnings_header = true;
                }
                print_secret_scanner_warning_line(error, false);
                flush_secret_scanner_stderr()
            }
            SecretScannerStreamFormat::Rich => {
                if !self.printed_warnings_header {
                    eprintln!();
                    eprintln!("{}", scan_paint("Warnings", ScanStyle::Warning, self.color));
                    self.printed_warnings_header = true;
                }
                print_secret_scanner_warning_line(error, self.color);
                flush_secret_scanner_stderr()
            }
            SecretScannerStreamFormat::Wrapped => {
                if !self.printed_warnings_header {
                    let rail = scan_rail(ScanStyle::Dim, self.color);
                    println!("{rail}");
                    let rail = scan_rail(ScanStyle::Warning, self.color);
                    println!(
                        "{rail} {}",
                        scan_paint("Warnings", ScanStyle::Warning, self.color)
                    );
                    self.printed_warnings_header = true;
                }
                print_wrapped_secret_scanner_warning_line(error, self.color);
                flush_secret_scanner_stdout()
            }
        }
    }

    fn finish(&mut self, report: &SecretScannerReport) -> Result<(), String> {
        match self.format {
            SecretScannerStreamFormat::Plain => {
                if report.findings.is_empty() {
                    println!("No plaintext secret exposure detected.");
                }
                println!(
                    "Summary: {}, {}, {}, {}.",
                    pluralize(report.summary.findings, "finding", "findings"),
                    pluralize(report.summary.errors, "warning", "warnings"),
                    pluralize(
                        report.summary.isotope_detectors,
                        "isotope detector",
                        "isotope detectors"
                    ),
                    secret_scanner_file_probe_summary(report)
                );
            }
            SecretScannerStreamFormat::Rich => {
                println!();
                if report.findings.is_empty() {
                    println!(
                        "{} No plaintext secret exposure detected",
                        scan_paint("✓", ScanStyle::Success, self.color)
                    );
                }
                println!("{}", scan_paint("Summary", ScanStyle::Heading, self.color));
                println!(
                    "  {} · {} · {} · {}",
                    pluralize(report.summary.findings, "finding", "findings"),
                    pluralize(report.summary.errors, "warning", "warnings"),
                    pluralize(
                        report.summary.isotope_detectors,
                        "isotope detector",
                        "isotope detectors"
                    ),
                    secret_scanner_file_probe_summary(report)
                );
            }
            SecretScannerStreamFormat::Wrapped => {
                if report.findings.is_empty() {
                    let rail = scan_rail(ScanStyle::Dim, self.color);
                    println!("{rail}");
                    let rail = scan_rail(ScanStyle::Success, self.color);
                    println!(
                        "{rail} {} No plaintext secret exposure detected",
                        scan_paint("✓", ScanStyle::Success, self.color)
                    );
                }
                let rail = scan_rail(ScanStyle::Dim, self.color);
                println!("{rail}");
                println!(
                    "{rail}   {}   {}",
                    scan_paint("Checked", ScanStyle::Dim, self.color),
                    pluralize(
                        report.summary.isotope_detectors,
                        "isotope detector",
                        "isotope detectors"
                    )
                );
                println!(
                    "{rail}   {}     {}",
                    scan_paint("Files", ScanStyle::Dim, self.color),
                    secret_scanner_file_probe_summary(report)
                );
                println!(
                    "{rail}   {}  {}",
                    scan_paint("Warnings", ScanStyle::Dim, self.color),
                    pluralize(report.summary.errors, "warning", "warnings")
                );
            }
        }
        flush_secret_scanner_stdout()
    }
}

fn flush_secret_scanner_stdout() -> Result<(), String> {
    std::io::stdout()
        .flush()
        .map_err(|err| format!("failed to flush scan output: {err}"))
}

fn flush_secret_scanner_stderr() -> Result<(), String> {
    std::io::stderr()
        .flush()
        .map_err(|err| format!("failed to flush scan warnings: {err}"))
}

fn scanner_wrapper_ui_enabled() -> bool {
    env::var(SCANNER_WRAPPER_UI_ENV).is_ok_and(|value| !value.is_empty() && value != "0")
}

fn print_secret_scanner_warning_line(error: &SecretScannerError, color: bool) {
    let source = scan_paint(&error.source, ScanStyle::Dim, color);
    match &error.path {
        Some(path) => eprintln!(
            "  {} {source} {} - {}",
            scan_paint("⚠", ScanStyle::Warning, color),
            scan_paint(path, ScanStyle::Path, color),
            error.message
        ),
        None => eprintln!(
            "  {} {source} - {}",
            scan_paint("⚠", ScanStyle::Warning, color),
            error.message
        ),
    }
}

fn print_wrapped_secret_scanner_warning_line(error: &SecretScannerError, color: bool) {
    let rail = scan_rail(ScanStyle::Warning, color);
    let source = scan_paint(&error.source, ScanStyle::Dim, color);
    match &error.path {
        Some(path) => println!(
            "{rail}   {} {source} {} - {}",
            scan_paint("!", ScanStyle::Warning, color),
            scan_paint(path, ScanStyle::Path, color),
            error.message
        ),
        None => println!(
            "{rail}   {} {source} - {}",
            scan_paint("!", ScanStyle::Warning, color),
            error.message
        ),
    }
}

fn print_scan_box(title: &str, lines: &[String], color: bool) {
    let width = scan_box_width(lines);
    println!(
        "{}",
        scan_paint(
            &format!(
                "╭─ {title} {}╮",
                "─".repeat(width.saturating_sub(title.len()))
            ),
            ScanStyle::Accent,
            color
        )
    );
    for line in lines {
        println!("│  {}", pad_scan_line(line, width));
    }
    println!(
        "{}",
        scan_paint(
            &format!("╰{}╯", "─".repeat(width + 3)),
            ScanStyle::Accent,
            color
        )
    );
}

fn scan_box_width(lines: &[String]) -> usize {
    lines
        .iter()
        .map(|line| strip_ansi_width(line))
        .max()
        .unwrap_or(42)
        .clamp(42, 76)
}

fn pad_scan_line(line: &str, width: usize) -> String {
    let visible = strip_ansi_width(line);
    format!("{line}{} │", " ".repeat(width.saturating_sub(visible)))
}

fn strip_ansi_width(line: &str) -> usize {
    let mut width = 0;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for next in chars.by_ref() {
                if next == 'm' {
                    break;
                }
            }
            continue;
        }
        width += 1;
    }
    width
}

fn secret_scanner_finding_location(finding: &SecretScannerFinding) -> Option<String> {
    match (&finding.path, finding.line) {
        (Some(path), Some(line)) => Some(format!("{path}:{line}")),
        (Some(path), None) => Some(path.clone()),
        (None, _) => None,
    }
}

fn secret_scanner_scope_label(scope: SecretScannerScope) -> &'static str {
    match scope {
        SecretScannerScope::Full => "isotope detectors and file probes",
        SecretScannerScope::IsotopesOnly => "isotope detectors only",
    }
}

fn secret_scanner_file_probe_summary(report: &SecretScannerReport) -> String {
    match report.scope {
        SecretScannerScope::Full => pluralize(
            report.summary.scanned_files,
            "file scanned",
            "files scanned",
        ),
        SecretScannerScope::IsotopesOnly => "file probes skipped".to_string(),
    }
}

fn pluralize(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

#[derive(Clone, Copy)]
enum ScanStyle {
    Accent,
    Dim,
    Error,
    Heading,
    Path,
    Success,
    Warning,
}

fn scan_severity_style(finding: &SecretScannerFinding) -> ScanStyle {
    match finding.severity.as_str() {
        "critical" | "high" => ScanStyle::Error,
        _ => ScanStyle::Warning,
    }
}

fn scan_paint(text: &str, style: ScanStyle, color: bool) -> String {
    if !color {
        return text.to_string();
    }

    let code = match style {
        ScanStyle::Accent => "38;2;224;90;71",
        ScanStyle::Dim => "2",
        ScanStyle::Error => "31;1",
        ScanStyle::Heading => "1",
        ScanStyle::Path => "36",
        ScanStyle::Success => "32;1",
        ScanStyle::Warning => "33;1",
    };
    format!("\x1b[{code}m{text}\x1b[0m")
}

fn scan_rail(style: ScanStyle, color: bool) -> String {
    scan_paint("│", style, color)
}

fn scan_stdout_is_rich() -> bool {
    env::var("CLICOLOR_FORCE").is_ok_and(|value| value != "0")
        || (std::io::stdout().is_terminal() && env::var("TERM").map_or(true, |term| term != "dumb"))
}

fn scan_stdout_supports_ansi() -> bool {
    output_supports_ansi(std::io::stdout().is_terminal())
}

fn output_supports_ansi(is_terminal: bool) -> bool {
    if env::var_os("NO_COLOR").is_some() {
        return false;
    }

    if env::var("CLICOLOR_FORCE").is_ok_and(|value| value != "0") {
        return true;
    }

    is_terminal && env::var("TERM").map_or(true, |term| term != "dumb")
}

struct SecretScanSkips {
    paths: HashSet<PathBuf>,
    cwd: Option<PathBuf>,
}

impl SecretScanSkips {
    fn new(root: Option<&Path>, skip_paths: &[PathBuf]) -> Self {
        let cwd = env::current_dir().ok().map(|path| normalize_path(&path));
        let raw_base = secret_scan_raw_skip_base(root);
        let mut paths = HashSet::new();

        for skip_path in skip_paths {
            if skip_path.is_absolute() {
                paths.insert(normalize_path(skip_path));
                continue;
            }

            let raw_skip_path = normalize_path(&raw_base.join(skip_path));
            paths.insert(raw_skip_path.clone());
            if !raw_skip_path.is_absolute()
                && let Some(cwd) = &cwd
            {
                paths.insert(normalize_path(&cwd.join(&raw_skip_path)));
            }
        }

        Self { paths, cwd }
    }

    fn should_skip(&self, path: &Path) -> bool {
        if self.paths.is_empty() {
            return false;
        }

        let normalized = normalize_path(path);
        if self.paths.contains(&normalized) {
            return true;
        }

        if normalized.is_absolute() {
            return false;
        }

        self.cwd
            .as_ref()
            .is_some_and(|cwd| self.paths.contains(&normalize_path(&cwd.join(normalized))))
    }
}

fn secret_scan_raw_skip_base(root: Option<&Path>) -> PathBuf {
    match root {
        Some(root) if root.is_dir() => root.to_path_buf(),
        Some(root) => root.parent().map(Path::to_path_buf).unwrap_or_default(),
        None => env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    }
}

fn scan_secret_file_probes<F>(
    root: Option<&Path>,
    skip_paths: &[PathBuf],
    findings: &mut Vec<SecretScannerFinding>,
    errors: &mut Vec<SecretScannerError>,
    seen_findings: &mut HashSet<SecretScannerFinding>,
    seen_errors: &mut HashSet<SecretScannerError>,
    on_event: &mut F,
) -> Result<(usize, usize), String>
where
    F: for<'a> FnMut(SecretScannerEvent<'a>) -> Result<(), String>,
{
    match root {
        Some(path) => scan_secret_file_probes_under_root(
            path,
            skip_paths,
            findings,
            errors,
            seen_findings,
            seen_errors,
            on_event,
        ),
        None => {
            let skips = SecretScanSkips::new(None, skip_paths);
            let mut scanned_files = 0;
            let mut file_probes = 0;
            for path in default_secret_scan_paths() {
                if skips.should_skip(&path) {
                    continue;
                }
                scan_secret_probe_path(
                    &path,
                    findings,
                    errors,
                    seen_findings,
                    seen_errors,
                    on_event,
                    &mut scanned_files,
                    &mut file_probes,
                )?;
            }
            Ok((scanned_files, file_probes))
        }
    }
}

fn scan_secret_file_probes_under_root<F>(
    root: &Path,
    skip_paths: &[PathBuf],
    findings: &mut Vec<SecretScannerFinding>,
    errors: &mut Vec<SecretScannerError>,
    seen_findings: &mut HashSet<SecretScannerFinding>,
    seen_errors: &mut HashSet<SecretScannerError>,
    on_event: &mut F,
) -> Result<(usize, usize), String>
where
    F: for<'a> FnMut(SecretScannerEvent<'a>) -> Result<(), String>,
{
    if !root.exists() {
        return Err(format!("scan path does not exist: {}", root.display()));
    }
    let skips = SecretScanSkips::new(Some(root), skip_paths);
    if root.is_file() {
        if skips.should_skip(root) {
            return Ok((0, 0));
        }
        let mut scanned_files = 0;
        let mut file_probes = 0;
        scan_secret_probe_path(
            root,
            findings,
            errors,
            seen_findings,
            seen_errors,
            on_event,
            &mut scanned_files,
            &mut file_probes,
        )?;
        return Ok((scanned_files, file_probes));
    }
    if !root.is_dir() {
        return Err(format!(
            "scan path is not a file or directory: {}",
            root.display()
        ));
    }
    if skips.should_skip(root) {
        return Ok((0, 0));
    }
    fs::read_dir(root)
        .map_err(|err| format!("failed to read scan path {}: {err}", root.display()))?;

    let mut scanned_files = 0;
    let mut file_probes = 0;
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            !secret_scan_should_skip_entry(entry) && !skips.should_skip(entry.path())
        })
    {
        match entry {
            Ok(entry) if entry.file_type().is_file() => {
                scan_secret_probe_path(
                    entry.path(),
                    findings,
                    errors,
                    seen_findings,
                    seen_errors,
                    on_event,
                    &mut scanned_files,
                    &mut file_probes,
                )?;
            }
            Ok(_) => {}
            Err(err) => record_secret_scanner_error(
                errors,
                seen_errors,
                SecretScannerError {
                    source: "file-probe".to_string(),
                    path: err.path().map(|path| path.display().to_string()),
                    message: format!("failed to walk entry: {err}"),
                },
                on_event,
            )?,
        }
    }

    Ok((scanned_files, file_probes))
}

#[allow(clippy::too_many_arguments)]
fn scan_secret_probe_path<F>(
    path: &Path,
    findings: &mut Vec<SecretScannerFinding>,
    errors: &mut Vec<SecretScannerError>,
    seen_findings: &mut HashSet<SecretScannerFinding>,
    seen_errors: &mut HashSet<SecretScannerError>,
    on_event: &mut F,
    scanned_files: &mut usize,
    file_probes: &mut usize,
) -> Result<(), String>
where
    F: for<'a> FnMut(SecretScannerEvent<'a>) -> Result<(), String>,
{
    *file_probes += 1;
    match scan_secret_file(path) {
        Ok(file_findings) => {
            if path.is_file() {
                *scanned_files += 1;
            }
            for finding in file_findings {
                record_secret_scanner_finding(findings, seen_findings, finding, on_event)?;
            }
        }
        Err(err) => record_secret_scanner_error(
            errors,
            seen_errors,
            SecretScannerError {
                source: "file-probe".to_string(),
                path: Some(path.display().to_string()),
                message: err,
            },
            on_event,
        )?,
    }
    Ok(())
}

fn secret_scan_should_skip_entry(entry: &walkdir::DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    if matches!(
        entry.file_name().to_str(),
        Some(
            ".git"
                | ".hg"
                | ".svn"
                | ".codex-worktrees"
                | ".build"
                | ".next"
                | "target"
                | "dist"
                | "node_modules"
                | "Vendor"
                | "vendor"
                | ".cache"
                | "cache"
                | "artifacts"
                | "DerivedData"
        )
    ) {
        return true;
    }

    let path = entry.path().to_string_lossy();
    path.contains("/isotopes/") || path.contains("/radioisotopes/")
}

fn default_secret_scan_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(cwd) = env::current_dir() {
        for relative in DEFAULT_SECRET_SCAN_CWD_FILES {
            paths.push(cwd.join(relative));
        }
    }

    if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
        for relative in DEFAULT_SECRET_SCAN_HOME_FILES {
            paths.push(home.join(relative));
        }
    }

    paths.extend(shell_secret_candidate_paths(ShellSecretFlavor::Bash));
    paths.extend(shell_secret_candidate_paths(ShellSecretFlavor::Zsh));

    paths.sort();
    paths.dedup();
    paths
}

const DEFAULT_SECRET_SCAN_CWD_FILES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".npmrc",
    ".pypirc",
    ".netrc",
];

const DEFAULT_SECRET_SCAN_HOME_FILES: &[&str] = &[
    ".env",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    ".aws/credentials",
    ".kube/config",
    ".config/gh/hosts.yml",
];

const BASH_SECRET_SCAN_HOME_FILES: &[&str] =
    &[".bashrc", ".bash_profile", ".bash_login", ".profile"];

const ZSH_SECRET_SCAN_HOME_FILES: &[&str] =
    &[".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout"];

const SECRET_SCAN_MAX_FILE_BYTES: u64 = 1024 * 1024;
const AUTOMIC_VAULT_DOTENV_ENCRYPTED_PREFIX: &str = "encrypted:";

pub(crate) fn bash_shell_secret_insecurity_reasons() -> Result<Vec<String>, String> {
    shell_secret_insecurity_reasons(ShellSecretFlavor::Bash)
}

pub(crate) fn zsh_shell_secret_insecurity_reasons() -> Result<Vec<String>, String> {
    shell_secret_insecurity_reasons(ShellSecretFlavor::Zsh)
}

fn shell_secret_insecurity_reasons(shell: ShellSecretFlavor) -> Result<Vec<String>, String> {
    let mut reasons = Vec::new();
    for path in shell_secret_candidate_paths(shell) {
        for finding in scan_secret_file(&path)? {
            let location = secret_scanner_finding_location(&finding)
                .unwrap_or_else(|| path.display().to_string());
            reasons.push(format!(
                "{} startup file contains plaintext-looking credential assignment: {} ({})",
                shell.display_name(),
                location,
                finding.message
            ));
        }
    }
    reasons.sort();
    reasons.dedup();
    Ok(reasons)
}

fn shell_secret_candidate_paths(shell: ShellSecretFlavor) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    match shell {
        ShellSecretFlavor::Bash => {
            if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
                for relative in BASH_SECRET_SCAN_HOME_FILES {
                    paths.push(home.join(relative));
                }
            }
            if let Some(path) = env::var_os("BASH_ENV").filter(|value| !value.is_empty()) {
                paths.push(PathBuf::from(path));
            }
        }
        ShellSecretFlavor::Zsh => {
            if let Some(base) = env::var_os("ZDOTDIR")
                .filter(|value| !value.is_empty())
                .or_else(|| env::var_os("HOME"))
                .map(PathBuf::from)
            {
                for relative in ZSH_SECRET_SCAN_HOME_FILES {
                    paths.push(base.join(relative));
                }
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

fn scan_secret_file(path: &Path) -> Result<Vec<SecretScannerFinding>, String> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(format!("failed to stat {}: {err}", path.display())),
    };
    if !metadata.is_file() || metadata.len() > SECRET_SCAN_MAX_FILE_BYTES {
        return Ok(Vec::new());
    }

    let bytes =
        fs::read(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    if bytes.contains(&0) {
        return Ok(Vec::new());
    }
    let Ok(contents) = String::from_utf8(bytes) else {
        return Ok(Vec::new());
    };

    let mut findings = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        if let Some(finding) = scan_secret_line(path, index + 1, line) {
            findings.push(finding);
        }
    }
    Ok(findings)
}

fn scan_secret_line(path: &Path, line_number: usize, line: &str) -> Option<SecretScannerFinding> {
    let trimmed = line.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with(';')
        || trimmed.starts_with("//")
        || secret_line_looks_like_source_string_fixture(path, trimmed)
    {
        return None;
    }

    if trimmed.contains("BEGIN ") && trimmed.contains("PRIVATE KEY") {
        if secret_private_key_line_is_fixture(path, trimmed) {
            return None;
        }
        return Some(secret_file_finding(
            path,
            line_number,
            "private-key",
            "critical",
            "Private key material appears in a readable file",
        ));
    }

    let Some(assignment) = parse_secret_assignment(trimmed) else {
        if secret_line_contains_standalone_token_literal(path, trimmed) {
            return Some(secret_file_finding(
                path,
                line_number,
                "token-literal",
                "high",
                "Known token-shaped value appears in a readable file",
            ));
        }
        return None;
    };
    if secret_assignment_looks_like_source_code(&assignment) {
        return None;
    }

    let value = normalized_secret_value(assignment.value);
    if secret_path_looks_like_env_file(path) && secret_value_looks_like_encrypted_dotenv(value) {
        return None;
    }
    let key_is_sensitive = secret_key_name_is_sensitive(assignment.key);
    let value_has_known_shape = secret_value_has_known_secret_shape(value);
    let value_has_strong_shape = secret_value_has_high_entropy_shape(value);
    let credential_context = secret_path_looks_like_credential_file(path);
    let source_context = secret_path_looks_like_source_file(path);
    let value_is_real = value_has_known_shape
        || (source_context
            && key_is_sensitive
            && secret_assignment_value_is_literal(assignment.value)
            && value_has_strong_shape)
        || (!source_context
            && key_is_sensitive
            && credential_context
            && (secret_value_is_real(value) || secret_sensitive_env_value_is_real(value)))
        || (!source_context && key_is_sensitive && value_has_strong_shape);
    if !value_is_real || secret_value_is_test_fixture(path, value) {
        return None;
    }
    if secret_path_looks_like_test_fixture(path) && key_is_sensitive {
        return None;
    }

    if key_is_sensitive {
        let key = shell_assignment_key_name(assignment.key).trim();
        return Some(secret_file_finding(
            path,
            line_number,
            "secret-assignment",
            "high",
            &format!("Plaintext-looking credential assigned to {key}"),
        ));
    }

    if value_has_known_shape {
        return Some(secret_file_finding(
            path,
            line_number,
            "token-literal",
            "high",
            "Known token-shaped value appears in a readable file",
        ));
    }

    None
}

fn secret_file_finding(
    path: &Path,
    line: usize,
    kind: &str,
    severity: &str,
    message: &str,
) -> SecretScannerFinding {
    SecretScannerFinding {
        source: secret_file_probe_source(path).to_string(),
        kind: kind.to_string(),
        severity: severity.to_string(),
        path: Some(path.display().to_string()),
        line: Some(line),
        message: message.to_string(),
    }
}

fn secret_file_probe_source(path: &Path) -> &'static str {
    secret_shell_startup_file_flavor(path).map_or("file-probe", ShellSecretFlavor::source_label)
}

struct SecretAssignment<'a> {
    key: &'a str,
    value: &'a str,
    separator: SecretAssignmentSeparator,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SecretAssignmentSeparator {
    Equals,
    Colon,
}

fn parse_secret_assignment(line: &str) -> Option<SecretAssignment<'_>> {
    let line = line.strip_prefix("- ").unwrap_or(line);
    let equals = find_secret_assignment_equals(line);
    let colon = find_secret_assignment_colon(line);
    match (equals, colon) {
        (Some(eq), Some(colon)) if eq < colon => Some(SecretAssignment {
            key: &line[..eq],
            value: &line[eq + 1..],
            separator: SecretAssignmentSeparator::Equals,
        }),
        (Some(_), Some(colon)) => Some(SecretAssignment {
            key: &line[..colon],
            value: &line[colon + 1..],
            separator: SecretAssignmentSeparator::Colon,
        }),
        (Some(eq), None) => Some(SecretAssignment {
            key: &line[..eq],
            value: &line[eq + 1..],
            separator: SecretAssignmentSeparator::Equals,
        }),
        (None, Some(colon)) => Some(SecretAssignment {
            key: &line[..colon],
            value: &line[colon + 1..],
            separator: SecretAssignmentSeparator::Colon,
        }),
        (None, None) => None,
    }
}

fn find_secret_assignment_equals(line: &str) -> Option<usize> {
    for (index, ch) in line.char_indices() {
        if ch != '=' {
            continue;
        }
        let previous = line[..index].chars().next_back();
        let next = line[index + ch.len_utf8()..].chars().next();
        if previous.is_some_and(|ch| matches!(ch, '!' | '<' | '>' | '='))
            || next.is_some_and(|ch| matches!(ch, '=' | '>'))
        {
            continue;
        }
        return Some(index);
    }
    None
}

fn find_secret_assignment_colon(line: &str) -> Option<usize> {
    for (index, ch) in line.char_indices() {
        if ch != ':' {
            continue;
        }
        let previous = line[..index].chars().next_back();
        let next = line[index + ch.len_utf8()..].chars().next();
        if previous.is_some_and(|ch| ch == ':') || next.is_some_and(|ch| ch == ':' || ch == '/') {
            continue;
        }
        return Some(index);
    }
    None
}

fn secret_assignment_looks_like_source_code(assignment: &SecretAssignment<'_>) -> bool {
    let key = assignment.key.trim();
    let value = assignment.value.trim();
    if key.starts_with("case ") {
        return true;
    }

    if assignment.separator == SecretAssignmentSeparator::Colon
        && (key.starts_with("let ")
            || key.starts_with("var ")
            || key.starts_with("const ")
            || key.starts_with("pub "))
    {
        return true;
    }

    if key.contains('(')
        || secret_key_looks_like_source_code(key)
        || secret_key_looks_like_source_reference(key)
        || secret_key_name_is_noncredential_metadata(key)
        || secret_key_looks_like_freeform_text(key)
    {
        return true;
    }

    if assignment.separator == SecretAssignmentSeparator::Colon
        && (key.contains('(')
            || secret_key_looks_like_freeform_text(key)
            || secret_value_looks_like_freeform_text(value)
            || secret_value_looks_like_type_annotation(value))
    {
        return true;
    }

    if secret_quoted_value_looks_like_source_expression(value) {
        return true;
    }

    secret_unquoted_value_looks_like_source_reference(value)
}

fn secret_key_looks_like_source_code(key: &str) -> bool {
    let trimmed = key.trim_start();
    trimmed.starts_with("type ")
        || trimmed.starts_with("interface ")
        || trimmed.starts_with("struct ")
        || trimmed.starts_with("class ")
        || trimmed.starts_with("enum ")
        || trimmed.starts_with("protocol ")
        || trimmed.starts_with("union ")
        || trimmed.starts_with("def ")
        || trimmed.starts_with("function ")
        || trimmed.starts_with("export function ")
        || trimmed.starts_with("return ")
        || trimmed.starts_with("if ")
        || trimmed.starts_with("if(")
        || trimmed.starts_with('.')
        || trimmed.starts_with("WHERE ")
        || trimmed.starts_with("where ")
}

fn secret_key_looks_like_source_reference(key: &str) -> bool {
    let key = key.trim();
    if key.starts_with('"') || key.starts_with('\'') {
        return false;
    }
    key.contains("->")
        || key.contains("::")
        || key.contains(',')
        || (key.contains('[') && key.contains(']'))
        || (key.contains('.') && key.chars().all(source_key_reference_char))
}

fn source_key_reference_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.')
}

fn secret_key_looks_like_freeform_text(key: &str) -> bool {
    let key = key.trim();
    if key.starts_with("export ")
        || key.starts_with("readonly ")
        || key.starts_with("declare ")
        || key.starts_with("typeset ")
        || key.starts_with("local ")
        || key.starts_with("let ")
        || key.starts_with("var ")
        || key.starts_with("const ")
    {
        return false;
    }
    let key = key.trim_matches('"').trim_matches('\'').trim_matches('`');
    if key.starts_with('/') || key.ends_with('/') {
        return true;
    }
    key.contains(',') || key.split_whitespace().count() > 1
}

fn secret_value_looks_like_freeform_text(value: &str) -> bool {
    if secret_raw_value_is_quoted(value) {
        return false;
    }
    let value = value
        .split_once('#')
        .map_or(value, |(before_comment, _)| before_comment)
        .trim();
    value.split_whitespace().count() >= 4 && value.chars().any(char::is_alphabetic)
}

fn secret_value_looks_like_type_annotation(value: &str) -> bool {
    let mut words = value.split_whitespace();
    let Some(first) = words.next() else {
        return false;
    };
    let has_more_words =
        words.any(|word| !word.chars().all(|ch| matches!(ch, '{' | '}' | ',' | ';')));
    let first = first.trim_matches(|ch: char| {
        matches!(
            ch,
            '?' | '!' | ')' | '(' | '[' | ']' | '<' | '>' | ',' | ';' | '{' | '}'
        )
    });
    let first = first
        .trim_start_matches('&')
        .trim_start_matches('\'')
        .trim_end_matches('\'');
    if first.is_empty() || first.starts_with('"') || first.starts_with('\'') {
        return false;
    }
    if matches!(first, "Bearer" | "Basic") {
        return false;
    }
    if first.chars().next().is_some_and(char::is_uppercase)
        && value.contains('=')
        && value.contains("nil")
    {
        return true;
    }
    matches!(
        first,
        "String"
            | "Bool"
            | "Boolean"
            | "Int"
            | "Integer"
            | "Double"
            | "Float"
            | "Date"
            | "Data"
            | "URL"
            | "UUID"
            | "static"
            | "str"
            | "string"
            | "bytes"
            | "bool"
            | "boolean"
            | "number"
            | "object"
            | "array"
    ) || (first.chars().next().is_some_and(char::is_uppercase)
        && (!has_more_words || first.contains('<')))
}

fn secret_unquoted_value_looks_like_source_reference(value: &str) -> bool {
    if secret_raw_value_is_quoted(value) {
        return false;
    }
    let value = value.trim().trim_end_matches([',', ';']);
    if value.is_empty() {
        return false;
    }
    if secret_unquoted_value_looks_like_placeholder_or_pattern(value)
        || secret_unquoted_value_looks_like_source_expression(value)
    {
        return true;
    }
    if value.starts_with('.') || value.contains('(') || value.contains("->") || value.contains("::")
    {
        return true;
    }
    if secret_value_has_known_token_shape(value) || secret_value_looks_like_jwt(value) {
        return false;
    }
    if value.contains('.') && value.chars().all(source_reference_char) {
        return true;
    }
    source_identifier(value).is_some_and(|identifier| {
        !identifier.chars().any(|ch| ch.is_ascii_digit())
            && identifier.chars().any(char::is_uppercase)
            && secret_key_name_is_sensitive(identifier)
    })
}

fn secret_unquoted_value_looks_like_placeholder_or_pattern(value: &str) -> bool {
    value == "?"
        || value.starts_with("//")
        || value.starts_with("{{")
        || value.starts_with("<%")
        || value.starts_with('{')
        || (value.starts_with('{') && value.ends_with('}'))
        || (value.starts_with('/') && value.ends_with('/'))
}

fn secret_unquoted_value_looks_like_source_expression(value: &str) -> bool {
    value.starts_with("f\"")
        || value.starts_with("f'")
        || value.starts_with('&')
        || value.starts_with('!')
        || value.starts_with("if ")
        || value.starts_with("self.")
        || value.starts_with("match ")
        || value.starts_with("process.env.")
        || value.starts_with("typeof ")
        || value.starts_with("ReturnType<")
        || value.contains(" as ")
        || value.contains(" + ")
        || value.contains(" - ")
        || value.contains(" ?? ")
        || value.contains("\\(")
        || value.contains(" * ")
        || value.contains(" ? ")
        || value.contains(" : ")
        || value.contains(" && ")
        || value.contains(" || ")
        || value.contains(" === ")
        || value.contains(" !== ")
        || value.contains(" == ")
        || value.contains(" != ")
        || value.contains(" <= ")
        || value.contains(" >= ")
        || (value.contains('[') && value.contains(']'))
        || value.ends_with('?')
        || value.ends_with('{')
}

fn secret_quoted_value_looks_like_source_expression(value: &str) -> bool {
    secret_raw_value_is_quoted(value)
        && (value.contains("\\(")
            || value.contains(".into()")
            || value.contains(".to_owned()")
            || value.contains(".to_string()")
            || value.contains(".spanned("))
}

fn secret_raw_value_is_quoted(value: &str) -> bool {
    let value = value.trim();
    value.starts_with('"') || value.starts_with('\'')
}

fn secret_assignment_value_is_literal(value: &str) -> bool {
    secret_raw_value_is_quoted(value)
}

fn source_identifier(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty() || !value.chars().all(source_reference_char) {
        return None;
    }
    Some(value.rsplit('.').next().unwrap_or(value))
}

fn source_reference_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.')
}

fn normalized_secret_value(value: &str) -> &str {
    let value = value
        .trim()
        .trim_end_matches([',', ';', '}', ']', ')', ':'])
        .trim();
    let value = if secret_raw_value_is_quoted(value) {
        value
    } else {
        value
            .split_once('#')
            .map_or(value, |(before_comment, _)| before_comment)
            .trim()
    };
    value.trim_matches('"').trim_matches('\'').trim()
}

fn secret_key_name_is_sensitive(key: &str) -> bool {
    if secret_key_name_is_noncredential_metadata(key) {
        return false;
    }

    let key = normalized_secret_key_name(key);
    key == "token"
        || key == "password"
        || key == "passwd"
        || key == "authorization"
        || key.contains("token")
        || key.contains("api_key")
        || key.contains("apikey")
        || key.contains("access_key")
        || key.contains("secret")
        || key.contains("auth_token")
        || key.contains("private_key")
        || key.contains("refresh_token")
        || key.contains("id_token")
        || key.contains("client_secret")
}

fn secret_key_name_is_noncredential_metadata(key: &str) -> bool {
    let key = normalized_secret_key_name(key);
    let compact = key.replace('_', "");
    let mentions_secretish_word = compact.contains("token")
        || compact.contains("secret")
        || compact.contains("password")
        || compact.contains("key");

    mentions_secretish_word
        && (compact.ends_with("type")
            || compact.ends_with("types")
            || compact.ends_with("name")
            || compact.ends_with("names")
            || compact.ends_with("prefix")
            || compact.ends_with("suffix")
            || compact.ends_with("service")
            || compact.ends_with("hash")
            || compact.ends_with("label")
            || compact.ends_with("labels")
            || compact.ends_with("pattern")
            || compact.ends_with("patterns")
            || compact.ends_with("class")
            || compact.ends_with("size")
            || compact.ends_with("margin")
            || compact.ends_with("padding")
            || compact.ends_with("width")
            || compact.ends_with("threshold")
            || compact.ends_with("version")
            || compact.ends_with("color")
            || compact.ends_with("dir")
            || compact.ends_with("path")
            || compact.ends_with("file")
            || compact.ends_with("url")
            || compact.ends_with("uri"))
}

fn normalized_secret_key_name(key: &str) -> String {
    shell_assignment_key_name(key)
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase()
        .chars()
        .map(|ch| match ch {
            '-' | '.' | ' ' => '_',
            _ => ch,
        })
        .collect()
}

fn shell_assignment_key_name(key: &str) -> &str {
    let key = key.trim();
    let Some((command, mut rest)) = shell_word(key) else {
        return key;
    };
    if !matches!(
        command,
        "export" | "readonly" | "declare" | "typeset" | "local"
    ) {
        return key;
    }

    while let Some((word, after_word)) = shell_word(rest) {
        if !word.starts_with('-') {
            return if after_word.trim().is_empty() && shell_assignment_word_looks_like_name(word) {
                word
            } else {
                key
            };
        }
        rest = after_word;
    }

    key
}

fn shell_word(value: &str) -> Option<(&str, &str)> {
    let value = value.trim_start();
    if value.is_empty() {
        return None;
    }
    let end = value
        .char_indices()
        .find_map(|(index, ch)| ch.is_whitespace().then_some(index))
        .unwrap_or(value.len());
    Some((&value[..end], &value[end..]))
}

fn shell_assignment_word_looks_like_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch == '-' || ch == '.' || ch.is_ascii_alphanumeric())
}

fn secret_value_is_real(value: &str) -> bool {
    if secret_value_is_obviously_not_real(value) {
        return false;
    }

    let lower = value.to_ascii_lowercase();
    if secret_value_has_known_secret_shape(value) {
        return true;
    }
    if lower == "secret_secret" {
        return true;
    }

    !secret_value_looks_like_package_or_label(value)
}

fn secret_sensitive_env_value_is_real(value: &str) -> bool {
    if value.len() < 12 || secret_value_is_obviously_not_real(value) {
        return false;
    }
    let has_alpha = value.chars().any(|ch| ch.is_ascii_alphabetic());
    let has_digit = value.chars().any(|ch| ch.is_ascii_digit());
    (value.len() >= 16 && has_alpha) || (value.len() >= 12 && has_alpha && has_digit)
}

fn secret_value_looks_like_encrypted_dotenv(value: &str) -> bool {
    let Some(payload) = value.strip_prefix(AUTOMIC_VAULT_DOTENV_ENCRYPTED_PREFIX) else {
        return false;
    };
    !payload.is_empty()
        && payload
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '='))
}

fn secret_value_has_known_secret_shape(value: &str) -> bool {
    secret_value_has_known_token_shape(value)
        || secret_value_looks_like_posthog_project_key(value)
        || secret_value_looks_like_jwt(value)
}

fn secret_value_has_high_entropy_shape(value: &str) -> bool {
    if value.len() < 20
        || secret_value_is_obviously_not_real(value)
        || secret_value_looks_like_package_or_label(value)
        || value.chars().any(char::is_whitespace)
    {
        return false;
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    for ch in value.chars() {
        if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else if matches!(ch, '_' | '-' | '.' | '+' | '/' | '=') {
            has_symbol = true;
        } else {
            return false;
        }
    }

    let category_count = usize::from(has_lower)
        + usize::from(has_upper)
        + usize::from(has_digit)
        + usize::from(has_symbol);
    let has_alpha = has_lower || has_upper;
    has_alpha && has_digit && ((value.len() >= 24 && category_count >= 3) || value.len() >= 32)
}

fn secret_value_is_obviously_not_real(value: &str) -> bool {
    if value.len() < 6 || value.contains("${") {
        return true;
    }

    let lower = value.to_ascii_lowercase();
    if lower.starts_with("options:") {
        return true;
    }
    let comparable =
        lower.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && !matches!(ch, '_' | '-'));
    if matches!(
        comparable,
        "secret"
            | "password"
            | "token"
            | "example"
            | "changeme"
            | "change_me"
            | "replace_me"
            | "redacted"
            | "access_token"
            | "refresh_token"
            | "id_token"
            | "client_secret"
            | "api_key"
            | "none"
            | "null"
            | "true"
            | "false"
            | "string"
            | "bytes"
            | "write"
            | "read"
            | "hashed"
            | "nullptr"
            | "nil"
    ) {
        return true;
    }

    lower.contains("example")
        || lower.contains("placeholder")
        || lower.contains("your_")
        || lower.contains("your-")
        || lower.contains("...")
        || lower.contains("***")
        || lower.contains("fake")
        || value.contains('…')
        || lower.contains("\\n")
        || lower.contains("base64url")
        || value.starts_with('$')
        || (lower.starts_with("env(") && lower.ends_with(')'))
        || lower.contains(".into()")
        || lower.contains(".to_string()")
        || lower.contains(".spanned(")
        || lower.contains("getenv(")
        || (value.contains('<') && value.contains('>'))
        || lower.chars().all(|ch| ch.is_ascii_digit())
        || lower.chars().all(|ch| ch == 'x' || ch == '*')
        || (value.starts_with('{') && value.ends_with('}'))
        || value.starts_with("{{")
        || value.starts_with('<')
        || (value.starts_with('%') && value.ends_with('%'))
        || secret_value_looks_like_file_path(value)
        || secret_value_looks_like_public_url(value)
        || secret_value_looks_like_version_requirement(value)
}

fn secret_value_is_test_fixture(path: &Path, value: &str) -> bool {
    if secret_path_looks_like_reference_fixture(path) {
        return true;
    }

    if !secret_path_looks_like_test_fixture(path) {
        return false;
    }

    let lower = value.to_ascii_lowercase();
    if secret_value_has_known_token_shape(value) || secret_value_looks_like_jwt(value) {
        return true;
    }
    if lower.contains("token") || lower.contains("secret") {
        return true;
    }

    matches!(
        lower.as_str(),
        "password123"
            | "handoff-token"
            | "test-token"
            | "test-password"
            | "polar_test_token"
            | "polar_webhook_secret"
    )
}

fn secret_path_looks_like_test_fixture(path: &Path) -> bool {
    let path = path.to_string_lossy().to_ascii_lowercase();
    path.contains("/test/")
        || path.contains("/tests/")
        || path.contains("\\test\\")
        || path.contains("\\tests\\")
        || path.contains(".test.")
        || path.contains(".spec.")
        || path.contains("_test.")
        || path.contains("_tests.")
}

fn secret_path_looks_like_reference_fixture(path: &Path) -> bool {
    let path = path.to_string_lossy().to_ascii_lowercase();
    path.contains("/testdata/")
        || path.contains("/fixtures/")
        || path.contains("/fixture/")
        || path.contains("/examples/")
        || path.contains("/example/")
        || path.contains("/samples/")
        || path.contains("/sample/")
        || path.contains("/cavs_samples/")
        || path.contains("/wycheproof/")
        || path.contains("/doc/")
        || path.contains("/docs/")
        || path.contains("/share/man/")
        || path.contains("/share/info/")
        || path.contains("/man/man")
        || path.contains("/resources/bundled/")
        || path.ends_with(".sample")
        || path.ends_with(".strings")
}

fn secret_path_looks_like_credential_file(path: &Path) -> bool {
    if secret_path_looks_like_env_file(path) {
        return true;
    }
    if secret_shell_startup_file_flavor(path).is_some() {
        return true;
    }

    let normalized_path = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if normalized_path.ends_with("/.aws/credentials")
        || normalized_path.ends_with("/.kube/config")
        || normalized_path.ends_with("/.config/gh/hosts.yml")
    {
        return true;
    }

    matches!(
        path.file_name()
            .and_then(|file_name| file_name.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some(".npmrc" | ".pypirc" | ".netrc" | ".git-credentials")
    )
}

fn secret_path_looks_like_env_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|file_name| file_name.to_str()) else {
        return false;
    };
    let file_name = file_name.to_ascii_lowercase();
    file_name == ".env"
        || file_name == ".envrc"
        || file_name.starts_with(".env.")
        || file_name.ends_with(".env")
        || file_name.contains(".env.")
}

fn secret_shell_startup_file_flavor(path: &Path) -> Option<ShellSecretFlavor> {
    if let Some(bash_env) = env::var_os("BASH_ENV")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        && secret_paths_match(path, &bash_env)
    {
        return Some(ShellSecretFlavor::Bash);
    }

    let file_name = path.file_name()?.to_str()?.to_ascii_lowercase();
    match file_name.as_str() {
        ".bashrc" | ".bash_profile" | ".bash_login" | ".profile" => Some(ShellSecretFlavor::Bash),
        ".zshenv" | ".zprofile" | ".zshrc" | ".zlogin" | ".zlogout" => Some(ShellSecretFlavor::Zsh),
        _ => None,
    }
}

fn secret_paths_match(left: &Path, right: &Path) -> bool {
    normalize_path(left) == normalize_path(right)
}

fn secret_private_key_line_is_fixture(path: &Path, line: &str) -> bool {
    secret_path_looks_like_reference_fixture(path)
        || (secret_path_looks_like_source_file(path) && !line.starts_with("-----BEGIN "))
}

fn secret_path_looks_like_source_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some(
            "c" | "cc"
                | "cpp"
                | "cxx"
                | "h"
                | "hh"
                | "hpp"
                | "hxx"
                | "go"
                | "rs"
                | "swift"
                | "js"
                | "jsx"
                | "sh"
                | "bash"
                | "zsh"
                | "ts"
                | "tsx"
                | "py"
                | "rb"
                | "pm"
                | "erl"
                | "hrl"
        )
    )
}

fn secret_line_looks_like_source_string_fixture(path: &Path, line: &str) -> bool {
    if !secret_path_looks_like_source_file(path) {
        return false;
    }
    let line = line.trim_start();
    (line.starts_with('"')
        || (line.starts_with('r') && line.contains("#\""))
        || line.starts_with("r\"")
        || line.starts_with("br#\""))
        && (line.contains('=') || line.contains(':'))
}

fn secret_line_contains_standalone_token_literal(path: &Path, line: &str) -> bool {
    if secret_path_looks_like_test_fixture(path) || secret_path_looks_like_reference_fixture(path) {
        return false;
    }
    if secret_path_looks_like_source_file(path) {
        return secret_line_contains_quoted_secret_literal(line);
    }
    line.split(|ch: char| !token_shape_char(ch))
        .any(secret_value_has_known_secret_shape)
}

fn secret_line_contains_quoted_secret_literal(line: &str) -> bool {
    let mut chars = line.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if !matches!(ch, '"' | '\'') {
            continue;
        }

        let quote = ch;
        let mut escaped = false;
        let start = chars.peek().map_or(line.len(), |(index, _)| *index);
        for (index, next) in chars.by_ref() {
            if escaped {
                escaped = false;
                continue;
            }
            if next == '\\' {
                escaped = true;
                continue;
            }
            if next == quote {
                let value = &line[start..index];
                if secret_value_has_known_secret_shape(value) {
                    return true;
                }
                break;
            }
        }
    }
    false
}

fn secret_value_looks_like_file_path(value: &str) -> bool {
    value.starts_with("~/")
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || value.ends_with(".pem")
        || value.ends_with(".key")
}

fn secret_value_looks_like_public_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    (lower.starts_with("http://") || lower.starts_with("https://"))
        && !value.contains('@')
        && !lower.contains("token=")
        && !lower.contains("access_token=")
        && !lower.contains("api_key=")
        && !lower.contains("apikey=")
        && !lower.contains("secret=")
}

fn secret_value_looks_like_version_requirement(value: &str) -> bool {
    value.contains('.')
        && value.chars().all(|ch| {
            ch.is_ascii_digit()
                || matches!(
                    ch,
                    '.' | '^' | '~' | '*' | '|' | '&' | '<' | '>' | '=' | '!' | ' ' | '-'
                )
        })
}

fn secret_value_looks_like_package_or_label(value: &str) -> bool {
    if value.len() > 48 {
        return false;
    }
    let mut has_alpha = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_space = false;
    for ch in value.chars() {
        if ch.is_ascii_alphabetic() {
            has_alpha = true;
            has_upper |= ch.is_ascii_uppercase();
            continue;
        }
        if ch.is_ascii_digit() {
            has_digit = true;
            continue;
        }
        if ch.is_ascii_whitespace() {
            has_space = true;
            continue;
        }
        if matches!(ch, '_' | '-' | '.' | '/' | ':') {
            continue;
        }
        return false;
    }
    has_alpha && (!has_upper || !has_digit) && (!has_space || has_upper)
}

fn secret_value_looks_like_jwt(value: &str) -> bool {
    if value.len() < 80 {
        return false;
    }
    let mut parts = value.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(second) = parts.next() else {
        return false;
    };
    let Some(third) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && [first, second, third]
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(base64_url_char))
}

fn base64_url_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '=')
}

fn secret_value_has_known_token_shape(value: &str) -> bool {
    let value = value.trim();
    if !value.chars().all(token_shape_char) {
        return false;
    }
    (value.starts_with("ghp_") && value.len() > 20)
        || (value.starts_with("gho_") && value.len() > 20)
        || (value.starts_with("ghs_") && value.len() > 20)
        || (value.starts_with("github_pat_") && value.len() > 30)
        || (value.starts_with("glpat-") && value.len() > 20)
        || (value.starts_with("xoxb-") && value.len() > 20)
        || (value.starts_with("xoxp-") && value.len() > 20)
        || (value.starts_with("sk_live_") && value.len() > 20)
        || (value.starts_with("npm_") && value.len() > 12)
        || (value.starts_with("sk-") && value.len() > 20)
        || (value.starts_with("xai-") && value.len() > 20)
        || (value.starts_with("AKIA") && value.len() >= 16)
}

fn secret_value_looks_like_posthog_project_key(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("phc_") && value.len() > 20 && value.chars().all(token_shape_char)
}

fn token_shape_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')
}

fn isotope_replaced_package_name(record: &IsotopePackageData) -> Result<Option<String>, String> {
    if isotope_has_post_install(&record.name) {
        return Ok(None);
    }
    let Some(replaces) = record.replaces.as_ref() else {
        return Ok(None);
    };
    crate::cli::parse_uninstall_package_name(&OsString::from(replaces))
        .map(Some)
        .map_err(|err| format!("invalid isotope replacement {}: {err}", replaces))
}

fn isotope_replaced_package_target(
    record: &IsotopePackageData,
) -> Result<Option<PackageAliasTarget>, String> {
    if isotope_has_post_install(&record.name) {
        return Ok(None);
    }
    let Some(replaces) = record.replaces.as_ref() else {
        return Ok(None);
    };
    match parse_package_alias_target(replaces)
        .map_err(|err| format!("invalid isotope replacement {}: {err}", replaces))?
    {
        target
        @ (PackageAliasTarget::HomebrewFormula(_) | PackageAliasTarget::VendorPackage(_)) => {
            Ok(Some(target))
        }
        _ => Ok(None),
    }
}

fn isotope_modified_package_target(
    record: &IsotopePackageData,
) -> Result<Option<PackageAliasTarget>, String> {
    let modifies = record.modifies.as_ref().or_else(|| {
        isotope_has_post_install(&record.name)
            .then_some(record.replaces.as_ref())
            .flatten()
    });
    let Some(modifies) = modifies else {
        return Ok(None);
    };
    match parse_package_alias_target(modifies)
        .map_err(|err| format!("invalid isotope modification {}: {err}", modifies))?
    {
        target
        @ (PackageAliasTarget::HomebrewFormula(_) | PackageAliasTarget::VendorPackage(_)) => {
            Ok(Some(target))
        }
        _ => Err(format!(
            "invalid isotope modification {}: radioisotopes may only modify Homebrew formulae or vendor packages",
            modifies
        )),
    }
}

fn isotope_modified_package_name(record: &IsotopePackageData) -> Result<Option<String>, String> {
    isotope_modified_package_target(record)?
        .as_ref()
        .map(radioisotope_modified_install_name)
        .transpose()
}

fn radioisotope_modified_install_name(target: &PackageAliasTarget) -> Result<String, String> {
    match target {
        PackageAliasTarget::HomebrewFormula(formula)
        | PackageAliasTarget::VendorPackage(formula) => Ok(formula.clone()),
        _ => Err(format!(
            "invalid isotope modification {}: radioisotopes may only modify Homebrew formulae or vendor packages",
            target.display_name()
        )),
    }
}

fn isotope_modified_or_replaced_package_name(
    record: &IsotopePackageData,
) -> Result<Option<String>, String> {
    match isotope_modified_package_name(record)? {
        Some(package) => Ok(Some(package)),
        None => isotope_replaced_package_name(record),
    }
}

fn isotope_dependency_graph(
    isotope: &IsotopePackageData,
    config: &Config,
) -> Result<Vec<FormulaSpec>, String> {
    let Some(replaces) = isotope.replaces.as_deref() else {
        return Ok(Vec::new());
    };
    let Some(formula) = replaces.strip_prefix(BREW_PACKAGE_PREFIX) else {
        return Ok(Vec::new());
    };
    let formula = canonical_formula_name(formula)?;
    let info = fetch_formula_info(&formula)?;
    resolve_formula_specs(&info.dependencies, config, true)
}

fn pip_package_install_data(package: &str) -> Option<&'static PackageInstallData> {
    embedded_pip_package_data().get(&normalize_pip_package_name(package))
}

fn pip_package_homebrew_dependencies(package: &str) -> Vec<String> {
    pip_package_install_data(package)
        .map(|entry| entry.homebrew_dependencies.clone())
        .unwrap_or_default()
}

fn append_pip_package_homebrew_dependencies(formula_names: &mut Vec<String>, package: &str) {
    for dependency in pip_package_homebrew_dependencies(package) {
        push_unique_string(formula_names, dependency);
    }
}

fn pip_package_python_formula(package: &str) -> String {
    pip_package_install_data(package)
        .and_then(|entry| entry.python_formula.clone())
        .unwrap_or_else(|| "python".to_string())
}

fn append_vendor_npm_homebrew_dependencies(
    formula_names: &mut Vec<String>,
    vendor_installs: &[VendorInstall],
) {
    for install in vendor_installs {
        if let vendor::InstallStrategy::NpmGlobal {
            package: npm_package,
        } = (install.package.install)(&install.version)
        {
            append_npm_package_homebrew_dependencies(formula_names, &npm_package);
        }
    }
}

#[cfg(not(feature = "gold-release"))]
#[allow(dead_code)]
fn maybe_self_update_and_restart(_request: &UpdateRequest) -> Result<(), String> {
    Ok(())
}

#[cfg(feature = "gold-release")]
#[allow(dead_code)]
fn maybe_self_update_and_restart(request: &UpdateRequest) -> Result<(), String> {
    if request.no_self_update || !running_from_self_update_target() {
        return Ok(());
    }

    let Some(release) = resolve_self_update_release()? else {
        return Ok(());
    };

    install_self_update(&release)?;
    exec_self_update_restart()
}

#[cfg(feature = "gold-release")]
fn running_from_self_update_target() -> bool {
    env::current_exe()
        .ok()
        .is_some_and(|path| path == Path::new(SELF_UPDATE_TARGET))
}

#[cfg(feature = "gold-release")]
fn resolve_self_update_release() -> Result<Option<SelfUpdateRelease>, String> {
    let release: GithubRelease = fetch_json(
        &format!("https://api.github.com/repos/{SELF_UPDATE_REPO}/releases/latest"),
        || format!("failed to fetch latest release for {SELF_UPDATE_REPO}"),
    )?;
    let current_version = semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|err| format!("failed to parse current av version: {err}"))?;
    let latest_version = parse_self_update_version(&release.tag_name)?;
    if latest_version <= current_version {
        return Ok(None);
    }

    let asset_name = current_self_update_asset_name(&latest_version).ok_or_else(|| {
        format!(
            "self-update is unsupported on {}-{}",
            env::consts::OS,
            env::consts::ARCH
        )
    })?;
    let asset = release
        .assets
        .into_iter()
        .find(|asset| asset.name == asset_name)
        .ok_or_else(|| {
            format!(
                "latest av release {} does not contain asset {}",
                release.tag_name, asset_name
            )
        })?;

    Ok(Some(SelfUpdateRelease {
        version: latest_version,
        asset_name,
        download_url: asset.browser_download_url,
    }))
}

#[cfg(feature = "gold-release")]
fn parse_self_update_version(tag: &str) -> Result<semver::Version, String> {
    semver::Version::parse(tag.strip_prefix('v').unwrap_or(tag))
        .map_err(|err| format!("failed to parse release version {tag}: {err}"))
}

#[cfg(feature = "gold-release")]
fn current_self_update_asset_name(version: &semver::Version) -> Option<String> {
    self_update_asset_name_for(version, env::consts::OS, env::consts::ARCH)
}

#[cfg(feature = "gold-release")]
fn self_update_asset_name_for(version: &semver::Version, os: &str, arch: &str) -> Option<String> {
    let os = match os {
        "macos" => "Darwin",
        "linux" => "Linux",
        _ => return None,
    };
    let arch = match arch {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        _ => return None,
    };
    Some(format!("nucleus-{version}-{os}-{arch}.tar.gz"))
}

#[cfg(feature = "gold-release")]
fn install_self_update(release: &SelfUpdateRelease) -> Result<(), String> {
    let target = Path::new(SELF_UPDATE_TARGET);
    let target_permissions = fs::metadata(target)
        .map_err(|err| format!("failed to stat {}: {err}", target.display()))?
        .permissions();
    let temp_dir = TempDir::new_in(USR_LOCAL_BIN)
        .map_err(|err| format!("failed to create temp dir in {USR_LOCAL_BIN}: {err}"))?;
    let archive_path = temp_dir.path().join(&release.asset_name);
    download_vendor_asset(&release.download_url, &archive_path, "av", None)?;
    unpack_bottle(&archive_path, temp_dir.path())?;

    let extracted = temp_dir.path().join("av");
    let metadata = fs::metadata(&extracted)
        .map_err(|err| format!("failed to stat {}: {err}", extracted.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "self-update archive for av {} did not contain an av binary",
            release.version
        ));
    }

    fs::set_permissions(&extracted, target_permissions)
        .map_err(|err| format!("failed to chmod {}: {err}", extracted.display()))?;
    fs::rename(&extracted, target).map_err(|err| {
        format!(
            "failed to replace {} with av {}: {err}",
            target.display(),
            release.version
        )
    })
}

#[cfg(feature = "gold-release")]
fn exec_self_update_restart() -> Result<(), String> {
    let mut command = Command::new(SELF_UPDATE_TARGET);
    for arg in env::args_os().skip(1) {
        command.arg(arg);
    }
    command.arg(SELF_UPDATE_DISABLE_FLAG);
    let err = command.exec();
    Err(format!("failed to exec {}: {err}", SELF_UPDATE_TARGET))
}

fn ensure_plan_parent_dirs(plan: &InstallPlan) -> Result<(), String> {
    let stable_parent = plan
        .stable_root
        .parent()
        .ok_or_else(|| format!("invalid stable root {}", plan.stable_root.display()))?;
    let install_parent = plan
        .install_root
        .parent()
        .ok_or_else(|| format!("invalid install root {}", plan.install_root.display()))?;
    fs::create_dir_all(stable_parent)
        .map_err(|err| format!("failed to create {}: {err}", stable_parent.display()))?;
    fs::create_dir_all(install_parent)
        .map_err(|err| format!("failed to create {}: {err}", install_parent.display()))?;
    fs::create_dir_all(&plan.tmp_root)
        .map_err(|err| format!("failed to create {}: {err}", plan.tmp_root.display()))?;
    Ok(())
}

fn install_package(
    config: &Config,
    plan: &InstallPlan,
    installs: &[InstalledFormula],
    changed_installs: &[InstalledFormula],
    rewrite_rules: &[RewriteRule],
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    if package_is_current(plan, installs, &config.bottle_tag)?
        && installed_formula_receipts_match_graph(plan, installs)?
    {
        return Ok(());
    }

    if plan.install_root.exists() && incremental_root_is_seeded(plan) {
        prepare_incremental_formula_update(plan, installs, changed_installs)?;
    } else {
        prepare_clean_install_root(plan)?;
    }
    let installs_to_write = if incremental_root_is_seeded(plan) {
        changed_installs
    } else {
        installs
    };
    let results: Vec<Result<(), String>> = installs_to_write
        .par_iter()
        .map(|install| install_formula(config, plan, install, rewrite_rules, progress))
        .collect();
    for result in results {
        result?;
    }
    Ok(())
}

fn installed_formula_receipts_match_graph(
    plan: &InstallPlan,
    installs: &[InstalledFormula],
) -> Result<bool, String> {
    let receipts_dir = plan.install_root.join(RECEIPTS_DIR);
    let entries = match fs::read_dir(&receipts_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(installs.is_empty()),
        Err(err) => return Err(format!("failed to read {}: {err}", receipts_dir.display())),
    };
    let expected = installs
        .iter()
        .map(|install| install.spec.name.as_str())
        .collect::<HashSet<_>>();
    for entry in entries {
        let entry =
            entry.map_err(|err| format!("failed to read {}: {err}", receipts_dir.display()))?;
        if entry.path().extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }
        let Some(receipt) = load_install_receipt(&entry.path())? else {
            continue;
        };
        if !expected.contains(receipt.formula.as_str()) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn install_dependency_formulas(
    config: &Config,
    plan: &InstallPlan,
    installs: &[InstalledFormula],
    changed_installs: &[InstalledFormula],
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    if installs.is_empty() {
        prepare_vendor_root_area(plan)?;
        return Ok(());
    }

    let rewrite_rules = build_rewrite_rules(plan, installs);
    install_package(
        config,
        plan,
        installs,
        changed_installs,
        &rewrite_rules,
        progress,
    )?;
    run_package_post_install(plan, installs, &managed_bin_root())
}

fn incremental_root_is_seeded(plan: &InstallPlan) -> bool {
    plan.install_root.is_dir() && plan.root_receipt_path().is_file()
}

fn prepare_incremental_formula_update(
    plan: &InstallPlan,
    installs: &[InstalledFormula],
    changed_installs: &[InstalledFormula],
) -> Result<(), String> {
    let new_names = installs
        .iter()
        .map(|install| install.spec.name.as_str())
        .collect::<HashSet<_>>();
    let changed_names = changed_installs
        .iter()
        .map(|install| install.spec.name.as_str())
        .collect::<HashSet<_>>();
    let receipts_dir = plan.install_root.join(RECEIPTS_DIR);
    let entries = match fs::read_dir(&receipts_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("failed to read {}: {err}", receipts_dir.display())),
    };
    for entry in entries {
        let entry =
            entry.map_err(|err| format!("failed to read {}: {err}", receipts_dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }
        let Some(receipt) = load_install_receipt(&path)? else {
            continue;
        };
        if changed_names.contains(receipt.formula.as_str())
            || !new_names.contains(receipt.formula.as_str())
        {
            remove_owned_paths(&plan.install_root, &receipt.owned_paths)?;
            remove_path(&path)?;
        }
    }
    Ok(())
}

fn dependencies_are_current(
    plan: &InstallPlan,
    installs: &[InstalledFormula],
    vendor_installs: &[VendorInstall],
    config: &Config,
) -> Result<bool, String> {
    if installs.is_empty() && vendor_installs.is_empty() {
        return Ok(
            plan.install_root.is_dir() && installed_formula_receipts_match_graph(plan, installs)?
        );
    }

    if !installs.is_empty() && !package_is_current(plan, installs, &config.bottle_tag)? {
        return Ok(false);
    }
    if !installed_formula_receipts_match_graph(plan, installs)? {
        return Ok(false);
    }

    vendor_dependencies_are_current(plan, vendor_installs)
}

fn vendor_root_is_current(
    plan: &InstallPlan,
    install: &VendorInstall,
    installs: &[InstalledFormula],
    bottle_tag: &str,
) -> Result<bool, String> {
    if !plan.install_root.is_dir() {
        return Ok(false);
    }
    if !installs.is_empty() && !package_is_current(plan, installs, bottle_tag)? {
        return Ok(false);
    }
    let Some(receipt) = load_package_receipt(&plan.root_receipt_path())? else {
        return Ok(false);
    };
    if receipt.package_name != plan.package_name
        || receipt.version != install.version.to_string()
        || receipt.source
            != (PackageReceiptSource::Vendor {
                vendor_name: install.package.name.to_string(),
            })
    {
        return Ok(false);
    }
    Ok(declared_root_executables_exist(
        &plan.install_root,
        install.package.executables.iter().copied(),
    ))
}

fn npm_root_is_current(
    plan: &InstallPlan,
    executable: &str,
    version: &semver::Version,
    installs: &[InstalledFormula],
    bottle_tag: &str,
) -> Result<bool, String> {
    if !plan.install_root.is_dir() {
        return Ok(false);
    }
    if !installs.is_empty() && !package_is_current(plan, installs, bottle_tag)? {
        return Ok(false);
    }
    let Some(receipt) = load_package_receipt(&plan.root_receipt_path())? else {
        return Ok(false);
    };
    if receipt.package_name != plan.package_name
        || receipt.version != version.to_string()
        || !matches!(receipt.source, PackageReceiptSource::Npm { .. })
    {
        return Ok(false);
    }
    Ok(declared_root_executables_exist(
        &plan.install_root,
        [executable],
    ))
}

fn pip_root_is_current(
    plan: &InstallPlan,
    version: &str,
    installs: &[InstalledFormula],
    bottle_tag: &str,
) -> Result<bool, String> {
    if !plan.install_root.is_dir() {
        return Ok(false);
    }
    if !installs.is_empty() && !package_is_current(plan, installs, bottle_tag)? {
        return Ok(false);
    }
    let Some(receipt) = load_package_receipt(&plan.root_receipt_path())? else {
        return Ok(false);
    };
    if receipt.package_name != plan.package_name
        || receipt.version != version
        || !matches!(receipt.source, PackageReceiptSource::Pip { .. })
    {
        return Ok(false);
    }
    if !plan.install_root.join("venv").join("pyvenv.cfg").is_file() {
        return Ok(false);
    }
    let manifest = load_root_executable_manifest(&plan.root_executables_manifest_path())?;
    Ok(declared_root_executables_exist(
        &plan.install_root,
        manifest.stubs.iter().map(String::as_str),
    ))
}

fn cask_binary_target(binary: &EmbeddedCaskBinary) -> Result<&str, String> {
    binary
        .target
        .as_deref()
        .or_else(|| {
            Path::new(&binary.source)
                .file_name()
                .and_then(OsStr::to_str)
        })
        .ok_or_else(|| format!("invalid cask binary path {}", binary.source))
}

fn cask_binary_names(cask: &EmbeddedCaskMetadata) -> Vec<String> {
    cask.binaries
        .iter()
        .filter_map(|binary| cask_binary_target(binary).ok().map(str::to_string))
        .collect()
}

fn cask_root_is_current(
    plan: &InstallPlan,
    cask: &EmbeddedCaskMetadata,
    installs: &[InstalledFormula],
    bottle_tag: &str,
) -> Result<bool, String> {
    if !plan.install_root.is_dir() {
        return Ok(false);
    }
    if !installs.is_empty() && !package_is_current(plan, installs, bottle_tag)? {
        return Ok(false);
    }
    let Some(receipt) = load_package_receipt(&plan.root_receipt_path())? else {
        return Ok(false);
    };
    if receipt.package_name != plan.package_name
        || receipt.version != cask.version
        || !matches!(receipt.source, PackageReceiptSource::Cask { .. })
    {
        return Ok(false);
    }
    Ok(declared_root_executables_exist(
        &plan.install_root,
        cask_binary_names(cask).iter().map(String::as_str),
    ))
}

fn isotope_root_is_current(
    plan: &InstallPlan,
    isotope: &IsotopePackageData,
) -> Result<bool, String> {
    if !plan.install_root.is_dir() {
        return Ok(false);
    }
    let Some(receipt) = load_package_receipt(&plan.root_receipt_path())? else {
        return Ok(false);
    };
    if receipt.package_name != plan.package_name
        || receipt.version != isotope.version
        || !matches!(receipt.source, PackageReceiptSource::Isotope { .. })
    {
        return Ok(false);
    }
    let manifest = load_root_executable_manifest(&plan.root_executables_manifest_path())?;
    Ok(declared_root_executables_exist(
        &plan.install_root,
        manifest.stubs.iter().map(String::as_str),
    ))
}

fn install_cask_root(
    plan: &InstallPlan,
    cask_name: &str,
    cask: &EmbeddedCaskMetadata,
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    let tmp_dir = TempDir::new_in(&plan.tmp_root)
        .map_err(|err| format!("failed to create temp dir for {cask_name}: {err}"))?;
    let archive_path = tmp_dir.path().join(vendor_archive_name(&cask.url));
    download_cask_archive(cask_name, cask, &archive_path, progress)?;
    if let Some(progress) = progress {
        progress.begin_install_phase();
        progress.log("unpacking archive");
    }
    let unpack_root = tmp_dir.path().join("unpacked");
    fs::create_dir_all(&unpack_root)
        .map_err(|err| format!("failed to create {}: {err}", unpack_root.display()))?;
    unpack_cask_payload(&archive_path, &unpack_root, cask_name, cask)?;

    let bin_root = plan.install_root.join("bin");
    fs::create_dir_all(&bin_root)
        .map_err(|err| format!("failed to create {}: {err}", bin_root.display()))?;
    for binary in &cask.binaries {
        let source_path = unpack_root.join(&binary.source);
        if !source_path.is_file() {
            return Err(format!(
                "cask {cask_name} expected {} in downloaded archive",
                source_path.display()
            ));
        }
        let destination = bin_root.join(cask_binary_target(binary)?);
        fs::copy(&source_path, &destination).map_err(|err| {
            format!(
                "failed to copy {} to {}: {err}",
                source_path.display(),
                destination.display()
            )
        })?;
        let mut permissions = fs::metadata(&destination)
            .map_err(|err| format!("failed to stat {}: {err}", destination.display()))?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&destination, permissions)
            .map_err(|err| format!("failed to chmod {}: {err}", destination.display()))?;
    }
    Ok(())
}

fn ensure_cask_install_metadata(
    cask_name: &str,
    cask: &EmbeddedCaskMetadata,
) -> Result<(), String> {
    if cask.version.trim().is_empty() {
        return Err(format!(
            "cask {cask_name} is missing version metadata in the package database"
        ));
    }
    if cask.url.trim().is_empty() {
        return Err(format!(
            "cask {cask_name} is missing archive URL metadata in the package database"
        ));
    }
    if cask.sha256.trim().is_empty() {
        return Err(format!(
            "cask {cask_name} is missing sha256 metadata in the package database"
        ));
    }
    Ok(())
}

fn install_isotope_root(
    plan: &InstallPlan,
    isotope: &IsotopePackageData,
    dependency_installs: &[InstalledFormula],
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    if isotope_root_is_current(plan, isotope)? {
        return Ok(());
    }

    let archive_url = isotope
        .archive_url
        .as_deref()
        .ok_or_else(|| format!("isotope {} has no archive URL", isotope.name))?;
    let tmp_dir = TempDir::new_in(&plan.tmp_root)
        .map_err(|err| format!("failed to create temp dir for {}: {err}", isotope.name))?;
    let archive_path = tmp_dir.path().join(vendor_archive_name(archive_url));
    download_vendor_asset(archive_url, &archive_path, &isotope.name, progress)?;
    if let Some(progress) = progress {
        progress.begin_install_phase();
        progress.log("unpacking isotope archive");
    }
    let unpack_root = tmp_dir.path().join("unpacked");
    fs::create_dir_all(&unpack_root)
        .map_err(|err| format!("failed to create {}: {err}", unpack_root.display()))?;
    unpack_vendor_archive(&archive_path, &unpack_root, &isotope.name)?;
    let isotope_root = resolve_isotope_archive_root(&unpack_root)?;
    let rules = build_rewrite_rules(plan, dependency_installs);
    relocate_tree(
        &isotope_root,
        &plan.stable_root,
        &isotope.name,
        &rules,
        progress,
    )?;
    stage_root_formula(&plan.install_root, &isotope_root, true)
}

fn resolve_isotope_archive_root(unpack_root: &Path) -> Result<PathBuf, String> {
    let mut entries = fs::read_dir(unpack_root)
        .map_err(|err| format!("failed to read {}: {err}", unpack_root.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("failed to read {}: {err}", unpack_root.display()))?;
    if entries
        .iter()
        .any(|entry| isotope_archive_top_level_entry_is_install_layout(&entry.file_name()))
    {
        return Ok(unpack_root.to_path_buf());
    }
    if entries.len() == 1 {
        let path = entries.remove(0).path();
        if path.is_dir() {
            return Ok(path);
        }
    }
    Ok(unpack_root.to_path_buf())
}

fn isotope_archive_top_level_entry_is_install_layout(name: &OsStr) -> bool {
    matches!(
        name.as_bytes(),
        b".bottle"
            | b".pkg"
            | b"bin"
            | b"etc"
            | b"include"
            | b"lib"
            | b"libexec"
            | b"sbin"
            | b"share"
            | b"ssl"
    )
}

fn download_cask_archive(
    cask_name: &str,
    cask: &EmbeddedCaskMetadata,
    destination: &Path,
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    if let Some(progress) = progress {
        progress.begin_download_phase();
    }
    let response = ureq::get(&cask.url)
        .set("User-Agent", USER_AGENT)
        .call()
        .map_err(|err| match err {
            UreqError::Status(code, _) => {
                format!("failed to download cask archive for {cask_name}: http {code}")
            }
            UreqError::Transport(err) => {
                format!("failed to download cask archive for {cask_name}: {err}")
            }
        })?;
    if let Some(progress) = progress {
        progress.add_download_total(
            response
                .header("Content-Length")
                .and_then(|value| value.parse::<u64>().ok()),
        );
    }
    let mut reader = response.into_reader();
    let mut file = File::create(destination)
        .map_err(|err| format!("failed to create {}: {err}", destination.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 32 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|err| format!("failed to read cask archive for {cask_name}: {err}"))?;
        if count == 0 {
            break;
        }
        file.write_all(&buffer[..count])
            .map_err(|err| format!("failed to write {}: {err}", destination.display()))?;
        if let Some(progress) = progress {
            progress.advance_download(count as u64);
        }
        hasher.update(&buffer[..count]);
    }
    let actual = format!("{:x}", hasher.finalize());
    if actual != cask.sha256 {
        return Err(format!(
            "sha256 mismatch for cask {cask_name}: expected {}, got {}",
            cask.sha256, actual
        ));
    }
    Ok(())
}

fn install_vendor_dependencies(
    plan: &InstallPlan,
    graph: &[FormulaSpec],
    vendor_installs: &[VendorInstall],
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    for vendor_install in vendor_installs {
        install_vendor_root(plan, graph, vendor_install, progress)?;
        write_package_receipt(
            &plan.receipt_path(vendor_install.package.name),
            &PackageReceipt {
                package_name: vendor_install.package.name.to_string(),
                version: vendor_install.version.to_string(),
                source: PackageReceiptSource::Vendor {
                    vendor_name: vendor_install.package.name.to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )?;
    }
    Ok(())
}

fn reinstall_vendor_dependency_tree(
    config: &Config,
    plan: &InstallPlan,
    installs: &[InstalledFormula],
    graph: &[FormulaSpec],
    vendor_installs: &[VendorInstall],
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    let downloads = if graph.is_empty() {
        None
    } else {
        Some(download_bottles(graph, &plan.tmp_root, progress)?)
    };
    let installs = if let Some(downloads) = downloads.as_ref() {
        inspect_keg_dirs(graph, downloads)?
    } else {
        installs.to_vec()
    };
    prepare_vendor_root_area(plan)?;
    install_dependency_formulas(config, plan, &installs, &installs, progress)?;
    drop(downloads);
    install_vendor_dependencies(plan, graph, vendor_installs, progress)
}

fn install_time_commands_are_usable<const N: usize>(
    plan: &InstallPlan,
    graph: &[FormulaSpec],
    executables: [&str; N],
    progress: Option<&InstallProgress>,
) -> Result<bool, String> {
    for executable in executables {
        if install_time_command_is_usable(plan, graph, executable)? {
            continue;
        }
        if let Some(progress) = progress {
            progress.log(format!("{executable} runtime probe failed"));
        }
        return Ok(false);
    }
    Ok(true)
}

fn install_time_command_is_usable(
    plan: &InstallPlan,
    graph: &[FormulaSpec],
    executable: &str,
) -> Result<bool, String> {
    let Some(path) = resolve_install_time_command(plan, graph, executable) else {
        return Ok(false);
    };
    let status = Command::new(&path)
        .arg("--version")
        .env("PATH", build_install_path(plan, graph))
        .env("TMPDIR", &plan.tmp_root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("failed to probe {}: {err}", path.display()))?;
    Ok(status.success())
}

fn resolve_dependency_install_state(
    graph: &[FormulaSpec],
    plan: &InstallPlan,
    bottle_tag: &str,
    tmp_root: &Path,
    progress: Option<&InstallProgress>,
) -> Result<DependencyInstallState, String> {
    if graph.is_empty() {
        return Ok(DependencyInstallState {
            _downloads: HashMap::new(),
            installs: Vec::new(),
            changed_installs: Vec::new(),
        });
    }

    let mut reusable_installs = Vec::new();
    let mut changed_specs = Vec::new();
    let can_reuse = incremental_root_is_seeded(plan);
    for spec in graph {
        if can_reuse && let Some(receipt) = formula_spec_receipt_is_current(plan, spec, bottle_tag)?
        {
            reusable_installs.push(InstalledFormula {
                spec: spec.clone(),
                keg_dir_name: receipt.version,
                archive_path: PathBuf::new(),
            });
            continue;
        }
        changed_specs.push(spec.clone());
    }

    let downloads = download_bottles(&changed_specs, tmp_root, progress)?;
    let changed_installs = inspect_keg_dirs(&changed_specs, &downloads)?;
    let mut installs = reusable_installs;
    installs.extend(changed_installs.iter().cloned());
    let graph_order = graph
        .iter()
        .enumerate()
        .map(|(index, spec)| (spec.name.as_str(), index))
        .collect::<HashMap<_, _>>();
    installs.sort_by_key(|install| graph_order[install.spec.name.as_str()]);
    Ok(DependencyInstallState {
        _downloads: downloads,
        installs,
        changed_installs,
    })
}

fn prepare_vendor_root_area(plan: &InstallPlan) -> Result<(), String> {
    fs::create_dir_all(&plan.install_root)
        .map_err(|err| format!("failed to create {}: {err}", plan.install_root.display()))?;
    for entry in fs::read_dir(&plan.install_root)
        .map_err(|err| format!("failed to read {}: {err}", plan.install_root.display()))?
    {
        let entry = entry
            .map_err(|err| format!("failed to read {}: {err}", plan.install_root.display()))?;
        remove_path(&entry.path())?;
    }
    fs::create_dir_all(&plan.install_root)
        .map_err(|err| format!("failed to create {}: {err}", plan.install_root.display()))?;
    Ok(())
}

fn vendor_dependencies_are_current(
    plan: &InstallPlan,
    installs: &[VendorInstall],
) -> Result<bool, String> {
    for install in installs {
        if !vendor_dependency_is_current(plan, install)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn vendor_dependency_is_current(
    plan: &InstallPlan,
    install: &VendorInstall,
) -> Result<bool, String> {
    let Some(receipt) = load_package_receipt(&plan.receipt_path(install.package.name))? else {
        return Ok(false);
    };

    if receipt.package_name != install.package.name
        || receipt.version != install.version.to_string()
        || receipt.source
            != (PackageReceiptSource::Vendor {
                vendor_name: install.package.name.to_string(),
            })
    {
        return Ok(false);
    }

    Ok(declared_root_executables_exist(
        &plan.install_root,
        install.package.executables.iter().copied(),
    ))
}

fn install_vendor_root(
    plan: &InstallPlan,
    graph: &[FormulaSpec],
    vendor_install: &VendorInstall,
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    let strategy = (vendor_install.package.install)(&vendor_install.version);
    match strategy {
        vendor::InstallStrategy::NpmGlobal { package } => install_npm_global(
            plan,
            graph,
            vendor_install.package.name,
            &package,
            &vendor_install.version,
            progress,
        ),
        vendor::InstallStrategy::CopyFile {
            source,
            destination_dir,
            destination_name,
            mode,
            create_dirs,
        } => install_vendor_copy_file(
            plan,
            graph,
            vendor_install,
            &source,
            &destination_dir,
            destination_name.as_deref(),
            mode,
            &create_dirs,
            progress,
        ),
        vendor::InstallStrategy::CopyTree { source } => {
            install_vendor_copy_tree(plan, vendor_install, &source, progress)
        }
    }
}

fn install_npm_root(
    plan: &InstallPlan,
    graph: &[FormulaSpec],
    display_name: &str,
    npm_package: &str,
    version: &semver::Version,
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    install_npm_global(plan, graph, display_name, npm_package, version, progress)
}

fn resolve_installable_npm_version(
    plan: &InstallPlan,
    graph: &[FormulaSpec],
    display_name: &str,
    package: &str,
    requested_version: Option<&str>,
    progress: Option<&InstallProgress>,
) -> Result<semver::Version, String> {
    let npm = resolve_install_time_command(plan, graph, "npm")
        .ok_or_else(|| format!("package {display_name} requires npm in PATH"))?;
    let path = build_install_path(plan, graph);
    if let Some(version) = requested_version {
        return vendor::parse_semver(version, package);
    }
    let versions = vendor::npm_versions_desc(package)?;
    let Some(latest_version) = versions.first().cloned() else {
        return Err(format!(
            "no installable npm release found for {display_name}"
        ));
    };
    let latest_error = probe_npm_install_version(
        plan,
        &npm,
        &path,
        display_name,
        package,
        &latest_version,
        progress,
    )?;
    if latest_error.is_none() {
        return Ok(latest_version);
    }
    Err(render_npm_probe_error(display_name, latest_error.unwrap()))
}

fn install_pip_root(
    plan: &InstallPlan,
    graph: &[FormulaSpec],
    display_name: &str,
    package: &str,
    version: &str,
    progress: Option<&InstallProgress>,
) -> Result<Vec<String>, String> {
    if let Some(progress) = progress {
        progress.begin_install_phase();
        progress.log("creating virtualenv");
    }
    let python = resolve_install_time_command(plan, graph, "python3")
        .or_else(|| resolve_install_time_command(plan, graph, "python"))
        .ok_or_else(|| format!("package {display_name} requires python in PATH"))?;
    let env_root = TempDir::new_in(&plan.tmp_root).map_err(|err| {
        format!("failed to create temp dir for pip install of {display_name}: {err}")
    })?;
    let venv_root = plan.install_root.join("venv");

    let mut venv_command =
        build_pip_venv_command(&python, &venv_root, env_root.path(), plan, graph)?;
    let output = run_command_with_logged_output(
        &mut venv_command,
        progress,
        &format!("failed to create virtualenv for {display_name}"),
    )?;
    if !output.status.success() {
        return Err(match output.status.code() {
            Some(code) => format!(
                "virtualenv creation failed for {display_name} with exit code {code}{}",
                format_command_output_suffix(&output.lines)
            ),
            None => format!(
                "virtualenv creation terminated by signal for {display_name}{}",
                format_command_output_suffix(&output.lines)
            ),
        });
    }

    if let Some(progress) = progress {
        progress.log("running pip install");
    }
    let pip = venv_root.join("bin/pip");
    let mut pip_command =
        build_pip_install_command(&pip, package, version, env_root.path(), plan, graph)?;
    let output = run_command_with_logged_output(
        &mut pip_command,
        progress,
        &format!("failed to run pip for {display_name}"),
    )?;
    if !output.status.success() {
        return Err(match output.status.code() {
            Some(code) => format!(
                "pip install failed for {display_name} with exit code {code}{}",
                format_command_output_suffix(&output.lines)
            ),
            None => format!(
                "pip install terminated by signal for {display_name}{}",
                format_command_output_suffix(&output.lines)
            ),
        });
    }

    let entrypoints = discover_pip_entrypoints(&venv_root, package)?;
    write_pip_entrypoint_stubs(plan, &venv_root, &entrypoints)?;
    Ok(entrypoints)
}

fn install_npm_global(
    plan: &InstallPlan,
    graph: &[FormulaSpec],
    display_name: &str,
    package: &str,
    version: &semver::Version,
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    if let Some(progress) = progress {
        progress.begin_install_phase();
        progress.log("running npm install");
    }
    let npm = resolve_install_time_command(plan, graph, "npm")
        .ok_or_else(|| format!("package {display_name} requires npm in PATH"))?;
    let npm_env = TempDir::new_in(&plan.tmp_root).map_err(|err| {
        format!("failed to create temp dir for npm install of {display_name}: {err}")
    })?;
    let install_spec = vendor::npm_tarball_url(package, version)?;
    let mut command = build_sandboxed_npm_install_command(
        SANDBOX_EXEC,
        &npm,
        &install_spec,
        &plan.install_root,
        &plan.tmp_root,
        &npm_env,
        build_install_path(plan, graph),
        false,
    )?;
    let output = run_command_with_logged_output(
        &mut command,
        progress,
        &format!("failed to run npm for {display_name}"),
    )?;
    preserve_temp_dir_in_debug(npm_env);
    if output.status.success() {
        normalize_bundled_npm_extension_dependencies(&plan.install_root)?;
        return Ok(());
    }

    Err(match output.status.code() {
        Some(code) => format!(
            "npm install failed for {display_name} with exit code {code}{}",
            format_command_output_suffix(&output.lines)
        ),
        None => format!(
            "npm install terminated by signal for {display_name}{}",
            format_command_output_suffix(&output.lines)
        ),
    })
}

fn pip_env_paths(sandbox_root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    (
        sandbox_root.join("home"),
        sandbox_root.join("xdg-cache"),
        sandbox_root.join("pip-cache"),
    )
}

fn prepare_pip_env(sandbox_root: &Path) -> Result<(), String> {
    let (home, xdg_cache_home, pip_cache_dir) = pip_env_paths(sandbox_root);
    for dir in [&home, &xdg_cache_home, &pip_cache_dir] {
        fs::create_dir_all(dir)
            .map_err(|err| format!("failed to create {}: {err}", dir.display()))?;
    }
    Ok(())
}

fn build_pip_venv_command(
    python: impl AsRef<Path>,
    venv_root: &Path,
    sandbox_root: &Path,
    plan: &InstallPlan,
    graph: &[FormulaSpec],
) -> Result<Command, String> {
    prepare_pip_env(sandbox_root)?;
    let mut command = Command::new(python.as_ref());
    command
        .arg("-m")
        .arg("venv")
        .arg("--copies")
        .arg(venv_root)
        .current_dir(sandbox_root)
        .env("PATH", build_install_path(plan, graph))
        .env("TMPDIR", &plan.tmp_root)
        .env("HOME", sandbox_root.join("home"))
        .env("XDG_CACHE_HOME", sandbox_root.join("xdg-cache"))
        .env("PIP_CACHE_DIR", sandbox_root.join("pip-cache"))
        .env("PYTHONNOUSERSITE", "1");
    Ok(command)
}

fn build_pip_install_command(
    pip: &Path,
    package: &str,
    version: &str,
    sandbox_root: &Path,
    plan: &InstallPlan,
    graph: &[FormulaSpec],
) -> Result<Command, String> {
    prepare_pip_env(sandbox_root)?;
    let mut command = Command::new(pip);
    command
        .arg("install")
        .arg("--disable-pip-version-check")
        .arg("--no-input")
        .arg(format!("{package}=={version}"))
        .current_dir(sandbox_root)
        .env("PATH", build_install_path(plan, graph))
        .env("TMPDIR", &plan.tmp_root)
        .env("HOME", sandbox_root.join("home"))
        .env("XDG_CACHE_HOME", sandbox_root.join("xdg-cache"))
        .env("PIP_CACHE_DIR", sandbox_root.join("pip-cache"))
        .env("PYTHONNOUSERSITE", "1");
    Ok(command)
}

fn discover_pip_entrypoints(venv_root: &Path, package: &str) -> Result<Vec<String>, String> {
    let python = venv_root.join("bin/python");
    let mut command = Command::new(&python);
    command.arg("-c").arg(pip_entrypoint_discovery_script());
    command.arg(package);
    let output = command
        .output()
        .map_err(|err| format!("failed to inspect entrypoints for {package}: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if stderr.is_empty() {
            String::new()
        } else {
            format!(": {stderr}")
        };
        return Err(format!(
            "failed to inspect entrypoints for {package}{detail}"
        ));
    }
    let mut entrypoints: Vec<String> = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse entrypoints for {package}: {err}"))?;
    entrypoints.retain(|entrypoint| is_executable(&venv_root.join("bin").join(entrypoint)));
    entrypoints.sort();
    entrypoints.dedup();
    Ok(entrypoints)
}

fn pip_entrypoint_discovery_script() -> &'static str {
    r#"import importlib.metadata as md, json, sys
def norm(value):
    out = []
    last_sep = False
    for ch in value.lower():
        if ch.isalnum():
            out.append(ch)
            last_sep = False
        elif ch in '-_.':
            if not last_sep:
                out.append('-')
                last_sep = True
    return ''.join(out).strip('-')
want = norm(sys.argv[1])
for dist in md.distributions():
    name = dist.metadata.get('Name')
    if name and norm(name) == want:
        print(json.dumps(sorted({ep.name for ep in dist.entry_points if ep.group in {'console_scripts', 'gui_scripts'}})))
        raise SystemExit(0)
print('[]')
"#
}

fn write_pip_entrypoint_stubs(
    plan: &InstallPlan,
    venv_root: &Path,
    entrypoints: &[String],
) -> Result<(), String> {
    let bin_dir = plan.install_root.join("bin");
    fs::create_dir_all(&bin_dir)
        .map_err(|err| format!("failed to create {}: {err}", bin_dir.display()))?;
    for entrypoint in entrypoints {
        write_venv_stub(
            plan,
            &bin_dir.join(entrypoint),
            &venv_root.join("bin").join(entrypoint),
            venv_root,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_sandboxed_npm_install_command(
    sandbox_exec: impl AsRef<Path>,
    npm: impl AsRef<Path>,
    install_spec: &str,
    install_root: &Path,
    tmp_root: &Path,
    sandbox_root: &TempDir,
    path: OsString,
    dry_run: bool,
) -> Result<Command, String> {
    let sandbox_home = sandbox_root.path().join("home");
    let xdg_config_home = sandbox_root.path().join("xdg-config");
    let xdg_cache_home = sandbox_root.path().join("xdg-cache");
    let npm_cache = sandbox_root.path().join("npm-cache");
    let npm_userconfig = sandbox_root.path().join("npmrc");
    let sandbox_profile = sandbox_root.path().join("sandbox.sb");
    let ca_file = npm
        .as_ref()
        .parent()
        .and_then(Path::parent)
        .unwrap_or(install_root)
        .join(OPENSSL_CERT_PEM_DESTINATION);

    for dir in [&sandbox_home, &xdg_config_home, &xdg_cache_home, &npm_cache] {
        fs::create_dir_all(dir)
            .map_err(|err| format!("failed to create {}: {err}", dir.display()))?;
    }
    fs::write(&npm_userconfig, b"" as &[u8])
        .map_err(|err| format!("failed to create {}: {err}", npm_userconfig.display()))?;
    fs::write(&sandbox_profile, npm_install_sandbox_profile(tmp_root))
        .map_err(|err| format!("failed to write {}: {err}", sandbox_profile.display()))?;

    let mut command = if should_bypass_npm_install_sandbox() {
        Command::new(npm.as_ref())
    } else {
        let mut command = Command::new(sandbox_exec.as_ref());
        command.arg("-f").arg(&sandbox_profile).arg(npm.as_ref());
        command
    };
    command
        .arg("install")
        .arg("-g")
        .args(dry_run.then_some("--dry-run"))
        .arg("--prefix")
        .arg(install_root)
        .arg(install_spec)
        .env("PATH", path)
        .env("HOME", &sandbox_home)
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("XDG_CACHE_HOME", &xdg_cache_home)
        .env("NPM_CONFIG_CACHE", &npm_cache)
        .env("NPM_CONFIG_USERCONFIG", &npm_userconfig)
        .env("NPM_CONFIG_CAFILE", &ca_file)
        .env("NODE_EXTRA_CA_CERTS", &ca_file)
        .env("TMPDIR", tmp_root)
        .current_dir(sandbox_root.path());
    Ok(command)
}

fn should_bypass_npm_install_sandbox() -> bool {
    cfg!(test) && env::var_os("CODEX_CI").is_some()
}

struct NpmProbeError {
    status: std::process::ExitStatus,
    lines: Vec<String>,
}

fn render_npm_probe_error(display_name: &str, error: NpmProbeError) -> String {
    match error.status.code() {
        Some(code) => format!(
            "npm install failed for {display_name} with exit code {code}{}",
            format_command_output_suffix(&error.lines)
        ),
        None => format!(
            "npm install terminated by signal for {display_name}{}",
            format_command_output_suffix(&error.lines)
        ),
    }
}

fn probe_npm_install_version(
    plan: &InstallPlan,
    npm: &Path,
    path: &OsString,
    display_name: &str,
    package: &str,
    version: &semver::Version,
    progress: Option<&InstallProgress>,
) -> Result<Option<NpmProbeError>, String> {
    let npm_env = TempDir::new_in(&plan.tmp_root).map_err(|err| {
        format!("failed to create temp dir for npm install of {display_name}: {err}")
    })?;
    let probe_root = TempDir::new_in(&plan.tmp_root).map_err(|err| {
        format!("failed to create temp dir for npm install of {display_name}: {err}")
    })?;
    for dir in ["bin", "lib"] {
        fs::create_dir_all(probe_root.path().join(dir)).map_err(|err| {
            format!(
                "failed to create {} for npm install of {display_name}: {err}",
                probe_root.path().join(dir).display()
            )
        })?;
    }
    let install_spec = vendor::npm_tarball_url(package, version)?;
    let mut command = build_sandboxed_npm_install_command(
        SANDBOX_EXEC,
        npm,
        &install_spec,
        probe_root.path(),
        &plan.tmp_root,
        &npm_env,
        path.clone(),
        true,
    )?;
    let output = run_command_with_logged_output(
        &mut command,
        progress,
        &format!("failed to run npm for {display_name}"),
    )?;
    preserve_temp_dir_in_debug(npm_env);
    preserve_temp_dir_in_debug(probe_root);
    if output.status.success() {
        return Ok(None);
    }
    Ok(Some(NpmProbeError {
        status: output.status,
        lines: output.lines,
    }))
}

fn normalize_bundled_npm_extension_dependencies(install_root: &Path) -> Result<(), String> {
    let node_modules_root = install_root.join("lib/node_modules");
    let package_roots = match collect_npm_package_roots(&node_modules_root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(format!(
                "failed to read {}: {err}",
                node_modules_root.display()
            ));
        }
    };

    for package_root in package_roots {
        let root_node_modules = package_root.join("node_modules");
        for extension_node_modules in collect_nested_node_modules_dirs(&package_root.join("dist"))?
        {
            link_missing_npm_packages(&extension_node_modules, &root_node_modules)?;
        }
    }

    Ok(())
}

fn collect_npm_package_roots(node_modules_root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut package_roots = Vec::new();
    for entry in fs::read_dir(node_modules_root)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if entry.file_name().to_string_lossy().starts_with('@') {
            package_roots.extend(collect_npm_package_roots(&path)?);
            continue;
        }
        package_roots.push(path);
    }
    Ok(package_roots)
}

fn collect_nested_node_modules_dirs(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut node_modules_dirs = Vec::new();
    collect_nested_node_modules_dirs_inner(root, &mut node_modules_dirs)?;
    Ok(node_modules_dirs)
}

fn collect_nested_node_modules_dirs_inner(
    root: &Path,
    node_modules_dirs: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("failed to read {}: {err}", root.display())),
    };

    for entry in entries {
        let entry = entry.map_err(|err| format!("failed to read {}: {err}", root.display()))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if entry.file_name() == OsStr::new("node_modules") {
            node_modules_dirs.push(path);
            continue;
        }
        collect_nested_node_modules_dirs_inner(&path, node_modules_dirs)?;
    }

    Ok(())
}

fn link_missing_npm_packages(source_root: &Path, target_root: &Path) -> Result<(), String> {
    let entries = match fs::read_dir(source_root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("failed to read {}: {err}", source_root.display())),
    };

    for entry in entries {
        let entry =
            entry.map_err(|err| format!("failed to read {}: {err}", source_root.display()))?;
        let source = entry.path();
        let name = entry.file_name();
        let target = target_root.join(&name);

        if name.to_string_lossy().starts_with('@') {
            link_missing_npm_packages(&source, &target)?;
            continue;
        }

        if target.exists() || fs::symlink_metadata(&target).is_ok() {
            continue;
        }

        fs::create_dir_all(target_root)
            .map_err(|err| format!("failed to create {}: {err}", target_root.display()))?;
        let relative_source = relative_path_from(
            target
                .parent()
                .ok_or_else(|| format!("failed to resolve parent of {}", target.display()))?,
            &source,
        );
        symlink(&relative_source, &target).map_err(|err| {
            format!(
                "failed to link {} -> {}: {err}",
                target.display(),
                relative_source.display()
            )
        })?;
    }

    Ok(())
}

fn npm_install_sandbox_profile(tmp_root: &Path) -> String {
    format!(
        r#"(version 1)
(allow default)
(deny file-read* (subpath "/Library"))
(deny file-write* (subpath "/Library"))
(deny file-write* (subpath "/System"))
(deny file-write* (subpath "/Applications"))
(deny file-write* (subpath "/etc"))
(deny file-read* (subpath "/Users"))
(deny file-write* (subpath "/Users"))
(allow file-read* (subpath "{}"))
(allow file-write* (subpath "{}"))
"#,
        escape_sandbox_path(tmp_root),
        escape_sandbox_path(tmp_root)
    )
}

fn escape_sandbox_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', r"\\")
        .replace('"', "\\\"")
}

#[allow(clippy::too_many_arguments)]
fn install_vendor_copy_file(
    plan: &InstallPlan,
    _graph: &[FormulaSpec],
    vendor_install: &VendorInstall,
    source: &str,
    destination_dir: &str,
    destination_name: Option<&str>,
    mode: u32,
    create_dirs: &[String],
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    let download_url = vendor_install.package.download_url.ok_or_else(|| {
        format!(
            "vendor package {} has no download URL",
            vendor_install.package.name
        )
    })?;
    let archive_url = download_url(&vendor_install.version);
    let tmp_dir = TempDir::new_in(&plan.tmp_root).map_err(|err| {
        format!(
            "failed to create temp dir for {}: {err}",
            vendor_install.package.name
        )
    })?;
    let archive_path = tmp_dir.path().join(vendor_archive_name(&archive_url));
    download_vendor_asset(
        &archive_url,
        &archive_path,
        vendor_install.package.name,
        progress,
    )?;
    if let Some(progress) = progress {
        progress.begin_install_phase();
        progress.log("unpacking archive");
    }
    let unpack_root = tmp_dir.path().join("unpacked");
    fs::create_dir_all(&unpack_root)
        .map_err(|err| format!("failed to create {}: {err}", unpack_root.display()))?;
    unpack_vendor_archive(&archive_path, &unpack_root, vendor_install.package.name)?;

    for dir in create_dirs {
        fs::create_dir_all(plan.install_root.join(dir)).map_err(|err| {
            format!(
                "failed to create {}: {err}",
                plan.install_root.join(dir).display()
            )
        })?;
    }

    let source_path = unpack_root.join(source);
    if !source_path.is_file() {
        return Err(format!(
            "vendor package {} expected {} in downloaded archive",
            vendor_install.package.name,
            source_path.display()
        ));
    }

    let destination_root = plan.install_root.join(destination_dir);
    fs::create_dir_all(&destination_root)
        .map_err(|err| format!("failed to create {}: {err}", destination_root.display()))?;
    let filename = destination_name
        .map(OsStr::new)
        .or_else(|| Path::new(source).file_name())
        .ok_or_else(|| format!("invalid vendor source path {source}"))?;
    let destination = destination_root.join(filename);
    fs::copy(&source_path, &destination).map_err(|err| {
        format!(
            "failed to copy {} to {}: {err}",
            source_path.display(),
            destination.display()
        )
    })?;
    let mut permissions = fs::metadata(&destination)
        .map_err(|err| format!("failed to stat {}: {err}", destination.display()))?
        .permissions();
    permissions.set_mode(mode);
    fs::set_permissions(&destination, permissions)
        .map_err(|err| format!("failed to chmod {}: {err}", destination.display()))
}

fn install_vendor_copy_tree(
    plan: &InstallPlan,
    vendor_install: &VendorInstall,
    source: &str,
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    let download_url = vendor_install.package.download_url.ok_or_else(|| {
        format!(
            "vendor package {} has no download URL",
            vendor_install.package.name
        )
    })?;
    let archive_url = download_url(&vendor_install.version);
    let tmp_dir = TempDir::new_in(&plan.tmp_root).map_err(|err| {
        format!(
            "failed to create temp dir for {}: {err}",
            vendor_install.package.name
        )
    })?;
    let archive_path = tmp_dir.path().join(vendor_archive_name(&archive_url));
    download_vendor_asset(
        &archive_url,
        &archive_path,
        vendor_install.package.name,
        progress,
    )?;
    if let Some(progress) = progress {
        progress.begin_install_phase();
        progress.log("unpacking archive");
    }
    let unpack_root = tmp_dir.path().join("unpacked");
    fs::create_dir_all(&unpack_root)
        .map_err(|err| format!("failed to create {}: {err}", unpack_root.display()))?;
    unpack_vendor_archive(&archive_path, &unpack_root, vendor_install.package.name)?;

    let source_root = unpack_root.join(source);
    if !source_root.is_dir() {
        return Err(format!(
            "vendor package {} expected {} in downloaded archive",
            vendor_install.package.name,
            source_root.display()
        ));
    }

    stage_root_formula(&plan.install_root, &source_root, true)
}

fn package_is_current(
    plan: &InstallPlan,
    installs: &[InstalledFormula],
    bottle_tag: &str,
) -> Result<bool, String> {
    if !plan.install_root.is_dir() {
        return Ok(false);
    }

    for install in installs {
        if !receipt_is_current(plan, install, bottle_tag)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn receipt_is_current(
    plan: &InstallPlan,
    install: &InstalledFormula,
    bottle_tag: &str,
) -> Result<bool, String> {
    let Some(receipt) = load_install_receipt(&plan.receipt_path(&install.spec.name))? else {
        return Ok(false);
    };
    Ok(receipt.formula == install.spec.name
        && receipt.version == install.keg_dir_name
        && receipt.bottle_sha256 == install.spec.bottle_sha256
        && receipt.bottle_tag == bottle_tag)
}

fn formula_spec_receipt_is_current(
    plan: &InstallPlan,
    spec: &FormulaSpec,
    bottle_tag: &str,
) -> Result<Option<InstallReceipt>, String> {
    let Some(receipt) = load_install_receipt(&plan.receipt_path(&spec.name))? else {
        return Ok(None);
    };
    if receipt.formula == spec.name
        && receipt.bottle_sha256 == spec.bottle_sha256
        && receipt.bottle_tag == bottle_tag
        && !receipt.owned_paths.is_empty()
    {
        return Ok(Some(receipt));
    }
    Ok(None)
}

fn prepare_clean_install_root(plan: &InstallPlan) -> Result<(), String> {
    if plan.install_root.exists() {
        remove_path(&plan.install_root)?;
    }
    fs::create_dir_all(&plan.install_root)
        .map_err(|err| format!("failed to create {}: {err}", plan.install_root.display()))?;
    Ok(())
}

fn activate_install(plan: &InstallPlan) -> Result<(), String> {
    if plan.install_root == plan.stable_root {
        return Ok(());
    }

    if plan.stable_root.exists() {
        remove_path(&plan.stable_root)?;
    }
    fs::rename(&plan.install_root, &plan.stable_root).map_err(|err| {
        format!(
            "failed to move {} to {}: {err}",
            plan.install_root.display(),
            plan.stable_root.display()
        )
    })?;

    Ok(())
}

fn uninstall_package(package_name: &str) -> Result<(), String> {
    ensure_package_installed(&opt_pkg_root(), package_name)?;
    remove_existing_package_install(&opt_pkg_root(), package_name, &managed_bin_root())
}

fn ensure_package_installed(opt_root: &Path, package_name: &str) -> Result<(), String> {
    let install_root = package_install_root(opt_root, package_name)?;
    match fs::symlink_metadata(&install_root) {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Err(format!("package {package_name} is not installed"))
        }
        Err(err) => Err(format!("failed to stat {}: {err}", install_root.display())),
    }
}

fn prepare_install_target(
    opt_root: &Path,
    package_name: &str,
    intent: InstallIntent,
    bin_dir: &Path,
) -> Result<(), String> {
    let install_root = package_install_root(opt_root, package_name)?;
    match fs::symlink_metadata(&install_root) {
        Ok(_) if intent == InstallIntent::Reinstall => {
            remove_existing_package_install(opt_root, package_name, bin_dir)
        }
        Ok(_) if !install_root_has_valid_receipt(package_name, &install_root)? => {
            remove_existing_package_install(opt_root, package_name, bin_dir)
        }
        Ok(_) if intent == InstallIntent::Update => Ok(()),
        Ok(_) => Err(format!(
            "package {package_name} is already installed; use --force/-f to reinstall"
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("failed to stat {}: {err}", install_root.display())),
    }
}

fn install_root_has_valid_receipt(package_name: &str, install_root: &Path) -> Result<bool, String> {
    let Some(receipt) = load_package_receipt(&install_root.join(ROOT_RECEIPT))? else {
        return Ok(false);
    };
    Ok(receipt.package_name == package_name)
}

fn rollback_failed_install(
    opt_root: &Path,
    package_name: &str,
    bin_dir: &Path,
) -> Result<(), String> {
    let install_root = package_install_root(opt_root, package_name)?;
    match fs::symlink_metadata(&install_root) {
        Ok(_) => remove_existing_package_install(opt_root, package_name, bin_dir),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("failed to stat {}: {err}", install_root.display())),
    }
}

fn remove_path(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
    if metadata.file_type().is_symlink() || metadata.is_file() {
        fs::remove_file(path).map_err(|err| format!("failed to remove {}: {err}", path.display()))
    } else {
        fs::remove_dir_all(path)
            .map_err(|err| format!("failed to remove {}: {err}", path.display()))
    }
}

fn push_unique_string(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|entry| entry == &value) {
        values.push(value);
    }
}

fn current_bottle_tag() -> Result<String, String> {
    match env::consts::OS {
        "macos" => current_macos_bottle_tag(),
        "linux" => current_linux_bottle_tag(),
        other => Err(format!("unsupported operating system {other}")),
    }
}

fn resolve_formula_specs(
    formulas: &[String],
    config: &Config,
    allow_supported_post_install: bool,
) -> Result<Vec<FormulaSpec>, String> {
    let mut visiting = HashSet::new();
    let mut resolved = HashMap::new();
    let mut order = Vec::new();

    for formula in formulas {
        resolve_formula_spec(
            formula,
            config,
            allow_supported_post_install,
            &mut visiting,
            &mut resolved,
            &mut order,
        )?;
    }

    let mut specs = Vec::with_capacity(order.len());
    for name in order {
        let info = resolved
            .remove(&name)
            .ok_or_else(|| format!("missing resolved metadata for {name}"))?;
        let file = select_formula_bottle_file(&name, &info, &config.bottle_tag)?;
        specs.push(FormulaSpec {
            name,
            bottle_sha256: file.sha256.clone(),
            bottle_url: file.url.clone(),
        });
    }

    Ok(specs)
}

fn resolve_vendor_dependency_specs(
    dependencies: &[&str],
    config: &Config,
    allow_supported_post_install: bool,
) -> Result<ResolvedVendorDependencies, String> {
    let (mut formula_names, vendor_names) = partition_dependency_names(dependencies)?;
    let mut vendor_installs = Vec::with_capacity(vendor_names.len());
    for name in vendor_names {
        let package =
            vendor::get(&name).ok_or_else(|| format!("vendor package {name} is not registered"))?;
        let version = (package.version)()?;
        vendor_installs.push(VendorInstall { package, version });
    }
    append_vendor_npm_homebrew_dependencies(&mut formula_names, &vendor_installs);
    let formula_graph =
        resolve_formula_specs(&formula_names, config, allow_supported_post_install)?;

    Ok(ResolvedVendorDependencies {
        formula_graph,
        vendor_installs,
    })
}

fn partition_dependency_names(dependencies: &[&str]) -> Result<(Vec<String>, Vec<String>), String> {
    let mut visiting = HashSet::new();
    let mut resolved_vendors = HashSet::new();
    let mut formula_names = Vec::new();
    let mut vendor_names = Vec::new();
    for dependency in dependencies {
        collect_dependency_names(
            dependency,
            &mut visiting,
            &mut resolved_vendors,
            &mut formula_names,
            &mut vendor_names,
        )?;
    }
    Ok((formula_names, vendor_names))
}

fn collect_dependency_names(
    dependency: &str,
    visiting: &mut HashSet<String>,
    resolved_vendors: &mut HashSet<String>,
    formula_names: &mut Vec<String>,
    vendor_names: &mut Vec<String>,
) -> Result<(), String> {
    let Some(package) = vendor::get(dependency) else {
        push_unique_string(formula_names, dependency.to_string());
        return Ok(());
    };

    if resolved_vendors.contains(dependency) {
        return Ok(());
    }
    if !visiting.insert(dependency.to_string()) {
        return Err(format!("cyclic vendor dependency detected at {dependency}"));
    }

    for child in package.dependencies {
        collect_dependency_names(
            child,
            visiting,
            resolved_vendors,
            formula_names,
            vendor_names,
        )?;
    }

    visiting.remove(dependency);
    resolved_vendors.insert(dependency.to_string());
    vendor_names.push(dependency.to_string());
    Ok(())
}

fn current_linux_bottle_tag() -> Result<String, String> {
    match env::consts::ARCH {
        "aarch64" => Ok("arm64_linux".to_string()),
        "x86_64" => Ok("x86_64_linux".to_string()),
        other => Err(format!("unsupported Linux architecture {other}")),
    }
}

fn current_macos_bottle_tag() -> Result<String, String> {
    let arch_prefix = match env::consts::ARCH {
        "aarch64" => "arm64_",
        "x86_64" => "",
        other => return Err(format!("unsupported macOS architecture {other}")),
    };
    let release = macos_release_name(macos_major_version()?)
        .ok_or_else(|| "unsupported macOS release for Homebrew bottles".to_string())?;
    Ok(format!("{arch_prefix}{release}"))
}

fn macos_major_version() -> Result<u32, String> {
    let output = Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .map_err(|err| format!("failed to run sw_vers: {err}"))?;
    if !output.status.success() {
        return Err("sw_vers -productVersion failed".to_string());
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|err| format!("sw_vers returned non-utf8: {err}"))?;
    let major = stdout
        .trim()
        .split('.')
        .next()
        .ok_or_else(|| "sw_vers returned an empty version".to_string())?;
    major
        .parse::<u32>()
        .map_err(|err| format!("failed to parse macOS version {major}: {err}"))
}

fn macos_release_name(major: u32) -> Option<&'static str> {
    match major {
        11 => Some("big_sur"),
        12 => Some("monterey"),
        13 => Some("ventura"),
        14 => Some("sonoma"),
        15 => Some("sequoia"),
        16 | 26 => Some("tahoe"),
        _ => None,
    }
}

fn resolve_formula_spec(
    formula: &str,
    config: &Config,
    allow_supported_post_install: bool,
    visiting: &mut HashSet<String>,
    resolved: &mut HashMap<String, FormulaInfo>,
    order: &mut Vec<String>,
) -> Result<(), String> {
    let formula = canonical_formula_name(formula)?;
    if resolved.contains_key(&formula) {
        return Ok(());
    }
    if !visiting.insert(formula.clone()) {
        return Err(format!("cyclic formula dependency detected at {formula}"));
    }

    let info = fetch_formula_info(&formula)?;
    if info.disabled {
        return Err(format!("formula {formula} is disabled"));
    }
    if formula_skips_unknown_post_install(&formula, &info, allow_supported_post_install) {
        let mut stderr = std::io::stderr();
        warn_skipped_post_install(&formula, &mut stderr);
    }
    ensure_formula_has_bottle(&formula, &info, &config.bottle_tag)?;

    let dependencies = info.dependencies.clone();
    for dependency in dependencies {
        resolve_formula_spec(
            &dependency,
            config,
            allow_supported_post_install,
            visiting,
            resolved,
            order,
        )?;
    }

    visiting.remove(&formula);
    resolved.insert(formula.clone(), info);
    order.push(formula);
    Ok(())
}

fn ensure_formula_has_bottle(
    formula: &str,
    info: &FormulaInfo,
    bottle_tag: &str,
) -> Result<(), String> {
    let _ = select_formula_bottle_file(formula, info, bottle_tag)?;
    Ok(())
}

fn select_formula_bottle_file<'a>(
    formula: &str,
    info: &'a FormulaInfo,
    bottle_tag: &str,
) -> Result<&'a BottleFile, String> {
    let bottle = info
        .bottle
        .stable
        .as_ref()
        .ok_or_else(|| format!("formula {formula} has no stable bottle"))?;
    bottle
        .files
        .get(bottle_tag)
        .or_else(|| bottle.files.get("all"))
        .ok_or_else(|| format!("formula {formula} has no bottle for {bottle_tag} or all"))
}

fn formula_version_string(info: &FormulaInfo) -> String {
    if info.revision == 0 {
        info.versions.stable.clone()
    } else {
        format!("{}_{}", info.versions.stable, info.revision)
    }
}

fn fetch_formula_info(formula: &str) -> Result<FormulaInfo, String> {
    if let Some(info) = fetch_formula_info_by_api_name(formula, formula)? {
        return Ok(info);
    }
    let resolved = resolve_formula_api_alias(formula)?
        .ok_or_else(|| format!("failed to fetch formula metadata for {formula}: http 404"))?;
    fetch_formula_info_by_api_name(formula, &resolved)?
        .ok_or_else(|| format!("failed to fetch formula metadata for {formula}: http 404"))
}

fn formula_metadata_exists(formula: &str) -> Result<bool, String> {
    if fetch_formula_info_by_api_name(formula, formula)?.is_some() {
        return Ok(true);
    }
    Ok(resolve_formula_api_alias(formula)?.is_some())
}

fn fetch_formula_info_by_api_name(
    formula: &str,
    api_name: &str,
) -> Result<Option<FormulaInfo>, String> {
    fetch_optional_json(&format!("{}/{api_name}.json", formula_api_root()), || {
        format!("failed to fetch formula metadata for {formula}")
    })
}

fn resolve_formula_api_alias(formula: &str) -> Result<Option<String>, String> {
    let index = formula_alias_index()?;
    Ok(index.get(formula).cloned())
}

fn embedded_cask(cask: &str) -> Result<EmbeddedCaskMetadata, String> {
    let db = crate::cli::load_db()?;
    crate::cli::ensure_db_schema(&db)?;
    let canonical = canonical_cask_name(cask, &db);
    db.casks
        .get(&canonical)
        .cloned()
        .ok_or_else(|| format!("no embedded cask metadata found for {cask}"))
}

fn canonical_cask_name(cask: &str, db: &Db) -> String {
    cask_alias_index(db)
        .get(cask)
        .cloned()
        .unwrap_or_else(|| cask.to_string())
}

fn cask_alias_index(db: &Db) -> &'static HashMap<String, String> {
    CASK_ALIAS_INDEX.get_or_init(|| {
        let mut aliases = HashMap::new();
        for (name, metadata) in &db.casks {
            for alias in &metadata.aliases {
                aliases.entry(alias.clone()).or_insert_with(|| name.clone());
            }
        }
        aliases
    })
}

fn canonical_formula_name(formula: &str) -> Result<String, String> {
    Ok(formula_install_package_name_with_aliases(
        formula,
        formula_alias_index()?,
    ))
}

fn formula_install_package_name(formula: &str) -> Result<String, String> {
    Ok(canonical_formula_name_with_aliases(
        formula,
        formula_alias_index()?,
    ))
}

fn embedded_provider_install_package_name(package_name: &str) -> Result<Option<String>, String> {
    let db = crate::cli::load_db()?;
    crate::cli::ensure_db_schema(&db)?;
    let Some(provider) = db.entries.get(package_name) else {
        return Ok(None);
    };
    let Some(resolved) = crate::cli::parse_embedded_provider(provider)? else {
        return Ok(None);
    };
    Ok(Some(match resolved {
        EmbeddedPackage::Formula(formula) => formula_install_package_name(&formula)?,
        EmbeddedPackage::Cask(cask) => cask,
        EmbeddedPackage::NpmPackage(package) => npm_package_display_name(&package),
    }))
}

fn formula_install_package_name_with_aliases(
    formula: &str,
    aliases: &HashMap<String, String>,
) -> String {
    canonical_formula_name_with_aliases(formula, aliases)
}

fn canonical_formula_name_with_aliases(formula: &str, aliases: &HashMap<String, String>) -> String {
    aliases
        .get(formula)
        .cloned()
        .unwrap_or_else(|| formula.to_string())
}

fn formula_alias_index() -> Result<&'static HashMap<String, String>, String> {
    FORMULA_ALIAS_INDEX
        .get_or_init(build_formula_alias_index)
        .as_ref()
        .map_err(|err| err.clone())
}

fn build_formula_alias_index() -> Result<HashMap<String, String>, String> {
    Ok(collect_formula_aliases(formula_index_entries()?.clone()))
}

fn build_formula_index() -> Result<Vec<FormulaIndexEntry>, String> {
    let db = crate::cli::load_db()?;
    crate::cli::ensure_db_schema(&db)?;
    let mut entries = db
        .formulas
        .into_iter()
        .map(|(name, metadata)| FormulaIndexEntry {
            name,
            summary: metadata.summary,
            aliases: metadata.aliases,
            oldnames: metadata.oldnames,
            category: metadata.category,
            homepage: metadata.homepage,
            repository: metadata.repository,
            upstream_docs: metadata.upstream_docs,
            docs: metadata.docs,
            popularity: metadata.popularity,
            last_updated_at: metadata.last_updated_at,
            pulse_kind: metadata.pulse_kind,
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

fn collect_formula_aliases(entries: Vec<FormulaIndexEntry>) -> HashMap<String, String> {
    let mut aliases = HashMap::new();
    for entry in entries {
        for alias in entry.aliases.into_iter().chain(entry.oldnames) {
            aliases.entry(alias).or_insert_with(|| entry.name.clone());
        }
    }
    aliases
}

fn fetch_json<T, F>(url: &str, context: F) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
    F: FnOnce() -> String,
{
    let context = context();
    fetch_optional_json(url, || context.clone())?.ok_or_else(|| format!("{context}: http 404"))
}

fn fetch_optional_json<T, F>(url: &str, context: F) -> Result<Option<T>, String>
where
    T: serde::de::DeserializeOwned,
    F: FnOnce() -> String,
{
    let context = context();
    let response = match ureq::get(url).set("User-Agent", USER_AGENT).call() {
        Ok(response) => response,
        Err(UreqError::Status(404, _)) => return Ok(None),
        Err(UreqError::Status(code, _)) => return Err(format!("{context}: http {code}")),
        Err(UreqError::Transport(err)) => return Err(format!("{context}: {err}")),
    };
    let mut reader = response.into_reader();
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|err| format!("{context}: {err}"))?;
    let value = serde_json::from_slice(&bytes).map_err(|err| format!("{context}: {err}"))?;
    Ok(Some(value))
}

fn ambiguous_install_target_message(package: &str, executable_provider: &str) -> String {
    format!(
        "ambiguous install target '{package}': use `{BREW_PACKAGE_PREFIX}{package}` for the Homebrew \
package or `{executable_provider}` for the package that provides the `{package}` executable"
    )
}

fn formula_skips_unknown_post_install(
    formula: &str,
    info: &FormulaInfo,
    allow_supported_post_install: bool,
) -> bool {
    info.post_install_defined
        && !embedded_post_install_check_skip().contains(formula)
        && !(allow_supported_post_install && post_install_hooks::supports(formula))
}

fn skipped_post_install_message(formula: &str) -> String {
    format!("warning: skipping Homebrew post_install for {formula}; install may be incomplete")
}

fn warn_skipped_post_install<W: Write>(formula: &str, stderr: &mut W) {
    let _ = writeln!(stderr, "{}", skipped_post_install_message(formula));
}

fn download_bottles(
    specs: &[FormulaSpec],
    tmp_root: &Path,
    progress: Option<&InstallProgress>,
) -> Result<HashMap<String, DownloadedBottle>, String> {
    if let Some(progress) = progress {
        progress.begin_download_phase();
    }
    let results: Vec<Result<(String, DownloadedBottle), String>> = specs
        .par_iter()
        .map(|spec| {
            let tmp_dir = TempDir::new_in(tmp_root)
                .map_err(|err| format!("failed to create tmp dir for {}: {err}", spec.name))?;
            let archive_path = tmp_dir.path().join("bottle.tar.gz");
            download_bottle(spec, &archive_path, progress)?;
            Ok((
                spec.name.clone(),
                DownloadedBottle {
                    path: archive_path,
                    _tmp_dir: tmp_dir,
                },
            ))
        })
        .collect();

    let mut downloads = HashMap::with_capacity(specs.len());
    for result in results {
        let (formula, download) = result?;
        downloads.insert(formula, download);
    }
    Ok(downloads)
}

fn download_bottle(
    spec: &FormulaSpec,
    destination: &Path,
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    if let Some(progress) = progress {
        progress.begin_download_for(&spec.name);
    }
    let mut request = ureq::get(&spec.bottle_url).set("User-Agent", USER_AGENT);
    if let Some(repo) = ghcr_repo_from_blob_url(&spec.bottle_url) {
        let token = ghcr_bearer_token(repo)?;
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    let response = request.call().map_err(|err| match err {
        UreqError::Status(code, _) => {
            format!("failed to download bottle for {}: http {code}", spec.name)
        }
        UreqError::Transport(err) => {
            format!("failed to download bottle for {}: {err}", spec.name)
        }
    })?;
    if let Some(progress) = progress {
        progress.add_download_total_for(
            &spec.name,
            response
                .header("Content-Length")
                .and_then(|value| value.parse::<u64>().ok()),
        );
    }
    let mut reader = response.into_reader();
    let mut file = File::create(destination)
        .map_err(|err| format!("failed to create {}: {err}", destination.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 32 * 1024];

    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|err| format!("failed to read bottle for {}: {err}", spec.name))?;
        if count == 0 {
            break;
        }
        file.write_all(&buffer[..count])
            .map_err(|err| format!("failed to write {}: {err}", destination.display()))?;
        if let Some(progress) = progress {
            progress.advance_download_for(&spec.name, count as u64);
        }
        hasher.update(&buffer[..count]);
    }

    let actual = format!("{:x}", hasher.finalize());
    if actual != spec.bottle_sha256 {
        return Err(format!(
            "sha256 mismatch for {}: expected {}, got {}",
            spec.name, spec.bottle_sha256, actual
        ));
    }

    Ok(())
}

fn ghcr_repo_from_blob_url(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://ghcr.io/v2/")?;
    let (repo, _) = rest.split_once("/blobs/")?;
    Some(repo)
}

fn ghcr_bearer_token(repo: &str) -> Result<String, String> {
    let url = format!("https://ghcr.io/token?service=ghcr.io&scope=repository:{repo}:pull");
    let response: GhcrTokenResponse =
        fetch_json(&url, || format!("failed to fetch GHCR token for {repo}"))?;
    Ok(response.token)
}

fn inspect_keg_dirs(
    specs: &[FormulaSpec],
    downloads: &HashMap<String, DownloadedBottle>,
) -> Result<Vec<InstalledFormula>, String> {
    let results: Vec<Result<InstalledFormula, String>> = specs
        .par_iter()
        .map(|spec| {
            let bottle_path = downloads
                .get(&spec.name)
                .ok_or_else(|| format!("missing downloaded bottle for {}", spec.name))?;
            let keg_dir_name = archive_keg_dir_name(&bottle_path.path, &spec.name)?;
            Ok(InstalledFormula {
                spec: spec.clone(),
                keg_dir_name,
                archive_path: bottle_path.path.clone(),
            })
        })
        .collect();

    let mut installs = Vec::with_capacity(specs.len());
    for result in results {
        installs.push(result?);
    }
    Ok(installs)
}

fn archive_keg_dir_name(archive_path: &Path, formula: &str) -> Result<String, String> {
    let file = File::open(archive_path)
        .map_err(|err| format!("failed to open {}: {err}", archive_path.display()))?;
    let decoder = GzDecoder::new(BufReader::new(file));
    let mut archive = Archive::new(decoder);
    let mut entries = archive
        .entries()
        .map_err(|err| format!("failed to read {}: {err}", archive_path.display()))?;

    let Some(entry) = entries.next() else {
        return Err(format!("empty bottle archive: {}", archive_path.display()));
    };
    let entry =
        entry.map_err(|err| format!("failed to inspect {}: {err}", archive_path.display()))?;
    let path = entry
        .path()
        .map_err(|err| format!("invalid archive path in {}: {err}", archive_path.display()))?;
    let mut components = path.components();
    let first = components
        .next()
        .and_then(|component| component.as_os_str().to_str())
        .ok_or_else(|| format!("invalid top-level path in {}", archive_path.display()))?;
    let second = components
        .next()
        .and_then(|component| component.as_os_str().to_str())
        .ok_or_else(|| format!("missing keg directory in {}", archive_path.display()))?;
    if first != formula {
        return Err(format!(
            "unexpected bottle layout in {}: expected {formula}/..., found {first}/...",
            archive_path.display()
        ));
    }

    Ok(second.to_string())
}

fn build_rewrite_rules(plan: &InstallPlan, installs: &[InstalledFormula]) -> Vec<RewriteRule> {
    let mut rules = Vec::with_capacity(installs.len() * 5 + 2);
    let stable_root = plan.stable_root.to_string_lossy().to_string();
    let openssl_cert_destination = plan
        .stable_root
        .join(OPENSSL_CERT_PEM_DESTINATION)
        .to_string_lossy()
        .to_string();
    rules.push(RewriteRule {
        source: HOMEBREW_REPOSITORY_PLACEHOLDER.to_string(),
        destination: stable_root.clone(),
    });
    rules.push(RewriteRule {
        source: HOMEBREW_LIBRARY_PLACEHOLDER.to_string(),
        destination: plan
            .stable_root
            .join("Library")
            .to_string_lossy()
            .to_string(),
    });
    rules.push(RewriteRule {
        source: HOMEBREW_PERL_PLACEHOLDER.to_string(),
        destination: perl_placeholder_target(plan, installs),
    });
    if let Some(java_target) = java_placeholder_target(plan, installs) {
        rules.push(RewriteRule {
            source: HOMEBREW_JAVA_PLACEHOLDER.to_string(),
            destination: java_target,
        });
    }
    // OpenSSL's bundled cert path must land on our managed CA bundle, not /etc.
    rules.push(RewriteRule {
        source: format!("{RELOCATABLE_HOMEBREW_PREFIX}{OPENSSL_CERT_PEM_PATH}"),
        destination: openssl_cert_destination.clone(),
    });
    rules.push(RewriteRule {
        source: format!("{HOMEBREW_PREFIX_PLACEHOLDER}{OPENSSL_CERT_PEM_PATH}"),
        destination: openssl_cert_destination,
    });
    rules.push(RewriteRule {
        source: format!("{RELOCATABLE_HOMEBREW_PREFIX}/etc"),
        destination: "/etc".to_string(),
    });
    rules.push(RewriteRule {
        source: format!("{HOMEBREW_PREFIX_PLACEHOLDER}/etc"),
        destination: "/etc".to_string(),
    });

    for install in installs {
        let target = plan.stable_target_dir(&install.spec.name);
        let target = target.to_string_lossy().to_string();
        let formula_cellar = format!("{RELOCATABLE_HOMEBREW_PREFIX}/Cellar/{}", install.spec.name);
        let cellar = format!(
            "{}/Cellar/{}/{}",
            RELOCATABLE_HOMEBREW_PREFIX, install.spec.name, install.keg_dir_name
        );
        let placeholder_formula_cellar =
            format!("{HOMEBREW_CELLAR_PLACEHOLDER}/{}", install.spec.name);
        let placeholder_cellar = format!(
            "{HOMEBREW_CELLAR_PLACEHOLDER}/{}/{}",
            install.spec.name, install.keg_dir_name
        );
        let escaped_name = install.spec.name.replace('@', "\\@");

        rules.push(RewriteRule {
            source: format!("{cellar}/etc"),
            destination: "/etc".to_string(),
        });
        rules.push(RewriteRule {
            source: format!("{placeholder_cellar}/etc"),
            destination: "/etc".to_string(),
        });
        rules.push(RewriteRule {
            source: formula_cellar,
            destination: target.clone(),
        });
        rules.push(RewriteRule {
            source: cellar,
            destination: target.clone(),
        });
        rules.push(RewriteRule {
            source: placeholder_formula_cellar,
            destination: target.clone(),
        });
        rules.push(RewriteRule {
            source: placeholder_cellar,
            destination: target.clone(),
        });
        rules.push(RewriteRule {
            source: format!("{RELOCATABLE_HOMEBREW_PREFIX}/opt/{}", install.spec.name),
            destination: target.clone(),
        });
        rules.push(RewriteRule {
            source: format!("{HOMEBREW_PREFIX_PLACEHOLDER}/opt/{}", install.spec.name),
            destination: target.clone(),
        });
        if escaped_name != install.spec.name {
            let escaped_formula_cellar =
                format!("{RELOCATABLE_HOMEBREW_PREFIX}/Cellar/{escaped_name}");
            let escaped_placeholder_formula_cellar =
                format!("{HOMEBREW_CELLAR_PLACEHOLDER}/{escaped_name}");
            let escaped_placeholder_cellar = format!(
                "{HOMEBREW_CELLAR_PLACEHOLDER}/{}/{}",
                escaped_name, install.keg_dir_name
            );
            rules.push(RewriteRule {
                source: escaped_formula_cellar,
                destination: target.clone(),
            });
            rules.push(RewriteRule {
                source: escaped_placeholder_formula_cellar,
                destination: target.clone(),
            });
            rules.push(RewriteRule {
                source: format!("{escaped_placeholder_cellar}/etc"),
                destination: "/etc".to_string(),
            });
            rules.push(RewriteRule {
                source: escaped_placeholder_cellar,
                destination: target.clone(),
            });
            rules.push(RewriteRule {
                source: format!("{RELOCATABLE_HOMEBREW_PREFIX}/opt/{escaped_name}"),
                destination: target.clone(),
            });
            rules.push(RewriteRule {
                source: format!("{HOMEBREW_PREFIX_PLACEHOLDER}/opt/{escaped_name}"),
                destination: target,
            });
        }
    }

    rules.push(RewriteRule {
        source: HOMEBREW_PREFIX_PLACEHOLDER.to_string(),
        destination: stable_root,
    });
    rules.sort_by_key(|rule| std::cmp::Reverse(rule.source.len()));
    rules
}

fn perl_placeholder_target(plan: &InstallPlan, installs: &[InstalledFormula]) -> String {
    if installs.iter().any(|install| install.spec.name == "perl") {
        return plan
            .stable_target_dir("perl")
            .join("bin/perl")
            .to_string_lossy()
            .to_string();
    }

    if env::consts::OS == "macos" {
        for candidate in [
            "/usr/bin/perl5.34",
            "/usr/bin/perl5.30",
            "/usr/bin/perl5.18",
            "/usr/bin/perl",
        ] {
            if Path::new(candidate).exists() {
                return candidate.to_string();
            }
        }
    }

    "/usr/bin/perl".to_string()
}

fn java_placeholder_target(plan: &InstallPlan, installs: &[InstalledFormula]) -> Option<String> {
    let openjdk = installs.iter().find(|install| {
        install.spec.name == "openjdk" || install.spec.name.starts_with("openjdk@")
    })?;
    let java_home = if env::consts::OS == "macos" {
        plan.stable_target_dir(&openjdk.spec.name)
            .join("libexec/openjdk.jdk/Contents/Home")
    } else {
        plan.stable_target_dir(&openjdk.spec.name).join("libexec")
    };
    Some(java_home.to_string_lossy().to_string())
}

fn install_formula(
    config: &Config,
    plan: &InstallPlan,
    install: &InstalledFormula,
    rewrite_rules: &[RewriteRule],
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    if let Some(progress) = progress {
        progress.begin_install_phase_for(&install.spec.name);
    }
    let tmp_root = TempDir::new_in(&plan.tmp_root)
        .map_err(|err| format!("failed to create tmp dir for {}: {err}", install.spec.name))?;
    unpack_bottle(&install.archive_path, tmp_root.path())?;

    let formula_root = tmp_root.path().join(&install.spec.name);
    let keg_root = formula_root.join(&install.keg_dir_name);
    if !keg_root.is_dir() {
        return Err(format!(
            "bottle for {} did not unpack to {}",
            install.spec.name,
            keg_root.display()
        ));
    }

    relocate_tree(
        &keg_root,
        &plan.stable_target_dir(&install.spec.name),
        &install.spec.name,
        rewrite_rules,
        progress,
    )?;
    let owned_paths = stage_formula(plan, install, &keg_root)?;
    write_receipt_with_owned_paths(
        &plan.receipt_path(&install.spec.name),
        install,
        &config.bottle_tag,
        owned_paths,
    )
}

fn stage_formula(
    plan: &InstallPlan,
    install: &InstalledFormula,
    keg_root: &Path,
) -> Result<Vec<String>, String> {
    let keep_root_entries = install.spec.name == plan.root_formula;
    let owned_paths = collect_stageable_owned_paths(keg_root, keep_root_entries)?;
    let root_executables = if install.spec.name == plan.root_formula {
        Some(
            collect_root_executables(keg_root)?
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    stage_root_formula(&plan.install_root, keg_root, keep_root_entries)?;
    if let Some(root_executables) = root_executables {
        write_root_executable_manifest(&plan.root_executables_manifest_path(), &root_executables)?;
    }
    Ok(owned_paths)
}

fn stage_root_formula(
    target_root: &Path,
    keg_root: &Path,
    keep_root_entries: bool,
) -> Result<(), String> {
    let entries = fs::read_dir(keg_root)
        .map_err(|err| format!("failed to read {}: {err}", keg_root.display()))?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("failed to read {}: {err}", keg_root.display()))?;
        if !should_stage_root_entry(&entry, keep_root_entries)? {
            remove_path(&entry.path())?;
            continue;
        }
        let source = entry.path();
        let target = target_root.join(entry.file_name());
        merge_path_into(&source, &target)?;
    }
    Ok(())
}

fn should_stage_root_entry(entry: &fs::DirEntry, keep_root_entries: bool) -> Result<bool, String> {
    let name = entry.file_name();
    let name = name.to_string_lossy();
    if name == ".brew" {
        return Ok(false);
    }
    if keep_root_entries || name == ".bottle" {
        return Ok(true);
    }

    let file_type = entry
        .file_type()
        .map_err(|err| format!("failed to stat {}: {err}", entry.path().display()))?;
    Ok(file_type.is_dir())
}

#[cfg(test)]
fn write_receipt(path: &Path, install: &InstalledFormula, bottle_tag: &str) -> Result<(), String> {
    let receipt = InstallReceipt {
        formula: install.spec.name.clone(),
        version: install.keg_dir_name.clone(),
        bottle_sha256: install.spec.bottle_sha256.clone(),
        bottle_tag: bottle_tag.to_string(),
        owned_paths: Vec::new(),
    };
    write_install_receipt(path, &receipt)
}

fn write_receipt_with_owned_paths(
    path: &Path,
    install: &InstalledFormula,
    bottle_tag: &str,
    owned_paths: Vec<String>,
) -> Result<(), String> {
    let receipt = InstallReceipt {
        formula: install.spec.name.clone(),
        version: install.keg_dir_name.clone(),
        bottle_sha256: install.spec.bottle_sha256.clone(),
        bottle_tag: bottle_tag.to_string(),
        owned_paths,
    };
    write_install_receipt(path, &receipt)
}

fn write_install_receipt(path: &Path, receipt: &InstallReceipt) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(&receipt)
        .map_err(|err| format!("failed to serialize receipt for {}: {err}", receipt.formula))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    fs::write(path, data).map_err(|err| format!("failed to write {}: {err}", path.display()))
}

fn load_install_receipt(path: &Path) -> Result<Option<InstallReceipt>, String> {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };
    serde_json::from_slice(&data)
        .map(Some)
        .map_err(|err| format!("failed to parse {}: {err}", path.display()))
}

fn load_root_ownership_manifest(path: &Path) -> Result<Option<StubManifest>, String> {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };
    serde_json::from_slice(&data)
        .map(Some)
        .map_err(|err| format!("failed to parse {}: {err}", path.display()))
}

fn write_root_ownership_manifest(
    plan: &InstallPlan,
    owned_paths: Vec<String>,
) -> Result<(), String> {
    write_stub_manifest(
        &plan.root_ownership_manifest_path(),
        &StubManifest { stubs: owned_paths },
    )
}

fn collect_owned_paths(root: &Path) -> Result<HashSet<String>, String> {
    let mut paths = HashSet::new();
    collect_owned_paths_inner(root, root, &mut paths)?;
    Ok(paths)
}

fn collect_owned_paths_inner(
    root: &Path,
    path: &Path,
    paths: &mut HashSet<String>,
) -> Result<(), String> {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };
    for entry in entries {
        let entry = entry.map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        let child = entry.path();
        let relative = child
            .strip_prefix(root)
            .map_err(|err| format!("failed to relativize {}: {err}", child.display()))?;
        if relative.starts_with(".pkg") {
            continue;
        }
        if entry
            .file_type()
            .map_err(|err| format!("failed to stat {}: {err}", child.display()))?
            .is_dir()
        {
            collect_owned_paths_inner(root, &child, paths)?;
        } else {
            paths.insert(normalize_owned_path(relative)?);
        }
    }
    Ok(())
}

fn sorted_owned_path_difference(before: HashSet<String>, after: HashSet<String>) -> Vec<String> {
    let mut paths = after.difference(&before).cloned().collect::<Vec<_>>();
    paths.sort();
    paths
}

fn collect_stageable_owned_paths(
    keg_root: &Path,
    keep_root_entries: bool,
) -> Result<Vec<String>, String> {
    let mut paths = Vec::new();
    let entries = fs::read_dir(keg_root)
        .map_err(|err| format!("failed to read {}: {err}", keg_root.display()))?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("failed to read {}: {err}", keg_root.display()))?;
        if !should_stage_root_entry(&entry, keep_root_entries)? {
            continue;
        }
        collect_stageable_owned_paths_inner(keg_root, &entry.path(), &mut paths)?;
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn collect_stageable_owned_paths_inner(
    keg_root: &Path,
    path: &Path,
    paths: &mut Vec<String>,
) -> Result<(), String> {
    let relative = path
        .strip_prefix(keg_root)
        .map_err(|err| format!("failed to relativize {}: {err}", path.display()))?;
    if fs::symlink_metadata(path)
        .map_err(|err| format!("failed to stat {}: {err}", path.display()))?
        .is_dir()
    {
        for entry in
            fs::read_dir(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?
        {
            let entry = entry.map_err(|err| format!("failed to read {}: {err}", path.display()))?;
            collect_stageable_owned_paths_inner(keg_root, &entry.path(), paths)?;
        }
    } else {
        paths.push(normalize_owned_path(relative)?);
    }
    Ok(())
}

fn normalize_owned_path(path: &Path) -> Result<String, String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(
                part.to_str()
                    .ok_or_else(|| format!("non-utf8 owned path {}", path.display()))?
                    .to_string(),
            ),
            _ => return Err(format!("invalid owned path {}", path.display())),
        }
    }
    if parts.is_empty() || parts.iter().any(|part| part == "." || part == "..") {
        return Err(format!("invalid owned path {}", path.display()));
    }
    Ok(parts.join("/"))
}

fn remove_owned_paths(root: &Path, paths: &[String]) -> Result<(), String> {
    let mut paths = paths.to_vec();
    paths.sort_by_key(|path| std::cmp::Reverse(path.matches('/').count()));
    for relative in paths {
        let target = root.join(&relative);
        if fs::symlink_metadata(&target).is_ok() {
            remove_path(&target)?;
        }
    }
    remove_empty_owned_dirs(root)
}

fn remove_empty_owned_dirs(root: &Path) -> Result<(), String> {
    for top in [
        "bin", "sbin", "lib", "include", "share", "etc", "opt", "var",
    ] {
        remove_empty_dirs_under(root, &root.join(top))?;
    }
    Ok(())
}

fn remove_empty_dirs_under(root: &Path, path: &Path) -> Result<bool, String> {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };
    let mut empty = true;
    for entry in entries {
        let entry = entry.map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        let child = entry.path();
        if entry
            .file_type()
            .map_err(|err| format!("failed to stat {}: {err}", child.display()))?
            .is_dir()
        {
            if !remove_empty_dirs_under(root, &child)? {
                empty = false;
            }
        } else {
            empty = false;
        }
    }
    if empty && path != root {
        fs::remove_dir(path)
            .map_err(|err| format!("failed to remove {}: {err}", path.display()))?;
    }
    Ok(empty)
}

fn prepare_root_payload_install(plan: &InstallPlan) -> Result<HashSet<String>, String> {
    if incremental_root_is_seeded(plan)
        && let Some(manifest) = load_root_ownership_manifest(&plan.root_ownership_manifest_path())?
    {
        remove_owned_paths(&plan.install_root, &manifest.stubs)?;
    }
    collect_owned_paths(&plan.install_root)
}

fn finish_root_payload_install(plan: &InstallPlan, before: HashSet<String>) -> Result<(), String> {
    let after = collect_owned_paths(&plan.install_root)?;
    write_root_ownership_manifest(plan, sorted_owned_path_difference(before, after))
}

fn merge_path_into(source: &Path, target: &Path) -> Result<(), String> {
    let source_metadata = fs::symlink_metadata(source)
        .map_err(|err| format!("failed to stat {}: {err}", source.display()))?;
    if target.exists() || fs::symlink_metadata(target).is_ok() {
        let target_metadata = fs::symlink_metadata(target)
            .map_err(|err| format!("failed to stat {}: {err}", target.display()))?;
        if source_metadata.is_dir() && target_metadata.is_dir() {
            fs::create_dir_all(target)
                .map_err(|err| format!("failed to create {}: {err}", target.display()))?;
            for entry in fs::read_dir(source)
                .map_err(|err| format!("failed to read {}: {err}", source.display()))?
            {
                let entry =
                    entry.map_err(|err| format!("failed to read {}: {err}", source.display()))?;
                merge_path_into(&entry.path(), &target.join(entry.file_name()))?;
            }
            fs::remove_dir(source)
                .map_err(|err| format!("failed to remove {}: {err}", source.display()))?;
            return Ok(());
        }
        remove_path(target)?;
    } else if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }

    match fs::rename(source, target) {
        Ok(()) => Ok(()),
        Err(_) if source_metadata.is_dir() && target.is_dir() => merge_path_into(source, target),
        Err(err) => Err(format!(
            "failed to move {} to {}: {err}",
            source.display(),
            target.display()
        )),
    }
}

fn unpack_bottle(archive_path: &Path, destination: &Path) -> Result<(), String> {
    let file = File::open(archive_path)
        .map_err(|err| format!("failed to open {}: {err}", archive_path.display()))?;
    let decoder = GzDecoder::new(BufReader::new(file));
    let mut archive = Archive::new(decoder);
    archive
        .unpack(destination)
        .map_err(|err| format!("failed to unpack {}: {err}", archive_path.display()))
}

fn relocate_tree(
    root: &Path,
    future_root: &Path,
    formula: &str,
    rules: &[RewriteRule],
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    let allow_failures =
        pkg_allow_contains("relocation-failures") || homebrew_debug_allowance_enabled();
    let mut stderr = std::io::stderr();
    relocate_tree_with_options(
        root,
        future_root,
        formula,
        rules,
        progress,
        allow_failures,
        &mut stderr,
    )
}

fn relocate_tree_with_options<W: Write>(
    root: &Path,
    future_root: &Path,
    formula: &str,
    rules: &[RewriteRule],
    progress: Option<&InstallProgress>,
    allow_failures: bool,
    stderr: &mut W,
) -> Result<(), String> {
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|err| format!("failed to walk {}: {err}", root.display()))?;
        let path = entry.path();

        if entry.file_type().is_symlink() {
            if let Err(err) = relocate_symlink(path, root, future_root, rules) {
                handle_allowed_failure(err, allow_failures, stderr)?;
            }
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }

        if let Err(err) = relocate_file(path, root, future_root, formula, rules, progress) {
            handle_allowed_failure(err, allow_failures, stderr)?;
        }
    }
    Ok(())
}

fn handle_allowed_failure<W: Write>(
    err: String,
    allow_failure: bool,
    stderr: &mut W,
) -> Result<(), String> {
    if !allow_failure {
        return Err(err);
    }
    let _ = writeln!(stderr, "{err}");
    Ok(())
}

fn pkg_allow_contains(flag: &str) -> bool {
    if !homebrew_debug_allowance_enabled() {
        return false;
    }
    env::var("PKG_ALLOW")
        .ok()
        .is_some_and(|value| pkg_allow_value_contains(&value, flag))
}

fn pkg_allow_value_contains(value: &str, flag: &str) -> bool {
    value
        .split(|ch: char| ch == ':' || ch == ',' || ch.is_ascii_whitespace())
        .any(|item| item == flag)
}

fn relocate_symlink(
    path: &Path,
    root: &Path,
    future_root: &Path,
    rules: &[RewriteRule],
) -> Result<(), String> {
    let target = fs::read_link(path)
        .map_err(|err| format!("failed to read symlink {}: {err}", path.display()))?;
    let rewritten = match target.to_str() {
        Some(target_str) => rewrite_absolute_path(target_str, rules)?.map(PathBuf::from),
        None => None,
    };
    let rewritten = match rewritten {
        Some(rewritten) => Some(rewritten),
        None if target.is_relative() => {
            rewrite_relative_symlink_target(path, root, future_root, &target, rules)?
        }
        None => None,
    };
    let Some(rewritten) = rewritten else {
        return Ok(());
    };

    fs::remove_file(path).map_err(|err| format!("failed to remove {}: {err}", path.display()))?;
    symlink(&rewritten, path).map_err(|err| {
        format!(
            "failed to rewrite symlink {} -> {}: {err}",
            path.display(),
            rewritten.display()
        )
    })
}

fn rewrite_relative_symlink_target(
    path: &Path,
    root: &Path,
    future_root: &Path,
    target: &Path,
    rules: &[RewriteRule],
) -> Result<Option<PathBuf>, String> {
    let relative_path = path
        .strip_prefix(root)
        .map_err(|err| format!("failed to relativize {}: {err}", path.display()))?;
    let source_root = source_keg_root(root)?;
    let source_path = source_root.join(relative_path);
    let source_parent = source_path
        .parent()
        .ok_or_else(|| format!("symlink {} has no parent directory", source_path.display()))?;
    let resolved = normalize_path(&source_parent.join(target));
    if resolved.starts_with(&source_root) {
        return Ok(None);
    }

    let Some(source) = homebrew_relative_symlink_source(&resolved) else {
        return Ok(None);
    };
    let Some(rewritten) = rewrite_absolute_path(&source, rules)? else {
        return Ok(None);
    };

    let future_path = future_root.join(relative_path);
    let future_parent = future_path
        .parent()
        .ok_or_else(|| format!("symlink {} has no parent directory", future_path.display()))?;
    Ok(Some(relative_path_from(
        future_parent,
        Path::new(&rewritten),
    )))
}

fn source_keg_root(root: &Path) -> Result<PathBuf, String> {
    let formula = root
        .parent()
        .and_then(Path::file_name)
        .ok_or_else(|| format!("keg root {} is missing a formula directory", root.display()))?;
    let version = root
        .file_name()
        .ok_or_else(|| format!("keg root {} is missing a version directory", root.display()))?;
    Ok(PathBuf::from(RELOCATABLE_HOMEBREW_PREFIX)
        .join("Cellar")
        .join(formula)
        .join(version))
}

fn homebrew_relative_symlink_source(resolved: &Path) -> Option<String> {
    let resolved = resolved.to_str()?;
    if let Some(opt_path) = resolved.strip_prefix(&format!("{RELOCATABLE_HOMEBREW_PREFIX}/opt/")) {
        return Some(format!("{HOMEBREW_PREFIX_PLACEHOLDER}/opt/{opt_path}"));
    }
    if let Some(cellar_path) =
        resolved.strip_prefix(&format!("{RELOCATABLE_HOMEBREW_PREFIX}/Cellar/"))
    {
        return Some(format!("{HOMEBREW_CELLAR_PLACEHOLDER}/{cellar_path}"));
    }

    None
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    let mut components = Vec::<OsString>::new();
    let mut has_root = false;
    let mut prefix = None;

    for component in path.components() {
        match component {
            Component::Prefix(value) => prefix = Some(value.as_os_str().to_os_string()),
            Component::RootDir => has_root = true,
            Component::CurDir => {}
            Component::ParentDir => match components.last() {
                Some(last) if last != ".." => {
                    components.pop();
                }
                _ if !has_root => components.push(OsString::from("..")),
                _ => {}
            },
            Component::Normal(value) => components.push(value.to_os_string()),
        }
    }

    if let Some(prefix) = prefix {
        normalized.push(prefix);
    }
    if has_root {
        normalized.push(Path::new("/"));
    }
    for component in components {
        normalized.push(component);
    }
    if normalized.as_os_str().is_empty() {
        normalized.push(".");
    }

    normalized
}

fn relative_path_from(from: &Path, to: &Path) -> PathBuf {
    let from_components: Vec<_> = from.components().collect();
    let to_components: Vec<_> = to.components().collect();

    if from.is_absolute() != to.is_absolute() {
        return to.to_path_buf();
    }

    let mut shared = 0usize;
    while shared < from_components.len()
        && shared < to_components.len()
        && from_components[shared] == to_components[shared]
    {
        shared += 1;
    }

    if shared == 0 && to.is_absolute() {
        return to.to_path_buf();
    }

    let mut relative = PathBuf::new();
    for component in &from_components[shared..] {
        if matches!(component, Component::Normal(_)) {
            relative.push("..");
        }
    }
    for component in &to_components[shared..] {
        relative.push(component.as_os_str());
    }
    if relative.as_os_str().is_empty() {
        relative.push(".");
    }

    relative
}

fn relocate_file(
    path: &Path,
    root: &Path,
    future_root: &Path,
    formula: &str,
    rules: &[RewriteRule],
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    if path.extension().and_then(|value| value.to_str()) == Some("a") {
        return Ok(());
    }

    let mut bytes =
        fs::read(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;

    if let Ok(text) = std::str::from_utf8(&bytes) {
        if is_documentation_text_path(path, root) {
            return Ok(());
        }
        let rewritten = rewrite_text(text, path, formula, rules)?;
        if rewritten.as_bytes() != bytes.as_slice() {
            ensure_writable(path)?;
            fs::write(path, rewritten.as_bytes())
                .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
        }
        return Ok(());
    }

    let mode = if is_macho(&bytes) {
        BinaryRewriteMode::Macho {
            path,
            root,
            future_root,
        }
    } else {
        BinaryRewriteMode::Slash
    };
    let changed = rewrite_binary(&mut bytes, path, formula, rules, mode)?;
    if changed {
        ensure_writable(path)?;
        fs::write(path, &bytes)
            .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
        codesign_if_macho(path, &bytes, progress)?;
    }
    Ok(())
}

fn is_documentation_text_path(path: &Path, root: &Path) -> bool {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let mut components = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value),
            _ => None,
        });
    let first = components.next();
    let second = components.next();
    if first == Some(OsStr::new("share")) && second == Some(OsStr::new("doc")) {
        return true;
    }

    let Some(file_name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    let stem = file_name
        .split_once('.')
        .map_or(file_name, |(stem, _)| stem)
        .to_ascii_uppercase();
    let prefixes = [
        "AUTHORS",
        "CHANGELOG",
        "CHANGES",
        "COPYING",
        "HISTORY",
        "LICENSE",
        "NEWS",
        "NOTICE",
        "README",
        "THANKS",
    ];
    prefixes
        .iter()
        .any(|prefix| stem == *prefix || stem.starts_with(&format!("{prefix}-")))
}

fn rewrite_text(
    text: &str,
    path: &Path,
    formula: &str,
    rules: &[RewriteRule],
) -> Result<String, String> {
    let mut rewritten = text.to_string();
    for rule in rules {
        rewritten = rewrite_prefixes_in_text(&rewritten, rule);
    }
    if contains_relocatable_homebrew_reference_text(&rewritten, rules) {
        return Err(unsupported_homebrew_rewrite_error(
            "text", formula, path, text, &rewritten, rules,
        ));
    }
    Ok(rewritten)
}

fn rewrite_prefixes_in_text(text: &str, rule: &RewriteRule) -> String {
    let mut output = String::with_capacity(text.len());
    let mut cursor = 0;
    while let Some(offset) = text[cursor..].find(&rule.source) {
        let absolute = cursor + offset;
        output.push_str(&text[cursor..absolute]);
        let suffix_index = absolute + rule.source.len();
        let boundary = text
            .as_bytes()
            .get(suffix_index)
            .copied()
            .is_none_or(|byte| byte == b'/' || !is_path_byte(byte));
        if boundary {
            output.push_str(&rule.destination);
            cursor = suffix_index;
        } else {
            output.push_str(&rule.source);
            cursor = suffix_index;
        }
    }
    output.push_str(&text[cursor..]);
    output
}

fn rewrite_binary(
    bytes: &mut [u8],
    path: &Path,
    formula: &str,
    rules: &[RewriteRule],
    mode: BinaryRewriteMode<'_>,
) -> Result<bool, String> {
    let mut changed = false;
    let mut start = 0usize;
    while start <= bytes.len() {
        let end = bytes[start..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| start + offset)
            .unwrap_or(bytes.len());
        let segment = &bytes[start..end];
        if contains_relocatable_homebrew_reference_bytes(segment, rules) {
            let rewritten = rewrite_binary_segment_bytes(segment, path, formula, rules, mode)?;
            if rewritten.len() > segment.len() {
                let original = String::from_utf8_lossy(segment);
                let rewritten = String::from_utf8_lossy(&rewritten);
                return Err(format!(
                    "{} cannot be rewritten safely because binary rewrite matched embedded Homebrew path {} and replacement {} is longer",
                    path.display(),
                    original,
                    rewritten
                ));
            }
            bytes[start..start + rewritten.len()].copy_from_slice(&rewritten);
            for byte in &mut bytes[start + rewritten.len()..end] {
                *byte = 0;
            }
            changed = true;
        }

        if end == bytes.len() {
            break;
        }
        start = end + 1;
    }

    if contains_relocatable_homebrew_reference_bytes(bytes, rules) {
        return Err(format!(
            "{} still contains unsupported Homebrew references after NUL-segment relocation",
            path.display()
        ));
    }

    Ok(changed)
}

fn is_path_byte(byte: u8) -> bool {
    SAFE_BINARY_PATH_BYTES.contains(&byte)
}

fn ensure_writable(path: &Path) -> Result<(), String> {
    let metadata =
        fs::metadata(path).map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
    let mut permissions = metadata.permissions();
    let mode = permissions.mode();
    if mode & 0o200 != 0 {
        return Ok(());
    }

    permissions.set_mode(mode | 0o200);
    fs::set_permissions(path, permissions)
        .map_err(|err| format!("failed to make {} writable: {err}", path.display()))
}

fn rewrite_binary_segment_bytes(
    segment: &[u8],
    path: &Path,
    formula: &str,
    rules: &[RewriteRule],
    mode: BinaryRewriteMode<'_>,
) -> Result<Vec<u8>, String> {
    let mut rewritten = segment.to_vec();
    for rule in rules {
        rewritten = rewrite_prefixes_in_bytes(&rewritten, rule, mode);
    }
    if contains_relocatable_homebrew_reference_bytes(&rewritten, rules) {
        if let (Ok(original), Ok(rewritten_text)) = (
            std::str::from_utf8(segment),
            std::str::from_utf8(&rewritten),
        ) {
            return Err(unsupported_homebrew_rewrite_error(
                "binary",
                formula,
                path,
                original,
                rewritten_text,
                rules,
            ));
        }
        return Err(format!(
            "formula {formula}: unsupported Homebrew path remains after binary rewrite in {}",
            path.display()
        ));
    }
    Ok(rewritten)
}

fn rewrite_prefixes_in_bytes(
    segment: &[u8],
    rule: &RewriteRule,
    mode: BinaryRewriteMode<'_>,
) -> Vec<u8> {
    let source = rule.source.as_bytes();
    let destination = binary_rewrite_destination(rule, mode);
    let mut output = Vec::with_capacity(segment.len());
    let mut cursor = 0usize;
    while let Some(offset) = find_subslice(&segment[cursor..], source) {
        let absolute = cursor + offset;
        output.extend_from_slice(&segment[cursor..absolute]);
        let suffix_index = absolute + source.len();
        let boundary = segment
            .get(suffix_index)
            .copied()
            .is_none_or(|byte| byte == b'/' || !is_path_byte(byte));
        if boundary {
            if let BinaryRewriteMode::Macho {
                path,
                root,
                future_root,
            } = mode
            {
                let path_end = segment[suffix_index..]
                    .iter()
                    .position(|byte| !is_path_byte(*byte))
                    .map(|offset| suffix_index + offset)
                    .unwrap_or(segment.len());
                let suffix = &segment[suffix_index..path_end];
                let original_path_len = path_end - absolute;
                if let Some(destination) = macho_binary_rewrite_destination(
                    rule,
                    suffix,
                    original_path_len,
                    path,
                    root,
                    future_root,
                ) {
                    output.extend_from_slice(destination.as_bytes());
                    cursor = path_end;
                    continue;
                }
            }
            output.extend_from_slice(&destination);
            cursor = suffix_index;
        } else {
            output.extend_from_slice(source);
            cursor = suffix_index;
        }
    }
    output.extend_from_slice(&segment[cursor..]);
    output
}

fn binary_rewrite_destination(rule: &RewriteRule, mode: BinaryRewriteMode<'_>) -> Vec<u8> {
    let source = rule.source.as_bytes();
    let destination = rule.destination.as_bytes();
    if matches!(mode, BinaryRewriteMode::Nul) || destination.len() >= source.len() {
        return destination.to_vec();
    }

    let Some(last_slash) = destination.iter().rposition(|byte| *byte == b'/') else {
        return destination.to_vec();
    };
    if last_slash == 0 {
        return destination.to_vec();
    }

    let mut padded = Vec::with_capacity(source.len());
    padded.extend_from_slice(&destination[..=last_slash]);
    padded.extend(std::iter::repeat_n(b'/', source.len() - destination.len()));
    padded.extend_from_slice(&destination[last_slash + 1..]);
    padded
}

fn macho_binary_rewrite_destination(
    rule: &RewriteRule,
    suffix: &[u8],
    max_len: usize,
    path: &Path,
    root: &Path,
    future_root: &Path,
) -> Option<String> {
    let suffix = std::str::from_utf8(suffix).ok()?;
    if !suffix.contains(".dylib") {
        return None;
    }
    let rewritten = format!("{}{}", rule.destination, suffix);
    let rewritten_path = Path::new(&rewritten);
    if !rewritten_path.starts_with(future_root) {
        return Some(rewritten);
    }
    let relative_path = path.strip_prefix(root).ok()?;
    let future_path = future_root.join(relative_path);
    let future_parent = future_path.parent()?;
    let relative = relative_path_from(future_parent, rewritten_path);
    let loader_path = format!("@loader_path/{}", relative.to_string_lossy());
    if loader_path.len() <= max_len {
        return Some(loader_path);
    }
    if rewritten.len() <= max_len {
        return Some(rewritten);
    }
    Some(loader_path)
}

fn unsupported_homebrew_rewrite_error(
    kind: &str,
    formula: &str,
    path: &Path,
    original: &str,
    rewritten: &str,
    rules: &[RewriteRule],
) -> String {
    let from = first_relocatable_homebrew_reference(original, rules)
        .unwrap_or(RELOCATABLE_HOMEBREW_PREFIX);
    let to = first_relocatable_homebrew_reference(rewritten, rules)
        .unwrap_or(RELOCATABLE_HOMEBREW_PREFIX);
    format!(
        "formula {formula}: unsupported Homebrew path remains after {kind} rewrite in {}: \
rewrote {from} -> {to}; original segment: {original}; rewritten segment: {rewritten}",
        path.display()
    )
}

fn run_command_with_logged_output(
    command: &mut Command,
    progress: Option<&InstallProgress>,
    context: &str,
) -> Result<LoggedCommandOutput, String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|err| format!("{context}: {err}"))?;
    let stdout = child
        .stdout
        .take()
        .map(|reader| spawn_output_reader(reader, progress.cloned()));
    let stderr = child
        .stderr
        .take()
        .map(|reader| spawn_output_reader(reader, progress.cloned()));
    let status = child.wait().map_err(|err| format!("{context}: {err}"))?;

    let mut lines = Vec::new();
    if let Some(handle) = stdout {
        lines.extend(join_output_reader(handle, context)?);
    }
    if let Some(handle) = stderr {
        lines.extend(join_output_reader(handle, context)?);
    }

    Ok(LoggedCommandOutput { status, lines })
}

fn spawn_output_reader<R>(
    reader: R,
    progress: Option<InstallProgress>,
) -> thread::JoinHandle<Result<Vec<String>, String>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut lines = Vec::new();
        let mut buffer = Vec::new();
        loop {
            buffer.clear();
            let count = reader
                .read_until(b'\n', &mut buffer)
                .map_err(|err| format!("failed to read subprocess output: {err}"))?;
            if count == 0 {
                break;
            }
            let line = sanitize_progress_message(&String::from_utf8_lossy(&buffer));
            if line.is_empty() {
                continue;
            }
            if let Some(progress) = &progress {
                progress.log(&line);
            }
            lines.push(line);
        }
        Ok(lines)
    })
}

fn join_output_reader(
    handle: thread::JoinHandle<Result<Vec<String>, String>>,
    context: &str,
) -> Result<Vec<String>, String> {
    handle
        .join()
        .map_err(|_| format!("{context}: subprocess output reader panicked"))?
}

fn format_command_output_suffix(lines: &[String]) -> String {
    lines
        .iter()
        .rev()
        .find(|line| !line.is_empty())
        .map(|line| format!(": {line}"))
        .unwrap_or_default()
}

#[derive(Debug, Clone)]
struct UserIdentity {
    uid: u32,
    gid: u32,
    home: Option<String>,
    name: Option<String>,
}

fn run_isotope_migration(
    plan: &InstallPlan,
    isotope: &IsotopePackageData,
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    let Some(script) = isotope.migrate.as_deref() else {
        if let Some(result) = run_generated_isotope_migration(&isotope.name) {
            if is_root() {
                return Err("isotope migration must not run as root".to_string());
            }
            if let Some(progress) = progress {
                progress.log("migrating secrets");
            }
            return result;
        }
        return Ok(());
    };
    let user = current_user_identity()?;
    let temp_parent = if is_root() {
        plan.tmp_root.clone()
    } else {
        env::temp_dir()
    };
    let temp_dir = TempDir::new_in(&temp_parent).map_err(|err| {
        format!(
            "failed to create temp dir for {} migration: {err}",
            isotope.name
        )
    })?;
    let mut temp_permissions = fs::metadata(temp_dir.path())
        .map_err(|err| format!("failed to stat {}: {err}", temp_dir.path().display()))?
        .permissions();
    temp_permissions.set_mode(0o755);
    fs::set_permissions(temp_dir.path(), temp_permissions)
        .map_err(|err| format!("failed to chmod {}: {err}", temp_dir.path().display()))?;
    let script_path = temp_dir.path().join("migrate.sh");
    let rewritten = executable_isotope_migration_script(script, plan, isotope)?;
    fs::write(&script_path, rewritten)
        .map_err(|err| format!("failed to write {}: {err}", script_path.display()))?;
    let mut permissions = fs::metadata(&script_path)
        .map_err(|err| format!("failed to stat {}: {err}", script_path.display()))?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script_path, permissions)
        .map_err(|err| format!("failed to chmod {}: {err}", script_path.display()))?;

    if let Some(progress) = progress {
        progress.log("migrating secrets");
    }
    let mut command = Command::new(&script_path);
    command.current_dir(&plan.install_root);
    command.env("ISOTOPE_PREFIX", &plan.install_root);
    command.env("ISOTOPE_NAME", &isotope.name);
    if let Some(name) = user.name.as_deref() {
        command.env("USER", name).env("LOGNAME", name);
    }
    if let Some(home) = user.home.as_deref() {
        command.env("HOME", home);
    }
    if is_root() {
        command.uid(user.uid);
        command.gid(user.gid);
    }

    let output = run_command_with_logged_output(
        &mut command,
        progress,
        &format!("failed to run migration for {}", isotope.name),
    )?;
    if output.status.success() {
        return Ok(());
    }
    Err(format_failed_isotope_migration(
        &isotope.name,
        output.status,
        &output.lines,
    ))
}

fn format_failed_isotope_migration(name: &str, status: ExitStatus, lines: &[String]) -> String {
    match status.code() {
        Some(code) => format!(
            "migration failed for {} with exit code {code}{}",
            name,
            format_command_output_suffix(lines)
        ),
        None => format!(
            "migration terminated by signal for {}{}",
            name,
            format_command_output_suffix(lines)
        ),
    }
}

fn rewrite_isotope_migration_script(
    script: &str,
    plan: &InstallPlan,
    isotope: &IsotopePackageData,
) -> Result<String, String> {
    let target_prefix = plan.install_root.display().to_string();
    let mut rewritten = script.to_string();

    if let Some(replaced_package) = isotope_replaced_package_name(isotope)? {
        let replaced_prefix = package_install_root(&opt_pkg_root(), &replaced_package)?
            .display()
            .to_string();
        rewritten = rewritten
            .replace(&replaced_prefix, &target_prefix)
            .replace(&format!("/opt/{replaced_package}"), &target_prefix);
    }

    for alias in isotope_migration_install_root_aliases(isotope) {
        rewritten = rewritten.replace(&alias, &target_prefix);
    }
    Ok(rewritten)
}

fn isotope_migration_install_root_aliases(isotope: &IsotopePackageData) -> Vec<String> {
    let mut names = Vec::new();
    push_unique_string(
        &mut names,
        isotope_unqualified_name(&isotope.name).to_string(),
    );
    if let Some(repository_leaf) = isotope
        ._repository
        .as_deref()
        .and_then(|repository| repository.rsplit('/').next())
        .filter(|repository_leaf| !repository_leaf.is_empty())
    {
        push_unique_string(&mut names, repository_leaf.to_string());
    }

    let mut aliases = Vec::new();
    for name in names {
        push_unique_string(
            &mut aliases,
            opt_pkg_root()
                .join(ISOTOPE_INSTALL_ROOT_DIR)
                .join(&name)
                .display()
                .to_string(),
        );
        push_unique_string(
            &mut aliases,
            format!("/opt/{ISOTOPE_INSTALL_ROOT_DIR}/{name}"),
        );
        push_unique_string(
            &mut aliases,
            opt_pkg_root()
                .join("isotopes")
                .join(&name)
                .display()
                .to_string(),
        );
        push_unique_string(&mut aliases, format!("/opt/isotopes/{name}"));
    }
    aliases.sort_by_key(|alias| std::cmp::Reverse(alias.len()));
    aliases
}

fn executable_isotope_migration_script(
    script: &str,
    plan: &InstallPlan,
    isotope: &IsotopePackageData,
) -> Result<String, String> {
    let rewritten = rewrite_isotope_migration_script(script, plan, isotope)?;
    if rewritten.starts_with("#!") {
        let Some((shebang, body)) = rewritten.split_once('\n') else {
            return Ok(format!("{rewritten}\n{}", isotope_migration_root_guard()));
        };
        return Ok(format!(
            "{shebang}\n{}{}",
            isotope_migration_root_guard(),
            body
        ));
    }
    Ok(format!(
        "#!/bin/sh\n{}{}",
        isotope_migration_root_guard(),
        rewritten
    ))
}

fn isotope_migration_root_guard() -> &'static str {
    "if [ \"$(id -u)\" -eq 0 ]; then\n  echo \"isotope migration must not run as root\" >&2\n  exit 77\nfi\n"
}

fn current_user_identity() -> Result<UserIdentity, String> {
    if !is_root() {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        return Ok(UserIdentity {
            uid,
            gid,
            home: env::var("HOME").ok(),
            name: env::var("USER").ok().or_else(|| env::var("LOGNAME").ok()),
        });
    }

    if let (Ok(uid), Ok(gid)) = (env::var("SUDO_UID"), env::var("SUDO_GID"))
        && let (Ok(uid), Ok(gid)) = (uid.parse::<u32>(), gid.parse::<u32>())
    {
        let (home, name) = passwd_entry(uid);
        return Ok(UserIdentity {
            uid,
            gid,
            home,
            name,
        });
    }

    let metadata = fs::metadata("/dev/console")
        .map_err(|err| format!("failed to stat /dev/console for migration user: {err}"))?;
    let uid = metadata.uid();
    let gid = metadata.gid();
    if uid == 0 {
        return Err("could not determine a non-root user for isotope migration".to_string());
    }
    let (home, name) = passwd_entry(uid);
    Ok(UserIdentity {
        uid,
        gid,
        home,
        name,
    })
}

fn passwd_entry(uid: u32) -> (Option<String>, Option<String>) {
    unsafe {
        let pwd = libc::getpwuid(uid);
        if pwd.is_null() {
            return (None, None);
        }
        let entry = *pwd;
        let home = (!entry.pw_dir.is_null()).then(|| {
            std::ffi::CStr::from_ptr(entry.pw_dir)
                .to_string_lossy()
                .into_owned()
        });
        let name = (!entry.pw_name.is_null()).then(|| {
            std::ffi::CStr::from_ptr(entry.pw_name)
                .to_string_lossy()
                .into_owned()
        });
        (home, name)
    }
}

fn codesign_if_macho(
    path: &Path,
    bytes: &[u8],
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    if !is_macho(bytes) {
        return Ok(());
    }

    let mut command = Command::new("codesign");
    command.arg("--force").arg("--sign").arg("-").arg(path);
    let output = run_command_with_logged_output(
        &mut command,
        progress,
        &format!("failed to run codesign for {}", path.display()),
    )?;
    if output.status.success() {
        return Ok(());
    }

    Err(match output.status.code() {
        Some(code) => format!(
            "codesign failed for {} with exit code {code}{}",
            path.display(),
            format_command_output_suffix(&output.lines)
        ),
        None => format!(
            "codesign terminated by signal for {}{}",
            path.display(),
            format_command_output_suffix(&output.lines)
        ),
    })
}

fn is_macho(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }

    matches!(
        &bytes[..4],
        [0xfe, 0xed, 0xfa, 0xce]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
            | [0xca, 0xfe, 0xba, 0xbf]
            | [0xbf, 0xba, 0xfe, 0xca]
    )
}

fn rewrite_absolute_path(path: &str, rules: &[RewriteRule]) -> Result<Option<String>, String> {
    if !contains_relocatable_homebrew_reference_text(path, rules) {
        return Ok(None);
    }

    for rule in rules {
        if path == rule.source {
            return Ok(Some(rule.destination.clone()));
        }
        if path.starts_with(&rule.source)
            && path.as_bytes().get(rule.source.len()).copied() == Some(b'/')
        {
            let suffix = &path[rule.source.len()..];
            return Ok(Some(format!("{}{}", rule.destination, suffix)));
        }
    }

    Err(format!("unsupported Homebrew path {path}"))
}

fn first_relocatable_homebrew_reference<'a>(
    text: &'a str,
    rules: &[RewriteRule],
) -> Option<&'a str> {
    let mut best: Option<(usize, &str)> = None;
    for marker in rules.iter().map(|rule| rule.source.as_str()).chain([
        HOMEBREW_PREFIX_PLACEHOLDER,
        HOMEBREW_CELLAR_PLACEHOLDER,
        HOMEBREW_REPOSITORY_PLACEHOLDER,
        HOMEBREW_LIBRARY_PLACEHOLDER,
        HOMEBREW_PERL_PLACEHOLDER,
        HOMEBREW_JAVA_PLACEHOLDER,
    ]) {
        if let Some(index) = text.find(marker) {
            match best {
                Some((best_index, _)) if best_index <= index => {}
                _ => best = Some((index, marker)),
            }
        }
    }
    let (index, marker) = best?;
    let tail = &text[index..];
    let end = tail
        .char_indices()
        .find(|(_, ch)| ch.is_whitespace() || matches!(ch, '"' | '\'' | ')' | '('))
        .map(|(offset, _)| offset)
        .unwrap_or(tail.len());
    Some(if end == 0 {
        &text[index..index + marker.len()]
    } else {
        &tail[..end]
    })
}

fn contains_relocatable_homebrew_reference_bytes(bytes: &[u8], rules: &[RewriteRule]) -> bool {
    if find_subslice(bytes, RELOCATABLE_HOMEBREW_PREFIX.as_bytes()).is_none()
        && HOMEBREW_NEEDLES
            .into_iter()
            .all(|needle| find_subslice(bytes, needle).is_none())
    {
        return false;
    }

    rules
        .iter()
        .map(|rule| rule.source.as_bytes())
        .chain(HOMEBREW_NEEDLES)
        .any(|needle| find_subslice(bytes, needle).is_some())
}

fn contains_relocatable_homebrew_reference_text(text: &str, rules: &[RewriteRule]) -> bool {
    first_relocatable_homebrew_reference(text, rules).is_some()
}

fn build_formula_order(plan: &InstallPlan, graph: &[FormulaSpec]) -> Vec<String> {
    let mut order = vec![plan.root_formula.clone()];
    for spec in graph {
        if spec.name != plan.root_formula {
            order.push(spec.name.clone());
        }
    }
    order
}

fn build_exec_path_entries(plan: &InstallPlan, graph: &[FormulaSpec]) -> Vec<PathBuf> {
    build_path_entries(plan, graph, InstallPlan::stable_target_dir)
}

fn build_install_path_entries(plan: &InstallPlan, graph: &[FormulaSpec]) -> Vec<PathBuf> {
    build_path_entries(plan, graph, InstallPlan::actual_target_dir)
}

fn build_path_entries(
    plan: &InstallPlan,
    graph: &[FormulaSpec],
    root_for: fn(&InstallPlan, &str) -> PathBuf,
) -> Vec<PathBuf> {
    let mut entries = Vec::new();
    for formula in build_formula_order(plan, graph) {
        let root = root_for(plan, &formula);
        push_unique_path(&mut entries, root.join("bin"));
        let sbin = root.join("sbin");
        if sbin.is_dir() {
            push_unique_path(&mut entries, sbin);
        }
    }
    entries
}

fn push_unique_path(entries: &mut Vec<PathBuf>, path: PathBuf) {
    if !entries.iter().any(|existing| existing == &path) {
        entries.push(path);
    }
}

fn is_executable(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(metadata) => metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

fn build_exec_path(entries: &[PathBuf]) -> OsString {
    let paths = combined_path_entries(entries);
    env::join_paths(paths).unwrap_or_else(|_| env::var_os("PATH").unwrap_or_default())
}

fn build_install_path(plan: &InstallPlan, graph: &[FormulaSpec]) -> OsString {
    build_exec_path(&build_install_path_entries(plan, graph))
}

fn combined_path_entries(entries: &[PathBuf]) -> Vec<PathBuf> {
    let mut paths = entries.to_vec();
    if let Some(current) = env::var_os("PATH") {
        for entry in env::split_paths(&current) {
            push_unique_path(&mut paths, entry);
        }
    }
    paths
}

fn resolve_command_in_path_entries(entries: &[PathBuf], executable: &str) -> Option<PathBuf> {
    for entry in entries {
        let candidate = entry.join(executable);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn resolve_install_time_command(
    plan: &InstallPlan,
    graph: &[FormulaSpec],
    executable: &str,
) -> Option<PathBuf> {
    let entries = combined_path_entries(&build_install_path_entries(plan, graph));
    resolve_command_in_path_entries(&entries, executable)
}

fn download_vendor_asset(
    url: &str,
    destination: &Path,
    name: &str,
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    if let Some(progress) = progress {
        progress.begin_download_phase();
    }
    let response = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .call()
        .map_err(|err| match err {
            UreqError::Status(code, _) => {
                format!("failed to download vendor asset for {name}: http {code}")
            }
            UreqError::Transport(err) => {
                format!("failed to download vendor asset for {name}: {err}")
            }
        })?;
    if let Some(progress) = progress {
        progress.add_download_total(
            response
                .header("Content-Length")
                .and_then(|value| value.parse::<u64>().ok()),
        );
    }
    let mut reader = response.into_reader();
    let mut file = File::create(destination)
        .map_err(|err| format!("failed to create {}: {err}", destination.display()))?;
    let mut buffer = [0u8; 32 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|err| format!("failed to read vendor asset for {name}: {err}"))?;
        if count == 0 {
            break;
        }
        file.write_all(&buffer[..count])
            .map_err(|err| format!("failed to write {}: {err}", destination.display()))?;
        if let Some(progress) = progress {
            progress.advance_download(count as u64);
        }
    }
    Ok(())
}

fn vendor_archive_name(url: &str) -> String {
    url.rsplit('/')
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or("archive")
        .to_string()
}

fn unpack_vendor_archive(
    archive_path: &Path,
    destination: &Path,
    name: &str,
) -> Result<(), String> {
    let archive_name = archive_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if vendor_archive_is_zip(archive_name) {
        let status = Command::new("ditto")
            .arg("-x")
            .arg("-k")
            .arg(archive_path)
            .arg(destination)
            .status()
            .map_err(|err| format!("failed to unpack vendor archive for {name}: {err}"))?;
        if status.success() {
            return Ok(());
        }

        return Err(match status.code() {
            Some(code) => format!("failed to unpack vendor archive for {name}: exit code {code}"),
            None => format!("failed to unpack vendor archive for {name}: terminated by signal"),
        });
    }
    if vendor_archive_is_tar(archive_name) {
        return unpack_tar_archive(archive_path, destination);
    }

    Err(format!(
        "unsupported vendor archive format for {name}: {}",
        archive_path.display()
    ))
}

fn unpack_cask_payload(
    archive_path: &Path,
    destination: &Path,
    cask_name: &str,
    cask: &EmbeddedCaskMetadata,
) -> Result<(), String> {
    let archive_name = archive_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if vendor_archive_is_zip(archive_name) || vendor_archive_is_tar(archive_name) {
        return unpack_vendor_archive(archive_path, destination, cask_name);
    }

    unpack_direct_cask_binary(archive_path, destination, cask_name, cask)
}

fn unpack_direct_cask_binary(
    archive_path: &Path,
    destination: &Path,
    cask_name: &str,
    cask: &EmbeddedCaskMetadata,
) -> Result<(), String> {
    let binary = match cask.binaries.as_slice() {
        [binary] => binary,
        _ => {
            return Err(format!(
                "unsupported vendor archive format for {cask_name}: {}",
                archive_path.display()
            ));
        }
    };
    let binary_source = Path::new(&binary.source);
    let archive_name = archive_path.file_name().ok_or_else(|| {
        format!(
            "unsupported vendor archive format for {cask_name}: {}",
            archive_path.display()
        )
    })?;
    if binary_source
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty())
        || binary_source.file_name() != Some(archive_name)
    {
        return Err(format!(
            "unsupported vendor archive format for {cask_name}: {}",
            archive_path.display()
        ));
    }

    fs::copy(archive_path, destination.join(binary_source)).map_err(|err| {
        format!(
            "failed to stage direct cask binary {} for {cask_name}: {err}",
            archive_path.display()
        )
    })?;
    Ok(())
}

fn vendor_archive_is_zip(archive_name: &str) -> bool {
    archive_name.ends_with(".zip")
}

fn vendor_archive_is_tar(archive_name: &str) -> bool {
    archive_name.ends_with(".tar.gz") || archive_name.ends_with(".tgz")
}

fn unpack_tar_archive(archive_path: &Path, destination: &Path) -> Result<(), String> {
    let mut file = File::open(archive_path)
        .map_err(|err| format!("failed to open {}: {err}", archive_path.display()))?;
    let mut magic = [0u8; 2];
    let read = file
        .read(&mut magic)
        .map_err(|err| format!("failed to read {}: {err}", archive_path.display()))?;
    drop(file);

    if read == 2 && magic == [0x1f, 0x8b] {
        return unpack_bottle(archive_path, destination);
    }

    unpack_plain_tar(archive_path, destination)
}

fn unpack_plain_tar(archive_path: &Path, destination: &Path) -> Result<(), String> {
    let file = File::open(archive_path)
        .map_err(|err| format!("failed to open {}: {err}", archive_path.display()))?;
    let mut archive = Archive::new(BufReader::new(file));
    archive
        .unpack(destination)
        .map_err(|err| format!("failed to unpack {}: {err}", archive_path.display()))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::{bun, get, github_release_url, parse_semver};
    use semver::Version;

    fn test_db(entries: &[(&str, &str)]) -> Db {
        Db {
            schema: DB_SCHEMA_VERSION,
            generated_at: String::new(),
            entries: entries
                .iter()
                .map(|(tool, formula)| (tool.to_string(), formula.to_string()))
                .collect(),
            formulas: HashMap::new(),
            casks: HashMap::new(),
            npms: HashMap::new(),
        }
    }

    fn write_executable(path: &Path) {
        write_executable_with_body(path, "")
    }

    fn write_executable_with_body(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, format!("#!/bin/sh\n{body}")).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    fn fixed_i_plan(package_name: &str, root_formula: &str) -> InstallPlan {
        InstallPlan {
            mode: Mode::I,
            package_name: package_name.to_string(),
            root_formula: root_formula.to_string(),
            stable_root: PathBuf::from("/opt").join(package_name),
            install_root: PathBuf::from("/opt").join(package_name),
            tmp_root: PathBuf::from("/opt/.tmp"),
        }
    }

    fn formula_info(post_install_defined: bool) -> FormulaInfo {
        FormulaInfo {
            desc: String::new(),
            homepage: String::new(),
            license: None,
            versions: FormulaVersions::default(),
            revision: 0,
            dependencies: Vec::new(),
            bottle: Bottle {
                stable: Some(BottleStable {
                    files: HashMap::new(),
                }),
            },
            disabled: false,
            post_install_defined,
        }
    }

    fn formula_index_entry(name: &str, aliases: &[&str], oldnames: &[&str]) -> FormulaIndexEntry {
        FormulaIndexEntry {
            name: name.to_string(),
            summary: String::new(),
            aliases: aliases.iter().map(|value| value.to_string()).collect(),
            oldnames: oldnames.iter().map(|value| value.to_string()).collect(),
            category: String::new(),
            homepage: String::new(),
            repository: String::new(),
            upstream_docs: String::new(),
            docs: Vec::new(),
            popularity: None,
            last_updated_at: None,
            pulse_kind: None,
        }
    }

    fn package_search_result(
        package_name: &str,
        source: PackageReceiptSource,
        summary: Option<&str>,
        rank: Option<u32>,
    ) -> PackageSearchResult {
        PackageSearchResult {
            package_name: package_name.to_string(),
            source,
            summary: summary.map(str::to_string),
            latest_version: None,
            homepage: None,
            repository: None,
            upstream_docs: None,
            docs: Vec::new(),
            category: None,
            dependencies: Vec::new(),
            install_package_names: Vec::new(),
            security_state: None,
            rank,
            last_updated_at: None,
            pulse_kind: None,
        }
    }

    #[test]
    fn formula_metadata_decodes_repo_alias_as_repository() {
        let metadata: EmbeddedFormulaMetadata =
            serde_json::from_str(r#"{"repo":"https://github.com/astral-sh/uv"}"#).unwrap();
        assert_eq!(metadata.repository, "https://github.com/astral-sh/uv");

        let entry: FormulaIndexEntry =
            serde_json::from_str(r#"{"name":"uv","repo":"https://github.com/astral-sh/uv"}"#)
                .unwrap();
        assert_eq!(entry.repository, "https://github.com/astral-sh/uv");
    }

    #[test]
    fn cask_metadata_tolerates_listing_only_rows() {
        let metadata: EmbeddedCaskMetadata = serde_json::from_str(
            r#"{
              "aliases": ["op"],
              "binaries": [{"source": "op", "target": "op"}],
              "homepage": "https://developer.1password.com/docs/cli",
              "summary": "Command-line interface for 1Password"
            }"#,
        )
        .unwrap();

        assert_eq!(metadata.summary, "Command-line interface for 1Password");
        assert!(metadata.url.is_empty());
        assert!(metadata.sha256.is_empty());
        assert!(metadata.version.is_empty());
        assert!(
            ensure_cask_install_metadata("1password-cli", &metadata)
                .unwrap_err()
                .contains("missing version metadata")
        );
    }

    #[test]
    fn resolve_i_root_formula_keeps_ffmpeg() {
        let db = test_db(&[]);
        assert_eq!(
            resolve_i_root_package_with_db("ffmpeg", &db, |_| Ok(true)).unwrap(),
            EmbeddedPackage::Formula("ffmpeg".to_string())
        );
    }

    #[test]
    fn resolve_i_root_formula_keeps_imagemagick() {
        let db = test_db(&[]);
        assert_eq!(
            resolve_i_root_package_with_db("imagemagick", &db, |_| Ok(true)).unwrap(),
            EmbeddedPackage::Formula("imagemagick".to_string())
        );
    }

    #[test]
    fn resolve_i_root_formula_uses_executable_mapping_when_no_formula_exists() {
        let db = test_db(&[("zopflipng", "zopfli")]);
        assert_eq!(
            resolve_i_root_package_with_db("zopflipng", &db, |_| Ok(false)).unwrap(),
            EmbeddedPackage::Formula("zopfli".to_string())
        );
    }

    #[test]
    fn formula_install_package_name_uses_canonical_provider_name() {
        let aliases = HashMap::from([("protoc".to_string(), "protobuf".to_string())]);

        assert_eq!(
            formula_install_package_name_with_aliases("protoc", &aliases),
            "protobuf"
        );
        assert_eq!(
            formula_install_package_name_with_aliases("protobuf", &aliases),
            "protobuf"
        );
    }

    #[test]
    fn resolve_i_root_formula_rejects_ambiguous_package_and_executable_names() {
        let db = test_db(&[("foo", "bar")]);
        assert_eq!(
            resolve_i_root_package_with_db("foo", &db, |_| Ok(true)),
            Err(
                "ambiguous install target 'foo': use `brew:foo` for the Homebrew \
package or `bar` for the package that provides the `foo` executable"
                    .to_string()
            )
        );
    }

    #[test]
    fn resolve_i_root_formula_keeps_exact_formula_name_when_executable_matches() {
        let db = test_db(&[("ripgrep", "ripgrep")]);
        assert_eq!(
            resolve_i_root_package_with_db("ripgrep", &db, |_| Ok(true)).unwrap(),
            EmbeddedPackage::Formula("ripgrep".to_string())
        );
    }

    #[test]
    fn resolve_i_root_package_supports_cask_providers() {
        let db = test_db(&[("codex", "cask:codex")]);
        assert_eq!(
            resolve_i_root_package_with_db("codex", &db, |_| Ok(false)).unwrap(),
            EmbeddedPackage::Cask("codex".to_string())
        );
    }

    #[test]
    fn resolve_i_root_package_supports_npm_providers() {
        let db = test_db(&[("tsx", "npm:tsx")]);
        assert_eq!(
            resolve_i_root_package_with_db("tsx", &db, |_| Ok(false)).unwrap(),
            EmbeddedPackage::NpmPackage("tsx".to_string())
        );
    }

    #[test]
    fn resolve_i_root_package_supports_scoped_npm_providers() {
        let db = test_db(&[("scoped-tool", "npm:@scope/scoped-tool")]);
        assert_eq!(
            resolve_i_root_package_with_db("scoped-tool", &db, |_| Ok(false)).unwrap(),
            EmbeddedPackage::NpmPackage("@scope/scoped-tool".to_string())
        );
    }

    #[test]
    fn resolve_i_root_package_rejects_formula_and_npm_executable_ambiguity() {
        let db = test_db(&[("tsx", "npm:tsx")]);
        assert_eq!(
            resolve_i_root_package_with_db("tsx", &db, |_| Ok(true)),
            Err(
                "ambiguous install target 'tsx': use `brew:tsx` for the Homebrew \
package or `npm:tsx` for the package that provides the `tsx` executable"
                    .to_string()
            )
        );
    }

    #[test]
    fn homebrew_executables_from_db_lists_formula_tools_without_prefix() {
        let db = test_db(&[
            ("ffmpeg", "ffmpeg"),
            ("ffplay", "ffmpeg"),
            ("ffprobe", "ffmpeg"),
            ("rg", "ripgrep"),
        ]);
        assert_eq!(
            homebrew_executables_from_db("ffmpeg", &db),
            vec![
                "ffmpeg".to_string(),
                "ffplay".to_string(),
                "ffprobe".to_string(),
            ]
        );
    }

    #[test]
    fn resolve_i_root_package_ignores_unknown_qualified_entry_providers() {
        let db = test_db(&[("future-tool", "future:provider")]);
        assert_eq!(
            resolve_i_root_package_with_db("future-tool", &db, |_| Ok(false)).unwrap(),
            EmbeddedPackage::Formula("future-tool".to_string())
        );
    }

    #[test]
    fn npm_package_executable_name_falls_back_to_install_leaf_name() {
        assert_eq!(
            npm_package_executable_name("unindexed-tool"),
            "unindexed-tool"
        );
        assert_eq!(
            npm_package_executable_name("@scope/unindexed-tool"),
            "unindexed-tool"
        );
    }

    #[test]
    fn collect_formula_aliases_maps_aliases_to_canonical_formula_names() {
        let aliases = collect_formula_aliases(vec![formula_index_entry(
            "python@3.14",
            &["python", "python3"],
            &[],
        )]);

        assert_eq!(
            aliases.get("python").map(String::as_str),
            Some("python@3.14")
        );
        assert_eq!(
            aliases.get("python3").map(String::as_str),
            Some("python@3.14")
        );
    }

    #[test]
    fn collect_formula_aliases_maps_old_names_to_canonical_formula_names() {
        let aliases = collect_formula_aliases(vec![formula_index_entry("foo", &[], &["foo-old"])]);

        assert_eq!(aliases.get("foo-old").map(String::as_str), Some("foo"));
    }

    #[test]
    fn canonical_formula_name_with_aliases_prefers_canonical_formula_name() {
        let aliases = collect_formula_aliases(vec![formula_index_entry(
            "python@3.14",
            &["python", "python3"],
            &[],
        )]);

        assert_eq!(
            canonical_formula_name_with_aliases("python", &aliases),
            "python@3.14"
        );
        assert_eq!(
            canonical_formula_name_with_aliases("python@3.14", &aliases),
            "python@3.14"
        );
    }

    #[test]
    fn mode_from_name_accepts_subcommands_and_aliases() {
        assert_eq!(Mode::from_name("run"), None);
        assert_eq!(Mode::from_name("use"), None);
        assert_eq!(Mode::from_name("x"), None);
        assert_eq!(Mode::from_name("install"), Some(Mode::I));
        assert_eq!(Mode::from_name("i"), Some(Mode::I));
        assert_eq!(Mode::from_name("av"), None);
    }

    #[test]
    fn invocation_from_program_uses_direct_mode_for_renamed_entrypoints() {
        let av = Invocation::from_program(&OsString::from("av"));
        assert_eq!(av.binary_name, "av");
        assert_eq!(av.name, "av");
        assert_eq!(av.mode, None);

        let install_invocation = Invocation::from_program(&OsString::from("install"));
        assert_eq!(install_invocation.mode, Some(Mode::I));

        let i_invocation = Invocation::from_program(&OsString::from("i"));
        assert_eq!(i_invocation.mode, Some(Mode::I));
    }

    #[test]
    fn invocation_for_subcommand_uses_requested_alias_in_display_name() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        assert_eq!(invocation.binary_name, "av");
        assert_eq!(invocation.name, "av i");
        assert_eq!(invocation.mode, Some(Mode::I));
    }

    #[test]
    fn parse_i_request_collects_multiple_packages() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        let request = parse_i_request_from_iter(
            &invocation,
            vec![
                OsString::from("cargo-binstall"),
                OsString::from("cargo-zigbuild"),
            ]
            .into_iter(),
        )
        .unwrap();

        assert_eq!(
            request,
            Some(IRequest {
                packages: vec![
                    RequestedPackage::Auto("cargo-binstall".to_string()),
                    RequestedPackage::Auto("cargo-zigbuild".to_string()),
                ],
                force: false,
            })
        );
    }

    #[test]
    fn parse_i_request_accepts_force_flag() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        let request = parse_i_request_from_iter(
            &invocation,
            vec![
                OsString::from("--force"),
                OsString::from("cargo-binstall"),
                OsString::from("-f"),
                OsString::from("cargo-zigbuild"),
            ]
            .into_iter(),
        )
        .unwrap();

        assert_eq!(
            request,
            Some(IRequest {
                packages: vec![
                    RequestedPackage::Auto("cargo-binstall".to_string()),
                    RequestedPackage::Auto("cargo-zigbuild".to_string()),
                ],
                force: true,
            })
        );
    }

    #[test]
    fn parse_i_request_rejects_path_separator_in_any_package() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        let request = parse_i_request_from_iter(
            &invocation,
            vec![OsString::from("cargo-binstall"), OsString::from("foo/bar")].into_iter(),
        );

        assert_eq!(
            request,
            Err("package name must not contain path separators".to_string())
        );
    }

    #[test]
    fn parse_i_request_accepts_qualified_homebrew_formula_names() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        let request = parse_i_request_from_iter(
            &invocation,
            vec![OsString::from("brew:zopflipng")].into_iter(),
        )
        .unwrap();

        assert_eq!(
            request,
            Some(IRequest {
                packages: vec![RequestedPackage::HomebrewFormula("zopflipng".to_string(),)],
                force: false,
            })
        );
    }

    #[test]
    fn parse_i_request_accepts_qualified_cask_names() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        let request =
            parse_i_request_from_iter(&invocation, vec![OsString::from("cask:codex")].into_iter())
                .unwrap();

        assert_eq!(
            request,
            Some(IRequest {
                packages: vec![RequestedPackage::HomebrewCask("codex".to_string())],
                force: false,
            })
        );
    }

    #[test]
    fn parse_i_request_accepts_qualified_isotope_names() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        let request =
            parse_i_request_from_iter(&invocation, vec![OsString::from("isotope:gh")].into_iter())
                .unwrap();

        assert_eq!(
            request,
            Some(IRequest {
                packages: vec![RequestedPackage::Isotope("gh".to_string())],
                force: false,
            })
        );
    }

    #[test]
    fn parse_i_request_accepts_unqualified_package_names() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        let request =
            parse_i_request_from_iter(&invocation, vec![OsString::from("clawhub")].into_iter())
                .unwrap();

        assert_eq!(
            request,
            Some(IRequest {
                packages: vec![RequestedPackage::Auto("clawhub".to_string())],
                force: false,
            })
        );
    }

    #[test]
    fn parse_i_request_keeps_unknown_unqualified_package_names_auto() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        let request =
            parse_i_request_from_iter(&invocation, vec![OsString::from("qmd")].into_iter())
                .unwrap();

        assert_eq!(
            request,
            Some(IRequest {
                packages: vec![RequestedPackage::Auto("qmd".to_string())],
                force: false,
            })
        );
    }

    #[test]
    fn parse_i_request_accepts_qualified_npm_package_names() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        let request = parse_i_request_from_iter(
            &invocation,
            vec![
                OsString::from("npm:openclaw"),
                OsString::from("npm:@tobilu/qmd"),
            ]
            .into_iter(),
        )
        .unwrap();

        assert_eq!(
            request,
            Some(IRequest {
                packages: vec![
                    RequestedPackage::NpmPackage {
                        package: "openclaw".to_string(),
                        version: None,
                    },
                    RequestedPackage::NpmPackage {
                        package: "@tobilu/qmd".to_string(),
                        version: None,
                    },
                ],
                force: false,
            })
        );
    }

    #[test]
    fn parse_i_request_accepts_versioned_qualified_npm_package_names() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        let request = parse_i_request_from_iter(
            &invocation,
            vec![OsString::from("npm:openclaw@2026.4.5")].into_iter(),
        )
        .unwrap();

        assert_eq!(
            request,
            Some(IRequest {
                packages: vec![RequestedPackage::NpmPackage {
                    package: "openclaw".to_string(),
                    version: Some("2026.4.5".to_string()),
                }],
                force: false,
            })
        );
    }

    #[test]
    fn parse_i_request_accepts_qualified_pip_package_names() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        let request = parse_i_request_from_iter(
            &invocation,
            vec![OsString::from("pip:Psycopg2")].into_iter(),
        )
        .unwrap();

        assert_eq!(
            request,
            Some(IRequest {
                packages: vec![RequestedPackage::PipPackage("psycopg2".to_string())],
                force: false,
            })
        );
    }

    #[test]
    fn parse_i_request_rejects_invalid_npm_package_name() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        let request =
            parse_i_request_from_iter(&invocation, vec![OsString::from("npm:foo/bar")].into_iter());

        assert_eq!(
            request,
            Err("npm package names must not contain path separators".to_string())
        );
    }

    #[test]
    fn parse_i_request_rejects_invalid_pip_package_name() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        let request =
            parse_i_request_from_iter(&invocation, vec![OsString::from("pip:foo/bar")].into_iter());

        assert_eq!(
            request,
            Err("pip package names must not contain path separators".to_string())
        );
    }

    #[test]
    fn parse_i_request_rejects_unsupported_pip_package_characters() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        let request = parse_i_request_from_iter(
            &invocation,
            vec![OsString::from("pip:foo[bar]")].into_iter(),
        );

        assert_eq!(
            request,
            Err(
                "pip package names may only contain ASCII letters, numbers, '.', '-' and '_'"
                    .to_string()
            )
        );
    }

    #[test]
    fn parse_i_request_rejects_empty_qualified_homebrew_formula_name() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        let request =
            parse_i_request_from_iter(&invocation, vec![OsString::from("brew:")].into_iter());

        assert_eq!(
            request,
            Err("package qualifier 'brew:' is missing a formula name".to_string())
        );
    }

    #[test]
    fn parse_i_request_rejects_additional_slashes_in_qualified_formula_name() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        let request = parse_i_request_from_iter(
            &invocation,
            vec![OsString::from("brew:foo/bar")].into_iter(),
        );

        assert_eq!(
            request,
            Err("qualified package name must not contain additional path separators".to_string())
        );
    }

    #[test]
    fn parse_uninstall_request_accepts_alias_and_qualified_formula_names() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av rm".to_string(),
            mode: None,
        };
        let request = parse_uninstall_request_from_iter(
            &invocation,
            vec![OsString::from("brew:python@3.12")].into_iter(),
        )
        .unwrap();

        assert_eq!(
            request,
            Some(UninstallRequest {
                packages: vec!["python@3.12".to_string()],
            })
        );
    }

    #[test]
    fn parse_uninstall_request_accepts_qualified_cask_names() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av rm".to_string(),
            mode: None,
        };
        let request = parse_uninstall_request_from_iter(
            &invocation,
            vec![OsString::from("cask:codex")].into_iter(),
        )
        .unwrap();

        assert_eq!(
            request,
            Some(UninstallRequest {
                packages: vec!["codex".to_string()],
            })
        );
    }

    #[test]
    fn parse_uninstall_request_accepts_qualified_npm_package_names() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av rm".to_string(),
            mode: None,
        };
        let request = parse_uninstall_request_from_iter(
            &invocation,
            vec![OsString::from("npm:@tobilu/qmd")].into_iter(),
        )
        .unwrap();

        assert_eq!(
            request,
            Some(UninstallRequest {
                packages: vec!["npm:@tobilu/qmd".to_string()],
            })
        );
    }

    #[test]
    fn parse_uninstall_request_preserves_qualified_isotope_names() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av rm".to_string(),
            mode: None,
        };
        let request = parse_uninstall_request_from_iter(
            &invocation,
            vec![OsString::from("isotope:gh")].into_iter(),
        )
        .unwrap();

        assert_eq!(
            request,
            Some(UninstallRequest {
                packages: vec!["isotope:gh".to_string()],
            })
        );
    }

    #[test]
    fn parse_uninstall_request_accepts_unqualified_package_names() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av rm".to_string(),
            mode: None,
        };
        let request = parse_uninstall_request_from_iter(
            &invocation,
            vec![OsString::from("clawhub")].into_iter(),
        )
        .unwrap();

        assert_eq!(
            request,
            Some(UninstallRequest {
                packages: vec!["clawhub".to_string()],
            })
        );
    }

    #[test]
    fn parse_uninstall_request_uses_homebrew_provider_names_for_executables() {
        let _env_lock = test_env_lock().lock().unwrap();
        let legacy_root = opt_pkg_root().join("rg");
        if fs::symlink_metadata(&legacy_root).is_ok() {
            remove_path(&legacy_root).unwrap();
        }
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av rm".to_string(),
            mode: None,
        };
        let request =
            parse_uninstall_request_from_iter(&invocation, vec![OsString::from("rg")].into_iter())
                .unwrap();

        assert_eq!(
            request,
            Some(UninstallRequest {
                packages: vec!["ripgrep".to_string()],
            })
        );
    }

    #[test]
    fn parse_uninstall_request_preserves_existing_legacy_executable_root() {
        let _env_lock = test_env_lock().lock().unwrap();
        let opt_root = opt_pkg_root();
        let install_root = opt_root.join("rg");
        if fs::symlink_metadata(&install_root).is_ok() {
            remove_path(&install_root).unwrap();
        }
        fs::create_dir_all(&install_root).unwrap();
        write_package_receipt(
            &install_root.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "rg".to_string(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "ripgrep".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();

        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av rm".to_string(),
            mode: None,
        };
        let request =
            parse_uninstall_request_from_iter(&invocation, vec![OsString::from("rg")].into_iter())
                .unwrap();

        assert_eq!(
            request,
            Some(UninstallRequest {
                packages: vec!["rg".to_string()],
            })
        );

        remove_path(&install_root).unwrap();
    }

    #[test]
    fn parse_uninstall_request_resolves_unique_installed_isotope_from_stub_name() {
        let _env_lock = test_env_lock().lock().unwrap();
        let opt_root = opt_pkg_root();
        let install_root = opt_root.join("awscli");
        if fs::symlink_metadata(&install_root).is_ok() {
            remove_path(&install_root).unwrap();
        }
        fs::create_dir_all(&install_root).unwrap();
        write_package_receipt(
            &install_root.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "isotope:aws-cli".to_string(),
                version: "2.0.0".to_string(),
                source: PackageReceiptSource::Isotope {
                    isotope_name: "aws-cli".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        write_stub_manifest(
            &install_root.join(STUB_MANIFEST),
            &StubManifest {
                stubs: vec!["aws".to_string()],
            },
        )
        .unwrap();

        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av rm".to_string(),
            mode: None,
        };
        let request =
            parse_uninstall_request_from_iter(&invocation, vec![OsString::from("aws")].into_iter())
                .unwrap();

        assert_eq!(
            request,
            Some(UninstallRequest {
                packages: vec!["isotope:aws-cli".to_string()],
            })
        );

        remove_path(&install_root).unwrap();
    }

    #[test]
    fn parse_uninstall_request_ignores_unknown_installed_isotopes_for_other_names() {
        let _env_lock = test_env_lock().lock().unwrap();
        let opt_root = opt_pkg_root();
        let install_root = opt_root.join(ISOTOPE_INSTALL_ROOT_DIR).join("flyctl");
        if fs::symlink_metadata(&install_root).is_ok() {
            remove_path(&install_root).unwrap();
        }
        fs::create_dir_all(&install_root).unwrap();
        write_package_receipt(
            &install_root.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "isotope:flyctl".to_string(),
                version: "0.3.0".to_string(),
                source: PackageReceiptSource::Isotope {
                    isotope_name: "flyctl".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        write_stub_manifest(
            &install_root.join(STUB_MANIFEST),
            &StubManifest {
                stubs: vec!["flyctl".to_string()],
            },
        )
        .unwrap();

        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av rm".to_string(),
            mode: None,
        };
        let request =
            parse_uninstall_request_from_iter(&invocation, vec![OsString::from("uv")].into_iter())
                .unwrap();

        assert_eq!(
            request,
            Some(UninstallRequest {
                packages: vec!["uv".to_string()],
            })
        );

        remove_path(&install_root).unwrap();
    }

    #[test]
    fn parse_uninstall_request_rejects_ambiguous_installed_names() {
        let _env_lock = test_env_lock().lock().unwrap();
        let opt_root = opt_pkg_root();
        let aws_root = opt_root.join("aws");
        let awscli_root = opt_root.join("awscli");
        for install_root in [&aws_root, &awscli_root] {
            if fs::symlink_metadata(install_root).is_ok() {
                remove_path(install_root).unwrap();
            }
        }
        fs::create_dir_all(&aws_root).unwrap();
        fs::create_dir_all(&awscli_root).unwrap();
        write_package_receipt(
            &aws_root.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "aws".to_string(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "aws".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        write_package_receipt(
            &awscli_root.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "isotope:aws-cli".to_string(),
                version: "2.0.0".to_string(),
                source: PackageReceiptSource::Isotope {
                    isotope_name: "aws-cli".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        write_stub_manifest(
            &awscli_root.join(STUB_MANIFEST),
            &StubManifest {
                stubs: vec!["aws".to_string()],
            },
        )
        .unwrap();

        let err = parse_uninstall_package_name(&OsString::from("aws")).unwrap_err();

        assert!(err.contains("package name aws is ambiguous"));
        assert!(err.contains("aws"));
        assert!(err.contains("isotope:aws-cli"));

        remove_path(&aws_root).unwrap();
        remove_path(&awscli_root).unwrap();
    }

    #[test]
    fn parse_uninstall_request_keeps_unknown_unqualified_package_names() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av rm".to_string(),
            mode: None,
        };
        let request =
            parse_uninstall_request_from_iter(&invocation, vec![OsString::from("qmd")].into_iter())
                .unwrap();

        assert_eq!(
            request,
            Some(UninstallRequest {
                packages: vec!["qmd".to_string()],
            })
        );
    }

    #[test]
    fn parse_uninstall_request_accepts_qualified_pip_package_names() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av rm".to_string(),
            mode: None,
        };
        let request = parse_uninstall_request_from_iter(
            &invocation,
            vec![OsString::from("pip:Psycopg2")].into_iter(),
        )
        .unwrap();

        assert_eq!(
            request,
            Some(UninstallRequest {
                packages: vec!["pip:psycopg2".to_string()],
            })
        );
    }

    #[test]
    fn parse_uninstall_request_rejects_paths() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av uninstall".to_string(),
            mode: None,
        };
        let request = parse_uninstall_request_from_iter(
            &invocation,
            vec![OsString::from("foo/bar")].into_iter(),
        );

        assert_eq!(
            request,
            Err("package name must not contain path separators".to_string())
        );
    }

    #[test]
    fn parse_update_request_without_args_selects_all_installed() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av update".to_string(),
            mode: None,
        };
        let request =
            parse_update_request_from_iter(&invocation, Vec::<OsString>::new().into_iter())
                .unwrap();

        assert_eq!(
            request,
            Some(UpdateRequest {
                selection: PackageSelection::AllInstalled,
                no_self_update: false,
            })
        );
    }

    #[test]
    fn parse_update_request_accepts_packages_and_hidden_self_update_flag() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av update".to_string(),
            mode: None,
        };
        let request = parse_update_request_from_iter(
            &invocation,
            vec![
                OsString::from("ffmpeg"),
                OsString::from(SELF_UPDATE_DISABLE_FLAG),
                OsString::from("brew:python@3.12"),
                OsString::from("npm:openclaw"),
                OsString::from("pip:psycopg2"),
            ]
            .into_iter(),
        )
        .unwrap();

        assert_eq!(
            request,
            Some(UpdateRequest {
                selection: PackageSelection::Requested(vec![
                    RequestedPackage::Auto("ffmpeg".to_string()),
                    RequestedPackage::HomebrewFormula("python@3.12".to_string()),
                    RequestedPackage::NpmPackage {
                        package: "openclaw".to_string(),
                        version: None,
                    },
                    RequestedPackage::PipPackage("psycopg2".to_string()),
                ]),
                no_self_update: true,
            })
        );
    }

    #[test]
    fn parse_info_request_accepts_single_package() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av info".to_string(),
            mode: None,
        };
        let request = parse_info_request_from_iter(
            &invocation,
            vec![OsString::from("npm:openclaw")].into_iter(),
        )
        .unwrap();

        assert_eq!(
            request,
            Some(InfoRequest {
                package: RequestedPackage::NpmPackage {
                    package: "openclaw".to_string(),
                    version: None,
                },
                output: OutputMode::Human,
            })
        );
    }

    #[test]
    fn parse_info_request_rejects_multiple_packages() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av info".to_string(),
            mode: None,
        };
        let request = parse_info_request_from_iter(
            &invocation,
            vec![OsString::from("ffmpeg"), OsString::from("deno")].into_iter(),
        );

        assert_eq!(request, Err("supports a single package".to_string()));
    }

    #[test]
    fn parse_info_request_accepts_json_output_flags() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av info".to_string(),
            mode: None,
        };
        let request = parse_info_request_from_iter(
            &invocation,
            vec![OsString::from("--json"), OsString::from("ffmpeg")].into_iter(),
        )
        .unwrap();

        assert_eq!(
            request,
            Some(InfoRequest {
                package: RequestedPackage::Auto("ffmpeg".to_string()),
                output: OutputMode::Json,
            })
        );
    }

    #[test]
    fn parse_search_request_accepts_single_query() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av search".to_string(),
            mode: None,
        };
        let request = parse_search_request_from_iter(
            &invocation,
            vec![OsString::from("--json"), OsString::from("rip")].into_iter(),
        )
        .unwrap();

        assert_eq!(
            request,
            Some(SearchRequest {
                query: "rip".to_string(),
                output: OutputMode::Json,
            })
        );
    }

    #[test]
    fn parse_search_request_rejects_multiple_query_tokens() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av search".to_string(),
            mode: None,
        };
        let request = parse_search_request_from_iter(
            &invocation,
            vec![OsString::from("rip"), OsString::from("grep")].into_iter(),
        );

        assert_eq!(request, Err("supports a single query string".to_string()));
    }

    #[test]
    fn ensure_package_installed_reports_missing_package() {
        let temp = TempDir::new().unwrap();

        assert_eq!(
            ensure_package_installed(temp.path(), "python"),
            Err("package python is not installed".to_string())
        );
    }

    #[test]
    fn format_installed_paths_returns_installed_for_empty_list() {
        assert_eq!(format_installed_paths(&[]), "installed");
    }

    #[test]
    fn format_installed_paths_separates_paths_with_newlines() {
        assert_eq!(
            format_installed_paths(&[
                "/usr/local/bin/node".to_string(),
                "/usr/local/bin/npm".to_string(),
            ]),
            "/usr/local/bin/node\n/usr/local/bin/npm"
        );
    }

    #[test]
    fn format_package_info_reports_homebrew_metadata() {
        let info = PackageInfo {
            package_name: "ffmpeg".to_string(),
            qualified_name: "brew:ffmpeg".to_string(),
            install_root: PathBuf::from("/opt/ffmpeg"),
            installed: true,
            source: Some(PackageReceiptSource::Formula {
                root_formula: "ffmpeg".to_string(),
            }),
            source_error: None,
            aliases: vec!["ffmpeg4".to_string()],
            aliases_error: None,
            installed_version: Some("7.1".to_string()),
            latest_version: Some("7.2".to_string()),
            latest_version_error: None,
            executable_paths: vec![
                "/usr/local/bin/ffmpeg".to_string(),
                "/usr/local/bin/ffprobe".to_string(),
            ],
            executable_paths_error: None,
            popularity: None,
            last_updated_at: None,
            homebrew_info: Some(HomebrewPackageInfo {
                formula: "ffmpeg".to_string(),
                description: Some("Play, record, convert, and stream audio and video".to_string()),
                homepage: Some("https://ffmpeg.org/".to_string()),
                repository: None,
                upstream_docs: None,
                docs: Vec::new(),
                license: Some("GPL-2.0-or-later".to_string()),
                dependencies: vec!["aom".to_string(), "x264".to_string()],
            }),
            homebrew_info_error: None,
            npm_homepage: None,
            npm_package_info_error: None,
            security_state: None,
            version_options: Vec::new(),
        };

        let rendered = format_package_info(&info);
        assert!(rendered.contains("📦 brew:ffmpeg"));
        assert!(rendered.contains("Aliases       ffmpeg4"));
        assert!(rendered.contains("Source        Homebrew"));
        assert!(rendered.contains("Formula Page  https://formulae.brew.sh/formula/ffmpeg"));
        assert!(rendered.contains("╭─ Dependencies "));
        assert!(rendered.contains("aom   x264"));
        assert!(rendered.contains("╭─ Executables "));
        assert!(rendered.contains("/usr/local/bin/ffmpeg"));
        assert!(rendered.contains("/usr/local/bin/ffprobe"));
        assert!(
            rendered
                .lines()
                .all(|line| line.chars().count() <= INFO_WIDTH)
        );
    }

    #[test]
    fn format_package_info_reports_unavailable_homebrew_metadata() {
        let info = PackageInfo {
            package_name: "foo".to_string(),
            qualified_name: "brew:foo".to_string(),
            install_root: PathBuf::from("/opt/foo"),
            installed: false,
            source: Some(PackageReceiptSource::Formula {
                root_formula: "foo".to_string(),
            }),
            source_error: None,
            aliases: Vec::new(),
            aliases_error: Some("failed to fetch Homebrew formula index".to_string()),
            installed_version: None,
            latest_version: None,
            latest_version_error: Some("failed to fetch formula metadata".to_string()),
            executable_paths: Vec::new(),
            executable_paths_error: None,
            popularity: None,
            last_updated_at: None,
            homebrew_info: None,
            homebrew_info_error: Some("failed to fetch formula metadata".to_string()),
            npm_homepage: None,
            npm_package_info_error: None,
            security_state: None,
            version_options: Vec::new(),
        };

        let rendered = format_package_info(&info);
        assert!(rendered.contains("📦 brew:foo"));
        assert!(rendered.contains("Installed     no"));
        assert!(rendered.contains("Source        Homebrew"));
        assert!(rendered.contains("Formula Page  https://formulae.brew.sh/formula/foo"));
        assert!(rendered.contains("Homebrew Info unavailable (failed to fetch formula metadata)"));
        assert!(
            rendered
                .lines()
                .all(|line| line.chars().count() <= INFO_WIDTH)
        );
    }

    #[test]
    fn format_package_info_reports_uninstalled_homebrew_executables_without_prefix() {
        let info = PackageInfo {
            package_name: "ffmpeg".to_string(),
            qualified_name: "brew:ffmpeg".to_string(),
            install_root: PathBuf::from("/opt/ffmpeg"),
            installed: false,
            source: Some(PackageReceiptSource::Formula {
                root_formula: "ffmpeg".to_string(),
            }),
            source_error: None,
            aliases: Vec::new(),
            aliases_error: None,
            installed_version: None,
            latest_version: Some("7.2".to_string()),
            latest_version_error: None,
            executable_paths: vec![
                "ffmpeg".to_string(),
                "ffplay".to_string(),
                "ffprobe".to_string(),
            ],
            executable_paths_error: None,
            popularity: None,
            last_updated_at: None,
            homebrew_info: Some(HomebrewPackageInfo {
                formula: "ffmpeg".to_string(),
                description: Some("Play, record, convert, and stream audio and video".to_string()),
                homepage: Some("https://ffmpeg.org/".to_string()),
                repository: None,
                upstream_docs: None,
                docs: Vec::new(),
                license: Some("GPL-2.0-or-later".to_string()),
                dependencies: vec![],
            }),
            homebrew_info_error: None,
            npm_homepage: None,
            npm_package_info_error: None,
            security_state: None,
            version_options: Vec::new(),
        };

        let rendered = format_package_info(&info);
        assert!(rendered.contains("╭─ Executables "));
        assert!(rendered.contains("ffmpeg"));
        assert!(rendered.contains("ffplay"));
        assert!(rendered.contains("ffprobe"));
        assert!(!rendered.contains("/usr/local/bin/ffmpeg"));
    }

    #[test]
    fn format_package_info_reports_cask_metadata() {
        let info = PackageInfo {
            package_name: "codex".to_string(),
            qualified_name: "cask:codex".to_string(),
            install_root: PathBuf::from("/opt/codex"),
            installed: true,
            source: Some(PackageReceiptSource::Cask {
                cask_name: "codex".to_string(),
            }),
            source_error: None,
            aliases: Vec::new(),
            aliases_error: None,
            installed_version: Some("0.1.2505231602".to_string()),
            latest_version: Some("0.1.2505231602".to_string()),
            latest_version_error: None,
            executable_paths: vec!["/usr/local/bin/codex".to_string()],
            executable_paths_error: None,
            popularity: None,
            last_updated_at: None,
            homebrew_info: Some(HomebrewPackageInfo {
                formula: "codex".to_string(),
                description: Some("OpenAI codex CLI".to_string()),
                homepage: Some("https://github.com/openai/codex".to_string()),
                repository: None,
                upstream_docs: None,
                docs: Vec::new(),
                license: None,
                dependencies: vec!["ripgrep".to_string()],
            }),
            homebrew_info_error: None,
            npm_homepage: None,
            npm_package_info_error: None,
            security_state: None,
            version_options: Vec::new(),
        };

        let rendered = format_package_info(&info);
        assert!(rendered.contains("📦 cask:codex"));
        assert!(rendered.contains("Source        Homebrew Cask"));
        assert!(rendered.contains("Description   OpenAI codex CLI"));
        assert!(rendered.contains("Homepage      https://github.com/openai/codex"));
        assert!(rendered.contains("ripgrep"));
    }

    #[test]
    fn format_package_info_reports_vendor_package_with_subs_prefix() {
        let info = PackageInfo {
            package_name: "deno".to_string(),
            qualified_name: "av:deno".to_string(),
            install_root: PathBuf::from("/opt/deno"),
            installed: false,
            source: Some(PackageReceiptSource::Vendor {
                vendor_name: "deno".to_string(),
            }),
            source_error: None,
            aliases: Vec::new(),
            aliases_error: None,
            installed_version: None,
            latest_version: Some("2.7.9".to_string()),
            latest_version_error: None,
            executable_paths: Vec::new(),
            executable_paths_error: None,
            popularity: None,
            last_updated_at: None,
            homebrew_info: None,
            homebrew_info_error: None,
            npm_homepage: None,
            npm_package_info_error: None,
            security_state: None,
            version_options: Vec::new(),
        };

        let rendered = format_package_info(&info);
        assert!(rendered.contains("📦 av:deno"));
        assert!(rendered.contains("Version       2.7.9"));
        assert!(rendered.contains("Installed     no"));
        assert!(rendered.contains("Source        Subs"));
        assert!(!rendered.contains("Aliases"));
        assert!(
            rendered
                .lines()
                .all(|line| line.chars().count() <= INFO_WIDTH)
        );
    }

    #[test]
    fn format_package_info_reports_npm_homepage() {
        let info = PackageInfo {
            package_name: "openclaw".to_string(),
            qualified_name: "npm:openclaw".to_string(),
            install_root: PathBuf::from("/opt/npm/openclaw"),
            installed: false,
            source: Some(PackageReceiptSource::Npm {
                package_name: "openclaw".to_string(),
            }),
            source_error: None,
            aliases: Vec::new(),
            aliases_error: None,
            installed_version: None,
            latest_version: Some("4.5.6".to_string()),
            latest_version_error: None,
            executable_paths: Vec::new(),
            executable_paths_error: None,
            popularity: None,
            last_updated_at: None,
            homebrew_info: None,
            homebrew_info_error: None,
            npm_homepage: Some("https://www.example.com/openclaw".to_string()),
            npm_package_info_error: None,
            security_state: None,
            version_options: Vec::new(),
        };

        let rendered = format_package_info(&info);
        assert!(rendered.contains("📦 npm:openclaw"));
        assert!(rendered.contains("https://www.example.com/openclaw"));
        assert!(
            rendered
                .lines()
                .all(|line| line.chars().count() <= INFO_WIDTH)
        );
    }

    #[test]
    fn package_info_helpers_cover_identity_formatting_and_wrapping() {
        assert_eq!(
            requested_package_name(&RequestedPackage::Isotope("gh".to_string())),
            "isotope:gh"
        );
        let status = PackageStatus {
            package_name: "npm:openclaw".to_string(),
            source: PackageReceiptSource::Npm {
                package_name: "openclaw".to_string(),
            },
            installed_version: "1.0.0".to_string(),
            latest_version: "1.0.0".to_string(),
        };
        assert_eq!(
            requested_package_from_status(&status),
            RequestedPackage::NpmPackage {
                package: "openclaw".to_string(),
                version: None,
            }
        );
        assert!(!status.is_outdated());
        assert_eq!(
            compare_package_names_for_search_order("npm:@scope/zeta", "brew:alpha"),
            std::cmp::Ordering::Greater
        );

        for (source, qualified, label) in [
            (
                PackageReceiptSource::Formula {
                    root_formula: "python@3.12".to_string(),
                },
                "brew:python@3.12",
                "Homebrew",
            ),
            (
                PackageReceiptSource::Cask {
                    cask_name: "visual-studio-code".to_string(),
                },
                "cask:visual-studio-code",
                "Homebrew Cask",
            ),
            (
                PackageReceiptSource::Isotope {
                    isotope_name: "gh".to_string(),
                },
                "isotope:gh",
                "Isotope",
            ),
            (
                PackageReceiptSource::Vendor {
                    vendor_name: "deno".to_string(),
                },
                "av:deno",
                "Subs",
            ),
            (
                PackageReceiptSource::Npm {
                    package_name: "openclaw".to_string(),
                },
                "npm:openclaw",
                "npm",
            ),
            (
                PackageReceiptSource::Pip {
                    package_name: "psycopg2".to_string(),
                },
                "pip:psycopg2",
                "PyPI",
            ),
        ] {
            assert_eq!(package_source_qualified_name(&source), qualified);
            assert_eq!(format_source_field(Some(&source)), label);
        }
        assert_eq!(format_source_field(None), "Unknown");

        let mut info = PackageInfo {
            package_name: "python@3.12".to_string(),
            qualified_name: String::new(),
            install_root: PathBuf::from("/opt/python@3.12"),
            installed: true,
            source: Some(PackageReceiptSource::Formula {
                root_formula: "python@3.12".to_string(),
            }),
            source_error: None,
            aliases: Vec::new(),
            aliases_error: None,
            installed_version: Some("3.12.1".to_string()),
            latest_version: Some("3.12.2".to_string()),
            latest_version_error: None,
            executable_paths: vec!["/usr/local/bin/python3.12".to_string()],
            executable_paths_error: None,
            popularity: None,
            last_updated_at: None,
            homebrew_info: Some(HomebrewPackageInfo {
                formula: "python@3.12".to_string(),
                description: Some("A language runtime".to_string()),
                homepage: Some("https://www.python.org".to_string()),
                repository: None,
                upstream_docs: None,
                docs: Vec::new(),
                license: Some("Python-2.0".to_string()),
                dependencies: vec!["openssl@3".to_string(), "sqlite".to_string()],
            }),
            homebrew_info_error: None,
            npm_homepage: None,
            npm_package_info_error: None,
            security_state: None,
            version_options: Vec::new(),
        };
        populate_package_info_identity(&mut info);
        assert_eq!(info.qualified_name, "brew:python@3.12");
        assert_eq!(
            format_version_status(&info),
            Some("update available (3.12.2)".to_string())
        );
        let rendered = format_package_info(&info);
        assert!(rendered.contains("Dependencies"));
        assert!(rendered.contains("Formula Page"));
        assert!(rendered.contains("/usr/local/bin/python3.12"));
        assert!(
            rendered
                .lines()
                .all(|line| line.chars().count() <= INFO_WIDTH)
        );

        assert_eq!(string_or_none("  value  "), Some("value".to_string()));
        assert_eq!(string_or_none(" \n\t "), None);
        assert_eq!(split_text_hard("abcdefgh", 3), vec!["abc", "def", "gh"]);
        assert_eq!(
            wrap_text("alpha beta\n\nsupercalifragilistic", 8),
            vec!["alpha", "beta", "", "supercal", "ifragili", "stic"]
        );
        assert_eq!(
            wrap_tokens(&["alpha".to_string(), "beta".to_string()], 2, 3),
            vec!["  alpha   beta"]
        );
        assert_eq!(
            homebrew_formula_page_url("python@3.12"),
            "https://formulae.brew.sh/formula/python@3.12"
        );
        assert!(plain_box_top().starts_with("╭"));
        assert!(section_top("Executables").contains("Executables"));
        assert!(plain_box_bottom().starts_with("╰"));
        assert!(section_bottom().starts_with("╰"));
    }

    #[test]
    fn package_info_source_resolution_and_scanning_cover_fallbacks() {
        let temp = TempDir::new().unwrap();
        let opt_root = temp.path().join("opt");
        let formula_root = opt_root.join("python@3.12");
        let npm_root = opt_root.join("npm/openclaw");
        let scoped_npm_root = opt_root.join("npm/@scope/tool");
        let pip_root = opt_root.join("pip/psycopg2");
        let isotope_root = opt_root.join("iso/gh");
        fs::create_dir_all(&formula_root).unwrap();
        fs::create_dir_all(&npm_root).unwrap();
        fs::create_dir_all(&scoped_npm_root).unwrap();
        fs::create_dir_all(&pip_root).unwrap();
        fs::create_dir_all(&isotope_root).unwrap();
        fs::write(opt_root.join("README"), b"skip").unwrap();
        fs::create_dir_all(opt_root.join(".tmp")).unwrap();
        fs::create_dir_all(opt_root.join("homebrew")).unwrap();
        write_package_receipt(
            &formula_root.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "python@3.12".to_string(),
                version: "3.12.1".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "python@3.12".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        write_package_receipt(
            &npm_root.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "npm:openclaw".to_string(),
                version: "4.5.6".to_string(),
                source: PackageReceiptSource::Npm {
                    package_name: "openclaw".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        write_stub_manifest(
            &formula_root.join(STUB_MANIFEST),
            &StubManifest {
                stubs: vec!["python3.12".to_string(), "pip3.12".to_string()],
            },
        )
        .unwrap();

        let refs = installed_package_refs(&opt_root).unwrap();
        assert!(
            refs.iter()
                .any(|package| package.package_name == "python@3.12")
        );
        assert!(
            refs.iter()
                .any(|package| package.package_name == "npm:openclaw")
        );
        assert!(
            refs.iter()
                .any(|package| package.package_name == "npm:@scope/tool")
        );
        assert!(
            refs.iter()
                .any(|package| package.package_name == "pip:psycopg2")
        );
        assert!(
            refs.iter()
                .any(|package| package.package_name == "isotope:gh")
        );
        assert_eq!(
            installed_stub_paths_at(&formula_root).unwrap(),
            vec![
                managed_bin_root().join("pip3.12").display().to_string(),
                managed_bin_root().join("python3.12").display().to_string(),
            ]
        );
        assert!(
            load_or_resolve_package_receipt("missing", temp.path())
                .unwrap_err()
                .contains("missing package metadata")
        );
        assert!(
            resolve_installed_package_record_at("file", &opt_root.join("README"))
                .unwrap_err()
                .contains("not a directory")
        );
        assert!(
            resolve_installed_package_record_at("absent", &opt_root.join("absent"))
                .unwrap_err()
                .contains("is not installed")
        );

        let mut warnings = Vec::new();
        let records = resolve_scanned_package_records(
            refs.clone(),
            |package| {
                if package.package_name == "pip:psycopg2" {
                    Err("bad receipt".to_string())
                } else {
                    Ok(InstalledPackageRecord {
                        package_name: package.package_name.clone(),
                        source: PackageReceiptSource::Formula {
                            root_formula: package.package_name.clone(),
                        },
                        installed_version: "1.0.0".to_string(),
                    })
                }
            },
            |message| warnings.push(message),
        )
        .unwrap();
        assert!(
            records
                .iter()
                .any(|record| record.package_name == "python@3.12")
        );
        assert!(
            warnings
                .iter()
                .any(|message| message.contains("bad receipt"))
        );

        let statuses = resolve_scanned_package_statuses(
            refs,
            |package| {
                Ok(PackageStatus {
                    package_name: package.package_name.clone(),
                    source: PackageReceiptSource::Formula {
                        root_formula: package.package_name.clone(),
                    },
                    installed_version: "1.0.0".to_string(),
                    latest_version: if package.package_name == "npm:openclaw" {
                        "2.0.0".to_string()
                    } else {
                        "1.0.0".to_string()
                    },
                })
            },
            |_message| {},
        )
        .unwrap();
        assert_eq!(
            filter_outdated_package_statuses(statuses)
                .into_iter()
                .map(|status| status.package_name)
                .collect::<Vec<_>>(),
            vec!["npm:openclaw".to_string()]
        );
    }

    #[test]
    fn package_record_and_status_wrappers_use_requested_selection() {
        let _env_lock = test_env_lock().lock().unwrap();
        let opt_root = opt_pkg_root();
        let record_name = "coverage-record";
        let status_name = "coverage-cask-status";
        let record_root = opt_root.join(record_name);
        let status_root = opt_root.join(status_name);
        for root in [&record_root, &status_root] {
            if fs::symlink_metadata(root).is_ok() {
                remove_path(root).unwrap();
            }
            fs::create_dir_all(root).unwrap();
        }
        write_package_receipt(
            &record_root.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: record_name.to_string(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: record_name.to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        write_package_receipt(
            &status_root.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: status_name.to_string(),
                version: "0.0.1".to_string(),
                source: PackageReceiptSource::Isotope {
                    isotope_name: "gh".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();

        let records = resolve_installed_package_records(&PackageSelection::Requested(vec![
            RequestedPackage::Auto(record_name.to_string()),
            RequestedPackage::Auto(record_name.to_string()),
        ]))
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].package_name, record_name);
        assert_eq!(
            resolve_installed_package_record(record_name)
                .unwrap()
                .installed_version,
            "1.0.0"
        );

        let config = Config {
            bottle_tag: "all".to_string(),
        };
        let statuses = resolve_package_statuses(
            &config,
            &PackageSelection::Requested(vec![RequestedPackage::Auto(status_name.to_string())]),
        )
        .unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].package_name, status_name);
        assert_eq!(statuses[0].installed_version, "0.0.1");
        assert!(statuses[0].is_outdated());
        assert_eq!(
            resolve_outdated_package_statuses(
                &config,
                &PackageSelection::Requested(vec![RequestedPackage::Auto(status_name.to_string())])
            )
            .unwrap()
            .len(),
            1
        );

        remove_path(&record_root).unwrap();
        remove_path(&status_root).unwrap();
    }

    #[test]
    fn secret_scanner_warnings_cover_path_and_source_only_errors() {
        let report = SecretScannerReport {
            scope: SecretScannerScope::Full,
            findings: Vec::new(),
            errors: vec![
                SecretScannerError {
                    source: "filesystem".to_string(),
                    path: Some("/tmp/secret".to_string()),
                    message: "permission denied".to_string(),
                },
                SecretScannerError {
                    source: "detector".to_string(),
                    path: None,
                    message: "unavailable".to_string(),
                },
            ],
            summary: SecretScannerSummary {
                scanned_files: 0,
                findings: 0,
                errors: 2,
                isotope_detectors: 0,
                file_probes: 0,
            },
        };

        for error in &report.errors {
            print_secret_scanner_warning_line(error, false);
            print_wrapped_secret_scanner_warning_line(error, false);
        }
    }

    #[test]
    fn secret_scanner_stream_printer_covers_wrapped_events_and_empty_summary() {
        let finding = SecretScannerFinding {
            source: "dotenv".to_string(),
            kind: "plaintext-secret".to_string(),
            severity: "high".to_string(),
            path: Some("/tmp/project/.env".to_string()),
            line: Some(3),
            message: "API_KEY is plaintext".to_string(),
        };
        let error = SecretScannerError {
            source: "file-probe:zsh".to_string(),
            path: Some("/tmp/.zshrc".to_string()),
            message: "permission denied".to_string(),
        };
        let report = SecretScannerReport {
            scope: SecretScannerScope::Full,
            findings: vec![finding.clone()],
            errors: vec![error.clone()],
            summary: SecretScannerSummary {
                scanned_files: 2,
                findings: 1,
                errors: 1,
                isotope_detectors: 1,
                file_probes: 1,
            },
        };
        let mut printer = SecretScannerStreamPrinter {
            format: SecretScannerStreamFormat::Wrapped,
            color: false,
            scope: SecretScannerScope::Full,
            finding_count: 0,
            printed_findings_header: false,
            printed_warnings_header: false,
        };
        printer.begin().unwrap();
        printer
            .print_event(SecretScannerEvent::Finding(&finding))
            .unwrap();
        printer
            .print_event(SecretScannerEvent::Error(&error))
            .unwrap();
        printer.finish(&report).unwrap();
        assert_eq!(printer.finding_count, 1);
        assert!(printer.printed_findings_header);
        assert!(printer.printed_warnings_header);

        let empty_report = SecretScannerReport {
            scope: SecretScannerScope::IsotopesOnly,
            findings: Vec::new(),
            errors: Vec::new(),
            summary: SecretScannerSummary {
                scanned_files: 0,
                findings: 0,
                errors: 0,
                isotope_detectors: 0,
                file_probes: 0,
            },
        };
        let mut empty_printer = SecretScannerStreamPrinter {
            format: SecretScannerStreamFormat::Wrapped,
            color: false,
            scope: SecretScannerScope::IsotopesOnly,
            finding_count: 0,
            printed_findings_header: false,
            printed_warnings_header: false,
        };
        empty_printer.begin().unwrap();
        empty_printer.finish(&empty_report).unwrap();
        assert_eq!(empty_printer.finding_count, 0);

        for format in [
            SecretScannerStreamFormat::Plain,
            SecretScannerStreamFormat::Rich,
        ] {
            let mut printer = SecretScannerStreamPrinter {
                format,
                color: true,
                scope: SecretScannerScope::Full,
                finding_count: 0,
                printed_findings_header: false,
                printed_warnings_header: false,
            };
            printer.begin().unwrap();
            printer
                .print_event(SecretScannerEvent::Finding(&finding))
                .unwrap();
            printer
                .print_event(SecretScannerEvent::Error(&error))
                .unwrap();
            printer.finish(&report).unwrap();
            assert_eq!(printer.finding_count, 1);
            assert!(printer.printed_findings_header);
            assert!(printer.printed_warnings_header);

            let mut empty_printer = SecretScannerStreamPrinter {
                format,
                color: true,
                scope: SecretScannerScope::IsotopesOnly,
                finding_count: 0,
                printed_findings_header: false,
                printed_warnings_header: false,
            };
            empty_printer.begin().unwrap();
            empty_printer.finish(&empty_report).unwrap();
            assert_eq!(empty_printer.finding_count, 0);
        }

        print_scan_box(
            "Scan",
            &[
                "short".to_string(),
                "a much longer scanner line that exercises clamped box width".to_string(),
            ],
            true,
        );
        assert_eq!(strip_ansi_width("\u{1b}[31mred\u{1b}[0m"), 3);
        assert_eq!(
            secret_scanner_file_probe_summary(&empty_report),
            "file probes skipped"
        );
        assert_eq!(pluralize(1, "finding", "findings"), "1 finding");
        assert!(matches!(
            scan_severity_style(&SecretScannerFinding {
                severity: "low".to_string(),
                ..finding.clone()
            }),
            ScanStyle::Warning
        ));
        assert!(scan_paint("x", ScanStyle::Error, true).contains("\u{1b}[31;1m"));
        assert_eq!(scan_paint("x", ScanStyle::Error, false), "x");

        let _env_lock = test_env_lock().lock().unwrap();
        let _clean_env =
            TestEnvGuard::unset(&["NO_COLOR", "CLICOLOR_FORCE", "TERM", SCANNER_WRAPPER_UI_ENV]);
        assert!(!scanner_wrapper_ui_enabled());
        assert!(!output_supports_ansi(false));
        {
            let _env = TestEnvGuard::set(&[(SCANNER_WRAPPER_UI_ENV, "1")]);
            assert!(scanner_wrapper_ui_enabled());
        }
        {
            let _env = TestEnvGuard::set(&[("CLICOLOR_FORCE", "1")]);
            assert!(scan_stdout_is_rich());
            assert!(output_supports_ansi(false));
        }
        {
            let _env = TestEnvGuard::set(&[("NO_COLOR", "1")]);
            assert!(!output_supports_ansi(true));
        }
        {
            let _env = TestEnvGuard::set(&[("TERM", "dumb")]);
            assert!(!output_supports_ansi(true));
        }
    }

    #[test]
    fn package_info_metadata_helpers_cover_source_variants() {
        assert_eq!(
            explicit_requested_package_source(&RequestedPackage::HomebrewCask(
                "visual-studio-code".to_string()
            )),
            Some(PackageReceiptSource::Cask {
                cask_name: "visual-studio-code".to_string()
            })
        );
        assert_eq!(
            infer_requested_package_source(&RequestedPackage::Auto("bun".to_string())).unwrap(),
            PackageReceiptSource::Vendor {
                vendor_name: "bun".to_string()
            }
        );
        assert_eq!(
            infer_requested_package_source(&RequestedPackage::Auto(
                "definitely-not-a-package".to_string()
            ))
            .unwrap(),
            PackageReceiptSource::Formula {
                root_formula: "definitely-not-a-package".to_string(),
            }
        );
        let (cask_aliases, cask_alias_error) =
            resolve_aliases_for_source(&PackageReceiptSource::Cask {
                cask_name: "visual-studio-code".to_string(),
            });
        assert!(cask_alias_error.is_none());
        assert!(cask_aliases.is_empty());
        assert!(
            homebrew_aliases_for_formula("nonexistent-formula")
                .unwrap()
                .is_empty()
        );
        assert_eq!(formula_versioned_base("openssl@3"), Some("openssl"));
        assert_eq!(formula_versioned_base("@3"), None);
        assert_eq!(formula_versioned_base("openssl@stable"), None);

        let mut formula = formula_info(false);
        formula.desc = " Demo formula ".to_string();
        formula.homepage = "https://example.com".to_string();
        formula.license = Some(" MIT ".to_string());
        formula.dependencies = vec!["openssl@3".to_string()];
        assert_eq!(
            homebrew_package_info_from_formula_info("demo", &formula),
            HomebrewPackageInfo {
                formula: "demo".to_string(),
                description: Some("Demo formula".to_string()),
                homepage: Some("https://example.com".to_string()),
                repository: None,
                upstream_docs: None,
                docs: Vec::new(),
                license: Some("MIT".to_string()),
                dependencies: vec!["openssl@3".to_string()],
            }
        );

        let isotope = isotope_package_data("gh").unwrap();
        let info = isotope_homebrew_info("gh", isotope);
        assert_eq!(info.formula, "gh");
        assert!(info.description.unwrap().contains("replacing brew:gh"));

        let mut results = vec![
            PackageSearchResult {
                package_name: "openssl".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "openssl".to_string(),
                },
                summary: None,
                latest_version: None,
                homepage: None,
                repository: None,
                upstream_docs: None,
                docs: Vec::new(),
                category: None,
                dependencies: Vec::new(),
                install_package_names: Vec::new(),
                security_state: None,
                rank: None,
                last_updated_at: None,
                pulse_kind: None,
            },
            PackageSearchResult {
                package_name: "openssl@3".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "openssl@3".to_string(),
                },
                summary: None,
                latest_version: None,
                homepage: None,
                repository: None,
                upstream_docs: None,
                docs: Vec::new(),
                category: None,
                dependencies: Vec::new(),
                install_package_names: Vec::new(),
                security_state: None,
                rank: None,
                last_updated_at: None,
                pulse_kind: None,
            },
            PackageSearchResult {
                package_name: "pip:openssl".to_string(),
                source: PackageReceiptSource::Pip {
                    package_name: "openssl".to_string(),
                },
                summary: None,
                latest_version: None,
                homepage: None,
                repository: None,
                upstream_docs: None,
                docs: Vec::new(),
                category: None,
                dependencies: Vec::new(),
                install_package_names: Vec::new(),
                security_state: None,
                rank: None,
                last_updated_at: None,
                pulse_kind: None,
            },
        ];
        suppress_unversioned_formulae_with_versioned_search_results(&mut results);
        assert_eq!(
            results
                .into_iter()
                .map(|result| result.package_name)
                .collect::<Vec<_>>(),
            vec!["openssl@3".to_string(), "pip:openssl".to_string()]
        );
        assert!(formula_index_entry_matches(
            &formula_index_entry("ripgrep", &["rg"], &["old-rg"]),
            "old-rg"
        ));
    }

    #[test]
    fn resolve_uninstalled_package_info_populates_all_source_metadata() {
        let _env_lock = test_env_lock().lock().unwrap();
        let (base, server) = start_test_http_server(
            vec![
                (
                    "/node.json".to_string(),
                    br#"{
                        "desc":"Node runtime",
                        "homepage":"https://nodejs.org",
                        "license":"MIT",
                        "versions":{"stable":"22.0.0"},
                        "dependencies":["openssl@3"],
                        "bottle":{
                            "stable":{
                                "files":{
                                    "all":{
                                        "sha256":"node-sha",
                                        "url":"https://example.test/node.tar.gz"
                                    }
                                }
                            }
                        },
                        "disabled":false
                    }"#
                    .to_vec(),
                ),
                (
                    "/coverage-npm".to_string(),
                    br#"{
                        "description":"Coverage npm package",
                        "homepage":"https://example.test/coverage-npm",
                        "dist-tags":{"latest":"1.2.3"},
                        "versions":{
                            "1.2.3":{
                                "dist":{"tarball":"https://example.test/coverage-npm.tgz"}
                            }
                        }
                    }"#
                    .to_vec(),
                ),
                (
                    "/coverage-pip/json".to_string(),
                    br#"{
                        "info":{
                            "version":"2.3.4",
                            "summary":"Coverage pip package",
                            "home_page":"https://example.test/coverage-pip"
                        }
                    }"#
                    .to_vec(),
                ),
            ],
            6,
        );
        let _endpoints = TestEndpointGuard::set(config::TestEndpointOverrides {
            formula_api_root: Some(base.clone()),
            npm_registry_root: Some(base.clone()),
            pypi_root: Some(base.clone()),
            ..Default::default()
        });
        let config = Config {
            bottle_tag: "all".to_string(),
        };

        let formula = resolve_package_info(
            &config,
            &RequestedPackage::HomebrewFormula("node".to_string()),
        )
        .unwrap();
        let expected_node_summary = crate::cli::load_db()
            .expect("embedded DB fixture must be available")
            .formulas
            .get("node")
            .and_then(|metadata| string_or_none(&metadata.summary))
            .expect("expected embedded DB to include a non-empty summary for formula `node`");
        let formula_homebrew_info = formula.homebrew_info.unwrap();
        assert!(!formula.installed);
        assert_eq!(formula.latest_version, Some("22.0.0".to_string()));
        assert_eq!(
            formula_homebrew_info.description,
            Some(expected_node_summary)
        );
        assert_eq!(formula_homebrew_info.license, Some("MIT".to_string()));
        assert_eq!(
            formula_homebrew_info.dependencies,
            vec!["openssl@3".to_string()]
        );

        let cask = resolve_package_info(
            &config,
            &RequestedPackage::HomebrewCask("codex".to_string()),
        )
        .unwrap();
        assert_eq!(
            cask.source,
            Some(PackageReceiptSource::Cask {
                cask_name: "codex".to_string()
            })
        );
        assert_eq!(cask.latest_version, Some("1.0.0".to_string()));

        let isotope =
            resolve_package_info(&config, &RequestedPackage::Isotope("gh".to_string())).unwrap();
        assert!(isotope.latest_version.is_some());
        assert!(
            isotope
                .homebrew_info
                .unwrap()
                .description
                .unwrap()
                .contains("replacing")
        );

        let npm = resolve_package_info(
            &config,
            &RequestedPackage::NpmPackage {
                package: "coverage-npm".to_string(),
                version: None,
            },
        )
        .unwrap();
        assert_eq!(npm.latest_version, Some("1.2.3".to_string()));
        assert_eq!(
            npm.npm_homepage,
            Some("https://example.test/coverage-npm".to_string())
        );

        let pip = resolve_package_info(
            &config,
            &RequestedPackage::PipPackage("coverage-pip".to_string()),
        )
        .unwrap();
        assert_eq!(pip.latest_version, Some("2.3.4".to_string()));
        server.join().unwrap();
    }

    #[test]
    fn parse_package_status_request_without_args_selects_all_installed() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av outdated".to_string(),
            mode: None,
        };
        let request = parse_package_status_request_from_iter(
            &invocation,
            Vec::<OsString>::new().into_iter(),
            print_outdated_usage,
        )
        .unwrap();

        assert_eq!(
            request,
            Some(PackageStatusRequest {
                selection: PackageSelection::AllInstalled,
                output: OutputMode::Human,
            })
        );
    }

    #[test]
    fn parse_package_status_request_accepts_multiple_packages() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av outdated".to_string(),
            mode: None,
        };
        let request = parse_package_status_request_from_iter(
            &invocation,
            vec![
                OsString::from("ffmpeg"),
                OsString::from("brew:python@3.12"),
                OsString::from("npm:openclaw"),
                OsString::from("pip:psycopg2"),
            ]
            .into_iter(),
            print_outdated_usage,
        )
        .unwrap();

        assert_eq!(
            request,
            Some(PackageStatusRequest {
                selection: PackageSelection::Requested(vec![
                    RequestedPackage::Auto("ffmpeg".to_string()),
                    RequestedPackage::HomebrewFormula("python@3.12".to_string()),
                    RequestedPackage::NpmPackage {
                        package: "openclaw".to_string(),
                        version: None,
                    },
                    RequestedPackage::PipPackage("psycopg2".to_string()),
                ]),
                output: OutputMode::Human,
            })
        );
    }

    #[test]
    fn parse_package_status_request_accepts_jsonl_output_flags() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av list".to_string(),
            mode: None,
        };
        let request = parse_package_status_request_from_iter(
            &invocation,
            vec![OsString::from("--jsonl"), OsString::from("ffmpeg")].into_iter(),
            print_list_usage,
        )
        .unwrap();

        assert_eq!(
            request,
            Some(PackageStatusRequest {
                selection: PackageSelection::Requested(vec![RequestedPackage::Auto(
                    "ffmpeg".to_string(),
                )]),
                output: OutputMode::Jsonl,
            })
        );
    }

    #[test]
    fn parse_package_status_request_rejects_conflicting_output_flags() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av list".to_string(),
            mode: None,
        };
        let request = parse_package_status_request_from_iter(
            &invocation,
            vec![OsString::from("--json"), OsString::from("--jsonl")].into_iter(),
            print_list_usage,
        );

        assert_eq!(
            request,
            Err("cannot combine --json and --jsonl".to_string())
        );
    }

    #[test]
    fn parse_secret_scanner_request_accepts_path_and_output_flags() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av scan".to_string(),
            mode: None,
        };
        let request = parse_secret_scanner_request_from_iter(
            &invocation,
            vec![
                OsString::from("--json"),
                OsString::from("--path"),
                OsString::from("/tmp/project"),
            ]
            .into_iter(),
        )
        .unwrap();

        assert_eq!(
            request,
            Some(SecretScannerRequest {
                path: Some(PathBuf::from("/tmp/project")),
                skip_paths: Vec::new(),
                output: OutputMode::Json,
                isotopes_only: false,
            })
        );
    }

    #[test]
    fn parse_secret_scanner_request_rejects_missing_path_value() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av scan".to_string(),
            mode: None,
        };
        let request = parse_secret_scanner_request_from_iter(
            &invocation,
            vec![OsString::from("--path")].into_iter(),
        );

        assert_eq!(request, Err("missing value for --path".to_string()));
    }

    #[test]
    fn secret_file_scanner_detects_env_tokens_without_printing_values() {
        let temp = TempDir::new().unwrap();
        let env_path = temp.path().join(".env");
        fs::write(
            &env_path,
            "OPENAI_API_KEY=sk-test_1234567890abcdef\nPLACEHOLDER=${TOKEN}\n",
        )
        .unwrap();

        let findings = scan_secret_file(&env_path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "secret-assignment");
        assert_eq!(findings[0].line, Some(1));
        assert!(!findings[0].message.contains("sk-test"));
    }

    #[test]
    fn secret_file_scanner_ignores_encrypted_dotenv_values() {
        let temp = TempDir::new().unwrap();
        let env_path = temp.path().join(".env");
        fs::write(
            &env_path,
            [
                "DOTENV_PUBLIC_KEY=abc",
                "POSTHOG_API_KEY=\"encrypted:BHvhiFrrSNTU2wyZKZZyXTJkeE/viMW2B4L40PlAwhMif8P5BPhG1ew9D7pmU3VFAejrrcQhqjiSog/vM8/wIGBHBYpM+0776ulrLQGbSrLtzjMyh0ig0AimnI9YFrctRb2bWkG7bqASerIwV+xvzQ==\"",
                "OPENAI_API_KEY=sk-test_1234567890abcdef",
            ]
            .join("\n"),
        )
        .unwrap();

        let findings = scan_secret_file(&env_path).unwrap();

        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].kind, "secret-assignment");
        assert_eq!(findings[0].line, Some(3));
        assert!(findings[0].message.contains("assigned to OPENAI_API_KEY"));
    }

    #[test]
    fn secret_file_scanner_ignores_source_code_token_references() {
        let temp = TempDir::new().unwrap();
        let swift_path = temp.path().join("SpotifyHelperBridge.swift");
        fs::write(
            &swift_path,
            [
                "private struct HelperEnvelope: Decodable {",
                "    let accessToken: String?",
                "    let refreshToken: String?",
                "}",
                "private enum HelperCommand: String {",
                "    case accessToken = \"access_token\"",
                "}",
                "private func token(from response: HelperEnvelope) throws -> SpotifyToken {",
                "    let accessToken = response.accessToken,",
                "    let refreshToken = response.refreshToken,",
                "    return SpotifyToken(accessToken: accessToken, refreshToken: refreshToken)",
                "}",
                "let apiKey = \"sk-test_1234567890abcdef\"",
            ]
            .join("\n"),
        )
        .unwrap();

        let findings = scan_secret_file(&swift_path).unwrap();

        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].line, Some(13));
        assert_eq!(findings[0].kind, "secret-assignment");
    }

    #[test]
    fn secret_file_scanner_ignores_source_constants_and_parser_tables() {
        let temp = TempDir::new().unwrap();
        let python_path = temp.path().join("tokenize.py");
        fs::write(
            &python_path,
            [
                "TOKEN_ENDS = TSPECIALS | WSP",
                "password = password or \"\"",
                "passwd = passwd or ''",
                "token_range = \"%d,%d-%d,%d:\" % (token.start + token.end)",
                "token = \"'\", token[0][1:-1]",
                "'a4337bc45a8fc544c03f52dc550cd6e1e87021bc896588bd79e901e2'",
                "'1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa'",
                "\"application/vnd.pypi.simple.v1+json\"",
            ]
            .join("\n"),
        )
        .unwrap();

        let findings = scan_secret_file(&python_path).unwrap();

        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn secret_file_scanner_ignores_shell_variable_expansions() {
        let temp = TempDir::new().unwrap();
        let shell_path = temp.path().join("dev.sh");
        fs::write(
            &shell_path,
            [
                "local npm_default_cache=\"$HOME/.npm\"",
                "local -a npm_residual_dirs=(\"_cacache\" \"_npx\" \"_logs\" \"_prebuilds\")",
                "local -a npm_descriptions=(\"npm cache directory\" \"npm npx cache\" \"npm logs\" \"npm prebuilds\")",
                "if [[ \"$npm_cache_path_normalized\" != \"$npm_default_cache_normalized\" ]]; then",
                "    for i in \"${!npm_residual_dirs[@]}\"; do",
                "        safe_clean \"$npm_cache_path/${npm_residual_dirs[$i]}\"/* \"${npm_descriptions[$i]} (custom path)\"",
                "    done",
                "fi",
            ]
            .join("\n"),
        )
        .unwrap();

        let findings = scan_secret_file(&shell_path).unwrap();

        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn secret_file_scanner_detects_source_secret_literals() {
        let temp = TempDir::new().unwrap();
        let source_path = temp.path().join("credentials.ts");
        fs::write(
            &source_path,
            [
                r#"const apiKey = "sk-live_1234567890abcdefghijklmnop";"#,
                r#"export const opaqueToken = "Rdb0XGysWuBnveWaNkyiM8Qz1Lp2";"#,
                r#"return "ghp_1234567890abcdefghijkl";"#,
            ]
            .join("\n"),
        )
        .unwrap();

        let findings = scan_secret_file(&source_path).unwrap();

        assert_eq!(findings.len(), 3, "{findings:?}");
        assert_eq!(findings[0].kind, "secret-assignment");
        assert_eq!(findings[1].kind, "secret-assignment");
        assert_eq!(findings[2].kind, "token-literal");
    }

    #[test]
    fn secret_file_scanner_ignores_json_boolean_and_null_values() {
        let temp = TempDir::new().unwrap();
        let json_path = temp.path().join("models.json");
        fs::write(
            &json_path,
            [
                r#"{"requiresAPIKey": false,"#,
                r#""remoteAuthentication": true,"#,
                r#""clientSecret": null,"#,
                r#""apiKey": "sk-test_1234567890abcdef","#,
                r#""token": "secret""#,
                r#"}"#,
            ]
            .join("\n"),
        )
        .unwrap();

        let findings = scan_secret_file(&json_path).unwrap();

        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].line, Some(4));
        assert_eq!(findings[0].kind, "secret-assignment");
    }

    #[test]
    fn secret_file_scanner_requires_stronger_values_outside_credential_files() {
        let temp = TempDir::new().unwrap();
        let notes_path = temp.path().join("notes.txt");
        fs::write(
            &notes_path,
            [
                "TOKEN_ENDS = TSPECIALS | WSP",
                "API_KEY=supervaultcodeqx",
                "API_KEY=Rdb0XGysWuBnveWaNkyiM8Qz1Lp2",
            ]
            .join("\n"),
        )
        .unwrap();

        let findings = scan_secret_file(&notes_path).unwrap();

        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].line, Some(3));
    }

    #[test]
    fn secret_file_scanner_ignores_code_docs_and_fixture_false_positives() {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path().join("test");
        fs::create_dir_all(&source_dir).unwrap();
        let source_path = source_dir.join("clawlicious-fixtures.test.ts");
        let lines = [
            "token.fromMs <= absoluteTimeMs && token.toMs > absoluteTimeMs;",
            "The user needs to create an access token by visiting https://console.mapbox.com/account/access-tokens/.",
            "REMOTION_MAPBOX_TOKEN==pk.your-mapbox-access-token",
            "mapboxgl.accessToken = process.env.REMOTION_MAPBOX_TOKEN as string;",
            r#""xi-api-key": process.env.ELEVENLABS_API_KEY!,"#,
            r#"const apiKey = typeof payload.apiKey === "string""#,
            r#"apiKey: typeof stored.apiKey === "string" ? stored.apiKey : "","#,
            r#"if (tokenScope === "full") {"#,
            "type ByoClawPollTokenRecord = NonNullable<ReturnType<typeof getByoClawPollToken>>;",
            "struct SpotifyToken: Codable {",
            "var plainTextSecretAlertSource: PackageSecurityNotice.Source? {",
            "secrets: BTreeMap<String, Result<String, String>>,",
            "if (!forumToken || forumToken.forum_id !== parsedParams.data.forumId) {",
            r#"const CHECKOUT_SUCCESS_TOKEN = "{CHECKOUT_SESSION_ID}";"#,
            "WHERE poll_token_id = ? AND id != ?`,",
            r#"data-api-key="{{ claw.api_key }}""#,
            r#"password: "password123","#,
            "const POLL_TOKEN_PATTERN = /^claw_poll_[a-f0-9]{48}$/;",
            r#"token: "handoff-token","#,
            "const renewedToken = tokenMatch[1];",
            r#"TOKEN_SERVICE = "https://ghcr.io/token""#,
            "def _fetch_json(url, github_token=None):",
            r#""Authorization": f"Bearer {token}","#,
            r#""token": bearer,"#,
            "metadata[token] = supported",
            ".secret-art::before {",
            "export AWS_SECRET_ACCESS_KEY=%awssecret%",
            "password=mb_password",
            r#""challengeToken": "f7D4...base64url...","#,
            r#""tokenType": "integration","#,
            r#""token": "clawlt_7wYx...base64url...","#,
            "export OUTCLAW_SSH_PRIVATE_KEY=~/.ssh/smbh-api-ec2-us-east-2.pem",
            r#"const TOKEN_PREFIX = "outclawclaw_";"#,
            r#"challengeToken: "string","#,
            "tokenHash: hashed,",
            r#""js-tokens": "^4.0.0","#,
            "id-token: write   # to verify the deployment originates from an appropriate source",
            "self.md.toc_tokens = toc_tokens",
            "MaxScanTokenSize = 64 * 1024",
            "token: &'static str,",
            "let executable = npm_package_executable_name(&npm_package);",
            "package_name: npm_package.clone(),",
            r#""[default]\naws_secret_access_key = secret\n","#,
            r#"static const char TestTokenLabel[] = "Test PKCS11 Token Label";"#,
            r#""input_token": "nextToken","#,
            "password: bytes | None,",
            "PASSWORD: optional password used to decrypt the structure",
            r#""detect-secrets": "detect-secrets","#,
            r#"export function randomToken(prefix = "pincerspace_", size = 24) {"#,
            "char const* token_last = nullptr;",
            "sso_token_cache=None):",
            r#"const apiKey = "sk-test_1234567890abcdef""#,
        ];
        fs::write(&source_path, lines.join("\n")).unwrap();

        let findings = scan_secret_file(&source_path).unwrap();

        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn secret_file_scanner_detects_jwt_tokens() {
        let temp = TempDir::new().unwrap();
        let env_path = temp.path().join(".env");
        fs::write(
            &env_path,
            "MAILERLITE_TOKEN=eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiIxMjM0NTY3ODkwIn0.signature_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\n",
        )
        .unwrap();

        let findings = scan_secret_file(&env_path).unwrap();

        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].kind, "secret-assignment");
    }

    #[test]
    fn secret_file_scanner_ignores_private_key_reference_fixtures() {
        let temp = TempDir::new().unwrap();
        let fixture_dir = temp.path().join("testdata");
        fs::create_dir_all(&fixture_dir).unwrap();
        let json_path = fixture_dir.join("wycheproof.json");
        fs::write(
            &json_path,
            r#""privateKeyPem": "-----BEGIN RSA PRIVATE KEY-----\nMIIEfixture\n-----END RSA PRIVATE KEY-----""#,
        )
        .unwrap();
        let source_path = temp.path().join("pubkey_pem.erl");
        fs::write(&source_path, r#"<<\"-----BEGIN RSA PRIVATE KEY-----\">>;"#).unwrap();

        assert!(scan_secret_file(&json_path).unwrap().is_empty());
        assert!(scan_secret_file(&source_path).unwrap().is_empty());
    }

    #[test]
    fn secret_file_scanner_helper_assumptions_cover_parser_edges() {
        let assignment = parse_secret_assignment("- token: value").unwrap();
        assert_eq!(assignment.key, "token");
        assert_eq!(assignment.value, " value");
        assert!(matches!(
            assignment.separator,
            SecretAssignmentSeparator::Colon
        ));

        let assignment = parse_secret_assignment("TOKEN=value").unwrap();
        assert_eq!(assignment.key, "TOKEN");
        assert_eq!(assignment.value, "value");
        assert!(matches!(
            assignment.separator,
            SecretAssignmentSeparator::Equals
        ));

        let assignment = parse_secret_assignment("URL=http://example.test/token").unwrap();
        assert_eq!(assignment.key, "URL");
        assert_eq!(assignment.value, "http://example.test/token");
        assert!(matches!(
            assignment.separator,
            SecretAssignmentSeparator::Equals
        ));

        let assignment = parse_secret_assignment(r#""token": "value""#).unwrap();
        assert_eq!(assignment.key, r#""token""#);
        assert_eq!(assignment.value, r#" "value""#);
        assert!(matches!(
            assignment.separator,
            SecretAssignmentSeparator::Colon
        ));

        for line in [
            "token == value",
            "token != value",
            "token <= value",
            "token >= value",
            "token => value",
            "SecretScannerStreamFormat::Plain => {",
            ".secret-art::before {",
            "https://example.test/token",
            "no assignment here",
        ] {
            assert!(parse_secret_assignment(line).is_none(), "{line}");
        }
    }

    #[test]
    fn secret_file_scanner_helper_assumptions_cover_source_code_rejection() {
        for line in [
            r#"case accessToken = "access_token""#,
            "type PollToken = string",
            "interface TokenRecord = {}",
            "union APIKeyPropertiesResult = APIKeyPropertiesOutput | UserFacingError",
            "def _fetch_json(url, github_token=None):",
            "function randomToken(prefix = \"pkg_\") {",
            "export function randomToken(prefix = \"pkg_\") {",
            "return accessToken = response.accessToken",
            "if token = value",
            "if(token = value)",
            "WHERE poll_token_id = ?",
            "where poll_token_id = ?",
            "fd->secret->state = _PR_FILEDESC_OPEN",
            "left, right = tokens",
            "metadata[token] = supported",
            "self.md.toc_tokens = toc_tokens",
            "This freeform token heading: has explanatory prose",
            "`/secret-scanner-for-ai-agents/`: 332 words",
            "Authorization: optional bearer token used by the request",
            "token: &'static str,",
            "token: bytes | None,",
            "token: ResponseToken,",
            "token = ?",
            "token = // comment",
            "token = {{ template.token }}",
            "token = <% template %>",
            "token = {CHECKOUT_SESSION_ID}",
            "token = /token-.*/",
            "token = f\"Bearer {token}\"",
            "token = f'Bearer {token}'",
            "token = process.env.API_TOKEN",
            "token = &self.external_secret",
            "token = !ready",
            "token = if conv_summary.token_count > 0 {",
            "token = self.apiKey!",
            "token = match launch_mode {",
            "token = typeof payload.token",
            "token = ReturnType<TokenFactory>",
            "token = payload.token as string",
            "token = 64 * 1024",
            "token = closeStart + closeDuration",
            "token = argument_idx - 1",
            r#"token = "\(editableNamePrefix)\(name)""#,
            r#"token = Settings.apiKey ?? """#,
            "token = condition ? a : b",
            "token = a && b",
            "token = a || b",
            "token = a === b",
            "token = a !== b",
            "token = a == b",
            "token = a != b",
            "token = a <= b",
            "token = a >= b",
            "token = tokenMatch[1]",
            "token = .leading.member",
            "token = tokenFactory()",
            "token = fd->secret",
            "token = Namespace::Token",
            "token = response.accessToken",
            "token = RefreshToken",
            "token = query?",
            "token = SecretRange {",
            "token: BTreeMap<String, Result<String, String>>,",
            "let token_syntax_color: AnsiColorIdentifier =",
            "pub parsed_token: &'a ParsedToken,",
            "token: FileIndexScanToken? = nil,",
            r#"secret: "fixture".to_owned(),"#,
        ] {
            let assignment = parse_secret_assignment(line).unwrap();
            assert!(
                secret_assignment_looks_like_source_code(&assignment),
                "{line}"
            );
        }

        for line in [
            "TOKEN=secret_secret",
            "OPENAI_API_KEY=sk-test_1234567890abcdef",
            "Authorization: Bearer realtoken1234567890",
        ] {
            let assignment = parse_secret_assignment(line).unwrap();
            assert!(
                !secret_assignment_looks_like_source_code(&assignment),
                "{line}"
            );
        }
    }

    #[test]
    fn secret_file_scanner_helper_assumptions_cover_sensitive_keys_and_metadata() {
        for key in [
            "token",
            "password",
            "passwd",
            "authorization",
            "API_KEY",
            "api.key",
            "apikey",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "auth_token",
            "private_key",
            "refresh_token",
            "id_token",
            "client_secret",
            "export OPENAI_API_KEY",
        ] {
            assert!(secret_key_name_is_sensitive(key), "{key}");
        }

        for key in [
            "tokenType",
            "token-types",
            "tokenName",
            "token_names",
            "TOKEN_PREFIX",
            "TOKEN_SUFFIX",
            "TOKEN_SERVICE",
            "tokenHash",
            "tokenLabel",
            "tokenLabels",
            "TOKEN_PATTERN",
            "tokenPatterns",
            "tokenClass",
            "MaxScanTokenSize",
            "SOFTOKEN_LIB_DIR",
            "PRIVATE_KEY_PATH",
            "private-key-file",
            "token.url",
            "token_uri",
        ] {
            assert!(secret_key_name_is_noncredential_metadata(key), "{key}");
            assert!(!secret_key_name_is_sensitive(key), "{key}");
        }
    }

    #[test]
    fn secret_file_scanner_helper_assumptions_cover_real_value_classification() {
        for value in [
            "short",
            "${TOKEN}",
            "secret",
            "password",
            "token",
            "example",
            "changeme",
            "change_me",
            "replace_me",
            "redacted",
            "access_token",
            "refresh_token",
            "id_token",
            "client_secret",
            "api_key",
            "none",
            "null",
            "true",
            "false",
            "string",
            "bytes",
            "write",
            "read",
            "hashed",
            "nullptr",
            "nil",
            "example-token",
            "placeholder-token",
            "your_token_here",
            "your-token-here",
            "clawlt_7wYx...base64url...",
            "gho_************************************",
            "gho_******",
            "fake-key",
            "fake-admin-key",
            "fake-token",
            "env(OPENAI_API_KEY)",
            "$tokens",
            "200000",
            "options:name1: blue,red,green",
            r#""[default]\naws_secret_access_key = secret\n""#,
            "Bearer <temporary_token>",
            "Bearer smbhclaw_\u{2026}",
            "xxxxxxxx",
            "********",
            "{TOKEN}",
            "{{ TOKEN }}",
            "<TOKEN>",
            "%awssecret%",
            "~/secret.pem",
            "./secret.key",
            "../secret.key",
            "/Users/me/secret.key",
            "https://ghcr.io/token",
            "^4.0.0",
            "3.0.0 || ^4.0.0",
            "cfengine",
            "detect-secrets",
            "nextToken",
            "NSS Certificate DB",
        ] {
            assert!(!secret_value_is_real(value), "{value}");
        }

        for value in [
            "secret_secret",
            "sk-test_1234567890abcdef",
            "phc_1234567890abcdefghijkl",
            "xai-CaxcatEA921Wrn5N6GyOuEfUrWwK90J1yBvn5Ehou5pUxWzgh0vGFBHrWCXAiBn68Z",
            "Rdb0XGysWuBnveWaNkyi",
            "dY3v9zk5epFZDMgoxUfDNp7fO2bGKQW4tT8wy58gGmHgg5oHPOeT9TdPDnzCINj3",
            "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiIxMjM0NTY3ODkwIn0.signature_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
        ] {
            assert!(secret_value_is_real(value), "{value}");
        }
    }

    #[test]
    fn secret_file_scanner_helper_assumptions_cover_token_shapes_and_normalization() {
        for value in [
            "ghp_1234567890abcdefghijkl",
            "gho_1234567890abcdefghijkl",
            "ghs_1234567890abcdefghijkl",
            "github_pat_1234567890abcdefghijklmnopqrstuvwxyz",
            "glpat-1234567890abcdefghijkl",
            "xoxb-1234567890abcdefghijkl",
            "xoxp-1234567890abcdefghijkl",
            "sk_live_1234567890abcdefghijkl",
            "npm_1234567890abcdef",
            "sk-proj-1234567890abcdef",
            "xai-1234567890abcdefghi",
            "AKIA1234567890ABCDEF",
        ] {
            assert!(secret_value_has_known_token_shape(value), "{value}");
        }

        assert!(!secret_value_has_known_token_shape("npm_pkg"));
        assert!(!secret_value_has_known_token_shape("gho_abc123"));
        assert!(!secret_value_has_known_token_shape("github_pat_abc123"));
        assert!(secret_value_has_high_entropy_shape(
            "Rdb0XGysWuBnveWaNkyiM8Qz1Lp2"
        ));
        assert!(!secret_value_has_high_entropy_shape("TSPECIALS | WSP"));
        assert!(!secret_value_has_high_entropy_shape("supervaultcodeqx"));
        assert!(secret_value_looks_like_jwt(
            "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiIxMjM0NTY3ODkwIn0.signature_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        ));
        assert!(!secret_value_looks_like_jwt("response.accessToken"));
        assert!(!secret_value_looks_like_jwt("one.two.three.four"));

        assert_eq!(normalized_secret_value(r#" "false", "#), "false");
        assert_eq!(normalized_secret_value(" write   # comment"), "write");
        assert_eq!(normalized_secret_value("'secret');"), "secret");
        assert_eq!(
            normalized_secret_key_name("export API-KEY.name"),
            "api_key_name"
        );
        assert!(!secret_value_has_known_token_shape("npm_payloads or {}"));
    }

    #[test]
    fn secret_file_scanner_helper_assumptions_cover_source_string_fixtures() {
        for line in [
            r###""    let accessToken = response.accessToken,","###,
            r###""TOKEN=secret_secret","#"###,
            r###""OPENAI_API_KEY=sk-test_1234567890abcdef","#"###,
            r###"r#""apiKey": "sk-test_1234567890abcdef","#,"###,
            r#####"r###"r#""apiKey": "sk-test_1234567890abcdef","#,"#####,
            r###"br#""token": "fake-token""#,"###,
        ] {
            assert!(
                secret_line_looks_like_source_string_fixture(Path::new("/repo/src/lib.rs"), line),
                "{line}"
            );
            assert!(
                !secret_line_looks_like_source_string_fixture(Path::new("/repo/config.json"), line),
                "{line}"
            );
        }
    }

    #[test]
    fn secret_file_scanner_helper_assumptions_cover_fixture_paths() {
        for path in [
            "/repo/test/file.ts",
            "/repo/tests/file.ts",
            r"C:\repo\test\file.ts",
            r"C:\repo\tests\file.ts",
            "/repo/token.test.ts",
            "/repo/token.spec.ts",
            "/repo/token_tests.rs",
        ] {
            assert!(
                secret_path_looks_like_test_fixture(Path::new(path)),
                "{path}"
            );
        }

        for path in [
            "/repo/testdata/vector.json",
            "/repo/fixtures/vector.json",
            "/repo/fixture/vector.json",
            "/repo/examples/key.rst",
            "/repo/example/key.rst",
            "/repo/samples/key.req",
            "/repo/sample/key.req",
            "/repo/cavs_samples/key.req",
            "/repo/wycheproof/key.json",
            "/repo/doc/key.rst",
            "/repo/docs/key.rst",
            "/repo/share/man/man5/key.5",
            "/repo/share/info/key.info",
            "/repo/man/man3/key.3",
            "/repo/resources/bundled/skills/README.md",
            "/repo/hooks/fsmonitor-watchman.sample",
            "/repo/en.lproj/Localizable.strings",
        ] {
            assert!(
                secret_path_looks_like_reference_fixture(Path::new(path)),
                "{path}"
            );
            assert!(secret_value_is_test_fixture(
                Path::new(path),
                "sk-real_1234567890abcdef"
            ));
        }

        for value in [
            "password123",
            "handoff-token",
            "test-token",
            "test-password",
            "polar_test_token",
            "polar_webhook_secret",
        ] {
            assert!(secret_value_is_test_fixture(
                Path::new("/repo/test/auth.ts"),
                value
            ));
        }

        assert!(!secret_value_is_test_fixture(
            Path::new("/repo/src/auth.ts"),
            "sk-test_1234567890abcdef"
        ));
    }

    #[test]
    fn secret_file_scanner_ignores_sample_hook_source() {
        let temp = TempDir::new().unwrap();
        let sample_path = temp.path().join("hooks/fsmonitor-watchman.sample");
        fs::create_dir_all(sample_path.parent().unwrap()).unwrap();
        fs::write(
            &sample_path,
            [
                "\t# further constrain the results.",
                "\tmy $last_update_line = \"\";",
                "\tif (substr($last_update_token, 0, 1) eq \"c\") {",
                "\t\t$last_update_token = \"\\\"$last_update_token\\\"\";",
                "\t\t$last_update_line = qq[\\n\"since\": $last_update_token,];",
                "\t}",
            ]
            .join("\n"),
        )
        .unwrap();

        assert!(scan_secret_file(&sample_path).unwrap().is_empty());
    }

    #[test]
    fn secret_file_scanner_ignores_sensitive_keys_in_test_fixtures() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("project");
        fs::create_dir_all(&root).unwrap();

        let test_path = root.join("secrets_test.rs");
        fs::write(
            &test_path,
            [
                r#"api_key = "sk-live_1234567890abcdefghijklmnop""#,
                r#"secret: "码1234".to_owned(),"#,
                r#"stripe_restricted_api_key = "rk_live_1234567890abcdefghijklmnop""#,
            ]
            .join("\n"),
        )
        .unwrap();

        assert!(scan_secret_file(&test_path).unwrap().is_empty());
    }

    #[test]
    fn secret_file_scanner_detects_posthog_keys_in_env_files() {
        let temp = TempDir::new().unwrap();
        let envrc_path = temp.path().join(".envrc");
        fs::write(
            &envrc_path,
            "export POSTHOG_API_KEY=phc_1234567890abcdefghijklmnop\n",
        )
        .unwrap();

        let findings = scan_secret_file(&envrc_path).unwrap();

        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].line, Some(1));
        assert_eq!(findings[0].kind, "secret-assignment");
    }

    #[test]
    fn secret_file_scanner_detects_lowercase_env_secret_values() {
        let temp = TempDir::new().unwrap();
        let envrc_path = temp.path().join(".envrc");
        fs::write(
            &envrc_path,
            [
                "export TMDB_API_KEY=5368abcd9012efab3456abcd9012efab",
                "export TWITCH_CLIENT_SECRET=mbji9xv2qlemn8n2sk4pxh71r03j2x",
                "export JEWELFORM_ADMIN_TOKEN=supervaultcodeqx",
                "export AWS_REGION=us-east-1",
                "export API_KEY=example",
                "export API_KEY=nextToken",
            ]
            .join("\n"),
        )
        .unwrap();

        let findings = scan_secret_file(&envrc_path).unwrap();

        assert_eq!(findings.len(), 3, "{findings:?}");
        assert_eq!(findings[0].line, Some(1));
        assert_eq!(findings[1].line, Some(2));
        assert_eq!(findings[2].line, Some(3));
    }

    #[test]
    fn secret_file_scanner_detects_shell_startup_secret_assignments() {
        let temp = TempDir::new().unwrap();
        let bash_profile = temp.path().join(".bash_profile");
        let zshenv = temp.path().join(".zshenv");
        fs::write(
            &bash_profile,
            [
                "declare -x OPENAI_API_KEY=sk-test_1234567890abcdef",
                "export AWS_REGION=us-east-1",
                "export GITHUB_TOKEN=$(gh auth token)",
            ]
            .join("\n"),
        )
        .unwrap();
        fs::write(
            &zshenv,
            [
                "typeset -gx TWITCH_CLIENT_SECRET=mbji9xv2qlemn8n2sk4pxh71r03j2x",
                "typeset -gx API_KEY=example",
            ]
            .join("\n"),
        )
        .unwrap();

        let bash_findings = scan_secret_file(&bash_profile).unwrap();
        let zsh_findings = scan_secret_file(&zshenv).unwrap();

        assert_eq!(bash_findings.len(), 1, "{bash_findings:?}");
        assert_eq!(bash_findings[0].source, "file-probe:bash");
        assert_eq!(bash_findings[0].line, Some(1));
        assert!(
            bash_findings[0]
                .message
                .contains("assigned to OPENAI_API_KEY")
        );
        assert_eq!(zsh_findings.len(), 1, "{zsh_findings:?}");
        assert_eq!(zsh_findings[0].source, "file-probe:zsh");
        assert_eq!(zsh_findings[0].line, Some(1));
        assert!(
            zsh_findings[0]
                .message
                .contains("assigned to TWITCH_CLIENT_SECRET")
        );
    }

    #[test]
    fn shell_secret_detectors_scan_bash_and_zsh_startup_files() {
        let _lock = test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let home = temp.path().join("home");
        let zdotdir = temp.path().join("zdotdir");
        let bash_env = temp.path().join("bash-env");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&zdotdir).unwrap();
        fs::write(
            home.join(".profile"),
            "export SERVICE_TOKEN=secret_secret\n",
        )
        .unwrap();
        fs::write(&bash_env, "readonly BASH_ENV_TOKEN=secret_secret\n").unwrap();
        fs::write(
            zdotdir.join(".zprofile"),
            "typeset -gx ZED_CLIENT_SECRET=zedsecret1234\n",
        )
        .unwrap();
        let _env = TestEnvGuard::set(&[
            ("HOME", home.to_str().unwrap()),
            ("BASH_ENV", bash_env.to_str().unwrap()),
            ("ZDOTDIR", zdotdir.to_str().unwrap()),
        ]);

        let paths = default_secret_scan_paths();
        assert!(paths.iter().any(|path| path == &home.join(".bash_profile")));
        assert!(paths.iter().any(|path| path == &bash_env));
        assert!(paths.iter().any(|path| path == &zdotdir.join(".zprofile")));

        let profile_findings = scan_secret_file(&home.join(".profile")).unwrap();
        let bash_env_findings = scan_secret_file(&bash_env).unwrap();
        let zsh_findings = scan_secret_file(&zdotdir.join(".zprofile")).unwrap();

        assert_eq!(profile_findings.len(), 1, "{profile_findings:?}");
        assert_eq!(profile_findings[0].source, "file-probe:bash");
        assert_eq!(bash_env_findings.len(), 1, "{bash_env_findings:?}");
        assert_eq!(bash_env_findings[0].source, "file-probe:bash");
        assert_eq!(zsh_findings.len(), 1, "{zsh_findings:?}");
        assert_eq!(zsh_findings[0].source, "file-probe:zsh");
    }

    #[test]
    fn secret_file_scanner_detects_standalone_posthog_key_literals_in_config() {
        let temp = TempDir::new().unwrap();
        let gradle_path = temp.path().join("build.gradle.kts");
        fs::write(
            &gradle_path,
            r#"val posthogKey = providers.environmentVariable("POSTHOG_PROJECT_TOKEN").orNull
        ?: "phc_1234567890abcdefghijklmnop""#,
        )
        .unwrap();

        let findings = scan_secret_file(&gradle_path).unwrap();

        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].line, Some(2));
        assert_eq!(findings[0].kind, "token-literal");
    }

    #[test]
    fn secret_file_scanner_ignores_secret_named_cargo_dependencies() {
        let temp = TempDir::new().unwrap();
        let cargo_path = temp.path().join("Cargo.toml");
        fs::write(
            &cargo_path,
            r#"warp_managed_secrets = { package = "warp-managed-secrets", workspace = true }
managed_secrets = ["dep:managed-secrets"]"#,
        )
        .unwrap();

        assert!(scan_secret_file(&cargo_path).unwrap().is_empty());
    }

    #[test]
    fn secret_file_scanner_helper_assumptions_cover_private_key_handling() {
        for path in [
            "/repo/pubkey_pem.c",
            "/repo/pubkey_pem.cc",
            "/repo/pubkey_pem.cpp",
            "/repo/pubkey_pem.cxx",
            "/repo/pubkey_pem.h",
            "/repo/pubkey_pem.hh",
            "/repo/pubkey_pem.hpp",
            "/repo/pubkey_pem.hxx",
            "/repo/pubkey_pem.go",
            "/repo/pubkey_pem.rs",
            "/repo/pubkey_pem.swift",
            "/repo/pubkey_pem.js",
            "/repo/pubkey_pem.jsx",
            "/repo/pubkey_pem.ts",
            "/repo/pubkey_pem.tsx",
            "/repo/pubkey_pem.py",
            "/repo/pubkey_pem.rb",
            "/repo/pubkey_pem.pm",
            "/repo/pubkey_pem.erl",
            "/repo/pubkey_pem.hrl",
        ] {
            assert!(
                secret_path_looks_like_source_file(Path::new(path)),
                "{path}"
            );
            assert!(secret_private_key_line_is_fixture(
                Path::new(path),
                r#"<<\"-----BEGIN RSA PRIVATE KEY-----\">>;"#
            ));
        }

        assert!(secret_private_key_line_is_fixture(
            Path::new("/repo/testdata/key.pem"),
            "-----BEGIN RSA PRIVATE KEY-----"
        ));
        assert!(!secret_private_key_line_is_fixture(
            Path::new("/repo/.env"),
            "-----BEGIN RSA PRIVATE KEY-----"
        ));
    }

    #[test]
    fn secret_file_probes_skip_generated_dependency_directories() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("project");
        fs::create_dir_all(root.join("artifacts")).unwrap();
        fs::create_dir_all(root.join("DerivedData")).unwrap();
        fs::create_dir_all(root.join(".codex-worktrees")).unwrap();
        fs::create_dir_all(root.join(".build")).unwrap();
        fs::create_dir_all(root.join(".next")).unwrap();
        fs::create_dir_all(root.join("cache")).unwrap();
        fs::create_dir_all(root.join("Vendor")).unwrap();
        fs::create_dir_all(root.join("isotopes/example")).unwrap();
        fs::create_dir_all(root.join("radioisotopes/example")).unwrap();
        fs::write(root.join("artifacts/.env"), "TOKEN=secret_secret\n").unwrap();
        fs::write(root.join("DerivedData/.env"), "TOKEN=secret_secret\n").unwrap();
        fs::write(root.join(".codex-worktrees/.env"), "TOKEN=secret_secret\n").unwrap();
        fs::write(root.join(".build/.env"), "TOKEN=secret_secret\n").unwrap();
        fs::write(root.join(".next/.env"), "TOKEN=secret_secret\n").unwrap();
        fs::write(root.join("cache/.env"), "TOKEN=secret_secret\n").unwrap();
        fs::write(root.join("Vendor/.env"), "TOKEN=secret_secret\n").unwrap();
        fs::write(
            root.join("isotopes/example/.env"),
            "TOKEN=secret_secret\n",
        )
        .unwrap();
        fs::write(
            root.join("radioisotopes/example/.env"),
            "TOKEN=secret_secret\n",
        )
        .unwrap();
        fs::write(root.join(".env"), "TOKEN=secret_secret\n").unwrap();

        let mut findings = Vec::new();
        let mut errors = Vec::new();
        let mut seen_findings = HashSet::new();
        let mut seen_errors = HashSet::new();
        scan_secret_file_probes(
            Some(&root),
            &[],
            &mut findings,
            &mut errors,
            &mut seen_findings,
            &mut seen_errors,
            &mut |_| Ok(()),
        )
        .unwrap();

        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0]
                .path
                .as_deref()
                .is_some_and(|path| path.ends_with("/.env"))
        );
    }

    #[test]
    fn secret_file_scanner_ignores_missing_default_candidates() {
        let temp = TempDir::new().unwrap();
        let findings = scan_secret_file(&temp.path().join(".env")).unwrap();

        assert!(findings.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn secret_file_probes_warn_for_unreadable_subdirectories() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("project");
        let restricted = root.join("restricted");
        let env_path = root.join(".env");
        fs::create_dir_all(&restricted).unwrap();
        fs::write(&env_path, "TOKEN=secret_secret\n").unwrap();
        let mut permissions = fs::metadata(&restricted).unwrap().permissions();
        permissions.set_mode(0o000);
        fs::set_permissions(&restricted, permissions).unwrap();

        let mut findings = Vec::new();
        let mut errors = Vec::new();
        let mut seen_findings = HashSet::new();
        let mut seen_errors = HashSet::new();
        let result = scan_secret_file_probes(
            Some(&root),
            &[],
            &mut findings,
            &mut errors,
            &mut seen_findings,
            &mut seen_errors,
            &mut |_| Ok(()),
        );

        let mut permissions = fs::metadata(&restricted).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&restricted, permissions).unwrap();
        result.unwrap();
        let env_path_display = env_path.display().to_string();
        assert!(findings.iter().any(|finding| {
            finding
                .path
                .as_deref()
                .is_some_and(|path| path == env_path_display)
        }));
        if unsafe { libc::geteuid() } != 0 {
            assert!(
                errors.iter().any(|error| error
                    .path
                    .as_deref()
                    .is_some_and(|path| path.contains("restricted"))),
                "{errors:?}"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn secret_file_probes_error_when_requested_root_is_unreadable() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }

        let temp = TempDir::new().unwrap();
        let root = temp.path().join("project");
        fs::create_dir_all(&root).unwrap();
        let mut permissions = fs::metadata(&root).unwrap().permissions();
        permissions.set_mode(0o000);
        fs::set_permissions(&root, permissions).unwrap();

        let mut findings = Vec::new();
        let mut errors = Vec::new();
        let mut seen_findings = HashSet::new();
        let mut seen_errors = HashSet::new();
        let result = scan_secret_file_probes(
            Some(&root),
            &[],
            &mut findings,
            &mut errors,
            &mut seen_findings,
            &mut seen_errors,
            &mut |_| Ok(()),
        );

        let mut permissions = fs::metadata(&root).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&root, permissions).unwrap();
        let err = result.unwrap_err();
        assert!(err.contains("failed to read scan path"));
    }

    #[test]
    fn secret_file_probes_emit_events_while_building_report_parts() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("project");
        let env_path = root.join(".env");
        fs::create_dir_all(&root).unwrap();
        fs::write(&env_path, "SERVICE_TOKEN=secret_secret\n").unwrap();

        let mut findings = Vec::new();
        let mut errors = Vec::new();
        let mut seen_findings = HashSet::new();
        let mut seen_errors = HashSet::new();
        let mut events = Vec::new();

        let (scanned_files, file_probes) = scan_secret_file_probes(
            Some(&root),
            &[],
            &mut findings,
            &mut errors,
            &mut seen_findings,
            &mut seen_errors,
            &mut |event| {
                match event {
                    SecretScannerEvent::Finding(finding) => {
                        events.push(format!("finding:{}", finding.source));
                    }
                    SecretScannerEvent::Error(error) => {
                        events.push(format!("error:{}", error.source));
                    }
                }
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(scanned_files, 1);
        assert_eq!(file_probes, 1);
        assert_eq!(findings.len(), 1);
        assert!(errors.is_empty());
        assert_eq!(events, vec!["finding:file-probe"]);
    }

    #[test]
    fn secret_file_probes_skip_files_and_prune_directories() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("project");
        let ignored_dir = root.join("ignored");
        let skipped_file = root.join("skip.env");
        let kept_file = root.join("keep.env");
        fs::create_dir_all(&ignored_dir).unwrap();
        fs::write(ignored_dir.join(".env"), "IGNORED_TOKEN=secret_secret\n").unwrap();
        fs::write(&skipped_file, "SKIPPED_TOKEN=secret_secret\n").unwrap();
        fs::write(&kept_file, "KEPT_TOKEN=secret_secret\n").unwrap();

        let mut findings = Vec::new();
        let mut errors = Vec::new();
        let mut seen_findings = HashSet::new();
        let mut seen_errors = HashSet::new();
        let (scanned_files, file_probes) = scan_secret_file_probes(
            Some(&root),
            &[PathBuf::from("ignored"), skipped_file.clone()],
            &mut findings,
            &mut errors,
            &mut seen_findings,
            &mut seen_errors,
            &mut |_| Ok(()),
        )
        .unwrap();

        assert_eq!(scanned_files, 1);
        assert_eq!(file_probes, 1);
        assert!(errors.is_empty());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, Some(kept_file.display().to_string()));
    }

    #[test]
    fn secret_file_probes_skip_direct_file_scan_targets() {
        let temp = TempDir::new().unwrap();
        let env_path = temp.path().join(".env");
        fs::write(&env_path, "SERVICE_TOKEN=secret_secret\n").unwrap();

        let mut findings = Vec::new();
        let mut errors = Vec::new();
        let mut seen_findings = HashSet::new();
        let mut seen_errors = HashSet::new();
        let (scanned_files, file_probes) = scan_secret_file_probes(
            Some(&env_path),
            std::slice::from_ref(&env_path),
            &mut findings,
            &mut errors,
            &mut seen_findings,
            &mut seen_errors,
            &mut |_| Ok(()),
        )
        .unwrap();

        assert_eq!(scanned_files, 0);
        assert_eq!(file_probes, 0);
        assert!(findings.is_empty());
        assert!(errors.is_empty());
    }

    #[test]
    fn secret_file_probe_paths_cover_direct_files_defaults_and_skip_resolution() {
        let temp = TempDir::new().unwrap();
        let env_path = temp.path().join(".env");
        fs::write(&env_path, "SERVICE_TOKEN=secret_secret\n").unwrap();

        let mut findings = Vec::new();
        let mut errors = Vec::new();
        let mut seen_findings = HashSet::new();
        let mut seen_errors = HashSet::new();
        let (scanned_files, file_probes) = scan_secret_file_probes(
            Some(&env_path),
            &[],
            &mut findings,
            &mut errors,
            &mut seen_findings,
            &mut seen_errors,
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!((scanned_files, file_probes), (1, 1));
        assert_eq!(findings.len(), 1);
        assert!(errors.is_empty());

        let root_file_skips = SecretScanSkips::new(Some(&env_path), &[PathBuf::from(".env")]);
        assert!(root_file_skips.should_skip(&env_path));
        let relative_skip = PathBuf::from("relative-secret.env");
        let relative_skips = SecretScanSkips::new(None, std::slice::from_ref(&relative_skip));
        assert!(relative_skips.should_skip(&relative_skip));
        assert!(!relative_skips.should_skip(Path::new("other-secret.env")));

        let mut none_findings = Vec::new();
        let mut none_errors = Vec::new();
        let mut none_seen_findings = HashSet::new();
        let mut none_seen_errors = HashSet::new();
        let skipped_defaults = default_secret_scan_paths();
        assert_eq!(
            scan_secret_file_probes(
                None,
                &skipped_defaults,
                &mut none_findings,
                &mut none_errors,
                &mut none_seen_findings,
                &mut none_seen_errors,
                &mut |_| Ok(())
            )
            .unwrap(),
            (0, 0)
        );

        assert!(
            scan_secret_file_probes(
                Some(&temp.path().join("missing")),
                &[],
                &mut Vec::new(),
                &mut Vec::new(),
                &mut HashSet::new(),
                &mut HashSet::new(),
                &mut |_| Ok(())
            )
            .unwrap_err()
            .contains("scan path does not exist")
        );

        let fifo_path = temp.path().join("secret.pipe");
        let fifo_c_path = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c_path.as_ptr(), 0o600) }, 0);
        assert!(
            scan_secret_file_probes(
                Some(&fifo_path),
                &[],
                &mut Vec::new(),
                &mut Vec::new(),
                &mut HashSet::new(),
                &mut HashSet::new(),
                &mut |_| Ok(())
            )
            .unwrap_err()
            .contains("not a file or directory")
        );

        assert_eq!(
            scan_secret_file_probes(
                Some(temp.path()),
                &[temp.path().to_path_buf()],
                &mut Vec::new(),
                &mut Vec::new(),
                &mut HashSet::new(),
                &mut HashSet::new(),
                &mut |_| Ok(())
            )
            .unwrap(),
            (0, 0)
        );
    }

    #[test]
    fn secret_scanner_runs_isotope_detectors_and_file_probes() {
        let _lock = test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let home = temp.path().join("home");
        let scan_root = temp.path().join("project");
        let aws_credentials = home.join(".aws/credentials");
        fs::create_dir_all(aws_credentials.parent().unwrap()).unwrap();
        fs::create_dir_all(&scan_root).unwrap();
        fs::write(
            &aws_credentials,
            "[default]\naws_secret_access_key = secretsecret1234\n",
        )
        .unwrap();
        fs::write(scan_root.join(".npmrc"), "_authToken=npm_secret_token\n").unwrap();

        let cargo_home = temp.path().join("cargo");
        let caroot = temp.path().join("mkcert");
        let helm_config_home = temp.path().join("helm");
        let helm_repository_config = temp.path().join("repositories.yaml");
        let kubeconfig = temp.path().join("kubeconfig");
        let npm_config = temp.path().join("empty-npmrc");
        let uv_credentials_dir = temp.path().join("uv");
        fs::create_dir_all(&uv_credentials_dir).unwrap();
        fs::write(&npm_config, "").unwrap();
        fs::write(&kubeconfig, "").unwrap();
        let _env = TestEnvGuard::set(&[
            ("HOME", home.to_str().unwrap()),
            (
                "AWS_SHARED_CREDENTIALS_FILE",
                aws_credentials.to_str().unwrap(),
            ),
            ("CARGO_HOME", cargo_home.to_str().unwrap()),
            ("CAROOT", caroot.to_str().unwrap()),
            ("HELM_CONFIG_HOME", helm_config_home.to_str().unwrap()),
            (
                "HELM_REPOSITORY_CONFIG",
                helm_repository_config.to_str().unwrap(),
            ),
            ("KUBECONFIG", kubeconfig.to_str().unwrap()),
            ("NPM_CONFIG_USERCONFIG", npm_config.to_str().unwrap()),
            ("UV_CREDENTIALS_DIR", uv_credentials_dir.to_str().unwrap()),
        ]);

        let report = run_secret_scan(&SecretScannerRequest {
            path: Some(scan_root.clone()),
            skip_paths: Vec::new(),
            output: OutputMode::Human,
            isotopes_only: false,
        })
        .unwrap();

        assert_eq!(report.summary.isotope_detectors, 0);
        assert!(
            report
                .findings
                .iter()
                .all(|finding| !finding.source.starts_with("isotope:"))
        );
        assert!(report.summary.scanned_files >= 1);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.source == "file-probe")
        );

        let default_report = run_secret_scan(&SecretScannerRequest {
            path: None,
            skip_paths: Vec::new(),
            output: OutputMode::Human,
            isotopes_only: false,
        })
        .unwrap();
        let has_aws_cli_detector = detect_isotope_install_reasons("aws-cli").is_some();
        if has_aws_cli_detector {
            assert!(default_report.summary.isotope_detectors > 0);
            assert!(
                default_report
                    .findings
                    .iter()
                    .any(|finding| finding.source == "isotope:aws-cli")
            );
        }

        let isotope_only_report = run_secret_scan(&SecretScannerRequest {
            path: Some(scan_root),
            skip_paths: Vec::new(),
            output: OutputMode::Human,
            isotopes_only: true,
        })
        .unwrap();

        assert_eq!(isotope_only_report.summary.scanned_files, 0);
        assert_eq!(isotope_only_report.summary.file_probes, 0);
        assert_eq!(isotope_only_report.summary.isotope_detectors, 0);
        assert!(isotope_only_report.findings.is_empty());
        assert!(
            isotope_only_report
                .findings
                .iter()
                .all(|finding| !finding.source.starts_with("file-probe"))
        );
    }

    #[test]
    fn secret_scanner_helpers_cover_default_paths_and_token_shapes() {
        let _lock = test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let home = temp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let _env = TestEnvGuard::set(&[("HOME", home.to_str().unwrap())]);

        let paths = default_secret_scan_paths();
        assert!(paths.iter().any(|path| path.ends_with(".env")));
        assert!(paths.iter().any(|path| path == &home.join(".bashrc")));
        assert!(paths.iter().any(|path| path == &home.join(".zshrc")));
        assert!(
            paths
                .iter()
                .any(|path| path == &home.join(".aws/credentials"))
        );

        let stripe_live = ["sk", "live", "abcdefghijklmnopqrstuvwxyz"].join("_");
        for token in [
            "ghp_abcdefghijklmnopqrstuvwxyz",
            "gho_abcdefghijklmnopqrstuvwxyz",
            "ghs_abcdefghijklmnopqrstuvwxyz",
            "github_pat_abcdefghijklmnopqrstuvwxyz",
            "glpat-abcdefghijklmnopqrstuvwxyz",
            "xoxb-abcdefghijklmnopqrstuvwxyz",
            "xoxp-abcdefghijklmnopqrstuvwxyz",
            stripe_live.as_str(),
            "npm_abcdefghijklmnop",
            "sk-abcdefghijklmnopqrstuv",
            "AKIAABCDEFGHIJKLMNOP",
        ] {
            assert!(secret_value_has_known_token_shape(token), "{token}");
        }
        assert!(!secret_value_has_known_token_shape("npm_short"));
        assert!(!secret_value_has_known_token_shape("plain-secret-value"));
    }

    #[test]
    fn is_list_subcommand_accepts_both_aliases() {
        assert!(is_list_subcommand("list"));
        assert!(is_list_subcommand("ls"));
        assert!(!is_list_subcommand("outdated"));
    }

    #[test]
    fn is_info_subcommand_accepts_info_only() {
        assert!(is_info_subcommand("info"));
        assert!(!is_info_subcommand("list"));
    }

    #[test]
    fn is_update_subcommand_accepts_update_only() {
        assert!(is_update_subcommand("update"));
        assert!(!is_update_subcommand("outdated"));
        assert!(!is_update_subcommand("install"));
    }

    #[test]
    fn installed_package_names_skip_hidden_entries_and_files() {
        let temp = TempDir::new().unwrap();
        fs::create_dir_all(temp.path().join("deno")).unwrap();
        fs::create_dir_all(temp.path().join("npm/openclaw")).unwrap();
        fs::create_dir_all(temp.path().join("npm/@tobilu/qmd")).unwrap();
        fs::create_dir_all(temp.path().join("pip/psycopg2")).unwrap();
        fs::create_dir_all(temp.path().join(".tmp")).unwrap();
        fs::write(temp.path().join("README"), b"not a package").unwrap();
        write_package_receipt(
            &temp.path().join("npm/openclaw").join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "npm:openclaw".to_string(),
                version: "1.2.3".to_string(),
                source: PackageReceiptSource::Npm {
                    package_name: "openclaw".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        write_package_receipt(
            &temp.path().join("npm/@tobilu/qmd").join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "npm:@tobilu/qmd".to_string(),
                version: "0.1.0".to_string(),
                source: PackageReceiptSource::Npm {
                    package_name: "@tobilu/qmd".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        write_package_receipt(
            &temp.path().join("pip/psycopg2").join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "pip:psycopg2".to_string(),
                version: "2.9.10".to_string(),
                source: PackageReceiptSource::Pip {
                    package_name: "psycopg2".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();

        let mut installed = installed_package_names(temp.path()).unwrap();
        installed.sort();
        assert_eq!(
            installed,
            vec![
                "deno".to_string(),
                "npm:@tobilu/qmd".to_string(),
                "npm:openclaw".to_string(),
                "pip:psycopg2".to_string()
            ]
        );
    }

    #[test]
    fn installed_package_names_include_isotopes_from_subdir() {
        let temp = TempDir::new().unwrap();
        fs::create_dir_all(temp.path().join("iso/gh")).unwrap();
        fs::create_dir_all(temp.path().join("iso/.tmp")).unwrap();

        let mut names = installed_package_names(temp.path()).unwrap();
        names.sort();

        assert_eq!(names, vec!["isotope:gh".to_string()]);
    }

    #[test]
    fn gh_isotope_migration_updates_keychain_without_login_subprocess() {
        let isotope = isotope_package_data("gh").unwrap();
        let script = isotope.migrate.as_deref().unwrap();

        assert_eq!(script, "/opt/iso/gh/bin/gh auth av-migrate \"$@\"");
        assert!(!script.contains("auth login"));
        assert!(!script.contains("--with-token"));
    }

    #[test]
    fn custom_isotope_migration_runs_rewritten_script_and_reports_failures() {
        if is_root() {
            return;
        }

        let _lock = test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let install_root = temp.path().join("install");
        let tmp_root = temp.path().join("tmp");
        fs::create_dir_all(&install_root).unwrap();
        fs::create_dir_all(&tmp_root).unwrap();
        let _env = TestEnvGuard::set(&[
            ("HOME", temp.path().to_str().unwrap()),
            ("USER", "coverage-user"),
            ("LOGNAME", "coverage-logname"),
        ]);
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "isotope:coverage-migrate".to_string(),
            root_formula: "isotope:coverage-migrate".to_string(),
            stable_root: install_root.clone(),
            install_root: install_root.clone(),
            tmp_root,
        };
        let isotope = IsotopePackageData {
            name: "coverage-migrate".to_string(),
            replaces: Some("brew:coverage-replaced".to_string()),
            modifies: None,
            migrate: Some(
                "#!/bin/sh\nprintf '%s\\n%s\\n%s\\n' \"$ISOTOPE_NAME\" \"$ISOTOPE_PREFIX\" \"$USER\" > /opt/iso/repository-leaf/migration.out\n"
                    .to_string(),
            ),
            _repository: Some("example/repository-leaf".to_string()),
            _upstream_repository: None,
            version: "1.0.0".to_string(),
            release_url: None,
            archive_url: None,
            published_at: None,
            applies_to_versioned_formulae: false,
        };
        let progress = InstallProgress::with_callback("coverage-migrate", None);

        run_isotope_migration(&plan, &isotope, Some(&progress)).unwrap();

        let output = fs::read_to_string(install_root.join("migration.out")).unwrap();
        assert!(output.contains("coverage-migrate"));
        assert!(output.contains(install_root.to_str().unwrap()));
        assert!(output.contains("coverage-user"));

        let failing = IsotopePackageData {
            migrate: Some("echo migration-broke >&2\nexit 9\n".to_string()),
            ..isotope
        };
        let err = run_isotope_migration(&plan, &failing, Some(&progress)).unwrap_err();
        assert!(err.contains("migration failed for coverage-migrate"));
        assert!(err.contains("exit code 9"));
        assert!(err.contains("migration-broke"));
    }

    #[test]
    fn gh_isotope_migration_plan_reports_replacement_package() {
        let plan = ops::isotope_migration_plan("gh").unwrap();

        assert_eq!(plan.isotope_name, "gh");
        assert_eq!(plan.replaces_package, Some("gh".to_string()));
        assert_eq!(plan.modifies_package, None);
        assert!(!plan.is_radioisotope);
        assert!(plan.has_migration);
    }

    #[test]
    fn aws_cli_radioisotope_plan_reports_modified_formula() {
        let plan = ops::isotope_migration_plan("aws-cli").unwrap();

        assert_eq!(plan.isotope_name, "aws-cli");
        assert_eq!(plan.replaces_package, None);
        assert_eq!(plan.modifies_package, Some("awscli".to_string()));
        assert_eq!(
            plan.is_radioisotope,
            isotope_has_post_install("isotope:aws-cli")
        );
        assert!(plan.has_migration);
        assert!(!isotope_has_post_install("isotope:gh"));
    }

    #[test]
    fn node_versioned_radioisotope_plan_reports_versioned_formula() {
        let plan = ops::isotope_migration_plan("node@24").unwrap();

        assert_eq!(plan.isotope_name, "node@24");
        assert_eq!(plan.replaces_package, None);
        assert_eq!(plan.modifies_package, Some("node@24".to_string()));
        assert!(plan.is_radioisotope);
        assert!(plan.has_migration);
    }

    #[test]
    fn explicit_homebrew_formula_install_uses_radioisotope_when_available() {
        assert_eq!(
            radioisotope_name_for_homebrew_formula_install("node@24").unwrap(),
            Some("node@24".to_string())
        );
        assert_eq!(
            radioisotope_name_for_homebrew_formula_install("ripgrep").unwrap(),
            None
        );
    }

    #[test]
    fn terraform_radioisotope_plan_reports_modified_vendor_package() {
        let isotope = isotope_package_data("terraform").unwrap();
        let plan = ops::isotope_migration_plan("terraform").unwrap();

        assert_eq!(isotope.modifies.as_deref(), Some("av:terraform"));
        assert_eq!(
            isotope_modified_package_name(isotope).unwrap(),
            Some("terraform".to_string())
        );
        assert_eq!(plan.isotope_name, "terraform");
        assert_eq!(plan.replaces_package, None);
        assert_eq!(plan.modifies_package, Some("terraform".to_string()));
        assert!(plan.is_radioisotope);
    }

    #[test]
    fn auto_install_prefers_installable_isotopes_for_matching_targets() {
        assert_eq!(
            preferred_auto_isotope_name("terraform").unwrap(),
            Some("terraform".to_string())
        );
        assert_eq!(
            installable_isotope_name_for_target(&PackageAliasTarget::HomebrewFormula(
                "awscli".to_string()
            ))
            .unwrap(),
            Some("aws-cli".to_string())
        );
        assert_eq!(
            installable_isotope_name_for_target(&PackageAliasTarget::HomebrewFormula(
                "node@24".to_string()
            ))
            .unwrap(),
            Some("node@24".to_string())
        );
        assert_eq!(
            installable_isotope_name_for_target(&PackageAliasTarget::HomebrewFormula(
                "curl".to_string()
            ))
            .unwrap(),
            None
        );
    }

    #[test]
    fn isotope_installability_distinguishes_payloads_from_detector_only_records() {
        assert!(isotope_is_installable(
            isotope_package_data("terraform").unwrap()
        ));
        let curl = isotope_package_data("curl").unwrap();
        assert_eq!(curl.version, "detector-only");
        assert!(!isotope_is_installable(curl));

        let archive_backed = IsotopePackageData {
            name: "isotope:archive-backed".to_string(),
            replaces: Some("brew:archive-backed".to_string()),
            modifies: None,
            migrate: None,
            _repository: None,
            _upstream_repository: None,
            version: "1.0.0".to_string(),
            release_url: None,
            archive_url: Some("https://example.test/archive.tgz".to_string()),
            published_at: None,
            applies_to_versioned_formulae: false,
        };
        assert!(isotope_is_installable(&archive_backed));

        let config = Config {
            bottle_tag: "all".to_string(),
        };
        let metadata_only = IsotopePackageData {
            name: "isotope:metadata-only".to_string(),
            replaces: None,
            modifies: None,
            ..archive_backed.clone()
        };
        assert!(
            isotope_dependency_graph(&metadata_only, &config)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            isotope_stub_executables(
                &metadata_only,
                &[(
                    "metadata-tool".to_string(),
                    PathBuf::from("bin/metadata-tool")
                )],
            )
            .unwrap(),
            ["metadata-tool".to_string()]
        );

        let npm_replacement = IsotopePackageData {
            name: "isotope:npm-replacement".to_string(),
            replaces: Some("npm:not-radio".to_string()),
            modifies: None,
            ..archive_backed.clone()
        };
        assert!(
            isotope_dependency_graph(&npm_replacement, &config)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            isotope_replaced_package_target(&npm_replacement).unwrap(),
            None
        );
        assert_eq!(
            isotope_modified_or_replaced_package_name(&npm_replacement).unwrap(),
            Some("npm:not-radio".to_string())
        );

        let invalid_modification = IsotopePackageData {
            name: "isotope:invalid-modification".to_string(),
            replaces: None,
            modifies: Some("npm:not-radio".to_string()),
            ..archive_backed.clone()
        };
        assert!(
            isotope_modified_package_target(&invalid_modification)
                .unwrap_err()
                .contains("radioisotopes may only modify")
        );
        assert!(
            radioisotope_modified_install_name(&PackageAliasTarget::NpmPackage(
                "not-radio".to_string()
            ))
            .unwrap_err()
            .contains("radioisotopes may only modify")
        );
    }

    #[test]
    fn run_i_package_dispatches_current_cask_isotope_and_error_paths() {
        let _env_lock = test_env_lock().lock().unwrap();
        let _package_lock = acquire_package_mutation_lock().unwrap();
        let config = Config {
            bottle_tag: "all".to_string(),
        };
        let opt_root = opt_pkg_root();
        let bin_root = managed_bin_root();

        for package_name in ["codex", "terraform", "isotope:gh", "isotope:terraform"] {
            let install_root = package_install_root(&opt_root, package_name).unwrap();
            if fs::symlink_metadata(&install_root).is_ok() {
                remove_existing_package_install(&opt_root, package_name, &bin_root).unwrap();
            }
        }

        let cask = embedded_cask("codex").unwrap();
        let cask_plan = InstallPlan::for_i("codex".to_string(), "codex".to_string());
        fs::create_dir_all(&cask_plan.install_root).unwrap();
        write_package_receipt(
            &cask_plan.root_receipt_path(),
            &PackageReceipt {
                package_name: "codex".to_string(),
                version: cask.version.clone(),
                source: PackageReceiptSource::Cask {
                    cask_name: "codex".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        write_root_ownership_manifest(&cask_plan, Vec::new()).unwrap();

        run_i_package(
            &config,
            RequestedPackage::HomebrewCask("codex".to_string()),
            InstallOptions {
                intent: InstallIntent::Update,
            },
        )
        .unwrap();
        assert_eq!(
            load_package_receipt(&cask_plan.root_receipt_path())
                .unwrap()
                .unwrap()
                .source,
            PackageReceiptSource::Cask {
                cask_name: "codex".to_string()
            }
        );

        let isotope_name = "gh";
        let isotope_package = isotope_qualified_name(isotope_name);
        let isotope = isotope_package_data(isotope_name).unwrap();
        let isotope_plan = InstallPlan::for_i_isotope(isotope_package.clone(), isotope_name);
        let gh_binary = isotope_plan.install_root.join("bin/gh");
        fs::create_dir_all(gh_binary.parent().unwrap()).unwrap();
        fs::write(&gh_binary, b"#!/bin/sh\nprintf gh\n").unwrap();
        let mut permissions = fs::metadata(&gh_binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&gh_binary, permissions).unwrap();
        write_root_executable_manifest(
            &isotope_plan.root_executables_manifest_path(),
            &["gh".to_string()],
        )
        .unwrap();
        write_root_ownership_manifest(&isotope_plan, Vec::new()).unwrap();
        write_package_receipt(
            &isotope_plan.root_receipt_path(),
            &PackageReceipt {
                package_name: isotope_package.clone(),
                version: isotope.version.clone(),
                source: PackageReceiptSource::Isotope {
                    isotope_name: isotope_name.to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();

        let mut bottle_server = start_counting_test_http_server(vec![(
            "/gh.tar.gz".to_string(),
            b"not a bottle".to_vec(),
        )]);
        let formula_json = serde_json::to_vec(&serde_json::json!({
            "versions": { "stable": "2.80.0" },
            "dependencies": [],
            "bottle": {
                "stable": {
                    "files": {
                        "all": {
                            "sha256": "0".repeat(64),
                            "url": format!("{}/gh.tar.gz", bottle_server.base_url),
                        }
                    }
                }
            },
            "disabled": false
        }))
        .unwrap();
        let mut formula_server =
            start_counting_test_http_server(vec![("/gh.json".to_string(), formula_json)]);
        let _endpoints = TestEndpointGuard::set(config::TestEndpointOverrides {
            formula_api_root: Some(formula_server.base_url.clone()),
            ..Default::default()
        });

        run_i_package(
            &config,
            RequestedPackage::Isotope("gh".to_string()),
            InstallOptions {
                intent: InstallIntent::Update,
            },
        )
        .unwrap();
        let auto_err = run_i_package(
            &config,
            RequestedPackage::Auto("gh".to_string()),
            InstallOptions {
                intent: InstallIntent::Update,
            },
        )
        .unwrap_err();
        assert!(auto_err.contains("gh"));
        assert!(is_executable(&bin_root.join("gh")));
        assert_eq!(
            load_package_receipt(&isotope_plan.root_receipt_path())
                .unwrap()
                .unwrap()
                .version,
            isotope.version
        );
        assert!(formula_server.request_count() >= 1);
        assert!(bottle_server.request_count() >= 1);
        bottle_server.stop().unwrap();
        formula_server.stop().unwrap();

        if fs::symlink_metadata(bin_root.join("gh")).is_ok() {
            remove_path(&bin_root.join("gh")).unwrap();
        }
        let stub_paths = install_isotope_stubs(isotope_name, None).unwrap();
        assert_eq!(stub_paths, vec![bin_root.join("gh").display().to_string()]);
        assert!(is_executable(&bin_root.join("gh")));

        let non_radio = run_i_radioisotope(
            &config,
            isotope_package,
            isotope_name.to_string(),
            InstallIntent::Install,
            None,
        )
        .unwrap_err();
        assert!(non_radio.contains("isotope:gh is not a radioisotope"));

        let invalid_modified_target = run_i_modified_package(
            &config,
            "npm:not-radio".to_string(),
            &PackageAliasTarget::NpmPackage("not-radio".to_string()),
            InstallIntent::Install,
            None,
        )
        .unwrap_err();
        assert!(invalid_modified_target.contains("radioisotopes may only modify"));

        let invalid_vendor_modification = run_i_modified_package(
            &config,
            "missing-vendor".to_string(),
            &PackageAliasTarget::VendorPackage("not-a-registered-vendor".to_string()),
            InstallIntent::Install,
            None,
        )
        .unwrap_err();
        assert!(invalid_vendor_modification.contains("not-a-registered-vendor is not registered"));

        let terraform_launcher = Path::new("/opt/terraform/bin/terraform");
        if !terraform_launcher.exists() {
            let terraform_plan = InstallPlan::for_i_radioisotope(
                "isotope:terraform".to_string(),
                "terraform".to_string(),
            );
            fs::create_dir_all(&terraform_plan.install_root).unwrap();
            write_package_receipt(
                &terraform_plan.root_receipt_path(),
                &PackageReceipt {
                    package_name: "terraform".to_string(),
                    version: "1.2.3".to_string(),
                    source: PackageReceiptSource::Vendor {
                        vendor_name: "terraform".to_string(),
                    },
                    metadata: PackageMetadata::default(),
                },
            )
            .unwrap();

            for requested in [
                RequestedPackage::Auto("terraform".to_string()),
                RequestedPackage::Isotope("terraform".to_string()),
            ] {
                let err = run_i_package(
                    &config,
                    requested,
                    InstallOptions {
                        intent: InstallIntent::Install,
                    },
                )
                .unwrap_err();
                assert!(
                    err.contains("terraform"),
                    "expected terraform install error, got: {err}"
                );
            }
        }

        let err = run_i_package(
            &config,
            RequestedPackage::VendorPackage("not-a-registered-vendor".to_string()),
            InstallOptions {
                intent: InstallIntent::Install,
            },
        )
        .unwrap_err();
        assert!(err.contains("not-a-registered-vendor is not registered"));

        let err = run_i_package(
            &config,
            RequestedPackage::VendorPackage("not-a-registered-vendor".to_string()),
            InstallOptions {
                intent: InstallIntent::Update,
            },
        )
        .unwrap_err();
        assert!(err.contains("not-a-registered-vendor is not registered"));

        let err = run_i_package(
            &config,
            RequestedPackage::NpmPackage {
                package: "@scope".to_string(),
                version: None,
            },
            InstallOptions {
                intent: InstallIntent::Install,
            },
        )
        .unwrap_err();
        assert!(err.contains("scoped npm package names"));

        let err = run_i_package(
            &config,
            RequestedPackage::PipPackage("bad/name".to_string()),
            InstallOptions {
                intent: InstallIntent::Install,
            },
        )
        .unwrap_err();
        assert!(err.contains("pip package names must not contain path separators"));

        let err = run_i_package(
            &config,
            RequestedPackage::Isotope("bad/name".to_string()),
            InstallOptions {
                intent: InstallIntent::Install,
            },
        )
        .unwrap_err();
        assert!(err.contains("qualified package name must not contain"));

        assert!(
            run_i_cask(
                &config,
                "missing-cask".to_string(),
                "missing-cask".to_string(),
                InstallIntent::Install,
                None,
            )
            .unwrap_err()
            .contains("no embedded cask metadata found")
        );
        assert!(
            run_i_isotope(
                &config,
                "isotope:missing-isotope".to_string(),
                "missing-isotope".to_string(),
                true,
                InstallIntent::Install,
                None,
            )
            .unwrap_err()
            .contains("unknown isotope")
        );
        assert!(
            run_i_radioisotope(
                &config,
                "isotope:missing-radio".to_string(),
                "missing-radio".to_string(),
                InstallIntent::Install,
                None,
            )
            .unwrap_err()
            .contains("unknown isotope")
        );
        assert!(
            run_i_isotope_root_only(
                &config,
                "isotope:missing-root".to_string(),
                "missing-root".to_string(),
                None,
            )
            .unwrap_err()
            .contains("unknown isotope")
        );

        for package_name in ["codex", "terraform", "isotope:gh", "isotope:terraform"] {
            remove_existing_package_install(&opt_root, package_name, &bin_root).unwrap();
        }
    }

    #[test]
    fn radioisotope_update_refreshes_modified_formula() {
        assert_eq!(
            radioisotope_modified_formula_intent(InstallIntent::Install),
            None
        );
        assert_eq!(
            radioisotope_modified_formula_intent(InstallIntent::Update),
            Some(InstallIntent::Update)
        );
        assert_eq!(
            radioisotope_modified_formula_intent(InstallIntent::Reinstall),
            Some(InstallIntent::Reinstall)
        );
    }

    #[test]
    fn aws_cli_radioisotope_info_uses_modified_formula_description() {
        let _env_lock = test_env_lock().lock().unwrap();
        let (base, _server) = start_test_http_server(
            vec![(
                "/awscli.json".to_string(),
                serde_json::to_vec(&serde_json::json!({
                    "desc": "Official Amazon AWS command-line interface",
                    "homepage": "https://aws.amazon.com/cli/",
                    "license": "Apache-2.0",
                    "versions": {"stable": "2.32.0"},
                    "revision": 0,
                    "dependencies": ["python@3.14"],
                    "bottle": {
                        "stable": {
                            "files": {
                                "arm64_tahoe": {
                                    "sha256": "awscli-sha",
                                    "url": "https://example.invalid/awscli.tar.gz"
                                }
                            }
                        }
                    },
                    "disabled": false,
                    "post_install_defined": false
                }))
                .unwrap(),
            )],
            1,
        );
        let _endpoints = TestEndpointGuard::set(config::TestEndpointOverrides {
            formula_api_root: Some(base),
            ..Default::default()
        });
        let mut info = PackageInfo {
            package_name: "isotope:aws-cli".to_string(),
            qualified_name: "isotope:aws-cli".to_string(),
            install_root: PathBuf::from("/opt/awscli"),
            installed: true,
            source: Some(PackageReceiptSource::Isotope {
                isotope_name: "aws-cli".to_string(),
            }),
            source_error: None,
            aliases: Vec::new(),
            aliases_error: None,
            installed_version: Some("2.31.0".to_string()),
            latest_version: None,
            latest_version_error: None,
            executable_paths: Vec::new(),
            executable_paths_error: None,
            popularity: None,
            last_updated_at: None,
            homebrew_info: None,
            homebrew_info_error: None,
            npm_homepage: None,
            npm_package_info_error: None,
            security_state: None,
            version_options: Vec::new(),
        };

        populate_package_info_metadata(
            &Config {
                bottle_tag: "arm64_tahoe".to_string(),
            },
            &mut info,
        );

        assert_eq!(info.latest_version, Some("2.32.0".to_string()));
        assert_eq!(
            info.homebrew_info,
            Some(HomebrewPackageInfo {
                formula: "awscli".to_string(),
                description: Some("Official Amazon AWS command-line interface".to_string()),
                homepage: Some("https://aws.amazon.com/cli/".to_string()),
                repository: None,
                upstream_docs: None,
                docs: Vec::new(),
                license: Some("Apache-2.0".to_string()),
                dependencies: vec!["python@3.14".to_string()],
            })
        );
    }

    #[test]
    fn isotope_migration_script_is_executable_shell_script() {
        let isotope = isotope_package_data("gh").unwrap();
        let script = isotope.migrate.as_deref().unwrap();
        let plan = InstallPlan::for_i_isotope("isotope:gh".to_string(), "gh");
        let executable = executable_isotope_migration_script(script, &plan, isotope).unwrap();

        assert!(executable.starts_with("#!/bin/sh\n"));
        assert!(executable.contains("isotope migration must not run as root"));
        assert!(executable.contains("exit 77"));
    }

    #[test]
    fn isotope_migration_script_rewrites_repository_named_install_root() {
        let isotope = IsotopePackageData {
            name: "isotope:supabase".to_string(),
            replaces: Some("brew:supabase".to_string()),
            modifies: None,
            migrate: None,
            _repository: Some("automic-vault/supabase-cli".to_string()),
            _upstream_repository: None,
            version: "2.102.0".to_string(),
            release_url: Some("https://example.test/isotopes/supabase".to_string()),
            archive_url: Some("https://example.test/supabase-cli.tgz".to_string()),
            published_at: None,
            applies_to_versioned_formulae: false,
        };
        let plan = InstallPlan::for_i_isotope("isotope:supabase".to_string(), "supabase");
        let executable = executable_isotope_migration_script(
            "/opt/iso/supabase-cli/bin/supabase-go av-migrate \"$@\"",
            &plan,
            &isotope,
        )
        .unwrap();

        assert!(
            executable.contains(
                &plan
                    .install_root
                    .join("bin/supabase-go")
                    .display()
                    .to_string()
            )
        );
        assert!(!executable.contains("/opt/iso/supabase-cli"));
        assert!(!executable.contains("/tmp/opt/iso/supabase-cli"));
    }

    #[test]
    fn isotope_migration_script_rewrites_legacy_isotopes_install_root() {
        let isotope = isotope_package_data("gh").unwrap();
        let plan = InstallPlan::for_i_isotope("isotope:gh".to_string(), "gh");
        let executable = executable_isotope_migration_script(
            "/opt/isotopes/gh/bin/gh auth av-migrate \"$@\"",
            &plan,
            isotope,
        )
        .unwrap();

        assert!(executable.contains(&plan.install_root.join("bin/gh").display().to_string()));
        assert!(!executable.contains("/opt/isotopes/gh"));
        assert!(!executable.contains("/tmp/opt/isotopes/gh"));
    }

    #[test]
    fn isotope_stub_executables_use_replaced_formula_metadata() {
        let isotope = isotope_package_data("aws-cli").unwrap();
        let discovered = vec![
            ("aws".to_string(), PathBuf::from("/opt/iso/aws-cli/bin/aws")),
            (
                "aws_completer".to_string(),
                PathBuf::from("/opt/iso/aws-cli/bin/aws_completer"),
            ),
            (
                "python3.14".to_string(),
                PathBuf::from("/opt/iso/aws-cli/bin/python3.14"),
            ),
        ];

        assert_eq!(
            isotope_stub_executables(isotope, &discovered).unwrap(),
            vec!["aws".to_string(), "aws_completer".to_string()]
        );
    }

    #[test]
    fn progress_log_event_serializes_for_helper_bridge() {
        let event = ProgressEvent::Log {
            package: "isotope:gh".to_string(),
            message: "migrating secrets".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();

        assert_eq!(
            json,
            r#"{"Log":{"package":"isotope:gh","message":"migrating secrets"}}"#
        );
    }

    #[test]
    fn install_progress_reports_download_fraction_without_terminal_bar() {
        let events = Arc::new(Mutex::new(Vec::<ProgressEvent>::new()));
        let callback_events = Arc::clone(&events);
        let callback: Arc<Mutex<Box<ProgressCallback>>> =
            Arc::new(Mutex::new(Box::new(move |event| {
                callback_events.lock().unwrap().push(event);
            })));
        let progress = InstallProgress::with_callback("brew:sqlite", Some(callback));

        progress.begin_download_phase();
        progress.add_download_total(Some(100));
        progress.advance_download(25);
        progress.advance_download(25);

        let download_progress = events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|event| match event {
                ProgressEvent::Downloading { progress, .. } => Some(*progress),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert!(
            download_progress
                .iter()
                .any(|progress| (*progress - 0.25).abs() < f32::EPSILON),
            "expected 25% download progress, got {download_progress:?}"
        );
        assert!(
            download_progress
                .iter()
                .any(|progress| (*progress - 0.50).abs() < f32::EPSILON),
            "expected 50% download progress, got {download_progress:?}"
        );
    }

    #[test]
    fn install_progress_tracks_transitive_downloads_individually() {
        let events = Arc::new(Mutex::new(Vec::<ProgressEvent>::new()));
        let callback_events = Arc::clone(&events);
        let callback: Arc<Mutex<Box<ProgressCallback>>> =
            Arc::new(Mutex::new(Box::new(move |event| {
                callback_events.lock().unwrap().push(event);
            })));
        let progress = InstallProgress::with_callback("brew:yt-dlp", Some(callback));

        progress.begin_download_phase();
        progress.begin_download_for("yt-dlp");
        progress.add_download_total_for("yt-dlp", Some(100));
        progress.advance_download_for("yt-dlp", 100);
        progress.begin_download_for("python@3.14");
        progress.add_download_total_for("python@3.14", Some(300));
        progress.advance_download_for("python@3.14", 150);

        let download_events = events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|event| match event {
                ProgressEvent::Downloading {
                    package, progress, ..
                } => Some((package.clone(), *progress)),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert!(
            download_events
                .iter()
                .any(|(package, progress)| package == "yt-dlp"
                    && (*progress - 1.0).abs() < f32::EPSILON),
            "expected yt-dlp to reach 100%, got {download_events:?}"
        );
        assert!(
            download_events
                .iter()
                .any(|(package, progress)| package == "python@3.14"
                    && (*progress - 0.50).abs() < f32::EPSILON),
            "expected python@3.14 to report 50%, got {download_events:?}"
        );
    }

    #[test]
    fn install_progress_emits_fallback_download_state_without_package_entry() {
        let events = Arc::new(Mutex::new(Vec::<ProgressEvent>::new()));
        let callback_events = Arc::clone(&events);
        let callback: Arc<Mutex<Box<ProgressCallback>>> =
            Arc::new(Mutex::new(Box::new(move |event| {
                callback_events.lock().unwrap().push(event);
            })));
        let progress = InstallProgress::with_callback("brew:sqlite", Some(callback));
        *progress.bytes_downloaded.lock().unwrap() = 75;
        *progress.total_bytes.lock().unwrap() = Some(100);
        *progress.download_started_at.lock().unwrap() =
            Some(Instant::now() - Duration::from_secs(3));

        progress.emit_downloading_for("sqlite");

        let event = events
            .lock()
            .unwrap()
            .iter()
            .find_map(|event| match event {
                ProgressEvent::Downloading {
                    package,
                    bytes_per_sec,
                    progress,
                } => Some((package.clone(), *bytes_per_sec, *progress)),
                _ => None,
            })
            .expect("fallback download event should be emitted");
        assert_eq!(event.0, "sqlite");
        assert!(event.1 > 0);
        assert!((event.2 - 0.75).abs() < f32::EPSILON);
    }

    #[test]
    fn install_progress_helpers_cover_empty_no_callback_and_style_paths() {
        let progress = InstallProgress::with_callback("coverage-progress", None);

        progress.emit(ProgressEvent::Resolving);
        progress.begin_download_phase();
        progress.add_download_total(None);
        progress.add_download_total(Some(0));
        progress.advance_download(0);
        progress.emit_downloading_for("missing-package");
        progress.begin_install_phase();
        progress.begin_install_phase();
        progress.log("\n\r");
        progress.log("first line\nsecond line");
        progress.finish_with_paths(&[]);
        progress.finish_with_paths(&["/tmp/av".to_string(), "/tmp/nuke-helper".to_string()]);
        progress.clear();

        let _ = download_progress_style();
        let _ = install_progress_style();
        let _ = final_progress_style();
    }

    #[test]
    fn installed_package_summary_serializes_source() {
        let summary = core::InstalledPackageSummary {
            name: "isotope:gh".to_string(),
            source: PackageReceiptSource::Isotope {
                isotope_name: "gh".to_string(),
            },
            version: "2.80.0".to_string(),
            description: None,
            homepage: None,
            repository: None,
            upstream_docs: None,
            docs: Vec::new(),
            category: None,
            security_state: None,
            installed_versions: Vec::new(),
            install_package_names: Vec::new(),
        };
        let json = serde_json::to_string(&summary).unwrap();

        assert_eq!(
            json,
            r#"{"name":"isotope:gh","source":{"kind":"isotope","isotope_name":"gh"},"version":"2.80.0","description":null,"securityState":null}"#
        );
    }

    #[test]
    fn package_security_state_runs_detect_for_installed_isotopes() {
        let _lock = test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let aws_dir = temp.path().join(".aws");
        fs::create_dir_all(&aws_dir).unwrap();
        fs::write(
            aws_dir.join("credentials"),
            "[default]\naws_secret_access_key = secret\n",
        )
        .unwrap();
        let _env = TestEnvGuard::set(&[("HOME", temp.path().to_str().unwrap())]);

        let state = package_security_state_for_identifiers(["awscli".to_string()]);

        if detect_isotope_install_reasons("aws-cli").is_some() {
            let state = state.expect("aws-cli should have security state");
            assert_eq!(state.isotope_name, "aws-cli");
            assert!(state.install_is_insecure);
            assert!(state.remediation_available);
            assert!(
                state
                    .reasons
                    .iter()
                    .any(|reason| reason.contains("AWS shared credentials file")),
                "expected credentials reason, got {:?}",
                state.reasons
            );
            assert_eq!(state.error, None);
        } else {
            assert_eq!(state, None);
        }
    }

    #[test]
    fn package_security_state_runs_detect_for_uninstalled_package_info() {
        let _lock = test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let aws_dir = temp.path().join(".aws");
        fs::create_dir_all(&aws_dir).unwrap();
        fs::write(
            aws_dir.join("credentials"),
            "[default]\naws_secret_access_key = secret\n",
        )
        .unwrap();
        let _env = TestEnvGuard::set(&[("HOME", temp.path().to_str().unwrap())]);

        let info = PackageInfo {
            package_name: "awscli".to_string(),
            qualified_name: "brew:awscli".to_string(),
            install_root: PathBuf::from("/opt/awscli"),
            installed: false,
            source: Some(PackageReceiptSource::Formula {
                root_formula: "awscli".to_string(),
            }),
            source_error: None,
            aliases: Vec::new(),
            aliases_error: None,
            installed_version: None,
            latest_version: None,
            latest_version_error: None,
            executable_paths: Vec::new(),
            executable_paths_error: None,
            popularity: None,
            last_updated_at: None,
            homebrew_info: None,
            homebrew_info_error: None,
            npm_homepage: None,
            npm_package_info_error: None,
            security_state: None,
            version_options: Vec::new(),
        };

        let state = package_security_state(&info);

        if detect_isotope_install_reasons("aws-cli").is_some() {
            let state = state.expect("aws-cli should have security state");
            assert_eq!(state.isotope_name, "aws-cli");
            assert!(state.install_is_insecure);
            assert!(state.remediation_available);
            assert!(
                state
                    .reasons
                    .iter()
                    .any(|reason| reason.contains("AWS shared credentials file")),
                "expected credentials reason, got {:?}",
                state.reasons
            );
            assert_eq!(state.error, None);
        } else {
            assert_eq!(state, None);
        }
    }

    #[test]
    fn gh_security_state_reports_manifest_migration_remediation() {
        let _lock = test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        fs::write(
            temp.path().join("hosts.yml"),
            "github.com:\n    oauth_token: ghp_secret\n",
        )
        .unwrap();
        let _env = TestEnvGuard::set(&[
            ("GH_CONFIG_DIR", temp.path().to_str().unwrap()),
            ("HOME", temp.path().to_str().unwrap()),
        ]);

        let state = package_security_state_for_identifiers(["brew:gh".to_string()])
            .expect("gh should have security state");

        assert_eq!(state.isotope_name, "gh");
        assert!(state.install_is_insecure);
        assert!(state.remediation_available);
        assert!(
            state
                .reasons
                .iter()
                .any(|reason| reason.contains("GitHub CLI hosts file")),
            "expected hosts file reason, got {:?}",
            state.reasons
        );
        assert_eq!(state.error, None);
    }

    #[test]
    fn hf_security_state_reports_huggingface_cli_remediation() {
        let _lock = test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let token_dir = temp.path().join(".cache/huggingface");
        fs::create_dir_all(&token_dir).unwrap();
        fs::write(token_dir.join("token"), "hf_secret\n").unwrap();
        let _env = TestEnvGuard::set(&[("HOME", temp.path().to_str().unwrap())]);

        let state = package_security_state_for_identifiers(["brew:hf".to_string()])
            .expect("brew:hf should have security state");

        assert_eq!(state.isotope_name, "huggingface-cli");
        assert!(state.install_is_insecure);
        assert!(state.remediation_available);
        assert!(
            state
                .reasons
                .iter()
                .any(|reason| reason.contains("Hugging Face token file")),
            "expected Hugging Face token reason, got {:?}",
            state.reasons
        );
        assert_eq!(state.error, None);
    }

    #[test]
    fn package_security_state_prefers_versioned_node_radioisotope() {
        let _lock = test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        fs::write(
            temp.path().join(".npmrc"),
            "//registry.npmjs.org/:_authToken=npm_secret\n",
        )
        .unwrap();
        let _env = TestEnvGuard::set(&[("HOME", temp.path().to_str().unwrap())]);

        let info = PackageInfo {
            package_name: "node".to_string(),
            qualified_name: "brew:node@24".to_string(),
            install_root: PathBuf::from("/opt/homebrew/Cellar/node@24"),
            installed: true,
            source: Some(PackageReceiptSource::Formula {
                root_formula: "node@24".to_string(),
            }),
            source_error: None,
            aliases: Vec::new(),
            aliases_error: None,
            installed_version: Some("24.16.0".to_string()),
            latest_version: Some("24.16.0".to_string()),
            latest_version_error: None,
            executable_paths: Vec::new(),
            executable_paths_error: None,
            popularity: None,
            last_updated_at: None,
            homebrew_info: None,
            homebrew_info_error: None,
            npm_homepage: None,
            npm_package_info_error: None,
            security_state: None,
            version_options: Vec::new(),
        };

        let state =
            package_security_state(&info).expect("brew:node@24 should have node@24 security state");

        assert_eq!(state.isotope_name, "node@24");
        assert!(state.install_is_insecure);
        assert!(state.remediation_available);
        assert!(
            state
                .reasons
                .iter()
                .any(|reason| reason.contains("npm user config")),
            "expected npm user config reason, got {:?}",
            state.reasons
        );
        assert_eq!(state.error, None);

        for identifier in ["node@24", "isotope:node@24", "brew:node@24"] {
            let state = package_security_state_for_identifiers([identifier.to_string()])
                .unwrap_or_else(|| panic!("{identifier} should map to node@24"));
            assert_eq!(isotope_unqualified_name(&state.isotope_name), "node@24");
            assert!(state.install_is_insecure);
        }
    }

    #[test]
    fn package_security_state_reports_detector_only_radioisotopes_without_remediation() {
        let _lock = test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let home = temp.path().join("home");
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::create_dir_all(home.join(".gem")).unwrap();
        fs::create_dir_all(home.join(".cpan/CPAN")).unwrap();
        fs::create_dir_all(home.join(".ssl")).unwrap();
        fs::write(
            home.join(".git-credentials"),
            "https://user:supersecret@example.com/repo.git\n",
        )
        .unwrap();
        fs::write(
            home.join(".netrc"),
            "machine example.com login user password supersecret\n",
        )
        .unwrap();
        fs::write(home.join(".rsync_pass"), "supersecret\n").unwrap();
        fs::write(
            home.join(".gem/credentials"),
            ":rubygems_api_key: rubygems_secret\n",
        )
        .unwrap();
        fs::write(
            home.join(".cpan/CPAN/MyConfig.pm"),
            "'proxy_pass' => 'supersecret',\n",
        )
        .unwrap();
        fs::write(
            home.join(".ssh/id_rsa"),
            "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        fs::write(
            home.join(".ssl/key.pem"),
            "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        fs::write(
            home.join(".bash_profile"),
            "export BASH_SERVICE_TOKEN=secret_secret\n",
        )
        .unwrap();
        fs::write(
            home.join(".zshrc"),
            "export OPENAI_API_KEY=\"sk-proj-THIS_IS_A_FAKE_KEY_FOR_TESTING_ONLY_1234567890abcdefghijklmnopqrstuvwxyz\"\n",
        )
        .unwrap();
        let _env = TestEnvGuard::set(&[("HOME", home.to_str().unwrap())]);

        for (package, isotope, reason) in [
            ("brew:bash", "bash", "Bash startup file"),
            ("brew:git", "git", "Git credential store"),
            ("brew:curl", "curl", "curl netrc"),
            ("brew:zsh", "zsh", "Zsh startup file"),
            ("brew:rsync", "rsync", "rsync password file"),
            ("brew:ruby", "ruby", "RubyGems credentials"),
            ("brew:perl", "perl", "CPAN config"),
            ("brew:openssh", "openssh", "SSH private key"),
            ("brew:openssl@3", "openssl@3", "OpenSSL private key"),
        ] {
            if detect_isotope_install_reasons(isotope).is_none() {
                continue;
            }
            let state = package_security_state_for_identifiers([package.to_string()])
                .unwrap_or_else(|| panic!("{package} should have security state"));
            assert_eq!(state.isotope_name, isotope);
            assert!(state.install_is_insecure, "{package}");
            assert!(!state.remediation_available, "{package}");
            assert!(
                state
                    .reasons
                    .iter()
                    .any(|candidate| candidate.contains(reason)),
                "expected {reason:?} in {:?}",
                state.reasons
            );
        }
    }

    #[test]
    fn git_security_state_reports_credential_fill_learn_more_guidance() {
        use std::os::unix::fs::PermissionsExt;

        let _lock = test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let home = temp.path().join("home");
        let bin = temp.path().join("bin");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&bin).unwrap();
        let git = bin.join("git");
        fs::write(
            &git,
            "#!/bin/sh\n\
             if [ \"$1\" != credential ] || [ \"$2\" != fill ]; then exit 2; fi\n\
             cat >/dev/null\n\
             printf 'protocol=https\\nhost=github.com\\nusername=x-access-token\\npassword=github_pat_fake\\n\\n'\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&git).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&git, permissions).unwrap();

        let path = match env::var_os("PATH") {
            Some(existing) if !existing.is_empty() => {
                format!("{}:{}", bin.display(), existing.to_string_lossy())
            }
            _ => bin.display().to_string(),
        };
        let _unset_disable =
            TestEnvGuard::unset(&["AUTOMIC_VAULT_DISABLE_GIT_CREDENTIAL_FILL_DETECTOR"]);
        let _env = TestEnvGuard::set(&[
            ("HOME", home.to_str().unwrap()),
            ("PATH", &path),
            ("AUTOMIC_VAULT_TEST_GIT_CREDENTIAL_FILL_DETECTOR", "1"),
        ]);

        let state = package_security_state_for_identifiers(["brew:git".to_string()])
            .expect("git should have security state");

        assert_eq!(state.isotope_name, "git");
        assert!(state.install_is_insecure);
        assert!(!state.remediation_available);
        assert!(
            state
                .reasons
                .iter()
                .any(|reason| reason.contains("git credential fill")
                    && reason.contains("Click Learn More")
                    && !reason.contains("git credential reject")
                    && !reason.contains("Keychain Access")),
            "expected credential-fill hazard to point to Learn More, got {:?}",
            state.reasons
        );
    }

    #[test]
    fn generated_isotope_integrations_tolerate_empty_home() {
        let _lock = test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let home = temp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let missing_path = temp.path().join("missing");
        let missing = missing_path.to_str().unwrap();
        let _env = TestEnvGuard::set(&[
            ("HOME", home.to_str().unwrap()),
            ("AKAMAI_EDGERC", missing),
            ("ARGOCD_CONFIG_DIR", missing),
            ("AWS_SHARED_CREDENTIALS_FILE", missing),
            ("BITWARDENCLI_APPDATA_DIR", missing),
            ("CARGO_HOME", missing),
            ("CAROOT", missing),
            ("CIVO_CONFIG", missing),
            ("COMPOSER_HOME", missing),
            ("CX_CONFIG_FILE_PATH", missing),
            ("DCOS_DIR", missing),
            ("DIGITALOCEAN_CONFIG", missing),
            ("DOCKER_CONFIG", missing),
            ("GH_CONFIG_DIR", missing),
            ("GLAB_CONFIG_DIR", missing),
            ("HCLOUD_CONFIG", missing),
            ("HELM_CONFIG_HOME", missing),
            ("HELM_REPOSITORY_CONFIG", missing),
            ("KUBECONFIG", missing),
            ("MCP_REMOTE_CONFIG_DIR", missing),
            ("NETRC", missing),
            ("NPM_CONFIG_USERCONFIG", missing),
            ("OCI_CLI_CONFIG_FILE", missing),
            ("PULUMI_CREDENTIALS_PATH", missing),
            ("PULUMI_HOME", missing),
            ("RCLONE_CONFIG", missing),
            ("REGISTRY_AUTH_FILE", missing),
            ("SUPABASE_HOME", missing),
            ("TALOSCONFIG", missing),
            ("TALOS_HOME", missing),
            ("UV_CREDENTIALS_DIR", missing),
            ("VAGRANT_HOME", missing),
            ("XDG_CACHE_HOME", missing),
            ("XDG_CONFIG_HOME", missing),
            ("XDG_RUNTIME_DIR", missing),
            ("XDG_STATE_HOME", missing),
        ]);

        for integration in isotope_integrations::INTEGRATIONS {
            if let Some(detect) = integration.detect {
                assert!(
                    !detect()
                        .unwrap_or_else(|err| panic!("{} detect failed: {err}", integration.name)),
                    "{} should not detect secrets in an empty home",
                    integration.name
                );
            }
            if let Some(detect_reasons) = integration.detect_reasons {
                let reasons = detect_reasons().unwrap_or_else(|err| {
                    panic!("{} detect reasons failed: {err}", integration.name)
                });
                assert!(
                    reasons.is_empty(),
                    "{} should not report reasons in an empty home: {reasons:?}",
                    integration.name
                );
            }
            if let Some(migrate) = integration.migrate {
                migrate()
                    .unwrap_or_else(|err| panic!("{} migrate failed: {err}", integration.name));
            }
        }
    }

    #[test]
    fn generated_isotope_detectors_report_seeded_secret_files() {
        let _lock = test_env_lock().lock().unwrap();
        if isotope_integrations::INTEGRATIONS
            .iter()
            .all(|integration| integration.detect_reasons.is_none())
        {
            return;
        }

        fn write_fixture(path: &Path, contents: impl AsRef<[u8]>) {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, contents).unwrap();
        }

        let temp = TempDir::new().unwrap();
        let home = temp.path().join("home");
        let xdg_config = temp.path().join("xdg-config");
        let xdg_cache = temp.path().join("xdg-cache");
        let xdg_data = temp.path().join("xdg-data");
        let xdg_state = temp.path().join("xdg-state");
        let xdg_runtime = temp.path().join("xdg-runtime");
        let missing = temp.path().join("missing");
        let akamai_edgerc = temp.path().join("akamai.edgerc");
        let argocd_config = temp.path().join("argocd");
        let aws_credentials = temp.path().join("aws-credentials");
        let bitwarden_appdata = temp.path().join("bitwarden");
        let cargo_home = temp.path().join("cargo");
        let caroot = temp.path().join("mkcert");
        let civo_config = temp.path().join("civo.json");
        let composer_home = temp.path().join("composer");
        let checkmarx_config = temp.path().join("checkmarx.yaml");
        let dcos_dir = temp.path().join("dcos");
        let doctl_config = temp.path().join("doctl.yaml");
        let docker_config = temp.path().join("docker");
        let gh_config = temp.path().join("gh");
        let glab_config = temp.path().join("glab");
        let hcloud_config = temp.path().join("hcloud.toml");
        let helm_config_home = temp.path().join("helm");
        let helm_repository_config = temp.path().join("repositories.yaml");
        let kubeconfig = temp.path().join("kubeconfig");
        let netrc = temp.path().join("netrc");
        let npmrc = temp.path().join("npmrc");
        let oci_config = temp.path().join("oci-config");
        let pulumi_credentials_dir = temp.path().join("pulumi-credentials");
        let pulumi_credentials = pulumi_credentials_dir.join("credentials.json");
        let pulumi_home = temp.path().join("pulumi-home");
        let rclone_config = temp.path().join("rclone.conf");
        let registry_auth = temp.path().join("containers-auth.json");
        let supabase_home = temp.path().join("supabase");
        let talosconfig = temp.path().join("talosconfig");
        let talos_home = temp.path().join("talos");
        let uv_credentials_dir = temp.path().join("uv");
        let vagrant_home = temp.path().join("vagrant");

        write_fixture(
            &home.join(".config/acli/jira_config.yaml"),
            "token: atlassian\n",
        );
        write_fixture(
            &home.join(".bash_profile"),
            "export BASH_SERVICE_TOKEN=secret_secret\n",
        );
        write_fixture(
            &home.join(".zshrc"),
            "export OPENAI_API_KEY=\"sk-proj-THIS_IS_A_FAKE_KEY_FOR_TESTING_ONLY_1234567890abcdefghijklmnopqrstuvwxyz\"\n",
        );
        write_fixture(&xdg_data.join("atuin/key"), "atuin-secret\n");
        write_fixture(
            &xdg_config.join("atuin/config.toml"),
            "session_path = \"~/atuin-session\"\n",
        );
        write_fixture(&home.join("atuin-session"), "atuin-session-secret\n");
        write_fixture(
            &home.join(".config/letsencrypt/live/example/privkey.pem"),
            "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
        );
        write_fixture(
            &akamai_edgerc,
            "[default]\nhost = akamai.example\nclient_token = tok\nclient_secret = sec\naccess_token = acc\n",
        );
        write_fixture(
            &xdg_config.join("algolia/config.toml"),
            "[default]\napplication_id = \"app\"\napi_key = \"algolia\"\n",
        );
        write_fixture(
            &home.join(".aliyun/config.json"),
            r#"{"profiles":[{"access_key_secret":"aliyun-secret"}]}"#,
        );
        write_fixture(
            &argocd_config.join("config"),
            "users:\n- auth-token: argocd\n",
        );
        write_fixture(&checkmarx_config, "cx_apikey: ast-secret\n");
        write_fixture(
            &bitwarden_appdata.join("data.json"),
            r#"{"accessToken":"bw"}"#,
        );
        write_fixture(&home.join(".bridgecrew/credentials"), "bridgecrew-token\n");
        write_fixture(&home.join(".circleci/cli.yml"), "token: circleci-token\n");
        write_fixture(&civo_config, r#"{"apikey":"civo-token"}"#);
        write_fixture(
            &composer_home.join("auth.json"),
            r#"{"github-oauth":{"github.com":"composer-token"}}"#,
        );
        write_fixture(
            &dcos_dir.join("clusters/prod/dcos.toml"),
            "dcos_acs_token = \"dcos-token\"\n",
        );
        write_fixture(
            &doctl_config,
            "context: default\naccess-token: doctl-token\n",
        );
        write_fixture(
            &docker_config.join("config.json"),
            r#"{"auths":{"registry.example":{"auth":"dXNlcjpwYXNz"}},"credsStore":"osxkeychain","credHelpers":{"ghcr.io":"desktop"}}"#,
        );
        write_fixture(
            &home.join(".docker/machine/machines/default/id_rsa"),
            "-----BEGIN RSA PRIVATE KEY-----\nkey\n-----END RSA PRIVATE KEY-----\n",
        );
        write_fixture(
            &home.join(".fastlane/spaceship/default/cookie"),
            "---\n- !ruby/object:HTTP::Cookie\n  name: myacinfo\n  value: secret\n",
        );
        write_fixture(
            &xdg_config.join("fastly/config.toml"),
            "token = \"fastly\"\n",
        );
        write_fixture(
            &home.join(".cloudflared/cert.pem"),
            "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
        );
        write_fixture(
            &xdg_config.join("cloudflared/credentials.json"),
            r#"{"TunnelSecret":"cloudflared-secret"}"#,
        );
        write_fixture(
            &xdg_config.join(".wrangler/config/default.toml"),
            "oauth_token = \"wrangler-oauth\"\nrefresh_token = \"wrangler-refresh\"\n",
        );
        write_fixture(&home.join(".fly/config.yml"), "access_token: FlyV1 token\n");
        write_fixture(
            &gh_config.join("hosts.yml"),
            "github.com:\n  oauth_token: ghp_secret\n",
        );
        write_fixture(
            &glab_config.join("config.yml"),
            "hosts:\n  gitlab.com:\n    token: glpat\n",
        );
        write_fixture(&xdg_config.join("gotify/cli.json"), r#"{"token":"gotify"}"#);
        write_fixture(
            &xdg_config.join("graphite/auth"),
            r#"{"authToken":"graphite"}"#,
        );
        write_fixture(&hcloud_config, "token = \"hcloud\"\n");
        write_fixture(&home.join(".cache/huggingface/token"), "hf_secret\n");
        write_fixture(
            &kubeconfig,
            "users:\n- name: prod\n  user:\n    token: kube-token\n",
        );
        write_fixture(
            &home.join("Library/Preferences/netlify/config.json"),
            r#"{"users":{"u":{"auth":{"token":"netlify"}}}}"#,
        );
        write_fixture(
            &xdg_config.join("NuGet/NuGet.Config"),
            r#"<configuration><apikeys><add key="feed" value="nuget-secret" /></apikeys></configuration>"#,
        );
        write_fixture(
            &home.join(".nuget/NuGet/NuGet.Config"),
            r#"<configuration></configuration>"#,
        );
        write_fixture(
            &xdg_config.join("openvpn/prod.auth"),
            "openvpn-user\nopenvpn-password\n",
        );
        write_fixture(
            &xdg_config.join("openvpn/prod.ovpn"),
            "auth-user-pass prod.auth\n<tls-crypt>\nline1\nline2\n</tls-crypt>\n",
        );
        write_fixture(&npmrc, "_authToken=npm-token\n");
        write_fixture(
            &xdg_config.join("containers/auth.json"),
            r#"{"auths":{"registry.example":{"auth":"dXNlcjpwYXNz"}}}"#,
        );
        write_fixture(
            &registry_auth,
            r#"{"auths":{"registry.example":{"auth":"dXNlcjpwYXNz"}}}"#,
        );
        write_fixture(
            &pulumi_credentials,
            r#"{"accessTokens":{"https://api.pulumi.com":"pulumi-token"}}"#,
        );
        write_fixture(
            &rclone_config,
            "[remote]\ntoken = {\"access_token\":\"rclone\"}\n",
        );
        write_fixture(&home.join(".sentryclirc"), "[auth]\ntoken=sentry-token\n");
        write_fixture(&home.join(".shodan/api_key"), "shodan-key\n");
        write_fixture(
            &xdg_config.join("configstore/snyk.json"),
            r#"{"api":"snyk-token"}"#,
        );
        write_fixture(
            &supabase_home.join("access-token"),
            format!("sbp_{}\n", "a".repeat(40)),
        );
        write_fixture(
            &home.join(".terraform.d/credentials.tfrc.json"),
            r#"{"credentials":{"app.terraform.io":{"token":"tf-token"}}}"#,
        );
        write_fixture(
            &xdg_config.join("todoist/config.json"),
            r#"{"token":"todoist"}"#,
        );
        write_fixture(
            &home.join(".travis/config.yml"),
            "access_token: travis-token\n",
        );
        write_fixture(&home.join(".pypirc"), "[pypi]\npassword = twine-token\n");
        write_fixture(
            &vagrant_home.join("data/vagrant_login_token"),
            "vagrant-token\n",
        );
        write_fixture(
            &xdg_data.join("com.vercel.cli/auth.json"),
            r#"{"token":"vercel-token","refreshToken":"vercel-refresh"}"#,
        );
        write_fixture(&home.join(".vault-token"), "hvs.secret\n");
        write_fixture(&home.join(".vt.toml"), "apikey=\"vt-key\"\n");
        write_fixture(&home.join(".vultr-cli.yaml"), "api-key: vultr-key\n");
        write_fixture(
            &home.join(".wakatime.cfg"),
            "[settings]\napi_key = wakatime\n",
        );
        write_fixture(&home.join(".wskprops"), "AUTH=fake-uuid:fake-secret\n");
        write_fixture(
            &talosconfig,
            "contexts:\n  prod:\n    endpoints: []\n    ca: talos-ca\n",
        );

        let netrc_contents = "\
machine buf.build login alice password buf-token
machine api.heroku.com login user password heroku-token
machine example.com login user password netrc-token
";
        write_fixture(&home.join(".netrc"), netrc_contents);
        write_fixture(&netrc, netrc_contents);

        let _env = TestEnvGuard::set(&[
            ("HOME", home.to_str().unwrap()),
            ("XDG_CONFIG_HOME", xdg_config.to_str().unwrap()),
            ("XDG_CACHE_HOME", xdg_cache.to_str().unwrap()),
            ("XDG_DATA_HOME", xdg_data.to_str().unwrap()),
            ("XDG_STATE_HOME", xdg_state.to_str().unwrap()),
            ("XDG_RUNTIME_DIR", xdg_runtime.to_str().unwrap()),
            ("AKAMAI_EDGERC", akamai_edgerc.to_str().unwrap()),
            ("ARGOCD_CONFIG_DIR", argocd_config.to_str().unwrap()),
            (
                "AWS_SHARED_CREDENTIALS_FILE",
                aws_credentials.to_str().unwrap(),
            ),
            (
                "BITWARDENCLI_APPDATA_DIR",
                bitwarden_appdata.to_str().unwrap(),
            ),
            ("CARGO_HOME", cargo_home.to_str().unwrap()),
            ("CAROOT", caroot.to_str().unwrap()),
            ("CIVO_CONFIG", civo_config.to_str().unwrap()),
            ("COMPOSER_HOME", composer_home.to_str().unwrap()),
            ("CX_CONFIG_FILE_PATH", checkmarx_config.to_str().unwrap()),
            ("DCOS_DIR", dcos_dir.to_str().unwrap()),
            ("DIGITALOCEAN_CONFIG", doctl_config.to_str().unwrap()),
            ("DOCKER_CONFIG", docker_config.to_str().unwrap()),
            ("GH_CONFIG_DIR", gh_config.to_str().unwrap()),
            ("GLAB_CONFIG_DIR", glab_config.to_str().unwrap()),
            ("HCLOUD_CONFIG", hcloud_config.to_str().unwrap()),
            ("HELM_CONFIG_HOME", helm_config_home.to_str().unwrap()),
            (
                "HELM_REPOSITORY_CONFIG",
                helm_repository_config.to_str().unwrap(),
            ),
            ("KUBECONFIG", kubeconfig.to_str().unwrap()),
            ("MCP_REMOTE_CONFIG_DIR", missing.to_str().unwrap()),
            ("NETRC", netrc.to_str().unwrap()),
            ("NPM_CONFIG_USERCONFIG", npmrc.to_str().unwrap()),
            ("OCI_CLI_CONFIG_FILE", oci_config.to_str().unwrap()),
            (
                "PULUMI_CREDENTIALS_PATH",
                pulumi_credentials_dir.to_str().unwrap(),
            ),
            ("PULUMI_HOME", pulumi_home.to_str().unwrap()),
            ("RCLONE_CONFIG", rclone_config.to_str().unwrap()),
            ("REGISTRY_AUTH_FILE", registry_auth.to_str().unwrap()),
            ("SUPABASE_HOME", supabase_home.to_str().unwrap()),
            ("TALOSCONFIG", talosconfig.to_str().unwrap()),
            ("TALOS_HOME", talos_home.to_str().unwrap()),
            ("UV_CREDENTIALS_DIR", uv_credentials_dir.to_str().unwrap()),
            ("VAGRANT_HOME", vagrant_home.to_str().unwrap()),
        ]);

        let mut triggered = Vec::new();
        for integration in isotope_integrations::INTEGRATIONS {
            let Some(detect_reasons) = integration.detect_reasons else {
                continue;
            };
            let reasons = detect_reasons()
                .unwrap_or_else(|err| panic!("{} detect reasons failed: {err}", integration.name));
            if !reasons.is_empty() {
                triggered.push(integration.name);
            }
        }

        for expected in [
            "acli",
            "akamai",
            "algolia",
            "argocd",
            "atuin",
            "bash",
            "bitwarden-cli",
            "certbot",
            "cloudflare-wrangler",
            "cloudflared",
            "docker",
            "docker-machine",
            "fastlane",
            "gh",
            "kubernetes-cli",
            "openvpn",
            "supabase",
            "terraform",
            "vercel-cli",
            "zsh",
        ] {
            assert!(
                triggered.contains(&expected),
                "expected {expected} to report seeded secrets, got {triggered:?}"
            );
        }
        assert!(
            triggered.len() >= 30,
            "expected broad generated detector coverage, got {triggered:?}"
        );
    }

    #[test]
    fn generated_isotope_migrations_scrub_seeded_secret_files() {
        let _lock = test_env_lock().lock().unwrap();
        if isotope_integrations::INTEGRATIONS
            .iter()
            .all(|integration| integration.migrate.is_none())
        {
            return;
        }

        fn write_fixture(path: &Path, contents: impl AsRef<[u8]>) {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, contents).unwrap();
        }

        let temp = TempDir::new().unwrap();
        let home = temp.path().join("home");
        let xdg_config = temp.path().join("xdg-config");
        let xdg_cache = temp.path().join("xdg-cache");
        let xdg_state = temp.path().join("xdg-state");
        let xdg_runtime = temp.path().join("xdg-runtime");
        let missing = temp.path().join("missing");
        let akamai_edgerc = temp.path().join("akamai.edgerc");
        let argocd_config = temp.path().join("argocd");
        let bitwarden_appdata = temp.path().join("bitwarden");
        let civo_config = temp.path().join("civo.json");
        let composer_home = temp.path().join("composer");
        let checkmarx_config = temp.path().join("checkmarx.yaml");
        let dcos_dir = temp.path().join("dcos");
        let doctl_config = temp.path().join("doctl.yaml");
        let glab_config = temp.path().join("glab");
        let hcloud_config = temp.path().join("hcloud.toml");
        let kubeconfig = temp.path().join("kubeconfig");
        let netrc = temp.path().join("netrc");
        let npmrc = temp.path().join("npmrc");
        let pulumi_credentials_dir = temp.path().join("pulumi-credentials");
        let pulumi_credentials = pulumi_credentials_dir.join("credentials.json");
        let rclone_config = temp.path().join("rclone.conf");
        let registry_auth = temp.path().join("containers-auth.json");
        let talosconfig = temp.path().join("talosconfig");
        let uv_credentials_dir = temp.path().join("uv");
        let vagrant_home = temp.path().join("vagrant");

        write_fixture(
            &home.join(".config/acli/jira_config.yaml"),
            "token: atlassian\n",
        );
        write_fixture(
            &akamai_edgerc,
            "[default]\nhost = akamai.example\nclient_token = tok\nclient_secret = sec\naccess_token = acc\n",
        );
        write_fixture(
            &xdg_config.join("algolia/config.toml"),
            "[default]\napplication_id = \"app\"\napi_key = \"algolia\"\n",
        );
        write_fixture(
            &home.join(".aliyun/config.json"),
            r#"{"profiles":[{"access_key_secret":"aliyun-secret"}]}"#,
        );
        write_fixture(
            &argocd_config.join("config"),
            "users:\n- auth-token: argocd\n",
        );
        write_fixture(
            &home.join(".aws/credentials"),
            "[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = aws-secret\n",
        );
        write_fixture(&checkmarx_config, "cx_apikey: ast-secret\n");
        write_fixture(
            &bitwarden_appdata.join("data.json"),
            r#"{"accessToken":"bw"}"#,
        );
        write_fixture(
            &home.join(".bridgecrew/credentials"),
            "access_key::secret_key\n",
        );
        write_fixture(
            &home.join(".circleci/cli.yml"),
            "host: https://circleci.com\ntoken: circleci-token\n",
        );
        write_fixture(&civo_config, r#"{"apikey":"civo-token"}"#);
        write_fixture(
            &composer_home.join("auth.json"),
            r#"{"github-oauth":{"github.com":"composer-token"}}"#,
        );
        write_fixture(
            &dcos_dir.join("clusters/prod/dcos.toml"),
            "dcos_acs_token = \"dcos-token\"\n",
        );
        write_fixture(
            &doctl_config,
            "context: default\naccess-token: doctl-token\n",
        );
        write_fixture(
            &home.join(".config/configstore/firebase-tools.json"),
            r#"{"tokens":{"refresh_token":"firebase-refresh","access_token":"firebase-access"}}"#,
        );
        write_fixture(
            &xdg_config.join("fastly/config.toml"),
            "token = \"fastly\"\n",
        );
        write_fixture(&home.join(".fly/config.yml"), "access_token: FlyV1 token\n");
        write_fixture(
            &xdg_config.join("gallery-dl/config.json"),
            r#"{"extractor":{"example":{"api-key":"gallery-secret"}}}"#,
        );
        write_fixture(
            &home.join(".config/gptcommit/config.toml"),
            "[openai]\napi_key = \"gptcommit-secret\"\n",
        );
        write_fixture(
            &glab_config.join("config.yml"),
            "hosts:\n  gitlab.com:\n    token: glpat\n",
        );
        write_fixture(
            &xdg_config.join("grafanactl/config.yaml"),
            "contexts:\n  default:\n    grafana:\n      server: https://grafana.example.com\n      token: grafana-token\n",
        );
        write_fixture(&xdg_config.join("gotify/cli.json"), r#"{"token":"gotify"}"#);
        write_fixture(
            &xdg_config.join("graphite/auth"),
            r#"{"authToken":"graphite"}"#,
        );
        write_fixture(&hcloud_config, "token = \"hcloud\"\n");
        write_fixture(&home.join(".cache/huggingface/token"), "hf_secret\n");
        write_fixture(
            &kubeconfig,
            "users:\n- name: prod\n  user:\n    token: kube-token\n",
        );
        write_fixture(
            &home.join("Library/Preferences/netlify/config.json"),
            r#"{"users":{"u":{"auth":{"token":"netlify"}}}}"#,
        );
        write_fixture(
            &xdg_config.join("luarocks/upload_config.lua"),
            "return { key = \"luarocks-secret\", server = \"https://luarocks.org\" }\n",
        );
        write_fixture(
            &home.join(".m2/settings.xml"),
            "<settings><servers><server><password>maven-secret</password></server></servers></settings>\n",
        );
        write_fixture(
            &xdg_config.join("NuGet/NuGet.Config"),
            r#"<configuration><apikeys><add key="feed" value="nuget-secret" /></apikeys></configuration>"#,
        );
        write_fixture(
            &home.join(".nuget/NuGet/NuGet.Config"),
            r#"<configuration></configuration>"#,
        );
        write_fixture(&npmrc, "_authToken=npm-token\n");
        write_fixture(
            &home.join(".config/openstack/clouds.yaml"),
            "clouds:\n  dev:\n    auth:\n      password: openstack-password\n",
        );
        write_fixture(
            &xdg_config.join("openhue/config.yaml"),
            "Bridge: 192.0.2.10\nKey: openhue-secret\n",
        );
        write_fixture(
            &home.join(".runpod/config.toml"),
            "apiKey = \"runpod-secret\"\napiUrl = \"https://api.runpod.io/graphql\"\n",
        );
        write_fixture(
            &home.join(".cargo/credentials.toml"),
            "[registry]\ntoken = \"cargo-secret\"\n",
        );
        write_fixture(
            &home.join(".s3cfg"),
            "access_key = AKIAEXAMPLE\nsecret_key = s3-secret\naccess_token = s3-session\n",
        );
        write_fixture(
            &home.join(".sbt/.credentials"),
            "realm=Repo\nhost=repo.example.com\nuser=me\npassword=sbt-secret\n",
        );
        write_fixture(
            &home.join(".snowflake/config.toml"),
            "[connections.default]\npassword = \"snowflake-secret\"\n",
        );
        write_fixture(
            &pulumi_credentials,
            r#"{"accessTokens":{"https://api.pulumi.com":"pulumi-token"}}"#,
        );
        write_fixture(
            &rclone_config,
            "[remote]\ntoken = {\"access_token\":\"rclone\"}\n",
        );
        write_fixture(
            &registry_auth,
            r#"{"auths":{"registry.example":{"auth":"dXNlcjpwYXNz"}}}"#,
        );
        write_fixture(&home.join(".sentryclirc"), "[auth]\ntoken=sentry-token\n");
        write_fixture(&home.join(".shodan/api_key"), "shodan-key\n");
        write_fixture(
            &xdg_config.join("configstore/snyk.json"),
            r#"{"api":"snyk-token"}"#,
        );
        write_fixture(
            &talosconfig,
            "contexts:\n  prod:\n    endpoints: []\n    ca: talos-ca\n",
        );
        write_fixture(
            &home.join(".terraform.d/credentials.tfrc.json"),
            r#"{"credentials":{"app.terraform.io":{"token":"tf-token"}}}"#,
        );
        write_fixture(
            &xdg_config.join("todoist/config.json"),
            r#"{"token":"todoist"}"#,
        );
        write_fixture(
            &home.join(".travis/config.yml"),
            "access_token: travis-token\n",
        );
        write_fixture(&home.join(".pypirc"), "[pypi]\npassword = twine-token\n");
        write_fixture(
            &home.join(".uaa/config.json"),
            r#"{"Token":{"access_token":"uaa-access","refresh_token":"uaa-refresh"}}"#,
        );
        write_fixture(
            &uv_credentials_dir.join("credentials.toml"),
            "[[credentials]]\npassword = \"uv-secret\"\n",
        );
        write_fixture(
            &vagrant_home.join("data/vagrant_login_token"),
            "vagrant-token\n",
        );
        write_fixture(&home.join(".vault-token"), "hvs.secret\n");
        write_fixture(&home.join(".vt.toml"), "apikey=\"vt-key\"\n");
        write_fixture(&home.join(".vultr-cli.yaml"), "api-key: vultr-key\n");
        write_fixture(
            &home.join(".wakatime.cfg"),
            "[settings]\napi_key = wakatime\n",
        );
        write_fixture(&home.join(".wskprops"), "AUTH=fake-uuid:fake-secret\n");
        let netrc_contents = "\
machine buf.build login alice password buf-token
machine api.heroku.com login user password heroku-token
machine example.com login user password netrc-token
";
        write_fixture(&home.join(".netrc"), netrc_contents);
        write_fixture(&netrc, netrc_contents);

        let _env = TestEnvGuard::set(&[
            ("HOME", home.to_str().unwrap()),
            ("XDG_CONFIG_HOME", xdg_config.to_str().unwrap()),
            ("XDG_CACHE_HOME", xdg_cache.to_str().unwrap()),
            ("XDG_STATE_HOME", xdg_state.to_str().unwrap()),
            ("XDG_RUNTIME_DIR", xdg_runtime.to_str().unwrap()),
            ("AKAMAI_EDGERC", akamai_edgerc.to_str().unwrap()),
            ("ARGOCD_CONFIG_DIR", argocd_config.to_str().unwrap()),
            ("AWS_SHARED_CREDENTIALS_FILE", ""),
            (
                "BITWARDENCLI_APPDATA_DIR",
                bitwarden_appdata.to_str().unwrap(),
            ),
            ("CARGO_HOME", ""),
            ("CAROOT", missing.to_str().unwrap()),
            ("CIVO_CONFIG", civo_config.to_str().unwrap()),
            ("COMPOSER_HOME", composer_home.to_str().unwrap()),
            ("CX_CONFIG_FILE_PATH", checkmarx_config.to_str().unwrap()),
            ("DCOS_DIR", dcos_dir.to_str().unwrap()),
            ("DIGITALOCEAN_CONFIG", doctl_config.to_str().unwrap()),
            ("DOCKER_CONFIG", missing.to_str().unwrap()),
            ("GH_CONFIG_DIR", missing.to_str().unwrap()),
            ("GLAB_CONFIG_DIR", glab_config.to_str().unwrap()),
            ("HCLOUD_CONFIG", hcloud_config.to_str().unwrap()),
            ("HELM_CONFIG_HOME", missing.to_str().unwrap()),
            ("HELM_REPOSITORY_CONFIG", missing.to_str().unwrap()),
            ("KUBECONFIG", kubeconfig.to_str().unwrap()),
            ("MCP_REMOTE_CONFIG_DIR", missing.to_str().unwrap()),
            ("NETRC", netrc.to_str().unwrap()),
            ("NPM_CONFIG_USERCONFIG", npmrc.to_str().unwrap()),
            ("OCI_CLI_CONFIG_FILE", missing.to_str().unwrap()),
            ("PULUMI_CREDENTIALS_PATH", ""),
            ("PULUMI_HOME", pulumi_credentials_dir.to_str().unwrap()),
            ("RCLONE_CONFIG", rclone_config.to_str().unwrap()),
            ("REGISTRY_AUTH_FILE", registry_auth.to_str().unwrap()),
            ("SUPABASE_HOME", missing.to_str().unwrap()),
            ("TALOSCONFIG", talosconfig.to_str().unwrap()),
            ("TALOS_HOME", missing.to_str().unwrap()),
            ("UV_CREDENTIALS_DIR", uv_credentials_dir.to_str().unwrap()),
            ("VAGRANT_HOME", vagrant_home.to_str().unwrap()),
        ]);

        let migration_targets = [
            "acli",
            "akamai",
            "algolia",
            "aliyun-cli",
            "argocd",
            "ast-cli",
            "aws-cli",
            "bitwarden-cli",
            "buf",
            "checkov",
            "circleci",
            "civo",
            "composer",
            "dcos-cli",
            "doctl",
            "firebase-cli",
            "fastly",
            "flyctl",
            "gallery-dl",
            "gptcommit",
            "glab",
            "grafanactl",
            "gotify",
            "graphite",
            "hcloud",
            "heroku",
            "huggingface-cli",
            "kubernetes-cli",
            "luarocks",
            "maven",
            "netlify-cli",
            "nuget",
            "openhue-cli",
            "openstackclient",
            "pulumi",
            "rclone",
            "runpodctl",
            "rust",
            "s3cmd",
            "sbt",
            "sentry-cli",
            "shodan",
            "snowflake-cli",
            "snyk",
            "talosctl",
            "terraform",
            "todoist-cli",
            "travis",
            "twine",
            "uaa-cli",
            "uv",
            "vagrant",
            "vault",
            "virustotal-cli",
            "vultr",
            "wakatime-cli",
            "wsk",
        ];

        for name in migration_targets {
            let integration = isotope_integrations::INTEGRATIONS
                .iter()
                .find(|integration| integration.name == name)
                .unwrap_or_else(|| panic!("missing generated integration {name}"));
            let migrate = integration
                .migrate
                .unwrap_or_else(|| panic!("missing generated migration {name}"));
            let detects_seeded_secret = || -> Result<bool, String> {
                if let Some(detect_reasons) = integration.detect_reasons {
                    return detect_reasons().map(|reasons| !reasons.is_empty());
                }
                if let Some(detect) = integration.detect {
                    return detect();
                }
                Ok(false)
            };
            assert!(
                detects_seeded_secret()
                    .unwrap_or_else(|err| panic!("{name} detect failed before migration: {err}")),
                "{name} should report its seeded secret before migration"
            );
            match migrate() {
                Ok(()) => assert!(
                    !detects_seeded_secret().unwrap_or_else(|err| panic!(
                        "{name} detect failed after migration: {err}"
                    )),
                    "{name} migration left its seeded secret detectable"
                ),
                Err(err) if err.contains("isotope keychain integration is only available") => {}
                Err(err) => panic!("{name} migration failed: {err}"),
            }
        }
    }

    #[test]
    fn generated_radioisotope_migrations_cover_additional_default_paths() {
        let _lock = test_env_lock().lock().unwrap();
        if isotope_integrations::INTEGRATIONS
            .iter()
            .all(|integration| integration.migrate.is_none())
        {
            return;
        }

        fn write_fixture(path: &Path, contents: impl AsRef<[u8]>) {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, contents).unwrap();
        }

        fn detects_seeded_secret(
            integration: &isotope_integrations::IsotopeIntegration,
        ) -> Result<bool, String> {
            if let Some(detect_reasons) = integration.detect_reasons {
                return detect_reasons().map(|reasons| !reasons.is_empty());
            }
            if let Some(detect) = integration.detect {
                return detect();
            }
            Ok(false)
        }

        fn run_case(name: &str, seed: fn(&Path, &Path, &Path, &Path, &Path, &Path)) {
            let temp = TempDir::new().unwrap();
            let home = temp.path().join("home");
            let xdg_config = temp.path().join("xdg-config");
            let xdg_cache = temp.path().join("xdg-cache");
            let xdg_state = temp.path().join("xdg-state");
            let xdg_runtime = temp.path().join("xdg-runtime");
            let npmrc = temp.path().join("npmrc");
            let oci_config = home.join(".oci/config");
            let mcp_remote_config = home.join(".mcp-auth");

            seed(
                &home,
                &xdg_config,
                &xdg_cache,
                &xdg_state,
                &xdg_runtime,
                &npmrc,
            );

            let _env = TestEnvGuard::set(&[
                ("HOME", home.to_str().unwrap()),
                ("XDG_CONFIG_HOME", xdg_config.to_str().unwrap()),
                ("XDG_CACHE_HOME", xdg_cache.to_str().unwrap()),
                ("XDG_STATE_HOME", xdg_state.to_str().unwrap()),
                ("XDG_RUNTIME_DIR", xdg_runtime.to_str().unwrap()),
                ("NPM_CONFIG_USERCONFIG", npmrc.to_str().unwrap()),
                ("OCI_CLI_CONFIG_FILE", oci_config.to_str().unwrap()),
                ("MCP_REMOTE_CONFIG_DIR", mcp_remote_config.to_str().unwrap()),
            ]);

            let integration = isotope_integrations::INTEGRATIONS
                .iter()
                .find(|integration| integration.name == name)
                .unwrap_or_else(|| panic!("missing generated integration {name}"));
            let migrate = integration
                .migrate
                .unwrap_or_else(|| panic!("missing generated migration {name}"));

            assert!(
                detects_seeded_secret(integration)
                    .unwrap_or_else(|err| panic!("{name} detect failed before migration: {err}")),
                "{name} should report its seeded secret before migration"
            );
            match migrate() {
                Ok(()) => assert!(
                    !detects_seeded_secret(integration).unwrap_or_else(|err| panic!(
                        "{name} detect failed after migration: {err}"
                    )),
                    "{name} migration left its seeded secret detectable"
                ),
                Err(err) if err.contains("isotope keychain integration is only available") => {}
                Err(err) => panic!("{name} migration failed: {err}"),
            }
        }

        type MigrationFixtureWriter = fn(&Path, &Path, &Path, &Path, &Path, &Path);

        let cases: &[(&str, MigrationFixtureWriter)] = &[
            ("astra", |_, xdg_config, _, _, _, _| {
                write_fixture(
                    &xdg_config.join("astra/.astrarc"),
                    "default=prod\ntoken=AstraCS:astra-secret\n",
                );
            }),
            ("censys", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".config/censys/censys.cfg"),
                    "[DEFAULT]\napi_id = fake-censys-id\napi_secret = fake-censys-secret\n",
                );
            }),
            ("cloudsmith-cli", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".cloudsmith/credentials.ini"),
                    "[default]\napi_key=fake-cloudsmith-key\n",
                );
            }),
            ("dropbox-uploader", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".dropbox_uploader"),
                    "APPKEY=fake-app\nOAUTH_ACCESS_TOKEN=fake-token\n",
                );
            }),
            ("gcli", |_, xdg_config, _, _, _, _| {
                write_fixture(
                    &xdg_config.join("gcli/config"),
                    "[github]\ntoken = fake-gcli-token\n",
                );
            }),
            ("goat", |_, _, _, xdg_state, _, _| {
                write_fixture(
                    &xdg_state.join("goat/auth-session.json"),
                    r#"{"password":"fake-app-password","access_token":"fake-access"}"#,
                );
            }),
            ("imap-backup", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".imap-backup/config.json"),
                    r#"{"accounts":[{"username":"a@example.com","password":"fake-password"}]}"#,
                );
            }),
            ("jfrog-cli", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".jfrog/jfrog-cli.conf.v6"),
                    r#"[{"serverId":"prod","url":"https://example.test","accessToken":"secret"}]"#,
                );
            }),
            ("mcp-remote", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".mcp-auth/server_tokens.json"),
                    r#"{"access_token":"mcp-access","refresh_token":"mcp-refresh"}"#,
                );
            }),
            ("minio-mc", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".mc/config.json"),
                    r#"{"aliases":{"minio":{"url":"https://minio.example.test","accessKey":"access","secretKey":"secret","sessionToken":"session"}}}"#,
                );
            }),
            ("mysql", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".my.cnf"),
                    "[client]\nuser = deploy\npassword = secret\n",
                );
            }),
            ("mysql-client", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".my.cnf"),
                    "[client]\nuser = deploy\npassword = secret\n",
                );
            }),
            ("mysql@8.0", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".my.cnf"),
                    "[client]\nuser = deploy\npassword = secret\n",
                );
            }),
            ("mysql@8.4", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".my.cnf"),
                    "[client]\nuser = deploy\npassword = secret\n",
                );
            }),
            ("node@18", |_, _, _, _, _, npmrc| {
                write_fixture(npmrc, "//registry.npmjs.org/:_authToken=npm_secret\n");
            }),
            ("oci-cli", |home, _, _, _, _, _| {
                write_fixture(&home.join(".oci/key.pem"), "private-key\n");
                write_fixture(
                    &home.join(".oci/config"),
                    "[DEFAULT]\nuser=ocid1.user\nkey_file=~/.oci/key.pem\n",
                );
            }),
            ("ossutil", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".ossutilconfig"),
                    "[Credentials]\naccessKeyID = LTAIEXAMPLE\naccessKeySecret = very-secret\n",
                );
            }),
            ("oxide-cli", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".config/oxide/credentials.toml"),
                    "[profile.prod]\nhost = \"https://oxide.example\"\ntoken = \"fake-oxide-token\"\n",
                );
            }),
            ("phylum-cli", |_, xdg_config, _, _, _, _| {
                write_fixture(
                    &xdg_config.join("phylum/settings.yaml"),
                    "offline_access: ph0_fake-token\n",
                );
            }),
            ("plumber", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".batchsh/plumber.json"),
                    r#"{"token":"plumber-token"}"#,
                );
            }),
            ("pnpm", |_, _, _, _, _, npmrc| {
                write_fixture(npmrc, "//registry.npmjs.org/:_authToken=pnpm_secret\n");
            }),
            ("qwen-code", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".qwen/settings.json"),
                    r#"{"env":{"DASHSCOPE_API_KEY":"sk-test"}}"#,
                );
            }),
            ("railway", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".railway/config.json"),
                    r#"{"user":{"token":"rw_legacy"}}"#,
                );
            }),
            ("soracom-cli", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".soracom/default.json"),
                    r#"{"authKeyId":"keyId-example","authKey":"secret-example"}"#,
                );
            }),
            ("sqlcmd", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".sqlcmd/sqlconfig"),
                    "users:\n- user:\n    username: sa\n    password: c2VjcmV0\n",
                );
            }),
            ("terraform-core", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".terraform.d/credentials.tfrc.json"),
                    r#"{"credentials":{"app.terraform.io":{"token":"secret"}}}"#,
                );
            }),
            ("transifex-cli", |home, _, _, _, _, _| {
                write_fixture(
                    &home.join(".transifexrc"),
                    "[https://app.transifex.com]\nrest_hostname = https://rest.api.transifex.com\ntoken = fake-token\n",
                );
            }),
        ];

        for (name, seed) in cases {
            run_case(name, *seed);
        }
    }

    #[test]
    fn generated_credential_helpers_cover_help_and_reject_bad_tokens() {
        struct MissingCredentialStore;

        impl isotope::CredentialHelperSecretStore for MissingCredentialStore {
            fn load_secret(&self, key: &str) -> Result<String, String> {
                Err(format!("missing stub credential {key}"))
            }

            fn store_secret(&self, _key: &str, _value: &str) -> Result<(), String> {
                Ok(())
            }
        }

        fn helper_args(name: &str) -> Vec<std::ffi::OsString> {
            match name {
                "aws" => Vec::new(),
                "cargo" => vec![std::ffi::OsString::from("--cargo-plugin")],
                "kubernetes" => vec![std::ffi::OsString::from("prod")],
                "nuget" => vec![
                    std::ffi::OsString::from("-Uri"),
                    std::ffi::OsString::from("https://api.nuget.org/v3/index.json"),
                ],
                "opentofu" | "terraform" => vec![
                    std::ffi::OsString::from("get"),
                    std::ffi::OsString::from("app.terraform.io"),
                ],
                "podman" | "skopeo" => vec![std::ffi::OsString::from("list")],
                "wakatime" => Vec::new(),
                other => panic!("unexpected credential helper {other}"),
            }
        }

        fn invocation<'a>(
            args: Vec<std::ffi::OsString>,
            token: Option<&str>,
            parent_executable_path: Option<&str>,
            store: &'a MissingCredentialStore,
        ) -> isotope::CredentialHelperInvocation<'a> {
            isotope::CredentialHelperInvocation {
                args,
                caller: isotope::CredentialHelperCallerContext {
                    token: token.map(str::to_string),
                    parent_executable_path: parent_executable_path.map(str::to_string),
                    parent_command: None,
                },
                store,
            }
        }

        let store = MissingCredentialStore;
        let helpers = isotope_integrations::INTEGRATIONS
            .iter()
            .filter_map(|integration| {
                Some((
                    integration.credential_helper_name?,
                    integration.credential_helper?,
                ))
            })
            .collect::<Vec<_>>();
        if helpers.is_empty() {
            return;
        }

        for (name, helper) in &helpers {
            helper(invocation(
                vec![std::ffi::OsString::from("--help")],
                None,
                None,
                &store,
            ))
            .unwrap();
            helper(invocation(
                vec![std::ffi::OsString::from("--version")],
                None,
                None,
                &store,
            ))
            .unwrap();

            let missing = helper(invocation(helper_args(name), None, None, &store)).unwrap_err();
            assert!(
                missing.to_ascii_lowercase().contains("token"),
                "expected missing token error for {name}, got {missing}"
            );
            let invalid =
                helper(invocation(helper_args(name), Some("short"), None, &store)).unwrap_err();
            assert!(
                invalid.to_ascii_lowercase().contains("token"),
                "expected invalid token error for {name}, got {invalid}"
            );
            let valid_token = "x".repeat(32);
            let missing_parent = helper(invocation(
                helper_args(name),
                Some(&valid_token),
                None,
                &store,
            ))
            .unwrap_err();
            assert!(
                missing_parent.to_ascii_lowercase().contains("parent"),
                "expected missing parent error for {name}, got {missing_parent}"
            );
            let wrong_parent = helper(invocation(
                helper_args(name),
                Some(&valid_token),
                Some("/tmp/not-the-approved-launcher"),
                &store,
            ))
            .unwrap_err();
            let wrong_parent = wrong_parent.to_ascii_lowercase();
            assert!(
                wrong_parent.contains("invoked")
                    || wrong_parent.contains("launcher")
                    || wrong_parent.contains("kubectl"),
                "expected wrong parent error for {name}, got {wrong_parent}"
            );
        }
        assert_eq!(helpers.len(), 9);
    }

    #[test]
    fn generated_isotope_helpers_return_none_without_compiled_integrations() {
        for name in ["gh", "aws-cli"] {
            let integration = isotope_integration(name);
            assert_eq!(
                integration.is_some(),
                isotope_integration(&format!("isotope:{name}")).is_some()
            );
            assert_eq!(
                isotope_has_migration(name),
                integration.and_then(|it| it.migrate).is_some()
            );
            assert_eq!(
                isotope_has_post_install(name),
                integration.and_then(|it| it.post_install).is_some()
            );

            if integration.is_none() {
                assert_eq!(run_generated_isotope_migration(name), None);
                assert_eq!(run_generated_isotope_post_install(name), None);
                assert_eq!(detect_isotope_install_reasons(name), None);
                assert_eq!(package_security_state_for_isotope(name), None);
            } else {
                if integration.and_then(|it| it.migrate).is_none() {
                    assert_eq!(run_generated_isotope_migration(name), None);
                }
                if integration.and_then(|it| it.post_install).is_none() {
                    assert_eq!(run_generated_isotope_post_install(name), None);
                }
            }
        }

        assert_eq!(
            package_security_state_for_identifiers(vec!["unrelated".to_string()]),
            None
        );
    }

    #[test]
    fn post_install_dispatcher_covers_supported_and_default_paths() {
        assert!(post_install_hooks::supports("python@3.14"));
        assert!(post_install_hooks::supports("openssl@3"));
        assert!(post_install_hooks::supports_dependency("openssl@3"));
        assert!(!post_install_hooks::supports_dependency("python@3.14"));
        assert!(!post_install_hooks::supports("ripgrep"));

        let temp = TempDir::new().unwrap();
        let prefix = temp.path().join("opt/python@3.14");
        let bin_dir = temp.path().join("bin");
        fs::create_dir_all(prefix.parent().unwrap().join("python@3.14")).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();
        fs::write(bin_dir.join("python3.14"), b"").unwrap();
        fs::write(bin_dir.join("pip3.14"), b"").unwrap();

        let python = post_install_hooks::run("python@3.14", &prefix, &bin_dir).unwrap();
        assert_eq!(
            python.managed_stubs,
            vec![
                "pip".to_string(),
                "pip3".to_string(),
                "python".to_string(),
                "python3".to_string(),
            ]
        );

        let openssl = post_install_hooks::run("openssl@3", temp.path(), &bin_dir).unwrap();
        assert_eq!(openssl, post_install_hooks::PostInstallOutcome::default());

        let unsupported = post_install_hooks::run("ripgrep", temp.path(), &bin_dir).unwrap();
        assert_eq!(
            unsupported,
            post_install_hooks::PostInstallOutcome::default()
        );
    }

    #[test]
    fn package_security_state_uses_source_and_alias_identifiers_without_integrations() {
        let info = PackageInfo {
            package_name: "gh".to_string(),
            qualified_name: "brew:gh".to_string(),
            install_root: PathBuf::from("/opt/gh"),
            installed: false,
            source: Some(PackageReceiptSource::Formula {
                root_formula: "gh".to_string(),
            }),
            source_error: None,
            aliases: vec!["GH".to_string(), "GitHub".to_string()],
            aliases_error: None,
            installed_version: None,
            latest_version: None,
            latest_version_error: None,
            executable_paths: Vec::new(),
            executable_paths_error: None,
            popularity: None,
            last_updated_at: None,
            homebrew_info: None,
            homebrew_info_error: None,
            npm_homepage: None,
            npm_package_info_error: None,
            security_state: None,
            version_options: Vec::new(),
        };

        let expected = package_security_state_for_isotope("gh");
        assert_eq!(package_security_state(&info), expected);
        assert_eq!(
            package_security_state_for_identifiers(info.aliases.clone()),
            expected
        );
    }

    #[test]
    fn resolve_scanned_package_statuses_warns_for_other_dirs() {
        let mut warnings = Vec::new();
        let statuses = resolve_scanned_package_statuses(
            vec![
                InstalledPackageRef {
                    package_name: "deno".to_string(),
                    install_root: PathBuf::from("/opt/deno"),
                },
                InstalledPackageRef {
                    package_name: "scratch".to_string(),
                    install_root: PathBuf::from("/opt/scratch"),
                },
            ],
            |package| match package.package_name.as_str() {
                "deno" => Ok(PackageStatus {
                    package_name: "deno".to_string(),
                    source: PackageReceiptSource::Vendor {
                        vendor_name: "deno".to_string(),
                    },
                    installed_version: "2.7.7".to_string(),
                    latest_version: "2.7.8".to_string(),
                }),
                _ => Err(format!(
                    "package {} is installed but missing package metadata",
                    package.package_name
                )),
            },
            |warning| warnings.push(warning),
        )
        .unwrap();

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].package_name, "deno");
        assert_eq!(
            warnings,
            vec!["warning: skipping /opt/scratch: package scratch is installed but missing package metadata".to_string()]
        );
    }

    #[test]
    fn resolve_scanned_package_records_warns_for_other_dirs() {
        let mut warnings = Vec::new();
        let records = resolve_scanned_package_records(
            vec![
                InstalledPackageRef {
                    package_name: "deno".to_string(),
                    install_root: PathBuf::from("/opt/deno"),
                },
                InstalledPackageRef {
                    package_name: "scratch".to_string(),
                    install_root: PathBuf::from("/opt/scratch"),
                },
            ],
            |package| match package.package_name.as_str() {
                "deno" => Ok(InstalledPackageRecord {
                    package_name: "deno".to_string(),
                    source: PackageReceiptSource::Vendor {
                        vendor_name: "deno".to_string(),
                    },
                    installed_version: "2.7.7".to_string(),
                }),
                _ => Err(format!(
                    "package {} is installed but missing package metadata",
                    package.package_name
                )),
            },
            |warning| warnings.push(warning),
        )
        .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].package_name, "deno");
        assert_eq!(
            warnings,
            vec!["warning: skipping /opt/scratch: package scratch is installed but missing package metadata".to_string()]
        );
    }

    #[test]
    fn resolve_scanned_package_records_sort_by_name_after_known_prefixes() {
        let records = resolve_scanned_package_records(
            vec![
                InstalledPackageRef {
                    package_name: "npm:zulu".to_string(),
                    install_root: PathBuf::from("/opt/npm/zulu"),
                },
                InstalledPackageRef {
                    package_name: "deno".to_string(),
                    install_root: PathBuf::from("/opt/deno"),
                },
                InstalledPackageRef {
                    package_name: "pip:bravo".to_string(),
                    install_root: PathBuf::from("/opt/pip/bravo"),
                },
                InstalledPackageRef {
                    package_name: "npm:@tobilu/qmd".to_string(),
                    install_root: PathBuf::from("/opt/npm/@tobilu/qmd"),
                },
                InstalledPackageRef {
                    package_name: "isotope:alpha".to_string(),
                    install_root: PathBuf::from("/opt/iso/alpha"),
                },
            ],
            |package| {
                Ok(InstalledPackageRecord {
                    package_name: package.package_name.clone(),
                    source: PackageReceiptSource::Vendor {
                        vendor_name: package.package_name.clone(),
                    },
                    installed_version: "1.0.0".to_string(),
                })
            },
            |_| {},
        )
        .unwrap();

        assert_eq!(
            records
                .into_iter()
                .map(|record| record.package_name)
                .collect::<Vec<_>>(),
            vec![
                "isotope:alpha".to_string(),
                "pip:bravo".to_string(),
                "deno".to_string(),
                "npm:@tobilu/qmd".to_string(),
                "npm:zulu".to_string(),
            ]
        );
    }

    #[test]
    fn resolve_outdated_package_statuses_filters_up_to_date_entries() {
        let statuses = vec![
            PackageStatus {
                package_name: "deno".to_string(),
                source: PackageReceiptSource::Vendor {
                    vendor_name: "deno".to_string(),
                },
                installed_version: "2.7.7".to_string(),
                latest_version: "2.7.8".to_string(),
            },
            PackageStatus {
                package_name: "gh".to_string(),
                source: PackageReceiptSource::Vendor {
                    vendor_name: "gh".to_string(),
                },
                installed_version: "2.80.0".to_string(),
                latest_version: "2.80.0".to_string(),
            },
        ];
        let outdated = filter_outdated_package_statuses(statuses);

        assert_eq!(outdated.len(), 1);
        assert_eq!(outdated[0].package_name, "deno");
    }

    #[test]
    fn requested_package_from_status_preserves_formula_identity() {
        let formula = PackageStatus {
            package_name: "python@3.12".to_string(),
            source: PackageReceiptSource::Formula {
                root_formula: "python@3.12".to_string(),
            },
            installed_version: "3.12.10".to_string(),
            latest_version: "3.12.11".to_string(),
        };
        let alias = PackageStatus {
            package_name: "ffmpeg".to_string(),
            source: PackageReceiptSource::Formula {
                root_formula: "ffmpeg-full".to_string(),
            },
            installed_version: "8.0".to_string(),
            latest_version: "8.1".to_string(),
        };
        let vendor = PackageStatus {
            package_name: "deno".to_string(),
            source: PackageReceiptSource::Vendor {
                vendor_name: "deno".to_string(),
            },
            installed_version: "2.7.7".to_string(),
            latest_version: "2.7.8".to_string(),
        };
        let npm = PackageStatus {
            package_name: "openclaw".to_string(),
            source: PackageReceiptSource::Npm {
                package_name: "openclaw".to_string(),
            },
            installed_version: "1.2.3".to_string(),
            latest_version: "1.2.4".to_string(),
        };
        let pip = PackageStatus {
            package_name: "psycopg2".to_string(),
            source: PackageReceiptSource::Pip {
                package_name: "psycopg2".to_string(),
            },
            installed_version: "2.9.9".to_string(),
            latest_version: "2.9.10".to_string(),
        };

        assert_eq!(
            requested_package_from_status(&formula),
            RequestedPackage::HomebrewFormula("python@3.12".to_string())
        );
        assert_eq!(
            requested_package_from_status(&alias),
            RequestedPackage::Auto("ffmpeg".to_string())
        );
        assert_eq!(
            requested_package_from_status(&vendor),
            RequestedPackage::VendorPackage("deno".to_string())
        );
        assert_eq!(
            requested_package_from_status(&npm),
            RequestedPackage::NpmPackage {
                package: "openclaw".to_string(),
                version: None,
            }
        );
        assert_eq!(
            requested_package_from_status(&pip),
            RequestedPackage::PipPackage("psycopg2".to_string())
        );
    }

    #[test]
    fn load_or_resolve_package_receipt_requires_root_receipt() {
        let temp = TempDir::new().unwrap();
        let receipts_dir = temp.path().join(RECEIPTS_DIR);
        fs::create_dir_all(&receipts_dir).unwrap();
        fs::write(
            receipts_dir.join("ffmpeg-full.json"),
            serde_json::to_vec_pretty(&InstallReceipt {
                formula: "ffmpeg-full".to_string(),
                version: "8.1".to_string(),
                bottle_sha256: "sha256".to_string(),
                bottle_tag: "arm64_tahoe".to_string(),
                owned_paths: Vec::new(),
            })
            .unwrap(),
        )
        .unwrap();

        let error = load_or_resolve_package_receipt("ffmpeg", temp.path()).unwrap_err();
        assert_eq!(
            error,
            "package ffmpeg is installed but missing package metadata"
        );
    }

    #[test]
    fn formula_version_string_appends_revision_suffix() {
        let info = FormulaInfo {
            versions: FormulaVersions {
                stable: "2.53.0".to_string(),
            },
            revision: 1,
            ..formula_info(false)
        };

        assert_eq!(formula_version_string(&info), "2.53.0_1");
    }

    #[test]
    fn extract_semver_from_text_handles_v_prefix() {
        assert_eq!(
            extract_semver_from_text("node v22.18.0").unwrap(),
            semver::Version::parse("22.18.0").unwrap()
        );
    }

    #[cfg(feature = "gold-release")]
    #[test]
    fn parse_self_update_version_strips_leading_v() {
        assert_eq!(
            parse_self_update_version("v0.1.0").unwrap(),
            semver::Version::parse("0.1.0").unwrap()
        );
    }

    #[cfg(feature = "gold-release")]
    #[test]
    fn self_update_asset_name_for_uses_release_naming() {
        let version = semver::Version::parse("0.1.0").unwrap();
        assert_eq!(
            self_update_asset_name_for(&version, "macos", "aarch64"),
            Some("nucleus-0.1.0-Darwin-arm64.tar.gz".to_string())
        );
        assert_eq!(
            self_update_asset_name_for(&version, "linux", "x86_64"),
            Some("nucleus-0.1.0-Linux-x86_64.tar.gz".to_string())
        );
        assert_eq!(
            self_update_asset_name_for(&version, "windows", "x86_64"),
            None
        );
    }

    #[test]
    fn rewrite_absolute_path_prefers_etc_over_keg_root() {
        let rules = vec![
            RewriteRule {
                source: "/opt/homebrew/Cellar/gum/0.17.0/etc".to_string(),
                destination: "/etc".to_string(),
            },
            RewriteRule {
                source: "/opt/homebrew/Cellar/gum/0.17.0".to_string(),
                destination: "/tmp/x/gum".to_string(),
            },
        ];
        let rewritten = rewrite_absolute_path(
            "/opt/homebrew/Cellar/gum/0.17.0/etc/bash_completion.d/gum",
            &rules,
        )
        .unwrap();
        assert_eq!(rewritten.unwrap(), "/etc/bash_completion.d/gum");
    }

    #[test]
    fn rewrite_text_rewrites_openssl_cert_pem_to_short_cert_path() {
        let plan = fixed_i_plan("curl", "curl");
        let rules = build_rewrite_rules(&plan, &[]);
        let rewritten = rewrite_text(
            "@@HOMEBREW_PREFIX@@/etc/openssl@3/cert.pem\n",
            Path::new("/tmp/curl"),
            "curl",
            &rules,
        )
        .unwrap();
        assert_eq!(rewritten, "/opt/curl/ssl/cert.pem\n");
    }

    #[test]
    fn rewrite_binary_rewrites_openssl_cert_path_to_short_cert_path() {
        let plan = fixed_i_plan("python@3.12", "python@3.12");
        let rules = build_rewrite_rules(&plan, &[]);
        let expected = binary_rewrite_destination(
            &RewriteRule {
                source: "/opt/homebrew/etc/openssl@3/cert.pem".to_string(),
                destination: "/opt/python@3.12/ssl/cert.pem".to_string(),
            },
            BinaryRewriteMode::Slash,
        );
        let mut bytes = b"prefix\0/opt/homebrew/etc/openssl@3/cert.pem\0".to_vec();
        let changed = rewrite_binary(
            &mut bytes,
            Path::new("/tmp/libcrypto.3.dylib"),
            "openssl@3",
            &rules,
            BinaryRewriteMode::Slash,
        )
        .unwrap();
        assert!(changed);
        assert!(find_subslice(&bytes, &expected).is_some());
        assert!(find_subslice(&bytes, b"/opt/homebrew/etc/openssl@3/cert.pem").is_none());
    }

    #[test]
    fn rewrite_binary_rewrites_paths_inside_nul_delimited_segments() {
        let rule = RewriteRule {
            source: "/opt/homebrew/Cellar/gum/0.17.0".to_string(),
            destination: "/tmp/x/gum".to_string(),
        };
        let rules = vec![rule.clone()];
        let mut bytes =
            b"prefix\0OPENSSLDIR: \"/opt/homebrew/Cellar/gum/0.17.0/bin/gum\"\0".to_vec();
        let changed = rewrite_binary(
            &mut bytes,
            Path::new("/tmp/gum"),
            "gum",
            &rules,
            BinaryRewriteMode::Slash,
        )
        .unwrap();
        assert!(changed);
        let mut expected = binary_rewrite_destination(&rule, BinaryRewriteMode::Slash);
        expected.extend_from_slice(b"/bin/gum");
        assert!(find_subslice(&bytes, &expected).is_some());
        assert!(find_subslice(&bytes, b"/opt/homebrew").is_none());
    }

    #[test]
    fn rewrite_binary_rewrites_paths_inside_non_utf8_segments() {
        let plan = fixed_i_plan("direnv", "direnv");
        let installs = vec![InstalledFormula {
            spec: FormulaSpec {
                name: "bash".to_string(),
                bottle_sha256: "sha256".to_string(),
                bottle_url: "https://example.invalid/bash.tar.gz".to_string(),
            },
            keg_dir_name: "5.3.9".to_string(),
            archive_path: PathBuf::from("/tmp/bash.tar.gz"),
        }];
        let rules = build_rewrite_rules(&plan, &installs);
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend_from_slice(b"/opt/homebrew/opt/bash/bin/bash");
        bytes.push(0x80);
        bytes.push(0);

        let changed = rewrite_binary(
            &mut bytes,
            Path::new("/tmp/direnv"),
            "direnv",
            &rules,
            BinaryRewriteMode::Slash,
        )
        .unwrap();

        assert!(changed);
        assert!(find_subslice(&bytes, b"/opt////////////direnv/bin/bash").is_some());
        assert!(find_subslice(&bytes, b"/opt/homebrew/opt/bash/bin/bash").is_none());
    }

    #[test]
    fn rewrite_binary_keeps_shorter_path_rewrites_nul_free() {
        let plan = fixed_i_plan("direnv", "direnv");
        let installs = vec![InstalledFormula {
            spec: FormulaSpec {
                name: "bash".to_string(),
                bottle_sha256: "sha256".to_string(),
                bottle_url: "https://example.invalid/bash.tar.gz".to_string(),
            },
            keg_dir_name: "5.3.9".to_string(),
            archive_path: PathBuf::from("/tmp/bash.tar.gz"),
        }];
        let rules = build_rewrite_rules(&plan, &installs);
        let mut bytes = vec![0xff];
        bytes.extend_from_slice(b"/opt/homebrew/opt/bash/bin/bash");
        bytes.push(0x80);
        bytes.push(0);

        let changed = rewrite_binary(
            &mut bytes,
            Path::new("/tmp/direnv"),
            "direnv",
            &rules,
            BinaryRewriteMode::Slash,
        )
        .unwrap();

        assert!(changed);
        assert!(find_subslice(&bytes, b"/opt////////////direnv/bin/bash").is_some());
        assert!(find_subslice(&bytes, b"/opt/direnv/bin/bash\0").is_none());
        assert_eq!(*bytes.last().unwrap(), 0);
    }

    #[test]
    fn rewrite_binary_can_nul_pad_shorter_macho_paths() {
        let rule = RewriteRule {
            source: "/opt/homebrew/opt/node".to_string(),
            destination: "/tmp/opt/npm/flood".to_string(),
        };
        let rules = vec![rule];
        let mut bytes = b"cmd\0/opt/homebrew/opt/node/lib/libllhttp.9.3.dylib\0".to_vec();

        let changed = rewrite_binary(
            &mut bytes,
            Path::new("/tmp/node"),
            "node",
            &rules,
            BinaryRewriteMode::Nul,
        )
        .unwrap();

        assert!(changed);
        assert!(find_subslice(&bytes, b"/tmp/opt/npm/flood/lib/libllhttp.9.3.dylib\0").is_some());
        assert!(find_subslice(&bytes, b"/tmp/opt/npm/////////////flood").is_none());
        assert!(find_subslice(&bytes, b"/opt/homebrew/opt/node").is_none());
    }

    #[test]
    fn rewrite_binary_uses_loader_path_for_macho_paths_inside_future_root() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("stage");
        let future_root = temp.path().join("opt/npm/flood");
        let path = root.join("bin/node");
        let rule = RewriteRule {
            source: "/opt/homebrew/opt/node".to_string(),
            destination: future_root.to_string_lossy().to_string(),
        };
        let rules = vec![rule];
        let mut bytes = b"cmd\0/opt/homebrew/opt/node/lib/libllhttp.9.3.dylib\0".to_vec();

        let changed = rewrite_binary(
            &mut bytes,
            &path,
            "node",
            &rules,
            BinaryRewriteMode::Macho {
                path: &path,
                root: &root,
                future_root: &future_root,
            },
        )
        .unwrap();

        assert!(changed);
        assert!(find_subslice(&bytes, b"@loader_path/../lib/libllhttp.9.3.dylib\0").is_some());
        assert!(find_subslice(&bytes, b"/tmp/opt/npm/flood/lib/libllhttp").is_none());
        assert!(find_subslice(&bytes, b"/opt/homebrew/opt/node").is_none());
    }

    #[test]
    fn rewrite_binary_prefers_loader_path_for_short_production_macho_paths() {
        let root = PathBuf::from("/opt/npm/.tmp/stage/install");
        let future_root = PathBuf::from("/opt/npm/flood");
        let path = root.join("bin/node");
        let rule = RewriteRule {
            source: "/opt/homebrew/opt/node".to_string(),
            destination: future_root.to_string_lossy().to_string(),
        };
        let rules = vec![rule];
        let mut bytes = b"cmd\0/opt/homebrew/opt/node/lib/libllhttp.9.4.dylib\0".to_vec();

        let changed = rewrite_binary(
            &mut bytes,
            &path,
            "node",
            &rules,
            BinaryRewriteMode::Macho {
                path: &path,
                root: &root,
                future_root: &future_root,
            },
        )
        .unwrap();

        assert!(changed);
        assert!(find_subslice(&bytes, b"@loader_path/../lib/libllhttp.9.4.dylib\0").is_some());
        assert!(find_subslice(&bytes, b"/opt/npm/flood/lib/libllhttp").is_none());
        assert!(find_subslice(&bytes, b"/opt/homebrew/opt/node").is_none());
    }

    #[test]
    fn rewrite_binary_uses_absolute_macho_path_when_loader_path_is_longer() {
        let root = PathBuf::from("/tmp/nucleus/.tmp08cFDL/python@3.14/3.14.4_1");
        let future_root = PathBuf::from("/tmp/opt/iso/aws-cli");
        let path = root.join(
            "Frameworks/Python.framework/Versions/3.14/lib/python3.14/lib-dynload/\
             _zstd.cpython-314-darwin.so",
        );
        let rule = RewriteRule {
            source: "@@HOMEBREW_PREFIX@@/opt/zstd".to_string(),
            destination: future_root.to_string_lossy().to_string(),
        };
        let rules = vec![rule];
        let mut bytes = b"cmd\0@@HOMEBREW_PREFIX@@/opt/zstd/lib/libzstd.1.dylib\0".to_vec();

        let changed = rewrite_binary(
            &mut bytes,
            &path,
            "python@3.14",
            &rules,
            BinaryRewriteMode::Macho {
                path: &path,
                root: &root,
                future_root: &future_root,
            },
        )
        .unwrap();

        assert!(changed);
        assert!(find_subslice(&bytes, b"/tmp/opt/iso/aws-cli/lib/libzstd.1.dylib\0").is_some());
        assert!(find_subslice(&bytes, b"@loader_path/../../../../../../../lib").is_none());
        assert!(find_subslice(&bytes, b"@@HOMEBREW_PREFIX@@/opt/zstd").is_none());
    }

    #[test]
    fn rewrite_binary_error_includes_formula_and_rewrite_details() {
        let rules = vec![RewriteRule {
            source: "/opt/homebrew/Cellar/glow/2.1.0".to_string(),
            destination: "/opt/homebrew/Cellar/glow/2.1.0-shadow".to_string(),
        }];
        let mut bytes =
            b"prefix\0OPENSSLDIR: \"/opt/homebrew/Cellar/glow/2.1.0/share/mime/globs2\"\0".to_vec();
        let error = rewrite_binary(
            &mut bytes,
            Path::new("/tmp/glow"),
            "glow",
            &rules,
            BinaryRewriteMode::Slash,
        )
        .unwrap_err();
        assert!(error.contains("formula glow"));
        assert!(error.contains("binary rewrite in /tmp/glow"));
        assert!(error.contains(
            "rewrote /opt/homebrew/Cellar/glow/2.1.0/share/mime/globs2 -> /opt/homebrew/Cellar/glow/2.1.0-shadow/share/mime/globs2"
        ));
        assert!(error.contains("original segment:"));
        assert!(error.contains("rewritten segment:"));
    }

    #[test]
    fn rewrite_binary_length_error_mentions_embedded_homebrew_path() {
        let rules = vec![RewriteRule {
            source: "/opt/homebrew/etc/openssl@3/cert.pem".to_string(),
            destination: "/opt/python@3.12/share/ca-certificates/cacert.pem".to_string(),
        }];
        let mut bytes = b"prefix\0/opt/homebrew/etc/openssl@3/cert.pem\0".to_vec();
        let error = rewrite_binary(
            &mut bytes,
            Path::new("/tmp/libcrypto.3.dylib"),
            "openssl@3",
            &rules,
            BinaryRewriteMode::Slash,
        )
        .unwrap_err();
        assert!(error.contains("matched embedded Homebrew path"));
        assert!(error.contains("/opt/homebrew/etc/openssl@3/cert.pem"));
        assert!(error.contains("/opt/python@3.12/share/ca-certificates/cacert.pem"));
    }

    #[test]
    fn relocatable_reference_detection_ignores_usr_local_paths() {
        let rules = vec![RewriteRule {
            source: "/opt/homebrew/Cellar/glow/2.1.1".to_string(),
            destination: "/tmp/x/glow".to_string(),
        }];
        assert!(!contains_relocatable_homebrew_reference_text(
            "MIME database at /usr/local/share/mime/globs2",
            &rules
        ));
        assert!(!contains_relocatable_homebrew_reference_bytes(
            b"MIME database at /usr/local/share/mime/globs2",
            &rules
        ));
    }

    #[test]
    fn build_rewrite_rules_only_match_opt_homebrew_sources() {
        let plan = fixed_i_plan("glow", "glow");
        let installs = vec![InstalledFormula {
            spec: FormulaSpec {
                name: "glow".to_string(),
                bottle_sha256: "sha256".to_string(),
                bottle_url: "https://example.invalid/glow.tar.gz".to_string(),
            },
            keg_dir_name: "2.1.1".to_string(),
            archive_path: PathBuf::from("/tmp/glow.tar.gz"),
        }];
        let rules = build_rewrite_rules(&plan, &installs);
        assert!(rules.iter().any(|rule| {
            rule.source == "/opt/homebrew/Cellar/glow/2.1.1" && rule.destination == "/opt/glow"
        }));
        assert!(rules.iter().any(|rule| {
            rule.source == "/opt/homebrew/opt/glow" && rule.destination == "/opt/glow"
        }));
        assert!(!rules.iter().any(|rule| rule.source.contains("/usr/local")));
        assert!(
            !rules
                .iter()
                .any(|rule| rule.source.contains("/home/linuxbrew/.linuxbrew"))
        );
        assert!(rules.iter().any(|rule| {
            rule.source == HOMEBREW_PREFIX_PLACEHOLDER && rule.destination == "/opt/glow"
        }));
    }

    #[test]
    fn build_rewrite_rules_expands_perl_and_repository_placeholders() {
        let plan = fixed_i_plan("ack", "ack");
        let rules = build_rewrite_rules(&plan, &[]);
        assert!(rules.iter().any(|rule| {
            rule.source == HOMEBREW_REPOSITORY_PLACEHOLDER && rule.destination == "/opt/ack"
        }));
        assert!(rules.iter().any(|rule| {
            rule.source == HOMEBREW_LIBRARY_PLACEHOLDER && rule.destination == "/opt/ack/Library"
        }));
        assert!(rules.iter().any(|rule| {
            rule.source == HOMEBREW_PERL_PLACEHOLDER
                && rule.destination.starts_with("/usr/bin/perl")
        }));
    }

    #[test]
    fn perl_placeholder_prefers_staged_perl_dependency() {
        let plan = fixed_i_plan("ack", "ack");
        let installs = vec![InstalledFormula {
            spec: FormulaSpec {
                name: "perl".to_string(),
                bottle_sha256: "sha256".to_string(),
                bottle_url: "https://example.invalid/perl.tar.gz".to_string(),
            },
            keg_dir_name: "5.40.2".to_string(),
            archive_path: PathBuf::from("/tmp/perl.tar.gz"),
        }];

        assert_eq!(
            perl_placeholder_target(&plan, &installs),
            "/opt/ack/bin/perl"
        );
    }

    #[test]
    fn java_placeholder_uses_staged_openjdk_layout() {
        let plan = fixed_i_plan("scala", "scala");
        let installs = vec![InstalledFormula {
            spec: FormulaSpec {
                name: "openjdk@21".to_string(),
                bottle_sha256: "sha256".to_string(),
                bottle_url: "https://example.invalid/openjdk.tar.gz".to_string(),
            },
            keg_dir_name: "21.0.8".to_string(),
            archive_path: PathBuf::from("/tmp/openjdk.tar.gz"),
        }];

        let target = java_placeholder_target(&plan, &installs).unwrap();
        if env::consts::OS == "macos" {
            assert_eq!(
                target,
                "/opt/scala/libexec/openjdk.jdk/Contents/Home".to_string()
            );
        } else {
            assert_eq!(target, "/opt/scala/libexec".to_string());
        }
        assert_eq!(java_placeholder_target(&plan, &[]), None);
    }

    #[test]
    fn rewrite_text_rewrites_homebrew_perl_shebang() {
        let plan = fixed_i_plan("ack", "ack");
        let rules = build_rewrite_rules(&plan, &[]);
        let rewritten = rewrite_text(
            "#!@@HOMEBREW_PERL@@\n",
            Path::new("/tmp/ack"),
            "ack",
            &rules,
        )
        .unwrap();
        assert!(rewritten.starts_with("#!/usr/bin/perl"));
    }

    #[test]
    fn rewrite_text_rewrites_raw_homebrew_opt_dependency_paths() {
        let plan = fixed_i_plan("direnv", "direnv");
        let installs = vec![InstalledFormula {
            spec: FormulaSpec {
                name: "bash".to_string(),
                bottle_sha256: "sha256".to_string(),
                bottle_url: "https://example.invalid/bash.tar.gz".to_string(),
            },
            keg_dir_name: "5.3.9".to_string(),
            archive_path: PathBuf::from("/tmp/bash.tar.gz"),
        }];
        let rules = build_rewrite_rules(&plan, &installs);
        let rewritten = rewrite_text(
            "/opt/homebrew/opt/bash/bin/bash\n",
            Path::new("/tmp/direnv"),
            "direnv",
            &rules,
        )
        .unwrap();
        assert_eq!(rewritten, "/opt/direnv/bin/bash\n");
    }

    #[test]
    fn rewrite_text_rewrites_generic_prefix_placeholder_paths() {
        let plan = fixed_i_plan("ripgrep", "ripgrep");
        let rules = build_rewrite_rules(&plan, &[]);
        let rewritten = rewrite_text(
            "@@HOMEBREW_PREFIX@@/share/ripgrep/help.txt\n",
            Path::new("/tmp/rg"),
            "ripgrep",
            &rules,
        )
        .unwrap();
        assert_eq!(rewritten, "/opt/ripgrep/share/ripgrep/help.txt\n");
    }

    #[test]
    fn rewrite_text_rewrites_versionless_cellar_placeholder_paths() {
        let plan = fixed_i_plan("python@3.12", "python@3.12");
        let installs = vec![InstalledFormula {
            spec: FormulaSpec {
                name: "python@3.12".to_string(),
                bottle_sha256: "sha256".to_string(),
                bottle_url: "https://example.invalid/python@3.12.tar.gz".to_string(),
            },
            keg_dir_name: "3.12.13".to_string(),
            archive_path: PathBuf::from("/tmp/python@3.12.tar.gz"),
        }];
        let rules = build_rewrite_rules(&plan, &installs);
        let rewritten = rewrite_text(
            "if os.path.realpath(sys.executable).startswith('@@HOMEBREW_CELLAR@@/python@3.12'):\n\
long_prefix = re.compile(r'@@HOMEBREW_CELLAR@@/python@3.12/[0-9\\._abrc]+')\n",
            Path::new("/tmp/sitecustomize.py"),
            "python@3.12",
            &rules,
        )
        .unwrap();
        assert_eq!(
            rewritten,
            "if os.path.realpath(sys.executable).startswith('/opt/python@3.12'):\n\
long_prefix = re.compile(r'/opt/python@3.12/[0-9\\._abrc]+')\n"
        );
    }

    #[test]
    fn relocate_file_skips_documentation_with_homebrew_placeholders() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("libssh2").join("1.11.1_1");
        let path = root.join("NEWS");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            &path,
            "Changelog for the libssh2 project. Generated with git2news.pl\n\
@@HOMEBREW_PREFIX@@/include -> @@HOMEBREW_CELLAR@@/autoconf/2.72/bin/autoconf\n",
        )
        .unwrap();

        let rules = vec![
            RewriteRule {
                source: "@@HOMEBREW_PREFIX@@".to_string(),
                destination: "/opt/bat".to_string(),
            },
            RewriteRule {
                source: "@@HOMEBREW_CELLAR@@/autoconf/2.72".to_string(),
                destination: "/opt/bat".to_string(),
            },
        ];

        relocate_file(&path, &root, Path::new("/opt/bat"), "libssh2", &rules, None).unwrap();

        let unchanged = fs::read_to_string(&path).unwrap();
        assert!(unchanged.contains("@@HOMEBREW_PREFIX@@/include"));
        assert!(unchanged.contains("@@HOMEBREW_CELLAR@@/autoconf/2.72/bin/autoconf"));
    }

    #[test]
    fn relocate_file_rewrites_non_utf8_binary_paths() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("ripgrep").join("14.1.1");
        let path = root.join("bin/rg");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            b"\xff/opt/homebrew/opt/pcre2/lib/libpcre2-8.dylib\0tail",
        )
        .unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o444);
        fs::set_permissions(&path, permissions).unwrap();
        let rules = vec![RewriteRule {
            source: "/opt/homebrew/opt/pcre2".to_string(),
            destination: "/opt/rg".to_string(),
        }];

        relocate_file(&path, &root, Path::new("/opt/rg"), "ripgrep", &rules, None).unwrap();

        let rewritten = fs::read(&path).unwrap();
        assert!(rewritten.starts_with(b"\xff/opt/"));
        assert!(
            !rewritten
                .windows(b"/opt/homebrew".len())
                .any(|window| window == b"/opt/homebrew")
        );
        assert!(
            rewritten
                .windows(b"lib/libpcre2-8.dylib".len())
                .any(|window| window == b"lib/libpcre2-8.dylib")
        );
        assert!(fs::metadata(&path).unwrap().permissions().mode() & 0o200 != 0);
    }

    #[test]
    fn relocate_file_rewrites_utf8_text_paths_and_skips_static_archives() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("ripgrep").join("14.1.1");
        let path = root.join("lib/pkgconfig/libpcre2.pc");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "prefix=/opt/homebrew/opt/pcre2\n").unwrap();
        let archive = root.join("lib/libpcre2.a");
        fs::write(&archive, b"/opt/homebrew/opt/pcre2").unwrap();
        let rules = vec![RewriteRule {
            source: "/opt/homebrew/opt/pcre2".to_string(),
            destination: "/opt/rg".to_string(),
        }];

        relocate_file(&path, &root, Path::new("/opt/rg"), "ripgrep", &rules, None).unwrap();
        relocate_file(
            &archive,
            &root,
            Path::new("/opt/rg"),
            "ripgrep",
            &rules,
            None,
        )
        .unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "prefix=/opt/rg\n");
        assert_eq!(
            fs::read_to_string(&archive).unwrap(),
            "/opt/homebrew/opt/pcre2"
        );
    }

    #[test]
    fn documentation_detection_covers_share_doc_and_changelog_names() {
        let root = Path::new("/tmp/keg");
        assert!(is_documentation_text_path(
            Path::new("/tmp/keg/share/doc/foo/config.example"),
            root
        ));
        assert!(is_documentation_text_path(
            Path::new("/tmp/keg/CHANGELOG.md"),
            root
        ));
        assert!(!is_documentation_text_path(
            Path::new("/tmp/keg/lib/pkgconfig/foo.pc"),
            root
        ));
    }

    #[test]
    fn relocate_symlink_rewrites_cross_keg_relative_target_for_i_installs() {
        let temp = TempDir::new().unwrap();
        let keg_root = temp.path().join("aws").join("2.0.0");
        let link = keg_root.join("libexec/bin/python3.13");
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        symlink("../../../../../opt/python@3.13/bin/python3.13", &link).unwrap();

        let plan = InstallPlan::for_i("aws".to_string(), "aws".to_string());
        let installs = vec![InstalledFormula {
            spec: FormulaSpec {
                name: "python@3.13".to_string(),
                bottle_sha256: "sha256".to_string(),
                bottle_url: "https://example.invalid/python@3.13.tar.gz".to_string(),
            },
            keg_dir_name: "3.13.2".to_string(),
            archive_path: temp.path().join("python@3.13.tar.gz"),
        }];
        let rules = build_rewrite_rules(&plan, &installs);

        relocate_symlink(&link, &keg_root, &plan.install_root, &rules).unwrap();

        assert_eq!(
            fs::read_link(&link).unwrap(),
            PathBuf::from("../../bin/python3.13")
        );
    }

    #[test]
    fn relocate_tree_rewrites_isotope_archive_cross_keg_relative_targets() {
        let temp = TempDir::new().unwrap();
        let isotope_root = temp.path().join("aws-cli");
        let link = isotope_root.join("libexec/bin/python3.14");
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        symlink("../../../../../opt/python@3.14/bin/python3.14", &link).unwrap();

        let plan = InstallPlan::for_i_isotope("isotope:aws-cli".to_string(), "aws-cli");
        let installs = vec![InstalledFormula {
            spec: FormulaSpec {
                name: "python@3.14".to_string(),
                bottle_sha256: "sha256".to_string(),
                bottle_url: "https://example.invalid/python@3.14.tar.gz".to_string(),
            },
            keg_dir_name: "3.14.0".to_string(),
            archive_path: temp.path().join("python@3.14.tar.gz"),
        }];
        let rules = build_rewrite_rules(&plan, &installs);

        relocate_tree(
            &isotope_root,
            &plan.stable_root,
            &plan.package_name,
            &rules,
            None,
        )
        .unwrap();

        assert_eq!(
            fs::read_link(&link).unwrap(),
            PathBuf::from("../../bin/python3.14")
        );
    }

    #[test]
    fn relocate_symlink_keeps_relative_targets_within_the_same_keg() {
        let temp = TempDir::new().unwrap();
        let keg_root = temp.path().join("aws").join("2.0.0");
        let link = keg_root.join("libexec/bin/aws");
        fs::create_dir_all(keg_root.join("bin")).unwrap();
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        symlink("../../bin/aws", &link).unwrap();

        let plan = InstallPlan::for_i("aws".to_string(), "aws".to_string());

        relocate_symlink(&link, &keg_root, &plan.install_root, &[]).unwrap();

        assert_eq!(
            fs::read_link(&link).unwrap(),
            PathBuf::from("../../bin/aws")
        );
    }

    #[test]
    fn rewrite_binary_ignores_unmatched_opt_homebrew_include_paths() {
        let rules = vec![RewriteRule {
            source: "/opt/homebrew/Cellar/abseil/20260107.1".to_string(),
            destination: "/tmp/x/abseil".to_string(),
        }];
        let mut bytes = b"prefix\0/opt/homebrew/include/gtest/gtest-matchers.h\0".to_vec();
        let changed = rewrite_binary(
            &mut bytes,
            Path::new("/tmp/abseil"),
            "abseil",
            &rules,
            BinaryRewriteMode::Slash,
        )
        .unwrap();
        assert!(!changed);
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "prefix\0/opt/homebrew/include/gtest/gtest-matchers.h\0"
        );
    }

    #[test]
    fn pkg_allow_value_contains_matches_colon_separated_flags() {
        // Keep parsing tolerant so additional allow flags can coexist.
        assert!(pkg_allow_value_contains(
            "other:relocation-failures unsupported-formulas",
            "relocation-failures"
        ));
        assert!(pkg_allow_value_contains(
            "other:relocation-failures unsupported-formulas",
            "unsupported-formulas"
        ));
    }

    #[test]
    fn configure_debug_install_environment_adds_debug_allow_flags() {
        let _env_lock = test_env_lock().lock().unwrap();
        let _env = TestEnvGuard::set(&[("PKG_ALLOW", "other-flag")]);

        configure_debug_install_environment();

        let value = env::var("PKG_ALLOW").unwrap();
        if cfg!(debug_assertions) {
            assert!(pkg_allow_value_contains(&value, "other-flag"));
            assert!(pkg_allow_value_contains(&value, "unsupported-formulas"));
            assert!(pkg_allow_value_contains(&value, "relocation-failures"));
        } else {
            assert_eq!(value, "other-flag");
        }
    }

    #[test]
    fn configure_debug_install_environment_preserves_existing_debug_flags() {
        let _env_lock = test_env_lock().lock().unwrap();
        let _env = TestEnvGuard::set(&[("PKG_ALLOW", "unsupported-formulas:relocation-failures")]);

        configure_debug_install_environment();

        let value = env::var("PKG_ALLOW").unwrap();
        assert_eq!(value, "unsupported-formulas:relocation-failures");
    }

    #[test]
    fn pkg_allow_runtime_override_stays_debug_only() {
        let _env_lock = test_env_lock().lock().unwrap();
        let _env = TestEnvGuard::set(&[("PKG_ALLOW", "relocation-failures")]);

        assert_eq!(
            pkg_allow_contains("relocation-failures"),
            cfg!(debug_assertions)
        );
    }

    #[test]
    fn handle_allowed_failure_writes_to_stderr_when_allowed() {
        let mut stderr = Vec::new();
        handle_allowed_failure("relocation failed".to_string(), true, &mut stderr).unwrap();
        assert_eq!(String::from_utf8(stderr).unwrap(), "relocation failed\n");
    }

    #[test]
    fn relocate_tree_with_options_allows_failures_and_reports_them() {
        let temp = TempDir::new().unwrap();
        let keg_root = temp.path().join("foo").join("1.0.0");
        let path = keg_root.join("share/foo/config.txt");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "/opt/homebrew/Cellar/foo/1.0.0/share/foo/config\n").unwrap();

        let rules = vec![RewriteRule {
            source: "/opt/homebrew/Cellar/foo/1.0.0".to_string(),
            destination: "/opt/homebrew/Cellar/foo/1.0.0-shadow".to_string(),
        }];
        let mut stderr = Vec::new();

        relocate_tree_with_options(
            &keg_root,
            temp.path(),
            "foo",
            &rules,
            None,
            true,
            &mut stderr,
        )
        .unwrap();

        let stderr = String::from_utf8(stderr).unwrap();
        assert!(stderr.contains("unsupported Homebrew path remains after text rewrite"));
        assert!(stderr.contains(path.to_string_lossy().as_ref()));
    }

    #[test]
    fn macos_release_name_maps_supported_versions() {
        assert_eq!(macos_release_name(14), Some("sonoma"));
        assert_eq!(macos_release_name(15), Some("sequoia"));
        assert_eq!(macos_release_name(26), Some("tahoe"));
    }

    #[test]
    fn ghcr_repo_from_blob_url_extracts_repository() {
        let repo =
            ghcr_repo_from_blob_url("https://ghcr.io/v2/homebrew/core/zopfli/blobs/sha256:abc123");
        assert_eq!(repo, Some("homebrew/core/zopfli"));
    }

    #[test]
    fn unsupported_install_hooks_allow_openssl3_post_install() {
        let info = formula_info(true);
        assert!(!formula_skips_unknown_post_install(
            "openssl@3",
            &info,
            false,
        ));
    }

    #[test]
    fn unsupported_install_hooks_allow_ca_certificates_post_install() {
        let info = formula_info(true);
        assert!(!formula_skips_unknown_post_install(
            "ca-certificates",
            &info,
            false,
        ));
    }

    #[test]
    fn unsupported_install_hooks_allow_service_formulae() {
        let info: FormulaInfo = serde_json::from_value(serde_json::json!({
            "versions": {
                "stable": "1.0.0"
            },
            "revision": 0,
            "dependencies": [],
            "bottle": {
                "stable": {
                    "files": {}
                }
            },
            "disabled": false,
            "service": {
                "run": ["bin/exampled"]
            },
            "post_install_defined": false
        }))
        .unwrap();
        assert!(!formula_skips_unknown_post_install("example", &info, false));
    }

    #[test]
    fn unsupported_install_hooks_warn_for_other_post_install_formulae() {
        let info = formula_info(true);
        assert!(formula_skips_unknown_post_install("gettext", &info, false));

        let mut stderr = Vec::new();
        warn_skipped_post_install("gettext", &mut stderr);
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "warning: skipping Homebrew post_install for gettext; install may be incomplete\n"
        );
    }

    #[test]
    fn unsupported_install_hooks_allow_python_formula_when_enabled() {
        let info = formula_info(true);
        assert!(formula_skips_unknown_post_install(
            "python@3.12",
            &info,
            false,
        ));
        assert!(!formula_skips_unknown_post_install(
            "python@3.12",
            &info,
            true,
        ));
    }

    #[test]
    fn prepare_vendor_root_area_clears_existing_contents() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "codex".to_string(),
            root_formula: "codex".to_string(),
            stable_root: temp.path().join("stable"),
            install_root: temp.path().join("install"),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(plan.install_root.join("pkgs/node")).unwrap();
        fs::create_dir_all(plan.install_root.join("bin")).unwrap();
        fs::create_dir_all(plan.install_root.join(".pkg")).unwrap();
        fs::write(plan.install_root.join("bin/codex"), b"old").unwrap();
        fs::write(plan.install_root.join(STUB_MANIFEST), b"old").unwrap();

        prepare_vendor_root_area(&plan).unwrap();

        assert!(!plan.install_root.join("pkgs").exists());
        assert!(!plan.install_root.join("bin/codex").exists());
        assert!(!plan.install_root.join(STUB_MANIFEST).exists());
    }

    #[test]
    fn partition_dependency_names_prefers_vendor_packages() {
        let (formulas, vendors) = partition_dependency_names(&["bun", "ripgrep"]).unwrap();

        assert_eq!(formulas, vec!["ripgrep".to_string()]);
        assert_eq!(vendors, vec!["bun".to_string()]);
    }

    #[test]
    fn partition_dependency_names_handles_vendor_packages_without_formula_dependencies() {
        let (formulas, vendors) = partition_dependency_names(&["bun"]).unwrap();

        assert!(formulas.is_empty());
        assert_eq!(vendors, vec!["bun".to_string()]);
    }

    #[test]
    fn npm_package_homebrew_dependencies_support_exact_and_leaf_matches() {
        assert_eq!(
            npm_package_homebrew_dependencies("@tobilu/qmd"),
            vec!["sqlite".to_string()]
        );
        assert_eq!(
            npm_package_homebrew_dependencies("openclaw"),
            vec!["sqlite".to_string()]
        );
    }

    #[test]
    fn pip_package_install_data_supports_dependencies_and_python_formula() {
        assert_eq!(
            pip_package_homebrew_dependencies("Psycopg2"),
            vec!["libpq".to_string()]
        );
        assert_eq!(pip_package_python_formula("psycopg2"), "python@3.12");
        assert_eq!(pip_package_python_formula("unknown"), "python");
    }

    #[test]
    fn append_vendor_npm_homebrew_dependencies_uses_vendor_install_strategy() {
        let qmd = VendorInstall {
            package: vendor::VendorPackage {
                name: "qmd",
                dependencies: &[],
                executables: &["qmd"],
                version: fake_vendor_version,
                download_url: None,
                install: fake_qmd_install_strategy,
            },
            version: Version::parse("1.2.3").unwrap(),
        };
        let mut formulas = Vec::new();

        append_vendor_npm_homebrew_dependencies(&mut formulas, &[qmd]);

        assert_eq!(formulas, vec!["sqlite".to_string()]);
    }

    #[test]
    fn append_pip_package_homebrew_dependencies_uses_embedded_data() {
        let mut formulas = vec!["python@3.12".to_string()];

        append_pip_package_homebrew_dependencies(&mut formulas, "psycopg2");

        assert_eq!(
            formulas,
            vec!["python@3.12".to_string(), "libpq".to_string()]
        );
    }

    #[test]
    fn vendor_dependency_is_current_requires_matching_receipt_and_executable() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "npm-openclaw".to_string(),
            root_formula: "npm-openclaw".to_string(),
            stable_root: temp.path().join("stable"),
            install_root: temp.path().join("install"),
            tmp_root: temp.path().join("tmp"),
        };
        let install = fake_vendor_install("bun", &["bun"], "1.2.3");

        fs::create_dir_all(plan.install_root.join("bin")).unwrap();
        write_package_receipt(
            &plan.receipt_path("bun"),
            &PackageReceipt {
                package_name: "bun".to_string(),
                version: "1.2.3".to_string(),
                source: PackageReceiptSource::Vendor {
                    vendor_name: "bun".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();

        assert!(!vendor_dependency_is_current(&plan, &install).unwrap());

        write_executable(&plan.install_root.join("bin/bun"));

        assert!(vendor_dependency_is_current(&plan, &install).unwrap());
        assert!(vendor_dependencies_are_current(&plan, std::slice::from_ref(&install)).unwrap());

        let missing = fake_vendor_install("codex", &["codex"], "0.2.0");
        assert!(!vendor_dependencies_are_current(&plan, &[missing]).unwrap());
        assert!(vendor_dependencies_are_current(&plan, &[]).unwrap());
        assert!(
            install_vendor_copy_tree(&plan, &install, "pkg", None)
                .unwrap_err()
                .contains("has no download URL")
        );
        assert!(
            install_vendor_copy_file(
                &plan,
                &[],
                &install,
                "pkg/bin/codex",
                "bin",
                None,
                0o755,
                &[],
                None
            )
            .unwrap_err()
            .contains("has no download URL")
        );
    }

    #[test]
    fn npm_install_sandbox_profile_denies_users_and_library() {
        let profile = npm_install_sandbox_profile(Path::new("/opt/.tmp/pkg"));

        assert!(profile.contains(r#"(deny file-read* (subpath "/Users"))"#));
        assert!(profile.contains(r#"(deny file-write* (subpath "/Users"))"#));
        assert!(profile.contains(r#"(deny file-read* (subpath "/Library"))"#));
        assert!(profile.contains(r#"(deny file-write* (subpath "/Library"))"#));
        assert!(profile.contains(r#"(allow file-read* (subpath "/opt/.tmp/pkg"))"#));
        assert!(profile.contains(r#"(allow file-write* (subpath "/opt/.tmp/pkg"))"#));
    }

    #[test]
    fn render_npm_probe_error_reports_exit_codes_and_signals() {
        use std::os::unix::process::ExitStatusExt;

        let exit_error = render_npm_probe_error(
            "openclaw",
            NpmProbeError {
                status: ExitStatus::from_raw(2 << 8),
                lines: vec!["npm ERR! denied".to_string()],
            },
        );
        assert!(exit_error.contains("exit code 2"));
        assert!(exit_error.contains("npm ERR! denied"));

        let signal_error = render_npm_probe_error(
            "openclaw",
            NpmProbeError {
                status: ExitStatus::from_raw(9),
                lines: Vec::new(),
            },
        );
        assert!(signal_error.contains("terminated by signal"));
    }

    #[test]
    fn build_sandboxed_npm_install_command_uses_isolated_env() {
        let _lock = test_env_lock().lock().unwrap();
        let _env = TestEnvGuard::set(&[("CODEX_CI", "1")]);
        let temp = TempDir::new().unwrap();
        let sandbox_root = TempDir::new_in(temp.path()).unwrap();
        let install_root = temp.path().join("install");
        let tmp_root = temp.path().join("tmp");
        fs::create_dir_all(&tmp_root).unwrap();

        let command = build_sandboxed_npm_install_command(
            "/usr/bin/sandbox-exec",
            "/opt/pkg/bin/npm",
            "https://registry.npmjs.org/openclaw/-/openclaw-1.2.3.tgz",
            &install_root,
            &tmp_root,
            &sandbox_root,
            OsString::from("/opt/pkg/bin"),
            false,
        )
        .unwrap();

        let args: Vec<_> = command.get_args().collect();
        assert!(should_bypass_npm_install_sandbox());
        assert_eq!(command.get_program(), OsStr::new("/opt/pkg/bin/npm"));
        assert_eq!(args[0], OsStr::new("install"));
        assert_eq!(args[1], OsStr::new("-g"));
        assert_eq!(args[2], OsStr::new("--prefix"));
        assert_eq!(args[3], install_root.as_os_str());
        assert_eq!(
            args[4],
            OsStr::new("https://registry.npmjs.org/openclaw/-/openclaw-1.2.3.tgz")
        );
        assert_eq!(
            *args.last().unwrap(),
            OsStr::new("https://registry.npmjs.org/openclaw/-/openclaw-1.2.3.tgz")
        );
        assert_eq!(command.get_current_dir().unwrap(), sandbox_root.path());

        let envs: HashMap<_, _> = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_owned(),
                    value.map(|value| value.to_owned()).unwrap_or_default(),
                )
            })
            .collect();
        assert_eq!(
            envs.get(OsStr::new("PATH")).unwrap(),
            &OsString::from("/opt/pkg/bin")
        );
        assert_eq!(
            envs.get(OsStr::new("TMPDIR")).unwrap(),
            tmp_root.as_os_str()
        );
        assert_eq!(
            envs.get(OsStr::new("HOME")).unwrap(),
            sandbox_root.path().join("home").as_os_str()
        );
        assert_eq!(
            envs.get(OsStr::new("XDG_CONFIG_HOME")).unwrap(),
            sandbox_root.path().join("xdg-config").as_os_str()
        );
        assert_eq!(
            envs.get(OsStr::new("XDG_CACHE_HOME")).unwrap(),
            sandbox_root.path().join("xdg-cache").as_os_str()
        );
        assert_eq!(
            envs.get(OsStr::new("NPM_CONFIG_CACHE")).unwrap(),
            sandbox_root.path().join("npm-cache").as_os_str()
        );
        assert_eq!(
            envs.get(OsStr::new("NPM_CONFIG_USERCONFIG")).unwrap(),
            sandbox_root.path().join("npmrc").as_os_str()
        );
        assert_eq!(
            envs.get(OsStr::new("NPM_CONFIG_CAFILE")).unwrap(),
            OsStr::new("/opt/pkg/ssl/cert.pem")
        );
        assert_eq!(
            envs.get(OsStr::new("NODE_EXTRA_CA_CERTS")).unwrap(),
            OsStr::new("/opt/pkg/ssl/cert.pem")
        );

        let profile_path = sandbox_root.path().join("sandbox.sb");
        assert!(profile_path.is_file());
        assert!(sandbox_root.path().join("npmrc").is_file());
        assert_eq!(
            fs::read_to_string(sandbox_root.path().join("npmrc")).unwrap(),
            ""
        );
    }

    #[test]
    fn build_sandboxed_npm_install_command_uses_sandbox_when_codex_bypass_is_absent() {
        let _lock = test_env_lock().lock().unwrap();
        let _env = TestEnvGuard::unset(&["CODEX_CI"]);
        let temp = TempDir::new().unwrap();
        let sandbox_root = TempDir::new_in(temp.path()).unwrap();
        let install_root = temp.path().join("install");
        let tmp_root = temp.path().join("tmp");
        fs::create_dir_all(&tmp_root).unwrap();

        let command = build_sandboxed_npm_install_command(
            "/usr/bin/sandbox-exec",
            "/opt/pkg/bin/npm",
            "coverage-npm",
            &install_root,
            &tmp_root,
            &sandbox_root,
            OsString::from("/opt/pkg/bin"),
            true,
        )
        .unwrap();

        let args = command.get_args().collect::<Vec<_>>();
        assert_eq!(command.get_program(), OsStr::new("/usr/bin/sandbox-exec"));
        assert_eq!(args[0], OsStr::new("-f"));
        assert_eq!(args[2], OsStr::new("/opt/pkg/bin/npm"));
        assert!(args.contains(&OsStr::new("--dry-run")));
        assert_eq!(*args.last().unwrap(), OsStr::new("coverage-npm"));
    }

    #[test]
    fn normalize_bundled_npm_extension_dependencies_links_missing_root_packages() {
        let temp = TempDir::new().unwrap();
        let install_root = temp.path().join("opt/npm/openclaw");
        let package_root = install_root.join("lib/node_modules/openclaw");
        let nested_carbon = package_root.join("dist/extensions/discord/node_modules/@buape/carbon");
        fs::create_dir_all(&nested_carbon).unwrap();

        normalize_bundled_npm_extension_dependencies(&install_root).unwrap();

        let root_carbon = package_root.join("node_modules/@buape/carbon");
        let metadata = fs::symlink_metadata(&root_carbon).unwrap();
        assert!(metadata.file_type().is_symlink());
        let target = fs::read_link(&root_carbon).unwrap();
        assert!(target.is_relative());
        assert_eq!(
            fs::canonicalize(root_carbon.parent().unwrap().join(&target)).unwrap(),
            fs::canonicalize(&nested_carbon).unwrap()
        );
    }

    #[test]
    fn normalize_bundled_npm_extension_dependencies_preserves_existing_root_packages() {
        let temp = TempDir::new().unwrap();
        let install_root = temp.path().join("opt/npm/openclaw");
        let package_root = install_root.join("lib/node_modules/openclaw");
        let nested_carbon = package_root.join("dist/extensions/discord/node_modules/@buape/carbon");
        let root_carbon = package_root.join("node_modules/@buape/carbon");
        fs::create_dir_all(&nested_carbon).unwrap();
        fs::create_dir_all(&root_carbon).unwrap();
        fs::write(root_carbon.join("package.json"), "{}").unwrap();

        normalize_bundled_npm_extension_dependencies(&install_root).unwrap();

        let metadata = fs::symlink_metadata(&root_carbon).unwrap();
        assert!(metadata.is_dir());
        assert!(!metadata.file_type().is_symlink());
    }

    #[test]
    fn normalize_bundled_npm_extension_dependencies_finds_scoped_package_roots() {
        let temp = TempDir::new().unwrap();
        let install_root = temp.path().join("opt/npm/widget");
        let package_root = install_root.join("lib/node_modules/@scope/widget");
        let nested_carbon = package_root.join("dist/extensions/discord/node_modules/@buape/carbon");
        fs::create_dir_all(&nested_carbon).unwrap();

        normalize_bundled_npm_extension_dependencies(&install_root).unwrap();

        let root_carbon = package_root.join("node_modules/@buape/carbon");
        let metadata = fs::symlink_metadata(&root_carbon).unwrap();
        assert!(metadata.file_type().is_symlink());
        let target = fs::read_link(&root_carbon).unwrap();
        assert!(target.is_relative());
        assert_eq!(
            fs::canonicalize(root_carbon.parent().unwrap().join(&target)).unwrap(),
            fs::canonicalize(&nested_carbon).unwrap()
        );
    }

    #[test]
    fn normalize_bundled_npm_extension_dependencies_finds_nested_dist_node_modules() {
        let temp = TempDir::new().unwrap();
        let install_root = temp.path().join("opt/npm/openclaw");
        let package_root = install_root.join("lib/node_modules/openclaw");
        let nested_carbon = package_root.join("dist/ui/runtime/node_modules/@buape/carbon");
        fs::create_dir_all(&nested_carbon).unwrap();

        normalize_bundled_npm_extension_dependencies(&install_root).unwrap();

        let root_carbon = package_root.join("node_modules/@buape/carbon");
        let metadata = fs::symlink_metadata(&root_carbon).unwrap();
        assert!(metadata.file_type().is_symlink());
        let target = fs::read_link(&root_carbon).unwrap();
        assert!(target.is_relative());
        assert_eq!(
            fs::canonicalize(root_carbon.parent().unwrap().join(&target)).unwrap(),
            fs::canonicalize(&nested_carbon).unwrap()
        );
    }

    #[test]
    fn build_pip_commands_use_isolated_env() {
        let temp = TempDir::new().unwrap();
        let sandbox_root = temp.path().join("sandbox");
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "pip:psycopg2".to_string(),
            root_formula: "pip:psycopg2".to_string(),
            stable_root: temp.path().join("opt/pip/psycopg2"),
            install_root: temp.path().join("opt/pip/psycopg2"),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(&plan.tmp_root).unwrap();

        let venv_command = build_pip_venv_command(
            "/opt/pip/psycopg2/bin/python3",
            &plan.install_root.join("venv"),
            &sandbox_root,
            &plan,
            &[],
        )
        .unwrap();
        assert_eq!(
            venv_command.get_program(),
            OsStr::new("/opt/pip/psycopg2/bin/python3")
        );
        let venv_args: Vec<_> = venv_command.get_args().collect();
        assert_eq!(
            venv_args,
            vec![
                OsStr::new("-m"),
                OsStr::new("venv"),
                OsStr::new("--copies"),
                plan.install_root.join("venv").as_os_str(),
            ]
        );

        let pip_command = build_pip_install_command(
            &plan.install_root.join("venv/bin/pip"),
            "psycopg2",
            "2.9.10",
            &sandbox_root,
            &plan,
            &[],
        )
        .unwrap();
        assert_eq!(
            pip_command.get_program(),
            plan.install_root.join("venv/bin/pip").as_os_str()
        );
        let pip_args: Vec<_> = pip_command.get_args().collect();
        assert_eq!(
            pip_args,
            vec![
                OsStr::new("install"),
                OsStr::new("--disable-pip-version-check"),
                OsStr::new("--no-input"),
                OsStr::new("psycopg2==2.9.10"),
            ]
        );

        for command in [&venv_command, &pip_command] {
            let envs: HashMap<_, _> = command
                .get_envs()
                .map(|(key, value)| {
                    (
                        key.to_owned(),
                        value.map(|value| value.to_owned()).unwrap_or_default(),
                    )
                })
                .collect();
            assert_eq!(
                envs.get(OsStr::new("TMPDIR")).unwrap(),
                plan.tmp_root.as_os_str()
            );
            assert_eq!(
                envs.get(OsStr::new("HOME")).unwrap(),
                sandbox_root.join("home").as_os_str()
            );
            assert_eq!(
                envs.get(OsStr::new("XDG_CACHE_HOME")).unwrap(),
                sandbox_root.join("xdg-cache").as_os_str()
            );
            assert_eq!(
                envs.get(OsStr::new("PIP_CACHE_DIR")).unwrap(),
                sandbox_root.join("pip-cache").as_os_str()
            );
            assert_eq!(
                envs.get(OsStr::new("PYTHONNOUSERSITE")).unwrap(),
                OsStr::new("1")
            );
        }
    }

    #[test]
    fn pip_entrypoint_discovery_script_has_indented_function_body() {
        let script = pip_entrypoint_discovery_script();

        assert!(script.contains("def norm(value):\n    out = []\n"));
        assert!(script.contains("\nfor dist in md.distributions():\n"));
    }

    #[test]
    fn collect_declared_root_executables_finds_bin_and_sbin() {
        let temp = TempDir::new().unwrap();
        let bin_dir = temp.path().join("bin");
        let sbin_dir = temp.path().join("sbin");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&sbin_dir).unwrap();
        let foo = bin_dir.join("foo");
        let bar = sbin_dir.join("bar");
        fs::write(&foo, b"#!/bin/sh\n").unwrap();
        fs::write(&bar, b"#!/bin/sh\n").unwrap();
        let mut permissions = fs::metadata(&foo).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&foo, permissions.clone()).unwrap();
        fs::set_permissions(&bar, permissions).unwrap();

        let found = collect_declared_root_executables(temp.path(), ["foo", "bar"]).unwrap();
        assert_eq!(
            found,
            vec![("bar".to_string(), bar), ("foo".to_string(), foo)]
        );
    }

    #[test]
    fn filter_stub_executables_omits_excluded_names() {
        let executables = vec![
            ("bash".to_string(), PathBuf::from("/tmp/bin/bash")),
            ("bashbug".to_string(), PathBuf::from("/tmp/bin/bashbug")),
        ];
        let excluded = HashSet::from(["bashbug".to_string()]);

        assert_eq!(
            filter_stub_executables(executables, &excluded),
            vec![("bash".to_string(), PathBuf::from("/tmp/bin/bash"))]
        );
    }

    #[test]
    fn formula_stub_exclusions_load_bashbug() {
        assert_eq!(
            formula_stub_exclusions("bash"),
            HashSet::from(["bashbug".to_string()])
        );
    }

    #[test]
    fn formula_stub_exclusions_alias_ffmpeg_to_ffmpeg_full() {
        assert_eq!(
            formula_stub_exclusions("ffmpeg"),
            formula_stub_exclusions("ffmpeg-full")
        );
    }

    #[test]
    fn formula_stub_exclusions_cover_dead_python_tools() {
        let exclusions = formula_stub_exclusions("python@3.12");

        for name in [
            "2to3",
            "2to3-3.12",
            "idle3",
            "idle3.12",
            "pydoc3",
            "pydoc3.12",
            "python3-config",
            "python3.12-config",
            "wheel",
            "wheel3",
            "wheel3.12",
        ] {
            assert!(exclusions.contains(name), "missing exclusion for {name}");
        }

        assert!(!exclusions.contains("python3.12"));
        assert!(!exclusions.contains("pip3.12"));
    }

    #[test]
    fn imagemagick_full_only_stubs_magick() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "imagemagick-full".to_string(),
            root_formula: "imagemagick-full".to_string(),
            stable_root: temp.path().join("opt/imagemagick-full"),
            install_root: temp.path().join("opt/imagemagick-full"),
            tmp_root: temp.path().join("tmp"),
        };
        let current = vec![
            ("convert".to_string(), PathBuf::from("/tmp/bin/convert")),
            ("magick".to_string(), PathBuf::from("/tmp/bin/magick")),
            ("identify".to_string(), PathBuf::from("/tmp/bin/identify")),
        ];

        assert_eq!(
            imagemagick_stub_exclusions(&plan, &current),
            HashSet::from(["convert".to_string(), "identify".to_string()])
        );
    }

    #[test]
    fn imagemagick_v7_only_stubs_magick() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "imagemagick".to_string(),
            root_formula: "imagemagick".to_string(),
            stable_root: temp.path().join("opt/imagemagick"),
            install_root: temp.path().join("opt/imagemagick"),
            tmp_root: temp.path().join("tmp"),
        };
        write_package_receipt(
            &plan.root_receipt_path(),
            &PackageReceipt {
                package_name: "imagemagick".to_string(),
                version: "7.1.2_3".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "imagemagick".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        let current = vec![
            ("convert".to_string(), PathBuf::from("/tmp/bin/convert")),
            ("magick".to_string(), PathBuf::from("/tmp/bin/magick")),
            ("mogrify".to_string(), PathBuf::from("/tmp/bin/mogrify")),
        ];

        assert_eq!(
            imagemagick_stub_exclusions(&plan, &current),
            HashSet::from(["convert".to_string(), "mogrify".to_string()])
        );
    }

    #[test]
    fn imagemagick_v6_keeps_legacy_stubs() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "imagemagick".to_string(),
            root_formula: "imagemagick".to_string(),
            stable_root: temp.path().join("opt/imagemagick"),
            install_root: temp.path().join("opt/imagemagick"),
            tmp_root: temp.path().join("tmp"),
        };
        write_package_receipt(
            &plan.root_receipt_path(),
            &PackageReceipt {
                package_name: "imagemagick".to_string(),
                version: "6.9.13_7".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "imagemagick".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        let current = vec![
            ("convert".to_string(), PathBuf::from("/tmp/bin/convert")),
            ("magick".to_string(), PathBuf::from("/tmp/bin/magick")),
        ];

        assert!(imagemagick_stub_exclusions(&plan, &current).is_empty());
    }

    #[test]
    fn stage_formula_merges_dependency_into_i_root() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "direnv".to_string(),
            root_formula: "direnv".to_string(),
            stable_root: temp.path().join("stable"),
            install_root: temp.path().join("direnv-2.37.1"),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(plan.install_root.join("existing")).unwrap();
        fs::write(plan.install_root.join("existing/root.txt"), b"root").unwrap();

        let keg_root = temp.path().join("ncurses/6.6");
        fs::create_dir_all(keg_root.join(".brew")).unwrap();
        fs::create_dir_all(keg_root.join(".bottle")).unwrap();
        fs::create_dir_all(keg_root.join("share")).unwrap();
        fs::write(keg_root.join("README"), b"dependency docs").unwrap();
        fs::write(
            keg_root.join(".brew/formula.rb"),
            b"class Ncurses < Formula",
        )
        .unwrap();
        fs::write(keg_root.join(".bottle/metadata.json"), b"{}").unwrap();
        fs::write(keg_root.join("share/term.info"), b"dep").unwrap();

        let install = InstalledFormula {
            spec: FormulaSpec {
                name: "ncurses".to_string(),
                bottle_sha256: "sha256".to_string(),
                bottle_url: "https://example.invalid/ncurses.tar.gz".to_string(),
            },
            keg_dir_name: "6.6".to_string(),
            archive_path: temp.path().join("ncurses.tar.gz"),
        };

        stage_formula(&plan, &install, &keg_root).unwrap();

        assert!(plan.install_root.join("existing/root.txt").is_file());
        assert!(plan.install_root.join("share/term.info").is_file());
        assert!(!plan.install_root.join("README").exists());
        assert!(!plan.install_root.join(".brew").exists());
        assert!(plan.install_root.join(".bottle/metadata.json").is_file());
        assert!(!keg_root.join("share/term.info").exists());
        assert!(!keg_root.join("README").exists());
        assert!(!keg_root.join(".brew").exists());
    }

    #[test]
    fn stage_formula_keeps_root_formula_docs_but_drops_brew_dir() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "direnv".to_string(),
            root_formula: "direnv".to_string(),
            stable_root: temp.path().join("stable"),
            install_root: temp.path().join("direnv-2.37.1"),
            tmp_root: temp.path().join("tmp"),
        };

        let keg_root = temp.path().join("direnv/2.37.1");
        fs::create_dir_all(keg_root.join(".brew")).unwrap();
        fs::create_dir_all(keg_root.join(".bottle")).unwrap();
        fs::create_dir_all(keg_root.join("bin")).unwrap();
        fs::write(keg_root.join("README"), b"root docs").unwrap();
        fs::write(keg_root.join(".brew/formula.rb"), b"class Direnv < Formula").unwrap();
        fs::write(keg_root.join(".bottle/metadata.json"), b"{}").unwrap();
        fs::write(keg_root.join("bin/direnv"), b"#!/bin/sh\n").unwrap();

        let install = InstalledFormula {
            spec: FormulaSpec {
                name: "direnv".to_string(),
                bottle_sha256: "sha256".to_string(),
                bottle_url: "https://example.invalid/direnv.tar.gz".to_string(),
            },
            keg_dir_name: "2.37.1".to_string(),
            archive_path: temp.path().join("direnv.tar.gz"),
        };

        stage_formula(&plan, &install, &keg_root).unwrap();

        assert!(plan.install_root.join("README").is_file());
        assert!(plan.install_root.join(".bottle/metadata.json").is_file());
        assert!(plan.install_root.join("bin/direnv").is_file());
        assert!(!plan.install_root.join(".brew").exists());
    }

    #[test]
    fn build_install_path_entries_dedupes_root_and_skips_missing_sbin() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "direnv".to_string(),
            root_formula: "direnv".to_string(),
            stable_root: temp.path().join("stable"),
            install_root: temp.path().join("direnv-2.37.1"),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(plan.install_root.join("bin")).unwrap();

        let graph = vec![FormulaSpec {
            name: "ncurses".to_string(),
            bottle_sha256: "sha256".to_string(),
            bottle_url: "https://example.invalid/ncurses.tar.gz".to_string(),
        }];

        let entries = build_install_path_entries(&plan, &graph);
        assert_eq!(entries, vec![plan.install_root.join("bin")]);

        fs::create_dir_all(plan.install_root.join("sbin")).unwrap();
        let entries = build_install_path_entries(&plan, &graph);
        assert_eq!(
            entries,
            vec![
                plan.install_root.join("bin"),
                plan.install_root.join("sbin")
            ]
        );
    }

    #[test]
    fn resolve_command_in_path_entries_finds_executable() {
        let temp = TempDir::new().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        write_executable(&second.join("npm"));

        let resolved = resolve_command_in_path_entries(&[first, second.clone()], "npm").unwrap();

        assert_eq!(resolved, second.join("npm"));
    }

    #[test]
    fn install_time_command_probes_cover_success_failure_and_missing_tools() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "coverage-runtime".to_string(),
            root_formula: "coverage-runtime".to_string(),
            stable_root: temp.path().join("stable"),
            install_root: temp.path().join("install"),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(plan.install_root.join("bin")).unwrap();
        fs::create_dir_all(&plan.tmp_root).unwrap();
        write_executable_with_body(&plan.install_root.join("bin/ok-runtime"), "exit 0\n");
        write_executable_with_body(&plan.install_root.join("bin/bad-runtime"), "exit 7\n");
        let progress = InstallProgress::with_callback("coverage-runtime", None);

        assert!(
            install_time_commands_are_usable(&plan, &[], ["ok-runtime"], Some(&progress)).unwrap()
        );
        assert!(
            !install_time_commands_are_usable(&plan, &[], ["ok-runtime", "bad-runtime"], None)
                .unwrap()
        );
        assert!(!install_time_commands_are_usable(&plan, &[], ["missing-runtime"], None).unwrap());
    }

    #[test]
    fn merge_path_into_recursively_merges_directories_and_replaces_files() {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::create_dir_all(target.join("nested")).unwrap();
        fs::write(source.join("nested/source.txt"), b"source").unwrap();
        fs::write(target.join("nested/target.txt"), b"target").unwrap();

        merge_path_into(&source, &target).unwrap();

        assert!(!source.exists());
        assert_eq!(
            fs::read(target.join("nested/source.txt")).unwrap(),
            b"source"
        );
        assert_eq!(
            fs::read(target.join("nested/target.txt")).unwrap(),
            b"target"
        );

        let source_file = temp.path().join("replacement");
        let target_file = target.join("nested/target.txt");
        fs::write(&source_file, b"replacement").unwrap();
        merge_path_into(&source_file, &target_file).unwrap();

        assert_eq!(fs::read(target_file).unwrap(), b"replacement");
    }

    #[test]
    fn passwd_entry_returns_current_user_when_available() {
        let uid = unsafe { libc::getuid() };
        let (home, name) = passwd_entry(uid);

        assert!(home.is_some() || name.is_some());

        if !is_root() {
            let identity = current_user_identity().unwrap();
            assert_eq!(identity.uid, uid);
            assert_eq!(identity.gid, unsafe { libc::getgid() });
        }
    }

    #[test]
    fn copy_path_preserves_symlinks_directories_and_file_modes() {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination/tree");
        fs::create_dir_all(source.join("bin")).unwrap();
        fs::write(source.join("bin/tool"), b"tool").unwrap();
        symlink("../bin/tool", source.join("tool-link")).unwrap();
        let mut dir_permissions = fs::metadata(source.join("bin")).unwrap().permissions();
        dir_permissions.set_mode(0o755);
        fs::set_permissions(source.join("bin"), dir_permissions).unwrap();
        let mut file_permissions = fs::metadata(source.join("bin/tool")).unwrap().permissions();
        file_permissions.set_mode(0o700);
        fs::set_permissions(source.join("bin/tool"), file_permissions).unwrap();

        copy_path(&source, &destination).unwrap();

        assert_eq!(fs::read(destination.join("bin/tool")).unwrap(), b"tool");
        assert_eq!(
            fs::read_link(destination.join("tool-link")).unwrap(),
            PathBuf::from("../bin/tool")
        );
        assert_eq!(
            fs::metadata(destination.join("bin"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(destination.join("bin/tool"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn sanitize_progress_message_uses_latest_non_empty_line() {
        let message = "\rfirst line\n\n replacing existing signature \n";
        assert_eq!(
            sanitize_progress_message(message),
            "replacing existing signature"
        );
    }

    #[test]
    fn installed_stub_paths_use_usr_local_bin_prefix() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "python".to_string(),
            root_formula: "python".to_string(),
            stable_root: temp.path().join("stable"),
            install_root: temp.path().join("python"),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(&plan.install_root).unwrap();
        write_stub_manifest(
            &plan.package_manifest_path(),
            &StubManifest {
                stubs: vec!["pip3".to_string(), "python".to_string()],
            },
        )
        .unwrap();

        assert_eq!(
            installed_stub_paths(&plan).unwrap(),
            vec![
                managed_bin_root().join("pip3").display().to_string(),
                managed_bin_root().join("python").display().to_string()
            ]
        );
    }

    #[test]
    fn sync_stubs_writes_root_executables_and_removes_stale_entries() {
        let _package_lock = acquire_package_mutation_lock().unwrap();
        let temp = TempDir::new().unwrap();
        let package_name = "coverage-sync-stubs";
        let bin_root = managed_bin_root();
        let stale_stub = bin_root.join("coverage-stale");
        let foo_stub = bin_root.join("coverage-sync-foo");
        let bar_stub = bin_root.join("coverage-sync-bar");

        for path in [&stale_stub, &foo_stub, &bar_stub] {
            if fs::symlink_metadata(path).is_ok() {
                remove_path(path).unwrap();
            }
        }

        let plan = InstallPlan {
            mode: Mode::I,
            package_name: package_name.to_string(),
            root_formula: package_name.to_string(),
            stable_root: temp.path().join("stable"),
            install_root: temp.path().join(package_name),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(plan.install_root.join("bin")).unwrap();
        fs::create_dir_all(plan.install_root.join("sbin")).unwrap();
        write_executable(&plan.install_root.join("bin/coverage-sync-foo"));
        write_executable(&plan.install_root.join("sbin/coverage-sync-bar"));
        write_executable(&stale_stub);

        sync_stubs(&plan, &[], &["coverage-stale".to_string()]).unwrap();

        assert!(is_executable(&foo_stub));
        assert!(is_executable(&bar_stub));
        assert!(fs::symlink_metadata(&stale_stub).is_err());
        assert_eq!(
            load_stub_manifest(&plan.package_manifest_path())
                .unwrap()
                .stubs,
            vec![
                "coverage-sync-bar".to_string(),
                "coverage-sync-foo".to_string(),
            ]
        );

        for path in [&foo_stub, &bar_stub] {
            remove_path(path).unwrap();
        }
    }

    #[test]
    fn sync_stubs_respects_declared_root_executable_manifest() {
        let _package_lock = acquire_package_mutation_lock().unwrap();
        let temp = TempDir::new().unwrap();
        let package_name = "coverage-sync-manifest";
        let bin_root = managed_bin_root();
        let kept_stub = bin_root.join("coverage-keep");
        let skipped_stub = bin_root.join("coverage-skip");

        for path in [&kept_stub, &skipped_stub] {
            if fs::symlink_metadata(path).is_ok() {
                remove_path(path).unwrap();
            }
        }

        let plan = InstallPlan {
            mode: Mode::I,
            package_name: package_name.to_string(),
            root_formula: package_name.to_string(),
            stable_root: temp.path().join("stable"),
            install_root: temp.path().join(package_name),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(plan.install_root.join("bin")).unwrap();
        write_executable(&plan.install_root.join("bin/coverage-keep"));
        write_executable(&plan.install_root.join("bin/coverage-skip"));
        write_root_executable_manifest(
            &plan.root_executables_manifest_path(),
            &["coverage-keep".to_string()],
        )
        .unwrap();

        sync_stubs(&plan, &[], &[]).unwrap();

        assert!(is_executable(&kept_stub));
        assert!(fs::symlink_metadata(&skipped_stub).is_err());
        assert_eq!(
            load_stub_manifest(&plan.package_manifest_path())
                .unwrap()
                .stubs,
            vec!["coverage-keep".to_string()]
        );

        remove_path(&kept_stub).unwrap();
    }

    #[test]
    fn stub_helpers_cover_missing_and_invalid_manifest_cases() {
        let temp = TempDir::new().unwrap();
        let manifest_path = temp.path().join("stub-manifest.json");
        fs::write(&manifest_path, b"{not json").unwrap();
        assert!(
            load_stub_manifest(&manifest_path)
                .unwrap_err()
                .contains("failed to parse")
        );

        assert!(!stub_belongs_to_package(&temp.path().join("missing-stub"), "coverage").unwrap());

        let empty_bin_dir = temp.path().join("missing-bin");
        refresh_post_uninstall_stubs(temp.path(), &empty_bin_dir).unwrap();

        let parent = temp.path().join("nested");
        fs::create_dir_all(&parent).unwrap();
        fs::write(parent.join("keep"), b"keep").unwrap();
        remove_empty_parent_dirs(&parent.join("missing/child"), temp.path()).unwrap();
        assert!(parent.exists());
    }

    #[test]
    fn stub_helpers_cover_non_not_found_io_errors() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("bin"), b"not a directory").unwrap();
        assert!(
            collect_root_executables(&root)
                .unwrap_err()
                .contains("failed to read")
        );

        let manifest_dir = temp.path().join("manifest-dir");
        fs::create_dir_all(&manifest_dir).unwrap();
        assert!(
            load_stub_manifest(&manifest_dir)
                .unwrap_err()
                .contains("failed to read")
        );
        assert!(
            stub_belongs_to_package(&manifest_dir, "coverage")
                .unwrap_err()
                .contains("failed to read")
        );

        let blocking_file = temp.path().join("blocking-file");
        fs::write(&blocking_file, b"file").unwrap();
        assert!(
            remove_empty_parent_dirs(&blocking_file.join("child"), temp.path())
                .unwrap_err()
                .contains("failed to remove")
        );

        let opt_root = temp.path().join("opt");
        let bin_dir = temp.path().join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        remove_existing_package_install(&opt_root, "missing", &bin_dir).unwrap();
    }

    #[test]
    fn sync_declared_stubs_filters_exclusions_and_removes_stale_entries() {
        let _package_lock = acquire_package_mutation_lock().unwrap();
        let temp = TempDir::new().unwrap();
        let package_name = "coverage-declared-stubs";
        let bin_root = managed_bin_root();
        let kept_stub = bin_root.join("coverage-declared-keep");
        let stale_stub = bin_root.join("coverage-declared-stale");
        let excluded_stub = bin_root.join("coverage-declared-skip");

        for path in [&kept_stub, &stale_stub, &excluded_stub] {
            if fs::symlink_metadata(path).is_ok() {
                remove_path(path).unwrap();
            }
        }

        let plan = InstallPlan {
            mode: Mode::I,
            package_name: package_name.to_string(),
            root_formula: package_name.to_string(),
            stable_root: temp.path().join("stable"),
            install_root: temp.path().join(package_name),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(plan.install_root.join("bin")).unwrap();
        write_executable(&plan.install_root.join("bin/coverage-declared-keep"));
        write_executable(&plan.install_root.join("bin/coverage-declared-skip"));
        write_executable(&stale_stub);

        let excluded = HashSet::from(["coverage-declared-skip".to_string()]);
        sync_declared_stubs(
            &plan,
            &[],
            ["coverage-declared-keep", "coverage-declared-skip"],
            &excluded,
            &["coverage-declared-stale".to_string()],
        )
        .unwrap();

        assert!(is_executable(&kept_stub));
        assert!(fs::symlink_metadata(&stale_stub).is_err());
        assert!(fs::symlink_metadata(&excluded_stub).is_err());
        assert_eq!(
            load_stub_manifest(&plan.package_manifest_path())
                .unwrap()
                .stubs,
            vec!["coverage-declared-keep".to_string()]
        );

        remove_path(&kept_stub).unwrap();
    }

    #[test]
    fn run_package_post_install_returns_early_without_supported_formulas() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "coverage-no-post-install".to_string(),
            root_formula: "coverage-no-post-install".to_string(),
            stable_root: temp.path().join("stable"),
            install_root: temp.path().join("coverage-no-post-install"),
            tmp_root: temp.path().join("tmp"),
        };
        let bin_dir = temp.path().join("bin");
        fs::create_dir_all(&bin_dir).unwrap();

        run_package_post_install(&plan, &[], &bin_dir).unwrap();

        assert!(fs::symlink_metadata(plan.package_manifest_path()).is_err());
    }

    #[test]
    fn run_package_post_install_creates_python_dispatchers_and_openssl_cert_path() {
        let temp = TempDir::new().unwrap();
        let opt_root = temp.path().join("opt");
        let bin_dir = temp.path().join("usr-local-bin");
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "python@3.12".to_string(),
            root_formula: "python@3.12".to_string(),
            stable_root: opt_root.join("python@3.12"),
            install_root: opt_root.join("python@3.12"),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(&plan.install_root).unwrap();
        fs::create_dir_all(opt_root.join("python@3.13")).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(plan.install_root.join(OPENSSL_CA_CERTIFICATES_DIR)).unwrap();
        fs::write(
            plan.install_root.join(OPENSSL_CA_CERTIFICATES_CERT),
            b"cert bundle",
        )
        .unwrap();
        fs::write(
            plan.install_root
                .join(OPENSSL_CA_CERTIFICATES_DIR)
                .join("extra.pem"),
            b"extra cert",
        )
        .unwrap();
        write_stub_manifest(
            &plan.package_manifest_path(),
            &StubManifest {
                stubs: vec!["pip3.12".to_string(), "python3.12".to_string()],
            },
        )
        .unwrap();
        for name in ["python3.12", "pip3.12", "python3.13", "pip3.13"] {
            let path = bin_dir.join(name);
            fs::write(&path, b"#!/bin/sh\n").unwrap();
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).unwrap();
        }

        let installs = vec![InstalledFormula {
            spec: FormulaSpec {
                name: "openssl@3".to_string(),
                bottle_sha256: "sha256".to_string(),
                bottle_url: "https://example.invalid/openssl@3.tar.gz".to_string(),
            },
            keg_dir_name: "3.6.1".to_string(),
            archive_path: temp.path().join("openssl@3.tar.gz"),
        }];

        run_package_post_install(&plan, &installs, &bin_dir).unwrap();

        assert_eq!(
            fs::read_link(bin_dir.join("python")).unwrap(),
            PathBuf::from("python3")
        );
        assert_eq!(
            fs::read_link(bin_dir.join("pip")).unwrap(),
            PathBuf::from("pip3")
        );

        assert_eq!(
            fs::read_link(bin_dir.join("python3")).unwrap(),
            PathBuf::from("python3.13")
        );
        assert_eq!(
            fs::read_link(bin_dir.join("pip3")).unwrap(),
            PathBuf::from("pip3.13")
        );
        assert_eq!(
            fs::read_to_string(plan.install_root.join(OPENSSL_CERT_PEM_DESTINATION)).unwrap(),
            "cert bundle"
        );
        assert_eq!(
            fs::read_to_string(
                plan.install_root
                    .join(OPENSSL_CERT_PEM_DESTINATION_DIR)
                    .join("extra.pem")
            )
            .unwrap(),
            "extra cert"
        );
        assert!(!plan.install_root.join(OPENSSL_CA_CERTIFICATES_DIR).exists());

        let manifest = load_stub_manifest(&plan.package_manifest_path()).unwrap();
        assert_eq!(
            manifest.stubs,
            vec![
                "pip".to_string(),
                "pip3".to_string(),
                "pip3.12".to_string(),
                "python".to_string(),
                "python3".to_string(),
                "python3.12".to_string(),
            ]
        );
    }

    #[test]
    fn reinstall_vendor_dependency_tree_restores_formula_dependencies() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "demo".to_string(),
            root_formula: "demo".to_string(),
            stable_root: temp.path().join("demo"),
            install_root: temp.path().join("demo"),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(&plan.tmp_root).unwrap();
        fs::create_dir_all(plan.install_root.join("bin")).unwrap();
        fs::write(plan.install_root.join("bin/demo"), b"#!/bin/sh\n").unwrap();

        let sqlite_archive = temp.path().join("sqlite.tar.gz");
        write_test_bottle_archive(
            &sqlite_archive,
            "sqlite",
            "3.49.1",
            &[("bin/sqlite3", b"#!/bin/sh\n")],
        );

        let installs = vec![InstalledFormula {
            spec: FormulaSpec {
                name: "sqlite".to_string(),
                bottle_sha256: "sha256".to_string(),
                bottle_url: "https://example.invalid/sqlite.tar.gz".to_string(),
            },
            keg_dir_name: "3.49.1".to_string(),
            archive_path: sqlite_archive,
        }];

        reinstall_vendor_dependency_tree(
            &Config {
                bottle_tag: "arm64_tahoe".to_string(),
            },
            &plan,
            &installs,
            &[],
            &[],
            None,
        )
        .unwrap();

        assert!(plan.install_root.join("bin/sqlite3").is_file());
        assert!(plan.receipt_path("sqlite").is_file());
        assert!(!plan.install_root.join("bin/demo").exists());
    }

    #[test]
    fn reinstall_vendor_dependency_tree_keeps_downloaded_bottles_alive_until_extract() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "demo".to_string(),
            root_formula: "demo".to_string(),
            stable_root: temp.path().join("demo"),
            install_root: temp.path().join("demo"),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(&plan.tmp_root).unwrap();
        fs::create_dir_all(plan.install_root.join("bin")).unwrap();
        fs::write(plan.install_root.join("bin/demo"), b"#!/bin/sh\n").unwrap();

        let sqlite_archive = temp.path().join("sqlite.tar.gz");
        write_test_bottle_archive(
            &sqlite_archive,
            "sqlite",
            "3.49.1",
            &[("bin/sqlite3", b"#!/bin/sh\n")],
        );
        let sqlite_bytes = fs::read(&sqlite_archive).unwrap();
        let sqlite_sha = format!("{:x}", Sha256::digest(&sqlite_bytes));
        let bottle_server =
            start_counting_test_http_server(vec![("/sqlite.tar.gz".to_string(), sqlite_bytes)]);
        let graph = vec![FormulaSpec {
            name: "sqlite".to_string(),
            bottle_sha256: sqlite_sha,
            bottle_url: format!("{}/sqlite.tar.gz", bottle_server.base_url),
        }];

        reinstall_vendor_dependency_tree(
            &Config {
                bottle_tag: "arm64_tahoe".to_string(),
            },
            &plan,
            &[],
            &graph,
            &[],
            None,
        )
        .unwrap();

        assert!(plan.install_root.join("bin/sqlite3").is_file());
        assert!(plan.receipt_path("sqlite").is_file());
        assert!(!plan.install_root.join("bin/demo").exists());
    }

    #[test]
    fn remove_package_stubs_preserves_shared_entries() {
        let temp = TempDir::new().unwrap();
        let opt_root = temp.path().join("opt");
        let bin_dir = temp.path().join("usr-local-bin");
        let python312 = opt_root.join("python@3.12");
        let python313 = opt_root.join("python@3.13");

        fs::create_dir_all(&python312).unwrap();
        fs::create_dir_all(&python313).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();

        write_stub_manifest(
            &python312.join(STUB_MANIFEST),
            &StubManifest {
                stubs: vec![
                    "pip".to_string(),
                    "python".to_string(),
                    "python3.12".to_string(),
                ],
            },
        )
        .unwrap();
        write_stub_manifest(
            &python313.join(STUB_MANIFEST),
            &StubManifest {
                stubs: vec![
                    "pip".to_string(),
                    "python".to_string(),
                    "python3.13".to_string(),
                ],
            },
        )
        .unwrap();

        for name in ["pip", "python", "python3.12", "python3.13"] {
            write_executable(&bin_dir.join(name));
        }

        remove_package_stubs_from_bin(&opt_root, "python@3.13", &bin_dir).unwrap();

        assert!(bin_dir.join("pip").exists());
        assert!(bin_dir.join("python").exists());
        assert!(fs::symlink_metadata(bin_dir.join("python3.12")).is_ok());
        assert!(fs::symlink_metadata(bin_dir.join("python3.13")).is_err());
    }

    #[test]
    fn remove_existing_package_install_removes_prefix_and_stubs() {
        let temp = TempDir::new().unwrap();
        let opt_root = temp.path().join("opt");
        let bin_dir = temp.path().join("usr-local-bin");
        let foo = opt_root.join("foo");

        fs::create_dir_all(foo.join("bin")).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();
        write_stub_manifest(
            &foo.join(STUB_MANIFEST),
            &StubManifest {
                stubs: vec!["foo".to_string(), "bar".to_string()],
            },
        )
        .unwrap();

        write_executable(&foo.join("bin/foo"));
        write_executable(&bin_dir.join("foo"));
        write_executable(&bin_dir.join("bar"));

        remove_existing_package_install(&opt_root, "foo", &bin_dir).unwrap();

        assert!(fs::symlink_metadata(&foo).is_err());
        assert!(fs::symlink_metadata(bin_dir.join("foo")).is_err());
        assert!(fs::symlink_metadata(bin_dir.join("bar")).is_err());
    }

    #[test]
    fn remove_existing_scoped_npm_install_removes_empty_scope_dir() {
        let temp = TempDir::new().unwrap();
        let opt_root = temp.path().join("opt");
        let bin_dir = temp.path().join("usr-local-bin");
        let qmd = opt_root.join("npm/@tobilu/qmd");

        fs::create_dir_all(qmd.join("bin")).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();
        write_stub_manifest(
            &qmd.join(STUB_MANIFEST),
            &StubManifest {
                stubs: vec!["qmd".to_string()],
            },
        )
        .unwrap();

        write_executable(&qmd.join("bin/qmd"));
        write_executable(&bin_dir.join("qmd"));

        remove_existing_package_install(&opt_root, "npm:@tobilu/qmd", &bin_dir).unwrap();

        assert!(fs::symlink_metadata(&qmd).is_err());
        assert!(fs::symlink_metadata(opt_root.join("npm/@tobilu")).is_err());
        assert!(fs::symlink_metadata(bin_dir.join("qmd")).is_err());
    }

    #[test]
    fn refresh_post_uninstall_stubs_updates_python_dispatchers() {
        let temp = TempDir::new().unwrap();
        let opt_root = temp.path().join("opt");
        let bin_dir = temp.path().join("usr-local-bin");
        let python312 = opt_root.join("python@3.12");
        let python313 = opt_root.join("python@3.13");

        fs::create_dir_all(&python312).unwrap();
        fs::create_dir_all(&python313).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();

        write_package_receipt(
            &python312.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "python@3.12".to_string(),
                version: "3.12.10".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "python@3.12".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        write_package_receipt(
            &python313.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "python@3.13".to_string(),
                version: "3.13.3".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "python@3.13".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();

        write_stub_manifest(
            &python312.join(STUB_MANIFEST),
            &StubManifest {
                stubs: vec![
                    "pip".to_string(),
                    "pip3".to_string(),
                    "pip3.12".to_string(),
                    "python".to_string(),
                    "python3".to_string(),
                    "python3.12".to_string(),
                ],
            },
        )
        .unwrap();
        write_stub_manifest(
            &python313.join(STUB_MANIFEST),
            &StubManifest {
                stubs: vec![
                    "pip".to_string(),
                    "pip3".to_string(),
                    "pip3.13".to_string(),
                    "python".to_string(),
                    "python3".to_string(),
                    "python3.13".to_string(),
                ],
            },
        )
        .unwrap();

        for name in ["python3.12", "pip3.12", "python3.13", "pip3.13"] {
            write_executable(&bin_dir.join(name));
        }

        post_install_hooks::run("python@3.13", &python313, &bin_dir).unwrap();
        remove_package_stubs_from_bin(&opt_root, "python@3.13", &bin_dir).unwrap();
        remove_path(&python313).unwrap();
        refresh_post_uninstall_stubs(&opt_root, &bin_dir).unwrap();

        assert_eq!(
            fs::read_link(bin_dir.join("python")).unwrap(),
            PathBuf::from("python3")
        );
        assert_eq!(
            fs::read_link(bin_dir.join("python3")).unwrap(),
            PathBuf::from("python3.12")
        );

        assert_eq!(
            fs::read_link(bin_dir.join("pip")).unwrap(),
            PathBuf::from("pip3")
        );
        assert_eq!(
            fs::read_link(bin_dir.join("pip3")).unwrap(),
            PathBuf::from("pip3.12")
        );
        assert!(fs::symlink_metadata(bin_dir.join("python3.13")).is_err());
        assert!(fs::symlink_metadata(bin_dir.join("pip3.13")).is_err());
    }

    #[test]
    fn refresh_post_uninstall_stubs_ignores_python_dependency_receipts() {
        let temp = TempDir::new().unwrap();
        let opt_root = temp.path().join("opt");
        let bin_dir = temp.path().join("usr-local-bin");
        let python312 = opt_root.join("python@3.12");
        let foo = opt_root.join("foo");

        fs::create_dir_all(python312.join(RECEIPTS_DIR)).unwrap();
        fs::create_dir_all(foo.join(RECEIPTS_DIR)).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();

        fs::write(python312.join(RECEIPTS_DIR).join("python@3.12.json"), b"{}").unwrap();
        write_package_receipt(
            &python312.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "python@3.12".to_string(),
                version: "3.12.10".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "python@3.12".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        fs::write(foo.join(RECEIPTS_DIR).join("python@3.12.json"), b"{}").unwrap();
        write_package_receipt(
            &foo.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "foo".to_string(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "foo".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();

        write_stub_manifest(
            &python312.join(STUB_MANIFEST),
            &StubManifest {
                stubs: vec![
                    "pip".to_string(),
                    "pip3".to_string(),
                    "pip3.12".to_string(),
                    "python".to_string(),
                    "python3".to_string(),
                    "python3.12".to_string(),
                ],
            },
        )
        .unwrap();

        for name in ["python", "python3", "python3.12", "pip", "pip3", "pip3.12"] {
            write_executable(&bin_dir.join(name));
        }

        remove_package_stubs_from_bin(&opt_root, "python@3.12", &bin_dir).unwrap();
        remove_path(&python312).unwrap();
        refresh_post_uninstall_stubs(&opt_root, &bin_dir).unwrap();

        for name in ["python", "python3", "python3.12", "pip", "pip3", "pip3.12"] {
            assert!(fs::symlink_metadata(bin_dir.join(name)).is_err());
        }
    }

    #[test]
    fn write_stub_double_quotes_entire_path_assignment() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "python@3.12".to_string(),
            root_formula: "python@3.12".to_string(),
            stable_root: temp.path().join("stable"),
            install_root: temp.path().join("python"),
            tmp_root: temp.path().join("tmp"),
        };
        let stub_path = temp.path().join("python3");
        let actual_path = PathBuf::from("/opt/python@3.12/bin/python3");
        let env_entries = vec![
            PathBuf::from("/opt/python@3.12/bin"),
            PathBuf::from("/opt/tools/$special/bin"),
        ];

        write_stub(&plan, &stub_path, &actual_path, &env_entries).unwrap();

        let script = fs::read_to_string(&stub_path).unwrap();
        assert!(script.starts_with("#!/bin/sh\n# generated by av python@3.12\n"));
        assert!(script.contains("PATH=\"/opt/python@3.12/bin:/opt/tools/\\$special/bin:$PATH\"\n"));
        assert!(script.contains("exec '/opt/python@3.12/bin/python3' \"$@\"\n"));
    }

    #[test]
    fn write_venv_stub_exports_virtualenv_before_execing_entrypoint() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "pip:psycopg2".to_string(),
            root_formula: "pip:psycopg2".to_string(),
            stable_root: temp.path().join("stable"),
            install_root: temp.path().join("psycopg2"),
            tmp_root: temp.path().join("tmp"),
        };
        let stub_path = temp.path().join("psql-tool");
        let venv_root = PathBuf::from("/opt/pip/psycopg2/venv");
        let actual_path = venv_root.join("bin/psql-tool");

        write_venv_stub(&plan, &stub_path, &actual_path, &venv_root).unwrap();

        let script = fs::read_to_string(&stub_path).unwrap();
        assert!(script.contains("VIRTUAL_ENV='/opt/pip/psycopg2/venv'\n"));
        assert!(script.contains("unset PYTHONHOME\n"));
        assert!(script.contains("PATH=\"/opt/pip/psycopg2/venv/bin:$PATH\"\n"));
        assert!(script.contains("exec '/opt/pip/psycopg2/venv/bin/psql-tool' \"$@\"\n"));
    }

    #[test]
    fn write_stub_execs_target_without_fork_bomb_guard() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "python@3.12".to_string(),
            root_formula: "python@3.12".to_string(),
            stable_root: temp.path().join("stable"),
            install_root: temp.path().join("python"),
            tmp_root: temp.path().join("tmp"),
        };
        let stub_path = temp.path().join("python3");
        let target_path = temp.path().join("actual-python3");

        fs::write(&target_path, "#!/bin/sh\nprintf 'ok\\n'\n").unwrap();
        let mut permissions = fs::metadata(&target_path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&target_path, permissions).unwrap();

        write_stub(&plan, &stub_path, &target_path, &[]).unwrap();

        let output = Command::new(&stub_path).output().unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout).unwrap(), "ok\n");
        assert_eq!(String::from_utf8(output.stderr).unwrap(), "");
    }

    #[test]
    fn prepare_install_target_requires_force_for_existing_install() {
        let temp = TempDir::new().unwrap();
        let install_root = temp.path().join("already-installed");
        fs::create_dir_all(&install_root).unwrap();
        write_package_receipt(
            &install_root.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "already-installed".to_string(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "already-installed".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();

        let err = prepare_install_target(
            temp.path(),
            "already-installed",
            InstallIntent::Install,
            temp.path(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            "package already-installed is already installed; use --force/-f to reinstall"
        );
        prepare_install_target(
            temp.path(),
            "already-installed",
            InstallIntent::Reinstall,
            temp.path(),
        )
        .unwrap();
        assert!(!install_root.exists());
        prepare_install_target(
            temp.path(),
            "not-installed",
            InstallIntent::Install,
            temp.path(),
        )
        .unwrap();
    }

    #[test]
    fn prepare_install_target_preserves_valid_roots_for_update() {
        let temp = TempDir::new().unwrap();
        let install_root = temp.path().join("already-installed");
        fs::create_dir_all(&install_root).unwrap();
        fs::write(install_root.join("sentinel"), b"keep").unwrap();
        write_package_receipt(
            &install_root.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "already-installed".to_string(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "already-installed".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();

        prepare_install_target(
            temp.path(),
            "already-installed",
            InstallIntent::Update,
            temp.path(),
        )
        .unwrap();

        assert!(install_root.join("sentinel").is_file());
    }

    #[test]
    fn prepare_i_install_plan_skips_seed_for_missing_formula_ownership() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "foo".to_string(),
            root_formula: "foo".to_string(),
            stable_root: temp.path().join("opt/foo"),
            install_root: temp.path().join("opt/foo"),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(plan.install_root.join("bin")).unwrap();
        fs::write(plan.install_root.join("bin/foo"), b"old").unwrap();
        write_package_receipt(
            &plan.root_receipt_path(),
            &PackageReceipt {
                package_name: "foo".to_string(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "foo".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        write_receipt(
            &plan.receipt_path("foo"),
            &InstalledFormula {
                spec: FormulaSpec {
                    name: "foo".to_string(),
                    bottle_sha256: "oldsha".to_string(),
                    bottle_url: "https://example.invalid/foo.tar.gz".to_string(),
                },
                keg_dir_name: "1.0.0".to_string(),
                archive_path: PathBuf::new(),
            },
            "arm64_tahoe",
        )
        .unwrap();

        let prepared = prepare_i_install_plan(&plan, InstallIntent::Update).unwrap();

        assert!(!prepared.plan.install_root.join("bin/foo").exists());
    }

    #[test]
    fn incremental_update_and_copy_helpers_cover_seed_edges() {
        let temp = TempDir::new().unwrap();
        let shared_file = temp.path().join("shared-file");
        fs::write(&shared_file, b"not a directory").unwrap();
        assert!(!shared_tmp_root_is_writable(&shared_file.join("child")));

        let missing_receipt = InstallPlan {
            mode: Mode::I,
            package_name: "missing-receipt".to_string(),
            root_formula: "missing-receipt".to_string(),
            stable_root: temp.path().join("opt/missing-receipt"),
            install_root: temp.path().join("opt/missing-receipt"),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(&missing_receipt.install_root).unwrap();
        assert!(!install_root_supports_incremental_update(&missing_receipt).unwrap());

        let unreadable_receipts = InstallPlan {
            package_name: "bad-receipts".to_string(),
            root_formula: "bad-receipts".to_string(),
            stable_root: temp.path().join("opt/bad-receipts"),
            install_root: temp.path().join("opt/bad-receipts"),
            ..missing_receipt.clone()
        };
        fs::create_dir_all(&unreadable_receipts.install_root).unwrap();
        write_package_receipt(
            &unreadable_receipts.root_receipt_path(),
            &PackageReceipt {
                package_name: unreadable_receipts.package_name.clone(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: unreadable_receipts.root_formula.clone(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        fs::write(unreadable_receipts.install_root.join(RECEIPTS_DIR), b"file").unwrap();
        assert!(
            formula_receipts_support_incremental_update(&unreadable_receipts)
                .unwrap_err()
                .contains("failed to read")
        );

        let invalid_receipts = InstallPlan {
            package_name: "invalid-receipts".to_string(),
            root_formula: "invalid-receipts".to_string(),
            stable_root: temp.path().join("opt/invalid-receipts"),
            install_root: temp.path().join("opt/invalid-receipts"),
            ..missing_receipt.clone()
        };
        fs::create_dir_all(invalid_receipts.install_root.join(RECEIPTS_DIR)).unwrap();
        write_package_receipt(
            &invalid_receipts.root_receipt_path(),
            &PackageReceipt {
                package_name: invalid_receipts.package_name.clone(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: invalid_receipts.root_formula.clone(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        fs::write(
            invalid_receipts
                .install_root
                .join(RECEIPTS_DIR)
                .join("invalid.json"),
            b"{not-json",
        )
        .unwrap();
        assert!(
            formula_receipts_support_incremental_update(&invalid_receipts)
                .unwrap_err()
                .contains("failed to parse")
        );

        let seeded = InstallPlan {
            mode: Mode::I,
            package_name: "seeded".to_string(),
            root_formula: "seeded".to_string(),
            stable_root: temp.path().join("opt/seeded"),
            install_root: temp.path().join("opt/seeded"),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(seeded.install_root.join("bin")).unwrap();
        fs::create_dir_all(seeded.install_root.join("share/doc")).unwrap();
        fs::write(seeded.install_root.join("bin/tool"), b"old tool").unwrap();
        fs::write(seeded.install_root.join("share/doc/readme"), b"docs").unwrap();
        symlink("bin/tool", seeded.install_root.join("tool-link")).unwrap();
        fs::create_dir_all(seeded.install_root.join(RECEIPTS_DIR)).unwrap();
        fs::write(
            seeded.install_root.join(RECEIPTS_DIR).join("notes.txt"),
            b"skip",
        )
        .unwrap();
        write_receipt_with_owned_paths(
            &seeded.receipt_path("seeded"),
            &InstalledFormula {
                spec: FormulaSpec {
                    name: "seeded".to_string(),
                    bottle_sha256: "sha".to_string(),
                    bottle_url: "https://example.invalid/seeded.tar.gz".to_string(),
                },
                keg_dir_name: "1.0.0".to_string(),
                archive_path: PathBuf::new(),
            },
            "arm64_tahoe",
            vec!["bin/tool".to_string()],
        )
        .unwrap();
        write_package_receipt(
            &seeded.root_receipt_path(),
            &PackageReceipt {
                package_name: seeded.package_name.clone(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: seeded.root_formula.clone(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();

        let prepared = prepare_i_install_plan(&seeded, InstallIntent::Update).unwrap();
        assert_eq!(
            fs::read(prepared.plan.install_root.join("bin/tool")).unwrap(),
            b"old tool"
        );
        assert_eq!(
            fs::read_link(prepared.plan.install_root.join("tool-link")).unwrap(),
            PathBuf::from("bin/tool")
        );
        assert!(prepared.plan.install_root.join("share/doc/readme").exists());

        let source_file = temp.path().join("source-file");
        let destination_file = temp.path().join("destination-file");
        fs::write(&source_file, b"replacement").unwrap();
        fs::write(&destination_file, b"existing").unwrap();
        let metadata = fs::metadata(&source_file).unwrap();
        copy_file_preserving_metadata(&source_file, &destination_file, &metadata).unwrap();
        assert_eq!(fs::read(&destination_file).unwrap(), b"replacement");
    }

    #[test]
    fn package_install_root_uses_iso_prefix() {
        let temp = TempDir::new().unwrap();

        let install_root = package_install_root(temp.path(), "isotope:gh").unwrap();

        assert_eq!(install_root, temp.path().join("iso/gh"));
    }

    #[test]
    fn package_name_validation_and_normalization_cover_error_paths() {
        assert_eq!(
            validate_npm_package_name(""),
            Err("package qualifier 'npm:' is missing a package name".to_string())
        );
        assert_eq!(
            validate_npm_package_name("@scope"),
            Err("scoped npm package names must be in the form @scope/name".to_string())
        );
        assert_eq!(
            validate_npm_package_name("@scope/name/extra"),
            Err("scoped npm package names must be in the form @scope/name".to_string())
        );
        assert_eq!(
            validate_npm_package_name("foo/bar"),
            Err("npm package names must not contain path separators".to_string())
        );
        assert_eq!(
            parse_npm_package_request("@scope/name@1.2.3").unwrap(),
            ("@scope/name".to_string(), Some("1.2.3".to_string()))
        );
        assert_eq!(
            parse_npm_package_request("openclaw@").unwrap_err(),
            "npm package version must not be empty".to_string()
        );
        assert!(
            parse_npm_package_request("openclaw@nope")
                .unwrap_err()
                .contains("invalid npm package version nope")
        );

        assert_eq!(
            validate_pip_package_name(""),
            Err("package qualifier 'pip:' is missing a package name".to_string())
        );
        assert_eq!(
            validate_pip_package_name("foo/bar"),
            Err("pip package names must not contain path separators".to_string())
        );
        assert_eq!(
            validate_pip_package_name("bad!name"),
            Err(
                "pip package names may only contain ASCII letters, numbers, '.', '-' and '_'"
                    .to_string()
            )
        );
        assert_eq!(
            normalize_pip_package_name("Py_Proj...Tool"),
            "py-proj-tool".to_string()
        );
    }

    #[test]
    fn package_alias_and_embedded_provider_parsing_cover_variants() {
        assert_eq!(
            parse_package_alias_target("brew:").unwrap_err(),
            "package qualifier 'brew:' is missing a formula name".to_string()
        );
        assert_eq!(
            parse_package_alias_target("brew:foo/bar").unwrap_err(),
            "qualified package name must not contain additional path separators".to_string()
        );
        assert_eq!(
            parse_package_alias_target("cask:").unwrap_err(),
            "package qualifier 'cask:' is missing a cask name".to_string()
        );
        assert_eq!(
            parse_package_alias_target("av:terraform").unwrap(),
            PackageAliasTarget::VendorPackage("terraform".to_string())
        );
        assert_eq!(
            parse_package_alias_target("npm:@scope/tool").unwrap(),
            PackageAliasTarget::NpmPackage("@scope/tool".to_string())
        );
        assert_eq!(
            parse_package_alias_target("pip:Py_Proj").unwrap(),
            PackageAliasTarget::PipPackage("py-proj".to_string())
        );
        assert_eq!(
            parse_package_alias_target("tool").unwrap_err(),
            "alias targets must use a package qualifier".to_string()
        );

        assert_eq!(
            parse_embedded_provider("npm:").unwrap_err(),
            "package qualifier 'npm:' is missing a package name".to_string()
        );
        assert_eq!(
            parse_embedded_provider("cask:").unwrap_err(),
            "package qualifier 'cask:' is missing a cask name".to_string()
        );
        assert_eq!(parse_embedded_provider("brew:git").unwrap(), None);
        assert_eq!(
            parse_embedded_provider("ripgrep").unwrap(),
            Some(EmbeddedPackage::Formula("ripgrep".to_string()))
        );
    }

    #[test]
    fn package_install_root_and_formula_recommendations_cover_edge_cases() {
        let temp = TempDir::new().unwrap();

        assert_eq!(
            package_install_root(temp.path(), "npm:@scope/tool").unwrap(),
            temp.path().join("npm/@scope/tool")
        );
        assert_eq!(
            package_install_root(temp.path(), "pip:Py_Proj...Tool").unwrap(),
            temp.path().join("pip/py-proj-tool")
        );
        assert_eq!(
            package_install_root(temp.path(), "isotope:").unwrap_err(),
            "package qualifier 'isotope:' is missing an isotope name".to_string()
        );
        assert_eq!(
            package_install_root(temp.path(), "isotope:foo/bar").unwrap_err(),
            "qualified package name must not contain additional path separators".to_string()
        );
        assert_eq!(
            package_install_root(temp.path(), "npm:@scope").unwrap_err(),
            "scoped npm package names must be in the form @scope/name".to_string()
        );
        assert_eq!(
            package_install_root(temp.path(), "pip:bad/name").unwrap_err(),
            "pip package names must not contain path separators".to_string()
        );

        let mut stderr = Vec::new();
        write_full_formula_recommendation("ffmpeg", &mut stderr).unwrap();
        assert!(String::from_utf8(stderr).unwrap().contains("ffmpeg-full"));

        let mut stderr = Vec::new();
        write_full_formula_recommendation("ripgrep", &mut stderr).unwrap();
        assert!(stderr.is_empty());
    }

    #[test]
    fn prepare_install_target_removes_incomplete_install() {
        let temp = TempDir::new().unwrap();
        let bin_dir = temp.path().join("bin");
        let install_root = package_install_root(temp.path(), "npm:openclaw").unwrap();
        fs::create_dir_all(&install_root).unwrap();
        fs::write(install_root.join("stale"), b"old").unwrap();
        write_stub_manifest(
            &install_root.join(STUB_MANIFEST),
            &StubManifest {
                stubs: vec!["openclaw".to_string()],
            },
        )
        .unwrap();
        fs::create_dir_all(&bin_dir).unwrap();
        fs::write(bin_dir.join("openclaw"), b"#!/bin/sh\n").unwrap();

        prepare_install_target(
            temp.path(),
            "npm:openclaw",
            InstallIntent::Install,
            &bin_dir,
        )
        .unwrap();

        assert!(!install_root.exists());
        assert!(!bin_dir.join("openclaw").exists());
    }

    #[test]
    fn rollback_failed_install_removes_partial_root_and_stubs() {
        let temp = TempDir::new().unwrap();
        let bin_dir = temp.path().join("bin");
        let install_root = package_install_root(temp.path(), "npm:openclaw").unwrap();
        fs::create_dir_all(&install_root).unwrap();
        fs::write(install_root.join("stale"), b"old").unwrap();
        write_stub_manifest(
            &install_root.join(STUB_MANIFEST),
            &StubManifest {
                stubs: vec!["openclaw".to_string()],
            },
        )
        .unwrap();
        fs::create_dir_all(&bin_dir).unwrap();
        fs::write(bin_dir.join("openclaw"), b"#!/bin/sh\n").unwrap();

        rollback_failed_install(temp.path(), "npm:openclaw", &bin_dir).unwrap();

        assert!(!install_root.exists());
        assert!(!bin_dir.join("openclaw").exists());
    }

    #[test]
    fn write_full_formula_recommendation_suggests_full_variants() {
        let mut stderr = Vec::new();
        write_full_formula_recommendation("ffmpeg", &mut stderr).unwrap();
        write_full_formula_recommendation("imagemagick", &mut stderr).unwrap();
        write_full_formula_recommendation("ripgrep", &mut stderr).unwrap();

        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "info: requested `ffmpeg`; `brew:ffmpeg-full` is recommended instead\n\
info: requested `imagemagick`; `brew:imagemagick-full` is recommended instead\n"
        );
    }

    #[test]
    fn prepare_i_install_plan_stages_under_tmp_root() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "caddy".to_string(),
            root_formula: "caddy".to_string(),
            stable_root: temp.path().join("opt/caddy"),
            install_root: temp.path().join("opt/caddy"),
            tmp_root: temp.path().join("opt/.tmp"),
        };

        let prepared = prepare_i_install_plan(&plan, InstallIntent::Install).unwrap();
        let staged_plan = prepared.plan;

        assert_eq!(staged_plan.stable_root, plan.stable_root);
        assert_ne!(staged_plan.install_root, plan.install_root);
        assert!(staged_plan.install_root.starts_with(&plan.tmp_root));
    }

    #[test]
    fn preserve_temp_dir_in_debug_keeps_debug_workspaces() {
        let temp = TempDir::new().unwrap();
        let workspace = TempDir::new_in(temp.path()).unwrap();
        let workspace_path = workspace.path().to_path_buf();

        preserve_temp_dir_in_debug(workspace);

        assert_eq!(workspace_path.exists(), cfg!(debug_assertions));
        if workspace_path.exists() {
            fs::remove_dir_all(&workspace_path).unwrap();
        }
    }

    #[test]
    fn activate_install_replaces_existing_root_with_staged_tree() {
        let temp = TempDir::new().unwrap();
        let stable_root = temp.path().join("opt/caddy");
        let install_root = temp.path().join("opt/.tmp/staged/install");
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "caddy".to_string(),
            root_formula: "caddy".to_string(),
            stable_root: stable_root.clone(),
            install_root: install_root.clone(),
            tmp_root: temp.path().join("opt/.tmp"),
        };

        fs::create_dir_all(stable_root.join("bin")).unwrap();
        fs::write(stable_root.join("bin/caddy"), b"old").unwrap();
        fs::create_dir_all(install_root.join("bin")).unwrap();
        fs::write(install_root.join("bin/caddy"), b"new").unwrap();

        activate_install(&plan).unwrap();

        assert_eq!(fs::read(stable_root.join("bin/caddy")).unwrap(), b"new");
        assert!(!install_root.exists());
    }

    #[test]
    fn temp_root_for_target_root_prefers_shared_tmp_root_on_same_device() {
        let temp = TempDir::new().unwrap();
        let target_root = temp.path().join("opt");
        let system_tmp_root = temp.path().join("tmp");
        let shared_tmp_root = temp.path().join("nucleus");

        assert_eq!(
            temp_root_for_target_root(&target_root, &system_tmp_root, &shared_tmp_root),
            shared_tmp_root
        );
    }

    #[test]
    fn temp_root_for_target_root_falls_back_when_shared_root_is_not_writable() {
        let temp = TempDir::new().unwrap();
        let target_root = temp.path().join("opt");
        let system_tmp_root = temp.path().join("tmp");
        let shared_tmp_root = temp.path().join("nucleus");
        fs::create_dir_all(&shared_tmp_root).unwrap();
        let mut permissions = fs::metadata(&shared_tmp_root).unwrap().permissions();
        permissions.set_mode(0o555);
        fs::set_permissions(&shared_tmp_root, permissions).unwrap();

        assert_eq!(
            temp_root_for_target_root(&target_root, &system_tmp_root, &shared_tmp_root),
            target_root.join(".tmp")
        );
    }

    #[test]
    fn temp_root_for_target_root_falls_back_when_target_root_has_no_existing_ancestor() {
        let temp = TempDir::new().unwrap();
        let target_root = PathBuf::from("relative/opt");
        let system_tmp_root = temp.path().join("tmp");
        let shared_tmp_root = temp.path().join("nucleus");

        assert_eq!(
            temp_root_for_target_root(&target_root, &system_tmp_root, &shared_tmp_root),
            target_root.join(".tmp")
        );
    }

    #[test]
    fn install_plan_for_i_uses_detected_tmp_root() {
        let plan = InstallPlan::for_i("caddy".to_string(), "caddy".to_string());

        assert_eq!(plan.stable_root, opt_pkg_root().join("caddy"));
        assert_eq!(plan.install_root, opt_pkg_root().join("caddy"));
        assert_eq!(
            plan.tmp_root,
            temp_root_for_target_root(
                &opt_pkg_root(),
                Path::new(SYSTEM_TMP_ROOT),
                Path::new(TMP_TOOL_ROOT),
            )
        );
    }

    #[test]
    fn debug_build_uses_tmp_install_roots() {
        assert_eq!(opt_pkg_root(), PathBuf::from("/tmp/opt"));
        assert_eq!(managed_bin_root(), PathBuf::from("/tmp/usr/local/bin"));
        assert!(!install_requires_root());
    }

    #[test]
    fn install_plan_for_i_npm_uses_dedicated_opt_root() {
        let plan = InstallPlan::for_i_npm(
            "npm:openclaw".to_string(),
            "npm:openclaw".to_string(),
            "openclaw",
        );

        assert_eq!(plan.stable_root, opt_npm_root().join("openclaw"));
        assert_eq!(plan.install_root, opt_npm_root().join("openclaw"));
        assert_eq!(
            plan.tmp_root,
            temp_root_for_target_root(
                &opt_npm_root(),
                Path::new(SYSTEM_TMP_ROOT),
                Path::new(TMP_TOOL_ROOT),
            )
        );
    }

    #[test]
    fn install_plan_for_i_scoped_npm_preserves_scope_in_opt_root() {
        let plan = InstallPlan::for_i_npm(
            "npm:@tobilu/qmd".to_string(),
            "npm:@tobilu/qmd".to_string(),
            "@tobilu/qmd",
        );

        assert_eq!(plan.stable_root, opt_npm_root().join("@tobilu/qmd"));
        assert_eq!(plan.install_root, opt_npm_root().join("@tobilu/qmd"));
    }

    #[test]
    fn install_plan_for_i_pip_uses_dedicated_opt_root() {
        let plan = InstallPlan::for_i_pip(
            "pip:psycopg2".to_string(),
            "pip:psycopg2".to_string(),
            "psycopg2",
        );

        assert_eq!(plan.stable_root, opt_pip_root().join("psycopg2"));
        assert_eq!(plan.install_root, opt_pip_root().join("psycopg2"));
        assert_eq!(
            plan.tmp_root,
            temp_root_for_target_root(
                &opt_pip_root(),
                Path::new(SYSTEM_TMP_ROOT),
                Path::new(TMP_TOOL_ROOT),
            )
        );
    }

    #[test]
    fn install_plan_for_i_radioisotope_uses_formula_root() {
        let plan =
            InstallPlan::for_i_radioisotope("isotope:aws-cli".to_string(), "awscli".to_string());

        assert_eq!(plan.package_name, "isotope:aws-cli");
        assert_eq!(plan.root_formula, "awscli");
        assert_eq!(plan.stable_root, opt_pkg_root().join("awscli"));
        assert_eq!(plan.install_root, opt_pkg_root().join("awscli"));
        assert_eq!(
            plan.tmp_root,
            temp_root_for_target_root(
                &opt_pkg_root(),
                Path::new(SYSTEM_TMP_ROOT),
                Path::new(TMP_TOOL_ROOT),
            )
        );
    }

    #[test]
    fn install_plan_paths_cover_dependency_layout_and_receipts() {
        let plan = InstallPlan::for_i("rg".to_string(), "rg".to_string());

        assert_eq!(plan.actual_target_dir("rg"), opt_pkg_root().join("rg"));
        assert_eq!(plan.actual_target_dir("pcre2"), opt_pkg_root().join("rg"));
        assert_eq!(plan.stable_target_dir("rg"), opt_pkg_root().join("rg"));
        assert_eq!(plan.stable_target_dir("pcre2"), opt_pkg_root().join("rg"));
        assert_eq!(
            plan.receipt_path("rg"),
            opt_pkg_root().join("rg/.pkg/receipts/rg.json")
        );
        assert_eq!(
            plan.receipt_path("pcre2"),
            opt_pkg_root().join("rg/.pkg/receipts/pcre2.json")
        );
        assert_eq!(
            plan.package_manifest_path(),
            opt_pkg_root().join("rg/.pkg/stubs.json")
        );
        assert_eq!(
            plan.root_receipt_path(),
            opt_pkg_root().join("rg/.pkg/root-receipt.json")
        );
        assert_eq!(
            plan.root_executables_manifest_path(),
            opt_pkg_root().join("rg/.pkg/root-executables.json")
        );
    }

    #[test]
    fn metadata_probe_path_and_device_helpers_use_existing_ancestors() {
        let temp = TempDir::new().unwrap();
        let nested = temp.path().join("a/b/c");

        assert_eq!(metadata_probe_path(&nested).unwrap(), temp.path());
        assert!(paths_share_device(temp.path(), &nested).unwrap());
    }

    #[test]
    fn acquire_package_mutation_lock_uses_flock() {
        let temp = TempDir::new().unwrap();
        let lock = acquire_package_mutation_lock_at(temp.path()).unwrap();
        let path = temp.path().join(PKG_STATE_LOCK);
        let second = File::options().read(true).write(true).open(&path).unwrap();

        let result = unsafe { libc::flock(second.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(result, -1);
        let err = std::io::Error::last_os_error().raw_os_error().unwrap();
        assert!(err == libc::EWOULDBLOCK || err == libc::EAGAIN);

        drop(lock);

        let result = unsafe { libc::flock(second.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(result, 0);
        unsafe {
            libc::flock(second.as_raw_fd(), libc::LOCK_UN);
        }
    }

    #[test]
    fn load_db_and_schema_checks_embedded_inventory() {
        let db = load_db().unwrap();
        ensure_db_schema(&db).unwrap();
        assert_eq!(db.schema, DB_SCHEMA_VERSION);

        let old = Db {
            schema: DB_SCHEMA_VERSION - 1,
            generated_at: String::new(),
            entries: HashMap::new(),
            formulas: HashMap::new(),
            casks: HashMap::new(),
            npms: HashMap::new(),
        };
        ensure_db_schema(&old).unwrap();

        let future = Db {
            schema: DB_SCHEMA_VERSION + 1,
            generated_at: String::new(),
            entries: HashMap::new(),
            formulas: HashMap::new(),
            casks: HashMap::new(),
            npms: HashMap::new(),
        };
        assert_eq!(
            ensure_db_schema(&future).unwrap_err(),
            format!(
                "unsupported db schema {} (maximum supported {})",
                DB_SCHEMA_VERSION + 1,
                DB_SCHEMA_VERSION
            )
        );
    }

    #[test]
    fn embedded_coverage_fixture_carries_test_contract_data() {
        let data = embedded_combined_data();
        let db = &data.sources.db;

        assert_eq!(data.generated_at, "2026-05-05T00:00:00Z");
        assert_eq!(db.schema, DB_SCHEMA_VERSION);
        assert_eq!(
            db.formulas
                .get("ripgrep")
                .expect("coverage fixture should include ripgrep")
                .aliases,
            vec!["rg".to_string()]
        );
        assert_eq!(
            db.formulas
                .get("node")
                .expect("coverage fixture should include node")
                .aliases,
            vec!["node@25".to_string()]
        );
        assert_eq!(
            db.casks
                .get("codex")
                .expect("coverage fixture should include codex cask")
                .version,
            "1.0.0"
        );
        assert_eq!(
            data.sources
                .isotopes
                .get("gh")
                .expect("coverage fixture should include gh isotope")
                .replaces
                .as_deref(),
            Some("brew:gh")
        );
        assert_eq!(
            data.sources
                .pip
                .get("coverage-pip")
                .expect("coverage fixture should include coverage pip package")
                .python_formula
                .as_deref(),
            Some("python@3.14")
        );
    }

    #[test]
    fn trusted_remote_combined_data_loads_readable_root_cache_shape() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("db.json");
        fs::write(&path, EMBEDDED_COMBINED_DATA).unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let data = load_trusted_remote_combined_data_from(temp.path(), &path, false).unwrap();

        assert_eq!(data.sources.db.schema, DB_SCHEMA_VERSION);
        assert!(data.sources.isotopes.contains_key("aws-cli"));
    }

    #[test]
    fn combined_data_freshness_rejects_older_remote_cache() {
        let embedded = test_combined_data_with_generated_at("2026-05-17T13:12:55Z");
        let older_remote = test_combined_data_with_generated_at("2026-05-17T12:42:37Z");
        let same_remote = test_combined_data_with_generated_at("2026-05-17T13:12:55Z");
        let newer_remote = test_combined_data_with_generated_at("2026-05-17T13:12:56Z");
        let invalid_remote = test_combined_data_with_generated_at("not-rfc3339");
        let invalid_embedded = test_combined_data_with_generated_at("not-rfc3339");

        assert!(!combined_data_is_at_least_as_new(&older_remote, &embedded));
        assert!(combined_data_is_at_least_as_new(&same_remote, &embedded));
        assert!(combined_data_is_at_least_as_new(&newer_remote, &embedded));
        assert!(!combined_data_is_at_least_as_new(
            &invalid_remote,
            &embedded
        ));
        assert!(combined_data_is_at_least_as_new(
            &same_remote,
            &invalid_embedded
        ));
    }

    #[test]
    fn trusted_remote_combined_data_rejects_world_writable_cache_file() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("db.json");
        fs::write(&path, EMBEDDED_COMBINED_DATA).unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();

        assert!(load_trusted_remote_combined_data_from(temp.path(), &path, false).is_none());
    }

    #[test]
    fn trusted_remote_combined_data_rejects_future_schema_cache_file() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("db.json");
        fs::write(
            &path,
            test_combined_data_json_with_db_schema(DB_SCHEMA_VERSION + 1),
        )
        .unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(load_trusted_remote_combined_data_from(temp.path(), &path, false).is_none());
    }

    #[test]
    fn refresh_remote_combined_data_uses_etags_and_validates_json() {
        let temp = TempDir::new().unwrap();
        let data_path = temp.path().join("db.json");
        let meta_path = temp.path().join("db.meta.json");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (base, server) = start_test_etag_server(requests.clone(), test_combined_data_json());
        let url = format!("{base}/db.json");

        assert!(
            refresh_remote_combined_data_with(&url, temp.path(), &data_path, &meta_path, 0)
                .unwrap()
        );
        assert!(
            !refresh_remote_combined_data_with(&url, temp.path(), &data_path, &meta_path, 0)
                .unwrap()
        );

        server.join().unwrap();
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains("accept-encoding: gzip, br")
        );
        assert!(
            requests[1]
                .to_ascii_lowercase()
                .contains("accept-encoding: gzip, br")
        );
        assert!(!requests[0].contains("If-None-Match"));
        assert!(requests[1].contains("If-None-Match: \"test-etag\""));
        let metadata = read_remote_combined_data_metadata(&meta_path);
        assert_eq!(metadata.etag.as_deref(), Some("\"test-etag\""));
    }

    #[test]
    fn refresh_remote_combined_data_rejects_future_schema_without_replacing_cache() {
        let temp = TempDir::new().unwrap();
        let data_path = temp.path().join("db.json");
        let meta_path = temp.path().join("db.meta.json");
        let cached_data = test_combined_data_json();
        fs::write(&data_path, &cached_data).unwrap();
        let (base, server) = start_test_http_server(
            vec![(
                "/db.json".to_string(),
                test_combined_data_json_with_db_schema(DB_SCHEMA_VERSION + 1),
            )],
            1,
        );
        let url = format!("{base}/db.json");

        let err = refresh_remote_combined_data_with(&url, temp.path(), &data_path, &meta_path, 0)
            .unwrap_err();

        server.join().unwrap();
        assert!(err.contains("unsupported remote database"));
        assert!(err.contains("unsupported db schema"));
        assert_eq!(fs::read(&data_path).unwrap(), cached_data);
        assert!(!meta_path.exists());
    }

    #[test]
    fn refresh_remote_combined_data_skips_recent_check_and_invalid_metadata_defaults() {
        let temp = TempDir::new().unwrap();
        let data_path = temp.path().join("db.json");
        let meta_path = temp.path().join("db.meta.json");

        fs::write(&meta_path, b"not-json").unwrap();
        let parsed = read_remote_combined_data_metadata(&meta_path);
        assert!(parsed.etag.is_none());
        assert!(parsed.checked_at.is_none());

        let metadata = RemoteCombinedDataMetadata {
            etag: Some("\"cached-etag\"".to_string()),
            checked_at: Some(current_unix_timestamp().unwrap()),
        };
        fs::write(&meta_path, serde_json::to_vec(&metadata).unwrap()).unwrap();

        let refreshed = refresh_remote_combined_data_with(
            "http://127.0.0.1:9/db.json",
            temp.path(),
            &data_path,
            &meta_path,
            u64::MAX,
        )
        .unwrap();

        assert!(!refreshed);
        let parsed = read_remote_combined_data_metadata(&meta_path);
        assert_eq!(parsed.etag, metadata.etag);
        assert_eq!(parsed.checked_at, metadata.checked_at);
        assert!(!data_path.exists());
    }

    #[test]
    fn trusted_remote_data_helpers_reject_bad_shapes_and_permissions() {
        let temp = TempDir::new().unwrap();
        let dir_file = temp.path().join("not-a-dir");
        let data_path = temp.path().join("db.json");
        fs::write(&dir_file, b"file").unwrap();
        fs::write(&data_path, EMBEDDED_COMBINED_DATA).unwrap();
        fs::set_permissions(&data_path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(!trusted_remote_data_path(&dir_file, &data_path, false));
        assert!(!trusted_remote_data_path(
            temp.path(),
            &temp.path().join("missing.json"),
            false
        ));

        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!trusted_remote_data_path(temp.path(), &data_path, false));

        let metadata = fs::metadata(&data_path).unwrap();
        assert!(trusted_remote_data_metadata(&metadata, false));
        assert!(!trusted_remote_data_metadata(&metadata, true));
    }

    #[test]
    fn remote_combined_data_writers_persist_cache_and_metadata() {
        let temp = TempDir::new().unwrap();
        let cache_dir = temp.path().join("cache");
        let data_path = cache_dir.join("db.json");
        let meta_path = cache_dir.join("db.meta.json");
        let bytes = test_combined_data_json();
        let metadata = RemoteCombinedDataMetadata {
            etag: Some("\"next-etag\"".to_string()),
            checked_at: Some(current_unix_timestamp().unwrap()),
        };

        write_remote_combined_data(&cache_dir, &data_path, &bytes).unwrap();
        write_remote_combined_data_metadata(&cache_dir, &meta_path, &metadata).unwrap();

        assert_eq!(fs::read(&data_path).unwrap(), bytes);
        let parsed = read_remote_combined_data_metadata(&meta_path);
        assert_eq!(parsed.etag, metadata.etag);
        assert_eq!(parsed.checked_at, metadata.checked_at);
        assert_eq!(
            fs::metadata(&cache_dir).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(&data_path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(
            fs::metadata(&meta_path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(current_unix_timestamp().unwrap() > 0);
    }

    #[test]
    fn help_and_version_parse_paths_return_none() {
        let invocation = Invocation {
            binary_name: "av".to_string(),
            name: "av update".to_string(),
            mode: None,
        };

        assert_eq!(
            parse_i_request_from_iter(&invocation, vec![OsString::from("-h")].into_iter()).unwrap(),
            None
        );
        assert_eq!(
            parse_uninstall_request_from_iter(
                &invocation,
                vec![OsString::from("--help")].into_iter()
            )
            .unwrap(),
            None
        );
        assert_eq!(
            parse_update_request_from_iter(&invocation, vec![OsString::from("-V")].into_iter())
                .unwrap(),
            None
        );
        assert_eq!(
            parse_package_status_request_from_iter(
                &invocation,
                vec![OsString::from("--help")].into_iter(),
                print_list_usage,
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn flag_and_subcommand_helpers_accept_supported_aliases() {
        assert!(is_help_flag(&OsString::from("-h")));
        assert!(is_help_flag(&OsString::from("--help")));
        assert!(is_version_flag(&OsString::from("-V")));
        assert!(is_version_flag(&OsString::from("--version")));
        assert!(is_force_flag(&OsString::from("-f")));
        assert!(is_force_flag(&OsString::from("--force")));
        assert!(is_no_self_update_flag(&OsString::from(
            SELF_UPDATE_DISABLE_FLAG
        )));
        assert!(is_uninstall_subcommand("rm"));
        assert!(is_uninstall_subcommand("uninstall"));
        assert!(is_outdated_subcommand("outdated"));
        assert!(!is_outdated_subcommand("list"));
    }

    #[test]
    fn package_receipts_and_stub_manifests_round_trip() {
        let temp = TempDir::new().unwrap();
        let receipt_path = temp.path().join("pkg/root.json");
        let stub_manifest_path = temp.path().join("pkg/stubs.json");
        let root_manifest_path = temp.path().join("pkg/root-executables.json");
        let receipt = PackageReceipt {
            package_name: "deno".to_string(),
            version: "2.7.7".to_string(),
            source: PackageReceiptSource::Vendor {
                vendor_name: "deno".to_string(),
            },
            metadata: PackageMetadata::default(),
        };

        assert!(load_package_receipt(&receipt_path).unwrap().is_none());
        write_package_receipt(&receipt_path, &receipt).unwrap();
        assert_eq!(load_package_receipt(&receipt_path).unwrap(), Some(receipt));

        assert_eq!(
            load_stub_manifest(&stub_manifest_path).unwrap(),
            StubManifest { stubs: Vec::new() }
        );
        write_stub_manifest(
            &stub_manifest_path,
            &StubManifest {
                stubs: vec!["deno".to_string()],
            },
        )
        .unwrap();
        assert_eq!(
            load_stub_manifest(&stub_manifest_path).unwrap(),
            StubManifest {
                stubs: vec!["deno".to_string()],
            }
        );

        write_root_executable_manifest(&root_manifest_path, &["deno".to_string()]).unwrap();
        assert_eq!(
            load_root_executable_manifest(&root_manifest_path).unwrap(),
            StubManifest {
                stubs: vec!["deno".to_string()],
            }
        );
    }

    #[test]
    fn package_receipts_without_metadata_remain_readable() {
        let temp = TempDir::new().unwrap();
        let receipt_path = temp.path().join("pkg/root.json");
        fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();
        fs::write(
            &receipt_path,
            br#"{
                "package_name": "ripgrep",
                "version": "14.1.1",
                "source": {
                    "kind": "formula",
                    "root_formula": "ripgrep"
                }
            }"#,
        )
        .unwrap();

        assert_eq!(
            load_package_receipt(&receipt_path).unwrap(),
            Some(PackageReceipt {
                package_name: "ripgrep".to_string(),
                version: "14.1.1".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "ripgrep".to_string(),
                },
                metadata: PackageMetadata::default(),
            })
        );
    }

    #[test]
    fn package_status_helpers_cover_current_and_missing_cases() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "sqlite".to_string(),
            root_formula: "sqlite".to_string(),
            stable_root: temp.path().join("opt/sqlite"),
            install_root: temp.path().join("opt/sqlite"),
            tmp_root: temp.path().join("tmp"),
        };
        let install = InstalledFormula {
            spec: FormulaSpec {
                name: "sqlite".to_string(),
                bottle_sha256: "sha256".to_string(),
                bottle_url: "https://example.invalid/sqlite.tar.gz".to_string(),
            },
            keg_dir_name: "3.49.1".to_string(),
            archive_path: temp.path().join("sqlite.tar.gz"),
        };

        assert!(!receipt_is_current(&plan, &install, "arm64_tahoe").unwrap());
        assert!(!package_is_current(&plan, std::slice::from_ref(&install), "arm64_tahoe").unwrap());

        write_receipt(&plan.receipt_path("sqlite"), &install, "arm64_tahoe").unwrap();
        fs::create_dir_all(&plan.install_root).unwrap();
        assert!(receipt_is_current(&plan, &install, "arm64_tahoe").unwrap());
        assert!(package_is_current(&plan, &[install], "arm64_tahoe").unwrap());
    }

    #[test]
    fn install_dependency_formulas_with_empty_graph_prepares_vendor_root() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "npm-openclaw".to_string(),
            root_formula: "npm-openclaw".to_string(),
            stable_root: temp.path().join("opt/npm-openclaw"),
            install_root: temp.path().join("opt/npm-openclaw"),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(&plan.install_root).unwrap();
        fs::write(plan.install_root.join("stale"), b"old").unwrap();

        install_dependency_formulas(
            &Config {
                bottle_tag: "arm64_tahoe".to_string(),
            },
            &plan,
            &[],
            &[],
            None,
        )
        .unwrap();

        assert!(plan.install_root.is_dir());
        assert!(!plan.install_root.join("stale").exists());
    }

    #[test]
    fn dependency_current_checks_cover_empty_and_vendor_roots() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "codex".to_string(),
            root_formula: "codex".to_string(),
            stable_root: temp.path().join("opt/codex"),
            install_root: temp.path().join("opt/codex"),
            tmp_root: temp.path().join("tmp"),
        };
        let config = Config {
            bottle_tag: "arm64_tahoe".to_string(),
        };

        assert!(!dependencies_are_current(&plan, &[], &[], &config).unwrap());
        fs::create_dir_all(&plan.install_root).unwrap();
        assert!(dependencies_are_current(&plan, &[], &[], &config).unwrap());

        fs::create_dir_all(plan.install_root.join("bin")).unwrap();
        write_executable(&plan.install_root.join("bin/codex"));
        let vendor_install = fake_vendor_install("codex", &["codex"], "0.1.0");
        write_package_receipt(
            &plan.root_receipt_path(),
            &PackageReceipt {
                package_name: "codex".to_string(),
                version: "0.1.0".to_string(),
                source: PackageReceiptSource::Vendor {
                    vendor_name: "codex".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        assert!(vendor_root_is_current(&plan, &vendor_install, &[], &config.bottle_tag).unwrap());

        remove_path(&plan.install_root.join("bin/codex")).unwrap();
        assert!(!vendor_root_is_current(&plan, &vendor_install, &[], &config.bottle_tag).unwrap());
    }

    #[test]
    fn dependency_current_checks_cover_npm_pip_cask_and_isotope_roots() {
        let temp = TempDir::new().unwrap();
        let config = Config {
            bottle_tag: "arm64_tahoe".to_string(),
        };

        let npm_plan = InstallPlan {
            mode: Mode::I,
            package_name: "npm:coverage-npm".to_string(),
            root_formula: "coverage-npm".to_string(),
            stable_root: temp.path().join("opt/npm/coverage-npm"),
            install_root: temp.path().join("opt/npm/coverage-npm"),
            tmp_root: temp.path().join("tmp"),
        };
        assert!(
            !npm_root_is_current(
                &npm_plan,
                "coverage-npm",
                &Version::parse("1.2.3").unwrap(),
                &[],
                &config.bottle_tag
            )
            .unwrap()
        );
        fs::create_dir_all(npm_plan.install_root.join("bin")).unwrap();
        write_executable(&npm_plan.install_root.join("bin/coverage-npm"));
        write_package_receipt(
            &npm_plan.root_receipt_path(),
            &PackageReceipt {
                package_name: "npm:coverage-npm".to_string(),
                version: "1.2.3".to_string(),
                source: PackageReceiptSource::Npm {
                    package_name: "coverage-npm".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        assert!(
            npm_root_is_current(
                &npm_plan,
                "coverage-npm",
                &Version::parse("1.2.3").unwrap(),
                &[],
                &config.bottle_tag,
            )
            .unwrap()
        );
        remove_path(&npm_plan.install_root.join("bin/coverage-npm")).unwrap();
        assert!(
            !npm_root_is_current(
                &npm_plan,
                "coverage-npm",
                &Version::parse("1.2.3").unwrap(),
                &[],
                &config.bottle_tag,
            )
            .unwrap()
        );

        let pip_plan = InstallPlan {
            mode: Mode::I,
            package_name: "pip:coverage-pip".to_string(),
            root_formula: "coverage-pip".to_string(),
            stable_root: temp.path().join("opt/pip/coverage-pip"),
            install_root: temp.path().join("opt/pip/coverage-pip"),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(pip_plan.install_root.join("bin")).unwrap();
        fs::create_dir_all(pip_plan.install_root.join("venv")).unwrap();
        fs::write(pip_plan.install_root.join("venv/pyvenv.cfg"), b"").unwrap();
        write_executable(&pip_plan.install_root.join("bin/coverage-pip"));
        write_root_executable_manifest(
            &pip_plan.root_executables_manifest_path(),
            &["coverage-pip".to_string()],
        )
        .unwrap();
        write_package_receipt(
            &pip_plan.root_receipt_path(),
            &PackageReceipt {
                package_name: "pip:coverage-pip".to_string(),
                version: "2.3.4".to_string(),
                source: PackageReceiptSource::Pip {
                    package_name: "coverage-pip".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        assert!(pip_root_is_current(&pip_plan, "2.3.4", &[], &config.bottle_tag).unwrap());
        remove_path(&pip_plan.install_root.join("venv/pyvenv.cfg")).unwrap();
        assert!(!pip_root_is_current(&pip_plan, "2.3.4", &[], &config.bottle_tag).unwrap());

        let cask_plan = InstallPlan {
            mode: Mode::I,
            package_name: "cask:codex".to_string(),
            root_formula: "codex".to_string(),
            stable_root: temp.path().join("opt/cask/codex"),
            install_root: temp.path().join("opt/cask/codex"),
            tmp_root: temp.path().join("tmp"),
        };
        let cask = EmbeddedCaskMetadata {
            version: "1.0.0".to_string(),
            binaries: vec![EmbeddedCaskBinary {
                source: "Codex.app/Contents/MacOS/codex".to_string(),
                target: Some("codex".to_string()),
            }],
            ..Default::default()
        };
        fs::create_dir_all(cask_plan.install_root.join("bin")).unwrap();
        write_executable(&cask_plan.install_root.join("bin/codex"));
        write_package_receipt(
            &cask_plan.root_receipt_path(),
            &PackageReceipt {
                package_name: "cask:codex".to_string(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Cask {
                    cask_name: "codex".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        assert!(cask_root_is_current(&cask_plan, &cask, &[], &config.bottle_tag).unwrap());
        remove_path(&cask_plan.install_root.join("bin/codex")).unwrap();
        assert!(!cask_root_is_current(&cask_plan, &cask, &[], &config.bottle_tag).unwrap());

        let isotope_plan = InstallPlan {
            mode: Mode::I,
            package_name: "isotope:gh".to_string(),
            root_formula: "gh".to_string(),
            stable_root: temp.path().join("opt/iso/gh"),
            install_root: temp.path().join("opt/iso/gh"),
            tmp_root: temp.path().join("tmp"),
        };
        let isotope = IsotopePackageData {
            name: "isotope:gh".to_string(),
            replaces: Some("brew:gh".to_string()),
            modifies: None,
            migrate: None,
            _repository: None,
            _upstream_repository: None,
            version: "2.80.0".to_string(),
            release_url: Some("https://example.test/isotopes/gh".to_string()),
            archive_url: Some("https://example.test/isotopes/gh.tar.gz".to_string()),
            published_at: None,
            applies_to_versioned_formulae: false,
        };
        fs::create_dir_all(isotope_plan.install_root.join("bin")).unwrap();
        write_executable(&isotope_plan.install_root.join("bin/gh"));
        write_root_executable_manifest(
            &isotope_plan.root_executables_manifest_path(),
            &["gh".to_string()],
        )
        .unwrap();
        write_package_receipt(
            &isotope_plan.root_receipt_path(),
            &PackageReceipt {
                package_name: "isotope:gh".to_string(),
                version: "2.80.0".to_string(),
                source: PackageReceiptSource::Isotope {
                    isotope_name: "gh".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        assert!(isotope_root_is_current(&isotope_plan, &isotope).unwrap());
        remove_path(&isotope_plan.install_root.join("bin/gh")).unwrap();
        assert!(!isotope_root_is_current(&isotope_plan, &isotope).unwrap());
    }

    #[test]
    fn find_supported_post_install_prefixes_filters_supported_formula_receipts() {
        let temp = TempDir::new().unwrap();
        let opt_root = temp.path().join("opt");
        let python = opt_root.join("python@3.12");
        let openssl = opt_root.join("openssl@3");
        let deno = opt_root.join("deno");
        fs::create_dir_all(&python).unwrap();
        fs::create_dir_all(&openssl).unwrap();
        fs::create_dir_all(&deno).unwrap();

        write_package_receipt(
            &python.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "python@3.12".to_string(),
                version: "3.12.10".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "python@3.12".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        write_package_receipt(
            &openssl.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "openssl@3".to_string(),
                version: "3.6.1".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "openssl@3".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        write_package_receipt(
            &deno.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "deno".to_string(),
                version: "2.7.7".to_string(),
                source: PackageReceiptSource::Vendor {
                    vendor_name: "deno".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();

        let mut prefixes = find_supported_post_install_prefixes(&opt_root).unwrap();
        prefixes.sort_by(|left, right| left.0.cmp(&right.0));
        assert_eq!(
            prefixes,
            vec![
                ("openssl@3".to_string(), openssl),
                ("python@3.12".to_string(), python),
            ]
        );
        assert_eq!(installed_post_install_formula(&deno).unwrap(), None);
    }

    #[test]
    fn post_install_helpers_cover_python_and_openssl_branches() {
        let temp = TempDir::new().unwrap();
        let opt_root = temp.path().join("opt");
        let bin_dir = temp.path().join("bin");
        let python312 = opt_root.join("python@3.12");
        let python313 = opt_root.join("python@3.13");
        fs::create_dir_all(&python312).unwrap();
        fs::create_dir_all(&python313).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();
        write_executable(&bin_dir.join("python3.12"));
        write_executable(&bin_dir.join("pip3.12"));
        fs::write(bin_dir.join("python3"), b"old").unwrap();
        assert!(post_install_hooks::supports("python@3.12"));
        assert!(!post_install_hooks::supports("python@3.12.1"));
        let outcome = post_install_hooks::run("python@3.12", &python312, &bin_dir).unwrap();
        assert_eq!(
            outcome.managed_stubs,
            vec![
                "pip".to_string(),
                "pip3".to_string(),
                "python".to_string(),
                "python3".to_string(),
            ]
        );
        assert_eq!(
            fs::read_link(bin_dir.join("python3")).unwrap(),
            PathBuf::from("python3.12")
        );

        let openssl_prefix = temp.path().join("openssl");
        let source_dir = openssl_prefix.join(OPENSSL_CA_CERTIFICATES_DIR);
        let target_dir = openssl_prefix.join(OPENSSL_CERT_PEM_DESTINATION_DIR);
        fs::create_dir_all(&source_dir).unwrap();
        fs::create_dir_all(&target_dir).unwrap();
        fs::write(source_dir.join("cacert.pem"), b"source").unwrap();
        fs::write(source_dir.join("extra.pem"), b"extra").unwrap();
        fs::write(target_dir.join("cert.pem"), b"old").unwrap();

        assert!(post_install_hooks::supports_dependency("openssl@3"));
        post_install_hooks::run("openssl@3", &openssl_prefix, &bin_dir).unwrap();

        assert_eq!(
            fs::read_to_string(target_dir.join("cert.pem")).unwrap(),
            "source"
        );
        assert_eq!(
            fs::read_to_string(target_dir.join("extra.pem")).unwrap(),
            "extra"
        );
        assert!(!source_dir.exists());
    }

    #[test]
    fn vendor_registry_helpers_cover_install_strategies_and_parse_errors() {
        assert!(get("missing").is_none());
        assert_eq!(
            github_release_url("foo/bar", "v1.2.3", "tool.tar.gz"),
            "https://github.com/foo/bar/releases/download/v1.2.3/tool.tar.gz"
        );
        assert!(parse_semver("nope", "test").is_err());

        match bun::install(&Version::parse("1.2.3").unwrap()) {
            vendor::InstallStrategy::CopyFile {
                source,
                destination_dir,
                destination_name,
                mode,
                create_dirs,
            } => {
                assert_eq!(source, "bun-darwin-aarch64/bun");
                assert_eq!(destination_dir, "bin");
                assert_eq!(destination_name, None);
                assert_eq!(mode, 0o755);
                assert_eq!(create_dirs, vec!["bin".to_string()]);
            }
            _ => panic!("bun should install a single binary"),
        }
    }

    #[test]
    fn formula_api_helpers_resolve_aliases_and_specs_from_fixture_server() {
        let _env_lock = test_env_lock().lock().unwrap();
        let (formula_alias, formula_name) = formula_index_entries()
            .unwrap()
            .iter()
            .find_map(|entry| {
                entry
                    .aliases
                    .first()
                    .cloned()
                    .map(|alias| (alias, entry.name.clone()))
            })
            .expect("embedded db should carry at least one formula alias");
        let (base, _server) = start_test_http_server(
            vec![
                (
                    "/formula.json".to_string(),
                    serde_json::to_vec(&vec![
                        serde_json::json!({
                            "name": formula_name,
                            "aliases": [formula_alias],
                            "oldnames": ["python3.12"],
                        }),
                        serde_json::json!({
                            "name": "openssl@3",
                            "aliases": [],
                            "oldnames": [],
                        }),
                    ])
                    .unwrap(),
                ),
                (
                    format!("/{formula_name}.json"),
                    serde_json::to_vec(&serde_json::json!({
                        "versions": {"stable": "3.12.10"},
                        "revision": 1,
                        "dependencies": ["openssl@3"],
                        "bottle": {
                            "stable": {
                                "files": {
                                    "arm64_tahoe": {
                                        "sha256": "python-sha",
                                        "url": "https://example.invalid/python.tar.gz"
                                    }
                                }
                            }
                        },
                        "disabled": false,
                        "post_install_defined": false
                    }))
                    .unwrap(),
                ),
                (
                    "/openssl@3.json".to_string(),
                    serde_json::to_vec(&serde_json::json!({
                        "versions": {"stable": "3.6.1"},
                        "revision": 0,
                        "dependencies": [],
                        "bottle": {
                            "stable": {
                                "files": {
                                    "arm64_tahoe": {
                                        "sha256": "openssl-sha",
                                        "url": "https://example.invalid/openssl.tar.gz"
                                    }
                                }
                            }
                        },
                        "disabled": false,
                        "post_install_defined": true
                    }))
                    .unwrap(),
                ),
            ],
            20,
        );
        let _endpoints = TestEndpointGuard::set(config::TestEndpointOverrides {
            formula_api_root: Some(base.clone()),
            ..Default::default()
        });

        assert_eq!(
            canonical_formula_name(&formula_alias).unwrap(),
            formula_name
        );
        assert!(formula_metadata_exists(&formula_alias).unwrap());
        let fetched_info = fetch_formula_info(&formula_alias).unwrap();
        assert_eq!(formula_version_string(&fetched_info), "3.12.10_1");
        assert_eq!(
            resolve_formula_latest_version(
                &Config {
                    bottle_tag: "arm64_tahoe".to_string(),
                },
                &formula_alias,
            )
            .unwrap(),
            "3.12.10_1"
        );
        let specs = resolve_formula_specs(
            std::slice::from_ref(&formula_alias),
            &Config {
                bottle_tag: "arm64_tahoe".to_string(),
            },
            true,
        )
        .unwrap();
        assert_eq!(
            specs
                .iter()
                .map(|spec| spec.name.as_str())
                .collect::<Vec<_>>(),
            vec!["openssl@3", formula_name.as_str()]
        );
    }

    #[test]
    fn resolve_package_search_results_matches_formula_names_and_aliases() {
        let _env_lock = test_env_lock().lock().unwrap();
        let formula_index = formula_index_entries().unwrap();
        let rg_formula = formula_alias_index()
            .unwrap()
            .get("rg")
            .cloned()
            .expect("embedded db should carry the rg alias");
        let rg_summary = formula_index
            .iter()
            .find(|entry| entry.name == rg_formula)
            .and_then(|entry| string_or_none(&entry.summary))
            .expect("embedded db should carry rg summary");

        let results = resolve_package_search_results(
            &Config {
                bottle_tag: "arm64_tahoe".to_string(),
            },
            "rg",
        )
        .unwrap();
        assert!(results.iter().any(|result| {
            result.package_name == rg_formula
                && result.source
                    == PackageReceiptSource::Formula {
                        root_formula: rg_formula.clone(),
                    }
                && result.summary == Some(rg_summary.clone())
                && result.latest_version.is_none()
                && result.homepage.is_none()
                && result.dependencies.is_empty()
        }));

        let alias_results = resolve_package_search_results(
            &Config {
                bottle_tag: "arm64_tahoe".to_string(),
            },
            "rg",
        )
        .unwrap();
        assert!(alias_results.iter().any(|result| {
            result.package_name == rg_formula && result.summary == Some(rg_summary.clone())
        }));

        let vendor_results = resolve_package_search_results(
            &Config {
                bottle_tag: "arm64_tahoe".to_string(),
            },
            "av:bun",
        )
        .unwrap();
        assert!(vendor_results.iter().any(|result| {
            result.package_name == "av:bun"
                && result.source
                    == PackageReceiptSource::Vendor {
                        vendor_name: "bun".to_string(),
                    }
        }));

        let npm_results = resolve_package_search_results(
            &Config {
                bottle_tag: "arm64_tahoe".to_string(),
            },
            "coverage-npm",
        )
        .unwrap();
        assert!(npm_results.iter().any(|result| {
            result.package_name == "npm:coverage-npm"
                && result.source
                    == PackageReceiptSource::Npm {
                        package_name: "coverage-npm".to_string(),
                    }
                && result.summary == Some("Coverage npm tool".to_string())
                && result.latest_version == Some("1.2.3".to_string())
        }));
    }

    #[test]
    fn package_search_relevance_prefers_exact_name_over_scoped_and_summary_matches() {
        let mut results = [
            package_search_result(
                "npm:@askjo/camofox-browser",
                PackageReceiptSource::Npm {
                    package_name: "@askjo/camofox-browser".to_string(),
                },
                Some("Headless browser automation server and OpenClaw plugin"),
                Some(1),
            ),
            package_search_result(
                "npm:@qingchencloud/openclaw-zh",
                PackageReceiptSource::Npm {
                    package_name: "@qingchencloud/openclaw-zh".to_string(),
                },
                Some("OpenClaw localized release"),
                Some(2),
            ),
            package_search_result(
                "npm:openclaw",
                PackageReceiptSource::Npm {
                    package_name: "openclaw".to_string(),
                },
                Some("Multi-channel AI gateway"),
                None,
            ),
            package_search_result(
                "openclaw-cli",
                PackageReceiptSource::Formula {
                    root_formula: "openclaw-cli".to_string(),
                },
                Some("Your own personal AI assistant"),
                None,
            ),
        ];

        results.sort_by(|left, right| {
            compare_package_search_results_for_query("openclaw", left, right)
        });

        assert_eq!(results[0].package_name, "npm:openclaw");
        assert!(
            results
                .iter()
                .position(|result| result.package_name == "npm:@askjo/camofox-browser")
                > results
                    .iter()
                    .position(|result| result.package_name == "openclaw-cli")
        );
        assert!(
            results
                .iter()
                .position(|result| result.package_name == "npm:@askjo/camofox-browser")
                > results
                    .iter()
                    .position(|result| result.package_name == "npm:@qingchencloud/openclaw-zh")
        );
    }

    #[test]
    fn resolve_package_search_results_do_not_surface_isotopes() {
        let _env_lock = test_env_lock().lock().unwrap();
        let results = resolve_package_search_results(
            &Config {
                bottle_tag: "arm64_tahoe".to_string(),
            },
            "isotope:gh",
        )
        .unwrap();

        assert!(
            results
                .iter()
                .all(|result| result.package_name != "isotope:gh")
        );
    }

    #[test]
    fn resolve_package_search_results_surfaces_versioned_formula_aliases() {
        let _env_lock = test_env_lock().lock().unwrap();
        let (name, alias) = formula_index_entries()
            .unwrap()
            .iter()
            .find_map(|entry| {
                entry
                    .aliases
                    .iter()
                    .find(|alias| formula_versioned_base(alias).is_some())
                    .map(|alias| (entry.name.clone(), alias.clone()))
            })
            .expect("embedded db should carry at least one versioned formula alias");

        let results = resolve_package_search_results(
            &Config {
                bottle_tag: "arm64_tahoe".to_string(),
            },
            &name,
        )
        .unwrap();
        assert!(
            results.iter().any(|result| result.package_name == alias),
            "search should include the versioned formula alias display name"
        );
        assert!(
            results.iter().any(|result| {
                result.package_name == "node@24"
                    && result.source
                        == PackageReceiptSource::Formula {
                            root_formula: "node@24".to_string(),
                        }
            }),
            "search should include versioned formula catalog entries"
        );
        assert!(
            results
                .iter()
                .all(|result| result.package_name != "brew:node@24"),
            "search should not synthesize a duplicate recommendation row when the formula catalog has the versioned formula"
        );
    }

    #[test]
    fn formula_search_results_preserve_versioned_display_names() {
        let versioned =
            formula_search_results_for_query(&formula_index_entry("gcc@15", &[], &[]), "gcc");
        assert_eq!(
            versioned
                .iter()
                .map(|result| (
                    result.package_name.as_str(),
                    package_source_qualified_name(&result.source)
                ))
                .collect::<Vec<_>>(),
            vec![("gcc@15", "brew:gcc@15".to_string())]
        );
        let aliased = formula_search_results_for_query(
            &formula_index_entry("node", &["node@25"], &[]),
            "node@25",
        );
        assert_eq!(
            aliased
                .iter()
                .map(|result| (
                    result.package_name.as_str(),
                    package_source_qualified_name(&result.source)
                ))
                .collect::<Vec<_>>(),
            vec![("node@25", "brew:node@25".to_string())]
        );
        assert_eq!(aliased[0].install_package_names, ["node@25"]);
        let family = formula_search_results_for_query(
            &formula_index_entry("node", &["node@25"], &[]),
            "node",
        );
        assert_eq!(
            family
                .iter()
                .map(|result| result.package_name.as_str())
                .collect::<Vec<_>>(),
            vec!["node", "node@25"]
        );
    }

    #[test]
    fn formula_display_aliases_cover_major_and_minor_version_families() {
        let python = formula_index_entry("python@3.14", &["python@3"], &[]);
        assert_eq!(
            formula_display_alias(&python, "python", "3.14.1"),
            Some("python@3.14".to_string())
        );

        let node = formula_index_entry("node", &["node@25"], &[]);
        assert_eq!(
            formula_display_alias(&node, "node", "26.0.0"),
            Some("node@26".to_string())
        );
    }

    #[test]
    fn search_packages_paginates_results() {
        let _env_lock = test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let _env = TestEnvGuard::set(&[
            ("HOME", temp.path().to_str().unwrap()),
            ("GH_CONFIG_DIR", temp.path().to_str().unwrap()),
        ]);
        let formula_index = formula_index_entries().unwrap();
        let query = (1..=3)
            .find_map(|prefix_length| {
                let mut prefix_counts = std::collections::BTreeMap::new();
                for entry in formula_index {
                    if entry.name.len() < prefix_length {
                        continue;
                    }
                    let prefix = entry.name[..prefix_length].to_ascii_lowercase();
                    let count = prefix_counts.entry(prefix.clone()).or_insert(0usize);
                    *count += 1;
                    if *count >= 2 {
                        return Some(prefix);
                    }
                }
                None
            })
            .expect("embedded db should carry at least one shared prefix");

        let first_page = ops::search_packages(&query, 0, 1).unwrap();
        assert_eq!(first_page.packages.len(), 1);
        assert!(first_page.total_count >= 2);
        assert_eq!(first_page.next_offset, Some(1));

        let second_page = ops::search_packages(&query, 1, 1).unwrap();
        assert_eq!(second_page.packages.len(), 1);
        assert_eq!(second_page.total_count, first_page.total_count);
        assert_ne!(first_page.packages[0].name, second_page.packages[0].name);

        let vendor_page = ops::search_packages("av:bun", 0, 10).unwrap();
        let vendor_package = vendor_page
            .packages
            .iter()
            .find(|package| package.name == "av:bun")
            .expect("search should include qualified vendor packages");
        assert_eq!(
            vendor_package.source,
            PackageReceiptSource::Vendor {
                vendor_name: "bun".to_string(),
            }
        );
    }

    #[test]
    fn list_available_packages_paginates_results_and_requires_rank_metadata() {
        let _env_lock = test_env_lock().lock().unwrap();
        let db = crate::cli::load_db().unwrap();
        crate::cli::ensure_db_schema(&db).unwrap();

        let mut ranked = db
            .formulas
            .into_iter()
            .filter_map(|(name, metadata)| {
                metadata
                    .popularity
                    .map(|popularity| (popularity.rank, name))
            })
            .chain(db.casks.into_iter().filter_map(|(name, metadata)| {
                metadata
                    .popularity
                    .map(|popularity| (popularity.rank, name))
            }))
            .chain(db.npms.into_iter().filter_map(|(name, metadata)| {
                metadata
                    .popularity
                    .map(|popularity| (popularity.rank, npm_package_display_name(&name)))
            }))
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
        ranked.dedup_by(|left, right| left.1 == right.1);
        assert!(
            ranked.len() >= 2,
            "embedded db should carry ranked packages"
        );

        let ranked_page = ops::list_available_packages_matching_category(0, 1, None, None).unwrap();
        assert_eq!(ranked_page.packages.len(), 1);
        assert!(
            !ranked_page.category_counts.is_empty(),
            "ranked catalog response should include category counts"
        );

        let first_page =
            ops::list_available_packages_matching_category(0, 1, None, Some("az")).unwrap();
        assert_eq!(first_page.packages.len(), 1);
        assert_eq!(
            first_page.total_count,
            ops::list_available_packages_matching_category(0, 0, None, Some("az"))
                .unwrap()
                .total_count
        );
        assert_eq!(first_page.next_offset, Some(1));

        let second_page =
            ops::list_available_packages_matching_category(1, 1, None, Some("az")).unwrap();
        assert_eq!(second_page.packages.len(), 1);
        assert_eq!(second_page.total_count, first_page.total_count);

        let category = first_page
            .category_counts
            .keys()
            .find(|category| category.as_str() != "other")
            .or_else(|| first_page.category_counts.keys().next())
            .expect("available package response should include category counts")
            .to_string();
        let category_page =
            ops::list_available_packages_matching_category(0, 2, Some(&category), Some("az"))
                .unwrap();
        assert_eq!(
            category_page.total_count,
            first_page.category_counts[&category]
        );
        assert!(category_page.packages.iter().all(|package| {
            package
                .category
                .as_deref()
                .map(str::trim)
                .filter(|category| !category.is_empty())
                .unwrap_or("other")
                == category
        }));
        let alphabetical_category_page = ops::list_available_packages_matching_category(
            0,
            4,
            Some("developer-tools"),
            Some("az"),
        )
        .unwrap();
        let alphabetical_names = alphabetical_category_page
            .packages
            .iter()
            .map(|package| package.name.as_str())
            .collect::<Vec<_>>();
        let mut sorted_names = alphabetical_names.clone();
        sorted_names.sort_by(|left, right| compare_package_names_for_search_order(left, right));
        assert_eq!(alphabetical_names, sorted_names);

        let available_packages = resolve_available_package_results(&Config {
            bottle_tag: "arm64_tahoe".to_string(),
        })
        .unwrap();
        assert!(available_packages.iter().any(|package| {
            package.package_name == "av:bun"
                && package.source
                    == PackageReceiptSource::Vendor {
                        vendor_name: "bun".to_string(),
                    }
        }));
        assert!(available_packages.iter().any(|package| {
            package.package_name == "npm:coverage-npm"
                && package.source
                    == PackageReceiptSource::Npm {
                        package_name: "coverage-npm".to_string(),
                    }
        }));
    }

    #[test]
    fn list_pulse_packages_paginates_recent_results() {
        let _env_lock = test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let _env = TestEnvGuard::set(&[
            ("HOME", temp.path().to_str().unwrap()),
            ("GH_CONFIG_DIR", temp.path().to_str().unwrap()),
        ]);
        let db = crate::cli::load_db().unwrap();
        crate::cli::ensure_db_schema(&db).unwrap();
        let pulse_reference_time = OffsetDateTime::parse(&db.generated_at, &Rfc3339).unwrap();

        let mut recent = db
            .formulas
            .into_iter()
            .filter_map(|(name, metadata)| {
                metadata.last_updated_at.and_then(|last_updated_at| {
                    OffsetDateTime::parse(&last_updated_at, &Rfc3339)
                        .ok()
                        .map(|parsed| {
                            let pulse_kind = metadata.pulse_kind.and_then(|kind| {
                                if kind.eq_ignore_ascii_case("new")
                                    && pulse_reference_time.unix_timestamp()
                                        - parsed.unix_timestamp()
                                        > 7 * 24 * 60 * 60
                                {
                                    None
                                } else {
                                    Some(kind)
                                }
                            });
                            (pulse_kind, parsed, name)
                        })
                })
            })
            .chain(db.casks.into_iter().filter_map(|(name, metadata)| {
                metadata.last_updated_at.and_then(|last_updated_at| {
                    OffsetDateTime::parse(&last_updated_at, &Rfc3339)
                        .ok()
                        .map(|parsed| {
                            let pulse_kind = metadata.pulse_kind.and_then(|kind| {
                                if kind.eq_ignore_ascii_case("new")
                                    && pulse_reference_time.unix_timestamp()
                                        - parsed.unix_timestamp()
                                        > 7 * 24 * 60 * 60
                                {
                                    None
                                } else {
                                    Some(kind)
                                }
                            });
                            (pulse_kind, parsed, name)
                        })
                })
            }))
            .chain(db.npms.into_iter().filter_map(|(name, metadata)| {
                metadata.last_updated_at.and_then(|last_updated_at| {
                    OffsetDateTime::parse(&last_updated_at, &Rfc3339)
                        .ok()
                        .map(|parsed| {
                            let pulse_kind = metadata.pulse_kind.and_then(|kind| {
                                if kind.eq_ignore_ascii_case("new")
                                    && pulse_reference_time.unix_timestamp()
                                        - parsed.unix_timestamp()
                                        > 7 * 24 * 60 * 60
                                {
                                    None
                                } else {
                                    Some(kind)
                                }
                            });
                            (pulse_kind, parsed, npm_package_display_name(&name))
                        })
                })
            }))
            .collect::<Vec<_>>();
        recent.sort_by(|left, right| left.2.cmp(&right.2));
        recent.dedup_by(|left, right| left.2 == right.2);
        recent.sort_by(|left, right| {
            let left_pulse_key = match left.0.as_deref() {
                Some(kind) if kind.eq_ignore_ascii_case("new") => 0,
                _ => 1,
            };
            let right_pulse_key = match right.0.as_deref() {
                Some(kind) if kind.eq_ignore_ascii_case("new") => 0,
                _ => 1,
            };
            left_pulse_key
                .cmp(&right_pulse_key)
                .then_with(|| right.1.cmp(&left.1))
                .then_with(|| left.2.cmp(&right.2))
        });
        assert!(
            recent.len() >= 2,
            "embedded db should carry recent packages"
        );

        let first_page = ops::list_pulse_packages(0, 1).unwrap();
        assert_eq!(first_page.packages.len(), 1);
        assert_eq!(
            first_page.total_count,
            ops::list_pulse_packages(0, 0).unwrap().total_count
        );
        assert_eq!(first_page.next_offset, Some(1));
        assert_eq!(first_page.packages[0].name, recent[0].2);
        assert!(matches!(
            first_page.packages[0].pulse_kind.as_deref(),
            Some("new" | "updated")
        ));

        let second_page = ops::list_pulse_packages(1, 1).unwrap();
        assert_eq!(second_page.packages.len(), 1);
        assert_eq!(second_page.total_count, first_page.total_count);
        assert_eq!(second_page.packages[0].name, recent[1].2);

        let stale_new = ops::list_pulse_packages(0, 10)
            .unwrap()
            .packages
            .into_iter()
            .find(|package| package.name == "portable-libffi")
            .expect("coverage fixture should include a stale new formula");
        assert_eq!(stale_new.pulse_kind.as_deref(), Some("updated"));
    }

    #[test]
    fn list_pulse_packages_preserves_pulse_order_for_active_security_hazards() {
        let _env_lock = test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let fly_dir = temp.path().join(".fly");
        fs::create_dir_all(&fly_dir).unwrap();
        fs::write(fly_dir.join("config.yml"), "access_token: FlyV1 secret\n").unwrap();
        let _env = TestEnvGuard::set(&[
            ("HOME", temp.path().to_str().unwrap()),
            ("GH_CONFIG_DIR", temp.path().to_str().unwrap()),
        ]);

        let Some(state) = package_security_state_for_identifiers(["brew:flyctl".to_string()])
        else {
            return;
        };
        assert!(state.install_is_insecure);

        let expected = resolve_pulse_package_results(&Config {
            bottle_tag: String::new(),
        })
        .unwrap();
        assert_ne!(
            expected
                .first()
                .map(|package| package.package_name.as_str()),
            Some("flyctl"),
            "fixture must distinguish natural pulse order from hazard promotion"
        );

        let page = ops::list_pulse_packages(0, 3).unwrap();
        let expected_names = expected
            .iter()
            .take(3)
            .map(|package| package.package_name.as_str())
            .collect::<Vec<_>>();
        let actual_names = page
            .packages
            .iter()
            .map(|package| package.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(actual_names, expected_names);
    }

    #[test]
    fn list_geiger_packages_returns_actionable_detector_hits() {
        let _env_lock = test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        fs::write(
            temp.path().join("hosts.yml"),
            "github.com:\n    user: monalisa\n    oauth_token: ghp_secret\n",
        )
        .unwrap();
        let _env = TestEnvGuard::set(&[
            ("HOME", temp.path().to_str().unwrap()),
            ("GH_CONFIG_DIR", temp.path().to_str().unwrap()),
        ]);

        let page = ops::list_geiger_packages(0, 25).unwrap();
        assert!(page.packages.iter().any(|package| {
            package.security_state.as_ref().is_some_and(|state| {
                state.isotope_name == "gh" && (state.install_is_insecure || state.error.is_some())
            })
        }));
    }

    #[test]
    fn protocol_method_parses_list_pulse() {
        assert_eq!(
            core::ProtocolMethod::parse("packages.listPulse"),
            Some(core::ProtocolMethod::PackagesListPulse)
        );
        assert_eq!(
            core::ProtocolMethod::parse("packages.listGeiger"),
            Some(core::ProtocolMethod::PackagesListGeiger)
        );
    }

    #[test]
    fn vendor_npm_and_pip_version_fetchers_use_fixture_metadata_servers() {
        let _env_lock = test_env_lock().lock().unwrap();
        let (base, _server) = start_test_http_server(
            vec![
                (
                    "/repos/oven-sh/bun/releases/latest".to_string(),
                    br#"{"tag_name":"bun-v1.2.3"}"#.to_vec(),
                ),
                (
                    "/openclaw".to_string(),
                    br#"{
                        "description":"A test npm package",
                        "homepage":"https://example.test/openclaw",
                        "dist-tags":{"latest":"4.5.6"},
                        "versions":{
                            "4.5.6":{
                                "dist":{"tarball":"https://registry.npmjs.org/openclaw/-/openclaw-4.5.6.tgz"}
                            }
                        }
                    }"#
                    .to_vec(),
                ),
                (
                    "/psycopg2/json".to_string(),
                    br#"{
                        "info":{
                            "version":"2.9.10",
                            "summary":"A test PyPI package",
                            "home_page":"https://example.test/psycopg2"
                        }
                    }"#
                    .to_vec(),
                ),
            ],
            20,
        );
        let _endpoints = TestEndpointGuard::set(config::TestEndpointOverrides {
            github_api_root: Some(base.clone()),
            npm_registry_root: Some(base.clone()),
            pypi_root: Some(base.clone()),
            ..Default::default()
        });

        assert_eq!(bun::version().unwrap(), Version::parse("1.2.3").unwrap());
        assert_eq!(
            resolve_npm_latest_version("openclaw").unwrap(),
            "4.5.6".to_string()
        );
        assert_eq!(
            vendor::npm_tarball_url("openclaw", &Version::parse("4.5.6").unwrap()).unwrap(),
            "https://registry.npmjs.org/openclaw/-/openclaw-4.5.6.tgz".to_string()
        );
        assert_eq!(
            resolve_pip_latest_version("psycopg2").unwrap(),
            "2.9.10".to_string()
        );
        assert_eq!(
            resolve_npm_package_metadata("openclaw").unwrap(),
            PackageMetadata {
                description: Some("A test npm package".to_string()),
                homepage: Some("https://example.test/openclaw".to_string()),
            }
        );
        assert_eq!(
            resolve_pip_package_metadata("psycopg2").unwrap(),
            PackageMetadata {
                description: Some("A test PyPI package".to_string()),
                homepage: Some("https://example.test/psycopg2".to_string()),
            }
        );
    }

    #[test]
    fn download_and_install_helpers_handle_local_archives() {
        let temp = TempDir::new().unwrap();
        let tmp_root = temp.path().join("tmp");
        fs::create_dir_all(&tmp_root).unwrap();

        let bottle_archive = temp.path().join("sqlite.tar.gz");
        write_test_bottle_archive(
            &bottle_archive,
            "sqlite",
            "3.49.1",
            &[("bin/sqlite3", b"#!/bin/sh\n")],
        );
        let bottle_bytes = fs::read(&bottle_archive).unwrap();
        let bottle_sha = format!("{:x}", Sha256::digest(&bottle_bytes));
        let (bottle_base, bottle_server) = start_test_http_server(
            vec![("/sqlite.tar.gz".to_string(), bottle_bytes.clone())],
            1,
        );
        let bottle_spec = FormulaSpec {
            name: "sqlite".to_string(),
            bottle_sha256: bottle_sha,
            bottle_url: format!("{bottle_base}/sqlite.tar.gz"),
        };

        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "sqlite".to_string(),
            root_formula: "sqlite".to_string(),
            stable_root: temp.path().join("opt/sqlite"),
            install_root: temp.path().join("opt/sqlite"),
            tmp_root: tmp_root.clone(),
        };
        let state = resolve_dependency_install_state(
            std::slice::from_ref(&bottle_spec),
            &plan,
            "all",
            &tmp_root,
            None,
        )
        .unwrap();
        bottle_server.join().unwrap();
        assert_eq!(state.installs.len(), 1);
        assert_eq!(state.installs[0].keg_dir_name, "3.49.1");

        let vendor_archive = temp.path().join("vendor.tar.gz");
        write_test_archive(
            &vendor_archive,
            &[
                ("pkg/bin/tool", b"#!/bin/sh\n"),
                ("pkg/share/doc.txt", b"hello\n"),
            ],
        );
        let vendor_bytes = fs::read(&vendor_archive).unwrap();
        let (vendor_base, vendor_server) =
            start_test_http_server(vec![("/vendor.tar.gz".to_string(), vendor_bytes)], 2);

        let copy_file_version = Version::parse("9.8.7").unwrap();
        register_test_download_url(&copy_file_version, format!("{vendor_base}/vendor.tar.gz"));
        let copy_tree_version = Version::parse("9.8.8").unwrap();
        register_test_download_url(&copy_tree_version, format!("{vendor_base}/vendor.tar.gz"));

        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "tool".to_string(),
            root_formula: "tool".to_string(),
            stable_root: temp.path().join("opt/tool"),
            install_root: temp.path().join("opt/tool"),
            tmp_root: tmp_root.clone(),
        };
        fs::create_dir_all(&plan.install_root).unwrap();

        let copy_file_install = VendorInstall {
            package: vendor::VendorPackage {
                name: "tool",
                dependencies: &[],
                executables: &["tool"],
                version: fake_vendor_version,
                download_url: Some(test_download_url),
                install: fake_vendor_install_strategy,
            },
            version: copy_file_version,
        };
        install_vendor_copy_file(
            &plan,
            &[],
            &copy_file_install,
            "pkg/bin/tool",
            "bin",
            Some("tool"),
            0o755,
            &["bin".to_string()],
            None,
        )
        .unwrap();
        assert!(is_executable(&plan.install_root.join("bin/tool")));

        let tree_plan = InstallPlan {
            mode: Mode::I,
            package_name: "tree".to_string(),
            root_formula: "tree".to_string(),
            stable_root: temp.path().join("opt/tree"),
            install_root: temp.path().join("opt/tree"),
            tmp_root,
        };
        fs::create_dir_all(&tree_plan.install_root).unwrap();
        let copy_tree_install = VendorInstall {
            package: vendor::VendorPackage {
                name: "tree",
                dependencies: &[],
                executables: &["tool"],
                version: fake_vendor_version,
                download_url: Some(test_download_url),
                install: fake_vendor_install_strategy,
            },
            version: copy_tree_version,
        };
        install_vendor_copy_tree(&tree_plan, &copy_tree_install, "pkg", None).unwrap();
        vendor_server.join().unwrap();
        assert!(tree_plan.install_root.join("bin/tool").is_file());
        assert!(tree_plan.install_root.join("share").is_dir());
    }

    #[test]
    fn run_i_package_keeps_downloaded_bottles_alive_until_extract() {
        let _env_lock = test_env_lock().lock().unwrap();
        let _package_lock = acquire_package_mutation_lock().unwrap();
        let package_name = "archive-lifetime-test";
        let auto_package_name = "auto-formula-dispatch-test";
        let opt_root = opt_pkg_root();
        let bin_root = managed_bin_root();
        let install_root = opt_root.join(package_name);
        let auto_install_root = opt_root.join(auto_package_name);
        let stub_path = bin_root.join(package_name);
        let auto_stub_path = bin_root.join(auto_package_name);
        for path in [
            &install_root,
            &auto_install_root,
            &stub_path,
            &auto_stub_path,
        ] {
            if fs::symlink_metadata(path).is_ok() {
                remove_path(path).unwrap();
            }
        }

        let temp = TempDir::new().unwrap();
        let bottle_archive = temp.path().join("archive-lifetime-test.tar.gz");
        write_test_bottle_archive(
            &bottle_archive,
            package_name,
            "1.0.0",
            &[("bin/archive-lifetime-test", b"#!/bin/sh\nprintf ok\n")],
        );
        let bottle_bytes = fs::read(&bottle_archive).unwrap();
        let bottle_sha = format!("{:x}", Sha256::digest(&bottle_bytes));
        let auto_bottle_archive = temp.path().join("auto-formula-dispatch-test.tar.gz");
        write_test_bottle_archive(
            &auto_bottle_archive,
            auto_package_name,
            "1.0.0",
            &[(
                "bin/auto-formula-dispatch-test",
                b"#!/bin/sh\nprintf auto\n",
            )],
        );
        let auto_bottle_bytes = fs::read(&auto_bottle_archive).unwrap();
        let auto_bottle_sha = format!("{:x}", Sha256::digest(&auto_bottle_bytes));
        let bottle_server = start_counting_test_http_server(vec![
            ("/bottle.tar.gz".to_string(), bottle_bytes),
            ("/auto-bottle.tar.gz".to_string(), auto_bottle_bytes),
        ]);
        let formula_json = serde_json::to_vec(&serde_json::json!({
            "versions": { "stable": "1.0.0" },
            "dependencies": [],
            "bottle": {
                "stable": {
                    "files": {
                        "all": {
                            "sha256": bottle_sha,
                            "url": format!("{}/bottle.tar.gz", bottle_server.base_url),
                        }
                    }
                }
            },
            "disabled": false
        }))
        .unwrap();
        let auto_formula_json = serde_json::to_vec(&serde_json::json!({
            "versions": { "stable": "1.0.0" },
            "dependencies": [],
            "bottle": {
                "stable": {
                    "files": {
                        "all": {
                            "sha256": auto_bottle_sha,
                            "url": format!("{}/auto-bottle.tar.gz", bottle_server.base_url),
                        }
                    }
                }
            },
            "disabled": false
        }))
        .unwrap();
        let formula_server = start_counting_test_http_server(vec![
            (format!("/{package_name}.json"), formula_json),
            (format!("/{auto_package_name}.json"), auto_formula_json),
        ]);
        let _endpoints = TestEndpointGuard::set(config::TestEndpointOverrides {
            formula_api_root: Some(formula_server.base_url.clone()),
            ..Default::default()
        });

        run_i_package(
            &Config {
                bottle_tag: "all".to_string(),
            },
            RequestedPackage::HomebrewFormula(package_name.to_string()),
            InstallOptions {
                intent: InstallIntent::Install,
            },
        )
        .unwrap();
        run_i_package(
            &Config {
                bottle_tag: "all".to_string(),
            },
            RequestedPackage::Auto(auto_package_name.to_string()),
            InstallOptions {
                intent: InstallIntent::Install,
            },
        )
        .unwrap();

        assert!(is_executable(
            &install_root.join("bin/archive-lifetime-test")
        ));
        assert!(is_executable(&stub_path));
        assert!(is_executable(
            &auto_install_root.join("bin/auto-formula-dispatch-test")
        ));
        assert!(is_executable(&auto_stub_path));

        for path in [
            &install_root,
            &auto_install_root,
            &stub_path,
            &auto_stub_path,
        ] {
            if fs::symlink_metadata(path).is_ok() {
                remove_path(path).unwrap();
            }
        }
    }

    #[test]
    fn run_i_formula_update_keeps_dependency_bottles_alive_until_parallel_extract() {
        let _env_lock = test_env_lock().lock().unwrap();
        let _package_lock = acquire_package_mutation_lock().unwrap();
        let package_name = "ripgrep-lifetime-test";
        let dependency_name = "pcre2-lifetime-test";
        let opt_root = opt_pkg_root();
        let bin_root = managed_bin_root();
        let install_root = opt_root.join(package_name);
        let stub_path = bin_root.join(package_name);
        for path in [&install_root, &stub_path] {
            if fs::symlink_metadata(path).is_ok() {
                remove_path(path).unwrap();
            }
        }

        fs::create_dir_all(install_root.join("bin")).unwrap();
        fs::write(install_root.join("bin/ripgrep-lifetime-test"), b"old").unwrap();
        write_package_receipt(
            &install_root.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: package_name.to_string(),
                version: "0.9.0".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: package_name.to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        write_install_receipt(
            &install_root
                .join(RECEIPTS_DIR)
                .join(format!("{dependency_name}.json")),
            &InstallReceipt {
                formula: dependency_name.to_string(),
                version: "0.9.0".to_string(),
                bottle_sha256: "old-dep-sha".to_string(),
                bottle_tag: "all".to_string(),
                owned_paths: vec!["lib/libpcre2-test.dylib".to_string()],
            },
        )
        .unwrap();
        write_install_receipt(
            &install_root
                .join(RECEIPTS_DIR)
                .join(format!("{package_name}.json")),
            &InstallReceipt {
                formula: package_name.to_string(),
                version: "0.9.0".to_string(),
                bottle_sha256: "old-root-sha".to_string(),
                bottle_tag: "all".to_string(),
                owned_paths: vec!["bin/ripgrep-lifetime-test".to_string()],
            },
        )
        .unwrap();

        let temp = TempDir::new().unwrap();
        let dep_archive = temp.path().join("pcre2-lifetime-test.tar.gz");
        write_test_bottle_archive(
            &dep_archive,
            dependency_name,
            "1.0.0",
            &[("lib/libpcre2-test.dylib", b"dep")],
        );
        let root_archive = temp.path().join("ripgrep-lifetime-test.tar.gz");
        write_test_bottle_archive(
            &root_archive,
            package_name,
            "1.0.0",
            &[("bin/ripgrep-lifetime-test", b"#!/bin/sh\nprintf rg\n")],
        );
        let dep_bytes = fs::read(&dep_archive).unwrap();
        let root_bytes = fs::read(&root_archive).unwrap();
        let dep_sha = format!("{:x}", Sha256::digest(&dep_bytes));
        let root_sha = format!("{:x}", Sha256::digest(&root_bytes));
        let bottle_server = start_counting_test_http_server(vec![
            ("/pcre2.tar.gz".to_string(), dep_bytes),
            ("/ripgrep.tar.gz".to_string(), root_bytes),
        ]);
        let dep_json = serde_json::to_vec(&serde_json::json!({
            "versions": { "stable": "1.0.0" },
            "dependencies": [],
            "bottle": {
                "stable": {
                    "files": {
                        "all": {
                            "sha256": dep_sha,
                            "url": format!("{}/pcre2.tar.gz", bottle_server.base_url),
                        }
                    }
                }
            },
            "disabled": false
        }))
        .unwrap();
        let root_json = serde_json::to_vec(&serde_json::json!({
            "versions": { "stable": "1.0.0" },
            "dependencies": [dependency_name],
            "bottle": {
                "stable": {
                    "files": {
                        "all": {
                            "sha256": root_sha,
                            "url": format!("{}/ripgrep.tar.gz", bottle_server.base_url),
                        }
                    }
                }
            },
            "disabled": false
        }))
        .unwrap();
        let formula_server = start_counting_test_http_server(vec![
            (format!("/{dependency_name}.json"), dep_json),
            (format!("/{package_name}.json"), root_json),
        ]);
        let _endpoints = TestEndpointGuard::set(config::TestEndpointOverrides {
            formula_api_root: Some(formula_server.base_url.clone()),
            ..Default::default()
        });

        run_i_formula(
            &Config {
                bottle_tag: "all".to_string(),
            },
            package_name.to_string(),
            package_name.to_string(),
            InstallIntent::Update,
            None,
        )
        .unwrap();

        assert!(is_executable(
            &install_root.join("bin/ripgrep-lifetime-test")
        ));
        assert!(install_root.join("lib/libpcre2-test.dylib").is_file());

        for path in [&install_root, &stub_path] {
            if fs::symlink_metadata(path).is_ok() {
                remove_path(path).unwrap();
            }
        }
    }

    #[test]
    fn run_i_vendor_installs_from_local_archive_and_writes_receipts_and_stubs() {
        let _env_lock = test_env_lock().lock().unwrap();
        let _package_lock = acquire_package_mutation_lock().unwrap();
        let package_name = "coverage-vendor";
        let opt_root = opt_pkg_root();
        let install_root = opt_root.join(package_name);
        let bin_root = managed_bin_root();
        let stub_path = bin_root.join(package_name);
        for path in [&install_root, &stub_path] {
            if fs::symlink_metadata(path).is_ok() {
                remove_path(path).unwrap();
            }
        }

        let temp = TempDir::new().unwrap();
        let vendor_archive = temp.path().join("coverage-vendor.tar.gz");
        write_test_archive(
            &vendor_archive,
            &[("pkg/bin/coverage-vendor", b"#!/bin/sh\nprintf coverage\n")],
        );
        let vendor_bytes = fs::read(&vendor_archive).unwrap();
        let mut vendor_server =
            start_counting_test_http_server(vec![("/vendor.tar.gz".to_string(), vendor_bytes)]);
        let vendor_base = vendor_server.base_url.clone();
        let version = Version::parse("0.0.0").unwrap();
        register_test_download_url(&version, format!("{vendor_base}/vendor.tar.gz"));

        let events = Arc::new(Mutex::new(Vec::<ProgressEvent>::new()));
        let callback_events = Arc::clone(&events);
        let callback: Arc<Mutex<Box<ProgressCallback>>> =
            Arc::new(Mutex::new(Box::new(move |event| {
                callback_events.lock().unwrap().push(event);
            })));

        run_i_vendor(
            &Config {
                bottle_tag: "all".to_string(),
            },
            package_name.to_string(),
            vendor::VendorPackage {
                name: package_name,
                dependencies: &[],
                executables: &["coverage-vendor"],
                version: fake_vendor_version,
                download_url: Some(test_download_url),
                install: coverage_vendor_install_strategy,
            },
            InstallIntent::Install,
            Some(callback),
        )
        .unwrap();

        let receipt = load_package_receipt(&install_root.join(ROOT_RECEIPT))
            .unwrap()
            .unwrap();
        assert_eq!(receipt.package_name, package_name);
        assert_eq!(receipt.version, "0.0.0");
        assert_eq!(
            receipt.source,
            PackageReceiptSource::Vendor {
                vendor_name: package_name.to_string(),
            }
        );
        assert!(is_executable(&install_root.join("bin/coverage-vendor")));
        assert!(is_executable(&stub_path));
        assert_eq!(
            load_stub_manifest(&install_root.join(STUB_MANIFEST))
                .unwrap()
                .stubs,
            vec![package_name.to_string()]
        );
        assert!(events.lock().unwrap().iter().any(
            |event| matches!(event, ProgressEvent::Completed { package } if package == package_name)
        ));

        fs::remove_file(install_root.join("bin/coverage-vendor")).unwrap();
        let reinstall_events = Arc::new(Mutex::new(Vec::<ProgressEvent>::new()));
        let reinstall_callback_events = Arc::clone(&reinstall_events);
        let reinstall_callback: Arc<Mutex<Box<ProgressCallback>>> =
            Arc::new(Mutex::new(Box::new(move |event| {
                reinstall_callback_events.lock().unwrap().push(event);
            })));

        run_i_vendor(
            &Config {
                bottle_tag: "all".to_string(),
            },
            package_name.to_string(),
            vendor::VendorPackage {
                name: package_name,
                dependencies: &[],
                executables: &["coverage-vendor"],
                version: fake_vendor_version,
                download_url: Some(test_download_url),
                install: coverage_vendor_install_strategy,
            },
            InstallIntent::Install,
            Some(reinstall_callback),
        )
        .unwrap();
        assert!(is_executable(&install_root.join("bin/coverage-vendor")));
        assert!(reinstall_events.lock().unwrap().iter().any(
            |event| matches!(event, ProgressEvent::Completed { package } if package == package_name)
        ));

        let current_events = Arc::new(Mutex::new(Vec::<ProgressEvent>::new()));
        let current_callback_events = Arc::clone(&current_events);
        let current_callback: Arc<Mutex<Box<ProgressCallback>>> =
            Arc::new(Mutex::new(Box::new(move |event| {
                current_callback_events.lock().unwrap().push(event);
            })));
        run_i_vendor(
            &Config {
                bottle_tag: "all".to_string(),
            },
            package_name.to_string(),
            vendor::VendorPackage {
                name: package_name,
                dependencies: &[],
                executables: &["coverage-vendor"],
                version: fake_vendor_version,
                download_url: Some(test_download_url),
                install: coverage_vendor_install_strategy,
            },
            InstallIntent::Install,
            Some(current_callback),
        )
        .unwrap();
        let current_events = current_events.lock().unwrap();
        assert!(current_events.iter().any(
            |event| matches!(event, ProgressEvent::Completed { package } if package == package_name)
        ));
        vendor_server.stop().unwrap();
        let vendor_requests = vendor_server.request_count();
        assert_eq!(vendor_requests, 3);
        remove_existing_package_install(&opt_root, package_name, &bin_root).unwrap();
    }

    #[test]
    fn run_i_vendor_reports_missing_download_url() {
        let _env_lock = test_env_lock().lock().unwrap();
        let _package_lock = acquire_package_mutation_lock().unwrap();
        let opt_root = opt_pkg_root();
        let bin_root = managed_bin_root();
        let package_name = "coverage-vendor-missing-url";
        let install_root = package_install_root(&opt_root, package_name).unwrap();
        if fs::symlink_metadata(&install_root).is_ok() {
            remove_existing_package_install(&opt_root, package_name, &bin_root).unwrap();
        }
        let package = fake_vendor_install(package_name, &["coverage-vendor"], "1.2.3").package;

        let err = run_i_vendor(
            &Config {
                bottle_tag: "all".to_string(),
            },
            package_name.to_string(),
            package,
            InstallIntent::Install,
            None,
        )
        .unwrap_err();

        assert!(err.contains("has no download URL"));
        if fs::symlink_metadata(&install_root).is_ok() {
            remove_existing_package_install(&opt_root, package_name, &bin_root).unwrap();
        }
    }

    #[test]
    fn run_i_vendor_skips_current_root_and_syncs_stubs() {
        let _env_lock = test_env_lock().lock().unwrap();
        let _package_lock = acquire_package_mutation_lock().unwrap();
        let opt_root = opt_pkg_root();
        let bin_root = managed_bin_root();
        let package_name = "coverage-vendor-current";
        let install_root = package_install_root(&opt_root, package_name).unwrap();
        if fs::symlink_metadata(&install_root).is_ok() {
            remove_existing_package_install(&opt_root, package_name, &bin_root).unwrap();
        }
        let stub = bin_root.join(package_name);
        if fs::symlink_metadata(&stub).is_ok() {
            remove_path(&stub).unwrap();
        }

        let plan = InstallPlan::for_i(package_name.to_string(), package_name.to_string());
        fs::create_dir_all(plan.install_root.join("bin")).unwrap();
        let executable = plan.install_root.join("bin").join(package_name);
        fs::write(&executable, b"#!/bin/sh\nprintf vendor\n").unwrap();
        let mut permissions = fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&executable, permissions).unwrap();
        write_package_receipt(
            &plan.root_receipt_path(),
            &PackageReceipt {
                package_name: package_name.to_string(),
                version: "0.0.0".to_string(),
                source: PackageReceiptSource::Vendor {
                    vendor_name: package_name.to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        write_root_ownership_manifest(&plan, vec![package_name.to_string()]).unwrap();

        let package = fake_vendor_install(
            "coverage-vendor-current",
            &["coverage-vendor-current"],
            "0.0.0",
        )
        .package;
        run_i_vendor(
            &Config {
                bottle_tag: "all".to_string(),
            },
            package_name.to_string(),
            package,
            InstallIntent::Update,
            None,
        )
        .unwrap();

        assert!(is_executable(&stub));
        remove_existing_package_install(&opt_root, package_name, &bin_root).unwrap();
    }

    #[test]
    fn run_i_npm_and_pip_install_with_local_formula_tools() {
        let _env_lock = test_env_lock().lock().unwrap();
        let _package_lock = acquire_package_mutation_lock().unwrap();
        let opt_root = opt_pkg_root();
        let bin_root = managed_bin_root();
        for package_name in ["npm:coverage-npm", "pip:coverage-pip"] {
            let install_root = package_install_root(&opt_root, package_name).unwrap();
            if fs::symlink_metadata(&install_root).is_ok() {
                remove_path(&install_root).unwrap();
            }
        }
        for stub in ["coverage-npm", "coverage-pip"] {
            let path = bin_root.join(stub);
            if fs::symlink_metadata(&path).is_ok() {
                remove_path(&path).unwrap();
            }
        }

        let temp = TempDir::new().unwrap();
        let node_archive = temp.path().join("node.tar.gz");
        let fake_npm = br#"#!/bin/sh
set -eu
prefix=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--prefix" ]; then
    prefix="$2"
    shift 2
  else
    shift
  fi
done
/bin/mkdir -p "$prefix/bin" "$prefix/lib/node_modules/coverage-npm"
/bin/cat > "$prefix/bin/coverage-npm" <<'EOF'
#!/bin/sh
printf 'coverage-npm\n'
EOF
/bin/chmod +x "$prefix/bin/coverage-npm"
"#;
        write_test_bottle_archive(&node_archive, "node", "1.0.0", &[("bin/npm", fake_npm)]);
        let node_bytes = fs::read(&node_archive).unwrap();
        let node_sha = format!("{:x}", Sha256::digest(&node_bytes));

        let python_archive = temp.path().join("python.tar.gz");
        let fake_python = br#"#!/bin/sh
set -eu
if [ "${1:-}" = "-m" ] && [ "${2:-}" = "venv" ]; then
  for last do :; done
  /bin/mkdir -p "$last/bin"
  /bin/cat > "$last/bin/python" <<'PY'
#!/bin/sh
if [ "${1:-}" = "-c" ]; then
  printf '["coverage-pip"]\n'
fi
PY
  /bin/chmod +x "$last/bin/python"
  /bin/cat > "$last/bin/pip" <<'PIP'
#!/bin/sh
dir=$(/usr/bin/dirname "$0")
/bin/cat > "$dir/coverage-pip" <<'ENTRY'
#!/bin/sh
printf 'coverage-pip\n'
ENTRY
/bin/chmod +x "$dir/coverage-pip"
PIP
  /bin/chmod +x "$last/bin/pip"
  /usr/bin/touch "$last/pyvenv.cfg"
fi
"#;
        write_test_bottle_archive(
            &python_archive,
            "python@3.14",
            "3.14.0",
            &[("bin/python3", fake_python)],
        );
        let python_bytes = fs::read(&python_archive).unwrap();
        let python_sha = format!("{:x}", Sha256::digest(&python_bytes));

        let (bottle_base, bottle_server) = start_test_http_server(
            vec![
                ("/node.tar.gz".to_string(), node_bytes),
                ("/python.tar.gz".to_string(), python_bytes),
            ],
            15,
        );
        let node_json = serde_json::to_vec(&serde_json::json!({
            "versions": { "stable": "1.0.0" },
            "dependencies": [],
            "bottle": {
                "stable": {
                    "files": {
                        "all": {
                            "sha256": node_sha,
                            "url": format!("{bottle_base}/node.tar.gz"),
                        }
                    }
                }
            },
            "disabled": false
        }))
        .unwrap();
        let python_json = serde_json::to_vec(&serde_json::json!({
            "versions": { "stable": "3.14.0" },
            "dependencies": [],
            "bottle": {
                "stable": {
                    "files": {
                        "all": {
                            "sha256": python_sha,
                            "url": format!("{bottle_base}/python.tar.gz"),
                        }
                    }
                }
            },
            "disabled": false
        }))
        .unwrap();

        let (base, server) = start_test_http_server(
            vec![
                ("/node.json".to_string(), node_json),
                ("/python@3.14.json".to_string(), python_json),
                (
                    "/coverage-npm".to_string(),
                    br#"{
                        "description":"Coverage npm package",
                        "homepage":"https://example.test/coverage-npm",
                        "dist-tags":{"latest":"1.2.3"},
                        "versions":{
                            "1.2.3":{
                                "dist":{"tarball":"https://example.test/coverage-npm.tgz"}
                            }
                        }
                    }"#
                    .to_vec(),
                ),
                (
                    "/coverage-pip/json".to_string(),
                    br#"{
                        "info":{
                            "version":"2.3.4",
                            "summary":"Coverage pip package",
                            "home_page":"https://example.test/coverage-pip"
                        }
                    }"#
                    .to_vec(),
                ),
            ],
            30,
        );
        let _endpoints = TestEndpointGuard::set(config::TestEndpointOverrides {
            formula_api_root: Some(base.clone()),
            npm_registry_root: Some(base.clone()),
            pypi_root: Some(base.clone()),
            ..Default::default()
        });

        run_i_package(
            &Config {
                bottle_tag: "all".to_string(),
            },
            RequestedPackage::Auto("coverage-npm".to_string()),
            InstallOptions {
                intent: InstallIntent::Install,
            },
        )
        .unwrap();
        run_i_package(
            &Config {
                bottle_tag: "all".to_string(),
            },
            RequestedPackage::PipPackage("coverage-pip".to_string()),
            InstallOptions {
                intent: InstallIntent::Install,
            },
        )
        .unwrap();

        let npm_root = opt_root.join("npm/coverage-npm");
        let pip_root = opt_root.join("pip/coverage-pip");
        assert!(is_executable(&npm_root.join("bin/coverage-npm")));
        assert!(is_executable(&pip_root.join("bin/coverage-pip")));
        assert!(is_executable(&bin_root.join("coverage-npm")));
        assert!(is_executable(&bin_root.join("coverage-pip")));
        assert_eq!(
            load_package_receipt(&npm_root.join(ROOT_RECEIPT))
                .unwrap()
                .unwrap()
                .version,
            "1.2.3"
        );
        assert_eq!(
            load_package_receipt(&pip_root.join(ROOT_RECEIPT))
                .unwrap()
                .unwrap()
                .version,
            "2.3.4"
        );

        fs::remove_file(npm_root.join("bin/coverage-npm")).unwrap();
        fs::remove_file(pip_root.join("bin/coverage-pip")).unwrap();

        let reinstall_events = Arc::new(Mutex::new(Vec::<ProgressEvent>::new()));
        let npm_reinstall_events = Arc::clone(&reinstall_events);
        let npm_callback: Arc<Mutex<Box<ProgressCallback>>> =
            Arc::new(Mutex::new(Box::new(move |event| {
                npm_reinstall_events.lock().unwrap().push(event);
            })));
        run_i_npm(
            &Config {
                bottle_tag: "all".to_string(),
            },
            "npm:coverage-npm".to_string(),
            "coverage-npm".to_string(),
            None,
            InstallOptions {
                intent: InstallIntent::Install,
            },
            InstallIntent::Install,
            Some(npm_callback),
        )
        .unwrap();

        let pip_reinstall_events = Arc::clone(&reinstall_events);
        let pip_callback: Arc<Mutex<Box<ProgressCallback>>> =
            Arc::new(Mutex::new(Box::new(move |event| {
                pip_reinstall_events.lock().unwrap().push(event);
            })));
        run_i_pip(
            &Config {
                bottle_tag: "all".to_string(),
            },
            "pip:coverage-pip".to_string(),
            "coverage-pip".to_string(),
            InstallIntent::Install,
            Some(pip_callback),
        )
        .unwrap();

        assert!(is_executable(&npm_root.join("bin/coverage-npm")));
        assert!(is_executable(&pip_root.join("bin/coverage-pip")));
        let reinstall_events = reinstall_events.lock().unwrap();
        assert!(reinstall_events.iter().any(
            |event| matches!(event, ProgressEvent::Completed { package } if package == "npm:coverage-npm")
        ));
        assert!(reinstall_events.iter().any(
            |event| matches!(event, ProgressEvent::Completed { package } if package == "pip:coverage-pip")
        ));

        run_i_npm(
            &Config {
                bottle_tag: "all".to_string(),
            },
            "npm:coverage-npm".to_string(),
            "coverage-npm".to_string(),
            None,
            InstallOptions {
                intent: InstallIntent::Update,
            },
            InstallIntent::Update,
            None,
        )
        .unwrap();
        run_i_pip(
            &Config {
                bottle_tag: "all".to_string(),
            },
            "pip:coverage-pip".to_string(),
            "coverage-pip".to_string(),
            InstallIntent::Update,
            None,
        )
        .unwrap();

        drain_test_server(&base, "/coverage-npm", 30);
        drain_test_server(&bottle_base, "/node.tar.gz", 15);
        server.join().unwrap();
        bottle_server.join().unwrap();
        remove_existing_package_install(&opt_root, "npm:coverage-npm", &bin_root).unwrap();
        remove_existing_package_install(&opt_root, "pip:coverage-pip", &bin_root).unwrap();
    }

    #[test]
    fn run_i_npm_repairs_current_but_unlaunchable_node_runtime() {
        let _env_lock = test_env_lock().lock().unwrap();
        let _package_lock = acquire_package_mutation_lock().unwrap();
        let opt_root = opt_pkg_root();
        let bin_root = managed_bin_root();
        let package_name = "npm:runtime-probe";
        let npm_package = "runtime-probe";
        let install_root = package_install_root(&opt_root, package_name).unwrap();
        if fs::symlink_metadata(&install_root).is_ok() {
            remove_existing_package_install(&opt_root, package_name, &bin_root).unwrap();
        }
        let stub = bin_root.join(npm_package);
        if fs::symlink_metadata(&stub).is_ok() {
            remove_path(&stub).unwrap();
        }

        fs::create_dir_all(install_root.join("bin")).unwrap();
        fs::write(
            install_root.join("bin/node"),
            b"#!/bin/sh\n# broken-node\nexit 78\n",
        )
        .unwrap();
        fs::write(
            install_root.join("bin/npm"),
            b"#!/usr/bin/env node\n# broken-npm\nexit 78\n",
        )
        .unwrap();
        fs::write(
            install_root.join("bin/runtime-probe"),
            b"#!/bin/sh\nprintf 'runtime-probe\\n'\n",
        )
        .unwrap();
        for path in [
            install_root.join("bin/node"),
            install_root.join("bin/npm"),
            install_root.join("bin/runtime-probe"),
        ] {
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).unwrap();
        }

        let temp = TempDir::new().unwrap();
        let node_archive = temp.path().join("node.tar.gz");
        let fake_node = br#"#!/bin/sh
if [ "${1:-}" = "--version" ]; then
  printf 'repaired-node\n'
  exit 0
fi
script="${1:-}"
if [ -z "$script" ]; then
  exit 0
fi
shift
exec /bin/sh "$script" "$@"
"#;
        let fake_npm = br#"#!/usr/bin/env node
set -eu
if [ "${1:-}" = "--version" ]; then
  printf 'repaired-npm\n'
  exit 0
fi
prefix=
dry_run=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix)
      prefix="$2"
      shift 2
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    *)
      shift
      ;;
  esac
done
if [ "$dry_run" = 1 ]; then
  exit 0
fi
/bin/mkdir -p "$prefix/bin" "$prefix/lib/node_modules/runtime-probe"
/bin/cat > "$prefix/bin/runtime-probe" <<'EOF'
#!/bin/sh
printf 'runtime-probe\n'
EOF
/bin/chmod +x "$prefix/bin/runtime-probe"
"#;
        write_test_bottle_archive(
            &node_archive,
            "node",
            "1.0.0",
            &[("bin/node", fake_node), ("bin/npm", fake_npm)],
        );
        let node_bytes = fs::read(&node_archive).unwrap();
        let node_sha = format!("{:x}", Sha256::digest(&node_bytes));
        let node_spec = InstalledFormula {
            spec: FormulaSpec {
                name: "node".to_string(),
                bottle_sha256: node_sha.clone(),
                bottle_url: "https://example.invalid/node.tar.gz".to_string(),
            },
            keg_dir_name: "1.0.0".to_string(),
            archive_path: PathBuf::new(),
        };
        write_receipt_with_owned_paths(
            &install_root.join(RECEIPTS_DIR).join("node.json"),
            &node_spec,
            "all",
            vec!["bin/node".to_string(), "bin/npm".to_string()],
        )
        .unwrap();
        write_package_receipt(
            &install_root.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: package_name.to_string(),
                version: "1.2.3".to_string(),
                source: PackageReceiptSource::Npm {
                    package_name: npm_package.to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();

        let (bottle_base, bottle_server) =
            start_test_http_server(vec![("/node.tar.gz".to_string(), node_bytes)], 5);
        let node_json = serde_json::to_vec(&serde_json::json!({
            "versions": { "stable": "1.0.0" },
            "dependencies": [],
            "bottle": {
                "stable": {
                    "files": {
                        "all": {
                            "sha256": node_sha,
                            "url": format!("{bottle_base}/node.tar.gz"),
                        }
                    }
                }
            },
            "disabled": false
        }))
        .unwrap();
        let package_json = br#"{
            "description":"Runtime probe npm package",
            "homepage":"https://example.test/runtime-probe",
            "dist-tags":{"latest":"1.2.3"},
            "versions":{
                "1.2.3":{
                    "dist":{"tarball":"https://example.test/runtime-probe.tgz"}
                }
            }
        }"#
        .to_vec();
        let (base, server) = start_test_http_server(
            vec![
                ("/node.json".to_string(), node_json),
                ("/runtime-probe".to_string(), package_json),
            ],
            10,
        );
        let _endpoints = TestEndpointGuard::set(config::TestEndpointOverrides {
            formula_api_root: Some(base.clone()),
            npm_registry_root: Some(base.clone()),
            ..Default::default()
        });

        run_i_npm(
            &Config {
                bottle_tag: "all".to_string(),
            },
            package_name.to_string(),
            npm_package.to_string(),
            None,
            InstallOptions {
                intent: InstallIntent::Update,
            },
            InstallIntent::Update,
            None,
        )
        .unwrap();

        assert!(
            String::from_utf8(fs::read(install_root.join("bin/node")).unwrap())
                .unwrap()
                .contains("repaired-node")
        );
        assert!(is_executable(&install_root.join("bin/runtime-probe")));
        assert!(is_executable(&bin_root.join("runtime-probe")));

        drain_test_server(&base, "/runtime-probe", 10);
        drain_test_server(&bottle_base, "/node.tar.gz", 5);
        server.join().unwrap();
        bottle_server.join().unwrap();
        remove_existing_package_install(&opt_root, package_name, &bin_root).unwrap();
    }

    #[test]
    fn unpack_vendor_archive_accepts_plain_tar_with_tgz_extension() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("plain.tgz");
        write_test_plain_tar_archive(
            &archive,
            &[
                ("pkg/bin/tool", b"#!/bin/sh\n"),
                ("pkg/share/doc.txt", b"hello\n"),
            ],
        );
        let destination = temp.path().join("out");
        fs::create_dir_all(&destination).unwrap();

        unpack_vendor_archive(&archive, &destination, "plain-tgz").unwrap();

        assert!(destination.join("pkg/bin/tool").is_file());
        assert!(destination.join("pkg/share/doc.txt").is_file());
    }

    #[test]
    fn unpack_vendor_archive_reports_unknown_and_zip_failures() {
        let temp = TempDir::new().unwrap();
        let destination = temp.path().join("out");
        fs::create_dir_all(&destination).unwrap();
        let unsupported = temp.path().join("payload.bin");
        fs::write(&unsupported, b"payload").unwrap();

        assert!(
            unpack_vendor_archive(&unsupported, &destination, "payload")
                .unwrap_err()
                .contains("unsupported vendor archive format")
        );

        #[cfg(target_os = "macos")]
        {
            let missing_zip = temp.path().join("missing.zip");
            assert!(
                unpack_vendor_archive(&missing_zip, &destination, "missing")
                    .unwrap_err()
                    .contains("failed to unpack vendor archive")
            );
        }
    }

    #[test]
    fn install_cask_root_accepts_direct_binary_payload() {
        let temp = TempDir::new().unwrap();
        let tmp_root = temp.path().join("tmp");
        fs::create_dir_all(&tmp_root).unwrap();
        let binary_bytes = b"#!/bin/sh\necho claude\n".to_vec();
        let binary_sha = format!("{:x}", Sha256::digest(&binary_bytes));
        let (base, server) = start_test_http_server(vec![("/claude".to_string(), binary_bytes)], 1);
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "claude-code".to_string(),
            root_formula: "claude-code".to_string(),
            stable_root: temp.path().join("opt/claude-code"),
            install_root: temp.path().join("opt/claude-code"),
            tmp_root,
        };
        let cask = EmbeddedCaskMetadata {
            url: format!("{base}/claude"),
            sha256: binary_sha,
            version: "2.1.112".to_string(),
            binaries: vec![EmbeddedCaskBinary {
                source: "claude".to_string(),
                target: None,
            }],
            ..Default::default()
        };

        install_cask_root(&plan, "claude-code", &cask, None).unwrap();
        server.join().unwrap();

        let installed = plan.install_root.join("bin/claude");
        assert!(installed.is_file());
        assert!(is_executable(&installed));
        assert_eq!(
            fs::read_to_string(&installed).unwrap(),
            "#!/bin/sh\necho claude\n"
        );
    }

    #[test]
    fn cask_install_helpers_cover_tar_payload_current_receipts_and_sha_mismatch() {
        let temp = TempDir::new().unwrap();
        let tmp_root = temp.path().join("tmp");
        fs::create_dir_all(&tmp_root).unwrap();
        let archive = temp.path().join("codex.tar.gz");
        write_test_archive(
            &archive,
            &[
                ("Codex.app/Contents/MacOS/codex", b"#!/bin/sh\necho codex\n"),
                ("Codex.app/Contents/MacOS/cdx", b"#!/bin/sh\necho cdx\n"),
            ],
        );
        let archive_bytes = fs::read(&archive).unwrap();
        let archive_sha = format!("{:x}", Sha256::digest(&archive_bytes));
        let (base, server) = start_test_http_server(
            vec![("/codex.tar.gz".to_string(), archive_bytes.clone())],
            2,
        );
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "cask:codex".to_string(),
            root_formula: "codex".to_string(),
            stable_root: temp.path().join("opt/cask/codex"),
            install_root: temp.path().join("opt/cask/codex"),
            tmp_root: tmp_root.clone(),
        };
        let cask = EmbeddedCaskMetadata {
            summary: "OpenAI Codex".to_string(),
            homepage: "https://example.test/codex".to_string(),
            url: format!("{base}/codex.tar.gz"),
            sha256: archive_sha,
            version: "1.0.0".to_string(),
            binaries: vec![
                EmbeddedCaskBinary {
                    source: "Codex.app/Contents/MacOS/codex".to_string(),
                    target: None,
                },
                EmbeddedCaskBinary {
                    source: "Codex.app/Contents/MacOS/cdx".to_string(),
                    target: Some("codex-chat".to_string()),
                },
            ],
            ..Default::default()
        };

        install_cask_root(&plan, "codex", &cask, None).unwrap();
        assert!(is_executable(&plan.install_root.join("bin/codex")));
        assert!(is_executable(&plan.install_root.join("bin/codex-chat")));
        write_package_receipt(
            &plan.root_receipt_path(),
            &PackageReceipt {
                package_name: "cask:codex".to_string(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Cask {
                    cask_name: "codex".to_string(),
                },
                metadata: PackageMetadata {
                    description: Some("OpenAI Codex".to_string()),
                    homepage: Some("https://example.test/codex".to_string()),
                },
            },
        )
        .unwrap();
        assert!(cask_root_is_current(&plan, &cask, &[], "all").unwrap());

        let bad_archive = temp.path().join("bad-codex.tar.gz");
        let bad_cask = EmbeddedCaskMetadata {
            sha256: "deadbeef".repeat(8),
            url: format!("{base}/codex.tar.gz"),
            version: "1.0.0".to_string(),
            binaries: vec![EmbeddedCaskBinary {
                source: "bad-codex.tar.gz".to_string(),
                target: None,
            }],
            ..Default::default()
        };
        let err = download_cask_archive("codex", &bad_cask, &bad_archive, None).unwrap_err();
        assert!(err.contains("sha256 mismatch for cask codex"));
        server.join().unwrap();
    }

    #[test]
    fn isotope_install_helpers_cover_nested_and_flat_archives() {
        let temp = TempDir::new().unwrap();
        let tmp_root = temp.path().join("tmp");
        fs::create_dir_all(&tmp_root).unwrap();

        let nested_archive = temp.path().join("gh.tar.gz");
        write_test_archive(
            &nested_archive,
            &[
                ("gh-2.80.0/bin/gh", b"#!/bin/sh\nprintf gh\\n\n"),
                ("gh-2.80.0/share/man/man1/gh.1", b"GH manual\n"),
            ],
        );
        let flat_archive = temp.path().join("aws-cli.tgz");
        write_test_archive(
            &flat_archive,
            &[
                ("bin/aws", b"#!/bin/sh\nprintf aws\\n\n"),
                ("share/doc/aws.txt", b"aws docs\n"),
            ],
        );
        let bin_only_archive = temp.path().join("supabase-cli.tgz");
        write_test_archive(
            &bin_only_archive,
            &[
                ("bin/supabase", b"#!/bin/sh\nprintf supabase\\n\n"),
                ("bin/supabase-go", b"#!/bin/sh\nprintf supabase-go\\n\n"),
            ],
        );
        let (base, server) = start_test_http_server(
            vec![
                ("/gh.tar.gz".to_string(), fs::read(&nested_archive).unwrap()),
                ("/aws-cli.tgz".to_string(), fs::read(&flat_archive).unwrap()),
                (
                    "/supabase-cli.tgz".to_string(),
                    fs::read(&bin_only_archive).unwrap(),
                ),
            ],
            3,
        );

        let isotope = IsotopePackageData {
            name: "isotope:gh".to_string(),
            replaces: Some("brew:gh".to_string()),
            modifies: None,
            migrate: None,
            _repository: None,
            _upstream_repository: None,
            version: "2.80.0".to_string(),
            release_url: Some("https://example.test/isotopes/gh".to_string()),
            archive_url: Some(format!("{base}/gh.tar.gz")),
            published_at: None,
            applies_to_versioned_formulae: false,
        };
        let gh_plan = InstallPlan {
            mode: Mode::I,
            package_name: "isotope:gh".to_string(),
            root_formula: "gh".to_string(),
            stable_root: temp.path().join("opt/iso/gh"),
            install_root: temp.path().join("opt/iso/gh"),
            tmp_root: tmp_root.clone(),
        };
        install_isotope_root(&gh_plan, &isotope, &[], None).unwrap();
        assert!(is_executable(&gh_plan.install_root.join("bin/gh")));
        assert!(gh_plan.install_root.join("share/man/man1/gh.1").is_file());
        write_root_executable_manifest(
            &gh_plan.root_executables_manifest_path(),
            &["gh".to_string()],
        )
        .unwrap();
        write_package_receipt(
            &gh_plan.root_receipt_path(),
            &PackageReceipt {
                package_name: "isotope:gh".to_string(),
                version: "2.80.0".to_string(),
                source: PackageReceiptSource::Isotope {
                    isotope_name: "gh".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        assert!(isotope_root_is_current(&gh_plan, &isotope).unwrap());

        let radioisotope = IsotopePackageData {
            name: "isotope:aws-cli".to_string(),
            replaces: None,
            modifies: Some("brew:awscli".to_string()),
            migrate: Some("aws configure import --csv file://$1".to_string()),
            _repository: None,
            _upstream_repository: None,
            version: "1.0.0".to_string(),
            release_url: Some("https://example.test/isotopes/aws-cli".to_string()),
            archive_url: Some(format!("{base}/aws-cli.tgz")),
            published_at: None,
            applies_to_versioned_formulae: false,
        };
        let aws_plan = InstallPlan {
            mode: Mode::I,
            package_name: "isotope:aws-cli".to_string(),
            root_formula: "awscli".to_string(),
            stable_root: temp.path().join("opt/iso/aws-cli"),
            install_root: temp.path().join("opt/iso/aws-cli"),
            tmp_root: tmp_root.clone(),
        };
        install_isotope_root(&aws_plan, &radioisotope, &[], None).unwrap();
        assert!(is_executable(&aws_plan.install_root.join("bin/aws")));
        assert!(aws_plan.install_root.join("share/doc/aws.txt").is_file());

        let bin_only_isotope = IsotopePackageData {
            name: "isotope:supabase".to_string(),
            replaces: Some("brew:supabase".to_string()),
            modifies: None,
            migrate: Some("/opt/iso/supabase/bin/supabase-go av-migrate \"$@\"".to_string()),
            _repository: None,
            _upstream_repository: None,
            version: "2.101.0".to_string(),
            release_url: Some("https://example.test/isotopes/supabase-cli".to_string()),
            archive_url: Some(format!("{base}/supabase-cli.tgz")),
            published_at: None,
            applies_to_versioned_formulae: false,
        };
        let bin_only_plan = InstallPlan {
            mode: Mode::I,
            package_name: "isotope:supabase".to_string(),
            root_formula: "supabase".to_string(),
            stable_root: temp.path().join("opt/iso/supabase"),
            install_root: temp.path().join("opt/iso/supabase"),
            tmp_root: tmp_root.clone(),
        };
        install_isotope_root(&bin_only_plan, &bin_only_isotope, &[], None).unwrap();
        assert!(is_executable(
            &bin_only_plan.install_root.join("bin/supabase")
        ));
        assert!(is_executable(
            &bin_only_plan.install_root.join("bin/supabase-go")
        ));
        assert!(!bin_only_plan.install_root.join("supabase").exists());

        let missing_archive = IsotopePackageData {
            archive_url: None,
            ..radioisotope
        };
        let err = install_isotope_root(&aws_plan, &missing_archive, &[], None).unwrap_err();
        assert!(err.contains("isotope isotope:aws-cli has no archive URL"));
        server.join().unwrap();
    }

    #[test]
    fn install_package_and_command_helpers_cover_end_to_end_staging() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "sqlite".to_string(),
            root_formula: "sqlite".to_string(),
            stable_root: temp.path().join("opt/sqlite"),
            install_root: temp.path().join("opt/sqlite"),
            tmp_root: temp.path().join("tmp"),
        };
        ensure_plan_parent_dirs(&plan).unwrap();

        let archive = temp.path().join("sqlite.tar.gz");
        write_test_bottle_archive(
            &archive,
            "sqlite",
            "3.49.1",
            &[
                ("bin/sqlite3", b"#!/bin/sh\n"),
                ("share/doc.txt", b"hello\n"),
            ],
        );
        let install = InstalledFormula {
            spec: FormulaSpec {
                name: "sqlite".to_string(),
                bottle_sha256: "sha256".to_string(),
                bottle_url: "https://example.invalid/sqlite.tar.gz".to_string(),
            },
            keg_dir_name: "3.49.1".to_string(),
            archive_path: archive,
        };
        let config = Config {
            bottle_tag: "arm64_tahoe".to_string(),
        };
        let graph = vec![install.spec.clone()];
        let rewrite_rules = build_rewrite_rules(&plan, std::slice::from_ref(&install));

        install_package(
            &config,
            &plan,
            std::slice::from_ref(&install),
            std::slice::from_ref(&install),
            &rewrite_rules,
            None,
        )
        .unwrap();

        assert!(plan.install_root.join("bin/sqlite3").is_file());
        assert!(plan.install_root.join("share/doc.txt").is_file());
        assert!(package_is_current(&plan, &[install], &config.bottle_tag).unwrap());
        assert_eq!(
            build_formula_order(&plan, &graph),
            vec!["sqlite".to_string()]
        );
        assert_eq!(
            resolve_install_time_command(&plan, &graph, "sqlite3").unwrap(),
            plan.install_root.join("bin/sqlite3")
        );
    }

    #[test]
    fn install_package_incremental_reuses_current_dependency_and_replaces_changed_root() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "foo".to_string(),
            root_formula: "foo".to_string(),
            stable_root: temp.path().join("opt/foo"),
            install_root: temp.path().join("opt/foo"),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(plan.install_root.join("bin")).unwrap();
        fs::create_dir_all(plan.install_root.join("lib")).unwrap();
        fs::create_dir_all(&plan.tmp_root).unwrap();
        fs::write(plan.install_root.join("bin/foo"), b"old").unwrap();
        fs::write(plan.install_root.join("bin/stale"), b"stale").unwrap();
        fs::write(plan.install_root.join("lib/bar.txt"), b"bar").unwrap();
        write_package_receipt(
            &plan.root_receipt_path(),
            &PackageReceipt {
                package_name: "foo".to_string(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "foo".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();

        let old_foo = InstalledFormula {
            spec: FormulaSpec {
                name: "foo".to_string(),
                bottle_sha256: "oldsha".to_string(),
                bottle_url: "https://example.invalid/foo-old.tar.gz".to_string(),
            },
            keg_dir_name: "1.0.0".to_string(),
            archive_path: PathBuf::new(),
        };
        write_receipt_with_owned_paths(
            &plan.receipt_path("foo"),
            &old_foo,
            "arm64_tahoe",
            vec!["bin/foo".to_string(), "bin/stale".to_string()],
        )
        .unwrap();
        let bar = InstalledFormula {
            spec: FormulaSpec {
                name: "bar".to_string(),
                bottle_sha256: "barsha".to_string(),
                bottle_url: "https://example.invalid/bar.tar.gz".to_string(),
            },
            keg_dir_name: "1.0.0".to_string(),
            archive_path: PathBuf::new(),
        };
        write_receipt_with_owned_paths(
            &plan.receipt_path("bar"),
            &bar,
            "arm64_tahoe",
            vec!["lib/bar.txt".to_string()],
        )
        .unwrap();

        let foo_archive = temp.path().join("foo-new.tar.gz");
        write_test_bottle_archive(&foo_archive, "foo", "2.0.0", &[("bin/foo", b"new")]);
        let new_foo = InstalledFormula {
            spec: FormulaSpec {
                name: "foo".to_string(),
                bottle_sha256: "newsha".to_string(),
                bottle_url: "https://example.invalid/foo-new.tar.gz".to_string(),
            },
            keg_dir_name: "2.0.0".to_string(),
            archive_path: foo_archive,
        };
        let installs = vec![bar.clone(), new_foo.clone()];
        let rewrite_rules = build_rewrite_rules(&plan, &installs);

        install_package(
            &Config {
                bottle_tag: "arm64_tahoe".to_string(),
            },
            &plan,
            &installs,
            std::slice::from_ref(&new_foo),
            &rewrite_rules,
            None,
        )
        .unwrap();

        assert_eq!(fs::read(plan.install_root.join("bin/foo")).unwrap(), b"new");
        assert!(plan.install_root.join("lib/bar.txt").is_file());
        assert!(!plan.install_root.join("bin/stale").exists());
        assert_eq!(
            load_install_receipt(&plan.receipt_path("bar"))
                .unwrap()
                .unwrap()
                .version,
            "1.0.0"
        );
        assert_eq!(
            load_install_receipt(&plan.receipt_path("foo"))
                .unwrap()
                .unwrap()
                .version,
            "2.0.0"
        );
    }

    #[test]
    fn install_package_incremental_removes_dropped_dependency() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "foo".to_string(),
            root_formula: "foo".to_string(),
            stable_root: temp.path().join("opt/foo"),
            install_root: temp.path().join("opt/foo"),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(plan.install_root.join("bin")).unwrap();
        fs::create_dir_all(plan.install_root.join("share/baz")).unwrap();
        fs::write(plan.install_root.join("bin/foo"), b"foo").unwrap();
        fs::write(plan.install_root.join("share/baz/data"), b"baz").unwrap();
        write_package_receipt(
            &plan.root_receipt_path(),
            &PackageReceipt {
                package_name: "foo".to_string(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "foo".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        let foo = InstalledFormula {
            spec: FormulaSpec {
                name: "foo".to_string(),
                bottle_sha256: "foosha".to_string(),
                bottle_url: "https://example.invalid/foo.tar.gz".to_string(),
            },
            keg_dir_name: "1.0.0".to_string(),
            archive_path: PathBuf::new(),
        };
        write_receipt_with_owned_paths(
            &plan.receipt_path("foo"),
            &foo,
            "arm64_tahoe",
            vec!["bin/foo".to_string()],
        )
        .unwrap();
        let baz = InstalledFormula {
            spec: FormulaSpec {
                name: "baz".to_string(),
                bottle_sha256: "bazsha".to_string(),
                bottle_url: "https://example.invalid/baz.tar.gz".to_string(),
            },
            keg_dir_name: "1.0.0".to_string(),
            archive_path: PathBuf::new(),
        };
        write_receipt_with_owned_paths(
            &plan.receipt_path("baz"),
            &baz,
            "arm64_tahoe",
            vec!["share/baz".to_string(), "share/baz/data".to_string()],
        )
        .unwrap();

        let rewrite_rules = build_rewrite_rules(&plan, std::slice::from_ref(&foo));
        install_package(
            &Config {
                bottle_tag: "arm64_tahoe".to_string(),
            },
            &plan,
            std::slice::from_ref(&foo),
            &[],
            &rewrite_rules,
            None,
        )
        .unwrap();

        assert!(plan.install_root.join("bin/foo").is_file());
        assert!(!plan.install_root.join("share/baz").exists());
        assert!(
            load_install_receipt(&plan.receipt_path("baz"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn root_payload_ownership_replaces_root_files_without_removing_dependencies() {
        let temp = TempDir::new().unwrap();
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "npm:tool".to_string(),
            root_formula: "npm:tool".to_string(),
            stable_root: temp.path().join("opt/npm/tool"),
            install_root: temp.path().join("opt/npm/tool"),
            tmp_root: temp.path().join("tmp"),
        };
        fs::create_dir_all(plan.install_root.join("bin")).unwrap();
        fs::create_dir_all(plan.install_root.join("lib")).unwrap();
        fs::write(plan.install_root.join("bin/tool"), b"old").unwrap();
        fs::write(plan.install_root.join("lib/dependency"), b"dep").unwrap();
        write_package_receipt(
            &plan.root_receipt_path(),
            &PackageReceipt {
                package_name: "npm:tool".to_string(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Npm {
                    package_name: "tool".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        write_root_ownership_manifest(&plan, vec!["bin/tool".to_string()]).unwrap();

        let before = prepare_root_payload_install(&plan).unwrap();
        fs::create_dir_all(plan.install_root.join("bin")).unwrap();
        fs::write(plan.install_root.join("bin/tool"), b"new").unwrap();
        finish_root_payload_install(&plan, before).unwrap();

        assert_eq!(
            fs::read(plan.install_root.join("bin/tool")).unwrap(),
            b"new"
        );
        assert_eq!(
            fs::read(plan.install_root.join("lib/dependency")).unwrap(),
            b"dep"
        );
        assert_eq!(
            load_root_ownership_manifest(&plan.root_ownership_manifest_path())
                .unwrap()
                .unwrap()
                .stubs,
            vec!["bin/tool".to_string()]
        );
    }

    #[test]
    fn path_and_process_helpers_cover_remaining_utility_branches() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("readonly");
        fs::write(&path, b"text").unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o555);
        fs::set_permissions(&path, permissions).unwrap();
        ensure_writable(&path).unwrap();
        assert_ne!(fs::metadata(&path).unwrap().permissions().mode() & 0o200, 0);

        assert_eq!(
            normalize_path(Path::new("/opt/homebrew/Cellar/../opt/./sqlite")),
            PathBuf::from("/opt/homebrew/opt/sqlite")
        );
        assert_eq!(
            relative_path_from(
                Path::new("/opt/sqlite/bin"),
                Path::new("/opt/sqlite/share/doc")
            ),
            PathBuf::from("../share/doc")
        );
        assert_eq!(
            relative_path_from(Path::new("relative"), Path::new("/absolute/path")),
            PathBuf::from("/absolute/path")
        );
        assert_eq!(
            source_keg_root(Path::new("/tmp/root/sqlite/3.49.1")).unwrap(),
            PathBuf::from("/opt/homebrew/Cellar/sqlite/3.49.1")
        );
        assert_eq!(
            homebrew_relative_symlink_source(Path::new("/opt/homebrew/opt/sqlite/bin/sqlite3")),
            Some("@@HOMEBREW_PREFIX@@/opt/sqlite/bin/sqlite3".to_string())
        );
        assert_eq!(
            homebrew_relative_symlink_source(Path::new(
                "/opt/homebrew/Cellar/sqlite/3.49.1/bin/sqlite3"
            )),
            Some("@@HOMEBREW_CELLAR@@/sqlite/3.49.1/bin/sqlite3".to_string())
        );
        assert!(!is_macho(b"abc"));
        assert!(codesign_if_macho(Path::new("/tmp/not-macho"), b"#!/bin/sh\n", None).is_ok());

        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("printf 'hello\\n'; printf 'warn\\n' >&2");
        let output = run_command_with_logged_output(&mut command, None, "test command").unwrap();
        assert!(output.status.success());
        assert!(output.lines.iter().any(|line| line == "hello"));
        assert!(output.lines.iter().any(|line| line == "warn"));
        assert_eq!(
            format_command_output_suffix(&["".to_string(), "warn".to_string()]),
            ": warn".to_string()
        );
    }

    fn fake_vendor_version() -> Result<semver::Version, String> {
        Ok(semver::Version::parse("0.0.0").unwrap())
    }

    fn fake_vendor_install_strategy(_version: &semver::Version) -> vendor::InstallStrategy {
        vendor::InstallStrategy::CopyTree {
            source: "ignored".to_string(),
        }
    }

    fn fake_qmd_install_strategy(_version: &semver::Version) -> vendor::InstallStrategy {
        vendor::InstallStrategy::NpmGlobal {
            package: "@tobilu/qmd".to_string(),
        }
    }

    fn coverage_vendor_install_strategy(_version: &semver::Version) -> vendor::InstallStrategy {
        vendor::InstallStrategy::CopyFile {
            source: "pkg/bin/coverage-vendor".to_string(),
            destination_dir: "bin".to_string(),
            destination_name: Some("coverage-vendor".to_string()),
            mode: 0o755,
            create_dirs: vec!["bin".to_string()],
        }
    }

    static TEST_DOWNLOAD_URLS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

    struct TestEnvGuard {
        previous: Vec<(String, Option<OsString>)>,
    }

    impl TestEnvGuard {
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

    impl Drop for TestEnvGuard {
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

    struct TestEndpointGuard;

    impl TestEndpointGuard {
        fn set(overrides: config::TestEndpointOverrides) -> Self {
            config::set_test_endpoint_overrides(overrides);
            Self
        }
    }

    impl Drop for TestEndpointGuard {
        fn drop(&mut self) {
            config::clear_test_endpoint_overrides();
        }
    }

    fn drain_test_server(base: &str, path: &str, attempts: usize) {
        let url = format!("{base}{path}");
        for _ in 0..attempts {
            let _ = ureq::get(&url).call();
        }
    }

    fn test_env_lock() -> &'static Mutex<()> {
        crate::global_test_env_lock()
    }

    fn test_download_urls() -> &'static Mutex<HashMap<String, String>> {
        TEST_DOWNLOAD_URLS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn register_test_download_url(version: &Version, url: String) {
        test_download_urls()
            .lock()
            .unwrap()
            .insert(version.to_string(), url);
    }

    fn test_download_url(version: &Version) -> String {
        test_download_urls()
            .lock()
            .unwrap()
            .get(&version.to_string())
            .cloned()
            .unwrap()
    }

    fn fake_vendor_install(
        name: &'static str,
        executables: &'static [&'static str],
        version: &str,
    ) -> VendorInstall {
        VendorInstall {
            package: vendor::VendorPackage {
                name,
                dependencies: &[],
                executables,
                version: fake_vendor_version,
                download_url: None,
                install: fake_vendor_install_strategy,
            },
            version: semver::Version::parse(version).unwrap(),
        }
    }

    fn write_test_bottle_archive(
        archive_path: &Path,
        formula: &str,
        keg_dir: &str,
        files: &[(&str, &[u8])],
    ) {
        let file = File::create(archive_path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);

        for (path, contents) in files {
            let archive_path = format!("{formula}/{keg_dir}/{path}");
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            archive
                .append_data(&mut header, archive_path, *contents)
                .unwrap();
        }

        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap();
    }

    fn write_test_archive(archive_path: &Path, files: &[(&str, &[u8])]) {
        let file = File::create(archive_path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);

        for (path, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            archive.append_data(&mut header, *path, *contents).unwrap();
        }

        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap();
    }

    fn write_test_plain_tar_archive(archive_path: &Path, files: &[(&str, &[u8])]) {
        let file = File::create(archive_path).unwrap();
        let mut archive = tar::Builder::new(file);

        for (path, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            archive.append_data(&mut header, *path, *contents).unwrap();
        }

        archive.finish().unwrap();
    }

    fn start_test_http_server(
        routes: Vec<(String, Vec<u8>)>,
        requests: usize,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let routes = Arc::new(routes.into_iter().collect::<HashMap<_, _>>());
        let handle = thread::spawn(move || {
            for _ in 0..requests {
                let (stream, _) = listener.accept().unwrap();
                respond_to_test_http_request(stream, routes.as_ref());
            }
        });
        (format!("http://{address}"), handle)
    }

    struct CountingTestHttpServer {
        base_url: String,
        requests: Arc<Mutex<usize>>,
        shutdown: std::sync::mpsc::Sender<()>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl CountingTestHttpServer {
        fn request_count(&self) -> usize {
            *self.requests.lock().unwrap()
        }

        fn stop(&mut self) -> thread::Result<()> {
            let Some(handle) = self.handle.take() else {
                return Ok(());
            };
            let _ = self.shutdown.send(());
            handle.join()
        }
    }

    impl Drop for CountingTestHttpServer {
        fn drop(&mut self) {
            let _ = self.stop();
        }
    }

    fn start_counting_test_http_server(routes: Vec<(String, Vec<u8>)>) -> CountingTestHttpServer {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let routes = Arc::new(routes.into_iter().collect::<HashMap<_, _>>());
        let requests = Arc::new(Mutex::new(0));
        let thread_requests = Arc::clone(&requests);
        let (shutdown, shutdown_rx) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            loop {
                if shutdown_rx.try_recv().is_ok() {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        *thread_requests.lock().unwrap() += 1;
                        respond_to_test_http_request(stream, routes.as_ref());
                    }
                    Err(err)
                        if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
                    {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) => panic!("failed to accept test HTTP request: {err}"),
                }
            }
        });
        CountingTestHttpServer {
            base_url: format!("http://{address}"),
            requests,
            shutdown,
            handle: Some(handle),
        }
    }

    fn respond_to_test_http_request(
        mut stream: std::net::TcpStream,
        routes: &HashMap<String, Vec<u8>>,
    ) {
        stream.set_nonblocking(false).unwrap();
        let mut buffer = [0u8; 4096];
        let count = stream.read(&mut buffer).unwrap();
        let request = String::from_utf8_lossy(&buffer[..count]);
        let path = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap();
        let (status, body) = match routes.get(path) {
            Some(body) => ("200 OK", body.clone()),
            None => ("404 Not Found", Vec::new()),
        };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(&body).unwrap();
    }

    fn start_test_etag_server(
        requests: Arc<Mutex<Vec<String>>>,
        body: Vec<u8>,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            for index in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0u8; 4096];
                let count = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..count]).to_string();
                requests.lock().unwrap().push(request);

                if index == 0 {
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nETag: \"test-etag\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).unwrap();
                    stream.write_all(&body).unwrap();
                    stream.flush().unwrap();
                } else {
                    stream
                        .write_all(
                            b"HTTP/1.1 304 Not Modified\r\nETag: \"test-etag\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .unwrap();
                    stream.flush().unwrap();
                }
            }
        });
        (format!("http://{address}"), handle)
    }

    fn test_combined_data_json() -> Vec<u8> {
        test_combined_data_json_with_db_schema(DB_SCHEMA_VERSION)
    }

    fn test_combined_data_with_generated_at(generated_at: &str) -> CombinedData {
        serde_json::from_value(serde_json::json!({
            "schema": 1,
            "generated_at": generated_at,
            "sources": {
                "db": {
                    "schema": DB_SCHEMA_VERSION,
                    "generated_at": generated_at,
                    "entries": {},
                    "npms": {}
                },
                "isotopes": {},
                "npm": {},
                "pip": {},
                "stub_exclusions": {}
            }
        }))
        .unwrap()
    }

    fn test_combined_data_json_with_db_schema(db_schema: u32) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": 1,
            "generated_at": "2026-05-05T00:00:00Z",
            "sources": {
                "db": {
                    "schema": db_schema,
                    "generated_at": "2026-05-05T00:00:00Z",
                    "entries": {},
                    "npms": {}
                },
                "isotopes": {},
                "npm": {},
                "pip": {},
                "stub_exclusions": {}
            }
        }))
        .unwrap()
    }
}
