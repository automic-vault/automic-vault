use std::collections::{HashMap, HashSet};
use std::env;
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
use std::time::Duration;

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

mod brew;
mod cask;
mod cli_help;
mod config;
mod core;
mod gate;
mod npm;
mod ops;
mod pip;
mod protocol;
mod state;
#[path = "../../../manifests/packages.rs"]
pub mod vendor;

mod cli;
mod info;
mod install;
mod isotope;
mod trace;
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

pub use cli::main_entry;
pub(crate) use cli::*;
pub(crate) use cli_help::*;
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
    ExecutionIntent, VaultApprovalRequest, VaultApprovalResponse, VaultClientRequest,
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
const EMBEDDED_COMBINED_DATA: &[u8] = include_bytes!("../../../data/combined.json");
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
const ISOTOPE_INSTALL_ROOT_DIR: &str = "isotopes";
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
const STUB_MANIFEST: &str = ".pkg/stubs.json";
const STUB_HEADER: &str = "# generated by av";
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const RENDERED_ERROR_PREFIX: &str = "__SUBS_RENDERED_ERROR__\n";
const SAFE_BINARY_PATH_BYTES: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-/@";
static POST_INSTALL_CHECK_SKIP: OnceLock<HashSet<String>> = OnceLock::new();
static PACKAGE_ALIASES: OnceLock<HashMap<String, PackageAliasTarget>> = OnceLock::new();
static NPM_PACKAGE_DATA: OnceLock<HashMap<String, PackageInstallData>> = OnceLock::new();
static PIP_PACKAGE_DATA: OnceLock<HashMap<String, PackageInstallData>> = OnceLock::new();
static ISOTOPE_DATA: OnceLock<HashMap<String, IsotopePackageData>> = OnceLock::new();
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
    aliases: HashMap<String, String>,
    db: Db,
    isotopes: HashMap<String, IsotopePackageData>,
    npm: HashMap<String, PackageInstallData>,
    pip: HashMap<String, PackageInstallData>,
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
            load_trusted_remote_combined_data().unwrap_or_else(|| {
                serde_json::from_slice(EMBEDDED_COMBINED_DATA)
                    .expect("failed to parse embedded combined package data JSON")
            })
        }
        #[cfg(any(test, not(feature = "packaged-db")))]
        {
            serde_json::from_slice(EMBEDDED_COMBINED_DATA)
                .expect("failed to parse embedded combined package data JSON")
        }
    })
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
    url: String,
    sha256: String,
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
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PackageSecurityState {
    #[serde(rename = "isotopeName")]
    isotope_name: String,
    #[serde(rename = "installIsInsecure")]
    install_is_insecure: bool,
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
    NpmPackage(String),
    PipPackage(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestedPackage {
    Auto(String),
    Alias {
        alias: String,
        target: PackageAliasTarget,
    },
    HomebrewFormula(String),
    HomebrewCask(String),
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
    output: OutputMode,
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
    steps: Vec<TraceStep>,
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
    findings: Vec<SecretScannerFinding>,
    errors: Vec<SecretScannerError>,
    summary: SecretScannerSummary,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
struct SecretScanPaths {
    paths: Vec<PathBuf>,
    errors: Vec<SecretScannerError>,
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
    dependencies: Vec<String>,
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
    download_started_at: Arc<Mutex<Option<std::time::Instant>>>,
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
    allow_reinstall: bool,
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

    fn actual_target_dir(&self, formula: &str) -> PathBuf {
        if self.mode == Mode::I || formula == self.root_formula {
            self.install_root.clone()
        } else {
            self.install_root.clone()
        }
    }

    fn stable_target_dir(&self, formula: &str) -> PathBuf {
        if self.mode == Mode::I || formula == self.root_formula {
            self.stable_root.clone()
        } else {
            self.stable_root.clone()
        }
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

fn prepare_i_install_plan(plan: &InstallPlan) -> Result<(InstallPlan, Option<TempDir>), String> {
    if plan.mode != Mode::I {
        return Ok((plan.clone(), None));
    }

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
    Ok((staged_plan, Some(workspace)))
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
        }
    }

    fn begin_download_phase(&self) {
        let mut state = self.state.lock().unwrap();
        state.phase = InstallProgressPhase::Download;
        drop(state);
        *self.bytes_downloaded.lock().unwrap() = 0;
        *self.total_bytes.lock().unwrap() = None;
        *self.download_started_at.lock().unwrap() = Some(std::time::Instant::now());
        if let Some(bar) = &self.bar {
            bar.set_style(download_progress_style());
            bar.set_position(0);
            bar.set_length(0);
            bar.set_message(String::new());
        }
        self.emit(ProgressEvent::Resolving);
    }

    fn add_download_total(&self, total: Option<u64>) {
        let Some(total) = total else {
            return;
        };
        if total == 0 {
            return;
        }
        *self.total_bytes.lock().unwrap() = Some(total);
        if let Some(bar) = &self.bar {
            bar.inc_length(total);
        }
        self.emit_downloading();
    }

    fn advance_download(&self, amount: u64) {
        if amount == 0 {
            return;
        }
        {
            let mut bytes_downloaded = self.bytes_downloaded.lock().unwrap();
            *bytes_downloaded += amount;
        }
        self.emit_downloading();
        if !self.enabled {
            return;
        }
        if let Some(bar) = &self.bar {
            bar.inc(amount);
        }
    }

    fn begin_install_phase(&self) {
        let mut state = self.state.lock().unwrap();
        if state.phase == InstallProgressPhase::Install {
            return;
        }
        state.phase = InstallProgressPhase::Install;
        drop(state);
        if let Some(bar) = &self.bar {
            bar.set_style(install_progress_style());
            bar.set_message("staging files".to_string());
        }
        self.emit(ProgressEvent::Installing {
            package: self.package_name.clone(),
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

    fn emit_downloading(&self) {
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
            package: self.package_name.clone(),
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
        .split(|ch| ch == '\n' || ch == '\r')
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .last()
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
                allow_reinstall: request.force,
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
            if let Some(package) = vendor::get(&package_name) {
                prepare_install_target(
                    &opt_pkg_root(),
                    &package_name,
                    options.allow_reinstall,
                    &managed_bin_root(),
                )?;
                run_i_vendor(
                    config,
                    package_name.clone(),
                    package,
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
                            options.allow_reinstall,
                            &managed_bin_root(),
                        )?;
                        run_i_formula(
                            config,
                            install_package_name,
                            root_formula,
                            progress_callback.clone(),
                        )
                    }
                    EmbeddedPackage::Cask(cask_name) => {
                        prepare_install_target(
                            &opt_pkg_root(),
                            &package_name,
                            options.allow_reinstall,
                            &managed_bin_root(),
                        )?;
                        run_i_cask(
                            config,
                            package_name.clone(),
                            cask_name,
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
        RequestedPackage::Alias { alias, target } => {
            ensure_alias_install_target_unambiguous(&alias, &target)?;
            run_i_package_with_progress(
                config,
                target.into_requested_package(),
                options,
                progress_callback.clone(),
            )
        }
        RequestedPackage::HomebrewFormula(formula) => {
            let package_name = formula_install_package_name(&formula)?;
            rollback_name = package_name.clone();
            prepare_install_target(
                &opt_pkg_root(),
                &package_name,
                options.allow_reinstall,
                &managed_bin_root(),
            )?;
            run_i_formula(config, package_name, formula, progress_callback.clone())
        }
        RequestedPackage::HomebrewCask(cask) => {
            prepare_install_target(
                &opt_pkg_root(),
                &cask,
                options.allow_reinstall,
                &managed_bin_root(),
            )?;
            run_i_cask(config, cask.clone(), cask, progress_callback.clone())
        }
        RequestedPackage::Isotope(isotope) => {
            let package_name = isotope_qualified_name(&isotope);
            if isotope_has_post_install(&package_name) {
                run_i_radioisotope(
                    config,
                    package_name,
                    isotope,
                    options.allow_reinstall,
                    progress_callback.clone(),
                )
            } else {
                prepare_install_target(
                    &opt_pkg_root(),
                    &package_name,
                    options.allow_reinstall,
                    &managed_bin_root(),
                )?;
                run_i_isotope(
                    config,
                    package_name,
                    isotope,
                    true,
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
                options.allow_reinstall,
                &managed_bin_root(),
            )?;
            run_i_npm(
                config,
                package_name.clone(),
                npm_package,
                version,
                options,
                progress_callback.clone(),
            )
        }
        RequestedPackage::PipPackage(pip_package) => {
            let package_name = pip_package_display_name(&pip_package);
            prepare_install_target(
                &opt_pkg_root(),
                &package_name,
                options.allow_reinstall,
                &managed_bin_root(),
            )?;
            run_i_pip(
                config,
                package_name.clone(),
                pip_package,
                progress_callback.clone(),
            )
        }
    };
    if let Err(err) = result {
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
        let (staged_plan, staging_workspace) = prepare_i_install_plan(&plan)?;
        let install_result = (|| {
            let downloads = download_bottles(&graph, &staged_plan.tmp_root, Some(&progress))?;
            progress.begin_install_phase();
            let installs = inspect_keg_dirs(&graph, &downloads)?;
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
            let rewrite_rules = build_rewrite_rules(&staged_plan, &installs);
            install_package(
                config,
                &staged_plan,
                &installs,
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
            run_package_post_install(&plan, &installs, &managed_bin_root())?;
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
    progress_callback: Option<Arc<Mutex<Box<ProgressCallback>>>>,
) -> Result<(), String> {
    let progress = InstallProgress::with_callback(&package_name, progress_callback);
    let result = (|| {
        let cask = embedded_cask(&cask_name)?;
        let dependency_graph = resolve_formula_specs(&cask.dependencies, config, true)?;
        let plan = InstallPlan::for_i(package_name.clone(), cask_name.clone());
        let previous_stubs = load_stub_manifest(&plan.package_manifest_path())?.stubs;
        let (staged_plan, staging_workspace) = prepare_i_install_plan(&plan)?;
        let install_result = (|| {
            let dependency_state = resolve_dependency_install_state(
                &dependency_graph,
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
                install_cask_root(&staged_plan, &cask_name, &cask, Some(&progress))?;
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
    progress_callback: Option<Arc<Mutex<Box<ProgressCallback>>>>,
) -> Result<(), String> {
    let progress = InstallProgress::with_callback(&package_name, progress_callback);
    let result = (|| {
        let record = isotope_package_data(&isotope_name)?.clone();
        let dependency_graph = isotope_dependency_graph(&record, config)?;
        let plan = InstallPlan::for_i_isotope(package_name.clone(), &isotope_name);
        let previous_stubs = load_stub_manifest(&plan.package_manifest_path())?.stubs;
        let (staged_plan, staging_workspace) = prepare_i_install_plan(&plan)?;
        let install_result = (|| {
            let dependency_state = resolve_dependency_install_state(
                &dependency_graph,
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
                    Some(&progress),
                )?;
                dependencies_reinstalled = true;
            }

            if !isotope_root_is_current(&staged_plan, &record)? {
                if !dependencies_reinstalled && dependency_graph.is_empty() {
                    prepare_vendor_root_area(&staged_plan)?;
                }
                install_isotope_root(
                    &staged_plan,
                    &record,
                    &dependency_state.installs,
                    Some(&progress),
                )?;
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
    run_i_isotope(config, package_name, isotope_name, false, progress_callback)
}

fn run_i_radioisotope(
    config: &Config,
    package_name: String,
    isotope_name: String,
    allow_reinstall: bool,
    progress_callback: Option<Arc<Mutex<Box<ProgressCallback>>>>,
) -> Result<(), String> {
    let progress = InstallProgress::with_callback(&package_name, progress_callback.clone());
    let result = (|| {
        let record = isotope_package_data(&isotope_name)?.clone();
        if !isotope_has_post_install(&record.name) {
            return Err(format!("isotope:{} is not a radioisotope", isotope_name));
        }
        let modified_package = isotope_modified_package_name(&record)?
            .ok_or_else(|| format!("radioisotope:{} does not declare modifies", isotope_name))?;
        let plan = InstallPlan::for_i_radioisotope(package_name.clone(), modified_package.clone());

        if allow_reinstall {
            prepare_install_target(
                &opt_pkg_root(),
                &modified_package,
                true,
                &managed_bin_root(),
            )?;
            run_i_formula(
                config,
                modified_package.clone(),
                modified_package.clone(),
                progress_callback.clone(),
            )?;
        } else {
            ensure_package_installed(&opt_pkg_root(), &modified_package)?;
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

fn install_isotope_stubs(
    isotope_name: &str,
    progress_callback: Option<Arc<Mutex<Box<ProgressCallback>>>>,
) -> Result<Vec<String>, String> {
    let package_name = isotope_qualified_name(isotope_name);
    let progress = InstallProgress::with_callback(&package_name, progress_callback);
    let record = isotope_package_data(isotope_name)?.clone();
    let plan = InstallPlan::for_i_isotope(package_name, isotope_name);
    if let Some(replaced_package) = isotope_replaced_package_name(&record)? {
        if package_install_root(&opt_pkg_root(), &replaced_package)?.exists() {
            return Err(format!(
                "cannot install isotope stubs while replacement package is installed: \
                 {replaced_package}"
            ));
        }
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
        .filter_map(|(name, _)| (name != "magick").then(|| name.clone()))
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
    if let Some((_, leaf_name)) = package.rsplit_once('/') {
        if let Some(entry) = data.get(leaf_name) {
            return entry.homebrew_dependencies.clone();
        }
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

fn isotope_package_data(name: &str) -> Result<&'static IsotopePackageData, String> {
    embedded_isotope_data()
        .get(&format!("{ISOTOPE_PACKAGE_PREFIX}{name}"))
        .ok_or_else(|| format!("unknown isotope {ISOTOPE_PACKAGE_PREFIX}{name}"))
}

fn isotope_qualified_name(name: &str) -> String {
    format!("{ISOTOPE_PACKAGE_PREFIX}{name}")
}

fn isotope_unqualified_name(name: &str) -> &str {
    name.strip_prefix(ISOTOPE_PACKAGE_PREFIX).unwrap_or(name)
}

fn isotope_integration(name: &str) -> Option<&'static isotope_integrations::IsotopeIntegration> {
    let name = isotope_unqualified_name(name);
    isotope_integrations::INTEGRATIONS
        .iter()
        .find(|integration| integration.name == name)
}

fn isotope_has_migration(name: &str) -> bool {
    isotope_integration(name)
        .and_then(|integration| integration.migrate)
        .is_some()
}

fn isotope_has_post_install(name: &str) -> bool {
    isotope_integration(name)
        .and_then(|integration| integration.post_install)
        .is_some()
}

fn run_generated_isotope_migration(name: &str) -> Option<Result<(), String>> {
    let migrate = isotope_integration(name)?.migrate?;
    Some(migrate())
}

fn run_generated_isotope_post_install(name: &str) -> Option<Result<(), String>> {
    let post_install = isotope_integration(name)?.post_install?;
    Some(post_install())
}

fn detect_isotope_install_reasons(name: &str) -> Option<Result<Vec<String>, String>> {
    let integration = isotope_integration(name)?;
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
    let identifiers = identifiers
        .into_iter()
        .map(|identifier| identifier.to_ascii_lowercase())
        .collect::<HashSet<_>>();
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

    None
}

fn package_security_state_for_isotope(isotope_name: &str) -> Option<PackageSecurityState> {
    let result = detect_isotope_install_reasons(isotope_name)?;
    Some(match result {
        Ok(reasons) => PackageSecurityState {
            isotope_name: isotope_name.to_string(),
            install_is_insecure: !reasons.is_empty(),
            reasons,
            error: None,
        },
        Err(err) => PackageSecurityState {
            isotope_name: isotope_name.to_string(),
            install_is_insecure: false,
            reasons: Vec::new(),
            error: Some(err),
        },
    })
}

fn run_secret_scan(request: &SecretScannerRequest) -> Result<SecretScannerReport, String> {
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let mut isotope_detectors = 0;

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
                findings.extend(reasons.into_iter().map(|reason| SecretScannerFinding {
                    source: format!("isotope:{}", integration.name),
                    kind: "detector".to_string(),
                    severity: "high".to_string(),
                    path: None,
                    line: None,
                    message: reason,
                }));
            }
            Err(err) => errors.push(SecretScannerError {
                source: format!("isotope:{}", integration.name),
                path: None,
                message: err,
            }),
        }
    }

    let scan_paths = secret_scan_paths(request.path.as_deref())?;
    errors.extend(scan_paths.errors);
    let file_probes = scan_paths.paths.len();
    let mut scanned_files = 0;
    for path in scan_paths.paths {
        match scan_secret_file(&path) {
            Ok(file_findings) => {
                if path.is_file() {
                    scanned_files += 1;
                }
                findings.extend(file_findings);
            }
            Err(err) => errors.push(SecretScannerError {
                source: "file-probe".to_string(),
                path: Some(path.display().to_string()),
                message: err,
            }),
        }
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

fn print_secret_scanner_report(report: &SecretScannerReport) {
    if !scan_stdout_is_rich() {
        print_plain_secret_scanner_report(report);
        return;
    }

    print_rich_secret_scanner_report(report);
}

fn print_plain_secret_scanner_report(report: &SecretScannerReport) {
    println!("Automic Vault scan");
    if report.findings.is_empty() {
        println!("No plaintext secret exposure detected.");
    } else {
        println!(
            "Plaintext secret exposure detected: {}.",
            pluralize(report.findings.len(), "finding", "findings")
        );
        println!();
        println!("Findings:");
        for (index, finding) in report.findings.iter().enumerate() {
            println!(
                "{}. {} {} - {}",
                index + 1,
                finding.severity,
                finding.source,
                finding.message
            );
            if let Some(location) = secret_scanner_finding_location(finding) {
                println!("   {location}");
            }
        }
    }
    println!(
        "Summary: {}, {}, {}, {}.",
        pluralize(report.summary.findings, "finding", "findings"),
        pluralize(report.summary.errors, "warning", "warnings"),
        pluralize(
            report.summary.scanned_files,
            "file scanned",
            "files scanned"
        ),
        pluralize(
            report.summary.isotope_detectors,
            "isotope detector",
            "isotope detectors"
        )
    );

    print_secret_scanner_warnings(report, false);
}

fn print_rich_secret_scanner_report(report: &SecretScannerReport) {
    let color = scan_stdout_supports_ansi();
    let status = if report.findings.is_empty() {
        scan_paint("✓", ScanStyle::Success, color)
    } else {
        scan_paint("✗", ScanStyle::Error, color)
    };
    let headline = if report.findings.is_empty() {
        "No plaintext secret exposure detected".to_string()
    } else {
        format!(
            "{} plaintext credential {}",
            report.findings.len(),
            if report.findings.len() == 1 {
                "finding"
            } else {
                "findings"
            }
        )
    };
    let summary = format!(
        "{} · {} · {}",
        pluralize(report.summary.isotope_detectors, "detector", "detectors"),
        pluralize(
            report.summary.scanned_files,
            "file scanned",
            "files scanned"
        ),
        pluralize(report.summary.errors, "warning", "warnings")
    );

    print_scan_box(
        "Automic Vault Scan",
        &[format!("{status} {headline}"), summary],
        color,
    );

    if !report.findings.is_empty() {
        println!();
        println!("{}", scan_paint("Findings", ScanStyle::Heading, color));
        for (index, finding) in report.findings.iter().enumerate() {
            let severity = scan_paint(&finding.severity, scan_severity_style(finding), color);
            println!(
                "  {}. {} {}",
                index + 1,
                severity,
                scan_paint(&finding.source, ScanStyle::Dim, color)
            );
            if let Some(location) = secret_scanner_finding_location(finding) {
                println!("     {}", scan_paint(&location, ScanStyle::Path, color));
            }
            println!("     {}", finding.message);
        }
    }

    print_secret_scanner_warnings(report, scan_stderr_supports_ansi());
}

fn print_secret_scanner_warnings(report: &SecretScannerReport, color: bool) {
    if report.errors.is_empty() {
        return;
    }

    eprintln!();
    eprintln!("{}", scan_paint("Warnings", ScanStyle::Warning, color));
    for error in &report.errors {
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
}

fn print_scan_box(title: &str, lines: &[String], color: bool) {
    let width = scan_box_width(lines);
    println!(
        "{}",
        scan_paint(
            &format!(
                "╭─ {title} {}╮",
                "─".repeat(width.saturating_sub(title.len() + 4))
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
            &format!("╰{}╯", "─".repeat(width + 2)),
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

fn scan_stdout_is_rich() -> bool {
    env::var("CLICOLOR_FORCE").is_ok_and(|value| value != "0")
        || (std::io::stdout().is_terminal() && env::var("TERM").map_or(true, |term| term != "dumb"))
}

fn scan_stdout_supports_ansi() -> bool {
    output_supports_ansi(std::io::stdout().is_terminal())
}

fn scan_stderr_supports_ansi() -> bool {
    output_supports_ansi(std::io::stderr().is_terminal())
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

fn secret_scan_paths(root: Option<&Path>) -> Result<SecretScanPaths, String> {
    match root {
        Some(path) => secret_scan_paths_under_root(path),
        None => Ok(SecretScanPaths {
            paths: default_secret_scan_paths(),
            errors: Vec::new(),
        }),
    }
}

fn secret_scan_paths_under_root(root: &Path) -> Result<SecretScanPaths, String> {
    if !root.exists() {
        return Err(format!("scan path does not exist: {}", root.display()));
    }
    if root.is_file() {
        return Ok(SecretScanPaths {
            paths: vec![root.to_path_buf()],
            errors: Vec::new(),
        });
    }
    if !root.is_dir() {
        return Err(format!(
            "scan path is not a file or directory: {}",
            root.display()
        ));
    }
    fs::read_dir(root)
        .map_err(|err| format!("failed to read scan path {}: {err}", root.display()))?;

    let mut paths = Vec::new();
    let mut errors = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !secret_scan_should_skip_entry(entry))
    {
        match entry {
            Ok(entry) if entry.file_type().is_file() => {
                paths.push(entry.path().to_path_buf());
            }
            Ok(_) => {}
            Err(err) => errors.push(SecretScannerError {
                source: "file-probe".to_string(),
                path: err.path().map(|path| path.display().to_string()),
                message: format!("failed to walk entry: {err}"),
            }),
        }
    }
    paths.sort();
    paths.dedup();
    Ok(SecretScanPaths { paths, errors })
}

fn secret_scan_should_skip_entry(entry: &walkdir::DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    matches!(
        entry.file_name().to_str(),
        Some(".git" | ".hg" | ".svn" | "target" | "dist" | "node_modules" | ".cache")
    )
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
    ".bashrc",
    ".zshrc",
    ".profile",
];

const SECRET_SCAN_MAX_FILE_BYTES: u64 = 1024 * 1024;

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
    if bytes.iter().any(|byte| *byte == 0) {
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
    {
        return None;
    }

    if trimmed.contains("BEGIN ") && trimmed.contains("PRIVATE KEY") {
        return Some(secret_file_finding(
            path,
            line_number,
            "private-key",
            "critical",
            "Private key material appears in a readable file",
        ));
    }

    let (key, value) = parse_secret_assignment(trimmed)?;
    let value = normalized_secret_value(value);
    if !secret_value_is_real(value) {
        return None;
    }

    if secret_key_name_is_sensitive(key) {
        return Some(secret_file_finding(
            path,
            line_number,
            "secret-assignment",
            "high",
            &format!("Plaintext-looking credential assigned to {}", key.trim()),
        ));
    }

    if secret_value_has_known_token_shape(value) {
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
        source: "file-probe".to_string(),
        kind: kind.to_string(),
        severity: severity.to_string(),
        path: Some(path.display().to_string()),
        line: Some(line),
        message: message.to_string(),
    }
}

fn parse_secret_assignment(line: &str) -> Option<(&str, &str)> {
    let line = line.strip_prefix("- ").unwrap_or(line);
    match (line.find('='), line.find(':')) {
        (Some(eq), Some(colon)) if eq < colon => Some((&line[..eq], &line[eq + 1..])),
        (Some(_), Some(colon)) => Some((&line[..colon], &line[colon + 1..])),
        (Some(eq), None) => Some((&line[..eq], &line[eq + 1..])),
        (None, Some(colon)) => Some((&line[..colon], &line[colon + 1..])),
        (None, None) => None,
    }
}

fn normalized_secret_value(value: &str) -> &str {
    value.trim().trim_matches('"').trim_matches('\'').trim()
}

fn secret_key_name_is_sensitive(key: &str) -> bool {
    let key = key
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase()
        .replace('-', "_");
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

fn secret_value_is_real(value: &str) -> bool {
    if value.len() < 6 || value.contains("${") {
        return false;
    }

    let lower = value.to_ascii_lowercase();
    !matches!(
        lower.as_str(),
        "secret"
            | "password"
            | "token"
            | "example"
            | "changeme"
            | "change_me"
            | "replace_me"
            | "redacted"
            | "none"
            | "null"
            | "true"
            | "false"
    ) && !lower.contains("example")
        && !lower.contains("placeholder")
        && !lower.contains("your_")
        && !lower.chars().all(|ch| ch == 'x' || ch == '*')
        && !value.starts_with('<')
}

fn secret_value_has_known_token_shape(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("ghp_")
        || value.starts_with("gho_")
        || value.starts_with("ghs_")
        || value.starts_with("github_pat_")
        || value.starts_with("glpat-")
        || value.starts_with("xoxb-")
        || value.starts_with("xoxp-")
        || value.starts_with("sk_live_")
        || (value.starts_with("npm_") && value.len() > 12)
        || (value.starts_with("sk-") && value.len() > 20)
        || (value.starts_with("AKIA") && value.len() >= 16)
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

fn isotope_modified_package_name(record: &IsotopePackageData) -> Result<Option<String>, String> {
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
        PackageAliasTarget::HomebrewFormula(formula) => Ok(Some(formula)),
        _ => Err(format!(
            "invalid isotope modification {}: radioisotopes may only modify Homebrew formulae",
            modifies
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
    rewrite_rules: &[RewriteRule],
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    if package_is_current(plan, installs, &config.bottle_tag)? {
        return Ok(());
    }

    prepare_clean_install_root(plan)?;
    let results: Vec<Result<(), String>> = installs
        .par_iter()
        .map(|install| install_formula(config, plan, install, rewrite_rules, progress))
        .collect();
    for result in results {
        result?;
    }
    Ok(())
}

fn install_dependency_formulas(
    config: &Config,
    plan: &InstallPlan,
    installs: &[InstalledFormula],
    progress: Option<&InstallProgress>,
) -> Result<(), String> {
    if installs.is_empty() {
        prepare_vendor_root_area(plan)?;
        return Ok(());
    }

    let rewrite_rules = build_rewrite_rules(plan, &installs);
    install_package(config, plan, &installs, &rewrite_rules, progress)?;
    run_package_post_install(plan, &installs, &managed_bin_root())
}

fn dependencies_are_current(
    plan: &InstallPlan,
    installs: &[InstalledFormula],
    vendor_installs: &[VendorInstall],
    config: &Config,
) -> Result<bool, String> {
    if installs.is_empty() && vendor_installs.is_empty() {
        return Ok(plan.install_root.is_dir());
    }

    if !installs.is_empty() && !package_is_current(plan, installs, &config.bottle_tag)? {
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
    if !installs.is_empty() {
        if !package_is_current(plan, &installs, bottle_tag)? {
            return Ok(false);
        }
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
    if entries.len() == 1 {
        let path = entries.remove(0).path();
        if path.is_dir() {
            return Ok(path);
        }
    }
    Ok(unpack_root.to_path_buf())
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
    prepare_vendor_root_area(plan)?;
    install_dependency_formulas(config, plan, installs, progress)?;
    install_vendor_dependencies(plan, graph, vendor_installs, progress)
}

fn resolve_dependency_install_state(
    graph: &[FormulaSpec],
    tmp_root: &Path,
    progress: Option<&InstallProgress>,
) -> Result<DependencyInstallState, String> {
    if graph.is_empty() {
        return Ok(DependencyInstallState {
            _downloads: HashMap::new(),
            installs: Vec::new(),
        });
    }

    let downloads = download_bottles(graph, tmp_root, progress)?;
    let installs = inspect_keg_dirs(graph, &downloads)?;
    Ok(DependencyInstallState {
        _downloads: downloads,
        installs,
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
    let path = plan.receipt_path(&install.spec.name);
    let data = match fs::read(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };
    let receipt: InstallReceipt = serde_json::from_slice(&data)
        .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;
    Ok(receipt.formula == install.spec.name
        && receipt.version == install.keg_dir_name
        && receipt.bottle_sha256 == install.spec.bottle_sha256
        && receipt.bottle_tag == bottle_tag)
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
    if plan.mode != Mode::I {
        return Ok(());
    }

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
    force: bool,
    bin_dir: &Path,
) -> Result<(), String> {
    let install_root = package_install_root(opt_root, package_name)?;
    match fs::symlink_metadata(&install_root) {
        Ok(_) if force || !install_root_has_valid_receipt(package_name, &install_root)? => {
            remove_existing_package_install(opt_root, package_name, bin_dir)
        }
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
        for alias in entry.aliases.into_iter().chain(entry.oldnames.into_iter()) {
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

fn ambiguous_alias_formula_message(package: &str, target: &PackageAliasTarget) -> String {
    format!(
        "ambiguous install target '{package}': use `{BREW_PACKAGE_PREFIX}{package}` for the Homebrew \
package or `{}` for the aliased package",
        target.display_name()
    )
}

fn ambiguous_alias_executable_message(
    package: &str,
    executable_provider: &str,
    target: &PackageAliasTarget,
) -> String {
    format!(
        "ambiguous install target '{package}': use `{executable_provider}` for the Homebrew package \
that provides the `{package}` executable or `{}` for the aliased package",
        target.display_name()
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
            .map_err(|err| format!("failed to read bottle for {}: {err}", spec.name))?;
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
    let entries = archive
        .entries()
        .map_err(|err| format!("failed to read {}: {err}", archive_path.display()))?;

    for entry in entries {
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
        return Ok(second.to_string());
    }

    Err(format!("empty bottle archive: {}", archive_path.display()))
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
    rules.sort_by(|left, right| right.source.len().cmp(&left.source.len()));
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
        progress.begin_install_phase();
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
    stage_formula(plan, install, &keg_root)?;
    write_receipt(
        &plan.receipt_path(&install.spec.name),
        install,
        &config.bottle_tag,
    )
}

fn stage_formula(
    plan: &InstallPlan,
    install: &InstalledFormula,
    keg_root: &Path,
) -> Result<(), String> {
    if plan.mode == Mode::I {
        let keep_root_entries = install.spec.name == plan.root_formula;
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
            write_root_executable_manifest(
                &plan.root_executables_manifest_path(),
                &root_executables,
            )?;
        }
        Ok(())
    } else if install.spec.name == plan.root_formula {
        stage_root_formula(&plan.install_root, keg_root, true)
    } else {
        let target = plan.actual_target_dir(&install.spec.name);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
        }
        fs::rename(keg_root, &target).map_err(|err| {
            format!(
                "failed to move {} to {}: {err}",
                keg_root.display(),
                target.display()
            )
        })
    }
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

fn write_receipt(path: &Path, install: &InstalledFormula, bottle_tag: &str) -> Result<(), String> {
    let receipt = InstallReceipt {
        formula: install.spec.name.clone(),
        version: install.keg_dir_name.clone(),
        bottle_sha256: install.spec.bottle_sha256.clone(),
        bottle_tag: bottle_tag.to_string(),
    };
    let data = serde_json::to_vec_pretty(&receipt).map_err(|err| {
        format!(
            "failed to serialize receipt for {}: {err}",
            install.spec.name
        )
    })?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    fs::write(path, data).map_err(|err| format!("failed to write {}: {err}", path.display()))
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
    if loader_path.len() < rewritten.len() && loader_path.len() <= max_len {
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
    let Some(replaced_package) = isotope_replaced_package_name(isotope)? else {
        return Ok(script.to_string());
    };
    let target_prefix = plan.install_root.display().to_string();
    let replaced_prefix = package_install_root(&opt_pkg_root(), &replaced_package)?
        .display()
        .to_string();
    Ok(script
        .replace(&replaced_prefix, &target_prefix)
        .replace(&format!("/opt/{replaced_package}"), &target_prefix))
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

    if let (Ok(uid), Ok(gid)) = (env::var("SUDO_UID"), env::var("SUDO_GID")) {
        if let (Ok(uid), Ok(gid)) = (uid.parse::<u32>(), gid.parse::<u32>()) {
            let (home, name) = passwd_entry(uid);
            return Ok(UserIdentity {
                uid,
                gid,
                home,
                name,
            });
        }
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
        .chain(HOMEBREW_NEEDLES.into_iter())
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
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, b"#!/bin/sh\n").unwrap();
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
            popularity: None,
            last_updated_at: None,
            pulse_kind: None,
        }
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
    fn ensure_alias_install_target_unambiguous_ignores_unknown_qualified_entry_providers() {
        let db = test_db(&[("future-tool", "future:provider")]);
        assert!(
            ensure_alias_install_target_unambiguous_with_db(
                "future-tool",
                &PackageAliasTarget::NpmPackage("future-tool".to_string()),
                &db,
                |_| Ok(false),
            )
            .is_ok()
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
    fn ensure_alias_install_target_unambiguous_accepts_unclaimed_aliases() {
        let db = test_db(&[]);
        assert!(
            ensure_alias_install_target_unambiguous_with_db(
                "clawhub",
                &PackageAliasTarget::NpmPackage("clawhub".to_string()),
                &db,
                |_| Ok(false),
            )
            .is_ok()
        );
    }

    #[test]
    fn ensure_alias_install_target_unambiguous_rejects_brew_executable_collisions() {
        let db = test_db(&[("openclaw", "openclaw-cli")]);
        assert_eq!(
            ensure_alias_install_target_unambiguous_with_db(
                "openclaw",
                &PackageAliasTarget::NpmPackage("openclaw".to_string()),
                &db,
                |_| Ok(false),
            ),
            Err(
                "ambiguous install target 'openclaw': use `openclaw-cli` for the Homebrew package \
that provides the `openclaw` executable or `npm:openclaw` for the aliased package"
                    .to_string()
            )
        );
    }

    #[test]
    fn ensure_alias_install_target_unambiguous_rejects_formula_collisions() {
        let db = test_db(&[]);
        assert_eq!(
            ensure_alias_install_target_unambiguous_with_db(
                "clawhub",
                &PackageAliasTarget::NpmPackage("clawhub".to_string()),
                &db,
                |_| Ok(true),
            ),
            Err(
                "ambiguous install target 'clawhub': use `brew:clawhub` for the Homebrew package \
or `npm:clawhub` for the aliased package"
                    .to_string()
            )
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
    fn parse_i_request_accepts_alias_package_names() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        let request =
            parse_i_request_from_iter(&invocation, vec![OsString::from("clawhub")].into_iter())
                .unwrap();

        assert_eq!(
            request,
            Some(IRequest {
                packages: vec![RequestedPackage::Alias {
                    alias: "clawhub".to_string(),
                    target: PackageAliasTarget::NpmPackage("clawhub".to_string()),
                }],
                force: false,
            })
        );
    }

    #[test]
    fn parse_i_request_accepts_alias_when_no_vendor_package_exists() {
        let invocation = Invocation::for_subcommand("av", "i", Mode::I);
        let request =
            parse_i_request_from_iter(&invocation, vec![OsString::from("qmd")].into_iter())
                .unwrap();

        assert_eq!(
            request,
            Some(IRequest {
                packages: vec![RequestedPackage::Alias {
                    alias: "qmd".to_string(),
                    target: PackageAliasTarget::NpmPackage("@tobilu/qmd".to_string()),
                }],
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
    fn parse_uninstall_request_accepts_alias_package_names() {
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
                packages: vec!["npm:clawhub".to_string()],
            })
        );
    }

    #[test]
    fn parse_uninstall_request_uses_homebrew_provider_names_for_executables() {
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
    fn parse_uninstall_request_resolves_alias_when_no_vendor_package_exists() {
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
                packages: vec!["npm:@tobilu/qmd".to_string()],
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
            requested_package_name(&RequestedPackage::Alias {
                alias: "pg".to_string(),
                target: PackageAliasTarget::PipPackage("psycopg2".to_string()),
            }),
            "pip:psycopg2"
        );
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
        assert!(status.is_outdated() == false);
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
        let isotope_root = opt_root.join("isotopes/gh");
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
            explicit_requested_package_source(&RequestedPackage::Alias {
                alias: "node-tool".to_string(),
                target: PackageAliasTarget::NpmPackage("openclaw".to_string()),
            }),
            Some(PackageReceiptSource::Npm {
                package_name: "openclaw".to_string()
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
            our_aliases_for_source(&PackageReceiptSource::Pip {
                package_name: "psycopg2".to_string()
            })
            .is_empty()
        );
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
                dependencies: Vec::new(),
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
                dependencies: Vec::new(),
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
                dependencies: Vec::new(),
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
            5,
        );
        let _endpoints = TestEndpointGuard::set(config::TestEndpointOverrides {
            formula_api_root: Some(base.clone()),
            npm_registry_root: Some(base.clone()),
            pypi_root: Some(base),
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
        assert!(!formula.installed);
        assert_eq!(formula.latest_version, Some("22.0.0".to_string()));
        assert_eq!(
            formula.homebrew_info.unwrap().description,
            Some("Node runtime".to_string())
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
                output: OutputMode::Json,
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
    fn secret_file_scanner_ignores_missing_default_candidates() {
        let temp = TempDir::new().unwrap();
        let findings = scan_secret_file(&temp.path().join(".env")).unwrap();

        assert!(findings.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn secret_scan_paths_warns_for_unreadable_subdirectories() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("project");
        let restricted = root.join("restricted");
        let env_path = root.join(".env");
        fs::create_dir_all(&restricted).unwrap();
        fs::write(&env_path, "TOKEN=secret_secret\n").unwrap();
        let mut permissions = fs::metadata(&restricted).unwrap().permissions();
        permissions.set_mode(0o000);
        fs::set_permissions(&restricted, permissions).unwrap();

        let result = secret_scan_paths_under_root(&root).unwrap();

        let mut permissions = fs::metadata(&restricted).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&restricted, permissions).unwrap();
        assert!(result.paths.contains(&env_path));
        if unsafe { libc::geteuid() } != 0 {
            assert!(
                result.errors.iter().any(|error| error
                    .path
                    .as_deref()
                    .is_some_and(|path| path.contains("restricted"))),
                "{:?}",
                result.errors
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn secret_scan_paths_errors_when_requested_root_is_unreadable() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }

        let temp = TempDir::new().unwrap();
        let root = temp.path().join("project");
        fs::create_dir_all(&root).unwrap();
        let mut permissions = fs::metadata(&root).unwrap().permissions();
        permissions.set_mode(0o000);
        fs::set_permissions(&root, permissions).unwrap();

        let result = secret_scan_paths_under_root(&root);

        let mut permissions = fs::metadata(&root).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&root, permissions).unwrap();
        let err = result.unwrap_err();
        assert!(err.contains("failed to read scan path"));
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
            "[default]\naws_secret_access_key = secretsecret\n",
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
            path: Some(scan_root),
            output: OutputMode::Human,
        })
        .unwrap();

        let has_aws_cli_detector = detect_isotope_install_reasons("aws-cli").is_some();
        if has_aws_cli_detector {
            assert!(report.summary.isotope_detectors > 0);
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.source == "isotope:aws-cli")
            );
        } else {
            assert_eq!(report.summary.isotope_detectors, 0);
            assert!(
                report
                    .findings
                    .iter()
                    .all(|finding| !finding.source.starts_with("isotope:"))
            );
        }
        assert!(report.summary.scanned_files >= 1);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.source == "file-probe")
        );
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
        fs::create_dir_all(temp.path().join("isotopes/gh")).unwrap();

        let mut names = installed_package_names(temp.path()).unwrap();
        names.sort();

        assert_eq!(names, vec!["isotope:gh".to_string()]);
    }

    #[test]
    fn gh_isotope_migration_updates_keychain_without_login_subprocess() {
        let isotope = isotope_package_data("gh").unwrap();
        let script = isotope.migrate.as_deref().unwrap();

        assert!(script.contains("gh auth av-migrate"));
        assert!(!script.contains("auth login"));
        assert!(!script.contains("--with-token"));
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
    fn isotope_stub_executables_use_replaced_formula_metadata() {
        let isotope = isotope_package_data("aws-cli").unwrap();
        let discovered = vec![
            (
                "aws".to_string(),
                PathBuf::from("/opt/isotopes/aws-cli/bin/aws"),
            ),
            (
                "aws_completer".to_string(),
                PathBuf::from("/opt/isotopes/aws-cli/bin/aws_completer"),
            ),
            (
                "python3.14".to_string(),
                PathBuf::from("/opt/isotopes/aws-cli/bin/python3.14"),
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
    fn installed_package_summary_serializes_source() {
        let summary = core::InstalledPackageSummary {
            name: "isotope:gh".to_string(),
            source: PackageReceiptSource::Isotope {
                isotope_name: "gh".to_string(),
            },
            version: "2.80.0".to_string(),
            description: None,
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
    fn generated_isotope_helpers_return_none_without_compiled_integrations() {
        assert!(isotope_integration("gh").is_none());
        assert!(isotope_integration("isotope:gh").is_none());
        assert!(isotope_integration("aws-cli").is_none());
        assert!(isotope_integration("isotope:aws-cli").is_none());

        assert!(!isotope_has_migration("gh"));
        assert!(!isotope_has_post_install("gh"));
        assert!(!isotope_has_migration("aws-cli"));
        assert!(!isotope_has_post_install("aws-cli"));

        assert_eq!(run_generated_isotope_migration("gh"), None);
        assert_eq!(run_generated_isotope_post_install("gh"), None);
        assert_eq!(detect_isotope_install_reasons("gh"), None);
        assert_eq!(detect_isotope_install_reasons("aws-cli"), None);
        assert_eq!(package_security_state_for_isotope("gh"), None);
        assert_eq!(package_security_state_for_isotope("aws-cli"), None);

        for identifiers in [
            vec!["gh".to_string()],
            vec!["isotope:gh".to_string()],
            vec!["brew:gh".to_string()],
            vec!["aws-cli".to_string()],
            vec!["awscli".to_string()],
            vec!["brew:awscli".to_string()],
            vec!["unrelated".to_string()],
        ] {
            assert_eq!(package_security_state_for_identifiers(identifiers), None);
        }
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
        assert_eq!(unsupported, post_install_hooks::PostInstallOutcome::default());
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

        assert_eq!(package_security_state(&info), None);
        assert_eq!(
            package_security_state_for_identifiers(info.aliases.clone()),
            None
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
                    install_root: PathBuf::from("/opt/isotopes/alpha"),
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
            RequestedPackage::Auto("deno".to_string())
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
    fn rewrite_binary_uses_absolute_macho_path_when_loader_path_is_longer() {
        let root = PathBuf::from("/tmp/nucleus/.tmp08cFDL/python@3.14/3.14.4_1");
        let future_root = PathBuf::from("/tmp/opt/isotopes/aws-cli");
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
        assert!(
            find_subslice(&bytes, b"/tmp/opt/isotopes/aws-cli/lib/libzstd.1.dylib\0").is_some()
        );
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
            npm_package_homebrew_dependencies("qmd"),
            vec!["sqlite".to_string()]
        );
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
    fn embedded_package_aliases_load_expected_entries() {
        assert_eq!(
            package_alias_target("openclaw"),
            Some(&PackageAliasTarget::NpmPackage("openclaw".to_string()))
        );
        assert_eq!(
            package_alias_target("clawhub"),
            Some(&PackageAliasTarget::NpmPackage("clawhub".to_string()))
        );
        assert_eq!(
            package_alias_target("qmd"),
            Some(&PackageAliasTarget::NpmPackage("@tobilu/qmd".to_string()))
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
    fn build_sandboxed_npm_install_command_uses_isolated_env() {
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
        if should_bypass_npm_install_sandbox() {
            assert_eq!(command.get_program(), OsStr::new("/opt/pkg/bin/npm"));
            assert_eq!(args[0], OsStr::new("install"));
            assert_eq!(args[1], OsStr::new("-g"));
            assert_eq!(args[2], OsStr::new("--prefix"));
            assert_eq!(args[3], install_root.as_os_str());
            assert_eq!(
                args[4],
                OsStr::new("https://registry.npmjs.org/openclaw/-/openclaw-1.2.3.tgz")
            );
        } else {
            assert_eq!(command.get_program(), OsStr::new("/usr/bin/sandbox-exec"));
            assert_eq!(args[0], OsStr::new("-f"));
            assert_eq!(args[2], OsStr::new("/opt/pkg/bin/npm"));
            assert_eq!(args[3], OsStr::new("install"));
            assert_eq!(args[4], OsStr::new("-g"));
            assert_eq!(args[5], OsStr::new("--prefix"));
            assert_eq!(args[6], install_root.as_os_str());
            assert_eq!(
                args[7],
                OsStr::new("https://registry.npmjs.org/openclaw/-/openclaw-1.2.3.tgz")
            );
        }
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

        let found = collect_declared_root_executables(temp.path(), &["foo", "bar"]).unwrap();
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

        let err = prepare_install_target(temp.path(), "already-installed", false, temp.path())
            .unwrap_err();

        assert_eq!(
            err,
            "package already-installed is already installed; use --force/-f to reinstall"
        );
        prepare_install_target(temp.path(), "already-installed", true, temp.path()).unwrap();
        assert!(!install_root.exists());
        prepare_install_target(temp.path(), "not-installed", false, temp.path()).unwrap();
    }

    #[test]
    fn package_install_root_uses_isotopes_prefix() {
        let temp = TempDir::new().unwrap();

        let install_root = package_install_root(temp.path(), "isotope:gh").unwrap();

        assert_eq!(install_root, temp.path().join("isotopes/gh"));
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

        prepare_install_target(temp.path(), "npm:openclaw", false, &bin_dir).unwrap();

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

        let (staged_plan, _workspace) = prepare_i_install_plan(&plan).unwrap();

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
        assert!(!trusted_remote_data_path(temp.path(), &temp.path().join("missing.json"), false));

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
        assert_eq!(fs::metadata(&cache_dir).unwrap().permissions().mode() & 0o777, 0o755);
        assert_eq!(fs::metadata(&data_path).unwrap().permissions().mode() & 0o777, 0o644);
        assert_eq!(fs::metadata(&meta_path).unwrap().permissions().mode() & 0o777, 0o644);
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
        assert!(vendor_root_is_current(&plan, &vendor_install, &[], &config.bottle_tag).unwrap());

        remove_path(&plan.install_root.join("bin/codex")).unwrap();
        assert!(!vendor_root_is_current(&plan, &vendor_install, &[], &config.bottle_tag).unwrap());
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
            &[formula_alias.clone()],
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
    fn resolve_package_search_results_collapses_versioned_formula_aliases_to_family_base() {
        let _env_lock = test_env_lock().lock().unwrap();
        let (alias, base) = formula_index_entries()
            .unwrap()
            .iter()
            .find_map(|entry| {
                entry
                    .aliases
                    .iter()
                    .find(|alias| formula_versioned_base(alias).is_some())
                    .and_then(|alias| {
                        formula_versioned_base(alias)
                            .map(|base| (alias.to_string(), base.to_string()))
                    })
            })
            .expect("embedded db should carry at least one versioned formula alias");

        let results = resolve_package_search_results(
            &Config {
                bottle_tag: "arm64_tahoe".to_string(),
            },
            &alias,
        )
        .unwrap();
        assert!(
            results.iter().any(|result| result.package_name == base),
            "search should include the family base for matching versioned aliases"
        );
        assert!(
            results.iter().all(|result| result.package_name != alias),
            "search should not surface versioned aliases as separate display results"
        );
    }

    #[test]
    fn formula_family_search_results_use_unversioned_family_base() {
        let versioned = formula_family_search_result(&formula_index_entry("gcc@15", &[], &[]));
        assert_eq!(
            (
                versioned.package_name.as_str(),
                package_source_qualified_name(&versioned.source)
            ),
            ("gcc", "brew:gcc@15".to_string())
        );
        let aliased = formula_family_search_result(&formula_index_entry("node", &["node@25"], &[]));
        assert_eq!(
            (
                aliased.package_name.as_str(),
                package_source_qualified_name(&aliased.source)
            ),
            ("node", "brew:node".to_string())
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
    fn list_available_packages_paginates_ranked_results() {
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
        ranked.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        ranked.dedup_by(|left, right| left.1 == right.1);
        assert!(
            ranked.len() >= 2,
            "embedded db should carry ranked packages"
        );

        let first_page = ops::list_available_packages(0, 1).unwrap();
        assert_eq!(first_page.packages.len(), 1);
        assert_eq!(
            first_page.total_count,
            ops::list_available_packages(0, 0).unwrap().total_count
        );
        assert_eq!(first_page.next_offset, Some(1));
        assert_eq!(first_page.packages[0].name, ranked[0].1);

        let second_page = ops::list_available_packages(1, 1).unwrap();
        assert_eq!(second_page.packages.len(), 1);
        assert_eq!(second_page.total_count, first_page.total_count);
        assert_eq!(second_page.packages[0].name, ranked[1].1);

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
    fn protocol_method_parses_list_pulse() {
        assert_eq!(
            core::ProtocolMethod::parse("packages.listPulse"),
            Some(core::ProtocolMethod::PackagesListPulse)
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
            pypi_root: Some(base),
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

        let state =
            resolve_dependency_install_state(std::slice::from_ref(&bottle_spec), &tmp_root, None)
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
        let (vendor_base, vendor_server) =
            start_test_http_server(vec![("/vendor.tar.gz".to_string(), vendor_bytes)], 1);
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
            Some(callback),
        )
        .unwrap();
        vendor_server.join().unwrap();

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
            2,
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
            6,
        );
        let _endpoints = TestEndpointGuard::set(config::TestEndpointOverrides {
            formula_api_root: Some(base.clone()),
            npm_registry_root: Some(base.clone()),
            pypi_root: Some(base),
            ..Default::default()
        });

        run_i_npm(
            &Config {
                bottle_tag: "all".to_string(),
            },
            "npm:coverage-npm".to_string(),
            "coverage-npm".to_string(),
            Some("1.2.3".to_string()),
            InstallOptions {
                allow_reinstall: false,
            },
            None,
        )
        .unwrap();
        run_i_pip(
            &Config {
                bottle_tag: "all".to_string(),
            },
            "pip:coverage-pip".to_string(),
            "coverage-pip".to_string(),
            None,
        )
        .unwrap();
        server.join().unwrap();
        bottle_server.join().unwrap();

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

        remove_existing_package_install(&opt_root, "npm:coverage-npm", &bin_root).unwrap();
        remove_existing_package_install(&opt_root, "pip:coverage-pip", &bin_root).unwrap();
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
                let (mut stream, _) = listener.accept().unwrap();
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
        });
        (format!("http://{address}"), handle)
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

    fn test_combined_data_json_with_db_schema(db_schema: u32) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": 1,
            "generated_at": "2026-05-05T00:00:00Z",
            "sources": {
                "aliases": {},
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
