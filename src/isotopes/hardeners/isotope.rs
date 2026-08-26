use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::digest::{Context, SHA256};

use super::{HardenerDetection, executable};

const AV_PATH: &str = "/usr/local/bin/av";
const SUDO_PATH: &str = "/usr/bin/sudo";
const TEAM_IDENTIFIER: &str = "ZU76A67LGU";
const TAP_FORMULA_ROOT: &str =
    "https://raw.githubusercontent.com/automic-vault/homebrew-isotopes/main/Formula";
const MAX_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;

pub(crate) const GH: Spec = Spec {
    hardener: "gh",
    formula: "gh-cli",
    repository: "gh-cli",
    primary: "gh",
    binaries: &["gh"],
    test_path: "AUTOMIC_VAULT_TEST_GH_CLI_PATH",
};
pub(crate) const STRIPE: Spec = Spec {
    hardener: "stripe",
    formula: "stripe-cli",
    repository: "stripe-cli",
    primary: "stripe",
    binaries: &["stripe"],
    test_path: "AUTOMIC_VAULT_TEST_STRIPE_CLI_PATH",
};
pub(crate) const SUPABASE: Spec = Spec {
    hardener: "supabase",
    formula: "supabase-cli",
    repository: "supabase-cli",
    primary: "supabase",
    binaries: &["supabase-go", "supabase"],
    test_path: "AUTOMIC_VAULT_TEST_SUPABASE_CLI_PATH",
};
pub(crate) const OPENTOFU: Spec = Spec {
    hardener: "opentofu",
    formula: "opentofu-isotope",
    repository: "opentofu",
    primary: "tofu",
    binaries: &["tofu"],
    test_path: "AUTOMIC_VAULT_TEST_OPENTOFU_TARGET",
};
pub(crate) const OXIDE: Spec = Spec {
    hardener: "oxide-cli",
    formula: "oxide-cli-isotope",
    repository: "oxide.rs",
    primary: "oxide",
    binaries: &["oxide"],
    test_path: "AUTOMIC_VAULT_TEST_OXIDE_TARGET",
};
pub(crate) const GOAT: Spec = Spec {
    hardener: "goat",
    formula: "goat-isotope",
    repository: "goat",
    primary: "goat",
    binaries: &["goat"],
    test_path: "AUTOMIC_VAULT_TEST_GOAT_TARGET",
};
pub(crate) const RAILWAY: Spec = Spec {
    hardener: "railway",
    formula: "railway-isotope",
    repository: "railway-cli",
    primary: "railway",
    binaries: &["railway"],
    test_path: "AUTOMIC_VAULT_TEST_RAILWAY_TARGET",
};
pub(crate) const ORDERCLI: Spec = Spec {
    hardener: "ordercli",
    formula: "ordercli-isotope",
    repository: "ordercli",
    primary: "ordercli",
    binaries: &["ordercli"],
    test_path: "AUTOMIC_VAULT_TEST_ORDERCLI_TARGET",
};
pub(crate) const OPENHUE: Spec = Spec {
    hardener: "openhue-cli",
    formula: "openhue-cli-isotope",
    repository: "openhue-cli",
    primary: "openhue",
    binaries: &["openhue"],
    test_path: "AUTOMIC_VAULT_TEST_OPENHUE_CLI_TARGET",
};
pub(crate) const UAA: Spec = Spec {
    hardener: "uaa-cli",
    formula: "uaa-cli-isotope",
    repository: "uaa-cli",
    primary: "uaa",
    binaries: &["uaa"],
    test_path: "AUTOMIC_VAULT_TEST_UAA_CLI_TARGET",
};
pub(crate) const PLUMBER: Spec = Spec {
    hardener: "plumber",
    formula: "plumber-isotope",
    repository: "plumber",
    primary: "plumber",
    binaries: &["plumber"],
    test_path: "AUTOMIC_VAULT_TEST_PLUMBER_TARGET",
};
pub(crate) const ALIYUN: Spec = Spec {
    hardener: "aliyun-cli",
    formula: "aliyun-cli-isotope",
    repository: "aliyun-cli",
    primary: "aliyun",
    binaries: &["aliyun"],
    test_path: "AUTOMIC_VAULT_TEST_ALIYUN_TARGET",
};
pub(crate) const WAKATIME: Spec = Spec {
    hardener: "wakatime-cli",
    formula: "wakatime-cli-isotope",
    repository: "wakatime-cli",
    primary: "wakatime-cli",
    binaries: &["wakatime-cli"],
    test_path: "AUTOMIC_VAULT_TEST_WAKATIME_TARGET",
};

#[derive(Clone, Copy)]
pub(crate) struct Spec {
    pub(crate) hardener: &'static str,
    formula: &'static str,
    repository: &'static str,
    primary: &'static str,
    binaries: &'static [&'static str],
    test_path: &'static str,
}

#[derive(Clone)]
pub(crate) struct Doctor {
    pub(crate) identifier: &'static str,
    pub(crate) formula_url: String,
    pub(crate) repository: &'static str,
    pub(crate) receipt_path: Option<String>,
}

pub(crate) enum InstallPlan {
    Ready,
    Homebrew {
        brew: PathBuf,
        conflict: Option<String>,
    },
    Direct {
        manifest: Manifest,
        update: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Manifest {
    url: String,
    sha256: String,
}

impl InstallPlan {
    pub(crate) fn needed(&self) -> bool {
        !matches!(self, Self::Ready)
    }

    pub(crate) fn write(&self, stdout: &mut dyn Write, spec: Spec) {
        match self {
            Self::Ready => {}
            Self::Homebrew { brew, conflict } => {
                if let Some(conflict) = conflict {
                    writeln!(stdout, "├─ run `{} unlink {conflict}`", brew.display()).ok();
                }
                writeln!(
                    stdout,
                    "├─ run `{} install automic-vault/isotopes/{}`",
                    brew.display(),
                    spec.formula
                )
                .ok();
            }
            Self::Direct { update, .. } => {
                let verb = if *update { "update" } else { "install" };
                for binary in spec.binaries {
                    writeln!(stdout, "├─ {verb} /usr/local/bin/{binary}").ok();
                }
            }
        }
    }

    pub(crate) fn apply(self, spec: Spec) -> Result<(), String> {
        match self {
            Self::Ready => Ok(()),
            Self::Homebrew { brew, conflict } => {
                install_with_homebrew(spec, &brew, conflict.as_deref())
            }
            Self::Direct { manifest, .. } => install_direct(spec, &manifest),
        }
    }
}

pub(crate) fn plan(spec: Spec) -> Result<InstallPlan, String> {
    let target = target(spec);
    if installed(spec, &target) {
        if is_direct_target(spec, &target) {
            let manifest = current_manifest(spec)?;
            let current = fs::read_to_string(receipt_path(spec)).ok();
            if current.as_deref().map(str::trim) != Some(manifest.sha256.as_str()) {
                return Ok(InstallPlan::Direct {
                    manifest,
                    update: true,
                });
            }
        }
        return Ok(InstallPlan::Ready);
    }
    if let Some(brew) = brew_path() {
        return Ok(InstallPlan::Homebrew {
            brew,
            conflict: conflicting_formula(spec),
        });
    }
    Ok(InstallPlan::Direct {
        manifest: current_manifest(spec)?,
        update: false,
    })
}

pub(crate) fn target(spec: Spec) -> PathBuf {
    if let Some(path) = crate::test_env_var(spec.test_path) {
        return path.into();
    }
    brew_path()
        .map(|_| brew_target(spec))
        .unwrap_or_else(|| direct_target(spec))
}

pub(crate) fn detect(spec: Spec) -> HardenerDetection {
    let target = target(spec);
    let exists = installed(spec, &target);
    let target_text = target.display().to_string();
    let mut detection =
        HardenerDetection::command(exists, spec.primary, Some(target_text.clone()), target_text);
    detection.commands[0].isotope = Some(Doctor {
        identifier: spec.primary,
        formula_url: formula_url(spec),
        repository: spec.repository,
        receipt_path: is_direct_target(spec, &target)
            .then(|| receipt_path(spec).display().to_string()),
    });
    detection
}

pub(crate) fn current_sha(source_url: &str, repository: &str) -> Result<String, String> {
    let contents = fetch(source_url, 5)?;
    parse_formula(&contents, Some(repository)).map(|manifest| manifest.sha256)
}

pub(crate) fn signature_valid(path: &Path, identifier: &str) -> bool {
    if crate::test_env_var("AUTOMIC_VAULT_TEST_ISOTOPE_DIRECT_DIR").is_some() {
        return executable(path);
    }
    #[cfg(target_os = "macos")]
    {
        let requirement = format!(
            "=identifier \"{identifier}\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"{TEAM_IDENTIFIER}\""
        );
        Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict", "-R", &requirement])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
    #[cfg(not(target_os = "macos"))]
    false
}

pub(crate) fn install_privileged(
    hardener: &str,
    sha256: &str,
    archive: &Path,
) -> Result<(), String> {
    let spec = spec(hardener).ok_or_else(|| format!("unknown isotope `{hardener}`"))?;
    if crate::test_env_var("AUTOMIC_VAULT_TEST_ISOTOPE_DIRECT_DIR").is_none()
        && super::effective_uid() != 0
    {
        return Err("isotope installation requires root".into());
    }
    validate_sha256(sha256)?;
    let bin_dir = direct_bin_dir();
    let receipt_dir = direct_receipt_dir();
    prepare_install_directory(&bin_dir)?;
    prepare_install_directory(&receipt_dir)?;
    let suffix = format!("{}.{}", std::process::id(), now_nanos());
    let root_stage = TemporaryDirectory::new_in(&receipt_dir, spec.hardener)?;
    let trusted_archive = root_stage.path.join("isotope.tgz");
    copy_new(archive, &trusted_archive)?;
    let actual = sha256_file(&trusted_archive)?;
    if actual != sha256 {
        return Err(format!(
            "downloaded {} digest {actual}, expected {sha256}",
            spec.formula
        ));
    }
    let sources = extract_and_verify(spec, &trusted_archive, &root_stage.path)?;
    let mut staged = Vec::new();
    for (source, binary) in sources.iter().zip(spec.binaries) {
        if source.file_name().and_then(|name| name.to_str()) != Some(*binary) {
            return Err(format!(
                "refusing isotope binary with unexpected basename: {}",
                source.display()
            ));
        }
        let stage = bin_dir.join(format!(".{binary}.av-{suffix}"));
        copy_new(source, &stage)?;
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o755))
            .map_err(|err| format!("failed to protect {}: {err}", stage.display()))?;
        if !signature_valid(&stage, binary) {
            let _ = fs::remove_file(&stage);
            return Err(format!(
                "refusing {} because its Automic Vault code signature is invalid",
                source.display()
            ));
        }
        if spec.hardener == OPENTOFU.hardener {
            super::terraform::verify_target(super::terraform::Tool::OpenTofu, &stage)?;
        }
        if spec.hardener == OXIDE.hardener {
            super::oxide_cli::verify_target(&stage)?;
        }
        if spec.hardener == GOAT.hardener {
            super::goat::verify_target(&stage)?;
        }
        if spec.hardener == RAILWAY.hardener {
            super::railway::verify_target(&stage)?;
        }
        if spec.hardener == ORDERCLI.hardener {
            super::ordercli::verify_target(&stage)?;
        }
        if spec.hardener == OPENHUE.hardener {
            super::openhue_cli::verify_target(&stage)?;
        }
        if spec.hardener == UAA.hardener {
            super::uaa_cli::verify_target(&stage)?;
        }
        if spec.hardener == PLUMBER.hardener {
            super::plumber::verify_target(&stage)?;
        }
        if spec.hardener == WAKATIME.hardener {
            super::wakatime_cli::verify_target(&stage)?;
        }
        staged.push((stage, bin_dir.join(binary)));
    }
    for (stage, destination) in &staged {
        fs::rename(stage, destination).map_err(|err| {
            format!(
                "failed to install {} at {}: {err}",
                stage.display(),
                destination.display()
            )
        })?;
    }
    let receipt = receipt_path(spec);
    let staged_receipt = receipt_dir.join(format!(".{}.sha256.av-{suffix}", spec.formula));
    fs::write(&staged_receipt, format!("{sha256}\n"))
        .map_err(|err| format!("failed to write {}: {err}", staged_receipt.display()))?;
    fs::set_permissions(&staged_receipt, fs::Permissions::from_mode(0o644))
        .map_err(|err| format!("failed to protect {}: {err}", staged_receipt.display()))?;
    fs::rename(&staged_receipt, &receipt)
        .map_err(|err| format!("failed to install {}: {err}", receipt.display()))?;
    Ok(())
}

fn install_with_homebrew(
    spec: Spec,
    brew: &Path,
    conflicting_formula: Option<&str>,
) -> Result<(), String> {
    if let Some(conflict) = conflicting_formula {
        let status = Command::new(brew)
            .args(["unlink", conflict])
            .status()
            .map_err(|err| format!("failed to run {}: {err}", brew.display()))?;
        if !status.success() {
            return Err(format!(
                "failed to unlink conflicting Homebrew formula {conflict}: {status}"
            ));
        }
    }

    match install_and_verify_with_homebrew(spec, brew) {
        Ok(()) => Ok(()),
        Err(error) => {
            if let Some(conflict) = conflicting_formula
                && let Err(rollback) = restore_homebrew_conflict(spec, brew, conflict)
            {
                return Err(format!("{error}; {rollback}"));
            }
            Err(error)
        }
    }
}

fn install_and_verify_with_homebrew(spec: Spec, brew: &Path) -> Result<(), String> {
    let package = format!("automic-vault/isotopes/{}", spec.formula);
    let status = Command::new(brew)
        .args(["install", &package])
        .status()
        .map_err(|err| format!("failed to run {}: {err}", brew.display()))?;
    if !status.success() {
        return Err(format!("Homebrew isotope installation failed: {status}"));
    }
    let target = target(spec);
    if !executable(&target) || !signature_valid(&target, spec.primary) {
        return Err(format!(
            "Homebrew installed {}, but {} is missing or has an invalid Automic Vault code signature",
            spec.formula,
            target.display()
        ));
    }
    Ok(())
}

fn restore_homebrew_conflict(spec: Spec, brew: &Path, conflict: &str) -> Result<(), String> {
    let _ = Command::new(brew).args(["unlink", spec.formula]).status();
    let status = Command::new(brew)
        .args(["link", conflict])
        .status()
        .map_err(|err| format!("failed to restore Homebrew formula {conflict}: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "failed to restore Homebrew formula {conflict}: {status}"
        ))
    }
}

fn install_direct(spec: Spec, manifest: &Manifest) -> Result<(), String> {
    let temporary = TemporaryDirectory::new(spec.hardener)?;
    let archive = temporary.path.join("isotope.tgz");
    download(&manifest.url, &archive)?;
    let actual = sha256_file(&archive)?;
    if actual != manifest.sha256 {
        return Err(format!(
            "downloaded {} digest {actual}, expected {}",
            spec.formula, manifest.sha256
        ));
    }
    extract_and_verify(spec, &archive, &temporary.path)?;
    if crate::test_env_var("AUTOMIC_VAULT_TEST_ISOTOPE_DIRECT_DIR").is_some() {
        return install_privileged(spec.hardener, &manifest.sha256, &archive);
    }
    super::env_wrapper::validate_privileged_av(Path::new(AV_PATH))?;
    let status = Command::new(SUDO_PATH)
        .args([
            AV_PATH,
            "__install-isotope",
            spec.hardener,
            &manifest.sha256,
        ])
        .arg(archive)
        .status()
        .map_err(|err| format!("failed to run sudo: {err}"))?;
    if !status.success() {
        return Err(format!("isotope installation failed: {status}"));
    }
    Ok(())
}

fn extract_and_verify(
    spec: Spec,
    archive: &Path,
    destination: &Path,
) -> Result<Vec<PathBuf>, String> {
    let expected = spec
        .binaries
        .iter()
        .map(|binary| format!("bin/{binary}"))
        .collect::<BTreeSet<_>>();
    let listing = Command::new("/usr/bin/tar")
        .args(["-tzf"])
        .arg(archive)
        .output()
        .map_err(|err| format!("failed to inspect {}: {err}", archive.display()))?;
    if !listing.status.success() {
        return Err(format!("invalid isotope archive: {}", archive.display()));
    }
    let entries = String::from_utf8(listing.stdout)
        .map_err(|_| "isotope archive contains non-UTF-8 paths".to_string())?
        .lines()
        .filter(|entry| *entry != "bin/")
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if entries != expected {
        return Err("isotope archive contains unexpected paths".into());
    }
    let status = Command::new("/usr/bin/tar")
        .args(["-xzf"])
        .arg(archive)
        .arg("-C")
        .arg(destination)
        .status()
        .map_err(|err| format!("failed to unpack isotope archive: {err}"))?;
    if !status.success() {
        return Err(format!("failed to unpack isotope archive: {status}"));
    }
    let sources = spec
        .binaries
        .iter()
        .map(|binary| destination.join("bin").join(binary))
        .collect::<Vec<_>>();
    for (source, binary) in sources.iter().zip(spec.binaries) {
        if !source
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_file())
            || !signature_valid(source, binary)
        {
            return Err(format!(
                "refusing {} because its Automic Vault code signature is invalid",
                source.display()
            ));
        }
    }
    Ok(sources)
}

fn current_manifest(spec: Spec) -> Result<Manifest, String> {
    let formula = fetch(&formula_url(spec), 15)?;
    parse_formula(&formula, Some(spec.repository))
}

fn parse_formula(contents: &str, repository: Option<&str>) -> Result<Manifest, String> {
    let values = |prefix: &str| {
        contents
            .lines()
            .filter_map(|line| line.trim().strip_prefix(prefix))
            .filter_map(|value| value.strip_suffix('"'))
            .collect::<Vec<_>>()
    };
    let urls = values("url \"");
    let hashes = values("sha256 \"");
    if urls.len() != 1 || hashes.len() != 1 {
        return Err("isotope formula must contain exactly one URL and SHA-256".into());
    }
    let url = urls[0];
    if let Some(repository) = repository {
        let prefix = format!(
            "https://github.com/automic-vault/{}/releases/download/",
            repository
        );
        if !url.starts_with(&prefix) || !url.ends_with(".tgz") {
            return Err(format!("refusing unexpected isotope URL: {url}"));
        }
    } else if !url.starts_with("https://github.com/automic-vault/") || !url.ends_with(".tgz") {
        return Err(format!("refusing unexpected isotope URL: {url}"));
    }
    validate_sha256(hashes[0])?;
    Ok(Manifest {
        url: url.to_string(),
        sha256: hashes[0].to_string(),
    })
}

fn fetch(url: &str, timeout: u32) -> Result<String, String> {
    if let Some(contents) = crate::test_env_string("AUTOMIC_VAULT_TEST_ISOTOPE_FORMULA") {
        return Ok(contents);
    }
    get(url, timeout)?
        .into_with_config()
        .limit(64 * 1024)
        .read_to_string()
        .map_err(|err| format!("failed to read {url}: {err}"))
}

fn download(url: &str, destination: &Path) -> Result<(), String> {
    let mut body = get(url, 120)?.into_reader().take(MAX_ARCHIVE_BYTES + 1);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .map_err(|err| format!("failed to create {}: {err}", destination.display()))?;
    let size = io::copy(&mut body, &mut output)
        .map_err(|err| format!("failed to download {url}: {err}"))?;
    if size > MAX_ARCHIVE_BYTES {
        return Err("refusing an isotope archive larger than 128 MiB".into());
    }
    output
        .sync_all()
        .map_err(|err| format!("failed to sync {}: {err}", destination.display()))
}

fn get(url: &str, timeout_secs: u32) -> Result<ureq::Body, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(5)
        .timeout_global(Some(Duration::from_secs(timeout_secs.into())))
        .build()
        .into();
    agent
        .get(url)
        .call()
        .map(|response| response.into_body())
        .map_err(|err| format!("failed to fetch {url}: {err}"))
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|err| format!("failed to hash {}: {err}", path.display()))?;
    if !file
        .metadata()
        .is_ok_and(|metadata| metadata.file_type().is_file())
    {
        return Err(format!(
            "refusing to hash non-regular file {}",
            path.display()
        ));
    }
    let mut context = Context::new(&SHA256);
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|err| format!("failed to hash {}: {err}", path.display()))?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    Ok(context
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub(crate) fn validate_sha256(value: &str) -> Result<(), String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("invalid isotope SHA-256".into())
    }
}

fn brew_path() -> Option<PathBuf> {
    if let Some(path) = crate::test_env_var("AUTOMIC_VAULT_TEST_ISOTOPE_BREW_PATH") {
        return (!path.is_empty()).then(|| path.into());
    }
    ["/usr/local/bin/brew", "/opt/homebrew/bin/brew"]
        .map(PathBuf::from)
        .into_iter()
        .find(|path| executable(path))
}

fn brew_target(spec: Spec) -> PathBuf {
    super::homebrew::brew_prefix()
        .join("opt")
        .join(spec.formula)
        .join("bin")
        .join(spec.primary)
}

fn conflicting_formula(spec: Spec) -> Option<String> {
    if crate::test_env_var("AUTOMIC_VAULT_TEST_ISOTOPE_BREW_PATH").is_some() {
        return crate::test_env_string("AUTOMIC_VAULT_TEST_ISOTOPE_CONFLICT")
            .filter(|formula| !formula.is_empty());
    }
    ["/opt/homebrew/opt", "/usr/local/opt"]
        .map(|root| {
            Path::new(root)
                .join(spec.hardener)
                .join("bin")
                .join(spec.primary)
        })
        .into_iter()
        .any(|path| executable(&path))
        .then(|| spec.hardener.to_string())
}

fn direct_target(spec: Spec) -> PathBuf {
    direct_bin_dir().join(spec.primary)
}

fn direct_bin_dir() -> PathBuf {
    crate::test_env_var("AUTOMIC_VAULT_TEST_ISOTOPE_DIRECT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/local/bin"))
}

fn direct_receipt_dir() -> PathBuf {
    crate::test_env_var("AUTOMIC_VAULT_TEST_ISOTOPE_DIRECT_DIR")
        .map(PathBuf::from)
        .map(|path| path.join(".automic-vault-isotopes"))
        .unwrap_or_else(|| PathBuf::from("/usr/local/share/automic-vault/isotopes"))
}

fn receipt_path(spec: Spec) -> PathBuf {
    direct_receipt_dir().join(format!("{}.sha256", spec.formula))
}

fn is_direct_target(spec: Spec, path: &Path) -> bool {
    path == direct_target(spec)
}

fn installed(spec: Spec, path: &Path) -> bool {
    if crate::test_env_var(spec.test_path).is_some() {
        return path.exists();
    }
    if !executable(path) {
        return false;
    }
    if spec.hardener == OPENTOFU.hardener {
        return super::terraform::verify_target(super::terraform::Tool::OpenTofu, path).is_ok();
    }
    if spec.hardener == OXIDE.hardener {
        return super::oxide_cli::verify_target(path).is_ok();
    }
    if spec.hardener == GOAT.hardener {
        return super::goat::verify_target(path).is_ok();
    }
    if spec.hardener == RAILWAY.hardener {
        return super::railway::verify_target(path).is_ok();
    }
    if spec.hardener == ORDERCLI.hardener {
        return super::ordercli::verify_target(path).is_ok();
    }
    if spec.hardener == OPENHUE.hardener {
        return super::openhue_cli::verify_target(path).is_ok();
    }
    if spec.hardener == UAA.hardener {
        return super::uaa_cli::verify_target(path).is_ok();
    }
    if spec.hardener == PLUMBER.hardener {
        return super::plumber::verify_target(path).is_ok();
    }
    if spec.hardener == ALIYUN.hardener {
        return super::aliyun_cli::verify_target(path).is_ok();
    }
    if spec.hardener == WAKATIME.hardener {
        return super::wakatime_cli::verify_target(path).is_ok();
    }
    true
}

fn formula_url(spec: Spec) -> String {
    format!("{TAP_FORMULA_ROOT}/{}.rb", spec.formula)
}

fn spec(hardener: &str) -> Option<Spec> {
    [
        GH, STRIPE, SUPABASE, OPENTOFU, OXIDE, GOAT, RAILWAY, ORDERCLI, OPENHUE, UAA, PLUMBER,
        ALIYUN, WAKATIME,
    ]
    .into_iter()
    .find(|spec| spec.hardener == hardener)
}

pub(crate) fn prepare_install_directory(path: &Path) -> Result<(), String> {
    if crate::test_env_var("AUTOMIC_VAULT_TEST_ISOTOPE_DIRECT_DIR").is_some() {
        fs::create_dir_all(path)
            .map_err(|err| format!("failed to create {}: {err}", path.display()))?;
        return Ok(());
    }
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata)
                if metadata.file_type().is_dir()
                    && metadata.uid() == 0
                    && metadata.permissions().mode() & 0o022 == 0 => {}
            Ok(_) => {
                return Err(format!(
                    "refusing to install through unsafe directory {}",
                    ancestor.display()
                ));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(ancestor)
                    .map_err(|err| format!("failed to create {}: {err}", ancestor.display()))?;
                fs::set_permissions(ancestor, fs::Permissions::from_mode(0o755))
                    .map_err(|err| format!("failed to protect {}: {err}", ancestor.display()))?;
            }
            Err(err) => return Err(format!("cannot trust {}: {err}", ancestor.display())),
        }
    }
    Ok(())
}

pub(crate) fn copy_new(source: &Path, destination: &Path) -> Result<(), String> {
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)
        .map_err(|err| format!("failed to open {}: {err}", source.display()))?;
    if !input
        .metadata()
        .is_ok_and(|metadata| metadata.file_type().is_file())
    {
        return Err(format!("refusing non-regular source {}", source.display()));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .map_err(|err| format!("failed to create {}: {err}", destination.display()))?;
    std::io::copy(&mut input, &mut output)
        .map_err(|err| format!("failed to copy {}: {err}", source.display()))?;
    output
        .sync_all()
        .map_err(|err| format!("failed to sync {}: {err}", destination.display()))
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(label: &str) -> Result<Self, String> {
        Self::new_in(&std::env::temp_dir(), label)
    }

    fn new_in(parent: &Path, label: &str) -> Result<Self, String> {
        let path = parent.join(format!(
            "av-isotope-{label}-{}-{}",
            std::process::id(),
            now_nanos()
        ));
        fs::create_dir(&path)
            .map_err(|err| format!("failed to create {}: {err}", path.display()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|err| format!("failed to protect {}: {err}", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(crate) fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isotope_downloads_require_https() {
        assert!(get("http://example.com/isotope.tgz", 1).is_err());
    }

    #[test]
    fn every_executable_isotope_is_registered_for_direct_fallback() {
        for expected in [
            OPENTOFU, OXIDE, GOAT, RAILWAY, ORDERCLI, OPENHUE, UAA, PLUMBER, WAKATIME,
        ] {
            assert_eq!(
                spec(expected.hardener).map(|value| value.hardener),
                Some(expected.hardener)
            );
        }
    }

    #[test]
    fn executable_isotopes_use_their_fork_formula_manifests() {
        for (isotope, formula, repository) in [
            (OPENTOFU, "opentofu-isotope", "opentofu"),
            (OXIDE, "oxide-cli-isotope", "oxide.rs"),
            (GOAT, "goat-isotope", "goat"),
            (RAILWAY, "railway-isotope", "railway-cli"),
            (ORDERCLI, "ordercli-isotope", "ordercli"),
            (UAA, "uaa-cli-isotope", "uaa-cli"),
            (OPENHUE, "openhue-cli-isotope", "openhue-cli"),
            (PLUMBER, "plumber-isotope", "plumber"),
            (WAKATIME, "wakatime-cli-isotope", "wakatime-cli"),
        ] {
            assert_eq!(isotope.formula, formula);
            assert_eq!(isotope.repository, repository);
            assert_eq!(
                formula_url(isotope),
                format!("{TAP_FORMULA_ROOT}/{formula}.rb")
            );
        }
    }

    #[test]
    fn every_tap_isotope_prefers_homebrew() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ISOTOPE_BREW_PATH", "/test/bin/brew");
        }
        for isotope in [
            GH, STRIPE, SUPABASE, OPENTOFU, OXIDE, GOAT, RAILWAY, ORDERCLI, OPENHUE, UAA, PLUMBER,
            WAKATIME,
        ] {
            let missing =
                std::env::temp_dir().join(format!("av-test-missing-{}-isotope", isotope.hardener));
            unsafe {
                std::env::set_var(isotope.test_path, missing);
            }
            assert!(matches!(plan(isotope), Ok(InstallPlan::Homebrew { .. })));
            unsafe {
                std::env::remove_var(isotope.test_path);
            }
        }
        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_ISOTOPE_BREW_PATH");
        }
    }

    #[test]
    fn homebrew_target_uses_the_homebrew_prefix_not_the_launcher_path() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let prefix = std::env::temp_dir().join("av-test-isotope-homebrew-prefix");
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_PREFIX", &prefix);
        }
        assert_eq!(brew_target(GH), prefix.join("opt/gh-cli/bin/gh"));
        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_BREW_PREFIX");
        }
    }

    #[test]
    fn executable_isotope_falls_back_to_direct_install_without_homebrew() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let missing = std::env::temp_dir().join("av-test-missing-direct-gh-isotope");
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_GH_CLI_PATH", missing);
            std::env::set_var("AUTOMIC_VAULT_TEST_ISOTOPE_BREW_PATH", "");
            std::env::set_var(
                "AUTOMIC_VAULT_TEST_ISOTOPE_FORMULA",
                r#"url "https://github.com/automic-vault/gh-cli/releases/download/v2.97.0/cli-2.97.0.tgz"
sha256 "29e7f73c54cc1c278b7431bc04d581b468ca033d1782c39c87034515ae5d7070""#,
            );
        }
        assert!(matches!(
            plan(GH),
            Ok(InstallPlan::Direct { update: false, .. })
        ));
        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_GH_CLI_PATH");
            std::env::remove_var("AUTOMIC_VAULT_TEST_ISOTOPE_BREW_PATH");
            std::env::remove_var("AUTOMIC_VAULT_TEST_ISOTOPE_FORMULA");
        }
    }

    #[test]
    fn formula_parser_accepts_only_the_expected_release_and_digest() {
        let formula = r#"
          url "https://github.com/automic-vault/gh-cli/releases/download/v2.97.0/cli-2.97.0.tgz"
          sha256 "29e7f73c54cc1c278b7431bc04d581b468ca033d1782c39c87034515ae5d7070"
        "#;
        assert_eq!(
            parse_formula(formula, Some(GH.repository)).unwrap(),
            Manifest {
                url: "https://github.com/automic-vault/gh-cli/releases/download/v2.97.0/cli-2.97.0.tgz".into(),
                sha256: "29e7f73c54cc1c278b7431bc04d581b468ca033d1782c39c87034515ae5d7070".into(),
            }
        );
        assert!(
            parse_formula(
                &formula.replace("automic-vault/gh-cli", "evil/gh-cli"),
                Some(GH.repository)
            )
            .is_err()
        );
    }

    #[test]
    fn missing_isotope_with_homebrew_plans_the_unlink_and_tap_install() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let missing = std::env::temp_dir().join("av-test-missing-gh-isotope");
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_GH_CLI_PATH", &missing);
            std::env::set_var("AUTOMIC_VAULT_TEST_ISOTOPE_BREW_PATH", "/test/bin/brew");
            std::env::set_var("AUTOMIC_VAULT_TEST_ISOTOPE_CONFLICT", "gh");
        }
        let plan = plan(GH).unwrap();
        let mut output = Vec::new();
        plan.write(&mut output, GH);
        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_GH_CLI_PATH");
            std::env::remove_var("AUTOMIC_VAULT_TEST_ISOTOPE_BREW_PATH");
            std::env::remove_var("AUTOMIC_VAULT_TEST_ISOTOPE_CONFLICT");
        }
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "├─ run `/test/bin/brew unlink gh`\n├─ run `/test/bin/brew install automic-vault/isotopes/gh-cli`\n"
        );
    }

    #[test]
    fn homebrew_install_unlinks_the_conflict_first() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let directory = TemporaryDirectory::new("brew-conflict").unwrap();
        let brew = directory.path.join("brew");
        let log = directory.path.join("brew.log");
        let gh = directory.path.join("gh");
        fs::write(
            &brew,
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$AUTOMIC_VAULT_TEST_BREW_LOG\"\n",
        )
        .unwrap();
        fs::write(&gh, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&brew, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&gh, fs::Permissions::from_mode(0o755)).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_LOG", &log);
            std::env::set_var("AUTOMIC_VAULT_TEST_GH_CLI_PATH", &gh);
            std::env::set_var("AUTOMIC_VAULT_TEST_ISOTOPE_DIRECT_DIR", &directory.path);
        }

        install_with_homebrew(GH, &brew, Some("gh")).unwrap();

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_BREW_LOG");
            std::env::remove_var("AUTOMIC_VAULT_TEST_GH_CLI_PATH");
            std::env::remove_var("AUTOMIC_VAULT_TEST_ISOTOPE_DIRECT_DIR");
        }
        assert_eq!(
            fs::read_to_string(log).unwrap(),
            "unlink gh\ninstall automic-vault/isotopes/gh-cli\n"
        );
    }

    #[test]
    fn failed_homebrew_install_restores_the_conflicting_formula() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let directory = TemporaryDirectory::new("brew-conflict-rollback").unwrap();
        let brew = directory.path.join("brew");
        let log = directory.path.join("brew.log");
        fs::write(
            &brew,
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$AUTOMIC_VAULT_TEST_BREW_LOG\"\n[ \"$1\" != install ]\n",
        )
        .unwrap();
        fs::set_permissions(&brew, fs::Permissions::from_mode(0o755)).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_LOG", &log);
        }

        let error = install_with_homebrew(GH, &brew, Some("gh")).unwrap_err();

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_BREW_LOG");
        }
        assert!(error.contains("Homebrew isotope installation failed"));
        assert_eq!(
            fs::read_to_string(log).unwrap(),
            "unlink gh\ninstall automic-vault/isotopes/gh-cli\nunlink gh-cli\nlink gh\n"
        );
    }

    #[test]
    fn privileged_installer_binds_the_receipt_to_the_archive() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let directory = TemporaryDirectory::new("install-test").unwrap();
        let source = directory.path.join("source");
        let bin = source.join("bin");
        let destination = directory.path.join("destination");
        fs::create_dir_all(&bin).unwrap();
        fs::write(bin.join("gh"), "#!/bin/sh\n").unwrap();
        fs::set_permissions(bin.join("gh"), fs::Permissions::from_mode(0o755)).unwrap();
        let archive = directory.path.join("gh.tgz");
        let status = Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&archive)
            .arg("-C")
            .arg(&source)
            .arg("bin")
            .status()
            .unwrap();
        assert!(status.success());
        let digest = sha256_file(&archive).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ISOTOPE_DIRECT_DIR", &destination);
        }
        install_privileged("gh", &digest, &archive).unwrap();
        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_ISOTOPE_DIRECT_DIR");
        }
        assert!(executable(&destination.join("gh")));
        assert_eq!(
            fs::read_to_string(
                destination
                    .join(".automic-vault-isotopes")
                    .join("gh-cli.sha256")
            )
            .unwrap(),
            format!("{digest}\n")
        );
    }
}
