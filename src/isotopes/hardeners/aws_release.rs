use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(target_os = "macos")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) const DOWNLOAD_ROOT: &str = "https://awscli.amazonaws.com";
const CHANGELOG_URL: &str = "https://raw.githubusercontent.com/aws/aws-cli/v2/CHANGELOG.rst";
pub(crate) const TARGET_PATH: &str = "/opt/av/aws/current/aws";
const INSTALL_ROOT: &str = "/opt/av/aws";
const PACKAGE_IDENTIFIER: &str = "com.amazon.aws.cli2";
const AWS_TEAM_IDENTIFIER: &str = "94KV3E626L";
const MAX_PACKAGE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_INSTALLED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: u64 = 12_000;

pub(crate) fn download(destination: &Path) -> Result<(String, String), String> {
    let version = latest_version()?;
    let url = download_url(&version)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(180)))
        .build()
        .into();
    let mut body = agent
        .get(&url)
        .call()
        .map_err(|err| format!("failed to download the official AWS CLI package: {err}"))?
        .into_body()
        .into_reader()
        .take(MAX_PACKAGE_BYTES + 1);
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(destination)
        .map_err(|err| format!("failed to create {}: {err}", destination.display()))?;
    let size = std::io::copy(&mut body, &mut output)
        .map_err(|err| format!("failed to download {url}: {err}"))?;
    if size > MAX_PACKAGE_BYTES {
        return Err("refusing an AWS CLI package larger than 128 MiB".into());
    }
    output
        .sync_all()
        .map_err(|err| format!("failed to sync {}: {err}", destination.display()))?;
    sha256_file(destination).map(|sha256| (version, sha256))
}

pub(crate) fn install_privileged(
    expected_version: &str,
    expected_sha256: &str,
    package: &Path,
) -> Result<(), String> {
    if crate::test_env_var("AUTOMIC_VAULT_TEST_AWS_INSTALL_ROOT").is_none()
        && super::effective_uid() != 0
    {
        return Err("official AWS CLI installation requires root".into());
    }
    validate_version(expected_version)?;
    validate_sha256(expected_sha256)?;
    let root = install_root();
    prepare_install_directory(&root)?;
    let staging = TemporaryDirectory::new_in(&root, ".install")?;
    let trusted_package = staging.path.join("AWSCLIV2.pkg");
    copy_regular_file(package, &trusted_package, MAX_PACKAGE_BYTES)?;
    fs::set_permissions(&trusted_package, fs::Permissions::from_mode(0o444))
        .map_err(|err| format!("failed to protect {}: {err}", trusted_package.display()))?;
    let actual_sha256 = sha256_file(&trusted_package)?;
    if actual_sha256 != expected_sha256 {
        return Err(format!(
            "downloaded AWS CLI package digest {actual_sha256}, expected {expected_sha256}"
        ));
    }

    #[cfg(target_os = "macos")]
    let release = verify_and_extract_package(&trusted_package, &staging.path)?;
    #[cfg(not(target_os = "macos"))]
    return Err("official AWS CLI packages can only be verified on macOS".into());

    #[cfg(target_os = "macos")]
    require_expected_version(&release.version, expected_version)?;

    #[cfg(target_os = "macos")]
    install_payload(&root, &release.payload, &release.version, &actual_sha256)
}

pub(crate) fn current_release_valid() -> Result<(), String> {
    let root = install_root();
    let versions = root.join("versions");
    for directory in [&root, &versions] {
        validate_protected_entry(
            directory,
            &fs::symlink_metadata(directory).map_err(|err| {
                format!(
                    "official AWS CLI install directory {} is unavailable: {err}",
                    directory.display()
                )
            })?,
        )?;
    }
    let current = root.join("current");
    let link_metadata = fs::symlink_metadata(&current)
        .map_err(|err| format!("official AWS CLI current release is unavailable: {err}"))?;
    let (required_uid, required_gid) = required_owner();
    if !link_metadata.file_type().is_symlink()
        || link_metadata.uid() != required_uid
        || link_metadata.gid() != required_gid
    {
        return Err("official AWS CLI current release link has unsafe identity or type".into());
    }
    let release = release_metadata(&current)?;
    let expected_link = Path::new("versions").join(&release.release);
    if fs::read_link(&current).ok().as_deref() != Some(expected_link.as_path()) {
        return Err(
            "official AWS CLI current release link does not match its signed release metadata"
                .into(),
        );
    }
    let release_root = root.join(expected_link);
    let target = release_root.join("aws");
    let metadata = fs::symlink_metadata(&target).map_err(|err| {
        format!(
            "official AWS CLI is unavailable at {}: {err}",
            target.display()
        )
    })?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!(
            "official AWS CLI target is not an executable regular file: {}",
            target.display()
        ));
    }
    verify_protected_manifest(&release_root)?;
    verify_aws_executable(&target)
}

pub(crate) fn current_version() -> Result<String, String> {
    release_metadata(&install_root().join("current")).map(|release| release.version)
}

pub(crate) fn latest_version() -> Result<String, String> {
    if let Some(changelog) = crate::test_env_string("AUTOMIC_VAULT_TEST_AWS_CHANGELOG") {
        return parse_latest_version(&changelog);
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(5)))
        .build()
        .into();
    let mut changelog = String::new();
    agent
        .get(CHANGELOG_URL)
        .call()
        .map_err(|err| format!("failed to fetch {CHANGELOG_URL}: {err}"))?
        .into_body()
        .into_reader()
        .take(64 * 1024)
        .read_to_string(&mut changelog)
        .map_err(|err| format!("failed to read {CHANGELOG_URL}: {err}"))?;
    downloadable_version(&changelog, |version| {
        let url = download_url(version)?;
        match agent.head(&url).call() {
            Ok(_) => Ok(true),
            Err(ureq::Error::StatusCode(404)) => Ok(false),
            Err(error) => Err(format!("failed to check {url}: {error}")),
        }
    })
}

pub(crate) fn update_available(installed: &str, latest: &str) -> Result<bool, String> {
    compare_versions(latest, installed).map(|ordering| ordering.is_gt())
}

fn download_url(version: &str) -> Result<String, String> {
    validate_version(version)?;
    Ok(format!("{DOWNLOAD_ROOT}/AWSCLIV2-{version}.pkg"))
}

fn require_expected_version(actual: &str, expected: &str) -> Result<(), String> {
    validate_version(expected)?;
    (actual == expected)
        .then_some(())
        .ok_or_else(|| format!("AWS CLI package contains version {actual}, expected {expected}"))
}

pub(crate) fn target_path() -> PathBuf {
    install_root().join("current/aws")
}

fn install_root() -> PathBuf {
    crate::test_env_var("AUTOMIC_VAULT_TEST_AWS_INSTALL_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(INSTALL_ROOT))
}

#[cfg(target_os = "macos")]
struct ExtractedRelease {
    version: String,
    payload: PathBuf,
}

#[cfg(target_os = "macos")]
fn verify_and_extract_package(package: &Path, staging: &Path) -> Result<ExtractedRelease, String> {
    let signature = command_output("/usr/sbin/pkgutil", &["--check-signature"], Some(package))?;
    for required in [
        "Status: signed by a developer certificate issued by Apple for distribution",
        "Notarization: trusted by the Apple notary service",
        "Signed with a trusted timestamp on:",
        "Developer ID Installer: AMZN Mobile LLC (94KV3E626L)",
    ] {
        if !signature.contains(required) {
            return Err(format!(
                "refusing AWS CLI package because pkgutil did not confirm {required:?}"
            ));
        }
    }
    command_success(
        "/usr/sbin/spctl",
        &["--assess", "--type", "install", "--verbose=4"],
        package,
        "Gatekeeper rejected the AWS CLI installer package",
    )?;

    let extraction_parent = staging.join("unpack");
    fs::create_dir(&extraction_parent)
        .map_err(|err| format!("failed to create {}: {err}", extraction_parent.display()))?;
    let isolated = crate::test_env_var("AUTOMIC_VAULT_TEST_AWS_INSTALL_ROOT").is_none();
    if isolated {
        fs::set_permissions(staging, fs::Permissions::from_mode(0o711))
            .map_err(|err| format!("failed to protect {}: {err}", staging.display()))?;
        let chown_status = unsafe {
            libc::chown(
                std::ffi::CString::new(extraction_parent.as_os_str().as_encoded_bytes())
                    .map_err(|_| "AWS extraction path contains NUL")?
                    .as_ptr(),
                u32::MAX - 1,
                u32::MAX - 1,
            )
        };
        if chown_status != 0 {
            return Err(format!(
                "failed to isolate AWS package extraction: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    fs::set_permissions(&extraction_parent, fs::Permissions::from_mode(0o700))
        .map_err(|err| format!("failed to protect {}: {err}", extraction_parent.display()))?;
    let extraction = extraction_parent.join("expanded");
    let mut command = Command::new("/usr/sbin/pkgutil");
    command
        .args(["--expand-full"])
        .arg(package)
        .arg(&extraction)
        .env_clear()
        .env("HOME", "/var/empty")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if isolated {
        unsafe {
            command.pre_exec(|| {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(u32::MAX - 1) != 0
                    || libc::setuid(u32::MAX - 1) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let status = command
        .output()
        .map_err(|err| format!("failed to inspect the AWS CLI package: {err}"))?;
    if !status.status.success() {
        return Err(format!(
            "failed to extract the AWS CLI package without running it: {}",
            String::from_utf8_lossy(&status.stderr).trim()
        ));
    }

    let component = extraction.join("aws-cli.pkg");
    let package_info = fs::read_to_string(component.join("PackageInfo"))
        .map_err(|err| format!("failed to inspect AWS PackageInfo: {err}"))?;
    let identifier = xml_attribute(&package_info, "pkg-info", "identifier")?;
    if identifier != PACKAGE_IDENTIFIER {
        return Err(format!(
            "refusing unexpected AWS package identifier {identifier}"
        ));
    }
    let version = xml_attribute(&package_info, "pkg-info", "version")?;
    validate_version(&version)?;
    let declared_files = xml_attribute(&package_info, "payload", "numberOfFiles")?
        .parse::<u64>()
        .map_err(|_| "invalid AWS package file count".to_string())?;
    let declared_kib = xml_attribute(&package_info, "payload", "installKBytes")?
        .parse::<u64>()
        .map_err(|_| "invalid AWS package installed size".to_string())?;
    if declared_files == 0
        || declared_files > MAX_ENTRIES
        || declared_kib == 0
        || declared_kib.saturating_mul(1024) > MAX_INSTALLED_BYTES
    {
        return Err("refusing AWS package with implausible payload limits".into());
    }
    let payload = component.join("Payload/aws-cli");
    let (entries, bytes) = validate_payload_tree(&payload)?;
    if entries > MAX_ENTRIES || bytes > MAX_INSTALLED_BYTES {
        return Err("refusing AWS package whose expanded payload exceeds safety limits".into());
    }
    verify_payload_signatures(&payload)?;
    Ok(ExtractedRelease { version, payload })
}

#[cfg(target_os = "macos")]
fn verify_payload_signatures(payload: &Path) -> Result<(), String> {
    let mut mach_objects = Vec::new();
    walk(payload, &mut |path, metadata| {
        if metadata.file_type().is_file() && is_mach_o(path)? {
            mach_objects.push(path.to_path_buf());
        }
        Ok(())
    })?;
    if mach_objects.is_empty() || !mach_objects.iter().any(|path| path == &payload.join("aws")) {
        return Err("AWS package contains no signed native aws executable".into());
    }
    for path in mach_objects {
        verify_aws_executable(&path)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_aws_executable(path: &Path) -> Result<(), String> {
    let requirement = format!(
        "=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"{AWS_TEAM_IDENTIFIER}\""
    );
    let status = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "-R", &requirement])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("failed to verify {}: {err}", path.display()))?;
    if !status.success() {
        return Err(format!(
            "refusing {} because its Amazon Developer ID signature is invalid",
            path.display()
        ));
    }
    let details = command_output("/usr/bin/codesign", &["-d", "-vvv"], Some(path))?;
    for required in [
        "flags=0x10000(runtime)",
        "Authority=Developer ID Application: AMZN Mobile LLC (94KV3E626L)",
        "TeamIdentifier=94KV3E626L",
        "Timestamp=",
    ] {
        if !details.contains(required) {
            return Err(format!(
                "refusing {} because code signing did not confirm {required:?}",
                path.display()
            ));
        }
    }
    let machine = command_output("/usr/bin/uname", &["-m"], None)?;
    let architectures = command_output("/usr/bin/lipo", &["-archs"], Some(path))?;
    let machine = machine.trim();
    if !architectures.split_whitespace().any(|arch| arch == machine) {
        return Err(format!(
            "refusing {} because it does not contain the current {machine} architecture",
            path.display()
        ));
    }
    let entitlements = command_output(
        "/usr/bin/codesign",
        &["-d", "--entitlements", ":-"],
        Some(path),
    )?;
    for blocked in [
        "com.apple.security.get-task-allow",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.cs.debugger",
    ] {
        if entitlements.contains(blocked) {
            return Err(format!(
                "refusing {} because it enables {blocked}",
                path.display()
            ));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn verify_aws_executable(_path: &Path) -> Result<(), String> {
    Err("official AWS CLI signature verification requires macOS".into())
}

fn install_payload(root: &Path, payload: &Path, version: &str, sha256: &str) -> Result<(), String> {
    validate_version(version)?;
    validate_sha256(sha256)?;
    let release_base = format!("{version}-{}", &sha256[..16]);
    let versions = root.join("versions");
    prepare_install_directory(&versions)?;
    if let Ok(current) = release_metadata(&root.join("current")) {
        match compare_versions(version, &current.version)? {
            std::cmp::Ordering::Less => {
                return Err(format!(
                    "refusing to downgrade AWS CLI from {} to {version}",
                    current.version
                ));
            }
            std::cmp::Ordering::Equal if current.sha256 != sha256 => {
                return Err(format!(
                    "refusing AWS CLI {version} because its signed package digest changed"
                ));
            }
            std::cmp::Ordering::Equal if current_release_valid().is_ok() => return Ok(()),
            _ => {}
        }
    }
    let release_name = if versions.join(&release_base).exists() {
        format!("{release_base}-repair-{}", now_nanos())
    } else {
        release_base
    };
    let destination = versions.join(&release_name);
    let replacement = versions.join(format!(".{release_name}.{}", now_nanos()));
    fs::rename(payload, &replacement)
        .map_err(|err| format!("failed to stage official AWS CLI: {err}"))?;
    protect_tree(&replacement)?;
    atomic_write(
        &replacement.join(".av-release"),
        format!("version={version}\nsha256={sha256}\nrelease={release_name}\n").as_bytes(),
        0o444,
    )?;
    let manifest = build_manifest(&replacement)?;
    atomic_write(
        &replacement.join(".av-manifest"),
        manifest.as_bytes(),
        0o444,
    )?;
    verify_protected_manifest(&replacement)?;

    fs::rename(&replacement, &destination)
        .map_err(|err| format!("failed to install official AWS CLI: {err}"))?;

    let link = root.join(format!(".current.{}", now_nanos()));
    std::os::unix::fs::symlink(Path::new("versions").join(&release_name), &link)
        .map_err(|err| format!("failed to stage AWS current release link: {err}"))?;
    fs::rename(&link, root.join("current"))
        .map_err(|err| format!("failed to activate official AWS CLI: {err}"))?;
    Ok(())
}

fn validate_payload_tree(root: &Path) -> Result<(u64, u64), String> {
    let root_metadata =
        fs::symlink_metadata(root).map_err(|err| format!("AWS payload is missing: {err}"))?;
    if !root_metadata.file_type().is_dir() {
        return Err("AWS package payload is not a directory".into());
    }
    if root_metadata.permissions().mode() & 0o7000 != 0 {
        return Err("AWS package payload root has special permission bits".into());
    }
    let mut entries = 0u64;
    let mut bytes = 0u64;
    walk(root, &mut |path, metadata| {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "AWS payload path escaped its root".to_string())?;
        let path_text = relative
            .to_str()
            .filter(|value| !value.chars().any(char::is_control))
            .ok_or_else(|| format!("refusing unsafe AWS payload path {}", path.display()))?;
        if path_text.contains(['\t', '\n', '\r']) {
            return Err(format!(
                "refusing unsafe AWS payload path {}",
                path.display()
            ));
        }
        entries = entries.saturating_add(1);
        if metadata.file_type().is_symlink()
            || !(metadata.file_type().is_file() || metadata.file_type().is_dir())
            || metadata.permissions().mode() & 0o7000 != 0
        {
            return Err(format!(
                "refusing unsupported AWS payload entry {}",
                path.display()
            ));
        }
        if metadata.file_type().is_file() {
            if metadata.nlink() != 1 {
                return Err(format!(
                    "refusing hard-linked AWS payload file {}",
                    path.display()
                ));
            }
            bytes = bytes.saturating_add(metadata.len());
        }
        if entries > MAX_ENTRIES || bytes > MAX_INSTALLED_BYTES {
            return Err("AWS payload exceeds safety limits".into());
        }
        Ok(())
    })?;
    let aws = root.join("aws");
    if !aws.symlink_metadata().is_ok_and(|metadata| {
        metadata.file_type().is_file() && metadata.permissions().mode() & 0o111 != 0
    }) {
        return Err("AWS payload does not contain an executable aws entry point".into());
    }
    Ok((entries, bytes))
}

#[derive(Debug)]
struct ReleaseMetadata {
    version: String,
    sha256: String,
    release: String,
}

fn release_metadata(root: &Path) -> Result<ReleaseMetadata, String> {
    let contents = fs::read_to_string(root.join(".av-release"))
        .map_err(|err| format!("official AWS CLI release metadata is unavailable: {err}"))?;
    let value = |name: &str| {
        let prefix = format!("{name}=");
        let values = contents
            .lines()
            .filter_map(|line| line.strip_prefix(&prefix))
            .collect::<Vec<_>>();
        (values.len() == 1).then(|| values[0].to_string())
    };
    let version =
        value("version").ok_or_else(|| "invalid AWS release version metadata".to_string())?;
    let sha256 =
        value("sha256").ok_or_else(|| "invalid AWS release digest metadata".to_string())?;
    let release =
        value("release").ok_or_else(|| "invalid AWS release name metadata".to_string())?;
    validate_version(&version)?;
    validate_sha256(&sha256)?;
    let base = format!("{version}-{}", &sha256[..16]);
    let valid_release = release == base
        || release
            .strip_prefix(&(base + "-repair-"))
            .is_some_and(|nonce| {
                !nonce.is_empty() && nonce.bytes().all(|byte| byte.is_ascii_digit())
            });
    if !valid_release {
        return Err("AWS release metadata does not bind its version and digest".into());
    }
    Ok(ReleaseMetadata {
        version,
        sha256,
        release,
    })
}

fn compare_versions(left: &str, right: &str) -> Result<std::cmp::Ordering, String> {
    validate_version(left)?;
    validate_version(right)?;
    let left = left
        .split('.')
        .map(|part| {
            part.parse::<u64>()
                .map_err(|_| "AWS version component overflows".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let right = right
        .split('.')
        .map(|part| {
            part.parse::<u64>()
                .map_err(|_| "AWS version component overflows".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(left.cmp(&right))
}

fn parse_latest_version(changelog: &str) -> Result<String, String> {
    versions(changelog)
        .next()
        .ok_or_else(|| "AWS CLI changelog does not begin with a valid release".to_string())
}

fn downloadable_version(
    changelog: &str,
    mut available: impl FnMut(&str) -> Result<bool, String>,
) -> Result<String, String> {
    // ponytail: three releases bounds Doctor latency; use vendor release metadata if AWS adds it.
    for version in versions(changelog).take(3) {
        if available(&version)? {
            return Ok(version);
        }
    }
    Err("AWS CLI has no downloadable recent macOS release".into())
}

fn versions(changelog: &str) -> impl Iterator<Item = String> + '_ {
    changelog
        .lines()
        .zip(changelog.lines().skip(1))
        .filter_map(|(line, underline)| {
            let version = line.trim();
            (validate_version(version).is_ok()
                && underline.len() == version.len()
                && underline.bytes().all(|byte| byte == b'='))
            .then(|| version.to_string())
        })
}

fn build_manifest(root: &Path) -> Result<String, String> {
    build_manifest_with(root, &mut |_, _| Ok(()))
}

fn build_manifest_with(
    root: &Path,
    visit: &mut impl FnMut(&Path, &fs::Metadata) -> Result<(), String>,
) -> Result<String, String> {
    let mut entries = Vec::new();
    walk(root, &mut |path, metadata| {
        visit(path, metadata)?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "AWS manifest path escaped its root".to_string())?
            .to_str()
            .filter(|value| !value.chars().any(char::is_control))
            .ok_or_else(|| format!("unsafe AWS manifest path {}", path.display()))?
            .to_string();
        if relative == ".av-manifest" {
            return Ok(());
        }
        let mode = metadata.permissions().mode() & 0o7777;
        if metadata.file_type().is_dir() {
            entries.push(format!("d\t{mode:04o}\t{relative}"));
        } else if metadata.file_type().is_file() {
            entries.push(format!(
                "f\t{mode:04o}\t{}\t{}\t{relative}",
                metadata.len(),
                sha256_file(path)?
            ));
        } else {
            return Err(format!("unsupported AWS manifest entry {}", path.display()));
        }
        Ok(())
    })?;
    entries.sort();
    Ok(entries.join("\n") + "\n")
}

fn verify_protected_manifest(root: &Path) -> Result<(), String> {
    validate_protected_entry(
        root,
        &fs::symlink_metadata(root).map_err(|err| err.to_string())?,
    )?;
    let actual = build_manifest_with(root, &mut validate_protected_entry)?;
    let expected = fs::read_to_string(root.join(".av-manifest"))
        .map_err(|err| format!("official AWS CLI integrity manifest is unavailable: {err}"))?;
    if actual == expected {
        Ok(())
    } else {
        Err("official AWS CLI files do not match the verified install manifest".into())
    }
}

fn protect_tree(root: &Path) -> Result<(), String> {
    let (required_uid, required_gid) = required_owner();
    let protect = &mut |path: &Path, metadata: &fs::Metadata| {
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| "AWS payload path contains NUL".to_string())?;
        if unsafe { libc::chown(c_path.as_ptr(), required_uid, required_gid) } != 0 {
            return Err(format!(
                "failed to set ownership on {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        let mode = metadata.permissions().mode() & 0o755;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|err| format!("failed to protect {}: {err}", path.display()))
    };
    protect(
        root,
        &fs::symlink_metadata(root)
            .map_err(|err| format!("failed to inspect {}: {err}", root.display()))?,
    )?;
    walk(root, protect)
}

fn validate_protected_entry(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    let (required_uid, required_gid) = required_owner();
    if metadata.file_type().is_symlink()
        || !(metadata.file_type().is_file() || metadata.file_type().is_dir())
        || metadata.uid() != required_uid
        || metadata.gid() != required_gid
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.permissions().mode() & 0o7000 != 0
    {
        return Err(format!(
            "official AWS CLI contains an unsafe entry: {}",
            path.display()
        ));
    }
    Ok(())
}

fn required_owner() -> (u32, u32) {
    if crate::test_env_var("AUTOMIC_VAULT_TEST_AWS_INSTALL_ROOT").is_some() {
        install_root()
            .metadata()
            .map(|metadata| (metadata.uid(), metadata.gid()))
            .unwrap_or_else(|_| (unsafe { libc::geteuid() }, unsafe { libc::getegid() }))
    } else {
        (0, 0)
    }
}

fn walk(
    root: &Path,
    visit: &mut impl FnMut(&Path, &fs::Metadata) -> Result<(), String>,
) -> Result<(), String> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|err| format!("failed to inspect {}: {err}", directory.display()))?
        {
            let entry = entry.map_err(|err| format!("failed to inspect AWS payload: {err}"))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|err| format!("failed to inspect {}: {err}", path.display()))?;
            visit(&path, &metadata)?;
            if metadata.file_type().is_dir() {
                pending.push(path);
            }
        }
    }
    Ok(())
}

fn copy_regular_file(source: &Path, destination: &Path, max_bytes: u64) -> Result<(), String> {
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)
        .map_err(|err| format!("failed to open {}: {err}", source.display()))?;
    let metadata = input
        .metadata()
        .map_err(|err| format!("failed to inspect {}: {err}", source.display()))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err("refusing an invalid AWS CLI package file".into());
    }
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(destination)
        .map_err(|err| format!("failed to create {}: {err}", destination.display()))?;
    let copied = std::io::copy(&mut input.take(max_bytes + 1), &mut output)
        .map_err(|err| format!("failed to copy {}: {err}", source.display()))?;
    if copied != metadata.len() || copied > max_bytes {
        return Err("AWS CLI package changed while it was being copied".into());
    }
    output
        .sync_all()
        .map_err(|err| format!("failed to sync {}: {err}", destination.display()))
}

fn prepare_install_directory(path: &Path) -> Result<(), String> {
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata)
                if metadata.file_type().is_dir()
                    && (crate::test_env_var("AUTOMIC_VAULT_TEST_AWS_INSTALL_ROOT").is_some()
                        || metadata.uid() == 0 && metadata.permissions().mode() & 0o022 == 0) => {}
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

fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "release receipt has no parent".to_string())?;
    let stage = parent.join(format!(".release.{}", now_nanos()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&stage)
            .map_err(|err| format!("failed to create {}: {err}", stage.display()))?;
        file.write_all(contents)
            .and_then(|()| file.sync_all())
            .map_err(|err| format!("failed to write {}: {err}", stage.display()))?;
        fs::set_permissions(&stage, fs::Permissions::from_mode(mode))
            .map_err(|err| format!("failed to protect {}: {err}", stage.display()))?;
        fs::rename(&stage, path)
            .map_err(|err| format!("failed to install {}: {err}", path.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(stage);
    }
    result
}

fn xml_attribute(xml: &str, element: &str, name: &str) -> Result<String, String> {
    let element_prefix = format!("<{element}");
    let elements = xml
        .split(&element_prefix)
        .skip(1)
        .filter_map(|tail| tail.split_once('>').map(|(start, _)| start))
        .collect::<Vec<_>>();
    if elements.len() != 1 {
        return Err(format!(
            "AWS PackageInfo must contain one {element} element"
        ));
    }
    let prefix = format!("{name}=\"");
    let values = elements[0]
        .split_ascii_whitespace()
        .filter_map(|word| {
            word.strip_prefix(&prefix)?
                .split_once('"')
                .map(|(value, _)| value)
        })
        .collect::<Vec<_>>();
    if values.len() != 1 || values[0].is_empty() {
        return Err(format!("AWS PackageInfo must contain one {name} attribute"));
    }
    Ok(values[0].to_string())
}

fn validate_version(version: &str) -> Result<(), String> {
    if version.len() <= 64
        && version.split('.').count() >= 3
        && version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        Ok(())
    } else {
        Err(format!("refusing invalid AWS CLI version {version:?}"))
    }
}

fn validate_sha256(value: &str) -> Result<(), String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("invalid AWS CLI SHA-256".into())
    }
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|err| format!("failed to hash {}: {err}", path.display()))?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|err| format!("failed to hash {}: {err}", path.display()))?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    let digest = context
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    validate_sha256(&digest)?;
    Ok(digest)
}

#[cfg(target_os = "macos")]
fn is_mach_o(path: &Path) -> Result<bool, String> {
    let mut magic = [0u8; 4];
    let mut file =
        File::open(path).map_err(|err| format!("failed to inspect {}: {err}", path.display()))?;
    if file.read_exact(&mut magic).is_err() {
        return Ok(false);
    }
    Ok(matches!(
        magic,
        [0xfe, 0xed, 0xfa, 0xce]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
            | [0xca, 0xfe, 0xba, 0xbf]
            | [0xbf, 0xba, 0xfe, 0xca]
    ))
}

#[cfg(target_os = "macos")]
fn command_output(program: &str, args: &[&str], path: Option<&Path>) -> Result<String, String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null());
    if let Some(path) = path {
        command.arg(path);
    }
    let output = command
        .output()
        .map_err(|err| format!("failed to run {program}: {err}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(text)
    } else {
        Err(format!("{program} rejected AWS release: {}", text.trim()))
    }
}

#[cfg(target_os = "macos")]
fn command_success(program: &str, args: &[&str], path: &Path, failure: &str) -> Result<(), String> {
    command_output(program, args, Some(path))
        .map(|_| ())
        .map_err(|err| format!("{failure}: {err}"))
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new_in(parent: &Path, label: &str) -> Result<Self, String> {
        let path = parent.join(format!("{label}.{}.{}", std::process::id(), now_nanos()));
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

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_info_parser_requires_single_safe_values() {
        let info = r#"<pkg-info identifier="com.amazon.aws.cli2" version="2.36.22"><payload numberOfFiles="8673" installKBytes="218361"/></pkg-info>"#;
        assert_eq!(
            xml_attribute(info, "pkg-info", "identifier").unwrap(),
            PACKAGE_IDENTIFIER
        );
        assert_eq!(
            xml_attribute(info, "pkg-info", "version").unwrap(),
            "2.36.22"
        );
        assert!(validate_version("2.36.22").is_ok());
        assert!(validate_version("../../tmp").is_err());
        assert!(
            xml_attribute(
                &format!("{info}<pkg-info version=\"2.0.0\">"),
                "pkg-info",
                "version"
            )
            .is_err()
        );
    }

    #[test]
    fn payload_validation_rejects_links_and_archive_bomb_limits() {
        let directory = temp_path("payload");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("aws"), "#!/bin/sh\n").unwrap();
        fs::set_permissions(directory.join("aws"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_payload_tree(&directory).is_ok());
        fs::set_permissions(directory.join("aws"), fs::Permissions::from_mode(0o4755)).unwrap();
        assert!(validate_payload_tree(&directory).is_err());
        fs::set_permissions(directory.join("aws"), fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("aws", directory.join("link")).unwrap();
        assert!(validate_payload_tree(&directory).is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn version_comparison_prevents_downgrades() {
        assert_eq!(
            compare_versions("2.36.22", "2.36.21").unwrap(),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_versions("2.36.22", "2.36.22").unwrap(),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            compare_versions("2.35.99", "2.36.1").unwrap(),
            std::cmp::Ordering::Less
        );
        assert!(update_available("2.36.21", "2.36.22").unwrap());
        assert!(!update_available("2.36.22", "2.36.22").unwrap());
        assert!(!update_available("2.36.22", "2.36.21").unwrap());
    }

    #[test]
    fn latest_version_requires_a_numeric_changelog_heading() {
        assert_eq!(
            parse_latest_version("=========\nCHANGELOG\n=========\n\n2.36.22\n=======\nnotes\n")
                .unwrap(),
            "2.36.22"
        );
        assert!(parse_latest_version("CHANGELOG\nlatest\n======\n").is_err());
    }

    #[test]
    fn latest_version_waits_for_the_mac_package() {
        let changelog = "2.36.22\n=======\nnotes\n\n2.36.21\n=======\nnotes\n";
        assert_eq!(
            downloadable_version(changelog, |version| Ok(version == "2.36.21")).unwrap(),
            "2.36.21"
        );
    }

    #[test]
    fn aws_download_is_bound_to_the_reported_version() {
        assert_eq!(
            download_url("2.36.22").unwrap(),
            "https://awscli.amazonaws.com/AWSCLIV2-2.36.22.pkg"
        );
        assert!(download_url("../../latest").is_err());
        assert!(require_expected_version("2.36.22", "2.36.22").is_ok());
        assert!(require_expected_version("2.36.21", "2.36.22").is_err());
    }

    #[test]
    fn protected_manifest_verification_rejects_unsafe_modes_and_content_changes() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root = temp_path("protected-manifest");
        let release = root.join("release");
        fs::create_dir_all(&release).unwrap();
        fs::write(release.join("aws"), "original").unwrap();
        let manifest = build_manifest(&release).unwrap();
        fs::write(release.join(".av-manifest"), manifest).unwrap();
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_AWS_INSTALL_ROOT", &root) };

        assert!(verify_protected_manifest(&release).is_ok());
        fs::set_permissions(release.join("aws"), fs::Permissions::from_mode(0o666)).unwrap();
        assert!(verify_protected_manifest(&release).is_err());
        fs::set_permissions(release.join("aws"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(release.join("aws"), "changed").unwrap();
        assert!(verify_protected_manifest(&release).is_err());

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_AWS_INSTALL_ROOT") };
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn verified_official_package_installs_rehardens_and_detects_corruption() {
        let Some(package) = crate::test_env_var("AUTOMIC_VAULT_TEST_AWS_PACKAGE") else {
            return;
        };
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root = Path::new("/private/tmp")
            .join(format!("av-aws-release-official-install-{}", now_nanos()));
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_AWS_INSTALL_ROOT", &root) };
        let digest = sha256_file(Path::new(&package)).unwrap();

        let expected_version = latest_version().unwrap();
        install_privileged(&expected_version, &digest, Path::new(&package)).unwrap();
        current_release_valid().unwrap();
        let version_output = Command::new(target_path())
            .arg("--version")
            .env_clear()
            .output()
            .unwrap();
        assert!(version_output.status.success());
        assert!(String::from_utf8_lossy(&version_output.stdout).contains("aws-cli/2."));
        install_privileged(&expected_version, &digest, Path::new(&package)).unwrap();
        current_release_valid().unwrap();

        fs::set_permissions(target_path(), fs::Permissions::from_mode(0o755)).unwrap();
        OpenOptions::new()
            .append(true)
            .open(target_path())
            .unwrap()
            .write_all(b"corrupt")
            .unwrap();
        assert!(current_release_valid().is_err());

        install_privileged(&expected_version, &digest, Path::new(&package)).unwrap();
        current_release_valid().unwrap();
        let release_root = fs::canonicalize(target_path())
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        fs::set_permissions(&release_root, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(current_release_valid().is_err());

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_AWS_INSTALL_ROOT") };
        let _ = fs::remove_dir_all(root);
    }

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("av-aws-release-{label}-{}", now_nanos()))
    }
}
