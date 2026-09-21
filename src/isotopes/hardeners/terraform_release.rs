use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;

pub(crate) const TARGET_PATH: &str = "/usr/local/bin/terraform";
const INDEX_URL: &str = "https://releases.hashicorp.com/terraform/index.json";
const MAX_INDEX_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;

pub(crate) fn download(destination: &Path) -> Result<String, String> {
    let index = fetch(INDEX_URL, MAX_INDEX_BYTES, Duration::from_secs(15))?;
    let version = latest_stable_version(&index)?;
    let url = release_url(&version, std::env::consts::ARCH)?;
    download_to(
        &url,
        destination,
        MAX_ARCHIVE_BYTES,
        Duration::from_secs(180),
    )?;
    super::isotope::sha256_file(destination)
}

fn release_url(version: &str, architecture: &str) -> Result<String, String> {
    let architecture = match architecture {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        _ => return Err("official Terraform is supported only on macOS arm64 and x86_64".into()),
    };
    Ok(format!(
        "https://releases.hashicorp.com/terraform/{version}/terraform_{version}_darwin_{architecture}.zip"
    ))
}

pub(crate) fn install_privileged(expected_sha256: &str, archive: &Path) -> Result<(), String> {
    if crate::test_env_var("AUTOMIC_VAULT_TEST_TERRAFORM_INSTALL_DIR").is_none()
        && super::effective_uid() != 0
    {
        return Err("Terraform installation requires root".into());
    }
    super::isotope::validate_sha256(expected_sha256)?;
    let bin = install_dir();
    super::isotope::prepare_install_directory(&bin)?;
    let suffix = format!("{}.{}", std::process::id(), super::isotope::now_nanos());
    let trusted_archive = bin.join(format!(".terraform-release-{suffix}.zip"));
    let staged = bin.join(format!(".terraform-{suffix}"));
    let result = (|| {
        super::isotope::copy_new(archive, &trusted_archive)?;
        if super::isotope::sha256_file(&trusted_archive)? != expected_sha256 {
            return Err("downloaded Terraform archive changed before installation".into());
        }
        verify_listing(&trusted_archive)?;
        extract_binary(&trusted_archive, &staged)?;
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("failed to protect {}: {error}", staged.display()))?;
        super::terraform::verify_target(super::terraform::Tool::Terraform, &staged)?;
        fs::rename(&staged, bin.join("terraform"))
            .map_err(|error| format!("failed to install Terraform: {error}"))
    })();
    let _ = fs::remove_file(&trusted_archive);
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

fn fetch(url: &str, limit: u64, timeout: Duration) -> Result<String, String> {
    if let Some(index) = crate::test_env_string("AUTOMIC_VAULT_TEST_TERRAFORM_RELEASE_INDEX") {
        return Ok(index);
    }
    let mut body = agent(timeout)
        .get(url)
        .call()
        .map_err(|error| format!("failed to fetch {url}: {error}"))?
        .into_body()
        .into_reader()
        .take(limit + 1);
    let mut bytes = Vec::new();
    body.read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read {url}: {error}"))?;
    if bytes.len() as u64 > limit {
        return Err(format!(
            "refusing oversized Terraform release metadata from {url}"
        ));
    }
    String::from_utf8(bytes).map_err(|_| "Terraform release metadata is not UTF-8".into())
}

fn download_to(url: &str, destination: &Path, limit: u64, timeout: Duration) -> Result<(), String> {
    let mut body = agent(timeout)
        .get(url)
        .call()
        .map_err(|error| format!("failed to download {url}: {error}"))?
        .into_body()
        .into_reader()
        .take(limit + 1);
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(destination)
        .map_err(|error| format!("failed to create {}: {error}", destination.display()))?;
    let size = std::io::copy(&mut body, &mut output)
        .map_err(|error| format!("failed to download {url}: {error}"))?;
    if size > limit {
        return Err("refusing a Terraform archive larger than 128 MiB".into());
    }
    output
        .sync_all()
        .map_err(|error| format!("failed to sync {}: {error}", destination.display()))
}

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .timeout_global(Some(timeout))
        .build()
        .into()
}

fn latest_stable_version(index: &str) -> Result<String, String> {
    let value: Value = serde_json::from_str(index)
        .map_err(|error| format!("invalid Terraform release metadata: {error}"))?;
    value
        .get("versions")
        .and_then(Value::as_object)
        .and_then(|versions| {
            versions
                .keys()
                .filter_map(|version| version_key(version).map(|key| (key, version)))
                .max_by_key(|(key, _)| *key)
                .map(|(_, version)| version.clone())
        })
        .ok_or_else(|| "Terraform release metadata contains no stable version".into())
}

fn version_key(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.');
    let key = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(key)
}

fn verify_listing(archive: &Path) -> Result<(), String> {
    let output = Command::new("/usr/bin/unzip")
        .args(["-Z1"])
        .arg(archive)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .output()
        .map_err(|error| format!("failed to inspect Terraform archive: {error}"))?;
    if !output.status.success() {
        return Err("invalid Terraform release archive".into());
    }
    let listing = String::from_utf8(output.stdout)
        .map_err(|_| "Terraform archive paths are not UTF-8".to_string())?;
    let mut entries = listing.lines().collect::<Vec<_>>();
    entries.sort_unstable();
    if entries != ["LICENSE.txt", "terraform"] {
        return Err("Terraform archive contains unexpected entries".into());
    }
    Ok(())
}

fn extract_binary(archive: &Path, destination: &Path) -> Result<(), String> {
    let mut child = Command::new("/usr/bin/unzip")
        .args(["-p"])
        .arg(archive)
        .arg("terraform")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("failed to extract Terraform: {error}"))?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(destination)
        .map_err(|error| format!("failed to create {}: {error}", destination.display()))?;
    let size = match std::io::copy(
        &mut child
            .stdout
            .take()
            .expect("piped stdout")
            .take(MAX_BINARY_BYTES + 1),
        &mut output,
    ) {
        Ok(size) => size,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("failed to extract Terraform: {error}"));
        }
    };
    if size == 0 || size > MAX_BINARY_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err("refusing invalid or oversized Terraform executable".into());
    }
    let status = child
        .wait()
        .map_err(|error| format!("failed to finish Terraform extraction: {error}"))?;
    if !status.success() {
        return Err("refusing invalid Terraform executable".into());
    }
    output
        .sync_all()
        .map_err(|error| format!("failed to sync {}: {error}", destination.display()))
}

fn install_dir() -> PathBuf {
    crate::test_env_var("AUTOMIC_VAULT_TEST_TERRAFORM_INSTALL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/local/bin"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_archive_matches_the_executing_architecture() {
        for (architecture, upstream) in [("aarch64", "arm64"), ("x86_64", "amd64")] {
            assert_eq!(
                release_url("1.15.9", architecture).unwrap(),
                format!(
                    "https://releases.hashicorp.com/terraform/1.15.9/terraform_1.15.9_darwin_{upstream}.zip"
                )
            );
        }
        assert!(release_url("1.15.9", "unknown").is_err());
    }

    #[test]
    fn release_index_selects_only_the_highest_stable_semver() {
        let index = r#"{"versions":{"1.15.9":{},"1.16.0-rc1":{},"1.14.12":{},"bad":{}}}"#;
        assert_eq!(latest_stable_version(index).unwrap(), "1.15.9");
    }

    #[test]
    fn installer_rejects_an_unsigned_binary_before_replacing_the_target() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let root = std::env::temp_dir().join(format!(
            "av-terraform-release-test-{}-{}",
            std::process::id(),
            super::super::isotope::now_nanos()
        ));
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("LICENSE.txt"), "license").unwrap();
        fs::write(source.join("terraform"), "unsigned").unwrap();
        let archive = root.join("terraform.zip");
        let status = Command::new("/usr/bin/zip")
            .args(["-q"])
            .arg(&archive)
            .args(["LICENSE.txt", "terraform"])
            .current_dir(&source)
            .status()
            .unwrap();
        assert!(status.success());
        let digest = super::super::isotope::sha256_file(&archive).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_TERRAFORM_INSTALL_DIR", &destination);
            std::env::set_var("AUTOMIC_VAULT_TEST_ISOTOPE_DIRECT_DIR", &destination);
        }
        let error = install_privileged(&digest, &archive).unwrap_err();
        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_TERRAFORM_INSTALL_DIR");
            std::env::remove_var("AUTOMIC_VAULT_TEST_ISOTOPE_DIRECT_DIR");
        }
        assert!(error.contains("Target signature is invalid"));
        assert!(!destination.join("terraform").exists());
        let _ = fs::remove_dir_all(root);
    }
}
