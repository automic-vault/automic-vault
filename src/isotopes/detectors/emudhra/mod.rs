mod sources;

use base64::Engine;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub(crate) const CERT_PATH: &str = "/etc/ssl/cert.pem";
const ROOTS: [(&str, &str); 2] = [
    (
        "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",
        "emSign ECC Root CA - G3",
    ),
    (
        "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4",
        "AAA Certificate Services",
    ),
];

pub(crate) fn cert_path() -> PathBuf {
    crate::test_env_var("AUTOMIC_VAULT_TEST_EMUDHRA_CERT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(CERT_PATH))
}

// Match DER fingerprints, not the optional human-readable comments in Apple's bundle.
pub(crate) fn filtered_bundle(contents: &str) -> Result<(String, Vec<&'static str>), String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut rest = contents;
    let mut filtered = String::new();
    let mut removed = Vec::new();
    let mut count = 0;
    while let Some(start) = rest.find(BEGIN) {
        filtered.push_str(&rest[..start]);
        rest = &rest[start..];
        let end = rest.find(END).ok_or("unterminated certificate")? + END.len();
        let encoded: String = rest[BEGIN.len()..end - END.len()]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| "invalid certificate encoding")?;
        let digest = ring::digest::digest(&ring::digest::SHA256, &der);
        let fingerprint: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        if let Some((_, name)) = ROOTS.iter().find(|(hash, _)| *hash == fingerprint) {
            if !removed.contains(name) {
                removed.push(*name);
            }
        } else {
            filtered.push_str(&rest[..end]);
        }
        rest = &rest[end..];
        count += 1;
    }
    filtered.push_str(rest);
    if count == 0 {
        return Err("certificate bundle is empty".into());
    }
    validate_bundle(contents)?;
    Ok((filtered, removed))
}

pub(crate) fn validate_bundle(contents: &str) -> Result<(), String> {
    if !contents.contains("-----BEGIN CERTIFICATE-----") {
        return Err("refusing an empty certificate bundle".into());
    }
    let mut child = Command::new("/usr/bin/openssl")
        .env_clear()
        .args(["crl2pkcs7", "-nocrl", "-certfile", "/dev/stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not validate certificate bundle: {e}"))?;
    let write = child.stdin.take().unwrap().write_all(contents.as_bytes());
    let status = child
        .wait()
        .map_err(|e| format!("could not validate certificate bundle: {e}"))?;
    if write.is_err() || !status.success() {
        return Err("invalid certificate bundle".into());
    }
    Ok(())
}

fn insecurity_reasons() -> Result<Vec<String>, String> {
    if !cfg!(target_os = "macos") {
        return Ok(Vec::new());
    }
    let path = cert_path();
    let result = std::fs::read_to_string(&path)
        .map_err(|e| e.to_string())
        .and_then(|contents| filtered_bundle(&contents));
    Ok(match result {
        Ok((_, roots)) => roots.into_iter().map(|root| format!(
            "TLS root {root} still trusts paths used by compromised eMudhra intermediates: {}", path.display()
        )).collect(),
        Err(error) => vec![format!("Could not check TLS root bundle ({error}): {}", path.display())],
    })
}

pub(crate) fn findings(home: &std::path::Path) -> Vec<crate::Finding> {
    let mut findings = super::radioisotope::findings("emudhra", insecurity_reasons, home);
    if cfg!(target_os = "macos")
        && crate::test_env_var("AUTOMIC_VAULT_TEST_EMUDHRA_CERT_PATH").is_none()
    {
        findings.extend(sources::findings(home));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(crate) const EMSIGN: &str = include_str!("testdata/emsign.pem");
    pub(crate) const AAA: &str = include_str!("testdata/aaa.pem");
    pub(crate) const SAFE: &str = include_str!("testdata/unaffected.pem");

    #[test]
    fn removes_exact_roots_without_relying_on_labels() {
        for bad in [EMSIGN, AAA, &format!("{EMSIGN}{AAA}{EMSIGN}")] {
            let input = format!("# custom bundle\n{SAFE}{bad}");
            let (filtered, roots) = filtered_bundle(&input).unwrap();
            assert!(!roots.is_empty());
            assert!(filtered.contains(SAFE.trim()));
            assert!(!filtered.contains(EMSIGN.trim()));
            assert!(!filtered.contains(AAA.trim()));
            assert!(filtered_bundle(&filtered).unwrap().1.is_empty());
        }
    }

    #[test]
    fn preserves_unaffected_bundle_byte_for_byte() {
        let input = format!("# AAA Certificate Services is only a comment\n{SAFE}");
        assert_eq!(filtered_bundle(&input).unwrap(), (input, vec![]));
    }

    #[test]
    fn rejects_empty_truncated_and_invalid_certificates() {
        for input in [
            "",
            "# empty",
            "-----BEGIN CERTIFICATE-----\nAAAA",
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
        ] {
            assert!(filtered_bundle(input).is_err());
        }
    }
}
