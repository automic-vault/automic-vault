//! Draft signing-key ACL inspection. No signing, key export, or trust evaluation.
//! Blocked on the legacy ACL API lock race documented in detector.md.
#[cfg(target_os = "macos")]
mod keychain;

use crate::Finding;
use std::path::Path;

#[derive(Default)]
struct Inspection {
    all_apps: usize,
    codesign: usize,
    unknown: usize,
}

pub(crate) fn findings(_home: &Path) -> Vec<Finding> {
    #[cfg(target_os = "macos")]
    {
        from_inspection(keychain::inspect().unwrap_or(Inspection {
            unknown: 1,
            ..Inspection::default()
        }))
    }
    #[cfg(not(target_os = "macos"))]
    Vec::new()
}

fn from_inspection(inspection: Inspection) -> Vec<Finding> {
    let mut explanations = Vec::new();
    if inspection.all_apps + inspection.codesign != 0 {
        explanations.push(format!(
            "Code-signing key access Hazard: {} signing identity ACL(s) trust all applications and {} trust /usr/bin/codesign. Agent-controlled code may be able to sign as you. Keychain lock state, partition restrictions, and other authentication requirements may still prevent unattended signing; no key was used to verify this.",
            inspection.all_apps, inspection.codesign,
        ));
    }
    if inspection.unknown != 0 {
        explanations.push("Code-signing key access inspection is incomplete: some identity or ACL metadata could not be read or interpreted. This Scan cannot establish those keys’ access controls; no key was used to probe them.".to_string());
    }
    explanations.into_iter().map(|explanation| Finding {
        source: "codesign",
        homepage: "https://developer.apple.com/documentation/security/code-signing-services",
        severity: "medium",
        explanation,
        solution: "Automic Vault does not yet provide a Hardener for code-signing keys. Review the signing identity’s Keychain access controls; changing them may interrupt builds.".to_string(),
        affected: Vec::new(),
        docs_url: "https://github.com/automic-vault/automic-vault/blob/main/src/isotopes/detectors/codesign/detector.md",
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_medium_hazards_and_incomplete_inspection_without_claiming_protection() {
        assert!(from_inspection(Inspection::default()).is_empty());
        let findings = from_inspection(Inspection {
            all_apps: 1,
            codesign: 2,
            unknown: 1,
        });
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|finding| finding.severity == "medium"));
        assert!(findings[0].explanation.contains(
            "1 signing identity ACL(s) trust all applications and 2 trust /usr/bin/codesign"
        ));
        assert!(findings[0].explanation.contains("no key was used"));
        assert!(findings[1].explanation.contains("incomplete"));
        assert!(
            findings
                .iter()
                .all(|finding| finding.solution.contains("does not yet provide a Hardener"))
        );
    }
}
