use std::ffi::OsString;
use std::path::Path;

use crate::path_security::{PathInspection, user_writable_path_reason};
use crate::{AffectedFile, Finding};

mod process_paths;

const DOCS_URL: &str = "https://github.com/automic-vault/automic-vault/blob/main/src/isotopes/detectors/macos/detector.md";

pub(crate) fn findings(_home: &Path) -> Vec<Finding> {
    let mut inspection = PathInspection::default();
    let mut findings = gui_path().map_or_else(Vec::new, |path| {
        findings_for_gui_path(&path, &mut inspection)
    });
    let mut seen = findings
        .iter()
        .map(|finding| finding.affected[0].path.clone())
        .collect::<std::collections::HashSet<_>>();
    for path in process_paths::observed_paths() {
        findings.extend(
            findings_for_path(&path, "Observed user process", &mut inspection)
                .into_iter()
                .filter(|finding| seen.insert(finding.affected[0].path.clone())),
        );
    }
    findings
}

fn findings_for_gui_path(path: &std::ffi::OsStr, inspection: &mut PathInspection) -> Vec<Finding> {
    if path.is_empty() {
        return Vec::new();
    }

    findings_for_path(path, "macOS GUI", inspection)
}

fn findings_for_path(
    path: &std::ffi::OsStr,
    source: &str,
    inspection: &mut PathInspection,
) -> Vec<Finding> {
    inspection
        .user_writable_entries_before_system_paths(path)
        .into_iter()
        .map(|entry| Finding {
            source: "macOS",
            homepage: DOCS_URL,
            severity: "medium",
            explanation: user_writable_path_reason(source, &entry),
            solution: super::detector_config("macOS").solution.clone(),
            affected: vec![AffectedFile {
                path: entry.display().to_string(),
                line: None,
            }],
            docs_url: DOCS_URL,
        })
        .collect()
}

#[cfg(target_os = "macos")]
pub(super) fn gui_path() -> Option<OsString> {
    use std::os::unix::ffi::OsStringExt;
    use std::process::{Command, Stdio};

    let mut output = Command::new("/bin/launchctl")
        .args(["getenv", "PATH"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    while output
        .stdout
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        output.stdout.pop();
    }
    Some(OsString::from_vec(output.stdout))
}

#[cfg(not(target_os = "macos"))]
pub(super) fn gui_path() -> Option<OsString> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    #[ignore = "subprocess fixture for the observed PATH regression test"]
    fn path_process_fixture() {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
    }

    #[test]
    fn finds_shell_inherited_path_even_when_scanner_path_differs() {
        let root = std::env::temp_dir().join(format!("av-observed-path-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = std::env::join_paths([root.as_path(), Path::new("/usr/bin")]).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "isotopes::detectors::macos::tests::path_process_fixture",
            ])
            .env_clear()
            .env("PATH", path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let detected = findings(Path::new("/unused"));
        child.kill().unwrap();
        child.wait().unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        assert!(
            detected.iter().any(|finding| finding
                .affected
                .iter()
                .any(|file| file.path == root.to_string_lossy())),
            "scan must inspect PATH inherited by running user commands"
        );
    }

    #[test]
    fn reports_each_writable_gui_entry_before_a_system_path() {
        let root = std::env::temp_dir().join(format!("av-macos-path-{}", std::process::id()));
        let writable = root.join("writable");
        let protected = root.join("protected");
        std::fs::create_dir_all(&writable).unwrap();
        std::fs::create_dir_all(&protected).unwrap();
        std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o555)).unwrap();
        let path = std::env::join_paths([&writable, &protected]).unwrap();

        let findings = findings_for_gui_path(&path, &mut PathInspection::default());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source, "macOS");
        assert_eq!(findings[0].severity, "medium");
        assert_eq!(findings[0].affected[0].path, writable.display().to_string());
        std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn does_not_treat_an_unset_launchd_path_as_an_empty_entry() {
        assert!(
            findings_for_gui_path(std::ffi::OsStr::new(""), &mut PathInspection::default())
                .is_empty()
        );
    }
}
