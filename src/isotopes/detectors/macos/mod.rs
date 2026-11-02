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
    append_observed_findings(
        &mut findings,
        process_paths::observed_paths(),
        &mut inspection,
    );
    findings
}

fn append_observed_findings(
    findings: &mut Vec<Finding>,
    paths: std::collections::BTreeMap<OsString, Vec<process_paths::ObservedProcess>>,
    inspection: &mut PathInspection,
) {
    let mut processes =
        std::collections::BTreeMap::<String, (usize, Vec<&process_paths::ObservedProcess>)>::new();
    for (path, observed) in &paths {
        for finding in findings_for_path(path, "Observed user process", inspection) {
            let entry = finding.affected[0].path.clone();
            let (total, sample) = processes.entry(entry.clone()).or_default();
            *total += observed.len();
            sample.extend(observed.iter().take(16 - sample.len()));
            if !findings
                .iter()
                .any(|existing| existing.affected[0].path == entry)
            {
                findings.push(finding);
            }
        }
    }
    for finding in findings {
        let Some((total, observed)) = processes.get(&finding.affected[0].path) else {
            continue;
        };
        finding
            .explanation
            .push_str("\n\nObserved in these processes at scan time:");
        for process in observed.iter().take(16) {
            // Quote untrusted names so control characters cannot impersonate report text.
            finding
                .explanation
                .push_str(&format!("\nPID {} — {:?}", process.pid, process.executable));
        }
        if *total > observed.len() {
            finding.explanation.push_str(&format!(
                "\n… and {} more processes.",
                total - observed.len()
            ));
        }
        finding.explanation.push_str(
            "\nProcesses may have exited since this scan; refresh before acting on a PID.",
        );
    }
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
        let finding = detected
            .iter()
            .find(|finding| finding.affected[0].path == root.to_string_lossy())
            .unwrap();
        assert!(
            finding
                .explanation
                .contains(&format!("PID {} —", child.id()))
        );
        assert!(finding.explanation.contains(&format!(
            "{:?}",
            std::env::current_exe().unwrap().into_os_string()
        )));
        assert!(!finding.explanation.contains("--ignored"));
    }

    #[test]
    fn includes_processes_when_paths_overlap_or_match_the_gui_path() {
        use process_paths::ObservedProcess;
        let root = std::env::temp_dir().join(format!("av-path-attribution-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = std::env::join_paths([root.as_path(), Path::new("/usr/bin")]).unwrap();
        let other_path = std::env::join_paths([root.as_path(), Path::new("/bin")]).unwrap();
        let mut inspection = PathInspection::default();
        let mut findings = findings_for_gui_path(&path, &mut inspection);
        let first = ObservedProcess {
            pid: 123,
            executable: OsString::from("/Applications/Example.app/Contents/MacOS/Example"),
        };
        let second = ObservedProcess {
            pid: 456,
            executable: OsString::from("/tmp/misleading\nname"),
        };
        append_observed_findings(
            &mut findings,
            [(path, vec![first]), (other_path, vec![second])].into(),
            &mut inspection,
        );
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(findings.len(), 1);
        let explanation = &findings[0].explanation;
        assert!(explanation.starts_with("macOS GUI PATH"));
        assert_eq!(explanation.matches("PID 123 —").count(), 1);
        assert!(explanation.contains("PID 456 — \"/tmp/misleading\\nname\""));

        let path = std::env::join_paths([root.as_path(), Path::new("/usr/bin")]).unwrap();
        let mut findings = Vec::new();
        let observed = (1..=20)
            .map(|pid| ObservedProcess {
                pid,
                executable: OsString::from("/bin/example"),
            })
            .collect();
        append_observed_findings(&mut findings, [(path, observed)].into(), &mut inspection);
        assert_eq!(findings[0].explanation.matches("\nPID ").count(), 16);
        assert!(findings[0].explanation.contains("and 4 more processes"));
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
