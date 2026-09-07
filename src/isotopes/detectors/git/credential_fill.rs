//! Security check: `git credential fill` GitHub token exposure.
//!
//! What this detects:
//! - Effective Git credential-helper configuration that gives GitHub HTTPS
//!   credential access to an ambient or untrusted helper.
//! - Git config that delegates GitHub credentials to an untrusted
//!   `gh auth git-credential` command.
//!
//! Why this matters:
//! - `git credential fill` is intentionally scriptable; any same-user process
//!   can ask Git for credentials if helper policy allows it.
//! - Agents often run shell commands and can trigger the same credential lookup.
//! - A GitHub token exposed this way may carry broad repository authority.
//!
//! Evidence used:
//! - `git config --includes --show-origin` resolves the effective helper chain
//!   without invoking any credential helper.
//! - A GitHub-scoped `credential.helper` command invoking an untrusted
//!   `gh auth git-credential` produces a finding.
//! - A helper chain is exempt only when an empty helper resets inherited
//!   helpers and every effective helper is an absolute, executable `gh` path
//!   carrying the Automic Vault Isotope signature.
//! - The affected file list points at the Git config line that enables the
//!   helper.
//!
//! Known issues:
//! - A configured helper is reported as a Hazard even when it currently has no
//!   cached GitHub credential.
//! - The detector may report a helper command even when `gh` is no longer
//!   installed.
//!
//! Known omissions:
//! - Only `github.com` is queried today.
//! - The detector does not inspect helper caches, token scopes, or token shape.
//! - It does not remediate helper configuration.
//! - It does not query repository-local credential context.
//!
//! Safety notes:
//! - The detector never runs `git credential fill` or any configured helper.
//! - It reads effective configuration through Git's config-only plumbing.
//! - Config-backed findings report the helper line, not any token value.

use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::isotopes::hardeners::{executable, isotope};
use crate::{AffectedFile, Finding};

use super::config::{self, read_to_string};

const NAME: &str = "git-credential-fill";
const DOCS_URL: &str = "https://github.com/automic-vault/automic-vault/blob/main/src/isotopes/detectors/git/credential_fill.md";
const GIT_PATH: &str = "/usr/bin/git";
const GH_HELPER_MESSAGE: &str = "Git config delegates github.com credentials to an untrusted `gh auth git-credential` command. Any same-user process can invoke this configured capability through `git credential fill`. Click Learn More to learn how to fix it.";
const GH_HELPER_SOLUTION: &str = "Edit the affected Git config and remove the `helper = !gh auth git-credential` line; then change GitHub remotes to SSH with `git remote set-url origin git@github.com:OWNER/REPO.git`.";
const AMBIENT_HELPER_MESSAGE: &str = "Git config enables an ambient credential helper for github.com. Any same-user process can invoke it through `git credential fill`. Click Learn More to learn how to fix it.";
const AMBIENT_HELPER_SOLUTION: &str = "Remove the affected credential helper, or reset the effective GitHub helper chain and retain only the signed Automic Vault `gh` Isotope. Use SSH remotes when HTTPS credentials are unnecessary.";
const UNRESET_ISOTOPE_MESSAGE: &str = "The signed Automic Vault `gh` Isotope is configured for GitHub without first resetting inherited credential helpers. The effective chain is not locked to the protected helper.";
const UNRESET_ISOTOPE_SOLUTION: &str = "Run `gh auth setup-git` with the signed Automic Vault `gh` Isotope, or add an empty GitHub-scoped `helper =` before its absolute helper command.";
const CONFIG_INSPECTION_MESSAGE: &str = "Git credential-helper configuration for github.com could not be inspected safely. Automic Vault did not invoke any credential helper.";
const CONFIG_INSPECTION_SOLUTION: &str = "Inspect `git config --includes --show-origin --get-regexp '^credential\\..*\\.helper$|^credential\\.helper$'`, remove ambient helpers, and retain only a reset followed by the signed Automic Vault `gh` Isotope when HTTPS credentials are required.";

#[derive(Debug)]
struct ResolvedGithubCredentialHelper {
    value: String,
    affected: Option<AffectedFile>,
}

fn high(
    explanation: impl Into<String>,
    solution: impl Into<String>,
    affected: Vec<AffectedFile>,
) -> Finding {
    config::high(NAME, DOCS_URL, explanation, solution, affected)
}

fn high_unattributed(explanation: impl Into<String>, solution: impl Into<String>) -> Finding {
    config::high_unattributed(NAME, DOCS_URL, explanation, solution)
}

fn affected(path: &Path, line: usize) -> AffectedFile {
    config::affected(path, line)
}

pub(crate) fn findings(home: &Path) -> Vec<Finding> {
    let helpers = match resolved_github_credential_helpers(home) {
        Ok(helpers) => helpers,
        Err(_) => {
            return vec![high_unattributed(
                CONFIG_INSPECTION_MESSAGE,
                CONFIG_INSPECTION_SOLUTION,
            )];
        }
    };
    findings_with(
        helpers,
        |path| executable(path) && isotope::signature_valid(path, "gh"),
        github_osxkeychain_credential_exists,
    )
}

fn findings_with(
    helpers: Vec<ResolvedGithubCredentialHelper>,
    trusted_gh_isotope: impl Fn(&Path) -> bool,
    osxkeychain_has_github_credential: impl Fn() -> Result<bool, String>,
) -> Vec<Finding> {
    let mut effective_helpers = Vec::new();
    let mut saw_reset = false;
    for helper in helpers {
        if helper.value.is_empty() {
            effective_helpers.clear();
            saw_reset = true;
            continue;
        }
        effective_helpers.push(helper);
    }

    if effective_helpers.is_empty() {
        return Vec::new();
    }

    let mut trusted_count = 0;
    let mut trusted_affected = Vec::new();
    let mut untrusted_gh_count = 0;
    let mut untrusted_gh_affected = Vec::new();
    let mut ambient_count = 0;
    let mut ambient_affected = Vec::new();
    let mut osxkeychain_count = 0;
    let mut osxkeychain_affected = Vec::new();
    for helper in effective_helpers {
        let helper_executable = config::gh_auth_git_credential_executable(&helper.value);
        let exact_helper_executable =
            config::exact_gh_auth_git_credential_executable(&helper.value);
        if helper_executable.as_deref() == exact_helper_executable.as_deref()
            && helper_executable.as_deref().is_some_and(|executable| {
                gh_helper_is_trusted_isotope(executable, &trusted_gh_isotope)
            })
        {
            trusted_count += 1;
            trusted_affected.extend(helper.affected);
        } else if helper_executable.is_some() {
            untrusted_gh_count += 1;
            untrusted_gh_affected.extend(helper.affected);
        } else if osxkeychain_helper(&helper.value) {
            osxkeychain_count += 1;
            osxkeychain_affected.extend(helper.affected);
        } else {
            ambient_count += 1;
            ambient_affected.extend(helper.affected);
        }
    }

    let mut findings = Vec::new();
    if untrusted_gh_count > 0 {
        findings.push(high(
            GH_HELPER_MESSAGE,
            GH_HELPER_SOLUTION,
            untrusted_gh_affected,
        ));
    }
    if ambient_count > 0 {
        findings.push(high(
            AMBIENT_HELPER_MESSAGE,
            AMBIENT_HELPER_SOLUTION,
            ambient_affected,
        ));
    }
    if osxkeychain_count > 0 {
        match osxkeychain_has_github_credential() {
            Ok(true) => findings.push(high(
                AMBIENT_HELPER_MESSAGE,
                AMBIENT_HELPER_SOLUTION,
                osxkeychain_affected,
            )),
            Ok(false) => {}
            Err(_) => findings.push(high(
                CONFIG_INSPECTION_MESSAGE,
                CONFIG_INSPECTION_SOLUTION,
                osxkeychain_affected,
            )),
        }
    }
    if trusted_count > 0 && !saw_reset {
        findings.push(high(
            UNRESET_ISOTOPE_MESSAGE,
            UNRESET_ISOTOPE_SOLUTION,
            trusted_affected,
        ));
    }

    findings
}

fn osxkeychain_helper(value: &str) -> bool {
    let Some(command) = value.split_whitespace().next() else {
        return false;
    };
    let name = Path::new(command)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(command);
    name == "osxkeychain" || name == "git-credential-osxkeychain"
}

fn github_osxkeychain_credential_exists() -> Result<bool, String> {
    let status = Command::new("/usr/bin/security")
        .args(["find-internet-password", "-s", "github.com", "-r", "htps"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "failed to inspect GitHub Keychain metadata".to_string())?;
    match status.code() {
        Some(0) => Ok(true),
        Some(44) => Ok(false),
        _ => Err("could not inspect GitHub Keychain metadata".to_string()),
    }
}

fn gh_helper_is_trusted_isotope(
    helper_executable: &str,
    trusted_gh_isotope: impl Fn(&Path) -> bool,
) -> bool {
    let path = Path::new(helper_executable);
    path.is_absolute()
        && path.file_name().is_some_and(|name| name == "gh")
        && trusted_gh_isotope(path)
}

fn resolved_github_credential_helpers(
    home: &Path,
) -> Result<Vec<ResolvedGithubCredentialHelper>, String> {
    let mut command = Command::new(GIT_PATH);
    resolved_github_credential_helpers_with(home, &mut command)
}

fn resolved_github_credential_helpers_with(
    home: &Path,
    command: &mut Command,
) -> Result<Vec<ResolvedGithubCredentialHelper>, String> {
    let output = match command
        .args([
            "config",
            "--includes",
            "--null",
            "--show-origin",
            "--get-regexp",
            r"^credential\..*\.helper$|^credential\.helper$",
        ])
        .env("HOME", home)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_COMMON_DIR")
        // Keep repository-local config out of this global environment scan.
        .current_dir("/")
        .output()
    {
        Ok(output) => output,
        Err(_) => return Err("failed to inspect Git credential-helper configuration".to_string()),
    };
    if output.status.code() == Some(1) {
        return Ok(Vec::new());
    }
    if !output.status.success() {
        return Err("Git could not inspect credential-helper configuration".to_string());
    }

    parse_resolved_github_credential_helpers(home, &output.stdout)
}

fn parse_resolved_github_credential_helpers(
    home: &Path,
    stdout: &[u8],
) -> Result<Vec<ResolvedGithubCredentialHelper>, String> {
    let stdout = std::str::from_utf8(stdout)
        .map_err(|_| "Git credential-helper configuration was not UTF-8".to_string())?;
    let mut fields = stdout.split('\0');
    let mut helpers = Vec::new();
    let mut occurrences = HashMap::<(std::path::PathBuf, String), usize>::new();
    while let Some(origin) = fields.next() {
        if origin.is_empty() {
            break;
        }
        let Some(entry) = fields.next() else {
            return Err("Git returned malformed credential-helper configuration".to_string());
        };
        let Some((key, value)) = entry.split_once('\n') else {
            return Err("Git returned malformed credential-helper configuration".to_string());
        };
        if !config::credential_helper_key_applies_to_github(key) {
            continue;
        }
        let affected = affected_from_origin(home, origin, value, &mut occurrences);
        helpers.push(ResolvedGithubCredentialHelper {
            value: value.to_string(),
            affected,
        });
    }
    Ok(helpers)
}

fn affected_from_origin(
    home: &Path,
    origin: &str,
    value: &str,
    occurrences: &mut HashMap<(std::path::PathBuf, String), usize>,
) -> Option<AffectedFile> {
    let path = origin.strip_prefix("file:").map(Path::new)?;
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        home.join(path)
    };
    let occurrence = occurrences
        .entry((path.clone(), value.to_string()))
        .or_default();
    let line = read_to_string(&path).and_then(|contents| {
        config::github_credential_helpers(&contents)
            .into_iter()
            .filter(|helper| helper.value == value)
            .nth(*occurrence)
            .map(|helper| helper.line)
    });
    *occurrence += 1;
    Some(match line {
        Some(line) => affected(&path, line),
        None => config::affected_path(&path),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detects_untrusted_github_cli_credential_helper() {
        let home = temp_home("gh-helper");
        let findings = findings_with(
            vec![
                helper(&home, "", 2),
                helper(&home, "!gh auth git-credential", 3),
            ],
            |_| false,
            || Ok(false),
        );

        assert_eq!(
            findings,
            vec![high(
                GH_HELPER_MESSAGE,
                GH_HELPER_SOLUTION,
                vec![affected(&home.join(".gitconfig"), 3)]
            )]
        );
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn accepts_reset_chain_containing_only_signed_gh_isotope() {
        let home = temp_home("signed-gh-helper");
        let gh = Path::new("/opt/homebrew/bin/gh");
        let findings = findings_with(
            vec![
                helper(&home, "", 2),
                helper(&home, "!/opt/homebrew/bin/gh auth git-credential", 3),
            ],
            |path| path == gh,
            || Ok(false),
        );

        assert!(findings.is_empty());
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn signed_gh_without_reset_is_a_config_backed_hazard() {
        let home = temp_home("signed-gh-without-reset");
        let findings = findings_with(
            vec![helper(
                &home,
                "!/opt/homebrew/bin/gh auth git-credential",
                2,
            )],
            |path| path == Path::new("/opt/homebrew/bin/gh"),
            || Ok(false),
        );

        assert_eq!(
            findings,
            vec![high(
                UNRESET_ISOTOPE_MESSAGE,
                UNRESET_ISOTOPE_SOLUTION,
                vec![affected(&home.join(".gitconfig"), 2)]
            )]
        );
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn unsigned_absolute_gh_helper_remains_a_finding() {
        let home = temp_home("unsigned-gh-helper");
        let findings = findings_with(
            vec![
                helper(&home, "", 2),
                helper(&home, "!/usr/local/bin/gh auth git-credential", 3),
            ],
            |_| false,
            || Ok(false),
        );

        assert_eq!(
            findings,
            vec![high(
                GH_HELPER_MESSAGE,
                GH_HELPER_SOLUTION,
                vec![affected(&home.join(".gitconfig"), 3)]
            )]
        );
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn signed_gh_with_trailing_shell_command_remains_a_finding() {
        let home = temp_home("signed-gh-shell-command");
        let findings = findings_with(
            vec![
                helper(&home, "", 2),
                helper(
                    &home,
                    "!/opt/homebrew/bin/gh auth git-credential ; printf password=stolen",
                    3,
                ),
            ],
            |_| true,
            || Ok(false),
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].affected,
            vec![affected(&home.join(".gitconfig"), 3)]
        );
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn osxkeychain_with_github_credential_is_a_config_backed_hazard() {
        let home = temp_home("ambient-helper");
        let findings = findings_with(
            vec![helper(&home, "", 2), helper(&home, "osxkeychain", 3)],
            |_| false,
            || Ok(true),
        );

        assert_eq!(
            findings,
            vec![high(
                AMBIENT_HELPER_MESSAGE,
                AMBIENT_HELPER_SOLUTION,
                vec![affected(&home.join(".gitconfig"), 3)]
            )]
        );
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn osxkeychain_without_github_credential_is_clean() {
        let home = temp_home("empty-osxkeychain");
        let findings = findings_with(
            vec![helper(&home, "", 2), helper(&home, "osxkeychain", 3)],
            |_| false,
            || Ok(false),
        );

        assert!(findings.is_empty());
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn osxkeychain_metadata_failure_is_a_finding() {
        let home = temp_home("unreadable-osxkeychain");
        let findings = findings_with(
            vec![helper(&home, "", 2), helper(&home, "osxkeychain", 3)],
            |_| false,
            || Err("unavailable".to_string()),
        );

        assert_eq!(
            findings,
            vec![high(
                CONFIG_INSPECTION_MESSAGE,
                CONFIG_INSPECTION_SOLUTION,
                vec![affected(&home.join(".gitconfig"), 3)]
            )]
        );
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn empty_osxkeychain_does_not_make_unreset_signed_isotope_safe() {
        let home = temp_home("unreset-isotope-with-osxkeychain");
        let findings = findings_with(
            vec![
                helper(&home, "osxkeychain", 1),
                helper(&home, "!/opt/homebrew/bin/gh auth git-credential", 2),
            ],
            |_| true,
            || Ok(false),
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].explanation, UNRESET_ISOTOPE_MESSAGE);
        assert_eq!(
            findings[0].affected,
            vec![affected(&home.join(".gitconfig"), 2)]
        );
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn arbitrary_helper_is_a_config_backed_hazard() {
        let home = temp_home("arbitrary-helper");
        let findings = findings_with(
            vec![
                helper(&home, "", 2),
                helper(&home, "!/usr/local/bin/custom-helper", 3),
            ],
            |_| false,
            || Ok(false),
        );

        assert_eq!(
            findings,
            vec![high(
                AMBIENT_HELPER_MESSAGE,
                AMBIENT_HELPER_SOLUTION,
                vec![affected(&home.join(".gitconfig"), 3)]
            )]
        );
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn later_reset_discards_inherited_ambient_helper() {
        let home = temp_home("reset-ambient-helper");
        let findings = findings_with(
            vec![
                helper(&home, "osxkeychain", 1),
                helper(&home, "", 2),
                helper(&home, "!/opt/homebrew/bin/gh auth git-credential", 3),
            ],
            |_| true,
            || panic!("discarded osxkeychain helper must not be inspected"),
        );

        assert!(findings.is_empty());
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn git_config_resolves_includes_without_invoking_helpers() {
        let home = temp_home("included-helper");
        let included = home.join(".gitconfig-extra");
        let marker = home.join("helper-invoked");
        fs::write(
            home.join(".gitconfig"),
            "[include]\npath = ~/.gitconfig-extra\n",
        )
        .unwrap();
        fs::write(
            &included,
            format!(
                "[credential]\nhelper = !printf invoked > {}\n[credential \"https://github.com\"]\nhelper =\nhelper = !/opt/homebrew/bin/gh auth git-credential\n",
                marker.display()
            ),
        )
        .unwrap();

        let mut command = Command::new("/usr/bin/git");
        command.env_clear().env("GIT_CONFIG_NOSYSTEM", "1");
        let helpers = resolved_github_credential_helpers_with(&home, &mut command).unwrap();

        assert_eq!(helpers.len(), 3);
        assert_eq!(
            helpers[0].value,
            format!("!printf invoked > {}", marker.display())
        );
        assert_eq!(helpers[1].value, "");
        assert_eq!(
            helpers[2].value,
            "!/opt/homebrew/bin/gh auth git-credential"
        );
        assert_eq!(helpers[2].affected, Some(affected(&included, 5)));
        assert!(!marker.exists());
        assert!(findings_with(helpers, |_| true, || Ok(false)).is_empty());
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn git_config_ignores_forced_repository_environment() {
        let home = temp_home("forced-repository");
        fs::write(
            home.join(".gitconfig"),
            "[credential \"https://github.com\"]\nhelper =\nhelper = !/opt/homebrew/bin/gh auth git-credential\n",
        )
        .unwrap();
        let git_dir = home.join("spoofed.git");
        assert!(
            Command::new("/usr/bin/git")
                .args(["init", "--bare"])
                .arg(&git_dir)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
        fs::write(
            git_dir.join("config"),
            "[credential \"https://github.com\"]\nhelper = !/tmp/spoofed-helper\n",
        )
        .unwrap();

        let mut command = Command::new("/usr/bin/git");
        command
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_DIR", &git_dir);
        let helpers = resolved_github_credential_helpers_with(&home, &mut command).unwrap();

        assert_eq!(helpers.len(), 2);
        assert_eq!(helpers[0].value, "");
        assert_eq!(
            helpers[1].value,
            "!/opt/homebrew/bin/gh auth git-credential"
        );
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn missing_git_is_an_inspection_failure() {
        let home = temp_home("missing-git");
        let mut command = Command::new(home.join("missing-git"));

        let error = resolved_github_credential_helpers_with(&home, &mut command).unwrap_err();

        assert_eq!(
            error,
            "failed to inspect Git credential-helper configuration"
        );
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn parser_ignores_helpers_scoped_to_other_hosts() {
        let home = temp_home("other-host");
        let stdout = b"file:/tmp/gitconfig\0credential.https://example.com.helper\nexample\0command line:\0credential.helper\nglobal\0";

        let helpers = parse_resolved_github_credential_helpers(&home, stdout).unwrap();

        assert_eq!(helpers.len(), 1);
        assert_eq!(helpers[0].value, "global");
        assert_eq!(helpers[0].affected, None);
        let _ = fs::remove_dir_all(home);
    }

    fn helper(home: &Path, value: &str, line: usize) -> ResolvedGithubCredentialHelper {
        ResolvedGithubCredentialHelper {
            value: value.to_string(),
            affected: Some(affected(&home.join(".gitconfig"), line)),
        }
    }

    fn temp_home(label: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "av-git-fill-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
