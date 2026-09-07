//! Shared security parser: Git credential-helper config.
//!
//! What this supports:
//! - Extracting `credential.helper` values from Git config text.
//! - Resolving whether helper configuration applies to `github.com`.
//! - Finding plaintext `store` helper file paths.
//! - Recognizing `gh auth git-credential` helper commands.
//! - Preserving the ordered GitHub helper chain, including empty values that
//!   reset helpers inherited from lower-precedence config files.
//!
//! Why this matters:
//! - Multiple Git detectors need the same boundary logic: which helper applies,
//!   which host it targets, and which file path it references.
//! - Keeping this logic shared prevents detector drift while avoiding a full
//!   Git config parser until it is needed.
//!
//! Evidence model:
//! - Supports section form, such as `[credential]` and
//!   `[credential "https://github.com"]`.
//! - Supports key form, such as `credential.helper = ...` and
//!   `credential.https://github.com.helper = ...`.
//! - Treats global credential helper settings as applying to GitHub.
//! - Expands only `~` and `~/...` for store helper paths.
//!
//! Known issues:
//! - This is intentionally smaller than Git's parser.
//! - It does not implement Git's escape rules, include directives, conditional
//!   includes, multiline values, or platform-specific config precedence.
//! - Shell parsing for helper commands is minimal and only needs enough to
//!   identify `gh auth git-credential` and its executable path.
//!
//! Known omissions:
//! - Repository-local config is not represented here.
//! - System config and global config outside the supplied scan home are not
//!   included by this helper.
//! - Non-GitHub host matching is only present where needed for exclusion.
//!
//! Safety notes:
//! - This module parses strings only; it does not read files or spawn commands.
//! - Callers decide which config files are in scope for a scan.

use std::path::{Path, PathBuf};

use crate::{AffectedFile, Finding};

pub(crate) const HOMEPAGE: &str = "https://git-scm.com/";
const HIGH: &str = "high";

pub(crate) fn high(
    source: &'static str,
    docs_url: &'static str,
    explanation: impl Into<String>,
    solution: impl Into<String>,
    affected: Vec<AffectedFile>,
) -> Finding {
    Finding {
        source,
        homepage: HOMEPAGE,
        severity: HIGH,
        explanation: explanation.into(),
        solution: solution.into(),
        affected,
        docs_url,
    }
}

pub(crate) fn high_unattributed(
    source: &'static str,
    docs_url: &'static str,
    explanation: impl Into<String>,
    solution: impl Into<String>,
) -> Finding {
    high(source, docs_url, explanation, solution, Vec::new())
}

pub(crate) fn affected(path: &Path, line: usize) -> AffectedFile {
    AffectedFile {
        path: path.display().to_string(),
        line: Some(line),
    }
}

pub(crate) fn affected_path(path: &Path) -> AffectedFile {
    AffectedFile {
        path: path.display().to_string(),
        line: None,
    }
}

pub(crate) fn git_config_paths(home: &Path) -> Vec<PathBuf> {
    // Git reads the XDG file before ~/.gitconfig, so preserve that precedence:
    // empty helper values in the latter must reset helpers from the former.
    let mut paths = Vec::new();
    if let Some(config_home) = std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty())
    {
        paths.push(PathBuf::from(config_home).join("git/config"));
    } else {
        paths.push(home.join(".config/git/config"));
    }
    let dot_gitconfig = home.join(".gitconfig");
    if paths.first() != Some(&dot_gitconfig) {
        paths.push(dot_gitconfig);
    }
    paths
}

pub(crate) fn read_to_string(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

#[derive(Clone, Copy)]
enum GitConfigSection {
    Other,
    Credential { applies_to_github: bool },
}

pub(crate) fn store_paths(home: &Path, contents: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for helper in credential_helpers(contents) {
        let value = helper.value;
        if value
            .split_whitespace()
            .next()
            .is_some_and(|word| word == "store")
        {
            paths.push(
                store_helper_file_path(home, value)
                    .unwrap_or_else(|| home.join(".git-credentials")),
            );
        }
    }
    paths
}

pub(crate) struct GithubCredentialHelper<'a> {
    pub(crate) value: &'a str,
    pub(crate) line: usize,
}

pub(crate) fn github_credential_helpers(contents: &str) -> Vec<GithubCredentialHelper<'_>> {
    credential_helpers(contents)
        .into_iter()
        .filter_map(|helper| {
            helper.applies_to_github.then_some(GithubCredentialHelper {
                value: helper.value,
                line: helper.line,
            })
        })
        .collect()
}

struct CredentialHelper<'a> {
    value: &'a str,
    applies_to_github: bool,
    line: usize,
}

fn credential_helpers(contents: &str) -> Vec<CredentialHelper<'_>> {
    let mut helpers = Vec::new();
    let mut section = GitConfigSection::Other;

    for (index, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(next_section) = git_config_section(trimmed) {
            section = next_section;
            continue;
        }

        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let Some(applies_to_github) = credential_helper_applies_to_github(key.trim(), section)
        else {
            continue;
        };
        helpers.push(CredentialHelper {
            value: git_config_value(value),
            applies_to_github,
            line: index + 1,
        });
    }

    helpers
}

fn git_config_section(trimmed: &str) -> Option<GitConfigSection> {
    let name = trimmed.strip_prefix('[')?.strip_suffix(']')?.trim();
    if name.len() < "credential".len()
        || !name[.."credential".len()].eq_ignore_ascii_case("credential")
    {
        return Some(GitConfigSection::Other);
    }
    let rest = &name["credential".len()..];
    let rest = rest.trim();
    if rest.is_empty() {
        return Some(GitConfigSection::Credential {
            applies_to_github: true,
        });
    }
    let scope = rest.trim_matches('"').trim_matches('\'');
    Some(GitConfigSection::Credential {
        applies_to_github: credential_scope_applies_to_github(scope),
    })
}

fn git_config_value(value: &str) -> &str {
    value.trim().trim_matches('"').trim_matches('\'')
}

fn credential_helper_applies_to_github(key: &str, section: GitConfigSection) -> Option<bool> {
    if key.eq_ignore_ascii_case("helper") {
        return match section {
            GitConfigSection::Credential { applies_to_github } => Some(applies_to_github),
            GitConfigSection::Other => None,
        };
    }
    if key.eq_ignore_ascii_case("credential.helper") {
        return Some(true);
    }
    let lower = key.to_ascii_lowercase();
    let scope = lower
        .strip_prefix("credential.")
        .and_then(|rest| rest.strip_suffix(".helper"))
        .map(|scope| &key["credential.".len().."credential.".len() + scope.len()])?;
    Some(credential_scope_applies_to_github(scope))
}

pub(crate) fn credential_helper_key_applies_to_github(key: &str) -> bool {
    credential_helper_applies_to_github(key, GitConfigSection::Other).unwrap_or(false)
}

fn credential_scope_applies_to_github(scope: &str) -> bool {
    let scope = scope.trim();
    if scope.is_empty() {
        return true;
    }
    let scope = scope
        .strip_prefix("https://")
        .or_else(|| scope.strip_prefix("http://"))
        .unwrap_or(scope);
    let host = scope
        .split(['/', ':'])
        .next()
        .unwrap_or(scope)
        .trim_end_matches('.');
    host.eq_ignore_ascii_case("github.com")
}

pub(crate) fn gh_auth_git_credential_executable(value: &str) -> Option<String> {
    let command = value.trim().strip_prefix('!')?;
    let words = shell_words(command)?;
    (words.len() >= 3
        && command_name_is_gh(&words[0])
        && words[1] == "auth"
        && words[2] == "git-credential")
        .then(|| words[0].clone())
}

pub(crate) fn exact_gh_auth_git_credential_executable(value: &str) -> Option<String> {
    let command = value.trim().strip_prefix('!')?;
    let words = shell_words(command)?;
    (words.len() == 3
        && command_name_is_gh(&words[0])
        && words[1] == "auth"
        && words[2] == "git-credential")
        .then(|| words[0].clone())
}

fn command_name_is_gh(command: &str) -> bool {
    Path::new(command)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "gh" || name == "gh.exe")
}

fn shell_words(value: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;

    for ch in value.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(quote_ch) = quote {
            if ch == quote_ch {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            continue;
        }
        if ch.is_whitespace() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(ch);
    }

    if escaped || quote.is_some() {
        return None;
    }
    if !current.is_empty() {
        words.push(current);
    }
    Some(words)
}

fn store_helper_file_path(home: &Path, value: &str) -> Option<PathBuf> {
    let mut words = value.split_whitespace().peekable();
    while let Some(word) = words.next() {
        if let Some(path) = word.strip_prefix("--file=") {
            return Some(expand_home_path(home, path));
        }
        if word == "--file" {
            return words
                .next()
                .map(|path| expand_home_path(home, path))
                .filter(|path| !path.as_os_str().is_empty());
        }
    }
    None
}

fn expand_home_path(home: &Path, value: &str) -> PathBuf {
    if value == "~" {
        return home.to_path_buf();
    }
    if let Some(rest) = value.strip_prefix("~/") {
        return home.join(rest);
    }
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_store_paths() {
        let home = Path::new("/tmp/home");

        assert_eq!(
            store_paths(home, "[credential]\nhelper = store --file ~/.git-store\n"),
            vec![PathBuf::from("/tmp/home/.git-store")]
        );
        assert_eq!(
            store_paths(home, "credential.helper = store --file=/tmp/tokens\n"),
            vec![PathBuf::from("/tmp/tokens")]
        );
    }

    #[test]
    fn detects_github_gh_helper_only_for_github_scope() {
        assert_eq!(
            github_credential_helpers(
                "[credential \"https://github.com\"]\nhelper = !'/Applications/GitHub CLI.app/Contents/MacOS/gh' auth git-credential\n"
            )
            .into_iter()
            .filter_map(|helper| gh_auth_git_credential_executable(helper.value).map(|_| helper.line))
            .collect::<Vec<_>>(),
            vec![2]
        );
        assert!(
            github_credential_helpers(
                "[credential \"https://example.com\"]\nhelper = !gh auth git-credential\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn preserves_github_helper_resets_and_executable_paths() {
        let helpers = github_credential_helpers(
            "[credential \"https://github.com\"]\nhelper =\nhelper = !'/opt/homebrew/bin/gh' auth git-credential\n",
        );

        assert_eq!(helpers.len(), 2);
        assert_eq!(helpers[0].value, "");
        assert_eq!(helpers[0].line, 2);
        assert_eq!(
            gh_auth_git_credential_executable(helpers[1].value).as_deref(),
            Some("/opt/homebrew/bin/gh")
        );
        assert_eq!(
            exact_gh_auth_git_credential_executable(helpers[1].value).as_deref(),
            Some("/opt/homebrew/bin/gh")
        );
        assert_eq!(helpers[1].line, 3);
    }

    #[test]
    fn exact_gh_helper_rejects_trailing_shell_commands() {
        let value = "!/opt/homebrew/bin/gh auth git-credential ; printf password=stolen";

        assert_eq!(
            gh_auth_git_credential_executable(value).as_deref(),
            Some("/opt/homebrew/bin/gh")
        );
        assert!(exact_gh_auth_git_credential_executable(value).is_none());
        assert!(gh_auth_git_credential_executable("!'unterminated auth git-credential").is_none());
    }

    #[test]
    fn recognizes_case_insensitive_git_config_names() {
        assert_eq!(
            github_credential_helpers(
                "[CrEdEnTiAl \"https://github.com\"]\nHeLpEr = !gh auth git-credential\n"
            )
            .len(),
            1
        );
    }
}
