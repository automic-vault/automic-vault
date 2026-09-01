use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::Finding;
use crate::path_security::USER_WRITABLE_PATH_REASON;

mod acli;
mod akamai;
mod algolia;
mod aliyun_cli;
mod ansible;
mod argocd;
mod ast_cli;
mod astra;
mod atuin;
mod aws_cli;
mod aws_sso_cli;
mod aws_vault;
mod azure_cli;
mod bash;
mod bitwarden_cli;
mod buf;
mod bun;
mod cariddi;
mod censys;
mod certbot;
mod checkov;
mod circleci;
mod civo;
mod cloudflare_wrangler;
mod cloudflared;
mod cloudsmith_cli;
pub(crate) mod codex;
mod composer;
mod curl;
mod databricks;
mod dcos_cli;
mod docker;
mod docker_credential_helper;
mod docker_machine;
mod doctl;
mod dropbox_uploader;
mod envchain;
mod fastlane;
mod fastly;
mod fauna_shell;
mod firebase_cli;
mod flyctl;
mod gallery_dl;
mod gcli;
pub(crate) mod gh_cli;
mod git;
mod glab;
mod goat;
mod gotify;
mod gptcommit;
mod grafanactl;
mod graphite;
mod hcloud;
mod helm;
mod heroku;
mod homebrew;
mod httpie;
mod huggingface_cli;
mod imap_backup;
mod jfrog_cli;
mod js_release_age;
mod k6;
mod kubernetes_cli;
mod luarocks;
mod macos;
mod maestro;
mod mariadb;
mod maven;
mod mcp_remote;
mod mercurial;
mod midnight_commander;
mod minio_mc;
mod mkcert;
mod mongodb_atlas_cli;
mod mycli;
mod mysql;
mod mysql_8_0;
mod mysql_8_4;
mod mysql_client;
mod netlify_cli;
mod node;
mod node_18;
mod npm;
mod nuget;
mod oauth2l;
mod oci_cli;
mod opencode;
mod openhue_cli;
mod openssh;
mod openssl_3;
mod openstackclient;
mod opentofu;
mod openvpn;
mod ordercli;
mod ossutil;
mod oxide_cli;
mod perl;
mod phylum_cli;
mod pianobar;
mod plumber;
mod pnpm;
mod podman;
pub(crate) use podman::candidate_auth_paths as podman_auth_paths;
mod poetry;
mod pulumi;
mod qwen_code;
mod radioisotope;
mod railway;
mod rclone;
mod rsync;
mod ruby;
mod runpodctl;
mod rust;
mod s3cmd;
mod sbt;
mod secretlint;
mod sentry_cli;
mod shodan;
mod sip;
mod skopeo;
mod snowflake_cli;
mod snyk;
mod soracom_cli;
mod sqlcmd;
mod sshpass;
mod sslmate;
mod stripe_cli;
pub(crate) mod sudo;
mod supabase;
mod tailscale;
mod talosctl;
mod terraform;
mod terraform_core;
mod todoist_cli;
mod transifex_cli;
mod travis;
mod twine;
mod uaa_cli;
mod uv;
mod vagrant;
mod vault;
mod vercel_cli;
mod virustotal_cli;
mod vultr;
mod wakatime_cli;
mod wget;
mod wget2;
mod wsk;
mod yarn;
mod yt_dlp;
mod zsh;

pub(crate) struct DetectorMetadata {
    pub(crate) name: String,
    pub(crate) homepage: String,
    pub(crate) docs_url: String,
    pub(crate) documentation: &'static str,
    pub(crate) watch_scopes: Vec<DetectorWatchScope>,
}

pub(crate) struct DetectorWatchScope {
    pub(crate) path: String,
    pub(crate) recursive: bool,
}

pub(crate) struct DetectorResult {
    pub(crate) detectors: Vec<String>,
    pub(crate) finding: Finding,
}

struct Detector {
    module: &'static str,
    findings: fn(&Path) -> Vec<Finding>,
    docs_url: &'static str,
    documentation: &'static str,
}

#[cfg(test)]
const DOCS_BASE: &str =
    "https://github.com/automic-vault/automic-vault/blob/main/src/isotopes/detectors/";

macro_rules! detector {
    ($module:ident) => {
        Detector {
            module: stringify!($module),
            findings: $module::findings,
            docs_url: concat!(
                "https://github.com/automic-vault/automic-vault/blob/main/src/isotopes/detectors/",
                stringify!($module),
                "/detector.md"
            ),
            documentation: include_str!(concat!(stringify!($module), "/detector.md")),
        }
    };
    ($package:ident::$module:ident, $name:literal) => {
        Detector {
            module: $name,
            findings: $package::$module::findings,
            docs_url: concat!(
                "https://github.com/automic-vault/automic-vault/blob/main/src/isotopes/detectors/",
                stringify!($package),
                "/",
                stringify!($module),
                ".md"
            ),
            documentation: include_str!(concat!(
                stringify!($package),
                "/",
                stringify!($module),
                ".md"
            )),
        }
    };
}

const DETECTORS: &[Detector] = &[
    detector!(acli),
    detector!(akamai),
    detector!(algolia),
    detector!(aliyun_cli),
    detector!(ansible),
    detector!(argocd),
    detector!(ast_cli),
    detector!(astra),
    detector!(atuin),
    detector!(aws_cli::credentials_file, "aws-cli-credentials-file"),
    detector!(aws_cli::legacy_plugins, "aws-cli-legacy-plugins"),
    detector!(aws_cli::login_cache, "aws-cli-login-cache"),
    detector!(aws_sso_cli),
    detector!(aws_vault),
    detector!(azure_cli),
    detector!(bash),
    detector!(bitwarden_cli),
    detector!(buf),
    detector!(bun),
    detector!(cariddi::persisted_output, "cariddi-persisted-output"),
    detector!(cariddi::shell_history, "cariddi-shell-history"),
    detector!(censys),
    detector!(certbot),
    detector!(checkov),
    detector!(circleci),
    detector!(civo),
    detector!(cloudflare_wrangler),
    detector!(cloudflared),
    detector!(cloudsmith_cli),
    detector!(codex),
    detector!(composer),
    detector!(curl),
    detector!(databricks),
    detector!(dcos_cli),
    detector!(docker::credential_helpers, "docker-credential-helpers"),
    detector!(docker::registry_credentials, "docker-registry-credentials"),
    detector!(docker_credential_helper),
    detector!(docker_machine),
    detector!(doctl),
    detector!(dropbox_uploader),
    detector!(envchain),
    detector!(fastlane),
    detector!(fastly),
    detector!(fauna_shell),
    detector!(firebase_cli),
    detector!(flyctl),
    detector!(gallery_dl),
    detector!(gcli),
    detector!(gh_cli::hosts_token, "gh-cli-hosts-token"),
    detector!(gh_cli::keychain_access, "gh-cli-keychain-access"),
    detector!(git::credential_fill, "git-credential-fill"),
    detector!(git::credential_oauth, "git-credential-oauth"),
    detector!(git::credentials_file, "git-credentials-file"),
    detector!(glab),
    detector!(goat),
    detector!(gotify),
    detector!(gptcommit),
    detector!(grafanactl),
    detector!(graphite),
    detector!(hcloud),
    detector!(helm),
    detector!(heroku),
    detector!(homebrew),
    detector!(httpie),
    detector!(huggingface_cli),
    detector!(imap_backup),
    detector!(jfrog_cli),
    detector!(k6),
    detector!(kubernetes_cli),
    detector!(luarocks),
    detector!(maestro),
    detector!(macos),
    detector!(mariadb),
    detector!(maven),
    detector!(mcp_remote),
    detector!(mercurial),
    detector!(midnight_commander),
    detector!(minio_mc),
    detector!(mkcert),
    detector!(mongodb_atlas_cli),
    detector!(mycli),
    detector!(mysql),
    detector!(mysql_client),
    detector!(mysql_8_0),
    detector!(mysql_8_4),
    detector!(netlify_cli),
    detector!(node),
    detector!(node_18),
    detector!(npm),
    detector!(nuget),
    detector!(oauth2l),
    detector!(oci_cli),
    detector!(opencode),
    detector!(openhue_cli),
    detector!(openssh),
    detector!(openssl_3),
    detector!(openstackclient),
    detector!(opentofu),
    detector!(openvpn),
    detector!(ordercli),
    detector!(ossutil),
    detector!(oxide_cli),
    detector!(perl),
    detector!(phylum_cli),
    detector!(pianobar),
    detector!(plumber),
    detector!(pnpm::auth_token, "pnpm-auth-token"),
    detector!(pnpm::minimum_release_age, "pnpm-minimum-release-age"),
    detector!(podman),
    detector!(poetry),
    detector!(pulumi),
    detector!(qwen_code),
    detector!(railway),
    detector!(rclone),
    detector!(rsync),
    detector!(ruby),
    detector!(runpodctl),
    detector!(rust),
    detector!(s3cmd),
    detector!(sbt),
    detector!(secretlint::persisted_report, "secretlint-persisted-report"),
    detector!(secretlint::shell_history, "secretlint-shell-history"),
    detector!(sentry_cli),
    detector!(shodan),
    detector!(sip),
    detector!(skopeo),
    detector!(snowflake_cli),
    detector!(snyk),
    detector!(soracom_cli),
    detector!(sqlcmd),
    detector!(sshpass),
    detector!(sslmate),
    detector!(stripe_cli),
    detector!(sudo),
    detector!(supabase),
    detector!(tailscale),
    detector!(talosctl),
    detector!(terraform),
    detector!(terraform_core),
    detector!(todoist_cli),
    detector!(transifex_cli),
    detector!(travis),
    detector!(twine),
    detector!(uaa_cli),
    detector!(uv),
    detector!(vagrant),
    detector!(vault),
    detector!(vercel_cli),
    detector!(virustotal_cli),
    detector!(vultr),
    detector!(wakatime_cli),
    detector!(wget),
    detector!(wget2),
    detector!(wsk),
    detector!(yarn),
    detector!(yt_dlp),
    detector!(zsh),
];

pub(crate) fn findings(home: &Path) -> Vec<Finding> {
    findings_for(home, &[])
        .expect("the full detector set is always valid")
        .into_iter()
        .map(|result| result.finding)
        .collect()
}

pub(crate) fn findings_for(
    home: &Path,
    detector_names: &[String],
) -> Result<Vec<DetectorResult>, String> {
    let selected = detector_names
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    for name in &selected {
        if !DETECTORS
            .iter()
            .any(|detector| detector_name(detector.module) == *name)
        {
            return Err(format!("unknown detector: {name}"));
        }
    }

    let mut findings = Vec::new();
    for detector in DETECTORS {
        let name = detector_name(detector.module);
        if !selected.is_empty() && !selected.contains(name.as_str()) {
            continue;
        }
        let mut detected = (detector.findings)(home);
        for finding in &mut detected {
            finding.homepage = detector.docs_url;
            finding.docs_url = detector.docs_url;
            if let Some(solution) = documented_solution(detector.documentation) {
                finding.solution = solution;
            }
        }
        findings.extend(detected.into_iter().map(|finding| DetectorResult {
            detectors: vec![name.clone()],
            finding,
        }));
    }
    Ok(merge_duplicate_owned_shell_path_findings(findings))
}

fn merge_duplicate_owned_shell_path_findings(findings: Vec<DetectorResult>) -> Vec<DetectorResult> {
    let mut merged: Vec<DetectorResult> = Vec::with_capacity(findings.len());
    for mut finding in findings {
        // Shell docs cover credential assignments and PATH hazards, but each
        // finding needs only the mitigation for the condition it reports.
        if shell_path_entry(&finding.finding).is_some() {
            finding.finding.solution = shell_path_solution(finding.finding.source);
        }
        let existing = shell_path_entry(&finding.finding).and_then(|entry| {
            merged.iter_mut().find(|candidate| {
                candidate.finding.source != finding.finding.source
                    && shell_path_entry(&candidate.finding) == Some(entry)
            })
        });
        match existing {
            Some(existing) => {
                merge_shell_path_finding(&mut existing.finding);
                existing.detectors.extend(finding.detectors);
            }
            None => merged.push(finding),
        }
    }
    merged
}

const SHELL_PATH_FINDING_SOURCES: &[&str] = &["bash", "zsh"];
const MERGED_SHELL_PATH_SOURCE: &str = "bash+zsh";

/// `bash` and `zsh` each detect the same process-wide `$PATH` independently,
/// so an insecure directory is reported once per shell. Collapse those
/// duplicates into a single finding that names every affected shell instead
/// of doubling the audit for anyone with both shells configured.
#[cfg(test)]
fn merge_duplicate_shell_path_findings(findings: Vec<Finding>) -> Vec<Finding> {
    merge_duplicate_owned_shell_path_findings(
        findings
            .into_iter()
            .map(|finding| DetectorResult {
                detectors: vec![finding.source.to_string()],
                finding,
            })
            .collect(),
    )
    .into_iter()
    .map(|result| result.finding)
    .collect()
}

/// The PATH entry a shell PATH finding reports, taken from the explanation
/// rather than `affected`: `affected` keeps only entries starting with `/` or
/// `~`, so it is empty for the relative and empty entries `path_security`
/// deliberately reports, and cannot distinguish one from another.
fn shell_path_entry(finding: &Finding) -> Option<&str> {
    if !SHELL_PATH_FINDING_SOURCES.contains(&finding.source) {
        return None;
    }
    finding
        .explanation
        .split_once(USER_WRITABLE_PATH_REASON)?
        .1
        .strip_prefix(": ")
}

fn shell_path_solution(source: &str) -> String {
    let documentation = DETECTORS
        .iter()
        .find(|detector| detector.module == source)
        .expect("shell PATH findings have a registered detector")
        .documentation;
    documented_section(documentation, "## PATH Mitigation")
        .map(first_paragraph)
        .filter(|solution| !solution.is_empty())
        .expect("shell detector documentation has a PATH mitigation")
}

fn merge_shell_path_finding(existing: &mut Finding) {
    if let Some(entry) = shell_path_entry(existing) {
        existing.explanation = format!(
            "Bash and zsh PATH have a user-writable directory before protected system directories: {entry}"
        );
    }
    existing.source = MERGED_SHELL_PATH_SOURCE;
}

pub(crate) fn documented_solution(documentation: &str) -> Option<String> {
    if let Some(mitigation) = documented_section(documentation, "## Mitigation") {
        if let Some(command) = mitigation.lines().find(|line| line.contains("av harden ")) {
            return Some(format!("Run `{}`.", command.trim()));
        }
        let paragraph = first_paragraph(mitigation);
        if !paragraph.is_empty() {
            return Some(paragraph);
        }
    }
    documentation
        .split_once("## Why This is not Yet Hardened")
        .map(|(_, section)| section)
        .and_then(|section| section.split("\n## ").next())
        .map(first_paragraph)
        .filter(|solution| !solution.is_empty())
}

fn documented_section<'a>(documentation: &'a str, heading: &str) -> Option<&'a str> {
    documentation
        .split_once(heading)
        .map(|(_, section)| section)
        .and_then(|section| section.split("\n## ").next())
}

fn first_paragraph(section: &str) -> String {
    section
        .lines()
        .skip_while(|line| line.trim().is_empty())
        .take_while(|line| !line.trim().is_empty())
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn metadata(home: &Path) -> Vec<DetectorMetadata> {
    DETECTORS
        .iter()
        .map(|detector| {
            let name = detector_name(detector.module);
            DetectorMetadata {
                documentation: detector.documentation,
                homepage: detector.docs_url.to_string(),
                docs_url: detector.docs_url.to_string(),
                name,
                watch_scopes: sensitive_file_scopes(detector.documentation, home),
            }
        })
        .collect()
}

fn sensitive_file_scopes(documentation: &str, home: &Path) -> Vec<DetectorWatchScope> {
    let Some(section) = documentation
        .split_once("## Sensitive Files")
        .map(|(_, section)| section)
        .and_then(|section| section.split("\n## ").next())
    else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    section
        .lines()
        .filter_map(|line| line.trim().strip_prefix("- `")?.strip_suffix('`'))
        .filter_map(|path| resolve_sensitive_path(path, home))
        .filter(|scope| seen.insert((scope.path.clone(), scope.recursive)))
        .collect()
}

fn resolve_sensitive_path(pattern: &str, home: &Path) -> Option<DetectorWatchScope> {
    if pattern.starts_with("./") {
        return None;
    }
    let home = home.to_str()?;
    let expanded = if let Some(rest) = pattern.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else if let Some(expression) = pattern.strip_prefix("${") {
        let (expression, suffix) = expression.split_once('}')?;
        let (name, fallback) = expression.split_once(":-")?;
        let base = std::env::var(name)
            .ok()
            .filter(|value| Path::new(value).is_absolute())
            .unwrap_or_else(|| fallback.replace("$HOME", home));
        format!("{base}{suffix}")
    } else if let Some(rest) = pattern.strip_prefix('$') {
        let name_end = rest.find('/').unwrap_or(rest.len());
        let (name, suffix) = rest.split_at(name_end);
        let base = if name == "HOME" {
            home.to_string()
        } else {
            std::env::var(name)
                .ok()
                .filter(|value| Path::new(value).is_absolute())?
        };
        format!("{base}{suffix}")
    } else if Path::new(pattern).is_absolute() {
        pattern.to_string()
    } else {
        return None;
    };
    if expanded.contains('$') {
        return None;
    }

    let wildcard = expanded.find('*');
    let path = match wildcard {
        Some(index) if expanded[..index].ends_with('/') => {
            PathBuf::from(expanded[..index].trim_end_matches('/'))
        }
        Some(index) => Path::new(&expanded[..index]).parent()?.to_path_buf(),
        None => PathBuf::from(expanded),
    };
    let path = path.to_str()?.to_string();
    (Path::new(&path).is_absolute() && path != home).then_some(DetectorWatchScope {
        path,
        recursive: wildcard.is_some(),
    })
}

fn detector_name(module: &str) -> String {
    match module {
        "mysql_8_0" => "mysql@8.0".to_string(),
        "mysql_8_4" => "mysql@8.4".to_string(),
        "macos" => "macOS".to_string(),
        "node_18" => "node@18".to_string(),
        "openssl_3" => "openssl@3".to_string(),
        _ => module.replace('_', "-"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_runs_every_registered_isotope() {
        assert_eq!(DETECTORS.len(), 157);
    }

    #[test]
    fn metadata_names_detectors() {
        let metadata = metadata(Path::new("/Users/tester"));
        let names = metadata
            .iter()
            .map(|detector| detector.name.clone())
            .collect::<Vec<_>>();

        assert!(!names.contains(&"aws".to_string()));
        assert!(!names.contains(&"aws-cli".to_string()));
        assert!(names.contains(&"aws-cli-credentials-file".to_string()));
        assert!(names.contains(&"pnpm-minimum-release-age".to_string()));
        assert!(!names.contains(&"git".to_string()));
        assert!(names.contains(&"git-credential-fill".to_string()));
        assert!(names.contains(&"git-credential-oauth".to_string()));
        assert!(names.contains(&"git-credentials-file".to_string()));
        assert!(names.contains(&"homebrew".to_string()));
        assert!(names.contains(&"macOS".to_string()));
        assert!(names.contains(&"sip".to_string()));
        assert!(names.contains(&"mysql@8.0".to_string()));
        assert!(names.contains(&"sudo".to_string()));
        assert!(names.contains(&"terraform-core".to_string()));
        assert_eq!(
            metadata
                .iter()
                .find(|detector| detector.name == "homebrew")
                .unwrap()
                .homepage,
            format!("{DOCS_BASE}homebrew/detector.md")
        );
        assert_eq!(
            metadata
                .iter()
                .find(|detector| detector.name == "git-credential-fill")
                .unwrap()
                .docs_url,
            format!("{DOCS_BASE}git/credential_fill.md")
        );
    }

    #[test]
    fn sensitive_files_resolve_to_narrow_absolute_watch_scopes() {
        let scopes = sensitive_file_scopes(
            "## Sensitive Files\n\n- `~/.aws/credentials`\n- `~/.aws/login/cache/*.json`\n- `./project.json`\n- Directories listed in `$PATH`\n",
            Path::new("/Users/tester"),
        );

        assert_eq!(scopes.len(), 2);
        assert_eq!(scopes[0].path, "/Users/tester/.aws/credentials");
        assert!(!scopes[0].recursive);
        assert_eq!(scopes[1].path, "/Users/tester/.aws/login/cache");
        assert!(scopes[1].recursive);
        assert!(scopes.iter().all(|scope| scope.path != "/Users/tester"));
    }

    #[test]
    fn every_file_driven_detector_has_only_narrow_watch_scopes() {
        let home = Path::new("/Users/tester");
        let metadata = metadata(home);
        let unwatched = metadata
            .iter()
            .filter(|detector| detector.watch_scopes.is_empty())
            .map(|detector| detector.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(unwatched, ["gh-cli-keychain-access", "macOS", "sip"]);
        assert!(
            metadata
                .iter()
                .all(|detector| detector.watch_scopes.len() <= 10)
        );
        assert!(
            metadata
                .iter()
                .flat_map(|detector| &detector.watch_scopes)
                .all(|scope| Path::new(&scope.path).is_absolute()
                    && scope.path != home.to_str().unwrap())
        );
    }

    #[test]
    fn documentation_supplies_hardening_or_deferred_solution() {
        assert_eq!(
            documented_solution("## Mitigation\n\n```sh\nsudo av harden foo\n```"),
            Some("Run `sudo av harden foo`.".to_string())
        );
        assert_eq!(
            documented_solution("## Mitigation\n\nRemove the reported token.\nThen log in again."),
            Some("Remove the reported token. Then log in again.".to_string())
        );
        assert_eq!(
            documented_solution(
                "## Why This is not Yet Hardened\n\nFoo needs a temporary secret file.\nThat is not sufficient.\n\n## Sensitive Files"
            ),
            Some("Foo needs a temporary secret file. That is not sufficient.".to_string())
        );
    }

    fn shell_path_finding(shell: &'static str, path: &str) -> Finding {
        let explanation = format!(
            "{} PATH has a user-writable directory before protected system directories: {path}",
            if shell == "bash" { "Bash" } else { "Zsh" },
        );
        let documentation = if shell == "bash" {
            include_str!("bash/detector.md")
        } else {
            include_str!("zsh/detector.md")
        };
        Finding {
            source: shell,
            homepage: "https://example.test/",
            severity: "high",
            // Built by the same function the detectors use, so relative and
            // empty entries have no affected path here either.
            affected: super::radioisotope::affected(&explanation),
            explanation,
            solution: documented_solution(documentation).unwrap(),
            docs_url: "https://example.test/docs.md",
        }
    }

    #[test]
    fn gives_a_lone_shell_path_finding_path_specific_mitigation() {
        let findings = vec![shell_path_finding("bash", "/Users/tester/.local/bin")];

        let merged = merge_duplicate_shell_path_findings(findings);

        assert_eq!(merged[0].solution, shell_path_solution("bash"));
    }

    #[test]
    fn bash_and_zsh_share_the_same_path_mitigation() {
        assert_eq!(shell_path_solution("bash"), shell_path_solution("zsh"));
    }

    #[test]
    fn merges_bash_and_zsh_findings_for_the_same_path_directory() {
        let findings = vec![
            shell_path_finding("bash", "/opt/homebrew/bin"),
            shell_path_finding("zsh", "/opt/homebrew/bin"),
        ];

        let merged = merge_duplicate_shell_path_findings(findings);

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].source, "bash+zsh");
        assert_eq!(merged[0].solution, shell_path_solution("bash"));
        assert_eq!(
            merged[0].explanation,
            "Bash and zsh PATH have a user-writable directory before protected system directories: /opt/homebrew/bin"
        );
        assert_eq!(merged[0].affected[0].path, "/opt/homebrew/bin");
    }

    #[test]
    fn keeps_shell_path_findings_for_different_directories_separate() {
        let findings = vec![
            shell_path_finding("bash", "/opt/homebrew/bin"),
            shell_path_finding("zsh", "/opt/homebrew/bin"),
            shell_path_finding("bash", "/Users/tester/.bun/bin"),
            shell_path_finding("zsh", "/Users/tester/.bun/bin"),
        ];

        let merged = merge_duplicate_shell_path_findings(findings);

        assert_eq!(merged.len(), 2);
        assert!(merged.iter().all(|finding| finding.source == "bash+zsh"));
    }

    /// Regression: `PATH="first:second:/usr/bin:/bin"`. Both relative entries
    /// have an empty `affected`, so keying the merge on `affected` collapsed
    /// them into one finding and `second` disappeared from the scan.
    #[test]
    fn keeps_relative_path_entries_separate_when_merging() {
        let findings = vec![
            shell_path_finding("bash", "first"),
            shell_path_finding("bash", "second"),
            shell_path_finding("zsh", "first"),
            shell_path_finding("zsh", "second"),
        ];

        let merged = merge_duplicate_shell_path_findings(findings);

        assert_eq!(merged.len(), 2);
        assert!(merged.iter().all(|finding| finding.source == "bash+zsh"));
        assert_eq!(
            merged[0].explanation,
            "Bash and zsh PATH have a user-writable directory before protected system directories: first"
        );
        assert_eq!(
            merged[1].explanation,
            "Bash and zsh PATH have a user-writable directory before protected system directories: second"
        );
    }

    #[test]
    fn merges_the_empty_path_entry_reported_as_a_dot() {
        let findings = vec![
            shell_path_finding("bash", "."),
            shell_path_finding("zsh", "."),
        ];

        let merged = merge_duplicate_shell_path_findings(findings);

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].source, "bash+zsh");
        assert_eq!(
            merged[0].explanation,
            "Bash and zsh PATH have a user-writable directory before protected system directories: ."
        );
        assert!(merged[0].affected.is_empty());
    }

    #[test]
    fn does_not_merge_two_findings_from_the_same_shell() {
        let findings = vec![
            shell_path_finding("bash", "relative"),
            shell_path_finding("bash", "relative"),
        ];

        let merged = merge_duplicate_shell_path_findings(findings);

        assert_eq!(merged.len(), 2);
        assert!(merged.iter().all(|finding| finding.source == "bash"));
    }

    #[test]
    fn does_not_merge_a_lone_shell_path_finding() {
        let findings = vec![shell_path_finding("zsh", "/opt/homebrew/bin")];

        let merged = merge_duplicate_shell_path_findings(findings);

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].source, "zsh");
    }

    #[test]
    fn does_not_merge_non_path_bash_and_zsh_findings() {
        let findings = vec![
            Finding {
                source: "bash",
                homepage: "https://example.test/",
                severity: "high",
                explanation: "Bash startup file contains plaintext-looking credential assignment: /home/user/.bashrc".to_string(),
                solution: "Move the reported value with `av save KEY`.".to_string(),
                affected: vec![crate::AffectedFile {
                    path: "/home/user/.bashrc".to_string(),
                    line: None,
                }],
                docs_url: "https://example.test/docs.md",
            },
            Finding {
                source: "zsh",
                homepage: "https://example.test/",
                severity: "high",
                explanation: "Zsh startup file contains plaintext-looking credential assignment: /home/user/.zshrc".to_string(),
                solution: "Move the reported value with `av save KEY`.".to_string(),
                affected: vec![crate::AffectedFile {
                    path: "/home/user/.zshrc".to_string(),
                    line: None,
                }],
                docs_url: "https://example.test/docs.md",
            },
        ];

        let merged = merge_duplicate_shell_path_findings(findings);

        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].source, "bash");
        assert_eq!(merged[1].source, "zsh");
    }

    #[test]
    fn does_not_merge_the_macos_gui_path_finding_with_shell_findings() {
        let findings = vec![
            shell_path_finding("bash", "/opt/homebrew/bin"),
            shell_path_finding("zsh", "/opt/homebrew/bin"),
            Finding {
                source: "macOS",
                homepage: "https://example.test/",
                severity: "high",
                explanation: "macOS GUI PATH has a user-writable directory before protected system directories: /opt/homebrew/bin".to_string(),
                solution: "Move protected system directories before user-writable directories in the launchd PATH.".to_string(),
                affected: vec![crate::AffectedFile {
                    path: "/opt/homebrew/bin".to_string(),
                    line: None,
                }],
                docs_url: "https://example.test/docs.md",
            },
        ];

        let merged = merge_duplicate_shell_path_findings(findings);

        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].source, "bash+zsh");
        assert_eq!(merged[1].source, "macOS");
    }
}
