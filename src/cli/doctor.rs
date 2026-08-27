use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(target_os = "macos")]
use std::process::Stdio;

use crate::isotopes::hardeners::{
    self, HardenerCommand, HardenerMetadata, RequiredExecutable, StubRequirements, aws_release,
    executable, isotope,
};

use super::scan::Style;

pub(crate) struct DoctorResult {
    name: String,
    commands: Vec<String>,
    issues: Vec<DoctorIssue>,
}

struct DoctorIssue {
    kind: &'static str,
    command: Option<String>,
    message: String,
    remediation: String,
    stub_path: Option<String>,
    target_path: Option<String>,
    resolved_path: Option<String>,
}

#[derive(Clone, Copy)]
struct AgentCliDoctor {
    command: &'static str,
    vendor: &'static str,
    team_identifier: &'static str,
    signing_identifier: &'static str,
    install_hint: &'static str,
}

const AGENT_CLIS: [AgentCliDoctor; 2] = [
    AgentCliDoctor {
        command: "claude",
        vendor: "Anthropic",
        team_identifier: "Q6L2SF6YDW",
        signing_identifier: "com.anthropic.claude-code",
        install_hint: "Anthropic's native installer or the Homebrew cask",
    },
    AgentCliDoctor {
        command: "codex",
        vendor: "OpenAI",
        team_identifier: "2DC432GLL2",
        signing_identifier: "codex",
        install_hint: "OpenAI's standalone installer or the Homebrew cask",
    },
];

const LAUNCHER_BUNDLE_ROOT: &str = "/Applications/Automic Vault";
const LAUNCHER_BUNDLE_COMMAND_ROOT: &str = "/usr/local/bin";

struct LauncherBundleDoctor {
    command: String,
    app: PathBuf,
}

pub(crate) fn run<W: Write>(
    stdout: &mut W,
    selector: Option<&str>,
    json: bool,
    style: Style,
) -> Result<i32, String> {
    let results = results(selector, None)?;
    let issue_count = results
        .iter()
        .map(|result| result.issues.len())
        .sum::<usize>();
    if json {
        print_json(stdout, &results);
    } else {
        print_human(stdout, &results, issue_count, style);
    }
    Ok(if issue_count == 0 { 0 } else { 1 })
}

pub(crate) fn dashboard_results_json<T>(
    load_hardeners: impl FnOnce() -> (Vec<HardenerMetadata>, T),
) -> Result<(T, Vec<serde_json::Value>), String> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let launcher_bundles = launcher_bundles();
    std::thread::scope(|scope| {
        let agent_results = scope.spawn(|| agent_cli_results(&path, vendor_signature_valid));
        let (hardeners, hardener_report) = load_hardeners();
        let mut results = diagnose(hardeners, None, &path)?;
        results.extend(launcher_bundles.iter().map(|launcher| {
            diagnose_launcher_bundle(launcher, Path::new(LAUNCHER_BUNDLE_COMMAND_ROOT), &path, 0)
        }));
        results.extend(
            agent_results
                .join()
                .expect("agent CLI Doctor worker panicked"),
        );
        Ok((hardener_report, json_results(&results)))
    })
}

fn results(
    selector: Option<&str>,
    hardeners: Option<Vec<HardenerMetadata>>,
) -> Result<Vec<DoctorResult>, String> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let launcher_bundles = launcher_bundles();
    if selector.is_none() {
        return std::thread::scope(|scope| {
            let agent_results = scope.spawn(|| agent_cli_results(&path, vendor_signature_valid));
            let mut results = diagnose(hardeners.unwrap_or_else(hardeners::metadata), None, &path)?;
            results.extend(launcher_bundles.iter().map(|launcher| {
                diagnose_launcher_bundle(
                    launcher,
                    Path::new(LAUNCHER_BUNDLE_COMMAND_ROOT),
                    &path,
                    0,
                )
            }));
            results.extend(
                agent_results
                    .join()
                    .expect("agent CLI Doctor worker panicked"),
            );
            Ok(results)
        });
    }
    let selected_launcher = selector.and_then(|selector| {
        launcher_bundles
            .iter()
            .find(|launcher| launcher.command == selector)
    });
    let results = if let Some(launcher) = selected_launcher {
        vec![diagnose_launcher_bundle(
            launcher,
            Path::new(LAUNCHER_BUNDLE_COMMAND_ROOT),
            &path,
            0,
        )]
    } else if let Some(agent) = select_agent_cli(selector) {
        vec![diagnose_agent_cli(agent, &path, vendor_signature_valid)]
    } else {
        diagnose(
            hardeners.unwrap_or_else(hardeners::metadata),
            selector,
            &path,
        )?
    };
    Ok(results)
}

fn agent_cli_results(
    path: &OsStr,
    signature_valid: fn(&Path, &str, &str) -> bool,
) -> Vec<DoctorResult> {
    AGENT_CLIS
        .iter()
        .filter(|agent| resolve(agent.command, path).is_some())
        .map(|agent| diagnose_agent_cli(agent, path, signature_valid))
        .collect()
}

fn select_agent_cli(selector: Option<&str>) -> Option<&'static AgentCliDoctor> {
    let selector = selector?;
    AGENT_CLIS.iter().find(|agent| agent.command == selector)
}

fn launcher_bundles() -> Vec<LauncherBundleDoctor> {
    let Ok(entries) = fs::read_dir(LAUNCHER_BUNDLE_ROOT) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let app = entry.path();
            let metadata = fs::symlink_metadata(&app).ok()?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || app.extension() != Some(OsStr::new("app"))
                || !plist_value(&app, "CFBundleIdentifier")?
                    .starts_with("com.automicvault.launcher-bundle.")
            {
                return None;
            }
            let command = plist_value(&app, "AVLauncherBundleCommandName")?;
            super::launcher_bundle::valid_command_name(&command)
                .then_some(LauncherBundleDoctor { command, app })
        })
        .collect()
}

fn plist_value(app: &Path, key: &str) -> Option<String> {
    let output = Command::new("/usr/bin/plutil")
        .args(["-extract", key, "raw", "-o", "-"])
        .arg(app.join("Contents/Info.plist"))
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn diagnose_launcher_bundle(
    launcher: &LauncherBundleDoctor,
    command_root: &Path,
    path: &OsStr,
    expected_uid: u32,
) -> DoctorResult {
    let command_path = command_root.join(&launcher.command);
    let runner = launcher.app.join("Contents/MacOS/launcher");
    let healthy_link = fs::symlink_metadata(&command_path).is_ok_and(|metadata| {
        metadata.file_type().is_symlink()
            && metadata.uid() == expected_uid
            && fs::read_link(&command_path).ok().as_deref() == Some(runner.as_path())
    });
    let mut issues = Vec::new();
    if !healthy_link {
        issues.push(DoctorIssue {
            kind: "launcher_bundle_command_invalid",
            command: Some(launcher.command.clone()),
            message: format!(
                "{} does not have its root-owned Launcher Bundle command link at {}",
                launcher.command,
                command_path.display()
            ),
            remediation: format!(
                "Review anything at {}, then recreate the `{}` Launcher Bundle in Automic Vault.",
                command_path.display(),
                launcher.command
            ),
            stub_path: Some(command_path.display().to_string()),
            target_path: Some(runner.display().to_string()),
            resolved_path: resolve(&launcher.command, path).map(|path| path.display().to_string()),
        });
    } else {
        let resolved = resolve(&launcher.command, path);
        if resolved.as_deref() != Some(command_path.as_path()) {
            let resolved_path = resolved.as_ref().map(|path| path.display().to_string());
            let message = resolved_path.as_ref().map_or_else(
                || format!("{} is not available through PATH", launcher.command),
                |resolved| {
                    format!(
                        "{} resolves to {resolved} before its Launcher Bundle command {}",
                        launcher.command,
                        command_path.display()
                    )
                },
            );
            issues.push(DoctorIssue {
                kind: "launcher_bundle_not_first_on_path",
                command: Some(launcher.command.clone()),
                message,
                remediation: format!(
                    "Put {} before other installations in PATH, then start a new shell and rerun `av doctor {}`.",
                    command_root.display(),
                    launcher.command
                ),
                stub_path: Some(command_path.display().to_string()),
                target_path: Some(runner.display().to_string()),
                resolved_path,
            });
        }
    }
    DoctorResult {
        name: format!("{} Launcher Bundle", launcher.command),
        commands: vec![launcher.command.clone()],
        issues,
    }
}

pub(crate) fn trusted_codex_cli() -> Result<PathBuf, String> {
    let agent = select_agent_cli(Some("codex")).unwrap();
    let path = std::env::var_os("PATH").unwrap_or_default();
    let executable = resolve(agent.command, &path)
        .ok_or_else(|| "codex is not available through PATH; run `av doctor codex`".to_string())?;
    if !vendor_signature_valid(&executable, agent.team_identifier, agent.signing_identifier) {
        return Err(format!(
            "refusing to run unsigned Codex CLI {}; run `av doctor codex`",
            executable.display()
        ));
    }
    Ok(executable)
}

fn diagnose_agent_cli(
    agent: &AgentCliDoctor,
    path: &OsStr,
    signature_valid: impl Fn(&Path, &str, &str) -> bool,
) -> DoctorResult {
    let resolved = resolve(agent.command, path);
    let issues = match resolved.as_deref() {
        Some(executable)
            if signature_valid(executable, agent.team_identifier, agent.signing_identifier) =>
        {
            Vec::new()
        }
        Some(executable) => vec![agent_cli_signature_issue(agent, executable)],
        None => vec![agent_cli_missing_issue(agent)],
    };
    DoctorResult {
        name: agent.command.to_string(),
        commands: vec![agent.command.to_string()],
        issues,
    }
}

fn agent_cli_signature_issue(agent: &AgentCliDoctor, executable: &Path) -> DoctorIssue {
    let executable = executable.display().to_string();
    let link = format!("/usr/local/bin/{}", agent.command);
    DoctorIssue {
        kind: "agent_cli_signature_invalid",
        command: Some(agent.command.to_string()),
        message: format!(
            "{} resolves to {executable}, which does not have a valid {} code signature. Without a valid code signature, Automic Vault cannot securely identify the CLI and enforce approval gates for it",
            agent.command, agent.vendor
        ),
        remediation: agent_cli_remediation(agent),
        stub_path: Some(link),
        target_path: None,
        resolved_path: Some(executable),
    }
}

fn agent_cli_missing_issue(agent: &AgentCliDoctor) -> DoctorIssue {
    DoctorIssue {
        kind: "agent_cli_unavailable",
        command: Some(agent.command.to_string()),
        message: format!("{} is not available through PATH", agent.command),
        remediation: agent_cli_remediation(agent),
        stub_path: Some(format!("/usr/local/bin/{}", agent.command)),
        target_path: None,
        resolved_path: None,
    }
}

fn agent_cli_remediation(agent: &AgentCliDoctor) -> String {
    format!(
        "Reinstall {} using {}, ensure that installation precedes other copies in PATH, then rerun `av doctor {}`.",
        agent.command, agent.install_hint, agent.command
    )
}

#[cfg(target_os = "macos")]
fn vendor_signature_valid(path: &Path, team_identifier: &str, signing_identifier: &str) -> bool {
    let requirement = format!(
        "=identifier \"{signing_identifier}\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"{team_identifier}\""
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
fn vendor_signature_valid(_path: &Path, _team_identifier: &str, _signing_identifier: &str) -> bool {
    false
}

fn diagnose(
    hardeners: Vec<HardenerMetadata>,
    selector: Option<&str>,
    path: &OsStr,
) -> Result<Vec<DoctorResult>, String> {
    if let Some(selector) = selector {
        let (hardener, command) =
            select(hardeners, selector).ok_or_else(|| format!("unknown command `{selector}`"))?;
        let checked = hardener
            .detection
            .commands
            .iter()
            .any(|candidate| command.as_deref().is_none_or(|name| candidate.name == name))
            || command.is_none() && !hardener.detection.diagnostics.is_empty();
        if !checked {
            return Err(format!(
                "`{selector}` has no Doctor-owned checks; use `av scan` for exposure findings"
            ));
        }
        return Ok(vec![diagnose_one(hardener, command.as_deref(), path)]);
    }

    Ok(hardeners
        .into_iter()
        .filter(|hardener| {
            hardener.detection.commands.iter().any(|command| {
                command.hardened
                    || command
                        .stub_path
                        .as_deref()
                        .is_some_and(|path| fs::symlink_metadata(path).is_ok())
            })
        })
        .map(|hardener| diagnose_one(hardener, None, path))
        .collect())
}

fn has_stub_checks(command: &HardenerCommand) -> bool {
    command
        .stub_path
        .as_deref()
        .is_some_and(|stub| Path::new(stub) != Path::new(&command.target_path))
}

fn select(
    hardeners: Vec<HardenerMetadata>,
    selector: &str,
) -> Option<(HardenerMetadata, Option<String>)> {
    let canonical = match selector {
        "gh-cli" => "gh",
        "homebrew" => "brew",
        "supabase-cli" => "supabase",
        selector => selector,
    };
    if let Some(index) = hardeners
        .iter()
        .position(|hardener| hardener.name == canonical)
    {
        return Some((hardeners.into_iter().nth(index).unwrap(), None));
    }
    let (index, command) = hardeners.iter().enumerate().find_map(|(index, hardener)| {
        hardener
            .detection
            .commands
            .iter()
            .find(|command| command.name == selector)
            .map(|command| (index, command.name.clone()))
    })?;
    Some((hardeners.into_iter().nth(index).unwrap(), Some(command)))
}

fn diagnose_one(
    hardener: HardenerMetadata,
    command_filter: Option<&str>,
    path: &OsStr,
) -> DoctorResult {
    let commands = hardener
        .detection
        .commands
        .iter()
        .filter(|command| command_filter.is_none_or(|filter| command.name == filter))
        .collect::<Vec<_>>();
    let mut issues = hardener
        .detection
        .diagnostics
        .iter()
        .map(|diagnostic| DoctorIssue {
            kind: diagnostic.kind,
            command: None,
            message: diagnostic.message.clone(),
            remediation: diagnostic.remediation.clone(),
            stub_path: None,
            target_path: diagnostic.path.clone(),
            resolved_path: None,
        })
        .collect::<Vec<_>>();
    issues.extend(
        commands
            .iter()
            .flat_map(|command| diagnose_command(hardener.name, command, path)),
    );
    if hardener.name == "aws"
        && hardener.detection.diagnostics.is_empty()
        && let Some(command) = commands.iter().find(|command| {
            command.stub_valid
                && Path::new(&command.target_path) == aws_release::target_path().as_path()
        })
    {
        issues.extend(aws_update_issue(
            command,
            aws_release::current_version(),
            aws_release::latest_version(),
        ));
    }

    DoctorResult {
        name: hardener.name.to_string(),
        commands: commands
            .iter()
            .map(|command| command.name.clone())
            .collect(),
        issues,
    }
}

fn aws_update_issue(
    command: &HardenerCommand,
    installed: Result<String, String>,
    latest: Result<String, String>,
) -> Option<DoctorIssue> {
    match installed.and_then(|installed| {
        latest.and_then(|latest| {
            aws_release::update_available(&installed, &latest)
                .map(|available| (installed, latest, available))
        })
    }) {
        Ok((_, _, false)) => None,
        Ok((installed, latest, true)) => Some(DoctorIssue {
            kind: "aws_update_available",
            command: Some(command.name.clone()),
            message: format!("AWS CLI {latest} is available; {installed} is installed"),
            remediation:
                "Run `av harden aws` to download and install the current verified AWS CLI release."
                    .into(),
            stub_path: command.stub_path.clone(),
            target_path: Some(command.target_path.clone()),
            resolved_path: None,
        }),
        Err(error) => Some(DoctorIssue {
            kind: "aws_update_check_failed",
            command: Some(command.name.clone()),
            message: format!("could not check AWS CLI for updates: {error}"),
            remediation: "Check the network connection and rerun `av doctor aws`.".into(),
            stub_path: command.stub_path.clone(),
            target_path: Some(command.target_path.clone()),
            resolved_path: None,
        }),
    }
}

fn diagnose_command(hardener: &str, command: &HardenerCommand, path: &OsStr) -> Vec<DoctorIssue> {
    let mut issues = Vec::new();
    if !executable(Path::new(&command.target_path)) {
        issues.push(target_issue(hardener, command));
    }
    issues.extend(
        command
            .required_paths
            .iter()
            .filter(|required| !executable(Path::new(&required.path)))
            .map(|required| dependency_issue(hardener, command, required)),
    );
    if has_stub_checks(command) {
        let stub_issues = stub_issues(hardener, command);
        let stub_is_healthy = stub_issues.is_empty();
        issues.extend(stub_issues);
        if stub_is_healthy {
            issues.extend(path_issue(command, path));
        }
    }
    if let Some(isotope) = &command.isotope {
        if let Some(issue) = isotope_path_issue(command, path, |path, identifier| {
            isotope::signature_valid(path, identifier)
        }) {
            issues.push(issue);
        }
        if let Some(issue) = isotope_update_issue(command, isotope) {
            issues.push(issue);
        }
    }
    issues
}

fn isotope_path_issue(
    command: &HardenerCommand,
    path: &OsStr,
    signature_valid: impl Fn(&Path, &str) -> bool,
) -> Option<DoctorIssue> {
    let isotope = command.isotope.as_ref()?;
    let resolved = resolve(&command.name, path);
    if resolved.as_deref().is_some_and(|path| {
        path.file_name().and_then(|name| name.to_str()) == Some(command.name.as_str())
            && signature_valid(path, isotope.identifier)
    }) {
        return None;
    }
    let resolved_path = resolved.as_ref().map(|path| path.display().to_string());
    let message = resolved_path.as_ref().map_or_else(
        || format!("{} is not available through PATH", command.name),
        |resolved| {
            format!(
                "{} resolves to {resolved}, which is not the signed Automic Vault isotope",
                command.name
            )
        },
    );
    Some(DoctorIssue {
        kind: "isotope_not_first_on_path",
        command: Some(command.name.clone()),
        message,
        remediation: format!(
            "Put the signed Automic Vault `{}` isotope first in PATH, then rerun `av doctor {}`.",
            command.name, command.name
        ),
        stub_path: command.stub_path.clone(),
        target_path: Some(command.target_path.clone()),
        resolved_path,
    })
}

fn isotope_update_issue(
    command: &HardenerCommand,
    doctor: &isotope::Doctor,
) -> Option<DoctorIssue> {
    let receipt = doctor.receipt_path.as_deref()?;
    let installed = fs::read_to_string(receipt).ok();
    let current = isotope::current_sha(&doctor.formula_url, doctor.repository);
    match (installed.as_deref().map(str::trim), current) {
        (Some(installed), Ok(current)) if installed == current => None,
        (_, Ok(_)) => Some(DoctorIssue {
            kind: "isotope_update_required",
            command: Some(command.name.clone()),
            message: format!(
                "the directly installed {} isotope has an update available",
                command.name
            ),
            remediation: format!(
                "Run `av harden {}` to install the current signed isotope.",
                command.name
            ),
            stub_path: command.stub_path.clone(),
            target_path: Some(command.target_path.clone()),
            resolved_path: None,
        }),
        (_, Err(error)) => Some(DoctorIssue {
            kind: "isotope_update_check_failed",
            command: Some(command.name.clone()),
            message: format!(
                "could not check the {} isotope for updates: {error}",
                command.name
            ),
            remediation: format!(
                "Check the network connection and rerun `av doctor {}`.",
                command.name
            ),
            stub_path: command.stub_path.clone(),
            target_path: Some(command.target_path.clone()),
            resolved_path: None,
        }),
    }
}

fn target_issue(hardener: &str, command: &HardenerCommand) -> DoctorIssue {
    let target = &command.target_path;
    DoctorIssue {
        kind: "target_unavailable",
        command: Some(command.name.clone()),
        message: format!(
            "{} target is missing or not executable: {}",
            command.name, target
        ),
        remediation: format!(
            "Install `{}` at {target}; the {hardener} hardener cannot wrap a missing target. If it is installed elsewhere, make {target} point to that executable, then rerun `av doctor {}`.",
            command.name, command.name
        ),
        stub_path: command.stub_path.clone(),
        target_path: Some(target.clone()),
        resolved_path: None,
    }
}

fn dependency_issue(
    hardener: &str,
    command: &HardenerCommand,
    required: &RequiredExecutable,
) -> DoctorIssue {
    DoctorIssue {
        kind: "dependency_unavailable",
        command: Some(command.name.clone()),
        message: format!(
            "{} hardening requires {} to be an executable file at {}",
            command.name, required.name, required.path
        ),
        remediation: format!(
            "Install or restore {} at {}, then rerun `av doctor {}`. If it is installed elsewhere, replace that path with a root-owned symlink to the executable.",
            required.name, required.path, hardener
        ),
        stub_path: command.stub_path.clone(),
        target_path: Some(required.path.clone()),
        resolved_path: None,
    }
}

fn stub_issues(hardener: &str, command: &HardenerCommand) -> Vec<DoctorIssue> {
    let Some(stub) = command.stub_path.as_deref() else {
        return Vec::new();
    };
    let mut issues = command
        .stub_requirements
        .iter()
        .flat_map(|requirements| identity_issues(hardener, command, stub, requirements))
        .collect::<Vec<_>>();
    let metadata = match fs::symlink_metadata(stub) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            issues.push(DoctorIssue {
                kind: "stub_missing",
                command: Some(command.name.clone()),
                message: format!(
                    "{} hardening is bypassed because its launcher is missing: {stub}",
                    command.name
                ),
                remediation: format!(
                    "Run `{}` to recreate it. Manual repair: {}. Then rerun `av doctor {}`.",
                    harden_invocation(hardener),
                    manual_stub_repair(hardener, command, stub),
                    command.name
                ),
                stub_path: Some(stub.to_string()),
                target_path: Some(command.target_path.clone()),
                resolved_path: None,
            });
            return issues;
        }
        Err(err) => {
            issues.push(DoctorIssue {
                kind: "stub_unreadable",
                command: Some(command.name.clone()),
                message: format!("cannot inspect hardened launcher {stub}: {err}"),
                remediation: format!(
                    "Ensure every parent directory permits metadata access and that {stub} is readable, then rerun `av doctor {}`.",
                    command.name
                ),
                stub_path: Some(stub.to_string()),
                target_path: Some(command.target_path.clone()),
                resolved_path: None,
            });
            return issues;
        }
    };
    if !metadata.file_type().is_file() {
        let actual = if metadata.file_type().is_symlink() {
            "a symbolic link"
        } else if metadata.file_type().is_dir() {
            "a directory"
        } else {
            "a non-regular file"
        };
        issues.push(DoctorIssue {
            kind: "stub_wrong_type",
            command: Some(command.name.clone()),
            message: format!(
                "hardened launcher {stub} is {actual}; expected a regular file"
            ),
            remediation: format!(
                "Remove {stub} after reviewing it, then run `{}`. Manual repair: install the documented launcher directly at {stub}; do not use a symlink.",
                harden_invocation(hardener)
            ),
            stub_path: Some(stub.to_string()),
            target_path: Some(command.target_path.clone()),
            resolved_path: None,
        });
        return issues;
    }

    let actual_mode = metadata.permissions().mode() & 0o7777;
    if !executable(Path::new(stub)) {
        issues.push(DoctorIssue {
            kind: "stub_not_executable",
            command: Some(command.name.clone()),
            message: format!(
                "hardened launcher {stub} is not executable (mode {actual_mode:#06o})"
            ),
            remediation: format!(
                "Set the expected mode with `sudo chmod {mode:04o} {stub}`, then rerun `av doctor {}`.",
                command.name,
                mode = command
                    .stub_requirements
                    .as_ref()
                    .map_or(0o755, |requirements| requirements.mode),
            ),
            stub_path: Some(stub.to_string()),
            target_path: Some(command.target_path.clone()),
            resolved_path: None,
        });
    } else if let Some(requirements) = &command.stub_requirements
        && actual_mode != requirements.mode
    {
        issues.push(DoctorIssue {
            kind: "stub_mode_mismatch",
            command: Some(command.name.clone()),
            message: format!(
                "hardened launcher {stub} has mode {actual_mode:#06o}; expected {:#06o}",
                requirements.mode
            ),
            remediation: format!(
                "Run `sudo chmod {mode:04o} {stub}`, then rerun `av doctor {}`.",
                command.name,
                mode = requirements.mode
            ),
            stub_path: Some(stub.to_string()),
            target_path: Some(command.target_path.clone()),
            resolved_path: None,
        });
    }
    if let Some(requirements) = &command.stub_requirements {
        let owner_mismatch = requirements
            .owner
            .id
            .is_some_and(|expected| metadata.uid() != expected);
        let group_mismatch = requirements
            .group
            .id
            .is_some_and(|expected| metadata.gid() != expected);
        if owner_mismatch || group_mismatch {
            issues.push(DoctorIssue {
                kind: "stub_owner_mismatch",
                command: Some(command.name.clone()),
                message: format!(
                    "hardened launcher {stub} is owned by uid {} and gid {}; expected {} ({}) and {} ({})",
                    metadata.uid(),
                    metadata.gid(),
                    requirements.owner.name,
                    requirements.owner.id.map_or_else(|| "missing".into(), |id| id.to_string()),
                    requirements.group.name,
                    requirements.group.id.map_or_else(|| "missing".into(), |id| id.to_string()),
                ),
                remediation: format!(
                    "Run `sudo chown {}:{} {stub}`, then rerun `av doctor {}`.",
                    requirements.owner.name, requirements.group.name, command.name
                ),
                stub_path: Some(stub.to_string()),
                target_path: Some(command.target_path.clone()),
                resolved_path: None,
            });
        }
    }
    if !command.stub_valid {
        let (kind, message) = if command.hardened {
            (
                "stub_upgrade_required",
                format!(
                    "hardened launcher {stub} is out of date and should be upgraded to the current {hardener} implementation"
                ),
            )
        } else {
            (
                "stub_content_invalid",
                format!(
                    "launcher {stub} does not contain the expected {hardener} hardening implementation"
                ),
            )
        };
        issues.push(DoctorIssue {
            kind,
            command: Some(command.name.clone()),
            message,
            remediation: format!(
                "Run `{}` to replace it. Manual repair: {}",
                harden_invocation(hardener),
                manual_stub_repair(hardener, command, stub)
            ),
            stub_path: Some(stub.to_string()),
            target_path: Some(command.target_path.clone()),
            resolved_path: None,
        });
    }
    issues
}

fn identity_issues(
    hardener: &str,
    command: &HardenerCommand,
    stub: &str,
    requirements: &StubRequirements,
) -> Vec<DoctorIssue> {
    [
        ("user", &requirements.owner),
        ("group", &requirements.group),
    ]
    .into_iter()
    .filter(|(_, identity)| identity.id.is_none())
    .map(|(kind, identity)| DoctorIssue {
        kind: "required_identity_missing",
        command: Some(command.name.clone()),
        message: format!(
            "{hardener} hardening requires local {kind} `{}`, but it cannot be resolved",
            identity.name
        ),
        remediation: format!(
            "Run `{}` to recreate the required account metadata. Manual repair: {}",
            harden_invocation(hardener),
            manual_identity_repair(hardener, kind, identity.name, stub)
        ),
        stub_path: Some(stub.to_string()),
        target_path: Some(command.target_path.clone()),
        resolved_path: None,
    })
    .collect()
}

fn harden_invocation(hardener: &str) -> String {
    format!("av harden {hardener}")
}

fn manual_identity_repair(hardener: &str, kind: &str, name: &str, stub: &str) -> String {
    match (hardener, kind, name) {
        ("brew", "group", "vault") => format!(
            "choose an unused GID from 550–599, then run `sudo dscl . -create /Groups/vault`, `sudo dscl . -create /Groups/vault RealName 'Automic Vault'`, and `sudo dscl . -create /Groups/vault PrimaryGroupID <gid>`; finally run `sudo chown automic:vault {stub}`."
        ),
        ("brew", "user", "automic") => format!(
            "create the `vault` group first, choose an unused UID from 550–599, then create `automic` with `sudo dscl . -create /Users/automic`, setting RealName to `Automic Vault Homebrew`, UserShell to `/usr/bin/false`, NFSHomeDirectory to `/opt/homebrew/var/automic`, UniqueID to the chosen UID, PrimaryGroupID to the vault GID, and Password to `*`; finally run `sudo chown automic:vault {stub}`."
        ),
        _ => format!(
            "create the documented `{name}` {kind}, set the owner of {stub} accordingly, and rerun `av doctor {hardener}`."
        ),
    }
}

fn manual_stub_repair(hardener: &str, command: &HardenerCommand, stub: &str) -> String {
    if hardener == "brew" {
        return format!(
            "copy the matching `av-brew-stub` binary from `/Applications/Automic Vault.app/Contents/MacOS/av-brew-stub` to {stub} with `sudo install -o automic -g vault -m 6755`, after creating the `automic` user and `vault` group"
        );
    }
    if hardener == "aws" {
        return format!(
            "install the exact `src/isotopes/hardeners/aws` launcher from this Automic Vault release at {stub}, ensure `/usr/local/bin/av` is the current root-owned signed CLI, then run `sudo chown root:wheel {stub} && sudo chmod 0755 {stub}`"
        );
    }
    let keys = command
        .injected_keys
        .iter()
        .map(|key| format!("+{key}"))
        .collect::<Vec<_>>()
        .join(" ");
    let assignments = if command.assignment_keys.is_empty() {
        String::new()
    } else {
        format!(
            "; before exec, split each newline-delimited value in {} into `NAME=value` entries and export them",
            command.assignment_keys.join(", ")
        )
    };
    let ownership = command.stub_requirements.as_ref().map_or_else(
        || "set it executable".to_string(),
        |requirements| {
            format!(
                "run `sudo chown {}:{} {stub} && sudo chmod {:04o} {stub}`",
                requirements.owner.name, requirements.group.name, requirements.mode
            )
        },
    );
    format!(
        "create a regular shell script at {stub} with shebang `#!/usr/local/bin/av inject --allow-missing-keys {keys} /bin/sh` that ends with `exec {} \"$@\"`{assignments}; {ownership}",
        command.target_path
    )
}

fn path_issue(command: &HardenerCommand, path: &OsStr) -> Option<DoctorIssue> {
    let stub = command.stub_path.as_deref()?;
    if Path::new(stub).file_name().and_then(|name| name.to_str()) != Some(command.name.as_str()) {
        return None;
    }
    if same_path(Path::new(stub), Path::new(&command.target_path)) {
        return None;
    }
    let resolved = resolve(&command.name, path);
    if resolved
        .as_deref()
        .is_some_and(|resolved| same_path(Path::new(stub), resolved))
    {
        return None;
    }
    let resolved_path = resolved.map(|path| path.display().to_string());
    let message = match &resolved_path {
        Some(resolved) => format!(
            "{} resolves to {resolved} before the hardened stub {stub}",
            command.name
        ),
        None => format!(
            "{} is not available through PATH; expected {stub}",
            command.name
        ),
    };
    Some(DoctorIssue {
        kind: "stub_not_first_on_path",
        command: Some(command.name.clone()),
        message,
        remediation: format!(
            "Put {stub_dir} before {target_dir} in PATH, then start a new shell. For example: `export PATH=\"{stub_dir}:$PATH\"`.",
            stub_dir = Path::new(stub)
                .parent()
                .unwrap_or_else(|| Path::new(stub))
                .display(),
            target_dir = Path::new(&command.target_path)
                .parent()
                .unwrap_or_else(|| Path::new(&command.target_path))
                .display(),
        ),
        stub_path: Some(stub.to_string()),
        target_path: Some(command.target_path.clone()),
        resolved_path,
    })
}

fn resolve(command: &str, path: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .map(|directory| directory.join(command))
        .find(|candidate| executable(candidate))
}

fn same_path(left: &Path, right: &Path) -> bool {
    left == right
        || left
            .canonicalize()
            .ok()
            .zip(right.canonicalize().ok())
            .is_some_and(|(left, right)| left == right)
}

fn print_json(stdout: &mut dyn Write, results: &[DoctorResult]) {
    let report = serde_json::json!({
        "results": json_results(results),
    });
    let _ = writeln!(stdout, "{report}");
}

fn json_results(results: &[DoctorResult]) -> Vec<serde_json::Value> {
    results
        .iter()
        .map(|result| {
            serde_json::json!({
                "name": result.name,
                "commands": result.commands,
                "issues": result.issues.iter().map(|issue| serde_json::json!({
                    "kind": issue.kind,
                    "command": issue.command,
                    "message": issue.message,
                    "remediation": issue.remediation,
                    "stub_path": issue.stub_path,
                    "target_path": issue.target_path,
                    "resolved_path": issue.resolved_path,
                })).collect::<Vec<_>>(),
            })
        })
        .collect()
}

fn print_human(stdout: &mut dyn Write, results: &[DoctorResult], issue_count: usize, style: Style) {
    let _ = writeln!(stdout, "╭─ doctor");
    let _ = writeln!(stdout, "│");
    if results.is_empty() {
        let _ = writeln!(
            stdout,
            "╰─ {}",
            style.paint("32", "No applicable hardeners found")
        );
        return;
    }
    for result in results {
        if result.issues.is_empty() {
            let _ = writeln!(
                stdout,
                "├─ {} {}",
                result.name,
                style.paint("32", "healthy ✔︎")
            );
        } else {
            let _ = writeln!(stdout, "├─ {}", result.name);
            for issue in &result.issues {
                super::scan::write_wrapped_with_continuation(
                    stdout,
                    "│  ├─ ",
                    "│  │  ",
                    &issue.message,
                    style,
                    Some("33"),
                );
                super::scan::write_wrapped_with_continuation(
                    stdout,
                    "│  ╰─ ",
                    "│     ",
                    &issue.remediation,
                    style,
                    None,
                );
            }
        }
    }
    let summary = if issue_count == 0 {
        style.paint("32", "No problems found")
    } else if issue_count == 1 {
        style.paint("33", "1 issue requires attention")
    } else {
        style.paint("33", format!("{issue_count} issues require attention"))
    };
    let _ = writeln!(stdout, "│");
    let _ = writeln!(stdout, "╰─ {summary}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isotopes::hardeners::{
        HardenerDetection, HardenerMetadata, RequiredIdentity, StubRequirements,
    };
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn explicit_doctor_can_inspect_tool_omitted_from_aggregate() {
        let dir = temp_dir("unhardened");
        let target = executable_file(&dir.join("npm"));
        let stub = dir.join("stub");
        let hardeners = vec![hardener(
            "node",
            false,
            command(
                "npm",
                false,
                stub.to_str().unwrap(),
                target.to_str().unwrap(),
            ),
        )];
        assert!(
            diagnose(hardeners, None, OsStr::new(""))
                .unwrap()
                .is_empty()
        );

        let results = diagnose(
            vec![hardener(
                "node",
                false,
                command(
                    "npm",
                    false,
                    stub.to_str().unwrap(),
                    target.to_str().unwrap(),
                ),
            )],
            Some("npm"),
            OsStr::new(""),
        )
        .unwrap();
        assert_eq!(
            results[0]
                .issues
                .iter()
                .map(|issue| issue.kind)
                .collect::<Vec<_>>(),
            ["stub_missing"]
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn agent_cli_doctors_require_the_expected_vendor_signature() {
        let dir = temp_dir("agent-cli-signatures");
        let codex = executable_file(&dir.join("codex"));
        let agent = select_agent_cli(Some("codex")).unwrap();

        let healthy = diagnose_agent_cli(agent, dir.as_os_str(), |path, team, identifier| {
            path == codex && team == "2DC432GLL2" && identifier == "codex"
        });
        assert!(healthy.issues.is_empty());

        let unsigned = diagnose_agent_cli(agent, dir.as_os_str(), |_, _, _| false);
        assert_eq!(unsigned.issues[0].kind, "agent_cli_signature_invalid");
        assert_eq!(unsigned.issues[0].resolved_path.as_deref(), codex.to_str());
        assert!(unsigned.issues[0].message.contains("OpenAI code signature"));
        assert!(
            unsigned.issues[0]
                .message
                .contains("cannot securely identify the CLI and enforce approval gates")
        );
        assert!(
            unsigned.issues[0]
                .remediation
                .contains("OpenAI's standalone installer or the Homebrew cask")
        );
        assert!(
            unsigned.issues[0]
                .remediation
                .contains("precedes other copies in PATH")
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn explicit_agent_cli_doctor_reports_a_missing_command() {
        let agent = select_agent_cli(Some("claude")).unwrap();
        let result = diagnose_agent_cli(agent, OsStr::new(""), |_, _, _| true);

        assert_eq!(result.name, "claude");
        assert_eq!(result.issues[0].kind, "agent_cli_unavailable");
        assert!(
            result.issues[0]
                .remediation
                .contains("Anthropic's native installer or the Homebrew cask")
        );
    }

    #[test]
    fn aggregate_agent_cli_results_preserve_catalog_order() {
        let dir = temp_dir("agent-order");
        executable_file(&dir.join("claude"));
        executable_file(&dir.join("codex"));

        let results = agent_cli_results(dir.as_os_str(), |_, _, _| false);

        assert_eq!(
            results
                .iter()
                .map(|result| result.name.as_str())
                .collect::<Vec<_>>(),
            ["claude", "codex"]
        );
        assert!(results.iter().all(|result| {
            result.issues.len() == 1 && result.issues[0].kind == "agent_cli_signature_invalid"
        }));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn launcher_bundle_doctor_requires_its_command_to_win_path_resolution() {
        let dir = temp_dir("launcher-bundle-path");
        let app = dir.join("Herdr.app");
        fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        let runner = executable_file(&app.join("Contents/MacOS/launcher"));
        let commands = dir.join("commands");
        let competing = dir.join("competing");
        fs::create_dir(&commands).unwrap();
        fs::create_dir(&competing).unwrap();
        executable_file(&competing.join("herdr"));
        symlink(&runner, commands.join("herdr")).unwrap();
        let launcher = LauncherBundleDoctor {
            command: "herdr".into(),
            app,
        };
        let shadowed_path = std::env::join_paths([&competing, &commands]).unwrap();

        let shadowed = diagnose_launcher_bundle(&launcher, &commands, &shadowed_path, unsafe {
            libc::geteuid()
        });
        assert_eq!(shadowed.issues[0].kind, "launcher_bundle_not_first_on_path");
        assert_eq!(
            shadowed.issues[0].resolved_path.as_deref(),
            competing.join("herdr").to_str()
        );

        let healthy_path = std::env::join_paths([&commands, &competing]).unwrap();
        assert!(
            diagnose_launcher_bundle(&launcher, &commands, &healthy_path, unsafe {
                libc::geteuid()
            },)
            .issues
            .is_empty()
        );

        fs::remove_file(commands.join("herdr")).unwrap();
        fs::write(commands.join("herdr"), "unrelated").unwrap();
        let invalid = diagnose_launcher_bundle(&launcher, &commands, &healthy_path, unsafe {
            libc::geteuid()
        });
        assert_eq!(invalid.issues[0].kind, "launcher_bundle_command_invalid");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn aggregate_reports_installed_but_broken_hardening() {
        let dir = temp_dir("nonexecutable");
        let target = dir.join("npm");
        fs::write(&target, "not executable").unwrap();
        let stub = executable_file(&dir.join("stub"));
        let hardeners = vec![hardener(
            "node",
            false,
            command(
                "npm",
                false,
                stub.to_str().unwrap(),
                target.to_str().unwrap(),
            ),
        )];
        let results = diagnose(hardeners, None, OsStr::new("")).unwrap();
        assert_eq!(
            results[0]
                .issues
                .iter()
                .map(|issue| issue.kind)
                .collect::<Vec<_>>(),
            ["target_unavailable", "stub_content_invalid"]
        );

        let results = diagnose(
            vec![hardener(
                "node",
                false,
                command(
                    "npm",
                    false,
                    dir.join("stub").to_str().unwrap(),
                    target.to_str().unwrap(),
                ),
            )],
            Some("node"),
            OsStr::new(""),
        )
        .unwrap();

        assert_eq!(results[0].issues[0].kind, "target_unavailable");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn accepts_homebrew_as_an_explicit_alias() {
        let results = diagnose(
            vec![hardener(
                "brew",
                false,
                command("brew", false, "/missing/stub", "/missing/brew"),
            )],
            Some("homebrew"),
            OsStr::new(""),
        )
        .unwrap();

        assert_eq!(results[0].name, "brew");
        assert_eq!(results[0].issues[0].kind, "target_unavailable");
    }

    #[test]
    fn accepts_hardener_aliases_and_limits_executable_selection() {
        let dir = temp_dir("aliases");
        let jf = executable_file(&dir.join("jf"));
        let jfrog = executable_file(&dir.join("jfrog"));
        let jf_target = executable_file(&dir.join("jf-target"));
        let jfrog_target = executable_file(&dir.join("jfrog-target"));
        let hardeners = vec![HardenerMetadata {
            name: "jfrog-cli",
            documentation: "",
            detection: HardenerDetection::commands(
                true,
                vec![
                    command(
                        "jf",
                        true,
                        jf.to_str().unwrap(),
                        jf_target.to_str().unwrap(),
                    ),
                    command(
                        "jfrog",
                        true,
                        jfrog.to_str().unwrap(),
                        jfrog_target.to_str().unwrap(),
                    ),
                ],
            ),
            secret_gate: None,
        }];
        let results = diagnose(hardeners, Some("jf"), dir.as_os_str()).unwrap();
        assert_eq!(results[0].commands, ["jf"]);
        assert!(results[0].issues.is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn reports_hardening_and_path_precedence() {
        let dir = temp_dir("path");
        let stub_dir = dir.join("stub");
        let target_dir = dir.join("target");
        fs::create_dir_all(&stub_dir).unwrap();
        fs::create_dir_all(&target_dir).unwrap();
        let stub = executable_file(&stub_dir.join("aws"));
        let target = executable_file(&target_dir.join("aws"));

        let unhardened = diagnose(
            vec![hardener(
                "aws",
                false,
                command(
                    "aws",
                    false,
                    stub.to_str().unwrap(),
                    target.to_str().unwrap(),
                ),
            )],
            Some("aws"),
            stub_dir.as_os_str(),
        )
        .unwrap();
        assert_eq!(unhardened[0].issues[0].kind, "stub_content_invalid");
        assert!(
            !unhardened[0].issues[0]
                .remediation
                .contains("waiting a few point releases")
        );

        let shadowed_path = std::env::join_paths([&target_dir, &stub_dir]).unwrap();
        let shadowed = diagnose(
            vec![hardener(
                "aws",
                true,
                command(
                    "aws",
                    true,
                    stub.to_str().unwrap(),
                    target.to_str().unwrap(),
                ),
            )],
            None,
            &shadowed_path,
        )
        .unwrap();
        assert_eq!(shadowed[0].issues[0].kind, "stub_not_first_on_path");
        assert_eq!(
            shadowed[0].issues[0].resolved_path.as_deref(),
            target.to_str()
        );
        assert!(shadowed[0].issues[0].remediation.contains("export PATH="));

        let healthy_path = std::env::join_paths([&stub_dir, &target_dir]).unwrap();
        let healthy = diagnose(
            vec![hardener(
                "aws",
                true,
                command(
                    "aws",
                    true,
                    stub.to_str().unwrap(),
                    target.to_str().unwrap(),
                ),
            )],
            None,
            &healthy_path,
        )
        .unwrap();
        assert!(healthy[0].issues.is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn credential_helpers_are_not_expected_on_the_cli_path() {
        let dir = temp_dir("credential-helper-path");
        let helper = executable_file(&dir.join("terraform-credentials-av"));
        let terraform = executable_file(&dir.join("terraform"));
        let command = command(
            "terraform",
            true,
            helper.to_str().unwrap(),
            terraform.to_str().unwrap(),
        );

        assert!(path_issue(&command, dir.as_os_str()).is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn outdated_hardened_stub_reports_upgrade_without_becoming_unhardened() {
        let dir = temp_dir("stub-upgrade");
        let stub = executable_file(&dir.join("brew"));
        let target = executable_file(&dir.join("brew-target"));
        let mut outdated = command(
            "brew",
            true,
            stub.to_str().unwrap(),
            target.to_str().unwrap(),
        );
        outdated.stub_valid = false;

        let results = diagnose(
            vec![hardener("brew", true, outdated)],
            None,
            dir.as_os_str(),
        )
        .unwrap();

        assert_eq!(results[0].issues[0].kind, "stub_upgrade_required");
        assert!(results[0].issues[0].message.contains("out of date"));
        assert!(results[0].issues[0].remediation.contains("av harden brew"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn outdated_aws_stub_requires_immediate_rehardening() {
        let dir = temp_dir("aws-stub-upgrade");
        let stub = executable_file(&dir.join("aws"));
        let target = executable_file(&dir.join("aws-target"));
        let mut outdated = command(
            "aws",
            true,
            stub.to_str().unwrap(),
            target.to_str().unwrap(),
        );
        outdated.stub_valid = false;

        let results = diagnose(
            vec![hardener("aws", false, outdated)],
            Some("aws"),
            dir.as_os_str(),
        )
        .unwrap();

        assert_eq!(results[0].issues[0].kind, "stub_upgrade_required");
        assert!(!results[0].issues[0].remediation.contains("waiting"));
        assert!(
            results[0].issues[0]
                .remediation
                .contains("Run `av harden aws`")
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn reports_each_broken_stub_invariant_precisely() {
        let dir = temp_dir("stub-invariants");
        let stub = executable_file(&dir.join("tool"));
        let target = executable_file(&dir.join("tool-target"));
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o777)).unwrap();
        let metadata = stub.metadata().unwrap();
        let mut command = command(
            "tool",
            false,
            stub.to_str().unwrap(),
            target.to_str().unwrap(),
        );
        command.required_paths.push(RequiredExecutable {
            name: "helper",
            path: dir.join("missing-helper").display().to_string(),
        });
        command.stub_requirements = Some(StubRequirements {
            mode: 0o755,
            owner: RequiredIdentity {
                name: "expected-user",
                id: Some(metadata.uid() + 1),
            },
            group: RequiredIdentity {
                name: "expected-group",
                id: Some(metadata.gid()),
            },
        });

        let results = diagnose(
            vec![hardener("tool", false, command)],
            None,
            dir.as_os_str(),
        )
        .unwrap();
        let issues = &results[0].issues;

        assert_eq!(
            issues.iter().map(|issue| issue.kind).collect::<Vec<_>>(),
            [
                "dependency_unavailable",
                "stub_mode_mismatch",
                "stub_owner_mismatch",
                "stub_content_invalid"
            ]
        );
        assert!(issues[0].message.contains("missing-helper"));
        assert!(issues[1].message.contains("0o0777"));
        assert!(issues[2].remediation.contains("sudo chown"));
        assert!(issues[3].remediation.contains("Manual repair:"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_symlinked_stubs_even_when_they_resolve_to_an_executable() {
        let dir = temp_dir("symlink-stub");
        let target = executable_file(&dir.join("target"));
        let stub = dir.join("stub");
        symlink(&target, &stub).unwrap();
        let results = diagnose(
            vec![hardener(
                "tool",
                true,
                command(
                    "tool",
                    true,
                    stub.to_str().unwrap(),
                    target.to_str().unwrap(),
                ),
            )],
            None,
            dir.as_os_str(),
        )
        .unwrap();

        assert_eq!(results[0].issues[0].kind, "stub_wrong_type");
        assert!(results[0].issues[0].message.contains("symbolic link"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn target_only_hardening_checks_the_isotope_without_inventing_a_stub() {
        let missing = "/missing/isotope/bin/gh";
        let results = diagnose(
            vec![hardener(
                "gh",
                false,
                command("gh", false, missing, missing),
            )],
            Some("gh"),
            OsStr::new(""),
        )
        .unwrap();

        assert_eq!(results[0].issues.len(), 1);
        assert_eq!(results[0].issues[0].kind, "target_unavailable");
        assert!(results[0].issues[0].message.contains(missing));
    }

    #[test]
    fn configuration_exposures_remain_owned_by_scan() {
        let hardener = HardenerMetadata {
            name: "sudo",
            documentation: "",
            detection: HardenerDetection::configuration(
                false,
                true,
                Some("/etc/pam.d/sudo_local".to_string()),
            ),
            secret_gate: None,
        };
        let error = diagnose(vec![hardener], Some("sudo"), OsStr::new(""))
            .err()
            .unwrap();

        assert_eq!(
            error,
            "`sudo` has no Doctor-owned checks; use `av scan` for exposure findings"
        );
    }

    #[test]
    fn every_hardener_has_an_explicit_doctor_or_scan_boundary() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        for hardener in hardeners::metadata() {
            if hardener.detection.commands.is_empty() {
                assert!(
                    matches!(hardener.name, "codex" | "sudo"),
                    "{} needs Doctor checks or an explicit Scan-owned exemption",
                    hardener.name
                );
                continue;
            }
            for command in &hardener.detection.commands {
                if has_stub_checks(command) {
                    assert!(
                        command.stub_requirements.is_some(),
                        "{}:{} lacks stub mode/ownership requirements",
                        hardener.name,
                        command.name
                    );
                    if hardener.name != "brew" {
                        assert!(
                            command
                                .required_paths
                                .iter()
                                .any(|required| required.name == "Automic Vault CLI"),
                            "{}:{} does not check its av interpreter",
                            hardener.name,
                            command.name
                        );
                    }
                } else {
                    assert!(
                        matches!(
                            hardener.name,
                            "aliyun-cli"
                                | "gh"
                                | "goat"
                                | "ordercli"
                                | "openhue-cli"
                                | "plumber"
                                | "uaa-cli"
                                | "railway"
                                | "rclone"
                                | "oxide-cli"
                                | "stripe"
                                | "supabase"
                                | "wakatime-cli"
                        ),
                        "{}:{} needs explicit target-only Doctor coverage review",
                        hardener.name,
                        command.name
                    );
                }
            }
        }
    }

    fn hardener(name: &'static str, hardened: bool, command: HardenerCommand) -> HardenerMetadata {
        HardenerMetadata {
            name,
            documentation: "",
            detection: HardenerDetection::commands(hardened, vec![command]),
            secret_gate: None,
        }
    }

    fn command(name: &str, hardened: bool, stub: &str, target: &str) -> HardenerCommand {
        HardenerCommand {
            name: name.to_string(),
            hardened,
            stub_valid: hardened,
            stub_path: Some(stub.to_string()),
            target_path: target.to_string(),
            required_paths: Vec::new(),
            stub_requirements: None,
            injected_keys: Vec::new(),
            assignment_keys: Vec::new(),
            isotope: None,
        }
    }

    #[test]
    fn isotope_path_check_requires_the_signed_basename_on_path() {
        let directory = temp_dir("isotope-path");
        let gh = executable_file(&directory.join("gh"));
        let mut command = command("gh", true, gh.to_str().unwrap(), gh.to_str().unwrap());
        command.isotope = Some(isotope::Doctor {
            identifier: "gh",
            formula_url: "https://example.invalid/gh-cli.rb".into(),
            repository: "gh-cli",
            receipt_path: None,
        });
        assert!(
            isotope_path_issue(&command, directory.as_os_str(), |_, identifier| identifier
                == "gh")
            .is_none()
        );
        assert_eq!(
            isotope_path_issue(&command, directory.as_os_str(), |_, _| false)
                .unwrap()
                .kind,
            "isotope_not_first_on_path"
        );
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn aws_update_check_directs_updates_back_to_the_hardener() {
        let command = command("aws", true, "/usr/local/bin/aws", aws_release::TARGET_PATH);
        let issue = aws_update_issue(&command, Ok("2.36.21".into()), Ok("2.36.22".into())).unwrap();

        assert_eq!(issue.kind, "aws_update_available");
        assert!(issue.message.contains("2.36.21"));
        assert!(issue.message.contains("2.36.22"));
        assert!(issue.remediation.contains("av harden aws"));
        assert!(aws_update_issue(&command, Ok("2.36.22".into()), Ok("2.36.22".into())).is_none());
    }

    #[test]
    fn direct_isotope_update_check_uses_the_formula_digest() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let directory = temp_dir("isotope-update");
        let receipt = directory.join("gh-cli.sha256");
        let hash = "29e7f73c54cc1c278b7431bc04d581b468ca033d1782c39c87034515ae5d7070";
        fs::write(&receipt, format!("{hash}\n")).unwrap();
        unsafe {
            std::env::set_var(
                "AUTOMIC_VAULT_TEST_ISOTOPE_FORMULA",
                format!(
                    "url \"https://github.com/automic-vault/gh-cli/releases/download/v1/cli.tgz\"\nsha256 \"{hash}\"\n"
                ),
            );
        }
        let command = command("gh", true, "/usr/local/bin/gh", "/usr/local/bin/gh");
        let doctor = isotope::Doctor {
            identifier: "gh",
            formula_url: "https://example.invalid/gh-cli.rb".into(),
            repository: "gh-cli",
            receipt_path: Some(receipt.display().to_string()),
        };
        assert!(isotope_update_issue(&command, &doctor).is_none());
        fs::write(&receipt, "different\n").unwrap();
        assert_eq!(
            isotope_update_issue(&command, &doctor).unwrap().kind,
            "isotope_update_required"
        );
        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_ISOTOPE_FORMULA");
        }
        let _ = fs::remove_dir_all(directory);
    }

    fn executable_file(path: &Path) -> PathBuf {
        fs::write(path, "#!/bin/sh\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_path_buf()
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("av-doctor-{label}-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
