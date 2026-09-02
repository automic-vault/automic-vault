use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

pub(crate) mod aliyun_credential;
mod aws;
mod bless;
pub(crate) mod docker_credential;
pub(crate) mod doctor;
pub(crate) mod fastly_credential;
pub(crate) mod goat_credential;
mod gpg_sign;
mod inject;
pub(crate) mod kubectl_credential;
mod launcher_bundle;
mod list;
mod open;
pub(crate) mod openhue_credential;
pub(crate) mod ordercli_credential;
pub(crate) mod oxide_credential;
pub(crate) mod plumber_credential;
mod proxy;
pub(crate) mod railway_credential;
pub(crate) mod rclone_password;
mod save;
mod scan;
mod shell_secrets;
pub(crate) mod sqlcmd_credential;
pub(crate) mod terraform_credential;
pub(crate) mod uaa_credential;
pub(crate) mod wakatime_credential;

use crate::isotopes::hardeners;

const USAGE: &str = "\
usage:
  av <command> [options]

commands:
  $ av scan [--show-all|--json]           # audit secrets and configuration
  $ av doctor [<tool>] [--json]           # verify installed hardening
  $ av detectors --json                   # print detector metadata
  $ av hardeners --json                   # print hardener metadata
  $ av bless [--endorse-launcher] <path>  # review a script for secret access
  $ av inject +KEY... [--] <command>      # inject secrets into a command
  $ av inject -- <command>                # run an approved script
  $ av proxy +KEY... [--] <command>       # proxy secret references for a command
  $ av list                               # list saved secret names
  $ av save [--project-directory=DIR] KEY # store a global or Project Value
  $ av harden <tool> [-y|--yes]           # harden a tool; migrate credentials
  $ av unharden brew [-y|--yes]           # temporarily restore Homebrew for cask migration
  $ av gpg-sign [GPG options]             # authorize and sign a Git payload
  $ av open [--secret-gate <id>]          # open the Automic Vault app

modes:
  $ av help                               # show this help
  $ av --version                          # print version

more:
  $ open https://www.automicvault.com/docs/";

pub(crate) const INSTALL_REVISION: u32 = 43;

pub(crate) fn bash_shell_secret_insecurity_reasons() -> Result<Vec<String>, String> {
    shell_secrets::bash_reasons()
}

pub(crate) fn zsh_shell_secret_insecurity_reasons() -> Result<Vec<String>, String> {
    shell_secrets::zsh_reasons()
}

pub(crate) fn ensure_aws_helper_ready() -> Result<(), String> {
    aws::ensure_helper_ready()
}

pub fn run<I, W, E>(args: I, stdout: &mut W, stderr: &mut E) -> i32
where
    I: IntoIterator<Item = OsString>,
    W: Write,
    E: Write,
{
    run_with_style(
        args,
        stdout,
        stderr,
        scan::Style::plain(),
        scan::Style::plain(),
    )
}

pub fn run_terminal<I>(args: I) -> i32
where
    I: IntoIterator<Item = OsString>,
{
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let terminal = stdout.is_terminal();
    let color = terminal && color_enabled();
    run_with_style(
        args,
        &mut stdout,
        &mut stderr,
        scan::Style { color },
        scan::Style { color: terminal },
    )
}

pub fn run_scanner_terminal<I>(args: I) -> i32
where
    I: IntoIterator<Item = OsString>,
{
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let terminal = stdout.is_terminal();
    run_scanner_with_style(
        args,
        &mut stdout,
        &mut stderr,
        scan::Style {
            color: terminal && color_enabled(),
        },
    )
}

fn run_scanner_with_style<I, W, E>(
    args: I,
    stdout: &mut W,
    stderr: &mut E,
    style: scan::Style,
) -> i32
where
    I: IntoIterator<Item = OsString>,
    W: Write,
    E: Write,
{
    let mut args = args.into_iter();
    let _program = args.next();
    match args.collect::<Vec<_>>().as_slice() {
        [] => scan::run(stdout, style, false),
        [arg] if arg == "--show-all" => scan::run(stdout, style, true),
        [arg] if arg == "--json" => scan::run_json(stdout, stderr, &[]),
        [arg] if arg == "--version" || arg == "-V" => {
            let _ = writeln!(stdout, "scanner {}", env!("CARGO_PKG_VERSION"));
            0
        }
        [arg] if arg == "--help" || arg == "-h" => {
            let _ = writeln!(stdout, "usage: scanner [--show-all|--json]");
            0
        }
        _ => {
            let _ = writeln!(stderr, "usage: scanner [--show-all|--json]");
            2
        }
    }
}

fn run_with_style<I, W, E>(
    args: I,
    stdout: &mut W,
    stderr: &mut E,
    style: scan::Style,
    help_style: scan::Style,
) -> i32
where
    I: IntoIterator<Item = OsString>,
    W: Write,
    E: Write,
{
    let mut args = args.into_iter();
    let _program = args.next();
    let Some(command) = args.next() else {
        let _ = writeln!(stderr, "{USAGE}");
        return 2;
    };
    if command == "help" || command == "--help" || command == "-h" {
        write_help(stdout, help_style);
        return 0;
    }
    if command == "--version" || command == "-V" {
        let _ = writeln!(stdout, "av {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }
    if command == "__version" {
        let _ = writeln!(stdout, "{INSTALL_REVISION}");
        return 0;
    }
    let mut rest = args.collect::<Vec<_>>();

    let mut shebang_script = None;
    let command = if let Some(words) = split_shebang_inject_arg(&command) {
        shebang_script = rest.first().cloned();
        rest.splice(0..0, words.into_iter().skip(1));
        OsString::from("inject")
    } else {
        command
    };

    match command.to_str() {
        Some("__install-launcher-bundle") if rest.len() == 6 => {
            let (Some(bundle_name), Some(command_name), Some(generation), Some(tree_sha256)) = (
                rest[1].to_str(),
                rest[2].to_str(),
                rest[3].to_str(),
                rest[4].to_str(),
            ) else {
                let _ = writeln!(stderr, "av: invalid Launcher Bundle arguments");
                return 2;
            };
            privileged_result(
                launcher_bundle::install(
                    &PathBuf::from(&rest[0]),
                    bundle_name,
                    command_name,
                    generation,
                    tree_sha256,
                    &PathBuf::from(&rest[5]),
                ),
                stderr,
            )
        }
        Some("__remove-launcher-bundle") if rest.len() == 4 => {
            let (Some(bundle_name), Some(command_name), Some(generation)) =
                (rest[0].to_str(), rest[1].to_str(), rest[2].to_str())
            else {
                let _ = writeln!(stderr, "av: invalid Launcher Bundle arguments");
                return 2;
            };
            privileged_result(
                launcher_bundle::remove(
                    bundle_name,
                    command_name,
                    generation,
                    &PathBuf::from(&rest[3]),
                ),
                stderr,
            )
        }
        Some("__harden-brew") if rest.is_empty() => {
            match hardeners::homebrew::harden_privileged(stdout) {
                Ok(()) => 0,
                Err(err) => {
                    let _ = writeln!(stderr, "av: {err}");
                    1
                }
            }
        }
        Some("__install-aws-release") if rest.len() == 2 => {
            let Some(sha256) = rest[0].to_str() else {
                let _ = writeln!(stderr, "av: invalid AWS release digest");
                return 2;
            };
            match hardeners::aws_cli::install_aws_release(sha256, &PathBuf::from(&rest[1])) {
                Ok(()) => 0,
                Err(err) => {
                    let _ = writeln!(stderr, "av: {err}");
                    1
                }
            }
        }
        Some("__install-terraform-release") if rest.len() == 2 => {
            let Some(sha256) = rest[0].to_str() else {
                let _ = writeln!(stderr, "av: invalid Terraform release digest");
                return 2;
            };
            privileged_result(
                hardeners::terraform::install_terraform_release(sha256, &PathBuf::from(&rest[1])),
                stderr,
            )
        }
        Some("__install-docker-helper") if rest.is_empty() => {
            match hardeners::docker::install_privileged() {
                Ok(()) => 0,
                Err(err) => {
                    let _ = writeln!(stderr, "av: {err}");
                    1
                }
            }
        }
        Some("__install-podman-helper") if rest.is_empty() => {
            match hardeners::podman::install_privileged() {
                Ok(()) => 0,
                Err(err) => {
                    let _ = writeln!(stderr, "av: {err}");
                    1
                }
            }
        }
        Some("__install-env-wrapper") if rest.len() >= 2 => {
            let Some(target) = rest[0].to_str() else {
                let _ = writeln!(stderr, "av: invalid env-wrapper hardener name");
                return 2;
            };
            let paths = rest[1..].iter().map(PathBuf::from).collect::<Vec<_>>();
            match hardeners::env_wrapper::install_target(target, &paths) {
                Ok(()) => 0,
                Err(err) => {
                    let _ = writeln!(stderr, "av: {err}");
                    1
                }
            }
        }
        Some("__install-isotope") if rest.len() == 3 => {
            let Some(hardener) = rest[0].to_str() else {
                let _ = writeln!(stderr, "av: invalid isotope hardener name");
                return 2;
            };
            let Some(sha256) = rest[1].to_str() else {
                let _ = writeln!(stderr, "av: invalid isotope digest");
                return 2;
            };
            let archive = PathBuf::from(&rest[2]);
            match hardeners::isotope::install_privileged(hardener, sha256, &archive) {
                Ok(()) => 0,
                Err(err) => {
                    let _ = writeln!(stderr, "av: {err}");
                    1
                }
            }
        }
        Some("scan") if rest.is_empty() => scan::run(stdout, style, false),
        Some("scan") if rest == [OsString::from("--show-all")] => scan::run(stdout, style, true),
        Some("scan") if rest.first() == Some(&OsString::from("--json")) => {
            let Some(detectors) = parse_scan_json_args(&rest) else {
                let _ = writeln!(stderr, "{USAGE}");
                return 2;
            };
            scan::run_json(stdout, stderr, &detectors)
        }
        Some("detectors") if rest == [OsString::from("--json")] => scan::run_detectors_json(stdout),
        Some("hardeners") if rest == [OsString::from("--json")] => scan::run_hardeners_json(stdout),
        Some("__dashboard-hardening-json") if rest.is_empty() => {
            match scan::run_dashboard_hardening_json(stdout) {
                Ok(code) => code,
                Err(err) => {
                    let _ = writeln!(stderr, "av: {err}");
                    1
                }
            }
        }
        Some("__secret-gates-json") if rest.is_empty() => scan::run_secret_gates_json(stdout),
        Some("gpg-sign") => gpg_sign::run(rest, stdout, stderr),
        Some("__gpg-public-key") if rest.is_empty() => gpg_sign::validate(stdout, stderr),
        Some("__gpg-generate-key") if rest.is_empty() => gpg_sign::generate(stdout, stderr),
        Some("doctor") => {
            let Some((selector, json)) = parse_doctor_args(&rest) else {
                let _ = writeln!(stderr, "{USAGE}");
                return 2;
            };
            match doctor::run(stdout, selector.as_deref(), json, style) {
                Ok(code) => code,
                Err(err) => {
                    let _ = writeln!(stderr, "av doctor: {err}");
                    2
                }
            }
        }
        Some("unharden") => {
            let Some((target, _yes)) = parse_harden_args(&rest) else {
                let _ = writeln!(stderr, "{USAGE}");
                return 2;
            };
            if target != "brew" && target != "homebrew" {
                let _ = writeln!(stderr, "{USAGE}");
                return 2;
            }
            match hardeners::homebrew::unharden(stdout) {
                Ok(hardeners::RootOnlyOutcome::Hardened) => 0,
                Ok(hardeners::RootOnlyOutcome::Previewed) => 1,
                Err(err) => {
                    let _ = writeln!(stderr, "av unharden: {err}");
                    1
                }
            }
        }
        Some("harden") => {
            let Some((target, yes)) = parse_harden_args(&rest) else {
                let _ = writeln!(stderr, "{USAGE}");
                return 2;
            };
            let target = if target == "fly" {
                OsString::from("flyctl")
            } else {
                target
            };
            if target == "aws" {
                let result = hardeners::aws_cli::run_aws(stdout, yes);
                return finish_hardening(result, "aws", stdout, stderr);
            }
            if target == "docker" {
                let result = hardeners::docker::run(stdout, yes);
                return finish_hardening(result, "docker", stdout, stderr);
            }
            if target == "podman" {
                let result = hardeners::podman::run(stdout, yes);
                return finish_hardening(result, "podman", stdout, stderr);
            }
            if target == "terraform" || target == "terraform-core" {
                let result =
                    hardeners::terraform::run(hardeners::terraform::Tool::Terraform, stdout, yes);
                return finish_hardening(result, "terraform", stdout, stderr);
            }
            if target == "opentofu" || target == "tofu" {
                let result =
                    hardeners::terraform::run(hardeners::terraform::Tool::OpenTofu, stdout, yes);
                return finish_hardening(result, "opentofu", stdout, stderr);
            }
            if target == "oxide" || target == "oxide-cli" {
                let result = hardeners::oxide_cli::run(stdout, yes);
                return finish_hardening(result, "oxide-cli", stdout, stderr);
            }
            if target == "fastly" || target == "fastly-cli" {
                let result = hardeners::fastly_cli::run(stdout, yes);
                return finish_hardening(result, "fastly-cli", stdout, stderr);
            }
            if target == "sqlcmd" {
                let result = hardeners::sqlcmd::run(stdout, yes);
                return finish_hardening(result, "sqlcmd", stdout, stderr);
            }
            if target == "aliyun" || target == "aliyun-cli" {
                let result = hardeners::aliyun_cli::run(stdout, yes);
                return finish_hardening(result, "aliyun-cli", stdout, stderr);
            }
            if target == "goat" {
                let result = hardeners::goat::run(stdout, yes);
                return finish_hardening(result, "goat", stdout, stderr);
            }
            if target == "railway" {
                let result = hardeners::railway::run(stdout, yes);
                return finish_hardening(result, "railway", stdout, stderr);
            }
            if target == "ordercli" {
                let result = hardeners::ordercli::run(stdout, yes);
                return finish_hardening(result, "ordercli", stdout, stderr);
            }
            if target == "uaa" || target == "uaa-cli" {
                let result = hardeners::uaa_cli::run(stdout, yes);
                return finish_hardening(result, "uaa-cli", stdout, stderr);
            }
            if target == "openhue" || target == "openhue-cli" {
                let result = hardeners::openhue_cli::run(stdout, yes);
                return finish_hardening(result, "openhue-cli", stdout, stderr);
            }
            if target == "plumber" {
                let result = hardeners::plumber::run(stdout, yes);
                return finish_hardening(result, "plumber", stdout, stderr);
            }
            if target == "wakatime" || target == "wakatime-cli" {
                let result = hardeners::wakatime_cli::run(stdout, yes);
                return finish_hardening(result, "wakatime-cli", stdout, stderr);
            }
            if target == "rclone" {
                let result = hardeners::rclone::run(stdout, yes);
                return finish_hardening(result, "rclone", stdout, stderr);
            }
            if target == "kubectl" || target == "kubernetes-cli" {
                let result = hardeners::kubectl::run(stdout, yes);
                return finish_hardening(result, "kubectl", stdout, stderr);
            }
            if target == "gh" || target == "gh-cli" {
                let result = hardeners::gh_cli::run(stdout, yes);
                return finish_hardening(result, "gh", stdout, stderr);
            }
            if target == "stripe" || target == "stripe-cli" {
                let result = hardeners::stripe_cli::run(stdout, yes);
                return finish_hardening(result, "stripe", stdout, stderr);
            }
            if target == "brew" || target == "homebrew" {
                let result = hardeners::homebrew::run(stdout, yes);
                return finish_hardening(result, "brew", stdout, stderr);
            }
            if target == "codex" {
                let result = hardeners::codex::run(stdout, yes);
                return finish_hardening(result, "codex", stdout, stderr);
            }
            if target == "sudo" {
                return match hardeners::sudo::run(stdout, style.color) {
                    Ok(hardeners::RootOnlyOutcome::Hardened) => {
                        print_hardening_followup(stdout, "sudo");
                        0
                    }
                    Ok(hardeners::RootOnlyOutcome::Previewed) => 1,
                    Err(err) => {
                        let _ = writeln!(stderr, "av harden: {err}");
                        1
                    }
                };
            }
            if target == "supabase" || target == "supabase-cli" {
                let result = hardeners::supabase::run(stdout, yes);
                return finish_hardening(result, "supabase", stdout, stderr);
            }
            if let Some(target) = target.to_str()
                && let Some(result) = hardeners::env_wrapper::run_target(target, stdout, yes)
            {
                return finish_hardening(result, target, stdout, stderr);
            }
            let _ = writeln!(
                stderr,
                "av harden: no such hardener `{}`",
                target.to_string_lossy()
            );
            2
        }
        Some("inject") => inject::run(rest, stdout, stderr, shebang_script),
        Some("proxy") => proxy::run(rest, stdout, stderr),
        Some("aws") => aws::run(rest, stderr),
        Some("aws-official") => aws::run_official(rest, stderr),
        Some("aws-credentials") if rest.is_empty() => aws::credentials(None, stdout, stderr),
        Some("aws-credentials") if rest == [OsString::from("official-v2")] => {
            aws::credentials(Some("official-v2"), stdout, stderr)
        }
        Some("docker-credential") => docker_credential::run(rest, stdout, stderr),
        Some("podman-credential") => docker_credential::run_podman(rest, stdout, stderr),
        Some("terraform-credential") => terraform_credential::run(rest, stdout, stderr),
        Some("aliyun-credential") => aliyun_credential::run(rest, stdout, stderr),
        Some("oxide-credential") => oxide_credential::run(rest, stdout, stderr),
        Some("fastly-credential") => fastly_credential::run(rest, stdout, stderr),
        Some("sqlcmd-credential") => sqlcmd_credential::run(rest, stdout, stderr),
        Some("goat-credential") => goat_credential::run(rest, stdout, stderr),
        Some("kubectl-credential") => kubectl_credential::run(rest, stdout, stderr),
        Some("ordercli-credential") => ordercli_credential::run(rest, stdout, stderr),
        Some("openhue-credential") => openhue_credential::run(rest, stdout, stderr),
        Some("plumber-credential") => plumber_credential::run(rest, stdout, stderr),
        Some("uaa-credential") => uaa_credential::run(rest, stdout, stderr),
        Some("railway-credential") => railway_credential::run(rest, stdout, stderr),
        Some("wakatime-credential") => wakatime_credential::run(rest, stdout, stderr),
        Some("rclone-password") => rclone_password::run(rest, stdout, stderr),
        Some("list" | "ls") => list::run(rest, stdout, stderr),
        Some("bless") => bless::run(rest, stderr),
        Some("open") => {
            let Some(secret_gate) = parse_open_args(&rest) else {
                let _ = writeln!(stderr, "{USAGE}");
                return 2;
            };
            open::run(stderr, secret_gate.as_deref())
        }
        Some("save") => save::run(rest, stderr),
        _ => {
            let _ = writeln!(stderr, "{USAGE}");
            2
        }
    }
}

fn privileged_result<E: Write>(result: Result<(), String>, stderr: &mut E) -> i32 {
    match result {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "av: {error}");
            1
        }
    }
}

fn write_help(stdout: &mut dyn Write, style: scan::Style) {
    for line in USAGE.lines() {
        let (command, comment) = line.split_once('#').unwrap_or((line, ""));
        let command = command
            .chars()
            .map(|ch| {
                if matches!(ch, '[' | ']' | '<' | '>' | '|' | '$') {
                    style.paint("2", ch.to_string())
                } else {
                    ch.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("");
        if comment.is_empty() {
            let _ = writeln!(stdout, "{command}");
        } else {
            let _ = writeln!(
                stdout,
                "{command}{}",
                style.paint("2", format!("#{comment}"))
            );
        }
    }
}

fn print_hardening_followup(stdout: &mut dyn Write, target: &str) {
    let _ = writeln!(stdout, "◇ next: run `av doctor {target}`");
}

fn finish_hardening<W: Write, E: Write>(
    result: Result<(), String>,
    target: &str,
    stdout: &mut W,
    stderr: &mut E,
) -> i32 {
    match result {
        Ok(()) => {
            print_hardening_followup(stdout, target);
            0
        }
        Err(err) => {
            let _ = writeln!(stderr, "av harden: {err}");
            1
        }
    }
}

fn parse_harden_args(args: &[OsString]) -> Option<(OsString, bool)> {
    let mut yes = false;
    let mut target = None;
    for arg in args {
        if arg == "--yes" || arg == "-y" {
            yes = true;
        } else if target.is_none() {
            target = Some(arg.clone());
        } else {
            return None;
        }
    }
    target.map(|target| (target, yes))
}

fn parse_scan_json_args(args: &[OsString]) -> Option<Vec<String>> {
    let mut args = args.iter();
    (args.next()? == "--json").then_some(())?;
    let mut detectors = Vec::new();
    while let Some(flag) = args.next() {
        if flag != "--detector" {
            return None;
        }
        detectors.push(args.next()?.to_str()?.to_string());
    }
    Some(detectors)
}

fn parse_open_args(args: &[OsString]) -> Option<Option<String>> {
    match args {
        [] => Some(None),
        [flag, id] if flag == "--secret-gate" => {
            let id = id.to_str()?;
            open::valid_secret_gate_id(id).then(|| Some(id.to_string()))
        }
        _ => None,
    }
}

fn parse_doctor_args(args: &[OsString]) -> Option<(Option<String>, bool)> {
    let mut selector = None;
    let mut json = false;
    for arg in args {
        if arg == "--json" {
            if json {
                return None;
            }
            json = true;
        } else if selector.is_none() {
            selector = Some(arg.to_str()?.to_string());
        } else {
            return None;
        }
    }
    Some((selector, json))
}

fn split_shebang_inject_arg(value: &OsString) -> Option<Vec<OsString>> {
    let value = value.to_str()?;
    if value == "inject" || !value.starts_with("inject ") {
        return None;
    }
    Some(value.split_whitespace().map(OsString::from).collect())
}

fn color_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none()
        && std::env::var_os("TERM").is_none_or(|term| term != "dumb")
}

#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn run_args(args: &[&str]) -> (i32, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(args.iter().map(OsString::from), &mut stdout, &mut stderr);
        (
            code,
            String::from_utf8(stdout).unwrap(),
            String::from_utf8(stderr).unwrap(),
        )
    }

    fn run_scanner_args(args: &[&str]) -> (i32, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_scanner_with_style(
            args.iter().map(OsString::from),
            &mut stdout,
            &mut stderr,
            scan::Style::plain(),
        );
        (
            code,
            String::from_utf8(stdout).unwrap(),
            String::from_utf8(stderr).unwrap(),
        )
    }

    #[test]
    fn scanner_only_accepts_scan_options() {
        let (code, stdout, stderr) = run_scanner_args(&["scanner", "--help"]);
        assert_eq!(
            (code, stdout.as_str(), stderr.as_str()),
            (0, "usage: scanner [--show-all|--json]\n", "")
        );

        let (code, stdout, stderr) = run_scanner_args(&["scanner", "doctor"]);
        assert_eq!(
            (code, stdout.as_str(), stderr.as_str()),
            (2, "", "usage: scanner [--show-all|--json]\n")
        );
    }

    #[test]
    fn scan_prints_clean_report() {
        let (code, stdout, stderr) = run_args(&["av", "scan"]);

        assert_eq!(code, 0);
        assert!(stdout.starts_with("╭─ system exposure audit\n"));
        assert_eq!(stderr, "");
    }

    #[test]
    fn scan_show_all_is_supported() {
        let (code, _, stderr) = run_args(&["av", "scan", "--show-all"]);

        assert_eq!(code, 0);
        assert_eq!(stderr, "");
    }

    #[test]
    fn private_dashboard_hardening_report_combines_hardeners_and_doctor() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_AWS_STUB_PATH", "/nonexistent");
        }

        let (code, stdout, stderr) = run_args(&["av", "__dashboard-hardening-json"]);

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_AWS_STUB_PATH") };
        let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(code, 0);
        assert_eq!(stderr, "");
        assert!(
            report["hardeners"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
        );
        assert!(
            report["detectors"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
        );
        assert!(report["secret_gates"].is_array());
        assert!(report["results"].is_array());
    }

    #[test]
    fn harden_brew_is_routed() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let missing = std::env::temp_dir().join(format!("av-missing-brew-{}", std::process::id()));
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_TARGET", &missing);
            std::env::set_var("AUTOMIC_VAULT_TEST_EUID", "501");
        }

        let (code, stdout, stderr) = run_args(&["av", "harden", "brew"]);

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_BREW_TARGET");
            std::env::remove_var("AUTOMIC_VAULT_TEST_EUID");
        }
        assert_eq!(code, 1);
        assert_eq!(stdout, "");
        assert_eq!(
            stderr,
            format!(
                "av harden: Homebrew is not installed at {}\n",
                missing.display()
            )
        );
    }

    #[test]
    fn unharden_brew_is_routed() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let missing =
            std::env::temp_dir().join(format!("av-missing-unharden-brew-{}", std::process::id()));
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_BREW_TARGET", &missing);
            std::env::set_var("AUTOMIC_VAULT_TEST_EUID", "0");
        }

        let (code, stdout, stderr) = run_args(&["av", "unharden", "brew"]);

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_BREW_TARGET");
            std::env::remove_var("AUTOMIC_VAULT_TEST_EUID");
        }
        assert_eq!(code, 1);
        assert_eq!(stdout, "");
        assert_eq!(
            stderr,
            format!(
                "av unharden: Homebrew is not installed at {}\n",
                missing.display()
            )
        );
    }

    #[test]
    fn harden_fly_aliases_flyctl() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let targets = std::env::temp_dir().join(format!("av-cli-fly-{}", std::process::id()));
        std::fs::create_dir_all(&targets).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_TARGET_DIR", &targets);
        }

        let (code, stdout, stderr) = run_args(&["av", "harden", "fly"]);

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_TARGET_DIR");
        }
        std::fs::remove_dir_all(&targets).unwrap();
        assert_eq!(code, 1);
        assert_eq!(stdout, "");
        assert_eq!(
            stderr,
            format!(
                "av harden: flyctl is not an executable file: {}\n",
                targets.join("flyctl").display()
            )
        );
    }

    #[test]
    fn harden_npm_aliases_node() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let targets = std::env::temp_dir().join(format!("av-cli-npm-{}", std::process::id()));
        std::fs::create_dir_all(&targets).unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_TARGET_DIR", &targets);
        }

        let (code, stdout, stderr) = run_args(&["av", "harden", "npm"]);

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_TARGET_DIR");
        }
        std::fs::remove_dir_all(&targets).unwrap();
        assert_eq!(code, 1);
        assert_eq!(stdout, "");
        assert_eq!(
            stderr,
            format!(
                "av harden: npm is not an executable file: {}\n",
                targets.join("npm").display()
            )
        );
    }

    #[test]
    fn harden_rejects_unknown_hardeners_with_a_specific_error() {
        let (code, stdout, stderr) = run_args(&["av", "harden", "foo"]);

        assert_eq!(code, 2);
        assert_eq!(stdout, "");
        assert_eq!(stderr, "av harden: no such hardener `foo`\n");
    }

    #[test]
    fn harden_sudo_previews_the_privileged_step() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let pam = std::env::temp_dir().join(format!("av-cli-sudo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&pam);
        std::fs::create_dir_all(&pam).unwrap();
        std::fs::write(pam.join("sudo_local"), "#auth sufficient pam_tid.so\n").unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_SUDO_PAM_DIR", &pam);
        }

        let (code, stdout, stderr) = run_args(&["av", "harden", "sudo"]);

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_SUDO_PAM_DIR");
        }
        let _ = std::fs::remove_dir_all(pam);
        assert_eq!(code, 1);
        assert_eq!(
            stdout,
            "╭─ harden sudo\n│\n├─ enable biometric authentication for sudo\n╰─ next: sudo av harden sudo\n"
        );
        assert_eq!(stderr, "");
    }

    #[test]
    fn user_only_hardeners_reject_root() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_EUID", "0") };

        for target in ["codex", "gh", "stripe", "supabase"] {
            let (code, stdout, stderr) = run_args(&["av", "harden", target]);
            assert_eq!(code, 1, "{target}");
            assert_eq!(stdout, "", "{target}");
            assert_eq!(
                stderr,
                format!("av harden: `av harden {target}` cannot be run as root\n")
            );
        }

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_EUID") };
    }

    #[test]
    fn harden_codex_performs_the_safe_migration_order() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let home = std::env::temp_dir().join(format!("av-cli-codex-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let codex = home.join("codex");
        std::fs::write(
            &codex,
            "#!/bin/sh\nexpected='cli_auth_credentials_store=\"keyring\"'\nif [ \"$1 $2\" = \"login --with-api-key\" ]; then read secret; [ \"$secret\" = api-secret ] && [ \"$3\" = -c ] && [ \"$4\" = \"$expected\" ]; exit; fi\n[ \"$1 $2\" = \"login status\" ] && [ \"$3\" = -c ] && [ \"$4\" = \"$expected\" ]\n",
        )
        .unwrap();
        std::fs::set_permissions(&codex, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(home.join("config.toml"), "model = \"gpt-5.6\"\n").unwrap();
        std::fs::write(home.join("auth.json"), r#"{"OPENAI_API_KEY":"api-secret"}"#).unwrap();
        unsafe {
            std::env::set_var("CODEX_HOME", &home);
            std::env::set_var("AUTOMIC_VAULT_TEST_CODEX_CLI_PATH", &codex);
            std::env::set_var("AUTOMIC_VAULT_TEST_CHATGPT_RUNNING", "0");
        }

        let (code, stdout, stderr) = run_args(&["av", "harden", "codex", "--yes"]);

        unsafe {
            std::env::remove_var("CODEX_HOME");
            std::env::remove_var("AUTOMIC_VAULT_TEST_CODEX_CLI_PATH");
            std::env::remove_var("AUTOMIC_VAULT_TEST_CHATGPT_RUNNING");
        }
        assert_eq!(code, 0);
        assert!(stdout.contains("delete"));
        assert!(stdout.contains("login --with-api-key"));
        assert!(stdout.contains("only after verification"));
        assert!(stdout.contains("verified Codex login from the Keychain"));
        assert!(stdout.contains("◇ next: run `av doctor codex`"));
        assert!(!stdout.contains("api-secret"));
        assert_eq!(
            std::fs::read_to_string(home.join("config.toml")).unwrap(),
            "cli_auth_credentials_store = \"keyring\"\nmodel = \"gpt-5.6\"\n"
        );
        assert!(!home.join("auth.json").exists());
        assert_eq!(stderr, "");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn harden_codex_rolls_back_when_login_verification_fails() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let home =
            std::env::temp_dir().join(format!("av-cli-codex-rollback-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let codex = home.join("codex");
        std::fs::write(
            &codex,
            "#!/bin/sh\n[ \"$1 $2\" = \"login -c\" ] && exit 0\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&codex, std::fs::Permissions::from_mode(0o755)).unwrap();
        let original = "model = \"gpt-5.6\"\n";
        std::fs::write(home.join("config.toml"), original).unwrap();
        std::fs::write(
            home.join("auth.json"),
            r#"{"tokens":{"access_token":"secret"}}"#,
        )
        .unwrap();
        unsafe {
            std::env::set_var("CODEX_HOME", &home);
            std::env::set_var("AUTOMIC_VAULT_TEST_CODEX_CLI_PATH", &codex);
            std::env::set_var("AUTOMIC_VAULT_TEST_CHATGPT_RUNNING", "0");
        }

        let (code, _, stderr) = run_args(&["av", "harden", "codex", "--yes"]);

        unsafe {
            std::env::remove_var("CODEX_HOME");
            std::env::remove_var("AUTOMIC_VAULT_TEST_CODEX_CLI_PATH");
            std::env::remove_var("AUTOMIC_VAULT_TEST_CHATGPT_RUNNING");
        }
        assert_eq!(code, 1);
        assert!(stderr.contains("restored the original Codex configuration"));
        assert_eq!(
            std::fs::read_to_string(home.join("config.toml")).unwrap(),
            original
        );
        assert!(home.join("auth.json").exists());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn harden_codex_refuses_while_chatgpt_is_running() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let home =
            std::env::temp_dir().join(format!("av-cli-codex-chatgpt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join("auth.json"), "secret").unwrap();
        unsafe {
            std::env::set_var("CODEX_HOME", &home);
            std::env::set_var("AUTOMIC_VAULT_TEST_CHATGPT_RUNNING", "1");
        }

        let (code, stdout, stderr) = run_args(&["av", "harden", "codex", "--yes"]);

        unsafe {
            std::env::remove_var("CODEX_HOME");
            std::env::remove_var("AUTOMIC_VAULT_TEST_CHATGPT_RUNNING");
        }
        assert_eq!(code, 1);
        assert!(stdout.starts_with("╭─ harden codex"));
        assert!(stderr.contains("quit ChatGPT.app"));
        assert!(!home.join("config.toml").exists());
        assert!(home.join("auth.json").exists());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn private_env_wrapper_installer_rejects_unknown_targets() {
        let (code, stdout, stderr) = run_args(&[
            "av",
            "__install-env-wrapper",
            "definitely-not-a-hardener",
            "/nix/store/example/bin/tool",
        ]);

        assert_eq!(code, 1);
        assert_eq!(stdout, "");
        assert_eq!(stderr, "av: unknown hardener `definitely-not-a-hardener`\n");
    }

    #[test]
    fn private_brew_hardener_requires_root() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_EUID", "501") };

        let (code, stdout, stderr) = run_args(&["av", "__harden-brew"]);

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_EUID") };
        assert_eq!(code, 1);
        assert_eq!(stdout, "");
        assert_eq!(stderr, "av: Homebrew installation requires root\n");
    }

    #[test]
    fn private_env_wrapper_installer_requires_root() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_EUID", "501") };

        let (code, stdout, stderr) = run_args(&[
            "av",
            "__install-env-wrapper",
            "doctl",
            "/nix/store/example/bin/doctl",
        ]);

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_EUID") };
        assert_eq!(code, 1);
        assert_eq!(stdout, "");
        assert_eq!(stderr, "av: env-wrapper installation requires root\n");
    }

    #[test]
    fn private_env_wrapper_installer_rejects_test_path_overrides() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", "/tmp/stubs");
        }

        let (code, stdout, stderr) = run_args(&[
            "av",
            "__install-env-wrapper",
            "doctl",
            "/nix/store/example/bin/doctl",
        ]);

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR") };
        assert_eq!(code, 1);
        assert_eq!(stdout, "");
        assert_eq!(
            stderr,
            "av: test path overrides are forbidden during privileged installation\n"
        );
    }

    #[test]
    fn private_terraform_installer_rejects_test_path_overrides() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_TERRAFORM_INSTALL_DIR", "/tmp/terraform");
        }

        let (code, stdout, stderr) = run_args(&[
            "av",
            "__install-terraform-release",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "/tmp/terraform.zip",
        ]);

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_TERRAFORM_INSTALL_DIR") };
        assert_eq!(code, 1);
        assert_eq!(stdout, "");
        assert_eq!(
            stderr,
            "av: test path overrides are forbidden during privileged installation\n"
        );
    }

    #[test]
    fn only_scan_is_supported() {
        for args in [&["av"][..], &["av", "harden"], &["av", "scan", "--bad"]] {
            let (code, stdout, stderr) = run_args(args);
            assert_eq!(code, 2);
            assert_eq!(stdout, "");
            assert_eq!(stderr, format!("{USAGE}\n"));
        }
    }

    #[test]
    fn help_describes_commands_and_required_arguments() {
        for help in ["help", "--help"] {
            let (code, stdout, stderr) = run_args(&["av", help]);

            assert_eq!(code, 0);
            assert_eq!(stdout, format!("{USAGE}\n"));
            assert_eq!(stderr, "");
            assert!(stdout.contains("\ncommands:\n"));
            assert!(stdout.contains("$ av harden <tool> [-y|--yes]"));
            assert!(stdout.contains("$ av list"));
            assert!(stdout.contains("$ av open [--secret-gate <id>]"));
            assert!(stdout.contains("\nmodes:\n"));
            assert!(stdout.contains("$ av help"));
            assert!(!stdout.contains("__version"));
        }

        assert!(
            USAGE
                .lines()
                .filter_map(|line| line.find('#'))
                .all(|column| column == 42)
        );

        let mut stdout = Vec::new();
        write_help(&mut stdout, scan::Style { color: true });
        let stdout = String::from_utf8(stdout).unwrap();
        assert!(stdout.contains("  \x1b[2m$\x1b[0m av scan"));
        assert!(stdout.contains("\x1b[2m[\x1b[0m--show-all\x1b[2m|\x1b[0m--json\x1b[2m]\x1b[0m"));
        assert!(stdout.contains("\x1b[2m<\x1b[0mtool\x1b[2m>\x1b[0m"));
        assert!(stdout.contains("\x1b[2m# audit secrets and configuration\x1b[0m"));

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            run_with_style(
                ["av", "help"].map(OsString::from),
                &mut stdout,
                &mut stderr,
                scan::Style::plain(),
                scan::Style { color: true },
            ),
            0
        );
        assert!(stdout.windows(4).any(|bytes| bytes == b"\x1b[2m"));
        assert!(stderr.is_empty());
    }

    #[test]
    fn secret_gate_open_arguments_are_strictly_parsed() {
        assert_eq!(parse_open_args(&[]), Some(None));
        assert_eq!(
            parse_open_args(&[OsString::from("--secret-gate"), OsString::from("aws")]),
            Some(Some("aws".to_string()))
        );
        assert_eq!(
            parse_open_args(&[OsString::from("--secret-gate"), OsString::from("../aws")]),
            None
        );
        assert_eq!(parse_open_args(&[OsString::from("--secret-gate")]), None);
    }

    #[test]
    fn versions_are_reported_separately() {
        let (code, stdout, stderr) = run_args(&["av", "--version"]);
        assert_eq!(
            (code, stdout.as_str(), stderr.as_str()),
            (0, concat!("av ", env!("CARGO_PKG_VERSION"), "\n"), "")
        );

        let (code, stdout, stderr) = run_args(&["av", "__version"]);
        assert_eq!(
            (code, stdout, stderr),
            (0, format!("{INSTALL_REVISION}\n"), String::new())
        );
    }

    #[test]
    fn detectors_json_is_supported() {
        let (code, stdout, stderr) = run_args(&["av", "detectors", "--json"]);

        assert_eq!(code, 0);
        assert!(stdout.contains(r#""detectors":["#));
        assert_eq!(stderr, "");
    }

    #[test]
    fn private_secret_gate_catalog_is_supported() {
        let (code, stdout, stderr) = run_args(&["av", "__secret-gates-json"]);
        let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let gates = report["secret_gates"].as_array().unwrap();

        assert_eq!(code, 0);
        assert!(gates.iter().any(|gate| gate["id"] == "aws"));
        assert!(gates.iter().any(|gate| gate["id"] == "docker"));
        assert_eq!(stderr, "");
    }
}
