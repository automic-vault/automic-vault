use std::ffi::OsString;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{
    HardenerCommand, HardenerDetection, HardenerMetadata, RequiredExecutable, RequiredIdentity,
    SecretGateDescriptor, SecretGateRoute, StubRequirements,
};

const MARKER: &str = "AUTOMIC_VAULT_ENV_WRAPPER_STUB_V2";
const STUB_DIR: &str = "/usr/local/bin";
const AV_PATH: &str = "/usr/local/bin/av";
const SUDO_PATH: &str = "/usr/bin/sudo";
const PRIVILEGE_MODE: super::PrivilegeMode = super::PrivilegeMode::Mixed;
const DOCUMENTATION: &str = "# Environment Wrapper\n\nUses the target executable selected by your current `PATH`, shows its exact path for confirmation, and embeds that path in a launcher stub. Then it migrates supported existing credentials into Automic Vault and runs the target through `av inject --allow-missing-keys` with those secrets. Automic Vault requests elevation only to install the launcher stub. This does not protect the target executable; anything that can replace it can read the injected credentials. Run `av scan` after hardening to find unsupported credentials or secrets written later.\n";

unsafe extern "C" {
    fn geteuid() -> u32;
}

pub(crate) fn run_target(
    target: &str,
    stdout: &mut dyn Write,
    yes: bool,
) -> Option<Result<(), String>> {
    Some(run(wrapper(target)?, stdout, yes))
}

pub(crate) fn install_target(name: &str, targets: &[PathBuf]) -> Result<(), String> {
    let wrapper = wrapper(name).ok_or_else(|| format!("unknown hardener `{name}`"))?;
    if test_stub_dir().is_some() || test_target_dir().is_some() {
        return Err("test path overrides are forbidden during privileged installation".into());
    }
    if actual_uid() != 0 {
        return Err("env-wrapper installation requires root".into());
    }
    let resolved = supplied_targets(wrapper, targets)?;
    preflight(&resolved)?;
    for target in &resolved {
        install_stub(target.stub, &target.path)?;
    }
    Ok(())
}

pub(crate) fn metadata() -> Vec<HardenerMetadata> {
    WRAPPERS
        .iter()
        .map(|wrapper| HardenerMetadata {
            name: wrapper.name,
            documentation: DOCUMENTATION,
            detection: detect(wrapper),
            secret_gate: Some(secret_gate(wrapper)),
        })
        .collect()
}

pub(crate) fn secret_gates() -> Vec<SecretGateDescriptor> {
    WRAPPERS.iter().map(secret_gate).collect()
}

pub(crate) fn invocation_is_secretless(
    script_path: &Path,
    script_data: &[u8],
    args: &[OsString],
) -> bool {
    let Some(stub) = WRAPPERS
        .iter()
        .flat_map(stubs)
        .find(|stub| same_path(script_path, &stub_path(stub.command)))
    else {
        return false;
    };
    let Ok(contents) = std::str::from_utf8(script_data) else {
        return false;
    };
    let Some(target) = embedded_target_from_contents(contents) else {
        return false;
    };
    if contents != stub_script(stub, &target) {
        return false;
    }
    let Some(script) = args.first() else {
        return false;
    };
    if !same_path(Path::new(script), script_path) {
        return false;
    }
    let args = &args[1..];
    match stub.command {
        "npm" => npm_invocation_is_secretless(args),
        "pnpm" => pnpm_invocation_is_secretless(args),
        "fly" | "flyctl" => local_command(args, &["completion", "help", "version"]),
        "k6" => k6_invocation_is_secretless(args),
        "twine" => twine_invocation_is_secretless(args),
        "vagrant" => vagrant_invocation_is_secretless(args),
        "hf" => hf_invocation_is_secretless(args),
        "composer" => composer_invocation_is_secretless(args),
        _ => false,
    }
}

fn local_command(args: &[OsString], commands: &[&str]) -> bool {
    args.is_empty()
        || args.iter().any(|arg| arg == "--help" || arg == "-h")
        || args.len() == 1
            && args
                .first()
                .is_some_and(|arg| arg == "--version" || arg == "-V" || arg == "-v")
        || args.first().is_some_and(|arg| {
            arg.to_str()
                .is_some_and(|command| commands.contains(&command))
        })
}

fn npm_invocation_is_secretless(args: &[OsString]) -> bool {
    let Some(command) = args.first().and_then(|arg| arg.to_str()) else {
        return true;
    };
    // Keep this positive list exact: npm's dynamic abbreviations can change
    // meaning when npm adds commands, and arbitrary package scripts must not
    // inherit NODE_AUTH_TOKEN merely because npm launched them.
    !matches!(
        command,
        "access"
            | "audit"
            | "ci"
            | "clean-install"
            | "ic"
            | "install-clean"
            | "isntall-clean"
            | "deprecate"
            | "diff"
            | "dist-tag"
            | "dist-tags"
            | "doctor"
            | "install"
            | "add"
            | "i"
            | "in"
            | "ins"
            | "inst"
            | "insta"
            | "instal"
            | "isnt"
            | "isnta"
            | "isntal"
            | "isntall"
            | "install-ci-test"
            | "cit"
            | "clean-install-test"
            | "sit"
            | "install-test"
            | "it"
            | "logout"
            | "org"
            | "ogr"
            | "outdated"
            | "owner"
            | "author"
            | "ping"
            | "profile"
            | "publish"
            | "search"
            | "find"
            | "s"
            | "se"
            | "stage"
            | "star"
            | "stars"
            | "team"
            | "token"
            | "trust"
            | "undeprecate"
            | "unpublish"
            | "unstar"
            | "update"
            | "u"
            | "up"
            | "upgrade"
            | "udpate"
            | "view"
            | "info"
            | "show"
            | "v"
            | "whoami"
    )
}

fn pnpm_invocation_is_secretless(args: &[OsString]) -> bool {
    let Some(command) = args.first().and_then(|arg| arg.to_str()) else {
        return true;
    };
    // Keep this positive list exact. Unknown commands and commands whose
    // purpose is arbitrary package or project code must not inherit
    // NODE_AUTH_TOKEN.
    !matches!(
        command,
        "access"
            | "add"
            | "audit"
            | "ci"
            | "clean-install"
            | "dedupe"
            | "deprecate"
            | "dist-tag"
            | "dist-tags"
            | "fetch"
            | "find"
            | "i"
            | "ic"
            | "info"
            | "install"
            | "install-clean"
            | "logout"
            | "outdated"
            | "owner"
            | "owners"
            | "ping"
            | "publish"
            | "s"
            | "se"
            | "search"
            | "show"
            | "stage"
            | "star"
            | "stars"
            | "team"
            | "undeprecate"
            | "unpublish"
            | "unstar"
            | "up"
            | "update"
            | "upgrade"
            | "v"
            | "view"
            | "whoami"
    ) && !(command == "store" && args.get(1).is_some_and(|arg| arg == "add"))
        && !(command == "config"
            && args.get(1).is_some_and(|arg| arg == "get")
            && args.iter().skip(2).any(|arg| {
                arg.to_str().is_some_and(|arg| {
                    let key = arg.to_ascii_lowercase();
                    key == "_authtoken" || key.ends_with(":_authtoken")
                })
            }))
}

fn k6_invocation_is_secretless(args: &[OsString]) -> bool {
    // Only explicit cloud operations receive the token. Config, environment,
    // extension, and future-command ambiguity must not expose it to scripts.
    if args
        .iter()
        .any(|arg| arg == "--help" || arg == "-h" || arg == "--version")
    {
        return true;
    }
    let Some(command) = k6_command_index(args, 0) else {
        return true;
    };
    match args[command].to_str() {
        Some("cloud") => {
            let Some(subcommand) = k6_command_index(args, command + 1) else {
                return true;
            };
            match args[subcommand].to_str() {
                Some("run" | "upload") => false,
                Some("project" | "load-zone" | "test") => {
                    k6_command_index(args, subcommand + 1).and_then(|index| args[index].to_str())
                        != Some("list")
                }
                _ => true,
            }
        }
        Some("run") => !k6_run_uses_cloud_output(&args[command + 1..]),
        _ => true,
    }
}

fn k6_command_index(args: &[OsString], mut index: usize) -> Option<usize> {
    while let Some(arg) = args.get(index).and_then(|arg| arg.to_str()) {
        if matches!(
            arg,
            "--no-color"
                | "--log-ns-timestamps"
                | "--verbose"
                | "-v"
                | "--quiet"
                | "-q"
                | "--profiling-enabled"
        ) {
            index += 1;
        } else if matches!(
            arg,
            "--secret-source"
                | "--log-output"
                | "--log-format"
                | "--config"
                | "-c"
                | "--address"
                | "-a"
        ) {
            args.get(index + 1)?;
            index += 2;
        } else if [
            "--secret-source=",
            "--log-output=",
            "--log-format=",
            "--config=",
            "--address=",
        ]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
            || [
                "--no-color=",
                "--log-ns-timestamps=",
                "--verbose=",
                "--quiet=",
                "--profiling-enabled=",
            ]
            .iter()
            .any(|prefix| arg.starts_with(prefix))
            || (arg.starts_with("-c") || arg.starts_with("-a")) && arg.len() > 2
        {
            index += 1;
        } else if arg.starts_with('-') {
            return None;
        } else {
            return Some(index);
        }
    }
    None
}

fn k6_run_uses_cloud_output(args: &[OsString]) -> bool {
    let mut index = 0;
    while let Some(arg) = args.get(index).and_then(|arg| arg.to_str()) {
        if arg == "--" {
            return false;
        }
        if arg == "--out" || arg == "-o" {
            if args
                .get(index + 1)
                .and_then(|value| value.to_str())
                .is_some_and(k6_cloud_output)
            {
                return true;
            }
            index += 2;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--out=") {
            if k6_cloud_output(value) {
                return true;
            }
        } else if let Some(value) = arg.strip_prefix("-o") {
            if k6_cloud_output(value.strip_prefix('=').unwrap_or(value)) {
                return true;
            }
        }
        index += 1;
    }
    false
}

fn k6_cloud_output(value: &str) -> bool {
    value == "cloud" || value.starts_with("cloud=")
}

fn twine_invocation_is_secretless(args: &[OsString]) -> bool {
    if args
        .iter()
        .any(|arg| arg == "--help" || arg == "-h" || arg == "--version")
    {
        return true;
    }
    let mut args = args.iter().skip_while(|arg| *arg == "--no-color");
    let command = args.next();
    let command = if command.is_some_and(|arg| arg == "--") {
        args.next()
    } else {
        command
    };
    command.is_none_or(|command| command != "upload")
}

fn vagrant_invocation_is_secretless(args: &[OsString]) -> bool {
    let Some(args) = args
        .iter()
        .map(|arg| arg.to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return true;
    };
    !vagrant_invocation_may_need_secret(&args)
}

fn vagrant_invocation_may_need_secret(args: &[&str]) -> bool {
    let separator = args
        .iter()
        .position(|arg| *arg == "--")
        .unwrap_or(args.len());
    if args[..separator]
        .iter()
        .any(|arg| matches!(*arg, "--help" | "-h" | "--version" | "-v"))
    {
        return false;
    }

    // Vagrant removes these flags before dispatch, wherever they occur before `--`.
    let args = args
        .iter()
        .enumerate()
        .filter_map(|(index, arg)| {
            (!(index < separator
                && matches!(
                    *arg,
                    "--color"
                        | "--no-color"
                        | "--machine-readable"
                        | "--debug"
                        | "--timestamp"
                        | "--debug-timestamp"
                        | "--no-tty"
                )))
            .then_some(*arg)
        })
        .collect::<Vec<_>>();
    let Some((command, args)) = vagrant_subcommand(&args) else {
        return false;
    };

    match command {
        "box" => vagrant_box_may_need_secret(args),
        "cloud" => vagrant_cloud_may_need_secret(args),
        "login" => vagrant_login_may_need_secret(args),
        "up" | "reload" | "resume" => true,
        "snapshot" => vagrant_subcommand(args).is_some_and(|(command, args)| {
            matches!(command, "restore" | "pop")
                && !args
                    .iter()
                    .take_while(|arg| **arg != "--")
                    .any(|arg| *arg == "--no-start")
        }),
        _ => false,
    }
}

fn vagrant_subcommand<'a>(args: &'a [&'a str]) -> Option<(&'a str, &'a [&'a str])> {
    let index = args.iter().position(|arg| !arg.starts_with('-'))?;
    Some((args[index], &args[index + 1..]))
}

fn vagrant_login_may_need_secret(args: &[&str]) -> bool {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index];
        if arg == "--" {
            return index + 1 == args.len();
        } else if arg == "-c" || arg == "--check" {
            index += 1;
        } else if matches!(arg, "-d" | "--description" | "-u" | "--username") {
            if index + 1 >= args.len() {
                return false;
            }
            index += 2;
        } else if matches!(arg, "-t" | "--token")
            || arg.starts_with("--token=")
            || arg.starts_with("-t") && !arg.starts_with("--") && arg.len() > 2
        {
            return false;
        } else if arg.starts_with("--description=")
            || arg.starts_with("--username=")
            || (arg.starts_with("-d") || arg.starts_with("-u"))
                && !arg.starts_with("--")
                && arg.len() > 2
        {
            index += 1;
        } else {
            return false;
        }
    }
    true
}

fn vagrant_whoami_may_need_secret(args: &[&str]) -> bool {
    let mut positionals = 0;
    let mut after_separator = false;
    for arg in args {
        if *arg == "--" && !after_separator {
            after_separator = true;
        } else if !after_separator && arg.starts_with('-') {
            return false;
        } else {
            positionals += 1;
        }
    }
    positionals == 0
}

fn vagrant_box_may_need_secret(args: &[&str]) -> bool {
    let Some((command, args)) = vagrant_subcommand(args) else {
        return false;
    };
    match command {
        "add" => vagrant_box_add_may_need_secret(args),
        "outdated" | "update" => true,
        _ => false,
    }
}

fn vagrant_box_add_may_need_secret(args: &[&str]) -> bool {
    const VALUE_OPTIONS: &[&str] = &[
        "-a",
        "--architecture",
        "--provider",
        "--box-version",
        "--checksum",
        "--checksum-type",
        "--name",
        "--cacert",
        "--capath",
        "--cert",
    ];
    const FLAG_OPTIONS: &[&str] = &[
        "-c",
        "--clean",
        "-f",
        "--force",
        "--insecure",
        "--location-trusted",
    ];

    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index];
        if arg == "--" {
            positionals.extend_from_slice(&args[index + 1..]);
            break;
        } else if VALUE_OPTIONS.contains(&arg) {
            if index + 1 >= args.len() {
                return false;
            }
            index += 2;
        } else if VALUE_OPTIONS.iter().any(|option| {
            arg.strip_prefix(option)
                .is_some_and(|rest| rest.starts_with('='))
        }) || arg.starts_with("-a") && !arg.starts_with("--") && arg.len() > 2
        {
            index += 1;
        } else if FLAG_OPTIONS.contains(&arg) {
            index += 1;
        } else if arg.starts_with('-') {
            return false;
        } else {
            positionals.push(arg);
            index += 1;
        }
    }

    let target = match positionals.as_slice() {
        [target] | [_, target] => *target,
        _ => return false,
    };
    if target.starts_with('/')
        || target.starts_with("./")
        || target.starts_with("../")
        || target.starts_with("~/")
        || !target.contains('/') && (target.ends_with(".box") || target.ends_with(".json"))
    {
        return false;
    }
    let Ok(target) = url::Url::parse(target) else {
        return true;
    };
    if target.scheme() == "file" {
        return false;
    }
    let Some(host) = target.host_str() else {
        return false;
    };
    if matches!(
        host,
        "vagrantcloud.com" | "app.vagrantup.com" | "atlas.hashicorp.com"
    ) {
        return true;
    }
    std::env::var("VAGRANT_SERVER_URL")
        .ok()
        .and_then(|server| url::Url::parse(&server).ok())
        .and_then(|server| server.host_str().map(str::to_owned))
        .is_some_and(|server| server == host)
}

fn vagrant_cloud_may_need_secret(args: &[&str]) -> bool {
    let Some((command, args)) = vagrant_subcommand(args) else {
        return false;
    };
    match command {
        "auth" => vagrant_subcommand(args).is_some_and(|(command, args)| match command {
            "login" => vagrant_login_may_need_secret(args),
            "whoami" => vagrant_whoami_may_need_secret(args),
            _ => false,
        }),
        "box" => vagrant_subcommand(args)
            .is_some_and(|(command, _)| matches!(command, "create" | "delete" | "show" | "update")),
        "provider" => vagrant_subcommand(args).is_some_and(|(command, _)| {
            matches!(command, "create" | "delete" | "update" | "upload")
        }),
        "publish" | "search" => true,
        "version" => vagrant_subcommand(args).is_some_and(|(command, _)| {
            matches!(
                command,
                "create" | "delete" | "release" | "revoke" | "update"
            )
        }),
        _ => false,
    }
}

fn hf_invocation_is_secretless(args: &[OsString]) -> bool {
    let Some(args) = args
        .iter()
        .map(|arg| arg.to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return true;
    };
    !hf_invocation_may_need_secret(&args)
}

fn hf_invocation_may_need_secret(args: &[&str]) -> bool {
    let args = &args[..args
        .iter()
        .position(|arg| *arg == "--")
        .unwrap_or(args.len())];
    let Some(command) = args.first().copied() else {
        return false;
    };
    if command.starts_with('-')
        || args.contains(&"--help")
        || args.contains(&"--token")
        || args.iter().any(|arg| arg.starts_with("--token="))
    {
        return false;
    }
    let subcommand = args.get(1).copied().unwrap_or_default();
    if args.contains(&"-h")
        && !matches!(
            (command, subcommand),
            ("datasets" | "models" | "spaces", "list" | "ls")
        )
    {
        return false;
    }

    // Reviewed against huggingface_hub c804cddf. Only first-party commands
    // that can consume HF_TOKEN belong here; extensions and future commands
    // remain tokenless until their credential boundary is reviewed.
    match command {
        "cp" | "download" | "sync" | "upload" | "upload-large-folder" => !subcommand.is_empty(),
        "env" => true,
        "auth" => matches!(subcommand, "token" | "whoami"),
        "cache" => subcommand == "verify",
        "buckets" => matches!(
            subcommand,
            "cp" | "create"
                | "list"
                | "ls"
                | "info"
                | "delete"
                | "remove"
                | "rm"
                | "move"
                | "settings"
                | "sync"
        ),
        "collections" => matches!(
            subcommand,
            "list"
                | "ls"
                | "info"
                | "create"
                | "update"
                | "delete"
                | "add-item"
                | "update-item"
                | "delete-item"
        ),
        "datasets" => matches!(
            subcommand,
            "list" | "ls" | "leaderboard" | "info" | "parquet" | "sql" | "card"
        ),
        "discussions" => matches!(
            subcommand,
            "list"
                | "ls"
                | "info"
                | "create"
                | "comment"
                | "edit"
                | "close"
                | "reopen"
                | "rename"
                | "merge"
                | "diff"
        ),
        "models" => matches!(subcommand, "list" | "ls" | "info" | "card"),
        "papers" => matches!(subcommand, "list" | "ls" | "search" | "info" | "read"),
        "repo" | "repos" => hf_repo_invocation_may_need_secret(&args[1..]),
        "repo-files" => subcommand == "delete",
        "jobs" => hf_jobs_invocation_may_need_secret(&args[1..]),
        "sandbox" => hf_sandbox_invocation_may_need_secret(&args[1..]),
        "spaces" => hf_spaces_invocation_may_need_secret(&args[1..]),
        "webhooks" => matches!(
            subcommand,
            "list" | "ls" | "info" | "create" | "update" | "enable" | "disable" | "delete"
        ),
        "endpoints" => match subcommand {
            "list" | "ls" | "hardware" | "deploy" | "describe" | "update" | "delete" | "pause"
            | "resume" | "scale-to-zero" | "list-catalog" => true,
            "catalog" => matches!(args.get(2), Some(&"deploy" | &"list" | &"ls")),
            _ => false,
        },
        _ => false,
    }
}

fn hf_repo_invocation_may_need_secret(args: &[&str]) -> bool {
    match args.first().copied().unwrap_or_default() {
        "cp" | "list" | "ls" | "create" | "duplicate" | "delete" | "move" | "settings"
        | "delete-files" => true,
        "branch" => matches!(args.get(1), Some(&"create" | &"delete")),
        "tag" => matches!(args.get(1), Some(&"create" | &"list" | &"ls" | &"delete")),
        _ => false,
    }
}

fn hf_jobs_invocation_may_need_secret(args: &[&str]) -> bool {
    match args.first().copied().unwrap_or_default() {
        "run" | "logs" | "stats" | "list" | "ls" | "ps" | "hardware" | "inspect" | "cancel"
        | "wait" | "labels" | "ssh" => true,
        "uv" => args.get(1) == Some(&"run"),
        "scheduled" => match args.get(1).copied().unwrap_or_default() {
            "run" | "list" | "ls" | "ps" | "inspect" | "delete" | "suspend" | "resume"
            | "trigger" | "labels" => true,
            "uv" => args.get(2) == Some(&"run"),
            _ => false,
        },
        _ => false,
    }
}

fn hf_sandbox_invocation_may_need_secret(args: &[&str]) -> bool {
    match args.first().copied().unwrap_or_default() {
        "create" | "exec" | "spawn" | "cp" | "kill" => true,
        "pool" => matches!(
            args.get(1),
            Some(&"create" | &"ls" | &"list" | &"delete" | &"rm")
        ),
        "process" => matches!(args.get(1), Some(&"ls" | &"list" | &"kill")),
        _ => false,
    }
}

fn hf_spaces_invocation_may_need_secret(args: &[&str]) -> bool {
    match args.first().copied().unwrap_or_default() {
        "list" | "ls" | "info" | "card" | "templates" | "search" | "wait" | "dev-mode" | "ssh"
        | "pause" | "restart" | "hardware" | "settings" | "logs" | "hot-reload" => true,
        "volumes" => matches!(args.get(1), Some(&"list" | &"ls" | &"set" | &"delete")),
        "secrets" | "variables" => {
            matches!(args.get(1), Some(&"list" | &"ls" | &"add" | &"delete"))
        }
        _ => false,
    }
}

const COMPOSER_COMMANDS: &[(&str, &[&str])] = &[
    ("about", &["about"]),
    ("archive", &["archive"]),
    ("audit", &["audit"]),
    ("browse", &["browse", "home"]),
    ("bump", &["bump"]),
    ("check-platform-reqs", &["check-platform-reqs"]),
    ("clear-cache", &["clear-cache", "clearcache", "cc"]),
    ("completion", &["completion", "_complete"]),
    ("config", &["config"]),
    ("create-project", &["create-project"]),
    ("depends", &["depends", "why"]),
    ("diagnose", &["diagnose"]),
    ("dump-autoload", &["dump-autoload", "dumpautoload"]),
    ("exec", &["exec"]),
    ("fund", &["fund"]),
    ("global", &["global"]),
    ("help", &["help"]),
    ("init", &["init"]),
    ("install", &["install", "i"]),
    ("licenses", &["licenses"]),
    ("list", &["list"]),
    ("outdated", &["outdated"]),
    ("policy", &["policy"]),
    ("prohibits", &["prohibits", "why-not"]),
    ("reinstall", &["reinstall"]),
    ("remove", &["remove", "rm", "uninstall"]),
    ("repository", &["repository", "repo"]),
    ("require", &["require", "r"]),
    ("run-script", &["run-script", "run"]),
    ("search", &["search"]),
    ("self-update", &["self-update", "selfupdate"]),
    ("show", &["show", "info"]),
    ("status", &["status"]),
    ("suggests", &["suggests"]),
    ("update", &["update", "u", "upgrade"]),
    ("validate", &["validate"]),
];

fn composer_invocation_is_secretless(args: &[OsString]) -> bool {
    let Some(args) = args
        .iter()
        .map(|arg| arg.to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return true;
    };
    !composer_invocation_may_need_secret(&args)
}

fn composer_invocation_may_need_secret(args: &[&str]) -> bool {
    composer_invocation_may_need_secret_with_options(args, false)
}

fn composer_invocation_may_need_secret_with_options(
    args: &[&str],
    inherited_non_interactive: bool,
) -> bool {
    let option_end = args
        .iter()
        .position(|arg| *arg == "--")
        .unwrap_or(args.len());
    let option_args = &args[..option_end];
    if option_args
        .iter()
        .any(|arg| matches!(*arg, "--help" | "-h" | "--version" | "-V"))
    {
        return false;
    }
    let non_interactive = inherited_non_interactive
        || option_args
            .iter()
            .any(|arg| matches!(*arg, "--no-interaction" | "-n"));
    let Some((command, args)) = composer_command_and_args(args) else {
        return false;
    };
    let network_enabled = std::env::var_os("COMPOSER_DISABLE_NETWORK")
        .is_none_or(|value| value.is_empty() || value == "0");

    // Reviewed against Composer 85ae025. Script aliases, plugin commands,
    // vendored binaries, and future commands stay tokenless so arbitrary code
    // never inherits COMPOSER_AUTH merely because Composer launched it.
    match command {
        "install" | "create-project" | "update" | "search" | "audit" | "reinstall" | "outdated"
        | "fund" | "diagnose" | "prohibits" => network_enabled,
        "require" => composer_require_may_need_secret(args, non_interactive, network_enabled),
        "remove" => network_enabled && !args.contains(&"--no-update"),
        "archive" | "browse" => network_enabled && composer_has_positional(args),
        "config" => composer_config_reads_auth(args),
        "global" => composer_invocation_may_need_secret_with_options(args, non_interactive),
        "init" => {
            network_enabled
                && !non_interactive
                && args
                    .iter()
                    .any(|arg| *arg == "--repository" || arg.starts_with("--repository="))
        }
        "show" => {
            network_enabled
                && args[..args
                    .iter()
                    .position(|arg| *arg == "--")
                    .unwrap_or(args.len())]
                    .iter()
                    .any(|arg| {
                        matches!(
                            *arg,
                            "--all"
                                | "--available"
                                | "-a"
                                | "--latest"
                                | "-l"
                                | "--outdated"
                                | "-o"
                        )
                    })
        }
        _ => false,
    }
}

fn composer_command_and_args<'a>(args: &'a [&'a str]) -> Option<(&'static str, &'a [&'a str])> {
    let mut index = 0;
    while let Some(argument) = args.get(index).copied() {
        if matches!(
            argument,
            "--profile"
                | "--no-plugins"
                | "--no-scripts"
                | "--no-cache"
                | "--quiet"
                | "-q"
                | "--verbose"
                | "-v"
                | "-vv"
                | "-vvv"
                | "--ansi"
                | "--no-ansi"
                | "--no-interaction"
                | "-n"
        ) {
            index += 1;
        } else if matches!(argument, "--working-dir" | "-d") {
            index += 2;
        } else if argument.starts_with("--working-dir=")
            || (argument.starts_with("-d") && argument.len() > 2)
        {
            index += 1;
        } else if argument.starts_with('-') {
            return None;
        } else {
            return composer_command(argument).map(|command| (command, &args[index + 1..]));
        }
    }
    None
}

fn composer_command(argument: &str) -> Option<&'static str> {
    if let Some((command, _)) = COMPOSER_COMMANDS
        .iter()
        .find(|(_, aliases)| aliases.contains(&argument))
    {
        return Some(command);
    }
    let mut matches = COMPOSER_COMMANDS
        .iter()
        .filter(|(_, aliases)| aliases.iter().any(|alias| alias.starts_with(argument)))
        .map(|(command, _)| *command);
    let command = matches.next()?;
    matches
        .all(|candidate| candidate == command)
        .then_some(command)
}

fn composer_has_positional(args: &[&str]) -> bool {
    !composer_positionals(
        args,
        &["--working-dir", "-d", "--format", "-f", "--dir", "--file"],
    )
    .is_empty()
}

fn composer_positionals<'a>(args: &[&'a str], options_with_values: &[&str]) -> Vec<&'a str> {
    let mut positionals = Vec::new();
    let mut skip_value = false;
    let mut options_ended = false;
    for argument in args {
        if skip_value {
            skip_value = false;
        } else if *argument == "--" {
            options_ended = true;
        } else if options_with_values.contains(argument) {
            skip_value = true;
        } else if options_ended || !argument.starts_with('-') {
            positionals.push(*argument);
        }
    }
    positionals
}

fn composer_require_may_need_secret(
    args: &[&str],
    non_interactive: bool,
    network_enabled: bool,
) -> bool {
    if !network_enabled {
        return false;
    }
    if !args.contains(&"--no-update") || !non_interactive {
        return true;
    }
    composer_positionals(
        args,
        &[
            "--working-dir",
            "-d",
            "--prefer-install",
            "--audit-format",
            "--ignore-platform-req",
            "--apcu-autoloader-prefix",
        ],
    )
    .iter()
    .any(|package| !package.contains(':') && !package.contains('=') && !package.contains(' '))
}

fn composer_config_reads_auth(args: &[&str]) -> bool {
    if args.iter().any(|arg| matches!(*arg, "--list" | "-l")) {
        return true;
    }
    if args
        .iter()
        .any(|arg| matches!(*arg, "--editor" | "-e" | "--unset"))
    {
        return false;
    }
    let positionals = composer_positionals(args, &["--working-dir", "-d", "--file", "-f"]);
    positionals.len() == 1
        && matches!(
            positionals[0].split('.').next(),
            Some(
                "bitbucket-oauth"
                    | "github-oauth"
                    | "gitlab-oauth"
                    | "gitlab-token"
                    | "http-basic"
                    | "custom-headers"
                    | "bearer"
                    | "client-certificate"
                    | "forgejo-token"
            )
        )
}

fn secret_gate(wrapper: &EnvWrapper) -> SecretGateDescriptor {
    let routes = stubs(wrapper)
        .map(|stub| SecretGateRoute {
            operation: "inject",
            script_path: Some(stub_path(stub.command).display().to_string()),
            target_path: "/bin/sh".to_string(),
            caller_identifiers: vec!["com.automicvault.av"],
            key_patterns: stub.keys.iter().map(|key| (*key).to_string()).collect(),
            replace_existing_env: false,
            allow_missing_keys: true,
        })
        .collect::<Vec<_>>();
    let mut key_patterns = routes
        .iter()
        .flat_map(|route| route.key_patterns.iter().cloned())
        .collect::<Vec<_>>();
    key_patterns.sort();
    key_patterns.dedup();
    SecretGateDescriptor {
        id: wrapper.name,
        key_patterns,
        routes,
    }
}

fn run(wrapper: &EnvWrapper, stdout: &mut dyn Write, yes: bool) -> Result<(), String> {
    PRIVILEGE_MODE.require_user(wrapper.name, test_stub_dir().is_some())?;
    let targets = resolve_targets(wrapper)?;
    preflight(&targets)?;

    writeln!(stdout, "╭─ harden {}", wrapper.name).ok();
    writeln!(stdout, "│").ok();
    for target in &targets {
        writeln!(stdout, "├─ target {}", target.path.display()).ok();
        writeln!(
            stdout,
            "├─ install launcher {}",
            stub_path(target.stub.command).display()
        )
        .ok();
    }
    writeln!(stdout, "│").ok();
    if !confirm(stdout, yes)? {
        writeln!(stdout, "╰─ cancelled").ok();
        return Ok(());
    }

    install_privileged(wrapper, &targets)?;
    writeln!(stdout, "├─ migrate existing credentials").ok();
    super::migrations::run(wrapper.name)
        .ok_or_else(|| format!("no credential migration registered for {}", wrapper.name))??;
    writeln!(stdout, "╰─ hardened {}", wrapper.name).ok();
    super::write_secret_gate_notice(stdout, wrapper.name);
    writeln!(stdout, "◇ next: run `hash -r`").ok();
    Ok(())
}

fn preflight(targets: &[ResolvedStub<'_>]) -> Result<(), String> {
    for target in targets {
        if !valid_target_path(&target.path, target.stub.command) {
            return Err(format!(
                "invalid target for {}: {}",
                target.stub.command,
                target.path.display()
            ));
        }
        if !super::executable(&target.path) {
            return Err(format!(
                "{} is not an executable file: {}",
                target.stub.command,
                target.path.display()
            ));
        }
        let stub_path = stub_path(target.stub.command);
        if stub_path.exists() && !is_managed_stub(&stub_path, target.stub) {
            return Err(format!(
                "{} already exists and is not an Automic Vault env-wrapper stub",
                stub_path.display()
            ));
        }
    }
    Ok(())
}

fn install_privileged(wrapper: &EnvWrapper, targets: &[ResolvedStub<'_>]) -> Result<(), String> {
    if test_stub_dir().is_some() {
        for target in targets {
            install_stub(target.stub, &target.path)?;
        }
        return Ok(());
    }
    validate_privileged_av(Path::new(AV_PATH))?;
    let mut command = Command::new(SUDO_PATH);
    command
        .args([AV_PATH, "__install-env-wrapper", wrapper.name])
        .args(targets.iter().map(|target| &target.path));
    let status = command
        .status()
        .map_err(|err| format!("failed to run sudo: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("launcher installation failed: {status}"))
    }
}

pub(crate) fn validate_privileged_av(path: &Path) -> Result<(), String> {
    for trusted in path.ancestors() {
        let metadata = trusted
            .metadata()
            .map_err(|err| format!("cannot trust {}: {err}", trusted.display()))?;
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            return Err(format!(
                "refusing to elevate {} because it is not root-owned and protected from group/world writes",
                trusted.display()
            ));
        }
    }
    if !super::executable(path) {
        return Err(format!(
            "refusing to elevate non-executable {}",
            path.display()
        ));
    }
    Ok(())
}

fn detect(wrapper: &EnvWrapper) -> HardenerDetection {
    let commands = stubs(wrapper)
        .map(|stub| {
            let path = stub_path(stub.command);
            let target = embedded_target(&path).or_else(|| find_target_on_path(stub.command));
            let stub_valid = target.as_deref().is_some_and(|target| {
                super::executable(target) && is_current_stub(&path, stub, target)
            });
            HardenerCommand {
                name: stub.command.to_string(),
                hardened: stub_valid,
                stub_valid,
                stub_path: Some(path.display().to_string()),
                target_path: target
                    .unwrap_or_else(|| PathBuf::from(stub.command))
                    .display()
                    .to_string(),
                required_paths: if test_stub_dir().is_some() {
                    Vec::new()
                } else {
                    vec![
                        RequiredExecutable {
                            name: "Automic Vault CLI",
                            path: "/usr/local/bin/av".to_string(),
                        },
                        RequiredExecutable {
                            name: "POSIX shell",
                            path: "/bin/sh".to_string(),
                        },
                    ]
                },
                stub_requirements: Some(root_stub_requirements(&path)),
                injected_keys: stub.keys.iter().map(|key| (*key).to_string()).collect(),
                assignment_keys: stub
                    .assignment_keys
                    .iter()
                    .map(|key| (*key).to_string())
                    .collect(),
                isotope: None,
            }
        })
        .collect::<Vec<_>>();
    let hardened = commands.iter().all(|command| command.hardened);
    HardenerDetection::commands(hardened, commands)
}

fn root_stub_requirements(path: &Path) -> StubRequirements {
    let test_ids = test_stub_dir().and_then(|_| {
        path.parent()
            .and_then(|parent| parent.metadata().ok())
            .map(|metadata| (metadata.uid(), metadata.gid()))
    });
    let (uid, gid) = test_ids.unwrap_or((0, 0));
    StubRequirements {
        mode: 0o755,
        owner: RequiredIdentity {
            name: if test_ids.is_some() {
                "test user"
            } else {
                "root"
            },
            id: Some(uid),
        },
        group: RequiredIdentity {
            name: if test_ids.is_some() {
                "test group"
            } else {
                "wheel"
            },
            id: Some(gid),
        },
    }
}

fn confirm(stdout: &mut dyn Write, yes: bool) -> Result<bool, String> {
    if yes {
        writeln!(stdout, "◇ Use these targets? yes (--yes)").ok();
        return Ok(true);
    }

    write!(stdout, "◇ Use these targets? [y/N] ").ok();
    stdout
        .flush()
        .map_err(|err| format!("failed to flush prompt: {err}"))?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|err| format!("failed to read confirmation: {err}"))?;
    if !io::stdin().is_terminal() {
        writeln!(stdout).ok();
    }
    Ok(matches!(
        input.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn install_stub(stub: &StubSpec, target: &Path) -> Result<(), String> {
    let path = stub_path(stub.command);
    fs::write(&path, stub_script(stub, target))
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
        .map_err(|err| format!("failed to chmod {}: {err}", path.display()))
}

fn is_managed_stub(path: &Path, stub: &StubSpec) -> bool {
    let Ok(contents) = fs::read_to_string(path) else {
        return false;
    };
    let Some(target) = embedded_target_from_contents(&contents) else {
        return false;
    };
    contents == stub_script(stub, &target)
}

fn is_current_stub(path: &Path, stub: &StubSpec, target: &Path) -> bool {
    fs::read_to_string(path).is_ok_and(|contents| contents == stub_script(stub, target))
}

fn stub_script(stub: &StubSpec, target: &Path) -> String {
    let keys = stub
        .keys
        .iter()
        .map(|key| format!(" +{key}"))
        .collect::<String>();
    let mut script = format!(
        "#!/usr/local/bin/av inject --allow-missing-keys{keys} /bin/sh\n\
set -eu\n\
# {MARKER}\n\
original='{}'\n",
        shell_single_argument(target)
    );
    for key in stub.assignment_keys {
        script.push_str(&format!(
            "if [ -n \"${{{key}:-}}\" ]; then\n  old_ifs=\"$IFS\"\n  IFS='\n'\n  for assignment in ${{{key}-}}; do\n    [ -n \"$assignment\" ] || continue\n    export \"$assignment\"\n  done\n  IFS=\"$old_ifs\"\nfi\n"
        ));
    }
    script.push_str("exec \"$original\" \"$@\"\n");
    script
}

fn shell_single_argument(path: &Path) -> String {
    path.to_string_lossy().replace('\'', r#"'\''"#)
}

fn embedded_target(path: &Path) -> Option<PathBuf> {
    embedded_target_from_contents(&fs::read_to_string(path).ok()?)
}

fn embedded_target_from_contents(contents: &str) -> Option<PathBuf> {
    if !contents.lines().any(|line| line == format!("# {MARKER}")) {
        return None;
    }
    contents
        .lines()
        .find_map(|line| line.strip_prefix("original='")?.strip_suffix('\''))
        .map(PathBuf::from)
}

fn wrapper(name: &str) -> Option<&'static EnvWrapper> {
    let name = if name == "npm" { "node" } else { name };
    WRAPPERS.iter().find(|wrapper| wrapper.name == name)
}

fn resolve_targets(wrapper: &EnvWrapper) -> Result<Vec<ResolvedStub<'_>>, String> {
    stubs(wrapper)
        .map(|stub| find_target(stub).map(|path| ResolvedStub { stub, path }))
        .collect()
}

fn supplied_targets<'a>(
    wrapper: &'a EnvWrapper,
    targets: &[PathBuf],
) -> Result<Vec<ResolvedStub<'a>>, String> {
    if targets.len() != stubs(wrapper).count() {
        return Err(format!("invalid target count for {}", wrapper.name));
    }
    stubs(wrapper)
        .zip(targets)
        .map(|(stub, path)| {
            if !valid_target_path(path, stub.command) {
                return Err(format!(
                    "invalid target for {}: {}",
                    stub.command,
                    path.display()
                ));
            }
            if same_path(path, &stub_path(stub.command)) {
                return Err(format!(
                    "{} target cannot be its launcher stub",
                    stub.command
                ));
            }
            Ok(ResolvedStub {
                stub,
                path: path.clone(),
            })
        })
        .collect()
}

fn find_target(stub: &StubSpec) -> Result<PathBuf, String> {
    if let Some(directory) = test_target_dir() {
        let path = directory.join(stub.command);
        return super::executable(&path)
            .then_some(path.clone())
            .ok_or_else(|| {
                format!(
                    "{} is not an executable file: {}",
                    stub.command,
                    path.display()
                )
            });
    }
    let launcher = stub_path(stub.command);
    if let Some(target) = embedded_target(&launcher)
        .filter(|path| !same_path(path, &launcher) && super::executable(path))
    {
        return Ok(target);
    }
    find_target_on_path(stub.command)
        .ok_or_else(|| format!("{} is not installed on PATH", stub.command))
}

fn find_target_on_path(command: &str) -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| {
            let directory = if directory.is_absolute() {
                directory
            } else {
                cwd.join(directory)
            };
            directory.join(command)
        })
        .find(|candidate| candidate != &stub_path(command) && super::executable(candidate))
}

fn same_path(left: &Path, right: &Path) -> bool {
    left == right
        || left
            .canonicalize()
            .ok()
            .zip(right.canonicalize().ok())
            .is_some_and(|(left, right)| left == right)
}

fn valid_target_path(path: &Path, command: &str) -> bool {
    path.is_absolute()
        && path.file_name() == Some(command.as_ref())
        && path
            .to_str()
            .is_some_and(|path| !path.contains(['\'', '\n', '\r']))
}

fn stub_path(command: &str) -> PathBuf {
    test_stub_dir()
        .unwrap_or_else(|| PathBuf::from(STUB_DIR))
        .join(command)
}

fn test_target_dir() -> Option<PathBuf> {
    crate::test_env_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_TARGET_DIR").map(PathBuf::from)
}

fn test_stub_dir() -> Option<PathBuf> {
    crate::test_env_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR").map(PathBuf::from)
}

fn actual_uid() -> u32 {
    unsafe { geteuid() }
}

#[derive(Clone, Copy)]
struct EnvWrapper {
    name: &'static str,
    primary: StubSpec,
    extra: &'static [StubSpec],
}

#[derive(Clone, Copy)]
struct StubSpec {
    command: &'static str,
    keys: &'static [&'static str],
    assignment_keys: &'static [&'static str],
}

struct ResolvedStub<'a> {
    stub: &'a StubSpec,
    path: PathBuf,
}

fn stubs(wrapper: &EnvWrapper) -> impl Iterator<Item = &StubSpec> {
    std::iter::once(&wrapper.primary).chain(wrapper.extra.iter())
}

const JFROG_EXTRA: &[StubSpec] = &[stub(
    "jfrog",
    &["JFROG_ENV_ASSIGNMENTS"],
    &["JFROG_ENV_ASSIGNMENTS"],
)];
const FLY_EXTRA: &[StubSpec] = &[stub("fly", &["FLY_ACCESS_TOKEN"], &[])];

const WRAPPERS: &[EnvWrapper] = &[
    one(
        "akamai",
        "akamai",
        &["AKAMAI_ENV_ASSIGNMENTS"],
        &["AKAMAI_ENV_ASSIGNMENTS"],
    ),
    one(
        "algolia",
        "algolia",
        &["ALGOLIA_ENV_ASSIGNMENTS"],
        &["ALGOLIA_ENV_ASSIGNMENTS"],
    ),
    one("argocd", "argocd", &["ARGOCD_AUTH_TOKEN"], &[]),
    one("ast-cli", "cx", &["CX_APIKEY", "CX_CLIENT_SECRET"], &[]),
    one("buf", "buf", &["BUF_TOKEN"], &[]),
    one(
        "censys",
        "censys",
        &["CENSYS_API_ID", "CENSYS_API_SECRET", "CENSYS_ASM_API_KEY"],
        &[],
    ),
    one("checkov", "checkov", &["BC_API_KEY"], &[]),
    one("circleci", "circleci", &["CIRCLECI_CLI_TOKEN"], &[]),
    one("civo", "civo", &["CIVO_TOKEN"], &[]),
    one("cloudsmith-cli", "cloudsmith", &["CLOUDSMITH_API_KEY"], &[]),
    one("composer", "composer", &["COMPOSER_AUTH"], &[]),
    one("doctl", "doctl", &["DIGITALOCEAN_ACCESS_TOKEN"], &[]),
    multi(
        "flyctl",
        stub("flyctl", &["FLY_ACCESS_TOKEN"], &[]),
        FLY_EXTRA,
    ),
    one(
        "glab",
        "glab",
        &["GLAB_ENV_ASSIGNMENTS"],
        &["GLAB_ENV_ASSIGNMENTS"],
    ),
    one("gotify", "gotify", &["GOTIFY_TOKEN"], &[]),
    one(
        "gptcommit",
        "gptcommit",
        &["GPTCOMMIT__OPENAI__API_KEY"],
        &[],
    ),
    one(
        "grafanactl",
        "grafanactl",
        &["GRAFANACTL_ENV_ASSIGNMENTS"],
        &["GRAFANACTL_ENV_ASSIGNMENTS"],
    ),
    one("heroku", "heroku", &["HEROKU_API_KEY"], &[]),
    one("hcloud", "hcloud", &["HCLOUD_TOKEN"], &[]),
    one("huggingface-cli", "hf", &["HF_TOKEN"], &[]),
    multi(
        "jfrog-cli",
        stub("jf", &["JFROG_ENV_ASSIGNMENTS"], &["JFROG_ENV_ASSIGNMENTS"]),
        JFROG_EXTRA,
    ),
    one("k6", "k6", &["K6_CLOUD_TOKEN"], &[]),
    one("luarocks", "luarocks", &["LUAROCKS_API_KEY"], &[]),
    one(
        "minio-mc",
        "mc",
        &["MINIO_MC_HOST_ENV"],
        &["MINIO_MC_HOST_ENV"],
    ),
    one("netlify-cli", "netlify", &["NETLIFY_AUTH_TOKEN"], &[]),
    one("node", "npm", &["NODE_AUTH_TOKEN"], &[]),
    one("pnpm", "pnpm", &["NODE_AUTH_TOKEN"], &[]),
    one("pulumi", "pulumi", &["PULUMI_ACCESS_TOKEN"], &[]),
    one(
        "qwen-code",
        "qwen",
        &["QWEN_ENV_ASSIGNMENTS"],
        &["QWEN_ENV_ASSIGNMENTS"],
    ),
    one("runpodctl", "runpodctl", &["RUNPOD_API_KEY"], &[]),
    one(
        "s3cmd",
        "s3cmd",
        &["S3CMD_ENV_ASSIGNMENTS"],
        &["S3CMD_ENV_ASSIGNMENTS"],
    ),
    one("sentry-cli", "sentry-cli", &["SENTRY_AUTH_TOKEN"], &[]),
    one(
        "snowflake-cli",
        "snow",
        &["SNOWFLAKE_ENV_ASSIGNMENTS"],
        &["SNOWFLAKE_ENV_ASSIGNMENTS"],
    ),
    one(
        "snyk",
        "snyk",
        &["SNYK_ENV_ASSIGNMENTS"],
        &["SNYK_ENV_ASSIGNMENTS"],
    ),
    one(
        "transifex-cli",
        "tx",
        &["TRANSIFEX_ENV_ASSIGNMENTS"],
        &["TRANSIFEX_ENV_ASSIGNMENTS"],
    ),
    one("travis", "travis", &["TRAVIS_TOKEN"], &[]),
    one(
        "twine",
        "twine",
        &["TWINE_ENV_ASSIGNMENTS"],
        &["TWINE_ENV_ASSIGNMENTS"],
    ),
    one("vagrant", "vagrant", &["VAGRANT_CLOUD_TOKEN"], &[]),
    one("vault", "vault", &["VAULT_TOKEN"], &[]),
    one("virustotal-cli", "vt", &["VTCLI_APIKEY"], &[]),
    one("vultr", "vultr-cli", &["VULTR_API_KEY"], &[]),
    one("wsk", "wsk", &["WHISK_AUTH"], &[]),
];

const fn one(
    name: &'static str,
    command: &'static str,
    keys: &'static [&'static str],
    assignment_keys: &'static [&'static str],
) -> EnvWrapper {
    EnvWrapper {
        name,
        primary: stub(command, keys, assignment_keys),
        extra: &[],
    }
}

const fn multi(name: &'static str, primary: StubSpec, extra: &'static [StubSpec]) -> EnvWrapper {
    EnvWrapper {
        name,
        primary,
        extra,
    }
}

const fn stub(
    command: &'static str,
    keys: &'static [&'static str],
    assignment_keys: &'static [&'static str],
) -> StubSpec {
    StubSpec {
        command,
        keys,
        assignment_keys,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn flyctl_wraps_both_commands() {
        let wrapper = wrapper("flyctl").unwrap();
        assert_eq!(
            stubs(wrapper).map(|stub| stub.command).collect::<Vec<_>>(),
            ["flyctl", "fly"]
        );
    }

    #[test]
    fn installs_with_user_writable_target() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let previous_home = std::env::var_os("HOME");
        let dir = temp_dir("env-wrapper-simple");
        let target_dir = dir.join("target");
        let stub_dir = dir.join("stub");
        fs::create_dir_all(&target_dir).unwrap();
        fs::create_dir_all(&stub_dir).unwrap();
        fs::write(target_dir.join("doctl"), "").unwrap();
        fs::set_permissions(target_dir.join("doctl"), fs::Permissions::from_mode(0o755)).unwrap();
        unsafe {
            std::env::set_var("HOME", &dir);
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_TARGET_DIR", &target_dir);
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &stub_dir);
            std::env::set_var("AUTOMIC_VAULT_TEST_EUID", "0");
        }

        let mut output = Vec::new();
        run(wrapper("doctl").unwrap(), &mut output, true).unwrap();

        unsafe {
            match previous_home {
                Some(home) => std::env::set_var("HOME", home),
                None => std::env::remove_var("HOME"),
            }
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_TARGET_DIR");
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
            std::env::remove_var("AUTOMIC_VAULT_TEST_EUID");
        }
        let script = fs::read_to_string(stub_dir.join("doctl")).unwrap();
        assert!(script.contains(MARKER));
        assert!(script.contains("+DIGITALOCEAN_ACCESS_TOKEN"));
        assert!(script.contains("exec \"$original\" \"$@\""));
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(&format!("target {}", target_dir.join("doctl").display())));
        assert!(output.contains("install launcher"));
        assert!(output.ends_with("◇ next: run `hash -r`\n"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn resolves_target_from_the_users_path() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let previous_path = std::env::var_os("PATH");
        let dir = temp_dir("env-wrapper-path");
        let bin = dir.join("nix-profile/bin");
        let stubs = dir.join("stubs");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&stubs).unwrap();
        let hcloud = bin.join("hcloud");
        fs::write(&hcloud, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&hcloud, fs::Permissions::from_mode(0o755)).unwrap();
        unsafe {
            std::env::set_var("PATH", &bin);
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &stubs);
        }

        let targets = resolve_targets(wrapper("hcloud").unwrap()).unwrap();

        unsafe {
            match previous_path {
                Some(path) => std::env::set_var("PATH", path),
                None => std::env::remove_var("PATH"),
            }
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
        }
        assert_eq!(targets[0].path, hcloud);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ignores_a_stub_that_embeds_itself_as_the_target() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let previous_path = std::env::var_os("PATH");
        let dir = temp_dir("env-wrapper-self-target");
        fs::create_dir_all(&dir).unwrap();
        let launcher = dir.join("hcloud");
        let spec = &wrapper("hcloud").unwrap().primary;
        fs::write(&launcher, stub_script(spec, &launcher)).unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755)).unwrap();
        unsafe {
            std::env::set_var("PATH", "");
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir);
        }

        let error = resolve_targets(wrapper("hcloud").unwrap()).err().unwrap();

        unsafe {
            match previous_path {
                Some(path) => std::env::set_var("PATH", path),
                None => std::env::remove_var("PATH"),
            }
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
        }
        assert_eq!(error, "hcloud is not installed on PATH");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn assignment_keys_are_exported() {
        let script = stub_script(
            &stub(
                "akamai",
                &["AKAMAI_ENV_ASSIGNMENTS"],
                &["AKAMAI_ENV_ASSIGNMENTS"],
            ),
            Path::new("/nix/store/example/bin/akamai"),
        );

        assert!(script.contains("+AKAMAI_ENV_ASSIGNMENTS"));
        assert!(script.contains("for assignment in ${AKAMAI_ENV_ASSIGNMENTS-}"));
        assert!(script.contains("export \"$assignment\""));
    }

    #[test]
    fn node_requests_secrets_only_for_reviewed_npm_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-node");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let script_path = dir.join("npm");
        let script = stub_script(
            &wrapper("node").unwrap().primary,
            Path::new("/opt/homebrew/bin/npm"),
        );
        let args = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for command in [
            vec![],
            vec!["ls", "-g", "--depth=0", "--json"],
            vec!["list"],
            vec!["ll"],
            vec!["la"],
            vec!["root", "-g"],
            vec!["prefix"],
            vec!["help", "install"],
            vec!["completion"],
            vec!["--version"],
            vec!["config", "get", "//registry.npmjs.org/:_authToken"],
            vec!["login"],
            vec!["run", "build"],
            vec!["version"],
            vec!["future-command"],
        ] {
            assert!(invocation_is_secretless(
                &script_path,
                script.as_bytes(),
                &args(&command),
            ));
        }
        for command in [
            vec!["install"],
            vec!["i", "private-package"],
            vec!["ci"],
            vec!["audit"],
            vec!["doctor"],
            vec!["view", "private-package"],
            vec!["whoami"],
            vec!["publish"],
            vec!["dist-tags", "ls", "private-package"],
            vec!["trust", "list", "private-package"],
        ] {
            assert!(!invocation_is_secretless(
                &script_path,
                script.as_bytes(),
                &args(&command),
            ));
        }
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["root"]),
        ));

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR") };
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn pnpm_requests_secrets_only_for_reviewed_registry_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-pnpm");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let script_path = dir.join("pnpm");
        let script = stub_script(
            &wrapper("pnpm").unwrap().primary,
            Path::new("/opt/homebrew/bin/pnpm"),
        );
        let args = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for command in [
            vec![],
            vec![
                "--global-dir",
                "/tmp/pnpm-sem/global",
                "--global-bin-dir",
                "/tmp/pnpm-sem/bin",
                "list",
                "-g",
                "--depth=0",
                "--json",
            ],
            vec!["list"],
            vec!["why", "example"],
            vec!["root", "-g"],
            vec!["store", "path"],
            vec!["store", "prune"],
            vec!["config", "get", "store-dir"],
            vec!["login"],
            vec!["run", "build"],
            vec!["exec", "example"],
            vec!["dlx", "example"],
            vec!["install-test"],
            vec!["it"],
            vec!["remove", "example"],
            vec!["config", "get", "unrelated_authtoken"],
            vec!["--version"],
            vec!["future-command"],
            vec!["--dir", "/tmp", "publish"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "pnpm {command:?}",
            );
        }
        for command in [
            vec!["add", "private-package"],
            vec!["install"],
            vec!["ci"],
            vec!["dedupe"],
            vec!["fetch"],
            vec!["audit"],
            vec!["outdated"],
            vec!["view", "private-package"],
            vec!["search", "private-package"],
            vec!["publish"],
            vec!["unpublish", "private-package"],
            vec!["deprecate", "private-package", "message"],
            vec!["dist-tag", "add", "private-package@1", "latest"],
            vec!["whoami"],
            vec!["logout"],
            vec!["stage", "list", "private-package"],
            vec!["store", "add", "private-package"],
            vec!["config", "get", "//registry.example/:_authToken"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "pnpm {command:?}",
            );
        }

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR") };
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn local_env_wrapper_commands_bypass_secret_application() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-commands");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };

        for (wrapper_name, command, args, expected) in [
            ("pnpm", "pnpm", &["root", "-g"][..], true),
            ("pnpm", "pnpm", &["store", "path"][..], true),
            ("pnpm", "pnpm", &["install"][..], false),
            ("flyctl", "flyctl", &["version"][..], true),
            ("flyctl", "fly", &["deploy", "--help"][..], true),
            ("flyctl", "fly", &["deploy"][..], false),
            ("k6", "k6", &["inspect", "script.js"][..], true),
            ("k6", "k6", &["run", "script.js"][..], true),
            ("twine", "twine", &["check", "dist/*"][..], true),
            ("twine", "twine", &["upload", "dist/*"][..], false),
            ("vagrant", "vagrant", &["validate"][..], true),
            ("vagrant", "vagrant", &["up"][..], false),
            ("huggingface-cli", "hf", &["cache", "ls"][..], true),
            ("huggingface-cli", "hf", &["download", "repo"][..], false),
            ("composer", "composer", &["validate"][..], true),
            ("composer", "composer", &["install"][..], false),
        ] {
            let stub = stubs(wrapper(wrapper_name).unwrap())
                .find(|stub| stub.command == command)
                .unwrap();
            let script_path = dir.join(command);
            let script = stub_script(stub, &Path::new("/opt/homebrew/bin").join(command));
            let invocation = std::iter::once(script_path.clone().into_os_string())
                .chain(args.iter().map(OsString::from))
                .collect::<Vec<_>>();

            assert_eq!(
                invocation_is_secretless(&script_path, script.as_bytes(), &invocation),
                expected,
                "{command} {args:?}",
            );
        }

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR") };
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn k6_requests_secrets_only_for_explicit_cloud_operations() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-k6");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let script_path = dir.join("k6");
        let script = stub_script(
            &wrapper("k6").unwrap().primary,
            Path::new("/opt/homebrew/bin/k6"),
        );
        let args = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for command in [
            vec![],
            vec!["help"],
            vec!["--help"],
            vec!["version"],
            vec!["--version"],
            vec!["archive", "script.js"],
            vec!["inspect", "script.js"],
            vec!["deps", "script.js"],
            vec!["new", "script.js"],
            vec!["run", "script.js"],
            vec!["run", "--out", "json=results.json", "script.js"],
            vec!["run", "--config", "cloud.json", "script.js"],
            vec!["run", "--", "script.js", "--out", "cloud"],
            vec!["cloud"],
            vec!["cloud", "login"],
            vec!["cloud", "future-command"],
            vec!["x", "extension-command"],
            vec!["future-command"],
            vec!["--quiet", "run", "script.js"],
            vec!["--future-option", "cloud", "run", "script.js"],
            vec!["--quiet", "cloud", "run", "script.js", "--help"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "k6 {command:?}",
            );
        }
        for command in [
            vec!["cloud", "run", "script.js"],
            vec!["cloud", "upload", "script.js"],
            vec!["cloud", "project", "list"],
            vec!["cloud", "load-zone", "list"],
            vec!["cloud", "test", "list"],
            vec!["run", "--out", "cloud", "script.js"],
            vec!["run", "--out=cloud", "script.js"],
            vec!["run", "--out=cloud=eu", "script.js"],
            vec!["run", "-o", "cloud", "script.js"],
            vec!["run", "-ocloud", "script.js"],
            vec!["--quiet", "cloud", "run", "script.js"],
            vec!["--quiet=false", "cloud", "run", "script.js"],
            vec!["--config", "config.json", "cloud", "project", "list"],
            vec!["-cconfig.json", "cloud", "upload", "script.js"],
            vec!["cloud", "--quiet", "test", "list"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "k6 {command:?}",
            );
        }
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["run", "script.js"]),
        ));

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR") };
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn twine_requests_secrets_only_for_uploads() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-twine");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let script_path = dir.join("twine");
        let script = stub_script(
            &wrapper("twine").unwrap().primary,
            Path::new("/opt/homebrew/bin/twine"),
        );
        let args = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for command in [
            vec![],
            vec!["--help"],
            vec!["--version"],
            vec!["check", "dist/package.whl"],
            vec!["check", "--strict", "dist/package.whl"],
            vec!["register", "dist/package.whl"],
            vec!["plugin-command", "argument"],
            vec!["future-command"],
            vec!["--no-color", "check", "dist/package.whl"],
            vec!["--future-option", "upload", "dist/package.whl"],
            vec!["--", "--no-color", "upload", "dist/package.whl"],
            vec!["--", "--", "upload", "dist/package.whl"],
            vec!["upload", "--help"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "twine {command:?}",
            );
        }
        for command in [
            vec!["upload", "dist/package.whl"],
            vec!["upload", "--repository", "testpypi", "dist/package.whl"],
            vec!["--no-color", "upload", "dist/package.whl"],
            vec!["--no-color", "--no-color", "upload", "dist/package.whl"],
            vec!["--", "upload", "dist/package.whl"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "twine {command:?}",
            );
        }
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["check", "dist/package.whl"]),
        ));

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR") };
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn vagrant_requests_secrets_only_for_cloud_capable_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-vagrant");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let previous_server = std::env::var_os("VAGRANT_SERVER_URL");
        unsafe {
            std::env::set_var(
                "VAGRANT_SERVER_URL",
                "https://private-vagrant.example.invalid",
            )
        };
        let script_path = dir.join("vagrant");
        let script = stub_script(
            &wrapper("vagrant").unwrap().primary,
            Path::new("/opt/homebrew/bin/vagrant"),
        );
        let args = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for command in [
            vec![],
            vec!["--help"],
            vec!["up", "--help"],
            vec!["--version"],
            vec!["up", "--version"],
            vec!["status"],
            vec!["global-status"],
            vec!["validate"],
            vec!["destroy"],
            vec!["halt"],
            vec!["suspend"],
            vec!["ssh", "--", "printf", "hello"],
            vec!["provision"],
            vec!["push", "staging"],
            vec!["plugin-command", "argument"],
            vec!["future-command"],
            vec!["--future-option", "future-command"],
            vec!["--debug", "status"],
            vec!["box", "list"],
            vec!["box", "remove", "local-box"],
            vec!["box", "prune"],
            vec!["box", "repackage", "local-box", "virtualbox", "1.0.0"],
            vec!["box", "add", "./fixtures/base.box"],
            vec!["box", "add", "base.box"],
            vec!["box", "add", "file:///tmp/base.box"],
            vec!["box", "add", "https://downloads.example.invalid/base.box"],
            vec!["box", "add", "--provider", "virtualbox", "./base.box"],
            vec!["box", "add", "--future-option", "owner/private-box"],
            vec!["cloud"],
            vec!["cloud", "future-command"],
            vec!["cloud", "auth", "logout"],
            vec!["cloud", "auth", "login", "--token", "replacement"],
            vec!["cloud", "auth", "login", "--token=replacement"],
            vec!["login", "--future-option"],
            vec!["cloud", "auth", "login", "--future-option"],
            vec!["cloud", "auth", "whoami", "explicit-token"],
            vec!["cloud", "auth", "whoami", "--future-option"],
            vec!["snapshot", "save", "before-upgrade"],
            vec!["snapshot", "restore", "--no-start", "before-upgrade"],
            vec!["snapshot", "pop", "--no-start"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "vagrant {command:?}",
            );
        }

        for command in [
            vec!["up"],
            vec!["--debug", "up"],
            vec!["up", "--machine-readable"],
            vec!["--future-option", "up"],
            vec!["--", "up"],
            vec!["up", "--", "--help"],
            vec!["reload"],
            vec!["resume"],
            vec!["snapshot", "restore", "before-upgrade"],
            vec!["snapshot", "pop"],
            vec!["box", "add", "owner/private-box"],
            vec!["box", "add", "-a", "arm64", "owner/private-box"],
            vec!["box", "add", "--provider=virtualbox", "owner/private-box"],
            vec!["box", "add", "https://vagrantcloud.com/owner/private-box"],
            vec![
                "box",
                "add",
                "https://private-vagrant.example.invalid/owner/private-box",
            ],
            vec!["box", "outdated"],
            vec!["box", "update"],
            vec!["login"],
            vec!["login", "--check"],
            vec!["cloud", "search", "private-box"],
            vec!["cloud", "auth", "login"],
            vec!["cloud", "auth", "login", "--check"],
            vec!["cloud", "auth", "whoami"],
            vec!["cloud", "box", "show", "owner/private-box"],
            vec!["cloud", "box", "create", "owner/private-box"],
            vec!["cloud", "provider", "upload", "owner/private-box"],
            vec!["cloud", "publish", "owner/private-box"],
            vec!["cloud", "version", "release", "owner/private-box", "1.0.0"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "vagrant {command:?}",
            );
        }
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["status"]),
        ));

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR") };
        match previous_server {
            Some(value) => unsafe { std::env::set_var("VAGRANT_SERVER_URL", value) },
            None => unsafe { std::env::remove_var("VAGRANT_SERVER_URL") },
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn huggingface_requests_secrets_only_for_reviewed_hub_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-huggingface");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let script_path = dir.join("hf");
        let script = stub_script(
            &wrapper("huggingface-cli").unwrap().primary,
            Path::new("/opt/homebrew/bin/hf"),
        );
        let args = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for command in [
            vec![],
            vec!["--help"],
            vec!["-v"],
            vec!["--install-completion"],
            vec!["version"],
            vec!["update"],
            vec!["auth", "list"],
            vec!["auth", "login"],
            vec!["cache", "ls"],
            vec!["cache", "rm", "model/repo"],
            vec!["cache", "prune"],
            vec!["skills", "update"],
            vec!["lfs-enable-largefiles", "."],
            vec!["lfs-multipart-upload"],
            vec!["extensions", "exec", "custom", "--", "--token"],
            vec!["custom-extension", "--token", "extension-value"],
            vec!["future-command", "argument"],
            vec!["models", "future-command"],
            vec!["download"],
            vec!["download", "private/repo", "--token", "replacement"],
            vec!["upload", "private/repo", "--token=replacement"],
            vec!["jobs", "run", "image", "--token", "replacement", "command"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "hf {command:?}",
            );
        }

        for command in [
            vec!["auth", "whoami"],
            vec!["auth", "token"],
            vec!["env"],
            vec!["cache", "verify", "private/repo"],
            vec!["download", "private/repo"],
            vec!["upload", "private/repo", "."],
            vec!["buckets", "ls"],
            vec!["buckets", "cp", "hf://buckets/owner/private/file", "."],
            vec!["collections", "info", "owner/collection"],
            vec!["datasets", "info", "private/repo"],
            vec!["discussions", "diff", "private/repo", "1"],
            vec!["endpoints", "describe", "private-endpoint"],
            vec!["endpoints", "catalog", "ls"],
            vec!["jobs", "run", "image", "command", "--", "--token"],
            vec!["models", "ls", "private/repo", "-h"],
            vec!["papers", "read", "1234.5678"],
            vec!["repo", "branch", "create", "private/repo", "new"],
            vec!["repos", "cp", "hf://private/repo/file", "."],
            vec!["repo-files", "delete", "private/repo", "file"],
            vec!["sandbox", "exec", "sandbox-id", "--", "command"],
            vec!["spaces", "secrets", "ls", "private/space"],
            vec!["webhooks", "ls"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "hf {command:?}",
            );
        }

        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["version"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &[Path::new("/tmp/not-hf").into(), OsString::from("version")],
        ));

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR") };
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn composer_requests_auth_only_for_private_repository_capable_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-composer");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let previous_disable_network = std::env::var_os("COMPOSER_DISABLE_NETWORK");
        unsafe { std::env::remove_var("COMPOSER_DISABLE_NETWORK") };
        let script_path = dir.join("composer");
        let script = stub_script(
            &wrapper("composer").unwrap().primary,
            Path::new("/opt/homebrew/bin/composer"),
        );
        let args = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for command in [
            vec![],
            vec!["--help"],
            vec!["-V"],
            vec!["install", "--help"],
            vec!["--profile", "--working-dir", "/tmp", "validate"],
            vec!["about"],
            vec!["archive"],
            vec!["bump"],
            vec!["check-platform-reqs"],
            vec!["cc"],
            vec!["completion"],
            vec!["config", "preferred-install"],
            vec![
                "config",
                "http-basic.private.example",
                "user",
                "replacement",
            ],
            vec!["config", "--unset", "bearer.private.example"],
            vec!["config", "--auth", "--editor"],
            vec!["depends", "private/package"],
            vec!["dumpautoload"],
            vec!["exec", "vendor/bin/tool", "install"],
            vec!["home"],
            vec!["-n", "init"],
            vec!["init"],
            vec!["-n", "global", "init"],
            vec!["-n", "require", "--no-update", "private/package:^1"],
            vec!["-n", "global", "req", "--no-update", "private/package=^1"],
            vec!["licenses"],
            vec![
                "policy",
                "add-source",
                "custom",
                "url",
                "https://example.invalid/list.json",
            ],
            vec!["repo", "list"],
            vec!["remove", "--no-update", "private/package"],
            vec!["run-script", "deploy", "--", "install"],
            vec!["self-update"],
            vec!["show"],
            vec!["show", "private/package"],
            vec!["show", "--", "--available"],
            vec!["status"],
            vec!["suggests"],
            vec!["validate"],
            vec!["deploy"],
            vec!["plugin-command", "install"],
            vec!["future-command"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "composer {command:?}",
            );
        }

        for command in [
            vec!["install"],
            vec!["i"],
            vec!["ins"],
            vec!["create-project", "private/package"],
            vec!["update"],
            vec!["up"],
            vec!["search", "private"],
            vec!["audit"],
            vec!["require", "private/package:^1"],
            vec!["req", "private/package:^1"],
            vec!["-n", "require", "--no-update", "private/package"],
            vec!["remove", "private/package"],
            vec!["reinstall", "private/package"],
            vec!["outdated"],
            vec!["fund"],
            vec!["diagnose"],
            vec!["why-not", "private/package", "2"],
            vec!["archive", "private/package"],
            vec!["archive", "--", "private/package"],
            vec!["browse", "private/package"],
            vec!["browse", "--", "private/package"],
            vec![
                "init",
                "--repository",
                "https://private.example.invalid/packages.json",
            ],
            vec!["show", "--available", "private/package"],
            vec!["show", "--latest"],
            vec!["config", "--list"],
            vec!["config", "http-basic.private.example"],
            vec!["config", "--source", "bearer.private.example"],
            vec!["config", "client-certificate.private.example"],
            vec!["config", "--", "bearer.private.example"],
            vec!["global", "require", "private/package:^1"],
            vec!["--profile", "-d", "/tmp", "require", "private/package:^1"],
            vec!["install", "--", "--help"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "composer {command:?}",
            );
        }

        unsafe { std::env::set_var("COMPOSER_DISABLE_NETWORK", "1") };
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["install"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["config", "github-oauth.github.com"]),
        ));
        unsafe { std::env::set_var("COMPOSER_DISABLE_NETWORK", "0") };
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["install"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["validate"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &[
                Path::new("/tmp/not-composer").into(),
                OsString::from("validate")
            ],
        ));

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
            match previous_disable_network {
                Some(value) => std::env::set_var("COMPOSER_DISABLE_NETWORK", value),
                None => std::env::remove_var("COMPOSER_DISABLE_NETWORK"),
            }
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn current_stub_validation_rejects_marker_preserving_edits() {
        let spec = stub("tool", &["TOOL_TOKEN"], &[]);
        let target = Path::new("/nix/store/example/bin/tool");
        let path = temp_dir("env-wrapper-exact").join("tool");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, stub_script(&spec, target)).unwrap();
        assert!(is_current_stub(&path, &spec, target));

        fs::write(
            &path,
            format!("{}\n# modified\n", stub_script(&spec, target)),
        )
        .unwrap();
        assert!(!is_managed_stub(&path, &spec));
        assert!(!is_current_stub(&path, &spec, target));
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn refuses_non_managed_stub() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-refuse");
        let target_dir = dir.join("target");
        let stub_dir = dir.join("stub");
        fs::create_dir_all(&target_dir).unwrap();
        fs::create_dir_all(&stub_dir).unwrap();
        fs::write(target_dir.join("doctl"), "").unwrap();
        fs::set_permissions(target_dir.join("doctl"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(stub_dir.join("doctl"), "#!/bin/sh\n").unwrap();
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_TARGET_DIR", &target_dir);
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &stub_dir);
            std::env::set_var("AUTOMIC_VAULT_TEST_EUID", "0");
        }

        let err = run(wrapper("doctl").unwrap(), &mut Vec::new(), true).unwrap_err();

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_TARGET_DIR");
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
            std::env::remove_var("AUTOMIC_VAULT_TEST_EUID");
        }
        assert!(err.contains("is not an Automic Vault env-wrapper stub"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn root_is_only_allowed_to_run_the_install_entrypoint() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_EUID", "0") };

        let err = run(wrapper("doctl").unwrap(), &mut Vec::new(), true).unwrap_err();

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_EUID") };
        assert_eq!(
            err,
            "run `av harden doctl` without sudo; av will request elevation when needed"
        );
    }

    #[test]
    fn install_entrypoint_rejects_unknown_hardeners() {
        assert_eq!(
            install_target("not-a-hardener", &[]).unwrap_err(),
            "unknown hardener `not-a-hardener`"
        );
    }

    #[test]
    fn elevation_rejects_user_owned_executables() {
        let dir = temp_dir("env-wrapper-untrusted-av");
        fs::create_dir_all(&dir).unwrap();
        let av = dir.join("av");
        fs::write(&av, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&av, fs::Permissions::from_mode(0o755)).unwrap();

        let err = validate_privileged_av(&av).unwrap_err();

        assert!(err.contains("not root-owned"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn every_wrapper_has_a_credential_migration() {
        let mut wrappers = WRAPPERS
            .iter()
            .map(|wrapper| wrapper.name)
            .collect::<Vec<_>>();
        let mut migrations = super::super::migrations::names().collect::<Vec<_>>();
        wrappers.sort_unstable();
        migrations.sort_unstable();
        assert_eq!(wrappers, migrations);
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("av-{label}-{}-{nanos}", std::process::id()))
    }
}
