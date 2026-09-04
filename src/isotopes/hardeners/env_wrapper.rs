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
        "buf" => buf_invocation_is_secretless(args),
        "npm" => npm_invocation_is_secretless(args),
        "pnpm" => {
            local_command(
                args,
                &["bin", "help", "list", "ls", "prefix", "root", "why"],
            ) || args.first().is_some_and(|arg| arg == "store")
                && args.get(1).is_some_and(|arg| arg == "path")
        }
        "fly" | "flyctl" => local_command(args, &["completion", "help", "version"]),
        "k6" => local_command(
            args,
            &["archive", "completion", "help", "inspect", "new", "version"],
        ),
        "twine" => local_command(args, &["check"]),
        "vagrant" => local_command(args, &["global-status", "validate", "version"]),
        "hf" => local_command(args, &["cache"]),
        "composer" => local_command(
            args,
            &[
                "clear-cache",
                "clearcache",
                "licenses",
                "status",
                "validate",
            ],
        ),
        _ => false,
    }
}

fn buf_invocation_is_secretless(args: &[OsString]) -> bool {
    if buf_help_requested(args) {
        return true;
    }
    let words = buf_command_words(args);
    !buf_command_needs_token(&words, args)
        || buf_may_launch_git_or_plugin(&words, args)
        || buf_netrc_supplies_token(&words, args)
}

// Reviewed against Buf CLI v1.72.0. Keep this positive: new commands must not
// inherit BUF_TOKEN until their token use and subprocess behavior are reviewed.
fn buf_command_needs_token(words: &[&str], args: &[OsString]) -> bool {
    match words {
        [
            "build" | "breaking" | "convert" | "export" | "format" | "lint" | "ls-files" | "stats",
            ..,
        ]
        | ["dep", "graph" | "prune" | "update", ..]
        | ["config", "ls-breaking-rules" | "ls-lint-rules", ..]
        | ["source", "edit", "deprecate", ..]
        | [
            "mod",
            "prune" | "update" | "ls-breaking-rules" | "ls-lint-rules",
            ..,
        ]
        | ["plugin" | "policy", "update", ..]
        | ["beta", "price", ..] => buf_invocation_references_registry(args),
        ["curl", ..] => {
            buf_flag_is_present(args, "--schema") && buf_invocation_references_registry(args)
        }
        ["push", ..] | ["plugin" | "policy", "push", ..] => true,
        ["registry", "whoami", ..] => true,
        [
            "registry",
            "commit",
            "add-label" | "info" | "list" | "resolve",
            ..,
        ]
        | [
            "registry",
            "label",
            "archive" | "info" | "list" | "unarchive",
            ..,
        ]
        | ["registry", "sdk", "info" | "version", ..] => true,
        ["registry", "organization", command, ..]
            if matches!(*command, "create" | "delete" | "info" | "update") =>
        {
            true
        }
        ["registry", resource, "create" | "delete" | "info", ..]
            if matches!(*resource, "module" | "plugin" | "policy") =>
        {
            true
        }
        [
            "registry",
            "module",
            "deprecate" | "undeprecate" | "update",
            ..,
        ] => true,
        ["registry", resource, "commit", command, ..]
            if matches!(*resource, "module" | "plugin" | "policy")
                && matches!(*command, "add-label" | "info" | "list" | "resolve") =>
        {
            true
        }
        ["registry", resource, "label", command, ..]
            if matches!(*resource, "module" | "plugin" | "policy")
                && matches!(*command, "archive" | "info" | "list" | "unarchive") =>
        {
            true
        }
        ["registry", resource, "settings", "update", ..]
            if matches!(*resource, "module" | "plugin" | "policy") =>
        {
            true
        }
        ["beta", "registry", "plugin", "delete" | "push", ..]
        | [
            "beta",
            "registry",
            "webhook",
            "create" | "delete" | "list",
            ..,
        ] => true,
        ["alpha", "registry", "token", "delete" | "get" | "list", ..] => true,
        _ => false,
    }
}

fn buf_invocation_references_registry(args: &[OsString]) -> bool {
    args.iter()
        .any(|argument| argument.to_str().is_some_and(buf_value_references_registry))
        || buf_project_references_registry(args)
}

fn buf_value_references_registry(value: &str) -> bool {
    let value = value
        .split_once('=')
        .map_or(value, |(_, value)| value)
        .trim_matches(['\'', '"']);
    if value.contains("://") {
        return false;
    }
    let Some((remote, _)) = value.split_once('/') else {
        return false;
    };
    remote != "."
        && remote != ".."
        && remote.contains('.')
        && remote
            .chars()
            .any(|character| character.is_ascii_alphanumeric())
}

fn buf_targets_only_default_registry(words: &[&str], args: &[OsString]) -> bool {
    let mut saw_default = false;
    let mut saw_custom = false;
    for (index, argument) in args.iter().enumerate() {
        let Some(argument) = argument.to_str() else {
            saw_custom = true;
            continue;
        };
        let value = argument
            .split_once('=')
            .map_or(argument, |(_, value)| value);
        let remote = buf_registry_remote(value)
            .or_else(|| (index > 0 && args[index - 1] == "--remote").then_some(value));
        match remote {
            Some("buf.build" | "go.buf.build") => saw_default = true,
            Some(_) => saw_custom = true,
            None => {}
        }
    }
    if matches!(words, ["registry", "whoami", remote, ..] if *remote != "buf.build" && *remote != "go.buf.build")
    {
        saw_custom = true;
    }
    !saw_custom && (saw_default || matches!(words, ["registry", "whoami"]))
}

fn buf_registry_remote(value: &str) -> Option<&str> {
    let value = value.trim_matches(['\'', '"']);
    if matches!(value, "buf.build" | "go.buf.build") {
        return Some(value);
    }
    if value.contains("://") {
        return None;
    }
    if !value.contains('/') && value.contains('.') && !value.starts_with('.') {
        return Some(value);
    }
    let (remote, _) = value.split_once('/')?;
    (remote != "."
        && remote != ".."
        && remote.contains('.')
        && remote
            .chars()
            .any(|character| character.is_ascii_alphanumeric()))
    .then_some(remote)
}

fn buf_netrc_supplies_token(words: &[&str], args: &[OsString]) -> bool {
    let Some(path) = std::env::var_os("NETRC")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".netrc"))
        })
    else {
        return false;
    };
    let Ok(contents) = fs::read_to_string(path) else {
        return false;
    };
    let fields = contents
        .lines()
        .flat_map(|line| {
            line.split_once('#')
                .map_or(line, |(line, _)| line)
                .split_whitespace()
        })
        .collect::<Vec<_>>();
    let mut machine = None;
    let mut default_token = false;
    let mut buf_token = false;
    let mut index = 0;
    while index < fields.len() {
        match fields[index] {
            "machine" if index + 1 < fields.len() => {
                machine = Some(fields[index + 1]);
                index += 2;
            }
            "default" => {
                machine = Some("default");
                index += 1;
            }
            "password" if index + 1 < fields.len() => {
                if !fields[index + 1].is_empty() {
                    default_token |= machine == Some("default");
                    buf_token |= matches!(machine, Some("buf.build" | "go.buf.build"));
                }
                index += 2;
            }
            _ => index += 1,
        }
    }
    default_token || buf_token && buf_targets_only_default_registry(words, args)
}

fn buf_project_references_registry(args: &[OsString]) -> bool {
    let Ok(current_dir) = std::env::current_dir() else {
        return false;
    };
    if buf_directory_references_registry(&current_dir) {
        return true;
    }
    args.iter()
        .filter_map(|argument| argument.to_str())
        .any(|argument| {
            let path = Path::new(
                argument
                    .split_once('=')
                    .map_or(argument, |(_, value)| value),
            );
            if path.extension().is_some_and(|extension| {
                matches!(extension.to_str(), Some("yaml" | "yml" | "lock"))
            }) && fs::read_to_string(path)
                .is_ok_and(|contents| buf_config_references_registry(&contents))
            {
                return true;
            }
            path.exists()
                && buf_directory_references_registry(if path.is_dir() {
                    path
                } else {
                    path.parent().unwrap_or(path)
                })
        })
}

fn buf_directory_references_registry(directory: &Path) -> bool {
    directory.ancestors().any(|directory| {
        ["buf.yaml", "buf.yml", "buf.lock"].iter().any(|name| {
            fs::read_to_string(directory.join(name))
                .is_ok_and(|contents| buf_config_references_registry(&contents))
        })
    })
}

fn buf_config_references_registry(contents: &str) -> bool {
    let mut remote_section_indent = None;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if matches!(trimmed, "deps:" | "plugins:" | "policies:") {
            remote_section_indent = Some(indent);
            continue;
        }
        let Some(section_indent) = remote_section_indent else {
            continue;
        };
        if indent <= section_indent {
            remote_section_indent = None;
            continue;
        }
        let value = trimmed
            .strip_prefix("- ")
            .unwrap_or(trimmed)
            .split_once(": ")
            .map_or(trimmed, |(_, value)| value);
        if buf_value_references_registry(value) {
            return true;
        }
    }
    false
}

fn buf_flag_is_present(args: &[OsString], flag: &str) -> bool {
    args.iter().any(|argument| {
        argument == flag
            || argument
                .to_str()
                .is_some_and(|argument| argument.starts_with(&format!("{flag}=")))
    })
}

fn buf_help_requested(args: &[OsString]) -> bool {
    args.iter()
        .take_while(|argument| argument != &"--")
        .any(|argument| {
            matches!(
                argument.to_str(),
                Some("--help" | "-h" | "--help-tree" | "--version")
            )
        })
}

fn buf_command_words(args: &[OsString]) -> Vec<&str> {
    let mut words = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let Some(argument) = args[index].to_str() else {
            return Vec::new();
        };
        if argument == "--" {
            break;
        }
        if matches!(argument, "--log-format" | "--timeout") {
            index += 2;
            continue;
        }
        if matches!(argument, "--debug" | "--debug=true" | "--debug=false")
            || argument.starts_with("--log-format=")
            || argument.starts_with("--timeout=")
        {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            break;
        }
        words.push(argument);
        index += 1;
    }
    words
}

fn buf_may_launch_git_or_plugin(words: &[&str], args: &[OsString]) -> bool {
    matches!(words, ["generate", ..] | ["alpha", "protoc", ..])
        || matches!(words, ["beta", command, ..] if command.starts_with("buf-plugin-"))
        || matches!(
            words,
            ["lint" | "breaking", ..]
                | ["config" | "mod", "ls-breaking-rules" | "ls-lint-rules", ..]
        ) && buf_project_launches_native_check_plugin(args)
        || args.iter().any(|argument| {
            argument.to_str().is_some_and(|argument| {
                argument == "--git-metadata"
                    || argument.starts_with("git@")
                    || argument.starts_with("git://")
                    || argument.starts_with("ssh://")
                    || argument.contains(".git#")
                    || argument.ends_with(".git")
                    || argument.contains("format=git")
            })
        })
}

fn buf_project_launches_native_check_plugin(args: &[OsString]) -> bool {
    let Ok(current_dir) = std::env::current_dir() else {
        return false;
    };
    if buf_directory_launches_native_check_plugin(&current_dir) {
        return true;
    }
    args.iter()
        .filter_map(|argument| argument.to_str())
        .any(|argument| {
            if argument.contains("plugins:") || argument.contains("policies:") {
                // --config accepts YAML data as well as a path. Keep inline
                // plugin configuration tokenless instead of trying to prove
                // that every flow-style value is a sandboxed remote plugin.
                return true;
            }
            let path = Path::new(
                argument
                    .split_once('=')
                    .map_or(argument, |(_, value)| value),
            );
            if path
                .extension()
                .is_some_and(|extension| matches!(extension.to_str(), Some("yaml" | "yml")))
                && fs::read_to_string(path)
                    .is_ok_and(|contents| buf_config_launches_native_check_plugin(&contents))
            {
                return true;
            }
            path.exists()
                && buf_directory_launches_native_check_plugin(if path.is_dir() {
                    path
                } else {
                    path.parent().unwrap_or(path)
                })
        })
}

fn buf_directory_launches_native_check_plugin(directory: &Path) -> bool {
    directory.ancestors().any(|directory| {
        ["buf.yaml", "buf.yml"].iter().any(|name| {
            fs::read_to_string(directory.join(name))
                .is_ok_and(|contents| buf_config_launches_native_check_plugin(&contents))
        })
    })
}

fn buf_config_launches_native_check_plugin(contents: &str) -> bool {
    let mut section = None;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if matches!(trimmed, "plugins:" | "policies:") {
            section = Some((trimmed, indent));
            continue;
        }
        let Some((section_name, section_indent)) = section else {
            continue;
        };
        if indent <= section_indent {
            section = None;
            continue;
        }
        let Some((key, value)) = trimmed
            .strip_prefix("- ")
            .unwrap_or(trimmed)
            .split_once(": ")
        else {
            continue;
        };
        let value = value.trim_matches(['\'', '"']);
        if section_name == "plugins:"
            && key == "plugin"
            && !value.ends_with(".wasm")
            && !buf_value_references_registry(value)
        {
            return true;
        }
        if section_name == "policies:" && key == "policy" && !buf_value_references_registry(value) {
            return true;
        }
    }
    false
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
    fn buf_requests_its_token_only_for_reviewed_registry_uses() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-buf");
        let previous_home = std::env::var_os("HOME");
        let previous_netrc = std::env::var_os("NETRC");
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir);
            std::env::set_var("HOME", &dir);
            std::env::remove_var("NETRC");
        }
        let script_path = dir.join("buf");
        let script = stub_script(
            &wrapper("buf").unwrap().primary,
            Path::new("/opt/homebrew/bin/buf"),
        );
        let project = dir.join("project");
        fs::create_dir_all(&project).unwrap();
        let config = project.join("buf.yaml");
        fs::write(&config, "version: v2\nmodules:\n  - path: proto\n").unwrap();
        let project_path = project.to_str().unwrap();
        let config_path = config.to_str().unwrap();
        let args = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for command in [
            vec![],
            vec!["--help"],
            vec!["--help-tree"],
            vec![
                "registry",
                "module",
                "info",
                "buf.build/acme/petapis",
                "--help",
            ],
            vec!["completion", "zsh"],
            vec!["config", "init"],
            vec!["config", "migrate"],
            vec!["build", project_path],
            vec!["format", project_path],
            vec!["lint", project_path],
            vec!["convert", project_path, "--type", "acme.v1.Pet"],
            vec!["dep", "graph", project_path],
            vec!["dep", "prune", project_path],
            vec!["plugin", "update", project_path],
            vec!["beta", "price", project_path],
            vec![
                "curl",
                "--schema",
                project_path,
                "https://example.com/acme.v1.API/Get",
            ],
            vec!["lsp", "serve"],
            vec!["registry", "login"],
            vec!["registry", "logout"],
            vec!["registry", "cc"],
            vec!["plugin", "prune"],
            vec!["policy", "prune"],
            vec!["mod", "open"],
            vec!["generate", "--template", "buf.gen.yaml", "."],
            vec!["alpha", "protoc", "--", "--plugin=protoc-gen-owned"],
            vec!["beta", "buf-plugin-v2"],
            vec!["beta", "studio-agent"],
            vec!["future-command"],
            vec!["registry", "future-command"],
            vec!["--future-flag", "registry", "whoami"],
            vec![
                "export",
                "https://example.com/source.git",
                "--output",
                "out",
            ],
            vec!["breaking", "--against", "ssh://git@example.com/source.git"],
            vec!["push", "--git-metadata"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "buf {command:?}",
            );
        }

        fs::write(
            &config,
            "version: v2\nmodules:\n  - path: proto\ndeps:\n  - buf.build/acme/private\nplugins:\n  - plugin: buf.build/acme/check\n",
        )
        .unwrap();

        for command in [
            vec!["build", "buf.build/acme/petapis"],
            vec!["format", "buf.build/acme/petapis"],
            vec!["lint", project_path],
            vec!["breaking", "--against", "buf.build/acme/petapis"],
            vec!["convert", "buf.build/acme/petapis", "--type", "acme.v1.Pet"],
            vec![
                "curl",
                "--schema",
                "buf.build/acme/petapis",
                "https://example.com/acme.v1.API/Get",
            ],
            vec!["dep", "graph", project_path],
            vec!["dep", "prune", project_path],
            vec!["dep", "update", project_path],
            vec!["config", "ls-lint-rules", "--config", config_path],
            vec!["source", "edit", "deprecate", project_path],
            vec!["push"],
            vec!["plugin", "push", "buf.build/acme/check"],
            vec!["plugin", "update", project_path],
            vec!["policy", "push", "buf.build/acme/policy"],
            vec!["registry", "whoami"],
            vec!["registry", "organization", "info", "buf.build/acme"],
            vec!["registry", "module", "create", "buf.build/acme/petapis"],
            vec![
                "registry",
                "module",
                "commit",
                "list",
                "buf.build/acme/petapis",
            ],
            vec![
                "registry",
                "plugin",
                "label",
                "archive",
                "buf.build/acme/check:main",
            ],
            vec![
                "registry",
                "policy",
                "settings",
                "update",
                "buf.build/acme/policy",
            ],
            vec![
                "registry",
                "sdk",
                "version",
                "--module",
                "buf.build/acme/petapis",
            ],
            vec!["beta", "price", project_path],
            vec![
                "beta",
                "registry",
                "webhook",
                "list",
                "--remote",
                "buf.build",
            ],
            vec!["alpha", "registry", "token", "list", "buf.build"],
            vec!["--log-format", "json", "--timeout=5s", "registry", "whoami"],
            vec![
                "registry",
                "--debug",
                "module",
                "info",
                "buf.build/acme/petapis",
            ],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "buf {command:?}",
            );
        }

        fs::write(
            &config,
            "version: v2\nmodules:\n  - path: proto\ndeps:\n  - buf.build/acme/private\nplugins:\n  - plugin: buf.build/acme/check\n  - plugin: ./untrusted-check-plugin\n",
        )
        .unwrap();
        for command in [
            vec!["lint", project_path],
            vec![
                "breaking",
                project_path,
                "--against",
                "buf.build/acme/petapis",
            ],
            vec!["config", "ls-lint-rules", "--config", config_path],
            vec![
                "lint",
                "--config",
                "version: v2\nplugins:\n  - plugin: ./untrusted-check-plugin\n",
                "buf.build/acme/petapis",
            ],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "buf must not pass BUF_TOKEN to a local check plugin: {command:?}",
            );
        }

        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["registry", "whoami"]),
        ));

        fs::write(
            dir.join(".netrc"),
            "machine buf.build login user password freshly-logged-in-token\n",
        )
        .unwrap();
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["registry", "whoami"]),
        ));
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["registry", "module", "info", "buf.build/acme/petapis",]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&[
                "registry",
                "module",
                "info",
                "registry.example.com/acme/petapis",
            ]),
        ));

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
            match previous_home {
                Some(home) => std::env::set_var("HOME", home),
                None => std::env::remove_var("HOME"),
            }
            match previous_netrc {
                Some(netrc) => std::env::set_var("NETRC", netrc),
                None => std::env::remove_var("NETRC"),
            }
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn local_env_wrapper_commands_bypass_secret_application() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-commands");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };

        for (wrapper_name, command, args, expected) in [
            ("buf", "buf", &["config", "init"][..], true),
            ("buf", "buf", &["registry", "whoami"][..], false),
            ("pnpm", "pnpm", &["root", "-g"][..], true),
            ("pnpm", "pnpm", &["store", "path"][..], true),
            ("pnpm", "pnpm", &["install"][..], false),
            ("flyctl", "flyctl", &["version"][..], true),
            ("flyctl", "fly", &["deploy", "--help"][..], true),
            ("flyctl", "fly", &["deploy"][..], false),
            ("k6", "k6", &["inspect", "script.js"][..], true),
            ("k6", "k6", &["run", "script.js"][..], false),
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
