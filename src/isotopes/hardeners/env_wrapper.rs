use std::ffi::OsString;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
        "circleci" => circleci_invocation_is_secretless(args),
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

// Reviewed against circleci-cli v1.0.49592 and the final v0.1 release,
// v0.1.47860. Keep this positive: v0.1 `run` executes arbitrary plugins, and
// v1 loads arbitrary extensions and MCP tools.
fn circleci_invocation_is_secretless(args: &[OsString]) -> bool {
    if args.is_empty()
        || args.iter().any(|arg| arg.to_str().is_none())
        || args.iter().any(|arg| arg == "--")
        || args.iter().any(|arg| {
            matches!(
                arg.to_str(),
                Some("--help" | "-h" | "--version" | "-V" | "-v")
            )
        })
        || circleci_has_nonempty_option(args, "--token")
        || std::env::var_os("CIRCLECI_CLI_TOKEN").is_some()
        || ["CIRCLE_TOKEN", "CIRCLE_CLI_TOKEN"]
            .iter()
            .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
    {
        return true;
    }

    let Some((command_index, explicit_config)) = circleci_command(args) else {
        return true;
    };
    let command = args[command_index].to_str().unwrap();
    let subcommand = circleci_subcommand(args, command_index + 1);
    let requests_token = match command {
        "admin" | "api" | "artifact" | "certificate" | "component-version" | "context"
        | "deploy" | "diagnostic" | "dlc" | "follow" | "info" | "job" | "my" | "namespace"
        | "org" | "pipeline" | "project" | "query" | "runner" | "signing-config"
        | "test-result" | "trigger" | "workflow" => true,
        "auth" => subcommand == Some("me"),
        "config" => {
            matches!(subcommand, Some("validate" | "check" | "process"))
                && circleci_has_private_org(args)
        }
        "orb" => matches!(
            subcommand,
            Some(
                "add-to-category"
                    | "create"
                    | "diff"
                    | "get"
                    | "info"
                    | "init"
                    | "list"
                    | "list-categories"
                    | "process"
                    | "publish"
                    | "remove-from-category"
                    | "source"
                    | "unlist"
                    | "validate"
            )
        ),
        "policy" => match subcommand {
            Some("bundle" | "compile") => false,
            Some("test") => circleci_has_private_org(args),
            Some("eval") => {
                !circleci_has_flag(args, "--no-compile")
                    && (!circleci_has_nonempty_option(args, "--context")
                        || circleci_option_equals(args, "--context", "config"))
            }
            Some("decide" | "diff" | "fetch" | "logs" | "push" | "settings") => true,
            _ => false,
        },
        // v0.1 `run` and local execution hand the environment to arbitrary
        // plugins or job code. Never route the protected token to them.
        "build" | "local" | "mcp" | "run" | "tests" => false,
        _ => false,
    };
    !requests_token
        || circleci_config_has_token(explicit_config.as_deref())
        || (test_stub_dir().is_none() && circleci_keychain_has_token(explicit_config.as_deref()))
}

fn circleci_command(args: &[OsString]) -> Option<(usize, Option<PathBuf>)> {
    let mut explicit_config = None;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].to_str()?;
        if matches!(argument, "--config" | "-c") {
            let value = args.get(index + 1)?.to_str()?;
            if value.is_empty() {
                return None;
            }
            explicit_config = Some(PathBuf::from(value));
            index += 2;
        } else if let Some(value) = argument.strip_prefix("--config=") {
            if value.is_empty() {
                return None;
            }
            explicit_config = Some(PathBuf::from(value));
            index += 1;
        } else if circleci_option_takes_value(argument) {
            if args.get(index + 1)?.is_empty() {
                return None;
            }
            index += 2;
        } else if circleci_inline_option_has_value(argument) {
            index += 1;
        } else if circleci_global_flag(argument) {
            index += 1;
        } else if argument.starts_with('-') {
            return None;
        } else {
            return Some((index, explicit_config));
        }
    }
    None
}

fn circleci_subcommand(args: &[OsString], mut index: usize) -> Option<&str> {
    while index < args.len() {
        let argument = args[index].to_str()?;
        if circleci_option_takes_value(argument)
            || matches!(argument, "--org" | "--org-id" | "--org-slug" | "-o")
        {
            index += 2;
        } else if circleci_inline_option_has_value(argument) {
            index += 1;
        } else if circleci_global_flag(argument)
            || matches!(argument, "--json" | "--private" | "--uncertified")
        {
            index += 1;
        } else if argument.starts_with('-') {
            return None;
        } else {
            return Some(argument);
        }
    }
    None
}

fn circleci_option_takes_value(argument: &str) -> bool {
    matches!(
        argument,
        "--endpoint" | "--github-api" | "--host" | "--mock-telemetry" | "--theme" | "--token"
    )
}

fn circleci_inline_option_has_value(argument: &str) -> bool {
    [
        "--endpoint",
        "--github-api",
        "--host",
        "--mock-telemetry",
        "--org",
        "--org-id",
        "--org-slug",
        "--theme",
        "--token",
    ]
    .iter()
    .any(|name| {
        argument
            .strip_prefix(name)
            .and_then(|argument| argument.strip_prefix('='))
            .is_some_and(|value| !value.is_empty())
    })
}

fn circleci_global_flag(argument: &str) -> bool {
    matches!(
        argument,
        "--debug"
            | "--insecure-storage"
            | "--json"
            | "--no-color"
            | "--quiet"
            | "--skip-update-check"
            | "--trace"
    )
}

fn circleci_has_flag(args: &[OsString], name: &str) -> bool {
    args.iter()
        .take_while(|arg| *arg != "--")
        .any(|arg| arg == name)
}

fn circleci_has_nonempty_option(args: &[OsString], name: &str) -> bool {
    args.iter()
        .take_while(|arg| *arg != "--")
        .enumerate()
        .any(|(index, arg)| {
            if arg == name {
                return args.get(index + 1).is_some_and(|value| !value.is_empty());
            }
            arg.to_str()
                .and_then(|arg| arg.strip_prefix(name))
                .and_then(|arg| arg.strip_prefix('='))
                .is_some_and(|value| !value.is_empty())
        })
}

fn circleci_option_equals(args: &[OsString], name: &str, expected: &str) -> bool {
    args.iter()
        .take_while(|arg| *arg != "--")
        .enumerate()
        .any(|(index, arg)| {
            arg == name && args.get(index + 1).is_some_and(|value| value == expected)
                || arg
                    .to_str()
                    .and_then(|arg| arg.strip_prefix(name))
                    .and_then(|arg| arg.strip_prefix('='))
                    == Some(expected)
        })
}

fn circleci_has_private_org(args: &[OsString]) -> bool {
    ["--org", "--org-id", "--org-slug", "-o"]
        .iter()
        .any(|name| circleci_has_nonempty_option(args, name))
}

fn circleci_config_has_token(explicit: Option<&Path>) -> bool {
    circleci_config_paths(explicit)
        .into_iter()
        .any(|path| circleci_config_value(&path, "token").is_some_and(|token| token != "token"))
}

fn circleci_config_paths(explicit: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(path) = explicit {
        paths.push(path.to_path_buf());
    }
    if let Some(base) = std::env::var_os("XDG_CONFIG_HOME") {
        paths.push(PathBuf::from(base).join("circleci/config.yml"));
    } else if let Some(home) = std::env::var_os("HOME") {
        paths.push(PathBuf::from(&home).join(".config/circleci/config.yml"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(PathBuf::from(home).join(".circleci/cli.yml"));
    }
    paths
}

fn circleci_config_value(path: &Path, key: &str) -> Option<String> {
    if !path.metadata().ok()?.is_file() {
        return None;
    }
    let mut contents = String::new();
    fs::File::open(path)
        .ok()?
        .take(64 * 1024)
        .read_to_string(&mut contents)
        .ok()?;
    contents.lines().find_map(|line| {
        if line.starts_with(char::is_whitespace) {
            return None;
        }
        let (name, value) = line.split_once(':')?;
        if name.trim() != key {
            return None;
        }
        let value = value
            .split_once(" #")
            .map_or(value, |(value, _)| value)
            .trim();
        if value.is_empty() || value.starts_with('#') {
            return None;
        }
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|value| value.strip_suffix('\''))
            })
            .unwrap_or(value)
            .trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}

fn circleci_keychain_has_token(explicit_config: Option<&Path>) -> bool {
    let host = std::env::var("CIRCLE_HOST")
        .ok()
        .filter(|host| !host.is_empty())
        .or_else(|| {
            circleci_config_paths(explicit_config)
                .into_iter()
                .find_map(|path| circleci_config_value(&path, "host"))
        })
        .unwrap_or_else(|| "https://circleci.com".to_string());
    let mut command = Command::new("/usr/bin/security");
    command.args([
        "find-generic-password",
        "-s",
        &format!("com.circleci.cli:{host}"),
    ]);
    circleci_keychain_query_succeeds(&mut command)
}

fn circleci_keychain_query_succeeds(command: &mut Command) -> bool {
    command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
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
    if stub.command == "circleci" {
        script.push_str(
            "if [ -n \"${CIRCLE_TOKEN:-}\" ]; then\n\
  [ \"${CIRCLECI_CLI_TOKEN+x}\" = x ] || export CIRCLECI_CLI_TOKEN=\"$CIRCLE_TOKEN\"\n\
  [ \"${CIRCLE_CLI_TOKEN+x}\" = x ] || export CIRCLE_CLI_TOKEN=\"$CIRCLE_TOKEN\"\n\
elif [ -n \"${CIRCLE_CLI_TOKEN:-}\" ]; then\n\
  [ \"${CIRCLECI_CLI_TOKEN+x}\" = x ] || export CIRCLECI_CLI_TOKEN=\"$CIRCLE_CLI_TOKEN\"\n\
  [ \"${CIRCLE_TOKEN+x}\" = x ] || export CIRCLE_TOKEN=\"$CIRCLE_CLI_TOKEN\"\n\
elif [ -n \"${CIRCLECI_CLI_TOKEN:-}\" ]; then\n\
  [ \"${CIRCLE_TOKEN+x}\" = x ] || export CIRCLE_TOKEN=\"$CIRCLECI_CLI_TOKEN\"\n\
  [ \"${CIRCLE_CLI_TOKEN+x}\" = x ] || export CIRCLE_CLI_TOKEN=\"$CIRCLECI_CLI_TOKEN\"\n\
fi\n",
        );
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
    use std::os::unix::ffi::OsStringExt;
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
    fn circleci_requests_its_token_only_for_reviewed_api_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-circleci");
        let stub_dir = dir.join("stubs");
        let xdg = dir.join("xdg");
        let legacy_config = dir.join(".circleci/cli.yml");
        let current_config = xdg.join("circleci/config.yml");
        let explicit_config = dir.join("explicit.yml");
        fs::create_dir_all(&stub_dir).unwrap();
        fs::create_dir_all(legacy_config.parent().unwrap()).unwrap();
        fs::create_dir_all(current_config.parent().unwrap()).unwrap();

        let env_names = [
            "AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR",
            "CIRCLECI_CLI_TOKEN",
            "CIRCLE_CLI_TOKEN",
            "CIRCLE_HOST",
            "CIRCLE_TOKEN",
            "HOME",
            "XDG_CONFIG_HOME",
        ];
        let previous = env_names.map(|name| (name, std::env::var_os(name)));
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &stub_dir);
            std::env::set_var("HOME", &dir);
            std::env::set_var("XDG_CONFIG_HOME", &xdg);
            for name in &env_names[1..5] {
                std::env::remove_var(name);
            }
        }

        let script_path = stub_dir.join("circleci");
        let target = dir.join("target/circleci");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(
            &target,
            "#!/bin/sh\nprintf '%s|%s|%s\\n' \"${CIRCLECI_CLI_TOKEN-}\" \"${CIRCLE_TOKEN-}\" \"${CIRCLE_CLI_TOKEN-}\"\n",
        )
        .unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        let stub = &wrapper("circleci").unwrap().primary;
        let script = stub_script(stub, &target);
        assert!(script.contains("export CIRCLE_TOKEN=\"$CIRCLECI_CLI_TOKEN\""));
        assert!(script.contains("export CIRCLECI_CLI_TOKEN=\"$CIRCLE_TOKEN\""));
        fs::write(&script_path, &script).unwrap();
        let output = Command::new("/bin/sh")
            .arg(&script_path)
            .env("CIRCLECI_CLI_TOKEN", "vaulted")
            .env_remove("CIRCLE_TOKEN")
            .env_remove("CIRCLE_CLI_TOKEN")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"vaulted|vaulted|vaulted\n");
        let invocation = |values: Vec<OsString>| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values)
                .collect::<Vec<_>>()
        };
        let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();

        for values in [
            vec![],
            vec!["--help"],
            vec!["--debug", "--version"],
            vec!["version"],
            vec!["help", "pipeline"],
            vec!["future-command"],
            vec!["extension", "install", "example"],
            vec!["mcp", "start"],
            vec!["run", "arbitrary-plugin", "--write"],
            vec!["local", "execute", "build"],
            vec!["build", "--job", "build"],
            vec!["tests", "split"],
            vec!["config", "validate"],
            vec!["config", "process", ".circleci/config.yml"],
            vec!["config", "pack", ".circleci"],
            vec!["policy", "bundle", "policies"],
            vec!["policy", "compile", "policies"],
            vec!["policy", "eval", "policies", "--no-compile"],
            vec!["policy", "eval", "policies", "--context", "other"],
            vec!["policy", "test", "policies"],
            vec!["auth", "login"],
            vec!["auth", "logout"],
            vec!["setup"],
            vec!["pipeline", "list", "--", "anything"],
        ] {
            assert!(
                invocation_is_secretless(
                    &script_path,
                    script.as_bytes(),
                    &invocation(args(&values)),
                ),
                "circleci {values:?}",
            );
        }
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &invocation(vec![OsString::from_vec(vec![0xff])]),
        ));

        for values in [
            vec!["pipeline", "list"],
            vec!["pipeline", "run", "main"],
            vec!["project", "list"],
            vec!["context", "list"],
            vec!["context", "create", "production"],
            vec!["auth", "me"],
            vec!["config", "validate", "--org", "gh/example"],
            vec![
                "config",
                "process",
                "--org-slug=github/example",
                "config.yml",
            ],
            vec!["orb", "validate", "orb.yml"],
            vec!["orb", "publish", "orb.yml", "example/orb@dev:first"],
            vec!["policy", "eval", "policies", "--input", "config.yml"],
            vec!["policy", "push", "policies", "--org", "gh/example"],
            vec!["api", "get", "/api/v2/me"],
            vec!["diagnostic"],
            vec!["workflow", "list"],
            vec![
                "--host=https://circleci.example",
                "--json",
                "pipeline",
                "list",
            ],
        ] {
            assert!(
                !invocation_is_secretless(
                    &script_path,
                    script.as_bytes(),
                    &invocation(args(&values)),
                ),
                "circleci {values:?}",
            );
        }

        for values in [
            vec!["--token", "explicit", "pipeline", "list"],
            vec!["pipeline", "list", "--token=explicit"],
        ] {
            assert!(invocation_is_secretless(
                &script_path,
                script.as_bytes(),
                &invocation(args(&values)),
            ));
        }

        unsafe { std::env::set_var("CIRCLE_TOKEN", "existing") };
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &invocation(args(&["pipeline", "list"])),
        ));
        unsafe {
            std::env::remove_var("CIRCLE_TOKEN");
            std::env::set_var("CIRCLECI_CLI_TOKEN", "");
        }
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &invocation(args(&["pipeline", "list"])),
        ));
        unsafe { std::env::remove_var("CIRCLECI_CLI_TOKEN") };

        fs::write(&current_config, "token: \"\"\n").unwrap();
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &invocation(args(&["pipeline", "list"])),
        ));
        fs::write(&current_config, "token: fresh\n").unwrap();
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &invocation(args(&["pipeline", "list"])),
        ));
        fs::remove_file(&current_config).unwrap();

        fs::write(&legacy_config, "host: https://circleci.com\ntoken: fresh\n").unwrap();
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &invocation(args(&["pipeline", "list"])),
        ));
        fs::remove_file(&legacy_config).unwrap();

        fs::write(&explicit_config, "token: fresh\n").unwrap();
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &invocation(args(&[
                "--config",
                explicit_config.to_str().unwrap(),
                "pipeline",
                "list",
            ])),
        ));

        assert!(circleci_keychain_query_succeeds(&mut Command::new(
            "/usr/bin/true"
        )));
        assert!(!circleci_keychain_query_succeeds(&mut Command::new(
            "/usr/bin/false"
        )));

        for (name, value) in previous {
            unsafe {
                if let Some(value) = value {
                    std::env::set_var(name, value);
                } else {
                    std::env::remove_var(name);
                }
            }
        }
        fs::remove_dir_all(dir).unwrap();
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
