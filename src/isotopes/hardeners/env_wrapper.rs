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
        "glab" => glab_invocation_is_secretless(args),
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

// Reviewed against glab v1.116.0-24-g7ee9692c. This is the exact canonical
// runnable vocabulary that can consume GitLab credentials. Parent, unknown,
// user-alias, and passthrough forms stay tokenless until audited.
const GLAB_AUTHENTICATED_COMMANDS: &str = "api,artifact-registry get-token,artifact-registry login,artifact-registry status,attestation verify,changelog generate,ci artifact,ci cancel job,ci cancel pipeline,ci ci lint,ci ci trace,ci ci view,ci config compile,ci delete,ci get,ci lint,ci list,ci retry,ci run,ci run-trig,ci status,ci trace,ci trigger,ci view,cluster agent bootstrap,cluster agent check-manifest-usage,cluster agent get-token,cluster agent list,cluster agent token list,cluster agent token revoke,cluster agent token-cache clear,cluster agent token-cache list,cluster agent update-kubeconfig,cluster graph,container-registry repository delete,container-registry repository list,container-registry repository view,container-registry tag delete,container-registry tag list,container-registry tag view,dependency-firewall ci-summary,deploy-key add,deploy-key delete,deploy-key get,deploy-key list,gpg-key add,gpg-key delete,gpg-key get,gpg-key list,incident close,incident list,incident note,incident reopen,incident subscribe,incident unsubscribe,incident view,issue board create,issue board view,issue close,issue create,issue delete,issue list,issue note,issue reopen,issue subscribe,issue unsubscribe,issue update,issue view,iteration list,job artifact,label create,label delete,label edit,label get,label list,mcp serve,milestone create,milestone delete,milestone edit,milestone get,milestone list,mr approve,mr approvers,mr checkout,mr close,mr create,mr delete,mr diff,mr for,mr issues,mr list,mr merge,mr note,mr note create,mr note delete,mr note list,mr note reopen,mr note resolve,mr note update,mr rebase,mr reopen,mr revoke,mr subscribe,mr todo,mr unsubscribe,mr update,mr view,opentofu init,opentofu state delete,opentofu state download,opentofu state list,opentofu state lock,opentofu state unlock,packages delete,packages download,packages list,packages upload,release create,release delete,release download,release list,release upload,release view,repo archive,repo clone,repo contributors,repo create,repo delete,repo fork,repo list,repo members add,repo members remove,repo mirror,repo prune,repo publish catalog,repo remote add,repo search,repo transfer,repo update,repo view,runner assign,runner delete,runner jobs,runner list,runner managers,runner unassign,runner update,runner-controller create,runner-controller delete,runner-controller get,runner-controller list,runner-controller scope create,runner-controller scope delete,runner-controller scope list,runner-controller token create,runner-controller token list,runner-controller token revoke,runner-controller token rotate,runner-controller update,schedule create,schedule delete,schedule list,schedule run,schedule update,search semantic,securefile create,securefile download,securefile get,securefile list,securefile remove,securefile update,security config disable,security config enable,security config status,snippet create,ssh-key add,ssh-key delete,ssh-key get,ssh-key list,todo done,todo list,token create,token list,token revoke,token rotate,user events,variable delete,variable export,variable get,variable import,variable list,variable set,variable update,work-items create,work-items delete,work-items list,work-items update";

fn glab_invocation_is_secretless(args: &[OsString]) -> bool {
    let Some(args) = args
        .iter()
        .map(|arg| arg.to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return true;
    };
    let option_end = args
        .iter()
        .position(|arg| *arg == "--")
        .unwrap_or(args.len());
    let option_args = &args[..option_end];
    if option_args
        .iter()
        .any(|arg| matches!(*arg, "--help" | "-h" | "--version"))
        || args.len() == 1 && args[0] == "-v"
        || glab_uses_another_credential()
    {
        return true;
    }

    let mut path = Vec::new();
    let mut index = 0;
    while index < option_end {
        let argument = args[index];
        let parent = path.join(" ");
        let config_get = parent == "config get";
        if matches!(argument, "--repo" | "-R") || config_get && argument == "--host" {
            if index + 1 >= option_end {
                return true;
            }
            index += 2;
            continue;
        }
        if argument.starts_with("--repo=")
            || config_get && argument.starts_with("--host=")
            || parent.starts_with("config ") && matches!(argument, "--global" | "-g")
            || parent == "orbit" && matches!(argument, "--yes" | "-y")
        {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            return true;
        }

        path.push(glab_canonical_command(&path, argument));
        let command = path.join(" ");
        if matches!(
            command.as_str(),
            "auth status"
                | "auth credential-helper"
                | "auth git-credential get"
                | "auth docker-helper get"
                | "duo ask"
                | "orbit remote"
                | "stack sync"
                | "stack reorder"
        ) || matches!(
            command.as_str(),
            "config get token" | "config get gitlab_token" | "config get oauth_token"
        ) || command == "auth dpop-gen" && !glab_has_option(option_args, "--pat")
        {
            return false;
        }
        if GLAB_AUTHENTICATED_COMMANDS
            .split(',')
            .any(|candidate| candidate == command)
        {
            return false;
        }
        index += 1;
    }
    true
}

fn glab_canonical_command(parent: &[String], argument: &str) -> String {
    let argument = argument.to_ascii_lowercase();
    let parent = parent.join(" ");
    match (parent.as_str(), argument.as_str()) {
        ("", "ar") => "artifact-registry",
        ("", "conf") => "config",
        ("", "cr") => "container-registry",
        ("", "df") => "dependency-firewall",
        ("", "pipe" | "pipeline") => "ci",
        ("", "project") => "repo",
        ("", "rc") => "runner-controller",
        ("", "sched" | "skd") => "schedule",
        ("", "stacks") => "stack",
        ("", "terraform" | "tf") => "opentofu",
        ("", "var") => "variable",
        ("ci", "artifact" | "push") => "artifact",
        ("ci", "create") => "run",
        ("ci", "stats") => "status",
        ("cluster agent", "bs") => "bootstrap",
        ("cluster agent", "check_manifest_usage") => "check-manifest-usage",
        ("container-registry", "tags") => "tag",
        ("incident", "resolve") => "close",
        ("job", "push") => "artifact",
        ("mr", "accept") => "merge",
        ("mr", "add-todo") => "todo",
        ("mr", "create-for" | "for-issue" | "new-for") => "for",
        ("mr", "issue") => "issues",
        ("mr", "unapprove") => "revoke",
        ("packages", "dl") => "download",
        ("packages", "rm") => "delete",
        ("packages", "ul") => "upload",
        ("repo", "find" | "lookup") => "search",
        ("repo", "users") => "contributors",
        ("securefile", "delete" | "rm") => "remove",
        ("securefile", "overwrite") => "update",
        ("securefile", "show") => "get",
        ("securefile", "upload") => "create",
        ("token", "rm") => "revoke",
        ("token", "rot") => "rotate",
        ("variable", "create" | "new") => "set",
        ("variable", "ex") => "export",
        ("variable", "im") => "import",
        ("variable", "remove") => "delete",
        (_, "comment") => "note",
        (_, "del") => "delete",
        (_, "ls") => "list",
        (_, "new") => "create",
        (_, "open") => "reopen",
        (_, "show") => "view",
        (_, "sub") => "subscribe",
        (_, "unsub") => "unsubscribe",
        _ => argument.as_str(),
    }
    .to_string()
}

fn glab_has_option(args: &[&str], option: &str) -> bool {
    args.iter()
        .any(|arg| *arg == option || arg.starts_with(&format!("{option}=")))
}

fn glab_uses_another_credential() -> bool {
    [
        "GITLAB_TOKEN",
        "GITLAB_ACCESS_TOKEN",
        "OAUTH_TOKEN",
        "JOB_TOKEN",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
        || std::env::var_os("GLAB_ENABLE_CI_AUTOLOGIN").is_some_and(|value| value == "true")
            && std::env::var_os("GITLAB_CI").is_some_and(|value| value == "true")
            && std::env::var_os("CI_JOB_TOKEN").is_some_and(|value| !value.is_empty())
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
    fn glab_requests_secrets_only_for_reviewed_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-glab");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let credential_vars = [
            "GITLAB_TOKEN",
            "GITLAB_ACCESS_TOKEN",
            "OAUTH_TOKEN",
            "JOB_TOKEN",
            "GLAB_ENABLE_CI_AUTOLOGIN",
            "GITLAB_CI",
            "CI_JOB_TOKEN",
        ];
        let previous_credentials = credential_vars.map(|name| std::env::var_os(name));
        for name in credential_vars {
            unsafe { std::env::remove_var(name) };
        }

        let script_path = dir.join("glab");
        let script = stub_script(
            &wrapper("glab").unwrap().primary,
            Path::new("/opt/homebrew/bin/glab"),
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
            vec!["-R", "group/project", "--help"],
            vec!["alias", "list"],
            vec!["config", "path"],
            vec!["config", "get", "editor"],
            vec!["config", "set", "editor", "vim"],
            vec!["auth", "login"],
            vec!["auth", "logout", "--hostname", "gitlab.com"],
            vec!["auth", "configure-docker"],
            vec!["auth", "docker-helper", "erase"],
            vec!["completion", "zsh"],
            vec!["version"],
            vec!["check-update"],
            vec!["whatsnew"],
            vec!["skills", "list"],
            vec!["stack", "list"],
            vec!["duo", "cli", "run", "--goal", "summarize"],
            vec!["orbit", "local", "sql", "select 1"],
            vec!["issue"],
            vec!["issue", "future-command"],
            vec!["my-shell-alias", "anything"],
            vec!["-g", "issue", "list"],
            vec!["--", "shell-passthrough"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "glab {command:?}",
            );
        }
        for command in [
            vec!["issue", "list"],
            vec!["project", "ls"],
            vec!["-R", "group/project", "mr", "view", "1"],
            vec!["--repo=group/project", "issue", "view", "1"],
            vec!["auth", "status"],
            vec!["auth", "credential-helper"],
            vec!["auth", "git-credential", "get"],
            vec!["auth", "docker-helper", "get"],
            vec!["auth", "dpop-gen", "--private-key", "/tmp/id"],
            vec!["config", "get", "token"],
            vec!["config", "get", "--host", "gitlab.com", "token"],
            vec!["conf", "get", "GITLAB_TOKEN"],
            vec!["artifact-registry", "get-token"],
            vec!["stack", "sync"],
            vec!["stacks", "reorder"],
            vec!["duo", "ask", "summarize"],
            vec!["orbit", "remote", "status"],
            vec!["orbit", "--yes", "remote", "status"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "glab {command:?}",
            );
        }
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&[
                "auth",
                "dpop-gen",
                "--private-key",
                "/tmp/id",
                "--pat=given"
            ]),
        ));

        for name in [
            "GITLAB_TOKEN",
            "GITLAB_ACCESS_TOKEN",
            "OAUTH_TOKEN",
            "JOB_TOKEN",
        ] {
            unsafe { std::env::set_var(name, "already-provided") };
            assert!(invocation_is_secretless(
                &script_path,
                script.as_bytes(),
                &args(&["issue", "list"]),
            ));
            unsafe { std::env::remove_var(name) };
        }
        unsafe {
            std::env::set_var("GLAB_ENABLE_CI_AUTOLOGIN", "true");
            std::env::set_var("GITLAB_CI", "true");
            std::env::set_var("CI_JOB_TOKEN", "already-provided");
        }
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["issue", "list"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["issue", "list"]),
        ));

        for (name, value) in credential_vars.into_iter().zip(previous_credentials) {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
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
