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
        "jf" | "jfrog" => jfrog_invocation_is_secretless(args),
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

// Reviewed against JFrog CLI v2.123.0. This is the exact built-in command
// vocabulary that can consume the migrated JFrog credential bundle. Dynamic
// plugins, unknown commands, and parent namespaces remain tokenless.
const JFROG_AUTHENTICATED_COMMANDS: &str = "access-token-create,ag,agent apm,agent apm install,agent apm publish,agent plugins delete,agent plugins install,agent plugins publish,agent plugins search,agent plugins update,agent skills delete,agent skills install,agent skills publish,agent skills search,agent skills update,ago,am,an,ap,ape,api,apk,apptrust ac,apptrust ad,apptrust aexp,apptrust aimp,apptrust app-create,apptrust app-delete,apptrust app-export,apptrust app-import,apptrust app-update,apptrust au,apptrust p,apptrust package-bind,apptrust package-unbind,apptrust pb,apptrust ping,apptrust pu,apptrust vc,apptrust vd,apptrust vdist,apptrust vdr,apptrust version-create,apptrust version-delete,apptrust version-delete-remote,apptrust version-distribute,apptrust version-promote,apptrust version-release,apptrust version-rollback,apptrust version-update,apptrust version-update-sources,apptrust vp,apptrust vr,apptrust vrb,apptrust vu,apptrust vus,apt,apt-get,at ac,at ad,at aexp,at aimp,at app-create,at app-delete,at app-export,at app-import,at app-update,at au,at p,at package-bind,at package-unbind,at pb,at ping,at pu,at vc,at vd,at vdist,at vdr,at version-create,at version-delete,at version-delete-remote,at version-distribute,at version-promote,at version-release,at version-rollback,at version-update,at version-update-sources,at vp,at vr,at vrb,at vu,at vus,atc,aud,audit,audit-go,audit-gradle,audit-mvn,audit-npm,audit-pip,audit-pipenv,bs,build-scan,ca,cargo,conan,conan-config,conanc,curation-audit,docker,dotnet,dotnet-config,dotnetc,ds rbc,ds rbd,ds rbdel,ds rbs,ds rbu,ds release-bundle-create,ds release-bundle-delete,ds release-bundle-distribute,ds release-bundle-sign,ds release-bundle-update,evd create,evd create-evidence,evd get,evd get-evidence,evd verify,evd verify-evidence,git a,git audit,go,go-config,go-publish,goc,gp,gradle,gradle-config,gradlec,helm,hf,hf d,hf download,hf u,hf upload,hugging-face,hugging-face d,hugging-face download,hugging-face u,hugging-face upload,ide s,ide setup,malicious-scan,mc ja,mc jd,mc jpd-add,mc jpd-delete,mc la,mc ld,mc license-acquire,mc license-deploy,mc license-release,mc lr,ms,mvn,mvn-config,mvnc,mvnw,nix,npm,npm-config,npmc,nuget,nuget-config,nugetc,pip,pip-config,pipc,pipec,pipenv,pipenv-config,pl s,pl ss,pl status,pl sy,pl sync,pl sync-status,pl t,pl trigger,pl v,pl version,pnpm,pnpm-config,pnpmc,poc,poetry,poetry-config,rba,rbc,rbd,rbdell,rbdelr,rbe,rbf,rbi,rbp,rbs,rbu,release-bundle-annotate,release-bundle-create,release-bundle-delete-local,release-bundle-delete-remote,release-bundle-distribute,release-bundle-export,release-bundle-finalize,release-bundle-import,release-bundle-promote,release-bundle-search,release-bundle-update,rt access-token-create,rt atc,rt ba,rt bdc,rt bdi,rt bp,rt bpr,rt bs,rt build-append,rt build-discard,rt build-docker-create,rt build-promote,rt build-publish,rt build-scan,rt cl,rt cocoapods-config,rt cocoapodsc,rt copy,rt cp,rt curl,rt ddl,rt del,rt delete,rt delete-props,rt delp,rt direct-download,rt dl,rt docker-promote,rt docker-pull,rt docker-push,rt dotnet,rt dotnet-config,rt dotnetc,rt download,rt dp,rt dpl,rt dpr,rt gau,rt gc,rt gdel,rt git-lfs-clean,rt glc,rt go,rt go-config,rt go-publish,rt gp,rt gradle,rt gradle-config,rt gradlec,rt group-add-users,rt group-create,rt group-delete,rt move,rt mv,rt mvn,rt mvn-config,rt mvnc,rt npm-ci,rt npm-config,rt npm-install,rt npm-publish,rt npmc,rt npmci,rt npmi,rt npmp,rt nuget,rt nuget-config,rt nugetc,rt oc,rt osb,rt p,rt permission-target-create,rt permission-target-delete,rt permission-target-update,rt ping,rt pip-config,rt pip-install,rt pipc,rt pipi,rt podman-pull,rt podman-push,rt pp,rt ppl,rt ptc,rt ptdel,rt ptu,rt rc,rt rdel,rt replication-create,rt replication-delete,rt repo-create,rt repo-delete,rt repo-update,rt rplc,rt rpldel,rt ru,rt s,rt search,rt set-props,rt sp,rt swift-config,rt swiftc,rt transfer-config,rt transfer-config-merge,rt transfer-files,rt transfer-plugin-install,rt transfer-settings,rt u,rt uc,rt udel,rt upload,rt user-create,rt users-create,rt users-delete,rt yarn,rt yarn-config,rt yarnc,ruby,ruby-config,rubyc,s,sast-server,sbom-enrich,scan,se,setup,skill delete,skill install,skill publish,skill search,skill update,skills delete,skills install,skills publish,skills search,skills update,source-mcp,st,stats,terraform,terraform-config,tf,tfc,twine,ucdx,upload-cdx,uv,worker add-secret,worker as,worker d,worker deploy,worker dr,worker dry-run,worker e,worker edit-schedule,worker eh,worker es,worker exec,worker exec-hist,worker execute,worker execution-history,worker i,worker init,worker le,worker list,worker list-event,worker ls,worker rm,worker test-run,worker tr,worker undeploy,xr ag,xr ago,xr am,xr an,xr ap,xr audit-go,xr audit-gradle,xr audit-mvn,xr audit-npm,xr audit-pip,xr cl,xr curl,xr offline-update,xr ou,xr s,xr scan,yarn,yarn-config,yarnc";

const JFROG_TOKENLESS_COMMANDS: &str = "api docs,api docs describe,api docs search,c add,c edit,c ex,c export,c im,c import,c remove,c rm,c s,c show,c use,completion bash,completion fish,completion zsh,config add,config edit,config ex,config export,config im,config import,config remove,config rm,config s,config show,config use,eot,evd gen-keys,evd generate-key-pair,exchange-oidc-token,generate-summary-markdown,git cc,git count-contributors,gsm,intro,login,mcp install,mcp show,mcp uninstall,options,package-alias install,package-alias status,package-alias uninstall,plugin ui,plugin uninstall,rt bc,rt bce,rt build-clean,rt build-collect-env,rt ndt,rt nuget-deps-tree,rt permission-target-template,rt ptt,rt replication-template,rt repo-template,rt rplt,rt rpt";

fn jfrog_invocation_is_secretless(args: &[OsString]) -> bool {
    let Some(args) = args
        .iter()
        .map(|arg| arg.to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return true;
    };
    let option_end = args
        .iter()
        .position(|argument| *argument == "--")
        .unwrap_or(args.len());
    let option_args = &args[..option_end];
    if option_args
        .iter()
        .any(|argument| matches!(*argument, "--help" | "-h"))
        || jfrog_uses_explicit_connection(option_args)
    {
        return true;
    }

    let mut command_args = option_args;
    while command_args.first().is_some_and(|argument| {
        matches!(*argument, "--ai-help" | "-ai-help")
            || argument.starts_with("--ai-help=")
            || argument.starts_with("-ai-help=")
    }) {
        command_args = &command_args[1..];
    }
    if command_args
        .first()
        .is_some_and(|argument| matches!(*argument, "--version" | "-v"))
    {
        return true;
    }
    if command_args.is_empty() || command_args[0].starts_with('-') {
        return true;
    }

    for length in (1..=command_args.len().min(3)).rev() {
        let command = command_args[..length].join(" ");
        match command.as_str() {
            "rt bad" | "rt build-add-dependencies" => {
                return !jfrog_true_flag(option_args, "--from-rt");
            }
            "rt bag" | "rt build-add-git" => {
                return jfrog_flag_value(option_args, "--config").is_none();
            }
            "agent plugins list" | "agent skills list" | "skill list" | "skills list" => {
                let harness = jfrog_flag_value(option_args, "--harness").is_some();
                let repo = jfrog_flag_value(option_args, "--repo").is_some();
                return !(repo || harness && jfrog_true_flag(option_args, "--check-updates"));
            }
            "plugin i" | "plugin install" | "plugin p" | "plugin publish" => {
                return std::env::var_os("JFROG_CLI_PLUGINS_SERVER")
                    .is_none_or(|value| value.is_empty());
            }
            _ => {}
        }
        if JFROG_TOKENLESS_COMMANDS
            .split(',')
            .any(|candidate| candidate == command)
        {
            return true;
        }
        if JFROG_AUTHENTICATED_COMMANDS
            .split(',')
            .any(|candidate| candidate == command)
        {
            return false;
        }
    }
    true
}

fn jfrog_uses_explicit_connection(args: &[&str]) -> bool {
    const AUTHORITIES: &[&str] = &[
        "--url",
        "--platform-url",
        "--artifactory-url",
        "--distribution-url",
        "--xray-url",
        "--mission-control-url",
        "--pipelines-url",
        "--dist-url",
        "--xr-url",
        "--mc-url",
        "--server-id",
        "--server-id-resolve",
        "--server-id-deploy",
    ];
    AUTHORITIES
        .iter()
        .any(|flag| jfrog_flag_value(args, flag).is_some())
        || jfrog_flag_value(args, "--access-token").is_some()
        || jfrog_true_flag(args, "--access-token-stdin")
        || jfrog_flag_value(args, "--user").is_some()
            && (jfrog_flag_value(args, "--password").is_some()
                || jfrog_true_flag(args, "--password-stdin"))
        || std::env::var_os("JFROG_CLI_SERVER_ID").is_some_and(|value| !value.is_empty())
        || std::env::var_os("JFROG_ACCESS_TOKEN").is_some_and(|value| !value.is_empty())
        || std::env::var_os("JFROG_USER").is_some_and(|value| !value.is_empty())
            && std::env::var_os("JFROG_PASSWORD").is_some_and(|value| !value.is_empty())
        || args.starts_with(&["ide", "setup"])
            && args.get(3).is_some_and(|argument| {
                argument.starts_with("https://") || argument.starts_with("http://")
            })
}

fn jfrog_flag_value<'a>(args: &'a [&str], flag: &str) -> Option<&'a str> {
    for (index, argument) in args.iter().enumerate() {
        if *argument == flag {
            return args
                .get(index + 1)
                .copied()
                .filter(|value| !value.is_empty());
        }
        if let Some(value) = argument.strip_prefix(&format!("{flag}=")) {
            return (!value.is_empty()).then_some(value);
        }
    }
    None
}

fn jfrog_true_flag(args: &[&str], flag: &str) -> bool {
    args.iter().any(|argument| {
        *argument == flag
            || argument
                .strip_prefix(&format!("{flag}="))
                .is_some_and(|value| matches!(value, "1" | "t" | "T" | "true" | "TRUE" | "True"))
    })
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
    fn jfrog_requests_secrets_only_for_reviewed_authenticated_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-jfrog");
        let env_names = [
            "JFROG_ACCESS_TOKEN",
            "JFROG_CLI_PLUGINS_SERVER",
            "JFROG_CLI_SERVER_ID",
            "JFROG_PASSWORD",
            "JFROG_USER",
        ];
        let previous_env = env_names.map(|name| (name, std::env::var_os(name)));
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir);
            for name in env_names {
                std::env::remove_var(name);
            }
        }

        for command in ["jf", "jfrog"] {
            let stub = stubs(wrapper("jfrog-cli").unwrap())
                .find(|stub| stub.command == command)
                .unwrap();
            let script_path = dir.join(command);
            let script = stub_script(stub, &Path::new("/opt/homebrew/bin").join(command));
            let invocation = |values: &[&str]| {
                std::iter::once(script_path.clone().into_os_string())
                    .chain(values.iter().map(OsString::from))
                    .collect::<Vec<_>>()
            };
            let secretless = |values: &[&str]| {
                invocation_is_secretless(&script_path, script.as_bytes(), &invocation(values))
            };

            for args in [
                &[][..],
                &["--help"][..],
                &["--version"][..],
                &["--ai-help", "config", "show"][..],
                &["config", "export"][..],
                &["login"][..],
                &["completion", "zsh"][..],
                &["mcp", "show"][..],
                &["plugin", "install", "hello-frog"][..],
                &["rt", "repo-template", "template.json"][..],
                &["rt", "build-add-dependencies", "target/release/*"][..],
                &["rt", "build-add-git", "."][..],
                &["agent", "skills", "list", "--harness", "codex"][..],
                &["api", "docs", "search", "artifact"][..],
                &["future-command"][..],
                &["custom-plugin", "run"][..],
            ] {
                assert!(secretless(args), "{command} {args:?}");
            }
            for args in [
                &["--ai-help", "rt", "search", "private/*"][..],
                &["rt", "s", "private/*"][..],
                &["rt", "upload", "dist/*", "repo/"][..],
                &["rt", "bad", "--from-rt", "repo/*"][..],
                &["rt", "bag", "--config", "issues.yaml"][..],
                &["agent", "skills", "list", "--repo", "skills-local"][..],
                &["agent", "plugins", "delete", "hello", "--version", "1.0.0"][..],
                &[
                    "agent",
                    "plugins",
                    "list",
                    "--harness",
                    "codex",
                    "--check-updates",
                ][..],
                &["api", "api/system/ping"][..],
                &["at", "p"][..],
                &["worker", "ls"][..],
                &["npm", "--", "install"][..],
                &["npm", "--version"][..],
                &["npm", "-v"][..],
                &["rt", "upload", "--", "--help"][..],
            ] {
                assert!(!secretless(args), "{command} {args:?}");
            }
            for args in [
                &["rt", "search", "private/*", "--url=https://other.jfrog.io"][..],
                &["rt", "search", "private/*", "--server-id", "other"][..],
                &[
                    "rt",
                    "search",
                    "private/*",
                    "--access-token",
                    "caller-token",
                ][..],
                &[
                    "rt",
                    "search",
                    "private/*",
                    "--user=caller",
                    "--password=caller-password",
                ][..],
                &[
                    "ide",
                    "setup",
                    "vscode",
                    "https://other.jfrog.io/artifactory/api/aieditorextensions/repo",
                ][..],
            ] {
                assert!(secretless(args), "{command} {args:?}");
            }

            unsafe { std::env::set_var("JFROG_CLI_PLUGINS_SERVER", "plugins") };
            assert!(!secretless(&["plugin", "install", "hello-frog"]));
            assert!(!secretless(&["plugin", "p"]));
            unsafe { std::env::remove_var("JFROG_CLI_PLUGINS_SERVER") };

            assert!(!invocation_is_secretless(
                &script_path,
                format!("{script}# changed\n").as_bytes(),
                &invocation(&["config", "show"]),
            ));
            assert!(!invocation_is_secretless(
                &script_path,
                script.as_bytes(),
                &[PathBuf::from("/tmp/not-the-stub").into_os_string()],
            ));
        }

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
            for (name, value) in previous_env {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
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
