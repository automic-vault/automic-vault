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
        "gptcommit" => gptcommit_invocation_is_secretless(args),
        "grafanactl" => grafanactl_invocation_is_secretless(args),
        "heroku" => heroku_invocation_is_secretless(args),
        "hcloud" => hcloud_invocation_is_secretless(args),
        "jf" | "jfrog" => jfrog_invocation_is_secretless(args),
        "mc" => minio_mc_invocation_is_secretless(args),
        "luarocks" => luarocks_invocation_is_secretless(args),
        "netlify" => netlify_invocation_is_secretless(
            args,
            std::env::var_os("NETLIFY_DB_BRANCH").is_some_and(|value| !value.is_empty()),
        ),
        "npm" => npm_invocation_is_secretless(args),
        "gotify" => gotify_invocation_is_secretless(args),
        "glab" => glab_invocation_is_secretless(args),
        "pnpm" => pnpm_invocation_is_secretless(args),
        "pulumi" => pulumi_invocation_is_secretless(args),
        "qwen" => qwen_invocation_is_secretless(args),
        "runpodctl" => runpodctl_invocation_is_secretless(args),
        "s3cmd" => s3cmd_invocation_is_secretless(args),
        "sentry-cli" => sentry_cli_invocation_is_secretless(args),
        "snow" => snowflake_cli_invocation_is_secretless(args),
        "snyk" => snyk_invocation_is_secretless(args),
        "tx" => transifex_cli_invocation_is_secretless(args),
        "travis" => travis_invocation_is_secretless(args),
        "vault" => vault_invocation_is_secretless(args),
        "akamai" => akamai_invocation_is_secretless(args),
        "algolia" => algolia_invocation_is_secretless(args),
        "vultr-cli" => vultr_invocation_is_secretless(args),
        "wsk" => wsk_invocation_is_secretless(args),
        "vt" => virustotal_invocation_is_secretless(args),
        "doctl" => doctl_invocation_is_secretless(args),
        "fly" | "flyctl" => flyctl_invocation_is_secretless(args),
        "k6" => k6_invocation_is_secretless(args),
        "twine" => twine_invocation_is_secretless(args),
        "vagrant" => vagrant_invocation_is_secretless(args),
        "hf" => hf_invocation_is_secretless(args),
        "composer" => composer_invocation_is_secretless(args),
        _ => false,
    }
}

fn luarocks_invocation_is_secretless(args: &[OsString]) -> bool {
    let Some(args) = args
        .iter()
        .map(|argument| argument.to_str())
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
        .any(|argument| matches!(*argument, "--help" | "-h" | "--version"))
        || ["--api-key", "--temp-key", "--server", "--from"]
            .iter()
            .any(|flag| luarocks_flag_value(option_args, flag).is_some())
    {
        return true;
    }

    const FLAGS: &[&str] = &[
        "--dev",
        "--local",
        "--global",
        "--no-project",
        "--force-lock",
        "--verbose",
    ];
    const OPTIONS: &[&str] = &[
        "--only-server",
        "--only-from",
        "--only-sources",
        "--only-sources-from",
        "--namespace",
        "--lua-dir",
        "--lua-version",
        "--tree",
        "--to",
        "--timeout",
        "--project-tree",
    ];
    let mut index = 0;
    while index < option_args.len() {
        let argument = option_args[index];
        if luarocks_assignment(argument) || FLAGS.contains(&argument) {
            index += 1;
        } else if OPTIONS.contains(&argument) {
            if option_args.get(index + 1).is_none() {
                return true;
            }
            index += 2;
        } else if OPTIONS
            .iter()
            .any(|option| argument.starts_with(&format!("{option}=")))
        {
            index += 1;
        } else if argument.starts_with('-') {
            return true;
        } else {
            return argument != "upload";
        }
    }
    true
}

fn luarocks_flag_value<'a>(args: &'a [&str], flag: &str) -> Option<&'a str> {
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

fn luarocks_assignment(argument: &str) -> bool {
    let Some((name, _)) = argument.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_uppercase())
        && chars.all(|character| {
            character == '_' || character.is_ascii_uppercase() || character.is_ascii_digit()
        })
}

// Reviewed against MinIO Client RELEASE.2025-08-13T08-35-41Z. The migrated
// bundle contains only aliases whose sanitized config entry retains an access
// key; inject it only when a built-in command actually names one of them.
const MINIO_MC_GLOBAL_FLAGS: &[&str] = &[
    "--quiet",
    "-q",
    "--disable-pager",
    "--dp",
    "--no-color",
    "--json",
    "--debug",
    "--insecure",
];
const MINIO_MC_GLOBAL_OPTIONS: &[&str] = &[
    "--config-dir",
    "-C",
    "--resolve",
    "--limit-upload",
    "--limit-download",
    "--custom-header",
    "-H",
];

fn minio_mc_invocation_is_secretless(args: &[OsString]) -> bool {
    let Some(args) = args
        .iter()
        .map(|argument| argument.to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return true;
    };
    let option_end = args
        .iter()
        .position(|argument| *argument == "--")
        .unwrap_or(args.len());
    let option_args = &args[..option_end];
    if option_args.iter().any(|argument| {
        matches!(
            *argument,
            "--help" | "-h" | "--version" | "-v" | "--autocompletion"
        )
    }) || minio_mc_flag_value(option_args, &["--config-dir", "-C"]).is_some()
        || ["MC_CONFIG_DIR", "MC_CONFIG_ENV_FILE"]
            .iter()
            .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
    {
        return true;
    }

    let Some((command, command_index)) = minio_mc_command(option_args) else {
        return true;
    };
    let aliases = minio_mc_protected_aliases();
    if aliases.is_empty() {
        return true;
    }
    if command == "alias" {
        let Some((subcommand, subcommand_index)) =
            minio_mc_command(&option_args[command_index + 1..])
        else {
            return true;
        };
        if !matches!(subcommand, "list" | "ls") {
            return true;
        }
        let named_alias =
            minio_mc_command(&option_args[command_index + subcommand_index + 2..]).is_some();
        return named_alias && !minio_mc_uses_protected_alias(&args, &aliases)
            || aliases
                .iter()
                .all(|alias| minio_mc_has_ambient_alias(alias));
    }
    if !matches!(
        command,
        "admin"
            | "anonymous"
            | "batch"
            | "cp"
            | "cat"
            | "cors"
            | "diff"
            | "du"
            | "encrypt"
            | "event"
            | "find"
            | "get"
            | "head"
            | "ilm"
            | "idp"
            | "license"
            | "legalhold"
            | "ls"
            | "mb"
            | "mv"
            | "mirror"
            | "od"
            | "ping"
            | "pipe"
            | "put"
            | "quota"
            | "rm"
            | "retention"
            | "rb"
            | "replicate"
            | "ready"
            | "sql"
            | "stat"
            | "support"
            | "share"
            | "tree"
            | "tag"
            | "undo"
            | "version"
            | "watch"
    ) {
        return true;
    }
    !minio_mc_uses_protected_alias(&args, &aliases)
}

fn minio_mc_command<'a>(args: &[&'a str]) -> Option<(&'a str, usize)> {
    let mut index = 0;
    while index < args.len() {
        let argument = args[index];
        if MINIO_MC_GLOBAL_FLAGS.contains(&argument) {
            index += 1;
        } else if MINIO_MC_GLOBAL_OPTIONS.contains(&argument) {
            args.get(index + 1)?;
            index += 2;
        } else if MINIO_MC_GLOBAL_OPTIONS
            .iter()
            .any(|option| argument.starts_with(&format!("{option}=")))
        {
            index += 1;
        } else if argument.starts_with('-') {
            return None;
        } else {
            return Some((argument, index));
        }
    }
    None
}

fn minio_mc_flag_value<'a>(args: &'a [&str], flags: &[&str]) -> Option<&'a str> {
    for (index, argument) in args.iter().enumerate() {
        for flag in flags {
            if *argument == *flag {
                return args
                    .get(index + 1)
                    .copied()
                    .filter(|value| !value.is_empty());
            }
            if let Some(value) = argument.strip_prefix(&format!("{flag}=")) {
                return (!value.is_empty()).then_some(value);
            }
        }
    }
    None
}

fn minio_mc_protected_aliases() -> Vec<String> {
    let Some(home) = std::env::var_os("HOME") else {
        return Vec::new();
    };
    let Ok(contents) = fs::read_to_string(PathBuf::from(home).join(".mc/config.json")) else {
        return Vec::new();
    };
    let Ok(config) = serde_json::from_str::<serde_json::Value>(&contents) else {
        return Vec::new();
    };
    config
        .get("aliases")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flat_map(|aliases| aliases.iter())
        .filter(|(_, config)| {
            config
                .get("accessKey")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| !value.is_empty())
        })
        .map(|(alias, _)| alias.clone())
        .collect()
}

fn minio_mc_uses_protected_alias(args: &[&str], aliases: &[String]) -> bool {
    let mut values = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let argument = args[index];
        if argument == "--" {
            values.extend_from_slice(&args[index + 1..]);
            break;
        }
        if MINIO_MC_GLOBAL_FLAGS.contains(&argument) {
            index += 1;
        } else if MINIO_MC_GLOBAL_OPTIONS.contains(&argument) {
            index += 2;
        } else if MINIO_MC_GLOBAL_OPTIONS
            .iter()
            .any(|option| argument.starts_with(&format!("{option}=")))
        {
            index += 1;
        } else {
            values.push(argument);
            index += 1;
        }
    }
    aliases.iter().any(|alias| {
        !minio_mc_has_ambient_alias(alias)
            && values.iter().any(|argument| {
                let value = argument
                    .split_once('=')
                    .map_or(*argument, |(_, value)| value);
                value == alias || value.starts_with(&format!("{alias}/"))
            })
    })
}

fn minio_mc_has_ambient_alias(alias: &str) -> bool {
    std::env::var_os(format!("MC_HOST_{alias}")).is_some_and(|value| !value.is_empty())
}

fn pulumi_invocation_is_secretless(args: &[OsString]) -> bool {
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
    if pulumi_boolean_flag(option_args, "--help", "-h")
        || pulumi_boolean_flag(option_args, "--version", "")
    {
        return true;
    }

    let Some(command_index) = pulumi_command_index(option_args) else {
        return true;
    };
    let command_args = &option_args[command_index..];
    let command = command_args[0];

    if command_args.len() == 1
        && matches!(
            command,
            "api"
                | "deployment"
                | "env"
                | "insights"
                | "org"
                | "package"
                | "plugin"
                | "policy"
                | "project"
                | "schema"
                | "state"
                | "template"
        )
    {
        return true;
    }

    // Reviewed against Pulumi v3.261.0. Only commands that may consume the
    // Pulumi Cloud token are positive matches; unknown future commands remain
    // tokenless.
    if !matches!(
        command,
        "about"
            | "api"
            | "cancel"
            | "config"
            | "console"
            | "convert"
            | "deployment"
            | "destroy"
            | "do"
            | "env"
            | "import"
            | "insights"
            | "install"
            | "login"
            | "logs"
            | "neo"
            | "new"
            | "org"
            | "package"
            | "plugin"
            | "policy"
            | "preview"
            | "project"
            | "refresh"
            | "schema"
            | "stack"
            | "state"
            | "template"
            | "up"
            | "watch"
            | "whoami"
    ) {
        return true;
    }

    match command_args {
        ["about", "env", ..]
        | ["stack", "unselect", ..]
        | ["plugin", "remove" | "rm" | "delete", ..]
        | ["package", "new" | "create" | "setup", ..]
        | ["policy", "new" | "create" | "setup", ..] => true,
        ["plugin", "list" | "ls", rest @ ..] => !pulumi_boolean_flag(rest, "--project", "-p"),
        ["new", rest @ ..] => {
            pulumi_boolean_flag(rest, "--generate-only", "-g")
                || pulumi_boolean_flag(rest, "--list-templates", "")
        }
        ["login", rest @ ..] => pulumi_login_is_secretless(rest),
        _ => false,
    }
}

fn pulumi_command_index(args: &[&str]) -> Option<usize> {
    const BOOLEAN_OPTIONS: &[&str] = &[
        "--disable-integrity-checking",
        "--emoji",
        "--fully-qualify-stack-names",
        "--help",
        "--logflow",
        "--logtostderr",
        "--non-interactive",
        "--version",
        "-Q",
        "-e",
        "-h",
    ];
    const VALUE_OPTIONS: &[&str] = &[
        "--color",
        "--cwd",
        "--memprofilerate",
        "--otel-traces",
        "--profiling",
        "--tracing",
        "--tracing-header",
        "--verbose",
        "-C",
        "-v",
    ];

    let mut index = 0;
    while let Some(argument) = args.get(index) {
        if !argument.starts_with('-') {
            return Some(index);
        }
        if BOOLEAN_OPTIONS.contains(argument)
            || argument.split_once('=').is_some_and(|(name, _)| {
                BOOLEAN_OPTIONS.contains(&name) || VALUE_OPTIONS.contains(&name)
            })
            || ["-C", "-v"]
                .iter()
                .any(|option| argument.starts_with(option) && argument.len() > option.len())
        {
            index += 1;
        } else if VALUE_OPTIONS.contains(argument) {
            args.get(index + 1)?;
            index += 2;
        } else {
            return None;
        }
    }
    None
}

fn pulumi_boolean_flag(args: &[&str], long: &str, short: &str) -> bool {
    args.iter().any(|argument| {
        *argument == long
            || !short.is_empty() && *argument == short
            || argument
                .strip_prefix(long)
                .is_some_and(|value| value == "=true")
            || !short.is_empty()
                && argument
                    .strip_prefix(short)
                    .is_some_and(|value| value == "=true")
    })
}

fn pulumi_login_is_secretless(args: &[&str]) -> bool {
    if pulumi_boolean_flag(args, "--local", "-l") {
        return true;
    }

    let mut backend = None;
    let mut explicit_oidc = false;
    let mut index = 0;
    while let Some(argument) = args.get(index) {
        if let Some(value) = argument.strip_prefix("--cloud-url=") {
            backend = Some(value);
        } else if let Some(value) = argument.strip_prefix("-c=").or_else(|| {
            argument
                .strip_prefix("-c")
                .filter(|value| !value.is_empty())
        }) {
            backend = Some(value);
        } else if let Some(value) = argument.strip_prefix("--oidc-token=") {
            explicit_oidc = !value.is_empty();
        } else if matches!(*argument, "--cloud-url" | "-c" | "--oidc-token") {
            let value = args.get(index + 1).copied().unwrap_or_default();
            if *argument == "--oidc-token" {
                explicit_oidc = !value.is_empty();
            } else {
                backend = Some(value);
            }
            index += 1;
        } else if matches!(
            *argument,
            "--default-org" | "--oidc-expiration" | "--oidc-org" | "--oidc-team" | "--oidc-user"
        ) {
            index += 1;
        } else if !argument.starts_with('-') && backend.is_none() {
            backend = Some(argument);
        }
        index += 1;
    }

    explicit_oidc || backend.is_some_and(pulumi_backend_is_diy)
}

fn pulumi_backend_is_diy(backend: &str) -> bool {
    ["file://", "s3://", "gs://", "azblob://", "postgres://"]
        .iter()
        .any(|scheme| backend.starts_with(scheme))
}

// Reviewed against @qwen-code/qwen-code 0.23.0. Keep this positive Secret
// route exact: every unlisted management command runs without the migrated
// environment assignment bundle.
fn qwen_invocation_is_secretless(args: &[OsString]) -> bool {
    if qwen_early_exit(args) {
        return true;
    }
    if args
        .iter()
        .take_while(|arg| arg.as_os_str() != "--")
        .filter_map(|arg| arg.to_str())
        .any(|arg| {
            arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 2 && !arg.contains('=')
        })
    {
        // Qwen/yargs accepts some compact short-option clusters, but their
        // interaction with the default agent command is not command-like.
        return false;
    }

    let Some((command, command_index)) = qwen_next_word(args, 0) else {
        return args
            .iter()
            .take_while(|arg| arg.as_os_str() != "--")
            .any(|arg| {
                arg.to_str()
                    .is_some_and(|arg| arg.starts_with('-') && !qwen_known_option(arg))
            });
    };
    match command {
        "auth" | "hook" | "hooks" | "extensions" | "sessions" | "update" => true,
        "serve" => false,
        "mcp" => {
            let subcommand = if command_index == 0 && args.get(1).is_some_and(|arg| arg == "--") {
                args.get(2).and_then(|arg| arg.to_str())
            } else {
                qwen_next_word(args, command_index + 1).map(|(subcommand, _)| subcommand)
            };
            subcommand != Some("reconnect")
        }
        "channel" => qwen_next_word(args, command_index + 1)
            .is_none_or(|(subcommand, _)| !matches!(subcommand, "start" | "daemon-worker")),
        "review" => qwen_next_word(args, command_index + 1)
            .is_none_or(|(subcommand, _)| subcommand != "run"),
        // Qwen's default command treats every other positional as an agent prompt.
        _ => false,
    }
}

fn qwen_early_exit(args: &[OsString]) -> bool {
    args.iter()
        .take_while(|arg| arg.as_os_str() != "--")
        .filter_map(|arg| arg.to_str())
        .any(|arg| {
            matches!(
                arg,
                "--help"
                    | "-h"
                    | "--help=true"
                    | "-h=true"
                    | "--version"
                    | "-v"
                    | "--version=true"
                    | "-v=true"
                    | "--list-extensions"
                    | "-l"
                    | "--list-extensions=true"
                    | "-l=true"
            ) || arg.starts_with('-')
                && !arg.starts_with("--")
                && arg.len() > 2
                && arg[1..].chars().all(|flag| "dhvlsyc".contains(flag))
                && arg[1..].chars().any(|flag| "hvl".contains(flag))
        })
}

fn qwen_next_word(args: &[OsString], mut index: usize) -> Option<(&str, usize)> {
    while index < args.len() {
        let arg = args[index].to_str()?;
        if arg == "--" {
            return None;
        }
        if !arg.starts_with('-') {
            return Some((arg, index));
        }
        if !qwen_known_option(arg) {
            return None;
        }
        if qwen_value_option(arg) && !arg.contains('=') {
            index += 1;
        } else if qwen_boolean_option(arg)
            && args
                .get(index + 1)
                .and_then(|arg| arg.to_str())
                .is_some_and(|arg| matches!(arg, "true" | "false"))
        {
            index += 1;
        }
        index += 1;
    }
    None
}

fn qwen_known_option(arg: &str) -> bool {
    qwen_value_option(arg) || qwen_boolean_option(arg)
}

fn qwen_value_option(arg: &str) -> bool {
    matches!(
        arg.split_once('=').map_or(arg, |(flag, _)| flag),
        "--telemetry-target"
            | "--telemetry-otlp-endpoint"
            | "--telemetry-otlp-protocol"
            | "--telemetry-outfile"
            | "--proxy"
            | "--model"
            | "-m"
            | "--fallback-model"
            | "--prompt"
            | "-p"
            | "--prompt-interactive"
            | "-i"
            | "--system-prompt"
            | "--append-system-prompt"
            | "--output-style"
            | "--sandbox-image"
            | "--approval-mode"
            | "--channel"
            | "--allowed-mcp-server-names"
            | "--mcp-config"
            | "--allowed-tools"
            | "--extensions"
            | "-e"
            | "--include-directories"
            | "--add-dir"
            | "--openai-logging-dir"
            | "--openai-api-key"
            | "--openai-base-url"
            | "--input-format"
            | "--output-format"
            | "-o"
            | "--json-fd"
            | "--json-file"
            | "--json-schema"
            | "--input-file"
            | "--resume"
            | "-r"
            | "--session-id"
            | "--worktree"
            | "--max-session-turns"
            | "--max-wall-time"
            | "--max-tool-calls"
            | "--max-subagent-depth"
            | "--core-tools"
            | "--exclude-tools"
            | "--disabled-slash-commands"
            | "--auth-type"
            | "--sandbox-session-id"
    )
}

fn qwen_boolean_option(arg: &str) -> bool {
    matches!(
        arg.split_once('=').map_or(arg, |(flag, _)| flag),
        "--help"
            | "-h"
            | "--version"
            | "-v"
            | "--telemetry"
            | "--telemetry-log-prompts"
            | "--debug"
            | "-d"
            | "--bare"
            | "--safe-mode"
            | "--insecure"
            | "--chat-recording"
            | "--sandbox"
            | "-s"
            | "--yolo"
            | "-y"
            | "--acp"
            | "--experimental-acp"
            | "--experimental-skills"
            | "--experimental-lsp"
            | "--restore-ask-user-question"
            | "--list-extensions"
            | "-l"
            | "--openai-logging"
            | "--screen-reader"
            | "--include-partial-messages"
            | "--continue"
            | "-c"
            | "--fork-session"
    )
}

// Reviewed against runpodctl 2.8.0. Unknown commands stay tokenless because
// Cobra rejects them; only commands that construct a RunPod API client receive
// the migrated API key.
fn runpodctl_invocation_is_secretless(args: &[OsString]) -> bool {
    if args.is_empty() || runpodctl_help_request(args) {
        return true;
    }
    let Some(words) = runpodctl_command_words(args) else {
        return true;
    };
    !runpodctl_needs_api_key(&words)
}

fn runpodctl_help_request(args: &[OsString]) -> bool {
    args.iter()
        .take_while(|arg| arg.as_os_str() != "--")
        .enumerate()
        .any(|(index, arg)| {
            let Some(arg) = arg.to_str() else {
                return false;
            };
            let enabled = matches!(arg, "--help" | "-h" | "--help=true" | "-h=true");
            if !enabled || arg.contains('=') || index == 0 {
                return enabled;
            }
            let Some(previous) = args[index - 1].to_str() else {
                return false;
            };
            !previous.starts_with('-')
                || previous.contains('=')
                || runpodctl_boolean_option(previous)
        })
}

fn runpodctl_command_words(args: &[OsString]) -> Option<Vec<&str>> {
    let mut words = Vec::with_capacity(2);
    let mut index = 0;
    while index < args.len() && words.len() < 2 {
        let arg = args[index].to_str()?;
        if arg == "--" {
            break;
        }
        if matches!(
            arg,
            "--version" | "-v" | "--version=true" | "-v=true" | "--version=false" | "-v=false"
        ) && words.is_empty()
        {
            return Some(vec!["version"]);
        }
        if matches!(arg, "--output" | "-o") {
            index += 2;
            continue;
        }
        if arg.starts_with("--output=")
            || arg.starts_with("-o=")
            || arg.starts_with("-o") && arg.len() > 2
        {
            index += 1;
            continue;
        }
        if arg.starts_with('-') {
            if words.is_empty() && matches!(arg, "--help=false" | "-h=false") {
                index += 1;
                continue;
            }
            return None;
        }
        words.push(arg);
        index += 1;
    }
    Some(words)
}

fn runpodctl_boolean_option(arg: &str) -> bool {
    matches!(
        arg.split_once('=').map_or(arg, |(flag, _)| flag),
        "--all"
            | "-a"
            | "--allfields"
            | "--clear-models"
            | "--community"
            | "-c"
            | "--communityCloud"
            | "--create-upload"
            | "--flash-boot"
            | "--global-networking"
            | "--include-env"
            | "--include-machine"
            | "--include-network-volume"
            | "--include-template"
            | "--include-unavailable"
            | "--include-workers"
            | "--init"
            | "-i"
            | "--prefix-pod-logs"
            | "--public-ip"
            | "--secure"
            | "-s"
            | "--secureCloud"
            | "--select-volume"
            | "--serverless"
            | "--ssh"
            | "--startSSH"
            | "--verbose"
            | "-v"
            | "--wait-for-hash"
    )
}

fn runpodctl_needs_api_key(words: &[&str]) -> bool {
    let Some(command) = words.first().copied() else {
        return false;
    };
    let subcommand = words.get(1).copied();
    match command {
        "doctor" | "user" | "account" | "me" => true,
        "pod" | "pods" => subcommand.is_some_and(|subcommand| {
            matches!(
                subcommand,
                "list"
                    | "get"
                    | "create"
                    | "update"
                    | "start"
                    | "stop"
                    | "restart"
                    | "reset"
                    | "delete"
                    | "rm"
                    | "remove"
            )
        }),
        "serverless" | "sls" => subcommand.is_some_and(|subcommand| {
            matches!(
                subcommand,
                "list" | "get" | "create" | "update" | "delete" | "rm" | "remove"
            )
        }),
        "template" | "tpl" | "templates" => subcommand.is_some_and(|subcommand| {
            matches!(
                subcommand,
                "list" | "search" | "get" | "create" | "update" | "delete" | "rm" | "remove"
            )
        }),
        "model" => subcommand.is_some_and(|subcommand| {
            matches!(
                subcommand,
                "list" | "ls" | "add" | "remove" | "rm" | "delete"
            )
        }),
        "network-volume" | "nv" => subcommand.is_some_and(|subcommand| {
            matches!(
                subcommand,
                "list" | "get" | "create" | "update" | "delete" | "rm" | "remove"
            )
        }),
        "registry" | "reg" => subcommand.is_some_and(|subcommand| {
            matches!(
                subcommand,
                "list" | "get" | "create" | "delete" | "rm" | "remove"
            )
        }),
        "hub" => {
            subcommand.is_some_and(|subcommand| matches!(subcommand, "list" | "search" | "get"))
        }
        "gpu" | "gpus" | "datacenter" | "dc" | "datacenters" => subcommand == Some("list"),
        "billing" => subcommand.is_some_and(|subcommand| {
            matches!(
                subcommand,
                "pods" | "serverless" | "sls" | "endpoints" | "network-volume" | "nv"
            )
        }),
        "ssh" => subcommand.is_some_and(|subcommand| {
            matches!(
                subcommand,
                "list-keys" | "add-key" | "remove-key" | "info" | "connect"
            )
        }),
        "exec" => subcommand == Some("python"),
        "project" => {
            subcommand.is_some_and(|subcommand| matches!(subcommand, "dev" | "start" | "deploy"))
        }
        "get" => subcommand
            .is_some_and(|subcommand| matches!(subcommand, "cloud" | "pod" | "models" | "model")),
        "create" => {
            subcommand.is_some_and(|subcommand| matches!(subcommand, "pod" | "pods" | "model"))
        }
        "remove" => {
            subcommand.is_some_and(|subcommand| matches!(subcommand, "pod" | "pods" | "model"))
        }
        "start" | "stop" => subcommand == Some("pod"),
        _ => false,
    }
}

// Reviewed against s3cmd 2.4.0. Every real command signs an S3 or CloudFront
// request; only parser exits and unknown commands run without the migrated
// AWS/GPG assignment bundle.
fn s3cmd_invocation_is_secretless(args: &[OsString]) -> bool {
    let mut command = None;
    let mut protected_option = false;
    let mut index = 0;
    while index < args.len() {
        let Some(arg) = args[index].to_str() else {
            return command.is_none();
        };
        if arg == "--" {
            if command.is_none() {
                command = args.get(index + 1).and_then(|arg| arg.to_str());
            }
            break;
        }
        if arg == "-" || !arg.starts_with('-') {
            command.get_or_insert(arg);
            index += 1;
            continue;
        }
        if arg.starts_with("--") {
            let (option, attached_value) = arg
                .split_once('=')
                .map_or((arg, false), |(key, _)| (key, true));
            let Some(kind) = s3cmd_long_option(option) else {
                return true;
            };
            if attached_value && kind != S3cmdOption::Value {
                return true;
            }
            match kind {
                S3cmdOption::LocalExit => return true,
                S3cmdOption::Protected => protected_option = true,
                S3cmdOption::Value if !attached_value => index += 1,
                S3cmdOption::Value | S3cmdOption::Flag => {}
            }
            index += 1;
            continue;
        }

        let Some((kind, consumes_next)) = s3cmd_short_options(arg) else {
            return true;
        };
        if kind == S3cmdOption::LocalExit {
            return true;
        }
        if consumes_next {
            index += 1;
        }
        index += 1;
    }

    !protected_option && command.is_none_or(|command| !S3CMD_COMMANDS.contains(&command))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum S3cmdOption {
    LocalExit,
    Protected,
    Value,
    Flag,
}

fn s3cmd_long_option(option: &str) -> Option<S3cmdOption> {
    let options = [
        (&["--help", "--version"][..], S3cmdOption::LocalExit),
        (
            &["--configure", "--dump-config"][..],
            S3cmdOption::Protected,
        ),
        (S3CMD_VALUE_OPTIONS, S3cmdOption::Value),
        (S3CMD_FLAG_OPTIONS, S3cmdOption::Flag),
    ];
    if let Some(kind) = options
        .iter()
        .find_map(|(names, kind)| names.contains(&option).then_some(*kind))
    {
        return Some(kind);
    }

    let mut matches = options.iter().flat_map(|(names, kind)| {
        names
            .iter()
            .filter(move |name| name.starts_with(option))
            .map(move |_| *kind)
    });
    let kind = matches.next()?;
    matches.next().is_none().then_some(kind)
}

fn s3cmd_short_options(arg: &str) -> Option<(S3cmdOption, bool)> {
    let mut flags = arg[1..].chars().peekable();
    while let Some(flag) = flags.next() {
        match flag {
            'h' => return Some((S3cmdOption::LocalExit, false)),
            'c' | 'D' | 'm' => return Some((S3cmdOption::Value, flags.peek().is_none())),
            'n' | 's' | 'e' | 'f' | 'r' | 'P' | 'p' | 'M' | 'H' | 'v' | 'd' | 'F' | 'q' | 'l' => {}
            _ => return None,
        }
    }
    Some((S3cmdOption::Flag, false))
}

const S3CMD_VALUE_OPTIONS: &[&str] = &[
    "--config",
    "--access_key",
    "--secret_key",
    "--access_token",
    "--upload-id",
    "--acl-grant",
    "--acl-revoke",
    "--restore-days",
    "--restore-priority",
    "--max-delete",
    "--limit",
    "--add-destination",
    "--exclude",
    "--exclude-from",
    "--rexclude",
    "--rexclude-from",
    "--include",
    "--include-from",
    "--rinclude",
    "--rinclude-from",
    "--files-from",
    "--region",
    "--bucket-location",
    "--host",
    "--host-bucket",
    "--storage-class",
    "--access-logging-target-prefix",
    "--default-mime-type",
    "--mime-type",
    "--add-header",
    "--remove-header",
    "--server-side-encryption-kms-id",
    "--encoding",
    "--add-encoding-exts",
    "--multipart-chunk-size-mb",
    "--ws-index",
    "--ws-error",
    "--expiry-date",
    "--expiry-days",
    "--expiry-prefix",
    "--cf-add-cname",
    "--cf-remove-cname",
    "--cf-comment",
    "--cf-default-root-object",
    "--cache-file",
    "--ca-certs",
    "--ssl-cert",
    "--ssl-key",
    "--limit-rate",
    "--max-retries",
    "--content-disposition",
    "--content-type",
];

const S3CMD_FLAG_OPTIONS: &[&str] = &[
    "--dry-run",
    "--ssl",
    "--no-ssl",
    "--encrypt",
    "--no-encrypt",
    "--force",
    "--continue",
    "--continue-put",
    "--skip-existing",
    "--recursive",
    "--check-md5",
    "--no-check-md5",
    "--acl-public",
    "--acl-private",
    "--delete-removed",
    "--no-delete-removed",
    "--delete-after",
    "--delay-updates",
    "--delete-after-fetch",
    "--preserve",
    "--no-preserve",
    "--keep-dirs",
    "--reduced-redundancy",
    "--rr",
    "--no-reduced-redundancy",
    "--no-rr",
    "--no-access-logging",
    "--guess-mime-type",
    "--no-guess-mime-type",
    "--no-mime-magic",
    "--server-side-encryption",
    "--verbatim",
    "--disable-multipart",
    "--list-md5",
    "--list-allow-unordered",
    "--human-readable-sizes",
    "--skip-destination-validation",
    "--progress",
    "--no-progress",
    "--stats",
    "--enable",
    "--disable",
    "--cf-invalidate",
    "--cf-invalidate-default-index",
    "--cf-no-invalidate-default-index-root",
    "--verbose",
    "--debug",
    "--follow-symlinks",
    "--quiet",
    "--check-certificate",
    "--no-check-certificate",
    "--check-hostname",
    "--no-check-hostname",
    "--signature-v2",
    "--no-connection-pooling",
    "--requester-pays",
    "--long-listing",
    "--stop-on-error",
];

const S3CMD_COMMANDS: &[&str] = &[
    "mb",
    "rb",
    "ls",
    "la",
    "put",
    "get",
    "del",
    "rm",
    "restore",
    "sync",
    "du",
    "info",
    "cp",
    "modify",
    "mv",
    "setacl",
    "setversioning",
    "setownership",
    "setblockpublicaccess",
    "setobjectlegalhold",
    "setobjectretention",
    "setpolicy",
    "delpolicy",
    "setcors",
    "delcors",
    "payer",
    "multipart",
    "abortmp",
    "listmp",
    "accesslog",
    "sign",
    "signurl",
    "fixbucket",
    "settagging",
    "gettagging",
    "deltagging",
    "ws-create",
    "ws-delete",
    "ws-info",
    "expire",
    "setlifecycle",
    "getlifecycle",
    "dellifecycle",
    "setnotification",
    "getnotification",
    "delnotification",
    "cflist",
    "cfinfo",
    "cfcreate",
    "cfdelete",
    "cfmodify",
    "cfinval",
    "cfinvalinfo",
];

// Reviewed against zurawiki/gptcommit v0.5.17. Configuration and hook
// management never consume the OpenAI key. The hook only reaches its LLM
// client for a new commit or an amend enabled by configuration.
fn gptcommit_invocation_is_secretless(args: &[OsString]) -> bool {
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
    let args = &args[..option_end];
    if args
        .iter()
        .any(|arg| matches!(*arg, "--help" | "-h" | "--version" | "-V"))
        || ["GPTCOMMIT__OPENAI__API_KEY", "OPENAI_API_KEY"]
            .iter()
            .any(|key| std::env::var_os(key).is_some_and(|value| !value.is_empty()))
        || std::env::var_os("GPTCOMMIT__MODEL_PROVIDER")
            .is_some_and(|value| value == "tester-foobar")
    {
        return true;
    }

    let Some(command_index) = args
        .iter()
        .position(|arg| !matches!(*arg, "--verbose" | "-v"))
    else {
        return true;
    };
    if args[command_index] != "prepare-commit-msg" {
        return true;
    }
    let args = &args[command_index + 1..];
    let has_commit_message_file = option_value(args, "--commit-msg-file").is_some();
    let commit_source = option_value(args, "--commit-source");
    !(has_commit_message_file && matches!(commit_source, Some("" | "commit")))
}

fn option_value<'a>(args: &'a [&str], option: &str) -> Option<&'a str> {
    args.iter().enumerate().find_map(|(index, argument)| {
        if *argument == option {
            return args.get(index + 1).copied();
        }
        argument
            .strip_prefix(option)
            .and_then(|value| value.strip_prefix('='))
    })
}

// Reviewed against grafana/grafanactl v0.1.10. Keep this as a positive list:
// config manipulation is local, while config check and every runnable
// resources command contact Grafana. Explicit context/server selection must
// not inherit a credential migrated from the default context.
fn grafanactl_invocation_is_secretless(args: &[OsString]) -> bool {
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
    let args = &args[..option_end];
    if args
        .iter()
        .any(|arg| matches!(*arg, "--help" | "-h" | "--version"))
        || grafanactl_uses_another_context(args)
    {
        return true;
    }

    let mut path = Vec::new();
    let mut index = 0;
    while index < args.len() && path.len() < 2 {
        let argument = args[index];
        if matches!(argument, "--config" | "--context") {
            if index + 1 >= args.len() {
                return true;
            }
            index += 2;
            continue;
        }
        if matches!(argument, "--no-color" | "--verbose")
            || argument.starts_with("--no-color=")
            || argument.starts_with("--verbose=")
            || argument
                .strip_prefix('-')
                .is_some_and(|value| !value.is_empty() && value.chars().all(|ch| ch == 'v'))
            || argument.starts_with("--config=")
            || argument.starts_with("--context=")
        {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            return true;
        }
        path.push(argument);
        index += 1;
    }

    !matches!(
        path.as_slice(),
        ["config", "check"]
            | [
                "resources",
                "delete" | "edit" | "get" | "list" | "pull" | "push" | "serve" | "validate"
            ]
    )
}

fn grafanactl_uses_another_context(args: &[&str]) -> bool {
    if [
        "GRAFANACTL_CONFIG",
        "GRAFANACTL_ENV_ASSIGNMENTS",
        "GRAFANA_SERVER",
        "GRAFANA_TOKEN",
        "GRAFANA_USER",
    ]
    .iter()
    .any(|key| std::env::var_os(key).is_some_and(|value| !value.is_empty()))
    {
        return true;
    }

    args.iter().enumerate().any(|(index, argument)| {
        if matches!(*argument, "--config" | "--context") {
            return args.get(index + 1).is_some_and(|value| !value.is_empty());
        }
        ["--config=", "--context="].iter().any(|prefix| {
            argument
                .strip_prefix(prefix)
                .is_some_and(|value| !value.is_empty())
        })
    })
}

// Reviewed against heroku/cli v11.10.0. Heroku loads runtime plugins, so keep
// the Secret boundary to this exact audited core vocabulary; plugin, future,
// local, login, update, and passthrough commands stay tokenless.
const HEROKU_AUTHENTICATED_COMMANDS: &str = "2fa,access,access:add,access:remove,access:update,accounts:add,addons,addons:add,addons:attach,addons:create,addons:destroy,addons:detach,addons:docs,addons:downgrade,addons:info,addons:open,addons:plans,addons:remove,addons:rename,addons:services,addons:upgrade,addons:wait,apps,apps:create,apps:delete,apps:destroy,apps:diff,apps:errors,apps:favorites,apps:favorites:add,apps:favorites:remove,apps:info,apps:join,apps:leave,apps:list,apps:lock,apps:open,apps:rename,apps:stacks,apps:stacks:set,apps:transfer,apps:unlock,auth:2fa,auth:logout,auth:token,auth:whoami,authorizations,authorizations:create,authorizations:destroy,authorizations:info,authorizations:revoke,authorizations:rotate,authorizations:update,buildpacks,buildpacks:add,buildpacks:clear,buildpacks:remove,buildpacks:set,buildpacks:versions,certs,certs:add,certs:auto,certs:auto:disable,certs:auto:enable,certs:auto:refresh,certs:generate,certs:info,certs:remove,certs:update,ci,ci:config,ci:config:get,ci:config:set,ci:config:unset,ci:debug,ci:info,ci:last,ci:open,ci:rerun,ci:run,clients,clients:create,clients:destroy,clients:info,clients:rotate,clients:update,config,config:add,config:edit,config:get,config:remove,config:set,config:unset,console,container:login,container:pull,container:push,container:release,container:rm,container:run,create,dashboard,data:maintenances,data:maintenances:history,data:maintenances:info,data:maintenances:run,data:maintenances:schedule,data:maintenances:wait,data:maintenances:window,data:maintenances:window:update,data:pg:attachments,data:pg:attachments:create,data:pg:attachments:destroy,data:pg:create,data:pg:credentials,data:pg:credentials:create,data:pg:credentials:destroy,data:pg:credentials:rotate,data:pg:credentials:url,data:pg:destroy,data:pg:fork,data:pg:info,data:pg:levels,data:pg:migrate,data:pg:psql,data:pg:quotas,data:pg:quotas:update,data:pg:settings,data:pg:update,data:pg:upgrade:run,data:pg:upgrade:wait,data:pg:wait,destroy,domains,domains:add,domains:clear,domains:info,domains:remove,domains:update,domains:wait,drains,drains:add,drains:get,drains:remove,drains:set,dyno:kill,dyno:resize,dyno:restart,dyno:scale,dyno:stop,dyno:type,features,features:disable,features:enable,features:info,git:clone,git:credentials,git:remote,info,join,keys,keys:add,keys:clear,keys:remove,kill,labs,labs:disable,labs:enable,labs:info,leave,list,lock,logout,logs,maintenance,maintenance:off,maintenance:on,mcp:start,members,members:add,members:remove,members:set,notifications,open,orgs,orgs:open,pg,pg:backups,pg:backups:cancel,pg:backups:capture,pg:backups:delete,pg:backups:download,pg:backups:info,pg:backups:restore,pg:backups:schedule,pg:backups:schedules,pg:backups:unschedule,pg:backups:url,pg:bloat,pg:blocking,pg:cache-hit,pg:cache_hit,pg:calls,pg:connection-pooling:attach,pg:copy,pg:credentials,pg:credentials:create,pg:credentials:destroy,pg:credentials:repair-default,pg:credentials:rotate,pg:credentials:url,pg:diagnose,pg:extensions,pg:fdwsql,pg:index-size,pg:index-usage,pg:index_size,pg:index_usage,pg:info,pg:kill,pg:killall,pg:links,pg:links:create,pg:links:destroy,pg:locks,pg:long-running-queries,pg:long_running_queries,pg:mandelbrot,pg:outliers,pg:promote,pg:ps,pg:psql,pg:pull,pg:push,pg:records-rank,pg:records_rank,pg:reset,pg:seq-scans,pg:seq_scans,pg:settings,pg:settings:auto-explain,pg:settings:auto-explain:log-analyze,pg:settings:auto-explain:log-buffers,pg:settings:auto-explain:log-format,pg:settings:auto-explain:log-min-duration,pg:settings:auto-explain:log-nested-statements,pg:settings:auto-explain:log-triggers,pg:settings:auto-explain:log-verbose,pg:settings:data-connector-details-logs,pg:settings:explain-data-connector-details,pg:settings:log-connections,pg:settings:log-lock-waits,pg:settings:log-min-duration-statement,pg:settings:log-min-error-statement,pg:settings:log-statement,pg:settings:track-functions,pg:stats-reset,pg:stats_reset,pg:table-indexes-size,pg:table-size,pg:table_indexes_size,pg:table_size,pg:total-index-size,pg:total-table-size,pg:total_index_size,pg:total_table_size,pg:unfollow,pg:unused-indexes,pg:unused_indexes,pg:upgrade:cancel,pg:upgrade:dryrun,pg:upgrade:prepare,pg:upgrade:run,pg:upgrade:wait,pg:user-connections,pg:user_connections,pg:vacuum-stats,pg:wait,pipelines,pipelines:add,pipelines:connect,pipelines:create,pipelines:destroy,pipelines:diff,pipelines:info,pipelines:open,pipelines:promote,pipelines:remove,pipelines:rename,pipelines:setup,pipelines:transfer,pipelines:update,ps,ps:autoscale:disable,ps:autoscale:enable,ps:copy,ps:exec,ps:forward,ps:kill,ps:resize,ps:restart,ps:scale,ps:socks,ps:stop,ps:type,ps:wait,psql,rake,redis,redis:cli,redis:credentials,redis:info,redis:keyspace-notifications,redis:maxmemory,redis:promote,redis:stats-reset,redis:timeout,redis:upgrade,redis:wait,regions,releases,releases:info,releases:output,releases:retry,releases:rollback,rename,resize,restart,reviewapps:create,reviewapps:disable,reviewapps:enable,reviewapps:wait,rollback,run,run:detached,run:inside,scale,sessions,sessions:destroy,spaces,spaces:create,spaces:destroy,spaces:drains:get,spaces:drains:set,spaces:hosts,spaces:info,spaces:peering:info,spaces:peerings,spaces:peerings:accept,spaces:peerings:destroy,spaces:peerings:info,spaces:ps,spaces:rename,spaces:topology,spaces:transfer,spaces:trusted-ips,spaces:trusted-ips:add,spaces:trusted-ips:remove,spaces:vpn:config,spaces:vpn:connect,spaces:vpn:connections,spaces:vpn:destroy,spaces:vpn:info,spaces:vpn:update,spaces:vpn:wait,spaces:wait,stack,stack:set,stop,teams,telemetry,telemetry:add,telemetry:info,telemetry:remove,telemetry:update,trusted-ips,trusted-ips:add,trusted-ips:remove,twofactor,unlock,usage:addons,webhooks,webhooks:add,webhooks:deliveries,webhooks:deliveries:info,webhooks:events,webhooks:events:info,webhooks:info,webhooks:remove,webhooks:update,whoami";

fn heroku_invocation_is_secretless(args: &[OsString]) -> bool {
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
    let args = &args[..option_end];
    if args
        .iter()
        .any(|arg| matches!(*arg, "--help" | "-h" | "--version"))
        || args
            .first()
            .is_some_and(|arg| matches!(*arg, "-v" | "version"))
        || heroku_uses_another_credential_or_authority()
    {
        return true;
    }
    let Some(command) = args.first().filter(|command| !command.starts_with('-')) else {
        return true;
    };
    !HEROKU_AUTHENTICATED_COMMANDS
        .split(',')
        .any(|candidate| candidate == *command)
}

fn heroku_uses_another_credential_or_authority() -> bool {
    std::env::var_os("HEROKU_CLOUD").is_some_and(|value| value == "staging")
        || [
            "HEROKU_API_KEY",
            "HEROKU_CI_WEBSOCKET_URL",
            "HEROKU_DATA_HOST",
            "HEROKU_EXEC_URL",
            "HEROKU_GIT_HOST",
            "HEROKU_HOST",
            "HEROKU_PARTICLEBOARD_URL",
            "HEROKU_REDIS_HOST",
            "PGDIAGNOSE_URL",
        ]
        .iter()
        .any(|key| std::env::var_os(key).is_some_and(|value| !value.is_empty()))
}

// Reviewed against hetznercloud/cli v1.67.0. Keep the Secret boundary to
// exact API command paths; local configuration, future commands, and unknown
// forms must not receive the protected token.
const HCLOUD_AUTHENTICATED_COMMANDS: &str = "all list,certificate add-label,certificate create,certificate delete,certificate describe,certificate list,certificate remove-label,certificate retry,certificate update,datacenter describe,datacenter list,firewall add-label,firewall add-rule,firewall apply-to-resource,firewall create,firewall delete,firewall delete-rule,firewall describe,firewall list,firewall remove-from-resource,firewall remove-label,firewall replace-rules,firewall update,floating-ip add-label,floating-ip assign,floating-ip create,floating-ip delete,floating-ip describe,floating-ip disable-protection,floating-ip enable-protection,floating-ip list,floating-ip remove-label,floating-ip set-rdns,floating-ip unassign,floating-ip update,image add-label,image delete,image describe,image disable-protection,image enable-protection,image list,image remove-label,image update,iso describe,iso list,load-balancer add-label,load-balancer add-service,load-balancer add-target,load-balancer attach-to-network,load-balancer change-algorithm,load-balancer change-type,load-balancer create,load-balancer delete,load-balancer delete-service,load-balancer describe,load-balancer detach-from-network,load-balancer disable-protection,load-balancer disable-public-interface,load-balancer enable-protection,load-balancer enable-public-interface,load-balancer list,load-balancer metrics,load-balancer remove-label,load-balancer remove-target,load-balancer set-rdns,load-balancer update,load-balancer update-service,load-balancer-type describe,load-balancer-type list,location describe,location list,network add-label,network add-route,network add-subnet,network change-ip-range,network create,network delete,network describe,network disable-protection,network enable-protection,network expose-routes-to-vswitch,network list,network remove-label,network remove-route,network remove-subnet,network update,placement-group add-label,placement-group create,placement-group delete,placement-group describe,placement-group list,placement-group remove-label,placement-group update,primary-ip add-label,primary-ip assign,primary-ip create,primary-ip delete,primary-ip describe,primary-ip disable-protection,primary-ip enable-protection,primary-ip list,primary-ip remove-label,primary-ip set-rdns,primary-ip unassign,primary-ip update,server add-label,server add-to-placement-group,server attach-iso,server attach-to-network,server change-alias-ips,server change-type,server create,server create-image,server delete,server describe,server detach-from-network,server detach-iso,server disable-backup,server disable-protection,server disable-rescue,server enable-backup,server enable-protection,server enable-rescue,server ip,server list,server metrics,server poweroff,server poweron,server reboot,server rebuild,server remove-from-placement-group,server remove-label,server request-console,server reset,server reset-password,server set-rdns,server shutdown,server ssh,server update,server-type describe,server-type list,ssh-key add-label,ssh-key create,ssh-key delete,ssh-key describe,ssh-key list,ssh-key remove-label,ssh-key update,storage-box add-label,storage-box change-type,storage-box create,storage-box delete,storage-box describe,storage-box disable-protection,storage-box disable-snapshot-plan,storage-box enable-protection,storage-box enable-snapshot-plan,storage-box folders,storage-box list,storage-box remove-label,storage-box reset-password,storage-box rollback-snapshot,storage-box snapshot add-label,storage-box snapshot create,storage-box snapshot delete,storage-box snapshot describe,storage-box snapshot list,storage-box snapshot remove-label,storage-box snapshot update,storage-box subaccount change-home-directory,storage-box subaccount create,storage-box subaccount delete,storage-box subaccount describe,storage-box subaccount list,storage-box subaccount reset-password,storage-box subaccount update,storage-box subaccount update-access-settings,storage-box update,storage-box update-access-settings,storage-box-type describe,storage-box-type list,volume add-label,volume attach,volume create,volume delete,volume describe,volume detach,volume disable-protection,volume enable-protection,volume list,volume remove-label,volume resize,volume update,zone add-label,zone add-records,zone change-primary-nameservers,zone change-ttl,zone create,zone delete,zone describe,zone disable-protection,zone enable-protection,zone export-zonefile,zone import-zonefile,zone list,zone remove-label,zone remove-records,zone rrset add-label,zone rrset add-records,zone rrset change-ttl,zone rrset create,zone rrset delete,zone rrset describe,zone rrset disable-protection,zone rrset enable-protection,zone rrset list,zone rrset remove-label,zone rrset remove-records,zone rrset set-records,zone set-records";

fn hcloud_invocation_is_secretless(args: &[OsString]) -> bool {
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
    let args = &args[..option_end];
    if args
        .iter()
        .any(|arg| matches!(*arg, "--help" | "-h" | "--version"))
        || std::env::var_os("HCLOUD_TOKEN").is_some_and(|value| !value.is_empty())
    {
        return true;
    }
    let Some(command) = hcloud_command_path(args) else {
        return true;
    };
    let consumes_secret = command == "context create" && hcloud_bool_flag(args, "--token-from-env")
        || command == "config get token" && hcloud_bool_flag(args, "--allow-sensitive")
        || command == "config list" && hcloud_bool_flag(args, "--allow-sensitive");
    if consumes_secret {
        return false;
    }
    if hcloud_uses_another_authority(args) {
        return true;
    }
    !HCLOUD_AUTHENTICATED_COMMANDS
        .split(',')
        .any(|candidate| candidate == command)
}

fn hcloud_command_path(args: &[&str]) -> Option<String> {
    const VALUE_FLAGS: &[&str] = &[
        "--config",
        "--context",
        "--debug-file",
        "--endpoint",
        "--hetzner-endpoint",
        "--http-timeout",
        "--poll-interval",
    ];
    const BOOL_FLAGS: &[&str] = &["--debug", "--no-experimental-warnings", "--quiet"];

    let mut words = Vec::with_capacity(3);
    let mut index = 0;
    while index < args.len() {
        let arg = args[index];
        if VALUE_FLAGS.contains(&arg) {
            index += 2;
            if index > args.len() {
                return None;
            }
            continue;
        }
        if words == ["config", "get"] && matches!(arg, "--allow-sensitive" | "--global")
            || words == ["config", "get"]
                && ["--allow-sensitive", "--global"]
                    .iter()
                    .any(|flag| arg.starts_with(&format!("{flag}=")))
        {
            index += 1;
            continue;
        }
        if VALUE_FLAGS
            .iter()
            .chain(BOOL_FLAGS)
            .any(|flag| arg.starts_with(&format!("{flag}=")))
            || BOOL_FLAGS.contains(&arg)
        {
            index += 1;
            continue;
        }
        if arg.starts_with('-') {
            return None;
        }
        words.push(arg);
        match words.as_slice() {
            ["version" | "completion"] => return Some(words.join(" ")),
            [_, _]
                if !matches!(
                    words.as_slice(),
                    ["config", "get"]
                        | [
                            "storage-box",
                            "snapshot" | "snapshots" | "subaccount" | "subaccounts"
                        ]
                        | [
                            "storage-boxes",
                            "snapshot" | "snapshots" | "subaccount" | "subaccounts"
                        ]
                        | ["zone" | "zones" | "dns", "rrset" | "record" | "records"]
                ) =>
            {
                break;
            }
            [_, _, _] => break,
            _ => {}
        }
        index += 1;
    }
    let first = match words.first().copied()? {
        "certificates" => "certificate",
        "datacenters" => "datacenter",
        "firewalls" => "firewall",
        "floating-ips" => "floating-ip",
        "images" => "image",
        "isos" => "iso",
        "loadbalancer" | "load-balancers" | "loadbalancers" => "load-balancer",
        "locations" => "location",
        "networks" => "network",
        "placement-groups" => "placement-group",
        "primary-ips" => "primary-ip",
        "servers" => "server",
        "ssh-keys" => "ssh-key",
        "storage-boxes" => "storage-box",
        "storage-box-types" => "storage-box-type",
        "volumes" => "volume",
        "dns" | "zones" => "zone",
        command => command,
    };
    words[0] = first;
    if words.len() == 3 {
        words[1] = match (first, words[1]) {
            ("storage-box", "snapshots") => "snapshot",
            ("storage-box", "subaccounts") => "subaccount",
            ("zone", "record" | "records") => "rrset",
            (_, command) => command,
        };
    }
    Some(words.join(" "))
}

fn hcloud_bool_flag(args: &[&str], flag: &str) -> bool {
    args.iter().any(|arg| {
        *arg == flag
            || arg
                .strip_prefix(flag)
                .and_then(|value| value.strip_prefix('='))
                .is_some_and(|value| matches!(value, "1" | "t" | "T" | "true" | "True" | "TRUE"))
    })
}

fn hcloud_uses_another_authority(args: &[&str]) -> bool {
    ["HCLOUD_ENDPOINT", "HETZNER_ENDPOINT"]
        .iter()
        .any(|key| std::env::var_os(key).is_some_and(|value| !value.is_empty()))
        || args.iter().any(|arg| {
            matches!(*arg, "--endpoint" | "--hetzner-endpoint")
                || arg.starts_with("--endpoint=")
                || arg.starts_with("--hetzner-endpoint=")
        })
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

fn npm_invocation_is_secretless(args: &[OsString]) -> bool {
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
    if option_args.iter().any(|argument| {
        matches!(
            *argument,
            "--help" | "-h" | "-?" | "-H" | "--version" | "--versions" | "-v"
        )
    }) || npm_uses_explicit_auth(option_args)
    {
        return true;
    }
    let Some(command) = npm_command(option_args) else {
        return true;
    };
    // Reviewed against npm v11.19.0. Keep this positive list exact: npm's
    // dynamic abbreviations can change meaning when npm adds commands, and
    // arbitrary package scripts must not inherit NODE_AUTH_TOKEN merely because
    // npm launched them.
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

fn npm_command<'a>(args: &'a [&str]) -> Option<&'a str> {
    const BOOLEAN_SHORT_OPTIONS: &str = "DEOPSadfglpqsy";
    const BOOLEAN_OPTIONS: &[&str] = &[
        "--all",
        "--dry-run",
        "--force",
        "--fund",
        "--global",
        "--ignore-scripts",
        "--include-workspace-root",
        "--json",
        "--local",
        "--long",
        "--offline",
        "--parseable",
        "--prefer-offline",
        "--prefer-online",
        "--quiet",
        "--readonly",
        "--silent",
        "--timing",
        "--verbose",
        "--workspaces",
        "--yes",
        "-D",
        "-E",
        "-O",
        "-P",
        "-S",
        "-a",
        "-d",
        "-dd",
        "-ddd",
        "-f",
        "-g",
        "-l",
        "-p",
        "-q",
        "-s",
        "-y",
    ];
    const VALUE_OPTIONS: &[&str] = &[
        "--cache",
        "--call",
        "--location",
        "--loglevel",
        "--otp",
        "--prefix",
        "--registry",
        "--reg",
        "--scope",
        "--tag",
        "--userconfig",
        "--workspace",
        "-C",
        "-L",
        "-c",
        "-m",
        "-w",
    ];
    const VALUE_SHORT_OPTIONS: &[&str] = &["-C", "-L", "-c", "-m", "-w"];

    let mut index = 0;
    while let Some(argument) = args.get(index) {
        if !argument.starts_with('-') {
            return Some(argument);
        }
        if argument.contains('=')
            || argument.starts_with("--no-")
            || BOOLEAN_OPTIONS.contains(argument)
            || argument.strip_prefix('-').is_some_and(|options| {
                options.len() > 1
                    && options
                        .chars()
                        .all(|option| BOOLEAN_SHORT_OPTIONS.contains(option))
            })
            || VALUE_SHORT_OPTIONS
                .iter()
                .any(|option| argument.starts_with(option) && argument.len() > option.len())
        {
            index += 1;
        } else if VALUE_OPTIONS.contains(argument) {
            args.get(index + 1)?;
            index += 2;
        } else {
            return None;
        }
    }
    None
}

fn npm_uses_explicit_auth(args: &[&str]) -> bool {
    args.iter().any(|argument| {
        let option = argument.strip_prefix("--").unwrap_or(argument);
        let option = option
            .split_once('=')
            .map_or(option, |(name, _)| name)
            .to_ascii_lowercase();
        option == "_authtoken"
            || option == "_auth-token"
            || option.ends_with(":_authtoken")
            || option.ends_with(":_auth-token")
    })
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

// Reviewed against doctl v1.168.0. Runnable-only names and context-checked
// ambiguous aliases cross from the tokenless command tree into a credentialed leaf.
const DOCTL_ROOTS: &str = "1-click,account,apps,app,a,auth,balance,billing-history,bh,compute,databases,db,dbs,d,database,dedicated-inference,di,dedicated-inferences,gradient,ai,genai,gradientai,invoice,kubernetes,kube,k8s,k,monitoring,network,nfs,projects,registries,regs,rs,registry,reg,r,secrets,security,serverless,sandbox,sbx,sls,serverless-inference,inference,si,spaces,sp,vector-databases,vdb,vdbs,version,vpcs";
const DOCTL_GROUP_ONLY: &str = "1-click,access-point,account,action,activation,activations,actv,agent,agents,ai,alert,alerts,apikeys,apk,app,apps,async,async-invoke,attachment,auth,autoscale,backup-policies,balance,bh,billing-history,byoip-prefix,byoip-prefixes,cdn,certificate,cfg,chat,chat-completions,chatcompletion,cluster,clusters,compute,configuration,da,das,database,databases,db,dbs,dedicated-inference,dedicated-inferences,dev,di,domain,droplet,droplet-action,droplet-autoscale,embeddings,events,fip,fipa,firewall,firewalls,floating-ip,floating-ip-action,floating-ip-actions,floating-ips,fn,fr,function,functionroute,functions,fw,garbage-collection,genai,gradient,gradientai,image,image-action,images,indexes,inference,instance-size,invoice,k8scfg,kb,key,keys,knowledge-base,kube,kubecfg,kubeconfig,kubernetes,lb,load-balancer,main,maintenance,maintenance-window,messages,monitoring,mw,namespace,namespaces,network,nfs,node-pool,node-pools,nodepool,nodepools,np,ns,o,ok,openai-key,options,opts,peerings,plugin,pool,pools,projects,records,reg,region,registries,registry,regs,rep,replica,repo,repository,reserved-ip,reserved-ip-action,reserved-ip-actions,reserved-ips,reserved-ipv6,reserved-ipv6s,responses,route,routes,sandbox,sbx,scan,scans,scenario-library,scenario-set,scenario-sets,secrets,security,serverless,serverless-inference,si,sim,simulation-run,simulation-runs,size,sl,sls,sm,sp,spaces,spec,sql-mode,ss,ssh-key,storage,storage-autoscale,tier,topics,trig,trigger,triggers,uptime,user,vdb,vdbs,vector-databases,vng,volume,volume-action,vpc-nat-gateway,vpcs";
const DOCTL_RUNNABLE_ONLY: &str = "actions,add,add-datasource,add-droplets,add-ds,add-forwarding-rules,add-rules,add-tags,affected-resources,append,apply,ar,assign,ath,attach,available-regions,b,backups,bu,build,c-ss,cancel,cancel-event,cancel-indexing-job,cancel-job,cancel-job-invocation,cd,ce,change-backup-policy,change-kernel,cji,conn,connect,connection,console,create,create-deployment,create-scenario-set,create-token,credentials,creds,cs,csv,ct,d-ds,del,delete,delete-dangerous,delete-datasource,delete-manifest,delete-node,delete-selective,delete-tag,deploy,detach,detach-by-droplet-id,disable,disable-backups,dl-url,dm,docker-config,download-url,ds,dt,dth,enable,enable-backups,enable-ipv6,enable-private-networking,eng,engines,exec-credential,f,fc,flush,fork,g-bgp-auth-key,g-j,g-service-key,g-t,g-t-url,ga,gd,ge,gen,generate,get,get-active,get-agents,get-bgp-auth-key,get-ca,get-deployment,get-event,get-gpu-model-config,get-indexing-job,get-job,get-job-invocation,get-journey,get-metadata,get-service-key,get-sizes,get-trajectory,get-trajectory-url,get-upgrades,ggmc,gji,gs,gu,i,import,in,init,install,invoke,kernels,kubernetes-manifest,l,la,latest,list,list-accelerators,list-alerts,list-application,list-associated-resources,list-buildpacks,list-by-droplet,list-datasources,list-deployments,list-distribution,list-events,list-history,list-indexing-job-data-sources,list-indexing-jobs,list-instances,list-job-invocations,list-journeys,list-manifests,list-members,list-models,list-regions,list-routes,list-scenarios,list-supported,list-tags,list-tokens,list-user,list-v2,list-versions,lm,login,logout,logs,lr,ls,ls-ds,ls-j,ls-job-ds,ls-jobs,ls-routes,ls-s,ls2,lsd,lse,lsji,lt,lv,m,migrate,n,neighbors,partitions,password-reset,pdf,power-cycle,power-off,power-on,promote,propose,purge-cache,ratelimit,reassign,reboot,rebuild,recycle,regen-api-key,regen-service-key,regenerate,regenerate-service-key,regions,remove,remove-droplets,remove-forwarding-rules,remove-rules,remove-tags,rename,replace,replace-node,reset,resize,resource,restart,restore,restore-status,result,revoke-token,rl,rm,rs-status,rt,run,save,set,show,shutdown,sizes,slugs,snapshots,ssh,start,status,subscription-tiers,summary,switch,switch-performance-tier,t,tags,tiers,token,transfer,uad,unassign,undeploy,uninstall,unset,untag,update,update-alert-destinations,update-vis,update-visibility,upgrade,upgrade-buildpack,uv,v,validate,version,versions,w,wait,watch";
const DOCTL_AMBIGUOUS: &str = "a,c,config,d,g,gc,k,k8s,models,p,r,resources,rs,s,snapshot,tag,u";

fn doctl_invocation_is_secretless(args: &[OsString]) -> bool {
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
        || doctl_uses_another_token(option_args)
    {
        return true;
    }

    let mut path = Vec::new();
    let mut index = 0;
    while index < option_end {
        let argument = args[index];
        if doctl_flag_takes_value(argument) {
            if index + 1 >= option_end {
                return true;
            }
            index += 2;
            continue;
        }
        if doctl_attached_value(argument)
            || matches!(argument, "--interactive" | "--trace" | "--verbose" | "-v")
        {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            return true;
        }
        if path.is_empty() {
            if !doctl_name_in(DOCTL_ROOTS, argument) || argument == "version" {
                return true;
            }
            path.push(argument);
            index += 1;
            continue;
        }
        if doctl_local_leaf(&path, argument) {
            return true;
        }
        if doctl_name_in(DOCTL_GROUP_ONLY, argument) || doctl_ambiguous_group(&path, argument) {
            path.push(argument);
            index += 1;
            continue;
        }
        return !doctl_name_in(DOCTL_RUNNABLE_ONLY, argument)
            && !doctl_name_in(DOCTL_AMBIGUOUS, argument);
    }
    true
}

fn doctl_uses_another_token(args: &[&str]) -> bool {
    let mut context = None;
    for (index, argument) in args.iter().enumerate() {
        if matches!(*argument, "--access-token" | "-t")
            || argument.starts_with("--access-token=")
            || argument.starts_with("-t") && argument.len() > 2
        {
            return true;
        }
        if *argument == "--context" {
            context = args.get(index + 1).copied();
        } else if let Some(value) = argument.strip_prefix("--context=") {
            context = Some(value);
        }
    }
    match context.filter(|value| !value.is_empty()) {
        Some(value) => !value.eq_ignore_ascii_case("default"),
        None => std::env::var_os("DIGITALOCEAN_CONTEXT")
            .is_some_and(|value| !value.is_empty() && value != "default"),
    }
}

fn doctl_flag_takes_value(argument: &str) -> bool {
    matches!(
        argument,
        "--access-token"
            | "-t"
            | "--api-url"
            | "-u"
            | "--config"
            | "-c"
            | "--context"
            | "--http-retry-max"
            | "--http-retry-wait-max"
            | "--http-retry-wait-min"
            | "--output"
            | "-o"
    )
}

fn doctl_attached_value(argument: &str) -> bool {
    [
        "--access-token=",
        "--api-url=",
        "--config=",
        "--context=",
        "--http-retry-max=",
        "--http-retry-wait-max=",
        "--http-retry-wait-min=",
        "--output=",
    ]
    .iter()
    .any(|prefix| argument.starts_with(prefix))
        || ["-t", "-u", "-c", "-o"]
            .iter()
            .any(|prefix| argument.starts_with(prefix) && argument.len() > prefix.len())
}

fn doctl_local_leaf(path: &[&str], leaf: &str) -> bool {
    let root = path[0];
    (root == "auth" && matches!(leaf, "list" | "ls" | "remove" | "switch"))
        || (matches!(root, "apps" | "app" | "a")
            && path.get(1).is_some_and(|command| *command == "spec")
            && leaf == "validate")
        || (matches!(root, "serverless" | "sandbox" | "sbx" | "sls") && leaf == "get-metadata")
        || (matches!(root, "serverless" | "sandbox" | "sbx" | "sls")
            && leaf == "install"
            && (std::env::var_os("SNAP_SANDBOX_INSTALL").is_some()
                || std::env::var_os("DOCKER_SANDBOX_INSTALL").is_some()))
}

fn doctl_ambiguous_group(path: &[&str], command: &str) -> bool {
    let parent = path.last().copied().unwrap_or_default();
    (parent == "dev" && matches!(command, "config" | "c"))
        || (parent == "compute"
            && matches!(
                command,
                "droplet" | "d" | "plugin" | "p" | "snapshot" | "s" | "ssh-key" | "k" | "tag"
            ))
        || (matches!(parent, "databases" | "db" | "dbs" | "d" | "database")
            && matches!(
                command,
                "configuration"
                    | "cfg"
                    | "config"
                    | "pool"
                    | "p"
                    | "replica"
                    | "rep"
                    | "r"
                    | "user"
                    | "u"
            ))
        || (matches!(parent, "gradient" | "ai" | "genai" | "gradientai")
            && matches!(command, "agent" | "agents" | "a"))
        || (matches!(parent, "agent" | "agents" | "a")
            && matches!(command, "route" | "routes" | "r"))
        || (matches!(parent, "kubernetes" | "kube" | "k8s" | "k")
            && matches!(command, "cluster" | "clusters" | "c"))
        || (matches!(parent, "cluster" | "clusters" | "c")
            && matches!(
                command,
                "kubeconfig"
                    | "kubecfg"
                    | "k8scfg"
                    | "config"
                    | "cfg"
                    | "node-pool"
                    | "node-pools"
                    | "nodepool"
                    | "nodepools"
                    | "pool"
                    | "pools"
                    | "np"
                    | "p"
            ))
        || (parent == "monitoring" && matches!(command, "alert" | "alerts" | "a"))
        || (parent == "nfs" && command == "snapshot")
        || (parent == "projects" && command == "resources")
        || (matches!(
            parent,
            "registries" | "regs" | "rs" | "registry" | "reg" | "r"
        ) && matches!(
            command,
            "garbage-collection" | "gc" | "g" | "repository" | "repo" | "r"
        ))
        || (matches!(parent, "serverless-inference" | "inference" | "si") && command == "models")
        || (matches!(parent, "spaces" | "sp") && matches!(command, "keys" | "k"))
}

fn doctl_name_in(names: &str, candidate: &str) -> bool {
    names.split(',').any(|name| name == candidate)
}

// Reviewed against flyctl v0.4.99. Unknown commands stay tokenless until their
// authority is audited; the current runnable command and alias vocabulary gates
// every authenticated leaf while local exceptions remain explicit below.
const FLYCTL_ROOT_GROUPS: &str = "agent,apps,app,auth,certs,checks,config,consul,create,extensions,ext,history,image,img,incidents,info,ips,ip,litefs-cloud,lfsc,machine,machines,m,mcp,metrics,mpg,orgs,platform,postgres,pg,redis,regions,registry,resume,scale,secrets,services,settings,sftp,ssh,storage,tigris,suspend,synthetics,tokens,volumes,volume,vol,v,wireguard,wg";
const FLYCTL_ROOT_RUNNABLE: &str = "console,curl,dashboard,dash,deploy,destroy,dig,doctor,launch,logs,move,open,ping,proxy,releases,status";
const FLYCTL_GROUP_ONLY: &str = "3p,app,apps,arcjet,auth,backups,barman,certs,checks,clusters,config,consul,cross-network-replays,database,databases,db,dbs,egress-ip,events,ext,extension,extensions,history,hosts,image,img,incidents,info,ip,ips,k8s,keys,kubernetes,lease,leases,lfsc,m,machine,machines,mcp,mpg,orgs,pg,plan,platform,registry,replay-sources,resume,scale,secrets,sentry,services,settings,sftp,snaps,snapshot,snapshots,storage,third-party,tokens,user,users,v,vector,vol,volumes,waf,wafris,wg";
const FLYCTL_RUNNABLE_ONLY: &str = "add,add-discharge,add_flycast,allocate,allocate-egress,allocate-v4,allocate-v6,analytics,api-proxy,attach,attenuate,autoupdate,check,clear,clone,connect,console,cordon,count,curl,daemon-start,dash,dashboard,debug,del,delete,deploy,destroy,detach,diag,dig,disable,discharge,display,docker,docs,doctor,enable,env,errors,exec,export,extend,failover,files,find,fork,gen,generate,get,import,inspect,invite,issue,jobs,kill,kubectl-token,launch,list,list-backup,log,login,logout,logs,ls,machine-exec,memory,move,open,org,ping,place,plans,private,promote,propose,proxy,put,readonly,recover,release,release-egress,releases,remove,renew-certs,reset,restart,restore,revoke,rm,run,save,save-install,save-kubeconfig,sbom,send,server,set,set-role,setup,shell,show,show-backup,signup,start,status,stop,switch-wal,sync,ticket,token,uncordon,unset,update,update-role,upgrade,validate,version,view,vm,vm-sizes,vulns,vulnsummary,wait,websockets,whoami,wrap";
const FLYCTL_AMBIGUOUS: &str = "agent,backup,create,litefs-cloud,metrics,postgres,redis,regions,ssh,suspend,synthetics,tigris,volume,wireguard";

fn flyctl_invocation_is_secretless(args: &[OsString]) -> bool {
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
        || flyctl_uses_another_token(option_args)
    {
        return true;
    }

    let mut path = Vec::new();
    let mut current_runnable = false;
    let mut index = 0;
    while index < option_end {
        let argument = args[index];
        if matches!(argument, "--access-token" | "-t") {
            return true;
        }
        if argument.starts_with("--access-token=")
            || argument.starts_with("-t") && argument.len() > 2
            || matches!(argument, "--verbose" | "--debug")
        {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            return !current_runnable;
        }
        if path.is_empty() {
            if matches!(argument, "docs" | "jobs" | "version" | "settings") {
                return true;
            }
            if flyctl_name_in(FLYCTL_ROOT_RUNNABLE, argument) {
                current_runnable = true;
            } else if !flyctl_name_in(FLYCTL_ROOT_GROUPS, argument) {
                return true;
            }
            path.push(argument);
            index += 1;
            continue;
        }
        if flyctl_local_leaf(&path, argument) {
            return true;
        }
        if flyctl_name_in(FLYCTL_GROUP_ONLY, argument) || flyctl_ambiguous_group(&path, argument) {
            path.push(argument);
            current_runnable = false;
            index += 1;
            continue;
        }
        if flyctl_name_in(FLYCTL_RUNNABLE_ONLY, argument)
            || flyctl_name_in(FLYCTL_AMBIGUOUS, argument)
        {
            return false;
        }
        return !current_runnable;
    }
    !current_runnable
}

fn flyctl_uses_another_token(args: &[&str]) -> bool {
    args.iter().any(|argument| {
        matches!(*argument, "--access-token" | "-t")
            || argument.starts_with("--access-token=")
            || argument.starts_with("-t") && argument.len() > 2
    }) || std::env::var_os("FLY_API_TOKEN").is_some_and(|value| !value.is_empty())
}

fn flyctl_local_leaf(path: &[&str], leaf: &str) -> bool {
    let root = path[0];
    (root == "agent" && matches!(leaf, "ping" | "stop"))
        || (root == "auth" && matches!(leaf, "login" | "signup"))
        || (root == "platform" && leaf == "status")
        || (root == "mcp" && matches!(leaf, "list" | "proxy" | "inspect" | "wrap"))
}

fn flyctl_ambiguous_group(path: &[&str], command: &str) -> bool {
    let parent = path.last().copied().unwrap_or_default();
    (matches!(parent, "apps" | "app") && command == "suspend")
        || (matches!(parent, "extensions" | "ext") && matches!(command, "storage" | "tigris"))
        || (matches!(parent, "mpg" | "postgres" | "pg") && matches!(command, "backup" | "backups"))
        || (parent == "tokens" && command == "create")
}

fn flyctl_name_in(names: &str, candidate: &str) -> bool {
    names.split(',').any(|name| name == candidate)
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
    args.iter().enumerate().any(|(index, argument)| {
        if *argument == option {
            return args.get(index + 1).is_some_and(|value| !value.is_empty());
        }
        argument
            .strip_prefix(option)
            .and_then(|value| value.strip_prefix('='))
            .is_some_and(|value| !value.is_empty())
    })
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

// Reviewed against gotify/cli v2.4.0. Only message delivery consumes the
// application token. `watch` remains credentialed because it delivers changes;
// arguments after `--` do not alter the routing decision.
fn gotify_invocation_is_secretless(args: &[OsString]) -> bool {
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
        .any(|arg| matches!(*arg, "--help" | "-h" | "--version" | "-v"))
        || std::env::var_os("GOTIFY_TOKEN").is_some_and(|value| !value.is_empty())
    {
        return true;
    }

    match option_args.first().copied() {
        Some("push" | "p" | "watch") => gotify_has_token_option(option_args),
        _ => true,
    }
}

fn gotify_has_token_option(args: &[&str]) -> bool {
    args.iter().enumerate().any(|(index, argument)| {
        if *argument == "--token" {
            return args.get(index + 1).is_some_and(|value| !value.is_empty());
        }
        argument
            .strip_prefix("--token=")
            .is_some_and(|value| !value.is_empty())
    })
}

// Reviewed against Netlify CLI v27.4.3. Keep this list positive: local dev,
// build-helper, and passthrough commands can launch project code that must not
// inherit the account token merely because Netlify can optionally use it.
fn netlify_invocation_is_secretless(args: &[OsString], remote_database_branch: bool) -> bool {
    if args.iter().any(|arg| arg == "--help" || arg == "-h")
        || args.iter().any(|arg| {
            arg == "--auth" || arg.to_str().is_some_and(|arg| arg.starts_with("--auth="))
        })
    {
        return true;
    }

    let mut command_index = 0;
    while args.get(command_index).is_some_and(|arg| {
        matches!(
            arg.to_str(),
            Some("--verbose" | "--telemetry-disable" | "--telemetry-enable" | "--")
        )
    }) {
        command_index += 1;
    }
    let Some(command) = args.get(command_index).and_then(|arg| arg.to_str()) else {
        return true;
    };
    if matches!(command, "-V" | "-v" | "--version" | "help" | "version") || command.starts_with('-')
    {
        return true;
    }

    let command_args = &args[command_index + 1..];
    let needs_secret = match command {
        "agents:create" | "agents:run" | "agents:list" | "agents:show" | "agents:stop"
        | "blob:delete" | "blob:get" | "blob:list" | "blob:set" | "blobs:delete" | "blobs:get"
        | "blobs:list" | "blobs:set" | "claim" | "clone" | "create" | "env:clone"
        | "env:delete" | "env:get" | "env:import" | "env:list" | "env:migrate" | "env:remove"
        | "env:set" | "env:unset" | "init" | "link" | "log" | "logs" | "open" | "open:admin"
        | "open:site" | "sites:create" | "sites:delete" | "sites:list" | "sites:search"
        | "status" | "status:hooks" | "teams:list" | "watch" => true,
        "api" => {
            !has_netlify_flag(command_args, "--list", None)
                && netlify_first_positional(command_args, &["--data", "-d"]).is_some()
        }
        "build" => !has_netlify_flag(command_args, "--offline", Some("-o")),
        "deploy" => !has_netlify_flag(command_args, "--allow-anonymous", None),
        "recipes" => {
            netlify_option_value(command_args, "--name") == Some("blobs-migrate")
                || netlify_first_positional(command_args, &[]) == Some("blobs-migrate")
        }
        "database" | "db" => {
            let first = netlify_first_positional(command_args, &[]);
            let second = first.and_then(|first| {
                let index = command_args.iter().position(|arg| arg == first)?;
                netlify_first_positional(&command_args[index + 1..], &[])
            });
            matches!((first, second), (Some("migrations"), Some("pull")))
                || remote_database_branch
                    && (first == Some("status")
                        || matches!((first, second), (Some("migrations"), Some("reset"))))
                || (first == Some("status")
                    || matches!((first, second), (Some("migrations"), Some("reset"))))
                    && has_netlify_flag(command_args, "--branch", Some("-b"))
        }
        _ => false,
    };
    !needs_secret
}

fn has_netlify_flag(args: &[OsString], long: &str, short: Option<&str>) -> bool {
    args.iter().any(|arg| {
        arg == long
            || short.is_some_and(|short| {
                arg == short
                    || arg
                        .to_str()
                        .is_some_and(|arg| arg.len() > short.len() && arg.starts_with(short))
            })
            || arg
                .to_str()
                .is_some_and(|arg| arg.starts_with(&format!("{long}=")))
    })
}

fn netlify_option_value<'a>(args: &'a [OsString], option: &str) -> Option<&'a str> {
    args.iter().enumerate().find_map(|(index, arg)| {
        let arg = arg.to_str()?;
        arg.strip_prefix(&format!("{option}=")).or_else(|| {
            (arg == option)
                .then(|| args.get(index + 1)?.to_str())
                .flatten()
        })
    })
}

fn netlify_first_positional<'a>(
    args: &'a [OsString],
    extra_options_with_values: &[&str],
) -> Option<&'a str> {
    const OPTIONS_WITH_VALUES: &[&str] = &[
        "--auth",
        "--cwd",
        "--filter",
        "--http-proxy",
        "--http-proxy-certificate-filename",
    ];
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].to_str()?;
        if OPTIONS_WITH_VALUES.contains(&arg) || extra_options_with_values.contains(&arg) {
            index += 2;
        } else if arg.starts_with('-') {
            index += 1;
        } else {
            return Some(arg);
        }
    }
    None
}

fn sentry_cli_invocation_is_secretless(args: &[OsString]) -> bool {
    // Reviewed against sentry-cli 3.7.0. Keep this positive: local commands,
    // DSN-only envelope commands, and unrecognized future commands must not
    // inherit the protected SENTRY_AUTH_TOKEN.
    let Some(args) = args
        .iter()
        .map(|arg| arg.to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return true;
    };
    let before_passthrough = args.iter().take_while(|arg| **arg != "--");
    if before_passthrough
        .clone()
        .any(|arg| matches!(*arg, "--help" | "-h" | "--version" | "-V"))
        || before_passthrough
            .clone()
            .any(|arg| *arg == "--auth-token" || arg.starts_with("--auth-token="))
    {
        return true;
    }
    let no_upload = before_passthrough.clone().any(|arg| *arg == "--no-upload");

    let Some((command_index, command)) = sentry_cli_positional(&args, 0, true) else {
        return true;
    };
    let subcommand = sentry_cli_positional(&args, command_index + 1, false);
    let requires_secret = match (command, subcommand.map(|(_, command)| command)) {
        ("info" | "upload-dif" | "upload-dsym", _) => true,
        ("upload-proguard", _) => !no_upload,
        ("proguard", Some("upload")) => !no_upload,
        ("build", Some("download" | "snapshots" | "upload"))
        | ("code-mappings" | "dart-symbol-map", Some("upload"))
        | ("debug-files" | "dif" | "difutil", Some("upload"))
        | ("deploys", Some("list" | "new"))
        | ("events", Some("list"))
        | ("issues", Some("list" | "mute" | "resolve" | "unresolve"))
        | ("logs", Some("list"))
        | ("monitors", Some("list"))
        | ("organizations", Some("list"))
        | ("projects", Some("list"))
        | ("react-native", Some("gradle" | "xcode"))
        | ("repos", Some("list"))
        | ("snapshots", Some("download" | "upload"))
        | ("sourcemaps", Some("upload")) => true,
        ("releases", Some("deploys")) => subcommand.is_some_and(|(index, _)| {
            sentry_cli_positional(&args, index + 1, false)
                .is_some_and(|(_, command)| matches!(command, "list" | "new"))
        }),
        (
            "releases",
            Some(
                "archive" | "delete" | "finalize" | "info" | "list" | "new" | "restore"
                | "set-commits",
            ),
        ) => true,
        _ => false,
    };
    !requires_secret
}

fn sentry_cli_positional<'a>(
    args: &'a [&'a str],
    start: usize,
    root: bool,
) -> Option<(usize, &'a str)> {
    let mut index = start;
    while let Some(&arg) = args.get(index) {
        if matches!(arg, "--header" | "--log-level" | "--auth-token") || root && arg == "--url" {
            index += 2;
        } else if matches!(arg, "--quiet" | "--silent" | "--allow-failure")
            || arg.starts_with("--header=")
            || arg.starts_with("--log-level=")
            || arg.starts_with("--auth-token=")
            || root && arg.starts_with("--url=")
        {
            index += 1;
        } else if arg == "--" || arg.starts_with('-') {
            return None;
        } else {
            return Some((index, arg));
        }
    }
    None
}

fn snowflake_cli_invocation_is_secretless(args: &[OsString]) -> bool {
    let Some(args) = args
        .iter()
        .map(|arg| arg.to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return true;
    };
    let args = &args[..args
        .iter()
        .position(|arg| *arg == "--")
        .unwrap_or(args.len())];

    let Some(command_index) = snowflake_root_command_index(args) else {
        return true;
    };
    let words = &args[command_index..];

    if words.starts_with(&["dbt", "execute"]) {
        return !snowflake_dbt_execute_requires_password(&words[2..]);
    }
    // Explicit authentication material supersedes the migrated connection
    // password. Keeping that invocation tokenless also avoids repeating a
    // command-line credential in an Authorization Request.
    if args.iter().any(|arg| snowflake_auth_option(arg)) {
        return true;
    }
    if args.iter().any(|arg| matches!(*arg, "--help" | "-h")) {
        return true;
    }

    !SNOWFLAKE_PASSWORD_COMMANDS.split(',').any(|command| {
        let mut command = command.split_whitespace();
        command
            .by_ref()
            .zip(words.iter().copied())
            .all(|(expected, actual)| expected == actual)
            && command.next().is_none()
    })
}

// Reviewed against Snowflake CLI v3.26.0's built-in command structure. New
// commands and external plugins remain tokenless until their credential use is
// reviewed.
const SNOWFLAKE_PASSWORD_COMMANDS: &str = "
app setup,app diff,app run,app open,app teardown,app deploy,app validate,app events,app publish,
app version create,app version list,app version drop,app release-directive list,
app release-directive set,app release-directive unset,app release-directive add-accounts,
app release-directive remove-accounts,app release-channel list,app release-channel add-accounts,
app release-channel remove-accounts,app release-channel set-accounts,app release-channel add-version,
app release-channel remove-version,connection test,cortex search,cortex complete,
cortex extract-answer,cortex sentiment,cortex summarize,cortex translate,dbt list,dbt drop,
dbt describe,dbt copy,dbt deploy,dcm list,dcm deploy,dcm purge,dcm plan,dcm raw-analyze,
dcm create,dcm drop,dcm describe,dcm list-deployments,dcm drop-deployment,dcm preview,dcm refresh,
dcm test,git list,git drop,git describe,git setup,git list-branches,git list-tags,git list-files,
git fetch,git copy,git execute,logs,notebook execute,notebook get-url,notebook open,notebook create,
notebook deploy,object list,object drop,object describe,object create,snowpark deploy,snowpark build,
snowpark execute,snowpark list,snowpark drop,snowpark describe,snowpark package lookup,
snowpark package upload,snowpark package create,spcs compute-pool list,spcs compute-pool drop,
spcs compute-pool describe,spcs compute-pool create,spcs compute-pool deploy,
spcs compute-pool stop-all,spcs compute-pool suspend,spcs compute-pool resume,spcs compute-pool set,
spcs compute-pool unset,spcs compute-pool status,spcs service list,spcs service describe,
spcs service drop,spcs service create,spcs service deploy,spcs service execute-job,
spcs service status,spcs service logs,spcs service events,spcs service metrics,spcs service upgrade,
spcs service list-endpoints,spcs service list-instances,spcs service list-containers,
spcs service list-roles,spcs service suspend,spcs service resume,spcs service set,
spcs service unset,spcs service build-image,spcs service remote-build,
spcs service remote-build-status,spcs service remote-build-history,spcs image-registry token,
spcs image-registry url,spcs image-registry login,spcs image-repository list,
spcs image-repository drop,spcs image-repository create,spcs image-repository deploy,
spcs image-repository list-images,spcs image-repository list-tags,spcs image-repository url,sql,
stage list,stage drop,stage describe,stage list-files,stage copy,stage create,stage remove,stage diff,
stage execute,streamlit list,streamlit drop,streamlit describe,streamlit execute,streamlit share,
streamlit deploy,streamlit get-url,streamlit logs,ws bundle,ws deploy,ws drop,ws validate,
ws version list,ws version create,ws version drop";

fn snowflake_root_command_index(args: &[&str]) -> Option<usize> {
    const VALUE_OPTIONS: &[&str] = &[
        "--config-file",
        "--pycharm-debug-library-path",
        "--pycharm-debug-server-host",
        "--pycharm-debug-server-port",
    ];
    let mut index = 0;
    while index < args.len() {
        let arg = args[index];
        if VALUE_OPTIONS.contains(&arg) {
            index += 2;
        } else if VALUE_OPTIONS
            .iter()
            .any(|option| arg.starts_with(&format!("{option}=")))
            || matches!(
                arg,
                "--disable-external-command-plugins" | "--commands-registration"
            )
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

fn snowflake_dbt_execute_requires_password(args: &[&str]) -> bool {
    const VALUE_OPTIONS: &[&str] = &[
        "--dbt-version",
        "--env",
        "--env-vars",
        "--import",
        "--connection",
        "-c",
        "--environment",
        "--host",
        "--port",
        "--protocol",
        "--account",
        "--accountname",
        "--user",
        "--username",
        "--authenticator",
        "--database",
        "--dbname",
        "--schema",
        "--schemaname",
        "--role",
        "--rolename",
        "--warehouse",
        "--mfa-passcode",
        "--diag-log-path",
        "--diag-allowlist-path",
        "--oauth-client-id",
        "--oauth-client-secret",
        "--oauth-authorization-url",
        "--oauth-token-request-url",
        "--oauth-redirect-uri",
        "--oauth-scope",
        "--secondary-roles",
        "--format",
        "--decimal-precision",
    ];
    const FLAGS: &[&str] = &[
        "--run-async",
        "--no-run-async",
        "--use-shell-env-vars",
        "--writeback",
        "--no-writeback",
        "--temporary-connection",
        "-x",
        "--enable-diag",
        "--oauth-disable-pkce",
        "--oauth-enable-refresh-tokens",
        "--oauth-enable-single-use-refresh-tokens",
        "--client-store-temporary-credential",
        "--server-session-keep-alive",
        "--verbose",
        "-v",
        "--debug",
        "--silent",
        "--enhanced-exit-codes",
    ];
    const COMMANDS: &[&str] = &[
        "build",
        "compile",
        "deps",
        "list",
        "parse",
        "retry",
        "run",
        "run-operation",
        "seed",
        "show",
        "snapshot",
        "test",
    ];

    let mut index = 0;
    let mut saw_name = false;
    let mut has_explicit_auth = false;
    while index < args.len() {
        let arg = args[index];
        if matches!(arg, "--help" | "-h") {
            return false;
        }
        if snowflake_auth_option(arg) {
            has_explicit_auth = true;
            index += usize::from(!arg.contains('=')) + 1;
        } else if VALUE_OPTIONS.contains(&arg) {
            index += 2;
        } else if VALUE_OPTIONS
            .iter()
            .any(|option| arg.starts_with(&format!("{option}=")))
            || FLAGS.contains(&arg)
        {
            index += 1;
        } else if arg.starts_with('-') {
            return false;
        } else if !saw_name {
            saw_name = true;
            index += 1;
        } else {
            return COMMANDS.contains(&arg) && !has_explicit_auth;
        }
    }
    false
}

fn snowflake_auth_option(arg: &str) -> bool {
    const OPTIONS: &[&str] = &[
        "--password",
        "--private-key-file",
        "--private-key-path",
        "--token",
        "--token-file-path",
        "--workload-identity-provider",
        "--session-token",
        "--master-token",
    ];
    OPTIONS.contains(&arg)
        || OPTIONS
            .iter()
            .any(|option| arg.starts_with(&format!("{option}=")))
}

fn snyk_invocation_is_secretless(args: &[OsString]) -> bool {
    let Some(args) = args
        .iter()
        .map(|arg| arg.to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return true;
    };
    let args = &args[..args
        .iter()
        .position(|arg| *arg == "--")
        .unwrap_or(args.len())];

    if args
        .iter()
        .any(|arg| matches!(*arg, "--help" | "-h" | "--version" | "-v" | "--about"))
    {
        return true;
    }
    let Some(command_index) = snyk_root_command_index(args) else {
        return true;
    };
    let words = &args[command_index..];

    // A caller-supplied credential is authoritative for this invocation. Do
    // not replace it with, or request approval for, the migrated credential.
    if ["SNYK_TOKEN", "SNYK_OAUTH_TOKEN", "SNYK_CFG_API"]
        .iter()
        .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
        || words.first() == Some(&"mcp")
            && std::env::var_os("IDE_CONFIG_PATH").is_some_and(|value| !value.is_empty())
        || snyk_docker_token_applies(words, args)
    {
        return true;
    }

    !snyk_command_requires_secret(words)
}

// Reviewed against Snyk CLI v1.1307.0. The CLI combines Cobra workflows with
// a legacy command parser; unknown and unaudited extension paths stay
// tokenless until their use of the migrated Snyk credential is reviewed.
fn snyk_command_requires_secret(words: &[&str]) -> bool {
    let Some(command) = words.first().copied() else {
        return false;
    };
    if snyk_alias(command, "test", 1) {
        return true;
    }
    if snyk_alias(command, "monitor", 1)
        || snyk_alias(command, "fix", 1)
        || snyk_alias(command, "ignore", 1)
    {
        return true;
    }

    match command {
        "whoami" | "sbom" | "aibom" | "agent-scan" | "mcp-scan" => true,
        "language-server" => !words
            .iter()
            .any(|argument| matches!(*argument, "--licenses" | "--protocolVersion" | "-p" | "--v")),
        "doctor" => snyk_doctor_requires_secret(words),
        "mcp" => snyk_subcommand(words, 1).is_none_or(|command| command != "configure"),
        "apps" | "app" | "ap" => snyk_subcommand(words, 1) == Some("create"),
        "container" => snyk_subcommand(words, 1).is_some_and(|command| {
            snyk_alias(command, "test", 1) || snyk_alias(command, "monitor", 1) || command == "sbom"
        }),
        "unmanaged" => snyk_subcommand(words, 1).is_some_and(|command| {
            snyk_alias(command, "test", 1) || snyk_alias(command, "monitor", 1)
        }),
        "code" => snyk_subcommand(words, 1).is_some_and(|command| snyk_alias(command, "test", 1)),
        "iac" => snyk_iac_requires_secret(words),
        "secrets" => snyk_subcommand(words, 1) == Some("test"),
        "tools" => snyk_subcommand(words, 1) == Some("connectivity-check"),
        "agent" => matches!(snyk_subcommand(words, 1), Some("feedback" | "test")),
        "cos" => snyk_cos_requires_secret(words),
        _ => false,
    }
}

fn snyk_root_command_index(args: &[&str]) -> Option<usize> {
    const VALUE_OPTIONS: &[&str] = &[
        "--integration-name",
        "--json-file-output",
        "--log-level",
        "--max-attempts",
        "--org",
        "--sarif-file-output",
        "--severity-threshold",
    ];
    const FLAGS: &[&str] = &[
        "--DISABLE_ANALYTICS",
        "--debug",
        "-d",
        "--include-ignores",
        "--insecure",
        "--json",
        "--proxy-noauth",
        "--sarif",
    ];
    let mut index = 0;
    while index < args.len() {
        let argument = args[index];
        if VALUE_OPTIONS.contains(&argument) {
            if index + 1 >= args.len() {
                return None;
            }
            index += 2;
        } else if VALUE_OPTIONS
            .iter()
            .any(|option| argument.starts_with(&format!("{option}=")))
            || FLAGS.contains(&argument)
        {
            index += 1;
        } else if argument.starts_with('-') {
            return None;
        } else {
            return Some(index);
        }
    }
    None
}

fn snyk_subcommand<'a>(words: &'a [&str], index: usize) -> Option<&'a str> {
    words
        .get(index)
        .copied()
        .filter(|word| !word.starts_with('-'))
}

fn snyk_alias(argument: &str, command: &str, minimum: usize) -> bool {
    argument.len() >= minimum && command.starts_with(argument)
}

fn snyk_doctor_requires_secret(words: &[&str]) -> bool {
    let has_input = words.iter().any(|argument| {
        matches!(*argument, "--input" | "--stdin") || argument.starts_with("--input=")
    });
    let live = words.iter().any(|argument| {
        *argument == "--live"
            || argument
                .strip_prefix("--live=")
                .is_some_and(|value| matches!(value, "1" | "t" | "T" | "true" | "TRUE" | "True"))
    });
    live || !has_input
}

fn snyk_iac_requires_secret(words: &[&str]) -> bool {
    let Some(command) = snyk_subcommand(words, 1) else {
        return false;
    };
    if snyk_alias(command, "test", 1)
        || snyk_alias(command, "describe", 1)
        || snyk_alias(command, "update-exclude-policy", 1)
        || command == "capture"
    {
        return true;
    }
    command == "rules" && snyk_subcommand(words, 2) == Some("push")
}

fn snyk_cos_requires_secret(words: &[&str]) -> bool {
    matches!(
        (snyk_subcommand(words, 1), snyk_subcommand(words, 2)),
        (Some("finding"), Some("get" | "list"))
            | (
                Some("scan"),
                Some("cancel" | "list" | "report" | "start" | "status")
            )
            | (
                Some("target"),
                Some("create" | "delete" | "dump" | "get" | "list" | "update")
            )
    )
}

fn snyk_docker_token_applies(words: &[&str], args: &[&str]) -> bool {
    if !std::env::var_os("SNYK_DOCKER_TOKEN").is_some_and(|value| !value.is_empty()) {
        return false;
    }
    let Some(command) = words.first().copied() else {
        return false;
    };
    command == "container"
        && snyk_subcommand(words, 1).is_some_and(|command| snyk_alias(command, "test", 1))
        || snyk_alias(command, "test", 1)
            && args
                .iter()
                .any(|argument| matches!(*argument, "--docker" | "--container"))
}

fn transifex_cli_invocation_is_secretless(args: &[OsString]) -> bool {
    let Some(args) = args
        .iter()
        .map(|arg| arg.to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return true;
    };
    let args = &args[..args
        .iter()
        .position(|arg| *arg == "--")
        .unwrap_or(args.len())];

    if args
        .iter()
        .any(|arg| matches!(*arg, "--help" | "-h" | "--version" | "-v"))
    {
        return true;
    }
    let Some((command_index, caller_supplied_authority)) = transifex_root_command(args) else {
        return true;
    };
    if caller_supplied_authority
        || ["TX_TOKEN", "TX_HOSTNAME"]
            .iter()
            .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
    {
        return true;
    }

    let words = &args[command_index..];
    !match words[0] {
        "merge" | "push" | "pull" | "delete" | "status" => true,
        "add" | "a" => transifex_add_requires_secret(&words[1..]),
        _ => false,
    }
}

// Reviewed against Transifex CLI v1.6.17 (30dac142). New commands remain
// tokenless until their use of the migrated credential is reviewed.
fn transifex_root_command(args: &[&str]) -> Option<(usize, bool)> {
    let mut index = 0;
    let mut caller_supplied_authority = false;
    while index < args.len() {
        let argument = args[index];
        if matches!(argument, "--token" | "-t") {
            let value = *args.get(index + 1)?;
            caller_supplied_authority |= !value.is_empty();
            index += 2;
        } else if let Some(value) = argument.strip_prefix("--token=") {
            caller_supplied_authority |= !value.is_empty();
            index += 1;
        } else if matches!(argument, "--hostname" | "-H") {
            let value = *args.get(index + 1)?;
            caller_supplied_authority |= !value.is_empty();
            index += 2;
        } else if let Some(value) = argument.strip_prefix("--hostname=") {
            caller_supplied_authority |= !value.is_empty();
            index += 1;
        } else if let Some(value) = argument.strip_prefix("-H=") {
            caller_supplied_authority |= !value.is_empty();
            index += 1;
        } else if matches!(argument, "--root-config" | "--config" | "-c" | "--cacert") {
            args.get(index + 1)?;
            index += 2;
        } else if ["--root-config=", "--config=", "-c=", "--cacert="]
            .iter()
            .any(|prefix| argument.starts_with(prefix))
        {
            index += 1;
        } else if argument.starts_with('-') {
            return None;
        } else {
            return Some((index, caller_supplied_authority));
        }
    }
    None
}

fn transifex_add_requires_secret(args: &[&str]) -> bool {
    const LOCAL_OPTIONS: &[&str] = &[
        "--organization",
        "--project",
        "--resource",
        "--file-filter",
        "--type",
    ];
    let mut index = 0;
    let mut has_local_option = false;
    let mut first_positional = None;
    while index < args.len() {
        let argument = args[index];
        if LOCAL_OPTIONS.contains(&argument) || argument == "--resource-name" {
            has_local_option |= LOCAL_OPTIONS.contains(&argument);
            if args.get(index + 1).is_none() {
                return false;
            }
            index += 2;
        } else if LOCAL_OPTIONS
            .iter()
            .any(|option| argument.starts_with(&format!("{option}=")))
            || argument.starts_with("--resource-name=")
        {
            has_local_option |= !argument.starts_with("--resource-name=");
            index += 1;
        } else if argument.starts_with('-') {
            return false;
        } else {
            first_positional.get_or_insert(argument);
            index += 1;
        }
    }
    first_positional == Some("remote") || !has_local_option
}

fn travis_invocation_is_secretless(args: &[OsString]) -> bool {
    let Some(args) = args
        .iter()
        .map(|argument| argument.to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return true;
    };
    let Some(command) = args.first() else {
        return true;
    };
    let command = command.strip_prefix("--").unwrap_or(command);
    if matches!(command, "help" | "version") || matches!(command, "-h" | "-?" | "-v") {
        return true;
    }

    let options = args[1..]
        .split(|argument| *argument == "--")
        .next()
        .unwrap_or_default();
    if options
        .iter()
        .any(|argument| matches!(*argument, "-h" | "--help"))
        || options.iter().any(|argument| {
            matches!(*argument, "--token")
                || argument.starts_with("--token=")
                || command != "settings" && (*argument == "-t" || argument.starts_with("-t"))
        })
        || std::env::var_os("TRAVIS_TOKEN").is_some_and(|value| !value.is_empty())
        || travis_invocation_selects_custom_authority(options)
    {
        return true;
    }

    // Travis loads plugins from the user's config directory. Keep this list
    // exact so an unreviewed plugin cannot inherit the protected token.
    let requires_token = matches!(
        command,
        "accounts"
            | "branches"
            | "cache"
            | "cancel"
            | "console"
            | "disable"
            | "enable"
            | "encrypt"
            | "encrypt-file"
            | "env"
            | "history"
            | "init"
            | "lint"
            | "logs"
            | "monitor"
            | "open"
            | "pubkey"
            | "raw"
            | "repos"
            | "requests"
            | "restart"
            | "settings"
            | "setup"
            | "show"
            | "sshkey"
            | "status"
            | "sync"
            | "token"
            | "whatsup"
            | "whoami"
    );
    !requires_token || !super::migrations::travis_default_config_is_safe_for_token()
}

fn travis_invocation_selects_custom_authority(options: &[&str]) -> bool {
    const OFFICIAL: &str = "https://api.travis-ci.com/";
    if std::env::var_os("TRAVIS_CONFIG_PATH").is_some_and(|value| !value.is_empty())
        || std::env::var_os("TRAVIS_ENDPOINT")
            .is_some_and(|value| !value.is_empty() && value != OFFICIAL)
    {
        return true;
    }
    let mut index = 0;
    while let Some(argument) = options.get(index) {
        if matches!(*argument, "-I" | "--insecure" | "-X" | "--enterprise")
            || argument.starts_with("-X")
            || argument.starts_with("--enterprise=")
        {
            return true;
        }
        if matches!(*argument, "-e" | "--api-endpoint") {
            if options
                .get(index + 1)
                .is_none_or(|value| *value != OFFICIAL)
            {
                return true;
            }
            index += 2;
            continue;
        }
        if let Some(value) = argument.strip_prefix("--api-endpoint=")
            && value != OFFICIAL
        {
            return true;
        }
        if let Some(value) = argument.strip_prefix("-e").filter(|_| *argument != "-E")
            && value != OFFICIAL
        {
            return true;
        }
        index += 1;
    }
    false
}

// Reviewed against Vault v2.1.0. Unknown command paths remain tokenless: a
// future command must not receive the protected token until its use is known.
fn vault_invocation_is_secretless(args: &[OsString]) -> bool {
    let Some(args) = args
        .iter()
        .map(|argument| argument.to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return true;
    };
    let before_separator = args
        .split(|argument| *argument == "--")
        .next()
        .unwrap_or_default();
    if before_separator.is_empty()
        || before_separator
            .iter()
            .any(|argument| matches!(*argument, "-h" | "-help" | "--help"))
        || before_separator.iter().any(|argument| {
            [
                "output-curl-string",
                "output-policy",
                "autocomplete-install",
                "autocomplete-uninstall",
            ]
            .iter()
            .any(|flag| vault_flag_is_enabled(argument, flag))
        })
        || std::env::var_os("VAULT_TOKEN").is_some_and(|value| !value.is_empty())
        || vault_invocation_uses_unsafe_transport(before_separator)
    {
        return true;
    }

    let command = before_separator[0];
    let subcommand = before_separator.get(1).copied();
    let requires_token = match command {
        "agent" => subcommand == Some("generate-config"),
        "debug" | "delete" | "list" | "monitor" | "patch" | "read" | "ssh" | "version-history"
        | "write" => true,
        "unwrap" => vault_unwrap_uses_ambient_token(&args),
        "events" => subcommand == Some("subscribe"),
        "audit" => matches!(subcommand, Some("disable" | "enable" | "list")),
        "auth" => match subcommand {
            Some("help") => !vault_auth_help_is_local(before_separator),
            command => matches!(
                command,
                Some("disable" | "enable" | "list" | "move" | "tune")
            ),
        },
        "lease" => matches!(subcommand, Some("lookup" | "renew" | "revoke")),
        "namespace" => matches!(
            subcommand,
            Some("create" | "delete" | "list" | "lock" | "lookup" | "patch" | "unlock")
        ),
        "operator" => vault_operator_invocation_requires_token(&before_separator[1..]),
        "pki" => matches!(
            subcommand,
            Some("health-check" | "issue" | "list-intermediates" | "reissue" | "verify-sign")
        ),
        "plugin" => match subcommand {
            Some("runtime") => matches!(
                before_separator.get(2).copied(),
                Some("deregister" | "info" | "list" | "register")
            ),
            command => matches!(
                command,
                Some("deregister" | "info" | "list" | "register" | "reload" | "reload-status")
            ),
        },
        "policy" => matches!(subcommand, Some("delete" | "list" | "read" | "write")),
        "print" => subcommand == Some("token"),
        "secrets" => matches!(
            subcommand,
            Some("disable" | "enable" | "list" | "move" | "tune")
        ),
        "transform" | "transit" => matches!(subcommand, Some("import" | "import-version")),
        "token" => matches!(
            subcommand,
            Some("capabilities" | "create" | "lookup" | "renew" | "revoke")
        ),
        "kv" => match subcommand {
            Some("metadata") => matches!(
                before_separator.get(2).copied(),
                Some("delete" | "get" | "patch" | "put")
            ),
            command => matches!(
                command,
                Some(
                    "delete"
                        | "destroy"
                        | "enable-versioning"
                        | "get"
                        | "list"
                        | "patch"
                        | "put"
                        | "rollback"
                        | "undelete"
                )
            ),
        },
        _ => false,
    };
    !requires_token
}

fn vault_operator_invocation_requires_token(args: &[&str]) -> bool {
    let Some(command) = args.first() else {
        return false;
    };
    match *command {
        "generate-root" => !args.iter().skip(1).any(|argument| {
            matches!(*argument, "-decode" | "--decode")
                || argument.starts_with("-decode=")
                || argument.starts_with("--decode=")
        }),
        "key-status" | "members" | "rekey" | "rotate" | "seal" | "step-down" | "usage"
        | "utilization" => true,
        "raft" => match args.get(1).copied() {
            Some("autopilot") => matches!(
                args.get(2).copied(),
                Some("get-config" | "set-config" | "state")
            ),
            Some("snapshot") => {
                matches!(args.get(2).copied(), Some("restore" | "save"))
            }
            command => matches!(command, Some("list-peers" | "remove-peer")),
        },
        _ => false,
    }
}

fn vault_auth_help_is_local(args: &[&str]) -> bool {
    matches!(
        args.last().copied(),
        Some(
            "alicloud"
                | "aws"
                | "cert"
                | "cf"
                | "gcp"
                | "github"
                | "kerberos"
                | "ldap"
                | "oci"
                | "oidc"
                | "okta"
                | "pcf"
                | "radius"
                | "token"
                | "userpass"
        )
    )
}

fn vault_unwrap_uses_ambient_token(args: &[&str]) -> bool {
    let options_with_values = [
        "-address",
        "--address",
        "-agent-address",
        "--agent-address",
        "-ca-cert",
        "--ca-cert",
        "-ca-path",
        "--ca-path",
        "-client-cert",
        "--client-cert",
        "-client-key",
        "--client-key",
        "-field",
        "--field",
        "-format",
        "--format",
        "-header",
        "--header",
        "-mfa",
        "--mfa",
        "-namespace",
        "--namespace",
        "-ns",
        "--ns",
        "-tls-server-name",
        "--tls-server-name",
        "-wrap-ttl",
        "--wrap-ttl",
    ];
    let mut index = 1;
    while let Some(argument) = args.get(index) {
        if *argument == "--" {
            return args.get(index + 1).is_none();
        }
        if options_with_values.contains(argument) {
            index += 2;
        } else if argument.starts_with('-') {
            index += 1;
        } else {
            return false;
        }
    }
    true
}

fn vault_invocation_uses_unsafe_transport(args: &[&str]) -> bool {
    if std::env::var_os("VAULT_SKIP_VERIFY")
        .and_then(|value| value.to_str().map(str::to_ascii_lowercase))
        .is_some_and(|value| matches!(value.as_str(), "1" | "t" | "true"))
        || ["VAULT_ADDR", "VAULT_AGENT_ADDR"].iter().any(|key| {
            std::env::var_os(key)
                .is_some_and(|value| value.to_str().is_none_or(vault_address_is_http))
        })
    {
        return true;
    }

    let mut index = 0;
    while let Some(argument) = args.get(index) {
        if vault_flag_is_enabled(argument, "tls-skip-verify") {
            return true;
        }
        if matches!(
            *argument,
            "-address" | "--address" | "-agent-address" | "--agent-address"
        ) {
            if args
                .get(index + 1)
                .is_some_and(|value| vault_address_is_http(value))
            {
                return true;
            }
            index += 2;
            continue;
        }
        if [
            "-address=",
            "--address=",
            "-agent-address=",
            "--agent-address=",
        ]
        .iter()
        .find_map(|prefix| argument.strip_prefix(prefix))
        .is_some_and(vault_address_is_http)
        {
            return true;
        }
        index += 1;
    }
    false
}

fn vault_flag_value_is_true(value: &str) -> bool {
    matches!(value, "1" | "t" | "T" | "true" | "TRUE" | "True")
}

fn vault_flag_is_enabled(argument: &str, name: &str) -> bool {
    ["-", "--"].iter().any(|dashes| {
        let Some(value) = argument
            .strip_prefix(dashes)
            .and_then(|argument| argument.strip_prefix(name))
        else {
            return false;
        };
        value.is_empty()
            || value
                .strip_prefix('=')
                .is_some_and(vault_flag_value_is_true)
    })
}

fn vault_address_is_http(value: &str) -> bool {
    value
        .get(.."http://".len())
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"))
}

// Reviewed against vt-cli v1.3.1. Unknown command paths remain tokenless: a
// future command must not receive the protected API key until it is reviewed.
fn virustotal_invocation_is_secretless(args: &[OsString]) -> bool {
    let Some(args) = args
        .iter()
        .map(|argument| argument.to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return true;
    };
    let args = args
        .split(|argument| *argument == "--")
        .next()
        .unwrap_or_default();
    if args.is_empty()
        || args
            .iter()
            .any(|argument| matches!(*argument, "-h" | "--help"))
        || virustotal_invocation_has_caller_api_key(args)
        || std::env::var_os("VTCLI_APIKEY").is_some_and(|value| !value.is_empty())
        || virustotal_invocation_selects_custom_host(args)
    {
        return true;
    }

    let Some(command) = virustotal_command(args) else {
        return true;
    };
    let requires_api_key = matches!(
        command,
        "analysis"
            | "an"
            | "collection"
            | "domain"
            | "download"
            | "dl"
            | "file"
            | "group"
            | "hunting"
            | "ht"
            | "iocstream"
            | "is"
            | "ip"
            | "meta"
            | "monitor"
            | "monitorpartner"
            | "retrohunt"
            | "rh"
            | "scan"
            | "search"
            | "threatprofile"
            | "url"
            | "user"
    );
    !requires_api_key
        || !(virustotal_invocation_selects_official_host(args)
            || super::migrations::virustotal_default_config_is_safe_for_api_key())
}

fn virustotal_command<'a>(args: &'a [&str]) -> Option<&'a str> {
    let options_with_values = ["--apikey", "-k", "--format", "--host", "--proxy"];
    let mut index = 0;
    while let Some(argument) = args.get(index) {
        if options_with_values.contains(argument) {
            index += 2;
        } else if ["--apikey=", "-k=", "--format=", "--host=", "--proxy="]
            .iter()
            .any(|prefix| argument.starts_with(prefix))
            || argument.starts_with("-k") && argument.len() > 2
            || matches!(*argument, "--silent" | "-s" | "--verbose" | "-v")
            || argument.strip_prefix('-').is_some_and(|flags| {
                !flags.is_empty() && flags.chars().all(|flag| matches!(flag, 's' | 'v'))
            })
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

fn virustotal_invocation_has_caller_api_key(args: &[&str]) -> bool {
    args.iter().enumerate().any(|(index, argument)| {
        matches!(*argument, "--apikey" | "-k") && args.get(index + 1).is_some()
            || argument.starts_with("--apikey=")
            || argument.starts_with("-k=")
            || argument.starts_with("-k") && argument.len() > 2
    })
}

fn virustotal_invocation_selects_official_host(args: &[&str]) -> bool {
    const OFFICIAL_HOST: &str = "www.virustotal.com";
    args.iter().enumerate().any(|(index, argument)| {
        let host = if *argument == "--host" {
            args.get(index + 1).copied()
        } else {
            argument.strip_prefix("--host=")
        };
        host.is_some_and(|host| host.is_empty() || host.eq_ignore_ascii_case(OFFICIAL_HOST))
    })
}

fn virustotal_invocation_selects_custom_host(args: &[&str]) -> bool {
    const OFFICIAL_HOST: &str = "www.virustotal.com";
    if std::env::var_os("VTCLI_HOST").is_some_and(|value| {
        value
            .to_str()
            .is_none_or(|value| !value.is_empty() && !value.eq_ignore_ascii_case(OFFICIAL_HOST))
    }) {
        return true;
    }
    args.iter().enumerate().any(|(index, argument)| {
        let host = if *argument == "--host" {
            args.get(index + 1).copied()
        } else {
            argument.strip_prefix("--host=")
        };
        host.is_some_and(|host| !host.is_empty() && !host.eq_ignore_ascii_case(OFFICIAL_HOST))
    })
}

// Reviewed against vultr-cli v3.11.0. Unknown command paths remain tokenless:
// a future command must not receive the protected API key until it is reviewed.
fn vultr_invocation_is_secretless(args: &[OsString]) -> bool {
    let Some(args) = args
        .iter()
        .map(|argument| argument.to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return true;
    };
    let args = args
        .split(|argument| *argument == "--")
        .next()
        .unwrap_or_default();
    if args.is_empty() || vultr_help_requested(args) {
        return true;
    }
    let Some((command, command_index)) = vultr_command(args) else {
        return true;
    };
    let authenticated_root = matches!(
        command,
        "account"
            | "backups"
            | "backup"
            | "b"
            | "bare-metal"
            | "bm"
            | "billing"
            | "block-storage"
            | "bs"
            | "cdn"
            | "container-registry"
            | "cr"
            | "database"
            | "dns"
            | "firewall"
            | "fw"
            | "inference"
            | "instance"
            | "iso"
            | "kubernetes"
            | "k"
            | "load-balancer"
            | "logs"
            | "log"
            | "object-storage"
            | "reserved-ip"
            | "rip"
            | "script"
            | "ss"
            | "startup-script"
            | "snapshot"
            | "sn"
            | "ssh-key"
            | "ssh"
            | "ssh-keys"
            | "sshkeys"
            | "user"
            | "users"
            | "u"
            | "vpc"
    );
    !authenticated_root
        || !vultr_command_path_requires_api_key(command, &args[command_index + 1..])
        || super::migrations::vultr_config_has_api_key(vultr_config_argument(args))
}

fn vultr_help_requested(args: &[&str]) -> bool {
    args.iter().enumerate().any(|(index, argument)| {
        matches!(*argument, "-h" | "--help") && (index == 0 || !args[index - 1].starts_with('-'))
    })
}

fn vultr_command<'a>(args: &'a [&str]) -> Option<(&'a str, usize)> {
    let mut index = 0;
    while let Some(argument) = args.get(index) {
        if matches!(*argument, "--config" | "--output" | "-o") {
            index += 2;
        } else if ["--config=", "--output=", "-o="]
            .iter()
            .any(|prefix| argument.starts_with(prefix))
            || argument.starts_with("-o") && argument.len() > 2
        {
            index += 1;
        } else if argument.starts_with('-') {
            return None;
        } else {
            return Some((argument, index));
        }
    }
    None
}

fn vultr_command_path_requires_api_key(root: &str, args: &[&str]) -> bool {
    let groups = [
        "acl",
        "advanced-option",
        "alert",
        "app",
        "artifact",
        "available-connector",
        "backup",
        "cluster",
        "connection-pool",
        "connector",
        "credentials",
        "db",
        "domain",
        "firewall",
        "firewall-rule",
        "forwarding",
        "group",
        "history",
        "image",
        "invoice",
        "ipv4",
        "ipv6",
        "iso",
        "kafka-connect",
        "kafka-rest",
        "maintenance",
        "migration",
        "nat-gateway",
        "node",
        "node-pool",
        "os",
        "plan",
        "port-forwarding-rule",
        "pull",
        "push",
        "quota",
        "read-replica",
        "record",
        "repository",
        "reverse-dns",
        "rule",
        "schema-registry",
        "ssl",
        "tier",
        "topic",
        "upgrades",
        "usage",
        "user",
        "user-data",
        "version",
        "vpc",
    ];
    let operations = [
        "attach",
        "bandwidth",
        "change",
        "config",
        "convert",
        "create",
        "create-endpoint",
        "create-url",
        "default-ipv4",
        "delete",
        "delete-file",
        "delete-ipv6",
        "destroy",
        "detach",
        "disable-auto-ssl",
        "dnssec",
        "dnssec-info",
        "docker",
        "fork",
        "get",
        "get-file",
        "get-schema",
        "get-status",
        "halt",
        "info",
        "items",
        "label",
        "list",
        "list-files",
        "list-ipv6",
        "pause",
        "plans",
        "promote",
        "public",
        "purge",
        "reboot",
        "recycle",
        "regenerate-keys",
        "regions",
        "reinstall",
        "resize",
        "restart",
        "restart-task",
        "restore",
        "resume",
        "set",
        "set-auto-ssl",
        "set-certificate",
        "set-ipv4",
        "set-ipv6",
        "soa-info",
        "soa-update",
        "start",
        "status",
        "stop",
        "tags",
        "tiers",
        "update",
        "update-firewall-group",
        "upgrade",
        "versions",
        "vnc",
    ];
    let aliases = ["a", "c", "d", "destroy", "g", "l", "u"];
    let mut index = 0;
    while let Some(argument) = args.get(index) {
        if matches!(*argument, "--config" | "--output" | "-o") {
            index += 2;
            continue;
        }
        if ["--config=", "--output=", "-o="]
            .iter()
            .any(|prefix| argument.starts_with(prefix))
            || argument.starts_with("-o") && argument.len() > 2
        {
            index += 1;
            continue;
        }
        if (root == "bare-metal" || root == "bm") && matches!(*argument, "ipv4" | "ipv6")
            || operations.contains(argument)
            || aliases.contains(argument)
        {
            return true;
        }
        if !groups.contains(argument) {
            return false;
        }
        index += 1;
    }
    false
}

fn vultr_config_argument<'a>(args: &'a [&'a str]) -> Option<&'a Path> {
    args.iter().enumerate().rev().find_map(|(index, argument)| {
        if *argument == "--config" {
            args.get(index + 1).map(Path::new)
        } else {
            argument.strip_prefix("--config=").map(Path::new)
        }
    })
}

fn wsk_invocation_is_secretless(args: &[OsString]) -> bool {
    let args = args
        .split(|arg| arg == "--")
        .next()
        .unwrap_or_default()
        .iter()
        .map(|arg| arg.to_str())
        .collect::<Option<Vec<_>>>();
    let Some(args) = args else { return true };
    let Some((root, mut index, caller_auth)) = wsk_root_command(&args) else {
        return true;
    };
    if root == "list" {
        return caller_auth || super::migrations::wsk_selected_props_have_auth();
    }

    while index < args.len() {
        match wsk_global_option(&args, index) {
            Some((next, _)) => index = next,
            None => break,
        }
    }
    let Some(operation) = args.get(index).copied() else {
        return true;
    };
    if is_help_argument(operation) {
        return true;
    }
    index += 1;
    if args.get(index).is_some_and(|arg| is_help_argument(arg)) {
        return true;
    }

    let needs_auth = match (root, operation) {
        ("action", "create" | "delete" | "get" | "invoke" | "list" | "update")
        | ("activation", "get" | "list" | "logs" | "poll" | "result")
        | ("api", "create" | "delete" | "get" | "list")
        | ("namespace", "get" | "list")
        | ("package", "bind" | "create" | "delete" | "get" | "list" | "refresh" | "update")
        | ("project", "deploy" | "export" | "sync" | "undeploy")
        | (
            "rule",
            "create" | "delete" | "disable" | "enable" | "get" | "list" | "status" | "update",
        )
        | ("trigger", "create" | "delete" | "fire" | "get" | "list" | "update") => true,
        ("property", "get") => wsk_property_get_needs_auth(&args[index..]),
        _ => false,
    };
    !needs_auth || caller_auth || super::migrations::wsk_selected_props_have_auth()
}

fn wsk_root_command<'a>(args: &'a [&str]) -> Option<(&'a str, usize, bool)> {
    let mut index = 0;
    let mut caller_auth = false;
    while index < args.len() {
        if is_help_argument(args[index]) || matches!(args[index], "--version" | "version") {
            return None;
        }
        let Some((next, auth)) = wsk_global_option(args, index) else {
            break;
        };
        caller_auth |= auth;
        index = next;
    }
    let root = *args.get(index)?;
    if root.starts_with('-') || matches!(root, "help" | "version") {
        return None;
    }
    Some((root, index + 1, caller_auth))
}

fn wsk_global_option(args: &[&str], index: usize) -> Option<(usize, bool)> {
    let argument = *args.get(index)?;
    if matches!(
        argument,
        "--debug" | "-d" | "--insecure" | "-i" | "--verbose" | "-v"
    ) {
        return Some((index + 1, false));
    }
    if [
        "--cert",
        "--key",
        "--auth",
        "-u",
        "--apihost",
        "--apiversion",
    ]
    .contains(&argument)
    {
        let value = *args.get(index + 1)?;
        return Some((
            index + 2,
            matches!(argument, "--auth" | "-u") && !value.is_empty(),
        ));
    }
    for option in ["--cert=", "--key=", "--apihost=", "--apiversion="] {
        if argument.starts_with(option) {
            return Some((index + 1, false));
        }
    }
    if let Some(value) = argument.strip_prefix("--auth=") {
        return Some((index + 1, !value.is_empty()));
    }
    if let Some(value) = argument.strip_prefix("-u") {
        if !value.is_empty() {
            return Some((index + 1, true));
        }
    }
    None
}

fn is_help_argument(argument: &str) -> bool {
    matches!(argument, "help" | "--help" | "-h")
}

fn wsk_property_get_needs_auth(args: &[&str]) -> bool {
    if args.is_empty() {
        return true;
    }
    let mut selected_property = false;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index];
        if matches!(argument, "--auth" | "--all" | "--namespace")
            || argument.starts_with("--auth=")
            || argument.starts_with("--all=")
            || argument.starts_with("--namespace=")
        {
            return true;
        }
        if matches!(
            argument,
            "--cert"
                | "--key"
                | "--apihost"
                | "--apiversion"
                | "--apibuild"
                | "--apibuildno"
                | "--cliversion"
        ) {
            selected_property = true;
            index += 1;
            continue;
        }
        if matches!(
            argument,
            "--debug" | "-d" | "--insecure" | "-i" | "--verbose" | "-v"
        ) {
            index += 1;
            continue;
        }
        if matches!(argument, "--output" | "-o") {
            if args.get(index + 1).is_none() {
                return false;
            }
            index += 2;
            continue;
        }
        if argument.starts_with("--output=") {
            index += 1;
            continue;
        }
        return false;
    }
    !selected_property
}

fn akamai_invocation_is_secretless(args: &[OsString]) -> bool {
    let args = args
        .iter()
        .map(|arg| arg.to_str())
        .collect::<Option<Vec<_>>>();
    let Some(args) = args else { return true };
    let mut index = 0;
    let mut edgerc = None;
    let mut section = std::env::var("AKAMAI_EDGERC_SECTION")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "default".to_string());
    while index < args.len() {
        let argument = args[index];
        if matches!(argument, "--help" | "-h" | "--version") {
            return true;
        }
        if argument == "--" {
            index += 1;
            break;
        }
        if matches!(argument, "--bash" | "--zsh" | "--generate-bash-completion") {
            index += 1;
            continue;
        }
        match argument {
            "--edgerc" | "-e" => {
                let Some(value) = args.get(index + 1) else {
                    return true;
                };
                edgerc = Some(PathBuf::from(value));
                index += 2;
            }
            "--section" | "-s" => {
                let Some(value) = args.get(index + 1) else {
                    return true;
                };
                section = (*value).to_string();
                index += 2;
            }
            "--accountkey" | "--account-key" | "--proxy" => {
                if args.get(index + 1).is_none() {
                    return true;
                }
                index += 2;
            }
            "--daemon" => return true,
            _ if argument.starts_with("--edgerc=") || argument.starts_with("-e=") => {
                edgerc = argument
                    .split_once('=')
                    .map(|(_, value)| PathBuf::from(value));
                index += 1;
            }
            _ if argument.starts_with("--section=") || argument.starts_with("-s=") => {
                section = argument
                    .split_once('=')
                    .map(|(_, value)| value.to_string())
                    .unwrap_or_default();
                index += 1;
            }
            _ if ["--accountkey=", "--account-key=", "--proxy="]
                .iter()
                .any(|option| argument.starts_with(option)) =>
            {
                index += 1;
            }
            _ if argument.starts_with('-') => return true,
            _ => break,
        }
    }
    let Some(command) = args.get(index).copied() else {
        return true;
    };
    if matches!(
        command,
        "config"
            | "get"
            | "help"
            | "install"
            | "list"
            | "search"
            | "uninstall"
            | "update"
            | "upgrade"
    ) {
        return true;
    }
    if args
        .get(index + 1)
        .is_some_and(|argument| matches!(*argument, "help" | "--help" | "-h" | "--version"))
    {
        return true;
    }
    !super::migrations::akamai_command_is_installed(command)
        || super::migrations::akamai_caller_has_credentials(edgerc.as_deref(), &section)
}

fn algolia_invocation_is_secretless(args: &[OsString]) -> bool {
    if algolia_help_requested(args) {
        return true;
    }
    let Some(command_index) = algolia_command_index(args) else {
        return true;
    };
    let Some(command) = args[command_index].to_str() else {
        return true;
    };

    let needs_search_credentials =
        matches!(
            command,
            "search"
                | "indices"
                | "index"
                | "objects"
                | "records"
                | "settings"
                | "rules"
                | "rule"
                | "synonyms"
                | "synonym"
                | "dictionary"
                | "dictionaries"
                | "dict"
                | "events"
                | "compositions"
        ) || matches!(command, "apikeys" | "api-key" | "api-keys" | "apikey")
            && args
                .get(command_index + 1)
                .is_none_or(|subcommand| subcommand != "rotate")
            || command == "auth"
                && args
                    .get(command_index + 1)
                    .is_some_and(|subcommand| subcommand == "status");
    if needs_search_credentials {
        return algolia_search_credentials_are_supplied(args);
    }

    if matches!(command, "crawler" | "crawlers") {
        return std::env::var_os("ALGOLIA_CRAWLER_USER_ID").is_some_and(|value| !value.is_empty())
            && std::env::var_os("ALGOLIA_CRAWLER_API_KEY").is_some_and(|value| !value.is_empty());
    }

    true
}

fn algolia_help_requested(args: &[OsString]) -> bool {
    for (index, argument) in args.iter().enumerate() {
        if argument == "--" {
            break;
        }
        if matches!(
            argument.to_str(),
            Some("--help" | "-h" | "--version" | "-v")
        ) && index
            .checked_sub(1)
            .and_then(|previous| args[previous].to_str())
            .is_none_or(|previous| !previous.starts_with('-'))
        {
            return true;
        }
    }
    false
}

fn algolia_command_index(args: &[OsString]) -> Option<usize> {
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].to_str()?;
        if argument == "--" {
            return None;
        }
        if matches!(argument, "--help" | "-h" | "--version" | "-v") {
            return None;
        }
        if matches!(
            argument,
            "--profile"
                | "-p"
                | "--application-id"
                | "--api-key"
                | "--admin-api-key"
                | "--search-hosts"
        ) {
            index += 2;
            continue;
        }
        if [
            "--profile=",
            "--application-id=",
            "--api-key=",
            "--admin-api-key=",
            "--search-hosts=",
        ]
        .iter()
        .any(|option| argument.starts_with(option))
        {
            index += 1;
            continue;
        }
        return (!argument.starts_with('-')).then_some(index);
    }
    None
}

fn algolia_search_credentials_are_supplied(args: &[OsString]) -> bool {
    let application_id = algolia_option_value(args, "--application-id")
        .or_else(|| std::env::var_os("ALGOLIA_APPLICATION_ID"));
    let api_key = algolia_option_value(args, "--api-key")
        .or_else(|| algolia_option_value(args, "--admin-api-key"))
        .or_else(|| std::env::var_os("ALGOLIA_API_KEY"))
        .or_else(|| std::env::var_os("ALGOLIA_ADMIN_API_KEY"));
    application_id.is_some_and(|value| !value.is_empty())
        && api_key.is_some_and(|value| !value.is_empty())
}

fn algolia_option_value(args: &[OsString], option: &str) -> Option<OsString> {
    let equals = format!("{option}=");
    for (index, argument) in args.iter().enumerate() {
        if argument == "--" {
            break;
        }
        if argument == option {
            return args.get(index + 1).cloned();
        }
        if let Some(value) = argument.to_str()?.strip_prefix(&equals) {
            return Some(OsString::from(value));
        }
    }
    None
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
            vec!["exec", "eslint", "."],
            vec!["init", "@scope/app"],
            vec!["version"],
            vec!["install", "--help"],
            vec!["install", "--version"],
            vec!["--cache", "install", "run", "build"],
            vec!["--future-option", "install"],
            vec![
                "install",
                "--//registry.npmjs.org/:_authToken=provided-token",
            ],
            vec!["install", "--_authToken"],
            vec!["install", "--//registry.npmjs.org/:_authToken"],
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
            vec!["--global", "install"],
            vec![
                "--registry",
                "https://registry.npmjs.org",
                "view",
                "private-package",
            ],
            vec!["--workspace", "app", "audit"],
            vec!["--loglevel", "verbose", "whoami"],
            vec!["--color=always", "publish"],
            vec!["-gq", "install"],
            vec!["-C/tmp", "view", "private-package"],
            vec!["i", "private-package"],
            vec!["ci"],
            vec!["audit"],
            vec!["doctor"],
            vec!["view", "private-package"],
            vec!["whoami"],
            vec!["publish"],
            vec!["dist-tags", "ls", "private-package"],
            vec!["trust", "list", "private-package"],
            vec!["install", "--", "--version"],
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
    fn doctl_requests_token_only_for_audited_runnable_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-doctl");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let previous_context = std::env::var_os("DIGITALOCEAN_CONTEXT");
        let previous_sandbox = std::env::var_os("SNAP_SANDBOX_INSTALL");
        unsafe {
            std::env::remove_var("DIGITALOCEAN_CONTEXT");
            std::env::remove_var("SNAP_SANDBOX_INSTALL");
        }
        let script_path = dir.join("doctl");
        let script = stub_script(
            &wrapper("doctl").unwrap().primary,
            Path::new("/opt/homebrew/bin/doctl"),
        );
        let args = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for command in [
            vec![],
            vec!["--help"],
            vec!["version"],
            vec!["completion", "zsh"],
            vec!["__complete", "auth"],
            vec!["compute"],
            vec!["compute", "droplet"],
            vec!["k8s", "c"],
            vec!["apps", "dev", "config"],
            vec!["apps", "spec", "validate", "app.yaml"],
            vec!["auth", "list"],
            vec!["auth", "ls"],
            vec!["auth", "switch", "--context", "team"],
            vec!["auth", "remove", "--context", "team"],
            vec!["serverless", "get-metadata", "."],
            vec!["future-command"],
            vec!["compute", "future-command"],
            vec!["--access-token", "caller-token", "account", "get"],
            vec!["-tcaller-token", "account", "get"],
            vec!["--context", "team", "account", "get"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "doctl {command:?}",
            );
        }

        for command in [
            vec!["account", "get"],
            vec!["compute", "droplet", "list"],
            vec!["compute", "d", "g", "123"],
            vec!["k8s", "c", "ls"],
            vec!["--output", "json", "account", "get"],
            vec!["account", "get", "--output=json"],
            vec!["--context", "default", "account", "get"],
            vec!["--context=DEFAULT", "account", "get"],
            vec!["auth", "init"],
            vec!["auth", "token"],
            vec!["serverless", "install"],
            vec!["serverless", "status"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "doctl {command:?}",
            );
        }

        unsafe { std::env::set_var("DIGITALOCEAN_CONTEXT", "team") };
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["account", "get"]),
        ));
        unsafe {
            std::env::remove_var("DIGITALOCEAN_CONTEXT");
            std::env::set_var("SNAP_SANDBOX_INSTALL", "1");
        }
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["serverless", "install"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["version"]),
        ));

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
            match previous_context {
                Some(value) => std::env::set_var("DIGITALOCEAN_CONTEXT", value),
                None => std::env::remove_var("DIGITALOCEAN_CONTEXT"),
            }
            match previous_sandbox {
                Some(value) => std::env::set_var("SNAP_SANDBOX_INSTALL", value),
                None => std::env::remove_var("SNAP_SANDBOX_INSTALL"),
            }
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn flyctl_requests_token_only_for_audited_authenticated_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-flyctl");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let previous_api_token = std::env::var_os("FLY_API_TOKEN");
        unsafe { std::env::remove_var("FLY_API_TOKEN") };
        let stub = &wrapper("flyctl").unwrap().primary;
        let script_path = dir.join("flyctl");
        let script = stub_script(stub, Path::new("/opt/homebrew/bin/flyctl"));
        let args = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for command in [
            vec![],
            vec!["--help"],
            vec!["--version"],
            vec!["deploy", "--help"],
            vec!["completion", "zsh"],
            vec!["docs"],
            vec!["jobs"],
            vec!["jobs", "open"],
            vec!["version", "upgrade"],
            vec!["settings", "analytics"],
            vec!["settings", "autoupdate", "disable"],
            vec!["agent"],
            vec!["agent", "ping"],
            vec!["agent", "stop"],
            vec!["auth", "login"],
            vec!["auth", "signup"],
            vec!["platform", "status", "--json"],
            vec!["mcp", "list"],
            vec!["mcp", "inspect", "--url", "http://localhost:8080"],
            vec!["mcp", "proxy", "--url", "http://localhost:8080"],
            vec!["mcp", "wrap", "--mcp", "server"],
            vec!["launch", "plan"],
            vec!["apps", "suspend"],
            vec!["tokens", "create"],
            vec!["future-command"],
            vec!["apps", "future-command"],
            vec!["--access-token", "caller-token", "apps", "list"],
            vec!["-tcaller-token", "apps", "list"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "flyctl {command:?}",
            );
        }

        for command in [
            vec!["apps", "list"],
            vec!["deploy"],
            vec!["dashboard"],
            vec!["--verbose", "apps", "list"],
            vec!["launch", "plan", "create", "manifest.json"],
            vec!["agent", "run"],
            vec!["auth", "logout"],
            vec!["auth", "token"],
            vec!["platform", "regions"],
            vec!["postgres", "list"],
            vec!["metrics", "send"],
            vec!["tokens", "debug"],
            vec!["mcp", "server"],
            vec!["mcp", "add"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "flyctl {command:?}",
            );
        }

        unsafe { std::env::set_var("FLY_API_TOKEN", "caller-token") };
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["apps", "list"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["version"]),
        ));

        let fly_stub = stubs(wrapper("flyctl").unwrap())
            .find(|candidate| candidate.command == "fly")
            .unwrap();
        let fly_path = dir.join("fly");
        let fly_script = stub_script(fly_stub, Path::new("/opt/homebrew/bin/fly"));
        let fly_args = [fly_path.clone().into_os_string(), OsString::from("version")];
        assert!(invocation_is_secretless(
            &fly_path,
            fly_script.as_bytes(),
            &fly_args,
        ));

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
            match previous_api_token {
                Some(value) => std::env::set_var("FLY_API_TOKEN", value),
                None => std::env::remove_var("FLY_API_TOKEN"),
            }
        }
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
            vec!["auth", "dpop-gen", "--private-key", "/tmp/id", "--pat="],
            vec!["auth", "dpop-gen", "--private-key", "/tmp/id", "--pat", ""],
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
    fn gotify_requests_secrets_only_for_message_delivery() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-gotify");
        let previous_token = std::env::var_os("GOTIFY_TOKEN");
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir);
            std::env::remove_var("GOTIFY_TOKEN");
        }
        let script_path = dir.join("gotify");
        let script = stub_script(
            &wrapper("gotify").unwrap().primary,
            Path::new("/opt/homebrew/bin/gotify"),
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
            vec!["help", "push"],
            vec!["init"],
            vec!["config"],
            vec!["version"],
            vec!["v"],
            vec!["future-command"],
            vec!["push", "--help"],
            vec!["watch", "--help"],
            vec!["--future-option", "push", "message"],
            vec!["push", "--token", "provided", "message"],
            vec!["p", "--token=provided", "message"],
            vec!["watch", "--token=provided", "--", "sh", "script.sh"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "gotify {command:?}",
            );
        }
        for command in [
            vec!["push", "message"],
            vec!["p", "message"],
            vec!["push", "--token=", "message"],
            vec!["push", "--token", "", "message"],
            vec!["watch", "date"],
            vec!["watch", "--", "sh", "script.sh"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "gotify {command:?}",
            );
        }

        unsafe { std::env::set_var("GOTIFY_TOKEN", "already-provided") };
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["push", "message"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["push", "message"]),
        ));

        unsafe {
            match previous_token {
                Some(value) => std::env::set_var("GOTIFY_TOKEN", value),
                None => std::env::remove_var("GOTIFY_TOKEN"),
            }
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn gptcommit_requests_secrets_only_when_the_hook_can_call_the_llm() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-gptcommit");
        let previous_gptcommit_key = std::env::var_os("GPTCOMMIT__OPENAI__API_KEY");
        let previous_openai_key = std::env::var_os("OPENAI_API_KEY");
        let previous_model_provider = std::env::var_os("GPTCOMMIT__MODEL_PROVIDER");
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir);
            std::env::remove_var("GPTCOMMIT__OPENAI__API_KEY");
            std::env::remove_var("OPENAI_API_KEY");
            std::env::remove_var("GPTCOMMIT__MODEL_PROVIDER");
        }
        let script_path = dir.join("gptcommit");
        let script = stub_script(
            &wrapper("gptcommit").unwrap().primary,
            Path::new("/opt/homebrew/bin/gptcommit"),
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
            vec!["help", "prepare-commit-msg"],
            vec!["install"],
            vec!["uninstall"],
            vec!["config", "keys"],
            vec!["config", "get", "openai.api_key"],
            vec!["config", "set", "output.lang", "fr"],
            vec!["future-command"],
            vec!["--verbose", "config", "list"],
            vec!["prepare-commit-msg", "--help"],
            vec!["prepare-commit-msg", "--commit-source", "message"],
            vec![
                "-v",
                "prepare-commit-msg",
                "--commit-msg-file=/tmp/message",
                "--commit-source=merge",
            ],
            vec![
                "prepare-commit-msg",
                "--commit-msg-file",
                "/tmp/message",
                "--commit-source",
                "squash",
            ],
            vec![
                "config",
                "set",
                "prompt.commit_title",
                "--",
                "arbitrary text",
            ],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "gptcommit {command:?}",
            );
        }
        for command in [
            vec![
                "prepare-commit-msg",
                "--commit-msg-file",
                "/tmp/message",
                "--commit-source",
                "",
            ],
            vec![
                "--verbose",
                "prepare-commit-msg",
                "--commit-source=commit",
                "--commit-msg-file=/tmp/message",
            ],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "gptcommit {command:?}",
            );
        }

        unsafe { std::env::set_var("OPENAI_API_KEY", "already-provided") };
        let credentialed = args(&[
            "prepare-commit-msg",
            "--commit-msg-file=/tmp/message",
            "--commit-source=commit",
        ]);
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &credentialed,
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &credentialed,
        ));

        unsafe {
            std::env::remove_var("OPENAI_API_KEY");
            std::env::set_var("GPTCOMMIT__MODEL_PROVIDER", "tester-foobar");
        }
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &credentialed,
        ));

        unsafe {
            match previous_gptcommit_key {
                Some(value) => std::env::set_var("GPTCOMMIT__OPENAI__API_KEY", value),
                None => std::env::remove_var("GPTCOMMIT__OPENAI__API_KEY"),
            }
            match previous_openai_key {
                Some(value) => std::env::set_var("OPENAI_API_KEY", value),
                None => std::env::remove_var("OPENAI_API_KEY"),
            }
            match previous_model_provider {
                Some(value) => std::env::set_var("GPTCOMMIT__MODEL_PROVIDER", value),
                None => std::env::remove_var("GPTCOMMIT__MODEL_PROVIDER"),
            }
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn grafanactl_requests_secrets_only_for_default_context_remote_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-grafanactl");
        let context_vars = [
            "GRAFANACTL_CONFIG",
            "GRAFANACTL_ENV_ASSIGNMENTS",
            "GRAFANA_SERVER",
            "GRAFANA_TOKEN",
            "GRAFANA_USER",
        ];
        let previous_values = context_vars.map(|name| std::env::var_os(name));
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir);
            for name in context_vars {
                std::env::remove_var(name);
            }
        }
        let script_path = dir.join("grafanactl");
        let script = stub_script(
            &wrapper("grafanactl").unwrap().primary,
            Path::new("/opt/homebrew/bin/grafanactl"),
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
            vec!["help", "resources"],
            vec!["config", "view"],
            vec!["config", "view", "--raw"],
            vec!["config", "current-context"],
            vec!["config", "list-contexts"],
            vec!["config", "set", "current-context", "dev"],
            vec!["config", "unset", "contexts.dev"],
            vec!["config", "use-context", "dev"],
            vec!["future-command"],
            vec!["resources", "future-command"],
            vec!["--future-option", "resources", "get", "dashboards/foo"],
            vec!["resources", "--config", "/tmp/other.yaml", "get"],
            vec!["resources", "get", "--context=staging", "dashboards/foo"],
            vec!["config", "set", "name", "--", "arbitrary value"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "grafanactl {command:?}",
            );
        }
        for command in [
            vec!["config", "check"],
            vec!["resources", "delete", "dashboards/foo"],
            vec!["resources", "edit", "dashboards/foo"],
            vec!["resources", "get", "dashboards/foo"],
            vec!["resources", "list"],
            vec!["resources", "pull", "dashboards/foo"],
            vec!["resources", "push", "dashboards/foo"],
            vec!["resources", "serve"],
            vec!["resources", "serve", "--script", "sh generate.sh"],
            vec!["resources", "validate"],
            vec!["--no-color", "resources", "-vv", "list"],
            vec!["--no-color=false", "--verbose=2", "resources", "list"],
            vec!["resources", "--config", "", "get", "dashboards/foo"],
            vec!["resources", "get", "--", "--config", "/tmp/selector"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "grafanactl {command:?}",
            );
        }

        for name in context_vars {
            unsafe { std::env::set_var(name, "already-provided") };
            assert!(invocation_is_secretless(
                &script_path,
                script.as_bytes(),
                &args(&["resources", "get", "dashboards/foo"]),
            ));
            unsafe { std::env::remove_var(name) };
        }
        unsafe { std::env::set_var("GRAFANA_TOKEN", "") };
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["resources", "get", "dashboards/foo"]),
        ));
        unsafe { std::env::set_var("GRAFANA_TOKEN", "already-provided") };
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["resources", "get", "dashboards/foo"]),
        ));

        unsafe {
            for (name, value) in context_vars.into_iter().zip(previous_values) {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn heroku_requests_secrets_only_for_reviewed_core_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-heroku");
        let authority_vars = [
            "HEROKU_API_KEY",
            "HEROKU_CI_WEBSOCKET_URL",
            "HEROKU_CLOUD",
            "HEROKU_DATA_HOST",
            "HEROKU_EXEC_URL",
            "HEROKU_GIT_HOST",
            "HEROKU_HOST",
            "HEROKU_PARTICLEBOARD_URL",
            "HEROKU_REDIS_HOST",
            "PGDIAGNOSE_URL",
        ];
        let previous_values = authority_vars.map(|name| std::env::var_os(name));
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir);
            for name in authority_vars {
                std::env::remove_var(name);
            }
        }
        let script_path = dir.join("heroku");
        let script = stub_script(
            &wrapper("heroku").unwrap().primary,
            Path::new("/opt/homebrew/bin/heroku"),
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
            vec!["-v"],
            vec!["version"],
            vec!["apps:info", "--help"],
            vec!["status"],
            vec!["auth:login"],
            vec!["login"],
            vec!["accounts"],
            vec!["accounts:current"],
            vec!["accounts:set", "work"],
            vec!["autocomplete"],
            vec!["buildpacks:info", "example/buildpack"],
            vec!["buildpacks:search", "ruby"],
            vec!["ci:migrate-manifest"],
            vec!["container:logout"],
            vec!["data:pg:docs"],
            vec!["local", "web"],
            vec!["local:run", "--", "sh", "script.sh"],
            vec!["repl"],
            vec!["version:info"],
            vec!["plugins:install", "third-party-plugin"],
            vec!["my-plugin:run", "--", "sh", "script.sh"],
            vec!["apps:future-command"],
            vec!["--future-option", "apps"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "heroku {command:?}",
            );
        }
        for command in [
            vec!["apps"],
            vec!["apps:info", "example"],
            vec!["info", "--app", "example"],
            vec!["auth:token"],
            vec!["auth:logout"],
            vec!["logout"],
            vec!["config:get", "DATABASE_URL", "--app", "example"],
            vec!["data:pg:levels"],
            vec!["mcp:start"],
            vec!["pg:psql", "--app", "example"],
            vec!["psql", "--app", "example"],
            vec!["run", "--app", "example", "--", "sh", "script.sh"],
            vec!["webhooks", "--app", "example"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "heroku {command:?}",
            );
        }

        unsafe { std::env::set_var("HEROKU_API_KEY", "already-provided") };
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["apps"]),
        ));
        unsafe {
            std::env::remove_var("HEROKU_API_KEY");
            std::env::set_var("HEROKU_HOST", "staging.heroku.com");
        }
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["apps"]),
        ));
        unsafe {
            std::env::remove_var("HEROKU_HOST");
            std::env::set_var("HEROKU_CLOUD", "production");
        }
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["apps"]),
        ));
        unsafe { std::env::set_var("HEROKU_CLOUD", "staging") };
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["apps"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["local:run", "--", "sh", "script.sh"]),
        ));

        unsafe {
            for (name, value) in authority_vars.into_iter().zip(previous_values) {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn heroku_authenticated_command_vocabulary_is_sorted_and_unique() {
        let commands = HEROKU_AUTHENTICATED_COMMANDS.split(',').collect::<Vec<_>>();
        assert_eq!(commands.len(), 391);
        assert!(commands.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn hcloud_requests_secrets_only_for_reviewed_api_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-hcloud");
        let authority_vars = ["HCLOUD_ENDPOINT", "HCLOUD_TOKEN", "HETZNER_ENDPOINT"];
        let previous_values = authority_vars.map(|name| std::env::var_os(name));
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir);
            for name in authority_vars {
                std::env::remove_var(name);
            }
        }
        let script_path = dir.join("hcloud");
        let script = stub_script(
            &wrapper("hcloud").unwrap().primary,
            Path::new("/opt/homebrew/bin/hcloud"),
        );
        let args = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for command in [
            vec![],
            vec!["--help"],
            vec!["version"],
            vec!["--context", "prod", "version"],
            vec!["completion", "zsh"],
            vec!["context"],
            vec!["context", "list"],
            vec!["context", "create", "dev"],
            vec!["context", "create", "--token-from-env=false", "dev"],
            vec!["config"],
            vec!["config", "list"],
            vec!["config", "list", "--allow-sensitive=false"],
            vec!["config", "get", "token"],
            vec!["server"],
            vec!["server", "list", "--help"],
            vec!["server", "future-command"],
            vec!["future-command", "--", "sh", "script.sh"],
            vec!["--future-option", "server", "list"],
            vec!["--allow-sensitive", "config", "list"],
            vec!["--token-from-env", "context", "create", "dev"],
            vec!["--endpoint", "https://example.invalid/v1", "server", "list"],
            vec!["server", "list", "--endpoint=https://example.invalid/v1"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "hcloud {command:?}",
            );
        }
        for command in [
            vec!["server", "list"],
            vec!["--context", "prod", "server", "list"],
            vec!["server", "--context", "prod", "list"],
            vec!["servers", "describe", "example"],
            vec!["dns", "records", "list", "example.com"],
            vec!["storage-boxes", "snapshots", "list", "example"],
            vec!["context", "create", "--token-from-env", "dev"],
            vec!["context", "create", "dev", "--token-from-env=true"],
            vec!["config", "get", "--allow-sensitive", "token"],
            vec!["config", "list", "--allow-sensitive=true"],
            vec!["server", "ssh", "example", "--", "sh", "script.sh"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "hcloud {command:?}",
            );
        }

        unsafe { std::env::set_var("HCLOUD_TOKEN", "already-provided") };
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["server", "list"]),
        ));
        unsafe {
            std::env::remove_var("HCLOUD_TOKEN");
            std::env::set_var("HCLOUD_ENDPOINT", "https://example.invalid/v1");
        }
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["server", "list"]),
        ));
        unsafe {
            std::env::remove_var("HCLOUD_ENDPOINT");
            std::env::set_var("HETZNER_ENDPOINT", "https://example.invalid/v1");
        }
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["storage-box", "list"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["future-command", "--", "sh", "script.sh"]),
        ));

        unsafe {
            for (name, value) in authority_vars.into_iter().zip(previous_values) {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn hcloud_authenticated_command_vocabulary_is_sorted_and_unique() {
        let commands = HCLOUD_AUTHENTICATED_COMMANDS.split(',').collect::<Vec<_>>();
        assert_eq!(commands.len(), 220);
        assert!(commands.windows(2).all(|pair| pair[0] < pair[1]));
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
    fn netlify_requests_secrets_only_for_reviewed_remote_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-netlify");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let script_path = dir.join("netlify");
        let script = stub_script(
            &wrapper("netlify-cli").unwrap().primary,
            Path::new("/opt/homebrew/bin/netlify"),
        );
        let args = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for command in [
            vec![],
            vec!["help", "deploy"],
            vec!["--verbose", "--version"],
            vec!["--verbose", "functions:list"],
            vec!["functions:build"],
            vec!["functions:create", "hello", "--template", "hello-world"],
            vec!["functions:invoke", "hello"],
            vec!["functions:serve"],
            vec!["dev"],
            vec!["dev:exec", "npm", "run", "build"],
            vec!["serve"],
            vec!["logs:function", "hello"],
            vec!["api", "--list"],
            vec!["api"],
            vec!["build", "--offline"],
            vec!["deploy", "--allow-anonymous"],
            vec!["database", "status"],
            vec!["db", "migrations", "new"],
            vec!["recipes", "vscode"],
            vec!["login", "--new"],
            vec!["sites:list", "--auth", "supplied-token"],
            vec!["sites:list", "--auth=supplied-token"],
            vec!["future-command"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "netlify {command:?}",
            );
        }
        for command in [
            vec!["status"],
            vec!["--verbose", "sites:list"],
            vec!["agents:run", "fix the build"],
            vec!["env:get", "API_TOKEN"],
            vec!["api", "getSite"],
            vec!["api", "--data", "{}", "getSite"],
            vec!["build"],
            vec!["deploy"],
            vec!["database", "migrations", "pull"],
            vec!["database", "status", "--branch", "preview"],
            vec!["database", "status", "-bpreview"],
            vec!["recipes", "blobs-migrate", "store"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "netlify {command:?}",
            );
        }
        assert!(!netlify_invocation_is_secretless(
            &args(&["database", "migrations", "reset"])[1..],
            true,
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["functions:list"]),
        ));
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &[
                script_path.clone().into_os_string(),
                OsString::from_vec(vec![0xff]),
                OsString::from("status"),
            ],
        ));

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR") };
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn pulumi_requests_secrets_only_for_reviewed_cloud_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-pulumi");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let script_path = dir.join("pulumi");
        let script = stub_script(
            &wrapper("pulumi").unwrap().primary,
            Path::new("/opt/homebrew/bin/pulumi"),
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
            vec!["up", "--help=true"],
            vec!["--version"],
            vec!["version"],
            vec!["logout"],
            vec!["about", "env"],
            vec!["gen-completion", "zsh"],
            vec!["view-trace", "trace.json"],
            vec!["stack", "unselect"],
            vec!["plugin", "list"],
            vec!["plugin"],
            vec!["state"],
            vec!["api"],
            vec!["plugin", "remove", "resource", "aws"],
            vec!["package", "new", "component-nodejs"],
            vec!["policy", "setup", "aws-typescript"],
            vec!["new", "--generate-only", "aws-typescript"],
            vec!["new", "-g=true", "aws-typescript"],
            vec!["new", "--list-templates"],
            vec!["login", "--local"],
            vec!["login", "file://~"],
            vec!["login", "--cloud-url", "s3://pulumi-state"],
            vec!["login", "-cs3://pulumi-state"],
            vec!["login", "--oidc-token=provided-token"],
            vec!["--cwd", "/tmp", "version"],
            vec!["--future-option", "up"],
            vec!["--future-option=true", "up"],
            vec!["future-command", "--", "arbitrary", "arguments"],
        ] {
            assert!(invocation_is_secretless(
                &script_path,
                script.as_bytes(),
                &args(&command),
            ));
        }

        for command in [
            vec!["up"],
            vec!["preview"],
            vec!["whoami"],
            vec!["config", "get", "region"],
            vec!["stack", "list"],
            vec!["--cwd", "/tmp", "stack", "list"],
            vec!["plugin", "list", "--project"],
            vec!["plugin", "install", "resource", "aws"],
            vec!["new", "aws-typescript"],
            vec!["login"],
            vec!["login", "https://api.pulumi.com"],
            vec!["login", "--local=false"],
            vec!["login", "--oidc-token="],
            vec!["about"],
            vec!["up", "--help=false"],
        ] {
            assert!(!invocation_is_secretless(
                &script_path,
                script.as_bytes(),
                &args(&command),
            ));
        }

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR") };
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn qwen_requests_secrets_only_for_agent_execution() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-qwen");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let script_path = dir.join("qwen");
        let script = stub_script(
            &wrapper("qwen-code").unwrap().primary,
            Path::new("/opt/homebrew/bin/qwen"),
        );
        let invocation = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for args in [
            vec!["--version"],
            vec!["--version=true"],
            vec!["--debug", "--help"],
            vec!["--help=true"],
            vec!["--list-extensions", "ignored-query"],
            vec!["--telemetry-target", "local", "sessions", "ps"],
            vec!["mcp"],
            vec!["mcp", "list"],
            vec!["mcp", "--", "list"],
            vec!["mcp", "approve", "example"],
            vec!["mcp", "future-command"],
            vec!["extensions", "install", "example"],
            vec!["auth"],
            vec!["hooks"],
            vec!["sessions", "list"],
            vec!["update"],
            vec!["channel", "status"],
            vec!["channel", "pairing", "list", "telegram"],
            vec!["channel", "future-command"],
            vec!["review", "drive", "--script", "env"],
            vec!["review", "submit"],
            vec!["review", "future-command"],
            vec!["review", "run", "--help"],
            vec!["--future-option", "mcp", "list"],
            vec!["-dl"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &invocation(&args)),
                "qwen {args:?}",
            );
        }

        for args in [
            vec![],
            vec!["fix", "the", "tests"],
            vec!["future-command"],
            vec!["chat"],
            vec!["--prompt", "fix the tests"],
            vec!["--debug"],
            vec!["--help=false"],
            vec!["--version=false"],
            vec!["--", "--help"],
            vec!["serve"],
            vec!["--debug", "serve"],
            vec!["mcp", "reconnect", "example"],
            vec!["mcp", "--", "reconnect", "--all"],
            vec!["--debug", "mcp", "reconnect", "--all"],
            vec!["channel", "start", "telegram"],
            vec!["channel", "daemon-worker"],
            vec!["review", "run", "123"],
            vec!["-dy"],
            vec!["-ds", "sessions", "ps"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &invocation(&args)),
                "qwen {args:?}",
            );
        }

        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &invocation(&["--version"]),
        ));

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR") };
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn runpodctl_requests_secrets_only_for_reviewed_api_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-runpodctl");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let script_path = dir.join("runpodctl");
        let script = stub_script(
            &wrapper("runpodctl").unwrap().primary,
            Path::new("/opt/homebrew/bin/runpodctl"),
        );
        let invocation = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for args in [
            vec![],
            vec!["help"],
            vec!["--help"],
            vec!["--help=true"],
            vec!["version"],
            vec!["--version"],
            vec!["--version=false", "pod", "list"],
            vec!["completion", "generate", "zsh"],
            vec!["send", "archive.tar"],
            vec!["receive", "1234-example"],
            vec!["update"],
            vec!["config", "--apiKey", "explicit-key"],
            vec!["project", "create", "--name", "example"],
            vec!["project", "build", "--include-env"],
            vec!["pod"],
            vec!["registry", "update"],
            vec!["future-command"],
            vec!["--future-option", "pod", "list"],
            vec!["pod", "list", "--all", "--help"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &invocation(&args)),
                "runpodctl {args:?}",
            );
        }

        for args in [
            vec!["pod", "list"],
            vec!["--output", "yaml", "pod", "get", "pod-id"],
            vec!["-oyaml", "pods", "create", "--image", "runpod/base"],
            vec!["--help=false", "pod", "list"],
            vec!["pod", "create", "--name", "--help"],
            vec!["serverless", "update", "endpoint-id"],
            vec!["tpl", "search", "pytorch"],
            vec!["model", "add", "owner/model"],
            vec!["nv", "delete", "volume-id"],
            vec!["reg", "create"],
            vec!["hub", "list"],
            vec!["gpus", "list"],
            vec!["dc", "list"],
            vec!["billing", "endpoints"],
            vec!["me"],
            vec!["doctor"],
            vec!["ssh", "connect", "pod-id"],
            vec!["exec", "python", "script.py"],
            vec!["project", "dev"],
            vec!["get", "cloud"],
            vec!["create", "pod"],
            vec!["remove", "model"],
            vec!["start", "pod"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &invocation(&args)),
                "runpodctl {args:?}",
            );
        }

        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &invocation(&["--version"]),
        ));

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR") };
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn s3cmd_requests_secrets_only_for_reviewed_credential_uses() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-s3cmd");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let script_path = dir.join("s3cmd");
        let script = stub_script(
            &wrapper("s3cmd").unwrap().primary,
            Path::new("/opt/homebrew/bin/s3cmd"),
        );
        let invocation = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for args in [
            vec![],
            vec!["--help"],
            vec!["-h"],
            vec!["ls", "--help"],
            vec!["--debug", "--version"],
            vec!["--vers"],
            vec!["future-command"],
            vec!["--future-option", "ls"],
            vec!["--confi", "/tmp/config", "ls"],
            vec!["--version=true", "ls"],
            vec!["--", "future-command"],
            vec!["-qv"],
            vec!["--dump-config", "--help"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &invocation(&args)),
                "s3cmd {args:?}",
            );
        }

        for &command in S3CMD_COMMANDS {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &invocation(&[command]),),
                "s3cmd {command}",
            );
        }
        for args in [
            vec!["--config", "/tmp/config", "ls", "s3://bucket"],
            vec!["--host=objects.example", "du"],
            vec!["--long-l", "info", "s3://bucket"],
            vec!["-qvc/tmp/config", "la"],
            vec!["--", "ls"],
            vec!["put", "--mime-type", "--help", "file", "s3://bucket"],
            vec!["--configure"],
            vec!["--dump-config"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &invocation(&args)),
                "s3cmd {args:?}",
            );
        }

        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &invocation(&["--version"]),
        ));

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR") };
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn sentry_cli_requests_its_token_only_for_reviewed_api_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-sentry-cli");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let script_path = dir.join("sentry-cli");
        let script = stub_script(
            &wrapper("sentry-cli").unwrap().primary,
            Path::new("/opt/homebrew/bin/sentry-cli"),
        );
        let args = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for invocation in [
            vec![],
            vec!["--help"],
            vec!["--version"],
            vec!["completions", "zsh"],
            vec!["bash-hook"],
            vec!["debug-files", "bundle-sources", "example.dSYM"],
            vec!["debug-files", "check", "example.dSYM"],
            vec!["debug-files", "bundle-jvm", "app.jar"],
            vec!["debug-files", "find", "example.dSYM"],
            vec!["debug-files", "print-sources", "example.dSYM"],
            vec!["dif", "check", "example.dSYM"],
            vec!["proguard", "uuid", "mapping.txt"],
            vec!["proguard", "upload", "--no-upload", "mapping.txt"],
            vec!["upload-proguard", "--no-upload", "mapping.txt"],
            vec!["releases", "propose-version"],
            vec!["sourcemaps", "inject", "dist"],
            vec!["sourcemaps", "resolve", "bundle.js.map"],
            vec!["snapshots", "diff", "base", "head"],
            vec!["send-event", "--message", "broken"],
            vec!["send-envelope", "event.envelope"],
            vec!["monitors", "run", "nightly", "--", "sh", "--help"],
            vec!["login"],
            vec!["uninstall"],
            vec!["update"],
            vec!["future-command"],
            vec!["releases", "future-command"],
            vec!["projects", "list", "--help"],
            vec!["projects", "--", "--help"],
            vec!["--url", "https://sentry.example", "future-command"],
            vec!["--auth-token", "explicit", "projects", "list"],
            vec!["projects", "list", "--auth-token=explicit"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&invocation)),
                "sentry-cli {invocation:?}",
            );
        }
        for invocation in [
            vec!["build", "download"],
            vec!["build", "upload"],
            vec!["build", "snapshots"],
            vec!["code-mappings", "upload"],
            vec!["dart-symbol-map", "upload"],
            vec!["projects", "list"],
            vec!["--url", "https://sentry.example", "projects", "list"],
            vec!["--header=X-Test:value", "events", "list"],
            vec!["deploys", "list"],
            vec!["deploys", "new"],
            vec!["info"],
            vec!["issues", "list"],
            vec!["issues", "mute", "123"],
            vec!["issues", "unresolve", "123"],
            vec!["logs", "list"],
            vec!["monitors", "list"],
            vec!["organizations", "list"],
            vec!["proguard", "upload", "mapping.txt"],
            vec!["react-native", "gradle"],
            vec!["releases", "list"],
            vec!["releases", "archive", "1.2.3"],
            vec!["releases", "delete", "1.2.3"],
            vec!["releases", "finalize", "1.2.3"],
            vec!["releases", "info", "1.2.3"],
            vec!["releases", "new", "1.2.3"],
            vec!["releases", "restore", "1.2.3"],
            vec!["releases", "set-commits", "1.2.3"],
            vec!["releases", "deploys", "list", "1.2.3"],
            vec!["releases", "deploys", "new", "1.2.3"],
            vec!["repos", "list"],
            vec!["issues", "resolve", "123"],
            vec!["debug-files", "upload", "example.dSYM"],
            vec!["dif", "upload", "example.dSYM"],
            vec!["difutil", "upload", "example.dSYM"],
            vec!["sourcemaps", "upload", "dist"],
            vec!["snapshots", "download"],
            vec!["snapshots", "upload"],
            vec!["react-native", "xcode"],
            vec!["upload-dif", "example.dSYM"],
            vec!["upload-dsym", "example.dSYM"],
            vec!["upload-proguard", "mapping.txt"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&invocation)),
                "sentry-cli {invocation:?}",
            );
        }
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["completions", "zsh"]),
        ));

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR") };
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn snowflake_cli_requests_passwords_only_for_reviewed_connection_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-snowflake-cli");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let script_path = dir.join("snow");
        let script = stub_script(
            &wrapper("snowflake-cli").unwrap().primary,
            Path::new("/opt/homebrew/bin/snow"),
        );
        let invokes_secretlessly = |values: &[&str]| {
            let invocation = std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>();
            invocation_is_secretless(&script_path, script.as_bytes(), &invocation)
        };

        for command in [
            "app setup",
            "app diff",
            "app run",
            "app open",
            "app teardown",
            "app deploy",
            "app validate",
            "app events",
            "app publish",
            "app version create",
            "app version list",
            "app version drop",
            "app release-directive list",
            "app release-directive set",
            "app release-directive unset",
            "app release-directive add-accounts",
            "app release-directive remove-accounts",
            "app release-channel list",
            "app release-channel add-accounts",
            "app release-channel remove-accounts",
            "app release-channel set-accounts",
            "app release-channel add-version",
            "app release-channel remove-version",
            "connection test",
            "cortex search",
            "cortex complete",
            "cortex extract-answer",
            "cortex sentiment",
            "cortex summarize",
            "cortex translate",
            "dbt list",
            "dbt drop",
            "dbt describe",
            "dbt copy",
            "dbt deploy",
            "dcm list",
            "dcm deploy",
            "dcm purge",
            "dcm plan",
            "dcm raw-analyze",
            "dcm create",
            "dcm drop",
            "dcm describe",
            "dcm list-deployments",
            "dcm drop-deployment",
            "dcm preview",
            "dcm refresh",
            "dcm test",
            "git list",
            "git drop",
            "git describe",
            "git setup",
            "git list-branches",
            "git list-tags",
            "git list-files",
            "git fetch",
            "git copy",
            "git execute",
            "logs",
            "notebook execute",
            "notebook get-url",
            "notebook open",
            "notebook create",
            "notebook deploy",
            "object list",
            "object drop",
            "object describe",
            "object create",
            "snowpark deploy",
            "snowpark build",
            "snowpark execute",
            "snowpark list",
            "snowpark drop",
            "snowpark describe",
            "snowpark package lookup",
            "snowpark package upload",
            "snowpark package create",
            "spcs compute-pool list",
            "spcs compute-pool drop",
            "spcs compute-pool describe",
            "spcs compute-pool create",
            "spcs compute-pool deploy",
            "spcs compute-pool stop-all",
            "spcs compute-pool suspend",
            "spcs compute-pool resume",
            "spcs compute-pool set",
            "spcs compute-pool unset",
            "spcs compute-pool status",
            "spcs service list",
            "spcs service describe",
            "spcs service drop",
            "spcs service create",
            "spcs service deploy",
            "spcs service execute-job",
            "spcs service status",
            "spcs service logs",
            "spcs service events",
            "spcs service metrics",
            "spcs service upgrade",
            "spcs service list-endpoints",
            "spcs service list-instances",
            "spcs service list-containers",
            "spcs service list-roles",
            "spcs service suspend",
            "spcs service resume",
            "spcs service set",
            "spcs service unset",
            "spcs service build-image",
            "spcs service remote-build",
            "spcs service remote-build-status",
            "spcs service remote-build-history",
            "spcs image-registry token",
            "spcs image-registry url",
            "spcs image-registry login",
            "spcs image-repository list",
            "spcs image-repository drop",
            "spcs image-repository create",
            "spcs image-repository deploy",
            "spcs image-repository list-images",
            "spcs image-repository list-tags",
            "spcs image-repository url",
            "sql",
            "stage list",
            "stage drop",
            "stage describe",
            "stage list-files",
            "stage copy",
            "stage create",
            "stage remove",
            "stage diff",
            "stage execute",
            "streamlit list",
            "streamlit drop",
            "streamlit describe",
            "streamlit execute",
            "streamlit share",
            "streamlit deploy",
            "streamlit get-url",
            "streamlit logs",
            "ws bundle",
            "ws deploy",
            "ws drop",
            "ws validate",
            "ws version list",
            "ws version create",
            "ws version drop",
        ] {
            let args = command.split_whitespace().collect::<Vec<_>>();
            assert!(!invokes_secretlessly(&args), "snow {command}");
        }
        for dbt_command in [
            "build",
            "compile",
            "deps",
            "list",
            "parse",
            "retry",
            "run",
            "run-operation",
            "seed",
            "show",
            "snapshot",
            "test",
        ] {
            assert!(!invokes_secretlessly(&[
                "dbt",
                "execute",
                "project",
                dbt_command
            ]));
        }

        for command in [
            vec![],
            vec!["--version"],
            vec!["--info"],
            vec!["--config-file", "/tmp/config.toml", "--help"],
            vec!["app", "bundle"],
            vec!["auth", "oidc", "read-token"],
            vec!["connection", "list"],
            vec!["connection", "generate-jwt"],
            vec!["connection", "generate-workload-identity-token"],
            vec!["custom-image", "validate"],
            vec!["helpers", "show-config-sources"],
            vec!["init"],
            vec!["plugin", "list"],
            vec!["ws", "dump"],
            vec!["future-command"],
            vec!["external-plugin", "deploy"],
            vec!["object", "future-command"],
            vec!["object", "list", "--help"],
            vec!["object", "list", "--password", "from-command-line"],
            vec!["sql", "--password=from-command-line", "-q", "select 1"],
            vec!["object", "list", "--private-key-file", "/tmp/key.p8"],
            vec![
                "sql",
                "--token-file-path=/tmp/oauth-token",
                "-q",
                "select 1",
            ],
            vec!["dbt", "execute", "project", "future-command", "--help"],
            vec!["dbt", "execute", "--help"],
        ] {
            assert!(invokes_secretlessly(&command), "snow {command:?}");
        }

        assert!(!invokes_secretlessly(&[
            "--disable-external-command-plugins",
            "--config-file=/tmp/config.toml",
            "object",
            "list",
        ]));
        assert!(!invokes_secretlessly(&[
            "dbt",
            "execute",
            "--dbt-version",
            "1.9",
            "project",
            "run",
            "--help",
        ]));
        assert!(!invokes_secretlessly(&[
            "dbt",
            "execute",
            "project",
            "run",
            "--password",
            "dbt-passthrough",
        ]));
        assert!(!invokes_secretlessly(&[
            "dbt",
            "execute",
            "project",
            "run",
            "--",
            "--password",
            "passthrough",
        ]));
        assert!(invokes_secretlessly(&[
            "dbt",
            "execute",
            "project",
            "--password",
            "from-command-line",
            "run",
        ]));

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR") };
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn snyk_requests_secrets_only_for_reviewed_authenticated_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-snyk");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let credential_vars = [
            "SNYK_TOKEN",
            "SNYK_OAUTH_TOKEN",
            "SNYK_CFG_API",
            "SNYK_DOCKER_TOKEN",
            "IDE_CONFIG_PATH",
        ];
        let previous_credentials = credential_vars.map(|name| std::env::var_os(name));
        for name in credential_vars {
            unsafe { std::env::remove_var(name) };
        }

        let script_path = dir.join("snyk");
        let script = stub_script(
            &wrapper("snyk").unwrap().primary,
            Path::new("/opt/homebrew/bin/snyk"),
        );
        let args = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for command in [
            vec![],
            vec!["--help"],
            vec!["test", "--help"],
            vec!["auth"],
            vec!["auth", "replacement-token"],
            vec!["config", "get", "api"],
            vec!["policy"],
            vec!["protect"],
            vec!["wizard"],
            vec!["woof"],
            vec!["log4shell"],
            vec!["depgraph"],
            vec!["container", "depgraph", "alpine:latest"],
            vec!["iac", "rules", "init"],
            vec!["iac", "rules", "test"],
            vec!["iac", "rules", "repl"],
            vec!["mcp", "configure", "--tool", "cursor"],
            vec!["tools", "ide-directory-check"],
            vec!["doctor", "--input", "snyk.log"],
            vec!["doctor", "--stdin"],
            vec!["doctor", "--input=snyk.log", "--live=false"],
            vec!["language-server", "--licenses"],
            vec!["language-server", "-p"],
            vec!["agent", "setup", "hooks"],
            vec!["daemon"],
            vec!["run", "arbitrary-script"],
            vec!["future-command"],
            vec!["--future-option", "test"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "snyk {command:?}",
            );
        }

        for command in [
            vec!["test"],
            vec!["t", "--all-projects"],
            vec!["monitor"],
            vec!["mo"],
            vec!["fix", "--dry-run"],
            vec!["f"],
            vec!["ignore", "--id", "SNYK-JS-EXAMPLE"],
            vec!["apps", "create", "--experimental"],
            vec!["whoami"],
            vec!["doctor"],
            vec!["doctor", "--live"],
            vec!["doctor", "--input", "snyk.log", "--live=true"],
            vec!["sbom", "--format", "cyclonedx1.5+json"],
            vec!["sbom", "monitor", "bom.json"],
            vec!["aibom"],
            vec!["aibom", "test"],
            vec!["agent-scan"],
            vec!["mcp-scan"],
            vec!["language-server"],
            vec!["mcp"],
            vec!["container", "test", "alpine:latest"],
            vec!["container", "m", "alpine:latest"],
            vec!["container", "sbom", "alpine:latest"],
            vec!["unmanaged", "test"],
            vec!["code", "t"],
            vec!["iac", "test"],
            vec!["iac", "d"],
            vec!["iac", "u"],
            vec!["iac", "capture"],
            vec!["iac", "rules", "push"],
            vec!["secrets", "test"],
            vec!["tools", "connectivity-check"],
            vec!["agent", "feedback"],
            vec!["agent", "test"],
            vec!["cos", "finding", "list"],
            vec!["cos", "scan", "start"],
            vec!["cos", "target", "create"],
            vec!["--org", "example", "test"],
            vec!["--org=example", "monitor"],
            vec!["-d", "whoami"],
            vec!["test", "--", "--help"],
            vec!["monitor", "--", "--offline"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "snyk {command:?}",
            );
        }

        for name in ["SNYK_TOKEN", "SNYK_OAUTH_TOKEN", "SNYK_CFG_API"] {
            unsafe { std::env::set_var(name, "caller-supplied") };
            assert!(invocation_is_secretless(
                &script_path,
                script.as_bytes(),
                &args(&["whoami"]),
            ));
            unsafe { std::env::remove_var(name) };
        }
        unsafe { std::env::set_var("SNYK_DOCKER_TOKEN", "caller-supplied") };
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["container", "test", "alpine:latest"]),
        ));
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["test", "--docker", "alpine:latest"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["whoami"]),
        ));
        unsafe { std::env::remove_var("SNYK_DOCKER_TOKEN") };
        unsafe { std::env::set_var("IDE_CONFIG_PATH", "cursor") };
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["mcp"]),
        ));

        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["config", "get", "api"]),
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
    fn transifex_requests_secrets_only_for_commands_that_consume_its_token() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-transifex");
        let previous_authority =
            ["TX_TOKEN", "TX_HOSTNAME"].map(|name| (name, std::env::var_os(name)));
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir);
            std::env::remove_var("TX_TOKEN");
            std::env::remove_var("TX_HOSTNAME");
        }
        let script_path = dir.join("tx");
        let script = stub_script(
            &wrapper("transifex-cli").unwrap().primary,
            Path::new("/opt/homebrew/bin/tx"),
        );
        let invokes_secretlessly = |values: &[&str]| {
            let invocation = std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>();
            invocation_is_secretless(&script_path, script.as_bytes(), &invocation)
        };

        for command in [
            vec![],
            vec!["help", "push"],
            vec!["push", "--help"],
            vec!["--version"],
            vec!["init"],
            vec!["update", "--check"],
            vec!["migrate"],
            vec!["mg"],
            vec!["add", "messages.po", "--organization", "example"],
            vec!["a", "messages.po", "--type=PO"],
            vec!["--hostname=https://example.invalid", "pull"],
            vec!["-H", "https://example.invalid", "status"],
            vec!["future-command"],
            vec!["--future-option", "push"],
            vec!["--", "push"],
        ] {
            assert!(invokes_secretlessly(&command), "tx {command:?}");
        }
        for command in [
            vec!["status"],
            vec!["--config", ".tx/config", "status"],
            vec!["merge", "project.resource"],
            vec!["push"],
            vec!["push", "--", "--help"],
            vec!["pull"],
            vec!["delete", "project.resource"],
            vec!["add"],
            vec!["a", "messages.po"],
            vec!["add", "--organization", "example", "remote"],
            vec!["add", "remote", "https://app.transifex.com/o/p/dashboard/"],
        ] {
            assert!(!invokes_secretlessly(&command), "tx {command:?}");
        }

        for command in [
            vec!["--token", "caller-token", "status"],
            vec!["--token=caller-token", "push"],
        ] {
            assert!(invokes_secretlessly(&command), "tx {command:?}");
        }
        unsafe { std::env::set_var("TX_TOKEN", "caller-token") };
        assert!(invokes_secretlessly(&["pull"]));
        unsafe {
            std::env::remove_var("TX_TOKEN");
            std::env::set_var("TX_HOSTNAME", "https://example.invalid");
        }
        assert!(invokes_secretlessly(&["status"]));

        let altered_script = format!("{script}# changed\n");
        let invocation = [script_path.clone().into_os_string(), OsString::from("init")];
        assert!(!invocation_is_secretless(
            &script_path,
            altered_script.as_bytes(),
            &invocation,
        ));

        unsafe {
            for (name, value) in previous_authority {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn travis_requests_its_token_only_for_reviewed_official_api_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let previous_home = std::env::var_os("HOME");
        let previous_stub_dir = std::env::var_os("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
        let previous_values = ["TRAVIS_TOKEN", "TRAVIS_ENDPOINT", "TRAVIS_CONFIG_PATH"]
            .map(|key| (key, std::env::var_os(key)));
        let dir = temp_dir("env-wrapper-secretless-travis");
        let config_dir = dir.join(".travis");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(
            config_dir.join("config.yml"),
            "endpoints:\n  https://api.travis-ci.com/:\n    access_token: ''\n",
        )
        .unwrap();
        unsafe {
            std::env::set_var("HOME", &dir);
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir);
            for (key, _) in &previous_values {
                std::env::remove_var(key);
            }
        }
        let script_path = dir.join("travis");
        let script = stub_script(
            &wrapper("travis").unwrap().primary,
            Path::new("/opt/homebrew/bin/travis"),
        );
        let args = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for command in [
            vec![],
            vec!["help"],
            vec!["version"],
            vec!["--version"],
            vec!["whoami", "--help"],
            vec!["endpoint"],
            vec!["login"],
            vec!["logout"],
            vec!["regenerate-token"],
            vec!["remove-token"],
            vec!["report"],
            vec!["plugin-command", "--", "payload"],
            vec!["future-command"],
            vec!["whoami", "--api-endpoint", "https://enterprise.example/api"],
            vec![
                "whoami",
                "--api-endpoint",
                "https://api.travis-ci.com/",
                "--api-endpoint",
                "https://enterprise.example/api",
            ],
            vec!["whoami", "-ehttps://enterprise.example/api"],
            vec!["whoami", "--insecure"],
            vec!["whoami", "-Xenterprise"],
            vec!["whoami", "--token=caller-token"],
            vec!["whoami", "-tcaller-token"],
            vec!["settings", "--token=caller-token"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "travis {command:?}",
            );
        }
        for command in [
            "accounts",
            "branches",
            "cache",
            "cancel",
            "console",
            "disable",
            "enable",
            "encrypt",
            "encrypt-file",
            "env",
            "history",
            "init",
            "lint",
            "logs",
            "monitor",
            "open",
            "pubkey",
            "raw",
            "repos",
            "requests",
            "restart",
            "settings",
            "setup",
            "show",
            "sshkey",
            "status",
            "sync",
            "token",
            "whatsup",
            "whoami",
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&[command])),
                "travis {command}",
            );
        }
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["settings", "-t"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["whoami", "--skip-version-check"]),
        ));
        for command in [
            vec!["whoami", "--com"],
            vec!["whoami", "--pro"],
            vec!["whoami", "--api-endpoint", "https://api.travis-ci.com/"],
            vec!["whoami", "-ehttps://api.travis-ci.com/"],
        ] {
            assert!(!invocation_is_secretless(
                &script_path,
                script.as_bytes(),
                &args(&command),
            ));
        }

        unsafe { std::env::set_var("TRAVIS_TOKEN", "caller-token") };
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["whoami"]),
        ));
        unsafe { std::env::remove_var("TRAVIS_TOKEN") };
        for key in ["TRAVIS_ENDPOINT", "TRAVIS_CONFIG_PATH"] {
            unsafe { std::env::set_var(key, "caller-value") };
            assert!(invocation_is_secretless(
                &script_path,
                script.as_bytes(),
                &args(&["whoami"]),
            ));
            unsafe { std::env::remove_var(key) };
        }
        unsafe { std::env::set_var("TRAVIS_ENDPOINT", "https://api.travis-ci.com/") };
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["whoami"]),
        ));
        unsafe { std::env::remove_var("TRAVIS_ENDPOINT") };
        fs::write(
            config_dir.join("config.yml"),
            "endpoints:\n  https://api.travis-ci.com/:\n",
        )
        .unwrap();
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["whoami"]),
        ));
        fs::write(
            config_dir.join("config.yml"),
            "endpoints:\n  https://enterprise.example/api:\n    access_token: ''\n",
        )
        .unwrap();
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["whoami"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["help"]),
        ));

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match previous_stub_dir {
                Some(value) => std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", value),
                None => std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR"),
            }
            for (key, value) in previous_values {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn vault_requests_its_token_only_for_reviewed_api_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let previous_stub_dir = std::env::var_os("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
        let previous_values = [
            "VAULT_TOKEN",
            "VAULT_SKIP_VERIFY",
            "VAULT_ADDR",
            "VAULT_AGENT_ADDR",
        ]
        .map(|key| (key, std::env::var_os(key)));
        let dir = temp_dir("env-wrapper-secretless-vault");
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir);
            for (key, _) in &previous_values {
                std::env::remove_var(key);
            }
        }
        let script_path = dir.join("vault");
        let script = stub_script(
            &wrapper("vault").unwrap().primary,
            Path::new("/opt/homebrew/bin/vault"),
        );
        let args = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for command in [
            vec![],
            vec!["help"],
            vec!["version"],
            vec!["--version"],
            vec!["status"],
            vec!["path-help", "secret/"],
            vec!["login"],
            vec!["agent", "-config=agent.hcl"],
            vec!["proxy", "-config=proxy.hcl"],
            vec!["server", "-config=server.hcl"],
            vec!["policy", "fmt", "policy.hcl"],
            vec!["operator", "init"],
            vec!["operator", "unseal"],
            vec!["operator", "generate-root", "-decode=encoded", "-otp=otp"],
            vec!["operator", "raft", "join", "https://vault-leader.example"],
            vec!["operator", "raft", "snapshot", "inspect", "snapshot.snap"],
            vec!["audit"],
            vec!["auth", "help", "userpass"],
            vec!["plugin", "runtime"],
            vec!["kv", "metadata"],
            vec!["unwrap", "caller-wrapping-token"],
            vec!["unwrap", "--", "caller-wrapping-token"],
            vec!["read", "-output-policy", "secret/example"],
            vec!["read", "-output-policy=true", "secret/example"],
            vec!["write", "--output-curl-string", "secret/example", "value=x"],
            vec!["future-command"],
            vec!["operator", "future-command"],
            vec!["plugin", "runtime", "future-command"],
            vec!["future-command", "--", "payload"],
            vec!["read", "-tls-skip-verify", "secret/example"],
            vec!["read", "-address", "http://vault.example", "secret/example"],
            vec!["read", "-address=hTtP://vault.example", "secret/example"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "vault {command:?}",
            );
        }

        for command in [
            vec!["read", "secret/example"],
            vec!["read", "-tls-skip-verify=false", "secret/example"],
            vec!["write", "-output-policy=false", "secret/example", "value=x"],
            vec![
                "agent",
                "generate-config",
                "-type=env-template",
                "secret/example",
            ],
            vec!["write", "secret/example", "value=x"],
            vec!["delete", "secret/example"],
            vec!["list", "secret/"],
            vec!["patch", "secret/example", "value=x"],
            vec!["debug"],
            vec!["monitor"],
            vec!["ssh", "-role", "admin", "host"],
            vec!["unwrap"],
            vec!["version-history"],
            vec!["events", "subscribe", "*"],
            vec!["audit", "list"],
            vec!["auth", "list"],
            vec!["lease", "lookup", "lease-id"],
            vec!["namespace", "list"],
            vec!["auth", "help", "custom/"],
            vec!["operator", "generate-root", "-status"],
            vec!["operator", "key-status"],
            vec!["operator", "rekey", "-status"],
            vec!["operator", "seal"],
            vec!["operator", "raft", "list-peers"],
            vec!["operator", "raft", "autopilot", "state"],
            vec!["operator", "raft", "snapshot", "save", "snapshot.snap"],
            vec!["pki", "health-check"],
            vec!["plugin", "list"],
            vec!["plugin", "runtime", "info", "container"],
            vec!["policy", "read", "default"],
            vec!["print", "token"],
            vec!["secrets", "list"],
            vec!["transform", "import", "role", "key"],
            vec!["transit", "import", "key", "material"],
            vec!["token", "lookup"],
            vec!["kv", "get", "secret/example"],
            vec!["kv", "metadata", "get", "secret/example"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "vault {command:?}",
            );
        }

        unsafe { std::env::set_var("VAULT_TOKEN", "caller-token") };
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["read", "secret/example"]),
        ));
        unsafe {
            std::env::remove_var("VAULT_TOKEN");
            std::env::set_var("VAULT_ADDR", "http://vault.example");
        }
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["read", "secret/example"]),
        ));
        unsafe { std::env::set_var("VAULT_ADDR", "https://vault.example") };
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["read", "-format=json", "secret/example"]),
        ));
        unsafe {
            std::env::remove_var("VAULT_ADDR");
            std::env::set_var("VAULT_SKIP_VERIFY", "false");
        }
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["read", "secret/example"]),
        ));
        unsafe {
            std::env::set_var("VAULT_SKIP_VERIFY", "true");
        }
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["read", "secret/example"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["status"]),
        ));

        unsafe {
            match previous_stub_dir {
                Some(value) => std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", value),
                None => std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR"),
            }
            for (key, value) in previous_values {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn virustotal_requests_its_api_key_only_for_reviewed_official_api_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let previous_home = std::env::var_os("HOME");
        let previous_stub_dir = std::env::var_os("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
        let previous_values =
            ["VTCLI_APIKEY", "VTCLI_HOST"].map(|key| (key, std::env::var_os(key)));
        let dir = temp_dir("env-wrapper-secretless-virustotal");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(".vt.toml"), "host=\"www.virustotal.com\"\n").unwrap();
        unsafe {
            std::env::set_var("HOME", &dir);
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir);
            for (key, _) in &previous_values {
                std::env::remove_var(key);
            }
        }
        let script_path = dir.join("vt");
        let script = stub_script(
            &wrapper("virustotal-cli").unwrap().primary,
            Path::new("/opt/homebrew/bin/vt"),
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
            vec!["file", "--help"],
            vec!["version"],
            vec!["completion", "zsh"],
            vec!["gendoc", "docs"],
            vec!["init"],
            vec!["future-command"],
            vec!["future-command", "--", "payload"],
            vec!["file", "hash", "--apikey", "caller-key"],
            vec!["file", "hash", "--apikey=caller-key"],
            vec!["file", "hash", "-kcaller-key"],
            vec!["file", "hash", "--apikey="],
            vec!["file", "hash", "--host", "private.example"],
            vec!["file", "hash", "--host=private.example"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "vt {command:?}",
            );
        }

        for command in [
            vec!["analysis", "id"],
            vec!["an", "id"],
            vec!["collection", "id"],
            vec!["domain", "example.com"],
            vec!["download", "hash"],
            vec!["dl", "hash"],
            vec!["file", "hash"],
            vec!["group", "name"],
            vec!["hunting", "notification", "list"],
            vec!["ht", "notification", "list"],
            vec!["iocstream", "list"],
            vec!["is", "list"],
            vec!["ip", "192.0.2.1"],
            vec!["meta"],
            vec!["monitor", "list"],
            vec!["monitorpartner", "list"],
            vec!["retrohunt", "list"],
            vec!["rh", "list"],
            vec!["scan", "url", "https://example.com"],
            vec!["search", "type:peexe"],
            vec!["threatprofile", "list"],
            vec!["url", "https://example.com"],
            vec!["user", "name"],
            vec!["--format", "json", "file", "hash"],
            vec!["-sv", "file", "hash"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "vt {command:?}",
            );
        }

        unsafe { std::env::set_var("VTCLI_APIKEY", "caller-key") };
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["file", "hash"]),
        ));
        unsafe {
            std::env::remove_var("VTCLI_APIKEY");
            std::env::set_var("VTCLI_HOST", "private.example");
        }
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["file", "hash"]),
        ));
        unsafe { std::env::remove_var("VTCLI_HOST") };

        fs::write(dir.join(".vt.toml"), "host=\"private.example\"\n").unwrap();
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["file", "hash"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["--host", "www.virustotal.com", "file", "hash"]),
        ));
        fs::write(dir.join(".vt.toml"), "apikey=\"caller-key\"\n").unwrap();
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["file", "hash"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["version"]),
        ));

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match previous_stub_dir {
                Some(value) => std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", value),
                None => std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR"),
            }
            for (key, value) in previous_values {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn vultr_requests_its_api_key_only_for_reviewed_authenticated_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let previous_home = std::env::var_os("HOME");
        let previous_stub_dir = std::env::var_os("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
        let previous_api_key = std::env::var_os("VULTR_API_KEY");
        let dir = temp_dir("env-wrapper-secretless-vultr");
        fs::create_dir_all(&dir).unwrap();
        unsafe {
            std::env::set_var("HOME", &dir);
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir);
            std::env::remove_var("VULTR_API_KEY");
        }
        let script_path = dir.join("vultr-cli");
        let script = stub_script(
            &wrapper("vultr").unwrap().primary,
            Path::new("/opt/homebrew/bin/vultr-cli"),
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
            vec!["instance", "--help"],
            vec!["completion", "zsh"],
            vec!["version"],
            vec!["v"],
            vec!["apps", "list"],
            vec!["a", "l"],
            vec!["marketplace", "app", "list-variables", "app"],
            vec!["os", "list"],
            vec!["o", "l"],
            vec!["plans", "list"],
            vec!["p", "m"],
            vec!["regions", "availability", "ewr"],
            vec!["r", "l"],
            vec!["--output", "json", "apps", "list"],
            vec!["future-command"],
            vec!["future-command", "--", "payload"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "vultr-cli {command:?}",
            );
        }

        for command in [
            vec!["account", "info"],
            vec!["backups", "list"],
            vec!["backup", "list"],
            vec!["b", "list"],
            vec!["bare-metal", "list"],
            vec!["bm", "list"],
            vec!["billing", "invoice", "list"],
            vec!["block-storage", "list"],
            vec!["bs", "list"],
            vec!["cdn", "pull", "list"],
            vec!["container-registry", "list"],
            vec!["cr", "list"],
            vec!["database", "list"],
            vec!["dns", "domain", "list"],
            vec!["firewall", "group", "list"],
            vec!["fw", "group", "list"],
            vec!["inference", "list"],
            vec!["instance", "list"],
            vec!["iso", "list"],
            vec!["kubernetes", "list"],
            vec!["k", "list"],
            vec!["load-balancer", "list"],
            vec!["logs", "list"],
            vec!["log", "list"],
            vec!["object-storage", "list"],
            vec!["reserved-ip", "list"],
            vec!["rip", "list"],
            vec!["script", "list"],
            vec!["ss", "list"],
            vec!["startup-script", "list"],
            vec!["snapshot", "list"],
            vec!["sn", "list"],
            vec!["ssh-key", "list"],
            vec!["ssh", "list"],
            vec!["ssh-keys", "list"],
            vec!["sshkeys", "list"],
            vec!["user", "list"],
            vec!["users", "list"],
            vec!["u", "list"],
            vec!["vpc", "list"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "vultr-cli {command:?}",
            );
        }
        for command in [
            vec!["instance"],
            vec!["dns", "domain"],
            vec!["database", "future-command"],
            vec!["instance", "future-command"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "vultr-cli {command:?}",
            );
        }
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["-ojson", "instance", "list"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["instance", "list", "--", "payload"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["user", "create", "--password", "-h"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["instance", "create", "--label", "--help"]),
        ));

        unsafe { std::env::set_var("VULTR_API_KEY", "caller-key") };
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["instance", "list"]),
        ));
        unsafe { std::env::remove_var("VULTR_API_KEY") };
        let caller_config = dir.join("caller.yaml");
        fs::write(&caller_config, "api-key: caller-key\n").unwrap();
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&[
                "--config",
                caller_config.to_str().unwrap(),
                "instance",
                "list",
            ]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["version"]),
        ));

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match previous_stub_dir {
                Some(value) => std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", value),
                None => std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR"),
            }
            match previous_api_key {
                Some(value) => std::env::set_var("VULTR_API_KEY", value),
                None => std::env::remove_var("VULTR_API_KEY"),
            }
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wsk_requests_secrets_only_for_reviewed_remote_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-wsk");
        let home = dir.join("home");
        let selected = home.join("selected.wskprops");
        fs::create_dir_all(&home).unwrap();
        let previous_home = std::env::var_os("HOME");
        let previous_config = std::env::var_os("WSK_CONFIG_FILE");
        let previous_auth = std::env::var_os("WHISK_AUTH");
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir);
            std::env::set_var("HOME", &home);
            std::env::set_var("WSK_CONFIG_FILE", &selected);
            std::env::remove_var("WHISK_AUTH");
        }
        let script_path = dir.join("wsk");
        let script = stub_script(
            &wrapper("wsk").unwrap().primary,
            Path::new("/opt/homebrew/bin/wsk"),
        );
        let secretless = |values: &[&str]| {
            let args = std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>();
            invocation_is_secretless(&script_path, script.as_bytes(), &args)
        };

        for command in [
            vec![],
            vec!["help"],
            vec!["--help"],
            vec!["--version"],
            vec!["action"],
            vec!["action", "--help"],
            vec!["action", "list", "--help"],
            vec!["action", "future"],
            vec!["future", "list"],
            vec!["action", "--", "list"],
            vec!["sdk", "install", "bashauto"],
            vec!["sdk", "install", "docker"],
            vec!["property", "set", "--auth", "caller"],
            vec!["property", "unset", "--auth"],
            vec!["property", "get", "--cert"],
            vec!["property", "get", "--key"],
            vec!["property", "get", "--apihost"],
            vec!["property", "get", "--apiversion"],
            vec!["property", "get", "--apibuild"],
            vec!["property", "get", "--apibuildno"],
            vec!["property", "get", "--cliversion"],
        ] {
            assert!(secretless(&command), "wsk {command:?}");
        }

        for command in [
            vec!["list"],
            vec!["action", "create"],
            vec!["action", "delete"],
            vec!["action", "get"],
            vec!["action", "invoke"],
            vec!["action", "list"],
            vec!["action", "update"],
            vec!["activation", "get"],
            vec!["activation", "list"],
            vec!["activation", "logs"],
            vec!["activation", "poll"],
            vec!["activation", "result"],
            vec!["api", "create"],
            vec!["api", "delete"],
            vec!["api", "get"],
            vec!["api", "list"],
            vec!["namespace", "get"],
            vec!["namespace", "list"],
            vec!["package", "bind"],
            vec!["package", "create"],
            vec!["package", "delete"],
            vec!["package", "get"],
            vec!["package", "list"],
            vec!["package", "refresh"],
            vec!["package", "update"],
            vec!["project", "deploy"],
            vec!["project", "export"],
            vec!["project", "sync"],
            vec!["project", "undeploy"],
            vec!["rule", "create"],
            vec!["rule", "delete"],
            vec!["rule", "disable"],
            vec!["rule", "enable"],
            vec!["rule", "get"],
            vec!["rule", "list"],
            vec!["rule", "status"],
            vec!["rule", "update"],
            vec!["trigger", "create"],
            vec!["trigger", "delete"],
            vec!["trigger", "fire"],
            vec!["trigger", "get"],
            vec!["trigger", "list"],
            vec!["trigger", "update"],
            vec!["property", "get"],
            vec!["property", "get", "--all"],
            vec!["property", "get", "--auth"],
            vec!["property", "get", "--namespace"],
            vec!["property", "get", "--output", "raw"],
            vec!["--debug", "action", "list"],
            vec!["action", "--insecure", "list"],
            vec!["action", "create", "name", "--param", "key", "-h"],
            vec!["action", "create", "--", "payload"],
        ] {
            assert!(!secretless(&command), "wsk {command:?}");
        }

        unsafe { std::env::set_var("WHISK_AUTH", "ambient-caller-auth") };
        assert!(!secretless(&["action", "list"]));
        assert!(secretless(&["--auth", "caller-auth", "action", "list"]));
        assert!(secretless(&["-u", "caller-auth", "action", "list"]));
        assert!(secretless(&["-ucaller-auth", "action", "list"]));
        fs::write(&selected, "AUTH=caller-file-auth\n").unwrap();
        assert!(secretless(&["action", "list"]));

        let invocation = [script_path.clone().into_os_string(), OsString::from("help")];
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &invocation,
        ));

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match previous_config {
                Some(value) => std::env::set_var("WSK_CONFIG_FILE", value),
                None => std::env::remove_var("WSK_CONFIG_FILE"),
            }
            match previous_auth {
                Some(value) => std::env::set_var("WHISK_AUTH", value),
                None => std::env::remove_var("WHISK_AUTH"),
            }
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn akamai_requests_secrets_only_for_installed_plugin_commands() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-akamai");
        let home = dir.join("home");
        let package = home.join(".akamai-cli/src/cli-property");
        fs::create_dir_all(&package).unwrap();
        fs::write(
            package.join("cli.json"),
            r#"{"commands":[{"name":"property-manager","aliases":["pm"]}]}"#,
        )
        .unwrap();
        let env_keys = [
            "HOME",
            "AKAMAI_CLI_HOME",
            "AKAMAI_EDGERC",
            "AKAMAI_EDGERC_SECTION",
            "AKAMAI_ENV_ASSIGNMENTS",
            "AKAMAI_CLIENT_TOKEN",
            "AKAMAI_CLIENT_SECRET",
            "AKAMAI_ACCESS_TOKEN",
            "AKAMAI_PROD_CLIENT_TOKEN",
            "AKAMAI_PROD_CLIENT_SECRET",
            "AKAMAI_PROD_ACCESS_TOKEN",
        ];
        let previous = env_keys.map(|key| (key, std::env::var_os(key)));
        unsafe {
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir);
            for key in env_keys {
                std::env::remove_var(key);
            }
            std::env::set_var("HOME", &home);
            std::env::set_var("AKAMAI_ENV_ASSIGNMENTS", "AKAMAI_CLIENT_TOKEN=protected");
        }
        let script_path = dir.join("akamai");
        let script = stub_script(
            &wrapper("akamai").unwrap().primary,
            Path::new("/opt/homebrew/bin/akamai"),
        );
        let secretless = |values: &[&str]| {
            let args = std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>();
            invocation_is_secretless(&script_path, script.as_bytes(), &args)
        };

        for command in [
            vec![],
            vec!["help"],
            vec!["--help"],
            vec!["--version"],
            vec!["--bash"],
            vec!["config", "list"],
            vec!["config", "get", "cli.cache-path"],
            vec!["config", "set", "cli.color", "true"],
            vec!["config", "unset", "cli.color"],
            vec!["get", "property-manager"],
            vec!["install", "property-manager"],
            vec!["list", "--remote"],
            vec!["search", "property"],
            vec!["uninstall", "property-manager"],
            vec!["update", "property-manager"],
            vec!["upgrade"],
            vec!["future-command"],
            vec!["property-manager", "--help"],
        ] {
            assert!(secretless(&command), "akamai {command:?}");
        }

        for command in [
            vec!["property-manager", "list"],
            vec!["pm", "list"],
            vec!["property/property-manager", "list"],
            vec!["--section", "prod", "property-manager", "list"],
            vec!["--proxy=https://proxy.example", "property-manager", "list"],
            vec!["property-manager", "action", "--param", "key", "-h"],
            vec!["property-manager", "--", "payload"],
        ] {
            assert!(!secretless(&command), "akamai {command:?}");
        }

        let caller_edgerc = home.join("caller.edgerc");
        fs::write(
            &caller_edgerc,
            "[prod]\nhost = example.luna.akamaiapis.net\nclient_token = caller\nclient_secret = caller\naccess_token = caller\n",
        )
        .unwrap();
        let caller_edgerc = caller_edgerc.to_str().unwrap();
        assert!(secretless(&[
            "--edgerc",
            caller_edgerc,
            "--section",
            "prod",
            "property-manager",
            "list",
        ]));
        unsafe {
            std::env::set_var("AKAMAI_CLIENT_TOKEN", "caller");
            std::env::set_var("AKAMAI_CLIENT_SECRET", "caller");
            std::env::set_var("AKAMAI_ACCESS_TOKEN", "caller");
        }
        assert!(secretless(&["property-manager", "list"]));
        unsafe {
            std::env::set_var("AKAMAI_PROD_CLIENT_TOKEN", "caller");
            std::env::set_var("AKAMAI_PROD_CLIENT_SECRET", "caller");
            std::env::set_var("AKAMAI_PROD_ACCESS_TOKEN", "caller");
        }
        assert!(secretless(&[
            "--account-key",
            "acct",
            "--section=prod",
            "property-manager",
            "list",
        ]));

        let invocation = [script_path.clone().into_os_string(), OsString::from("help")];
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &invocation,
        ));

        unsafe {
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
            for (key, value) in previous {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn algolia_requests_secrets_only_for_commands_that_can_use_them() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-algolia");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let script_path = dir.join("algolia");
        let script = stub_script(
            &wrapper("algolia").unwrap().primary,
            Path::new("/opt/homebrew/bin/algolia"),
        );
        let args = |values: &[&str]| {
            std::iter::once(script_path.clone().into_os_string())
                .chain(values.iter().map(OsString::from))
                .collect::<Vec<_>>()
        };

        for command in [
            vec![],
            vec!["--help"],
            vec!["search", "--help"],
            vec!["--version"],
            vec!["completion", "zsh"],
            vec!["describe", "objects", "browse"],
            vec!["schema", "search"],
            vec!["application", "list"],
            vec!["app", "select"],
            vec!["open", "docs"],
            vec!["profile", "list"],
            vec!["auth", "login"],
            vec!["future-command"],
            vec!["--profile", "work", "describe"],
            vec!["--future-global", "search", "INDEX"],
        ] {
            assert!(
                invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "algolia {command:?}",
            );
        }
        for command in [
            vec!["search", "INDEX"],
            vec!["indices", "list"],
            vec!["records", "browse", "INDEX"],
            vec!["api-keys", "list"],
            vec!["settings", "get", "INDEX"],
            vec!["rules", "browse", "INDEX"],
            vec!["synonyms", "browse", "INDEX"],
            vec!["dict", "entries", "browse"],
            vec!["events", "tail"],
            vec!["compositions", "list"],
            vec!["crawler", "list"],
            vec!["auth", "status"],
            vec!["--profile", "work", "objects", "browse", "INDEX"],
            vec!["search", "INDEX", "--query", "--help"],
            vec!["search", "INDEX", "--", "--help"],
        ] {
            assert!(
                !invocation_is_secretless(&script_path, script.as_bytes(), &args(&command)),
                "algolia {command:?}",
            );
        }
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["apikeys", "rotate"]),
        ));
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&[
                "--application-id=APP",
                "--api-key",
                "caller-key",
                "search",
                "INDEX",
            ]),
        ));

        unsafe {
            std::env::set_var("ALGOLIA_APPLICATION_ID", "APP");
            std::env::set_var("ALGOLIA_API_KEY", "caller-key");
        }
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["objects", "browse", "INDEX"]),
        ));
        unsafe {
            std::env::remove_var("ALGOLIA_APPLICATION_ID");
            std::env::remove_var("ALGOLIA_API_KEY");
            std::env::set_var("ALGOLIA_CRAWLER_USER_ID", "caller-user");
            std::env::set_var("ALGOLIA_CRAWLER_API_KEY", "caller-key");
        }
        assert!(invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["crawler", "list"]),
        ));
        unsafe {
            std::env::remove_var("ALGOLIA_CRAWLER_USER_ID");
            std::env::remove_var("ALGOLIA_CRAWLER_API_KEY");
            std::env::set_var(
                "ALGOLIA_ENV_ASSIGNMENTS",
                "ALGOLIA_APPLICATION_ID=APP\nALGOLIA_API_KEY=vault-key",
            );
        }
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &args(&["search", "INDEX"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &args(&["describe"]),
        ));

        unsafe {
            std::env::remove_var("ALGOLIA_ENV_ASSIGNMENTS");
            std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR");
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
    fn luarocks_requests_its_api_key_only_for_upload() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-luarocks");
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir) };
        let stub = &wrapper("luarocks").unwrap().primary;
        let script_path = dir.join("luarocks");
        let script = stub_script(stub, Path::new("/opt/homebrew/bin/luarocks"));
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
            &["help", "upload"][..],
            &["completion", "zsh"][..],
            &["build", "example.rockspec"][..],
            &["config", "lua_version"][..],
            &["doc", "example"][..],
            &["download", "example"][..],
            &["init", "example"][..],
            &["install", "example"][..],
            &["lint", "example.rockspec"][..],
            &["new_version", "example.rockspec"][..],
            &["pack", "example.rockspec"][..],
            &["path"][..],
            &["purge"][..],
            &["remove", "example"][..],
            &["search", "example"][..],
            &["show", "example"][..],
            &["test", "example"][..],
            &["unpack", "example.src.rock"][..],
            &["which", "example"][..],
            &["write_rockspec", "example"][..],
            &["--lua-version=5.4", "list"][..],
            &["CC=clang", "--tree", "vendor", "make"][..],
            &["future-command"][..],
            &["external-command", "upload"][..],
            &["upload", "example.rockspec", "--api-key=caller-key"][..],
            &["--temp-key", "caller-key", "upload", "example.rockspec"][..],
            &[
                "upload",
                "example.rockspec",
                "--server=https://other.example",
            ][..],
        ] {
            assert!(secretless(args), "luarocks {args:?}");
        }
        for args in [
            &["upload", "example.rockspec"][..],
            &["--verbose", "upload", "example.rockspec"][..],
            &["--lua-version", "5.4", "upload", "example.rockspec"][..],
            &["CC=clang", "upload", "example.rockspec"][..],
            &["upload", "--", "--help"][..],
        ] {
            assert!(!secretless(args), "luarocks {args:?}");
        }
        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &invocation(&["search", "example"]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &[PathBuf::from("/tmp/not-the-stub").into_os_string()],
        ));

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR") };
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn minio_mc_requests_secrets_only_for_configured_remote_aliases() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = temp_dir("env-wrapper-secretless-minio-mc");
        let env_names = [
            "HOME",
            "MC_CONFIG_DIR",
            "MC_CONFIG_ENV_FILE",
            "MC_HOST_private",
        ];
        let previous_env = env_names.map(|name| (name, std::env::var_os(name)));
        fs::create_dir_all(dir.join(".mc")).unwrap();
        fs::write(
            dir.join(".mc/config.json"),
            r#"{"aliases":{"private":{"url":"https://minio.example","accessKey":"access"},"anonymous":{"url":"https://public.example","accessKey":""}}}"#,
        )
        .unwrap();
        unsafe {
            std::env::set_var("HOME", &dir);
            std::env::set_var("AUTOMIC_VAULT_TEST_ENV_WRAPPER_STUB_DIR", &dir);
            for name in env_names.into_iter().skip(1) {
                std::env::remove_var(name);
            }
        }
        let stub = &wrapper("minio-mc").unwrap().primary;
        let script_path = dir.join("mc");
        let script = stub_script(stub, Path::new("/opt/homebrew/bin/mc"));
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
            &["--autocompletion"][..],
            &["ls", "--help", "private/bucket"][..],
            &["alias", "set", "other", "https://other.example"][..],
            &["alias", "list", "anonymous"][..],
            &["alias", "export", "private"][..],
            &["update"][..],
            &["ls", "."][..],
            &["ls", "--resolve", "private/bucket", "."][..],
            &["cp", "./source", "../target"][..],
            &["mirror", "/tmp/source", "/tmp/target"][..],
            &["ls", "other/bucket"][..],
            &["future-command", "private/bucket"][..],
            &["--future-flag", "ls", "private/bucket"][..],
            &["--config-dir", "/tmp/other", "ls", "private/bucket"][..],
        ] {
            assert!(secretless(args), "mc {args:?}");
        }
        for args in [
            &["alias", "list"][..],
            &["alias", "ls", "private"][..],
            &["alias", "--json", "list"][..],
            &["alias", "list", "--resolve", "minio.example=127.0.0.1"][..],
            &["ls", "private/bucket"][..],
            &["--json", "ls", "private/bucket"][..],
            &["cp", "./source", "private/bucket"][..],
            &["mirror", "private/source", "/tmp/target"][..],
            &["admin", "info", "private"][..],
            &["version", "info", "private/bucket"][..],
            &["ls", "--", "private/bucket"][..],
        ] {
            assert!(!secretless(args), "mc {args:?}");
        }

        unsafe { std::env::set_var("MC_HOST_private", "https://caller@other.example") };
        assert!(secretless(&["ls", "private/bucket"]));
        assert!(secretless(&["alias", "list"]));
        unsafe {
            std::env::remove_var("MC_HOST_private");
            std::env::set_var("MC_CONFIG_DIR", "/tmp/other");
        }
        assert!(secretless(&["ls", "private/bucket"]));
        unsafe { std::env::remove_var("MC_CONFIG_DIR") };

        assert!(!invocation_is_secretless(
            &script_path,
            format!("{script}# changed\n").as_bytes(),
            &invocation(&["ls", "."]),
        ));
        assert!(!invocation_is_secretless(
            &script_path,
            script.as_bytes(),
            &[PathBuf::from("/tmp/not-the-stub").into_os_string()],
        ));

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
