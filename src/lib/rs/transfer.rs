use super::*;

use std::collections::BTreeSet;
use std::io;

const TRANSFER_BUNDLE_SCHEMA_VERSION: u32 = 1;
const DEFAULT_REMOTE_AV: &str = "av";
const INSTALLED_REMOTE_AV: &str = "/usr/local/bin/av";

#[derive(Debug, Clone, PartialEq, Eq)]
enum TransferCommand {
    Send(TransferSendOptions),
    Receive(TransferReceiveOptions),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransferSendOptions {
    ssh_target: String,
    file: PathBuf,
    include_dotenv: bool,
    keys: Vec<String>,
    replace: bool,
    ssh_options: Vec<String>,
    remote_av: String,
    remote_av_explicit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransferReceiveOptions {
    stdin: bool,
    check: bool,
    replace: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TransferBundle {
    schema_version: u32,
    source: KeyTransferApprovalSource,
    items: Vec<TransferBundleItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TransferBundleItem {
    DotenvPrivateKey {
        env_file_path: String,
        public_key_name: String,
        public_key: String,
        public_key_fingerprint: String,
        private_key: String,
    },
    IsotopeSecret {
        key: String,
        value: String,
    },
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct TransferImportPlan {
    approval_request: KeyTransferApprovalRequest,
    actions: Vec<TransferImportAction>,
    already_present: usize,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum TransferImportAction {
    StoreDotenvPrivateKey {
        public_key: String,
        private_key: String,
    },
    StoreIsotopeSecret {
        key: String,
        value: String,
    },
}

trait TransferSecretStore {
    fn export_dotenv_private_key(
        &self,
        file: &Path,
    ) -> Result<dotenv::DotenvPrivateKeyTransferMaterial, String>;
    fn load_isotope_secret(&self, key: &str) -> Result<String, String>;
    #[cfg(test)]
    fn load_existing_dotenv_private_key(&self, public_key: &str) -> Result<Option<String>, String>;
    #[cfg(test)]
    fn store_dotenv_private_key(&self, public_key: &str, private_key: &str) -> Result<(), String>;
    #[cfg(test)]
    fn load_existing_isotope_secret(&self, key: &str) -> Result<Option<String>, String>;
    #[cfg(test)]
    fn store_isotope_secret(&self, key: &str, value: &str) -> Result<(), String>;
}

struct KeychainTransferSecretStore;

impl TransferSecretStore for KeychainTransferSecretStore {
    fn export_dotenv_private_key(
        &self,
        file: &Path,
    ) -> Result<dotenv::DotenvPrivateKeyTransferMaterial, String> {
        dotenv::load_dotenv_private_key_for_transfer(file)
    }

    fn load_isotope_secret(&self, key: &str) -> Result<String, String> {
        isotope::load_isotope_secret_for_transfer(key)
    }

    #[cfg(test)]
    fn load_existing_dotenv_private_key(&self, public_key: &str) -> Result<Option<String>, String> {
        dotenv::load_existing_dotenv_private_key_for_transfer(public_key)
    }

    #[cfg(test)]
    fn store_dotenv_private_key(&self, public_key: &str, private_key: &str) -> Result<(), String> {
        dotenv::store_dotenv_private_key_for_transfer(public_key, private_key)
    }

    #[cfg(test)]
    fn load_existing_isotope_secret(&self, key: &str) -> Result<Option<String>, String> {
        isotope::load_existing_isotope_secret_for_transfer(key)
    }

    #[cfg(test)]
    fn store_isotope_secret(&self, key: &str, value: &str) -> Result<(), String> {
        isotope::store_isotope_secret_for_transfer(key, value)
    }
}

pub(crate) fn run_transfer_entry(program_name: &str, args: env::ArgsOs) -> Result<(), String> {
    let Some(command) = parse_transfer_command(program_name, args)? else {
        return Ok(());
    };
    match command {
        TransferCommand::Send(options) => run_transfer_send(&options, &KeychainTransferSecretStore),
        TransferCommand::Receive(options) => {
            run_transfer_receive(&options, vault::ensure_vaultd_available, |request| {
                vault::request_key_transfer_import(request)
            })
        }
    }
}

fn parse_transfer_command(
    program_name: &str,
    mut args: impl Iterator<Item = OsString>,
) -> Result<Option<TransferCommand>, String> {
    let Some(first_arg) = args.next() else {
        print_transfer_usage(program_name);
        return Err("missing ssh target".to_string());
    };
    if is_help_flag(&first_arg) {
        print_transfer_usage(program_name);
        return Ok(None);
    }
    if is_version_flag(&first_arg) {
        println!("{program_name} {}", env!("CARGO_PKG_VERSION"));
        return Ok(None);
    }
    if first_arg == "receive" {
        return parse_transfer_receive(program_name, args)
            .map(|value| value.map(TransferCommand::Receive));
    }
    parse_transfer_send(program_name, std::iter::once(first_arg).chain(args))
        .map(|value| value.map(TransferCommand::Send))
}

fn parse_transfer_send(
    program_name: &str,
    args: impl Iterator<Item = OsString>,
) -> Result<Option<TransferSendOptions>, String> {
    let mut ssh_target: Option<String> = None;
    let mut file = PathBuf::from(".env");
    let mut include_dotenv = true;
    let mut keys = Vec::new();
    let mut seen_keys = BTreeSet::new();
    let mut replace = false;
    let mut ssh_options = Vec::new();
    let mut remote_av = DEFAULT_REMOTE_AV.to_string();
    let mut remote_av_explicit = false;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        if is_help_flag(&arg) {
            print_transfer_usage(program_name);
            return Ok(None);
        }
        if is_version_flag(&arg) {
            println!("{program_name} {}", env!("CARGO_PKG_VERSION"));
            return Ok(None);
        }
        if arg == "--file" || arg == "-f" {
            file = next_transfer_value(&mut args, "--file").map(PathBuf::from)?;
            continue;
        }
        if arg == "--no-dotenv" {
            include_dotenv = false;
            continue;
        }
        if arg == "--key" || arg == "-k" {
            let key = next_transfer_value(&mut args, "--key")?;
            isotope::validate_isotope_key_name_for_transfer(&key)?;
            if !seen_keys.insert(key.clone()) {
                return Err(format!("duplicate key requested: {key}"));
            }
            keys.push(key);
            continue;
        }
        if arg == "--replace" {
            replace = true;
            continue;
        }
        if arg == "--ssh-option" {
            ssh_options.push(next_transfer_value(&mut args, "--ssh-option")?);
            continue;
        }
        if arg == "--remote-av" {
            remote_av = next_transfer_value(&mut args, "--remote-av")?;
            remote_av_explicit = true;
            if remote_av.trim().is_empty() {
                return Err("--remote-av must not be empty".to_string());
            }
            continue;
        }
        let value = arg
            .to_str()
            .ok_or_else(|| "ssh target must be valid UTF-8".to_string())?;
        if ssh_target.is_some() {
            return Err("transfer supports one ssh target".to_string());
        }
        ssh_target = Some(value.to_string());
    }

    let Some(ssh_target) = ssh_target else {
        print_transfer_usage(program_name);
        return Err("missing ssh target".to_string());
    };
    if ssh_target.trim().is_empty() {
        return Err("empty ssh target".to_string());
    }
    Ok(Some(TransferSendOptions {
        ssh_target,
        file,
        include_dotenv,
        keys,
        replace,
        ssh_options,
        remote_av,
        remote_av_explicit,
    }))
}

fn parse_transfer_receive(
    program_name: &str,
    args: impl Iterator<Item = OsString>,
) -> Result<Option<TransferReceiveOptions>, String> {
    let mut stdin = false;
    let mut check = false;
    let mut replace = false;
    for arg in args {
        if is_help_flag(&arg) {
            print_transfer_receive_usage(program_name);
            return Ok(None);
        }
        if is_version_flag(&arg) {
            println!("{program_name} {}", env!("CARGO_PKG_VERSION"));
            return Ok(None);
        }
        if arg == "--stdin" {
            stdin = true;
            continue;
        }
        if arg == "--check" {
            check = true;
            continue;
        }
        if arg == "--replace" {
            replace = true;
            continue;
        }
        return Err(format!(
            "unknown transfer receive argument '{}'",
            arg.to_string_lossy()
        ));
    }
    if check {
        return Ok(Some(TransferReceiveOptions {
            stdin,
            check,
            replace,
        }));
    }
    if !stdin {
        print_transfer_receive_usage(program_name);
        return Err("transfer receive requires --stdin".to_string());
    }
    Ok(Some(TransferReceiveOptions {
        stdin,
        check,
        replace,
    }))
}

fn next_transfer_value<I>(args: &mut std::iter::Peekable<I>, flag: &str) -> Result<String, String>
where
    I: Iterator<Item = OsString>,
{
    args.next()
        .ok_or_else(|| format!("missing value for {flag}"))?
        .into_string()
        .map_err(|_| format!("{flag} value must be valid UTF-8"))
}

fn run_transfer_send(
    options: &TransferSendOptions,
    store: &dyn TransferSecretStore,
) -> Result<(), String> {
    let mut bundle = build_transfer_bundle(options, store)?;
    if let Err(err) = check_remote_transfer_receiver(options) {
        zeroize_transfer_bundle(&mut bundle);
        return Err(err);
    }
    let item_count = bundle.items.len();
    let ssh_args = build_ssh_command_args(options);
    let mut payload = serde_json::to_string(&bundle)
        .map_err(|err| format!("failed to encode transfer bundle: {err}"))?;
    zeroize_transfer_bundle(&mut bundle);

    let mut child = Command::new("ssh")
        .args(&ssh_args)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to start ssh: {err}"))?;
    let write_result = if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(payload.as_bytes())
            .and_then(|_| stdin.flush())
            .map_err(|err| format!("failed to send transfer bundle over ssh: {err}"))
    } else {
        Err("failed to open ssh stdin".to_string())
    };
    zeroize_string(&mut payload);
    let status = child
        .wait()
        .map_err(|err| format!("failed to wait for ssh: {err}"))?;
    write_result?;
    if !status.success() {
        return Err(format!("transfer failed: ssh exited with {status}"));
    }
    println!(
        "sent {} to {}",
        pluralize(item_count, "key", "keys"),
        options.ssh_target
    );
    Ok(())
}

fn check_remote_transfer_receiver(options: &TransferSendOptions) -> Result<(), String> {
    let output = Command::new("ssh")
        .args(build_ssh_check_command_args(options))
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("failed to start ssh for transfer check: {err}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    transfer_check_failure_result(&options.ssh_target, &output.status.to_string(), &stderr)
}

fn transfer_check_failure_result(
    ssh_target: &str,
    status: &str,
    stderr: &str,
) -> Result<(), String> {
    if stderr.contains("unknown transfer receive argument '--check'") {
        return Ok(());
    }
    let stderr = stderr.trim();
    if stderr.contains("vaultd unavailable") {
        let detail = stderr
            .strip_prefix("av transfer: ")
            .unwrap_or(stderr)
            .trim();
        if detail.is_empty() {
            return Err(format!(
                "receiving Automic Vault.app is unavailable on {}; open Automic Vault.app there and try again",
                ssh_target
            ));
        }
        return Err(format!(
            "receiving Automic Vault.app is unavailable on {}; open Automic Vault.app there and try again ({detail})",
            ssh_target
        ));
    }
    if stderr.is_empty() {
        return Err(format!(
            "transfer check failed on {ssh_target}: ssh exited with {status}"
        ));
    }
    Err(format!("transfer check failed on {ssh_target}: {stderr}"))
}

fn build_transfer_bundle(
    options: &TransferSendOptions,
    store: &dyn TransferSecretStore,
) -> Result<TransferBundle, String> {
    let mut items = Vec::new();
    if options.include_dotenv {
        let material = store.export_dotenv_private_key(&options.file)?;
        items.push(TransferBundleItem::DotenvPrivateKey {
            env_file_path: material.env_file_path.to_string_lossy().into_owned(),
            public_key_name: material.public_key_name,
            public_key: material.public_key,
            public_key_fingerprint: material.public_key_fingerprint,
            private_key: material.private_key,
        });
    }
    for key in &options.keys {
        let value = store.load_isotope_secret(key)?;
        items.push(TransferBundleItem::IsotopeSecret {
            key: key.clone(),
            value,
        });
    }
    if items.is_empty() {
        return Err("nothing to transfer; remove --no-dotenv or add --key KEY".to_string());
    }
    Ok(TransferBundle {
        schema_version: TRANSFER_BUNDLE_SCHEMA_VERSION,
        source: transfer_source_metadata(Some(&options.ssh_target)),
        items,
    })
}

fn transfer_source_metadata(ssh_target: Option<&str>) -> KeyTransferApprovalSource {
    KeyTransferApprovalSource {
        user: env::var("USER")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "unknown".to_string()),
        host: local_hostname(),
        cwd: env::current_dir()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_else(|_| ".".to_string()),
        ssh_target: ssh_target.map(str::to_string),
    }
}

fn local_hostname() -> String {
    Command::new("/bin/hostname")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn build_ssh_command_args(options: &TransferSendOptions) -> Vec<String> {
    build_ssh_command_args_for(options, false)
}

fn build_ssh_check_command_args(options: &TransferSendOptions) -> Vec<String> {
    build_ssh_command_args_for(options, true)
}

fn build_ssh_command_args_for(options: &TransferSendOptions, check: bool) -> Vec<String> {
    let mut args = options.ssh_options.clone();
    args.push(options.ssh_target.clone());
    args.push(remote_receive_command(
        &options.remote_av,
        options.remote_av_explicit,
        options.replace,
        check,
    ));
    args
}

fn remote_receive_command(
    remote_av: &str,
    remote_av_explicit: bool,
    replace: bool,
    check: bool,
) -> String {
    if !remote_av_explicit && remote_av == DEFAULT_REMOTE_AV {
        return format!(
            "if command -v {} >/dev/null 2>&1; then exec {}; else exec {}; fi",
            shell_quote(DEFAULT_REMOTE_AV),
            remote_receive_invocation(DEFAULT_REMOTE_AV, replace, check),
            remote_receive_invocation(INSTALLED_REMOTE_AV, replace, check)
        );
    }
    remote_receive_invocation(remote_av, replace, check)
}

fn remote_receive_invocation(remote_av: &str, replace: bool, check: bool) -> String {
    let mut parts = vec![
        shell_quote(remote_av),
        shell_quote("transfer"),
        shell_quote("receive"),
    ];
    if check {
        parts.push(shell_quote("--check"));
    } else {
        parts.push(shell_quote("--stdin"));
    }
    if replace {
        parts.push(shell_quote("--replace"));
    }
    parts.join(" ")
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn run_transfer_receive<C, I>(
    options: &TransferReceiveOptions,
    check_daemon: C,
    import: I,
) -> Result<(), String>
where
    C: FnOnce() -> Result<(), String>,
    I: FnOnce(KeyTransferImportRequest) -> Result<KeyTransferImportResponse, String>,
{
    if options.check {
        check_daemon()?;
        return Ok(());
    }
    if !options.stdin {
        return Err("transfer receive requires --stdin".to_string());
    }
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|err| format!("failed to read transfer bundle from stdin: {err}"))?;
    let mut bundle: TransferBundle = serde_json::from_str(&input)
        .map_err(|err| format!("failed to decode transfer bundle: {err}"))?;
    zeroize_string(&mut input);
    let request = build_key_transfer_import_request(&bundle, options.replace)?;
    zeroize_transfer_bundle(&mut bundle);
    let response = import(request)?;
    println!(
        "imported {}; {} already present",
        pluralize(response.imported, "key", "keys"),
        pluralize(response.already_present, "key", "keys")
    );
    Ok(())
}

fn build_key_transfer_import_request(
    bundle: &TransferBundle,
    replace: bool,
) -> Result<KeyTransferImportRequest, String> {
    validate_transfer_bundle(bundle)?;
    Ok(KeyTransferImportRequest {
        id: vault::new_vault_request_id()?,
        source: bundle.source.clone(),
        replace,
        items: bundle
            .items
            .iter()
            .map(|item| match item {
                TransferBundleItem::DotenvPrivateKey {
                    env_file_path,
                    public_key_name,
                    public_key,
                    public_key_fingerprint,
                    private_key,
                } => KeyTransferImportItem::DotenvPrivateKey {
                    env_file_path: env_file_path.clone(),
                    public_key_name: public_key_name.clone(),
                    public_key: public_key.clone(),
                    public_key_fingerprint: public_key_fingerprint.clone(),
                    private_key: private_key.clone(),
                },
                TransferBundleItem::IsotopeSecret { key, value } => {
                    KeyTransferImportItem::IsotopeSecret {
                        key: key.clone(),
                        value: value.clone(),
                    }
                }
            })
            .collect(),
    })
}

#[cfg(test)]
fn plan_transfer_import(
    bundle: &TransferBundle,
    replace: bool,
    store: &dyn TransferSecretStore,
) -> Result<TransferImportPlan, String> {
    validate_transfer_bundle(bundle)?;
    let mut items = Vec::new();
    let mut actions = Vec::new();
    let mut already_present = 0;
    let mut conflicts = Vec::new();

    for item in &bundle.items {
        match item {
            TransferBundleItem::DotenvPrivateKey {
                env_file_path,
                public_key_name,
                public_key,
                public_key_fingerprint,
                private_key,
            } => {
                let existing = store.load_existing_dotenv_private_key(public_key)?;
                let replacing_existing = existing
                    .as_deref()
                    .is_some_and(|existing| existing != private_key);
                items.push(KeyTransferApprovalItem {
                    kind: "dotenv".to_string(),
                    name: public_key_name.clone(),
                    detail: Some(format!(
                        "{} ({})",
                        env_file_path,
                        fingerprint_prefix(public_key_fingerprint)
                    )),
                    replacing_existing,
                });
                match existing {
                    Some(existing) if existing == *private_key => already_present += 1,
                    Some(_) if !replace => conflicts.push(format!(
                        "dotenv private key {}",
                        fingerprint_prefix(public_key_fingerprint)
                    )),
                    Some(_) | None => actions.push(TransferImportAction::StoreDotenvPrivateKey {
                        public_key: public_key.clone(),
                        private_key: private_key.clone(),
                    }),
                }
            }
            TransferBundleItem::IsotopeSecret { key, value } => {
                let existing = store.load_existing_isotope_secret(key)?;
                let replacing_existing = existing
                    .as_deref()
                    .is_some_and(|existing| existing != value);
                items.push(KeyTransferApprovalItem {
                    kind: "isotope".to_string(),
                    name: key.clone(),
                    detail: None,
                    replacing_existing,
                });
                match existing {
                    Some(existing) if existing == *value => already_present += 1,
                    Some(_) if !replace => conflicts.push(format!("isotope key {key}")),
                    Some(_) | None => actions.push(TransferImportAction::StoreIsotopeSecret {
                        key: key.clone(),
                        value: value.clone(),
                    }),
                }
            }
        }
    }

    if !conflicts.is_empty() {
        return Err(format!(
            "destination already has different values for {}; rerun with --replace to overwrite",
            conflicts.join(", ")
        ));
    }

    Ok(TransferImportPlan {
        approval_request: KeyTransferApprovalRequest {
            id: vault::new_vault_request_id()?,
            source: bundle.source.clone(),
            item_count: bundle.items.len(),
            replace,
            items,
        },
        actions,
        already_present,
    })
}

fn validate_transfer_bundle(bundle: &TransferBundle) -> Result<(), String> {
    if bundle.schema_version != TRANSFER_BUNDLE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported transfer bundle schema {}",
            bundle.schema_version
        ));
    }
    if bundle.items.is_empty() {
        return Err("transfer bundle contains no keys".to_string());
    }
    let mut seen = BTreeSet::new();
    for item in &bundle.items {
        match item {
            TransferBundleItem::DotenvPrivateKey {
                public_key_name,
                public_key,
                public_key_fingerprint,
                private_key,
                ..
            } => {
                dotenv::validate_dotenv_public_key_name_for_transfer(public_key_name)?;
                dotenv::validate_dotenv_public_key_for_transfer(public_key)?;
                dotenv::validate_dotenv_private_key_for_transfer(private_key)?;
                let expected = dotenv::dotenv_public_key_fingerprint_for_transfer(public_key);
                if expected != *public_key_fingerprint {
                    return Err("dotenv public key fingerprint mismatch".to_string());
                }
                if !seen.insert(format!("dotenv:{public_key_fingerprint}")) {
                    return Err(format!(
                        "duplicate dotenv private key {}",
                        fingerprint_prefix(public_key_fingerprint)
                    ));
                }
            }
            TransferBundleItem::IsotopeSecret { key, .. } => {
                isotope::validate_isotope_key_name_for_transfer(key)?;
                if !seen.insert(format!("isotope:{key}")) {
                    return Err(format!("duplicate isotope key {key}"));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn apply_transfer_import(
    plan: &mut TransferImportPlan,
    store: &dyn TransferSecretStore,
) -> Result<(usize, usize), String> {
    let mut imported = 0;
    for action in &mut plan.actions {
        match action {
            TransferImportAction::StoreDotenvPrivateKey {
                public_key,
                private_key,
            } => {
                store.store_dotenv_private_key(public_key, private_key)?;
                zeroize_string(private_key);
                imported += 1;
            }
            TransferImportAction::StoreIsotopeSecret { key, value } => {
                store.store_isotope_secret(key, value)?;
                zeroize_string(value);
                imported += 1;
            }
        }
    }
    plan.actions.clear();
    Ok((imported, plan.already_present))
}

fn fingerprint_prefix(value: &str) -> String {
    value.chars().take(12).collect()
}

fn pluralize(count: usize, singular: &str, plural: &str) -> String {
    let noun = if count == 1 { singular } else { plural };
    format!("{count} {noun}")
}

fn zeroize_transfer_bundle(bundle: &mut TransferBundle) {
    for item in &mut bundle.items {
        match item {
            TransferBundleItem::DotenvPrivateKey { private_key, .. } => {
                zeroize_string(private_key);
            }
            TransferBundleItem::IsotopeSecret { value, .. } => {
                zeroize_string(value);
            }
        }
    }
}

fn zeroize_string(value: &mut String) {
    unsafe {
        value.as_mut_vec().fill(0);
    }
    value.clear();
}

pub(crate) fn print_transfer_usage(program_name: &str) {
    println!(
        "\
Usage: {program_name} <ssh-target> [--file .env] [--no-dotenv] [--key KEY]... [--replace] [--ssh-option ARG]... [--remote-av av]
       {program_name} receive --stdin [--replace]

Transfers Automic Vault keys to another Mac over ssh. The receiving Mac must
have Automic Vault.app running and approve the import."
    );
}

fn print_transfer_receive_usage(program_name: &str) {
    println!("Usage: {program_name} receive --stdin [--replace]");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct StubTransferStore {
        dotenv_exports: RefCell<HashMap<PathBuf, dotenv::DotenvPrivateKeyTransferMaterial>>,
        isotope_exports: RefCell<HashMap<String, String>>,
        dotenv_existing: RefCell<HashMap<String, String>>,
        isotope_existing: RefCell<HashMap<String, String>>,
        stored_dotenv: RefCell<HashMap<String, String>>,
        stored_isotope: RefCell<HashMap<String, String>>,
    }

    impl TransferSecretStore for StubTransferStore {
        fn export_dotenv_private_key(
            &self,
            file: &Path,
        ) -> Result<dotenv::DotenvPrivateKeyTransferMaterial, String> {
            self.dotenv_exports
                .borrow()
                .get(file)
                .cloned()
                .ok_or_else(|| format!("missing dotenv export {}", file.display()))
        }

        fn load_isotope_secret(&self, key: &str) -> Result<String, String> {
            self.isotope_exports
                .borrow()
                .get(key)
                .cloned()
                .ok_or_else(|| format!("missing isotope key {key}"))
        }

        fn load_existing_dotenv_private_key(
            &self,
            public_key: &str,
        ) -> Result<Option<String>, String> {
            Ok(self.dotenv_existing.borrow().get(public_key).cloned())
        }

        fn store_dotenv_private_key(
            &self,
            public_key: &str,
            private_key: &str,
        ) -> Result<(), String> {
            self.stored_dotenv
                .borrow_mut()
                .insert(public_key.to_string(), private_key.to_string());
            Ok(())
        }

        fn load_existing_isotope_secret(&self, key: &str) -> Result<Option<String>, String> {
            Ok(self.isotope_existing.borrow().get(key).cloned())
        }

        fn store_isotope_secret(&self, key: &str, value: &str) -> Result<(), String> {
            self.stored_isotope
                .borrow_mut()
                .insert(key.to_string(), value.to_string());
            Ok(())
        }
    }

    fn transfer_keypair() -> (String, String) {
        let (private_key, public_key) = ecies::utils::generate_keypair();
        (
            encode_hex(&public_key.serialize_compressed()),
            encode_hex(&private_key.serialize()),
        )
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const TABLE: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(TABLE[(byte >> 4) as usize] as char);
            output.push(TABLE[(byte & 0x0f) as usize] as char);
        }
        output
    }

    fn test_source() -> KeyTransferApprovalSource {
        KeyTransferApprovalSource {
            user: "alice".to_string(),
            host: "source-mac".to_string(),
            cwd: "/Users/alice/project".to_string(),
            ssh_target: Some("bob@dest".to_string()),
        }
    }

    fn dotenv_item(public_key: String, private_key: String) -> TransferBundleItem {
        TransferBundleItem::DotenvPrivateKey {
            env_file_path: "/Users/alice/project/.env".to_string(),
            public_key_name: "DOTENV_PUBLIC_KEY".to_string(),
            public_key_fingerprint: dotenv::dotenv_public_key_fingerprint_for_transfer(&public_key),
            public_key,
            private_key,
        }
    }

    fn bundle(items: Vec<TransferBundleItem>) -> TransferBundle {
        TransferBundle {
            schema_version: TRANSFER_BUNDLE_SCHEMA_VERSION,
            source: test_source(),
            items,
        }
    }

    #[test]
    fn transfer_parse_send_defaults_and_options() {
        let command = parse_transfer_command(
            "av transfer",
            [
                OsString::from("--file"),
                OsString::from(".env.prod"),
                OsString::from("--key"),
                OsString::from("TOKEN"),
                OsString::from("--replace"),
                OsString::from("--ssh-option"),
                OsString::from("-p 2222"),
                OsString::from("--remote-av"),
                OsString::from("/opt/homebrew/bin/av"),
                OsString::from("me@mac"),
            ]
            .into_iter(),
        )
        .unwrap()
        .unwrap();

        let TransferCommand::Send(options) = command else {
            panic!("expected send command");
        };
        assert_eq!(options.ssh_target, "me@mac");
        assert_eq!(options.file, PathBuf::from(".env.prod"));
        assert_eq!(options.keys, vec!["TOKEN"]);
        assert!(options.replace);
        assert_eq!(options.ssh_options, vec!["-p 2222"]);
        assert_eq!(options.remote_av, "/opt/homebrew/bin/av");
        assert!(options.remote_av_explicit);
    }

    #[test]
    fn transfer_parse_error_edges_cover_remaining_branches() {
        assert!(
            parse_transfer_command("av transfer", [OsString::from("--help")].into_iter())
                .unwrap()
                .is_none()
        );
        assert!(
            parse_transfer_command("av transfer", [OsString::from("--version")].into_iter())
                .unwrap()
                .is_none()
        );
        assert!(
            parse_transfer_command(
                "av transfer",
                [
                    OsString::from("--no-dotenv"),
                    OsString::from("--ssh-option"),
                    OsString::from("-A"),
                    OsString::from("host"),
                ]
                .into_iter()
            )
            .unwrap()
            .is_some()
        );
        assert_eq!(
            parse_transfer_command(
                "av transfer",
                [
                    OsString::from("--key"),
                    OsString::from("TOKEN"),
                    OsString::from("--key"),
                    OsString::from("TOKEN"),
                    OsString::from("host"),
                ]
                .into_iter()
            )
            .unwrap_err(),
            "duplicate key requested: TOKEN"
        );
        assert_eq!(
            parse_transfer_command(
                "av transfer",
                [
                    OsString::from("--remote-av"),
                    OsString::from(""),
                    OsString::from("host"),
                ]
                .into_iter()
            )
            .unwrap_err(),
            "--remote-av must not be empty"
        );
        assert_eq!(
            parse_transfer_command(
                "av transfer",
                [OsString::from("one"), OsString::from("two")].into_iter()
            )
            .unwrap_err(),
            "transfer supports one ssh target"
        );
        assert_eq!(
            parse_transfer_command("av transfer", [OsString::from(" ")].into_iter()).unwrap_err(),
            "empty ssh target"
        );
        assert!(
            parse_transfer_command(
                "av transfer",
                [OsString::from("receive"), OsString::from("--help")].into_iter()
            )
            .unwrap()
            .is_none()
        );
        assert!(
            parse_transfer_command(
                "av transfer",
                [OsString::from("receive"), OsString::from("--version")].into_iter()
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(
            parse_transfer_command(
                "av transfer",
                [OsString::from("receive"), OsString::from("--bogus")].into_iter()
            )
            .unwrap_err(),
            "unknown transfer receive argument '--bogus'"
        );
    }

    #[test]
    fn transfer_parse_receive_requires_stdin() {
        assert_eq!(
            parse_transfer_command(
                "av transfer",
                [OsString::from("receive"), OsString::from("--replace")].into_iter()
            )
            .unwrap_err(),
            "transfer receive requires --stdin"
        );
        let command = parse_transfer_command(
            "av transfer",
            [
                OsString::from("receive"),
                OsString::from("--stdin"),
                OsString::from("--replace"),
            ]
            .into_iter(),
        )
        .unwrap()
        .unwrap();
        let TransferCommand::Receive(options) = command else {
            panic!("expected receive command");
        };
        assert!(options.stdin);
        assert!(!options.check);
        assert!(options.replace);

        let command = parse_transfer_command(
            "av transfer",
            [OsString::from("receive"), OsString::from("--check")].into_iter(),
        )
        .unwrap()
        .unwrap();
        let TransferCommand::Receive(options) = command else {
            panic!("expected receive command");
        };
        assert!(!options.stdin);
        assert!(options.check);
    }

    #[test]
    fn transfer_keychain_store_wrappers_reject_invalid_inputs_before_keychain() {
        let store = KeychainTransferSecretStore;
        assert!(
            !store
                .export_dotenv_private_key(Path::new("/definitely/missing/.env"))
                .unwrap_err()
                .is_empty()
        );
        assert!(
            store
                .load_isotope_secret("BAD-NAME")
                .unwrap_err()
                .contains("invalid isotope key name")
        );
        assert!(
            store
                .load_existing_dotenv_private_key("abc")
                .unwrap_err()
                .contains("hex value")
        );
        assert!(
            store
                .store_dotenv_private_key("abc", "value")
                .unwrap_err()
                .contains("hex value")
        );
        assert!(
            store
                .load_existing_isotope_secret("BAD-NAME")
                .unwrap_err()
                .contains("invalid isotope key name")
        );
        assert!(
            store
                .store_isotope_secret("BAD-NAME", "value")
                .unwrap_err()
                .contains("invalid isotope key name")
        );
    }

    #[test]
    fn transfer_builds_bundle_with_dotenv_and_named_keys() {
        let (public_key, private_key) = transfer_keypair();
        let store = StubTransferStore::default();
        store.dotenv_exports.borrow_mut().insert(
            PathBuf::from(".env"),
            dotenv::DotenvPrivateKeyTransferMaterial {
                env_file_path: PathBuf::from("/repo/.env"),
                public_key_name: "DOTENV_PUBLIC_KEY".to_string(),
                public_key: public_key.clone(),
                public_key_fingerprint: dotenv::dotenv_public_key_fingerprint_for_transfer(
                    &public_key,
                ),
                private_key,
            },
        );
        store
            .isotope_exports
            .borrow_mut()
            .insert("TOKEN".to_string(), "secret".to_string());
        let options = TransferSendOptions {
            ssh_target: "me@mac".to_string(),
            file: PathBuf::from(".env"),
            include_dotenv: true,
            keys: vec!["TOKEN".to_string()],
            replace: false,
            ssh_options: Vec::new(),
            remote_av: DEFAULT_REMOTE_AV.to_string(),
            remote_av_explicit: false,
        };

        let bundle = build_transfer_bundle(&options, &store).unwrap();

        assert_eq!(bundle.items.len(), 2);
        assert_eq!(bundle.source.ssh_target.as_deref(), Some("me@mac"));
    }

    #[test]
    fn transfer_rejects_empty_bundle() {
        let store = StubTransferStore::default();
        let options = TransferSendOptions {
            ssh_target: "me@mac".to_string(),
            file: PathBuf::from(".env"),
            include_dotenv: false,
            keys: Vec::new(),
            replace: false,
            ssh_options: Vec::new(),
            remote_av: DEFAULT_REMOTE_AV.to_string(),
            remote_av_explicit: false,
        };

        assert!(
            build_transfer_bundle(&options, &store)
                .unwrap_err()
                .contains("nothing to transfer")
        );
    }

    #[test]
    fn transfer_run_send_receive_and_zeroize_edges() {
        let store = StubTransferStore::default();
        let options = TransferSendOptions {
            ssh_target: "me@mac".to_string(),
            file: PathBuf::from(".env"),
            include_dotenv: false,
            keys: Vec::new(),
            replace: false,
            ssh_options: Vec::new(),
            remote_av: DEFAULT_REMOTE_AV.to_string(),
            remote_av_explicit: false,
        };
        assert!(
            run_transfer_send(&options, &store)
                .unwrap_err()
                .contains("nothing to transfer")
        );
        assert_eq!(
            run_transfer_receive(
                &TransferReceiveOptions {
                    stdin: false,
                    check: false,
                    replace: false,
                },
                || unreachable!("check=false returns before daemon check"),
                |_| unreachable!("stdin=false returns before import"),
            )
            .unwrap_err(),
            "transfer receive requires --stdin"
        );
        assert_eq!(shell_quote(""), "''");
        assert_eq!(pluralize(1, "key", "keys"), "1 key");
        assert_eq!(pluralize(2, "key", "keys"), "2 keys");

        let (public_key, private_key) = transfer_keypair();
        let mut transfer_bundle = bundle(vec![
            dotenv_item(public_key, private_key),
            TransferBundleItem::IsotopeSecret {
                key: "TOKEN".to_string(),
                value: "secret".to_string(),
            },
        ]);
        zeroize_transfer_bundle(&mut transfer_bundle);
        assert!(matches!(
            &transfer_bundle.items[0],
            TransferBundleItem::DotenvPrivateKey { private_key, .. } if private_key.is_empty()
        ));
        assert!(matches!(
            &transfer_bundle.items[1],
            TransferBundleItem::IsotopeSecret { value, .. } if value.is_empty()
        ));
    }

    #[test]
    fn transfer_ssh_command_shell_quotes_remote_command() {
        let options = TransferSendOptions {
            ssh_target: "me@mac".to_string(),
            file: PathBuf::from(".env"),
            include_dotenv: true,
            keys: Vec::new(),
            replace: true,
            ssh_options: vec!["-p 2222".to_string()],
            remote_av: "/Applications/Automic Vault/av".to_string(),
            remote_av_explicit: true,
        };

        let args = build_ssh_command_args(&options);

        assert_eq!(args[0], "-p 2222");
        assert_eq!(args[1], "me@mac");
        assert_eq!(
            args[2],
            "'/Applications/Automic Vault/av' 'transfer' 'receive' '--stdin' '--replace'"
        );
    }

    #[test]
    fn transfer_ssh_command_falls_back_to_usr_local_bin_for_default_remote_av() {
        let options = TransferSendOptions {
            ssh_target: "me@mac".to_string(),
            file: PathBuf::from(".env"),
            include_dotenv: true,
            keys: Vec::new(),
            replace: false,
            ssh_options: Vec::new(),
            remote_av: DEFAULT_REMOTE_AV.to_string(),
            remote_av_explicit: false,
        };

        let args = build_ssh_command_args(&options);

        assert_eq!(args[0], "me@mac");
        assert_eq!(
            args[1],
            "if command -v 'av' >/dev/null 2>&1; then exec 'av' 'transfer' 'receive' '--stdin'; else exec '/usr/local/bin/av' 'transfer' 'receive' '--stdin'; fi"
        );
    }

    #[test]
    fn transfer_ssh_check_command_uses_receive_check() {
        let options = TransferSendOptions {
            ssh_target: "me@mac".to_string(),
            file: PathBuf::from(".env"),
            include_dotenv: true,
            keys: Vec::new(),
            replace: false,
            ssh_options: Vec::new(),
            remote_av: DEFAULT_REMOTE_AV.to_string(),
            remote_av_explicit: false,
        };

        let args = build_ssh_check_command_args(&options);

        assert_eq!(args[0], "me@mac");
        assert_eq!(
            args[1],
            "if command -v 'av' >/dev/null 2>&1; then exec 'av' 'transfer' 'receive' '--check'; else exec '/usr/local/bin/av' 'transfer' 'receive' '--check'; fi"
        );
    }

    #[test]
    fn transfer_receive_check_pings_daemon_without_reading_stdin() {
        let options = TransferReceiveOptions {
            stdin: false,
            check: true,
            replace: false,
        };
        let mut checked = false;
        let mut imported = false;

        run_transfer_receive(
            &options,
            || {
                checked = true;
                Ok(())
            },
            |_| {
                imported = true;
                Err("unexpected import".to_string())
            },
        )
        .unwrap();

        assert!(checked);
        assert!(!imported);
    }

    #[test]
    fn transfer_check_failure_result_handles_expected_remote_errors() {
        assert!(
            transfer_check_failure_result(
                "me@mac",
                "exit status: 1",
                "av transfer: unknown transfer receive argument '--check'\n",
            )
            .is_ok()
        );

        assert_eq!(
            transfer_check_failure_result(
                "me@mac",
                "exit status: 1",
                "av transfer: vaultd unavailable at /tmp/vault.sock: Connection refused\n",
            )
            .unwrap_err(),
            "receiving Automic Vault.app is unavailable on me@mac; open Automic Vault.app there and try again (vaultd unavailable at /tmp/vault.sock: Connection refused)"
        );

        assert_eq!(
            transfer_check_failure_result("me@mac", "exit status: 255", "").unwrap_err(),
            "transfer check failed on me@mac: ssh exited with exit status: 255"
        );
    }

    #[test]
    fn transfer_plan_imports_absent_values_after_approval() {
        let (public_key, private_key) = transfer_keypair();
        let store = StubTransferStore::default();
        let mut plan = plan_transfer_import(
            &bundle(vec![
                dotenv_item(public_key.clone(), private_key.clone()),
                TransferBundleItem::IsotopeSecret {
                    key: "TOKEN".to_string(),
                    value: "secret".to_string(),
                },
            ]),
            false,
            &store,
        )
        .unwrap();

        assert_eq!(plan.approval_request.item_count, 2);
        assert_eq!(plan.actions.len(), 2);
        assert_eq!(apply_transfer_import(&mut plan, &store).unwrap(), (2, 0));
        assert_eq!(
            store.stored_dotenv.borrow().get(&public_key),
            Some(&private_key)
        );
        assert_eq!(
            store.stored_isotope.borrow().get("TOKEN"),
            Some(&"secret".to_string())
        );
    }

    #[test]
    fn transfer_import_is_idempotent_for_identical_values() {
        let (public_key, private_key) = transfer_keypair();
        let store = StubTransferStore::default();
        store
            .dotenv_existing
            .borrow_mut()
            .insert(public_key.clone(), private_key.clone());
        store
            .isotope_existing
            .borrow_mut()
            .insert("TOKEN".to_string(), "secret".to_string());

        let mut plan = plan_transfer_import(
            &bundle(vec![
                dotenv_item(public_key, private_key),
                TransferBundleItem::IsotopeSecret {
                    key: "TOKEN".to_string(),
                    value: "secret".to_string(),
                },
            ]),
            false,
            &store,
        )
        .unwrap();

        assert!(plan.actions.is_empty());
        assert_eq!(apply_transfer_import(&mut plan, &store).unwrap(), (0, 2));
    }

    #[test]
    fn transfer_import_requires_replace_for_different_existing_values() {
        let (public_key, private_key) = transfer_keypair();
        let store = StubTransferStore::default();
        store
            .dotenv_existing
            .borrow_mut()
            .insert(public_key.clone(), "different".to_string());

        let err = plan_transfer_import(
            &bundle(vec![dotenv_item(public_key, private_key)]),
            false,
            &store,
        )
        .unwrap_err();

        assert!(err.contains("rerun with --replace"));
    }

    #[test]
    fn transfer_import_replace_marks_approval_items() {
        let (public_key, private_key) = transfer_keypair();
        let store = StubTransferStore::default();
        store
            .dotenv_existing
            .borrow_mut()
            .insert(public_key.clone(), "different".to_string());

        let plan = plan_transfer_import(
            &bundle(vec![dotenv_item(public_key, private_key)]),
            true,
            &store,
        )
        .unwrap();

        assert_eq!(plan.actions.len(), 1);
        assert!(plan.approval_request.items[0].replacing_existing);
        assert!(plan.approval_request.replace);
    }

    #[test]
    fn transfer_validates_bundle_schema_duplicates_and_fingerprints() {
        let (public_key, private_key) = transfer_keypair();
        assert_eq!(
            validate_transfer_bundle(&bundle(Vec::new())).unwrap_err(),
            "transfer bundle contains no keys"
        );

        let mut wrong_schema = bundle(vec![dotenv_item(public_key.clone(), private_key.clone())]);
        wrong_schema.schema_version = 999;
        assert!(
            validate_transfer_bundle(&wrong_schema)
                .unwrap_err()
                .contains("unsupported")
        );

        let mut bad_fingerprint =
            bundle(vec![dotenv_item(public_key.clone(), private_key.clone())]);
        if let TransferBundleItem::DotenvPrivateKey {
            public_key_fingerprint,
            ..
        } = &mut bad_fingerprint.items[0]
        {
            *public_key_fingerprint = "0".repeat(64);
        }
        assert!(
            validate_transfer_bundle(&bad_fingerprint)
                .unwrap_err()
                .contains("fingerprint mismatch")
        );

        assert!(
            validate_transfer_bundle(&bundle(vec![
                TransferBundleItem::IsotopeSecret {
                    key: "TOKEN".to_string(),
                    value: "one".to_string(),
                },
                TransferBundleItem::IsotopeSecret {
                    key: "TOKEN".to_string(),
                    value: "two".to_string(),
                },
            ]))
            .unwrap_err()
            .contains("duplicate isotope key")
        );
        assert!(
            validate_transfer_bundle(&bundle(vec![
                dotenv_item(public_key.clone(), private_key.clone()),
                dotenv_item(public_key, private_key),
            ]))
            .unwrap_err()
            .contains("duplicate dotenv private key")
        );
    }

    #[test]
    fn transfer_builds_daemon_import_request_with_secret_payload() {
        let (public_key, private_key) = transfer_keypair();
        let request = build_key_transfer_import_request(
            &bundle(vec![
                dotenv_item(public_key.clone(), private_key.clone()),
                TransferBundleItem::IsotopeSecret {
                    key: "TOKEN".to_string(),
                    value: "secret".to_string(),
                },
            ]),
            true,
        )
        .unwrap();

        assert_eq!(request.source, test_source());
        assert!(request.replace);
        assert_eq!(request.items.len(), 2);
        assert!(matches!(
            &request.items[0],
            KeyTransferImportItem::DotenvPrivateKey {
                public_key: imported_public_key,
                private_key: imported_private_key,
                ..
            } if imported_public_key == &public_key && imported_private_key == &private_key
        ));
        assert_eq!(
            request.items[1],
            KeyTransferImportItem::IsotopeSecret {
                key: "TOKEN".to_string(),
                value: "secret".to_string(),
            }
        );
    }
}
