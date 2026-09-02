use std::path::PathBuf;

const APPROVAL_SERVICE: &str = "com.automicvault.av2.approval";
const ALIYUN_HELPER_PROTOCOL_VERSION: u64 = 1;
const REGISTRY_HELPER_PROTOCOL_VERSION: u64 = 3;
const OXIDE_HELPER_PROTOCOL_VERSION: u64 = 1;
const FASTLY_HELPER_PROTOCOL_VERSION: u64 = 1;
const GOAT_HELPER_PROTOCOL_VERSION: u64 = 1;
const KUBECTL_HELPER_PROTOCOL_VERSION: u64 = 1;
const ORDERCLI_HELPER_PROTOCOL_VERSION: u64 = 1;
const OPENHUE_HELPER_PROTOCOL_VERSION: u64 = 1;
const PLUMBER_HELPER_PROTOCOL_VERSION: u64 = 1;
const RAILWAY_HELPER_PROTOCOL_VERSION: u64 = 1;
const RCLONE_HELPER_PROTOCOL_VERSION: u64 = 1;
const TERRAFORM_HELPER_PROTOCOL_VERSION: u64 = 1;
const UAA_HELPER_PROTOCOL_VERSION: u64 = 1;
const WAKATIME_HELPER_PROTOCOL_VERSION: u64 = 1;

struct XpcReply {
    value: Option<String>,
    names: Vec<String>,
}

pub(crate) fn ensure_aliyun_helper_ready() -> Result<(), String> {
    if crate::test_keychain_dir().is_some() {
        return Ok(());
    }
    let reply = xpc_request(
        "aliyun-helper-version",
        None,
        None,
        None,
        Some((b"requested_version\0", ALIYUN_HELPER_PROTOCOL_VERSION)),
    )
    .map_err(|error| {
        format!(
            "Alibaba Cloud credential-helper protocol negotiation failed; update and open the Automic Vault app: {error}"
        )
    })?;
    match reply.value.as_deref() {
        Some("1") => Ok(()),
        Some(version) => Err(format!(
            "the running Automic Vault app reported unsupported Alibaba Cloud helper version {version}"
        )),
        None => {
            Err("the running Automic Vault app returned no Alibaba Cloud helper version".into())
        }
    }
}

pub(crate) fn store_secret(account: &str, value: &str) -> Result<(), String> {
    if let Some(dir) = crate::test_keychain_dir() {
        std::fs::create_dir_all(&dir)
            .map_err(|err| format!("failed to create test keychain dir: {err}"))?;
        let path = dir.join(account);
        return std::fs::write(&path, value)
            .map_err(|err| format!("failed to write {}: {err}", path.display()));
    }
    xpc_request(
        "save",
        Some((b"key\0", account)),
        Some((b"value\0", value)),
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn store_project_secret(
    account: &str,
    value: &str,
    project_directory: &str,
) -> Result<(), String> {
    if let Some(dir) = crate::test_keychain_dir() {
        let path = test_project_secret_path(&dir, project_directory, account);
        std::fs::create_dir_all(path.parent().unwrap())
            .map_err(|err| format!("failed to create test project keychain dir: {err}"))?;
        return std::fs::write(&path, value)
            .map_err(|err| format!("failed to write {}: {err}", path.display()));
    }
    xpc_request_with_project_directory(
        "save",
        Some((b"key\0", account)),
        Some((b"value\0", value)),
        None,
        None,
        Some(project_directory),
    )
    .map(|_| ())
}

pub(crate) fn test_project_secret_path(
    keychain_directory: &std::path::Path,
    project_directory: &str,
    account: &str,
) -> PathBuf {
    keychain_directory
        .join(".project-values")
        .join(hex(project_directory.as_bytes()))
        .join(account)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn store_secret_if_absent_or_equal(account: &str, value: &str) -> Result<(), String> {
    if let Some(dir) = crate::test_keychain_dir() {
        std::fs::create_dir_all(&dir)
            .map_err(|err| format!("failed to create test keychain dir: {err}"))?;
        let path = dir.join(account);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                use std::io::Write;
                file.write_all(value.as_bytes())
                    .map_err(|err| format!("failed to write {}: {err}", path.display()))
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = std::fs::read_to_string(&path)
                    .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
                (existing == value)
                    .then_some(())
                    .ok_or_else(|| format!("refusing to replace existing secret {account}"))
            }
            Err(err) => Err(format!("failed to create {}: {err}", path.display())),
        }
    } else {
        xpc_request(
            "save-if-absent",
            Some((b"key\0", account)),
            Some((b"value\0", value)),
            None,
            None,
        )
        .map(|_| ())
    }
}

pub(crate) fn bless_script(path: &str, endorse_launcher: bool) -> Result<bool, String> {
    xpc_request(
        "bless",
        Some((b"path\0", path)),
        None,
        // Compatibility wire key. The domain term is Launcher Endorsement.
        endorse_launcher.then_some(&b"endorse_caller\0"[..]),
        None,
    )
    .map(|reply| reply.value.as_deref() == Some("already blessed"))
}

pub(crate) fn list_secret_names() -> Result<Vec<String>, String> {
    list_secret_names_filtered(false)
}

pub(crate) fn list_global_secret_names() -> Result<Vec<String>, String> {
    list_secret_names_filtered(true)
}

fn list_secret_names_filtered(global_only: bool) -> Result<Vec<String>, String> {
    if let Some(dir) = crate::test_keychain_dir() {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(format!("failed to list test keychain: {err}")),
        };
        let mut names = entries
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_type().ok()?.is_file().then(|| entry.file_name()))
            .filter_map(|name| name.into_string().ok())
            .collect::<Vec<_>>();
        names.sort();
        return Ok(names);
    }
    Ok(xpc_request(
        "list",
        None,
        None,
        global_only.then_some(&b"global_only\0"[..]),
        None,
    )?
    .names)
}

pub(crate) fn ensure_registry_helper_ready() -> Result<(), String> {
    if crate::test_keychain_dir().is_some() {
        return Ok(());
    }
    // Stable compatibility wire name shared by Docker and Podman registry helpers.
    let reply = xpc_request(
        "docker-helper-version",
        None,
        None,
        None,
        Some((b"requested_version\0", REGISTRY_HELPER_PROTOCOL_VERSION)),
    )
    .map_err(|error| {
        format!(
            "Registry credential-helper protocol negotiation failed; update and open the Automic Vault app: {error}"
        )
    })?;
    match reply.value.as_deref() {
        Some(version) if version == REGISTRY_HELPER_PROTOCOL_VERSION.to_string() => Ok(()),
        Some(version) => Err(format!(
            "the running Automic Vault app reported unsupported registry helper version {version}"
        )),
        None => Err("the running Automic Vault app returned no registry helper version".into()),
    }
}

pub(crate) fn store_registry_credential(account: &str, value: &str) -> Result<(), String> {
    if let Some(dir) = crate::test_keychain_dir() {
        std::fs::create_dir_all(&dir)
            .map_err(|err| format!("failed to create test keychain dir: {err}"))?;
        let path = dir.join(account);
        return std::fs::write(&path, value)
            .map_err(|err| format!("failed to write {}: {err}", path.display()));
    }
    // Stable compatibility wire name shared by Docker and Podman.
    xpc_request(
        "docker-save",
        Some((b"key\0", account)),
        Some((b"value\0", value)),
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn delete_registry_credential(account: &str, server_url: &str) -> Result<(), String> {
    if let Some(dir) = crate::test_keychain_dir() {
        return match std::fs::remove_file(dir.join(account)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!("failed to delete test registry credential: {err}")),
        };
    }
    // Stable compatibility wire names and field shared by Docker and Podman.
    xpc_request(
        "docker-delete",
        Some((b"key\0", account)),
        Some((b"docker_server_url\0", server_url)),
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn ensure_terraform_helper_ready() -> Result<(), String> {
    if crate::test_keychain_dir().is_some() {
        return Ok(());
    }
    let reply = xpc_request(
        "terraform-helper-version",
        None,
        None,
        None,
        Some((b"requested_version\0", TERRAFORM_HELPER_PROTOCOL_VERSION)),
    )
    .map_err(|error| {
        format!(
            "Terraform credential-helper protocol negotiation failed; update and open the Automic Vault app: {error}"
        )
    })?;
    match reply.value.as_deref() {
        Some("1") => Ok(()),
        Some(version) => Err(format!(
            "the running Automic Vault app reported unsupported Terraform helper version {version}"
        )),
        None => Err("the running Automic Vault app returned no Terraform helper version".into()),
    }
}

pub(crate) fn ensure_wakatime_helper_ready() -> Result<(), String> {
    if crate::test_keychain_dir().is_some() {
        return Ok(());
    }
    let reply = xpc_request(
        "wakatime-helper-version",
        None,
        None,
        None,
        Some((b"requested_version\0", WAKATIME_HELPER_PROTOCOL_VERSION)),
    )
    .map_err(|error| {
        format!(
            "WakaTime credential-helper protocol negotiation failed; update and open the Automic Vault app: {error}"
        )
    })?;
    match reply.value.as_deref() {
        Some("1") => Ok(()),
        Some(version) => Err(format!(
            "the running Automic Vault app reported unsupported WakaTime helper version {version}"
        )),
        None => Err("the running Automic Vault app returned no WakaTime helper version".into()),
    }
}

pub(crate) fn ensure_rclone_helper_ready() -> Result<(), String> {
    if crate::test_keychain_dir().is_some() {
        return Ok(());
    }
    let reply = xpc_request(
        "rclone-helper-version",
        None,
        None,
        None,
        Some((b"requested_version\0", RCLONE_HELPER_PROTOCOL_VERSION)),
    )
    .map_err(|error| {
        format!(
            "rclone password-command protocol negotiation failed; update and open the Automic Vault app: {error}"
        )
    })?;
    match reply.value.as_deref() {
        Some("1") => Ok(()),
        Some(version) => Err(format!(
            "the running Automic Vault app reported unsupported rclone helper version {version}"
        )),
        None => Err("the running Automic Vault app returned no rclone helper version".into()),
    }
}

pub(crate) fn ensure_kubectl_helper_ready() -> Result<(), String> {
    if crate::test_keychain_dir().is_some() {
        return Ok(());
    }
    let reply = xpc_request(
        "kubectl-helper-version",
        None,
        None,
        None,
        Some((b"requested_version\0", KUBECTL_HELPER_PROTOCOL_VERSION)),
    )
    .map_err(|error| {
        format!(
            "kubectl credential-helper protocol negotiation failed; update and open the Automic Vault app: {error}"
        )
    })?;
    match reply.value.as_deref() {
        Some("1") => Ok(()),
        Some(version) => Err(format!(
            "the running Automic Vault app reported unsupported kubectl helper version {version}"
        )),
        None => Err("the running Automic Vault app returned no kubectl helper version".into()),
    }
}

pub(crate) fn store_terraform_credential(hostname: &str, value: &str) -> Result<(), String> {
    if crate::test_keychain_dir().is_some() {
        return store_secret(
            &crate::cli::terraform_credential::secret_name(hostname),
            value,
        );
    }
    xpc_request(
        "terraform-save",
        Some((b"terraform_hostname\0", hostname)),
        Some((b"value\0", value)),
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn delete_terraform_credential(hostname: &str) -> Result<(), String> {
    let account = crate::cli::terraform_credential::secret_name(hostname);
    if let Some(dir) = crate::test_keychain_dir() {
        return match std::fs::remove_file(dir.join(&account)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!("failed to delete test Terraform credential: {err}")),
        };
    }
    xpc_request(
        "terraform-delete",
        Some((b"terraform_hostname\0", hostname)),
        None,
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn ensure_oxide_helper_ready() -> Result<(), String> {
    if crate::test_keychain_dir().is_some() {
        return Ok(());
    }
    let reply = xpc_request(
        "oxide-helper-version",
        None,
        None,
        None,
        Some((b"requested_version\0", OXIDE_HELPER_PROTOCOL_VERSION)),
    )
    .map_err(|error| {
        format!(
            "Oxide credential-helper protocol negotiation failed; update and open the Automic Vault app: {error}"
        )
    })?;
    match reply.value.as_deref() {
        Some("1") => Ok(()),
        Some(version) => Err(format!(
            "the running Automic Vault app reported unsupported Oxide helper version {version}"
        )),
        None => Err("the running Automic Vault app returned no Oxide helper version".into()),
    }
}

pub(crate) fn ensure_fastly_helper_ready() -> Result<(), String> {
    if crate::test_keychain_dir().is_some() {
        return Ok(());
    }
    let reply = xpc_request(
        "fastly-helper-version",
        None,
        None,
        None,
        Some((b"requested_version\0", FASTLY_HELPER_PROTOCOL_VERSION)),
    )
    .map_err(|error| {
        format!(
            "Fastly credential-helper protocol negotiation failed; update and open the Automic Vault app: {error}"
        )
    })?;
    match reply.value.as_deref() {
        Some("1") => Ok(()),
        Some(version) => Err(format!(
            "the running Automic Vault app reported unsupported Fastly helper version {version}"
        )),
        None => Err("the running Automic Vault app returned no Fastly helper version".into()),
    }
}

pub(crate) fn store_fastly_credential(scope: &str, value: &str) -> Result<(), String> {
    let (name, endpoint) = crate::cli::fastly_credential::parse_scope(scope)?;
    let account = crate::cli::fastly_credential::secret_name(&name, &endpoint);
    if crate::test_keychain_dir().is_some() {
        return store_secret(&account, value);
    }
    xpc_request(
        "fastly-save",
        Some((b"fastly_scope\0", scope)),
        Some((b"value\0", value)),
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn delete_fastly_credential(scope: &str, account: &str) -> Result<(), String> {
    if let Some(dir) = crate::test_keychain_dir() {
        return match std::fs::remove_file(dir.join(account)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("failed to delete test Fastly credential: {error}")),
        };
    }
    xpc_request(
        "fastly-delete",
        Some((b"fastly_scope\0", scope)),
        None,
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn store_oxide_credential(scope: &str, value: &str) -> Result<(), String> {
    let (profile, host) = crate::cli::oxide_credential::parse_scope(scope)?;
    let account = crate::cli::oxide_credential::secret_name(&profile, &host);
    if crate::test_keychain_dir().is_some() {
        return store_secret(&account, value);
    }
    xpc_request(
        "oxide-save",
        Some((b"oxide_scope\0", scope)),
        Some((b"value\0", value)),
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn delete_oxide_credential(scope: &str, account: &str) -> Result<(), String> {
    if let Some(dir) = crate::test_keychain_dir() {
        return match std::fs::remove_file(dir.join(account)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("failed to delete test Oxide credential: {error}")),
        };
    }
    xpc_request(
        "oxide-delete",
        Some((b"oxide_scope\0", scope)),
        None,
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn ensure_goat_helper_ready() -> Result<(), String> {
    if crate::test_keychain_dir().is_some() {
        return Ok(());
    }
    let reply = xpc_request(
        "goat-helper-version",
        None,
        None,
        None,
        Some((b"requested_version\0", GOAT_HELPER_PROTOCOL_VERSION)),
    )
    .map_err(|error| {
        format!(
            "goat credential-helper protocol negotiation failed; update and open the Automic Vault app: {error}"
        )
    })?;
    match reply.value.as_deref() {
        Some("1") => Ok(()),
        Some(version) => Err(format!(
            "the running Automic Vault app reported unsupported goat helper version {version}"
        )),
        None => Err("the running Automic Vault app returned no goat helper version".into()),
    }
}

pub(crate) fn store_goat_credential(scope: &str, value: &str) -> Result<(), String> {
    let (did, pds) = crate::cli::goat_credential::parse_scope(scope)?;
    let account = crate::cli::goat_credential::secret_name(&did, &pds);
    if crate::test_keychain_dir().is_some() {
        return store_secret(&account, value);
    }
    xpc_request(
        "goat-save",
        Some((b"goat_scope\0", scope)),
        Some((b"value\0", value)),
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn delete_goat_credential(scope: &str, account: &str) -> Result<(), String> {
    if let Some(dir) = crate::test_keychain_dir() {
        return match std::fs::remove_file(dir.join(account)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("failed to delete test goat credential: {error}")),
        };
    }
    xpc_request(
        "goat-delete",
        Some((b"goat_scope\0", scope)),
        None,
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn ensure_railway_helper_ready() -> Result<(), String> {
    if crate::test_keychain_dir().is_some() {
        return Ok(());
    }
    let reply = xpc_request(
        "railway-helper-version",
        None,
        None,
        None,
        Some((b"requested_version\0", RAILWAY_HELPER_PROTOCOL_VERSION)),
    )?;
    match reply.value.as_deref() {
        Some("1") => Ok(()),
        Some(version) => Err(format!(
            "the running Automic Vault app reported unsupported Railway helper version {version}"
        )),
        None => Err("the running Automic Vault app returned no Railway helper version".into()),
    }
}

pub(crate) fn ensure_ordercli_helper_ready() -> Result<(), String> {
    if crate::test_keychain_dir().is_some() {
        return Ok(());
    }
    let reply = xpc_request(
        "ordercli-helper-version",
        None,
        None,
        None,
        Some((b"requested_version\0", ORDERCLI_HELPER_PROTOCOL_VERSION)),
    )?;
    match reply.value.as_deref() {
        Some("1") => Ok(()),
        Some(version) => Err(format!(
            "the running Automic Vault app reported unsupported ordercli helper version {version}"
        )),
        None => Err("the running Automic Vault app returned no ordercli helper version".into()),
    }
}

pub(crate) fn store_ordercli_credential(scope: &str, value: &str) -> Result<(), String> {
    crate::cli::ordercli_credential::parse_scope(scope)?;
    if crate::test_keychain_dir().is_some() {
        return store_secret(crate::cli::ordercli_credential::SECRET_NAME, value);
    }
    xpc_request(
        "ordercli-save",
        Some((b"ordercli_scope\0", scope)),
        Some((b"value\0", value)),
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn delete_ordercli_credential(scope: &str, account: &str) -> Result<(), String> {
    crate::cli::ordercli_credential::parse_scope(scope)?;
    if account != crate::cli::ordercli_credential::SECRET_NAME {
        return Err("invalid ordercli Secret Name".into());
    }
    if let Some(dir) = crate::test_keychain_dir() {
        return match std::fs::remove_file(dir.join(account)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "failed to delete test ordercli credential: {error}"
            )),
        };
    }
    xpc_request(
        "ordercli-delete",
        Some((b"ordercli_scope\0", scope)),
        None,
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn ensure_uaa_helper_ready() -> Result<(), String> {
    if crate::test_keychain_dir().is_some() {
        return Ok(());
    }
    let reply = xpc_request(
        "uaa-helper-version",
        None,
        None,
        None,
        Some((b"requested_version\0", UAA_HELPER_PROTOCOL_VERSION)),
    )?;
    match reply.value.as_deref() {
        Some("1") => Ok(()),
        Some(version) => Err(format!(
            "the running Automic Vault app reported unsupported UAA helper version {version}"
        )),
        None => Err("the running Automic Vault app returned no UAA helper version".into()),
    }
}

pub(crate) fn store_uaa_credential(scope: &str, value: &str) -> Result<(), String> {
    crate::cli::uaa_credential::parse_scope(scope)?;
    if crate::test_keychain_dir().is_some() {
        return store_secret(crate::cli::uaa_credential::SECRET_NAME, value);
    }
    xpc_request(
        "uaa-save",
        Some((b"uaa_scope\0", scope)),
        Some((b"value\0", value)),
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn delete_uaa_credential(scope: &str, account: &str) -> Result<(), String> {
    crate::cli::uaa_credential::parse_scope(scope)?;
    if account != crate::cli::uaa_credential::SECRET_NAME {
        return Err("invalid UAA Secret Name".into());
    }
    if let Some(dir) = crate::test_keychain_dir() {
        return match std::fs::remove_file(dir.join(account)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("failed to delete test UAA credential: {error}")),
        };
    }
    xpc_request(
        "uaa-delete",
        Some((b"uaa_scope\0", scope)),
        None,
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn ensure_openhue_helper_ready() -> Result<(), String> {
    if crate::test_keychain_dir().is_some() {
        return Ok(());
    }
    let reply = xpc_request(
        "openhue-helper-version",
        None,
        None,
        None,
        Some((b"requested_version\0", OPENHUE_HELPER_PROTOCOL_VERSION)),
    )?;
    match reply.value.as_deref() {
        Some("1") => Ok(()),
        Some(version) => Err(format!(
            "the running Automic Vault app reported unsupported OpenHue helper version {version}"
        )),
        None => Err("the running Automic Vault app returned no OpenHue helper version".into()),
    }
}

pub(crate) fn store_openhue_credential(scope: &str, value: &str) -> Result<(), String> {
    crate::cli::openhue_credential::parse_scope(scope)?;
    crate::cli::openhue_credential::validate_key(value)?;
    if crate::test_keychain_dir().is_some() {
        return store_secret(crate::cli::openhue_credential::SECRET_NAME, value);
    }
    xpc_request(
        "openhue-save",
        Some((b"openhue_scope\0", scope)),
        Some((b"value\0", value)),
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn ensure_plumber_helper_ready() -> Result<(), String> {
    if crate::test_keychain_dir().is_some() {
        return Ok(());
    }
    let reply = xpc_request(
        "plumber-helper-version",
        None,
        None,
        None,
        Some((b"requested_version\0", PLUMBER_HELPER_PROTOCOL_VERSION)),
    )?;
    match reply.value.as_deref() {
        Some("1") => Ok(()),
        Some(version) => Err(format!(
            "the running Automic Vault app reported unsupported Plumber helper version {version}"
        )),
        None => Err("the running Automic Vault app returned no Plumber helper version".into()),
    }
}

pub(crate) fn store_plumber_credential(scope: &str, value: &str) -> Result<(), String> {
    crate::cli::plumber_credential::parse_scope(scope)?;
    crate::cli::plumber_credential::parse_config(value)?;
    if crate::test_keychain_dir().is_some() {
        return store_secret(crate::cli::plumber_credential::SECRET_NAME, value);
    }
    xpc_request("plumber-save", None, Some((b"value\0", value)), None, None).map(|_| ())
}

pub(crate) fn store_railway_credential(scope: &str, value: &str) -> Result<(), String> {
    let (environment, host) = crate::cli::railway_credential::parse_scope(scope)?;
    let account = crate::cli::railway_credential::secret_name(&environment, &host);
    if crate::test_keychain_dir().is_some() {
        return store_secret(&account, value);
    }
    xpc_request(
        "railway-save",
        Some((b"railway_scope\0", scope)),
        Some((b"value\0", value)),
        None,
        None,
    )
    .map(|_| ())
}

pub(crate) fn delete_railway_credential(scope: &str, account: &str) -> Result<(), String> {
    if let Some(dir) = crate::test_keychain_dir() {
        return match std::fs::remove_file(dir.join(account)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("failed to delete test Railway credential: {error}")),
        };
    }
    xpc_request(
        "railway-delete",
        Some((b"railway_scope\0", scope)),
        None,
        None,
        None,
    )
    .map(|_| ())
}

#[cfg(target_os = "macos")]
fn xpc_request(
    operation: &str,
    field: Option<(&'static [u8], &str)>,
    extra: Option<(&'static [u8], &str)>,
    bool_field: Option<&'static [u8]>,
    uint_field: Option<(&'static [u8], u64)>,
) -> Result<XpcReply, String> {
    xpc_request_with_project_directory(operation, field, extra, bool_field, uint_field, None)
}

#[cfg(target_os = "macos")]
fn xpc_request_with_project_directory(
    operation: &str,
    field: Option<(&'static [u8], &str)>,
    extra: Option<(&'static [u8], &str)>,
    bool_field: Option<&'static [u8]>,
    uint_field: Option<(&'static [u8], u64)>,
    project_directory: Option<&str>,
) -> Result<XpcReply, String> {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int, c_void};

    type XpcObject = *mut c_void;

    unsafe extern "C" {
        static _xpc_type_error: u8;
        static _xpc_type_array: u8;
        static _xpc_error_key_description: *const c_char;

        fn xpc_connection_create_mach_service(
            name: *const c_char,
            targetq: *mut c_void,
            flags: u64,
        ) -> XpcObject;
        fn xpc_connection_activate(connection: XpcObject);
        fn xpc_connection_cancel(connection: XpcObject);
        fn xpc_connection_send_message_with_reply_sync(
            connection: XpcObject,
            message: XpcObject,
        ) -> XpcObject;
        fn xpc_dictionary_create_empty() -> XpcObject;
        fn xpc_dictionary_set_bool(xdict: XpcObject, key: *const c_char, value: bool);
        fn xpc_dictionary_set_uint64(xdict: XpcObject, key: *const c_char, value: u64);
        fn xpc_dictionary_get_bool(xdict: XpcObject, key: *const c_char) -> bool;
        fn xpc_dictionary_set_string(xdict: XpcObject, key: *const c_char, value: *const c_char);
        fn xpc_dictionary_get_string(xdict: XpcObject, key: *const c_char) -> *const c_char;
        fn xpc_dictionary_get_value(xdict: XpcObject, key: *const c_char) -> XpcObject;
        fn xpc_array_get_count(array: XpcObject) -> usize;
        fn xpc_array_get_string(array: XpcObject, index: usize) -> *const c_char;
        fn xpc_get_type(object: XpcObject) -> *const c_void;
        fn xpc_release(object: XpcObject);
        fn xpc_connection_set_peer_code_signing_requirement(
            connection: XpcObject,
            requirement: *const c_char,
        ) -> c_int;
        fn av_xpc_connection_set_empty_event_handler(connection: XpcObject);
    }

    unsafe fn set_string(dict: XpcObject, key: &[u8], value: &str) -> Result<(), String> {
        let value =
            CString::new(value).map_err(|_| format!("XPC field contains NUL: {value:?}"))?;
        unsafe { xpc_dictionary_set_string(dict, key.as_ptr().cast(), value.as_ptr()) };
        Ok(())
    }

    let cwd = xpc_operation_requires_cwd(operation)
        .then(crate::path_security::current_working_directory_utf8)
        .transpose()?;
    let service = CString::new(APPROVAL_SERVICE).unwrap();
    let connection =
        unsafe { xpc_connection_create_mach_service(service.as_ptr(), std::ptr::null_mut(), 0) };
    if connection.is_null() {
        return Err("failed to create approval XPC connection".into());
    }

    let menu_requirement = CString::new(crate::MENU_HELPER_CODE_SIGNING_REQUIREMENT).unwrap();
    let requirement_status = unsafe {
        xpc_connection_set_peer_code_signing_requirement(connection, menu_requirement.as_ptr())
    };
    if requirement_status != 0 {
        unsafe { xpc_release(connection) };
        return Err("failed to configure approval XPC signing requirement".into());
    }

    unsafe {
        av_xpc_connection_set_empty_event_handler(connection);
        xpc_connection_activate(connection);
    }

    let message = unsafe { xpc_dictionary_create_empty() };
    if message.is_null() {
        unsafe { xpc_connection_cancel(connection) };
        unsafe { xpc_release(connection) };
        return Err("failed to create approval XPC message".into());
    }

    unsafe {
        set_string(message, b"op\0", operation)?;
        if let Some(cwd) = cwd.as_deref() {
            set_string(message, b"cwd\0", cwd)?;
        }
        if let Some((field, value)) = field {
            set_string(message, field, value)?;
        }
        if let Some((extra_field, value)) = extra {
            set_string(message, extra_field, value)?;
        }
        if let Some(bool_field) = bool_field {
            xpc_dictionary_set_bool(message, bool_field.as_ptr().cast(), true);
        }
        if let Some((uint_field, value)) = uint_field {
            xpc_dictionary_set_uint64(message, uint_field.as_ptr().cast(), value);
        }
        if let Some(project_directory) = project_directory {
            set_string(message, b"project_directory\0", project_directory)?;
        }
        xpc_dictionary_set_bool(message, b"interactive\0".as_ptr().cast(), true);
    }

    let reply = unsafe { xpc_connection_send_message_with_reply_sync(connection, message) };
    unsafe {
        xpc_release(message);
        xpc_connection_cancel(connection);
        xpc_release(connection);
    }
    if reply.is_null() {
        return Err("Automic Vault approval did not reply".into());
    }

    let reply_is_error =
        unsafe { xpc_get_type(reply) == std::ptr::addr_of!(_xpc_type_error).cast() };
    if !reply_is_error {
        let human_approval_decision = unsafe {
            xpc_dictionary_get_string(reply, b"human_approval_decision\0".as_ptr().cast())
        };
        if !human_approval_decision.is_null() {
            if let Some(decision) = unsafe {
                human_approval_message(std::ffi::CStr::from_ptr(human_approval_decision).to_bytes())
            } {
                eprintln!("automic vault: {decision}");
            }
        }
    }

    let result = unsafe {
        if reply_is_error {
            if crate::approval_service_connection_invalid(reply) {
                Err(crate::approval_service_unavailable_message(&service).into())
            } else {
                let error = xpc_dictionary_get_string(reply, _xpc_error_key_description);
                let error = if error.is_null() {
                    "approval XPC connection failed".into()
                } else {
                    std::ffi::CStr::from_ptr(error)
                        .to_string_lossy()
                        .into_owned()
                };
                Err(error)
            }
        } else if xpc_dictionary_get_bool(reply, b"ok\0".as_ptr().cast()) {
            let value = xpc_dictionary_get_string(reply, b"value\0".as_ptr().cast());
            let value = (!value.is_null()).then(|| {
                std::ffi::CStr::from_ptr(value)
                    .to_string_lossy()
                    .into_owned()
            });
            let names = xpc_dictionary_get_value(reply, b"names\0".as_ptr().cast());
            let names = if names.is_null()
                || xpc_get_type(names) != std::ptr::addr_of!(_xpc_type_array).cast()
            {
                Vec::new()
            } else {
                (0..xpc_array_get_count(names))
                    .filter_map(|index| {
                        let name = xpc_array_get_string(names, index);
                        (!name.is_null()).then(|| {
                            std::ffi::CStr::from_ptr(name)
                                .to_string_lossy()
                                .into_owned()
                        })
                    })
                    .collect()
            };
            Ok(XpcReply { value, names })
        } else {
            let error = xpc_dictionary_get_string(reply, b"error\0".as_ptr().cast());
            Err(if error.is_null() {
                format!("secret {operation} failed")
            } else {
                std::ffi::CStr::from_ptr(error)
                    .to_string_lossy()
                    .into_owned()
            })
        }
    };
    unsafe { xpc_release(reply) };
    result
}

fn human_approval_message(decision: &[u8]) -> Option<&'static str> {
    match decision {
        b"approved" => Some("approved"),
        b"denied" => Some("denied"),
        _ => None,
    }
}

fn xpc_operation_requires_cwd(operation: &str) -> bool {
    matches!(
        operation,
        "save"
            | "save-if-absent"
            | "docker-save"
            | "docker-delete"
            | "goat-save"
            | "goat-delete"
            | "oxide-save"
            | "oxide-delete"
            | "fastly-save"
            | "fastly-delete"
            | "ordercli-save"
            | "ordercli-delete"
            | "openhue-save"
            | "plumber-save"
            | "railway-save"
            | "railway-delete"
            | "terraform-save"
            | "terraform-delete"
            | "uaa-save"
            | "uaa-delete"
    )
}

#[cfg(not(target_os = "macos"))]
fn xpc_request(
    _operation: &str,
    _field: Option<(&'static [u8], &str)>,
    _extra: Option<(&'static [u8], &str)>,
    _bool_field: Option<&'static [u8]>,
    _uint_field: Option<(&'static [u8], u64)>,
) -> Result<XpcReply, String> {
    Err("the Automic Vault menu bar approval service is only available on macOS".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_only_known_human_approval_decisions() {
        assert_eq!(human_approval_message(b"approved"), Some("approved"));
        assert_eq!(human_approval_message(b"denied"), Some("denied"));
        assert_eq!(human_approval_message(b"unexpected"), None);
    }

    #[test]
    fn only_mutations_require_a_working_directory() {
        assert!(xpc_operation_requires_cwd("save"));
        assert!(xpc_operation_requires_cwd("docker-delete"));
        assert!(xpc_operation_requires_cwd("goat-save"));
        assert!(xpc_operation_requires_cwd("oxide-save"));
        assert!(xpc_operation_requires_cwd("fastly-save"));
        assert!(xpc_operation_requires_cwd("ordercli-save"));
        assert!(xpc_operation_requires_cwd("openhue-save"));
        assert!(xpc_operation_requires_cwd("plumber-save"));
        assert!(xpc_operation_requires_cwd("railway-save"));
        assert!(xpc_operation_requires_cwd("terraform-save"));
        assert!(xpc_operation_requires_cwd("uaa-save"));
        assert!(!xpc_operation_requires_cwd("bless"));
        assert!(!xpc_operation_requires_cwd("docker-helper-version"));
        assert!(!xpc_operation_requires_cwd("list"));
    }
}
