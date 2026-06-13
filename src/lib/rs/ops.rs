use super::*;
use std::collections::BTreeMap;

const MAX_HELPER_PACKAGES: usize = 50;
const HELPER_AV_INSTALL_TARGET: &str = "/usr/local/bin/av";
const HELPER_CLI_INSTALL_TARGETS: [(&str, &str); 1] = [("av", "/usr/local/bin/av")];
const ISOTOPE_ALWAYS_ALLOW_PATH: &str =
    "/Library/Application Support/Automic Vault/isotope/always-allow.json";
const DEFAULT_SEARCH_PAGE_SIZE: usize = 100;
const MAX_SEARCH_PAGE_SIZE: usize = 200;

#[cfg(test)]
static TEST_ASSUME_HELPER_ROOT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HelperCommand {
    Install {
        packages: Vec<PackageSpec>,
    },
    Update {
        packages: Vec<PackageSpec>,
    },
    Uninstall {
        packages: Vec<PackageSpec>,
    },
    MakeDefault {
        packages: Vec<PackageSpec>,
    },
    UpdateAll,
    InstallAv {
        source_path: String,
        caller_path: String,
    },
    InstallIsotopeRoot {
        isotope_name: String,
    },
    ConvertRadioisotope {
        isotope_name: String,
    },
    InstallIsotopeStubs {
        isotope_name: String,
    },
    RememberIsotopeAlwaysAllow {
        executable_path: String,
        script_path: Option<String>,
        script_sha256: Option<String>,
        keys: Vec<String>,
    },
    GetDotenvApprovalPolicy,
    SetDotenvApprovalPolicy {
        policy: dotenv::DotenvApprovalPolicy,
    },
    RememberDotenvApproval {
        mode: dotenv::DotenvApprovalMode,
        env_file_path: String,
        project_root: String,
        env_sha256: String,
        public_key_fingerprint: String,
        keys: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageSpec {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProgressEvent {
    Resolving,
    Downloading {
        package: String,
        bytes_per_sec: u64,
        progress: f32,
    },
    Installing {
        package: String,
    },
    Log {
        package: String,
        message: String,
    },
    Completed {
        package: String,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HelperCommandSuccess {
    pub message: String,
    pub processed_packages: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

pub type HelperCommandResult = Result<HelperCommandSuccess, String>;

pub fn execute_helper_command<F>(
    command: HelperCommand,
    progress_callback: F,
) -> HelperCommandResult
where
    F: FnMut(ProgressEvent) + Send + 'static,
{
    let progress_callback = Arc::new(Mutex::new(
        Box::new(progress_callback) as Box<ProgressCallback>
    ));
    let result = match command {
        HelperCommand::Install { packages } => {
            install_packages(packages, progress_callback.clone())
        }
        HelperCommand::Update { packages } => update_packages(packages, progress_callback.clone()),
        HelperCommand::Uninstall { packages } => {
            uninstall_packages(packages, progress_callback.clone())
        }
        HelperCommand::MakeDefault { packages } => {
            make_default_packages(packages, progress_callback.clone())
        }
        HelperCommand::UpdateAll => update_all_packages(progress_callback.clone()),
        HelperCommand::InstallAv {
            source_path,
            caller_path,
        } => install_cli_tools(&source_path, &caller_path, progress_callback.clone()),
        HelperCommand::InstallIsotopeRoot { isotope_name } => {
            install_isotope_root_with_helper(&isotope_name, progress_callback.clone())
        }
        HelperCommand::ConvertRadioisotope { isotope_name } => {
            convert_radioisotope_with_helper(&isotope_name, progress_callback.clone())
        }
        HelperCommand::InstallIsotopeStubs { isotope_name } => {
            install_isotope_stubs_with_helper(&isotope_name, progress_callback.clone())
        }
        HelperCommand::RememberIsotopeAlwaysAllow {
            executable_path,
            script_path,
            script_sha256,
            keys,
        } => remember_isotope_always_allow(
            &executable_path,
            script_path.as_deref(),
            script_sha256.as_deref(),
            keys,
        ),
        HelperCommand::GetDotenvApprovalPolicy => get_dotenv_approval_policy(),
        HelperCommand::SetDotenvApprovalPolicy { policy } => set_dotenv_approval_policy(policy),
        HelperCommand::RememberDotenvApproval {
            mode,
            env_file_path,
            project_root,
            env_sha256,
            public_key_fingerprint,
            keys,
        } => remember_dotenv_approval_with_helper(
            mode,
            &env_file_path,
            &project_root,
            &env_sha256,
            &public_key_fingerprint,
            keys,
        ),
    };
    if let Err(err) = &result
        && let Ok(mut callback) = progress_callback.lock()
    {
        callback(ProgressEvent::Error {
            message: err.clone(),
        });
    }
    result
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct IsotopeAlwaysAllowEntry {
    executable_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    script_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    script_sha256: Option<String>,
    keys: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct IsotopeAlwaysAllowStore {
    entries: Vec<IsotopeAlwaysAllowEntry>,
}

pub fn check_for_updates() -> Result<bool, String> {
    let config = load_config()?;
    Ok(!resolve_outdated_package_statuses(&config, &PackageSelection::AllInstalled)?.is_empty())
}

pub(crate) fn list_installed_packages() -> Result<core::ListInstalledResponse, String> {
    let mut packages = state::list_installed_package_refs()?;
    packages.sort_by(|left, right| {
        compare_package_names_for_search_order(&left.package_name, &right.package_name)
    });
    packages.dedup_by(|left, right| left.package_name == right.package_name);

    let mut results = Vec::with_capacity(packages.len());
    for package in packages {
        let receipt =
            state::load_installed_package_receipt(&package.package_name, &package.install_root)?;
        let qualified_name = package_source_qualified_name(&receipt.source);
        let security_state =
            package_security_state_for_identifiers([receipt.package_name.clone(), qualified_name]);
        let catalog_metadata = catalog_metadata_for_source(&receipt.source);
        results.push(core::InstalledPackageSummary {
            name: receipt.package_name,
            source: receipt.source,
            version: receipt.version,
            description: catalog_metadata.summary.or(receipt.metadata.description),
            homepage: catalog_metadata.homepage.or(receipt.metadata.homepage),
            repository: catalog_metadata.repository,
            upstream_docs: catalog_metadata.upstream_docs,
            docs: catalog_metadata.docs,
            category: catalog_metadata.category,
            installed_versions: Vec::new(),
            install_package_names: Vec::new(),
            security_state,
        });
    }

    Ok(core::ListInstalledResponse { packages: results })
}

#[derive(Debug, Default)]
struct CatalogPackageMetadata {
    summary: Option<String>,
    homepage: Option<String>,
    repository: Option<String>,
    upstream_docs: Option<String>,
    docs: Vec<String>,
    category: Option<String>,
}

fn catalog_metadata_for_source(source: &PackageReceiptSource) -> CatalogPackageMetadata {
    match source {
        PackageReceiptSource::Formula { root_formula } => formula_catalog_metadata(root_formula),
        PackageReceiptSource::Cask { cask_name } => cask_catalog_metadata(cask_name),
        PackageReceiptSource::Isotope { isotope_name } => isotope_catalog_metadata(isotope_name),
        PackageReceiptSource::Npm { package_name } => npm_catalog_metadata(package_name),
        _ => CatalogPackageMetadata::default(),
    }
}

fn formula_catalog_metadata(root_formula: &str) -> CatalogPackageMetadata {
    let Ok(db) = crate::cli::load_db() else {
        return CatalogPackageMetadata::default();
    };
    if crate::cli::ensure_db_schema(&db).is_err() {
        return CatalogPackageMetadata::default();
    }
    let canonical =
        canonical_formula_name(root_formula).unwrap_or_else(|_| root_formula.to_string());
    let Some(metadata) = db.formulas.get(&canonical) else {
        return CatalogPackageMetadata::default();
    };
    CatalogPackageMetadata {
        summary: string_or_none(&metadata.summary),
        homepage: string_or_none(&metadata.homepage),
        repository: string_or_none(&metadata.repository),
        upstream_docs: string_or_none(&metadata.upstream_docs)
            .or_else(|| metadata.docs.iter().find_map(|doc| string_or_none(doc))),
        docs: metadata
            .docs
            .iter()
            .filter_map(|doc| string_or_none(doc))
            .collect(),
        category: string_or_none(&metadata.category),
    }
}

fn cask_catalog_metadata(cask_name: &str) -> CatalogPackageMetadata {
    let Ok(cask) = embedded_cask(cask_name) else {
        return CatalogPackageMetadata::default();
    };
    CatalogPackageMetadata {
        summary: string_or_none(&cask.summary),
        homepage: string_or_none(&cask.homepage),
        ..CatalogPackageMetadata::default()
    }
}

fn isotope_catalog_metadata(isotope_name: &str) -> CatalogPackageMetadata {
    let Ok(isotope) = isotope_package_data(isotope_name) else {
        return CatalogPackageMetadata::default();
    };
    if let Some(formula) = isotope_homebrew_formula_target(isotope) {
        let metadata = formula_catalog_metadata(&formula);
        if metadata.has_visible_fields() {
            return metadata;
        }
    }
    CatalogPackageMetadata {
        homepage: isotope.release_url.as_deref().and_then(string_or_none),
        ..CatalogPackageMetadata::default()
    }
}

fn npm_catalog_metadata(package_name: &str) -> CatalogPackageMetadata {
    let Ok(db) = crate::cli::load_db() else {
        return CatalogPackageMetadata::default();
    };
    if crate::cli::ensure_db_schema(&db).is_err() {
        return CatalogPackageMetadata::default();
    }
    let Some(metadata) = db.npms.get(package_name) else {
        return CatalogPackageMetadata::default();
    };
    CatalogPackageMetadata {
        summary: string_or_none(&metadata.summary),
        homepage: string_or_none(&metadata.homepage),
        ..CatalogPackageMetadata::default()
    }
}

impl CatalogPackageMetadata {
    fn has_visible_fields(&self) -> bool {
        self.summary.is_some()
            || self.homepage.is_some()
            || self.repository.is_some()
            || self.upstream_docs.is_some()
            || !self.docs.is_empty()
            || self.category.is_some()
    }
}

pub(crate) fn list_available_packages_matching_category(
    offset: usize,
    limit: usize,
    category: Option<&str>,
    sort: Option<&str>,
) -> Result<core::SearchPackagesResponse, String> {
    let mut packages = resolve_available_package_results(&Config {
        bottle_tag: String::new(),
    })?;
    let category_counts = package_category_counts(&packages);
    if let Some(category) = normalized_requested_category(category) {
        packages.retain(|package| package_category_identifier(package) == category);
    }
    sort_available_packages(&mut packages, normalized_package_sort(sort))?;
    Ok(search_packages_response_with_category_counts(
        packages,
        offset,
        limit,
        category_counts,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageListSort {
    Rank,
    Alphabetical,
}

fn normalized_package_sort(sort: Option<&str>) -> PackageListSort {
    match sort.map(str::trim).filter(|sort| !sort.is_empty()) {
        Some("az") | Some("a-z") | Some("alphabetical") => PackageListSort::Alphabetical,
        _ => PackageListSort::Rank,
    }
}

fn sort_available_packages(
    packages: &mut [PackageSearchResult],
    sort: PackageListSort,
) -> Result<(), String> {
    match sort {
        PackageListSort::Rank => packages.sort_by(compare_package_rank_order),
        PackageListSort::Alphabetical => packages.sort_by(|left, right| {
            compare_package_names_for_search_order(&left.package_name, &right.package_name)
        }),
    }
    Ok(())
}

fn compare_package_rank_order(
    left: &PackageSearchResult,
    right: &PackageSearchResult,
) -> std::cmp::Ordering {
    match (left.rank, right.rank) {
        (Some(left_rank), Some(right_rank)) => left_rank
            .cmp(&right_rank)
            .then_with(|| left.package_name.cmp(&right.package_name)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => left.package_name.cmp(&right.package_name),
    }
}

pub(crate) fn list_pulse_packages(
    offset: usize,
    limit: usize,
) -> Result<core::SearchPackagesResponse, String> {
    let packages = resolve_pulse_package_results(&Config {
        bottle_tag: String::new(),
    })?;
    Ok(search_packages_response(packages, offset, limit))
}

pub(crate) fn list_geiger_packages(
    offset: usize,
    limit: usize,
) -> Result<core::SearchPackagesResponse, String> {
    let packages = resolve_geiger_package_results(&Config {
        bottle_tag: String::new(),
    })?;
    Ok(search_packages_response(packages, offset, limit))
}

pub(crate) fn list_security_recommendation_packages(
    offset: usize,
    limit: usize,
) -> Result<core::SearchPackagesResponse, String> {
    let packages = resolve_security_recommendation_package_results(&Config {
        bottle_tag: String::new(),
    })?;
    Ok(search_packages_response(packages, offset, limit))
}

pub(crate) fn search_packages(
    query: &str,
    offset: usize,
    limit: usize,
) -> Result<core::SearchPackagesResponse, String> {
    let packages = resolve_package_search_results(
        &Config {
            bottle_tag: String::new(),
        },
        query,
    )?;
    Ok(search_packages_response(packages, offset, limit))
}

fn search_packages_response(
    packages: Vec<PackageSearchResult>,
    offset: usize,
    limit: usize,
) -> core::SearchPackagesResponse {
    let category_counts = package_category_counts(&packages);
    search_packages_response_with_category_counts(packages, offset, limit, category_counts)
}

fn search_packages_response_with_category_counts(
    packages: Vec<PackageSearchResult>,
    offset: usize,
    limit: usize,
    category_counts: BTreeMap<String, usize>,
) -> core::SearchPackagesResponse {
    let limit = search_page_size(limit);
    let total_count = packages.len();
    let packages = packages
        .into_iter()
        .map(search_package_summary)
        .collect::<Vec<_>>();
    let next_offset_value = offset.saturating_add(limit);
    let next_offset = packages.get(next_offset_value).map(|_| next_offset_value);
    let packages = packages.into_iter().skip(offset).take(limit).collect();
    core::SearchPackagesResponse {
        packages,
        total_count,
        next_offset,
        category_counts,
    }
}

fn normalized_requested_category(category: Option<&str>) -> Option<&str> {
    category
        .map(str::trim)
        .filter(|category| !category.is_empty())
}

fn package_category_identifier(package: &PackageSearchResult) -> &str {
    package
        .category
        .as_deref()
        .map(str::trim)
        .filter(|category| !category.is_empty())
        .unwrap_or("other")
}

fn package_category_counts(packages: &[PackageSearchResult]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for package in packages {
        *counts
            .entry(package_category_identifier(package).to_string())
            .or_insert(0) += 1;
    }
    counts
}

fn search_page_size(limit: usize) -> usize {
    match limit {
        0 => DEFAULT_SEARCH_PAGE_SIZE,
        _ => limit.min(MAX_SEARCH_PAGE_SIZE),
    }
}

fn search_package_summary(package: PackageSearchResult) -> core::SearchPackageSummary {
    let qualified_name = package_source_qualified_name(&package.source);
    let installs_hardened =
        search_package_installs_hardened(&package.source, &package.install_package_names);
    let security_state = package.security_state.or_else(|| {
        package_security_state_for_identifiers([package.package_name.clone(), qualified_name])
    });
    core::SearchPackageSummary {
        name: package.package_name,
        source: package.source,
        version: package.latest_version,
        description: package.summary,
        homepage: package.homepage,
        repository: package.repository,
        upstream_docs: package.upstream_docs,
        docs: package.docs,
        category: package.category,
        install_package_names: package.install_package_names,
        installs_hardened,
        rank: package.rank,
        last_updated_at: package.last_updated_at,
        pulse_kind: package.pulse_kind,
        security_state,
    }
}

fn search_package_installs_hardened(
    source: &PackageReceiptSource,
    install_package_names: &[String],
) -> bool {
    if !install_package_names.is_empty() {
        return install_package_names
            .iter()
            .any(|package_name| install_package_name_installs_hardened(package_name));
    }
    source_default_install_installs_hardened(source)
}

fn source_default_install_installs_hardened(source: &PackageReceiptSource) -> bool {
    match source {
        PackageReceiptSource::Formula { root_formula } => installable_isotope_name_for_target(
            &PackageAliasTarget::HomebrewFormula(root_formula.clone()),
        )
        .is_ok_and(|isotope_name| isotope_name.is_some()),
        PackageReceiptSource::Isotope { .. } => true,
        PackageReceiptSource::Vendor { vendor_name } => preferred_auto_isotope_name(vendor_name)
            .is_ok_and(|isotope_name| isotope_name.is_some()),
        PackageReceiptSource::Cask { .. }
        | PackageReceiptSource::Npm { .. }
        | PackageReceiptSource::Pip { .. } => false,
    }
}

fn install_package_name_installs_hardened(package_name: &str) -> bool {
    let Ok(requested) = cli::parse_package_name(&OsString::from(package_name)) else {
        return false;
    };
    match requested {
        RequestedPackage::Auto(package_name) => preferred_auto_isotope_name(&package_name)
            .is_ok_and(|isotope_name| isotope_name.is_some()),
        RequestedPackage::HomebrewFormula(formula) => {
            radioisotope_name_for_homebrew_formula_install(&formula)
                .is_ok_and(|isotope_name| isotope_name.is_some())
        }
        RequestedPackage::Isotope(_) => true,
        RequestedPackage::HomebrewCask(_)
        | RequestedPackage::VendorPackage(_)
        | RequestedPackage::NpmPackage { .. }
        | RequestedPackage::PipPackage(_) => false,
    }
}

pub(crate) fn package_info(package: &str) -> Result<PackageInfo, String> {
    let config = load_config()?;
    let requested = cli::parse_package_name(&OsString::from(package))?;
    resolve_package_info(&config, &requested)
}

pub(crate) fn list_outdated_packages() -> Result<core::ListOutdatedResponse, String> {
    let config = load_config()?;
    let packages = resolve_scanned_package_statuses(
        state::list_installed_package_refs()?,
        |package| resolve_package_status_at(&config, &package.package_name, &package.install_root),
        |_| {},
    )?
    .into_iter()
    .filter(PackageStatus::is_outdated)
    .map(|package| core::OutdatedPackageSummary {
        name: package.package_name,
        current_version: package.installed_version,
        latest_version: package.latest_version,
    })
    .collect();

    Ok(core::ListOutdatedResponse { packages })
}

pub(crate) fn system_info() -> core::SystemInfoResponse {
    core::SystemInfoResponse {
        version: env!("CARGO_PKG_VERSION"),
        protocol_version: core::PROTOCOL_VERSION,
        build_id: env!("NUKE_BUILD_ID"),
    }
}

pub(crate) fn isotope_migration_plan(
    isotope_name: &str,
) -> Result<core::IsotopeMigrationPlanResponse, String> {
    let isotope_name = normalized_isotope_name(isotope_name)?;
    let record = isotope_package_data(&isotope_name)?;
    Ok(core::IsotopeMigrationPlanResponse {
        isotope_name,
        replaces_package: isotope_replaced_package_name(record)?,
        modifies_package: isotope_modified_package_name(record)?,
        is_radioisotope: isotope_has_post_install(&record.name),
        has_migration: record.migrate.is_some() || isotope_has_migration(&record.name),
    })
}

pub(crate) fn migrate_isotope(
    isotope_name: &str,
) -> Result<core::IsotopeMigrationPlanResponse, String> {
    let isotope_name = normalized_isotope_name(isotope_name)?;
    let record = isotope_package_data(&isotope_name)?;
    let plan = InstallPlan::for_i_isotope(isotope_qualified_name(&isotope_name), &isotope_name);
    run_isotope_migration(&plan, record, None)?;
    isotope_migration_plan(&isotope_name)
}

fn normalized_isotope_name(value: &str) -> Result<String, String> {
    let name = value.strip_prefix(ISOTOPE_PACKAGE_PREFIX).unwrap_or(value);
    if name.is_empty() {
        return Err("missing isotope name".to_string());
    }
    if name.contains('/') {
        return Err(format!("invalid isotope name: {name}"));
    }
    Ok(name.to_string())
}

fn install_packages(
    packages: Vec<PackageSpec>,
    progress_callback: Arc<Mutex<Box<ProgressCallback>>>,
) -> HelperCommandResult {
    require_root()?;
    let requested = validate_install_specs(packages)?;
    let processed_packages = requested
        .iter()
        .map(requested_package_name)
        .collect::<Vec<_>>();

    let _lock = acquire_package_mutation_lock()?;
    let config = load_config()?;
    for package in requested {
        run_i_package_with_progress(
            &config,
            package,
            InstallOptions {
                intent: InstallIntent::Install,
            },
            Some(progress_callback.clone()),
        )?;
    }

    Ok(HelperCommandSuccess {
        message: "Install complete".to_string(),
        processed_packages,
        value: None,
    })
}

fn uninstall_packages(
    packages: Vec<PackageSpec>,
    progress_callback: Arc<Mutex<Box<ProgressCallback>>>,
) -> HelperCommandResult {
    require_root()?;
    let package_names = validate_uninstall_specs(packages)?;
    let _lock = acquire_package_mutation_lock()?;
    for package_name in &package_names {
        if let Ok(mut callback) = progress_callback.lock() {
            callback(ProgressEvent::Installing {
                package: package_name.clone(),
            });
        }
        ensure_package_installed(&opt_pkg_root(), package_name)?;
        uninstall_package(package_name)?;
        if let Ok(mut callback) = progress_callback.lock() {
            callback(ProgressEvent::Completed {
                package: package_name.clone(),
            });
        }
    }

    Ok(HelperCommandSuccess {
        message: "Uninstall complete".to_string(),
        processed_packages: package_names,
        value: None,
    })
}

fn update_packages(
    packages: Vec<PackageSpec>,
    progress_callback: Arc<Mutex<Box<ProgressCallback>>>,
) -> HelperCommandResult {
    require_root()?;
    let requested = validate_install_specs(packages)?;
    let processed_packages = requested
        .iter()
        .map(requested_package_name)
        .collect::<Vec<_>>();

    let _lock = acquire_package_mutation_lock()?;
    let config = load_config()?;
    for package in requested {
        run_i_package_with_progress(
            &config,
            package,
            InstallOptions {
                intent: InstallIntent::Update,
            },
            Some(progress_callback.clone()),
        )?;
    }

    Ok(HelperCommandSuccess {
        message: "Update complete".to_string(),
        processed_packages,
        value: None,
    })
}

fn update_all_packages(
    progress_callback: Arc<Mutex<Box<ProgressCallback>>>,
) -> HelperCommandResult {
    require_root()?;
    let _lock = acquire_package_mutation_lock()?;
    let config = load_config()?;
    if let Ok(mut callback) = progress_callback.lock() {
        callback(ProgressEvent::Resolving);
    }
    let update_candidates =
        resolve_update_package_statuses(&config, &PackageSelection::AllInstalled)?;
    let processed_packages = update_candidates
        .iter()
        .map(|package| package.package_name.clone())
        .collect::<Vec<_>>();

    for package in update_candidates {
        run_i_package_with_progress(
            &config,
            requested_package_from_status(&package),
            InstallOptions {
                intent: InstallIntent::Update,
            },
            Some(progress_callback.clone()),
        )?;
    }

    Ok(HelperCommandSuccess {
        message: if processed_packages.is_empty() {
            "System already current".to_string()
        } else {
            "Update complete".to_string()
        },
        processed_packages,
        value: None,
    })
}

fn install_isotope_stubs_with_helper(
    isotope_name: &str,
    progress_callback: Arc<Mutex<Box<ProgressCallback>>>,
) -> HelperCommandResult {
    require_root()?;
    let isotope_name = normalized_isotope_name(isotope_name)?;
    let package_name = isotope_qualified_name(&isotope_name);
    let _lock = acquire_package_mutation_lock()?;
    install_isotope_stubs(&isotope_name, Some(progress_callback))?;
    Ok(HelperCommandSuccess {
        message: "Isotope stubs installed".to_string(),
        processed_packages: vec![package_name],
        value: None,
    })
}

fn install_isotope_root_with_helper(
    isotope_name: &str,
    progress_callback: Arc<Mutex<Box<ProgressCallback>>>,
) -> HelperCommandResult {
    require_root()?;
    let isotope_name = normalized_isotope_name(isotope_name)?;
    let package_name = isotope_qualified_name(&isotope_name);
    let _lock = acquire_package_mutation_lock()?;
    let config = load_config()?;
    run_i_isotope_root_only(
        &config,
        package_name.clone(),
        isotope_name,
        Some(progress_callback),
    )?;
    Ok(HelperCommandSuccess {
        message: "Isotope root installed".to_string(),
        processed_packages: vec![package_name],
        value: None,
    })
}

fn convert_radioisotope_with_helper(
    isotope_name: &str,
    progress_callback: Arc<Mutex<Box<ProgressCallback>>>,
) -> HelperCommandResult {
    require_root()?;
    let isotope_name = normalized_isotope_name(isotope_name)?;
    let package_name = isotope_qualified_name(&isotope_name);
    let _lock = acquire_package_mutation_lock()?;
    let config = load_config()?;
    run_i_radioisotope(
        &config,
        package_name.clone(),
        isotope_name,
        InstallIntent::Install,
        Some(progress_callback),
    )?;
    Ok(HelperCommandSuccess {
        message: "Isotope conversion complete".to_string(),
        processed_packages: vec![package_name],
        value: None,
    })
}

fn install_cli_tools(
    source_path: &str,
    caller_path: &str,
    progress_callback: Arc<Mutex<Box<ProgressCallback>>>,
) -> HelperCommandResult {
    require_root()?;

    let installs = cli_tool_installs_for_source(Path::new(source_path));
    verify_cli_install_signatures(
        &installs
            .iter()
            .map(|(_, source_path, _)| source_path.as_path())
            .collect::<Vec<_>>(),
        Path::new(caller_path),
    )?;
    install_cli_tool_records(installs, progress_callback)
}

fn cli_tool_installs_for_source(source_path: &Path) -> Vec<(&'static str, PathBuf, PathBuf)> {
    if source_path.is_dir() {
        return HELPER_CLI_INSTALL_TARGETS
            .iter()
            .map(|(tool_name, target_path)| {
                (
                    *tool_name,
                    source_path.join(tool_name),
                    PathBuf::from(target_path),
                )
            })
            .collect();
    }

    vec![(
        PKG_DISPLAY_NAME,
        source_path.to_path_buf(),
        PathBuf::from(HELPER_AV_INSTALL_TARGET),
    )]
}

pub fn verify_helper_codesign_identity() -> Result<(), String> {
    verify_expected_codesign_identity(
        &std::env::current_exe()
            .map_err(|err| format!("failed to resolve helper executable path: {err}"))?,
    )
}

#[cfg(target_os = "macos")]
fn verify_cli_install_signatures(source_paths: &[&Path], caller_path: &Path) -> Result<(), String> {
    if required_codesign_identity()?.is_none() {
        return Ok(());
    }
    if source_paths.is_empty() {
        return Err("no staged command line tools to install".to_string());
    }
    if caller_path.as_os_str().is_empty() {
        return Err("unable to identify the GUI app requesting CLI installation".to_string());
    }

    let helper_path = std::env::current_exe()
        .map_err(|err| format!("failed to resolve helper executable path: {err}"))?;
    let helper_signature = code_signature_authorities(&helper_path)?;
    ensure_expected_codesign_identity("helper", &helper_path, &helper_signature)?;

    let caller_signature = code_signature_authorities(caller_path)?;
    if caller_signature != helper_signature {
        return Err(format!(
            "GUI app signature does not match helper signature: {}",
            caller_path.display()
        ));
    }

    for source_path in source_paths {
        let source_signature = code_signature_authorities(source_path)?;
        ensure_expected_codesign_identity("staged av", source_path, &source_signature)?;
        if source_signature != caller_signature {
            return Err(format!(
                "staged av signature does not match GUI app and helper: {}",
                source_path.display()
            ));
        }
    }

    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn verify_cli_install_signatures(
    _source_paths: &[&Path],
    _caller_path: &Path,
) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_expected_codesign_identity(path: &Path) -> Result<(), String> {
    if required_codesign_identity()?.is_none() {
        return Ok(());
    }
    let signature = code_signature_authorities(path)?;
    ensure_expected_codesign_identity("helper", path, &signature)
}

#[cfg(not(target_os = "macos"))]
fn verify_expected_codesign_identity(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn ensure_expected_codesign_identity(
    label: &str,
    path: &Path,
    authorities: &[String],
) -> Result<(), String> {
    ensure_expected_codesign_identity_with_expected(
        label,
        path,
        authorities,
        required_codesign_identity()?,
    )
}

#[cfg(target_os = "macos")]
fn ensure_expected_codesign_identity_with_expected(
    label: &str,
    path: &Path,
    authorities: &[String],
    expected: Option<&str>,
) -> Result<(), String> {
    let Some(expected) = expected else {
        return Ok(());
    };
    match authorities.first() {
        Some(actual) if codesign_authority_matches_expected(actual, expected) => Ok(()),
        Some(actual) => Err(format!(
            "{label} signature identity mismatch for {}: expected {expected}, got {actual}",
            path.display()
        )),
        None => Err(format!(
            "{label} is not signed with expected identity {expected}: {}",
            path.display()
        )),
    }
}

#[cfg(target_os = "macos")]
fn codesign_authority_matches_expected(actual: &str, expected: &str) -> bool {
    actual == expected
        || actual
            .strip_prefix("Developer ID Application: ")
            .is_some_and(|short| short == expected)
}

#[cfg(target_os = "macos")]
fn required_codesign_identity() -> Result<Option<&'static str>, String> {
    match expected_codesign_identity() {
        Some(expected) => Ok(Some(expected)),
        None if cfg!(debug_assertions) => Ok(None),
        None => Err("release build missing embedded codesign identity".to_string()),
    }
}

#[cfg(target_os = "macos")]
fn expected_codesign_identity() -> Option<&'static str> {
    let expected = env!("NUKE_CODESIGN_IDENTITY").trim();
    (!expected.is_empty() && expected != "-").then_some(expected)
}

#[cfg(target_os = "macos")]
fn code_signature_authorities(path: &Path) -> Result<Vec<String>, String> {
    let output = Command::new("/usr/bin/codesign")
        .args(["-dv", "--verbose=4"])
        .arg(path)
        .output()
        .map_err(|err| format!("failed to run codesign for {}: {err}", path.display()))?;
    code_signature_authorities_from_output(path, output.status.success(), &output.stderr)
}

#[cfg(target_os = "macos")]
fn code_signature_authorities_from_output(
    path: &Path,
    status_success: bool,
    stderr: &[u8],
) -> Result<Vec<String>, String> {
    if !status_success {
        let stderr_lines = String::from_utf8_lossy(stderr)
            .lines()
            .map(str::to_string)
            .collect::<Vec<_>>();
        return Err(format!(
            "failed to inspect code signature for {}{}",
            path.display(),
            format_command_output_suffix(&stderr_lines)
        ));
    }

    let stderr = String::from_utf8_lossy(stderr);
    let authorities = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("Authority="))
        .map(str::to_string)
        .collect::<Vec<_>>();
    if authorities.is_empty() {
        return Err(format!(
            "code signature for {} has no signing authority",
            path.display()
        ));
    }
    Ok(authorities)
}

fn install_binary_at(
    source_path: &Path,
    target_path: &Path,
    tool_name: &str,
) -> Result<(), String> {
    let source_metadata = fs::metadata(source_path)
        .map_err(|err| format!("failed to stat {}: {err}", source_path.display()))?;
    if !source_metadata.is_file() {
        return Err(format!(
            "staged {tool_name} binary is not a file: {}",
            source_path.display()
        ));
    }

    let target_dir = target_path.parent().ok_or_else(|| {
        format!(
            "invalid {tool_name} install target {}",
            target_path.display()
        )
    })?;
    fs::create_dir_all(target_dir)
        .map_err(|err| format!("failed to create {}: {err}", target_dir.display()))?;

    let temp_dir = TempDir::new_in(target_dir).map_err(|err| {
        format!(
            "failed to create temp dir in {}: {err}",
            target_dir.display()
        )
    })?;
    let staged_target = temp_dir.path().join(tool_name);
    fs::copy(source_path, &staged_target).map_err(|err| {
        format!(
            "failed to copy {} to {}: {err}",
            source_path.display(),
            staged_target.display()
        )
    })?;

    let mut permissions = fs::metadata(&staged_target)
        .map_err(|err| format!("failed to stat {}: {err}", staged_target.display()))?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&staged_target, permissions)
        .map_err(|err| format!("failed to chmod {}: {err}", staged_target.display()))?;

    fs::rename(&staged_target, target_path).map_err(|err| {
        format!(
            "failed to install {tool_name} at {}: {err}",
            target_path.display()
        )
    })?;

    Ok(())
}

fn remember_isotope_always_allow(
    executable_path: &str,
    script_path: Option<&str>,
    script_sha256: Option<&str>,
    mut keys: Vec<String>,
) -> HelperCommandResult {
    require_root()?;
    let executable_path = validate_isotope_always_allow_target(executable_path)?;
    let script =
        validate_isotope_always_allow_script(&executable_path, script_path, script_sha256)?;
    validate_isotope_keys(&keys)?;
    keys.sort();
    keys.dedup();
    let (script_path, script_sha256) = match script {
        Some(script) => (Some(script.path), script.sha256),
        None => (None, None),
    };
    remember_isotope_always_allow_at_path(
        Path::new(ISOTOPE_ALWAYS_ALLOW_PATH),
        executable_path,
        script_path,
        script_sha256,
        keys,
    )
}

fn get_dotenv_approval_policy() -> HelperCommandResult {
    require_root()?;
    let policy = dotenv::load_dotenv_approval_policy()?;
    Ok(HelperCommandSuccess {
        message: "Dotenv approval policy loaded".to_string(),
        processed_packages: Vec::new(),
        value: Some(policy.raw_value().to_string()),
    })
}

fn set_dotenv_approval_policy(policy: dotenv::DotenvApprovalPolicy) -> HelperCommandResult {
    require_root()?;
    if policy == dotenv::DotenvApprovalPolicy::ApproveEveryTime {
        dotenv::clear_dotenv_remembered_approvals()?;
    }
    dotenv::write_dotenv_approval_policy(policy)?;
    Ok(HelperCommandSuccess {
        message: "Dotenv approval policy updated".to_string(),
        processed_packages: Vec::new(),
        value: Some(policy.raw_value().to_string()),
    })
}

fn remember_dotenv_approval_with_helper(
    mode: dotenv::DotenvApprovalMode,
    env_file_path: &str,
    project_root: &str,
    env_sha256: &str,
    public_key_fingerprint: &str,
    keys: Vec<String>,
) -> HelperCommandResult {
    require_root()?;
    dotenv::remember_dotenv_approval_from_helper(
        mode,
        env_file_path,
        project_root,
        env_sha256,
        public_key_fingerprint,
        keys,
    )?;
    Ok(HelperCommandSuccess {
        message: "Dotenv approval remembered".to_string(),
        processed_packages: Vec::new(),
        value: None,
    })
}

fn install_cli_tool_records(
    installs: Vec<(&'static str, PathBuf, PathBuf)>,
    progress_callback: Arc<Mutex<Box<ProgressCallback>>>,
) -> HelperCommandResult {
    let mut processed_packages = Vec::with_capacity(installs.len());

    for (tool_name, source_path, target_path) in installs {
        if let Ok(mut callback) = progress_callback.lock() {
            callback(ProgressEvent::Installing {
                package: tool_name.to_string(),
            });
        }

        install_binary_at(&source_path, &target_path, tool_name)?;
        processed_packages.push(tool_name.to_string());

        if let Ok(mut callback) = progress_callback.lock() {
            callback(ProgressEvent::Completed {
                package: tool_name.to_string(),
            });
        }
    }

    Ok(HelperCommandSuccess {
        message: "Automic Vault command line tools installed to /usr/local/bin".to_string(),
        processed_packages,
        value: None,
    })
}

fn remember_isotope_always_allow_at_path(
    path: &Path,
    executable_path: String,
    script_path: Option<String>,
    script_sha256: Option<String>,
    keys: Vec<String>,
) -> HelperCommandResult {
    let mut store = load_isotope_always_allow_store(path)?;
    if !store.entries.iter().any(|entry| {
        entry.executable_path == executable_path
            && entry.script_path == script_path
            && entry.script_sha256 == script_sha256
            && entry.keys == keys
    }) {
        store.entries.push(IsotopeAlwaysAllowEntry {
            executable_path,
            script_path,
            script_sha256,
            keys,
        });
        store.entries.sort_by(|left, right| {
            left.executable_path
                .cmp(&right.executable_path)
                .then_with(|| left.script_path.cmp(&right.script_path))
                .then_with(|| left.script_sha256.cmp(&right.script_sha256))
                .then_with(|| left.keys.cmp(&right.keys))
        });
        write_isotope_always_allow_store(path, &store)?;
    }

    Ok(HelperCommandSuccess {
        message: "Isotope always-allow remembered".to_string(),
        processed_packages: Vec::new(),
        value: None,
    })
}

fn validate_isotope_always_allow_target(executable_path: &str) -> Result<String, String> {
    let path = fs::canonicalize(executable_path)
        .map_err(|err| format!("failed to resolve isotope target {executable_path}: {err}"))?;
    let metadata = fs::metadata(&path)
        .map_err(|err| format!("failed to stat isotope target {}: {err}", path.display()))?;
    if !metadata.is_file() {
        return Err("isotope target must be a regular file".to_string());
    }
    if metadata.uid() != 0 {
        return Err("isotope target must be owned by root".to_string());
    }
    if metadata.mode() & ((libc::S_IWGRP | libc::S_IWOTH) as u32) != 0 {
        return Err("isotope target must not be writable by group or others".to_string());
    }
    for directory in path.ancestors().skip(1) {
        let metadata = fs::metadata(directory)
            .map_err(|err| format!("failed to stat {}: {err}", directory.display()))?;
        if metadata.mode() & ((libc::S_IWGRP | libc::S_IWOTH) as u32) != 0 {
            return Err(format!(
                "isotope target directory must not be writable by group or others: {}",
                directory.display()
            ));
        }
    }
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| "isotope target path must be valid UTF-8".to_string())
}

fn validate_isotope_always_allow_script(
    executable_path: &str,
    script_path: Option<&str>,
    script_sha256: Option<&str>,
) -> Result<Option<IsotopeAlwaysAllowScript>, String> {
    let is_interpreter = is_isotope_script_interpreter(Path::new(executable_path));
    if Path::new(executable_path)
        .file_name()
        .and_then(|value| value.to_str())
        == Some("env")
    {
        return Err("isotope env always-allow is not supported".to_string());
    }
    match (is_interpreter, script_path.filter(|path| !path.is_empty())) {
        (true, Some(script_path)) => {
            validate_isotope_always_allow_script_path(script_path, script_sha256).map(Some)
        }
        (true, None) => Err("isotope interpreter target requires a script path".to_string()),
        (false, Some(_)) => Err("isotope script path requires an interpreter target".to_string()),
        (false, None) => Ok(None),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IsotopeAlwaysAllowScript {
    path: String,
    sha256: Option<String>,
}

fn validate_isotope_always_allow_script_path(
    script_path: &str,
    script_sha256: Option<&str>,
) -> Result<IsotopeAlwaysAllowScript, String> {
    if !Path::new(script_path).is_absolute() {
        return Err("isotope script path must be absolute".to_string());
    }
    if let Ok(path) = validate_isotope_always_allow_target(script_path) {
        return Ok(IsotopeAlwaysAllowScript { path, sha256: None });
    }

    let expected_sha256 =
        script_sha256.ok_or_else(|| "non-root isotope script requires a sha256".to_string())?;
    validate_isotope_script_sha256(expected_sha256)?;
    let path = fs::canonicalize(script_path)
        .map_err(|err| format!("failed to resolve isotope script {script_path}: {err}"))?;
    let metadata = fs::metadata(&path)
        .map_err(|err| format!("failed to stat isotope script {}: {err}", path.display()))?;
    if !metadata.is_file() {
        return Err("isotope script must be a regular file".to_string());
    }
    let actual_sha256 = sha256_file(&path)?;
    if actual_sha256 != expected_sha256 {
        return Err(
            "isotope script sha256 changed before always-allow could be remembered".to_string(),
        );
    }
    Ok(IsotopeAlwaysAllowScript {
        path: path
            .to_str()
            .map(str::to_string)
            .ok_or_else(|| "isotope script path must be valid UTF-8".to_string())?,
        sha256: Some(expected_sha256.to_string()),
    })
}

fn validate_isotope_script_sha256(value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("isotope script sha256 must be a 64-character hex digest".to_string());
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn is_isotope_script_interpreter(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    matches!(
        file_name,
        "bash"
            | "dash"
            | "env"
            | "ksh"
            | "node"
            | "osascript"
            | "perl"
            | "python"
            | "python3"
            | "ruby"
            | "sh"
            | "zsh"
    ) || is_versioned_python_name(file_name)
}

fn is_versioned_python_name(file_name: &str) -> bool {
    let Some(suffix) = file_name.strip_prefix("python") else {
        return false;
    };
    !suffix.is_empty() && suffix.chars().all(|ch| ch == '.' || ch.is_ascii_digit())
}

fn validate_isotope_keys(keys: &[String]) -> Result<(), String> {
    if keys.is_empty() {
        return Err("at least one isotope key is required".to_string());
    }
    for key in keys {
        let mut chars = key.chars();
        let Some(first) = chars.next() else {
            return Err("empty isotope key name".to_string());
        };
        if !(first == '_' || first.is_ascii_alphabetic())
            || chars.any(|ch| !(ch == '_' || ch.is_ascii_alphanumeric()))
        {
            return Err(format!("invalid isotope key name: {key}"));
        }
    }
    Ok(())
}

fn load_isotope_always_allow_store(path: &Path) -> Result<IsotopeAlwaysAllowStore, String> {
    if !path.exists() {
        return Ok(IsotopeAlwaysAllowStore::default());
    }
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&contents)
        .map_err(|err| format!("failed to decode {}: {err}", path.display()))
}

fn write_isotope_always_allow_store(
    path: &Path,
    store: &IsotopeAlwaysAllowStore,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("invalid isotope always-allow path {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
        .map_err(|err| format!("failed to chmod {}: {err}", parent.display()))?;
    if path == Path::new(ISOTOPE_ALWAYS_ALLOW_PATH)
        && !is_root_controlled_isotope_store_directory(parent)?
    {
        return Err(format!(
            "isotope always-allow directory is not root-controlled: {}",
            parent.display()
        ));
    }
    let temp_dir = TempDir::new_in(parent)
        .map_err(|err| format!("failed to create temp dir in {}: {err}", parent.display()))?;
    let temp_path = temp_dir.path().join("always-allow.json");
    let payload = serde_json::to_vec_pretty(store)
        .map_err(|err| format!("failed to encode isotope always-allow store: {err}"))?;
    fs::write(&temp_path, payload)
        .map_err(|err| format!("failed to write {}: {err}", temp_path.display()))?;
    fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o644))
        .map_err(|err| format!("failed to chmod {}: {err}", temp_path.display()))?;
    fs::rename(&temp_path, path)
        .map_err(|err| format!("failed to install {}: {err}", path.display()))?;
    Ok(())
}

fn is_root_controlled_isotope_store_directory(path: &Path) -> Result<bool, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
    Ok(metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
}

fn require_root() -> Result<(), String> {
    #[cfg(test)]
    if TEST_ASSUME_HELPER_ROOT.load(std::sync::atomic::Ordering::SeqCst) {
        return Ok(());
    }

    if is_root() {
        return Ok(());
    }
    Err("must be run as root".to_string())
}

fn validate_install_specs(packages: Vec<PackageSpec>) -> Result<Vec<RequestedPackage>, String> {
    validate_request_count(&packages)?;
    let mut requested = Vec::with_capacity(packages.len());
    for package in packages {
        requested.push(requested_package_from_spec(&package)?);
    }
    Ok(requested)
}

fn validate_uninstall_specs(packages: Vec<PackageSpec>) -> Result<Vec<String>, String> {
    validate_request_count(&packages)?;
    let mut package_names = Vec::with_capacity(packages.len());
    for package in packages {
        if package.version.is_some() {
            return Err(format!(
                "package {} cannot specify a version for uninstall",
                package.name
            ));
        }
        package_names.push(cli::parse_uninstall_package_name(&OsString::from(
            package.name,
        ))?);
    }
    Ok(package_names)
}

fn make_default_packages(
    packages: Vec<PackageSpec>,
    progress_callback: Arc<Mutex<Box<ProgressCallback>>>,
) -> HelperCommandResult {
    require_root()?;
    let package_names = validate_uninstall_specs(packages)?;
    let mut processed_packages = Vec::new();
    for package_name in package_names {
        make_package_default_root(&package_name, Some(progress_callback.clone()))?;
        processed_packages.push(package_name);
    }
    Ok(HelperCommandSuccess {
        message: "Package default updated".to_string(),
        processed_packages,
        value: None,
    })
}

pub(crate) fn make_package_default(package: &str) -> Result<HelperCommandSuccess, String> {
    require_root()?;
    let package_name = crate::cli::parse_uninstall_package_name(&OsString::from(package))?;
    make_package_default_root(&package_name, None)?;
    Ok(HelperCommandSuccess {
        message: "Package default updated".to_string(),
        processed_packages: vec![package_name],
        value: None,
    })
}

fn make_package_default_root(
    package_name: &str,
    progress_callback: Option<Arc<Mutex<Box<ProgressCallback>>>>,
) -> Result<(), String> {
    let install_root = package_install_root(&opt_pkg_root(), package_name)?;
    ensure_package_installed(&opt_pkg_root(), package_name)?;
    let receipt = load_or_resolve_package_receipt(package_name, &install_root)?;
    let PackageReceiptSource::Formula { root_formula } = receipt.source else {
        return Err(format!("package {package_name} is not a Homebrew formula"));
    };
    if root_formula.starts_with("python@") || package_name.starts_with("python@") {
        return Err(
            "Python uses side-by-side stubs and cannot be made default this way".to_string(),
        );
    }
    if let Some(mut callback) = progress_callback
        .as_ref()
        .and_then(|callback| callback.lock().ok())
    {
        callback(ProgressEvent::Installing {
            package: package_name.to_string(),
        });
    }
    let config = load_config()?;
    let graph = resolve_formula_specs(std::slice::from_ref(&root_formula), &config, true)?;
    let plan = InstallPlan::for_i(package_name.to_string(), root_formula);
    sync_stubs(&plan, &graph, &[])?;
    if let Some(mut callback) = progress_callback
        .as_ref()
        .and_then(|callback| callback.lock().ok())
    {
        callback(ProgressEvent::Completed {
            package: package_name.to_string(),
        });
    }
    Ok(())
}

fn validate_request_count(packages: &[PackageSpec]) -> Result<(), String> {
    if packages.is_empty() {
        return Err("at least one package is required".to_string());
    }
    if packages.len() > MAX_HELPER_PACKAGES {
        return Err(format!(
            "at most {MAX_HELPER_PACKAGES} packages are allowed per request"
        ));
    }
    Ok(())
}

fn requested_package_from_spec(package: &PackageSpec) -> Result<RequestedPackage, String> {
    let requested = cli::parse_package_name(&OsString::from(package.name.clone()))?;
    match requested {
        RequestedPackage::NpmPackage {
            package: npm_package,
            version: _,
        } => Ok(RequestedPackage::NpmPackage {
            package: npm_package,
            version: validate_optional_version(package.version.as_deref())?,
        }),
        RequestedPackage::Auto(_)
        | RequestedPackage::HomebrewFormula(_)
        | RequestedPackage::HomebrewCask(_)
        | RequestedPackage::VendorPackage(_)
        | RequestedPackage::Isotope(_)
        | RequestedPackage::PipPackage(_) => {
            if package.version.is_some() {
                return Err(format!(
                    "package {} does not support explicit version selection",
                    package.name
                ));
            }
            Ok(requested)
        }
    }
}

fn validate_optional_version(version: Option<&str>) -> Result<Option<String>, String> {
    let Some(version) = version else {
        return Ok(None);
    };
    let trimmed = version.trim();
    if trimmed.is_empty() {
        return Err("version must not be empty".to_string());
    }
    if trimmed
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err("version must not contain whitespace or control characters".to_string());
    }
    Ok(Some(trimmed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EndpointOverrideGuard;

    impl Drop for EndpointOverrideGuard {
        fn drop(&mut self) {
            config::clear_test_endpoint_overrides();
        }
    }

    fn set_formula_api_root(base: String) -> EndpointOverrideGuard {
        config::set_test_endpoint_overrides(config::TestEndpointOverrides {
            formula_api_root: Some(base),
            ..Default::default()
        });
        EndpointOverrideGuard
    }

    struct TestHelperRootGuard {
        previous: bool,
    }

    impl TestHelperRootGuard {
        fn enable() -> Self {
            Self {
                previous: TEST_ASSUME_HELPER_ROOT.swap(true, std::sync::atomic::Ordering::SeqCst),
            }
        }
    }

    impl Drop for TestHelperRootGuard {
        fn drop(&mut self) {
            TEST_ASSUME_HELPER_ROOT.store(self.previous, std::sync::atomic::Ordering::SeqCst);
        }
    }

    struct TestEnvVarGuard {
        previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl TestEnvVarGuard {
        fn set(values: &[(&'static str, &str)]) -> Self {
            let previous = values
                .iter()
                .map(|(key, value)| {
                    let previous = std::env::var_os(key);
                    unsafe {
                        std::env::set_var(key, value);
                    }
                    (*key, previous)
                })
                .collect();
            Self { previous }
        }
    }

    impl Drop for TestEnvVarGuard {
        fn drop(&mut self) {
            for (key, previous) in self.previous.drain(..).rev() {
                unsafe {
                    match previous {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
    }

    fn start_ops_test_http_server(
        routes: Vec<(String, Vec<u8>)>,
        requests: usize,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let routes = Arc::new(routes.into_iter().collect::<HashMap<_, _>>());
        let handle = thread::spawn(move || {
            for _ in 0..requests {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 1024];
                let count = stream.read(&mut request).unwrap_or(0);
                let first_line = std::str::from_utf8(&request[..count])
                    .unwrap_or_default()
                    .lines()
                    .next()
                    .unwrap_or_default();
                let path = first_line.split_whitespace().nth(1).unwrap_or("/");
                let (status, body) = routes
                    .get(path)
                    .map(|body| ("200 OK", body.as_slice()))
                    .unwrap_or(("404 Not Found", b"not found".as_slice()));
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(body).unwrap();
            }
        });
        (format!("http://{address}"), handle)
    }

    fn write_test_receipt(
        package_name: &str,
        version: &str,
        source: PackageReceiptSource,
    ) -> PathBuf {
        write_test_receipt_with_metadata(package_name, version, source, PackageMetadata::default())
    }

    fn write_test_receipt_with_metadata(
        package_name: &str,
        version: &str,
        source: PackageReceiptSource,
        metadata: PackageMetadata,
    ) -> PathBuf {
        let install_root = opt_pkg_root().join(package_name);
        if fs::symlink_metadata(&install_root).is_ok() {
            remove_path(&install_root).unwrap();
        }
        fs::create_dir_all(&install_root).unwrap();
        write_package_receipt(
            &install_root.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: package_name.to_string(),
                version: version.to_string(),
                source,
                metadata,
            },
        )
        .unwrap();
        install_root
    }

    #[test]
    fn install_binary_at_copies_binary_and_sets_mode() {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("source-av");
        let target_dir = temp.path().join("usr/local/bin");
        let target = target_dir.join("av");

        fs::write(&source, "#!/bin/sh\necho av\n").unwrap();
        let mut source_permissions = fs::metadata(&source).unwrap().permissions();
        source_permissions.set_mode(0o700);
        fs::set_permissions(&source, source_permissions).unwrap();

        install_binary_at(&source, &target, "av").unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "#!/bin/sh\necho av\n");
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn install_binary_at_reports_invalid_sources_and_targets() {
        let temp = TempDir::new().unwrap();
        let source_dir = temp.path().join("staged-dir");
        fs::create_dir_all(&source_dir).unwrap();
        assert!(
            install_binary_at(&source_dir, &temp.path().join("av"), "av")
                .unwrap_err()
                .contains("is not a file")
        );

        let missing = temp.path().join("missing-av");
        assert!(
            install_binary_at(&missing, &temp.path().join("av"), "av")
                .unwrap_err()
                .contains("failed to stat")
        );

        let source_file = temp.path().join("staged-av");
        fs::write(&source_file, "av").unwrap();
        assert!(
            install_binary_at(&source_file, Path::new(""), "av")
                .unwrap_err()
                .contains("invalid av install target")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn codesign_helpers_parse_authorities_and_identity_errors() {
        let path = Path::new("/tmp/staged-av");
        let authorities = code_signature_authorities_from_output(
            path,
            true,
            b"Executable=/tmp/staged-av\nAuthority=Developer ID Application: Example\nAuthority=Apple Root CA\n",
        )
        .unwrap();
        assert_eq!(
            authorities,
            vec![
                "Developer ID Application: Example".to_string(),
                "Apple Root CA".to_string()
            ]
        );

        assert!(
            code_signature_authorities_from_output(path, true, b"Executable=/tmp/staged-av\n")
                .unwrap_err()
                .contains("has no signing authority")
        );
        assert!(
            code_signature_authorities_from_output(
                path,
                false,
                b"/tmp/staged-av: code object is not signed at all\n"
            )
            .unwrap_err()
            .contains("code object is not signed at all")
        );

        assert!(
            ensure_expected_codesign_identity_with_expected(
                "helper",
                path,
                &authorities,
                Some("Developer ID Application: Example")
            )
            .is_ok()
        );
        assert!(
            ensure_expected_codesign_identity_with_expected(
                "helper",
                path,
                &authorities,
                Some("Example")
            )
            .is_ok()
        );
        assert!(
            ensure_expected_codesign_identity_with_expected(
                "helper",
                path,
                &authorities,
                Some("Developer ID Application: Other")
            )
            .unwrap_err()
            .contains("signature identity mismatch")
        );
        assert!(
            ensure_expected_codesign_identity_with_expected("helper", path, &[], Some("Expected"))
                .unwrap_err()
                .contains("is not signed with expected identity")
        );
        assert!(ensure_expected_codesign_identity_with_expected("helper", path, &[], None).is_ok());
    }

    #[test]
    fn install_cli_tool_records_emits_progress_and_copies_all_targets() {
        let temp = TempDir::new().unwrap();
        let first_source = temp.path().join("staged-av");
        let second_source = temp.path().join("staged-helper");
        let first_target = temp.path().join("usr/local/bin/av");
        let second_target = temp.path().join("usr/local/bin/helper");
        fs::write(&first_source, "#!/bin/sh\necho av\n").unwrap();
        fs::write(&second_source, "#!/bin/sh\necho helper\n").unwrap();

        let events = Arc::new(Mutex::new(Vec::new()));
        let callback_events = Arc::clone(&events);
        let callback: Arc<Mutex<Box<ProgressCallback>>> =
            Arc::new(Mutex::new(Box::new(move |event| {
                callback_events.lock().unwrap().push(event);
            })));

        let result = install_cli_tool_records(
            vec![
                ("av", first_source.clone(), first_target.clone()),
                ("helper", second_source.clone(), second_target.clone()),
            ],
            callback,
        )
        .unwrap();

        assert_eq!(result.processed_packages, ["av", "helper"]);
        assert_eq!(
            fs::read_to_string(&first_target).unwrap(),
            "#!/bin/sh\necho av\n"
        );
        assert_eq!(
            fs::read_to_string(&second_target).unwrap(),
            "#!/bin/sh\necho helper\n"
        );
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &[
                ProgressEvent::Installing {
                    package: "av".to_string(),
                },
                ProgressEvent::Completed {
                    package: "av".to_string(),
                },
                ProgressEvent::Installing {
                    package: "helper".to_string(),
                },
                ProgressEvent::Completed {
                    package: "helper".to_string(),
                },
            ]
        );
    }

    #[test]
    fn install_cli_tool_records_stops_after_first_install_error() {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("missing-av");
        let target = temp.path().join("usr/local/bin/av");

        let events = Arc::new(Mutex::new(Vec::new()));
        let callback_events = Arc::clone(&events);
        let callback: Arc<Mutex<Box<ProgressCallback>>> =
            Arc::new(Mutex::new(Box::new(move |event| {
                callback_events.lock().unwrap().push(event);
            })));

        let err = install_cli_tool_records(vec![("av", source, target)], callback).unwrap_err();
        assert!(err.contains("failed to stat"));
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &[ProgressEvent::Installing {
                package: "av".to_string(),
            }]
        );
    }

    #[test]
    fn cli_tool_installs_for_source_expands_staging_directory() {
        let temp = TempDir::new().unwrap();
        let installs = cli_tool_installs_for_source(temp.path());

        assert_eq!(
            installs,
            vec![(
                "av",
                temp.path().join("av"),
                PathBuf::from("/usr/local/bin/av")
            )]
        );

        let file = temp.path().join("av");
        fs::write(&file, b"av").unwrap();
        assert_eq!(
            cli_tool_installs_for_source(&file),
            vec![(
                PKG_DISPLAY_NAME,
                file,
                PathBuf::from(HELPER_AV_INSTALL_TARGET)
            )]
        );
    }

    #[test]
    fn isotope_always_allow_store_uses_script_path_shape() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("always-allow.json");
        let script_sha = "a".repeat(64);
        let store = IsotopeAlwaysAllowStore {
            entries: vec![IsotopeAlwaysAllowEntry {
                executable_path: "/opt/awscli/bin/python3.14".to_string(),
                script_path: Some("/opt/awscli/bin/aws".to_string()),
                script_sha256: Some(script_sha),
                keys: vec![
                    "AWS_ACCESS_KEY_ID".to_string(),
                    "AWS_SECRET_ACCESS_KEY".to_string(),
                ],
            }],
        };

        write_isotope_always_allow_store(&path, &store).unwrap();
        let reloaded = load_isotope_always_allow_store(&path).unwrap();

        assert_eq!(reloaded, store);
        let encoded = fs::read_to_string(path).unwrap();
        assert!(encoded.contains("\"script_path\""));
        assert!(encoded.contains("\"script_sha256\""));
    }

    #[test]
    fn isotope_interpreter_detection_accepts_versioned_python() {
        assert!(is_isotope_script_interpreter(Path::new(
            "/opt/awscli/bin/python3.14"
        )));
        assert!(is_isotope_script_interpreter(Path::new("/bin/python3")));
        assert!(!is_isotope_script_interpreter(Path::new(
            "/bin/python-config"
        )));
    }

    #[test]
    fn list_installed_packages_keeps_versioned_formulae_separate() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let roots = [
            write_test_receipt(
                "coverage-python@3.13",
                "3.13.9",
                PackageReceiptSource::Formula {
                    root_formula: "coverage-python@3.13".to_string(),
                },
            ),
            write_test_receipt(
                "coverage-python@3.14",
                "3.14.1",
                PackageReceiptSource::Formula {
                    root_formula: "coverage-python@3.14".to_string(),
                },
            ),
            write_test_receipt_with_metadata(
                "coverage-cask",
                "1.0.0",
                PackageReceiptSource::Cask {
                    cask_name: "coverage-cask".to_string(),
                },
                PackageMetadata {
                    description: Some("Coverage cask".to_string()),
                    homepage: Some("https://example.test/coverage-cask".to_string()),
                },
            ),
            write_test_receipt(
                "isotope:uv",
                "0.11.18",
                PackageReceiptSource::Isotope {
                    isotope_name: "uv".to_string(),
                },
            ),
        ];

        let packages = list_installed_packages().unwrap().packages;
        let versioned = packages
            .iter()
            .filter(|package| package.name.starts_with("coverage-python@"))
            .collect::<Vec<_>>();
        assert_eq!(
            versioned
                .iter()
                .map(|package| (package.name.as_str(), package.version.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("coverage-python@3.13", "3.13.9"),
                ("coverage-python@3.14", "3.14.1")
            ]
        );
        assert!(
            versioned
                .iter()
                .all(|package| package.installed_versions.is_empty()
                    && package.install_package_names.is_empty())
        );

        let cask = packages
            .iter()
            .find(|package| package.name == "coverage-cask")
            .unwrap();
        assert_eq!(
            cask.source,
            PackageReceiptSource::Cask {
                cask_name: "coverage-cask".to_string()
            }
        );
        assert_eq!(
            cask.homepage.as_deref(),
            Some("https://example.test/coverage-cask")
        );
        let uv = packages
            .iter()
            .find(|package| package.name == "isotope:uv")
            .unwrap();
        assert_eq!(uv.homepage.as_deref(), Some("https://docs.astral.sh/uv/"));
        assert_eq!(
            uv.repository.as_deref(),
            Some("https://github.com/astral-sh/uv")
        );
        assert_eq!(
            uv.upstream_docs.as_deref(),
            Some("https://docs.astral.sh/uv")
        );
        assert_eq!(uv.docs, vec!["https://docs.astral.sh/uv".to_string()]);

        for root in roots {
            remove_path(&root).unwrap();
        }
    }

    #[test]
    fn helper_command_errors_emit_progress_error() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = events.clone();
        let result = execute_helper_command(
            HelperCommand::Install {
                packages: Vec::new(),
            },
            move |event| captured.lock().unwrap().push(event),
        );

        assert!(result.is_err());
        assert!(matches!(
            events.lock().unwrap().last(),
            Some(ProgressEvent::Error { .. })
        ));
    }

    #[test]
    fn helper_command_bodies_cover_root_bypassed_safe_errors() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let _root = TestHelperRootGuard::enable();
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("project");
        fs::create_dir_all(&project).unwrap();
        let env_path = project.join(".env");
        fs::write(&env_path, "DOTENV_PUBLIC_KEY=public-key\nAPI_TOKEN=plain\n").unwrap();
        let policy_path = temp.path().join("dotenv-policy.json");
        let approvals_path = temp.path().join("dotenv-approvals.json");
        let _dotenv_env = TestEnvVarGuard::set(&[
            ("AV_TEST_DOTENV_POLICY_PATH", policy_path.to_str().unwrap()),
            (
                "AV_TEST_DOTENV_REMEMBERED_APPROVALS_PATH",
                approvals_path.to_str().unwrap(),
            ),
        ]);
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let formula_api_root = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let _endpoint = set_formula_api_root(formula_api_root);
        let events = Arc::new(Mutex::new(Vec::new()));
        let progress = || {
            let captured = Arc::clone(&events);
            Arc::new(Mutex::new(Box::new(move |event| {
                captured.lock().unwrap().push(event);
            }) as Box<ProgressCallback>))
        };
        let formula = PackageSpec {
            name: "brew:coverage-helper-formula".to_string(),
            version: None,
        };

        assert!(
            install_packages(vec![formula.clone()], progress())
                .unwrap_err()
                .contains("coverage-helper-formula")
        );
        assert!(
            update_packages(Vec::new(), progress())
                .unwrap_err()
                .contains("at least one package")
        );
        let _ = update_all_packages(progress());
        assert!(
            uninstall_packages(
                vec![PackageSpec {
                    name: "coverage-missing-package".to_string(),
                    version: None,
                }],
                progress()
            )
            .unwrap_err()
            .contains("not installed")
        );
        assert!(
            install_isotope_stubs_with_helper("", progress())
                .unwrap_err()
                .contains("missing isotope name")
        );
        assert!(
            install_isotope_root_with_helper("bad/name", progress())
                .unwrap_err()
                .contains("invalid isotope name")
        );
        assert!(
            convert_radioisotope_with_helper("bad/name", progress())
                .unwrap_err()
                .contains("invalid isotope name")
        );
        assert!(
            install_cli_tools(
                "/tmp/coverage-missing-av",
                "/tmp/Coverage Caller.app",
                progress()
            )
            .is_err()
        );
        assert_eq!(
            get_dotenv_approval_policy().unwrap().value.as_deref(),
            Some("approve_every_time")
        );
        assert_eq!(
            set_dotenv_approval_policy(dotenv::DotenvApprovalPolicy::RememberApproved)
                .unwrap()
                .value
                .as_deref(),
            Some("remember_approved")
        );
        assert!(
            remember_dotenv_approval_with_helper(
                dotenv::DotenvApprovalMode::Run,
                env_path.to_str().unwrap(),
                project.to_str().unwrap(),
                "f15d64528dce9aa1e20497a5d9ef60783080fe5e3d5051de19c8fae7c78c4607",
                "43a46f1d081d270130e2210a1de59f9715de033307d068edc65a335b27e95d3d",
                vec!["API_TOKEN".to_string(), "API_TOKEN".to_string()],
            )
            .is_ok()
        );
        let remembered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&approvals_path).unwrap()).unwrap();
        assert_eq!(remembered["entries"].as_array().unwrap().len(), 1);
        assert_eq!(
            set_dotenv_approval_policy(dotenv::DotenvApprovalPolicy::ApproveEveryTime)
                .unwrap()
                .value
                .as_deref(),
            Some("approve_every_time")
        );
        let remembered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&approvals_path).unwrap()).unwrap();
        assert!(remembered["entries"].as_array().unwrap().is_empty());
        assert!(events.lock().unwrap().iter().any(
            |event| matches!(event, ProgressEvent::Installing { package } if package == "coverage-missing-package" || package == PKG_DISPLAY_NAME)
        ));
    }

    #[test]
    fn helper_command_routes_isotope_and_always_allow_errors() {
        for command in [
            HelperCommand::Update {
                packages: vec![PackageSpec {
                    name: "rg".to_string(),
                    version: None,
                }],
            },
            HelperCommand::Uninstall {
                packages: vec![PackageSpec {
                    name: "rg".to_string(),
                    version: None,
                }],
            },
            HelperCommand::MakeDefault {
                packages: vec![PackageSpec {
                    name: "rg".to_string(),
                    version: None,
                }],
            },
            HelperCommand::UpdateAll,
            HelperCommand::InstallAv {
                source_path: "/tmp/av".to_string(),
                caller_path: "/tmp/Automic Vault.app".to_string(),
            },
            HelperCommand::InstallIsotopeRoot {
                isotope_name: String::new(),
            },
            HelperCommand::ConvertRadioisotope {
                isotope_name: "bad/name".to_string(),
            },
            HelperCommand::InstallIsotopeStubs {
                isotope_name: String::new(),
            },
            HelperCommand::RememberIsotopeAlwaysAllow {
                executable_path: String::new(),
                script_path: None,
                script_sha256: None,
                keys: Vec::new(),
            },
        ] {
            let result = execute_helper_command(command, |_| {});
            assert!(result.is_err());
        }
    }

    #[test]
    fn package_search_wrappers_cover_pagination_edges() {
        let empty = search_packages("", 0, 10).unwrap();
        assert_eq!(empty.total_count, 0);
        assert!(empty.packages.is_empty());
        assert_eq!(empty.next_offset, None);

        let default_page =
            list_available_packages_matching_category(0, 0, None, Some("az")).unwrap();
        assert!(default_page.total_count >= default_page.packages.len());
        assert!(default_page.packages.len() <= DEFAULT_SEARCH_PAGE_SIZE);

        let capped_page =
            list_available_packages_matching_category(0, usize::MAX, None, Some("az")).unwrap();
        assert!(capped_page.packages.len() <= MAX_SEARCH_PAGE_SIZE);

        let past_end = search_packages("rg", usize::MAX / 2, 1).unwrap();
        assert!(past_end.packages.is_empty());
        assert_eq!(past_end.next_offset, None);

        let pulse = list_pulse_packages(0, 1).unwrap();
        assert_eq!(pulse.packages.len(), 1);
        assert!(pulse.next_offset.is_some());

        let geiger = list_geiger_packages(0, 1).unwrap();
        assert!(geiger.total_count >= geiger.packages.len());
        assert!(geiger.packages.len() <= 1);

        let recommendations = list_security_recommendation_packages(0, 1).unwrap();
        assert!(recommendations.total_count >= recommendations.packages.len());
        assert!(recommendations.packages.len() <= 1);
    }

    #[test]
    fn package_rank_sort_is_ascending_with_unranked_packages_last() {
        let mut packages = vec![
            ranked_search_result("alpha", Some(1)),
            ranked_search_result("missing", None),
            ranked_search_result("zulu", Some(3)),
            ranked_search_result("middle", Some(2)),
        ];
        sort_available_packages(&mut packages, PackageListSort::Rank).unwrap();
        assert_eq!(
            packages
                .iter()
                .map(|package| package.package_name.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "middle", "zulu", "missing"]
        );

        sort_available_packages(&mut packages, PackageListSort::Alphabetical).unwrap();
        assert_eq!(
            packages
                .iter()
                .map(|package| package.package_name.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "middle", "missing", "zulu"]
        );
    }

    fn ranked_search_result(package_name: &str, rank: Option<u32>) -> PackageSearchResult {
        PackageSearchResult {
            package_name: package_name.to_string(),
            source: PackageReceiptSource::Formula {
                root_formula: package_name.to_string(),
            },
            summary: None,
            latest_version: None,
            homepage: None,
            repository: None,
            upstream_docs: None,
            docs: Vec::new(),
            category: None,
            dependencies: Vec::new(),
            install_package_names: Vec::new(),
            security_state: None,
            rank,
            last_updated_at: None,
            pulse_kind: None,
        }
    }

    #[test]
    fn search_package_response_preserves_explicit_security_state() {
        let page = search_packages_response(
            vec![PackageSearchResult {
                package_name: "brew:detector-target".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "detector-target".to_string(),
                },
                summary: Some("Detector flagged local plaintext credential exposure".to_string()),
                latest_version: None,
                homepage: None,
                repository: None,
                upstream_docs: None,
                docs: Vec::new(),
                category: None,
                dependencies: Vec::new(),
                install_package_names: Vec::new(),
                security_state: Some(PackageSecurityState {
                    isotope_name: "unmapped-isotope".to_string(),
                    install_is_insecure: true,
                    remediation_available: false,
                    reasons: vec!["local detector hit".to_string()],
                    error: None,
                }),
                rank: None,
                last_updated_at: None,
                pulse_kind: None,
            }],
            0,
            25,
        );

        assert_eq!(page.total_count, 1);
        assert_eq!(
            page.packages[0]
                .security_state
                .as_ref()
                .map(|state| (state.isotope_name.as_str(), state.install_is_insecure)),
            Some(("unmapped-isotope", true))
        );
    }

    #[test]
    fn search_package_response_marks_hardened_install_targets() {
        let hardened = search_package_summary(ranked_search_result("node@24", None));
        let mut explicit_hardened = ranked_search_result("brew:node@24", None);
        explicit_hardened.source = PackageReceiptSource::Formula {
            root_formula: "node@24".to_string(),
        };
        explicit_hardened.install_package_names = vec!["brew:node@24".to_string()];
        let explicit_hardened = search_package_summary(explicit_hardened);
        let plain = search_package_summary(ranked_search_result("ripgrep", None));

        assert!(hardened.installs_hardened);
        assert!(explicit_hardened.installs_hardened);
        assert!(!plain.installs_hardened);
    }

    #[test]
    fn catalog_metadata_helpers_cover_source_variants_and_defaults() {
        let formula = catalog_metadata_for_source(&PackageReceiptSource::Formula {
            root_formula: "uv".to_string(),
        });
        assert_eq!(
            formula.summary.as_deref(),
            Some("Extremely fast Python package installer and resolver, written in Rust")
        );
        assert_eq!(
            formula.homepage.as_deref(),
            Some("https://docs.astral.sh/uv/")
        );
        assert_eq!(
            formula.repository.as_deref(),
            Some("https://github.com/astral-sh/uv")
        );
        assert_eq!(
            formula.upstream_docs.as_deref(),
            Some("https://docs.astral.sh/uv")
        );
        assert_eq!(formula.docs, vec!["https://docs.astral.sh/uv".to_string()]);
        assert_eq!(formula.category.as_deref(), Some("developer-tools"));
        assert!(formula.has_visible_fields());

        let alias = formula_catalog_metadata("rg");
        assert_eq!(alias.summary.as_deref(), Some("Search tool"));
        assert!(alias.has_visible_fields());

        let cask = catalog_metadata_for_source(&PackageReceiptSource::Cask {
            cask_name: "codex".to_string(),
        });
        assert!(cask.summary.is_some());
        assert!(cask.homepage.is_some());

        let isotope_with_formula = catalog_metadata_for_source(&PackageReceiptSource::Isotope {
            isotope_name: "uv".to_string(),
        });
        assert_eq!(
            isotope_with_formula.repository.as_deref(),
            Some("https://github.com/astral-sh/uv")
        );

        let versioned_isotope = catalog_metadata_for_source(&PackageReceiptSource::Isotope {
            isotope_name: "node@24".to_string(),
        });
        assert_eq!(
            versioned_isotope.summary.as_deref(),
            Some("JavaScript runtime")
        );

        let detector_only_isotope = catalog_metadata_for_source(&PackageReceiptSource::Isotope {
            isotope_name: "curl".to_string(),
        });
        assert!(detector_only_isotope.homepage.is_none());
        assert!(!detector_only_isotope.has_visible_fields());

        let npm = catalog_metadata_for_source(&PackageReceiptSource::Npm {
            package_name: "coverage-npm".to_string(),
        });
        assert_eq!(npm.summary.as_deref(), Some("Coverage npm tool"));
        assert_eq!(npm.homepage.as_deref(), Some("https://example.test/npm"));

        let missing = catalog_metadata_for_source(&PackageReceiptSource::Pip {
            package_name: "coverage-pip".to_string(),
        });
        assert!(!missing.has_visible_fields());
        assert!(!formula_catalog_metadata("missing-formula").has_visible_fields());
        assert!(!cask_catalog_metadata("missing-cask").has_visible_fields());
        assert!(!isotope_catalog_metadata("missing-isotope").has_visible_fields());
        assert!(!npm_catalog_metadata("missing-npm").has_visible_fields());
    }

    #[test]
    fn search_package_summary_covers_hardened_source_and_install_name_variants() {
        let isotope = search_package_summary(PackageSearchResult {
            source: PackageReceiptSource::Isotope {
                isotope_name: "gh".to_string(),
            },
            ..ranked_search_result("isotope:gh", None)
        });
        assert!(isotope.installs_hardened);

        let vendor = search_package_summary(PackageSearchResult {
            source: PackageReceiptSource::Vendor {
                vendor_name: "terraform".to_string(),
            },
            ..ranked_search_result("terraform", None)
        });
        assert!(vendor.installs_hardened);

        let plain_sources = [
            PackageReceiptSource::Cask {
                cask_name: "codex".to_string(),
            },
            PackageReceiptSource::Npm {
                package_name: "coverage-npm".to_string(),
            },
            PackageReceiptSource::Pip {
                package_name: "coverage-pip".to_string(),
            },
        ];
        for source in plain_sources {
            let summary = search_package_summary(PackageSearchResult {
                source,
                ..ranked_search_result("plain", None)
            });
            assert!(!summary.installs_hardened);
        }

        let mut names = ranked_search_result("mixed", None);
        names.install_package_names = vec![
            "bad/name".to_string(),
            "cask:codex".to_string(),
            "isotope:gh".to_string(),
        ];
        assert!(search_package_summary(names).installs_hardened);

        for package_name in [
            "isotope:gh",
            "brew:node@24",
            "terraform",
            "cask:codex",
            "npm:coverage-npm",
            "pip:coverage-pip",
            "bad/name",
        ] {
            let _ = install_package_name_installs_hardened(package_name);
        }
        assert!(install_package_name_installs_hardened("isotope:gh"));
        assert!(install_package_name_installs_hardened("brew:node@24"));
        assert!(install_package_name_installs_hardened("terraform"));
        assert!(!install_package_name_installs_hardened("cask:codex"));
        assert!(!install_package_name_installs_hardened("npm:coverage-npm"));
        assert!(!install_package_name_installs_hardened("pip:coverage-pip"));
        assert!(!install_package_name_installs_hardened("bad/name"));
    }

    #[test]
    fn helper_command_routes_dotenv_approval_errors_through_progress() {
        let commands = [
            HelperCommand::GetDotenvApprovalPolicy,
            HelperCommand::SetDotenvApprovalPolicy {
                policy: dotenv::DotenvApprovalPolicy::RememberApproved,
            },
            HelperCommand::RememberDotenvApproval {
                mode: dotenv::DotenvApprovalMode::Run,
                env_file_path: "/tmp/project/.env".to_string(),
                project_root: "/tmp/project".to_string(),
                env_sha256: "0".repeat(64),
                public_key_fingerprint: "f".repeat(64),
                keys: vec!["API_TOKEN".to_string()],
            },
        ];

        for command in commands {
            let events = Arc::new(Mutex::new(Vec::new()));
            let captured = Arc::clone(&events);
            let result = execute_helper_command(command, move |event| {
                captured.lock().unwrap().push(event);
            });
            assert!(result.is_err());
            assert!(matches!(
                events.lock().unwrap().last(),
                Some(ProgressEvent::Error { message }) if message.contains("root")
            ));
        }
    }

    #[test]
    fn validation_helpers_cover_limits_versions_and_isotope_names() {
        assert_eq!(search_page_size(0), DEFAULT_SEARCH_PAGE_SIZE);
        assert_eq!(search_page_size(1), 1);
        assert_eq!(search_page_size(usize::MAX), MAX_SEARCH_PAGE_SIZE);
        assert_eq!(
            normalized_requested_category(Some(" developer-tools ")),
            Some("developer-tools")
        );
        assert_eq!(normalized_requested_category(Some(" ")), None);
        assert_eq!(normalized_requested_category(None), None);
        for (raw, expected) in [
            (Some("security"), Some("security")),
            (Some("\tcloud\n"), Some("cloud")),
            (Some(""), None),
        ] {
            assert_eq!(normalized_requested_category(raw), expected);
        }

        assert_eq!(normalized_isotope_name("isotope:gh").unwrap(), "gh");
        assert_eq!(normalized_isotope_name("aws-cli").unwrap(), "aws-cli");
        assert!(normalized_isotope_name("").unwrap_err().contains("missing"));
        assert!(
            normalized_isotope_name("bad/name")
                .unwrap_err()
                .contains("invalid")
        );

        assert_eq!(
            validate_optional_version(Some(" 1.2.3 ")).unwrap(),
            Some("1.2.3".to_string())
        );
        assert_eq!(
            validate_optional_version(Some("1.2.3")).unwrap(),
            Some("1.2.3".to_string())
        );
        assert_eq!(validate_optional_version(None).unwrap(), None);
        assert!(validate_optional_version(Some(" ")).is_err());
        assert!(validate_optional_version(Some("1.2.3 beta")).is_err());

        assert!(validate_install_specs(Vec::new()).is_err());
        assert!(
            validate_install_specs(vec![PackageSpec {
                name: "npm:openclaw".to_string(),
                version: Some("4.5.6".to_string()),
            }])
            .is_ok()
        );
        assert!(
            validate_install_specs(vec![
                PackageSpec {
                    name: "cask:cursor".to_string(),
                    version: None,
                },
                PackageSpec {
                    name: "isotope:gh".to_string(),
                    version: None,
                },
                PackageSpec {
                    name: "pip:My_Package.Name".to_string(),
                    version: None,
                },
                PackageSpec {
                    name: "rg".to_string(),
                    version: None,
                },
            ])
            .is_ok()
        );
        assert!(
            validate_install_specs(vec![PackageSpec {
                name: "brew:sqlite".to_string(),
                version: Some("3".to_string()),
            }])
            .unwrap_err()
            .contains("does not support explicit version")
        );
        assert!(
            validate_uninstall_specs(vec![PackageSpec {
                name: "npm:openclaw".to_string(),
                version: Some("4.5.6".to_string()),
            }])
            .unwrap_err()
            .contains("cannot specify a version")
        );
        let too_many = (0..=MAX_HELPER_PACKAGES)
            .map(|index| PackageSpec {
                name: format!("pkg-{index}"),
                version: None,
            })
            .collect();
        assert!(
            validate_install_specs(too_many)
                .unwrap_err()
                .contains("at most")
        );
        assert_eq!(
            validate_uninstall_specs(vec![
                PackageSpec {
                    name: "brew:ripgrep".to_string(),
                    version: None,
                },
                PackageSpec {
                    name: "cask:cursor".to_string(),
                    version: None,
                },
                PackageSpec {
                    name: "isotope:gh".to_string(),
                    version: None,
                },
                PackageSpec {
                    name: "pip:My_Package.Name".to_string(),
                    version: None,
                },
            ])
            .unwrap(),
            vec![
                "ripgrep".to_string(),
                "cursor".to_string(),
                "isotope:gh".to_string(),
                "pip:my-package-name".to_string()
            ]
        );
    }

    #[test]
    fn isotope_always_allow_validation_rejects_bad_inputs() {
        assert!(
            validate_isotope_keys(&[])
                .unwrap_err()
                .contains("at least one")
        );
        assert!(
            validate_isotope_keys(&["".to_string()])
                .unwrap_err()
                .contains("empty")
        );
        assert!(
            validate_isotope_keys(&["1BAD".to_string()])
                .unwrap_err()
                .contains("invalid")
        );
        assert!(validate_isotope_keys(&["GOOD_1".to_string()]).is_ok());

        assert!(
            validate_isotope_always_allow_script("/bin/sh", None, None)
                .unwrap_err()
                .contains("requires a script path")
        );
        assert!(
            validate_isotope_always_allow_script("/bin/echo", Some("/tmp/script"), None)
                .unwrap_err()
                .contains("requires an interpreter target")
        );
        assert_eq!(
            validate_isotope_always_allow_script("/bin/echo", None, None).unwrap(),
            None
        );
        assert!(
            validate_isotope_always_allow_script("/usr/bin/env", Some("/tmp/script"), None)
                .unwrap_err()
                .contains("env always-allow")
        );
        assert!(
            validate_isotope_always_allow_script("/bin/sh", Some("relative.sh"), None)
                .unwrap_err()
                .contains("must be absolute")
        );
        assert!(
            validate_isotope_always_allow_script("/bin/sh", Some("/tmp/missing-script"), Some("z"))
                .unwrap_err()
                .contains("64-character")
        );
    }

    #[test]
    fn isotope_always_allow_validates_non_root_script_sha() {
        let temp = TempDir::new().unwrap();
        let script = temp.path().join("tool.sh");
        fs::write(&script, b"#!/bin/sh\necho hi\n").unwrap();
        let sha = sha256_file(&script).unwrap();
        let script_path = script.to_string_lossy().into_owned();

        let validated =
            validate_isotope_always_allow_script("/bin/sh", Some(&script_path), Some(&sha))
                .unwrap()
                .unwrap();
        assert_eq!(
            validated.path,
            fs::canonicalize(&script)
                .unwrap()
                .to_string_lossy()
                .into_owned()
        );
        assert_eq!(validated.sha256.as_deref(), Some(sha.as_str()));

        let wrong_sha = "0".repeat(64);
        assert!(
            validate_isotope_always_allow_script("/bin/sh", Some(&script_path), Some(&wrong_sha))
                .unwrap_err()
                .contains("sha256 changed")
        );
        assert!(
            validate_isotope_always_allow_script("/bin/sh", Some(&script_path), None)
                .unwrap_err()
                .contains("requires a sha256")
        );
    }

    #[test]
    fn isotope_always_allow_target_and_store_helpers_cover_success_paths() {
        let validated_executable = validate_isotope_always_allow_target("/bin/sh").unwrap();
        let validated_script =
            validate_isotope_always_allow_script("/bin/sh", Some("/etc/profile"), None)
                .unwrap()
                .unwrap();
        assert_eq!(validated_executable, "/bin/sh");
        assert!(validated_script.path.ends_with("/etc/profile"));

        let temp = TempDir::new().unwrap();
        let path = temp.path().join("always-allow.json");

        let first = remember_isotope_always_allow_at_path(
            &path,
            validated_executable.clone(),
            Some(validated_script.path.clone()),
            None,
            vec!["AAA_TOKEN".to_string(), "ZZZ_TOKEN".to_string()],
        )
        .unwrap();
        assert!(first.processed_packages.is_empty());

        remember_isotope_always_allow_at_path(
            &path,
            "/bin/echo".to_string(),
            None,
            None,
            vec!["ONLY_TOKEN".to_string()],
        )
        .unwrap();
        remember_isotope_always_allow_at_path(
            &path,
            validated_executable,
            Some(validated_script.path),
            None,
            vec!["AAA_TOKEN".to_string(), "ZZZ_TOKEN".to_string()],
        )
        .unwrap();

        let store = load_isotope_always_allow_store(&path).unwrap();
        assert_eq!(store.entries.len(), 2);
        assert_eq!(store.entries[0].executable_path, "/bin/echo");
        assert_eq!(store.entries[1].executable_path, "/bin/sh");
        assert_eq!(
            store.entries[1].keys,
            vec!["AAA_TOKEN".to_string(), "ZZZ_TOKEN".to_string()]
        );
    }

    #[test]
    fn package_info_and_outdated_wrappers_cover_installed_formula_receipts() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let install_root = write_test_receipt(
            "ripgrep",
            "0.0.1",
            PackageReceiptSource::Formula {
                root_formula: "ripgrep".to_string(),
            },
        );

        let info = package_info("ripgrep").unwrap();
        assert!(info.installed);
        assert_eq!(info.package_name, "ripgrep");
        assert_eq!(info.installed_version, Some("0.0.1".to_string()));

        let outdated = list_outdated_packages().unwrap();
        assert!(outdated.packages.iter().any(|package| {
            package.name == "ripgrep"
                && package.current_version == "0.0.1"
                && package.latest_version != "0.0.1"
        }));

        remove_path(&install_root).unwrap();
    }

    #[test]
    fn make_package_default_root_rejects_non_formula_and_python_receipts() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let cask_root = write_test_receipt(
            "coverage-default-cask",
            "1.0.0",
            PackageReceiptSource::Cask {
                cask_name: "coverage-default-cask".to_string(),
            },
        );
        assert!(
            make_package_default_root("coverage-default-cask", None)
                .unwrap_err()
                .contains("is not a Homebrew formula")
        );

        let python_root = write_test_receipt(
            "python@3.14",
            "3.14.1",
            PackageReceiptSource::Formula {
                root_formula: "python@3.14".to_string(),
            },
        );
        assert!(
            make_package_default_root("python@3.14", None)
                .unwrap_err()
                .contains("Python uses side-by-side stubs")
        );

        remove_path(&cask_root).unwrap();
        remove_path(&python_root).unwrap();
    }

    #[test]
    fn make_package_default_requires_root_before_dispatching() {
        if !is_root() {
            assert!(
                make_package_default("ripgrep")
                    .unwrap_err()
                    .contains("must be run as root")
            );
        }
    }

    #[test]
    fn make_package_default_root_syncs_formula_stubs_and_reports_progress() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let formula_json = serde_json::to_vec(&serde_json::json!({
            "versions": { "stable": "14.1.1" },
            "dependencies": [],
            "bottle": {
                "stable": {
                    "files": {
                        "all": {
                            "sha256": "0".repeat(64),
                            "url": "https://example.invalid/ripgrep.tar.gz",
                        }
                    }
                }
            },
            "disabled": false
        }))
        .unwrap();
        let (base, server) =
            start_ops_test_http_server(vec![("/ripgrep.json".to_string(), formula_json)], 1);
        let _endpoint_guard = set_formula_api_root(base);
        let install_root = write_test_receipt(
            "ripgrep",
            "14.1.1",
            PackageReceiptSource::Formula {
                root_formula: "ripgrep".to_string(),
            },
        );
        fs::create_dir_all(install_root.join("bin")).unwrap();
        let rg = install_root.join("bin/rg");
        fs::write(&rg, b"#!/bin/sh\nprintf rg\n").unwrap();
        let mut permissions = fs::metadata(&rg).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&rg, permissions).unwrap();

        let events = Arc::new(Mutex::new(Vec::<ProgressEvent>::new()));
        let callback_events = Arc::clone(&events);
        let callback: Arc<Mutex<Box<ProgressCallback>>> =
            Arc::new(Mutex::new(Box::new(move |event| {
                callback_events.lock().unwrap().push(event);
            })));

        make_package_default_root("ripgrep", Some(callback)).unwrap();

        let events = events.lock().unwrap();
        assert!(events.iter().any(
            |event| matches!(event, ProgressEvent::Installing { package } if package == "ripgrep")
        ));
        assert!(events.iter().any(
            |event| matches!(event, ProgressEvent::Completed { package } if package == "ripgrep")
        ));
        drop(events);
        assert!(managed_bin_root().join("rg").exists());

        server.join().unwrap();
        remove_existing_package_install(&opt_pkg_root(), "ripgrep", &managed_bin_root()).unwrap();
        if install_root.exists() {
            remove_path(&install_root).unwrap();
        }
    }

    #[test]
    fn always_allow_store_reports_decode_errors() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("always-allow.json");
        fs::write(&path, b"{not json").unwrap();

        assert!(
            load_isotope_always_allow_store(&path)
                .unwrap_err()
                .contains("failed to decode")
        );
        assert_eq!(
            load_isotope_always_allow_store(&temp.path().join("missing.json")).unwrap(),
            IsotopeAlwaysAllowStore::default()
        );
    }
}
