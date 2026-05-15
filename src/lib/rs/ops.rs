use super::*;

const MAX_HELPER_PACKAGES: usize = 50;
const HELPER_AV_INSTALL_TARGET: &str = "/usr/local/bin/av";
const HELPER_CLI_INSTALL_TARGETS: [(&str, &str); 1] = [("av", "/usr/local/bin/av")];
const ISOTOPE_ALWAYS_ALLOW_PATH: &str =
    "/Library/Application Support/Automic Vault/isotope/always-allow.json";
const DEFAULT_SEARCH_PAGE_SIZE: usize = 100;
const MAX_SEARCH_PAGE_SIZE: usize = 200;
const HOMEBREW_CELLAR_PATH: &str = "/opt/homebrew/Cellar";
const HOMEBREW_CASKROOM_PATH: &str = "/opt/homebrew/Caskroom";
const HOMEBREW_BINARY_PATH: &str = "/opt/homebrew/bin/brew";

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
            keys,
        } => remember_isotope_always_allow(&executable_path, script_path.as_deref(), keys),
    };
    if let Err(err) = &result {
        if let Ok(mut callback) = progress_callback.lock() {
            callback(ProgressEvent::Error {
                message: err.clone(),
            });
        }
    }
    result
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct IsotopeAlwaysAllowEntry {
    executable_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    script_path: Option<String>,
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
        results.push(core::InstalledPackageSummary {
            name: receipt.package_name,
            source: receipt.source,
            version: receipt.version,
            description: receipt.metadata.description,
            installed_versions: Vec::new(),
            install_package_names: Vec::new(),
            security_state,
        });
    }

    Ok(core::ListInstalledResponse {
        packages: group_installed_versioned_formulae(results),
    })
}

fn group_installed_versioned_formulae(
    packages: Vec<core::InstalledPackageSummary>,
) -> Vec<core::InstalledPackageSummary> {
    let versioned_bases = packages
        .iter()
        .filter_map(|package| match &package.source {
            PackageReceiptSource::Formula { root_formula } => formula_versioned_base(&package.name)
                .or_else(|| formula_versioned_base(root_formula))
                .map(str::to_string),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut grouped: HashMap<String, Vec<core::InstalledPackageSummary>> = HashMap::new();
    let mut passthrough = Vec::new();
    for package in packages {
        let PackageReceiptSource::Formula { root_formula } = &package.source else {
            passthrough.push(package);
            continue;
        };
        let base = formula_versioned_base(&package.name)
            .or_else(|| formula_versioned_base(root_formula))
            .map(str::to_string);
        if let Some(base) = base {
            grouped.entry(base).or_default().push(package);
        } else if versioned_bases.contains(&package.name) {
            grouped
                .entry(package.name.clone())
                .or_default()
                .push(package);
        } else {
            passthrough.push(package);
        }
    }

    passthrough.extend(grouped.into_iter().map(|(base, mut versions)| {
        versions
            .sort_by(|left, right| compare_versioned_package_names_desc(&left.name, &right.name));
        let mut primary = versions
            .iter()
            .find(|package| package.name == base)
            .cloned()
            .unwrap_or_else(|| versions[0].clone());
        primary.name = base;
        primary.installed_versions = versions
            .iter()
            .map(|package| package.version.clone())
            .collect();
        primary.install_package_names = versions
            .iter()
            .map(|package| package.name.clone())
            .collect();
        primary
    }));
    passthrough
        .sort_by(|left, right| compare_package_names_for_search_order(&left.name, &right.name));
    passthrough
}

fn compare_versioned_package_names_desc(left: &str, right: &str) -> std::cmp::Ordering {
    let (left_base, left_version) = left.rsplit_once('@').unwrap_or((left, ""));
    let (right_base, right_version) = right.rsplit_once('@').unwrap_or((right, ""));
    left_base
        .cmp(right_base)
        .then_with(|| compare_version_suffixes(right_version, left_version))
        .then_with(|| right.cmp(left))
}

fn compare_version_suffixes(left: &str, right: &str) -> std::cmp::Ordering {
    let mut left_parts = left.split(['.', '_']).map(|part| part.parse::<u64>());
    let mut right_parts = right.split(['.', '_']).map(|part| part.parse::<u64>());
    loop {
        match (left_parts.next(), right_parts.next()) {
            (None, None) => return left.cmp(right),
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(Ok(left)), Some(Ok(right))) if left != right => return left.cmp(&right),
            (Some(Ok(_)), Some(Ok(_))) => continue,
            _ => return left.cmp(right),
        }
    }
}

pub(crate) fn list_available_packages(
    offset: usize,
    limit: usize,
) -> Result<core::SearchPackagesResponse, String> {
    let packages = resolve_available_package_results(&Config {
        bottle_tag: String::new(),
    })?;
    let limit = search_page_size(limit);
    let total_count = packages.len();
    let next_offset = packages.get(offset + limit).map(|_| offset + limit);
    let packages = packages
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(search_package_summary)
        .collect();
    Ok(core::SearchPackagesResponse {
        packages,
        total_count,
        next_offset,
    })
}

pub(crate) fn list_pulse_packages(
    offset: usize,
    limit: usize,
) -> Result<core::SearchPackagesResponse, String> {
    let packages = resolve_pulse_package_results(&Config {
        bottle_tag: String::new(),
    })?;
    let limit = search_page_size(limit);
    let total_count = packages.len();
    let next_offset = packages.get(offset + limit).map(|_| offset + limit);
    let packages = packages
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(search_package_summary)
        .collect();
    Ok(core::SearchPackagesResponse {
        packages,
        total_count,
        next_offset,
    })
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
    let limit = search_page_size(limit);
    let total_count = packages.len();
    let next_offset = packages.get(offset + limit).map(|_| offset + limit);
    let packages = packages
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(search_package_summary)
        .collect();
    Ok(core::SearchPackagesResponse {
        packages,
        total_count,
        next_offset,
    })
}

fn search_page_size(limit: usize) -> usize {
    match limit {
        0 => DEFAULT_SEARCH_PAGE_SIZE,
        _ => limit.min(MAX_SEARCH_PAGE_SIZE),
    }
}

fn search_package_summary(package: PackageSearchResult) -> core::SearchPackageSummary {
    let qualified_name = package_source_qualified_name(&package.source);
    let security_state =
        package_security_state_for_identifiers([package.package_name.clone(), qualified_name]);
    core::SearchPackageSummary {
        name: package.package_name,
        source: package.source,
        version: package.latest_version,
        description: package.summary,
        pulse_kind: package.pulse_kind,
        security_state,
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

pub(crate) fn homebrew_migration_recommendation()
-> Result<core::HomebrewMigrationRecommendationResponse, String> {
    if !homebrew_package_root_has_packages(Path::new(HOMEBREW_CELLAR_PATH))?
        && !homebrew_package_root_has_packages(Path::new(HOMEBREW_CASKROOM_PATH))?
    {
        return Ok(core::HomebrewMigrationRecommendationResponse {
            packages: Vec::new(),
            hazards: Vec::new(),
        });
    }

    let packages = explicitly_installed_homebrew_packages()?;
    let hazards = packages
        .iter()
        .filter_map(|package| homebrew_migration_hazard_for_package(&package.name))
        .collect();

    Ok(core::HomebrewMigrationRecommendationResponse { packages, hazards })
}

fn homebrew_package_root_has_packages(root: &Path) -> Result<bool, String> {
    match fs::read_dir(root) {
        Ok(entries) => {
            for entry in entries {
                let entry =
                    entry.map_err(|err| format!("failed to read {}: {err}", root.display()))?;
                let name = entry.file_name();
                if name.to_string_lossy().starts_with('.') {
                    continue;
                }
                if entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!("failed to read {}: {err}", root.display())),
    }
}

fn explicitly_installed_homebrew_packages()
-> Result<Vec<core::HomebrewMigrationPackageSummary>, String> {
    let output = Command::new(HOMEBREW_BINARY_PATH)
        .args(["info", "--json=v2", "--installed"])
        .output()
        .map_err(|err| format!("failed to run {HOMEBREW_BINARY_PATH}: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "{HOMEBREW_BINARY_PATH} info failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let report: HomebrewInfoReport = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse Homebrew package inventory: {err}"))?;
    let mut packages = homebrew_migration_packages_from_report(report);
    packages.sort_by(|left, right| compare_package_names_for_search_order(&left.name, &right.name));
    packages.dedup_by(|left, right| left.name == right.name);
    Ok(packages)
}

fn homebrew_migration_packages_from_report(
    report: HomebrewInfoReport,
) -> Vec<core::HomebrewMigrationPackageSummary> {
    let formulae = report
        .formulae
        .into_iter()
        .filter(HomebrewInfoFormula::is_installed_on_request)
        .map(|formula| {
            let is_migratable = formula.is_migratable();
            let name = format!("{BREW_PACKAGE_PREFIX}{}", formula.migration_display_name());
            let security_state =
                homebrew_migration_security_state_for_package(&name, &[formula.name.as_str()]);
            core::HomebrewMigrationPackageSummary {
                name,
                version: formula
                    .installed
                    .iter()
                    .find(|install| install.installed_on_request)
                    .and_then(|install| empty_string_as_none(install.version.clone())),
                description: empty_string_as_none(formula.description),
                tap: empty_string_as_none(formula.tap),
                is_migratable,
                security_state,
            }
        });
    let casks = report.casks.into_iter().filter_map(|cask| {
        let name = empty_string_as_none(cask.token)?;
        if embedded_cask(&name).is_err() {
            return None;
        }
        let name = crate::cask::qualified_name(&name);
        let security_state = homebrew_migration_security_state_for_package(&name, &[]);
        Some(core::HomebrewMigrationPackageSummary {
            name,
            version: empty_string_as_none(cask.version),
            description: empty_string_as_none(cask.description),
            tap: None,
            is_migratable: true,
            security_state,
        })
    });

    formulae.chain(casks).collect()
}

fn homebrew_migration_security_state_for_package(
    package_name: &str,
    additional_identifiers: &[&str],
) -> Option<PackageSecurityState> {
    let mut identifiers = vec![package_name.to_string()];
    if let Some(cask) = package_name.strip_prefix(CASK_PACKAGE_PREFIX) {
        identifiers.push(cask.to_string());
    } else if let Some(formula) = package_name.strip_prefix(BREW_PACKAGE_PREFIX) {
        identifiers.push(formula.to_string());
    } else {
        identifiers.push(format!("{BREW_PACKAGE_PREFIX}{package_name}"));
    }
    identifiers.extend(
        additional_identifiers
            .iter()
            .map(|identifier| identifier.to_string()),
    );
    package_security_state_for_identifiers(identifiers)
}

fn homebrew_migration_hazard_for_package(
    package_name: &str,
) -> Option<core::HomebrewMigrationHazardSummary> {
    let state = homebrew_migration_security_state_for_package(package_name, &[])?;
    if !state.install_is_insecure && state.error.is_none() {
        return None;
    }
    Some(core::HomebrewMigrationHazardSummary {
        package_name: package_name.to_string(),
        isotope_name: state.isotope_name,
        reasons: state.reasons,
        error: state.error,
    })
}

fn empty_string_as_none(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

#[derive(Debug, Deserialize)]
struct HomebrewInfoReport {
    #[serde(default)]
    formulae: Vec<HomebrewInfoFormula>,
    #[serde(default)]
    casks: Vec<HomebrewInfoCask>,
}

#[derive(Debug, Deserialize)]
struct HomebrewInfoFormula {
    name: String,
    #[serde(default)]
    full_name: String,
    #[serde(default)]
    tap: String,
    #[serde(default, rename = "desc")]
    description: String,
    #[serde(default)]
    installed: Vec<HomebrewInfoInstall>,
}

impl HomebrewInfoFormula {
    fn is_installed_on_request(&self) -> bool {
        self.installed
            .iter()
            .any(|install| install.installed_on_request)
    }

    fn is_migratable(&self) -> bool {
        self.tap.is_empty() || self.tap == "homebrew/core"
    }

    fn migration_display_name(&self) -> &str {
        if self.is_migratable() {
            return &self.name;
        }
        if self.full_name.contains('/') {
            return &self.full_name;
        }
        &self.name
    }
}

#[derive(Debug, Deserialize)]
struct HomebrewInfoInstall {
    #[serde(default)]
    version: String,
    #[serde(default)]
    installed_on_request: bool,
}

#[derive(Debug, Deserialize)]
struct HomebrewInfoCask {
    #[serde(default)]
    token: String,
    #[serde(default, rename = "desc")]
    description: String,
    #[serde(default)]
    version: String,
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
                allow_reinstall: false,
            },
            Some(progress_callback.clone()),
        )?;
    }

    Ok(HelperCommandSuccess {
        message: "Install complete".to_string(),
        processed_packages,
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
                allow_reinstall: true,
            },
            Some(progress_callback.clone()),
        )?;
    }

    Ok(HelperCommandSuccess {
        message: "Update complete".to_string(),
        processed_packages,
    })
}

fn update_all_packages(
    progress_callback: Arc<Mutex<Box<ProgressCallback>>>,
) -> HelperCommandResult {
    require_root()?;
    let _lock = acquire_package_mutation_lock()?;
    let config = load_config()?;
    let outdated = resolve_outdated_package_statuses(&config, &PackageSelection::AllInstalled)?;
    let processed_packages = outdated
        .iter()
        .map(|package| package.package_name.clone())
        .collect::<Vec<_>>();

    for package in outdated {
        run_i_package_with_progress(
            &config,
            requested_package_from_status(&package),
            InstallOptions {
                allow_reinstall: true,
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
        false,
        Some(progress_callback),
    )?;
    Ok(HelperCommandSuccess {
        message: "Isotope conversion complete".to_string(),
        processed_packages: vec![package_name],
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
    })
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
    let Some(expected) = required_codesign_identity()? else {
        return Ok(());
    };

    match authorities.first() {
        Some(actual) if actual == expected => Ok(()),
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
    if !output.status.success() {
        let stderr_lines = String::from_utf8_lossy(&output.stderr)
            .lines()
            .map(str::to_string)
            .collect::<Vec<_>>();
        return Err(format!(
            "failed to inspect code signature for {}{}",
            path.display(),
            format_command_output_suffix(&stderr_lines)
        ));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
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
    mut keys: Vec<String>,
) -> HelperCommandResult {
    require_root()?;
    let executable_path = validate_isotope_always_allow_target(executable_path)?;
    let script_path = validate_isotope_always_allow_script(&executable_path, script_path)?;
    validate_isotope_keys(&keys)?;
    keys.sort();
    keys.dedup();

    let path = Path::new(ISOTOPE_ALWAYS_ALLOW_PATH);
    let mut store = load_isotope_always_allow_store(path)?;
    if !store.entries.iter().any(|entry| {
        entry.executable_path == executable_path
            && entry.script_path == script_path
            && entry.keys == keys
    }) {
        store.entries.push(IsotopeAlwaysAllowEntry {
            executable_path: executable_path.clone(),
            script_path: script_path.clone(),
            keys,
        });
        store.entries.sort_by(|left, right| {
            left.executable_path
                .cmp(&right.executable_path)
                .then_with(|| left.script_path.cmp(&right.script_path))
                .then_with(|| left.keys.cmp(&right.keys))
        });
        write_isotope_always_allow_store(path, &store)?;
    }

    Ok(HelperCommandSuccess {
        message: "Isotope always-allow remembered".to_string(),
        processed_packages: Vec::new(),
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
) -> Result<Option<String>, String> {
    let is_interpreter = is_isotope_script_interpreter(Path::new(executable_path));
    match (is_interpreter, script_path.filter(|path| !path.is_empty())) {
        (true, Some(script_path)) => validate_isotope_always_allow_target(script_path).map(Some),
        (true, None) => Err("isotope interpreter target requires a script path".to_string()),
        (false, Some(_)) => Err("isotope script path requires an interpreter target".to_string()),
        (false, None) => Ok(None),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn write_test_receipt(
        package_name: &str,
        version: &str,
        source: PackageReceiptSource,
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
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        install_root
    }

    #[test]
    fn homebrew_info_formula_reads_nested_on_request_flag() {
        let report: HomebrewInfoReport = serde_json::from_value(serde_json::json!({
            "formulae": [
                {
                    "name": "dependency",
                    "installed": [
                        {
                            "version": "1.0.0",
                            "installed_on_request": false
                        }
                    ]
                },
                {
                    "name": "explicit",
                    "installed": [
                        {
                            "version": "2.0.0",
                            "installed_on_request": true
                        }
                    ]
                }
            ]
        }))
        .unwrap();

        let explicit = report
            .formulae
            .iter()
            .filter(|formula| formula.is_installed_on_request())
            .map(|formula| formula.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(explicit, vec!["explicit"]);
    }

    #[test]
    fn homebrew_migration_packages_include_supported_casks_without_on_request_flag() {
        let report: HomebrewInfoReport = serde_json::from_value(serde_json::json!({
            "formulae": [
                {
                    "name": "dependency",
                    "desc": "Dependency formula",
                    "installed": [
                        {
                            "version": "1.0.0",
                            "installed_on_request": false
                        }
                    ]
                },
                {
                    "name": "explicit",
                    "full_name": "explicit",
                    "tap": "homebrew/core",
                    "desc": "Explicit formula",
                    "installed": [
                        {
                            "version": "2.0.0",
                            "installed_on_request": true
                        }
                    ]
                },
                {
                    "name": "custom",
                    "full_name": "example/tap/custom",
                    "tap": "example/tap",
                    "desc": "Tapped formula",
                    "installed": [
                        {
                            "version": "9.0.0",
                            "installed_on_request": true
                        }
                    ]
                },
                {
                    "name": "tapped-dependency",
                    "full_name": "example/tap/tapped-dependency",
                    "tap": "example/tap",
                    "desc": "Tapped dependency",
                    "installed": [
                        {
                            "version": "8.0.0",
                            "installed_on_request": false
                        }
                    ]
                }
            ],
            "casks": [
                {
                    "token": "codex",
                    "desc": "Codex CLI",
                    "version": "3.0.0"
                },
                {
                    "token": "unsupported-cask",
                    "desc": "Unsupported cask",
                    "version": "4.0.0"
                }
            ]
        }))
        .unwrap();

        let mut packages = homebrew_migration_packages_from_report(report);
        packages
            .sort_by(|left, right| compare_package_names_for_search_order(&left.name, &right.name));

        assert_eq!(
            packages,
            vec![
                core::HomebrewMigrationPackageSummary {
                    name: "cask:codex".to_string(),
                    version: Some("3.0.0".to_string()),
                    description: Some("Codex CLI".to_string()),
                    tap: None,
                    is_migratable: true,
                    security_state: homebrew_migration_security_state_for_package(
                        "cask:codex",
                        &[]
                    ),
                },
                core::HomebrewMigrationPackageSummary {
                    name: "brew:example/tap/custom".to_string(),
                    version: Some("9.0.0".to_string()),
                    description: Some("Tapped formula".to_string()),
                    tap: Some("example/tap".to_string()),
                    is_migratable: false,
                    security_state: homebrew_migration_security_state_for_package(
                        "brew:example/tap/custom",
                        &["custom"],
                    ),
                },
                core::HomebrewMigrationPackageSummary {
                    name: "brew:explicit".to_string(),
                    version: Some("2.0.0".to_string()),
                    description: Some("Explicit formula".to_string()),
                    tap: Some("homebrew/core".to_string()),
                    is_migratable: true,
                    security_state: homebrew_migration_security_state_for_package(
                        "brew:explicit",
                        &["explicit"],
                    ),
                },
            ]
        );
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
        let store = IsotopeAlwaysAllowStore {
            entries: vec![IsotopeAlwaysAllowEntry {
                executable_path: "/opt/awscli/bin/python3.14".to_string(),
                script_path: Some("/opt/awscli/bin/aws".to_string()),
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
    fn versioned_package_name_sort_places_newer_versions_first() {
        let mut packages = vec![
            "python@3.13".to_string(),
            "python@3.14".to_string(),
            "python@3.9".to_string(),
        ];
        packages.sort_by(|left, right| compare_versioned_package_names_desc(left, right));
        assert_eq!(packages, ["python@3.14", "python@3.13", "python@3.9"]);
    }

    #[test]
    fn grouped_versioned_formulae_report_versions_separately_from_package_names() {
        let grouped = group_installed_versioned_formulae(vec![
            installed_formula_summary("python@3.13", "3.13.9"),
            installed_formula_summary("python@3.14", "3.14.1"),
        ]);

        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].name, "python");
        assert_eq!(grouped[0].installed_versions, ["3.14.1", "3.13.9"]);
        assert_eq!(
            grouped[0].install_package_names,
            ["python@3.14", "python@3.13"]
        );
    }

    #[test]
    fn list_installed_packages_groups_versioned_formulae_and_keeps_other_sources() {
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
            write_test_receipt(
                "coverage-cask",
                "1.0.0",
                PackageReceiptSource::Cask {
                    cask_name: "coverage-cask".to_string(),
                },
            ),
        ];

        let packages = list_installed_packages().unwrap().packages;
        let grouped = packages
            .iter()
            .find(|package| package.name == "coverage-python")
            .unwrap();
        assert_eq!(grouped.installed_versions, ["3.14.1", "3.13.9"]);
        assert_eq!(
            grouped.install_package_names,
            ["coverage-python@3.14", "coverage-python@3.13"]
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

        for root in roots {
            remove_path(&root).unwrap();
        }
    }

    #[test]
    fn grouped_versioned_formulae_prefers_unversioned_primary_and_sorted_passthrough() {
        let grouped = group_installed_versioned_formulae(vec![
            installed_formula_summary("python@3.12", "3.12.11"),
            installed_formula_summary("python", "3.14.2"),
            installed_formula_summary("python@3.14", "3.14.2"),
            core::InstalledPackageSummary {
                name: "codex".to_string(),
                source: PackageReceiptSource::Cask {
                    cask_name: "codex".to_string(),
                },
                version: "1.0.0".to_string(),
                description: Some("Codex".to_string()),
                installed_versions: Vec::new(),
                install_package_names: Vec::new(),
                security_state: None,
            },
        ]);

        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[0].name, "codex");
        assert_eq!(grouped[1].name, "python");
        assert_eq!(grouped[1].version, "3.14.2");
        assert_eq!(grouped[1].installed_versions, ["3.14.2", "3.12.11", "3.14.2"]);
        assert_eq!(
            grouped[1].install_package_names,
            ["python@3.14", "python@3.12", "python"]
        );
    }

    fn installed_formula_summary(name: &str, version: &str) -> core::InstalledPackageSummary {
        core::InstalledPackageSummary {
            name: name.to_string(),
            source: PackageReceiptSource::Formula {
                root_formula: name.to_string(),
            },
            version: version.to_string(),
            description: None,
            installed_versions: Vec::new(),
            install_package_names: Vec::new(),
            security_state: None,
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

        let default_page = list_available_packages(0, 0).unwrap();
        assert!(default_page.total_count >= default_page.packages.len());
        assert!(default_page.packages.len() <= DEFAULT_SEARCH_PAGE_SIZE);

        let capped_page = list_available_packages(0, usize::MAX).unwrap();
        assert!(capped_page.packages.len() <= MAX_SEARCH_PAGE_SIZE);

        let past_end = search_packages("rg", usize::MAX / 2, 1).unwrap();
        assert!(past_end.packages.is_empty());
        assert_eq!(past_end.next_offset, None);

        let pulse = list_pulse_packages(0, 1).unwrap();
        assert_eq!(pulse.packages.len(), 1);
        assert!(pulse.next_offset.is_some());
    }

    #[test]
    fn validation_helpers_cover_limits_versions_and_isotope_names() {
        assert_eq!(search_page_size(0), DEFAULT_SEARCH_PAGE_SIZE);
        assert_eq!(search_page_size(1), 1);
        assert_eq!(search_page_size(usize::MAX), MAX_SEARCH_PAGE_SIZE);

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
    fn compare_version_suffixes_covers_numeric_and_text_paths() {
        assert_eq!(
            compare_version_suffixes("3.14.1", "3.14.1"),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            compare_version_suffixes("3.14", "3.14.1"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_version_suffixes("3.14.1", "3.14"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_version_suffixes("3.14_a", "3.14_b"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_version_suffixes("3.14.beta", "3.14.1"),
            "3.14.beta".cmp("3.14.1")
        );
    }

    #[test]
    fn homebrew_package_root_checks_cover_missing_hidden_and_present_dirs() {
        let temp = TempDir::new().unwrap();
        let missing = temp.path().join("missing");
        assert!(!homebrew_package_root_has_packages(&missing).unwrap());

        let hidden_only = temp.path().join("hidden-only");
        fs::create_dir_all(hidden_only.join(".cache")).unwrap();
        fs::write(hidden_only.join("README.txt"), "note").unwrap();
        assert!(!homebrew_package_root_has_packages(&hidden_only).unwrap());

        let visible = temp.path().join("visible");
        fs::create_dir_all(visible.join("rg")).unwrap();
        assert!(homebrew_package_root_has_packages(&visible).unwrap());
    }

    #[test]
    fn homebrew_migration_packages_skip_empty_tokens_and_unsupported_casks() {
        let report: HomebrewInfoReport = serde_json::from_value(serde_json::json!({
            "formulae": [
                {
                    "name": "dependency-only",
                    "desc": "",
                    "installed": [
                        {
                            "version": "1.0.0",
                            "installed_on_request": false
                        }
                    ]
                },
                {
                    "name": "uv",
                    "full_name": "uv",
                    "tap": "",
                    "desc": "",
                    "installed": [
                        {
                            "version": "",
                            "installed_on_request": true
                        }
                    ]
                }
            ],
            "casks": [
                {
                    "token": "",
                    "desc": "Skipped empty token",
                    "version": "1.0.0"
                },
                {
                    "token": "unsupported-cask",
                    "desc": "Unsupported cask",
                    "version": "2.0.0"
                },
                {
                    "token": "codex",
                    "desc": "",
                    "version": ""
                }
            ]
        }))
        .unwrap();

        let packages = homebrew_migration_packages_from_report(report);
        assert_eq!(packages.len(), 2);
        assert!(packages.iter().any(|package| {
            package.name == "brew:uv"
                && package.version.is_none()
                && package.description.is_none()
                && package.tap.is_none()
        }));
        assert!(packages.iter().any(|package| {
            package.name == "cask:codex"
                && package.version.is_none()
                && package.description.is_none()
                && package.is_migratable
        }));
    }

    #[test]
    fn homebrew_migration_helper_metadata_and_security_paths_are_stable() {
        let tapped = HomebrewInfoFormula {
            name: "mise".to_string(),
            full_name: "jdx/mise/mise".to_string(),
            tap: "jdx/mise".to_string(),
            description: "Runtime manager".to_string(),
            installed: vec![HomebrewInfoInstall {
                version: "2026.5.0".to_string(),
                installed_on_request: true,
            }],
        };
        assert!(tapped.is_installed_on_request());
        assert!(!tapped.is_migratable());
        assert_eq!(tapped.migration_display_name(), "jdx/mise/mise");

        let untapped = HomebrewInfoFormula {
            name: "uv".to_string(),
            full_name: "uv".to_string(),
            tap: String::new(),
            description: String::new(),
            installed: vec![HomebrewInfoInstall {
                version: String::new(),
                installed_on_request: false,
            }],
        };
        assert!(!untapped.is_installed_on_request());
        assert!(untapped.is_migratable());
        assert_eq!(untapped.migration_display_name(), "uv");

        assert_eq!(empty_string_as_none(String::new()), None);
        assert_eq!(
            empty_string_as_none("kept".to_string()),
            Some("kept".to_string())
        );

        let gh_security_state = crate::package_security_state_for_isotope("gh");
        assert_eq!(
            homebrew_migration_security_state_for_package("brew:gh", &[]),
            gh_security_state
        );
        assert_eq!(
            homebrew_migration_security_state_for_package("gh", &[]),
            gh_security_state
        );
        assert_eq!(homebrew_migration_hazard_for_package("brew:gh"), None);

        let info = system_info();
        assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(info.protocol_version, core::PROTOCOL_VERSION);
        assert_eq!(info.build_id, env!("NUKE_BUILD_ID"));
    }

    #[test]
    fn homebrew_migration_packages_preserve_tapped_formula_metadata() {
        let report: HomebrewInfoReport = serde_json::from_value(serde_json::json!({
            "formulae": [
                {
                    "name": "mise",
                    "full_name": "jdx/mise/mise",
                    "tap": "jdx/mise",
                    "desc": "Runtime manager",
                    "installed": [
                        {
                            "version": "2026.5.0",
                            "installed_on_request": true
                        }
                    ]
                }
            ],
            "casks": [
                {
                    "token": "codex",
                    "desc": "OpenAI Codex",
                    "version": "0.1.0"
                }
            ]
        }))
        .unwrap();

        let packages = homebrew_migration_packages_from_report(report);
        assert_eq!(packages.len(), 2);
        assert!(packages.iter().any(|package| {
            package.name == "brew:jdx/mise/mise"
                && package.version.as_deref() == Some("2026.5.0")
                && package.description.as_deref() == Some("Runtime manager")
                && package.tap.as_deref() == Some("jdx/mise")
                && !package.is_migratable
        }));
        assert!(packages.iter().any(|package| {
            package.name == "cask:codex"
                && package.version.as_deref() == Some("0.1.0")
                && package.description.as_deref() == Some("OpenAI Codex")
                && package.tap.is_none()
                && package.is_migratable
        }));
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
            validate_isotope_always_allow_script("/bin/sh", None)
                .unwrap_err()
                .contains("requires a script path")
        );
        assert!(
            validate_isotope_always_allow_script("/bin/echo", Some("/tmp/script"))
                .unwrap_err()
                .contains("requires an interpreter target")
        );
        assert_eq!(
            validate_isotope_always_allow_script("/bin/echo", None).unwrap(),
            None
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

fn require_root() -> Result<(), String> {
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
    })
}

pub(crate) fn make_package_default(package: &str) -> Result<HelperCommandSuccess, String> {
    require_root()?;
    let package_name = crate::cli::parse_uninstall_package_name(&OsString::from(package))?;
    make_package_default_root(&package_name, None)?;
    Ok(HelperCommandSuccess {
        message: "Package default updated".to_string(),
        processed_packages: vec![package_name],
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
        | RequestedPackage::Alias { .. }
        | RequestedPackage::HomebrewFormula(_)
        | RequestedPackage::HomebrewCask(_)
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
