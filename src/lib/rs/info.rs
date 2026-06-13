use super::*;

pub(crate) const INFO_WIDTH: usize = 64;
pub(crate) const INFO_INNER_WIDTH: usize = INFO_WIDTH - 2;
pub(crate) const INFO_LABEL_WIDTH: usize = 14;
const PULSE_NEW_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;
const HOMEBREW_INSTALL_RECEIPT: &str = "INSTALL_RECEIPT.json";

pub(crate) fn load_config() -> Result<Config, String> {
    let bottle_tag = current_bottle_tag()?;
    Ok(Config { bottle_tag })
}

impl PackageStatus {
    pub(crate) fn is_outdated(&self) -> bool {
        self.installed_version != self.latest_version
    }
}

pub(crate) fn compare_package_names_for_search_order(
    left: &str,
    right: &str,
) -> std::cmp::Ordering {
    package_search_order_name(left)
        .cmp(package_search_order_name(right))
        .then_with(|| left.cmp(right))
}

fn package_search_order_name(package_name: &str) -> &str {
    for prefix in [
        BREW_PACKAGE_PREFIX,
        CASK_PACKAGE_PREFIX,
        ISOTOPE_PACKAGE_PREFIX,
        VENDOR_PACKAGE_PREFIX,
        "npm:",
        "pip:",
    ] {
        if let Some(name) = package_name.strip_prefix(prefix) {
            return package_scope_order_name(name);
        }
    }
    package_scope_order_name(package_name)
}

fn package_scope_order_name(package_name: &str) -> &str {
    if let Some(scoped_name) = package_name.strip_prefix('@')
        && let Some((_, name)) = scoped_name.split_once('/')
    {
        return name;
    }
    package_name
}

pub(crate) fn resolve_package_statuses(
    config: &Config,
    selection: &PackageSelection,
) -> Result<Vec<PackageStatus>, String> {
    match selection {
        PackageSelection::AllInstalled => resolve_scanned_package_statuses(
            installed_package_refs(&opt_pkg_root())?,
            |package| {
                resolve_package_status_at(config, &package.package_name, &package.install_root)
            },
            |message| eprintln!("{message}"),
        ),
        PackageSelection::Requested(packages) => {
            let mut package_names = Vec::with_capacity(packages.len());
            for package in packages {
                package_names.push(requested_install_package_name(package)?);
            }
            package_names.sort();
            package_names.dedup();

            let mut statuses = Vec::with_capacity(package_names.len());
            for package_name in package_names {
                statuses.push(resolve_package_status(config, &package_name)?);
            }
            Ok(statuses)
        }
    }
}

pub(crate) fn resolve_installed_package_records(
    selection: &PackageSelection,
) -> Result<Vec<InstalledPackageRecord>, String> {
    match selection {
        PackageSelection::AllInstalled => resolve_scanned_package_records(
            installed_package_refs(&opt_pkg_root())?,
            |package| {
                resolve_installed_package_record_at(&package.package_name, &package.install_root)
            },
            |message| eprintln!("{message}"),
        ),
        PackageSelection::Requested(packages) => {
            let mut package_names = Vec::with_capacity(packages.len());
            for package in packages {
                package_names.push(requested_install_package_name(package)?);
            }
            package_names.sort();
            package_names.dedup();

            let mut records = Vec::with_capacity(package_names.len());
            for package_name in package_names {
                records.push(resolve_installed_package_record(&package_name)?);
            }
            Ok(records)
        }
    }
}

pub(crate) fn resolve_outdated_package_statuses(
    config: &Config,
    selection: &PackageSelection,
) -> Result<Vec<PackageStatus>, String> {
    Ok(filter_outdated_package_statuses(resolve_package_statuses(
        config, selection,
    )?))
}

pub(crate) fn resolve_update_package_statuses(
    config: &Config,
    selection: &PackageSelection,
) -> Result<Vec<PackageStatus>, String> {
    Ok(filter_update_package_statuses(resolve_package_statuses(
        config, selection,
    )?))
}

pub(crate) fn filter_outdated_package_statuses(statuses: Vec<PackageStatus>) -> Vec<PackageStatus> {
    statuses
        .into_iter()
        .filter(PackageStatus::is_outdated)
        .collect()
}

pub(crate) fn filter_update_package_statuses(statuses: Vec<PackageStatus>) -> Vec<PackageStatus> {
    statuses
        .into_iter()
        .filter(|status| status.is_outdated() || status_has_radioisotope_remediation(status))
        .collect()
}

fn status_has_radioisotope_remediation(status: &PackageStatus) -> bool {
    match &status.source {
        PackageReceiptSource::Isotope { isotope_name } => isotope_has_post_install(isotope_name),
        _ => false,
    }
}

pub(crate) fn resolve_scanned_package_records<Resolve, Warn>(
    mut packages: Vec<InstalledPackageRef>,
    mut resolve: Resolve,
    mut warn: Warn,
) -> Result<Vec<InstalledPackageRecord>, String>
where
    Resolve: FnMut(&InstalledPackageRef) -> Result<InstalledPackageRecord, String>,
    Warn: FnMut(String),
{
    packages.sort_by(|left, right| {
        compare_package_names_for_search_order(&left.package_name, &right.package_name)
    });
    packages.dedup_by(|left, right| left.package_name == right.package_name);

    let mut records = Vec::with_capacity(packages.len());
    for package in packages {
        match resolve(&package) {
            Ok(record) => records.push(record),
            Err(err) => warn(format!(
                "warning: skipping {}: {err}",
                package.install_root.display()
            )),
        }
    }
    Ok(records)
}

pub(crate) fn resolve_scanned_package_statuses<Resolve, Warn>(
    mut packages: Vec<InstalledPackageRef>,
    mut resolve: Resolve,
    mut warn: Warn,
) -> Result<Vec<PackageStatus>, String>
where
    Resolve: FnMut(&InstalledPackageRef) -> Result<PackageStatus, String>,
    Warn: FnMut(String),
{
    packages.sort_by(|left, right| {
        compare_package_names_for_search_order(&left.package_name, &right.package_name)
    });
    packages.dedup_by(|left, right| left.package_name == right.package_name);

    let mut statuses = Vec::with_capacity(packages.len());
    for package in packages {
        match resolve(&package) {
            Ok(status) => statuses.push(status),
            Err(err) => warn(format!(
                "warning: skipping {}: {err}",
                package.install_root.display()
            )),
        }
    }
    Ok(statuses)
}

pub(crate) fn resolve_installed_package_record(
    package_name: &str,
) -> Result<InstalledPackageRecord, String> {
    let install_root = package_install_root(&opt_pkg_root(), package_name)?;
    resolve_installed_package_record_at(package_name, &install_root)
}

pub(crate) fn resolve_package_status(
    config: &Config,
    package_name: &str,
) -> Result<PackageStatus, String> {
    let install_root = package_install_root(&opt_pkg_root(), package_name)?;
    resolve_package_status_at(config, package_name, &install_root)
}

pub(crate) fn resolve_installed_package_record_at(
    package_name: &str,
    install_root: &Path,
) -> Result<InstalledPackageRecord, String> {
    let metadata = fs::symlink_metadata(install_root).map_err(|err| match err.kind() {
        std::io::ErrorKind::NotFound => format!("package {package_name} is not installed"),
        _ => format!("failed to stat {}: {err}", install_root.display()),
    })?;
    if !metadata.is_dir() {
        return Err(format!(
            "installed package root {} is not a directory",
            install_root.display()
        ));
    }

    let receipt = load_or_resolve_package_receipt(package_name, install_root)?;
    Ok(InstalledPackageRecord {
        package_name: receipt.package_name,
        source: receipt.source,
        installed_version: receipt.version,
    })
}

pub(crate) fn resolve_package_status_at(
    config: &Config,
    package_name: &str,
    install_root: &Path,
) -> Result<PackageStatus, String> {
    let metadata = fs::symlink_metadata(install_root).map_err(|err| match err.kind() {
        std::io::ErrorKind::NotFound => format!("package {package_name} is not installed"),
        _ => format!("failed to stat {}: {err}", install_root.display()),
    })?;
    if !metadata.is_dir() {
        return Err(format!(
            "installed package root {} is not a directory",
            install_root.display()
        ));
    }

    let record = resolve_installed_package_record_at(package_name, install_root)?;
    let latest_version = resolve_latest_version_for_source(config, &record.source)?;

    Ok(PackageStatus {
        package_name: record.package_name,
        source: record.source,
        installed_version: record.installed_version,
        latest_version,
    })
}

pub(crate) fn requested_package_name(package: &RequestedPackage) -> String {
    match package {
        RequestedPackage::Auto(package_name)
        | RequestedPackage::HomebrewFormula(package_name)
        | RequestedPackage::HomebrewCask(package_name)
        | RequestedPackage::VendorPackage(package_name) => package_name.clone(),
        RequestedPackage::Isotope(package_name) => {
            format!("{ISOTOPE_PACKAGE_PREFIX}{package_name}")
        }
        RequestedPackage::NpmPackage { package, .. } => npm_package_display_name(package),
        RequestedPackage::PipPackage(package_name) => pip_package_display_name(package_name),
    }
}

pub(crate) fn requested_install_package_name(package: &RequestedPackage) -> Result<String, String> {
    match package {
        RequestedPackage::Auto(package_name) => {
            if let Some(isotope_name) = preferred_auto_isotope_name(package_name)? {
                return Ok(isotope_qualified_name(&isotope_name));
            }
            if vendor::get(package_name).is_some() {
                return Ok(package_name.clone());
            }
            if let Some(provider_name) = embedded_provider_install_package_name(package_name)? {
                return Ok(provider_name);
            }
            let formula = formula_install_package_name(package_name)?;
            if formula != *package_name {
                return Ok(formula);
            }
            Ok(package_name.clone())
        }
        RequestedPackage::HomebrewFormula(formula) => formula_install_package_name(formula),
        RequestedPackage::HomebrewCask(cask) => Ok(cask.clone()),
        RequestedPackage::VendorPackage(package_name) => Ok(package_name.clone()),
        RequestedPackage::Isotope(package_name) => {
            Ok(format!("{ISOTOPE_PACKAGE_PREFIX}{package_name}"))
        }
        RequestedPackage::NpmPackage { package, .. } => Ok(npm_package_display_name(package)),
        RequestedPackage::PipPackage(package_name) => Ok(pip_package_display_name(package_name)),
    }
}

pub(crate) fn requested_package_from_status(status: &PackageStatus) -> RequestedPackage {
    match &status.source {
        PackageReceiptSource::Formula { root_formula } if status.package_name == *root_formula => {
            RequestedPackage::HomebrewFormula(root_formula.clone())
        }
        PackageReceiptSource::Cask { cask_name } if status.package_name == *cask_name => {
            RequestedPackage::HomebrewCask(cask_name.clone())
        }
        PackageReceiptSource::Vendor { vendor_name } if status.package_name == *vendor_name => {
            RequestedPackage::VendorPackage(vendor_name.clone())
        }
        PackageReceiptSource::Isotope { isotope_name } => {
            RequestedPackage::Isotope(isotope_name.clone())
        }
        PackageReceiptSource::Npm { package_name } => RequestedPackage::NpmPackage {
            package: package_name.clone(),
            version: None,
        },
        PackageReceiptSource::Pip { package_name } => {
            RequestedPackage::PipPackage(package_name.clone())
        }
        _ => RequestedPackage::Auto(status.package_name.clone()),
    }
}

pub(crate) fn resolve_package_info(
    config: &Config,
    requested: &RequestedPackage,
) -> Result<PackageInfo, String> {
    let package_name = requested_install_package_name(requested)?;
    let install_root = package_info_install_root(requested, &package_name)?;
    let metadata = match fs::symlink_metadata(&install_root) {
        Ok(metadata) => Some(metadata),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(format!("failed to stat {}: {err}", install_root.display())),
    };

    if let Some(metadata) = metadata {
        if !metadata.is_dir() {
            return Err(format!(
                "installed package root {} is not a directory",
                install_root.display()
            ));
        }
        return resolve_installed_package_info(config, requested, package_name, install_root);
    }

    Ok(resolve_uninstalled_package_info(
        config,
        requested,
        package_name,
        install_root,
    ))
}

fn package_info_install_root(
    requested: &RequestedPackage,
    package_name: &str,
) -> Result<PathBuf, String> {
    if let RequestedPackage::Isotope(isotope_name) = requested
        && let Ok(record) = isotope_package_data(isotope_name)
        && let Some(modified_package) = isotope_modified_package_name(record)?
    {
        let modified_root = package_install_root(&opt_pkg_root(), &modified_package)?;
        if let Ok(Some(receipt)) = load_package_receipt(&modified_root.join(ROOT_RECEIPT))
            && receipt.package_name == package_name
        {
            return Ok(modified_root);
        }
    }
    package_install_root(&opt_pkg_root(), package_name)
}

pub(crate) fn resolve_package_search_results(
    _config: &Config,
    query: &str,
) -> Result<Vec<PackageSearchResult>, String> {
    let lowered_query = query.trim().to_ascii_lowercase();
    if lowered_query.is_empty() {
        return Ok(Vec::new());
    }

    let mut results = formula_index_entries()?
        .iter()
        .filter(|entry| formula_index_entry_matches(entry, &lowered_query))
        .flat_map(|entry| formula_search_results_for_query(entry, &lowered_query))
        .collect::<Vec<_>>();
    let db = crate::cli::load_db()?;
    crate::cli::ensure_db_schema(&db)?;
    results.extend(
        db.casks
            .iter()
            .filter(|(name, metadata)| {
                name.to_ascii_lowercase().contains(&lowered_query)
                    || metadata
                        .aliases
                        .iter()
                        .any(|alias| alias.to_ascii_lowercase().contains(&lowered_query))
                    || metadata
                        .summary
                        .to_ascii_lowercase()
                        .contains(&lowered_query)
            })
            .map(|(name, metadata)| PackageSearchResult {
                package_name: name.clone(),
                source: PackageReceiptSource::Cask {
                    cask_name: name.clone(),
                },
                summary: string_or_none(&metadata.summary),
                latest_version: Some(metadata.version.clone()),
                homepage: string_or_none(&metadata.homepage),
                repository: None,
                upstream_docs: None,
                docs: Vec::new(),
                category: None,
                dependencies: metadata.dependencies.clone(),
                install_package_names: Vec::new(),
                security_state: None,
                rank: metadata
                    .popularity
                    .as_ref()
                    .map(|popularity| popularity.rank),
                last_updated_at: metadata.last_updated_at.clone(),
                pulse_kind: None,
            }),
    );
    results.extend(
        db.npms
            .iter()
            .filter(|(name, metadata)| npm_entry_matches(name, metadata, &lowered_query))
            .map(|(name, metadata)| npm_search_result(name, metadata)),
    );
    results.extend(
        vendor::PACKAGES
            .iter()
            .copied()
            .filter(|entry| vendor_entry_matches(entry, &lowered_query))
            .map(vendor_search_result),
    );
    results.extend(resolve_security_recommendation_search_results(
        &lowered_query,
    )?);
    results.sort_by(|left, right| left.package_name.cmp(&right.package_name));
    results.dedup_by(|left, right| left.package_name == right.package_name);
    results.sort_by(|left, right| {
        compare_package_search_results_for_query(&lowered_query, left, right)
    });
    Ok(results)
}

pub(crate) fn compare_package_search_results_for_query(
    query: &str,
    left: &PackageSearchResult,
    right: &PackageSearchResult,
) -> std::cmp::Ordering {
    let query = query.trim().to_ascii_lowercase();
    search_result_formula_family_rank(left, &query)
        .cmp(&search_result_formula_family_rank(right, &query))
        .then_with(|| {
            search_result_match_rank(left, &query).cmp(&search_result_match_rank(right, &query))
        })
        .then_with(|| {
            search_result_match_distance(left, &query)
                .cmp(&search_result_match_distance(right, &query))
        })
        .then_with(|| compare_optional_popularity_rank(left.rank, right.rank))
        .then_with(|| {
            compare_package_names_for_search_order(&left.package_name, &right.package_name)
        })
}

fn search_result_formula_family_rank(package: &PackageSearchResult, query: &str) -> u8 {
    let query = package_search_order_name(query);
    if query.is_empty() {
        return 1;
    }

    let PackageReceiptSource::Formula { root_formula } = &package.source else {
        return 1;
    };

    for candidate in [&package.package_name, root_formula] {
        let order_name = package_search_order_name(candidate);
        let family_base = formula_versioned_base(order_name).unwrap_or(order_name);
        if family_base.eq_ignore_ascii_case(query) {
            return 0;
        }
    }
    1
}

fn compare_optional_popularity_rank(left: Option<u32>, right: Option<u32>) -> std::cmp::Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

fn search_result_match_rank(package: &PackageSearchResult, query: &str) -> u8 {
    if query.is_empty() {
        return 5;
    }

    let candidates = search_result_name_candidates(package);
    if candidates.iter().any(|candidate| candidate == query) {
        return 0;
    }
    if candidates
        .iter()
        .any(|candidate| candidate.starts_with(query))
    {
        return 1;
    }
    if candidates.iter().any(|candidate| candidate.contains(query)) {
        return 2;
    }
    if package
        .summary
        .as_deref()
        .is_some_and(|summary| summary.to_ascii_lowercase().contains(query))
    {
        return 3;
    }
    4
}

fn search_result_match_distance(package: &PackageSearchResult, query: &str) -> usize {
    if query.is_empty() {
        return usize::MAX;
    }

    let name_distance = search_result_name_candidates(package)
        .into_iter()
        .filter_map(|candidate| {
            if candidate == query {
                Some(0)
            } else if candidate.starts_with(query) {
                Some(candidate.len().saturating_sub(query.len()))
            } else {
                candidate
                    .find(query)
                    .map(|index| candidate.len().saturating_sub(query.len()) + index)
            }
        })
        .min();
    if let Some(distance) = name_distance {
        return distance;
    }

    package
        .summary
        .as_deref()
        .and_then(|summary| summary.to_ascii_lowercase().find(query))
        .unwrap_or(usize::MAX)
}

fn search_result_name_candidates(package: &PackageSearchResult) -> Vec<String> {
    let mut candidates = Vec::new();
    push_search_result_name_candidate(&mut candidates, &package.package_name);

    let qualified_name = package_source_qualified_name(&package.source);
    push_search_result_name_candidate(&mut candidates, &qualified_name);

    match &package.source {
        PackageReceiptSource::Formula { root_formula } => {
            push_search_result_name_candidate(&mut candidates, root_formula);
        }
        PackageReceiptSource::Cask { cask_name } => {
            push_search_result_name_candidate(&mut candidates, cask_name);
        }
        PackageReceiptSource::Isotope { isotope_name } => {
            push_search_result_name_candidate(&mut candidates, isotope_name);
        }
        PackageReceiptSource::Vendor { vendor_name } => {
            push_search_result_name_candidate(&mut candidates, vendor_name);
        }
        PackageReceiptSource::Npm { package_name } | PackageReceiptSource::Pip { package_name } => {
            push_search_result_name_candidate(&mut candidates, package_name);
        }
    }

    candidates
}

fn push_search_result_name_candidate(candidates: &mut Vec<String>, candidate: &str) {
    let candidate = candidate.trim().to_ascii_lowercase();
    if candidate.is_empty() {
        return;
    }
    push_unique_search_candidate(candidates, candidate.clone());

    let order_name = package_search_order_name(&candidate).to_string();
    push_unique_search_candidate(candidates, order_name);
}

fn push_unique_search_candidate(candidates: &mut Vec<String>, candidate: String) {
    if candidate.is_empty() || candidates.contains(&candidate) {
        return;
    }
    candidates.push(candidate);
}

pub(crate) fn resolve_available_package_results(
    _config: &Config,
) -> Result<Vec<PackageSearchResult>, String> {
    let mut results = formula_index_entries()?
        .iter()
        .map(|entry| formula_search_result(entry, &entry.name))
        .collect::<Vec<_>>();
    let db = crate::cli::load_db()?;
    crate::cli::ensure_db_schema(&db)?;
    results.extend(
        db.casks
            .into_iter()
            .map(|(name, metadata)| PackageSearchResult {
                package_name: name.clone(),
                source: PackageReceiptSource::Cask {
                    cask_name: name.clone(),
                },
                summary: string_or_none(&metadata.summary),
                latest_version: Some(metadata.version),
                homepage: string_or_none(&metadata.homepage),
                repository: None,
                upstream_docs: None,
                docs: Vec::new(),
                category: None,
                dependencies: metadata.dependencies,
                install_package_names: Vec::new(),
                security_state: None,
                rank: metadata.popularity.map(|popularity| popularity.rank),
                last_updated_at: metadata.last_updated_at,
                pulse_kind: None,
            }),
    );
    results.extend(
        db.npms
            .into_iter()
            .map(|(name, metadata)| npm_search_result(&name, &metadata)),
    );
    results.extend(vendor::PACKAGES.iter().copied().map(vendor_search_result));
    results.sort_by(|left, right| left.package_name.cmp(&right.package_name));
    results.dedup_by(|left, right| left.package_name == right.package_name);
    results.sort_by(|left, right| match (left.rank, right.rank) {
        (Some(left_rank), Some(right_rank)) => left_rank
            .cmp(&right_rank)
            .then_with(|| left.package_name.cmp(&right.package_name)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => left.package_name.cmp(&right.package_name),
    });
    Ok(results)
}

fn vendor_entry_matches(entry: &vendor::VendorEntry, lowered_query: &str) -> bool {
    entry.name.to_ascii_lowercase().contains(lowered_query)
        || format!("av:{}", entry.name)
            .to_ascii_lowercase()
            .contains(lowered_query)
        || (entry.executables)()
            .iter()
            .any(|executable| executable.to_ascii_lowercase().contains(lowered_query))
}

fn npm_entry_matches(
    package_name: &str,
    metadata: &EmbeddedNpmMetadata,
    lowered_query: &str,
) -> bool {
    package_name.to_ascii_lowercase().contains(lowered_query)
        || format!("npm:{package_name}")
            .to_ascii_lowercase()
            .contains(lowered_query)
        || metadata
            .executable
            .to_ascii_lowercase()
            .contains(lowered_query)
        || metadata
            .summary
            .to_ascii_lowercase()
            .contains(lowered_query)
}

fn npm_search_result(package_name: &str, metadata: &EmbeddedNpmMetadata) -> PackageSearchResult {
    let source = PackageReceiptSource::Npm {
        package_name: package_name.to_string(),
    };
    PackageSearchResult {
        package_name: package_source_qualified_name(&source),
        source,
        summary: string_or_none(&metadata.summary),
        latest_version: Some(metadata.version.clone()),
        homepage: string_or_none(&metadata.homepage),
        repository: None,
        upstream_docs: None,
        docs: Vec::new(),
        category: None,
        dependencies: Vec::new(),
        install_package_names: Vec::new(),
        security_state: None,
        rank: metadata
            .popularity
            .as_ref()
            .map(|popularity| popularity.rank),
        last_updated_at: metadata.last_updated_at.clone(),
        pulse_kind: None,
    }
}

fn vendor_search_result(entry: &vendor::VendorEntry) -> PackageSearchResult {
    let source = PackageReceiptSource::Vendor {
        vendor_name: entry.name.to_string(),
    };
    PackageSearchResult {
        package_name: package_source_qualified_name(&source),
        source,
        summary: None,
        latest_version: None,
        homepage: None,
        repository: None,
        upstream_docs: None,
        docs: Vec::new(),
        category: None,
        dependencies: entry
            .dependencies
            .map(|dependencies| {
                dependencies()
                    .iter()
                    .map(|dependency| dependency.to_string())
                    .collect()
            })
            .unwrap_or_default(),
        install_package_names: Vec::new(),
        security_state: None,
        rank: None,
        last_updated_at: None,
        pulse_kind: None,
    }
}

pub(crate) fn resolve_pulse_package_results(
    _config: &Config,
) -> Result<Vec<PackageSearchResult>, String> {
    let db = crate::cli::load_db()?;
    crate::cli::ensure_db_schema(&db)?;
    let pulse_reference_time = parse_embedded_package_timestamp(&db.generated_at);
    let mut results = formula_index_entries()?
        .iter()
        .filter_map(|entry| {
            entry.last_updated_at.as_ref().map(|last_updated_at| {
                let mut result = formula_search_result(entry, &entry.name);
                result.last_updated_at = Some(last_updated_at.clone());
                result.pulse_kind = Some(pulse_kind_for_timestamp(
                    entry.pulse_kind.clone(),
                    last_updated_at,
                    pulse_reference_time,
                ));
                result
            })
        })
        .collect::<Vec<_>>();
    results.extend(db.casks.into_iter().filter_map(|(name, metadata)| {
        metadata.last_updated_at.clone().map(|last_updated_at| {
            let pulse_kind = pulse_kind_for_timestamp(
                metadata.pulse_kind,
                &last_updated_at,
                pulse_reference_time,
            );
            PackageSearchResult {
                package_name: name.clone(),
                source: PackageReceiptSource::Cask { cask_name: name },
                summary: string_or_none(&metadata.summary),
                latest_version: Some(metadata.version),
                homepage: string_or_none(&metadata.homepage),
                repository: None,
                upstream_docs: None,
                docs: Vec::new(),
                category: None,
                dependencies: metadata.dependencies,
                install_package_names: Vec::new(),
                security_state: None,
                rank: metadata.popularity.map(|popularity| popularity.rank),
                last_updated_at: Some(last_updated_at),
                pulse_kind: Some(pulse_kind),
            }
        })
    }));
    results.extend(db.npms.into_iter().filter_map(|(name, metadata)| {
        metadata.last_updated_at.clone().map(|last_updated_at| {
            let pulse_kind = pulse_kind_for_timestamp(
                metadata.pulse_kind.clone(),
                &last_updated_at,
                pulse_reference_time,
            );
            let mut result = npm_search_result(&name, &metadata);
            result.last_updated_at = Some(last_updated_at);
            result.pulse_kind = Some(pulse_kind);
            result
        })
    }));
    results.sort_by(|left, right| left.package_name.cmp(&right.package_name));
    results.dedup_by(|left, right| left.package_name == right.package_name);
    results.sort_by(compare_pulse_package_results);
    Ok(results)
}

pub(crate) fn resolve_geiger_package_results(
    _config: &Config,
) -> Result<Vec<PackageSearchResult>, String> {
    let mut results = isotope_integrations::INTEGRATIONS
        .iter()
        .filter_map(geiger_package_result_for_integration)
        .collect::<Vec<_>>();
    results.sort_by(|left, right| {
        compare_package_names_for_search_order(&left.package_name, &right.package_name)
    });
    results.dedup_by(|left, right| left.package_name == right.package_name);
    Ok(results)
}

pub(crate) fn resolve_security_recommendation_package_results(
    _config: &Config,
) -> Result<Vec<PackageSearchResult>, String> {
    let homebrew_cellar = Path::new(RELOCATABLE_HOMEBREW_PREFIX).join("Cellar");
    resolve_security_recommendation_package_results_at(&homebrew_cellar, &opt_pkg_root())
}

fn resolve_security_recommendation_package_results_at(
    homebrew_cellar: &Path,
    opt_root: &Path,
) -> Result<Vec<PackageSearchResult>, String> {
    let formulae = formula_index_entries()?;
    let mut results = embedded_security_recommendations()
        .packages
        .iter()
        .filter_map(|(package_key, recommendation)| {
            let formula = security_recommendation_formula(package_key, recommendation)?;
            if !homebrew_formula_is_installed_at(homebrew_cellar, &formula)
                || security_recommendation_has_vault_install(opt_root, package_key, recommendation)
            {
                return None;
            }
            let result =
                security_recommendation_package_result(package_key, recommendation, formulae)?;
            Some((recommendation.priority, result))
        })
        .collect::<Vec<_>>();

    results.sort_by(|(left_priority, left), (right_priority, right)| {
        left_priority
            .cmp(right_priority)
            .then_with(|| compare_security_recommendation_rank_order(left, right))
            .then_with(|| {
                compare_package_names_for_search_order(&left.package_name, &right.package_name)
            })
    });
    let mut results = results
        .into_iter()
        .map(|(_, result)| result)
        .collect::<Vec<_>>();
    results.dedup_by(|left, right| left.package_name == right.package_name);
    Ok(results)
}

fn security_recommendation_formula(
    package_key: &str,
    recommendation: &SecurityRecommendationPackage,
) -> Option<String> {
    string_or_none(&recommendation.name).or_else(|| {
        package_key
            .strip_prefix(BREW_PACKAGE_PREFIX)
            .and_then(string_or_none)
    })
}

fn homebrew_formula_cellar_name(formula: &str) -> &str {
    formula
        .strip_prefix(BREW_PACKAGE_PREFIX)
        .unwrap_or(formula)
        .rsplit('/')
        .next()
        .unwrap_or(formula)
}

fn homebrew_formula_is_installed_at(homebrew_cellar: &Path, formula: &str) -> bool {
    let formula_dir = homebrew_cellar.join(homebrew_formula_cellar_name(formula));
    let Ok(entries) = fs::read_dir(formula_dir) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|entry| {
        entry.file_type().is_ok_and(|file_type| file_type.is_dir())
            && entry.path().join(HOMEBREW_INSTALL_RECEIPT).is_file()
    })
}

fn security_recommendation_has_vault_install(
    opt_root: &Path,
    package_key: &str,
    recommendation: &SecurityRecommendationPackage,
) -> bool {
    let mut candidates = Vec::new();
    append_security_recommendation_install_candidate(&mut candidates, package_key);
    append_security_recommendation_install_candidate(
        &mut candidates,
        &recommendation.install_package_name,
    );
    if let Some(isotope_package) = recommendation.isotope_package.as_deref() {
        append_security_recommendation_install_candidate(&mut candidates, isotope_package);
    }

    candidates
        .into_iter()
        .any(|package_name| vault_package_receipt_exists(opt_root, &package_name))
}

fn append_security_recommendation_install_candidate(candidates: &mut Vec<String>, value: &str) {
    let Some(trimmed) = string_or_none(value) else {
        return;
    };
    let package_name = trimmed
        .strip_prefix(BREW_PACKAGE_PREFIX)
        .unwrap_or(&trimmed);
    push_unique_string(candidates, package_name.to_string());
    let cellar_name = homebrew_formula_cellar_name(package_name);
    if cellar_name != package_name {
        push_unique_string(candidates, cellar_name.to_string());
    }
}

fn vault_package_receipt_exists(opt_root: &Path, package_name: &str) -> bool {
    let Ok(install_root) = package_install_root(opt_root, package_name) else {
        return false;
    };
    load_package_receipt(&install_root.join(ROOT_RECEIPT))
        .ok()
        .flatten()
        .is_some()
}

fn security_recommendation_package_result(
    package_key: &str,
    recommendation: &SecurityRecommendationPackage,
    formulae: &[FormulaIndexEntry],
) -> Option<PackageSearchResult> {
    let formula = security_recommendation_formula(package_key, recommendation)?;
    let source = PackageReceiptSource::Formula {
        root_formula: formula.clone(),
    };
    let package_name = package_source_qualified_name(&source);
    let mut result = formula_index_entry_for_security_recommendation(formulae, &formula)
        .map(|entry| formula_search_result(entry, &package_name))
        .unwrap_or_else(|| PackageSearchResult {
            package_name,
            source: source.clone(),
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
            rank: None,
            last_updated_at: None,
            pulse_kind: None,
        });

    result.source = source;
    result.summary = Some(security_recommendation_summary(recommendation));
    result.install_package_names = vec![security_recommendation_install_package_name(
        package_key,
        recommendation,
    )];
    if result.security_state.is_none()
        && let Some(isotope) = recommendation.isotope.as_deref()
    {
        result.security_state = package_security_state_for_isotope(isotope);
    }
    Some(result)
}

fn resolve_security_recommendation_search_results(
    query: &str,
) -> Result<Vec<PackageSearchResult>, String> {
    let formulae = formula_index_entries()?;
    let mut results = embedded_security_recommendations()
        .packages
        .iter()
        .filter_map(|(package_key, recommendation)| {
            let formula = security_recommendation_formula(package_key, recommendation)?;
            if formula_index_contains_exact_formula(formulae, &formula) {
                return None;
            }
            security_recommendation_package_result(package_key, recommendation, formulae)
        })
        .filter(|result| {
            search_result_is_versioned_formula(result)
                && search_result_match_rank(result, query) < 4
        })
        .collect::<Vec<_>>();
    results.sort_by(|left, right| left.package_name.cmp(&right.package_name));
    results.dedup_by(|left, right| left.package_name == right.package_name);
    Ok(results)
}

fn formula_index_contains_exact_formula(formulae: &[FormulaIndexEntry], formula: &str) -> bool {
    let cellar_name = homebrew_formula_cellar_name(formula);
    formulae
        .iter()
        .any(|entry| entry.name == formula || entry.name == cellar_name)
}

fn search_result_is_versioned_formula(result: &PackageSearchResult) -> bool {
    match &result.source {
        PackageReceiptSource::Formula { root_formula } => {
            formula_versioned_base(root_formula).is_some()
        }
        _ => false,
    }
}

fn formula_index_entry_for_security_recommendation<'a>(
    formulae: &'a [FormulaIndexEntry],
    formula: &str,
) -> Option<&'a FormulaIndexEntry> {
    let cellar_name = homebrew_formula_cellar_name(formula);
    formulae
        .iter()
        .find(|entry| entry.name == formula || entry.name == cellar_name)
        .or_else(|| {
            formulae.iter().find(|entry| {
                entry.aliases.iter().any(|alias| {
                    alias == formula || homebrew_formula_cellar_name(alias) == cellar_name
                })
            })
        })
}

fn security_recommendation_install_package_name(
    package_key: &str,
    recommendation: &SecurityRecommendationPackage,
) -> String {
    string_or_none(&recommendation.install_package_name).unwrap_or_else(|| package_key.to_string())
}

fn security_recommendation_summary(recommendation: &SecurityRecommendationPackage) -> String {
    let mut summary = recommendation
        .reasons
        .iter()
        .find_map(|reason| string_or_none(reason))
        .unwrap_or_else(|| "Root-owned Automic Vault install recommended.".to_string());

    if let Some(level) = recommendation
        .geiger_level
        .as_deref()
        .and_then(string_or_none)
    {
        summary.push_str(&format!(" Geiger: {level}."));
    }
    if let Some(confidence) = recommendation
        .geiger_confidence
        .as_deref()
        .and_then(string_or_none)
    {
        summary.push_str(&format!(" Confidence: {confidence}."));
    }
    if let Some(category) = recommendation
        .geiger_category
        .as_deref()
        .and_then(string_or_none)
    {
        summary.push_str(&format!(" Category: {category}."));
    }
    if recommendation.approval_gate
        && !recommendation
            .signals
            .iter()
            .any(|signal| signal == "approval_gate")
    {
        summary.push_str(" Approval gate metadata is available.");
    }
    summary
}

fn compare_security_recommendation_rank_order(
    left: &PackageSearchResult,
    right: &PackageSearchResult,
) -> std::cmp::Ordering {
    match (left.rank, right.rank) {
        (Some(left_rank), Some(right_rank)) => left_rank.cmp(&right_rank),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

fn geiger_package_result_for_integration(
    integration: &isotope_integrations::IsotopeIntegration,
) -> Option<PackageSearchResult> {
    let state = package_security_state_for_isotope(integration.name)?;
    if !package_security_state_needs_geiger_action(&state) {
        return None;
    }

    let isotope = embedded_isotope_data().get(&isotope_qualified_name(integration.name));
    let target = isotope
        .and_then(|record| {
            isotope_modified_or_replaced_package_name(record)
                .ok()
                .flatten()
        })
        .map(|target| {
            if target.contains(':') {
                target
            } else {
                format!("{BREW_PACKAGE_PREFIX}{target}")
            }
        })
        .unwrap_or_else(|| format!("{BREW_PACKAGE_PREFIX}{}", integration.name));
    let target = parse_package_alias_target(&target).ok()?;
    let source = match target {
        PackageAliasTarget::HomebrewFormula(formula) => PackageReceiptSource::Formula {
            root_formula: formula,
        },
        PackageAliasTarget::HomebrewCask(cask_name) => PackageReceiptSource::Cask { cask_name },
        PackageAliasTarget::VendorPackage(vendor_name) => {
            PackageReceiptSource::Vendor { vendor_name }
        }
        PackageAliasTarget::NpmPackage(package_name) => PackageReceiptSource::Npm { package_name },
        PackageAliasTarget::PipPackage(package_name) => PackageReceiptSource::Pip { package_name },
    };
    let package_name = package_source_qualified_name(&source);
    let mut result = geiger_package_result_with_source_metadata(&source, &package_name);
    result.summary = Some(geiger_package_summary(&state));
    if result.homepage.is_none() {
        result.homepage = isotope.and_then(|record| record.release_url.clone());
    }
    result.security_state = Some(state);
    result.last_updated_at = isotope.and_then(|record| record.published_at.clone());
    Some(result)
}

fn geiger_package_result_with_source_metadata(
    source: &PackageReceiptSource,
    package_name: &str,
) -> PackageSearchResult {
    if let PackageReceiptSource::Formula { root_formula } = source
        && let Ok(formulae) = formula_index_entries()
        && let Some(entry) = formula_index_entry_for_security_recommendation(formulae, root_formula)
    {
        return formula_search_result(entry, package_name);
    }

    PackageSearchResult {
        package_name: package_name.to_string(),
        source: source.clone(),
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
        rank: None,
        last_updated_at: None,
        pulse_kind: None,
    }
}

fn package_security_state_needs_geiger_action(state: &PackageSecurityState) -> bool {
    state.install_is_insecure
        || state
            .error
            .as_ref()
            .is_some_and(|error| !error.trim().is_empty())
}

fn geiger_package_summary(state: &PackageSecurityState) -> String {
    if state
        .error
        .as_ref()
        .is_some_and(|error| !error.trim().is_empty())
    {
        return format!("Detector for isotope:{} needs review", state.isotope_name);
    }
    "Detector flagged local plaintext credential exposure".to_string()
}

fn pulse_kind_for_timestamp(
    pulse_kind: Option<String>,
    last_updated_at: &str,
    reference_time: Option<OffsetDateTime>,
) -> String {
    let pulse_kind = pulse_kind.unwrap_or_else(|| "updated".to_string());
    if !pulse_kind.eq_ignore_ascii_case("new") {
        return pulse_kind;
    }

    let is_recent = reference_time
        .zip(parse_embedded_package_timestamp(last_updated_at))
        .map(|(reference_time, last_updated_at)| {
            let age_seconds = reference_time.unix_timestamp() - last_updated_at.unix_timestamp();
            (0..=PULSE_NEW_WINDOW_SECONDS).contains(&age_seconds)
        })
        .unwrap_or(false);
    if is_recent {
        pulse_kind
    } else {
        "updated".to_string()
    }
}

fn compare_pulse_package_results(
    left: &PackageSearchResult,
    right: &PackageSearchResult,
) -> std::cmp::Ordering {
    pulse_kind_sort_key(left)
        .cmp(&pulse_kind_sort_key(right))
        .then_with(|| {
            match (
                left.last_updated_at
                    .as_deref()
                    .and_then(parse_embedded_package_timestamp),
                right
                    .last_updated_at
                    .as_deref()
                    .and_then(parse_embedded_package_timestamp),
            ) {
                (Some(left_time), Some(right_time)) => right_time.cmp(&left_time),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        })
        .then_with(|| left.package_name.cmp(&right.package_name))
}

fn pulse_kind_sort_key(package: &PackageSearchResult) -> u8 {
    match package.pulse_kind.as_deref() {
        Some(kind) if kind.eq_ignore_ascii_case("new") => 0,
        _ => 1,
    }
}

fn parse_embedded_package_timestamp(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

pub(crate) fn formula_index_entry_matches(entry: &FormulaIndexEntry, query: &str) -> bool {
    entry.name.to_ascii_lowercase().contains(query)
        || entry
            .aliases
            .iter()
            .any(|alias| alias.to_ascii_lowercase().contains(query))
        || entry
            .oldnames
            .iter()
            .any(|oldname| oldname.to_ascii_lowercase().contains(query))
}

fn formula_search_result(entry: &FormulaIndexEntry, package_name: &str) -> PackageSearchResult {
    PackageSearchResult {
        package_name: package_name.to_string(),
        source: PackageReceiptSource::Formula {
            root_formula: formula_search_result_root_formula(entry, package_name),
        },
        summary: string_or_none(&entry.summary),
        latest_version: None,
        homepage: string_or_none(&entry.homepage),
        repository: string_or_none(&entry.repository),
        upstream_docs: formula_upstream_docs(entry),
        docs: non_empty_docs(&entry.docs),
        category: string_or_none(&entry.category),
        dependencies: Vec::new(),
        install_package_names: formula_search_result_install_package_names(entry, package_name),
        security_state: None,
        rank: entry.popularity.as_ref().map(|popularity| popularity.rank),
        last_updated_at: entry.last_updated_at.clone(),
        pulse_kind: None,
    }
}

fn formula_search_result_root_formula(entry: &FormulaIndexEntry, package_name: &str) -> String {
    if formula_search_result_uses_display_name_as_install_target(entry, package_name) {
        return package_name.to_string();
    }
    entry.name.clone()
}

fn formula_search_result_install_package_names(
    entry: &FormulaIndexEntry,
    package_name: &str,
) -> Vec<String> {
    if formula_search_result_uses_display_name_as_install_target(entry, package_name) {
        return vec![package_name.to_string()];
    }
    Vec::new()
}

fn formula_search_result_uses_display_name_as_install_target(
    entry: &FormulaIndexEntry,
    package_name: &str,
) -> bool {
    package_name != entry.name
        && !package_name.contains(':')
        && formula_versioned_base(package_name).is_some()
}

fn formula_upstream_docs(entry: &FormulaIndexEntry) -> Option<String> {
    string_or_none(&entry.upstream_docs)
        .or_else(|| entry.docs.iter().find_map(|doc| string_or_none(doc)))
}

fn non_empty_docs(docs: &[String]) -> Vec<String> {
    docs.iter().filter_map(|doc| string_or_none(doc)).collect()
}

pub(crate) fn formula_search_results_for_query(
    entry: &FormulaIndexEntry,
    query: &str,
) -> Vec<PackageSearchResult> {
    formula_search_result_display_names(entry, query)
        .into_iter()
        .map(|package_name| formula_search_result(entry, &package_name))
        .collect()
}

fn formula_search_result_display_names(entry: &FormulaIndexEntry, query: &str) -> Vec<String> {
    let query = query.trim().to_ascii_lowercase();
    let mut names = Vec::new();
    if query.is_empty() || entry.name.to_ascii_lowercase().contains(&query) {
        names.push(entry.name.clone());
    }

    names.extend(
        entry
            .aliases
            .iter()
            .chain(entry.oldnames.iter())
            .filter(|name| {
                formula_versioned_base(name).is_some() && name.to_ascii_lowercase().contains(&query)
            })
            .cloned(),
    );

    if names.is_empty() {
        names.push(entry.name.clone());
    }
    names.sort();
    names.dedup();
    names
}

#[cfg(test)]
pub(crate) fn suppress_unversioned_formulae_with_versioned_search_results(
    results: &mut Vec<PackageSearchResult>,
) {
    let versioned_formula_bases = results
        .iter()
        .filter(|result| matches!(result.source, PackageReceiptSource::Formula { .. }))
        .filter_map(|result| formula_versioned_base(&result.package_name))
        .map(|base| base.to_ascii_lowercase())
        .collect::<HashSet<_>>();

    if versioned_formula_bases.is_empty() {
        return;
    }

    results.retain(|result| match &result.source {
        PackageReceiptSource::Formula { .. } => {
            formula_versioned_base(&result.package_name).is_some()
                || !versioned_formula_bases.contains(&result.package_name.to_ascii_lowercase())
        }
        _ => true,
    });
}

pub(crate) fn formula_versioned_base(formula: &str) -> Option<&str> {
    let (base, version) = formula.rsplit_once('@')?;
    if base.is_empty() || version.is_empty() || !version.chars().any(|ch| ch.is_ascii_digit()) {
        return None;
    }
    Some(base)
}

fn formula_family_base(formula: &str) -> String {
    formula_versioned_base(formula)
        .unwrap_or(formula)
        .to_string()
}

fn formula_version_alias(base: &str, version: &str) -> Option<String> {
    let major = version.split(['.', '_']).next()?;
    if major.is_empty() || !major.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    Some(format!("{base}@{major}"))
}

fn parsed_stable_version(value: &str) -> Option<(u64, u64, u64)> {
    let stable = value.split('_').next().unwrap_or(value);
    let mut parts = stable.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

fn version_is_recommendable(version: &str) -> bool {
    let Some((_major, minor, patch)) = parsed_stable_version(version) else {
        return false;
    };
    minor > 1 || (minor == 1 && patch >= 1)
}

fn compare_version_strings(left: &str, right: &str) -> std::cmp::Ordering {
    parsed_stable_version(left)
        .cmp(&parsed_stable_version(right))
        .then_with(|| left.cmp(right))
}

pub(crate) fn formula_display_alias(
    entry: &FormulaIndexEntry,
    base: &str,
    version: &str,
) -> Option<String> {
    if formula_versioned_base(&entry.name) == Some(base) {
        return Some(entry.name.clone());
    }
    formula_version_alias(base, version).or_else(|| {
        entry
            .aliases
            .iter()
            .find(|alias| formula_versioned_base(alias) == Some(base))
            .cloned()
    })
}

fn formula_family_entries(root_formula: &str) -> Result<Vec<FormulaIndexEntry>, String> {
    let base = formula_family_base(root_formula);
    let entries = formula_index_entries()?
        .iter()
        .filter(|entry| {
            entry.name == base
                || formula_versioned_base(&entry.name) == Some(base.as_str())
                || entry
                    .aliases
                    .iter()
                    .chain(entry.oldnames.iter())
                    .any(|alias| {
                        alias == &base || formula_versioned_base(alias) == Some(base.as_str())
                    })
        })
        .cloned()
        .collect::<Vec<_>>();
    Ok(entries)
}

fn formula_version_options(root_formula: &str) -> Result<Vec<FormulaVersionOption>, String> {
    let base = formula_family_base(root_formula);
    let mut entries = formula_family_entries(root_formula)?;
    if entries.len() <= 1
        && entries.first().is_none_or(|entry| {
            entry
                .aliases
                .iter()
                .all(|alias| formula_versioned_base(alias).is_none())
        })
    {
        return Ok(Vec::new());
    }

    entries.sort_by(|left, right| left.name.cmp(&right.name));
    entries.dedup_by(|left, right| left.name == right.name);

    let mut candidates = Vec::new();
    for entry in entries {
        if let Ok(info) = fetch_formula_info(&entry.name) {
            let version = formula_version_string(&info);
            let alias_name = formula_display_alias(&entry, &base, &version);
            candidates.push((entry, version, alias_name));
        }
    }
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    candidates.sort_by(|left, right| compare_version_strings(&right.1, &left.1));
    let latest_formula = candidates
        .first()
        .map(|(entry, _, _)| entry.name.clone())
        .unwrap_or_else(|| root_formula.to_string());
    let recommended_formula = candidates
        .iter()
        .find(|(_, version, _)| version_is_recommendable(version))
        .map(|(entry, _, _)| entry.name.clone());

    let mut options = Vec::new();
    for (entry, version, alias_name) in candidates {
        let display_name = alias_name.clone().unwrap_or_else(|| entry.name.clone());
        options.push(build_formula_version_option(
            display_name,
            alias_name,
            entry.name.clone(),
            entry.name.clone(),
            Some(version),
            entry.name == latest_formula,
            recommended_formula
                .as_deref()
                .is_some_and(|formula| formula == entry.name),
        )?);
    }
    Ok(options)
}

fn build_formula_version_option(
    display_name: String,
    alias_name: Option<String>,
    package_name: String,
    root_formula: String,
    version: Option<String>,
    is_latest: bool,
    is_recommended: bool,
) -> Result<FormulaVersionOption, String> {
    let install_root = package_install_root(&opt_pkg_root(), &package_name)?;
    let installed = install_root.is_dir();
    let stub_active = installed && package_stubs_are_active(&install_root, &package_name)?;
    let install_package_name = format!("{BREW_PACKAGE_PREFIX}{package_name}");
    let supports_side_by_side_stubs = package_name.starts_with("python@");
    Ok(FormulaVersionOption {
        display_name,
        alias_name,
        package_name,
        install_package_name,
        root_formula,
        version,
        install_root,
        installed,
        stub_active,
        is_latest,
        is_recommended,
        supports_side_by_side_stubs,
    })
}

fn package_stubs_are_active(install_root: &Path, package_name: &str) -> Result<bool, String> {
    let manifest = load_stub_manifest(&install_root.join(STUB_MANIFEST))?;
    if manifest.stubs.is_empty() {
        return Ok(false);
    }
    for stub in manifest.stubs {
        let stub_path = managed_bin_root().join(stub);
        if stub_belongs_to_package(&stub_path, package_name)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn resolve_installed_package_info(
    config: &Config,
    requested: &RequestedPackage,
    package_name: String,
    install_root: PathBuf,
) -> Result<PackageInfo, String> {
    let mut info = PackageInfo {
        package_name,
        qualified_name: String::new(),
        install_root,
        installed: true,
        source: None,
        source_error: None,
        aliases: Vec::new(),
        aliases_error: None,
        installed_version: None,
        latest_version: None,
        latest_version_error: None,
        executable_paths: Vec::new(),
        executable_paths_error: None,
        popularity: None,
        last_updated_at: None,
        homebrew_info: None,
        homebrew_info_error: None,
        npm_homepage: None,
        npm_package_info_error: None,
        security_state: None,
        version_options: Vec::new(),
    };

    match load_package_receipt(&info.install_root.join(ROOT_RECEIPT)) {
        Ok(Some(receipt)) => {
            info.package_name = receipt.package_name;
            info.source = Some(receipt.source);
            info.installed_version = Some(receipt.version);
        }
        Ok(None) => info.source_error = Some("missing package metadata".to_string()),
        Err(err) => info.source_error = Some(err),
    }

    if info.source.is_none() {
        info.source = explicit_requested_package_source(requested);
    }
    match installed_stub_paths_at(&info.install_root) {
        Ok(paths) => info.executable_paths = paths,
        Err(err) => info.executable_paths_error = Some(err),
    }
    populate_package_info_identity(&mut info);
    populate_package_info_metadata(config, &mut info);
    populate_formula_version_options(&mut info);
    info.security_state = package_security_state(&info);
    Ok(info)
}

pub(crate) fn resolve_uninstalled_package_info(
    config: &Config,
    requested: &RequestedPackage,
    package_name: String,
    install_root: PathBuf,
) -> PackageInfo {
    let mut info = PackageInfo {
        package_name,
        qualified_name: String::new(),
        install_root,
        installed: false,
        source: None,
        source_error: None,
        aliases: Vec::new(),
        aliases_error: None,
        installed_version: None,
        latest_version: None,
        latest_version_error: None,
        executable_paths: Vec::new(),
        executable_paths_error: None,
        popularity: None,
        last_updated_at: None,
        homebrew_info: None,
        homebrew_info_error: None,
        npm_homepage: None,
        npm_package_info_error: None,
        security_state: None,
        version_options: Vec::new(),
    };

    match infer_requested_package_source(requested) {
        Ok(source) => info.source = Some(source),
        Err(err) => info.source_error = Some(err),
    }
    if let Some(PackageReceiptSource::Formula { root_formula }) = info.source.as_ref() {
        match predicted_homebrew_executables(root_formula) {
            Ok(paths) => info.executable_paths = paths,
            Err(err) => info.executable_paths_error = Some(err),
        }
    }
    populate_package_info_identity(&mut info);
    populate_package_info_metadata(config, &mut info);
    populate_formula_version_options(&mut info);
    info.security_state = package_security_state(&info);
    info
}

fn populate_formula_version_options(info: &mut PackageInfo) {
    let Some(PackageReceiptSource::Formula { root_formula }) = info.source.as_ref() else {
        return;
    };
    if let Ok(options) = formula_version_options(root_formula) {
        info.version_options = options;
    }
}

pub(crate) fn predicted_homebrew_executables(formula: &str) -> Result<Vec<String>, String> {
    let db = crate::cli::load_db()?;
    crate::cli::ensure_db_schema(&db)?;
    let canonical = canonical_formula_name(formula)?;
    Ok(homebrew_executables_from_db(&canonical, &db))
}

pub(crate) fn homebrew_executables_from_db(formula: &str, db: &Db) -> Vec<String> {
    let mut executables = db
        .entries
        .iter()
        .filter_map(|(executable, provider)| (provider == formula).then_some(executable.clone()))
        .collect::<Vec<_>>();
    executables.sort();
    executables.dedup();
    executables
}

pub(crate) fn populate_package_info_identity(info: &mut PackageInfo) {
    if let Some(source) = info.source.as_ref() {
        info.qualified_name = package_source_qualified_name(source);
        let (aliases, alias_error) = resolve_aliases_for_source(source);
        info.aliases = aliases;
        info.aliases_error = alias_error;
    } else {
        info.qualified_name = info.package_name.clone();
    }
}

pub(crate) fn populate_package_info_metadata(config: &Config, info: &mut PackageInfo) {
    let Some(source) = info.source.clone() else {
        return;
    };

    match source {
        PackageReceiptSource::Formula { root_formula } => match fetch_formula_info(&root_formula) {
            Ok(formula_info) => {
                info.homebrew_info = Some(homebrew_package_info_from_formula_info(
                    &root_formula,
                    &formula_info,
                ));
                apply_formula_db_metadata(&root_formula, info);
                if info.last_updated_at.is_none() {
                    let canonical = canonical_formula_name(&root_formula)
                        .unwrap_or_else(|_| root_formula.clone());
                    info.last_updated_at =
                        resolve_formula_last_updated_at(&canonical).ok().flatten();
                }
                match ensure_formula_has_bottle(&root_formula, &formula_info, &config.bottle_tag) {
                    Ok(()) => info.latest_version = Some(formula_version_string(&formula_info)),
                    Err(err) => info.latest_version_error = Some(err),
                }
            }
            Err(err) => {
                apply_formula_db_metadata(&root_formula, info);
                info.latest_version_error = Some(err.clone());
                info.homebrew_info_error = Some(err);
            }
        },
        PackageReceiptSource::Cask { cask_name } => match embedded_cask(&cask_name) {
            Ok(cask_info) => {
                info.homebrew_info = Some(HomebrewPackageInfo {
                    formula: cask_name.clone(),
                    description: string_or_none(&cask_info.summary),
                    homepage: string_or_none(&cask_info.homepage),
                    repository: None,
                    upstream_docs: None,
                    docs: Vec::new(),
                    license: None,
                    dependencies: cask_info.dependencies.clone(),
                });
                info.popularity = cask_info.popularity.clone();
                info.last_updated_at = cask_info.last_updated_at.clone();
                if info.last_updated_at.is_none() {
                    info.last_updated_at = resolve_cask_last_updated_at(&cask_name).ok().flatten();
                }
                info.latest_version = Some(cask_info.version);
            }
            Err(err) => {
                info.latest_version_error = Some(err.clone());
                info.homebrew_info_error = Some(err);
            }
        },
        PackageReceiptSource::Isotope { isotope_name } => {
            match isotope_package_data(&isotope_name) {
                Ok(isotope) => {
                    info.last_updated_at = isotope.published_at.clone();
                    match isotope_modified_package_target(isotope) {
                        Ok(Some(PackageAliasTarget::HomebrewFormula(formula))) => {
                            match fetch_formula_info(&formula) {
                                Ok(formula_info) => {
                                    info.homebrew_info =
                                        Some(homebrew_package_info_from_formula_info(
                                            &formula,
                                            &formula_info,
                                        ));
                                    apply_formula_db_homebrew_metadata(&formula, info);
                                    match ensure_formula_has_bottle(
                                        &formula,
                                        &formula_info,
                                        &config.bottle_tag,
                                    ) {
                                        Ok(()) => {
                                            info.latest_version =
                                                Some(formula_version_string(&formula_info))
                                        }
                                        Err(err) => {
                                            info.latest_version = Some(isotope.version.clone());
                                            info.latest_version_error = Some(err);
                                        }
                                    }
                                }
                                Err(err) => {
                                    info.latest_version = Some(isotope.version.clone());
                                    info.latest_version_error = Some(err.clone());
                                    info.homebrew_info_error = Some(err);
                                    info.homebrew_info =
                                        Some(isotope_homebrew_info(&isotope_name, isotope));
                                    apply_formula_db_homebrew_metadata(&formula, info);
                                }
                            }
                        }
                        Ok(Some(PackageAliasTarget::VendorPackage(vendor_name))) => {
                            match resolve_vendor_latest_version(&vendor_name) {
                                Ok(version) => info.latest_version = Some(version),
                                Err(err) => info.latest_version_error = Some(err),
                            }
                            info.homebrew_info =
                                Some(isotope_homebrew_info(&isotope_name, isotope));
                        }
                        _ => {
                            info.latest_version = Some(isotope.version.clone());
                            info.homebrew_info =
                                Some(isotope_homebrew_info(&isotope_name, isotope));
                            if let Some(formula) = isotope_homebrew_formula_target(isotope) {
                                apply_formula_db_homebrew_link_metadata(&formula, info);
                            }
                        }
                    }
                }
                Err(err) => {
                    info.latest_version_error = Some(err.clone());
                    info.homebrew_info_error = Some(err);
                }
            }
        }
        PackageReceiptSource::Npm { ref package_name } => {
            match resolve_latest_version_for_source(config, &source) {
                Ok(latest_version) => info.latest_version = Some(latest_version),
                Err(err) => info.latest_version_error = Some(err),
            }
            match resolve_npm_homepage(package_name) {
                Ok(homepage) => info.npm_homepage = homepage,
                Err(err) => info.npm_package_info_error = Some(err),
            }
        }
        _ => match resolve_latest_version_for_source(config, &source) {
            Ok(latest_version) => info.latest_version = Some(latest_version),
            Err(err) => info.latest_version_error = Some(err),
        },
    }
}

fn resolve_formula_last_updated_at(formula: &str) -> Result<Option<String>, String> {
    let path = format!(
        "Formula/{}/{}.rb",
        formula.chars().next().unwrap_or('f'),
        formula
    );
    resolve_homebrew_repo_last_updated_at("Homebrew/homebrew-core", &path)
}

fn resolve_cask_last_updated_at(cask: &str) -> Result<Option<String>, String> {
    let path = format!("Casks/{}/{}.rb", cask.chars().next().unwrap_or('c'), cask);
    resolve_homebrew_repo_last_updated_at("Homebrew/homebrew-cask", &path)
}

fn resolve_homebrew_repo_last_updated_at(repo: &str, path: &str) -> Result<Option<String>, String> {
    let encoded_path = path.replace('/', "%2F");
    let url = format!("https://api.github.com/repos/{repo}/commits?path={encoded_path}&per_page=1");
    let commits = fetch_optional_json::<Vec<GitHubCommitListEntry>, _>(&url, || {
        format!("failed to fetch commit metadata for {path}")
    })?;
    Ok(commits.and_then(|commits| {
        commits.into_iter().next().and_then(|entry| {
            entry
                .commit
                .committer
                .map(|identity| identity.date)
                .or_else(|| entry.commit.author.map(|identity| identity.date))
        })
    }))
}

pub(crate) fn explicit_requested_package_source(
    requested: &RequestedPackage,
) -> Option<PackageReceiptSource> {
    match requested {
        RequestedPackage::HomebrewFormula(formula) => Some(PackageReceiptSource::Formula {
            root_formula: formula.clone(),
        }),
        RequestedPackage::HomebrewCask(cask) => Some(PackageReceiptSource::Cask {
            cask_name: cask.clone(),
        }),
        RequestedPackage::VendorPackage(package_name) => Some(PackageReceiptSource::Vendor {
            vendor_name: package_name.clone(),
        }),
        RequestedPackage::Isotope(isotope) => Some(PackageReceiptSource::Isotope {
            isotope_name: isotope.clone(),
        }),
        RequestedPackage::NpmPackage { package, .. } => Some(PackageReceiptSource::Npm {
            package_name: package.clone(),
        }),
        RequestedPackage::PipPackage(package_name) => Some(PackageReceiptSource::Pip {
            package_name: package_name.clone(),
        }),
        RequestedPackage::Auto(_) => None,
    }
}

pub(crate) fn infer_requested_package_source(
    requested: &RequestedPackage,
) -> Result<PackageReceiptSource, String> {
    if let Some(source) = explicit_requested_package_source(requested) {
        return Ok(source);
    }

    let RequestedPackage::Auto(package_name) = requested else {
        unreachable!("qualified and aliased packages are handled above")
    };
    if let Some(package) = vendor::get(package_name) {
        if let Some(isotope_name) = preferred_auto_isotope_name(package_name)? {
            return Ok(PackageReceiptSource::Isotope { isotope_name });
        }
        return Ok(PackageReceiptSource::Vendor {
            vendor_name: package.name.to_string(),
        });
    }

    Ok(match resolve_i_root_package(package_name)? {
        EmbeddedPackage::Formula(root_formula) => {
            if let Some(isotope_name) = installable_isotope_name_for_target(
                &PackageAliasTarget::HomebrewFormula(root_formula.clone()),
            )? {
                PackageReceiptSource::Isotope { isotope_name }
            } else {
                PackageReceiptSource::Formula { root_formula }
            }
        }
        EmbeddedPackage::Cask(cask_name) => PackageReceiptSource::Cask { cask_name },
        EmbeddedPackage::NpmPackage(package_name) => PackageReceiptSource::Npm { package_name },
    })
}

pub(crate) fn resolve_latest_version_for_source(
    config: &Config,
    source: &PackageReceiptSource,
) -> Result<String, String> {
    match source {
        PackageReceiptSource::Formula { root_formula } => {
            resolve_formula_latest_version(config, root_formula)
        }
        PackageReceiptSource::Cask { cask_name } => resolve_cask_latest_version(cask_name),
        PackageReceiptSource::Isotope { isotope_name } => {
            let isotope = isotope_package_data(isotope_name)?;
            if let Some(target) = isotope_modified_package_target(isotope)? {
                return match target {
                    PackageAliasTarget::HomebrewFormula(formula) => {
                        resolve_formula_latest_version(config, &formula)
                    }
                    PackageAliasTarget::VendorPackage(vendor_name) => {
                        resolve_vendor_latest_version(&vendor_name)
                    }
                    _ => Ok(isotope.version.clone()),
                };
            }
            Ok(isotope.version.clone())
        }
        PackageReceiptSource::Vendor { vendor_name } => resolve_vendor_latest_version(vendor_name),
        PackageReceiptSource::Npm { package_name } => resolve_npm_latest_version(package_name),
        PackageReceiptSource::Pip { package_name } => resolve_pip_latest_version(package_name),
    }
}

pub(crate) fn package_source_qualified_name(source: &PackageReceiptSource) -> String {
    match source {
        PackageReceiptSource::Formula { root_formula } => crate::brew::qualified_name(root_formula),
        PackageReceiptSource::Cask { cask_name } => crate::cask::qualified_name(cask_name),
        PackageReceiptSource::Isotope { isotope_name } => {
            format!("{ISOTOPE_PACKAGE_PREFIX}{isotope_name}")
        }
        PackageReceiptSource::Vendor { vendor_name } => format!("av:{vendor_name}"),
        PackageReceiptSource::Npm { package_name } => npm_package_display_name(package_name),
        PackageReceiptSource::Pip { package_name } => pip_package_display_name(package_name),
    }
}

pub(crate) fn resolve_aliases_for_source(
    source: &PackageReceiptSource,
) -> (Vec<String>, Option<String>) {
    let mut aliases = Vec::new();
    let mut alias_error = None;

    if let PackageReceiptSource::Formula { root_formula } = source {
        match homebrew_aliases_for_formula(root_formula) {
            Ok(mut brew_aliases) => aliases.append(&mut brew_aliases),
            Err(err) => alias_error = Some(err),
        }
    } else if let PackageReceiptSource::Cask { cask_name } = source
        && let Ok(cask) = embedded_cask(cask_name)
    {
        aliases.extend(cask.aliases.iter().cloned());
    }

    aliases.sort();
    aliases.dedup();
    (aliases, alias_error)
}

pub(crate) fn homebrew_aliases_for_formula(formula: &str) -> Result<Vec<String>, String> {
    let mut aliases = formula_alias_index()?
        .iter()
        .filter_map(|(alias, canonical)| (canonical == formula).then_some(alias.clone()))
        .collect::<Vec<_>>();
    aliases.sort();
    Ok(aliases)
}

pub(crate) fn homebrew_package_info_from_formula_info(
    formula: &str,
    info: &FormulaInfo,
) -> HomebrewPackageInfo {
    HomebrewPackageInfo {
        formula: formula.to_string(),
        description: string_or_none(&info.desc),
        homepage: string_or_none(&info.homepage),
        repository: None,
        upstream_docs: None,
        docs: Vec::new(),
        license: info
            .license
            .clone()
            .and_then(|value| string_or_none(&value)),
        dependencies: info.dependencies.clone(),
    }
}

pub(crate) fn isotope_homebrew_info(
    isotope_name: &str,
    isotope: &IsotopePackageData,
) -> HomebrewPackageInfo {
    HomebrewPackageInfo {
        formula: isotope_name.to_string(),
        description: isotope
            .modifies
            .as_deref()
            .map(|modifies| format!("Radioisotope modifying {modifies}"))
            .or_else(|| {
                isotope
                    .replaces
                    .as_deref()
                    .map(|replaces| format!("Isotope mirror replacing {replaces}"))
            }),
        homepage: isotope.release_url.clone(),
        repository: None,
        upstream_docs: None,
        docs: Vec::new(),
        license: None,
        dependencies: Vec::new(),
    }
}

pub(crate) fn isotope_homebrew_formula_target(record: &IsotopePackageData) -> Option<String> {
    isotope_modified_package_target(record)
        .ok()
        .flatten()
        .or_else(|| isotope_replaced_package_target(record).ok().flatten())
        .and_then(|target| match target {
            PackageAliasTarget::HomebrewFormula(formula) => Some(formula),
            _ => None,
        })
}

fn apply_formula_db_homebrew_metadata(root_formula: &str, info: &mut PackageInfo) {
    let Ok(db) = crate::cli::load_db() else {
        return;
    };
    if crate::cli::ensure_db_schema(&db).is_err() {
        return;
    }
    let canonical =
        canonical_formula_name(root_formula).unwrap_or_else(|_| root_formula.to_string());
    let Some(metadata) = db.formulas.get(&canonical) else {
        return;
    };
    apply_formula_db_metadata_to_info(root_formula, metadata, info);
}

fn apply_formula_db_homebrew_link_metadata(root_formula: &str, info: &mut PackageInfo) {
    let description = info
        .homebrew_info
        .as_ref()
        .and_then(|homebrew_info| homebrew_info.description.clone());
    apply_formula_db_homebrew_metadata(root_formula, info);
    if let Some(description) = description
        && let Some(homebrew_info) = info.homebrew_info.as_mut()
    {
        homebrew_info.description = Some(description);
    }
}

fn apply_formula_db_metadata_to_info(
    root_formula: &str,
    metadata: &EmbeddedFormulaMetadata,
    info: &mut PackageInfo,
) {
    let existing = info
        .homebrew_info
        .take()
        .unwrap_or_else(|| HomebrewPackageInfo {
            formula: root_formula.to_string(),
            description: None,
            homepage: None,
            repository: None,
            upstream_docs: None,
            docs: Vec::new(),
            license: None,
            dependencies: Vec::new(),
        });
    let docs = non_empty_docs(&metadata.docs);
    info.homebrew_info = Some(HomebrewPackageInfo {
        formula: existing.formula,
        description: string_or_none(&metadata.summary).or(existing.description),
        homepage: string_or_none(&metadata.homepage).or(existing.homepage),
        repository: string_or_none(&metadata.repository).or(existing.repository),
        upstream_docs: string_or_none(&metadata.upstream_docs)
            .or_else(|| metadata.docs.iter().find_map(|doc| string_or_none(doc)))
            .or(existing.upstream_docs),
        docs: if docs.is_empty() { existing.docs } else { docs },
        license: existing.license,
        dependencies: existing.dependencies,
    });
}

fn apply_formula_db_metadata(root_formula: &str, info: &mut PackageInfo) {
    let Ok(db) = crate::cli::load_db() else {
        return;
    };
    if crate::cli::ensure_db_schema(&db).is_err() {
        return;
    }
    let canonical =
        canonical_formula_name(root_formula).unwrap_or_else(|_| root_formula.to_string());
    let Some(metadata) = db.formulas.get(&canonical) else {
        return;
    };
    apply_formula_db_metadata_to_info(root_formula, metadata, info);
    info.popularity = metadata.popularity.clone();
    info.last_updated_at = metadata.last_updated_at.clone();
}

pub(crate) fn formula_package_metadata(formula: &str) -> Result<PackageMetadata, String> {
    let info = fetch_formula_info(formula)?;
    Ok(PackageMetadata {
        description: string_or_none(&info.desc),
        homepage: string_or_none(&info.homepage),
    })
}

pub(crate) fn string_or_none(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub(crate) fn formula_index_entries() -> Result<&'static Vec<FormulaIndexEntry>, String> {
    FORMULA_INDEX
        .get_or_init(build_formula_index)
        .as_ref()
        .map_err(|err| err.clone())
}

pub(crate) fn format_package_info(info: &PackageInfo) -> String {
    let installed_value = if info.installed {
        info.install_root.display().to_string()
    } else {
        "no".to_string()
    };
    let mut lines = vec![plain_box_top()];
    for (index, line) in wrap_text(&info.qualified_name, INFO_WIDTH - 6)
        .into_iter()
        .enumerate()
    {
        if index == 0 {
            lines.push(format!("   📦 {line}"));
        } else {
            lines.push(format!("     {line}"));
        }
    }
    lines.push(plain_box_bottom());
    lines.push(String::new());

    push_single_line_field(
        &mut lines,
        "Version",
        &format_version_value(info),
        format_version_status(info).as_deref(),
    );
    push_single_line_field(&mut lines, "Installed", &installed_value, None);
    push_wrapped_field(
        &mut lines,
        "Source",
        &format_source_field(info.source.as_ref()),
    );
    if !info.aliases.is_empty() {
        push_wrapped_field(&mut lines, "Aliases", &info.aliases.join(", "));
    }

    let mut metadata_lines = Vec::new();
    if let Some(homebrew_info) = info.homebrew_info.as_ref() {
        if let Some(description) = homebrew_info.description.as_deref() {
            push_wrapped_field(&mut metadata_lines, "Description", description);
        }
        if let Some(homepage) = homebrew_info.homepage.as_deref() {
            push_wrapped_field(&mut metadata_lines, "Homepage", homepage);
        }
        if let Some(repository) = homebrew_info.repository.as_deref() {
            push_wrapped_field(&mut metadata_lines, "Repository", repository);
        }
        if let Some(docs) = homebrew_info.upstream_docs.as_deref() {
            push_wrapped_field(&mut metadata_lines, "Docs", docs);
        }
        if let Some(license) = homebrew_info.license.as_deref() {
            push_wrapped_field(&mut metadata_lines, "License", license);
        }
        push_wrapped_field(
            &mut metadata_lines,
            "Formula Page",
            &homebrew_formula_page_url(&homebrew_info.formula),
        );
    } else if let Some(PackageReceiptSource::Formula { root_formula }) = info.source.as_ref() {
        push_wrapped_field(
            &mut metadata_lines,
            "Formula Page",
            &homebrew_formula_page_url(root_formula),
        );
        if let Some(err) = info.homebrew_info_error.as_deref() {
            push_wrapped_field(
                &mut metadata_lines,
                "Homebrew Info",
                &format!("unavailable ({err})"),
            );
        }
    }
    if let Some(PackageReceiptSource::Npm { .. }) = info.source.as_ref() {
        if let Some(homepage) = info.npm_homepage.as_deref() {
            push_wrapped_field(&mut metadata_lines, "Homepage", homepage);
        } else if let Some(err) = info.npm_package_info_error.as_deref() {
            push_wrapped_field(
                &mut metadata_lines,
                "Homepage",
                &format!("unavailable ({err})"),
            );
        }
    }

    if !metadata_lines.is_empty() {
        lines.push(String::new());
        lines.extend(metadata_lines);
    }

    if let Some(homebrew_info) = info.homebrew_info.as_ref()
        && !homebrew_info.dependencies.is_empty()
    {
        lines.push(String::new());
        lines.push(section_top("Dependencies"));
        for line in wrap_tokens(&homebrew_info.dependencies, 2, 3) {
            lines.push(line);
        }
        lines.push(section_bottom());
    }

    if !info.executable_paths.is_empty() || info.executable_paths_error.is_some() {
        lines.push(String::new());
        lines.push(section_top("Executables"));
        if let Some(err) = info.executable_paths_error.as_deref() {
            for line in wrap_text(&format!("unavailable ({err})"), INFO_INNER_WIDTH - 2) {
                lines.push(format!("  {line}"));
            }
        } else {
            for executable in &info.executable_paths {
                for line in wrap_text(executable, INFO_INNER_WIDTH - 2) {
                    lines.push(format!("  {line}"));
                }
            }
        }
        lines.push(section_bottom());
    }

    lines.join("\n")
}

pub(crate) fn plain_box_top() -> String {
    format!("╭{}╮", "─".repeat(INFO_INNER_WIDTH))
}

pub(crate) fn plain_box_bottom() -> String {
    format!("╰{}╯", "─".repeat(INFO_INNER_WIDTH))
}

pub(crate) fn section_top(title: &str) -> String {
    let prefix = format!("╭─ {title} ");
    let fill = "─".repeat(INFO_WIDTH - prefix.chars().count() - 1);
    format!("{prefix}{fill}╮")
}

pub(crate) fn section_bottom() -> String {
    format!("╰{}╯", "─".repeat(INFO_INNER_WIDTH))
}

pub(crate) fn push_single_line_field(
    lines: &mut Vec<String>,
    label: &str,
    value: &str,
    suffix: Option<&str>,
) {
    let mut line = format!("  {label:<INFO_LABEL_WIDTH$}{value}");
    if let Some(suffix) = suffix {
        line.push_str("  ");
        line.push_str(suffix);
    }
    lines.push(line);
}

pub(crate) fn push_wrapped_field(lines: &mut Vec<String>, label: &str, value: &str) {
    let wrapped = wrap_text(value, INFO_WIDTH - 2 - INFO_LABEL_WIDTH - 2);
    let mut iter = wrapped.into_iter();
    if let Some(first) = iter.next() {
        lines.push(format!("  {label:<INFO_LABEL_WIDTH$}{first}"));
        for line in iter {
            lines.push(format!("  {:<INFO_LABEL_WIDTH$}{line}", ""));
        }
    } else {
        lines.push(format!("  {label:<INFO_LABEL_WIDTH$}"));
    }
}

pub(crate) fn wrap_text(value: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for paragraph in value.lines() {
        if paragraph.is_empty() {
            if lines.is_empty() || !lines.last().unwrap().is_empty() {
                lines.push(String::new());
            }
            continue;
        }
        let mut current = String::new();
        for word in paragraph.split_whitespace() {
            let chunks = split_text_hard(word, width);
            for chunk in chunks {
                let next_len = if current.is_empty() {
                    chunk.chars().count()
                } else {
                    current.chars().count() + 1 + chunk.chars().count()
                };
                if !current.is_empty() && next_len > width {
                    lines.push(current);
                    current = chunk;
                } else {
                    if !current.is_empty() {
                        current.push(' ');
                    }
                    current.push_str(&chunk);
                }
            }
        }
        if !current.is_empty() {
            lines.push(current);
        }
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

pub(crate) fn split_text_hard(value: &str, width: usize) -> Vec<String> {
    if value.chars().count() <= width {
        return vec![value.to_string()];
    }

    let mut chunks = Vec::new();
    let mut current = String::new();
    for ch in value.chars() {
        if current.chars().count() == width {
            chunks.push(current);
            current = String::new();
        }
        current.push(ch);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

pub(crate) fn wrap_tokens(tokens: &[String], indent: usize, gap: usize) -> Vec<String> {
    let indent_str = " ".repeat(indent);
    let gap_str = " ".repeat(gap);
    let mut lines = Vec::new();
    let mut current = indent_str.clone();
    for token in tokens {
        let candidate = if current.trim().is_empty() {
            format!("{indent_str}{token}")
        } else {
            format!("{current}{gap_str}{token}")
        };
        if current != indent_str && candidate.chars().count() > INFO_WIDTH {
            lines.push(current);
            current = format!("{indent_str}{token}");
        } else if current == indent_str {
            current.push_str(token);
        } else {
            current.push_str(&gap_str);
            current.push_str(token);
        }
    }
    if current != indent_str {
        lines.push(current);
    }
    lines
}

pub(crate) fn format_source_field(source: Option<&PackageReceiptSource>) -> String {
    match source {
        Some(PackageReceiptSource::Formula { .. }) => "Homebrew".to_string(),
        Some(PackageReceiptSource::Cask { .. }) => "Homebrew Cask".to_string(),
        Some(PackageReceiptSource::Isotope { .. }) => "Isotope".to_string(),
        Some(PackageReceiptSource::Vendor { .. }) => "Subs".to_string(),
        Some(PackageReceiptSource::Npm { .. }) => "npm".to_string(),
        Some(PackageReceiptSource::Pip { .. }) => "PyPI".to_string(),
        None => "Unknown".to_string(),
    }
}

pub(crate) fn format_version_value(info: &PackageInfo) -> String {
    if let Some(installed_version) = info.installed_version.as_deref() {
        installed_version.to_string()
    } else if let Some(latest_version) = info.latest_version.as_deref() {
        latest_version.to_string()
    } else {
        "unknown".to_string()
    }
}

pub(crate) fn format_version_status(info: &PackageInfo) -> Option<String> {
    if !info.installed {
        return None;
    }
    match (&info.installed_version, &info.latest_version) {
        (Some(installed_version), Some(latest_version)) if installed_version == latest_version => {
            Some("✔ up to date".to_string())
        }
        (Some(_), Some(latest_version)) => Some(format!("update available ({latest_version})")),
        (_, Some(_)) => None,
        (_, None) => info
            .latest_version_error
            .as_ref()
            .map(|err| format!("latest unknown ({err})")),
    }
}

pub(crate) fn homebrew_formula_page_url(formula: &str) -> String {
    format!("https://formulae.brew.sh/formula/{formula}")
}

pub(crate) fn installed_stub_paths_at(install_root: &Path) -> Result<Vec<String>, String> {
    let mut paths = load_stub_manifest(&install_root.join(STUB_MANIFEST))?
        .stubs
        .into_iter()
        .map(|stub| managed_bin_root().join(stub).display().to_string())
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

#[cfg(test)]
pub(crate) fn installed_package_names(opt_root: &Path) -> Result<Vec<String>, String> {
    Ok(installed_package_refs(opt_root)?
        .into_iter()
        .map(|package| package.package_name)
        .collect())
}

pub(crate) fn installed_package_refs(opt_root: &Path) -> Result<Vec<InstalledPackageRef>, String> {
    let entries = match fs::read_dir(opt_root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(format!("failed to read {}: {err}", opt_root.display())),
    };

    let mut packages = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| format!("failed to read {}: {err}", opt_root.display()))?;
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("non-utf8 directory name under {}", opt_root.display()))?;
        if name.starts_with('.') || !path.is_dir() {
            continue;
        }
        if name == "homebrew" {
            continue;
        }
        if name == "npm" {
            packages.extend(installed_npm_package_refs(&path)?);
            continue;
        }
        if name == "pip" {
            packages.extend(installed_pip_package_refs(&path)?);
            continue;
        }
        if name == ISOTOPE_INSTALL_ROOT_DIR {
            packages.extend(installed_isotope_package_refs(&path)?);
            continue;
        }
        packages.push(InstalledPackageRef {
            package_name: name,
            install_root: path,
        });
    }
    Ok(packages)
}

pub(crate) fn installed_npm_package_refs(
    npm_root: &Path,
) -> Result<Vec<InstalledPackageRef>, String> {
    let entries = match fs::read_dir(npm_root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(format!("failed to read {}: {err}", npm_root.display())),
    };

    let mut packages = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| format!("failed to read {}: {err}", npm_root.display()))?;
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("non-utf8 directory name under {}", npm_root.display()))?;
        if name.starts_with('.') || !path.is_dir() {
            continue;
        }
        if name.starts_with('@') {
            let scope_entries = fs::read_dir(&path)
                .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
            for scope_entry in scope_entries {
                let scope_entry = scope_entry
                    .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
                let scoped_path = scope_entry.path();
                let scoped_name = scope_entry
                    .file_name()
                    .into_string()
                    .map_err(|_| format!("non-utf8 directory name under {}", path.display()))?;
                if scoped_name.starts_with('.') || !scoped_path.is_dir() {
                    continue;
                }
                let package = format!("{name}/{scoped_name}");
                packages.push(InstalledPackageRef {
                    package_name: match load_package_receipt(&scoped_path.join(ROOT_RECEIPT)) {
                        Ok(Some(receipt)) => receipt.package_name,
                        Ok(None) | Err(_) => npm_package_display_name(&package),
                    },
                    install_root: scoped_path,
                });
            }
            continue;
        }
        packages.push(InstalledPackageRef {
            package_name: match load_package_receipt(&path.join(ROOT_RECEIPT)) {
                Ok(Some(receipt)) => receipt.package_name,
                Ok(None) | Err(_) => npm_package_display_name(&name),
            },
            install_root: path,
        });
    }
    Ok(packages)
}

pub(crate) fn installed_isotope_package_refs(
    isotope_root: &Path,
) -> Result<Vec<InstalledPackageRef>, String> {
    let entries = match fs::read_dir(isotope_root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(format!("failed to read {}: {err}", isotope_root.display())),
    };

    let mut packages = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|err| format!("failed to read {}: {err}", isotope_root.display()))?;
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("non-utf8 directory name under {}", isotope_root.display()))?;
        if name.starts_with('.') || !path.is_dir() {
            continue;
        }
        packages.push(InstalledPackageRef {
            package_name: format!("{ISOTOPE_PACKAGE_PREFIX}{name}"),
            install_root: path,
        });
    }
    Ok(packages)
}

pub(crate) fn installed_pip_package_refs(
    pip_root: &Path,
) -> Result<Vec<InstalledPackageRef>, String> {
    let entries = match fs::read_dir(pip_root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(format!("failed to read {}: {err}", pip_root.display())),
    };

    let mut packages = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| format!("failed to read {}: {err}", pip_root.display()))?;
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("non-utf8 directory name under {}", pip_root.display()))?;
        if name.starts_with('.') || !path.is_dir() {
            continue;
        }
        packages.push(InstalledPackageRef {
            package_name: match load_package_receipt(&path.join(ROOT_RECEIPT)) {
                Ok(Some(receipt)) => receipt.package_name,
                Ok(None) | Err(_) => pip_package_display_name(&name),
            },
            install_root: path,
        });
    }
    Ok(packages)
}

pub(crate) fn load_or_resolve_package_receipt(
    package_name: &str,
    install_root: &Path,
) -> Result<PackageReceipt, String> {
    load_package_receipt(&install_root.join(ROOT_RECEIPT))?
        .ok_or_else(|| format!("package {package_name} is installed but missing package metadata"))
}

pub(crate) fn load_package_receipt(path: &Path) -> Result<Option<PackageReceipt>, String> {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };
    let receipt = serde_json::from_slice(&data)
        .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;
    Ok(Some(receipt))
}

pub(crate) fn write_package_receipt(path: &Path, receipt: &PackageReceipt) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(receipt)
        .map_err(|err| format!("failed to serialize package receipt: {err}"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    fs::write(path, data).map_err(|err| format!("failed to write {}: {err}", path.display()))
}

pub(crate) fn resolve_formula_latest_version(
    config: &Config,
    formula: &str,
) -> Result<String, String> {
    let info = fetch_formula_info(formula)?;
    ensure_formula_has_bottle(formula, &info, &config.bottle_tag)?;
    Ok(formula_version_string(&info))
}

pub(crate) fn resolve_cask_latest_version(cask: &str) -> Result<String, String> {
    Ok(embedded_cask(cask)?.version.clone())
}

pub(crate) fn resolve_vendor_latest_version(package_name: &str) -> Result<String, String> {
    let package = vendor::get(package_name)
        .ok_or_else(|| format!("vendor package {package_name} is not registered"))?;
    (package.version)().map(|version| version.to_string())
}

pub(crate) fn resolve_npm_package_version(package_name: &str) -> Result<semver::Version, String> {
    let version = vendor::npm_latest_tag(package_name)?;
    vendor::parse_semver(&version, package_name)
}

pub(crate) fn resolve_npm_latest_version(package_name: &str) -> Result<String, String> {
    resolve_npm_package_version(package_name).map(|version| version.to_string())
}

pub(crate) fn resolve_npm_homepage(package_name: &str) -> Result<Option<String>, String> {
    Ok(resolve_npm_package_metadata(package_name)?.homepage)
}

pub(crate) fn resolve_npm_package_metadata(package_name: &str) -> Result<PackageMetadata, String> {
    let url = format!(
        "{}/{}",
        config::npm_registry_root(),
        urlencoding::encode(package_name)
    );
    let response: NpmPackageMetadata = fetch_json(&url, || {
        format!("failed to fetch npm metadata for {package_name}")
    })?;
    Ok(PackageMetadata {
        description: response
            .description
            .and_then(|value| string_or_none(&value)),
        homepage: response.homepage.and_then(|value| string_or_none(&value)),
    })
}

pub(crate) fn resolve_pip_latest_version(package_name: &str) -> Result<String, String> {
    let response = fetch_pypi_package_info(package_name)?;
    if response.info.version.is_empty() {
        return Err(format!(
            "failed to resolve latest PyPI version for {package_name}"
        ));
    }
    Ok(response.info.version)
}

pub(crate) fn resolve_pip_package_metadata(package_name: &str) -> Result<PackageMetadata, String> {
    let response = fetch_pypi_package_info(package_name)?;
    Ok(PackageMetadata {
        description: string_or_none(&response.info.summary),
        homepage: string_or_none(&response.info.home_page),
    })
}

fn fetch_pypi_package_info(package_name: &str) -> Result<PypiPackageInfoResponse, String> {
    let normalized = normalize_pip_package_name(package_name);
    let url = format!("{}/{}/json", pypi_root(), urlencoding::encode(&normalized));
    fetch_json(&url, || {
        format!("failed to fetch PyPI metadata for {package_name}")
    })
}

#[cfg(test)]
pub(crate) fn extract_semver_from_text(text: &str) -> Option<semver::Version> {
    for token in text.split_whitespace() {
        let token = token.trim_matches(|ch: char| {
            !ch.is_ascii_alphanumeric() && !matches!(ch, '.' | '-' | '+' | '_')
        });
        let token = token.strip_prefix('v').unwrap_or(token);
        if token.is_empty() {
            continue;
        }
        if let Ok(version) = semver::Version::parse(token) {
            return Some(version);
        }
    }
    None
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

    fn search_result(
        package_name: &str,
        source: PackageReceiptSource,
        summary: Option<&str>,
        rank: Option<u32>,
    ) -> PackageSearchResult {
        PackageSearchResult {
            package_name: package_name.to_string(),
            source,
            summary: summary.map(str::to_string),
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
    fn homebrew_formula_is_installed_at_requires_version_receipt() {
        let temp = TempDir::new().unwrap();
        let cellar = temp.path().join("Cellar");

        assert!(!homebrew_formula_is_installed_at(&cellar, "awscli"));

        let formula_root = cellar.join("awscli");
        fs::create_dir_all(&formula_root).unwrap();
        assert!(!homebrew_formula_is_installed_at(&cellar, "awscli"));

        let version_root = formula_root.join("2.27.0");
        fs::create_dir_all(&version_root).unwrap();
        assert!(!homebrew_formula_is_installed_at(&cellar, "awscli"));

        fs::write(version_root.join(HOMEBREW_INSTALL_RECEIPT), "{}").unwrap();
        assert!(homebrew_formula_is_installed_at(&cellar, "awscli"));

        let tapped_root = cellar.join("acli").join("1.2.3");
        fs::create_dir_all(&tapped_root).unwrap();
        fs::write(tapped_root.join(HOMEBREW_INSTALL_RECEIPT), "{}").unwrap();
        assert!(homebrew_formula_is_installed_at(
            &cellar,
            "atlassian/acli/acli"
        ));
    }

    #[test]
    fn security_recommendation_vault_filter_matches_formula_receipts() {
        let temp = TempDir::new().unwrap();
        let opt_root = temp.path().join("opt");
        let recommendation = SecurityRecommendationPackage {
            name: "awscli".to_string(),
            install_package_name: "brew:awscli".to_string(),
            ..SecurityRecommendationPackage::default()
        };

        assert!(!security_recommendation_has_vault_install(
            &opt_root,
            "brew:awscli",
            &recommendation
        ));

        let install_root = package_install_root(&opt_root, "awscli").unwrap();
        fs::create_dir_all(&install_root).unwrap();
        write_package_receipt(
            &install_root.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "awscli".to_string(),
                version: "2.27.0".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "awscli".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();

        assert!(security_recommendation_has_vault_install(
            &opt_root,
            "brew:awscli",
            &recommendation
        ));
    }

    #[test]
    fn security_recommendation_results_require_homebrew_without_vault_install() {
        let temp = TempDir::new().unwrap();
        let cellar = temp.path().join("Cellar");
        let opt_root = temp.path().join("opt");
        for formula in ["awscli", "gh"] {
            let version_root = cellar.join(formula).join("1.0.0");
            fs::create_dir_all(&version_root).unwrap();
            fs::write(version_root.join(HOMEBREW_INSTALL_RECEIPT), "{}").unwrap();
        }

        let results =
            resolve_security_recommendation_package_results_at(&cellar, &opt_root).unwrap();
        assert_eq!(results.len(), 2);
        let awscli = results
            .iter()
            .find(|result| result.package_name == "brew:awscli")
            .unwrap();
        assert_eq!(awscli.install_package_names, vec!["brew:awscli"]);
        assert!(awscli.summary.as_deref().unwrap().contains("AWS"));
        assert!(awscli.security_state.is_some());

        let gh = results
            .iter()
            .find(|result| result.package_name == "brew:gh")
            .unwrap();
        let gh_summary = gh.summary.as_deref().unwrap();
        assert!(gh_summary.contains("GitHub CLI"));
        assert!(gh_summary.contains("Geiger: orange."));
        assert!(gh_summary.contains("Confidence: high."));
        assert!(gh_summary.contains("Category: infrastructure."));

        let isotope_root = package_install_root(&opt_root, "isotope:gh").unwrap();
        fs::create_dir_all(&isotope_root).unwrap();
        write_package_receipt(
            &isotope_root.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "isotope:gh".to_string(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Isotope {
                    isotope_name: "gh".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();

        let filtered =
            resolve_security_recommendation_package_results_at(&cellar, &opt_root).unwrap();
        assert!(
            filtered
                .iter()
                .all(|result| result.package_name != "brew:gh")
        );
        assert!(
            filtered
                .iter()
                .any(|result| result.package_name == "brew:awscli")
        );
    }

    #[test]
    fn security_recommendation_result_falls_back_without_formula_index_match() {
        let recommendation = SecurityRecommendationPackage {
            install_package_name: "brew:tap/tool/tool".to_string(),
            reasons: vec!["  ".to_string()],
            approval_gate: true,
            signals: vec!["isotope".to_string()],
            ..SecurityRecommendationPackage::default()
        };

        let result =
            security_recommendation_package_result("brew:tap/tool/tool", &recommendation, &[])
                .unwrap();

        assert_eq!(result.package_name, "brew:tap/tool/tool");
        assert_eq!(
            result.source,
            PackageReceiptSource::Formula {
                root_formula: "tap/tool/tool".to_string()
            }
        );
        assert_eq!(result.install_package_names, vec!["brew:tap/tool/tool"]);
        assert_eq!(
            result.summary.as_deref(),
            Some(
                "Root-owned Automic Vault install recommended. Approval gate metadata is available."
            )
        );
        assert_eq!(homebrew_formula_cellar_name("tap/tool/tool"), "tool");
        assert_eq!(
            compare_security_recommendation_rank_order(
                &search_result("ranked", result.source.clone(), None, Some(1)),
                &search_result("unranked", result.source, None, None),
            ),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn search_ranking_helpers_cover_names_summaries_sources_and_popularity() {
        let exact = search_result(
            "ripgrep",
            PackageReceiptSource::Formula {
                root_formula: "ripgrep".to_string(),
            },
            Some("fast recursive search"),
            Some(20),
        );
        let prefix = search_result(
            "ripgrep-all",
            PackageReceiptSource::Cask {
                cask_name: "rg-suite".to_string(),
            },
            None,
            Some(10),
        );
        let summary = search_result(
            "other-tool",
            PackageReceiptSource::Npm {
                package_name: "@scope/other-tool".to_string(),
            },
            Some("contains ripgrep in summary"),
            None,
        );
        let vendor = search_result(
            "av:terraform",
            PackageReceiptSource::Vendor {
                vendor_name: "terraform".to_string(),
            },
            None,
            Some(1),
        );
        let pip = search_result(
            "pip:ruff",
            PackageReceiptSource::Pip {
                package_name: "ruff".to_string(),
            },
            None,
            None,
        );
        let isotope = search_result(
            "isotope:aws-cli",
            PackageReceiptSource::Isotope {
                isotope_name: "aws-cli".to_string(),
            },
            None,
            None,
        );

        assert_eq!(search_result_match_rank(&exact, "ripgrep"), 0);
        assert_eq!(search_result_match_rank(&prefix, "rip"), 1);
        assert_eq!(search_result_match_rank(&summary, "ripgrep"), 3);
        assert_eq!(search_result_match_rank(&summary, "missing"), 4);
        assert_eq!(search_result_match_rank(&summary, ""), 5);
        assert_eq!(search_result_match_distance(&prefix, "grep"), 10);
        assert_eq!(search_result_match_distance(&summary, "ripgrep"), 9);
        assert_eq!(search_result_match_distance(&summary, ""), usize::MAX);
        assert!(search_result_name_candidates(&vendor).contains(&"terraform".to_string()));
        assert!(search_result_name_candidates(&pip).contains(&"ruff".to_string()));
        assert!(search_result_name_candidates(&isotope).contains(&"aws-cli".to_string()));
        assert_eq!(
            compare_optional_popularity_rank(Some(1), None),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_optional_popularity_rank(None, Some(1)),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_package_search_results_for_query("ripgrep", &exact, &summary),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn search_relevance_prioritizes_formula_family_for_base_query() {
        let mut results = [
            search_result(
                "npm:@babel/node",
                PackageReceiptSource::Npm {
                    package_name: "@babel/node".to_string(),
                },
                Some("Babel command line"),
                Some(105),
            ),
            search_result(
                "node@20",
                PackageReceiptSource::Formula {
                    root_formula: "node@20".to_string(),
                },
                Some("JavaScript runtime"),
                Some(348),
            ),
            search_result(
                "nodenv",
                PackageReceiptSource::Formula {
                    root_formula: "nodenv".to_string(),
                },
                Some("Node.js version manager"),
                Some(1318),
            ),
            search_result(
                "node",
                PackageReceiptSource::Formula {
                    root_formula: "node".to_string(),
                },
                Some("JavaScript runtime"),
                Some(5),
            ),
            search_result(
                "node@24",
                PackageReceiptSource::Formula {
                    root_formula: "node@24".to_string(),
                },
                Some("JavaScript runtime"),
                Some(481),
            ),
            search_result(
                "npm:nodemon",
                PackageReceiptSource::Npm {
                    package_name: "nodemon".to_string(),
                },
                Some("Monitor script for Node.js apps"),
                Some(29),
            ),
        ];

        results
            .sort_by(|left, right| compare_package_search_results_for_query("node", left, right));

        assert_eq!(
            results
                .iter()
                .map(|result| result.package_name.as_str())
                .collect::<Vec<_>>(),
            [
                "node",
                "node@20",
                "node@24",
                "npm:@babel/node",
                "nodenv",
                "npm:nodemon",
            ]
        );
    }

    #[test]
    fn installed_package_refs_cover_nested_source_roots_and_receipt_fallbacks() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("npm/@scope/pkg")).unwrap();
        fs::create_dir_all(root.join("npm/plain")).unwrap();
        fs::create_dir_all(root.join("pip/Some_Pkg")).unwrap();
        fs::create_dir_all(root.join(ISOTOPE_INSTALL_ROOT_DIR).join("gh")).unwrap();
        fs::create_dir_all(root.join("regular")).unwrap();
        fs::create_dir_all(root.join(".hidden")).unwrap();
        fs::write(root.join("not-a-dir"), b"file").unwrap();
        write_package_receipt(
            &root.join("npm/@scope/pkg").join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "npm:@scope/pkg".to_string(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Npm {
                    package_name: "@scope/pkg".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();
        write_package_receipt(
            &root.join("pip/Some_Pkg").join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "pip:custom-name".to_string(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Pip {
                    package_name: "Some_Pkg".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();

        let names = installed_package_refs(root)
            .unwrap()
            .into_iter()
            .map(|package| package.package_name)
            .collect::<Vec<_>>();

        assert!(names.contains(&"npm:@scope/pkg".to_string()));
        assert!(names.contains(&"npm:plain".to_string()));
        assert!(names.contains(&"pip:custom-name".to_string()));
        assert!(names.contains(&"isotope:gh".to_string()));
        assert!(names.contains(&"regular".to_string()));
        assert!(!names.contains(&".hidden".to_string()));
    }

    #[test]
    fn package_stubs_are_active_requires_manifest_and_owned_stub() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let install_root = temp.path().join("install");
        fs::create_dir_all(&install_root).unwrap();
        assert!(!package_stubs_are_active(&install_root, "coverage-active").unwrap());

        write_stub_manifest(
            &install_root.join(STUB_MANIFEST),
            &StubManifest {
                stubs: vec!["coverage-active".to_string()],
            },
        )
        .unwrap();
        assert!(!package_stubs_are_active(&install_root, "coverage-active").unwrap());

        let stub_path = managed_bin_root().join("coverage-active");
        fs::create_dir_all(stub_path.parent().unwrap()).unwrap();
        if fs::symlink_metadata(&stub_path).is_ok() {
            remove_path(&stub_path).unwrap();
        }
        let plan = InstallPlan {
            mode: Mode::I,
            package_name: "coverage-active".to_string(),
            root_formula: "coverage-active".to_string(),
            stable_root: install_root.clone(),
            install_root: install_root.clone(),
            tmp_root: temp.path().join("tmp"),
        };
        write_stub(
            &plan,
            &stub_path,
            &install_root.join("bin/coverage-active"),
            &[],
        )
        .unwrap();

        assert!(package_stubs_are_active(&install_root, "coverage-active").unwrap());
        remove_path(&stub_path).unwrap();
    }

    #[test]
    fn status_and_record_wrappers_cover_all_installed_and_requested_paths() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let record_root = write_test_receipt(
            "coverage-all-record",
            "1.0.0",
            PackageReceiptSource::Formula {
                root_formula: "coverage-all-record".to_string(),
            },
        );
        let status_root = write_test_receipt(
            "coverage-all-status",
            "0.0.1",
            PackageReceiptSource::Isotope {
                isotope_name: "gh".to_string(),
            },
        );
        let config = Config {
            bottle_tag: "all".to_string(),
        };

        let all_statuses =
            resolve_package_statuses(&config, &PackageSelection::AllInstalled).unwrap();
        assert!(all_statuses.iter().any(|status| {
            status.package_name == "coverage-all-status"
                && status.installed_version == "0.0.1"
                && status.latest_version != "0.0.1"
        }));

        let requested_statuses = resolve_package_statuses(
            &config,
            &PackageSelection::Requested(vec![RequestedPackage::Auto(
                "coverage-all-status".to_string(),
            )]),
        )
        .unwrap();
        assert_eq!(requested_statuses.len(), 1);
        assert_eq!(requested_statuses[0].package_name, "coverage-all-status");

        let all_records =
            resolve_installed_package_records(&PackageSelection::AllInstalled).unwrap();
        assert!(all_records.iter().any(|record| {
            record.package_name == "coverage-all-record" && record.installed_version == "1.0.0"
        }));

        let requested_records =
            resolve_installed_package_records(&PackageSelection::Requested(vec![
                RequestedPackage::Auto("coverage-all-record".to_string()),
            ]))
            .unwrap();
        assert_eq!(requested_records.len(), 1);
        assert_eq!(requested_records[0].package_name, "coverage-all-record");

        remove_path(&record_root).unwrap();
        remove_path(&status_root).unwrap();
    }

    #[test]
    fn package_status_at_rejects_missing_and_non_directory_roots() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let temp = TempDir::new().unwrap();
        let config = Config {
            bottle_tag: "all".to_string(),
        };
        let missing = temp.path().join("missing");
        assert!(
            resolve_package_status_at(&config, "missing", &missing)
                .unwrap_err()
                .contains("is not installed")
        );

        let file = temp.path().join("not-a-directory");
        fs::write(&file, b"hi").unwrap();
        assert!(
            resolve_package_status_at(&config, "file", &file)
                .unwrap_err()
                .contains("is not a directory")
        );
    }

    #[test]
    fn package_name_helpers_cover_all_supported_request_shapes() {
        assert_eq!(
            compare_package_names_for_search_order("npm:@scope/zeta", "brew:alpha"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_package_names_for_search_order("pip:@scope/alpha", "npm:@other/alpha"),
            std::cmp::Ordering::Greater
        );

        assert_eq!(
            requested_package_name(&RequestedPackage::Auto("ripgrep".to_string())),
            "ripgrep"
        );
        assert_eq!(
            requested_package_name(&RequestedPackage::HomebrewFormula("ripgrep".to_string())),
            "ripgrep"
        );
        assert_eq!(
            requested_package_name(&RequestedPackage::HomebrewCask("cursor".to_string())),
            "cursor"
        );
        assert_eq!(
            requested_package_name(&RequestedPackage::VendorPackage("terraform".to_string())),
            "terraform"
        );
        assert_eq!(
            requested_package_name(&RequestedPackage::Isotope("gh".to_string())),
            "isotope:gh"
        );
        assert_eq!(
            requested_package_name(&RequestedPackage::NpmPackage {
                package: "@openai/codex".to_string(),
                version: Some("1.0.0".to_string()),
            }),
            "npm:@openai/codex"
        );
        assert_eq!(
            requested_package_name(&RequestedPackage::PipPackage("My_Package.Name".to_string())),
            "pip:My_Package.Name"
        );
    }

    #[test]
    fn install_name_and_status_helpers_cover_variants_and_deduping() {
        assert_eq!(
            requested_install_package_name(&RequestedPackage::Auto("bun".to_string())).unwrap(),
            "bun"
        );
        assert_eq!(
            requested_install_package_name(&RequestedPackage::Auto("terraform".to_string()))
                .unwrap(),
            "isotope:terraform"
        );
        assert_eq!(
            requested_install_package_name(&RequestedPackage::Auto("awscli".to_string())).unwrap(),
            "isotope:aws-cli"
        );
        assert_eq!(
            requested_install_package_name(&RequestedPackage::Auto("rg".to_string())).unwrap(),
            "ripgrep"
        );
        assert_eq!(
            requested_install_package_name(&RequestedPackage::HomebrewFormula(
                "awscli".to_string()
            ))
            .unwrap(),
            "awscli"
        );
        assert_eq!(
            requested_install_package_name(&RequestedPackage::HomebrewFormula(
                "python@3.14".to_string()
            ))
            .unwrap(),
            "python@3.14"
        );
        assert_eq!(
            requested_install_package_name(&RequestedPackage::VendorPackage(
                "terraform".to_string()
            ))
            .unwrap(),
            "terraform"
        );
        assert_eq!(
            requested_install_package_name(&RequestedPackage::HomebrewCask("codex".to_string()))
                .unwrap(),
            "codex"
        );
        assert_eq!(
            requested_install_package_name(&RequestedPackage::Isotope("gh".to_string())).unwrap(),
            "isotope:gh"
        );
        assert_eq!(
            requested_install_package_name(&RequestedPackage::NpmPackage {
                package: "@openai/codex".to_string(),
                version: Some("1.0.0".to_string()),
            })
            .unwrap(),
            "npm:@openai/codex"
        );
        assert_eq!(
            requested_install_package_name(&RequestedPackage::PipPackage(
                "My_Package.Name".to_string()
            ))
            .unwrap(),
            "pip:My_Package.Name"
        );

        let outdated = filter_outdated_package_statuses(vec![
            PackageStatus {
                package_name: "ripgrep".to_string(),
                source: PackageReceiptSource::Formula {
                    root_formula: "ripgrep".to_string(),
                },
                installed_version: "14.0.0".to_string(),
                latest_version: "14.1.0".to_string(),
            },
            PackageStatus {
                package_name: "codex".to_string(),
                source: PackageReceiptSource::Cask {
                    cask_name: "codex".to_string(),
                },
                installed_version: "1.0.0".to_string(),
                latest_version: "1.0.0".to_string(),
            },
        ]);
        assert_eq!(outdated.len(), 1);
        assert_eq!(outdated[0].package_name, "ripgrep");

        let update_candidates = filter_update_package_statuses(vec![
            PackageStatus {
                package_name: "isotope:aws-cli".to_string(),
                source: PackageReceiptSource::Isotope {
                    isotope_name: "aws-cli".to_string(),
                },
                installed_version: "2.34.54".to_string(),
                latest_version: "2.34.54".to_string(),
            },
            PackageStatus {
                package_name: "isotope:gh".to_string(),
                source: PackageReceiptSource::Isotope {
                    isotope_name: "gh".to_string(),
                },
                installed_version: "2.83.0".to_string(),
                latest_version: "2.83.0".to_string(),
            },
            PackageStatus {
                package_name: "deno".to_string(),
                source: PackageReceiptSource::Vendor {
                    vendor_name: "deno".to_string(),
                },
                installed_version: "2.7.7".to_string(),
                latest_version: "2.7.8".to_string(),
            },
        ]);
        assert_eq!(
            update_candidates
                .into_iter()
                .map(|status| status.package_name)
                .collect::<Vec<_>>(),
            vec!["isotope:aws-cli".to_string(), "deno".to_string()]
        );

        let cask = PackageStatus {
            package_name: "codex".to_string(),
            source: PackageReceiptSource::Cask {
                cask_name: "codex".to_string(),
            },
            installed_version: "1.0.0".to_string(),
            latest_version: "1.1.0".to_string(),
        };
        let isotope = PackageStatus {
            package_name: "isotope:gh".to_string(),
            source: PackageReceiptSource::Isotope {
                isotope_name: "gh".to_string(),
            },
            installed_version: "2.0.0".to_string(),
            latest_version: "2.1.0".to_string(),
        };
        let vendor = PackageStatus {
            package_name: "bun".to_string(),
            source: PackageReceiptSource::Vendor {
                vendor_name: "bun".to_string(),
            },
            installed_version: "1.0.0".to_string(),
            latest_version: "1.1.0".to_string(),
        };
        assert_eq!(
            requested_package_from_status(&cask),
            RequestedPackage::HomebrewCask("codex".to_string())
        );
        assert_eq!(
            requested_package_from_status(&isotope),
            RequestedPackage::Isotope("gh".to_string())
        );
        assert_eq!(
            requested_package_from_status(&vendor),
            RequestedPackage::VendorPackage("bun".to_string())
        );
    }

    #[test]
    fn scanned_record_and_status_helpers_sort_dedupe_and_warn() {
        let packages = vec![
            InstalledPackageRef {
                package_name: "npm:@scope/zeta".to_string(),
                install_root: PathBuf::from("/tmp/zeta"),
            },
            InstalledPackageRef {
                package_name: "brew:alpha".to_string(),
                install_root: PathBuf::from("/tmp/alpha-b"),
            },
            InstalledPackageRef {
                package_name: "brew:alpha".to_string(),
                install_root: PathBuf::from("/tmp/alpha-a"),
            },
        ];

        let mut record_warnings = Vec::new();
        let records = resolve_scanned_package_records(
            packages.clone(),
            |package| {
                if package.package_name == "npm:@scope/zeta" {
                    return Err("boom".to_string());
                }
                Ok(InstalledPackageRecord {
                    package_name: package.package_name.clone(),
                    source: PackageReceiptSource::Formula {
                        root_formula: package.package_name.clone(),
                    },
                    installed_version: "1.0.0".to_string(),
                })
            },
            |message| record_warnings.push(message),
        )
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].package_name, "brew:alpha");
        assert_eq!(record_warnings.len(), 1);
        assert!(record_warnings[0].contains("/tmp/zeta"));

        let mut status_warnings = Vec::new();
        let statuses = resolve_scanned_package_statuses(
            packages,
            |package| {
                if package.install_root == Path::new("/tmp/alpha-a") {
                    return Err("skip duplicate root".to_string());
                }
                Ok(PackageStatus {
                    package_name: package.package_name.clone(),
                    source: PackageReceiptSource::Formula {
                        root_formula: package.package_name.clone(),
                    },
                    installed_version: "1.0.0".to_string(),
                    latest_version: "1.1.0".to_string(),
                })
            },
            |message| status_warnings.push(message),
        )
        .unwrap();
        assert_eq!(statuses.len(), 2);
        assert_eq!(statuses[0].package_name, "brew:alpha");
        assert_eq!(statuses[1].package_name, "npm:@scope/zeta");
        assert_eq!(status_warnings.len(), 0);
    }

    #[test]
    fn requested_source_helpers_cover_explicit_and_inferred_variants() {
        assert_eq!(
            explicit_requested_package_source(&RequestedPackage::HomebrewFormula(
                "python@3.14".to_string()
            )),
            Some(PackageReceiptSource::Formula {
                root_formula: "python@3.14".to_string(),
            })
        );
        assert_eq!(
            explicit_requested_package_source(&RequestedPackage::HomebrewCask("codex".to_string())),
            Some(PackageReceiptSource::Cask {
                cask_name: "codex".to_string(),
            })
        );
        assert_eq!(
            explicit_requested_package_source(&RequestedPackage::VendorPackage(
                "terraform".to_string()
            )),
            Some(PackageReceiptSource::Vendor {
                vendor_name: "terraform".to_string(),
            })
        );
        assert_eq!(
            explicit_requested_package_source(&RequestedPackage::Isotope("gh".to_string())),
            Some(PackageReceiptSource::Isotope {
                isotope_name: "gh".to_string(),
            })
        );
        assert_eq!(
            explicit_requested_package_source(&RequestedPackage::PipPackage(
                "My_Package.Name".to_string()
            )),
            Some(PackageReceiptSource::Pip {
                package_name: "My_Package.Name".to_string(),
            })
        );
        assert_eq!(
            explicit_requested_package_source(&RequestedPackage::NpmPackage {
                package: "@scope/tool".to_string(),
                version: Some("1.2.3".to_string()),
            }),
            Some(PackageReceiptSource::Npm {
                package_name: "@scope/tool".to_string(),
            })
        );
        assert_eq!(
            explicit_requested_package_source(&RequestedPackage::Auto("bun".to_string())),
            None
        );

        assert_eq!(
            infer_requested_package_source(&RequestedPackage::Auto("bun".to_string())).unwrap(),
            PackageReceiptSource::Vendor {
                vendor_name: "bun".to_string(),
            }
        );
        assert_eq!(
            infer_requested_package_source(&RequestedPackage::Auto("terraform".to_string()))
                .unwrap(),
            PackageReceiptSource::Isotope {
                isotope_name: "terraform".to_string(),
            }
        );
        assert_eq!(
            infer_requested_package_source(&RequestedPackage::Auto("awscli".to_string())).unwrap(),
            PackageReceiptSource::Isotope {
                isotope_name: "aws-cli".to_string(),
            }
        );
        assert_eq!(
            infer_requested_package_source(&RequestedPackage::Auto("ripgrep".to_string())).unwrap(),
            PackageReceiptSource::Formula {
                root_formula: "ripgrep".to_string(),
            }
        );
        assert_eq!(
            infer_requested_package_source(&RequestedPackage::Auto("coverage-npm".to_string()))
                .unwrap(),
            PackageReceiptSource::Npm {
                package_name: "coverage-npm".to_string(),
            }
        );
    }

    #[test]
    fn installed_package_ref_helpers_cover_nested_source_roots() {
        let temp = TempDir::new().unwrap();
        let opt_root = temp.path();
        fs::create_dir_all(opt_root.join("ripgrep")).unwrap();
        fs::create_dir_all(opt_root.join("homebrew")).unwrap();
        fs::write(opt_root.join("plain-file"), b"ignored").unwrap();
        fs::create_dir_all(opt_root.join(".hidden")).unwrap();

        let npm_unscoped = opt_root.join("npm/openclaw");
        fs::create_dir_all(&npm_unscoped).unwrap();
        write_package_receipt(
            &npm_unscoped.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "npm:coverage-npm".to_string(),
                version: "1.0.0".to_string(),
                source: PackageReceiptSource::Npm {
                    package_name: "coverage-npm".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();

        let npm_scoped = opt_root.join("npm/@openai/codex");
        fs::create_dir_all(&npm_scoped).unwrap();

        let pip_package = opt_root.join("pip/My_Package.Name");
        fs::create_dir_all(&pip_package).unwrap();

        let isotope_package = opt_root.join("iso/gh");
        fs::create_dir_all(&isotope_package).unwrap();

        let mut names = installed_package_names(opt_root).unwrap();
        names.sort();
        assert_eq!(
            names,
            vec![
                "isotope:gh".to_string(),
                "npm:@openai/codex".to_string(),
                "npm:coverage-npm".to_string(),
                "pip:My_Package.Name".to_string(),
                "ripgrep".to_string(),
            ]
        );

        let npm_refs = installed_npm_package_refs(&opt_root.join("npm")).unwrap();
        assert_eq!(npm_refs.len(), 2);
        assert!(
            npm_refs
                .iter()
                .any(|package| package.package_name == "npm:coverage-npm")
        );
        assert!(
            npm_refs
                .iter()
                .any(|package| package.package_name == "npm:@openai/codex")
        );

        let pip_refs = installed_pip_package_refs(&opt_root.join("pip")).unwrap();
        assert_eq!(pip_refs.len(), 1);
        assert_eq!(pip_refs[0].package_name, "pip:My_Package.Name");

        let isotope_refs = installed_isotope_package_refs(&opt_root.join("iso")).unwrap();
        assert_eq!(isotope_refs.len(), 1);
        assert_eq!(isotope_refs[0].package_name, "isotope:gh");
    }

    #[test]
    fn search_and_metadata_helpers_cover_embedded_catalog_paths() {
        let config = Config {
            bottle_tag: "all".to_string(),
        };
        let db = crate::cli::load_db().unwrap();
        let npm_metadata = db.npms.get("coverage-npm").unwrap();

        assert_eq!(string_or_none("  "), None);
        assert_eq!(string_or_none("  hello  "), Some("hello".to_string()));
        assert!(vendor_entry_matches(vendor::PACKAGES[0], "bun"));
        assert!(vendor_entry_matches(vendor::PACKAGES[0], "av:bun"));
        assert!(npm_entry_matches("coverage-npm", npm_metadata, "coverage"));
        assert!(npm_entry_matches(
            "coverage-npm",
            npm_metadata,
            "npm:coverage"
        ));
        assert_eq!(
            package_source_qualified_name(&PackageReceiptSource::Vendor {
                vendor_name: "bun".to_string(),
            }),
            "av:bun"
        );
        assert_eq!(
            package_source_qualified_name(&PackageReceiptSource::Formula {
                root_formula: "ripgrep".to_string(),
            }),
            "brew:ripgrep"
        );
        assert_eq!(
            package_source_qualified_name(&PackageReceiptSource::Cask {
                cask_name: "codex".to_string(),
            }),
            "cask:codex"
        );
        assert_eq!(
            package_source_qualified_name(&PackageReceiptSource::Isotope {
                isotope_name: "gh".to_string(),
            }),
            "isotope:gh"
        );
        assert_eq!(
            package_source_qualified_name(&PackageReceiptSource::Npm {
                package_name: "@scope/tool".to_string(),
            }),
            "npm:@scope/tool"
        );
        assert_eq!(
            package_source_qualified_name(&PackageReceiptSource::Pip {
                package_name: "My_Package.Name".to_string(),
            }),
            "pip:My_Package.Name"
        );

        assert!(
            homebrew_aliases_for_formula("ripgrep")
                .unwrap()
                .contains(&"rg".to_string())
        );

        let isotope = isotope_package_data("gh").unwrap();
        let isotope_info = isotope_homebrew_info("gh", isotope);
        assert_eq!(isotope_info.formula, "gh");
        assert!(isotope_info.description.is_some());

        let uv_isotope = isotope_package_data("uv").unwrap();
        assert_eq!(
            isotope_homebrew_formula_target(uv_isotope),
            Some("uv".to_string())
        );
        let mut uv_info = PackageInfo {
            package_name: "isotope:uv".to_string(),
            qualified_name: "isotope:uv".to_string(),
            install_root: PathBuf::from("/opt/iso/uv"),
            installed: true,
            source: Some(PackageReceiptSource::Isotope {
                isotope_name: "uv".to_string(),
            }),
            source_error: None,
            aliases: Vec::new(),
            aliases_error: None,
            installed_version: None,
            latest_version: Some("0.11.18".to_string()),
            latest_version_error: None,
            executable_paths: Vec::new(),
            executable_paths_error: None,
            popularity: None,
            last_updated_at: Some("2026-06-02T15:02:25Z".to_string()),
            homebrew_info: Some(isotope_homebrew_info("uv", uv_isotope)),
            homebrew_info_error: None,
            npm_homepage: None,
            npm_package_info_error: None,
            security_state: None,
            version_options: Vec::new(),
        };
        apply_formula_db_homebrew_metadata("uv", &mut uv_info);
        let uv_homebrew_info = uv_info.homebrew_info.unwrap();
        assert_eq!(
            uv_homebrew_info.homepage.as_deref(),
            Some("https://docs.astral.sh/uv/")
        );
        assert_eq!(
            uv_homebrew_info.repository.as_deref(),
            Some("https://github.com/astral-sh/uv")
        );
        assert_eq!(
            uv_homebrew_info.upstream_docs.as_deref(),
            Some("https://docs.astral.sh/uv")
        );
        assert_eq!(
            uv_homebrew_info.docs,
            vec!["https://docs.astral.sh/uv".to_string()]
        );
        assert_eq!(
            uv_info.last_updated_at.as_deref(),
            Some("2026-06-02T15:02:25Z")
        );

        let uv_geiger = geiger_package_result_with_source_metadata(
            &PackageReceiptSource::Formula {
                root_formula: "uv".to_string(),
            },
            "brew:uv",
        );
        assert_eq!(uv_geiger.package_name, "brew:uv");
        assert_eq!(
            uv_geiger.homepage.as_deref(),
            Some("https://docs.astral.sh/uv/")
        );
        assert_eq!(
            uv_geiger.repository.as_deref(),
            Some("https://github.com/astral-sh/uv")
        );
        assert_eq!(
            uv_geiger.upstream_docs.as_deref(),
            Some("https://docs.astral.sh/uv")
        );
        assert_eq!(
            uv_geiger.docs,
            vec!["https://docs.astral.sh/uv".to_string()]
        );

        let fallback_geiger = geiger_package_result_with_source_metadata(
            &PackageReceiptSource::Npm {
                package_name: "left-pad".to_string(),
            },
            "npm:left-pad",
        );
        assert_eq!(fallback_geiger.package_name, "npm:left-pad");
        assert_eq!(fallback_geiger.summary, None);
        assert!(fallback_geiger.docs.is_empty());

        let reference_time = OffsetDateTime::parse("2026-06-06T00:00:00Z", &Rfc3339).unwrap();
        assert_eq!(
            pulse_kind_for_timestamp(
                Some("new".to_string()),
                "2026-06-05T00:00:00Z",
                Some(reference_time)
            ),
            "new"
        );
        assert_eq!(
            pulse_kind_for_timestamp(
                Some("new".to_string()),
                "2026-01-01T00:00:00Z",
                Some(reference_time)
            ),
            "updated"
        );
        assert_eq!(
            pulse_kind_for_timestamp(Some("featured".to_string()), "bad", None),
            "featured"
        );

        let mut fallback_info = PackageInfo {
            package_name: "brew:demo".to_string(),
            qualified_name: "brew:demo".to_string(),
            install_root: PathBuf::from("/opt/demo"),
            installed: true,
            source: Some(PackageReceiptSource::Formula {
                root_formula: "demo".to_string(),
            }),
            source_error: None,
            aliases: Vec::new(),
            aliases_error: None,
            installed_version: None,
            latest_version: None,
            latest_version_error: None,
            executable_paths: Vec::new(),
            executable_paths_error: None,
            popularity: None,
            last_updated_at: None,
            homebrew_info: None,
            homebrew_info_error: None,
            npm_homepage: None,
            npm_package_info_error: None,
            security_state: None,
            version_options: Vec::new(),
        };
        apply_formula_db_metadata_to_info(
            "demo",
            &EmbeddedFormulaMetadata {
                summary: " Demo package ".to_string(),
                homepage: " https://example.com/demo ".to_string(),
                repository: " https://github.com/example/demo ".to_string(),
                docs: vec![
                    " ".to_string(),
                    " https://docs.example.com/demo ".to_string(),
                ],
                ..EmbeddedFormulaMetadata::default()
            },
            &mut fallback_info,
        );
        let fallback_homebrew = fallback_info.homebrew_info.unwrap();
        assert_eq!(fallback_homebrew.formula, "demo");
        assert_eq!(
            fallback_homebrew.description.as_deref(),
            Some("Demo package")
        );
        assert_eq!(
            fallback_homebrew.upstream_docs.as_deref(),
            Some("https://docs.example.com/demo")
        );
        assert_eq!(
            fallback_homebrew.docs,
            vec!["https://docs.example.com/demo".to_string()]
        );

        let versioned_entry = FormulaIndexEntry {
            name: "openssl@3".to_string(),
            summary: "TLS toolkit".to_string(),
            aliases: vec!["openssl@3.0".to_string()],
            oldnames: vec!["libssl@1.1".to_string()],
            category: "security".to_string(),
            homepage: "https://openssl.org".to_string(),
            repository: String::new(),
            upstream_docs: String::new(),
            docs: vec![" https://docs.openssl.org ".to_string()],
            popularity: Some(EmbeddedPackagePopularity {
                installs_per_365_days: 10,
                rank: 7,
            }),
            last_updated_at: Some("2026-06-05T00:00:00Z".to_string()),
            pulse_kind: Some("new".to_string()),
        };
        assert!(formula_index_entry_matches(&versioned_entry, "libssl"));
        assert_eq!(
            formula_search_result_display_names(&versioned_entry, "libssl"),
            vec!["libssl@1.1".to_string()]
        );
        assert_eq!(
            formula_search_result_display_names(&versioned_entry, "nomatch"),
            vec!["openssl@3".to_string()]
        );
        let versioned_result = formula_search_result(&versioned_entry, "openssl@3.0");
        assert_eq!(
            versioned_result.source,
            PackageReceiptSource::Formula {
                root_formula: "openssl@3.0".to_string()
            }
        );
        assert_eq!(
            versioned_result.install_package_names,
            vec!["openssl@3.0".to_string()]
        );
        assert!(search_result_is_versioned_formula(&versioned_result));
        assert_eq!(
            formula_upstream_docs(&versioned_entry).as_deref(),
            Some("https://docs.openssl.org")
        );
        assert_eq!(formula_version_alias("openssl", "bad"), None);
        assert_eq!(
            formula_version_alias("openssl", "3.2.1"),
            Some("openssl@3".to_string())
        );
        assert_eq!(parsed_stable_version("3.2.1_1"), Some((3, 2, 1)));
        assert!(!version_is_recommendable("bad"));
        assert!(version_is_recommendable("3.1.1"));
        assert_eq!(
            compare_version_strings("3.10.0", "3.2.0"),
            std::cmp::Ordering::Greater
        );
        let alias_entry = FormulaIndexEntry {
            name: "openssl".to_string(),
            aliases: vec!["openssl@3".to_string()],
            oldnames: Vec::new(),
            category: String::new(),
            summary: String::new(),
            homepage: String::new(),
            repository: String::new(),
            upstream_docs: String::new(),
            docs: Vec::new(),
            popularity: None,
            last_updated_at: None,
            pulse_kind: None,
        };
        assert_eq!(
            formula_display_alias(&alias_entry, "openssl", "3.2.1"),
            Some("openssl@3".to_string())
        );
        assert_eq!(
            formula_display_alias(&alias_entry, "openssl", "bad"),
            Some("openssl@3".to_string())
        );
        assert_eq!(
            formula_index_entry_for_security_recommendation(
                std::slice::from_ref(&alias_entry),
                "openssl@3",
            )
            .unwrap()
            .name,
            "openssl"
        );

        let review_state = PackageSecurityState {
            isotope_name: "demo".to_string(),
            install_is_insecure: false,
            remediation_available: true,
            reasons: Vec::new(),
            error: Some("detector failed".to_string()),
        };
        assert!(package_security_state_needs_geiger_action(&review_state));
        assert_eq!(
            geiger_package_summary(&review_state),
            "Detector for isotope:demo needs review"
        );

        fn search_result(
            package_name: &str,
            source: PackageReceiptSource,
            rank: Option<u32>,
        ) -> PackageSearchResult {
            PackageSearchResult {
                package_name: package_name.to_string(),
                source,
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
        let npm_result = search_result(
            "npm:left-pad",
            PackageReceiptSource::Npm {
                package_name: "left-pad".to_string(),
            },
            None,
        );
        assert!(!search_result_is_versioned_formula(&npm_result));
        let mut filtered_results = vec![
            search_result(
                "openssl",
                PackageReceiptSource::Formula {
                    root_formula: "openssl".to_string(),
                },
                None,
            ),
            search_result(
                "openssl@3",
                PackageReceiptSource::Formula {
                    root_formula: "openssl@3".to_string(),
                },
                None,
            ),
            npm_result.clone(),
        ];
        suppress_unversioned_formulae_with_versioned_search_results(&mut filtered_results);
        assert_eq!(
            filtered_results
                .iter()
                .map(|result| result.package_name.as_str())
                .collect::<Vec<_>>(),
            vec!["openssl@3", "npm:left-pad"]
        );
        let mut unversioned_only = vec![search_result(
            "zlib",
            PackageReceiptSource::Formula {
                root_formula: "zlib".to_string(),
            },
            None,
        )];
        suppress_unversioned_formulae_with_versioned_search_results(&mut unversioned_only);
        assert_eq!(unversioned_only.len(), 1);
        assert_eq!(
            compare_security_recommendation_rank_order(
                &search_result(
                    "ranked",
                    PackageReceiptSource::Vendor {
                        vendor_name: "ranked".to_string(),
                    },
                    Some(1),
                ),
                &search_result(
                    "unranked",
                    PackageReceiptSource::Vendor {
                        vendor_name: "unranked".to_string(),
                    },
                    None,
                ),
            ),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_security_recommendation_rank_order(
                &search_result(
                    "rank-two",
                    PackageReceiptSource::Vendor {
                        vendor_name: "rank-two".to_string(),
                    },
                    Some(2),
                ),
                &search_result(
                    "rank-three",
                    PackageReceiptSource::Vendor {
                        vendor_name: "rank-three".to_string(),
                    },
                    Some(3),
                ),
            ),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_security_recommendation_rank_order(
                &search_result(
                    "unranked",
                    PackageReceiptSource::Vendor {
                        vendor_name: "unranked".to_string(),
                    },
                    None,
                ),
                &search_result(
                    "ranked",
                    PackageReceiptSource::Vendor {
                        vendor_name: "ranked".to_string(),
                    },
                    Some(1),
                ),
            ),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_security_recommendation_rank_order(
                &search_result(
                    "left",
                    PackageReceiptSource::Vendor {
                        vendor_name: "left".to_string(),
                    },
                    None,
                ),
                &search_result(
                    "right",
                    PackageReceiptSource::Vendor {
                        vendor_name: "right".to_string(),
                    },
                    None,
                ),
            ),
            std::cmp::Ordering::Equal
        );

        let mut recent_pulse = search_result(
            "recent",
            PackageReceiptSource::Vendor {
                vendor_name: "recent".to_string(),
            },
            None,
        );
        recent_pulse.pulse_kind = Some("updated".to_string());
        recent_pulse.last_updated_at = Some("2026-06-05T00:00:00Z".to_string());
        let mut missing_pulse_time = search_result(
            "missing",
            PackageReceiptSource::Vendor {
                vendor_name: "missing".to_string(),
            },
            None,
        );
        missing_pulse_time.pulse_kind = Some("updated".to_string());
        assert_eq!(
            compare_pulse_package_results(&recent_pulse, &missing_pulse_time),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_pulse_package_results(&missing_pulse_time, &recent_pulse),
            std::cmp::Ordering::Greater
        );
        let mut equal_pulse_left = search_result(
            "a",
            PackageReceiptSource::Vendor {
                vendor_name: "a".to_string(),
            },
            None,
        );
        equal_pulse_left.pulse_kind = Some("updated".to_string());
        let mut equal_pulse_right = search_result(
            "b",
            PackageReceiptSource::Vendor {
                vendor_name: "b".to_string(),
            },
            None,
        );
        equal_pulse_right.pulse_kind = Some("updated".to_string());
        assert_eq!(
            compare_pulse_package_results(&equal_pulse_left, &equal_pulse_right),
            std::cmp::Ordering::Less
        );

        let available = resolve_available_package_results(&config).unwrap();
        assert!(!available.is_empty());
        assert!(
            available
                .iter()
                .any(|package| package.package_name == "ripgrep")
        );
        assert!(
            available
                .iter()
                .any(|package| package.package_name == "codex")
        );
        assert!(
            available
                .iter()
                .any(|package| package.package_name == "npm:coverage-npm")
        );
        assert!(
            available
                .iter()
                .any(|package| package.package_name == "av:bun")
        );

        let pulse = resolve_pulse_package_results(&config).unwrap();
        assert!(!pulse.is_empty());
        assert!(
            pulse
                .iter()
                .all(|package| package.last_updated_at.is_some())
        );
        assert!(pulse.iter().all(|package| package.pulse_kind.is_some()));
    }

    #[test]
    fn resolve_package_info_covers_non_directory_and_isotope_modified_roots() {
        let _lock = crate::global_test_env_lock().lock().unwrap();
        let config = Config {
            bottle_tag: "all".to_string(),
        };
        let opt_root = opt_pkg_root();
        fs::create_dir_all(&opt_root).unwrap();

        let file_root = opt_root.join("coverage-info-file");
        if fs::symlink_metadata(&file_root).is_ok() {
            remove_path(&file_root).unwrap();
        }
        fs::write(&file_root, b"not a directory").unwrap();
        assert!(
            resolve_package_info(
                &config,
                &RequestedPackage::Auto("coverage-info-file".to_string())
            )
            .unwrap_err()
            .contains("is not a directory")
        );
        remove_path(&file_root).unwrap();

        let modified_root = opt_root.join("awscli");
        if fs::symlink_metadata(&modified_root).is_ok() {
            remove_path(&modified_root).unwrap();
        }
        fs::create_dir_all(&modified_root).unwrap();
        write_package_receipt(
            &modified_root.join(ROOT_RECEIPT),
            &PackageReceipt {
                package_name: "isotope:aws-cli".to_string(),
                version: "2.0.0".to_string(),
                source: PackageReceiptSource::Isotope {
                    isotope_name: "aws-cli".to_string(),
                },
                metadata: PackageMetadata::default(),
            },
        )
        .unwrap();

        let info = resolve_package_info(&config, &RequestedPackage::Isotope("aws-cli".to_string()))
            .unwrap();
        assert!(info.installed);
        assert_eq!(info.install_root, modified_root);
        assert_eq!(info.installed_version, Some("2.0.0".to_string()));
        assert_eq!(
            info.source,
            Some(PackageReceiptSource::Isotope {
                isotope_name: "aws-cli".to_string(),
            })
        );

        remove_path(&opt_root.join("awscli")).unwrap();
    }

    #[test]
    fn format_package_info_covers_wrapped_metadata_and_error_sections() {
        let info = PackageInfo {
            package_name: "coverage-formula".to_string(),
            qualified_name:
                "brew:coverage-formula-with-a-very-long-name-that-wraps-in-the-title".to_string(),
            install_root: PathBuf::from("/opt/pkg/coverage-formula"),
            installed: true,
            source: Some(PackageReceiptSource::Formula {
                root_formula: "coverage-formula".to_string(),
            }),
            source_error: None,
            aliases: vec![
                "coverage-alias".to_string(),
                "coverage-second-alias-that-wraps".to_string(),
            ],
            aliases_error: None,
            installed_version: Some("1.0.0".to_string()),
            latest_version: None,
            latest_version_error: Some("registry unavailable".to_string()),
            executable_paths: Vec::new(),
            executable_paths_error: Some("stub manifest missing".to_string()),
            popularity: None,
            last_updated_at: None,
            homebrew_info: Some(HomebrewPackageInfo {
                formula: "coverage-formula".to_string(),
                description: Some("A long description that should wrap over multiple lines in the package info renderer".to_string()),
                homepage: Some("https://example.test/coverage-formula".to_string()),
                repository: Some("https://github.com/example/coverage-formula".to_string()),
                upstream_docs: Some("https://docs.example.test/coverage-formula".to_string()),
                docs: Vec::new(),
                license: Some("MIT".to_string()),
                dependencies: vec![
                    "dependency-one".to_string(),
                    "dependency-two-with-a-long-name".to_string(),
                    "dependency-three".to_string(),
                ],
            }),
            homebrew_info_error: None,
            npm_homepage: None,
            npm_package_info_error: None,
            security_state: None,
            version_options: Vec::new(),
        };

        let rendered = format_package_info(&info);
        assert!(rendered.contains("brew:coverage-formula"));
        assert!(rendered.contains("registry unavailable"));
        assert!(rendered.contains("Description"));
        assert!(rendered.contains("Repository"));
        assert!(rendered.contains("Docs"));
        assert!(rendered.contains("Dependencies"));
        assert!(rendered.contains("stub manifest missing"));

        let npm_info = PackageInfo {
            package_name: "coverage-npm".to_string(),
            qualified_name: "npm:coverage-npm".to_string(),
            install_root: PathBuf::from("/opt/npm/coverage-npm"),
            installed: true,
            source: Some(PackageReceiptSource::Npm {
                package_name: "coverage-npm".to_string(),
            }),
            source_error: None,
            aliases: Vec::new(),
            aliases_error: None,
            installed_version: None,
            latest_version: Some("2.0.0".to_string()),
            latest_version_error: None,
            executable_paths: vec![
                "/opt/npm/bin/coverage-npm-with-a-long-executable-name".to_string(),
            ],
            executable_paths_error: None,
            popularity: None,
            last_updated_at: None,
            homebrew_info: None,
            homebrew_info_error: None,
            npm_homepage: None,
            npm_package_info_error: Some("npm metadata timeout".to_string()),
            security_state: None,
            version_options: Vec::new(),
        };
        let rendered = format_package_info(&npm_info);
        assert!(rendered.contains("npm metadata timeout"));
        assert!(rendered.contains("coverage-npm-with-a-long-executable-name"));

        let mut lines = Vec::new();
        push_wrapped_field(&mut lines, "Empty", "");
        assert_eq!(lines, vec![format!("  {:<INFO_LABEL_WIDTH$}", "Empty")]);
        assert_eq!(wrap_text("", 4), vec![String::new()]);
        assert_eq!(split_text_hard("abcdef", 2), vec!["ab", "cd", "ef"]);
        assert!(wrap_tokens(&[], 2, 3).is_empty());
        assert!(wrap_tokens(&["a".repeat(INFO_WIDTH), "b".to_string()], 2, 3).len() > 1);
    }
}
