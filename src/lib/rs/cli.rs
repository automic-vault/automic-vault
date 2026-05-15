use super::*;

pub fn main_entry() {
    configure_debug_install_environment();
    let mut args = env::args_os();
    let program = args.next().unwrap_or_else(|| OsString::from("av"));
    let invocation = Invocation::from_program(&program);

    let result = match invocation.binary_name.as_str() {
        "isotope" => isotope::run_isotope_entry("isotope", args),
        "vault" => vault::run_vault_entry("vault", args),
        _ => match invocation.mode {
            Some(mode) => run_mode(mode, &invocation, args),
            None => dispatch_pkg(&invocation, args),
        },
    };

    if let Err(err) = result {
        if let Some(rendered) = err.strip_prefix(RENDERED_ERROR_PREFIX) {
            eprintln!("{rendered}");
        } else {
            eprintln!("{}: {err}", invocation.name);
        }
        process::exit(1);
    }
}

impl Invocation {
    pub(crate) fn from_program(program: &OsString) -> Self {
        let binary_name = Path::new(program)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("av")
            .to_string();
        let mode = Mode::from_name(&binary_name);
        Self {
            binary_name: binary_name.clone(),
            name: binary_name,
            mode,
        }
    }

    pub(crate) fn for_subcommand(binary_name: &str, subcommand: &str, mode: Mode) -> Self {
        Self {
            binary_name: binary_name.to_string(),
            name: format!("{binary_name} {subcommand}"),
            mode: Some(mode),
        }
    }
}

impl Mode {
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        match name {
            "i" | "install" => Some(Self::I),
            _ => None,
        }
    }

    pub(crate) fn canonical_name(self) -> &'static str {
        match self {
            Self::I => "install",
        }
    }
}

pub(crate) fn run_mode(
    mode: Mode,
    invocation: &Invocation,
    args: env::ArgsOs,
) -> Result<(), String> {
    match mode {
        Mode::I => run_i(invocation, args),
    }
}

pub(crate) fn run_uninstall(invocation: &Invocation, mut args: env::ArgsOs) -> Result<(), String> {
    let request = match parse_uninstall_request(invocation, &mut args)? {
        Some(request) => request,
        None => return Ok(()),
    };

    if install_requires_root() && !is_root() {
        return Err("must be run as root".to_string());
    }

    let _lock = acquire_package_mutation_lock()?;
    for package in &request.packages {
        ensure_package_installed(&opt_pkg_root(), package)?;
    }

    for package in request.packages {
        uninstall_package(&package)?;
    }
    Ok(())
}

pub(crate) fn run_outdated(invocation: &Invocation, mut args: env::ArgsOs) -> Result<(), String> {
    let request = match parse_package_status_request(invocation, &mut args, print_outdated_usage)? {
        Some(request) => request,
        None => return Ok(()),
    };

    let config = load_config()?;
    let packages = resolve_outdated_package_statuses(&config, &request.selection)?;
    match request.output {
        OutputMode::Human => {
            for package in packages {
                println!(
                    "{} {} -> {}",
                    package.package_name, package.installed_version, package.latest_version
                );
            }
        }
        OutputMode::Json => {
            println!(
                "{}",
                serde_json::to_string(&packages)
                    .map_err(|err| format!("failed to serialize package statuses: {err}"))?
            );
        }
        OutputMode::Jsonl => {
            for package in packages {
                println!(
                    "{}",
                    serde_json::to_string(&package)
                        .map_err(|err| format!("failed to serialize package status: {err}"))?
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn run_update(invocation: &Invocation, mut args: env::ArgsOs) -> Result<(), String> {
    let request = match parse_update_request(invocation, &mut args)? {
        Some(request) => request,
        None => return Ok(()),
    };

    if !is_root() {
        return Err("must be run as root".to_string());
    }

    let _lock = acquire_package_mutation_lock()?;
    let config = load_config()?;
    for package in resolve_outdated_package_statuses(&config, &request.selection)? {
        run_i_package(
            &config,
            requested_package_from_status(&package),
            InstallOptions {
                allow_reinstall: true,
            },
        )?;
    }
    Ok(())
}

pub(crate) fn run_list(invocation: &Invocation, mut args: env::ArgsOs) -> Result<(), String> {
    let request = match parse_package_status_request(invocation, &mut args, print_list_usage)? {
        Some(request) => request,
        None => return Ok(()),
    };

    let packages = resolve_installed_package_records(&request.selection)?;
    match request.output {
        OutputMode::Human => {
            for package in packages {
                println!("{} {}", package.package_name, package.installed_version);
            }
        }
        OutputMode::Json => {
            println!(
                "{}",
                serde_json::to_string(&packages)
                    .map_err(|err| format!("failed to serialize package statuses: {err}"))?
            );
        }
        OutputMode::Jsonl => {
            for package in packages {
                println!(
                    "{}",
                    serde_json::to_string(&package)
                        .map_err(|err| format!("failed to serialize package status: {err}"))?
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn run_info(invocation: &Invocation, mut args: env::ArgsOs) -> Result<(), String> {
    let request = match parse_info_request(invocation, &mut args)? {
        Some(request) => request,
        None => return Ok(()),
    };

    let config = load_config()?;
    let info = resolve_package_info(&config, &request.package)?;
    match request.output {
        OutputMode::Human => print!("{}\n", format_package_info(&info)),
        OutputMode::Json | OutputMode::Jsonl => {
            println!(
                "{}",
                serde_json::to_string(&info)
                    .map_err(|err| format!("failed to serialize package info: {err}"))?
            );
        }
    }
    Ok(())
}

pub(crate) fn run_search(invocation: &Invocation, mut args: env::ArgsOs) -> Result<(), String> {
    let request = match parse_search_request(invocation, &mut args)? {
        Some(request) => request,
        None => return Ok(()),
    };

    let config = load_config()?;
    let results = resolve_package_search_results(&config, &request.query)?;
    match request.output {
        OutputMode::Human => {
            for result in results {
                println!("{}", result.package_name);
            }
        }
        OutputMode::Json => {
            println!(
                "{}",
                serde_json::to_string(&results)
                    .map_err(|err| format!("failed to serialize search results: {err}"))?
            );
        }
        OutputMode::Jsonl => {
            for result in results {
                println!(
                    "{}",
                    serde_json::to_string(&result)
                        .map_err(|err| format!("failed to serialize search result: {err}"))?
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn run_secret_scanner(
    invocation: &Invocation,
    mut args: env::ArgsOs,
) -> Result<(), String> {
    let request = match parse_secret_scanner_request(invocation, &mut args)? {
        Some(request) => request,
        None => return Ok(()),
    };

    let report = run_secret_scan(&request)?;
    match request.output {
        OutputMode::Human => print_secret_scanner_report(&report),
        OutputMode::Json => {
            println!(
                "{}",
                serde_json::to_string(&report)
                    .map_err(|err| format!("failed to serialize secret scanner report: {err}"))?
            );
        }
        OutputMode::Jsonl => {
            for finding in &report.findings {
                println!(
                    "{}",
                    serde_json::to_string(finding)
                        .map_err(|err| format!("failed to serialize secret finding: {err}"))?
                );
            }
            for error in &report.errors {
                println!(
                    "{}",
                    serde_json::to_string(error).map_err(|err| format!(
                        "failed to serialize secret scanner error: {err}"
                    ))?
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn run_serve(invocation: &Invocation, mut args: env::ArgsOs) -> Result<(), String> {
    let Some(first_arg) = args.next() else {
        return protocol::run_server();
    };

    if is_help_flag(&first_arg) {
        print_serve_usage(&invocation.name);
        return Ok(());
    }

    if is_version_flag(&first_arg) {
        println!("{} {}", invocation.name, env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    Err(format!(
        "unknown argument '{}'",
        first_arg.to_string_lossy()
    ))
}

pub(crate) fn dispatch_pkg(invocation: &Invocation, mut args: env::ArgsOs) -> Result<(), String> {
    let Some(first_arg) = args.next() else {
        print_pkg_usage(&invocation.name);
        return Err("missing subcommand".to_string());
    };

    if is_help_flag(&first_arg) {
        print_pkg_usage(&invocation.name);
        return Ok(());
    }

    if is_version_flag(&first_arg) {
        println!("{PKG_DISPLAY_NAME} {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if matches!(first_arg.to_str(), Some("help")) {
        if let Some(topic) = args.next() {
            match topic.to_str() {
                Some(subcommand) if is_uninstall_subcommand(subcommand) => {
                    print_uninstall_usage(&format!("{} {}", invocation.binary_name, subcommand));
                }
                Some(subcommand) if is_outdated_subcommand(subcommand) => {
                    print_outdated_usage(&format!("{} {}", invocation.binary_name, subcommand));
                }
                Some(subcommand) if is_update_subcommand(subcommand) => {
                    print_update_usage(&format!("{} {}", invocation.binary_name, subcommand));
                }
                Some(subcommand) if is_list_subcommand(subcommand) => {
                    print_list_usage(&format!("{} {}", invocation.binary_name, subcommand));
                }
                Some(subcommand) if is_info_subcommand(subcommand) => {
                    print_info_usage(&format!("{} {}", invocation.binary_name, subcommand));
                }
                Some(subcommand) if is_search_subcommand(subcommand) => {
                    print_search_usage(&format!("{} {}", invocation.binary_name, subcommand));
                }
                Some(subcommand) if is_secret_scanner_subcommand(subcommand) => {
                    print_secret_scanner_usage(&format!("{} scan", invocation.binary_name));
                }
                Some(subcommand) if is_trace_subcommand(subcommand) => {
                    print_trace_usage(&format!("{} trace", invocation.binary_name));
                }
                Some(subcommand) if is_serve_subcommand(subcommand) => {
                    print_serve_usage(&format!("{} {}", invocation.binary_name, subcommand));
                }
                Some("inject") => {
                    isotope::print_isotope_usage(&format!("{} inject", invocation.binary_name));
                }
                Some("save") => {
                    isotope::print_save_usage(&format!("{} save", invocation.binary_name));
                }
                Some("gate") => {
                    gate::print_gate_usage(&format!("{} gate", invocation.binary_name));
                }
                Some("contain") => {
                    vault::print_vault_usage(&format!("{} contain", invocation.binary_name));
                }
                Some(subcommand) => match Mode::from_name(subcommand) {
                    Some(mode) => {
                        let nested = Invocation::for_subcommand(
                            &invocation.binary_name,
                            mode.canonical_name(),
                            mode,
                        );
                        print_mode_usage(mode, &nested.name);
                    }
                    None => print_pkg_usage(&invocation.name),
                },
                None => print_pkg_usage(&invocation.name),
            }
        } else {
            print_pkg_usage(&invocation.name);
        }
        return Ok(());
    }

    let subcommand = first_arg
        .to_str()
        .ok_or_else(|| "subcommand must be valid UTF-8".to_string())?;
    if is_uninstall_subcommand(subcommand) {
        return run_uninstall(
            &Invocation {
                binary_name: invocation.binary_name.clone(),
                name: format!("{} {subcommand}", invocation.binary_name),
                mode: None,
            },
            args,
        );
    }
    if is_outdated_subcommand(subcommand) {
        return run_outdated(
            &Invocation {
                binary_name: invocation.binary_name.clone(),
                name: format!("{} {subcommand}", invocation.binary_name),
                mode: None,
            },
            args,
        );
    }
    if is_update_subcommand(subcommand) {
        return run_update(
            &Invocation {
                binary_name: invocation.binary_name.clone(),
                name: format!("{} {subcommand}", invocation.binary_name),
                mode: None,
            },
            args,
        );
    }
    if is_list_subcommand(subcommand) {
        return run_list(
            &Invocation {
                binary_name: invocation.binary_name.clone(),
                name: format!("{} {subcommand}", invocation.binary_name),
                mode: None,
            },
            args,
        );
    }
    if is_info_subcommand(subcommand) {
        return run_info(
            &Invocation {
                binary_name: invocation.binary_name.clone(),
                name: format!("{} {subcommand}", invocation.binary_name),
                mode: None,
            },
            args,
        );
    }
    if is_search_subcommand(subcommand) {
        return run_search(
            &Invocation {
                binary_name: invocation.binary_name.clone(),
                name: format!("{} {subcommand}", invocation.binary_name),
                mode: None,
            },
            args,
        );
    }
    if is_secret_scanner_subcommand(subcommand) {
        return run_secret_scanner(
            &Invocation {
                binary_name: invocation.binary_name.clone(),
                name: format!("{} scan", invocation.binary_name),
                mode: None,
            },
            args,
        );
    }
    if is_trace_subcommand(subcommand) {
        return run_trace(
            &Invocation {
                binary_name: invocation.binary_name.clone(),
                name: format!("{} trace", invocation.binary_name),
                mode: None,
            },
            args,
        );
    }
    if is_serve_subcommand(subcommand) {
        return run_serve(
            &Invocation {
                binary_name: invocation.binary_name.clone(),
                name: format!("{} {subcommand}", invocation.binary_name),
                mode: None,
            },
            args,
        );
    }
    if subcommand == "inject" {
        let program_name = format!("{} inject", invocation.binary_name);
        return isotope::run_isotope_entry(&program_name, args)
            .map_err(|err| format!("{RENDERED_ERROR_PREFIX}{program_name}: {err}"));
    }
    if subcommand == "save" {
        let program_name = format!("{} save", invocation.binary_name);
        return isotope::run_save_entry(&program_name, args)
            .map_err(|err| format!("{RENDERED_ERROR_PREFIX}{program_name}: {err}"));
    }
    if subcommand == "gate" {
        let program_name = format!("{} gate", invocation.binary_name);
        return gate::run_gate_entry(&program_name, args)
            .map_err(|err| format!("{RENDERED_ERROR_PREFIX}{program_name}: {err}"));
    }
    if subcommand == "contain" {
        let program_name = format!("{} contain", invocation.binary_name);
        return vault::run_vault_entry(&program_name, args)
            .map_err(|err| format!("{RENDERED_ERROR_PREFIX}{program_name}: {err}"));
    }
    let Some(mode) = Mode::from_name(subcommand) else {
        print_pkg_usage(&invocation.name);
        return Err(format!("unknown subcommand '{subcommand}'"));
    };
    let nested = Invocation::for_subcommand(&invocation.binary_name, subcommand, mode);
    run_mode(mode, &nested, args)
}

pub(crate) fn parse_i_request(
    invocation: &Invocation,
    args: &mut env::ArgsOs,
) -> Result<Option<IRequest>, String> {
    parse_i_request_from_iter(invocation, args)
}

pub(crate) fn parse_uninstall_request(
    invocation: &Invocation,
    args: &mut env::ArgsOs,
) -> Result<Option<UninstallRequest>, String> {
    parse_uninstall_request_from_iter(invocation, args)
}

pub(crate) fn parse_update_request(
    invocation: &Invocation,
    args: &mut env::ArgsOs,
) -> Result<Option<UpdateRequest>, String> {
    parse_update_request_from_iter(invocation, args)
}

pub(crate) fn parse_info_request(
    invocation: &Invocation,
    args: &mut env::ArgsOs,
) -> Result<Option<InfoRequest>, String> {
    parse_info_request_from_iter(invocation, args)
}

pub(crate) fn parse_package_status_request(
    invocation: &Invocation,
    args: &mut env::ArgsOs,
    print_usage: fn(&str),
) -> Result<Option<PackageStatusRequest>, String> {
    parse_package_status_request_from_iter(invocation, args, print_usage)
}

pub(crate) fn parse_i_request_from_iter<I>(
    invocation: &Invocation,
    args: I,
) -> Result<Option<IRequest>, String>
where
    I: Iterator<Item = OsString>,
{
    let mut force = false;
    let mut packages = Vec::new();

    for arg in args {
        if is_help_flag(&arg) {
            print_i_usage(&invocation.name);
            return Ok(None);
        }

        if is_version_flag(&arg) {
            println!("{} {}", invocation.name, env!("CARGO_PKG_VERSION"));
            return Ok(None);
        }

        if is_force_flag(&arg) {
            force = true;
            continue;
        }

        packages.push(parse_package_name(&arg)?);
    }

    if packages.is_empty() {
        print_i_usage(&invocation.name);
        return Err("missing package name".to_string());
    }

    Ok(Some(IRequest { packages, force }))
}

pub(crate) fn parse_uninstall_request_from_iter<I>(
    invocation: &Invocation,
    mut args: I,
) -> Result<Option<UninstallRequest>, String>
where
    I: Iterator<Item = OsString>,
{
    let Some(first_arg) = args.next() else {
        print_uninstall_usage(&invocation.name);
        return Err("missing package name".to_string());
    };

    if is_help_flag(&first_arg) {
        print_uninstall_usage(&invocation.name);
        return Ok(None);
    }

    if is_version_flag(&first_arg) {
        println!("{} {}", invocation.name, env!("CARGO_PKG_VERSION"));
        return Ok(None);
    }

    let mut packages = vec![parse_uninstall_package_name(&first_arg)?];
    for arg in args {
        packages.push(parse_uninstall_package_name(&arg)?);
    }

    Ok(Some(UninstallRequest { packages }))
}

pub(crate) fn parse_update_request_from_iter<I>(
    invocation: &Invocation,
    args: I,
) -> Result<Option<UpdateRequest>, String>
where
    I: Iterator<Item = OsString>,
{
    let mut no_self_update = false;
    let mut packages = Vec::new();

    for arg in args {
        if is_help_flag(&arg) {
            print_update_usage(&invocation.name);
            return Ok(None);
        }

        if is_version_flag(&arg) {
            println!("{} {}", invocation.name, env!("CARGO_PKG_VERSION"));
            return Ok(None);
        }

        if is_no_self_update_flag(&arg) {
            no_self_update = true;
            continue;
        }

        packages.push(parse_package_name(&arg)?);
    }

    let selection = if packages.is_empty() {
        PackageSelection::AllInstalled
    } else {
        PackageSelection::Requested(packages)
    };

    Ok(Some(UpdateRequest {
        selection,
        no_self_update,
    }))
}

pub(crate) fn parse_info_request_from_iter<I>(
    invocation: &Invocation,
    mut args: I,
) -> Result<Option<InfoRequest>, String>
where
    I: Iterator<Item = OsString>,
{
    let mut output = OutputMode::Human;
    let Some(mut first_arg) = args.next() else {
        print_info_usage(&invocation.name);
        return Err("missing package name".to_string());
    };

    while is_json_flag(&first_arg) || is_jsonl_flag(&first_arg) {
        output = update_output_mode(output, &first_arg)?;
        first_arg = args.next().ok_or_else(|| {
            print_info_usage(&invocation.name);
            "missing package name".to_string()
        })?;
    }

    if is_help_flag(&first_arg) {
        print_info_usage(&invocation.name);
        return Ok(None);
    }

    if is_version_flag(&first_arg) {
        println!("{} {}", invocation.name, env!("CARGO_PKG_VERSION"));
        return Ok(None);
    }

    let package = parse_package_name(&first_arg)?;
    for arg in args {
        if is_json_flag(&arg) || is_jsonl_flag(&arg) {
            output = update_output_mode(output, &arg)?;
            continue;
        }
        return Err("supports a single package".to_string());
    }

    Ok(Some(InfoRequest { package, output }))
}

pub(crate) fn parse_search_request(
    invocation: &Invocation,
    args: &mut env::ArgsOs,
) -> Result<Option<SearchRequest>, String> {
    parse_search_request_from_iter(invocation, args)
}

pub(crate) fn parse_secret_scanner_request(
    invocation: &Invocation,
    args: &mut env::ArgsOs,
) -> Result<Option<SecretScannerRequest>, String> {
    parse_secret_scanner_request_from_iter(invocation, args)
}

pub(crate) fn parse_search_request_from_iter<I>(
    invocation: &Invocation,
    mut args: I,
) -> Result<Option<SearchRequest>, String>
where
    I: Iterator<Item = OsString>,
{
    let mut output = OutputMode::Human;
    let Some(mut first_arg) = args.next() else {
        print_search_usage(&invocation.name);
        return Err("missing query".to_string());
    };

    while is_json_flag(&first_arg) || is_jsonl_flag(&first_arg) {
        output = update_output_mode(output, &first_arg)?;
        first_arg = args.next().ok_or_else(|| {
            print_search_usage(&invocation.name);
            "missing query".to_string()
        })?;
    }

    if is_help_flag(&first_arg) {
        print_search_usage(&invocation.name);
        return Ok(None);
    }

    if is_version_flag(&first_arg) {
        println!("{} {}", invocation.name, env!("CARGO_PKG_VERSION"));
        return Ok(None);
    }

    let query = first_arg
        .to_str()
        .ok_or_else(|| "query must be valid UTF-8".to_string())?
        .to_string();
    for arg in args {
        if is_json_flag(&arg) || is_jsonl_flag(&arg) {
            output = update_output_mode(output, &arg)?;
            continue;
        }
        return Err("supports a single query string".to_string());
    }

    Ok(Some(SearchRequest { query, output }))
}

pub(crate) fn parse_secret_scanner_request_from_iter<I>(
    invocation: &Invocation,
    args: I,
) -> Result<Option<SecretScannerRequest>, String>
where
    I: Iterator<Item = OsString>,
{
    let mut output = OutputMode::Human;
    let mut path = None;
    let mut pending_path = false;

    for arg in args {
        if pending_path {
            path = Some(PathBuf::from(arg));
            pending_path = false;
            continue;
        }

        if is_help_flag(&arg) {
            print_secret_scanner_usage(&invocation.name);
            return Ok(None);
        }

        if is_version_flag(&arg) {
            println!("{} {}", invocation.name, env!("CARGO_PKG_VERSION"));
            return Ok(None);
        }

        if is_json_flag(&arg) || is_jsonl_flag(&arg) {
            output = update_output_mode(output, &arg)?;
            continue;
        }

        match arg.to_str() {
            Some("--path") => {
                if path.is_some() {
                    return Err("secret scanner path specified more than once".to_string());
                }
                pending_path = true;
            }
            Some(value) if value.starts_with('-') => {
                return Err(format!("unknown argument '{value}'"));
            }
            Some(_) => {
                if path.is_some() {
                    return Err("supports a single scan path".to_string());
                }
                path = Some(PathBuf::from(arg));
            }
            None => return Err("secret scanner path must be valid UTF-8".to_string()),
        }
    }

    if pending_path {
        return Err("missing value for --path".to_string());
    }

    Ok(Some(SecretScannerRequest { path, output }))
}

pub(crate) fn parse_package_status_request_from_iter<I>(
    invocation: &Invocation,
    mut args: I,
    print_usage: fn(&str),
) -> Result<Option<PackageStatusRequest>, String>
where
    I: Iterator<Item = OsString>,
{
    let mut output = OutputMode::Human;
    let Some(mut first_arg) = args.next() else {
        return Ok(Some(PackageStatusRequest {
            selection: PackageSelection::AllInstalled,
            output,
        }));
    };

    while is_json_flag(&first_arg) || is_jsonl_flag(&first_arg) {
        output = update_output_mode(output, &first_arg)?;
        let Some(next_arg) = args.next() else {
            return Ok(Some(PackageStatusRequest {
                selection: PackageSelection::AllInstalled,
                output,
            }));
        };
        first_arg = next_arg;
    }

    if is_help_flag(&first_arg) {
        print_usage(&invocation.name);
        return Ok(None);
    }

    if is_version_flag(&first_arg) {
        println!("{} {}", invocation.name, env!("CARGO_PKG_VERSION"));
        return Ok(None);
    }

    let mut packages = vec![parse_package_name(&first_arg)?];
    for arg in args {
        if is_json_flag(&arg) || is_jsonl_flag(&arg) {
            output = update_output_mode(output, &arg)?;
            continue;
        }
        packages.push(parse_package_name(&arg)?);
    }

    Ok(Some(PackageStatusRequest {
        selection: PackageSelection::Requested(packages),
        output,
    }))
}

pub(crate) fn update_output_mode(
    current: OutputMode,
    arg: &OsString,
) -> Result<OutputMode, String> {
    match arg.to_str() {
        Some("--json") => {
            if current == OutputMode::Jsonl {
                Err("cannot combine --json and --jsonl".to_string())
            } else {
                Ok(OutputMode::Json)
            }
        }
        Some("--jsonl") => {
            if current == OutputMode::Json {
                Err("cannot combine --json and --jsonl".to_string())
            } else {
                Ok(OutputMode::Jsonl)
            }
        }
        _ => Ok(current),
    }
}

pub(crate) fn parse_package_name(value: &OsString) -> Result<RequestedPackage, String> {
    let package = value
        .to_str()
        .ok_or_else(|| "package name must be valid UTF-8".to_string())?
        .to_string();
    if let Some(formula) = package.strip_prefix(BREW_PACKAGE_PREFIX) {
        if formula.is_empty() {
            return Err(format!(
                "package qualifier '{BREW_PACKAGE_PREFIX}' is missing a formula name"
            ));
        }
        if formula.contains('/') {
            return Err(
                "qualified package name must not contain additional path separators".to_string(),
            );
        }
        return Ok(RequestedPackage::HomebrewFormula(formula.to_string()));
    }
    if let Some(cask) = package.strip_prefix(CASK_PACKAGE_PREFIX) {
        if cask.is_empty() {
            return Err(format!(
                "package qualifier '{CASK_PACKAGE_PREFIX}' is missing a cask name"
            ));
        }
        if cask.contains('/') {
            return Err(
                "qualified package name must not contain additional path separators".to_string(),
            );
        }
        return Ok(RequestedPackage::HomebrewCask(cask.to_string()));
    }
    if let Some(isotope) = package.strip_prefix(ISOTOPE_PACKAGE_PREFIX) {
        if isotope.is_empty() {
            return Err(format!(
                "package qualifier '{ISOTOPE_PACKAGE_PREFIX}' is missing an isotope name"
            ));
        }
        if isotope.contains('/') {
            return Err(
                "qualified package name must not contain additional path separators".to_string(),
            );
        }
        return Ok(RequestedPackage::Isotope(isotope.to_string()));
    }
    if let Some(npm_package) = package.strip_prefix("npm:") {
        let (package, version) = parse_npm_package_request(npm_package)?;
        return Ok(RequestedPackage::NpmPackage { package, version });
    }
    if let Some(pip_package) = package.strip_prefix("pip:") {
        validate_pip_package_name(pip_package)?;
        return Ok(RequestedPackage::PipPackage(normalize_pip_package_name(
            pip_package,
        )));
    }
    if package.contains('/') {
        return Err("package name must not contain path separators".to_string());
    }
    if vendor::get(&package).is_none() {
        if let Some(target) = package_alias_target(&package) {
            return Ok(RequestedPackage::Alias {
                alias: package,
                target: target.clone(),
            });
        }
    }
    Ok(RequestedPackage::Auto(package))
}

pub(crate) fn parse_uninstall_package_name(value: &OsString) -> Result<String, String> {
    let package = value
        .to_str()
        .ok_or_else(|| "package name must be valid UTF-8".to_string())?;
    if let Some(formula) = package.strip_prefix(BREW_PACKAGE_PREFIX) {
        if formula.is_empty() {
            return Err(format!(
                "package qualifier '{BREW_PACKAGE_PREFIX}' is missing a formula name"
            ));
        }
        if formula.contains('/') {
            return Err(
                "qualified package name must not contain additional path separators".to_string(),
            );
        }
        return formula_install_package_name(formula);
    }
    if let Some(cask) = package.strip_prefix(CASK_PACKAGE_PREFIX) {
        if cask.is_empty() {
            return Err(format!(
                "package qualifier '{CASK_PACKAGE_PREFIX}' is missing a cask name"
            ));
        }
        if cask.contains('/') {
            return Err(
                "qualified package name must not contain additional path separators".to_string(),
            );
        }
        return Ok(cask.to_string());
    }
    if let Some(isotope) = package.strip_prefix(ISOTOPE_PACKAGE_PREFIX) {
        if isotope.is_empty() {
            return Err(format!(
                "package qualifier '{ISOTOPE_PACKAGE_PREFIX}' is missing an isotope name"
            ));
        }
        if isotope.contains('/') {
            return Err(
                "qualified package name must not contain additional path separators".to_string(),
            );
        }
        return Ok(format!("{ISOTOPE_PACKAGE_PREFIX}{isotope}"));
    }
    if let Some(npm_package) = package.strip_prefix("npm:") {
        validate_npm_package_name(npm_package)?;
        return Ok(npm_package_display_name(npm_package));
    }
    if let Some(pip_package) = package.strip_prefix("pip:") {
        validate_pip_package_name(pip_package)?;
        return Ok(pip_package_display_name(&normalize_pip_package_name(
            pip_package,
        )));
    }
    if package.contains('/') {
        return Err("package name must not contain path separators".to_string());
    }
    if vendor::get(package).is_none() {
        if let Some(target) = package_alias_target(package) {
            return Ok(target.display_name());
        }
        if let Ok(install_root) = package_install_root(&opt_pkg_root(), package)
            && install_root_has_valid_receipt(package, &install_root).unwrap_or(false)
        {
            return Ok(package.to_string());
        }
        if let Some(provider_name) = embedded_provider_install_package_name(package)? {
            return Ok(provider_name);
        }
        let formula = formula_install_package_name(package)?;
        if formula != package {
            return Ok(formula);
        }
    }
    Ok(package.to_string())
}

pub(crate) fn validate_npm_package_name(package: &str) -> Result<(), String> {
    if package.is_empty() {
        return Err("package qualifier 'npm:' is missing a package name".to_string());
    }
    if let Some(scoped) = package.strip_prefix('@') {
        let Some((scope, name)) = scoped.split_once('/') else {
            return Err("scoped npm package names must be in the form @scope/name".to_string());
        };
        if scope.is_empty() || name.is_empty() || name.contains('/') {
            return Err("scoped npm package names must be in the form @scope/name".to_string());
        }
        return Ok(());
    }
    if package.contains('/') {
        return Err("npm package names must not contain path separators".to_string());
    }
    Ok(())
}

pub(crate) fn parse_npm_package_request(package: &str) -> Result<(String, Option<String>), String> {
    let (name, version) = if let Some(stripped) = package.strip_prefix('@') {
        match stripped.rsplit_once('@') {
            Some((scoped_name, version)) if scoped_name.contains('/') => {
                (format!("@{scoped_name}"), Some(version.to_string()))
            }
            _ => (package.to_string(), None),
        }
    } else {
        match package.rsplit_once('@') {
            Some((name, version)) if !name.is_empty() => {
                (name.to_string(), Some(version.to_string()))
            }
            _ => (package.to_string(), None),
        }
    };
    validate_npm_package_name(&name)?;
    if let Some(version) = &version {
        if version.is_empty() {
            return Err("npm package version must not be empty".to_string());
        }
        semver::Version::parse(version)
            .map_err(|err| format!("invalid npm package version {version}: {err}"))?;
    }
    Ok((name, version))
}

pub(crate) fn npm_package_display_name(package: &str) -> String {
    crate::npm::qualified_name(package)
}

pub(crate) fn npm_package_install_relative_path(package: &str) -> PathBuf {
    crate::npm::install_relative_path(package)
}

pub(crate) fn npm_package_executable_name(package: &str) -> String {
    load_db()
        .ok()
        .and_then(|db| ensure_db_schema(&db).ok().map(|_| db))
        .and_then(|db| {
            db.npms
                .get(package)
                .map(|metadata| metadata.executable.clone())
        })
        .filter(|executable| !executable.is_empty())
        .unwrap_or_else(|| crate::npm::executable_name(package))
}

pub(crate) fn validate_pip_package_name(package: &str) -> Result<(), String> {
    if package.is_empty() {
        return Err("package qualifier 'pip:' is missing a package name".to_string());
    }
    if package.contains('/') {
        return Err("pip package names must not contain path separators".to_string());
    }
    if !package
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(
            "pip package names may only contain ASCII letters, numbers, '.', '-' and '_'"
                .to_string(),
        );
    }
    Ok(())
}

pub(crate) fn normalize_pip_package_name(package: &str) -> String {
    let mut normalized = String::with_capacity(package.len());
    let mut saw_separator = false;
    for ch in package.chars() {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            normalized.push(lower);
            saw_separator = false;
        } else if matches!(lower, '-' | '_' | '.') && !saw_separator {
            normalized.push('-');
            saw_separator = true;
        }
    }
    normalized.trim_matches('-').to_string()
}

pub(crate) fn pip_package_display_name(package: &str) -> String {
    crate::pip::qualified_name(package)
}

pub(crate) fn pip_package_install_leaf_name(package: &str) -> String {
    normalize_pip_package_name(&crate::pip::install_leaf_name(package))
}

impl PackageAliasTarget {
    pub(crate) fn display_name(&self) -> String {
        match self {
            Self::HomebrewFormula(formula) => format!("{BREW_PACKAGE_PREFIX}{formula}"),
            Self::HomebrewCask(cask) => crate::cask::qualified_name(cask),
            Self::NpmPackage(package) => npm_package_display_name(package),
            Self::PipPackage(package) => pip_package_display_name(package),
        }
    }

    pub(crate) fn into_requested_package(self) -> RequestedPackage {
        match self {
            Self::HomebrewFormula(formula) => RequestedPackage::HomebrewFormula(formula),
            Self::HomebrewCask(cask) => RequestedPackage::HomebrewCask(cask),
            Self::NpmPackage(package) => RequestedPackage::NpmPackage {
                package,
                version: None,
            },
            Self::PipPackage(package) => RequestedPackage::PipPackage(package),
        }
    }
}

pub(crate) fn embedded_package_aliases() -> &'static HashMap<String, PackageAliasTarget> {
    PACKAGE_ALIASES.get_or_init(|| {
        embedded_combined_data()
            .sources
            .aliases
            .clone()
            .into_iter()
            .map(|(alias, target)| {
                let parsed = parse_package_alias_target(&target)
                    .unwrap_or_else(|err| panic!("invalid alias target {target}: {err}"));
                (alias, parsed)
            })
            .collect()
    })
}

pub(crate) fn package_alias_target(package: &str) -> Option<&'static PackageAliasTarget> {
    embedded_package_aliases().get(package)
}

pub(crate) fn parse_package_alias_target(value: &str) -> Result<PackageAliasTarget, String> {
    if let Some(formula) = value.strip_prefix(BREW_PACKAGE_PREFIX) {
        if formula.is_empty() {
            return Err(format!(
                "package qualifier '{BREW_PACKAGE_PREFIX}' is missing a formula name"
            ));
        }
        if formula.contains('/') {
            return Err(
                "qualified package name must not contain additional path separators".to_string(),
            );
        }
        return Ok(PackageAliasTarget::HomebrewFormula(formula.to_string()));
    }
    if let Some(cask) = value.strip_prefix(CASK_PACKAGE_PREFIX) {
        if cask.is_empty() {
            return Err(format!(
                "package qualifier '{CASK_PACKAGE_PREFIX}' is missing a cask name"
            ));
        }
        if cask.contains('/') {
            return Err(
                "qualified package name must not contain additional path separators".to_string(),
            );
        }
        return Ok(PackageAliasTarget::HomebrewCask(cask.to_string()));
    }
    if let Some(npm_package) = value.strip_prefix("npm:") {
        validate_npm_package_name(npm_package)?;
        return Ok(PackageAliasTarget::NpmPackage(npm_package.to_string()));
    }
    if let Some(pip_package) = value.strip_prefix("pip:") {
        validate_pip_package_name(pip_package)?;
        return Ok(PackageAliasTarget::PipPackage(normalize_pip_package_name(
            pip_package,
        )));
    }
    Err("alias targets must use a package qualifier".to_string())
}

pub(crate) fn package_install_root(opt_root: &Path, package_name: &str) -> Result<PathBuf, String> {
    if let Some(isotope) = package_name.strip_prefix(ISOTOPE_PACKAGE_PREFIX) {
        if isotope.is_empty() {
            return Err(format!(
                "package qualifier '{ISOTOPE_PACKAGE_PREFIX}' is missing an isotope name"
            ));
        }
        if isotope.contains('/') {
            return Err(
                "qualified package name must not contain additional path separators".to_string(),
            );
        }
        if let Ok(record) = isotope_package_data(isotope) {
            if let Some(modified_package) = isotope_modified_package_name(record)? {
                return Ok(opt_root.join(modified_package));
            }
        }
        return Ok(opt_root.join(ISOTOPE_INSTALL_ROOT_DIR).join(isotope));
    }
    if let Some(npm_package) = package_name.strip_prefix("npm:") {
        validate_npm_package_name(npm_package)?;
        return Ok(opt_root
            .join("npm")
            .join(npm_package_install_relative_path(npm_package)));
    }
    if let Some(pip_package) = package_name.strip_prefix("pip:") {
        validate_pip_package_name(pip_package)?;
        return Ok(opt_root
            .join("pip")
            .join(pip_package_install_leaf_name(pip_package)));
    }
    Ok(opt_root.join(package_name))
}

pub(crate) fn parse_embedded_provider(value: &str) -> Result<Option<EmbeddedPackage>, String> {
    if let Some(package) = value.strip_prefix("npm:") {
        if package.is_empty() {
            return Err("package qualifier 'npm:' is missing a package name".to_string());
        }
        return Ok(Some(EmbeddedPackage::NpmPackage(package.to_string())));
    }
    if let Some(cask) = value.strip_prefix(CASK_PACKAGE_PREFIX) {
        if cask.is_empty() {
            return Err(format!(
                "package qualifier '{CASK_PACKAGE_PREFIX}' is missing a cask name"
            ));
        }
        return Ok(Some(EmbeddedPackage::Cask(cask.to_string())));
    }
    if value.contains(':') {
        return Ok(None);
    }
    Ok(Some(EmbeddedPackage::Formula(value.to_string())))
}

pub(crate) fn resolve_i_root_package(package: &str) -> Result<EmbeddedPackage, String> {
    let db = load_db()?;
    ensure_db_schema(&db)?;
    resolve_i_root_package_with_db(package, &db, formula_metadata_exists)
}

pub(crate) fn ensure_alias_install_target_unambiguous(
    alias: &str,
    target: &PackageAliasTarget,
) -> Result<(), String> {
    let db = load_db()?;
    ensure_db_schema(&db)?;
    ensure_alias_install_target_unambiguous_with_db(alias, target, &db, formula_metadata_exists)
}

pub(crate) fn resolve_i_root_package_with_db<F>(
    package: &str,
    db: &Db,
    formula_exists: F,
) -> Result<EmbeddedPackage, String>
where
    F: FnOnce(&str) -> Result<bool, String>,
{
    let Some(provider) = db.entries.get(package) else {
        return Ok(EmbeddedPackage::Formula(package.to_string()));
    };
    let Some(resolved) = parse_embedded_provider(provider)? else {
        return Ok(EmbeddedPackage::Formula(package.to_string()));
    };
    if provider == package {
        return Ok(resolved);
    }
    if formula_exists(package)? {
        return Err(ambiguous_install_target_message(package, provider));
    }
    Ok(resolved)
}

pub(crate) fn ensure_alias_install_target_unambiguous_with_db<F>(
    alias: &str,
    target: &PackageAliasTarget,
    db: &Db,
    formula_exists: F,
) -> Result<(), String>
where
    F: FnOnce(&str) -> Result<bool, String>,
{
    if let Some(provider) = db.entries.get(alias) {
        if parse_embedded_provider(provider)?.is_none() {
            return Ok(());
        }
        if provider == alias {
            return Err(ambiguous_alias_formula_message(alias, target));
        }
        return Err(ambiguous_alias_executable_message(alias, provider, target));
    }
    if formula_exists(alias)? {
        return Err(ambiguous_alias_formula_message(alias, target));
    }
    Ok(())
}

pub(crate) fn recommended_full_formula(formula: &str) -> Option<&'static str> {
    match formula {
        "ffmpeg" => Some("ffmpeg-full"),
        "imagemagick" => Some("imagemagick-full"),
        _ => None,
    }
}

pub(crate) fn print_full_formula_recommendation(formula: &str) -> Result<(), String> {
    let mut stderr = std::io::stderr();
    write_full_formula_recommendation(formula, &mut stderr)
}

pub(crate) fn write_full_formula_recommendation<W: Write>(
    formula: &str,
    stderr: &mut W,
) -> Result<(), String> {
    let Some(recommended) = recommended_full_formula(formula) else {
        return Ok(());
    };
    writeln!(
        stderr,
        "info: requested `{formula}`; `{BREW_PACKAGE_PREFIX}{recommended}` is recommended instead"
    )
    .map_err(|err| format!("failed to write stderr: {err}"))
}

pub(crate) fn load_db() -> Result<Db, String> {
    Ok(embedded_combined_data().sources.db.clone())
}

pub(crate) fn ensure_db_schema(db: &Db) -> Result<(), String> {
    if db.schema > DB_SCHEMA_VERSION {
        return Err(format!(
            "unsupported db schema {} (maximum supported {})",
            db.schema, DB_SCHEMA_VERSION
        ));
    }
    Ok(())
}

pub(crate) fn is_help_flag(value: &OsString) -> bool {
    matches!(value.to_str(), Some("-h" | "--help"))
}

pub(crate) fn is_version_flag(value: &OsString) -> bool {
    matches!(value.to_str(), Some("-V" | "--version"))
}

pub(crate) fn is_json_flag(value: &OsString) -> bool {
    matches!(value.to_str(), Some("--json"))
}

pub(crate) fn is_jsonl_flag(value: &OsString) -> bool {
    matches!(value.to_str(), Some("--jsonl"))
}

pub(crate) fn is_force_flag(value: &OsString) -> bool {
    matches!(value.to_str(), Some("-f" | "--force"))
}

pub(crate) fn is_no_self_update_flag(value: &OsString) -> bool {
    matches!(value.to_str(), Some(SELF_UPDATE_DISABLE_FLAG))
}

pub(crate) fn is_uninstall_subcommand(value: &str) -> bool {
    matches!(value, "uninstall" | "rm")
}

pub(crate) fn is_outdated_subcommand(value: &str) -> bool {
    value == "outdated"
}

pub(crate) fn is_update_subcommand(value: &str) -> bool {
    matches!(value, "update" | "up")
}

pub(crate) fn is_list_subcommand(value: &str) -> bool {
    matches!(value, "list" | "ls")
}

pub(crate) fn is_info_subcommand(value: &str) -> bool {
    value == "info"
}

pub(crate) fn is_search_subcommand(value: &str) -> bool {
    value == "search"
}

pub(crate) fn is_secret_scanner_subcommand(value: &str) -> bool {
    matches!(value, "scan" | "secret-scanner")
}

pub(crate) fn is_serve_subcommand(value: &str) -> bool {
    value == "serve"
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    fn invocation(name: &str) -> Invocation {
        Invocation {
            binary_name: "av".to_string(),
            name: name.to_string(),
            mode: None,
        }
    }

    #[test]
    fn secret_scanner_parser_rejects_duplicate_unknown_and_missing_paths() {
        let request = parse_secret_scanner_request_from_iter(
            &invocation("av scan"),
            vec![OsString::from("--jsonl"), OsString::from("--path"), OsString::from("/tmp/secrets")]
                .into_iter(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(request.output, OutputMode::Jsonl);
        assert_eq!(request.path, Some(PathBuf::from("/tmp/secrets")));

        assert_eq!(
            parse_secret_scanner_request_from_iter(
                &invocation("av scan"),
                vec![OsString::from("--path"), OsString::from("/tmp/a"), OsString::from("--path")]
                    .into_iter(),
            )
            .unwrap_err(),
            "secret scanner path specified more than once"
        );
        assert_eq!(
            parse_secret_scanner_request_from_iter(
                &invocation("av scan"),
                vec![OsString::from("--wat")].into_iter(),
            )
            .unwrap_err(),
            "unknown argument '--wat'"
        );
        assert_eq!(
            parse_secret_scanner_request_from_iter(
                &invocation("av scan"),
                vec![OsString::from("/tmp/a"), OsString::from("/tmp/b")].into_iter(),
            )
            .unwrap_err(),
            "supports a single scan path"
        );
        assert_eq!(
            parse_secret_scanner_request_from_iter(
                &invocation("av scan"),
                vec![OsString::from("--path")].into_iter(),
            )
            .unwrap_err(),
            "missing value for --path"
        );
        #[cfg(unix)]
        assert_eq!(
            parse_secret_scanner_request_from_iter(
                &invocation("av scan"),
                vec![OsString::from_vec(vec![0xff])].into_iter(),
            )
            .unwrap_err(),
            "secret scanner path must be valid UTF-8"
        );
    }

    #[test]
    fn package_name_parsers_cover_cask_isotope_and_fallback_edges() {
        assert_eq!(
            parse_package_name(&OsString::from("cask:")).unwrap_err(),
            "package qualifier 'cask:' is missing a cask name"
        );
        assert_eq!(
            parse_package_name(&OsString::from("cask:iterm2/tap")).unwrap_err(),
            "qualified package name must not contain additional path separators"
        );
        assert_eq!(
            parse_package_name(&OsString::from("isotope:")).unwrap_err(),
            "package qualifier 'isotope:' is missing an isotope name"
        );
        assert_eq!(
            parse_package_name(&OsString::from("isotope:gh/tools")).unwrap_err(),
            "qualified package name must not contain additional path separators"
        );

        assert_eq!(
            parse_uninstall_package_name(&OsString::from("cask:")).unwrap_err(),
            "package qualifier 'cask:' is missing a cask name"
        );
        assert_eq!(
            parse_uninstall_package_name(&OsString::from("cask:iterm2/tap")).unwrap_err(),
            "qualified package name must not contain additional path separators"
        );
        assert_eq!(
            parse_uninstall_package_name(&OsString::from("isotope:")).unwrap_err(),
            "package qualifier 'isotope:' is missing an isotope name"
        );
        assert_eq!(
            parse_uninstall_package_name(&OsString::from("isotope:gh/tools")).unwrap_err(),
            "qualified package name must not contain additional path separators"
        );
        assert_eq!(
            parse_uninstall_package_name(&OsString::from("slash/name")).unwrap_err(),
            "package name must not contain path separators"
        );
    }

    #[test]
    fn alias_target_and_install_root_helpers_cover_uncovered_variants() {
        assert_eq!(
            parse_package_alias_target("cask:").unwrap_err(),
            "package qualifier 'cask:' is missing a cask name"
        );
        assert_eq!(
            parse_package_alias_target("cask:visual-studio/code").unwrap_err(),
            "qualified package name must not contain additional path separators"
        );
        let cask_target = parse_package_alias_target("cask:iterm2").unwrap();
        assert_eq!(cask_target.display_name(), "cask:iterm2");
        assert_eq!(
            cask_target.clone().into_requested_package(),
            RequestedPackage::HomebrewCask("iterm2".to_string())
        );
        let npm_target = parse_package_alias_target("npm:@scope/pkg").unwrap();
        assert_eq!(
            npm_target.into_requested_package(),
            RequestedPackage::NpmPackage {
                package: "@scope/pkg".to_string(),
                version: None,
            }
        );
        let pip_target = parse_package_alias_target("pip:Requests").unwrap();
        assert_eq!(
            pip_target.into_requested_package(),
            RequestedPackage::PipPackage("requests".to_string())
        );

        assert_eq!(
            package_install_root(Path::new("/tmp/opt"), "isotope:").unwrap_err(),
            "package qualifier 'isotope:' is missing an isotope name"
        );
        assert_eq!(
            package_install_root(Path::new("/tmp/opt"), "isotope:aws-cli").unwrap(),
            Path::new("/tmp/opt").join("awscli")
        );
        assert_eq!(
            parse_embedded_provider("npm:").unwrap_err(),
            "package qualifier 'npm:' is missing a package name"
        );
        assert_eq!(
            parse_embedded_provider("cask:").unwrap_err(),
            "package qualifier 'cask:' is missing a cask name"
        );
        assert_eq!(parse_embedded_provider("pkg:custom").unwrap(), None);

        assert!(
            ensure_alias_install_target_unambiguous(
                "__coverage_alias__",
                &PackageAliasTarget::NpmPackage("coverage-npm".to_string()),
            )
            .is_ok()
        );
    }

    #[test]
    fn request_parsers_cover_help_version_missing_and_flag_shapes() {
        assert!(
            parse_i_request_from_iter(&invocation("av install"), Vec::<OsString>::new().into_iter())
                .unwrap_err()
                .contains("missing package name")
        );
        assert!(
            parse_i_request_from_iter(
                &invocation("av install"),
                vec![OsString::from("--help")].into_iter(),
            )
            .unwrap()
            .is_none()
        );
        assert!(
            parse_i_request_from_iter(
                &invocation("av install"),
                vec![OsString::from("--version")].into_iter(),
            )
            .unwrap()
            .is_none()
        );

        assert!(
            parse_uninstall_request_from_iter(
                &invocation("av uninstall"),
                Vec::<OsString>::new().into_iter(),
            )
            .unwrap_err()
            .contains("missing package name")
        );
        assert!(
            parse_uninstall_request_from_iter(
                &invocation("av uninstall"),
                vec![OsString::from("--help")].into_iter(),
            )
            .unwrap()
            .is_none()
        );
        assert!(
            parse_uninstall_request_from_iter(
                &invocation("av uninstall"),
                vec![OsString::from("--version")].into_iter(),
            )
            .unwrap()
            .is_none()
        );
        let uninstall = parse_uninstall_request_from_iter(
            &invocation("av uninstall"),
            vec![OsString::from("brew:ripgrep"), OsString::from("npm:@scope/pkg")].into_iter(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(uninstall.packages, ["ripgrep", "npm:@scope/pkg"]);

        assert!(
            parse_update_request_from_iter(
                &invocation("av update"),
                vec![OsString::from("--help")].into_iter(),
            )
            .unwrap()
            .is_none()
        );
        assert!(
            parse_update_request_from_iter(
                &invocation("av update"),
                vec![OsString::from("--version")].into_iter(),
            )
            .unwrap()
            .is_none()
        );
        let update = parse_update_request_from_iter(
            &invocation("av update"),
            vec![
                OsString::from("--no-self-update"),
                OsString::from("ripgrep"),
                OsString::from("npm:@scope/pkg@1.2.3"),
            ]
            .into_iter(),
        )
        .unwrap()
        .unwrap();
        assert!(update.no_self_update);
        match update.selection {
            PackageSelection::Requested(packages) => assert_eq!(packages.len(), 2),
            PackageSelection::AllInstalled => panic!("expected requested packages"),
        }

        assert!(
            parse_info_request_from_iter(&invocation("av info"), Vec::<OsString>::new().into_iter())
                .unwrap_err()
                .contains("missing package name")
        );
        assert!(
            parse_info_request_from_iter(
                &invocation("av info"),
                vec![OsString::from("--json")].into_iter(),
            )
            .unwrap_err()
            .contains("missing package name")
        );
        assert!(
            parse_info_request_from_iter(
                &invocation("av info"),
                vec![OsString::from("--help")].into_iter(),
            )
            .unwrap()
            .is_none()
        );
        assert!(
            parse_info_request_from_iter(
                &invocation("av info"),
                vec![OsString::from("--version")].into_iter(),
            )
            .unwrap()
            .is_none()
        );
        let info = parse_info_request_from_iter(
            &invocation("av info"),
            vec![OsString::from("--json"), OsString::from("ripgrep")].into_iter(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(info.output, OutputMode::Json);

        assert!(
            parse_search_request_from_iter(
                &invocation("av search"),
                Vec::<OsString>::new().into_iter(),
            )
            .unwrap_err()
            .contains("missing query")
        );
        assert!(
            parse_search_request_from_iter(
                &invocation("av search"),
                vec![OsString::from("--jsonl")].into_iter(),
            )
            .unwrap_err()
            .contains("missing query")
        );
        assert!(
            parse_search_request_from_iter(
                &invocation("av search"),
                vec![OsString::from("--help")].into_iter(),
            )
            .unwrap()
            .is_none()
        );
        assert!(
            parse_search_request_from_iter(
                &invocation("av search"),
                vec![OsString::from("--version")].into_iter(),
            )
            .unwrap()
            .is_none()
        );
        assert!(
            parse_search_request_from_iter(
                &invocation("av search"),
                vec![OsString::from("rg"), OsString::from("ripgrep")].into_iter(),
            )
            .unwrap_err()
            .contains("single query string")
        );

        assert!(
            parse_package_status_request_from_iter(
                &invocation("av list"),
                vec![OsString::from("--help")].into_iter(),
                print_list_usage,
            )
            .unwrap()
            .is_none()
        );
        assert!(
            parse_package_status_request_from_iter(
                &invocation("av list"),
                vec![OsString::from("--version")].into_iter(),
                print_list_usage,
            )
            .unwrap()
            .is_none()
        );
        let all_installed = parse_package_status_request_from_iter(
            &invocation("av list"),
            vec![OsString::from("--json")].into_iter(),
            print_list_usage,
        )
        .unwrap()
        .unwrap();
        assert_eq!(all_installed.output, OutputMode::Json);
        assert!(matches!(all_installed.selection, PackageSelection::AllInstalled));
    }

    #[test]
    fn request_parsers_cover_output_conflicts_and_search_path_edges() {
        assert_eq!(
            update_output_mode(OutputMode::Json, &OsString::from("--jsonl")).unwrap_err(),
            "cannot combine --json and --jsonl"
        );
        assert_eq!(
            update_output_mode(OutputMode::Jsonl, &OsString::from("--json")).unwrap_err(),
            "cannot combine --json and --jsonl"
        );
        assert_eq!(
            update_output_mode(OutputMode::Human, &OsString::from("--wat")).unwrap(),
            OutputMode::Human
        );

        let request = parse_search_request_from_iter(
            &invocation("av search"),
            vec![OsString::from("--jsonl"), OsString::from("rg")].into_iter(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(request.output, OutputMode::Jsonl);
        assert_eq!(request.query, "rg");

        let request = parse_package_status_request_from_iter(
            &invocation("av outdated"),
            vec![
                OsString::from("ripgrep"),
                OsString::from("npm:@scope/pkg"),
                OsString::from("--jsonl"),
            ]
            .into_iter(),
            print_outdated_usage,
        )
        .unwrap()
        .unwrap();
        assert_eq!(request.output, OutputMode::Jsonl);
        match request.selection {
            PackageSelection::Requested(packages) => assert_eq!(packages.len(), 2),
            PackageSelection::AllInstalled => panic!("expected requested packages"),
        }
    }

    #[test]
    fn alias_and_provider_resolution_cover_ambiguous_and_fallback_paths() {
        assert_eq!(
            PackageAliasTarget::HomebrewFormula("ripgrep".to_string()).into_requested_package(),
            RequestedPackage::HomebrewFormula("ripgrep".to_string())
        );

        assert_eq!(
            package_install_root(Path::new("/tmp/opt"), "isotope:coverage-missing").unwrap(),
            Path::new("/tmp/opt")
                .join(ISOTOPE_INSTALL_ROOT_DIR)
                .join("coverage-missing")
        );

        assert_eq!(
            parse_package_alias_target("brew:ripgrep")
                .unwrap()
                .into_requested_package(),
            RequestedPackage::HomebrewFormula("ripgrep".to_string())
        );
        assert_eq!(
            parse_package_alias_target("target-without-qualifier").unwrap_err(),
            "alias targets must use a package qualifier"
        );

        assert_eq!(
            parse_embedded_provider("ripgrep").unwrap(),
            Some(EmbeddedPackage::Formula("ripgrep".to_string()))
        );

        let mut db = load_db().unwrap();
        ensure_db_schema(&db).unwrap();

        db.entries.insert(
            "coverage-provider".to_string(),
            "npm:coverage-npm".to_string(),
        );
        assert_eq!(
            resolve_i_root_package_with_db("coverage-provider", &db, |_| Ok(false)).unwrap(),
            EmbeddedPackage::NpmPackage("coverage-npm".to_string())
        );
        assert!(
            resolve_i_root_package_with_db("coverage-provider", &db, |_| Ok(true))
                .unwrap_err()
                .contains("ambiguous")
        );

        db.entries.insert(
            "coverage-custom".to_string(),
            "pkg:custom-provider".to_string(),
        );
        assert_eq!(
            resolve_i_root_package_with_db("coverage-custom", &db, |_| Ok(false)).unwrap(),
            EmbeddedPackage::Formula("coverage-custom".to_string())
        );

        let target = PackageAliasTarget::HomebrewFormula("ripgrep".to_string());
        db.entries.insert(
            "coverage-alias".to_string(),
            "npm:coverage-npm".to_string(),
        );
        assert!(
            ensure_alias_install_target_unambiguous_with_db(
                "coverage-alias",
                &target,
                &db,
                |_| Ok(false),
            )
            .unwrap_err()
            .contains("ambiguous")
        );

        db.entries.insert(
            "coverage-formula-alias".to_string(),
            "coverage-formula-alias".to_string(),
        );
        assert!(
            ensure_alias_install_target_unambiguous_with_db(
                "coverage-formula-alias",
                &target,
                &db,
                |_| Ok(false),
            )
            .unwrap_err()
            .contains("ambiguous")
        );
        assert!(
            ensure_alias_install_target_unambiguous_with_db(
                "ripgrep",
                &target,
                &db,
                |_| Ok(true),
            )
            .unwrap_err()
            .contains("ambiguous")
        );

        let mut stderr = Vec::new();
        write_full_formula_recommendation("ffmpeg", &mut stderr).unwrap();
        assert!(String::from_utf8(stderr).unwrap().contains("ffmpeg-full"));
        assert!(print_full_formula_recommendation("imagemagick").is_ok());
    }

    #[test]
    fn package_helper_variants_cover_pip_npm_and_provider_branches() {
        assert_eq!(
            validate_pip_package_name("").unwrap_err(),
            "package qualifier 'pip:' is missing a package name"
        );
        assert_eq!(
            validate_pip_package_name("bad/name").unwrap_err(),
            "pip package names must not contain path separators"
        );
        assert!(
            validate_pip_package_name("bad!name")
                .unwrap_err()
                .contains("may only contain ASCII letters")
        );
        assert_eq!(normalize_pip_package_name("My..Pkg__Name"), "my-pkg-name");

        assert_eq!(
            parse_embedded_provider("npm:coverage-npm").unwrap(),
            Some(EmbeddedPackage::NpmPackage("coverage-npm".to_string()))
        );
        assert_eq!(
            parse_embedded_provider("cask:codex").unwrap(),
            Some(EmbeddedPackage::Cask("codex".to_string()))
        );
        assert_eq!(parse_embedded_provider("pkg:custom").unwrap(), None);

        assert_eq!(
            parse_npm_package_request("@scope/pkg@1.2.3").unwrap(),
            ("@scope/pkg".to_string(), Some("1.2.3".to_string()))
        );
        assert_eq!(
            parse_npm_package_request("coverage-npm@1.2.3").unwrap(),
            ("coverage-npm".to_string(), Some("1.2.3".to_string()))
        );
        assert_eq!(
            parse_npm_package_request("@scope/pkg").unwrap(),
            ("@scope/pkg".to_string(), None)
        );

        assert_eq!(
            parse_uninstall_package_name(&OsString::from("brew:")).unwrap_err(),
            "package qualifier 'brew:' is missing a formula name"
        );
        assert_eq!(
            parse_uninstall_package_name(&OsString::from("brew:ripgrep/tools")).unwrap_err(),
            "qualified package name must not contain additional path separators"
        );
        #[cfg(unix)]
        assert_eq!(
            parse_uninstall_package_name(&OsString::from_vec(vec![0xff])).unwrap_err(),
            "package name must be valid UTF-8"
        );
    }
}
