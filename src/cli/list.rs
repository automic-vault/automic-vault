use std::ffi::OsString;
use std::io::Write;

use serde::{Deserialize, Serialize};

const USAGE: &str = "usage: av list [--json] [--project-directory=DIR]";

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "source", rename_all = "lowercase", deny_unknown_fields)]
enum Source {
    Global {
        name: String,
    },
    Project {
        name: String,
        #[serde(rename = "projectDirectory")]
        project_directory: String,
    },
    Missing {
        name: String,
    },
}

impl Source {
    fn name(&self) -> &str {
        match self {
            Self::Global { name } | Self::Project { name, .. } | Self::Missing { name } => name,
        }
    }
}

pub(super) fn run(
    args: Vec<OsString>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    terminal: bool,
) -> i32 {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        let _ = writeln!(
            stdout,
            "{USAGE}\n\nTerminals show selected sources; pipes receive names only unless an option is supplied.\nSource previews require Approval and never read Secret bytes or authorize Secret Use."
        );
        return 0;
    }
    let (json, directory) = match parse_args(args) {
        Ok(options) => options,
        Err(error) => {
            let _ = writeln!(stderr, "av list: {error}\n{USAGE}");
            return 2;
        }
    };
    let result = if terminal || json || directory.is_some() {
        preview_directory(directory)
            .and_then(|directory| crate::secrets::list_secret_sources(&directory))
            .and_then(|response| {
                render_sources(&response, stdout, json, terminal && super::color_enabled())
            })
    } else {
        crate::secrets::list_secret_names().and_then(|mut names| {
            names.sort();
            for name in names {
                writeln!(stdout, "{name}").map_err(|error| error.to_string())?;
            }
            Ok(())
        })
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "av list: {error}");
            1
        }
    }
}

fn parse_args(args: Vec<OsString>) -> Result<(bool, Option<OsString>), String> {
    let mut json = false;
    let mut directory = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--json" && !json {
            json = true;
        } else if arg == "--project-directory" && directory.is_none() {
            directory = Some(args.next().ok_or("missing project directory")?);
        } else if let Some(path) = arg
            .to_str()
            .and_then(|arg| arg.strip_prefix("--project-directory="))
        {
            if path.is_empty() || directory.is_some() {
                return Err("invalid project directory option".into());
            }
            directory = Some(path.into());
        } else {
            return Err("unexpected or repeated option".into());
        }
    }
    Ok((json, directory))
}

fn preview_directory(directory: Option<OsString>) -> Result<String, String> {
    let path = directory
        .map(std::path::PathBuf::from)
        .map(Ok)
        .unwrap_or_else(std::env::current_dir)
        .map_err(|error| error.to_string())?;
    if path.as_os_str().is_empty() {
        return Err("empty selection directory".into());
    }
    let path = std::fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve selection directory: {error}"))?;
    if !path.is_dir() {
        return Err("selection directory is not a directory".into());
    }
    path.into_os_string()
        .into_string()
        .map_err(|_| "selection directory must be UTF-8".into())
}

fn render_sources(
    response: &str,
    stdout: &mut dyn Write,
    json: bool,
    color: bool,
) -> Result<(), String> {
    let mut sources: Vec<Source> =
        serde_json::from_str(response).map_err(|_| "invalid Secret source preview")?;
    sources.sort_by(|a, b| a.name().cmp(b.name()));
    if json {
        serde_json::to_writer(&mut *stdout, &sources).map_err(|error| error.to_string())?;
        return writeln!(stdout).map_err(|error| error.to_string());
    }
    for source in sources {
        let name = safe_text(source.name());
        let label = match &source {
            Source::Global { .. } => "Global Value".into(),
            Source::Project {
                project_directory, ..
            } => format!("Project Value: {}", safe_text(project_directory)),
            Source::Missing { .. } => "No matching Value".into(),
        };
        if color && matches!(source, Source::Project { .. }) {
            writeln!(stdout, "\x1b[36m{name}\t{label}\x1b[0m")
        } else {
            writeln!(stdout, "{name}\t{label}")
        }
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn safe_text(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCES: &str = r#"[{"name":"Z","source":"project","projectDirectory":"/project\u001b[31m\n"},{"name":"A","source":"global"},{"name":"M","source":"missing"}]"#;

    #[test]
    fn json_is_sorted_and_never_colored() {
        let mut output = Vec::new();
        render_sources(SOURCES, &mut output, true, true).unwrap();
        let rows: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(rows[0]["name"], "A");
        assert_eq!(rows[1]["source"], "missing");
        assert_eq!(rows[2]["projectDirectory"], "/project\x1b[31m\n");
        assert!(!output.contains(&27));
        assert!(
            render_sources(
                r#"[{"name":"A","source":"global","value":"SECRET"}]"#,
                &mut Vec::new(),
                true,
                false
            )
            .is_err()
        );
    }

    #[test]
    fn text_colors_only_projects_and_escapes_controls() {
        let mut plain = Vec::new();
        render_sources(SOURCES, &mut plain, false, false).unwrap();
        let plain = String::from_utf8(plain).unwrap();
        assert!(plain.starts_with("A\tGlobal Value\nM\tNo matching Value\n"));
        assert!(plain.contains("Project Value: /project\\u{1b}[31m\\n"));
        assert!(!plain.contains('\x1b'));
        let mut colored = Vec::new();
        render_sources(SOURCES, &mut colored, false, true).unwrap();
        let colored = String::from_utf8(colored).unwrap();
        assert!(colored.starts_with("A\tGlobal Value\nM\tNo matching Value\n\x1b[36mZ"));
        assert!(colored.ends_with("\x1b[0m\n"));
    }

    #[test]
    fn options_reject_ambiguous_or_unknown_arguments() {
        for args in [
            vec!["--json", "--json"],
            vec!["--project-directory"],
            vec!["--project-directory="],
            vec!["--value"],
        ] {
            assert!(parse_args(args.into_iter().map(Into::into).collect()).is_err());
        }
        assert_eq!(
            parse_args(vec!["--json".into(), "--project-directory=/tmp".into()]).unwrap(),
            (true, Some("/tmp".into()))
        );
    }

    #[test]
    fn lists_only_test_keychain_files_in_name_order() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = std::env::temp_dir().join(format!("av-list-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("ignored-directory")).unwrap();
        std::fs::write(dir.join("Z_SECRET"), "z").unwrap();
        std::fs::write(dir.join("A_SECRET"), "a").unwrap();
        unsafe { std::env::set_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR", &dir) };

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(Vec::new(), &mut stdout, &mut stderr, false);

        unsafe { std::env::remove_var("AUTOMIC_VAULT_TEST_KEYCHAIN_DIR") };
        assert_eq!(code, 0);
        assert_eq!(String::from_utf8(stdout).unwrap(), "A_SECRET\nZ_SECRET\n");
        assert!(stderr.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
