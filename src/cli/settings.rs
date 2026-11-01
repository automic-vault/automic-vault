use serde::Deserialize;
use std::ffi::OsString;
use std::io::Write;

const USAGE: &str = "usage: av settings list [--json]\n       av settings get <key> [--json]\n       av settings set <key> <value> [--json]";

#[derive(Debug, PartialEq)]
struct Options {
    operation: &'static str,
    key: Option<String>,
    value: Option<String>,
    json: bool,
}

impl Options {
    fn parse(args: Vec<OsString>) -> Result<Self, String> {
        let mut json = false;
        let mut operands = Vec::new();
        for arg in args {
            let arg = arg.into_string().map_err(|_| "arguments must be UTF-8")?;
            if arg == "--json" && !json {
                json = true;
            } else if arg.starts_with('-') {
                return Err(format!("unknown or repeated option: {arg}"));
            } else if arg.contains('\0') {
                return Err("arguments must not contain NUL".into());
            } else {
                operands.push(arg);
            }
        }
        let (operation, key, value) = match operands.as_slice() {
            [op] if op == "list" => ("settings-list", None, None),
            [op, key] if op == "get" => ("settings-get", Some(key.clone()), None),
            [op, key, value] if op == "set" => {
                ("settings-set", Some(key.clone()), Some(value.clone()))
            }
            _ => return Err("expected list, get <key>, or set <key> <value>".into()),
        };
        Ok(Self {
            operation,
            key,
            value,
            json,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Setting {
    key: String,
    value: String,
    default_value: String,
    accepted_values: Vec<String>,
    requires_approval: bool,
}

pub(super) fn run(args: Vec<OsString>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        let _ = writeln!(stdout, "{USAGE}");
        return 0;
    }
    let options = match Options::parse(args) {
        Ok(options) => options,
        Err(error) => {
            let _ = writeln!(stderr, "av settings: {error}\n{USAGE}");
            return 2;
        }
    };
    let result = crate::secrets::settings(
        options.operation,
        options.key.as_deref(),
        options.value.as_deref(),
    )
    .and_then(|value| write_response(stdout, &value, &options));
    match result {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "av settings: {error}");
            1
        }
    }
}

fn write_response(out: &mut dyn Write, response: &str, options: &Options) -> Result<(), String> {
    let settings: Vec<Setting> = serde_json::from_str(response)
        .map_err(|error| format!("invalid settings response: {error}"))?;
    if let Some(key) = &options.key {
        if settings.len() != 1 || settings[0].key != *key {
            return Err("settings response did not match the requested key".into());
        }
    }
    let result = if options.json {
        writeln!(out, "{response}")
    } else if options.operation == "settings-get" {
        writeln!(out, "{}", settings[0].value)
    } else {
        settings.iter().try_for_each(|s| {
            writeln!(
                out,
                "{} = {} (default: {}; values: {}; {})",
                s.key,
                s.value,
                s.default_value,
                s.accepted_values.join(", "),
                if s.requires_approval {
                    "changes require Approval"
                } else {
                    "directly writable"
                }
            )
        })
    };
    result.map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(args: &[&str]) -> Result<Options, String> {
        Options::parse(args.iter().map(OsString::from).collect())
    }
    #[test]
    fn exact_command_shapes() {
        assert_eq!(
            parse(&["list", "--json"]).unwrap().operation,
            "settings-list"
        );
        let options = parse(&["--json", "set", "compact-notifications", "false"]).unwrap();
        assert_eq!(options.value.as_deref(), Some("false"));
        for args in [
            vec![],
            vec!["set", "key"],
            vec!["list", "key"],
            vec!["get", "key", "extra"],
            vec!["list", "--json", "--json"],
            vec!["set", "key", "a\0b"],
            vec!["list", "--all"],
        ] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
    }
    #[test]
    fn get_and_json_output_and_mismatched_reply() {
        let response = r#"[{"key":"compact-notifications","value":"true","defaultValue":"true","acceptedValues":["true","false"],"requiresApproval":false}]"#;
        let mut output = Vec::new();
        write_response(
            &mut output,
            response,
            &parse(&["get", "compact-notifications"]).unwrap(),
        )
        .unwrap();
        assert_eq!(output, b"true\n");
        output.clear();
        write_response(&mut output, response, &parse(&["list", "--json"]).unwrap()).unwrap();
        assert_eq!(String::from_utf8(output).unwrap(), format!("{response}\n"));
        assert!(write_response(&mut Vec::new(), "[]", &parse(&["get", "key"]).unwrap()).is_err());
    }
}
