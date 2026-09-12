use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct HistoryRecord {
    id: String,
    date: String,
    tool: String,
    command: String,
    display_command: Option<String>,
    decision: String,
    approval_source: Option<String>,
    reason: String,
    launcher: Option<String>,
    launcher_icon_path: Option<String>,
    caller_path: String,
    target: String,
    target_runtime_protection: Option<String>,
    cwd: String,
    keys: Vec<String>,
    detail: Option<String>,
    secret_value_sources: Option<BTreeMap<String, String>>,
}

pub(super) fn run(args: Vec<OsString>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let json = match args.as_slice() {
        [] => false,
        [arg] if arg == "--json" => true,
        _ => {
            let _ = writeln!(stderr, "usage: av history [--json]");
            return 2;
        }
    };
    match crate::secrets::authorization_history()
        .and_then(|value| write_response(stdout, &value, json))
    {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "av history: {error}");
            1
        }
    }
}

fn write_response(output: &mut dyn Write, value: &str, json: bool) -> Result<(), String> {
    let records = serde_json::from_str::<Vec<HistoryRecord>>(value)
        .map_err(|error| format!("invalid Authorization History response: {error}"))?;
    if json {
        serde_json::to_writer_pretty(&mut *output, &records).map_err(|error| error.to_string())?;
        writeln!(output).map_err(|error| error.to_string())
    } else {
        write_table(output, &records)
    }
}

fn write_table(output: &mut dyn Write, records: &[HistoryRecord]) -> Result<(), String> {
    let mut rows = vec![[
        "DATE".into(),
        "DECISION".into(),
        "SOURCE".into(),
        "LAUNCHER".into(),
        "COMMAND".into(),
        "SECRET NAMES".into(),
        "REASON".into(),
        "TARGET".into(),
    ]];
    rows.extend(records.iter().map(|record| {
        let command = record
            .display_command
            .clone()
            .unwrap_or_else(|| format!("{} <arguments hidden>", record.tool));
        [
            safe_cell(&record.date),
            safe_cell(&record.decision),
            safe_cell(&record.source_label()),
            safe_cell(record.launcher.as_deref().unwrap_or(&record.caller_path)),
            safe_cell(&command),
            safe_cell(&record.keys.join(", ")),
            safe_cell(&record.reason),
            safe_cell(&record.target),
        ]
    }));
    let widths: [usize; 8] = std::array::from_fn(|column| {
        rows.iter()
            .map(|row| row[column].chars().count())
            .max()
            .unwrap_or(0)
    });
    for row in rows {
        for (column, cell) in row.iter().enumerate() {
            write!(output, "{cell:width$}", width = widths[column])
                .map_err(|error| error.to_string())?;
            if column + 1 < row.len() {
                write!(output, "  ").map_err(|error| error.to_string())?;
            }
        }
        writeln!(output).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn safe_cell(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| {
            if character.is_control() {
                character.escape_default().collect::<Vec<_>>()
            } else {
                vec![character]
            }
        })
        .collect()
}

impl HistoryRecord {
    fn source_label(&self) -> String {
        match self
            .approval_source
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("auto" | "automatic" | "policy") => "Policy".into(),
            Some("manual" | "human") => "Human".into(),
            Some(source) if !source.is_empty() => source.into(),
            _ if self.reason.to_ascii_lowercase().contains("auto")
                || self.reason.to_ascii_lowercase().contains("reused") =>
            {
                "Policy".into()
            }
            _ if self.reason.to_ascii_lowercase().contains("prompt") => "Human".into(),
            _ => "Unknown".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESPONSE: &str = r#"[{"id":"1","date":"2026-09-12T12:00:00Z","tool":"av","command":"av history --token <redacted>","displayCommand":"av history --token <redacted>","decision":"Approved","approvalSource":"Auto","reason":"Always allowed\nin Settings","launcher":"Terminal","launcherIconPath":null,"callerPath":"/usr/local/bin/av","target":"av\u001b[31m","targetRuntimeProtection":null,"cwd":"","keys":[],"detail":null,"secretValueSources":null}]"#;

    #[test]
    fn table_labels_sources_and_escapes_terminal_controls() {
        let mut output = Vec::new();
        write_response(&mut output, RESPONSE, false).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Policy"));
        assert!(output.contains("av history --token <redacted>"));
        assert!(output.contains(r"Always allowed\nin Settings"));
        assert!(output.contains(r"av\u{1b}[31m"));
        assert!(!output.contains('\u{1b}'));
    }

    #[test]
    fn json_decodes_wire_response_and_writes_camel_case_document() {
        let mut output = Vec::new();
        write_response(&mut output, RESPONSE, true).unwrap();
        let document: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(document[0]["date"], "2026-09-12T12:00:00Z");
        assert_eq!(
            document[0]["displayCommand"],
            "av history --token <redacted>"
        );
        assert!(document[0].get("display_command").is_none());
    }
}
