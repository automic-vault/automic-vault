use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

const MAXIMUM_HISTORY_AGE_SECONDS: u64 = 30 * 24 * 60 * 60;

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
    let options = match Options::parse(args) {
        Ok(options) => options,
        Err(error) => {
            let _ = writeln!(stderr, "av history: {error}");
            let _ = writeln!(stderr, "usage: av history [--json] [--since <duration>]");
            return 2;
        }
    };
    match crate::secrets::authorization_history(options.since).and_then(|value| {
        serde_json::from_str::<Vec<HistoryRecord>>(&value)
            .map_err(|error| format!("invalid Authorization History response: {error}"))
    }) {
        Ok(records) => {
            let result = if options.json {
                serde_json::to_writer_pretty(&mut *stdout, &records)
                    .map_err(|error| error.to_string())
                    .and_then(|()| writeln!(stdout).map_err(|error| error.to_string()))
            } else {
                write_table(stdout, &records)
            };
            if let Err(error) = result {
                let _ = writeln!(stderr, "av history: {error}");
                return 1;
            }
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "av history: {error}");
            1
        }
    }
}

struct Options {
    json: bool,
    since: Option<u64>,
}

impl Options {
    fn parse(args: Vec<OsString>) -> Result<Self, String> {
        let mut json = false;
        let mut since = None;
        let mut args = args.into_iter();
        while let Some(argument) = args.next() {
            match argument.to_str() {
                Some("--json") if !json => json = true,
                Some("--since") if since.is_none() => {
                    let duration = args
                        .next()
                        .and_then(|value| value.into_string().ok())
                        .ok_or_else(|| "--since requires a duration".to_string())?;
                    let seconds = parse_duration_seconds(&duration)?;
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| "system clock is before the Unix epoch".to_string())?
                        .as_secs();
                    since = Some(now.saturating_sub(seconds));
                }
                _ => return Err("invalid arguments".into()),
            }
        }
        Ok(Self { json, since })
    }
}

fn parse_duration_seconds(value: &str) -> Result<u64, String> {
    let (number, unit) = value.split_at(value.len().saturating_sub(1));
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        "w" => 7 * 24 * 60 * 60,
        _ => return Err("duration must end in s, m, h, d, or w".into()),
    };
    let count = number
        .parse::<u64>()
        .map_err(|_| "duration must be a positive whole number".to_string())?;
    let seconds = count
        .checked_mul(multiplier)
        .filter(|seconds| *seconds > 0 && *seconds <= MAXIMUM_HISTORY_AGE_SECONDS)
        .ok_or_else(|| "duration must be between 1 second and 30 days".to_string())?;
    Ok(seconds)
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

    #[test]
    fn table_labels_sources_and_escapes_terminal_controls() {
        let records: Vec<HistoryRecord> = serde_json::from_str(
            r#"[{"id":"1","date":"2026-09-12T12:00:00Z","tool":"av","command":"history","displayCommand":null,"decision":"Approved","approvalSource":"Auto","reason":"Always allowed\nin Settings","launcher":"Terminal","launcherIconPath":null,"callerPath":"/usr/local/bin/av","target":"av\u001b[31m","targetRuntimeProtection":null,"cwd":"","keys":[],"detail":null,"secretValueSources":null}]"#,
        ).unwrap();
        let mut output = Vec::new();
        write_table(&mut output, &records).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Policy"));
        assert!(output.contains(r"Always allowed\nin Settings"));
        assert!(output.contains(r"av\u{1b}[31m"));
        assert!(!output.contains('\u{1b}'));
    }

    #[test]
    fn since_duration_is_bounded_and_unambiguous() {
        assert_eq!(parse_duration_seconds("1s"), Ok(1));
        assert_eq!(parse_duration_seconds("7d"), Ok(7 * 24 * 60 * 60));
        assert_eq!(parse_duration_seconds("4w"), Ok(28 * 24 * 60 * 60));
        assert!(parse_duration_seconds("0s").is_err());
        assert!(parse_duration_seconds("31d").is_err());
        assert!(parse_duration_seconds("1.5h").is_err());
        assert!(parse_duration_seconds("yesterday").is_err());
    }
}
