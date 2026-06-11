//! Optional, non-blocking, tamper-evident audit log for `av`.
//!
//! Design constraints (see DESIGN discussion):
//! - **Exec-safe**: secret-pull events are written synchronously *before* the
//!   `execve`/spawn that replaces or detaches the process, so no background
//!   thread is involved.
//! - **Non-blocking**: a single `O_APPEND` write, no `fsync`, and every error is
//!   swallowed — auditing must never break or slow a gated operation.
//! - **Optional**: gated on [`crate::config::audit_enabled`] (default OFF). Turn
//!   it on/off persistently with `av audit enable` / `av audit disable` (writes
//!   `~/Library/Application Support/Automic Vault/audit-config.json`); the
//!   `AV_AUDIT` env var overrides the file for one-shot/CI use. When disabled,
//!   [`record`] returns before touching the filesystem.
//! - **No secret values**: the [`Body`] type has no field that can hold a secret
//!   value. Emit sites pass key *names*, paths, argv, decisions — never values.
//! - **Tamper-evident**: every record carries a SHA-256 hash chain (always on);
//!   an optional Keychain-keyed HMAC layer (`AV_AUDIT_HMAC=1`) adds
//!   forgery-resistance against anyone without the Keychain key. The key is
//!   provisioned once via `av audit setup` (a non-exec context); the exec path
//!   only *reads* it (never generates it), so it cannot trigger a Keychain
//!   write prompt mid-injection. If no key is present, records fall back to
//!   chain-only for that write.
//! - **Inspectable**: newline-delimited JSON (JSONL), one record per line.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

/// Genesis previous-hash for the first record in a chain (64 hex zeros).
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const SCHEMA_VERSION: u32 = 1;

/// Keychain coordinates for the optional HMAC signing key.
const HMAC_SERVICE: &str = "com.automicvault.audit";
const HMAC_ACCOUNT: &str = "hmac-key-v1";

// Event names.
pub(crate) const EVENT_SECRET_INJECT: &str = "secret.inject";
pub(crate) const EVENT_SECRET_PULL: &str = "secret.pull";
pub(crate) const EVENT_APPROVAL_DECISION: &str = "approval.decision";
pub(crate) const EVENT_COMMAND_GATE: &str = "command.gate";
pub(crate) const EVENT_COMMAND_CONTAIN: &str = "command.contain";
pub(crate) const EVENT_KEY_TRANSFER_IMPORT: &str = "key.transfer.import";

// Decisions.
pub(crate) const DECISION_APPROVED: &str = "approved";
pub(crate) const DECISION_DENIED: &str = "denied";
pub(crate) const DECISION_AUTO_GRANT: &str = "auto_grant";
pub(crate) const DECISION_OBSERVED: &str = "observed";

/// Non-secret parent-process context.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ParentInfo {
    pub(crate) pid: i64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) executable_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) display_name: Option<String>,
}

/// Event-specific payload. **By construction this type holds no secret values** —
/// only key NAMES, paths, argv, digests, fingerprints, decisions, and counts.
/// Redaction is enforced by the type, not by filtering.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct Body {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    keys: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    exec_path: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    argv: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    parent: Option<ParentInfo>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    env_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    project_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    env_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    public_key_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    request_id: Option<String>,
    /// Whether a credential-helper auth token was present — NEVER the token value.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    token_present: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    imported: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    already_present: Option<u64>,
}

/// A pending audit event, built at an emit site and handed to [`record`].
pub(crate) struct Event {
    event: &'static str,
    decision: &'static str,
    body: Body,
}

impl Event {
    pub(crate) fn new(event: &'static str, decision: &'static str) -> Self {
        Event {
            event,
            decision,
            body: Body::default(),
        }
    }

    pub(crate) fn keys<I, S>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.body.keys = keys.into_iter().map(Into::into).collect();
        self
    }

    pub(crate) fn exec(mut self, exec_path: impl Into<String>, argv: Vec<String>) -> Self {
        self.body.exec_path = Some(exec_path.into());
        self.body.argv = argv;
        self
    }

    pub(crate) fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.body.cwd = Some(cwd.into());
        self
    }

    pub(crate) fn parent(
        mut self,
        pid: i64,
        executable_path: Option<String>,
        display_name: Option<String>,
    ) -> Self {
        self.body.parent = Some(ParentInfo {
            pid,
            executable_path,
            display_name,
        });
        self
    }

    pub(crate) fn message(mut self, message: impl Into<String>) -> Self {
        self.body.message = Some(message.into());
        self
    }

    pub(crate) fn reason(mut self, reason: Option<String>) -> Self {
        self.body.reason = reason;
        self
    }

    pub(crate) fn outcome(mut self, outcome: impl Into<String>) -> Self {
        self.body.outcome = Some(outcome.into());
        self
    }

    pub(crate) fn mode(mut self, mode: impl Into<String>) -> Self {
        self.body.mode = Some(mode.into());
        self
    }

    pub(crate) fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.body.request_id = Some(request_id.into());
        self
    }

    pub(crate) fn token_present(mut self, present: bool) -> Self {
        self.body.token_present = Some(present);
        self
    }

    pub(crate) fn dotenv(
        mut self,
        env_path: impl Into<String>,
        project_root: impl Into<String>,
        env_sha256: impl Into<String>,
        public_key_fingerprint: impl Into<String>,
    ) -> Self {
        self.body.env_path = Some(env_path.into());
        self.body.project_root = Some(project_root.into());
        self.body.env_sha256 = Some(env_sha256.into());
        self.body.public_key_fingerprint = Some(public_key_fingerprint.into());
        self
    }

    pub(crate) fn counts(mut self, imported: u64, already_present: u64) -> Self {
        self.body.imported = Some(imported);
        self.body.already_present = Some(already_present);
        self
    }
}

/// Canonical (signed) view of a record: everything that gets hashed, in a fixed
/// field order. Excludes `prev_hash`/`hash`/`mac`.
#[derive(Serialize)]
struct CoreView<'a> {
    v: u32,
    seq: u64,
    ts: &'a str,
    ts_unix: u64,
    pid: u32,
    event: &'a str,
    decision: &'a str,
    #[serde(flatten)]
    body: &'a Body,
}

/// A full, persisted record (one JSONL line).
#[derive(Serialize, Deserialize)]
struct Record {
    v: u32,
    seq: u64,
    ts: String,
    ts_unix: u64,
    pid: u32,
    event: String,
    decision: String,
    #[serde(flatten)]
    body: Body,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    mac: String,
    prev_hash: String,
    hash: String,
}

impl Record {
    /// Recompute the canonical signed bytes for this record (used by the verifier).
    fn canonical_body(&self) -> Result<String, String> {
        let core = CoreView {
            v: self.v,
            seq: self.seq,
            ts: &self.ts,
            ts_unix: self.ts_unix,
            pid: self.pid,
            event: &self.event,
            decision: &self.decision,
            body: &self.body,
        };
        serde_json::to_string(&core).map_err(|err| format!("serialize core: {err}"))
    }
}

/// THE entry point used at every emit site. Best-effort, never panics, exec-safe.
pub(crate) fn record(event: Event) {
    if !crate::config::audit_enabled() {
        return;
    }
    let _ = try_record(event);
}

fn try_record(mut event: Event) -> Result<(), ()> {
    // argv/cwd can themselves carry a secret if the user put one on the command
    // line (e.g. `--token=...`). Honor the opt-out by dropping them.
    if crate::config::audit_redact_argv() {
        event.body.argv.clear();
        event.body.cwd = None;
    }

    let path = crate::config::audit_log_path().map_err(|_| ())?;
    let dir = path.parent().ok_or(())?;
    let _ = fs::create_dir_all(dir);
    let _ = fs::set_permissions(dir, Permissions::from_mode(0o700));

    // Serialize writers across processes with a dedicated lock file that never
    // rotates (so reopening the data file mid-critical-section is safe).
    let lock_path = dir.join("audit.lock");
    let lock_file = OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|_| ())?;
    // Non-blocking: if another `av` process holds the lock, skip this record
    // rather than delay the exec. Lock is held (released on drop) across the
    // read-tip + rotate + write critical section. `lock_file` (and thus the fd)
    // outlives the guard, and the data file may be reopened on rotation without
    // affecting this lock.
    let _lock = FlockGuard::try_acquire(&lock_file).ok_or(())?;

    // Read the chain tip from the active file (carried across rotation).
    let (prev_hash, seq) = read_tip(&path);

    let mut file = open_append(&path)?;

    // Size-based rotation: rename active -> .1 and continue the chain.
    let max_bytes = crate::config::audit_max_bytes();
    let current_len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if max_bytes > 0 && current_len >= max_bytes {
        let _ = fs::rename(&path, rotated_path(&path));
        file = open_append(&path)?;
        // prev_hash/seq intentionally retained so the chain spans rotation.
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ts = fmt_rfc3339(now);
    let pid = process::id();

    let core = CoreView {
        v: SCHEMA_VERSION,
        seq,
        ts: &ts,
        ts_unix: now,
        pid,
        event: event.event,
        decision: event.decision,
        body: &event.body,
    };
    let body_json = serde_json::to_string(&core).map_err(|_| ())?;

    let mac = match resolve_key() {
        Some(key) => hmac_sha256_hex(&key, format!("{prev_hash}\n{body_json}").as_bytes()),
        None => String::new(),
    };
    let hash = chain_hash(&prev_hash, &body_json, &mac);

    let rec = Record {
        v: SCHEMA_VERSION,
        seq,
        ts,
        ts_unix: now,
        pid,
        event: event.event.to_string(),
        decision: event.decision.to_string(),
        body: event.body,
        mac,
        prev_hash,
        hash,
    };
    let mut line = serde_json::to_string(&rec).map_err(|_| ())?;
    line.push('\n');
    file.write_all(line.as_bytes()).map_err(|_| ())?;
    // Deliberately NO fsync: keeps the pre-exec path non-blocking.
    Ok(())
}

fn open_append(path: &Path) -> Result<File, ()> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| ())?;
    // Tighten perms if the file pre-existed with looser bits.
    let _ = fs::set_permissions(path, Permissions::from_mode(0o600));
    Ok(file)
}

/// Scan a file for its last well-formed record; return `(prev_hash, next_seq)`.
fn read_tip(path: &Path) -> (String, u64) {
    let Ok(file) = File::open(path) else {
        return (GENESIS.to_string(), 0);
    };
    let mut last: Option<(String, u64)> = None;
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(rec) = serde_json::from_str::<Record>(trimmed) {
            last = Some((rec.hash, rec.seq));
        }
    }
    match last {
        Some((hash, seq)) => (hash, seq + 1),
        None => (GENESIS.to_string(), 0),
    }
}

fn rotated_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".1");
    PathBuf::from(name)
}

fn chain_hash(prev_hash: &str, body_json: &str, mac: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(b"\n");
    hasher.update(body_json.as_bytes());
    if !mac.is_empty() {
        hasher.update(b"\n");
        hasher.update(mac.as_bytes());
    }
    encode_hex(&hasher.finalize())
}

/// HMAC-SHA256 over `message`, hex-encoded. Hand-rolled on `sha2` (zero new deps).
fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] = block[i] ^ 0x36;
        opad[i] = block[i] ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    encode_hex(&outer.finalize())
}

/// Provision the HMAC signing key in the Keychain. Run from `av audit setup`
/// (a non-exec-critical context) — never on the exec path, because key
/// generation writes to the Keychain and may surface a user prompt. Returns
/// `true` if a new key was created, `false` if one already existed.
fn provision_hmac_key() -> Result<bool, String> {
    match crate::isotope::keychain_read_audit_secret(HMAC_SERVICE, HMAC_ACCOUNT)? {
        Some(existing) if decode_hex(&existing).map(|b| b.len() == 32).unwrap_or(false) => {
            Ok(false)
        }
        _ => {
            let key = random_key().ok_or_else(|| "failed to read /dev/urandom".to_string())?;
            crate::isotope::keychain_write_audit_secret(
                HMAC_SERVICE,
                HMAC_ACCOUNT,
                &encode_hex(&key),
            )?;
            Ok(true)
        }
    }
}

fn random_key() -> Option<Vec<u8>> {
    let mut file = File::open("/dev/urandom").ok()?;
    let mut buf = [0u8; 32];
    file.read_exact(&mut buf).ok()?;
    Some(buf.to_vec())
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

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    for pair in bytes.chunks(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

/// Format unix seconds as RFC3339 UTC (e.g. `2026-06-11T18:04:07Z`). Hand-rolled
/// because the `time` crate is built with `features = ["parsing"]` only.
fn fmt_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // Howard Hinnant's civil_from_days, days since 1970-01-01.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    if month <= 2 {
        year += 1;
    }
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

struct FlockGuard {
    fd: i32,
}

impl FlockGuard {
    /// Acquire an exclusive lock *without blocking*. Returns `None` if the lock
    /// is already held by another `av` process (or on any flock error), so the
    /// caller drops this record rather than stalling the pre-exec path. This
    /// keeps the contract: auditing never delays a gated operation.
    fn try_acquire(file: &File) -> Option<Self> {
        let fd = file.as_raw_fd();
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            return None;
        }
        Some(FlockGuard { fd })
    }
}

impl Drop for FlockGuard {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.fd, libc::LOCK_UN);
        }
    }
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum VerifyOutcome {
    Ok {
        records: usize,
        hmac_checked: bool,
        head: String,
    },
    /// The final line is unparseable/invalid — likely a crash or torn write.
    TrailingPartial {
        line: usize,
    },
    Break {
        line: usize,
        kind: &'static str,
    },
}

fn verify_lines(lines: &[String], key: Option<&[u8]>) -> VerifyOutcome {
    let nonempty: Vec<(usize, &String)> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .collect();
    let mut prev = GENESIS.to_string();
    let mut expect_seq: Option<u64> = None;
    let total = nonempty.len();

    for (idx, (orig_line, raw)) in nonempty.iter().enumerate() {
        let is_last = idx + 1 == total;
        let line_no = orig_line + 1;
        let rec: Record = match serde_json::from_str(raw.trim()) {
            Ok(rec) => rec,
            Err(_) if is_last => return VerifyOutcome::TrailingPartial { line: line_no },
            Err(_) => {
                return VerifyOutcome::Break {
                    line: line_no,
                    kind: "malformed",
                };
            }
        };

        // Allow a non-genesis start (history may begin mid-chain after the
        // oldest rotated segment ages out).
        if idx == 0 {
            expect_seq = Some(rec.seq);
        }
        if let Some(want) = expect_seq {
            if rec.seq != want {
                return VerifyOutcome::Break {
                    line: line_no,
                    kind: "seq_gap",
                };
            }
        }
        if idx > 0 && rec.prev_hash != prev {
            return VerifyOutcome::Break {
                line: line_no,
                kind: "chain_break",
            };
        }

        let Ok(body_json) = rec.canonical_body() else {
            return VerifyOutcome::Break {
                line: line_no,
                kind: "malformed",
            };
        };

        if let Some(key) = key {
            let want_mac = hmac_sha256_hex(key, format!("{}\n{body_json}", rec.prev_hash).as_bytes());
            if want_mac != rec.mac {
                return VerifyOutcome::Break {
                    line: line_no,
                    kind: "mac_break",
                };
            }
        }

        if chain_hash(&rec.prev_hash, &body_json, &rec.mac) != rec.hash {
            return VerifyOutcome::Break {
                line: line_no,
                kind: "chain_break",
            };
        }

        prev = rec.hash.clone();
        expect_seq = Some(rec.seq + 1);
    }

    VerifyOutcome::Ok {
        records: total,
        hmac_checked: key.is_some(),
        head: prev,
    }
}

/// Read the full available history (rotated segment, then active) as lines.
fn read_history(path: &Path) -> Vec<String> {
    let mut lines = Vec::new();
    for candidate in [rotated_path(path), path.to_path_buf()] {
        if let Ok(content) = fs::read_to_string(&candidate) {
            lines.extend(content.lines().map(str::to_string));
        }
    }
    lines
}

// ---------------------------------------------------------------------------
// CLI: `av log` (viewer) and `av audit` (integrity / diagnostics)
// ---------------------------------------------------------------------------

pub(crate) fn is_audit_subcommand(value: &str) -> bool {
    value == "audit"
}

pub(crate) fn is_log_subcommand(value: &str) -> bool {
    value == "log"
}

pub(crate) fn run_audit_cli(
    program_name: &str,
    subcommand: &str,
    args: env::ArgsOs,
) -> Result<(), String> {
    let argv: Vec<String> = args.map(|a| a.to_string_lossy().into_owned()).collect();
    if subcommand == "log" {
        return run_log_view(program_name, &argv);
    }
    // `av audit ...`
    match argv.first().map(String::as_str) {
        Some("verify") => run_verify(program_name, &argv[1..]),
        Some("path") => run_path(),
        Some("setup") => run_setup(),
        Some("enable") => run_set_enabled(true),
        Some("disable") => run_set_enabled(false),
        Some("tail") | None => run_log_view(program_name, &argv),
        Some("--help") | Some("-h") => {
            print_audit_usage(program_name);
            Ok(())
        }
        Some(other) => Err(format!("unknown audit command '{other}'")),
    }
}

fn run_set_enabled(enabled: bool) -> Result<(), String> {
    let path = crate::config::set_persisted_audit_enabled(enabled)?;
    println!(
        "audit logging {} ({})",
        if enabled { "enabled" } else { "disabled" },
        path.display()
    );
    if std::env::var_os("AV_AUDIT").is_some() {
        eprintln!(
            "note: the AV_AUDIT environment variable is set and overrides this setting for the current environment"
        );
    }
    Ok(())
}

fn run_setup() -> Result<(), String> {
    if !crate::config::audit_hmac_enabled() {
        return Err(
            "enable the HMAC layer first (set AV_AUDIT_HMAC=1), then re-run `av audit setup`"
                .to_string(),
        );
    }
    if provision_hmac_key()? {
        println!("provisioned a new audit HMAC key in the keychain");
    } else {
        println!("audit HMAC key already present");
    }
    Ok(())
}

fn run_path() -> Result<(), String> {
    let path = crate::config::audit_log_path()?;
    let key_present = crate::config::audit_hmac_enabled()
        && matches!(
            crate::isotope::keychain_read_audit_secret(HMAC_SERVICE, HMAC_ACCOUNT),
            Ok(Some(_))
        );
    println!("path:    {}", path.display());
    if let Ok(config_path) = crate::config::audit_config_path() {
        println!("config:  {}", config_path.display());
    }
    println!(
        "enabled: {}",
        if crate::config::audit_enabled() {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "hmac:    {}",
        if !crate::config::audit_hmac_enabled() {
            "off"
        } else if key_present {
            "on (key present)"
        } else {
            "on (no key yet)"
        }
    );
    Ok(())
}

fn resolve_key() -> Option<Vec<u8>> {
    if !crate::config::audit_hmac_enabled() {
        return None;
    }
    match crate::isotope::keychain_read_audit_secret(HMAC_SERVICE, HMAC_ACCOUNT) {
        Ok(Some(encoded)) => decode_hex(&encoded).filter(|bytes| bytes.len() == 32),
        _ => None,
    }
}

fn run_verify(_program_name: &str, args: &[String]) -> Result<(), String> {
    let json = args.iter().any(|a| a == "--json");
    let path = crate::config::audit_log_path()?;
    let lines = read_history(&path);
    if lines.iter().all(|l| l.trim().is_empty()) {
        if json {
            println!("{{\"status\":\"empty\",\"path\":{}}}", json_str(&path.display().to_string()));
        } else {
            println!("audit log is empty ({})", path.display());
        }
        return Ok(());
    }
    let key = resolve_key();
    match verify_lines(&lines, key.as_deref()) {
        VerifyOutcome::Ok {
            records,
            hmac_checked,
            head,
        } => {
            if json {
                println!(
                    "{{\"status\":\"ok\",\"records\":{records},\"hmac\":{hmac_checked},\"head\":{}}}",
                    json_str(&head)
                );
            } else {
                println!(
                    "OK — {records} record(s) verified{}; head {}",
                    if hmac_checked { " (chain + HMAC)" } else { " (chain)" },
                    &head[..head.len().min(12)]
                );
            }
            Ok(())
        }
        VerifyOutcome::TrailingPartial { line } => {
            if json {
                println!("{{\"status\":\"trailing_partial\",\"line\":{line}}}");
                Ok(())
            } else {
                println!("WARNING — trailing partial record at line {line} (likely a crash/torn write)");
                Ok(())
            }
        }
        VerifyOutcome::Break { line, kind } => {
            if json {
                println!("{{\"status\":\"break\",\"line\":{line},\"kind\":{}}}", json_str(kind));
            }
            Err(format!("integrity check failed: {kind} at line {line}"))
        }
    }
}

fn run_log_view(program_name: &str, args: &[String]) -> Result<(), String> {
    let mut limit: usize = 20;
    let mut json = false;
    let mut event_filter: Option<String> = None;
    let mut do_verify = false;
    let mut do_path = false;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "tail" => {}
            "-n" | "--limit" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("{arg} requires a number"))?;
                limit = value
                    .parse()
                    .map_err(|_| format!("invalid value for {arg}: {value}"))?;
            }
            "--json" => json = true,
            "--verify" => do_verify = true,
            "--path" => do_path = true,
            "--event" => {
                event_filter = Some(
                    iter.next()
                        .ok_or_else(|| "--event requires a value".to_string())?
                        .clone(),
                );
            }
            "--help" | "-h" => {
                print_log_usage(program_name);
                return Ok(());
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown flag '{other}'"));
            }
            _ => {}
        }
    }

    if do_path {
        return run_path();
    }
    if do_verify {
        let verify_args: Vec<String> = if json {
            vec!["--json".to_string()]
        } else {
            Vec::new()
        };
        return run_verify(program_name, &verify_args);
    }

    let path = crate::config::audit_log_path()?;
    let lines = read_history(&path);
    let mut records: Vec<Record> = lines
        .iter()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<Record>(l.trim()).ok())
        .collect();

    if let Some(ref kind) = event_filter {
        records.retain(|r| &r.event == kind);
    }

    if records.is_empty() {
        if !json {
            let state = if crate::config::audit_enabled() {
                "enabled"
            } else {
                "disabled"
            };
            println!(
                "No audit records at {} (auditing is {state}).",
                path.display()
            );
        }
        return Ok(());
    }

    let start = records.len().saturating_sub(limit);
    for rec in &records[start..] {
        if json {
            if let Ok(line) = serde_json::to_string(rec) {
                println!("{line}");
            }
        } else {
            println!("{}", format_human(rec));
        }
    }
    Ok(())
}

fn format_human(rec: &Record) -> String {
    let mut parts = vec![
        rec.ts.clone(),
        format!("{:<18}", rec.event),
        format!("{:<10}", rec.decision),
    ];
    if !rec.body.keys.is_empty() {
        parts.push(format!("keys={}", rec.body.keys.join(",")));
    }
    if let Some(ref exec) = rec.body.exec_path {
        parts.push(format!("exec={exec}"));
    }
    if let Some(ref msg) = rec.body.message {
        parts.push(format!("msg={msg:?}"));
    }
    if let Some(ref cwd) = rec.body.cwd {
        parts.push(format!("cwd={cwd}"));
    }
    if let Some(parent) = &rec.body.parent {
        if let Some(name) = &parent.display_name {
            parts.push(format!("parent={name}"));
        }
    }
    if let Some(ref reason) = rec.body.reason {
        parts.push(format!("reason={reason:?}"));
    }
    parts.join("  ")
}

fn json_str(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

fn print_audit_usage(program: &str) {
    println!("Usage: {program} <enable|disable|verify|path|setup|tail> [--json]");
    println!();
    println!("Manage, inspect, and verify the av audit log.");
    println!("  enable   turn audit logging on (persisted to the config file)");
    println!("  disable  turn audit logging off");
    println!("  verify   check the hash chain (and HMAC, if enabled)");
    println!("  path     show the log path and enabled/HMAC state");
    println!("  setup    provision the optional Keychain HMAC key (needs AV_AUDIT_HMAC=1)");
}

fn print_log_usage(program: &str) {
    println!("Usage: {program} [-n N] [--event KIND] [--json] [--verify] [--path]");
    println!();
    println!("Shows recent audit-log records (secret pulls and command invocations).");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(event: &'static str, decision: &'static str) -> Event {
        Event::new(event, decision)
            .keys(["AWS_ACCESS_KEY_ID".to_string(), "AWS_SECRET_ACCESS_KEY".to_string()])
            .exec("/usr/local/bin/terraform", vec!["terraform".to_string(), "apply".to_string()])
            .cwd("/work")
            .parent(42, Some("/bin/zsh".to_string()), Some("zsh".to_string()))
    }

    fn build_line(prev_hash: &str, seq: u64, event: Event, key: Option<&[u8]>) -> (String, String) {
        let now = 1_700_000_000;
        let ts = fmt_rfc3339(now);
        let core = CoreView {
            v: SCHEMA_VERSION,
            seq,
            ts: &ts,
            ts_unix: now,
            pid: 1,
            event: event.event,
            decision: event.decision,
            body: &event.body,
        };
        let body_json = serde_json::to_string(&core).unwrap();
        let mac = match key {
            Some(k) => hmac_sha256_hex(k, format!("{prev_hash}\n{body_json}").as_bytes()),
            None => String::new(),
        };
        let hash = chain_hash(prev_hash, &body_json, &mac);
        let rec = Record {
            v: SCHEMA_VERSION,
            seq,
            ts,
            ts_unix: now,
            pid: 1,
            event: event.event.to_string(),
            decision: event.decision.to_string(),
            body: event.body,
            mac,
            prev_hash: prev_hash.to_string(),
            hash: hash.clone(),
        };
        (serde_json::to_string(&rec).unwrap(), hash)
    }

    #[test]
    fn rfc3339_known_vectors() {
        assert_eq!(fmt_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(fmt_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn hmac_known_vector() {
        // RFC 4231 test case 1: key = 0x0b*20, data = "Hi There".
        let key = vec![0x0b; 20];
        let mac = hmac_sha256_hex(&key, b"Hi There");
        assert_eq!(
            mac,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hex_round_trips() {
        let bytes = vec![0u8, 1, 15, 16, 255, 128];
        assert_eq!(decode_hex(&encode_hex(&bytes)), Some(bytes));
        assert_eq!(decode_hex("zz"), None);
        assert_eq!(decode_hex("abc"), None);
    }

    #[test]
    fn chain_verifies_and_detects_tampering() {
        let (l0, h0) = build_line(GENESIS, 0, sample(EVENT_SECRET_INJECT, DECISION_AUTO_GRANT), None);
        let (l1, h1) = build_line(&h0, 1, sample(EVENT_COMMAND_CONTAIN, DECISION_OBSERVED), None);
        let (l2, _h2) = build_line(&h1, 2, sample(EVENT_COMMAND_GATE, DECISION_DENIED), None);

        let lines = vec![l0.clone(), l1.clone(), l2.clone()];
        assert!(matches!(
            verify_lines(&lines, None),
            VerifyOutcome::Ok { records: 3, .. }
        ));

        // Tamper with a middle record's decision field.
        let tampered_mid = l1.replace("\"observed\"", "\"approved\"");
        let lines = vec![l0.clone(), tampered_mid, l2.clone()];
        assert!(matches!(
            verify_lines(&lines, None),
            VerifyOutcome::Break { line: 2, .. }
        ));

        // Truncated tail verifies OK as a shorter chain.
        let lines = vec![l0.clone(), l1.clone()];
        assert!(matches!(
            verify_lines(&lines, None),
            VerifyOutcome::Ok { records: 2, .. }
        ));
    }

    #[test]
    fn hmac_layer_detects_body_edit() {
        let key = vec![7u8; 32];
        let (l0, h0) = build_line(GENESIS, 0, sample(EVENT_SECRET_INJECT, DECISION_APPROVED), Some(&key));
        let (l1, _h1) = build_line(&h0, 1, sample(EVENT_COMMAND_CONTAIN, DECISION_OBSERVED), Some(&key));
        let lines = vec![l0.clone(), l1.clone()];
        assert!(matches!(
            verify_lines(&lines, Some(&key)),
            VerifyOutcome::Ok { records: 2, hmac_checked: true, .. }
        ));

        // Editing the body without the key cannot produce a valid mac.
        let forged = l1.replace("terraform", "rm -rf /");
        let lines = vec![l0, forged];
        assert!(matches!(
            verify_lines(&lines, Some(&key)),
            VerifyOutcome::Break { line: 2, kind: "mac_break" }
        ));
    }

    #[test]
    fn trailing_partial_is_a_warning_not_a_break() {
        let (l0, _h0) = build_line(GENESIS, 0, sample(EVENT_SECRET_INJECT, DECISION_APPROVED), None);
        let lines = vec![l0, "{\"v\":1,\"seq\":1,\"par".to_string()];
        assert!(matches!(
            verify_lines(&lines, None),
            VerifyOutcome::TrailingPartial { line: 2 }
        ));
    }

    #[test]
    fn record_never_contains_secret_values() {
        // Even if a builder is fed only names, ensure no value-shaped field exists.
        let (line, _h) = build_line(
            GENESIS,
            0,
            Event::new(EVENT_SECRET_INJECT, DECISION_APPROVED)
                .keys(["MY_SECRET".to_string()])
                .token_present(true),
            None,
        );
        assert!(line.contains("MY_SECRET")); // the NAME is present
        assert!(!line.contains("\"value\""));
        assert!(!line.contains("\"secret\""));
        assert!(!line.contains("\"token\":")); // only token_present, never token
        assert!(line.contains("token_present"));
    }

    #[test]
    fn writer_round_trips_to_disk_and_verifies() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        crate::config::set_test_audit_overrides(Some(true), Some(path.clone()), None);

        record(
            Event::new(EVENT_SECRET_INJECT, DECISION_AUTO_GRANT)
                .keys(["A_KEY".to_string()])
                .exec("/bin/true", vec!["true".to_string()]),
        );
        record(
            Event::new(EVENT_COMMAND_GATE, DECISION_DENIED)
                .message("rm -rf /")
                .reason(Some("nope".to_string())),
        );

        crate::config::clear_test_audit_overrides();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            serde_json::from_str::<serde_json::Value>(line).expect("each line is valid JSON");
        }
        let history = read_history(&path);
        assert!(matches!(
            verify_lines(&history, None),
            VerifyOutcome::Ok { records: 2, .. }
        ));
    }

    #[test]
    fn disabled_writes_nothing() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        crate::config::set_test_audit_overrides(Some(false), Some(path.clone()), None);

        record(Event::new(EVENT_SECRET_INJECT, DECISION_APPROVED).keys(["A_KEY".to_string()]));

        crate::config::clear_test_audit_overrides();
        assert!(!path.exists());
    }

    #[test]
    fn rotation_preserves_chain() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        crate::config::set_test_audit_overrides(Some(true), Some(path.clone()), None);
        // SAFETY: env mutation is serialized by the global test env lock.
        unsafe {
            std::env::set_var("AV_AUDIT_MAX_BYTES", "300");
        }

        for i in 0..20 {
            record(Event::new(EVENT_COMMAND_GATE, DECISION_APPROVED).message(format!("cmd-{i}")));
        }

        unsafe {
            std::env::remove_var("AV_AUDIT_MAX_BYTES");
        }
        crate::config::clear_test_audit_overrides();

        assert!(rotated_path(&path).exists(), "expected a rotated segment");
        let history = read_history(&path);
        assert!(
            matches!(verify_lines(&history, None), VerifyOutcome::Ok { .. }),
            "chain must verify continuously across rotation"
        );
    }

    #[test]
    fn cli_view_and_verify_run_on_seeded_log() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        crate::config::set_test_audit_overrides(Some(true), Some(path.clone()), None);

        record(
            Event::new(EVENT_SECRET_INJECT, DECISION_AUTO_GRANT)
                .keys(["K".to_string()])
                .exec("/bin/true", vec!["true".to_string()]),
        );
        record(
            Event::new(EVENT_COMMAND_CONTAIN, DECISION_OBSERVED)
                .exec("/bin/ls", vec!["ls".to_string()])
                .request_id("agent-1"),
        );

        assert!(run_log_view("av log", &[]).is_ok());
        assert!(
            run_log_view(
                "av log",
                &["-n".to_string(), "1".to_string(), "--json".to_string()]
            )
            .is_ok()
        );
        assert!(
            run_log_view("av log", &["--event".to_string(), "secret.inject".to_string()]).is_ok()
        );
        assert!(run_verify("av audit", &[]).is_ok());
        assert!(run_verify("av audit", &["--json".to_string()]).is_ok());

        crate::config::clear_test_audit_overrides();
    }

    #[test]
    fn flock_is_non_blocking_under_contention() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("audit.lock");
        let open = || {
            OpenOptions::new()
                .create(true)
                .write(true)
                .mode(0o600)
                .open(&lock_path)
                .unwrap()
        };
        let f1 = open();
        let f2 = open();
        let g1 = FlockGuard::try_acquire(&f1);
        assert!(g1.is_some(), "first lock should be acquired");
        // Must return immediately with None rather than block.
        assert!(
            FlockGuard::try_acquire(&f2).is_none(),
            "contended lock must not block; returns None"
        );
        drop(g1);
        assert!(
            FlockGuard::try_acquire(&f2).is_some(),
            "lock is acquirable again after release"
        );
    }

    #[test]
    fn config_file_toggles_enabled_state() {
        let _guard = crate::global_test_env_lock().lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("audit-config.json");
        // enabled override = None so the persisted file decides the state.
        crate::config::set_test_audit_overrides(None, None, Some(cfg.clone()));

        assert!(
            !crate::config::audit_enabled(),
            "default OFF when no config file exists"
        );

        let written = crate::config::set_persisted_audit_enabled(true).unwrap();
        assert_eq!(written, cfg);
        assert!(cfg.exists());
        assert!(
            crate::config::audit_enabled(),
            "enabled after `av audit enable`"
        );

        crate::config::set_persisted_audit_enabled(false).unwrap();
        assert!(
            !crate::config::audit_enabled(),
            "disabled after `av audit disable`"
        );

        crate::config::clear_test_audit_overrides();
    }
}
