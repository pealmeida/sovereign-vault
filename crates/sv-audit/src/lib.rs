//! Append-only JSONL audit log with a tamper-evident hash chain and
//! size-based rotation.
//!
//! Every read, write, delete, approve, or deny operation emits one
//! structured line to a per-vault JSONL file. Each persisted line carries
//! the SHA-256 of the previous line (`prev_sha256`, hex), forming a chain
//! the genesis entry of which references [`GENESIS_PREV`]. The hash of an
//! entry is computed over its canonical JSON bytes *including*
//! `prev_sha256`; verifiers recompute it, so it is not persisted.
//!
//! When appending would exceed [`DEFAULT_MAX_BYTES`] the active file is
//! renamed to a timestamped archive and a fresh active file is started.
//! The chain RESETS to genesis at the start of each new active file, so
//! chain continuity is per-file, not across rotations — each archive is
//! independently verifiable.
//!
//! # Stability
//!
//! Pre-1.0.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fs::OpenOptions;
use std::io::{Read as _, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Audit filename inside the vault root.
pub const AUDIT_FILE: &str = "audit.jsonl";

/// Well-known genesis `prev_sha256` value (64 hex zeros) starting each file.
pub const GENESIS_PREV: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Default rotation threshold in bytes (8 MiB).
pub const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Audit log errors.
#[derive(Debug, Error)]
pub enum AuditError {
    /// Filesystem I/O failure.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    /// JSON encoding failure.
    #[error("Encoding: {0}")]
    Encoding(#[from] serde_json::Error),

    /// Internal lock was poisoned by a panicking writer.
    #[error("audit log lock poisoned")]
    LockPoisoned,
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, AuditError>;

/// High-level action recorded in the audit stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Vault bootstrapped.
    VaultInit,
    /// Vault unlocked.
    VaultUnlock,
    /// Vault unlocked via recovery phrase.
    VaultUnlockRecovery,
    /// Vault locked.
    VaultLock,
    /// Recovery phrase issued.
    RecoveryIssued,
    /// Vault passphrase changed (KEK re-derived, DEK re-wrapped).
    PassphraseChanged,
    /// Data-encryption key rotated.
    KeyRotated,
    /// List all containers.
    ListContainers,
    /// List files inside a container.
    ListFiles,
    /// Read a file.
    ReadFile,
    /// Write a file.
    WriteFile,
    /// Delete a file.
    DeleteFile,
    /// Create a container.
    CreateContainer,
    /// Delete a container.
    DeleteContainer,
}

/// Final outcome for an audited action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    /// Operation was allowed and completed successfully.
    Allowed,
    /// Operation was explicitly denied.
    Denied,
    /// Operation failed after being attempted.
    Error,
}

/// One line in the append-only audit stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Timestamp when the event was recorded.
    pub timestamp: DateTime<Utc>,
    /// Action being recorded.
    pub action: AuditAction,
    /// Final decision for the action.
    pub decision: AuditDecision,
    /// Transport or origin, for example `desktop-ui` or `mcp-ws`.
    pub transport: String,
    /// Container involved in the action, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// File involved in the action, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    /// Effective mode used to make the decision, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Byte size involved in the operation, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_size: Option<usize>,
    /// Human-readable detail such as "approved via desktop modal".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Error message for failed operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AuditEvent {
    /// Build a new audit event with the current timestamp.
    pub fn new(action: AuditAction, decision: AuditDecision, transport: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            action,
            decision,
            transport: transport.into(),
            container: None,
            file_name: None,
            mode: None,
            byte_size: None,
            detail: None,
            error: None,
        }
    }
}

/// Persisted form of an [`AuditEvent`]: the event flattened together with
/// the chain link `prev_sha256`. The entry's own hash is recomputed by
/// verifiers over these canonical bytes and is not stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditRecord {
    prev_sha256: String,
    #[serde(flatten)]
    event: AuditEvent,
}

/// Outcome of [`AuditLog::verify_chain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Whether every link in the active file is intact.
    pub ok: bool,
    /// Number of entries scanned.
    pub entries: usize,
    /// Number of legacy lines (pre-chain, lacking `prev_sha256`).
    pub legacy_entries: usize,
    /// Zero-based index of the first broken link, when `ok` is false.
    pub first_broken: Option<usize>,
    /// Human-readable reason for the first break, when `ok` is false.
    pub reason: Option<String>,
}

/// Compute the lowercase-hex SHA-256 of the canonical JSON for a record.
fn hash_record(prev: &str, event: &AuditEvent) -> Result<String> {
    let rec = AuditRecord {
        prev_sha256: prev.to_string(),
        event: event.clone(),
    };
    let bytes = serde_json::to_vec(&rec)?;
    Ok(hex_sha256(&bytes))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Read the last non-empty line of a file by tailing from the end without
/// loading the whole file into memory.
fn read_last_line(path: &Path) -> Result<Option<String>> {
    let mut file = match OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let len = file.seek(SeekFrom::End(0))?;
    if len == 0 {
        return Ok(None);
    }
    let mut buf: Vec<u8> = Vec::new();
    let chunk = 4096u64;
    let mut pos = len;
    // Walk backwards in chunks until we find a newline preceding content.
    loop {
        let read_size = chunk.min(pos);
        pos -= read_size;
        file.seek(SeekFrom::Start(pos))?;
        let mut tmp = vec![0u8; read_size as usize];
        file.read_exact(&mut tmp)?;
        tmp.extend_from_slice(&buf);
        buf = tmp;
        // Trim a single trailing newline so a final "\n" is not a "line".
        while buf.last() == Some(&b'\n') || buf.last() == Some(&b'\r') {
            buf.pop();
        }
        if let Some(idx) = buf.iter().rposition(|&b| b == b'\n') {
            let line = &buf[idx + 1..];
            return Ok(Some(String::from_utf8_lossy(line).into_owned()));
        }
        if pos == 0 {
            return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
        }
    }
}

/// Append-only JSONL writer with a per-file SHA-256 hash chain.
pub struct AuditLog {
    path: PathBuf,
    max_bytes: u64,
    head: Mutex<String>,
}

impl AuditLog {
    /// Build an audit log rooted at the given vault path using the default
    /// rotation threshold. If the active file already exists, the chain
    /// head is recovered from its last line.
    pub fn new(root: &Path) -> Self {
        Self::with_max_bytes(root, DEFAULT_MAX_BYTES)
    }

    /// Like [`AuditLog::new`] but with a custom rotation threshold (bytes).
    pub fn with_max_bytes(root: &Path, max_bytes: u64) -> Self {
        let path = root.join(AUDIT_FILE);
        let head = recover_head(&path);
        Self {
            path,
            max_bytes,
            head: Mutex::new(head),
        }
    }

    /// Path to the active log file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one event and flush it durably, chaining it to the prior line.
    pub fn record(&self, event: &AuditEvent) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut head = self.head.lock().map_err(|_| AuditError::LockPoisoned)?;

        // Rotate before writing if the active file would grow too large.
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if meta.len() >= self.max_bytes {
                self.rotate()?;
                *head = GENESIS_PREV.to_string();
            }
        }

        let rec = AuditRecord {
            prev_sha256: head.clone(),
            event: event.clone(),
        };
        let bytes = serde_json::to_vec(&rec)?;
        let this = hex_sha256(&bytes);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;

        *head = this;
        Ok(())
    }

    /// Rename the active file to a timestamped archive alongside it.
    fn rotate(&self) -> Result<()> {
        let stamp = Utc::now().format("%Y%m%dT%H%M%S%.6fZ").to_string();
        let archive = self.path.with_file_name(format!("audit-{stamp}.jsonl"));
        std::fs::rename(&self.path, &archive)?;
        Ok(())
    }

    /// Walk the active file start-to-end, recomputing each link, and report
    /// the first broken or missing link. Chain continuity is per-file.
    pub fn verify_chain(&self) -> Result<VerifyReport> {
        let raw = match std::fs::read_to_string(&self.path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(VerifyReport {
                    ok: true,
                    entries: 0,
                    legacy_entries: 0,
                    first_broken: None,
                    reason: None,
                });
            }
            Err(e) => return Err(e.into()),
        };

        let mut expected_prev = GENESIS_PREV.to_string();
        let mut entries = 0usize;
        let mut legacy_entries = 0usize;

        for (idx, line) in raw.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let rec: AuditRecord = match serde_json::from_str(line) {
                Ok(r) => r,
                Err(_) => {
                    // Legacy line without prev_sha256: report, don't crash.
                    if serde_json::from_str::<AuditEvent>(line).is_ok() {
                        legacy_entries += 1;
                        continue;
                    }
                    return Ok(VerifyReport {
                        ok: false,
                        entries,
                        legacy_entries,
                        first_broken: Some(idx),
                        reason: Some("malformed JSON line".into()),
                    });
                }
            };
            entries += 1;

            if rec.prev_sha256 != expected_prev {
                return Ok(VerifyReport {
                    ok: false,
                    entries,
                    legacy_entries,
                    first_broken: Some(idx),
                    reason: Some(format!(
                        "prev_sha256 mismatch: expected {expected_prev}, found {}",
                        rec.prev_sha256
                    )),
                });
            }
            expected_prev = hash_record(&rec.prev_sha256, &rec.event)?;
        }

        Ok(VerifyReport {
            ok: true,
            entries,
            legacy_entries,
            first_broken: None,
            reason: None,
        })
    }
}

/// Recover the chain head from an existing active file (the hash of its
/// last line), or [`GENESIS_PREV`] when missing/empty.
fn recover_head(path: &Path) -> String {
    match read_last_line(path) {
        Ok(Some(line)) => match serde_json::from_str::<AuditRecord>(&line) {
            Ok(rec) => hash_record(&rec.prev_sha256, &rec.event).unwrap_or_else(|_| GENESIS_PREV.to_string()),
            // Legacy last line without prev_sha256: treat head as genesis.
            Err(_) => GENESIS_PREV.to_string(),
        },
        _ => GENESIS_PREV.to_string(),
    }
}

/// Crate version string.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tmp_dir(label: &str) -> PathBuf {
        let mut p = env::temp_dir();
        p.push(format!("sv-audit-test-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn appends_jsonl_lines() {
        let root = tmp_dir("jsonl");
        std::fs::create_dir_all(&root).unwrap();
        let log = AuditLog::new(&root);

        log.record(&AuditEvent::new(
            AuditAction::ReadFile,
            AuditDecision::Allowed,
            "desktop-ui",
        ))
        .unwrap();
        log.record(&AuditEvent::new(
            AuditAction::DeleteFile,
            AuditDecision::Denied,
            "mcp-ws",
        ))
        .unwrap();

        let raw = std::fs::read_to_string(log.path()).unwrap();
        let lines: Vec<_> = raw.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        let second: AuditEvent = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(first.action, AuditAction::ReadFile);
        assert_eq!(second.decision, AuditDecision::Denied);

        let _ = std::fs::remove_dir_all(&root);
    }

    fn ev(action: AuditAction) -> AuditEvent {
        AuditEvent::new(action, AuditDecision::Allowed, "test")
    }

    #[test]
    fn genesis_prev_and_chaining() {
        let root = tmp_dir("chain");
        std::fs::create_dir_all(&root).unwrap();
        let log = AuditLog::new(&root);
        log.record(&ev(AuditAction::ReadFile)).unwrap();
        log.record(&ev(AuditAction::WriteFile)).unwrap();

        let raw = std::fs::read_to_string(log.path()).unwrap();
        let lines: Vec<_> = raw.lines().collect();
        let r0: AuditRecord = serde_json::from_str(lines[0]).unwrap();
        let r1: AuditRecord = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(r0.prev_sha256, GENESIS_PREV);
        // line1.prev == hash(line0)
        let h0 = hash_record(&r0.prev_sha256, &r0.event).unwrap();
        assert_eq!(r1.prev_sha256, h0);

        let report = log.verify_chain().unwrap();
        assert!(report.ok);
        assert_eq!(report.entries, 2);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn head_recovered_on_reopen() {
        let root = tmp_dir("reopen");
        std::fs::create_dir_all(&root).unwrap();
        {
            let log = AuditLog::new(&root);
            log.record(&ev(AuditAction::ReadFile)).unwrap();
        }
        // Reopen and append; chain must remain valid.
        let log = AuditLog::new(&root);
        log.record(&ev(AuditAction::WriteFile)).unwrap();
        let report = log.verify_chain().unwrap();
        assert!(report.ok, "{report:?}");
        assert_eq!(report.entries, 2);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn tampering_is_detected() {
        let root = tmp_dir("tamper");
        std::fs::create_dir_all(&root).unwrap();
        let log = AuditLog::new(&root);
        log.record(&ev(AuditAction::ReadFile)).unwrap();
        log.record(&ev(AuditAction::WriteFile)).unwrap();
        log.record(&ev(AuditAction::DeleteFile)).unwrap();

        let raw = std::fs::read_to_string(log.path()).unwrap();
        let mut lines: Vec<String> = raw.lines().map(String::from).collect();
        // Tamper with the second line's transport.
        lines[1] = lines[1].replace("\"test\"", "\"evil\"");
        std::fs::write(log.path(), lines.join("\n") + "\n").unwrap();

        let report = log.verify_chain().unwrap();
        assert!(!report.ok);
        assert_eq!(report.first_broken, Some(2));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn deletion_is_detected() {
        let root = tmp_dir("delete");
        std::fs::create_dir_all(&root).unwrap();
        let log = AuditLog::new(&root);
        for _ in 0..3 {
            log.record(&ev(AuditAction::ReadFile)).unwrap();
        }
        let raw = std::fs::read_to_string(log.path()).unwrap();
        let mut lines: Vec<String> = raw.lines().map(String::from).collect();
        lines.remove(1); // drop a middle line
        std::fs::write(log.path(), lines.join("\n") + "\n").unwrap();

        let report = log.verify_chain().unwrap();
        assert!(!report.ok);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rotation_resets_chain_per_file() {
        let root = tmp_dir("rotate");
        std::fs::create_dir_all(&root).unwrap();
        // Tiny threshold forces rotation after the first line.
        let log = AuditLog::with_max_bytes(&root, 64);
        log.record(&ev(AuditAction::ReadFile)).unwrap();
        log.record(&ev(AuditAction::WriteFile)).unwrap();
        log.record(&ev(AuditAction::DeleteFile)).unwrap();

        // An archive file must now exist.
        let archives: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                n.starts_with("audit-") && n.ends_with(".jsonl")
            })
            .collect();
        assert!(!archives.is_empty(), "expected at least one archive");

        // Active file starts a fresh chain at genesis and verifies.
        let raw = std::fs::read_to_string(log.path()).unwrap();
        let first: AuditRecord = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(first.prev_sha256, GENESIS_PREV);
        assert!(log.verify_chain().unwrap().ok);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn legacy_lines_do_not_panic() {
        let root = tmp_dir("legacy");
        std::fs::create_dir_all(&root).unwrap();
        let log = AuditLog::new(&root);
        // Write an old-style line lacking prev_sha256.
        let legacy = serde_json::to_string(&ev(AuditAction::ReadFile)).unwrap();
        std::fs::write(log.path(), legacy + "\n").unwrap();

        let report = log.verify_chain().unwrap();
        assert!(report.ok);
        assert_eq!(report.legacy_entries, 1);

        let _ = std::fs::remove_dir_all(&root);
    }
}
