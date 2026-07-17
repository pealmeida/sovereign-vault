//! Authenticated, append-only audit log with durable checkpoints and rotation.
//!
//! Every record is authenticated with HMAC-SHA256 using caller-supplied key
//! material. Records form one sequence and MAC chain across all rotated
//! segments. An independently authenticated checkpoint commits the expected
//! record count, head MAC, and active segment, allowing verification to detect
//! edits, truncation, and missing active or archive files.
//!
//! This format intentionally does not accept the earlier unauthenticated JSONL
//! format. Callers must explicitly create a new authenticated log or open an
//! existing one; missing or malformed state is never treated as a new chain.
//!
//! The checkpoint is stored beside the log. It detects selective modification
//! or deletion relative to that checkpoint, but it cannot detect rollback of a
//! complete, mutually consistent audit directory snapshot. Detecting full
//! snapshot rollback requires anchoring the checkpoint head in external trusted
//! storage such as an OS keychain or remote transparency service.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Audit filename inside the vault root.
pub const AUDIT_FILE: &str = "audit.jsonl";

/// Authenticated checkpoint filename inside the vault root.
pub const CHECKPOINT_FILE: &str = "audit.head.json";

/// Well-known genesis chain value (32 zero bytes encoded as lowercase hex).
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Default configured rotation ceiling in bytes (8 MiB).
///
/// The mutable active segment may rotate earlier to keep append-time
/// authentication work bounded.
pub const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024;

const FORMAT_VERSION: u8 = 2;
const RECORD_DOMAIN: &[u8] = b"sovereign-vault/audit-record/v2\0";
const CHECKPOINT_DOMAIN: &[u8] = b"sovereign-vault/audit-checkpoint/v2\0";
const REDACTION_DOMAIN: &[u8] = b"sovereign-vault/audit-redaction/v2\0";
const LOCK_FILE: &str = ".audit-write.lock";
const ARCHIVE_PREFIX: &str = "audit-";
const ARCHIVE_SUFFIX: &str = ".jsonl";
const ARCHIVE_DIGITS: usize = 20;
const MAX_TEMP_ATTEMPTS: usize = 32;
// Bound append-time verification work. Historical segments are immutable and
// are scanned only on open or explicit full verification.
const MAX_ACTIVE_VERIFY_BYTES: u64 = 256 * 1024;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Audit log errors.
#[derive(Debug, Error)]
pub enum AuditError {
    /// Filesystem I/O failure.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    /// JSON encoding failure.
    #[error("Encoding: {0}")]
    Encoding(#[from] serde_json::Error),

    /// Authenticated audit state is missing.
    #[error("audit state is not initialized: {0}")]
    NotInitialized(String),

    /// Audit state already exists and must not be replaced implicitly.
    #[error("audit state already exists: {0}")]
    AlreadyExists(String),

    /// A checkpoint or record authentication tag is invalid.
    #[error("audit authentication failed: {0}")]
    Authentication(String),

    /// Authenticated state is structurally inconsistent or incomplete.
    #[error("audit integrity check failed: {0}")]
    Integrity(String),

    /// Another writer owns the cross-instance audit lock.
    #[error("audit log is busy; another writer may be active")]
    Busy,

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
    /// Create an agent identity.
    AgentCreate,
    /// List agent identities.
    AgentList,
    /// Revoke an agent identity.
    AgentRevoke,
    /// Create a transit key.
    CreateTransitKey,
    /// List transit keys.
    ListTransitKeys,
    /// Encrypt with a transit key.
    Encrypt,
    /// Decrypt with a transit key.
    Decrypt,
    /// Create a signing key.
    CreateSigningKey,
    /// List signing keys.
    ListSigningKeys,
    /// Sign with a signing key.
    Sign,
    /// Verify a signature.
    Verify,
    /// Create a brokered secret.
    CreateBrokerSecret,
    /// List brokered secrets.
    ListBrokerSecrets,
    /// Broker an outbound request with a stored secret.
    Broker,
    /// Query vault metadata (version, custody mode, container count).
    VaultInfo,
}

/// Final outcome for an audited action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    /// Durable intent recorded before a security-sensitive operation begins.
    Attempted,
    /// Operation was allowed and completed successfully.
    Allowed,
    /// Operation was explicitly denied.
    Denied,
    /// Operation failed after being attempted.
    Error,
}

/// One event in the authenticated audit stream.
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
    /// Identity of the agent that originated the action, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
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
            agent_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct RecordPayload<'a> {
    format_version: u8,
    sequence: u64,
    prev_mac: &'a str,
    event: &'a AuditEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditRecord {
    format_version: u8,
    sequence: u64,
    prev_mac: String,
    event: AuditEvent,
    mac: String,
}

#[derive(Debug, Clone, Serialize)]
struct CheckpointPayload<'a> {
    format_version: u8,
    record_count: u64,
    head_mac: &'a str,
    active_segment: u64,
    active_record_count: u64,
    active_start_prev_mac: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    format_version: u8,
    record_count: u64,
    head_mac: String,
    active_segment: u64,
    active_record_count: u64,
    active_start_prev_mac: String,
    mac: String,
}

impl Checkpoint {
    fn genesis(key: &[u8; 32]) -> Result<Self> {
        Self::signed(
            0,
            GENESIS_PREV.to_string(),
            0,
            0,
            GENESIS_PREV.to_string(),
            key,
        )
    }

    fn signed(
        record_count: u64,
        head_mac: String,
        active_segment: u64,
        active_record_count: u64,
        active_start_prev_mac: String,
        key: &[u8; 32],
    ) -> Result<Self> {
        let payload = CheckpointPayload {
            format_version: FORMAT_VERSION,
            record_count,
            head_mac: &head_mac,
            active_segment,
            active_record_count,
            active_start_prev_mac: &active_start_prev_mac,
        };
        let bytes = serde_json::to_vec(&payload)?;
        let mac = authenticate_hex(key, CHECKPOINT_DOMAIN, &bytes);
        Ok(Self {
            format_version: FORMAT_VERSION,
            record_count,
            head_mac,
            active_segment,
            active_record_count,
            active_start_prev_mac,
            mac,
        })
    }

    fn verify(&self, key: &[u8; 32]) -> Result<()> {
        if self.format_version != FORMAT_VERSION {
            return Err(AuditError::Integrity(format!(
                "unsupported checkpoint format version {}",
                self.format_version
            )));
        }
        validate_mac_string(&self.head_mac, "checkpoint head")?;
        validate_mac_string(&self.active_start_prev_mac, "active segment starting MAC")?;
        let payload = CheckpointPayload {
            format_version: self.format_version,
            record_count: self.record_count,
            head_mac: &self.head_mac,
            active_segment: self.active_segment,
            active_record_count: self.active_record_count,
            active_start_prev_mac: &self.active_start_prev_mac,
        };
        let bytes = serde_json::to_vec(&payload)?;
        verify_hex_tag(key, CHECKPOINT_DOMAIN, &bytes, &self.mac)
            .map_err(|_| AuditError::Authentication("checkpoint MAC does not verify".into()))?;
        if self.active_record_count > self.record_count {
            return Err(AuditError::Integrity(
                "active record count exceeds total record count".into(),
            ));
        }
        Ok(())
    }
}

/// Outcome of [`AuditLog::verify_chain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Whether all expected segments, records, and checkpoint fields agree.
    pub ok: bool,
    /// Number of authenticated entries scanned across archives and active log.
    pub entries: usize,
    /// Number of rejected legacy/unauthenticated entries encountered.
    pub legacy_entries: usize,
    /// Global zero-based sequence of the first broken record, when applicable.
    pub first_broken: Option<usize>,
    /// Human-readable reason for the first integrity failure.
    pub reason: Option<String>,
}

impl VerifyReport {
    fn success(entries: usize) -> Self {
        Self {
            ok: true,
            entries,
            legacy_entries: 0,
            first_broken: None,
            reason: None,
        }
    }

    fn failure(entries: usize, legacy_entries: usize, reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            entries,
            legacy_entries,
            first_broken: Some(entries),
            reason: Some(reason.into()),
        }
    }
}

struct ScannedChain {
    entries: u64,
    head_mac: String,
}

enum ScanResult {
    Valid(ScannedChain),
    Invalid(VerifyReport),
}

/// Authenticated audit log bound to one vault directory and one secret key.
pub struct AuditLog {
    root: PathBuf,
    path: PathBuf,
    checkpoint_path: PathBuf,
    max_bytes: u64,
    key: [u8; 32],
    operation: Mutex<()>,
}

impl Drop for AuditLog {
    fn drop(&mut self) {
        self.key.fill(0);
    }
}

impl AuditLog {
    /// Create a new authenticated audit log.
    ///
    /// This refuses to replace any active log, checkpoint, or rotated archive.
    /// Use [`AuditLog::open`] for existing state.
    /// `authentication_key` must be a dedicated stable audit key that remains
    /// unchanged across data-encryption-key rotation.
    pub fn create(root: &Path, authentication_key: [u8; 32]) -> Result<Self> {
        Self::create_with_max_bytes(root, authentication_key, DEFAULT_MAX_BYTES)
    }

    /// Create a new authenticated audit log with a custom rotation threshold.
    pub fn create_with_max_bytes(
        root: &Path,
        authentication_key: [u8; 32],
        max_bytes: u64,
    ) -> Result<Self> {
        ensure_root(root, true)?;
        let log = Self::build(root, authentication_key, max_bytes);
        let _lock = AuditWriteLock::acquire(root)?;
        let archives = archive_segments(root)?;
        if !archives.is_empty() || fs::symlink_metadata(&log.checkpoint_path).is_ok() {
            let path = first_audit_artifact(root)?.unwrap_or_else(|| root.to_path_buf());
            return Err(AuditError::AlreadyExists(path.display().to_string()));
        }
        match fs::symlink_metadata(&log.path) {
            Ok(metadata) => {
                ensure_regular_metadata(&log.path, &metadata, "active audit log")?;
                if metadata.len() != 0 {
                    return Err(AuditError::AlreadyExists(log.path.display().to_string()));
                }
                // Creation writes the empty active file before its checkpoint.
                // Retrying this exact empty/genesis partial state is safe.
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                atomic_replace(&log.path, b"")?;
            }
            Err(error) => return Err(error.into()),
        }
        let checkpoint = Checkpoint::genesis(&log.key)?;
        log.write_checkpoint(&checkpoint)?;
        Ok(log)
    }

    /// Open and fully verify an existing authenticated audit log.
    ///
    /// The supplied key must be the same stable audit key used at creation.
    pub fn open(root: &Path, authentication_key: [u8; 32]) -> Result<Self> {
        Self::open_with_max_bytes(root, authentication_key, DEFAULT_MAX_BYTES)
    }

    /// Open and verify an existing log with a custom future rotation threshold.
    pub fn open_with_max_bytes(
        root: &Path,
        authentication_key: [u8; 32],
        max_bytes: u64,
    ) -> Result<Self> {
        ensure_root(root, false)?;
        let log = Self::build(root, authentication_key, max_bytes);
        let _lock = AuditWriteLock::acquire(root)?;
        let checkpoint = log.load_checkpoint()?;
        let archive_report = log.verify_committed_archives(&checkpoint)?;
        if !archive_report.ok {
            return Err(AuditError::Integrity(
                archive_report
                    .reason
                    .unwrap_or_else(|| "archive verification failed".into()),
            ));
        }
        log.recover_interrupted_commit()?;
        let report = log.verify_locked()?;
        if !report.ok {
            return Err(AuditError::Integrity(
                report
                    .reason
                    .unwrap_or_else(|| "verification failed".into()),
            ));
        }
        Ok(log)
    }

    /// Compatibility alias for [`AuditLog::open`].
    ///
    /// The key now authenticates complete records and checkpoints in addition
    /// to redacting sensitive path fields. This method never creates state.
    pub fn with_hmac_key(root: &Path, authentication_key: [u8; 32]) -> Result<Self> {
        Self::open(root, authentication_key)
    }

    fn build(root: &Path, key: [u8; 32], max_bytes: u64) -> Self {
        Self {
            root: root.to_path_buf(),
            path: root.join(AUDIT_FILE),
            checkpoint_path: root.join(CHECKPOINT_FILE),
            max_bytes,
            key,
            operation: Mutex::new(()),
        }
    }

    /// Path to the active log file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Keyed, domain-separated HMAC-SHA256 of a sensitive field value.
    ///
    /// The `Option` return is retained for source compatibility and is always
    /// `Some` for authenticated logs.
    pub fn hmac_value(&self, plaintext: &str) -> Option<String> {
        Some(authenticate_hex(
            &self.key,
            REDACTION_DOMAIN,
            plaintext.as_bytes(),
        ))
    }

    fn redact(&self, event: &AuditEvent) -> AuditEvent {
        let mut event = event.clone();
        event.container = event
            .container
            .as_deref()
            .and_then(|value| self.hmac_value(value));
        event.file_name = event
            .file_name
            .as_deref()
            .and_then(|value| self.hmac_value(value));
        event
    }

    /// Append one authenticated event and durably advance the checkpoint.
    ///
    /// Before writing, the mutable active segment and checkpoint are reverified
    /// under the cross-instance write lock. Existing archives are fully checked
    /// on open and by [`AuditLog::verify_chain`].
    pub fn record(&self, event: &AuditEvent) -> Result<()> {
        let _operation = self
            .operation
            .lock()
            .map_err(|_| AuditError::LockPoisoned)?;
        let _file_lock = AuditWriteLock::acquire(&self.root)?;

        let active_verified = self.recover_interrupted_commit()?;
        let mut checkpoint = self.load_checkpoint()?;
        if !active_verified {
            let report = self.verify_active_against(&checkpoint)?;
            if !report.ok {
                return Err(AuditError::Integrity(
                    report
                        .reason
                        .unwrap_or_else(|| "verification failed".into()),
                ));
            }
        }

        let redacted = self.redact(event);
        let mut record = sign_record(
            checkpoint.record_count,
            &checkpoint.head_mac,
            redacted,
            &self.key,
        )?;
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        if line.len() as u64 > MAX_ACTIVE_VERIFY_BYTES {
            return Err(AuditError::Integrity(format!(
                "audit record exceeds the {} byte limit",
                MAX_ACTIVE_VERIFY_BYTES
            )));
        }

        let active_len = regular_file_len(&self.path, "active audit log")?;
        let active_limit = self.max_bytes.min(MAX_ACTIVE_VERIFY_BYTES);
        if active_len > 0 && active_len.saturating_add(line.len() as u64) > active_limit {
            self.rotate(&mut checkpoint)?;
            record = sign_record(
                checkpoint.record_count,
                &checkpoint.head_mac,
                record.event,
                &self.key,
            )?;
            line = serde_json::to_vec(&record)?;
            line.push(b'\n');
        }

        let mut active = OpenOptions::new().append(true).open(&self.path)?;
        active.write_all(&line)?;
        active.sync_all()?;

        checkpoint = Checkpoint::signed(
            checkpoint
                .record_count
                .checked_add(1)
                .ok_or_else(|| AuditError::Integrity("record sequence overflow".into()))?,
            record.mac,
            checkpoint.active_segment,
            checkpoint
                .active_record_count
                .checked_add(1)
                .ok_or_else(|| AuditError::Integrity("active record count overflow".into()))?,
            checkpoint.active_start_prev_mac,
            &self.key,
        )?;
        self.write_checkpoint(&checkpoint)
    }

    fn rotate(&self, checkpoint: &mut Checkpoint) -> Result<()> {
        let archive = self.root.join(archive_name(checkpoint.active_segment));
        if fs::symlink_metadata(&archive).is_ok() {
            return Err(AuditError::Integrity(format!(
                "rotation destination already exists: {}",
                archive.display()
            )));
        }
        ensure_regular_file(&self.path, "active audit log")?;
        fs::rename(&self.path, &archive)?;
        sync_directory(&self.root)?;
        atomic_replace(&self.path, b"")?;

        *checkpoint = Checkpoint::signed(
            checkpoint.record_count,
            checkpoint.head_mac.clone(),
            checkpoint
                .active_segment
                .checked_add(1)
                .ok_or_else(|| AuditError::Integrity("segment sequence overflow".into()))?,
            0,
            checkpoint.head_mac.clone(),
            &self.key,
        )?;
        self.write_checkpoint(checkpoint)
    }

    /// Verify every expected archive and the active file against the durable
    /// authenticated checkpoint.
    pub fn verify_chain(&self) -> Result<VerifyReport> {
        let _operation = self
            .operation
            .lock()
            .map_err(|_| AuditError::LockPoisoned)?;
        let _file_lock = AuditWriteLock::acquire(&self.root)?;
        self.verify_locked()
    }

    fn verify_locked(&self) -> Result<VerifyReport> {
        let checkpoint = self.load_checkpoint()?;
        self.verify_against(&checkpoint)
    }

    fn verify_against(&self, checkpoint: &Checkpoint) -> Result<VerifyReport> {
        let archives = match archive_segments(&self.root) {
            Ok(segments) => segments,
            Err(error) => return Ok(VerifyReport::failure(0, 0, error.to_string())),
        };
        let expected_archives: BTreeSet<u64> = (0..checkpoint.active_segment).collect();
        if archives != expected_archives {
            return Ok(VerifyReport::failure(
                0,
                0,
                format!("archive set mismatch: expected {expected_archives:?}, found {archives:?}"),
            ));
        }
        if let Err(error) = ensure_regular_file(&self.path, "active audit log") {
            return Ok(VerifyReport::failure(0, 0, error.to_string()));
        }

        let archive_paths: Vec<_> = (0..checkpoint.active_segment)
            .map(|segment| self.root.join(archive_name(segment)))
            .collect();
        let archived = match self.scan_paths(&archive_paths)? {
            ScanResult::Valid(scanned) => scanned,
            ScanResult::Invalid(report) => return Ok(report),
        };
        let expected_archive_records = checkpoint
            .record_count
            .checked_sub(checkpoint.active_record_count)
            .ok_or_else(|| AuditError::Integrity("invalid active record count".into()))?;
        if archived.entries != expected_archive_records
            || archived.head_mac != checkpoint.active_start_prev_mac
        {
            return Ok(VerifyReport::failure(
                archived.entries as usize,
                0,
                "active segment boundary does not match checkpoint",
            ));
        }

        let scanned = match self.scan_paths_from(
            std::slice::from_ref(&self.path),
            archived.entries,
            archived.head_mac,
        )? {
            ScanResult::Valid(scanned) => scanned,
            ScanResult::Invalid(report) => return Ok(report),
        };

        if scanned.entries != checkpoint.record_count {
            return Ok(VerifyReport::failure(
                scanned.entries as usize,
                0,
                format!(
                    "checkpoint record count mismatch: expected {}, found {}",
                    checkpoint.record_count, scanned.entries
                ),
            ));
        }
        if scanned.head_mac != checkpoint.head_mac {
            return Ok(VerifyReport::failure(
                scanned.entries as usize,
                0,
                "checkpoint head MAC mismatch",
            ));
        }
        Ok(VerifyReport::success(scanned.entries as usize))
    }

    fn verify_active_against(&self, checkpoint: &Checkpoint) -> Result<VerifyReport> {
        if let Err(error) = ensure_regular_file(&self.path, "active audit log") {
            return Ok(VerifyReport::failure(0, 0, error.to_string()));
        }
        let start_sequence = checkpoint
            .record_count
            .checked_sub(checkpoint.active_record_count)
            .ok_or_else(|| AuditError::Integrity("invalid active record count".into()))?;
        let scanned = match self.scan_paths_from(
            std::slice::from_ref(&self.path),
            start_sequence,
            checkpoint.active_start_prev_mac.clone(),
        )? {
            ScanResult::Valid(scanned) => scanned,
            ScanResult::Invalid(report) => return Ok(report),
        };
        if scanned.entries != checkpoint.record_count || scanned.head_mac != checkpoint.head_mac {
            return Ok(VerifyReport::failure(
                scanned.entries as usize,
                0,
                "active segment does not match checkpoint",
            ));
        }
        Ok(VerifyReport::success(checkpoint.record_count as usize))
    }

    fn verify_committed_archives(&self, checkpoint: &Checkpoint) -> Result<VerifyReport> {
        let archives = archive_segments(&self.root)?;
        let expected: BTreeSet<u64> = (0..checkpoint.active_segment).collect();
        let interrupted_rotation: BTreeSet<u64> = (0..=checkpoint.active_segment).collect();
        if archives != expected && archives != interrupted_rotation {
            return Ok(VerifyReport::failure(
                0,
                0,
                format!(
                    "committed archive set mismatch: expected {expected:?}, found {archives:?}"
                ),
            ));
        }
        let paths: Vec<_> = (0..checkpoint.active_segment)
            .map(|segment| self.root.join(archive_name(segment)))
            .collect();
        let scanned = match self.scan_paths(&paths)? {
            ScanResult::Valid(scanned) => scanned,
            ScanResult::Invalid(report) => return Ok(report),
        };
        let expected_entries = checkpoint
            .record_count
            .checked_sub(checkpoint.active_record_count)
            .ok_or_else(|| AuditError::Integrity("invalid active record count".into()))?;
        if scanned.entries != expected_entries
            || scanned.head_mac != checkpoint.active_start_prev_mac
        {
            return Ok(VerifyReport::failure(
                scanned.entries as usize,
                0,
                "committed archive boundary does not match checkpoint",
            ));
        }
        Ok(VerifyReport::success(scanned.entries as usize))
    }

    fn scan_paths(&self, paths: &[PathBuf]) -> Result<ScanResult> {
        self.scan_paths_from(paths, 0, GENESIS_PREV.to_string())
    }

    fn scan_paths_from(
        &self,
        paths: &[PathBuf],
        mut expected_sequence: u64,
        mut expected_prev: String,
    ) -> Result<ScanResult> {
        for path in paths {
            ensure_regular_file(path, "audit segment")?;
            let raw = fs::read(path)?;
            if !raw.is_empty() && !raw.ends_with(b"\n") {
                return Ok(ScanResult::Invalid(VerifyReport::failure(
                    expected_sequence as usize,
                    0,
                    format!("segment has an incomplete final record: {}", path.display()),
                )));
            }
            let text = match std::str::from_utf8(&raw) {
                Ok(text) => text,
                Err(_) => {
                    return Ok(ScanResult::Invalid(VerifyReport::failure(
                        expected_sequence as usize,
                        0,
                        format!("segment is not valid UTF-8: {}", path.display()),
                    )));
                }
            };
            for line in text.lines() {
                if line.is_empty() {
                    return Ok(ScanResult::Invalid(VerifyReport::failure(
                        expected_sequence as usize,
                        0,
                        "blank audit record",
                    )));
                }
                let record: AuditRecord = match serde_json::from_str(line) {
                    Ok(record) => record,
                    Err(_) => {
                        let legacy = serde_json::from_str::<serde_json::Value>(line).is_ok();
                        return Ok(ScanResult::Invalid(VerifyReport::failure(
                            expected_sequence as usize,
                            usize::from(legacy),
                            if legacy {
                                "legacy or unauthenticated audit record is not accepted"
                            } else {
                                "malformed audit record"
                            },
                        )));
                    }
                };
                if let Err(reason) =
                    verify_record(&record, expected_sequence, &expected_prev, &self.key)
                {
                    return Ok(ScanResult::Invalid(VerifyReport::failure(
                        expected_sequence as usize,
                        0,
                        reason,
                    )));
                }
                expected_prev = record.mac;
                expected_sequence = expected_sequence
                    .checked_add(1)
                    .ok_or_else(|| AuditError::Integrity("record sequence overflow".into()))?;
            }
        }
        Ok(ScanResult::Valid(ScannedChain {
            entries: expected_sequence,
            head_mac: expected_prev,
        }))
    }

    fn recover_interrupted_commit(&self) -> Result<bool> {
        let mut checkpoint = self.load_checkpoint()?;
        let start_sequence = checkpoint
            .record_count
            .checked_sub(checkpoint.active_record_count)
            .ok_or_else(|| AuditError::Integrity("invalid active record count".into()))?;
        if ensure_regular_file(&self.path, "active audit log").is_ok() {
            if let ScanResult::Valid(scanned) = self.scan_paths_from(
                std::slice::from_ref(&self.path),
                start_sequence,
                checkpoint.active_start_prev_mac.clone(),
            )? {
                if scanned.entries == checkpoint.record_count
                    && scanned.head_mac == checkpoint.head_mac
                {
                    return Ok(true);
                }
                if scanned.entries == checkpoint.record_count.saturating_add(1)
                    && scanned.head_mac != checkpoint.head_mac
                {
                    // Appending and syncing the record precedes its checkpoint.
                    // Exactly one valid successor proves an interrupted commit.
                    checkpoint = Checkpoint::signed(
                        scanned.entries,
                        scanned.head_mac,
                        checkpoint.active_segment,
                        checkpoint
                            .active_record_count
                            .checked_add(1)
                            .ok_or_else(|| {
                                AuditError::Integrity("active record count overflow".into())
                            })?,
                        checkpoint.active_start_prev_mac,
                        &self.key,
                    )?;
                    self.write_checkpoint(&checkpoint)?;
                    return Ok(true);
                }
            }
        }

        let archives = archive_segments(&self.root)?;
        let interrupted_rotation: BTreeSet<u64> = (0..=checkpoint.active_segment).collect();
        if archives != interrupted_rotation {
            return Ok(false);
        }
        let archive_paths: Vec<_> = (0..=checkpoint.active_segment)
            .map(|segment| self.root.join(archive_name(segment)))
            .collect();
        let ScanResult::Valid(scanned) = self.scan_paths(&archive_paths)? else {
            return Ok(false);
        };
        if scanned.entries != checkpoint.record_count || scanned.head_mac != checkpoint.head_mac {
            return Ok(false);
        }
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) => {
                ensure_regular_metadata(&self.path, &metadata, "active audit log")?;
                if metadata.len() != 0 {
                    return Ok(false);
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                atomic_replace(&self.path, b"")?;
            }
            Err(error) => return Err(error.into()),
        }
        checkpoint = Checkpoint::signed(
            checkpoint.record_count,
            checkpoint.head_mac,
            checkpoint
                .active_segment
                .checked_add(1)
                .ok_or_else(|| AuditError::Integrity("segment sequence overflow".into()))?,
            0,
            scanned.head_mac,
            &self.key,
        )?;
        self.write_checkpoint(&checkpoint)?;
        Ok(true)
    }

    fn load_checkpoint(&self) -> Result<Checkpoint> {
        let metadata = match fs::symlink_metadata(&self.checkpoint_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let detail = if first_audit_artifact(&self.root)?.is_some() {
                    "checkpoint is missing while audit artifacts exist"
                } else {
                    "checkpoint is missing"
                };
                return Err(AuditError::NotInitialized(detail.into()));
            }
            Err(error) => return Err(error.into()),
        };
        ensure_regular_metadata(&self.checkpoint_path, &metadata, "audit checkpoint")?;
        let bytes = fs::read(&self.checkpoint_path)?;
        let checkpoint: Checkpoint = serde_json::from_slice(&bytes).map_err(|error| {
            AuditError::Integrity(format!("malformed audit checkpoint: {error}"))
        })?;
        checkpoint.verify(&self.key)?;
        Ok(checkpoint)
    }

    fn write_checkpoint(&self, checkpoint: &Checkpoint) -> Result<()> {
        let mut bytes = serde_json::to_vec(checkpoint)?;
        bytes.push(b'\n');
        atomic_replace(&self.checkpoint_path, &bytes)
    }
}

fn sign_record(
    sequence: u64,
    prev_mac: &str,
    event: AuditEvent,
    key: &[u8; 32],
) -> Result<AuditRecord> {
    let payload = RecordPayload {
        format_version: FORMAT_VERSION,
        sequence,
        prev_mac,
        event: &event,
    };
    let bytes = serde_json::to_vec(&payload)?;
    Ok(AuditRecord {
        format_version: FORMAT_VERSION,
        sequence,
        prev_mac: prev_mac.to_string(),
        event,
        mac: authenticate_hex(key, RECORD_DOMAIN, &bytes),
    })
}

fn verify_record(
    record: &AuditRecord,
    expected_sequence: u64,
    expected_prev: &str,
    key: &[u8; 32],
) -> std::result::Result<(), String> {
    if record.format_version != FORMAT_VERSION {
        return Err(format!(
            "unsupported record format version {}",
            record.format_version
        ));
    }
    if record.sequence != expected_sequence {
        return Err(format!(
            "record sequence mismatch: expected {expected_sequence}, found {}",
            record.sequence
        ));
    }
    if record.prev_mac != expected_prev {
        return Err(format!(
            "previous MAC mismatch at sequence {expected_sequence}"
        ));
    }
    if validate_mac_string(&record.prev_mac, "previous record MAC").is_err() {
        return Err(format!(
            "invalid previous MAC encoding at sequence {expected_sequence}"
        ));
    }
    let payload = RecordPayload {
        format_version: record.format_version,
        sequence: record.sequence,
        prev_mac: &record.prev_mac,
        event: &record.event,
    };
    let bytes = serde_json::to_vec(&payload).map_err(|error| error.to_string())?;
    verify_hex_tag(key, RECORD_DOMAIN, &bytes, &record.mac)
        .map_err(|_| format!("record MAC mismatch at sequence {expected_sequence}"))
}

fn authenticate_hex(key: &[u8; 32], domain: &[u8], bytes: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(domain);
    mac.update(bytes);
    encode_hex(&mac.finalize().into_bytes())
}

fn verify_hex_tag(
    key: &[u8; 32],
    domain: &[u8],
    bytes: &[u8],
    encoded_tag: &str,
) -> std::result::Result<(), ()> {
    let tag = decode_hex_32(encoded_tag).ok_or(())?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| ())?;
    mac.update(domain);
    mac.update(bytes);
    mac.verify_slice(&tag).map_err(|_| ())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.is_ascii() {
        return None;
    }
    let mut output = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble(pair[0])?;
        let low = decode_nibble(pair[1])?;
        output[index] = (high << 4) | low;
    }
    Some(output)
}

fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn validate_mac_string(value: &str, label: &str) -> Result<()> {
    decode_hex_32(value)
        .map(|_| ())
        .ok_or_else(|| AuditError::Integrity(format!("{label} is not canonical lowercase hex")))
}

fn archive_name(segment: u64) -> String {
    format!("{ARCHIVE_PREFIX}{segment:0ARCHIVE_DIGITS$}{ARCHIVE_SUFFIX}")
}

fn archive_segments(root: &Path) -> Result<BTreeSet<u64>> {
    let mut segments = BTreeSet::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(ARCHIVE_PREFIX) || !name.ends_with(ARCHIVE_SUFFIX) {
            continue;
        }
        let digits = &name[ARCHIVE_PREFIX.len()..name.len() - ARCHIVE_SUFFIX.len()];
        if digits.len() != ARCHIVE_DIGITS || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(AuditError::Integrity(format!(
                "unrecognized audit archive name: {name}"
            )));
        }
        let segment = digits
            .parse::<u64>()
            .map_err(|_| AuditError::Integrity(format!("invalid audit archive segment: {name}")))?;
        let path = entry.path();
        ensure_regular_metadata(&path, &fs::symlink_metadata(&path)?, "audit archive")?;
        segments.insert(segment);
    }
    Ok(segments)
}

fn first_audit_artifact(root: &Path) -> Result<Option<PathBuf>> {
    let checkpoint = root.join(CHECKPOINT_FILE);
    if fs::symlink_metadata(&checkpoint).is_ok() {
        return Ok(Some(checkpoint));
    }
    let active = root.join(AUDIT_FILE);
    if fs::symlink_metadata(&active).is_ok() {
        return Ok(Some(active));
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(ARCHIVE_PREFIX) && name.ends_with(ARCHIVE_SUFFIX) {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

fn ensure_root(root: &Path, create: bool) -> Result<()> {
    if create {
        fs::create_dir_all(root)?;
    }
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        if error.kind() == ErrorKind::NotFound {
            AuditError::NotInitialized(format!("vault directory is missing: {}", root.display()))
        } else {
            error.into()
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AuditError::Integrity(format!(
            "vault audit root is not a regular directory: {}",
            root.display()
        )));
    }
    Ok(())
}

fn ensure_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == ErrorKind::NotFound {
            AuditError::Integrity(format!("{label} is missing: {}", path.display()))
        } else {
            error.into()
        }
    })?;
    ensure_regular_metadata(path, &metadata, label)
}

fn ensure_regular_metadata(path: &Path, metadata: &fs::Metadata, label: &str) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AuditError::Integrity(format!(
            "{label} is not a regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn regular_file_len(path: &Path, label: &str) -> Result<u64> {
    let metadata = fs::symlink_metadata(path)?;
    ensure_regular_metadata(path, &metadata, label)?;
    Ok(metadata.len())
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        AuditError::Integrity(format!("audit path has no parent: {}", path.display()))
    })?;
    let (temp_path, mut temp_file) = create_unique_temp(parent, path.file_name())?;
    let result = (|| -> Result<()> {
        temp_file.write_all(bytes)?;
        temp_file.sync_all()?;
        drop(temp_file);
        if let Ok(metadata) = fs::symlink_metadata(path) {
            ensure_regular_metadata(path, &metadata, "audit destination")?;
        }
        install_temp_file(&temp_path, path, parent)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

#[cfg(not(windows))]
fn install_temp_file(temp_path: &Path, destination: &Path, _parent: &Path) -> Result<()> {
    fs::rename(temp_path, destination)?;
    Ok(())
}

#[cfg(windows)]
fn install_temp_file(temp_path: &Path, destination: &Path, parent: &Path) -> Result<()> {
    match fs::symlink_metadata(destination) {
        Err(error) if error.kind() == ErrorKind::NotFound => {
            fs::rename(temp_path, destination)?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }

    // `std::fs::rename` does not replace an existing destination on Windows.
    // Move the verified old file aside first, then install the synced temp.
    // Any interrupted intermediate state is intentionally fail-closed.
    for _ in 0..MAX_TEMP_ATTEMPTS {
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let backup = parent.join(format!(
            ".audit-replace-backup-{}-{nonce:016x}",
            std::process::id()
        ));
        match fs::rename(destination, &backup) {
            Ok(()) => {
                sync_directory(parent)?;
                if let Err(error) = fs::rename(temp_path, destination) {
                    let _ = fs::rename(&backup, destination);
                    let _ = sync_directory(parent);
                    return Err(error.into());
                }
                sync_directory(parent)?;
                fs::remove_file(backup)?;
                return Ok(());
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(AuditError::Integrity(
        "unable to allocate unique audit replacement backup".into(),
    ))
}

fn create_unique_temp(
    parent: &Path,
    target_name: Option<&std::ffi::OsStr>,
) -> Result<(PathBuf, File)> {
    let target = target_name
        .and_then(|name| name.to_str())
        .unwrap_or("audit");
    for _ in 0..MAX_TEMP_ATTEMPTS {
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(".{target}.tmp-{}-{nonce:016x}", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(AuditError::Integrity(
        "unable to allocate unique audit temporary file".into(),
    ))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_directory(path: &Path) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?
        .sync_all()?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_directory(_path: &Path) -> Result<()> {
    // The Rust standard library does not expose a portable directory fsync for
    // this platform. Desktop targets are covered by the Unix/Windows branches.
    Ok(())
}

// ---------------------------------------------------------------------------
// Cross-instance advisory write lock hardened against symlink attacks
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct AuditWriteLock {
    _file: File,
}

impl AuditWriteLock {
    fn acquire(root: &Path) -> Result<Self> {
        let path = root.join(LOCK_FILE);

        // Reject a pre-existing symlink or non-regular file before opening.
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(AuditError::Integrity(format!(
                    "audit write lock is not a regular file: {}",
                    path.display()
                )));
            }
        }

        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut options = OpenOptions::new();
            options.read(true).write(true).create(true);
            options.mode(0o600);
            // SAFETY: libc::O_NOFOLLOW is a well-known POSIX constant; the
            // custom_flags method is a safe std API.
            options.custom_flags(libc::O_NOFOLLOW);
            options.open(&path).map_err(|error| {
                if error.kind() == ErrorKind::NotFound {
                    AuditError::Integrity(format!(
                        "audit write lock is not a regular file: {}",
                        path.display()
                    ))
                } else {
                    AuditError::Io(error)
                }
            })?
        };

        #[cfg(windows)]
        let file = open_existing_or_new_audit_lock(&path)?;

        #[cfg(not(any(unix, windows)))]
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .map_err(|error| {
                if error.kind() == ErrorKind::NotFound {
                    AuditError::Integrity(format!(
                        "audit write lock is not a regular file: {}",
                        path.display()
                    ))
                } else {
                    AuditError::Io(error)
                }
            })?;

        // Validate the opened descriptor is a regular file (not a device,
        // FIFO, etc.). On Unix with O_NOFOLLOW a symlink would have caused
        // open(2) to fail with ELOOP, so this is defense-in-depth.
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(AuditError::Integrity(format!(
                "audit write lock is not a regular file: {}",
                path.display()
            )));
        }

        // On Windows, additionally check that the path we opened is not a
        // reparse point (symlink, junction, etc.).
        #[cfg(windows)]
        {
            let path_meta = fs::symlink_metadata(&path).map_err(|error| {
                if error.kind() == ErrorKind::NotFound {
                    AuditError::Integrity(format!(
                        "audit write lock is not a regular file: {}",
                        path.display()
                    ))
                } else {
                    AuditError::Io(error)
                }
            })?;
            if path_meta.file_type().is_symlink() {
                return Err(AuditError::Integrity(format!(
                    "audit write lock is not a regular file: {}",
                    path.display()
                )));
            }
        }

        // Sync the containing directory so a newly-created lock file is
        // durable before we proceed.
        sync_directory(root)?;

        match fs4::FileExt::try_lock(&file) {
            Ok(()) => Ok(Self { _file: file }),
            Err(fs4::TryLockError::WouldBlock) => Err(AuditError::Busy),
            Err(fs4::TryLockError::Error(error)) => Err(error.into()),
        }
    }
}

#[cfg(windows)]
fn open_existing_or_new_audit_lock(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    // Attempt to open an existing file with the reparse-safe flag so we can
    // inspect it. FILE_FLAG_OPEN_REPARSE_POINT is incompatible with CREATE,
    // so creation is handled separately without any custom flags.
    match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            // No existing file; create a new one without the reparse flag.
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(file) => Ok(file),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    // Lost the create race; retry the existing reparse-safe open.
                    OpenOptions::new()
                        .read(true)
                        .write(true)
                        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                        .open(path)
                        .map_err(Into::into)
                }
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error.into()),
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

    const KEY: [u8; 32] = [0x5a; 32];

    fn tmp_dir(label: &str) -> PathBuf {
        let mut path = env::temp_dir();
        path.push(format!(
            "sv-audit-test-{label}-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        path
    }

    fn ev(action: AuditAction) -> AuditEvent {
        AuditEvent::new(action, AuditDecision::Allowed, "test")
    }

    fn create_log(root: &Path) -> AuditLog {
        AuditLog::create(root, KEY).unwrap()
    }

    #[test]
    fn attempted_agent_actions_round_trip_through_serde() {
        for action in [
            AuditAction::AgentCreate,
            AuditAction::AgentList,
            AuditAction::AgentRevoke,
        ] {
            let event = AuditEvent::new(action, AuditDecision::Attempted, "test");
            let encoded = serde_json::to_vec(&event).unwrap();
            let decoded: AuditEvent = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(decoded.action, action);
            assert_eq!(decoded.decision, AuditDecision::Attempted);
        }
    }

    fn active_records(root: &Path) -> Vec<AuditRecord> {
        fs::read_to_string(root.join(AUDIT_FILE))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn append_without_checkpoint(log: &AuditLog, event: AuditEvent) -> AuditRecord {
        let checkpoint = log.load_checkpoint().unwrap();
        let record = sign_record(
            checkpoint.record_count,
            &checkpoint.head_mac,
            event,
            &log.key,
        )
        .unwrap();
        let mut line = serde_json::to_vec(&record).unwrap();
        line.push(b'\n');
        let mut file = OpenOptions::new().append(true).open(log.path()).unwrap();
        file.write_all(&line).unwrap();
        file.sync_all().unwrap();
        record
    }

    #[test]
    fn append_authenticates_records_and_checkpoint() {
        let root = tmp_dir("append");
        let log = create_log(&root);
        log.record(&ev(AuditAction::ReadFile)).unwrap();
        log.record(&ev(AuditAction::DeleteFile)).unwrap();

        let records = active_records(&root);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].sequence, 0);
        assert_eq!(records[0].prev_mac, GENESIS_PREV);
        assert_eq!(records[1].sequence, 1);
        assert_eq!(records[1].prev_mac, records[0].mac);
        assert!(log.verify_chain().unwrap().ok);

        let checkpoint = log.load_checkpoint().unwrap();
        assert_eq!(checkpoint.record_count, 2);
        assert_eq!(checkpoint.head_mac, records[1].mac);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reopen_verifies_then_continues_chain() {
        let root = tmp_dir("reopen");
        create_log(&root)
            .record(&ev(AuditAction::ReadFile))
            .unwrap();
        let log = AuditLog::open(&root, KEY).unwrap();
        log.record(&ev(AuditAction::WriteFile)).unwrap();
        let report = log.verify_chain().unwrap();
        assert!(report.ok, "{report:?}");
        assert_eq!(report.entries, 2);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn partial_genesis_creation_resumes_safely() {
        let root = tmp_dir("partial-create");
        fs::create_dir_all(&root).unwrap();
        atomic_replace(&root.join(AUDIT_FILE), b"").unwrap();

        let log = AuditLog::create(&root, KEY).unwrap();
        assert!(log.verify_chain().unwrap().ok);
        assert!(root.join(CHECKPOINT_FILE).is_file());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn synced_record_without_checkpoint_is_recovered_once() {
        let root = tmp_dir("append-crash");
        let log = create_log(&root);
        let record = append_without_checkpoint(&log, ev(AuditAction::ReadFile));

        let reopened = AuditLog::open(&root, KEY).unwrap();
        let checkpoint = reopened.load_checkpoint().unwrap();
        assert_eq!(checkpoint.record_count, 1);
        assert_eq!(checkpoint.head_mac, record.mac);
        assert_eq!(checkpoint.active_record_count, 1);
        assert!(reopened.verify_chain().unwrap().ok);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn more_than_one_uncheckpointed_record_fails_closed() {
        let root = tmp_dir("multiple-uncheckpointed");
        let log = create_log(&root);
        let first = append_without_checkpoint(&log, ev(AuditAction::ReadFile));
        let second = sign_record(1, &first.mac, ev(AuditAction::WriteFile), &KEY).unwrap();
        let mut line = serde_json::to_vec(&second).unwrap();
        line.push(b'\n');
        let mut file = OpenOptions::new().append(true).open(log.path()).unwrap();
        file.write_all(&line).unwrap();
        file.sync_all().unwrap();

        assert!(matches!(
            AuditLog::open(&root, KEY),
            Err(AuditError::Integrity(_))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_rotation_is_recovered_with_or_without_new_active_file() {
        for active_created in [false, true] {
            let root = tmp_dir(if active_created {
                "rotation-crash-active"
            } else {
                "rotation-crash-missing"
            });
            let log = create_log(&root);
            log.record(&ev(AuditAction::ReadFile)).unwrap();
            fs::rename(log.path(), root.join(archive_name(0))).unwrap();
            sync_directory(&root).unwrap();
            if active_created {
                atomic_replace(log.path(), b"").unwrap();
            }

            let reopened = AuditLog::open(&root, KEY).unwrap();
            let checkpoint = reopened.load_checkpoint().unwrap();
            assert_eq!(checkpoint.active_segment, 1);
            assert_eq!(checkpoint.active_record_count, 0);
            assert!(reopened.path().is_file());
            assert!(reopened.verify_chain().unwrap().ok);
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn advisory_lock_releases_when_guard_drops() {
        let root = tmp_dir("advisory-lock");
        fs::create_dir_all(&root).unwrap();
        let first = AuditWriteLock::acquire(&root).unwrap();
        assert!(matches!(
            AuditWriteLock::acquire(&root),
            Err(AuditError::Busy)
        ));
        drop(first);
        AuditWriteLock::acquire(&root).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn wrong_key_cannot_open_or_verify_checkpoint() {
        let root = tmp_dir("wrong-key");
        create_log(&root)
            .record(&ev(AuditAction::ReadFile))
            .unwrap();
        assert!(matches!(
            AuditLog::open(&root, [7u8; 32]),
            Err(AuditError::Authentication(_))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn record_edit_is_detected_and_append_fails_closed() {
        let root = tmp_dir("edit");
        let log = create_log(&root);
        log.record(&ev(AuditAction::ReadFile)).unwrap();
        let raw = fs::read_to_string(log.path()).unwrap();
        fs::write(log.path(), raw.replace("\"test\"", "\"evil\"")).unwrap();

        let report = log.verify_chain().unwrap();
        assert!(!report.ok);
        assert!(report.reason.unwrap().contains("MAC mismatch"));
        assert!(matches!(
            log.record(&ev(AuditAction::WriteFile)),
            Err(AuditError::Integrity(_))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn suffix_truncation_is_detected_by_checkpoint() {
        let root = tmp_dir("truncate");
        let log = create_log(&root);
        log.record(&ev(AuditAction::ReadFile)).unwrap();
        log.record(&ev(AuditAction::WriteFile)).unwrap();
        let raw = fs::read_to_string(log.path()).unwrap();
        let first = raw.lines().next().unwrap();
        fs::write(log.path(), format!("{first}\n")).unwrap();

        let report = log.verify_chain().unwrap();
        assert!(!report.ok);
        assert!(report.reason.unwrap().contains("record count mismatch"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn active_file_deletion_is_detected() {
        let root = tmp_dir("delete-active");
        let log = create_log(&root);
        log.record(&ev(AuditAction::ReadFile)).unwrap();
        fs::remove_file(log.path()).unwrap();
        let report = log.verify_chain().unwrap();
        assert!(!report.ok);
        assert!(report
            .reason
            .unwrap()
            .contains("active audit log is missing"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn checkpoint_deletion_and_malformed_checkpoint_fail_closed() {
        let root = tmp_dir("checkpoint");
        let log = create_log(&root);
        log.record(&ev(AuditAction::ReadFile)).unwrap();
        fs::remove_file(root.join(CHECKPOINT_FILE)).unwrap();
        assert!(matches!(
            log.verify_chain(),
            Err(AuditError::NotInitialized(_))
        ));

        fs::write(root.join(CHECKPOINT_FILE), b"not-json\n").unwrap();
        assert!(matches!(log.verify_chain(), Err(AuditError::Integrity(_))));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rotation_keeps_one_chain_and_missing_archive_is_detected() {
        let root = tmp_dir("rotation");
        let log = AuditLog::create_with_max_bytes(&root, KEY, 1).unwrap();
        log.record(&ev(AuditAction::ReadFile)).unwrap();
        log.record(&ev(AuditAction::WriteFile)).unwrap();
        log.record(&ev(AuditAction::DeleteFile)).unwrap();

        let archive0 = root.join(archive_name(0));
        let archive1 = root.join(archive_name(1));
        assert!(archive0.is_file());
        assert!(archive1.is_file());
        let first: AuditRecord = serde_json::from_str(
            fs::read_to_string(&archive0)
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        let second: AuditRecord = serde_json::from_str(
            fs::read_to_string(&archive1)
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        let third = active_records(&root).remove(0);
        assert_eq!(second.prev_mac, first.mac);
        assert_eq!(third.prev_mac, second.mac);
        assert!(log.verify_chain().unwrap().ok);

        fs::remove_file(archive0).unwrap();
        let report = log.verify_chain().unwrap();
        assert!(!report.ok);
        assert!(report.reason.unwrap().contains("archive set mismatch"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn malformed_and_legacy_records_are_rejected() {
        let malformed_root = tmp_dir("malformed");
        let malformed = create_log(&malformed_root);
        fs::write(malformed.path(), b"{bad-json}\n").unwrap();
        let report = malformed.verify_chain().unwrap();
        assert!(!report.ok);
        assert!(report.reason.unwrap().contains("malformed"));

        let legacy_root = tmp_dir("legacy");
        fs::create_dir_all(&legacy_root).unwrap();
        let legacy = serde_json::to_vec(&ev(AuditAction::ReadFile)).unwrap();
        fs::write(legacy_root.join(AUDIT_FILE), legacy).unwrap();
        assert!(matches!(
            AuditLog::create(&legacy_root, KEY),
            Err(AuditError::AlreadyExists(_))
        ));
        assert!(matches!(
            AuditLog::open(&legacy_root, KEY),
            Err(AuditError::NotInitialized(_))
        ));
        let _ = fs::remove_dir_all(malformed_root);
        let _ = fs::remove_dir_all(legacy_root);
    }

    #[test]
    fn checkpoint_edit_is_authenticated() {
        let root = tmp_dir("checkpoint-edit");
        let log = create_log(&root);
        log.record(&ev(AuditAction::ReadFile)).unwrap();
        let path = root.join(CHECKPOINT_FILE);
        let raw = fs::read_to_string(&path).unwrap();
        fs::write(
            &path,
            raw.replace("\"record_count\":1", "\"record_count\":0"),
        )
        .unwrap();
        assert!(matches!(
            log.verify_chain(),
            Err(AuditError::Authentication(_))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sensitive_fields_are_domain_separated_hmacs() {
        let root = tmp_dir("redaction");
        let log = create_log(&root);
        let mut event = ev(AuditAction::ReadFile);
        event.container = Some("secret-container".into());
        event.file_name = Some("passwords.txt".into());
        log.record(&event).unwrap();

        let record = active_records(&root).remove(0);
        assert_eq!(record.event.container, log.hmac_value("secret-container"));
        assert_eq!(record.event.file_name, log.hmac_value("passwords.txt"));
        assert_ne!(record.event.container.as_deref(), Some("secret-container"));
        assert!(log.verify_chain().unwrap().ok);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn atomic_replacements_leave_no_temp_files() {
        let root = tmp_dir("temps");
        let log = create_log(&root);
        for _ in 0..4 {
            log.record(&ev(AuditAction::ReadFile)).unwrap();
        }
        assert!(fs::read_dir(&root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")
        }));
        let _ = fs::remove_dir_all(root);
    }

    // -----------------------------------------------------------------------
    // Symlink / non-regular-file hardening tests
    // -----------------------------------------------------------------------

    #[test]
    #[cfg(unix)]
    fn lock_rejects_symlink_to_outside_sentinel() {
        let root = tmp_dir("lock-symlink");
        fs::create_dir_all(&root).unwrap();

        // Create an outside sentinel file that must not be modified.
        let sentinel = root.join("sentinel.txt");
        fs::write(&sentinel, b"untouched").unwrap();
        let sentinel_hash = {
            use sha2::Digest;
            let contents = fs::read(&sentinel).unwrap();
            sha2::Sha256::digest(&contents)
        };

        // Replace .audit-write.lock with a symlink to the sentinel.
        let lock_path = root.join(LOCK_FILE);
        std::os::unix::fs::symlink(&sentinel, &lock_path).unwrap();

        // Acquiring the lock must fail.
        let result = AuditWriteLock::acquire(&root);
        assert!(
            result.is_err(),
            "lock acquisition should have failed for a symlink"
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not a regular file"),
            "error should mention 'not a regular file'"
        );

        // The sentinel must be untouched.
        let sentinel_after = fs::read(&sentinel).unwrap();
        {
            use sha2::Digest;
            assert_eq!(
                sha2::Sha256::digest(&sentinel_after),
                sentinel_hash,
                "sentinel file was modified"
            );
        }

        // Creating a new audit log in this directory must also fail.
        assert!(AuditLog::create(&root, KEY).is_err());
        // Opening must also fail.
        assert!(AuditLog::open(&root, KEY).is_err());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    #[cfg(unix)]
    fn lock_rejects_symlink_created_after_directory_exists() {
        let root = tmp_dir("lock-symlink-race");
        fs::create_dir_all(&root).unwrap();

        // Pre-create a legitimate lock file, then replace it with a symlink.
        let lock_path = root.join(LOCK_FILE);
        fs::write(&lock_path, b"legitimate").unwrap();

        let sentinel = root.join("sentinel.txt");
        fs::write(&sentinel, b"untouched").unwrap();

        // Replace with symlink.
        fs::remove_file(&lock_path).unwrap();
        std::os::unix::fs::symlink(&sentinel, &lock_path).unwrap();

        let result = AuditWriteLock::acquire(&root);
        assert!(
            result.is_err(),
            "lock acquisition should have failed for a symlink"
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not a regular file"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lock_rejects_non_regular_file() {
        let root = tmp_dir("lock-nonfile");
        fs::create_dir_all(&root).unwrap();

        // Create a directory where the lock file should be.
        let lock_path = root.join(LOCK_FILE);
        fs::create_dir(&lock_path).unwrap();

        let result = AuditWriteLock::acquire(&root);
        assert!(
            result.is_err(),
            "lock acquisition should have failed for a directory"
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not a regular file"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lock_creates_and_syncs_new_lock_file() {
        let root = tmp_dir("lock-create");
        fs::create_dir_all(&root).unwrap();

        let lock_path = root.join(LOCK_FILE);
        assert!(!lock_path.exists());

        let lock = AuditWriteLock::acquire(&root).unwrap();
        assert!(lock_path.is_file());

        // Check that the file is a regular file (not a symlink).
        let metadata = fs::symlink_metadata(&lock_path).unwrap();
        assert!(metadata.is_file());
        assert!(!metadata.file_type().is_symlink());

        drop(lock);
        let _ = fs::remove_dir_all(root);
    }
}
