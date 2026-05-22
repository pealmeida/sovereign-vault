//! Append-only JSONL audit log.
//!
//! Every read, write, delete, approve, or deny operation emits one
//! structured event to a per-vault JSONL file. v1.0 keeps it simple:
//! plaintext JSONL, line-delimited, no rotation, no hash chain.
//!
//! Hash-chained audit (each entry includes the SHA-256 of the previous
//! entry) is deferred to v1.1.
//!
//! # Stability
//!
//! Pre-1.0.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Audit filename inside the vault root.
pub const AUDIT_FILE: &str = "audit.jsonl";

/// Audit log errors.
#[derive(Debug, Error)]
pub enum AuditError {
    /// Filesystem I/O failure.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    /// JSON encoding failure.
    #[error("Encoding: {0}")]
    Encoding(#[from] serde_json::Error),
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

/// Append-only JSONL writer.
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    /// Build an audit log rooted at the given vault path.
    pub fn new(root: &Path) -> Self {
        Self {
            path: root.join(AUDIT_FILE),
        }
    }

    /// Path to the log file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one event and flush it durably.
    pub fn record(&self, event: &AuditEvent) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        serde_json::to_writer(&mut file, event)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
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
}
