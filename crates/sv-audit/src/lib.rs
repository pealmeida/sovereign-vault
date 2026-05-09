//! Append-only JSONL audit log.
//!
//! Every read, write, delete, approve, or deny operation emits one
//! structured event to a per-vault JSONL file. v1.0 keeps it simple:
//! plaintext JSONL, line-delimited, no rotation, no hash chain.
//!
//! Hash-chained audit (each entry includes the SHA-256 of the previous
//! entry) is deferred to v1.1.
//!
//! Real implementation lands in M4.
//!
//! # Stability
//!
//! Pre-1.0.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use thiserror::Error;

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

/// Stub indicating the crate compiles. Replaced in M4.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
