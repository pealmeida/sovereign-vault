//! Sovereign Vault storage layer.
//!
//! Defines the on-disk layout of the vault: a single root directory containing
//! containers (folders) which hold chunked-encrypted files. Resolves a folder's
//! effective security mode through `manifest.json` glob rules.
//!
//! # Layout
//!
//! ```text
//! <vault_root>/
//!   manifest.json          # global manifest with default_mode + glob rules
//!   <container>/
//!     <file>.svault-v2     # chunked AEAD file (see ADR-003)
//!   ...
//! ```
//!
//! # Stability
//!
//! Pre-1.0. APIs subject to change.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use thiserror::Error;

/// Storage layer errors.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Filesystem I/O error.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    /// Manifest parse / format error.
    #[error("Manifest: {0}")]
    Manifest(String),

    /// Path traversal or invalid container/file path.
    #[error("Invalid path: {0}")]
    InvalidPath(String),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, StorageError>;

/// Stub indicating the crate compiles. Replaced in M2.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
