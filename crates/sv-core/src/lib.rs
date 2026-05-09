//! High-level integration crate for Sovereign Vault.
//!
//! Embeds the storage, crypto, keychain, recovery, audit, MCP, and HTTP
//! layers behind a single `Vault` facade so apps (`apps/desktop`,
//! `apps/cli`, future mobile) depend on this crate only. Re-exports the
//! stable public types from each sub-crate.
//!
//! Real implementation lands in M4-M5 once the lower layers are in place.
//!
//! # Stability
//!
//! Pre-1.0.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use sv_audit;
pub use sv_crypto;
pub use sv_http;
pub use sv_keychain;
pub use sv_mcp;
pub use sv_recovery;
pub use sv_storage;

use thiserror::Error;

/// Top-level error returned by the integration layer.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Crypto layer failure.
    #[error(transparent)]
    Crypto(#[from] sv_crypto::CryptoError),

    /// Storage layer failure.
    #[error(transparent)]
    Storage(#[from] sv_storage::StorageError),

    /// Keychain layer failure.
    #[error(transparent)]
    Keychain(#[from] sv_keychain::KeychainError),

    /// Recovery layer failure.
    #[error(transparent)]
    Recovery(#[from] sv_recovery::RecoveryError),

    /// Audit layer failure.
    #[error(transparent)]
    Audit(#[from] sv_audit::AuditError),

    /// MCP layer failure.
    #[error(transparent)]
    Mcp(#[from] sv_mcp::McpError),

    /// HTTP layer failure.
    #[error(transparent)]
    Http(#[from] sv_http::HttpError),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, CoreError>;

/// Crate version string for logging and the `app_version` Tauri command.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
