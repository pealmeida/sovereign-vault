//! OS keychain abstraction for master-key custody.
//!
//! Wraps the platform keychain (Windows DPAPI / macOS Keychain / Linux
//! Secret Service via libsecret). Falls back to a passphrase-derived KEK
//! (Argon2id) when no keychain is available or when the user opts in.
//!
//! # Stability
//!
//! Pre-1.0.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use thiserror::Error;

/// Keychain errors.
#[derive(Debug, Error)]
pub enum KeychainError {
    /// The OS keychain is unavailable on this platform/session.
    #[error("Keychain unavailable: {0}")]
    Unavailable(String),

    /// Item missing from keychain.
    #[error("Item not found: {0}")]
    NotFound(String),

    /// Unspecified backend error.
    #[error("Backend error: {0}")]
    Backend(String),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, KeychainError>;

/// Custody mode for the master key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyMode {
    /// Wrapped by the OS keychain (default when available).
    OsKeychain,
    /// Wrapped by an Argon2id KEK derived from a user passphrase.
    Passphrase,
}

/// Stub indicating the crate compiles. Replaced in M3.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
