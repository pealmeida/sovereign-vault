//! Sovereign Vault cryptographic primitives.
//!
//! Provides authenticated encryption (XChaCha20-Poly1305), key derivation
//! (Argon2id, HKDF), and key wrapping for the chunked file format defined in
//! ADR-003. All sensitive byte buffers implement `Zeroize` so plaintext is
//! cleared from memory promptly.
//!
//! # Stability
//!
//! Pre-1.0. APIs subject to change. The `.svault-v2` chunked format defined
//! here is versioned via `key_version: u32` so v1.0 vaults remain readable
//! after primitive rotation.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use thiserror::Error;

/// Crate-wide error type.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// AEAD operation failed (authentication tag mismatch or malformed input).
    #[error("AEAD operation failed: {0}")]
    Aead(String),

    /// Key derivation failed.
    #[error("Key derivation failed: {0}")]
    Kdf(String),

    /// Encoding or framing error.
    #[error("Encoding error: {0}")]
    Encoding(String),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Stub indicating the crate compiles. Replaced in M2 with real primitives.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_version() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
    }
}
