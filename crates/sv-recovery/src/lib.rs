//! Pluggable master-key recovery providers.
//!
//! v1.0 ships a single provider implementation: a 24-word BIP39 phrase
//! generated at first launch. The phrase wraps a copy of the master key
//! stored in `recovery.svault`. Future providers (Shamir's Secret Sharing,
//! hardware token, cloud-escrowed encrypted backup) plug in via the
//! [`RecoveryProvider`] trait without breaking v1.0 vaults.
//!
//! Real implementation lands in M3.
//!
//! # Stability
//!
//! Pre-1.0.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use thiserror::Error;

/// Recovery layer errors.
#[derive(Debug, Error)]
pub enum RecoveryError {
    /// The recovery code did not validate (bad checksum, wrong word count).
    #[error("Invalid recovery code: {0}")]
    InvalidCode(String),

    /// Provider-specific failure.
    #[error("Provider error: {0}")]
    Provider(String),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, RecoveryError>;

/// Trait implemented by each recovery method (BIP39, Shamir, hardware, …).
///
/// v1.0 includes only the BIP39 implementation. The trait signature is
/// frozen so future providers do not require breaking changes.
pub trait RecoveryProvider {
    /// Stable identifier for the provider, e.g. `"bip39-24"`.
    fn id(&self) -> &'static str;
}

/// Stub indicating the crate compiles. Replaced in M3.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
