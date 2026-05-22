//! OS keychain abstraction for master-key custody.
//!
//! Wraps the platform keychain via the `keyring` crate (Windows Credential
//! Manager / macOS Keychain / Linux Secret Service). Stores the master
//! key as a base64 string under service `"sovereign-vault"` / account
//! `"master-key"`.
//!
//! # Stability
//!
//! Pre-1.0.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use thiserror::Error;

/// Service name used in the OS keychain.
pub const SERVICE: &str = "sovereign-vault";

/// Account name used in the OS keychain.
pub const ACCOUNT: &str = "master-key";

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

impl From<keyring::Error> for KeychainError {
    fn from(e: keyring::Error) -> Self {
        match e {
            keyring::Error::NoEntry => KeychainError::NotFound(ACCOUNT.to_string()),
            keyring::Error::PlatformFailure(inner) => KeychainError::Backend(inner.to_string()),
            keyring::Error::NoStorageAccess(inner) => KeychainError::Unavailable(inner.to_string()),
            other => KeychainError::Backend(other.to_string()),
        }
    }
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
    /// Restored from the recovery bundle for the current session.
    Recovery,
}

fn entry() -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, ACCOUNT).map_err(KeychainError::from)
}

/// Store the master key (already base64-encoded) in the OS keychain.
pub fn store_master_key(b64: &str) -> Result<()> {
    let e = entry()?;
    e.set_password(b64)?;
    Ok(())
}

/// Load the master key from the OS keychain. Returns `Ok(None)` if absent.
pub fn load_master_key() -> Result<Option<String>> {
    let e = entry()?;
    match e.get_password() {
        Ok(s) => Ok(Some(s)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(other) => Err(other.into()),
    }
}

/// Delete the master key from the OS keychain. No-op if absent.
pub fn delete_master_key() -> Result<()> {
    let e = entry()?;
    match e.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(other) => Err(other.into()),
    }
}

/// Crate version string.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
