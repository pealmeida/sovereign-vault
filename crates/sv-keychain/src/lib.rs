//! OS keychain abstraction for master-key custody.
//!
//! Wraps the platform keychain via the `keyring` crate (Windows Credential
//! Manager / macOS Keychain / Linux Secret Service). Stores the master
//! key as a base64 string under service `"sovereign-vault"`. The legacy
//! account is `"master-key"`; newer callers should use root-scoped accounts.
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
        keyring_error_for_account(ACCOUNT, e)
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

/// Live OS keychain availability for the current platform session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeychainAvailability {
    /// The platform backend selected at compile time.
    pub backend: &'static str,
    /// True when this process can create, read, and delete a test credential.
    pub available: bool,
    /// Human-readable failure detail when unavailable.
    pub error: Option<String>,
}

fn entry() -> Result<keyring::Entry> {
    entry_for_account(ACCOUNT)
}

fn entry_for_account(account: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, account).map_err(|e| keyring_error_for_account(account, e))
}

fn keyring_error_for_account(account: &str, e: keyring::Error) -> KeychainError {
    match e {
        keyring::Error::NoEntry => KeychainError::NotFound(account.to_string()),
        keyring::Error::NoStorageAccess(inner) => {
            KeychainError::Unavailable(format_platform_error(inner.to_string()))
        }
        keyring::Error::PlatformFailure(inner) => {
            KeychainError::Backend(format_platform_error(inner.to_string()))
        }
        keyring::Error::BadEncoding(_) => {
            KeychainError::Backend("stored keychain credential is not valid UTF-8".into())
        }
        keyring::Error::TooLong(attribute, limit) => KeychainError::Backend(format!(
            "keychain attribute '{attribute}' exceeds the platform limit of {limit} characters"
        )),
        keyring::Error::Invalid(attribute, reason) => KeychainError::Backend(format!(
            "keychain attribute '{attribute}' is invalid: {reason}"
        )),
        keyring::Error::Ambiguous(items) => KeychainError::Backend(format!(
            "multiple keychain credentials matched account '{account}' ({})",
            items.len()
        )),
        other => KeychainError::Backend(format_platform_error(other.to_string())),
    }
}

fn format_platform_error(detail: String) -> String {
    format!("{}: {detail}", platform_backend())
}

/// Name of the native keychain backend compiled for this target.
pub fn platform_backend() -> &'static str {
    if cfg!(target_os = "windows") {
        "Windows Credential Manager"
    } else if cfg!(target_os = "macos") {
        "macOS Keychain"
    } else if cfg!(target_os = "linux") {
        "Linux Secret Service/keyutils"
    } else {
        "unsupported OS keychain backend"
    }
}

/// Verify that the current OS session can use the native keychain backend.
///
/// This performs a short create/read/delete round trip using a unique probe
/// account. It catches locked keychains, missing Linux Secret Service sessions,
/// and Windows logon-session failures before vault custody state is written.
pub fn availability() -> KeychainAvailability {
    match roundtrip_probe() {
        Ok(()) => KeychainAvailability {
            backend: platform_backend(),
            available: true,
            error: None,
        },
        Err(error) => KeychainAvailability {
            backend: platform_backend(),
            available: false,
            error: Some(error.to_string()),
        },
    }
}

/// Return an error if the current OS session cannot use the native keychain.
pub fn ensure_available() -> Result<()> {
    let availability = availability();
    if availability.available {
        Ok(())
    } else {
        Err(KeychainError::Unavailable(
            availability
                .error
                .unwrap_or_else(|| format!("{} is unavailable", platform_backend())),
        ))
    }
}

fn roundtrip_probe() -> Result<()> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let account = format!("availability-probe-{}-{nanos}", std::process::id());
    let expected = "sovereign-vault-keychain-probe";

    store_master_key_for_account(&account, expected)?;
    let loaded = load_master_key_for_account(&account);
    let delete_result = delete_master_key_for_account(&account);
    delete_result?;
    let loaded = loaded?;

    match loaded.as_deref() {
        Some(actual) if actual == expected => Ok(()),
        Some(_) => Err(KeychainError::Backend(format!(
            "{} returned a different probe credential",
            platform_backend()
        ))),
        None => Err(KeychainError::Backend(format!(
            "{} did not return the probe credential",
            platform_backend()
        ))),
    }
}

/// Store the master key (already base64-encoded) in the OS keychain.
pub fn store_master_key(b64: &str) -> Result<()> {
    let e = entry()?;
    e.set_password(b64)
        .map_err(|error| keyring_error_for_account(ACCOUNT, error))?;
    Ok(())
}

/// Store the master key (already base64-encoded) under a caller-supplied account.
pub fn store_master_key_for_account(account: &str, b64: &str) -> Result<()> {
    let e = entry_for_account(account)?;
    e.set_password(b64)
        .map_err(|error| keyring_error_for_account(account, error))?;
    Ok(())
}

/// Load the master key from the OS keychain. Returns `Ok(None)` if absent.
pub fn load_master_key() -> Result<Option<String>> {
    let e = entry()?;
    match e.get_password() {
        Ok(s) => Ok(Some(s)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(other) => Err(keyring_error_for_account(ACCOUNT, other)),
    }
}

/// Load the master key from a caller-supplied account. Returns `Ok(None)` if absent.
pub fn load_master_key_for_account(account: &str) -> Result<Option<String>> {
    let e = entry_for_account(account)?;
    match e.get_password() {
        Ok(s) => Ok(Some(s)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(other) => Err(keyring_error_for_account(account, other)),
    }
}

/// Delete the master key from the OS keychain. No-op if absent.
pub fn delete_master_key() -> Result<()> {
    let e = entry()?;
    match e.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(other) => Err(keyring_error_for_account(ACCOUNT, other)),
    }
}

/// Delete the master key from a caller-supplied account. No-op if absent.
pub fn delete_master_key_for_account(account: &str) -> Result<()> {
    let e = entry_for_account(account)?;
    match e.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(other) => Err(keyring_error_for_account(account, other)),
    }
}

/// Crate version string.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
