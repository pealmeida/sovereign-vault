//! Pluggable master-key recovery providers.
//!
//! v1.0 ships a single provider implementation: a 24-word BIP39 phrase
//! generated at first launch. The phrase wraps a copy of the master key
//! stored in `recovery.svault`. Future providers (Shamir's Secret Sharing,
//! hardware token, cloud-escrowed encrypted backup) plug in via the
//! [`RecoveryProvider`] trait without breaking v1.0 vaults.
//!
//! # Stability
//!
//! Pre-1.0.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fs;
use std::io::Write;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use bip39::{Language, Mnemonic};
use serde::{Deserialize, Serialize};
use sv_crypto::{MasterKey, MASTER_KEY_LEN, SALT_LEN};
use thiserror::Error;

const RECOVERY_AAD: &[u8] = b"sv-recovery-v1";
const RECOVERY_VERSION: u32 = 1;

/// Recovery bundle filename inside the vault root.
pub const RECOVERY_FILE: &str = "recovery.svault";

/// Recovery layer errors.
#[derive(Debug, Error)]
pub enum RecoveryError {
    /// The recovery code did not validate (bad checksum, wrong word count).
    #[error("Invalid recovery code: {0}")]
    InvalidCode(String),

    /// Provider-specific failure.
    #[error("Provider error: {0}")]
    Provider(String),

    /// Filesystem I/O failure.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    /// Encoding failure.
    #[error("Encoding: {0}")]
    Encoding(#[from] serde_json::Error),

    /// Base64 failure.
    #[error("Base64: {0}")]
    Base64(String),

    /// Crypto failure.
    #[error(transparent)]
    Crypto(#[from] sv_crypto::CryptoError),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, RecoveryError>;

/// Trait implemented by each recovery method (BIP39, Shamir, hardware, …).
pub trait RecoveryProvider {
    /// Stable identifier for the provider, e.g. `"bip39-24"`.
    fn id(&self) -> &'static str;
}

/// Built-in BIP39 recovery provider.
pub struct Bip39Recovery;

impl RecoveryProvider for Bip39Recovery {
    fn id(&self) -> &'static str {
        "bip39-24"
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RecoveryBundle {
    version: u32,
    provider: String,
    salt_b64: String,
    wrapped_key_b64: String,
}

/// True when a recovery bundle exists in the vault root.
pub fn has_recovery_bundle(root: &Path) -> bool {
    root.join(RECOVERY_FILE).exists()
}

/// Issue a new recovery phrase and persist an encrypted master-key copy.
pub fn issue_recovery_phrase(root: &Path, master: &MasterKey) -> Result<String> {
    let entropy = sv_crypto::random_bytes(32)?;
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| RecoveryError::Provider(e.to_string()))?;
    let phrase = mnemonic.to_string();
    let salt = sv_crypto::random_salt()?;
    let recovery_key = MasterKey::from_passphrase(&phrase, &salt)?;
    let wrapped_key = sv_crypto::seal(&recovery_key, master.as_bytes(), RECOVERY_AAD)?;

    let bundle = RecoveryBundle {
        version: RECOVERY_VERSION,
        provider: Bip39Recovery.id().to_string(),
        salt_b64: B64.encode(salt),
        wrapped_key_b64: B64.encode(wrapped_key),
    };
    write_bundle(root, &bundle)?;
    Ok(phrase)
}

/// Restore the vault master key from a persisted bundle and a BIP39 phrase.
pub fn restore_master_key(root: &Path, phrase: &str) -> Result<MasterKey> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|e| RecoveryError::InvalidCode(e.to_string()))?;
    let normalized = mnemonic.to_string();

    let bundle = read_bundle(root)?;
    if bundle.version != RECOVERY_VERSION {
        return Err(RecoveryError::Provider(format!(
            "unsupported recovery bundle version: {}",
            bundle.version
        )));
    }

    let salt_raw = B64
        .decode(bundle.salt_b64.as_bytes())
        .map_err(|e| RecoveryError::Base64(e.to_string()))?;
    if salt_raw.len() != SALT_LEN {
        return Err(RecoveryError::Provider(format!(
            "invalid recovery salt length: {}",
            salt_raw.len()
        )));
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&salt_raw);

    let wrapped_key = B64
        .decode(bundle.wrapped_key_b64.as_bytes())
        .map_err(|e| RecoveryError::Base64(e.to_string()))?;
    let recovery_key = MasterKey::from_passphrase(&normalized, &salt)?;
    let raw = sv_crypto::open(&recovery_key, &wrapped_key, RECOVERY_AAD)?;
    if raw.len() != MASTER_KEY_LEN {
        return Err(RecoveryError::Provider(format!(
            "invalid recovered master-key length: {}",
            raw.len()
        )));
    }
    let mut bytes = [0u8; MASTER_KEY_LEN];
    bytes.copy_from_slice(&raw);
    Ok(MasterKey::from_bytes(bytes))
}

fn read_bundle(root: &Path) -> Result<RecoveryBundle> {
    let path = root.join(RECOVERY_FILE);
    let raw = fs::read(&path).map_err(|e| {
        RecoveryError::Io(std::io::Error::new(
            e.kind(),
            format!("{} ({})", e, path.display()),
        ))
    })?;
    Ok(serde_json::from_slice(&raw)?)
}

fn write_bundle(root: &Path, bundle: &RecoveryBundle) -> Result<()> {
    if !root.exists() {
        fs::create_dir_all(root)?;
    }
    let path = root.join(RECOVERY_FILE);
    let tmp = root.join(".recovery.svault.tmp");
    let bytes = serde_json::to_vec_pretty(bundle)?;
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    Ok(())
}

/// Crate version string.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tmp_dir(label: &str) -> std::path::PathBuf {
        let mut p = env::temp_dir();
        p.push(format!("sv-recovery-test-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn issue_and_restore_roundtrip() {
        let root = tmp_dir("roundtrip");
        fs::create_dir_all(&root).unwrap();
        let master = MasterKey::generate();

        let phrase = issue_recovery_phrase(&root, &master).unwrap();
        assert!(has_recovery_bundle(&root));

        let restored = restore_master_key(&root, &phrase).unwrap();
        assert_eq!(restored.as_bytes(), master.as_bytes());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn invalid_phrase_is_rejected() {
        let root = tmp_dir("invalid");
        fs::create_dir_all(&root).unwrap();
        let master = MasterKey::generate();
        let _phrase = issue_recovery_phrase(&root, &master).unwrap();

        assert!(restore_master_key(&root, "not a valid recovery phrase").is_err());

        let _ = fs::remove_dir_all(&root);
    }
}
