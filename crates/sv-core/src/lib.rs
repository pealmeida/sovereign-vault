//! High-level integration crate for Sovereign Vault.
//!
//! Embeds the storage, crypto, keychain, recovery, audit, MCP, and HTTP
//! layers behind a single [`VaultHandle`] facade so apps (`apps/desktop`,
//! `apps/cli`, future mobile) depend on this crate only.
//!
//! For the MVP, only `sv-crypto`, `sv-storage`, and `sv-keychain` are
//! actively wired; the other re-exports keep their stub status until
//! later milestones.
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

use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use sv_crypto::{MasterKey, MASTER_KEY_LEN, SALT_LEN};
use sv_storage::{ContainerInfo, FileInfo, SecurityMode, Vault};
use thiserror::Error;

pub use sv_keychain::CustodyMode;

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

    /// I/O failure outside the storage layer.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    /// Base64 decode failure.
    #[error("Base64 decode: {0}")]
    Base64(String),

    /// Caller misuse (missing passphrase, vault already initialised, etc.).
    #[error("{0}")]
    Misuse(String),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, CoreError>;

const SALT_FILENAME: &str = "master.salt";

/// Live, unlocked vault handle.
///
/// Owns an open [`Vault`] (and therefore the master key). Drop the
/// handle to lock the vault — the underlying [`MasterKey`] zeroises on drop.
pub struct VaultHandle {
    vault: Vault,
    custody: CustodyMode,
}

impl VaultHandle {
    /// Bootstrap a brand-new vault at `root`.
    ///
    /// * `OsKeychain` custody — generates a random master key and stores it
    ///   in the OS keychain. Refuses to overwrite an existing entry.
    /// * `Passphrase` custody — generates a random salt, derives the master
    ///   key from `passphrase` + salt, persists the salt to `master.salt`.
    ///
    /// Returns an error if the vault already appears initialised (manifest
    /// exists, or the appropriate custody artefact is already present).
    pub fn bootstrap(root: &Path, custody: CustodyMode, passphrase: Option<&str>) -> Result<Self> {
        if !root.exists() {
            fs::create_dir_all(root)?;
        }

        match custody {
            CustodyMode::OsKeychain => {
                if sv_keychain::load_master_key()?.is_some() {
                    return Err(CoreError::Misuse(
                        "OS keychain already holds a master key — call unlock instead".into(),
                    ));
                }
                let key = MasterKey::generate();
                let b64 = B64.encode(key.as_bytes());
                sv_keychain::store_master_key(&b64)?;
                let vault = Vault::open_or_init(root, key)?;
                Ok(Self { vault, custody })
            }
            CustodyMode::Passphrase => {
                let pass = passphrase.ok_or_else(|| {
                    CoreError::Misuse("passphrase custody requires a passphrase".into())
                })?;
                let salt_path = root.join(SALT_FILENAME);
                if salt_path.exists() {
                    return Err(CoreError::Misuse(
                        "vault already initialised (master.salt exists) — call unlock instead"
                            .into(),
                    ));
                }
                let salt = sv_crypto::random_salt()?;
                fs::write(&salt_path, salt)?;
                let key = MasterKey::from_passphrase(pass, &salt)?;
                let vault = Vault::open_or_init(root, key)?;
                Ok(Self { vault, custody })
            }
        }
    }

    /// Unlock an existing vault using the previously-chosen custody mode.
    pub fn unlock(root: &Path, custody: CustodyMode, passphrase: Option<&str>) -> Result<Self> {
        match custody {
            CustodyMode::OsKeychain => {
                let b64 = sv_keychain::load_master_key()?.ok_or_else(|| {
                    CoreError::Misuse(
                        "no master key in OS keychain — bootstrap the vault first".into(),
                    )
                })?;
                let raw = B64
                    .decode(b64.as_bytes())
                    .map_err(|e| CoreError::Base64(e.to_string()))?;
                if raw.len() != MASTER_KEY_LEN {
                    return Err(CoreError::Misuse(format!(
                        "keychain entry has wrong length: {}",
                        raw.len()
                    )));
                }
                let mut bytes = [0u8; MASTER_KEY_LEN];
                bytes.copy_from_slice(&raw);
                let key = MasterKey::from_bytes(bytes);
                let vault = Vault::open_or_init(root, key)?;
                Ok(Self { vault, custody })
            }
            CustodyMode::Passphrase => {
                let pass = passphrase.ok_or_else(|| {
                    CoreError::Misuse("passphrase custody requires a passphrase".into())
                })?;
                let salt_path = root.join(SALT_FILENAME);
                let salt_raw = fs::read(&salt_path).map_err(|_| {
                    CoreError::Misuse(
                        "no master.salt — bootstrap the vault with passphrase custody first".into(),
                    )
                })?;
                if salt_raw.len() != SALT_LEN {
                    return Err(CoreError::Misuse(format!(
                        "master.salt has wrong length: {}",
                        salt_raw.len()
                    )));
                }
                let mut salt = [0u8; SALT_LEN];
                salt.copy_from_slice(&salt_raw);
                let key = MasterKey::from_passphrase(pass, &salt)?;
                let vault = Vault::open_or_init(root, key)?;
                Ok(Self { vault, custody })
            }
        }
    }

    /// Custody mode in use for this handle.
    pub fn custody(&self) -> CustodyMode {
        self.custody
    }

    /// Path to the vault root.
    pub fn root(&self) -> &Path {
        self.vault.root()
    }

    // ---- storage facade --------------------------------------------------

    /// List all containers.
    pub fn list_containers(&self) -> Result<Vec<ContainerInfo>> {
        Ok(self.vault.list_containers()?)
    }

    /// Create a new container.
    pub fn create_container(
        &self,
        name: &str,
        mode: SecurityMode,
        description: Option<String>,
    ) -> Result<()> {
        Ok(self.vault.create_container(name, mode, description)?)
    }

    /// Delete a container.
    pub fn delete_container(&self, name: &str) -> Result<()> {
        Ok(self.vault.delete_container(name)?)
    }

    /// List the files inside a container.
    pub fn list_files(&self, container: &str) -> Result<Vec<FileInfo>> {
        Ok(self.vault.list_files(container)?)
    }

    /// Encrypt and write a file.
    pub fn write_file(&self, container: &str, file_name: &str, plaintext: &[u8]) -> Result<()> {
        Ok(self.vault.write_file(container, file_name, plaintext)?)
    }

    /// Read and decrypt a file.
    pub fn read_file(&self, container: &str, file_name: &str) -> Result<Vec<u8>> {
        Ok(self.vault.read_file(container, file_name)?)
    }

    /// Delete a file.
    pub fn delete_file(&self, container: &str, file_name: &str) -> Result<()> {
        Ok(self.vault.delete_file(container, file_name)?)
    }
}

impl sv_mcp::VaultFacade for VaultHandle {
    fn list_containers(&self) -> std::result::Result<Vec<ContainerInfo>, String> {
        VaultHandle::list_containers(self).map_err(|e| e.to_string())
    }
    fn list_files(&self, container: &str) -> std::result::Result<Vec<FileInfo>, String> {
        VaultHandle::list_files(self, container).map_err(|e| e.to_string())
    }
    fn read_file(&self, container: &str, file_name: &str) -> std::result::Result<Vec<u8>, String> {
        VaultHandle::read_file(self, container, file_name).map_err(|e| e.to_string())
    }
    fn write_file(
        &self,
        container: &str,
        file_name: &str,
        plaintext: &[u8],
    ) -> std::result::Result<(), String> {
        VaultHandle::write_file(self, container, file_name, plaintext).map_err(|e| e.to_string())
    }
    fn delete_file(&self, container: &str, file_name: &str) -> std::result::Result<(), String> {
        VaultHandle::delete_file(self, container, file_name).map_err(|e| e.to_string())
    }
}

/// Generate a fresh URL-safe-base64 32-byte pairing secret using the OS RNG
/// from `sv-crypto`. Use this from the desktop app on every unlock.
pub fn fresh_pairing_secret() -> Result<String> {
    let bytes = sv_crypto::random_bytes(32)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Inspect a vault root and report whether it has been initialised, and
/// which custody mode artefact is present (if any).
pub struct InitState {
    /// True if the vault root has a `manifest.json`.
    pub initialized: bool,
    /// True if `master.salt` is present (passphrase custody).
    pub has_passphrase_salt: bool,
    /// True if the OS keychain has a master-key entry.
    pub has_keychain_entry: bool,
}

/// Probe the on-disk + keychain state of a vault root.
pub fn probe(root: &Path) -> Result<InitState> {
    let manifest = root.join("manifest.json");
    let salt = root.join(SALT_FILENAME);
    Ok(InitState {
        initialized: manifest.exists(),
        has_passphrase_salt: salt.exists(),
        has_keychain_entry: sv_keychain::load_master_key()?.is_some(),
    })
}

/// Resolve a candidate vault root path, creating any missing parents.
pub fn ensure_root(root: &Path) -> Result<PathBuf> {
    if let Some(parent) = root.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(root.to_path_buf())
}

/// Crate version string for logging and the `app_version` Tauri command.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
