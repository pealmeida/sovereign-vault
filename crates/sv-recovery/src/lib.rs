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

use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64_URL},
    Engine as _,
};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dek_version: Option<u32>,
    salt_b64: String,
    wrapped_key_b64: String,
}

/// A recovered data-encryption key and the keyring version it belongs to.
///
/// Bundles written before version binding was introduced have no
/// `dek_version`; callers may retain their legacy compatibility behavior for
/// those bundles, but must never relabel a versioned key.
pub struct RecoveredMasterKey {
    /// Restored data-encryption key.
    pub master_key: MasterKey,
    /// Exact DEK version, or `None` for a legacy unversioned bundle.
    pub dek_version: Option<u32>,
}

/// True when a recovery bundle exists in the vault root.
pub fn has_recovery_bundle(root: &Path) -> bool {
    fs::symlink_metadata(root.join(RECOVERY_FILE))
        .is_ok_and(|metadata| !metadata.file_type().is_symlink() && metadata.is_file())
}

/// Issue a new recovery phrase and persist an encrypted master-key copy.
pub fn issue_recovery_phrase(root: &Path, master: &MasterKey) -> Result<String> {
    issue_recovery_phrase_inner(root, master, None)
}

/// Issue a recovery phrase bound to an exact keyring DEK version.
pub fn issue_recovery_phrase_for_version(
    root: &Path,
    master: &MasterKey,
    dek_version: u32,
) -> Result<String> {
    if dek_version == 0 {
        return Err(RecoveryError::Provider(
            "recovery DEK version must be greater than zero".into(),
        ));
    }
    issue_recovery_phrase_inner(root, master, Some(dek_version))
}

fn issue_recovery_phrase_inner(
    root: &Path,
    master: &MasterKey,
    dek_version: Option<u32>,
) -> Result<String> {
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
        dek_version,
        salt_b64: B64.encode(salt),
        wrapped_key_b64: B64.encode(wrapped_key),
    };
    write_bundle(root, &bundle)?;
    Ok(phrase)
}

/// Restore the vault master key from a persisted bundle and a BIP39 phrase.
pub fn restore_master_key(root: &Path, phrase: &str) -> Result<MasterKey> {
    Ok(restore_master_key_with_version(root, phrase)?.master_key)
}

/// Restore a key together with its bound keyring version.
pub fn restore_master_key_with_version(root: &Path, phrase: &str) -> Result<RecoveredMasterKey> {
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
    Ok(RecoveredMasterKey {
        master_key: MasterKey::from_bytes(bytes),
        dek_version: bundle.dek_version,
    })
}

fn read_bundle(root: &Path) -> Result<RecoveryBundle> {
    ensure_real_directory(root)?;
    let path = root.join(RECOVERY_FILE);
    ensure_regular_file(&path, "recovery bundle")?;
    let raw = fs::read(&path).map_err(|e| {
        RecoveryError::Io(std::io::Error::new(
            e.kind(),
            format!("{} ({})", e, path.display()),
        ))
    })?;
    Ok(serde_json::from_slice(&raw)?)
}

fn write_bundle(root: &Path, bundle: &RecoveryBundle) -> Result<()> {
    ensure_real_directory_or_create(root)?;
    let path = root.join(RECOVERY_FILE);
    ensure_regular_file_or_missing(&path, "recovery bundle")?;
    let bytes = serde_json::to_vec_pretty(bundle)?;
    let mut file = create_secure_temp(root)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    ensure_regular_file_or_missing(&path, "recovery bundle")?;
    let temporary_path = file.into_temp_path();
    atomicwrites::replace_atomic(&temporary_path, &path)?;
    sync_parent(root)
}

fn create_secure_temp(root: &Path) -> Result<tempfile::NamedTempFile> {
    for _ in 0..16 {
        let suffix = B64_URL.encode(sv_crypto::random_bytes(12)?);
        let path = root.join(format!(".{RECOVERY_FILE}.{suffix}.tmp"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&path) {
            Ok(file) => {
                let temp_path = tempfile::TempPath::try_from_path(path)?;
                return Ok(tempfile::NamedTempFile::from_parts(file, temp_path));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(RecoveryError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique recovery temp file",
    )))
}

fn ensure_real_directory_or_create(root: &Path) -> Result<()> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => ensure_directory_metadata(root, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(root)?;
            ensure_real_directory(root)
        }
        Err(error) => Err(error.into()),
    }
}

fn ensure_real_directory(root: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(root)?;
    ensure_directory_metadata(root, &metadata)
}

fn ensure_directory_metadata(root: &Path, metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RecoveryError::Provider(format!(
            "vault root is not a real directory: {}",
            root.display()
        )));
    }
    Ok(())
}

fn ensure_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RecoveryError::Provider(format!(
            "{label} is not a regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_regular_file_or_missing(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => ensure_regular_file(path, label),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn sync_parent(root: &Path) -> Result<()> {
    fs::File::open(root)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_parent(root: &Path) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(root)?
        .sync_all()?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_parent(_root: &Path) -> Result<()> {
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
    fn versioned_bundle_restores_exact_dek_version() {
        let root = tmp_dir("versioned");
        fs::create_dir_all(&root).unwrap();
        let master = MasterKey::generate();

        let phrase = issue_recovery_phrase_for_version(&root, &master, 7).unwrap();
        let restored = restore_master_key_with_version(&root, &phrase).unwrap();
        assert_eq!(restored.master_key.as_bytes(), master.as_bytes());
        assert_eq!(restored.dek_version, Some(7));

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

    #[test]
    fn reissuing_recovery_atomically_replaces_the_bundle() {
        let root = tmp_dir("replace");
        fs::create_dir_all(&root).unwrap();
        let master = MasterKey::generate();

        let first = issue_recovery_phrase_for_version(&root, &master, 1).unwrap();
        let second = issue_recovery_phrase_for_version(&root, &master, 2).unwrap();

        assert!(restore_master_key_with_version(&root, &first).is_err());
        let restored = restore_master_key_with_version(&root, &second).unwrap();
        assert_eq!(restored.master_key.as_bytes(), master.as_bytes());
        assert_eq!(restored.dek_version, Some(2));
        assert!(fs::read_dir(&root).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_recovery_boundaries_are_rejected() {
        use std::os::unix::fs::symlink;

        let root = tmp_dir("symlink-bundle");
        fs::create_dir_all(&root).unwrap();
        let outside = tmp_dir("symlink-outside");
        fs::write(&outside, b"do-not-replace").unwrap();
        symlink(&outside, root.join(RECOVERY_FILE)).unwrap();

        assert!(!has_recovery_bundle(&root));
        assert!(issue_recovery_phrase(&root, &MasterKey::generate()).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"do-not-replace");

        let linked_root = tmp_dir("symlink-root");
        symlink(&root, &linked_root).unwrap();
        assert!(issue_recovery_phrase(&linked_root, &MasterKey::generate()).is_err());

        let _ = fs::remove_file(&linked_root);
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_file(&outside);
    }
}
