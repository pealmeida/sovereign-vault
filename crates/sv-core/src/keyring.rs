//! The vault keyring: a root-key/data-key hierarchy (ADR-0007).
//!
//! Custody methods (OS keychain, passphrase) yield a **Key-Encryption Key
//! (KEK)**. The KEK never seals file data directly; instead it wraps one or
//! more versioned **Data-Encryption Keys (DEKs)** stored in `keyring.svault`.
//! Files are sealed with the active DEK (see `sv-storage`).
//!
//! This indirection makes two operations cheap:
//! - **Passphrase / KEK change**: re-wrap the DEK(s) under a new KEK. The file
//!   data is never touched ([`rewrap_under_new_kek`]).
//! - **Key rotation**: add a new DEK version and re-seal files forward
//!   ([`add_active_dek`]); old versions stay in the keyring until retired so a
//!   partially-rotated vault remains readable.
//!
//! The version numbers in the keyring are not secret — only the wrapped DEK
//! bytes are encrypted under the KEK.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64_URL},
    Engine as _,
};
use serde::{Deserialize, Serialize};
use sv_crypto::{open as aead_open, seal as aead_seal, MasterKey, MASTER_KEY_LEN};

use crate::CoreError;

/// Filename of the keyring inside the vault root.
pub const KEYRING_FILE: &str = "keyring.svault";

/// Staged keyring used by custody transactions before the commit rename.
pub const STAGED_KEYRING_FILE: &str = ".keyring.svault.next";

/// AAD bound into every wrapped-DEK envelope.
const KEYRING_AAD: &[u8] = b"sv-keyring-v1";

/// Keyring schema version.
const KEYRING_SCHEMA: u32 = 1;

type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WrappedDek {
    dek_version: u32,
    wrapped_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyringFile {
    version: u32,
    active_dek_version: u32,
    min_decryption_version: u32,
    entries: Vec<WrappedDek>,
}

/// Whether a `keyring.svault` is present at `root`.
pub fn exists(root: &Path) -> bool {
    fs::symlink_metadata(root.join(KEYRING_FILE)).is_ok()
}

/// The unwrapped contents of a keyring: every DEK version available, plus the
/// active version that new writes should use.
pub struct Unwrapped {
    /// Version → DEK, ready to hand to `sv-storage`.
    pub keys: BTreeMap<u32, MasterKey>,
    /// The active DEK version.
    pub active_version: u32,
}

impl Unwrapped {
    /// The active DEK (cloned).
    pub fn active_dek(&self) -> MasterKey {
        self.keys
            .get(&self.active_version)
            .expect("active version is always present in keys")
            .clone()
    }
}

fn keyring_path(root: &Path) -> PathBuf {
    root.join(KEYRING_FILE)
}

fn read_keyring_file(path: &Path) -> Result<KeyringFile> {
    ensure_regular_file(path, "keyring")?;
    let raw = fs::read(path)?;
    let kr: KeyringFile =
        serde_json::from_slice(&raw).map_err(|e| CoreError::Misuse(format!("keyring: {e}")))?;
    if kr.version != KEYRING_SCHEMA {
        return Err(CoreError::Misuse(format!(
            "unsupported keyring schema: {}",
            kr.version
        )));
    }
    Ok(kr)
}

fn read_keyring(root: &Path) -> Result<KeyringFile> {
    ensure_directory(root, "vault root")?;
    read_keyring_file(&keyring_path(root))
}

fn write_keyring(root: &Path, kr: &KeyringFile) -> Result<()> {
    write_keyring_to(root, &keyring_path(root), kr)
}

fn write_keyring_to(root: &Path, path: &Path, kr: &KeyringFile) -> Result<()> {
    ensure_directory(root, "vault root")?;
    ensure_destination_is_regular_or_missing(path, "keyring destination")?;
    let bytes =
        serde_json::to_vec_pretty(kr).map_err(|e| CoreError::Misuse(format!("keyring: {e}")))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| CoreError::Misuse("keyring path has an invalid filename".into()))?;
    let (tmp, mut file) = create_secure_temp(root, name)?;
    let result = (|| -> Result<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        ensure_destination_is_regular_or_missing(path, "keyring destination")?;
        atomicwrites::replace_atomic(&tmp, path)?;
        sync_parent(root)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn write_staged_keyring(root: &Path, kr: &KeyringFile) -> Result<()> {
    write_keyring_to(root, &root.join(STAGED_KEYRING_FILE), kr)
}

fn create_secure_temp(root: &Path, name: &str) -> Result<(PathBuf, fs::File)> {
    for _ in 0..16 {
        let suffix = B64_URL.encode(sv_crypto::random_bytes(12)?);
        let path = root.join(format!(".{name}.{suffix}.tmp"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(CoreError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique keyring temp file",
    )))
}

#[cfg(unix)]
fn sync_parent(root: &Path) -> Result<()> {
    fs::File::open(root)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_parent(root: &Path) -> Result<()> {
    // Windows directory fsync is a no-op; durability is handled by the OS.
    let _ = root;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_parent(_root: &Path) -> Result<()> {
    Ok(())
}

fn wrap(kek: &MasterKey, dek: &MasterKey) -> Result<String> {
    let sealed = aead_seal(kek, dek.as_bytes(), KEYRING_AAD)?;
    Ok(B64.encode(sealed))
}

fn unwrap(kek: &MasterKey, wrapped_b64: &str) -> Result<MasterKey> {
    let sealed = B64
        .decode(wrapped_b64.as_bytes())
        .map_err(|e| CoreError::Base64(e.to_string()))?;
    let raw = aead_open(kek, &sealed, KEYRING_AAD)?;
    if raw.len() != MASTER_KEY_LEN {
        return Err(CoreError::Misuse(format!(
            "unwrapped DEK has wrong length: {}",
            raw.len()
        )));
    }
    let mut bytes = [0u8; MASTER_KEY_LEN];
    bytes.copy_from_slice(&raw);
    Ok(MasterKey::from_bytes(bytes))
}

/// Create a fresh keyring wrapping `dek` (as version 1) under `kek`.
pub fn create(root: &Path, kek: &MasterKey, dek: &MasterKey) -> Result<()> {
    let kr = KeyringFile {
        version: KEYRING_SCHEMA,
        active_dek_version: 1,
        min_decryption_version: 1,
        entries: vec![WrappedDek {
            dek_version: 1,
            wrapped_b64: wrap(kek, dek)?,
        }],
    };
    write_keyring(root, &kr)
}

/// Replace the keyring with a single active DEK wrapped under `kek`.
///
/// Used by recovery repair when the existing KEK is lost: the recovery bundle
/// restores the active DEK directly, so older wrapped entries cannot be
/// unwrapped and must be discarded.
pub fn replace_with_single_active_dek(
    root: &Path,
    kek: &MasterKey,
    active_version: u32,
    dek: &MasterKey,
) -> Result<()> {
    if active_version == 0 {
        return Err(CoreError::Misuse(
            "keyring active version must be greater than zero".into(),
        ));
    }
    let kr = KeyringFile {
        version: KEYRING_SCHEMA,
        active_dek_version: active_version,
        min_decryption_version: active_version,
        entries: vec![WrappedDek {
            dek_version: active_version,
            wrapped_b64: wrap(kek, dek)?,
        }],
    };
    write_keyring(root, &kr)
}

/// Migrate a legacy vault (no keyring) whose files were sealed directly with
/// `legacy_key`. The legacy key becomes DEK v1 and is wrapped under itself as
/// the KEK — `seal(K, K)` — so the existing custody artefact (keychain entry
/// or passphrase-derived key) keeps working unchanged as the KEK. No file
/// data is re-encrypted. Idempotent: a no-op if a keyring already exists.
pub fn migrate_legacy(root: &Path, legacy_key: &MasterKey) -> Result<()> {
    if exists(root) {
        return Ok(());
    }
    create(root, legacy_key, legacy_key)
}

/// Unwrap every DEK in the keyring using `kek`.
pub fn load(root: &Path, kek: &MasterKey) -> Result<Unwrapped> {
    let kr = read_keyring(root)?;
    unwrap_keyring(&kr, kek)
}

fn unwrap_keyring(kr: &KeyringFile, kek: &MasterKey) -> Result<Unwrapped> {
    let mut keys = BTreeMap::new();
    for entry in &kr.entries {
        if entry.dek_version < kr.min_decryption_version {
            continue;
        }
        keys.insert(entry.dek_version, unwrap(kek, &entry.wrapped_b64)?);
    }
    if !keys.contains_key(&kr.active_dek_version) {
        return Err(CoreError::Misuse(
            "keyring active version is not decryptable with this key".into(),
        ));
    }
    Ok(Unwrapped {
        keys,
        active_version: kr.active_dek_version,
    })
}

/// Read the active DEK version without unwrapping anything (the version
/// numbers are not secret). Used by the recovery break-glass path.
pub fn active_version(root: &Path) -> Result<u32> {
    Ok(read_keyring(root)?.active_dek_version)
}

/// Re-wrap all DEKs under `new_kek`, replacing `old_kek`. O(1) in file data —
/// used for passphrase change and keychain re-key.
pub fn rewrap_under_new_kek(root: &Path, old_kek: &MasterKey, new_kek: &MasterKey) -> Result<()> {
    let mut kr = read_keyring(root)?;
    for entry in kr.entries.iter_mut() {
        let dek = unwrap(old_kek, &entry.wrapped_b64)?;
        entry.wrapped_b64 = wrap(new_kek, &dek)?;
    }
    write_keyring(root, &kr)
}

/// Prepare a replacement keyring under `new_kek` without changing the live
/// keyring. The staged file is durable before this function returns.
pub fn stage_rewrap_under_new_kek(
    root: &Path,
    old_kek: &MasterKey,
    new_kek: &MasterKey,
) -> Result<()> {
    let mut kr = read_keyring(root)?;
    for entry in &mut kr.entries {
        let dek = unwrap(old_kek, &entry.wrapped_b64)?;
        entry.wrapped_b64 = wrap(new_kek, &dek)?;
    }
    write_staged_keyring(root, &kr)
}

/// Test whether the staged custody keyring unwraps under `kek`.
pub fn load_staged(root: &Path, kek: &MasterKey) -> Result<Unwrapped> {
    ensure_directory(root, "vault root")?;
    let kr = read_keyring_file(&root.join(STAGED_KEYRING_FILE))?;
    unwrap_keyring(&kr, kek)
}

/// Atomically promote the staged custody keyring to the live keyring.
pub fn commit_staged(root: &Path) -> Result<()> {
    ensure_directory(root, "vault root")?;
    let staged = root.join(STAGED_KEYRING_FILE);
    let destination = keyring_path(root);
    ensure_regular_file(&staged, "staged keyring")?;
    ensure_destination_is_regular_or_missing(&destination, "keyring destination")?;
    atomicwrites::replace_atomic(&staged, &destination)?;
    sync_parent(root)
}

/// Remove any uncommitted staged custody keyring.
pub fn discard_staged(root: &Path) -> Result<()> {
    ensure_directory(root, "vault root")?;
    let staged = root.join(STAGED_KEYRING_FILE);
    match fs::symlink_metadata(&staged) {
        Ok(_) => ensure_regular_file(&staged, "staged keyring")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    match fs::remove_file(staged) {
        Ok(()) => sync_parent(root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn ensure_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CoreError::Misuse(format!("{label} does not exist: {}", path.display()))
        } else {
            error.into()
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(CoreError::Misuse(format!(
            "{label} is not a real directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CoreError::Misuse(format!("{label} does not exist: {}", path.display()))
        } else {
            error.into()
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(CoreError::Misuse(format!(
            "{label} is not a regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_destination_is_regular_or_missing(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => ensure_regular_file(path, label),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Add `new_dek` as a new version and mark it active. Returns the new version
/// number. Old versions are retained (for reading not-yet-migrated files)
/// until [`retire_below`] is called.
pub fn add_active_dek(root: &Path, kek: &MasterKey, new_dek: &MasterKey) -> Result<u32> {
    let mut kr = read_keyring(root)?;
    let new_version = kr.entries.iter().map(|e| e.dek_version).max().unwrap_or(0) + 1;
    kr.entries.push(WrappedDek {
        dek_version: new_version,
        wrapped_b64: wrap(kek, new_dek)?,
    });
    kr.active_dek_version = new_version;
    write_keyring(root, &kr)?;
    Ok(new_version)
}

/// Drop DEK versions below `min` from the keyring and raise the minimum
/// decryption version. Call after all files have been rewrapped forward.
pub fn retire_below(root: &Path, min: u32) -> Result<()> {
    let mut kr = read_keyring(root)?;
    kr.entries.retain(|e| e.dek_version >= min);
    kr.min_decryption_version = min;
    write_keyring(root, &kr)
}

/// Change only the active version while retaining every DEK entry.
pub fn set_active_version(root: &Path, version: u32) -> Result<()> {
    let mut kr = read_keyring(root)?;
    if !kr.entries.iter().any(|entry| entry.dek_version == version) {
        return Err(CoreError::Misuse(format!(
            "keyring has no DEK version {version}"
        )));
    }
    kr.active_dek_version = version;
    write_keyring(root, &kr)
}

/// Remove a non-active DEK version after a transaction rollback.
pub fn remove_version(root: &Path, version: u32) -> Result<()> {
    let mut kr = read_keyring(root)?;
    if kr.active_dek_version == version {
        return Err(CoreError::Misuse(
            "cannot remove the active DEK version".into(),
        ));
    }
    kr.entries.retain(|entry| entry.dek_version != version);
    kr.min_decryption_version = kr
        .entries
        .iter()
        .map(|entry| entry.dek_version)
        .min()
        .unwrap_or(1);
    write_keyring(root, &kr)
}
