//! Sovereign Vault storage layer.
//!
//! Defines the on-disk layout of the vault and exposes container/file
//! operations. MVP uses a whole-file envelope: `[1-byte format_version=1
//! | 4-byte key_version=1 | sealed bytes from sv-crypto::seal]`. The
//! chunked `.svault-v2` format described in ADR-003 lands later but the
//! version bytes are already in place.
//!
//! # Layout
//!
//! ```text
//! <vault_root>/
//!   manifest.json          # global manifest with default_mode + glob rules
//!   master.salt            # 16 random bytes (passphrase custody only)
//!   <container>/
//!     <file>.svault        # whole-file AEAD envelope
//!   ...
//! ```
//!
//! # Stability
//!
//! Pre-1.0. APIs subject to change.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sv_crypto::{derive_subkey, open as aead_open, seal as aead_seal, MasterKey};
use thiserror::Error;

/// Storage layer errors.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Filesystem I/O error.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    /// Manifest parse / format error.
    #[error("Manifest: {0}")]
    Manifest(String),

    /// Path traversal or invalid container/file path.
    #[error("Invalid path: {0}")]
    InvalidPath(String),

    /// Vault is in an inconsistent state (missing dir, missing manifest, etc.).
    #[error("Vault state: {0}")]
    State(String),

    /// Crypto layer failure.
    #[error(transparent)]
    Crypto(#[from] sv_crypto::CryptoError),

    /// JSON (de)serialisation failure.
    #[error("Serde: {0}")]
    Serde(String),
}

impl From<serde_json::Error> for StorageError {
    fn from(e: serde_json::Error) -> Self {
        StorageError::Serde(e.to_string())
    }
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, StorageError>;

/// Current envelope format version (whole-file MVP).
pub const FORMAT_VERSION: u8 = 1;

/// Current key version. Bumped when the master key is rotated.
pub const KEY_VERSION: u32 = 1;

/// File suffix used for encrypted blobs.
pub const FILE_SUFFIX: &str = ".svault";

/// Manifest filename inside the vault root.
pub const MANIFEST_FILE: &str = "manifest.json";

/// Salt filename inside the vault root.
pub const SALT_FILE: &str = "master.salt";

const MANIFEST_UPDATE_LOCK: &str = ".manifest-update.lock";

const MANIFEST_AUTH_CONTEXT: &[u8] = b"sv-manifest-auth-v1";
const MANIFEST_INTEGRITY_VERSION: u32 = 1;

/// Manifest schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// Effective security mode applied to a folder or file.
///
/// Aligned with ADR-005: there is one container type; the mode determines
/// how reads/writes are mediated by the UI/MCP layer above. The storage
/// crate stores the mode but does not enforce HITL — that is done by
/// higher layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SecurityMode {
    /// Direct access (no HITL).
    Direct,
    /// Human approval required.
    Approval,
    /// One-time-password approval required.
    Otp,
    /// Anonymized access (PII scrubbed).
    Anonymized,
    /// Zero-knowledge proof verification required.
    Zkp,
    /// Native device access only, no network.
    Native,
}

impl SecurityMode {
    /// Parse a security mode from a case-insensitive string.
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_uppercase().as_str() {
            "DIRECT" => Ok(Self::Direct),
            "APPROVAL" => Ok(Self::Approval),
            "OTP" => Ok(Self::Otp),
            "ANONYMIZED" => Ok(Self::Anonymized),
            "ZKP" => Ok(Self::Zkp),
            "NATIVE" => Ok(Self::Native),
            other => Err(StorageError::Manifest(format!(
                "unknown security mode: {other}"
            ))),
        }
    }

    /// Human-readable mode label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "DIRECT",
            Self::Approval => "APPROVAL",
            Self::Otp => "OTP",
            Self::Anonymized => "ANONYMIZED",
            Self::Zkp => "ZKP",
            Self::Native => "NATIVE",
        }
    }
}

/// Single rule in the manifest's rule list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRule {
    /// Glob pattern matched against `<container>/<file>` paths.
    pub pattern: String,
    /// Mode applied when the pattern matches.
    pub mode: SecurityMode,
    /// Optional description shown in the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Vault manifest — the global rules file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema version.
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    /// Default mode applied when no rule matches.
    #[serde(rename = "defaultMode")]
    pub default_mode: SecurityMode,
    /// Ordered list of rules.
    #[serde(default)]
    pub rules: Vec<ManifestRule>,
    /// Authentication metadata. Production vaults require this field and
    /// verify it before any policy value is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<ManifestIntegrity>,
}

/// Keyed integrity metadata for [`Manifest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestIntegrity {
    /// Integrity framing version.
    pub version: u32,
    /// Lowercase hexadecimal HMAC-SHA256 tag over the canonical manifest.
    #[serde(rename = "hmacSha256")]
    pub hmac_sha256: String,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            default_mode: SecurityMode::Direct,
            rules: Vec::new(),
            integrity: None,
        }
    }
}

/// Information about a container folder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    /// Container name (folder name under the vault root).
    pub name: String,
    /// Effective mode for the container (`<name>/**` rule, else default).
    pub mode: SecurityMode,
    /// Number of `.svault` files in the container.
    #[serde(rename = "fileCount")]
    pub file_count: usize,
    /// Optional description from the manifest rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Information about an encrypted file inside a container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    /// Logical file name (without the `.svault` suffix).
    pub name: String,
    /// Encrypted-blob size in bytes (envelope + nonce + tag included).
    #[serde(rename = "byteSize")]
    pub byte_size: u64,
    /// Last-modified timestamp from the filesystem.
    #[serde(rename = "modifiedAt")]
    pub modified_at: DateTime<Utc>,
    /// Effective security mode for this file.
    pub mode: SecurityMode,
}

/// Open vault handle.
///
/// Owns one or more in-memory data-encryption keys (DEKs) keyed by version,
/// plus the path to the vault root. Files are sealed with the *active* DEK
/// and recorded with that version in the envelope header; reads select the
/// DEK matching the file's recorded version, so files written before a key
/// rotation keep decrypting. Drop the handle to zeroize the keys.
pub struct Vault {
    root: PathBuf,
    keys: BTreeMap<u32, MasterKey>,
    active_version: u32,
    manifest_auth_key: MasterKey,
}

impl Vault {
    /// Open an existing vault or initialise an empty one at `root`.
    ///
    /// Creates the directory and an empty `manifest.json` if needed. Does
    /// **not** generate or persist a key — that is the caller's job (see
    /// `sv-core`). The supplied key becomes the active DEK at [`KEY_VERSION`].
    pub fn open_or_init(root: &Path, master: MasterKey) -> Result<Self> {
        let manifest_auth_key = derive_manifest_auth_key(&master);
        Self::open_or_init_with_manifest_key(root, master, manifest_auth_key)
    }

    /// Open or initialize a vault using a caller-supplied manifest
    /// authentication key. `sv-core` derives this key from its stable identity
    /// root so manifest authentication survives data-key rotation.
    pub fn open_or_init_with_manifest_key(
        root: &Path,
        master: MasterKey,
        manifest_auth_key: MasterKey,
    ) -> Result<Self> {
        match fs::symlink_metadata(root) {
            Ok(metadata) => ensure_directory_metadata(root, &metadata, "vault root")?,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                create_private_directory_all(root)?;
                ensure_directory(root, "vault root")?;
            }
            Err(error) => return Err(error.into()),
        }
        secure_directory_permissions(root)?;
        let manifest_path = root.join(MANIFEST_FILE);
        match fs::symlink_metadata(&manifest_path) {
            Ok(metadata) => {
                ensure_regular_file_metadata(&manifest_path, &metadata, "vault manifest")?;
                secure_regular_file_permissions(&manifest_path)?;
                let _ = read_manifest(root, &manifest_auth_key)?;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                write_manifest(root, &Manifest::default(), &manifest_auth_key)?;
            }
            Err(error) => return Err(error.into()),
        }
        harden_existing_storage_permissions(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            keys: single_key_map(master),
            active_version: KEY_VERSION,
            manifest_auth_key,
        })
    }

    /// Open an existing vault at `root`.
    ///
    /// Refuses to create missing directories or manifests. Use this when a
    /// caller expects existing data and wants missing state treated as an
    /// error instead of silently bootstrapping a new vault. The supplied key
    /// becomes the active DEK at [`KEY_VERSION`].
    pub fn open_existing(root: &Path, master: MasterKey) -> Result<Self> {
        let manifest_auth_key = derive_manifest_auth_key(&master);
        Self::open_existing_with_keys_and_manifest_key(
            root,
            single_key_map(master),
            KEY_VERSION,
            manifest_auth_key,
        )
    }

    /// Open an existing vault with an explicit version→DEK map and active
    /// version. Used after key rotation, where multiple DEK versions must be
    /// available so files sealed under older versions remain readable.
    pub fn open_existing_with_keys(
        root: &Path,
        keys: BTreeMap<u32, MasterKey>,
        active_version: u32,
    ) -> Result<Self> {
        if !keys.contains_key(&active_version) {
            return Err(StorageError::State(format!(
                "active key version {active_version} not present in key map"
            )));
        }
        let manifest_material = keys.first_key_value().map(|(_, key)| key).ok_or_else(|| {
            StorageError::State(format!(
                "active key version {active_version} not present in empty key map"
            ))
        })?;
        let manifest_auth_key = derive_manifest_auth_key(manifest_material);
        Self::open_existing_with_keys_and_manifest_key(
            root,
            keys,
            active_version,
            manifest_auth_key,
        )
    }

    /// Open an existing multi-key vault with a caller-supplied stable manifest
    /// authentication key.
    pub fn open_existing_with_keys_and_manifest_key(
        root: &Path,
        keys: BTreeMap<u32, MasterKey>,
        active_version: u32,
        manifest_auth_key: MasterKey,
    ) -> Result<Self> {
        ensure_directory(root, "vault root")?;
        secure_directory_permissions(root)?;
        let manifest_path = root.join(MANIFEST_FILE);
        ensure_regular_file(&manifest_path, "vault manifest")?;
        secure_regular_file_permissions(&manifest_path)?;
        if !keys.contains_key(&active_version) {
            return Err(StorageError::State(format!(
                "active key version {active_version} not present in key map"
            )));
        }
        let _ = read_manifest(root, &manifest_auth_key)?;
        harden_existing_storage_permissions(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            keys,
            active_version,
            manifest_auth_key,
        })
    }

    /// Path to the vault root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Read the manifest from disk.
    pub fn manifest(&self) -> Result<Manifest> {
        read_manifest(&self.root, &self.manifest_auth_key)
    }

    /// Resolve the effective security mode of a container.
    pub fn container_mode(&self, container: &str) -> Result<SecurityMode> {
        validate_container_name(container)?;
        let dir = self.root.join(container);
        ensure_directory(&dir, "container")?;
        let manifest = self.manifest()?;
        let rule_index = container_rule_index(&manifest);
        Ok(rule_index
            .get(container)
            .map(|r| r.mode)
            .unwrap_or(manifest.default_mode))
    }

    /// List containers inside the vault.
    pub fn list_containers(&self) -> Result<Vec<ContainerInfo>> {
        let manifest = self.manifest()?;
        let rule_index = container_rule_index(&manifest);
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if !is_valid_container_name(&name) {
                continue;
            }
            let (mode, description) = rule_index
                .get(&name)
                .map(|r| (r.mode, r.description.clone()))
                .unwrap_or((manifest.default_mode, None));
            let file_count = count_files(&entry.path())?;
            out.push(ContainerInfo {
                name,
                mode,
                file_count,
                description,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Create a new container.
    ///
    /// Validates the name, persists a `<name>/**` rule with the requested mode,
    /// and then creates the folder.
    pub fn create_container(
        &self,
        name: &str,
        mode: SecurityMode,
        description: Option<String>,
    ) -> Result<()> {
        validate_container_name(name)?;
        let _manifest_lock = ManifestUpdateLock::acquire(&self.root)?;
        let path = self.root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(StorageError::State(format!(
                    "container already exists: {name}"
                )))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut manifest = self.manifest()?;
        manifest.rules.retain(|r| r.pattern != format!("{name}/**"));
        manifest.rules.push(ManifestRule {
            pattern: format!("{name}/**"),
            mode,
            description,
        });
        write_manifest(&self.root, &manifest, &self.manifest_auth_key)?;
        // Commit policy before visibility. If directory creation fails, the
        // inert rule is safe and a retry can complete the operation. The
        // opposite order could expose a protected container as default-mode.
        create_private_directory(&path)?;
        sync_directory(&self.root)?;
        Ok(())
    }

    /// Delete a container and remove its rule from the manifest.
    pub fn delete_container(&self, name: &str) -> Result<()> {
        validate_container_name(name)?;
        let _manifest_lock = ManifestUpdateLock::acquire(&self.root)?;
        let path = self.root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                ensure_directory_metadata(&path, &metadata, "container")?;
                fs::remove_dir_all(&path)?;
                sync_directory(&self.root)?;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut manifest = self.manifest()?;
        manifest.rules.retain(|r| r.pattern != format!("{name}/**"));
        write_manifest(&self.root, &manifest, &self.manifest_auth_key)?;
        Ok(())
    }

    /// List files inside a container.
    pub fn list_files(&self, container: &str) -> Result<Vec<FileInfo>> {
        validate_container_name(container)?;
        let dir = self.root.join(container);
        ensure_directory(&dir, "container")?;
        let mode = self.container_mode(container)?;
        let mut out = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let fname = entry.file_name().to_string_lossy().to_string();
            let Some(stem) = fname.strip_suffix(FILE_SUFFIX) else {
                continue;
            };
            let meta = entry.metadata()?;
            let modified_at: DateTime<Utc> = meta
                .modified()
                .map(DateTime::<Utc>::from)
                .unwrap_or_else(|_| Utc::now());
            out.push(FileInfo {
                name: stem.to_string(),
                byte_size: meta.len(),
                modified_at,
                mode,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Encrypt and write `plaintext` to `<container>/<file_name>.svault`.
    ///
    /// Atomic via tempfile + rename. AAD binds the logical path so a
    /// blob renamed across containers will fail to decrypt.
    pub fn write_file(&self, container: &str, file_name: &str, plaintext: &[u8]) -> Result<()> {
        validate_container_name(container)?;
        validate_file_name(file_name)?;
        let dir = self.root.join(container);
        ensure_directory(&dir, "container")?;
        let final_path = dir.join(format!("{file_name}{FILE_SUFFIX}"));
        ensure_destination_is_regular_or_missing(&final_path, "vault file")?;
        let aad = aad_for(container, file_name);
        let active_key = self.keys.get(&self.active_version).ok_or_else(|| {
            StorageError::State(format!(
                "active key version {} not present",
                self.active_version
            ))
        })?;
        let sealed = aead_seal(active_key, plaintext, aad.as_bytes())?;

        let mut envelope = Vec::with_capacity(1 + 4 + sealed.len());
        envelope.push(FORMAT_VERSION);
        envelope.extend_from_slice(&self.active_version.to_be_bytes());
        envelope.extend_from_slice(&sealed);

        atomic_write(&final_path, &envelope)?;
        secure_regular_file_permissions(&final_path)
    }

    /// Read and decrypt `<container>/<file_name>.svault`.
    pub fn read_file(&self, container: &str, file_name: &str) -> Result<Vec<u8>> {
        validate_container_name(container)?;
        validate_file_name(file_name)?;
        let path = self
            .root
            .join(container)
            .join(format!("{file_name}{FILE_SUFFIX}"));
        ensure_directory(&self.root.join(container), "container")?;
        ensure_regular_file(&path, "vault file")?;
        let raw = fs::read(&path)?;
        if raw.len() < 1 + 4 {
            return Err(StorageError::State("envelope too short".into()));
        }
        let format_version = raw[0];
        if format_version != FORMAT_VERSION {
            return Err(StorageError::State(format!(
                "unsupported format_version: {format_version}"
            )));
        }
        let mut kv = [0u8; 4];
        kv.copy_from_slice(&raw[1..5]);
        let key_version = u32::from_be_bytes(kv);
        let key = self.keys.get(&key_version).ok_or_else(|| {
            StorageError::State(format!("no key available for key_version {key_version}"))
        })?;
        let sealed = &raw[5..];
        let aad = aad_for(container, file_name);
        let pt = aead_open(key, sealed, aad.as_bytes())?;
        Ok(pt)
    }

    /// Delete a file inside a container.
    pub fn delete_file(&self, container: &str, file_name: &str) -> Result<()> {
        validate_container_name(container)?;
        validate_file_name(file_name)?;
        let path = self
            .root
            .join(container)
            .join(format!("{file_name}{FILE_SUFFIX}"));
        let dir = self.root.join(container);
        ensure_directory(&dir, "container")?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                ensure_regular_file_metadata(&path, &metadata, "vault file")?;
                fs::remove_file(&path)?;
                sync_directory(&dir)?;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    /// The active DEK version files are currently sealed under.
    pub fn active_version(&self) -> u32 {
        self.active_version
    }

    /// Derive a 32-byte subkey from the active DEK for a given context.
    ///
    /// Does not expose the DEK itself; callers receive only the derived
    /// subkey (HKDF-SHA256, see [`sv_crypto::derive_subkey`]).
    pub fn derive_subkey(&self, context: &[u8]) -> [u8; 32] {
        let active_key = self
            .keys
            .get(&self.active_version)
            .expect("active key version is always present (checked at open)");
        sv_crypto::derive_subkey(active_key, context)
    }

    /// Re-seal a file under the active DEK if it is sealed under an older
    /// version. Returns `true` if the file was rewrapped, `false` if it was
    /// already at the active version. Used to migrate files forward after a
    /// key rotation without forcing a bulk rewrite up front.
    pub fn rewrap_file(&self, container: &str, file_name: &str) -> Result<bool> {
        validate_container_name(container)?;
        validate_file_name(file_name)?;
        let path = self
            .root
            .join(container)
            .join(format!("{file_name}{FILE_SUFFIX}"));
        let raw = fs::read(&path)?;
        if raw.len() >= 5 {
            let mut kv = [0u8; 4];
            kv.copy_from_slice(&raw[1..5]);
            if u32::from_be_bytes(kv) == self.active_version {
                return Ok(false);
            }
        }
        let plaintext = self.read_file(container, file_name)?;
        self.write_file(container, file_name, &plaintext)?;
        Ok(true)
    }
}

fn single_key_map(master: MasterKey) -> BTreeMap<u32, MasterKey> {
    let mut m = BTreeMap::new();
    m.insert(KEY_VERSION, master);
    m
}

fn aad_for(container: &str, file_name: &str) -> String {
    format!("{container}/{file_name}")
}

fn count_files(dir: &Path) -> Result<usize> {
    let mut n = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry.file_name().to_string_lossy().ends_with(FILE_SUFFIX)
        {
            n += 1;
        }
    }
    Ok(n)
}

fn container_rule_index(manifest: &Manifest) -> BTreeMap<String, ManifestRule> {
    let mut out = BTreeMap::new();
    for rule in &manifest.rules {
        if let Some(name) = rule.pattern.strip_suffix("/**") {
            out.insert(name.to_string(), rule.clone());
        }
    }
    out
}

/// Derive the dedicated manifest-authentication key from stable vault key
/// material. Callers should pass the persistent identity root, not a rotating
/// data key, when one is available.
pub fn derive_manifest_auth_key(material: &MasterKey) -> MasterKey {
    MasterKey::from_bytes(derive_subkey(material, MANIFEST_AUTH_CONTEXT))
}

/// Return the canonical SHA-256 digest of a manifest without its integrity
/// field. This digest is the explicit confirmation token for one-time legacy
/// manifest migration.
pub fn manifest_migration_digest(root: &Path) -> Result<String> {
    let manifest = read_manifest_unverified(root)?;
    Ok(hex_encode(&Sha256::digest(manifest_auth_bytes(&manifest)?)))
}

/// Validate a candidate key against one encrypted file in a pre-keyring
/// vault without trusting the unauthenticated manifest policy. Empty legacy
/// vaults have no ciphertext verifier, so successful explicit digest review
/// remains the only available confirmation in that case.
pub fn validate_legacy_vault_key(root: &Path, candidate: &MasterKey) -> Result<()> {
    let _ = read_manifest_unverified(root)?;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(container) = name.to_str() else {
            continue;
        };
        if !is_valid_container_name(container) {
            continue;
        }
        let container_path = entry.path();
        let metadata = fs::symlink_metadata(&container_path)?;
        ensure_directory_metadata(&container_path, &metadata, "legacy container")?;
        for file in fs::read_dir(&container_path)? {
            let file = file?;
            let file_name = file.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };
            let Some(logical_name) = file_name.strip_suffix(FILE_SUFFIX) else {
                continue;
            };
            validate_file_name(logical_name)?;
            let path = file.path();
            let metadata = fs::symlink_metadata(&path)?;
            ensure_regular_file_metadata(&path, &metadata, "legacy vault file")?;
            let raw = fs::read(path)?;
            if raw.len() < 5 {
                return Err(StorageError::State("legacy envelope too short".into()));
            }
            if raw[0] != FORMAT_VERSION {
                return Err(StorageError::State(format!(
                    "unsupported legacy format_version: {}",
                    raw[0]
                )));
            }
            let mut version = [0u8; 4];
            version.copy_from_slice(&raw[1..5]);
            if u32::from_be_bytes(version) != KEY_VERSION {
                return Err(StorageError::State(
                    "legacy vault file does not use key version 1".into(),
                ));
            }
            aead_open(
                candidate,
                &raw[5..],
                aad_for(container, logical_name).as_bytes(),
            )?;
            return Ok(());
        }
    }
    Ok(())
}

/// Authenticate one exact legacy manifest after an operator has reviewed its
/// canonical digest. This never runs implicitly during vault open.
pub fn migrate_legacy_manifest(
    root: &Path,
    manifest_auth_key: &MasterKey,
    expected_sha256: &str,
) -> Result<()> {
    let expected = decode_hex_32(expected_sha256, "expected manifest SHA-256")?;
    let _manifest_lock = ManifestUpdateLock::acquire(root)?;
    let manifest = read_manifest_unverified(root)?;
    let actual = Sha256::digest(manifest_auth_bytes(&manifest)?);
    if actual.as_slice() != expected {
        return Err(StorageError::Manifest(
            "legacy manifest changed after review; migration digest does not match".into(),
        ));
    }

    if manifest.integrity.is_some() {
        verify_manifest_integrity(&manifest, manifest_auth_key)?;
        return Ok(());
    }
    write_manifest(root, &manifest, manifest_auth_key)
}

fn read_manifest_unverified(root: &Path) -> Result<Manifest> {
    ensure_directory(root, "vault root")?;
    let path = root.join(MANIFEST_FILE);
    ensure_regular_file(&path, "vault manifest")?;
    secure_regular_file_permissions(&path)?;
    let raw = fs::read(path)?;
    let manifest: Manifest = serde_json::from_slice(&raw)?;
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(StorageError::Manifest(format!(
            "unsupported manifest schema: {}",
            manifest.schema_version
        )));
    }
    Ok(manifest)
}

fn read_manifest(root: &Path, manifest_auth_key: &MasterKey) -> Result<Manifest> {
    let manifest = read_manifest_unverified(root)?;
    verify_manifest_integrity(&manifest, manifest_auth_key)?;
    Ok(manifest)
}

fn write_manifest(root: &Path, manifest: &Manifest, manifest_auth_key: &MasterKey) -> Result<()> {
    ensure_directory(root, "vault root")?;
    let path = root.join(MANIFEST_FILE);
    ensure_destination_is_regular_or_missing(&path, "vault manifest")?;
    let mut authenticated = manifest.clone();
    authenticated.integrity = None;
    let tag = manifest_hmac(manifest_auth_key, &authenticated)?;
    authenticated.integrity = Some(ManifestIntegrity {
        version: MANIFEST_INTEGRITY_VERSION,
        hmac_sha256: hex_encode(&tag),
    });
    let bytes = serde_json::to_vec_pretty(&authenticated)?;
    atomic_write(&path, &bytes)?;
    secure_regular_file_permissions(&path)
}

fn verify_manifest_integrity(manifest: &Manifest, manifest_auth_key: &MasterKey) -> Result<()> {
    let integrity = manifest.integrity.as_ref().ok_or_else(|| {
        StorageError::Manifest(
            "manifest authentication is missing; explicit legacy migration is required".into(),
        )
    })?;
    if integrity.version != MANIFEST_INTEGRITY_VERSION {
        return Err(StorageError::Manifest(format!(
            "unsupported manifest integrity version: {}",
            integrity.version
        )));
    }
    let tag = decode_hex_32(&integrity.hmac_sha256, "manifest HMAC-SHA256")?;
    let mut unsigned = manifest.clone();
    unsigned.integrity = None;
    let bytes = manifest_auth_bytes(&unsigned)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(manifest_auth_key.as_bytes())
        .map_err(|error| StorageError::Manifest(format!("manifest HMAC key: {error}")))?;
    mac.update(&bytes);
    mac.verify_slice(&tag)
        .map_err(|_| StorageError::Manifest("manifest authentication failed".into()))
}

fn manifest_hmac(manifest_auth_key: &MasterKey, manifest: &Manifest) -> Result<[u8; 32]> {
    let bytes = manifest_auth_bytes(manifest)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(manifest_auth_key.as_bytes())
        .map_err(|error| StorageError::Manifest(format!("manifest HMAC key: {error}")))?;
    mac.update(&bytes);
    Ok(mac.finalize().into_bytes().into())
}

fn manifest_auth_bytes(manifest: &Manifest) -> Result<Vec<u8>> {
    let mut unsigned = manifest.clone();
    unsigned.integrity = None;
    serde_json::to_vec(&unsigned).map_err(Into::into)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex_32(encoded: &str, label: &str) -> Result<[u8; 32]> {
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StorageError::Manifest(format!(
            "{label} must be exactly 64 hexadecimal characters"
        )));
    }
    let mut out = [0u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| StorageError::Manifest(format!("{label} is not valid UTF-8")))?;
        out[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| StorageError::Manifest(format!("{label} is not hexadecimal")))?;
    }
    Ok(out)
}

fn ensure_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == ErrorKind::NotFound {
            StorageError::State(format!("{label} does not exist: {}", path.display()))
        } else {
            error.into()
        }
    })?;
    ensure_directory_metadata(path, &metadata, label)
}

fn ensure_directory_metadata(path: &Path, metadata: &fs::Metadata, label: &str) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(StorageError::State(format!(
            "{label} is not a real directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == ErrorKind::NotFound {
            StorageError::State(format!("{label} does not exist: {}", path.display()))
        } else {
            error.into()
        }
    })?;
    ensure_regular_file_metadata(path, &metadata, label)
}

fn ensure_regular_file_metadata(path: &Path, metadata: &fs::Metadata, label: &str) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(StorageError::State(format!(
            "{label} is not a regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_destination_is_regular_or_missing(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => ensure_regular_file_metadata(path, &metadata, label),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn harden_existing_storage_permissions(root: &Path) -> Result<()> {
    secure_directory_permissions(root)?;
    secure_regular_file_permissions(&root.join(MANIFEST_FILE))?;
    let lock = root.join(MANIFEST_UPDATE_LOCK);
    match fs::symlink_metadata(&lock) {
        Ok(metadata) => {
            ensure_regular_file_metadata(&lock, &metadata, "manifest update lock")?;
            secure_regular_file_permissions(&lock)?;
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_valid_container_name(name) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        ensure_directory_metadata(&path, &metadata, "container")?;
        secure_directory_permissions(&path)?;
        for file in fs::read_dir(&path)? {
            let file = file?;
            if !file.file_name().to_string_lossy().ends_with(FILE_SUFFIX) {
                continue;
            }
            let file_path = file.path();
            let metadata = fs::symlink_metadata(&file_path)?;
            ensure_regular_file_metadata(&file_path, &metadata, "vault file")?;
            secure_regular_file_permissions(&file_path)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)?;
    secure_directory_permissions(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    Ok(())
}

#[cfg(unix)]
fn create_private_directory_all(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(path)?;
    secure_directory_permissions(path)
}

#[cfg(not(unix))]
fn create_private_directory_all(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    Ok(())
}

#[cfg(unix)]
fn secure_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = fs::symlink_metadata(path)?;
    ensure_directory_metadata(path, &metadata, "permission target")?;
    if metadata.permissions().mode() & 0o777 != 0o700 {
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn secure_regular_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = fs::symlink_metadata(path)?;
    ensure_regular_file_metadata(path, &metadata, "permission target")?;
    if metadata.permissions().mode() & 0o777 != 0o600 {
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_regular_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| StorageError::State(format!("path has no parent: {}", path.display())))?;
    ensure_directory(parent, "destination parent")?;

    let mut temp = create_unique_temp_file(parent)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|error| error.error)?;
    sync_directory(parent)
}

fn create_unique_temp_file(parent: &Path) -> Result<tempfile::NamedTempFile> {
    for _ in 0..16 {
        let nonce = sv_crypto::random_bytes(16)?;
        let suffix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = parent.join(format!(".sv-write-{suffix}.tmp"));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => {
                let temp_path = tempfile::TempPath::try_from_path(path)?;
                return Ok(tempfile::NamedTempFile::from_parts(file, temp_path));
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(StorageError::State(
        "unable to allocate a unique temporary file".into(),
    ))
}

struct ManifestUpdateLock {
    file: fs::File,
}

impl ManifestUpdateLock {
    fn acquire(root: &Path) -> Result<Self> {
        ensure_directory(root, "vault root")?;
        let path = root.join(MANIFEST_UPDATE_LOCK);
        let existed = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                ensure_regular_file_metadata(&path, &metadata, "manifest update lock")?;
                secure_regular_file_permissions(&path)?;
                true
            }
            Err(error) if error.kind() == ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };

        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        if !file.metadata()?.is_file() {
            return Err(StorageError::State(format!(
                "manifest update lock is not a regular file: {}",
                path.display()
            )));
        }
        if !existed {
            sync_directory(root)?;
        }

        match fs4::FileExt::try_lock(&file) {
            Ok(()) => Ok(Self { file }),
            Err(fs4::TryLockError::WouldBlock) => Err(StorageError::State(
                "another process is updating the vault manifest".into(),
            )),
            Err(fs4::TryLockError::Error(error)) => Err(error.into()),
        }
    }
}

impl Drop for ManifestUpdateLock {
    fn drop(&mut self) {
        let _ = fs4::FileExt::unlock(&self.file);
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

/// Validate a container name. Allowed: `[A-Za-z0-9_-]`, length 1-64.
pub fn is_valid_container_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn validate_container_name(name: &str) -> Result<()> {
    if is_valid_container_name(name) {
        Ok(())
    } else {
        Err(StorageError::InvalidPath(format!(
            "invalid container name: {name:?}"
        )))
    }
}

/// Validate a file name. Allows `.` anywhere — including a leading dot, so
/// dotfiles such as `.env` are storable. Still forbids the traversal names
/// `.`/`..`, any `..` sequence, and path separators (only `[A-Za-z0-9._-]`).
pub fn is_valid_file_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    if name == "." || name == ".." {
        return false;
    }
    if name.contains("..") {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fn validate_file_name(name: &str) -> Result<()> {
    if is_valid_file_name(name) {
        Ok(())
    } else {
        Err(StorageError::InvalidPath(format!(
            "invalid file name: {name:?}"
        )))
    }
}

/// Crate version string.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tmp_dir(label: &str) -> PathBuf {
        let mut p = env::temp_dir();
        let nonce = sv_crypto::random_bytes(8).unwrap();
        let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        p.push(format!("sv-storage-test-{label}-{hex}"));
        p
    }

    #[test]
    fn roundtrip_file_in_container() {
        let root = tmp_dir("rt");
        let key = MasterKey::generate();
        let v = Vault::open_or_init(&root, key).unwrap();
        v.create_container("notes", SecurityMode::Direct, Some("test".into()))
            .unwrap();
        v.write_file("notes", "hello.txt", b"sovereign").unwrap();
        let got = v.read_file("notes", "hello.txt").unwrap();
        assert_eq!(got, b"sovereign");
        let files = v.list_files("notes").unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "hello.txt");
        assert_eq!(files[0].mode, SecurityMode::Direct);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn list_containers_reports_modes() {
        let root = tmp_dir("lc");
        let key = MasterKey::generate();
        let v = Vault::open_or_init(&root, key).unwrap();
        v.create_container("alpha", SecurityMode::Direct, None)
            .unwrap();
        v.create_container("beta", SecurityMode::Otp, Some("approve me".into()))
            .unwrap();
        let cs = v.list_containers().unwrap();
        assert_eq!(cs.len(), 2);
        assert_eq!(cs[0].name, "alpha");
        assert_eq!(cs[0].mode, SecurityMode::Direct);
        assert_eq!(cs[1].name, "beta");
        assert_eq!(cs[1].mode, SecurityMode::Otp);
        assert_eq!(cs[1].description.as_deref(), Some("approve me"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn aad_mismatch_fails_decrypt() {
        let root = tmp_dir("aad");
        let key = MasterKey::generate();
        let v = Vault::open_or_init(&root, key).unwrap();
        v.create_container("c1", SecurityMode::Direct, None)
            .unwrap();
        v.create_container("c2", SecurityMode::Direct, None)
            .unwrap();
        v.write_file("c1", "f", b"secret").unwrap();
        // Move the blob to c2; AAD now mismatches.
        let from = root.join("c1").join(format!("f{FILE_SUFFIX}"));
        let to = root.join("c2").join(format!("f{FILE_SUFFIX}"));
        fs::rename(&from, &to).unwrap();
        assert!(v.read_file("c2", "f").is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_path_traversal() {
        let root = tmp_dir("pj");
        let key = MasterKey::generate();
        let v = Vault::open_or_init(&root, key).unwrap();
        assert!(v
            .create_container("..", SecurityMode::Direct, None)
            .is_err());
        assert!(v
            .create_container("a/b", SecurityMode::Direct, None)
            .is_err());
        v.create_container("ok", SecurityMode::Direct, None)
            .unwrap();
        assert!(v.write_file("ok", "../escape", b"x").is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn open_existing_rejects_missing_manifest() {
        let root = tmp_dir("existing");
        fs::create_dir_all(&root).unwrap();
        let key = MasterKey::generate();

        assert!(Vault::open_existing(&root, key).is_err());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn parses_approval_mode() {
        assert_eq!(
            SecurityMode::parse("APPROVAL").unwrap(),
            SecurityMode::Approval
        );
    }

    #[test]
    fn rotated_vault_reads_old_and_writes_new_version() {
        let root = tmp_dir("rotate");
        let dek_v1 = MasterKey::generate();
        // Write a file under v1.
        {
            let v = Vault::open_or_init(&root, dek_v1.clone()).unwrap();
            v.create_container("c", SecurityMode::Direct, None).unwrap();
            v.write_file("c", "old.txt", b"v1-data").unwrap();
        }
        // Reopen with v1 + v2, active = v2.
        let dek_v2 = MasterKey::generate();
        let mut keys = BTreeMap::new();
        keys.insert(1u32, dek_v1);
        keys.insert(2u32, dek_v2);
        let v = Vault::open_existing_with_keys(&root, keys, 2).unwrap();
        assert_eq!(v.active_version(), 2);
        // Old file (sealed under v1) still decrypts.
        assert_eq!(v.read_file("c", "old.txt").unwrap(), b"v1-data");
        // New file is sealed under v2.
        v.write_file("c", "new.txt", b"v2-data").unwrap();
        let raw = fs::read(root.join("c").join(format!("new.txt{FILE_SUFFIX}"))).unwrap();
        assert_eq!(u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]), 2);
        // rewrap migrates the old file forward to v2; reading still works.
        assert!(v.rewrap_file("c", "old.txt").unwrap());
        assert!(!v.rewrap_file("c", "old.txt").unwrap());
        assert_eq!(v.read_file("c", "old.txt").unwrap(), b"v1-data");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn derive_subkey_matches_for_same_active_key() {
        let root_a = tmp_dir("subkey-a");
        let root_b = tmp_dir("subkey-b");
        let key = MasterKey::from_bytes([9u8; 32]);
        let va = Vault::open_or_init(&root_a, key.clone()).unwrap();
        let vb = Vault::open_or_init(&root_b, key).unwrap();
        assert_eq!(
            va.derive_subkey(b"sv-audit-hmac-v1"),
            vb.derive_subkey(b"sv-audit-hmac-v1")
        );
        assert_ne!(
            va.derive_subkey(b"sv-audit-hmac-v1"),
            va.derive_subkey(b"other")
        );
        let _ = fs::remove_dir_all(&root_a);
        let _ = fs::remove_dir_all(&root_b);
    }

    #[test]
    fn dotfiles_are_storable() {
        assert!(is_valid_file_name(".env"));
        assert!(is_valid_file_name(".gitignore"));
        assert!(!is_valid_file_name("."));
        assert!(!is_valid_file_name(".."));
        assert!(!is_valid_file_name("..env"));
        assert!(!is_valid_file_name("a/b"));

        let root = tmp_dir("dotenv");
        let v = Vault::open_or_init(&root, MasterKey::generate()).unwrap();
        v.create_container("env", SecurityMode::Direct, None)
            .unwrap();
        v.write_file("env", ".env", b"API_KEY=fake").unwrap();
        assert_eq!(v.read_file("env", ".env").unwrap(), b"API_KEY=fake");
        let files = v.list_files("env").unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, ".env");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_key_version_is_rejected() {
        let root = tmp_dir("missingver");
        let dek_v1 = MasterKey::generate();
        {
            let v = Vault::open_or_init(&root, dek_v1).unwrap();
            v.create_container("c", SecurityMode::Direct, None).unwrap();
            v.write_file("c", "f.txt", b"data").unwrap();
        }
        // Reopen with only v2 — the v1 file has no available key.
        let mut keys = BTreeMap::new();
        keys.insert(2u32, MasterKey::generate());
        assert!(Vault::open_existing_with_keys(&root, keys, 2).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn atomic_writes_leave_no_predictable_temp_files() {
        let root = tmp_dir("atomic-cleanup");
        let vault = Vault::open_or_init(&root, MasterKey::generate()).unwrap();
        vault
            .create_container("notes", SecurityMode::Approval, None)
            .unwrap();
        vault.write_file("notes", "a.txt", b"first").unwrap();
        vault.write_file("notes", "a.txt", b"second").unwrap();

        assert_eq!(vault.read_file("notes", "a.txt").unwrap(), b"second");
        for dir in [&root, &root.join("notes")] {
            assert!(fs::read_dir(dir).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp")));
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn concurrent_manifest_mutation_fails_closed() {
        let root = tmp_dir("manifest-lock");
        let vault = Vault::open_or_init(&root, MasterKey::generate()).unwrap();
        let manifest_lock = ManifestUpdateLock::acquire(&root).unwrap();

        assert!(vault
            .create_container("protected", SecurityMode::Approval, None)
            .is_err());
        assert!(!root.join("protected").exists());
        drop(manifest_lock);

        vault
            .create_container("protected", SecurityMode::Approval, None)
            .unwrap();
        assert_eq!(
            vault.container_mode("protected").unwrap(),
            SecurityMode::Approval
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn manifest_lock_crash_helper() {
        let Some(root) = env::var_os("SV_STORAGE_MANIFEST_LOCK_CRASH_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let _lock = ManifestUpdateLock::acquire(&root).unwrap();
        fs::write(root.join("lock-ready"), b"ready").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(60));
    }

    #[test]
    fn manifest_lock_is_released_when_holder_process_dies() {
        use std::process::{Child, Command, Stdio};

        struct ChildGuard(Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let root = tmp_dir("manifest-lock-crash");
        let _vault = Vault::open_or_init(&root, MasterKey::generate()).unwrap();
        let child = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::manifest_lock_crash_helper",
                "--nocapture",
            ])
            .env("SV_STORAGE_MANIFEST_LOCK_CRASH_ROOT", &root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut child = ChildGuard(child);

        let ready = root.join("lock-ready");
        for _ in 0..200 {
            if ready.exists() {
                break;
            }
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "lock helper exited early"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(ready.exists(), "lock helper did not acquire the lock");
        assert!(ManifestUpdateLock::acquire(&root).is_err());

        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let recovered = ManifestUpdateLock::acquire(&root).unwrap();
        drop(recovered);

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_vault_boundaries_are_rejected() {
        use std::os::unix::fs::symlink;

        let outside = tmp_dir("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.svault"), b"outside").unwrap();

        let root_link = tmp_dir("root-link");
        symlink(&outside, &root_link).unwrap();
        assert!(Vault::open_or_init(&root_link, MasterKey::generate()).is_err());
        fs::remove_file(&root_link).unwrap();

        let root = tmp_dir("symlink-boundaries");
        let vault = Vault::open_or_init(&root, MasterKey::generate()).unwrap();
        symlink(
            outside.join("secret.svault"),
            root.join(MANIFEST_UPDATE_LOCK),
        )
        .unwrap();
        assert!(vault
            .create_container("blocked", SecurityMode::Approval, None)
            .is_err());
        fs::remove_file(root.join(MANIFEST_UPDATE_LOCK)).unwrap();
        symlink(&outside, root.join("linked")).unwrap();
        assert!(vault.container_mode("linked").is_err());
        assert!(vault.list_files("linked").is_err());
        assert!(vault.write_file("linked", "secret", b"overwrite").is_err());
        assert!(vault.delete_container("linked").is_err());
        assert_eq!(fs::read(outside.join("secret.svault")).unwrap(), b"outside");

        vault
            .create_container("real", SecurityMode::Direct, None)
            .unwrap();
        symlink(outside.join("secret.svault"), root.join("real/item.svault")).unwrap();
        assert!(vault.read_file("real", "item").is_err());
        assert!(vault.write_file("real", "item", b"overwrite").is_err());
        assert!(vault.delete_file("real", "item").is_err());
        assert_eq!(fs::read(outside.join("secret.svault")).unwrap(), b"outside");

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_manifest_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = tmp_dir("manifest-link");
        fs::create_dir_all(&root).unwrap();
        let outside = tmp_dir("manifest-outside");
        fs::write(&outside, serde_json::to_vec(&Manifest::default()).unwrap()).unwrap();
        symlink(&outside, root.join(MANIFEST_FILE)).unwrap();

        assert!(Vault::open_or_init(&root, MasterKey::generate()).is_err());

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_file(&outside);
    }
}
