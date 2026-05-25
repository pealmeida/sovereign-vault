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
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sv_crypto::{open as aead_open, seal as aead_seal, MasterKey};
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
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            default_mode: SecurityMode::Direct,
            rules: Vec::new(),
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
}

impl Vault {
    /// Open an existing vault or initialise an empty one at `root`.
    ///
    /// Creates the directory and an empty `manifest.json` if needed. Does
    /// **not** generate or persist a key — that is the caller's job (see
    /// `sv-core`). The supplied key becomes the active DEK at [`KEY_VERSION`].
    pub fn open_or_init(root: &Path, master: MasterKey) -> Result<Self> {
        if !root.exists() {
            fs::create_dir_all(root)?;
        }
        let manifest_path = root.join(MANIFEST_FILE);
        if !manifest_path.exists() {
            write_manifest(root, &Manifest::default())?;
        } else {
            // Validate the manifest parses.
            let _ = read_manifest(root)?;
        }
        Ok(Self {
            root: root.to_path_buf(),
            keys: single_key_map(master),
            active_version: KEY_VERSION,
        })
    }

    /// Open an existing vault at `root`.
    ///
    /// Refuses to create missing directories or manifests. Use this when a
    /// caller expects existing data and wants missing state treated as an
    /// error instead of silently bootstrapping a new vault. The supplied key
    /// becomes the active DEK at [`KEY_VERSION`].
    pub fn open_existing(root: &Path, master: MasterKey) -> Result<Self> {
        Self::open_existing_with_keys(root, single_key_map(master), KEY_VERSION)
    }

    /// Open an existing vault with an explicit version→DEK map and active
    /// version. Used after key rotation, where multiple DEK versions must be
    /// available so files sealed under older versions remain readable.
    pub fn open_existing_with_keys(
        root: &Path,
        keys: BTreeMap<u32, MasterKey>,
        active_version: u32,
    ) -> Result<Self> {
        if !root.exists() {
            return Err(StorageError::State(format!(
                "vault root does not exist: {}",
                root.display()
            )));
        }
        if !root.is_dir() {
            return Err(StorageError::State(format!(
                "vault root is not a directory: {}",
                root.display()
            )));
        }
        let manifest_path = root.join(MANIFEST_FILE);
        if !manifest_path.exists() {
            return Err(StorageError::State(format!(
                "vault manifest missing: {}",
                manifest_path.display()
            )));
        }
        if !keys.contains_key(&active_version) {
            return Err(StorageError::State(format!(
                "active key version {active_version} not present in key map"
            )));
        }
        let _ = read_manifest(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            keys,
            active_version,
        })
    }

    /// Path to the vault root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Read the manifest from disk.
    pub fn manifest(&self) -> Result<Manifest> {
        read_manifest(&self.root)
    }

    /// Resolve the effective security mode of a container.
    pub fn container_mode(&self, container: &str) -> Result<SecurityMode> {
        validate_container_name(container)?;
        let dir = self.root.join(container);
        if !dir.exists() {
            return Err(StorageError::State(format!(
                "container does not exist: {container}"
            )));
        }
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
    /// Validates the name, creates the folder, and appends a `<name>/**`
    /// rule to the manifest with the requested mode.
    pub fn create_container(
        &self,
        name: &str,
        mode: SecurityMode,
        description: Option<String>,
    ) -> Result<()> {
        validate_container_name(name)?;
        let path = self.root.join(name);
        if path.exists() {
            return Err(StorageError::State(format!(
                "container already exists: {name}"
            )));
        }
        fs::create_dir_all(&path)?;

        let mut manifest = self.manifest()?;
        manifest.rules.retain(|r| r.pattern != format!("{name}/**"));
        manifest.rules.push(ManifestRule {
            pattern: format!("{name}/**"),
            mode,
            description,
        });
        write_manifest(&self.root, &manifest)?;
        Ok(())
    }

    /// Delete a container and remove its rule from the manifest.
    pub fn delete_container(&self, name: &str) -> Result<()> {
        validate_container_name(name)?;
        let path = self.root.join(name);
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        let mut manifest = self.manifest()?;
        manifest.rules.retain(|r| r.pattern != format!("{name}/**"));
        write_manifest(&self.root, &manifest)?;
        Ok(())
    }

    /// List files inside a container.
    pub fn list_files(&self, container: &str) -> Result<Vec<FileInfo>> {
        validate_container_name(container)?;
        let dir = self.root.join(container);
        if !dir.exists() {
            return Err(StorageError::State(format!(
                "container does not exist: {container}"
            )));
        }
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
        if !dir.exists() {
            return Err(StorageError::State(format!(
                "container does not exist: {container}"
            )));
        }
        let final_path = dir.join(format!("{file_name}{FILE_SUFFIX}"));
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

        let tmp_path = dir.join(format!(".{file_name}{FILE_SUFFIX}.tmp"));
        {
            let mut f = fs::File::create(&tmp_path)?;
            f.write_all(&envelope)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &final_path)?;
        Ok(())
    }

    /// Read and decrypt `<container>/<file_name>.svault`.
    pub fn read_file(&self, container: &str, file_name: &str) -> Result<Vec<u8>> {
        validate_container_name(container)?;
        validate_file_name(file_name)?;
        let path = self
            .root
            .join(container)
            .join(format!("{file_name}{FILE_SUFFIX}"));
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
            StorageError::State(format!(
                "no key available for key_version {key_version}"
            ))
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
        if path.exists() {
            fs::remove_file(&path)?;
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

fn read_manifest(root: &Path) -> Result<Manifest> {
    let raw = fs::read(root.join(MANIFEST_FILE))?;
    let m: Manifest = serde_json::from_slice(&raw)?;
    Ok(m)
}

fn write_manifest(root: &Path, manifest: &Manifest) -> Result<()> {
    let path = root.join(MANIFEST_FILE);
    let tmp = root.join(".manifest.json.tmp");
    let bytes = serde_json::to_vec_pretty(manifest)?;
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
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
        assert_eq!(SecurityMode::parse("APPROVAL").unwrap(), SecurityMode::Approval);
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
        v.create_container("env", SecurityMode::Direct, None).unwrap();
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
        let v = Vault::open_existing_with_keys(&root, keys, 2).unwrap();
        assert!(v.read_file("c", "f.txt").is_err());
        let _ = fs::remove_dir_all(&root);
    }
}
