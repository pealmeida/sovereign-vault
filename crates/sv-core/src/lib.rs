//! High-level integration crate for Sovereign Vault.
//!
//! Embeds the storage, crypto, keychain, recovery, audit, MCP, and HTTP
//! layers behind a single [`VaultHandle`] facade so apps (`apps/desktop`,
//! `apps/cli`, future mobile) depend on this crate alone.
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

pub mod agents;
pub mod broker;
pub mod keyring;
pub mod transit;

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
use sha2::{Digest, Sha256};
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

    /// Another process already holds this vault's exclusive lock.
    #[error("vault is already open by another process ({0})")]
    VaultLocked(PathBuf),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, CoreError>;

const SALT_FILENAME: &str = "master.salt";
const LIFECYCLE_FILE: &str = ".lifecycle.json";
const LIFECYCLE_AAD: &[u8] = b"sv-lifecycle-phrase-v1";
const VAULT_LOCK_FILE: &str = ".vault.lock";

/// Minimum Unicode scalar-value count accepted for newly configured
/// passphrases. Existing vaults with older, shorter passphrases remain
/// unlockable for backward compatibility.
pub const MIN_PASSPHRASE_CHARS: usize = 16;

/// HKDF context for the key under which transit/signing/broker material is
/// sealed. Derived from the active DEK, so rotation must re-wrap material
/// forward (see [`transit::rewrap_all_material`]).
const MATERIAL_WRAP_CONTEXT: &[u8] = b"sv-transit-wrap-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum LifecycleJournal {
    Bootstrap {
        custody: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        salt_b64: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scoped_kek_fingerprint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wrapped_phrase_b64: Option<String>,
    },
    ChangePassphrase {
        old_salt_b64: String,
        new_salt_b64: String,
    },
    MoveToKeychain,
    Rotate {
        old_version: u32,
        new_version: u32,
        recovery_backup_b64: String,
    },
}

/// Live, unlocked vault handle.
///
/// Owns an open [`Vault`] (and therefore the master key). Drop the
/// handle to lock the vault — the underlying [`MasterKey`] zeroises on drop.
pub struct VaultHandle {
    vault: Vault,
    custody: CustodyMode,
    identity_root: MasterKey,
    _lock: VaultLock,
}

#[derive(Debug)]
struct VaultLock {
    _file: fs::File,
}

impl VaultLock {
    fn acquire(root: &Path) -> Result<Self> {
        ensure_directory(root, "vault root")?;
        harden_existing_core_permissions(root)?;
        let path = root.join(VAULT_LOCK_FILE);

        // Reject a pre-existing symlink or non-regular file before opening.
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(CoreError::Misuse(format!(
                    "vault lock is not a regular file: {}",
                    path.display()
                )));
            }
        }

        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);

        // Close the check/open race on Unix with O_NOFOLLOW.
        #[cfg(unix)]
        {
            options.mode(0o600);
            options.custom_flags(libc::O_NOFOLLOW);
        }

        // On Windows, open the reparse point itself so we can inspect it.
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }

        let file = options.open(&path).map_err(|error| {
            // If the file was replaced with a symlink or special entry between
            // the symlink_metadata check and open(2), O_NOFOLLOW causes open to
            // fail with ELOOP on Unix. Map that to the same Misuse shape as the
            // pre-check so we never leak a symlink follow.
            let is_symlink_open_error = error.kind() == std::io::ErrorKind::Other;
            #[cfg(unix)]
            let is_symlink_open_error =
                is_symlink_open_error || error.raw_os_error() == Some(libc::ELOOP);
            if is_symlink_open_error {
                CoreError::Misuse(format!(
                    "vault lock is not a regular file: {}",
                    path.display()
                ))
            } else {
                error.into()
            }
        })?;

        // Validate the opened descriptor is a regular file (not a device,
        // FIFO, etc.). On Unix with O_NOFOLLOW a symlink would have caused
        // open(2) to fail with ELOOP, so this is defense-in-depth.
        if !file.metadata()?.file_type().is_file() {
            return Err(CoreError::Misuse(format!(
                "vault lock is not a regular file: {}",
                path.display()
            )));
        }

        // On Windows, additionally check that the path we opened is not a
        // reparse point (symlink, junction, etc.).
        #[cfg(windows)]
        {
            let path_meta = fs::symlink_metadata(&path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    CoreError::Misuse(format!(
                        "vault lock is not a regular file: {}",
                        path.display()
                    ))
                } else {
                    error.into()
                }
            })?;
            if path_meta.file_type().is_symlink() {
                return Err(CoreError::Misuse(format!(
                    "vault lock is not a regular file: {}",
                    path.display()
                )));
            }
        }

        // Enforce 0600 permissions on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = file.metadata()?.permissions();
            if permissions.mode() & 0o777 != 0o600 {
                permissions.set_mode(0o600);
                file.set_permissions(permissions)?;
            }
        }

        // Sync the parent directory so a newly-created lock file is durable.
        sync_parent(root)?;

        match fs4::FileExt::try_lock(&file) {
            Ok(()) => Ok(Self { _file: file }),
            Err(fs4::TryLockError::WouldBlock) => Err(CoreError::VaultLocked(path)),
            Err(fs4::TryLockError::Error(error)) => Err(error.into()),
        }
    }
}

/// Result of bootstrapping a brand-new vault.
pub struct BootstrapResult {
    /// Live unlocked handle.
    pub handle: VaultHandle,
    /// Recovery phrase issued during bootstrap.
    pub recovery_phrase: String,
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
    pub fn bootstrap(
        root: &Path,
        custody: CustodyMode,
        passphrase: Option<&str>,
    ) -> Result<BootstrapResult> {
        if !root.exists() {
            create_private_directory_all(root)?;
            sync_parent(root.parent().unwrap_or(root))?;
        }
        let vault_lock = VaultLock::acquire(root)?;

        if let Some(journal) = read_lifecycle(root)? {
            match journal {
                LifecycleJournal::Bootstrap {
                    custody: pending_custody,
                    salt_b64,
                    scoped_kek_fingerprint: _,
                    wrapped_phrase_b64: Some(wrapped_phrase_b64),
                } => {
                    let expected = custody_label(custody);
                    if pending_custody != expected {
                        return Err(CoreError::Misuse(format!(
                            "bootstrap already completed with {pending_custody} custody"
                        )));
                    }
                    let kek = match custody {
                        CustodyMode::Passphrase => {
                            let pass = passphrase.ok_or_else(|| {
                                CoreError::Misuse(
                                    "passphrase custody requires a passphrase".into(),
                                )
                            })?;
                            let salt = decode_salt(salt_b64.as_deref().ok_or_else(|| {
                                CoreError::Misuse("bootstrap journal is missing its salt".into())
                            })?)?;
                            MasterKey::from_passphrase(pass, &salt)?
                        }
                        CustodyMode::OsKeychain => load_verified_keychain_kek(root)?,
                        CustodyMode::Recovery => {
                            return Err(CoreError::Misuse(
                                "recovery custody cannot be used for bootstrap".into(),
                            ))
                        }
                    };
                    let unwrapped = keyring::load(root, &kek)?;
                    let identity = load_authenticated_identity(root, &unwrapped.active_dek())?;
                    let manifest_auth_key =
                        sv_storage::derive_manifest_auth_key(&identity.root);
                    let vault = Vault::open_existing_with_keys_and_manifest_key(
                        root,
                        unwrapped.keys,
                        unwrapped.active_version,
                        manifest_auth_key,
                    )?;
                    let recovery_phrase = open_lifecycle_phrase(&kek, &wrapped_phrase_b64)?;
                    ensure_bootstrap_audit(root, &identity.root)?;
                    remove_lifecycle(root)?;
                    return Ok(BootstrapResult {
                        handle: Self {
                            vault,
                            custody,
                            identity_root: identity.root,
                            _lock: vault_lock,
                        },
                        recovery_phrase,
                    });
                }
                LifecycleJournal::Bootstrap {
                    custody: pending_custody,
                    scoped_kek_fingerprint,
                    ..
                } => {
                    rollback_incomplete_bootstrap(
                        root,
                        &pending_custody,
                        scoped_kek_fingerprint.as_deref(),
                    )?;
                }
                _ => {
                    return Err(CoreError::Misuse(
                        "a vault lifecycle operation is already in progress; unlock the vault to recover it"
                            .into(),
                    ))
                }
            }
        }

        if path_entry_exists(&root.join("manifest.json")) || keyring::exists(root) {
            return Err(CoreError::Misuse(
                "vault already initialised on disk - call unlock instead".into(),
            ));
        }

        match custody {
            CustodyMode::OsKeychain => {
                sv_keychain::ensure_available()?;
                if load_scoped_keychain_b64(root)?.is_some() {
                    return Err(CoreError::Misuse(
                        "a vault-scoped OS keychain credential already exists without matching vault state; remove that scoped credential explicitly or use passphrase custody"
                            .into(),
                    ));
                }
                // Keychain holds the KEK; a fresh random DEK seals the data and
                // is wrapped under the KEK in the keyring.
                let kek = MasterKey::generate();
                let dek = MasterKey::generate();
                write_lifecycle(
                    root,
                    &LifecycleJournal::Bootstrap {
                        custody: custody_label(custody).into(),
                        salt_b64: None,
                        scoped_kek_fingerprint: Some(keychain_kek_fingerprint(&kek)),
                        wrapped_phrase_b64: None,
                    },
                )?;
                store_scoped_keychain_kek(root, &kek)?;
                keyring::create(root, &kek, &dek)?;
                let recovery_key = dek.clone();
                let identity = create_identity(root, &recovery_key)?;
                let manifest_auth_key = sv_storage::derive_manifest_auth_key(&identity.root);
                let vault = Vault::open_or_init_with_manifest_key(root, dek, manifest_auth_key)?;
                ensure_destination_is_regular_or_missing(
                    &root.join(sv_recovery::RECOVERY_FILE),
                    "recovery bundle",
                )?;
                let recovery_phrase =
                    sv_recovery::issue_recovery_phrase_for_version(root, &recovery_key, 1)?;
                write_lifecycle(
                    root,
                    &LifecycleJournal::Bootstrap {
                        custody: custody_label(custody).into(),
                        salt_b64: None,
                        scoped_kek_fingerprint: Some(keychain_kek_fingerprint(&kek)),
                        wrapped_phrase_b64: Some(seal_lifecycle_phrase(&kek, &recovery_phrase)?),
                    },
                )?;
                ensure_bootstrap_audit(root, &identity.root)?;
                remove_lifecycle(root)?;
                Ok(BootstrapResult {
                    handle: Self {
                        vault,
                        custody,
                        identity_root: identity.root,
                        _lock: vault_lock,
                    },
                    recovery_phrase,
                })
            }
            CustodyMode::Passphrase => {
                let pass = passphrase.ok_or_else(|| {
                    CoreError::Misuse("passphrase custody requires a passphrase".into())
                })?;
                validate_new_passphrase(pass)?;
                let salt_path = root.join(SALT_FILENAME);
                // Passphrase derives the KEK; a fresh random DEK seals the data.
                let salt = sv_crypto::random_salt()?;
                let kek = MasterKey::from_passphrase(pass, &salt)?;
                let dek = MasterKey::generate();
                write_lifecycle(
                    root,
                    &LifecycleJournal::Bootstrap {
                        custody: custody_label(custody).into(),
                        salt_b64: Some(B64.encode(salt)),
                        scoped_kek_fingerprint: None,
                        wrapped_phrase_b64: None,
                    },
                )?;
                write_atomic(&salt_path, &salt)?;
                keyring::create(root, &kek, &dek)?;
                let recovery_key = dek.clone();
                let identity = create_identity(root, &recovery_key)?;
                let manifest_auth_key = sv_storage::derive_manifest_auth_key(&identity.root);
                let vault = Vault::open_or_init_with_manifest_key(root, dek, manifest_auth_key)?;
                ensure_destination_is_regular_or_missing(
                    &root.join(sv_recovery::RECOVERY_FILE),
                    "recovery bundle",
                )?;
                let recovery_phrase =
                    sv_recovery::issue_recovery_phrase_for_version(root, &recovery_key, 1)?;
                write_lifecycle(
                    root,
                    &LifecycleJournal::Bootstrap {
                        custody: custody_label(custody).into(),
                        salt_b64: Some(B64.encode(salt)),
                        scoped_kek_fingerprint: None,
                        wrapped_phrase_b64: Some(seal_lifecycle_phrase(&kek, &recovery_phrase)?),
                    },
                )?;
                ensure_bootstrap_audit(root, &identity.root)?;
                remove_lifecycle(root)?;
                Ok(BootstrapResult {
                    handle: Self {
                        vault,
                        custody,
                        identity_root: identity.root,
                        _lock: vault_lock,
                    },
                    recovery_phrase,
                })
            }
            CustodyMode::Recovery => Err(CoreError::Misuse(
                "recovery custody cannot be used for bootstrap".into(),
            )),
        }
    }

    /// Unlock an existing vault using the previously-chosen custody mode.
    ///
    /// Derives the KEK from the custody source, transparently migrating a
    /// legacy (pre-keyring) vault on first unlock, then unwraps the DEK(s)
    /// from the keyring and opens the vault.
    pub fn unlock(root: &Path, custody: CustodyMode, passphrase: Option<&str>) -> Result<Self> {
        let vault_lock = VaultLock::acquire(root)?;
        let recovered_custody = recover_lifecycle_for_unlock(root, custody, passphrase)?;
        if recovered_custody == CustodyMode::OsKeychain {
            return unlock_with_keychain(root, vault_lock);
        }

        let kek = match custody {
            CustodyMode::Passphrase => {
                let pass = passphrase.ok_or_else(|| {
                    CoreError::Misuse("passphrase custody requires a passphrase".into())
                })?;
                derive_passphrase_kek(root, pass)?
            }
            CustodyMode::OsKeychain => unreachable!("handled above"),
            CustodyMode::Recovery => {
                return Err(CoreError::Misuse(
                    "use unlock_with_recovery for recovery custody".into(),
                ))
            }
        };
        if !keyring::exists(root) {
            return Err(legacy_manifest_migration_error(root));
        }
        let unwrapped = keyring::load(root, &kek)?;
        let identity = load_authenticated_identity(root, &unwrapped.active_dek())?;
        let manifest_auth_key = sv_storage::derive_manifest_auth_key(&identity.root);
        let vault = Vault::open_existing_with_keys_and_manifest_key(
            root,
            unwrapped.keys,
            unwrapped.active_version,
            manifest_auth_key,
        )?;
        finish_pending_bootstrap(root, &identity.root)?;
        Ok(Self {
            vault,
            custody,
            identity_root: identity.root,
            _lock: vault_lock,
        })
    }

    /// Return the canonical SHA-256 confirmation token for a one-time legacy
    /// manifest migration. Review the manifest and record this digest before
    /// calling [`Self::migrate_manifest_authentication`].
    pub fn manifest_migration_digest(root: &Path) -> Result<String> {
        Ok(sv_storage::manifest_migration_digest(root)?)
    }

    /// Detect the normal custody mode recorded by an existing vault.
    ///
    /// Passphrase custody is recorded by the private `master.salt` file.
    /// OS-keychain custody deliberately has no salt file, including legacy
    /// vaults that predate the keyring. This is the same discriminator used
    /// by the keychain unlock path, so callers can select custody before
    /// asking for a passphrase or accessing the OS keychain.
    pub fn detect_custody(root: &Path) -> Result<CustodyMode> {
        let salt = root.join(SALT_FILENAME);
        if path_entry_exists(&salt) {
            ensure_regular_file(&salt, "passphrase salt")?;
            Ok(CustodyMode::Passphrase)
        } else {
            Ok(CustodyMode::OsKeychain)
        }
    }

    /// Authenticate one exact legacy manifest and permanently require
    /// manifest authentication for this vault.
    ///
    /// This operation is deliberately separate from [`Self::unlock`]. The
    /// supplied digest must match the canonical manifest bytes currently on
    /// disk, so normal unlock can never silently endorse plaintext policy.
    /// The authenticated manifest is committed before the protected identity
    /// marker, making an interruption safe to retry with the same digest.
    pub fn migrate_manifest_authentication(
        root: &Path,
        custody: CustodyMode,
        passphrase: Option<&str>,
        expected_manifest_sha256: &str,
    ) -> Result<()> {
        let _vault_lock = VaultLock::acquire(root)?;
        if read_lifecycle(root)?.is_some() {
            return Err(CoreError::Misuse(
                "finish the pending vault lifecycle operation before migrating manifest authentication"
                    .into(),
            ));
        }

        let (kek, promote_legacy_keychain) =
            match custody {
                CustodyMode::Passphrase => {
                    let passphrase = passphrase.ok_or_else(|| {
                        CoreError::Misuse("passphrase custody requires a passphrase".into())
                    })?;
                    let kek = derive_passphrase_kek(root, passphrase)?;
                    if keyring::exists(root) {
                        keyring::load(root, &kek)?;
                    } else {
                        sv_storage::validate_legacy_vault_key(root, &kek)?;
                    }
                    (kek, false)
                }
                CustodyMode::OsKeychain => {
                    if keyring::exists(root) {
                        let (kek, _) = load_keychain_unwrapped(root)?;
                        (kek, false)
                    } else {
                        let mut candidates = load_keychain_kek_candidates(root)?;
                        candidates.sort_by_key(|candidate| match candidate.source {
                            KeychainKekSource::Legacy => 0,
                            KeychainKekSource::Scoped => 1,
                        });
                        let mut selected = None;
                        for candidate in candidates {
                            if sv_storage::validate_legacy_vault_key(root, &candidate.kek).is_ok() {
                                selected = Some((
                                    candidate.kek,
                                    candidate.source == KeychainKekSource::Legacy,
                                ));
                                break;
                            }
                        }
                        selected.ok_or_else(|| {
                            CoreError::Misuse(
                                "OS keychain key could not validate this legacy vault".into(),
                            )
                        })?
                    }
                }
                CustodyMode::Recovery => return Err(CoreError::Misuse(
                    "legacy manifest migration requires normal passphrase or OS keychain custody"
                        .into(),
                )),
            };

        keyring::migrate_legacy(root, &kek)?;
        let unwrapped = keyring::load(root, &kek)?;
        let active_dek = unwrapped.active_dek();
        let material_wrap = material_wrap_for_dek(&active_dek);
        let identity = transit::load_identity_if_present(root, &material_wrap)?;
        let identity_root = identity
            .map(|state| state.root)
            .unwrap_or_else(|| active_dek.clone());
        let manifest_auth_key = sv_storage::derive_manifest_auth_key(&identity_root);

        sv_storage::migrate_legacy_manifest(root, &manifest_auth_key, expected_manifest_sha256)?;
        transit::enable_manifest_authentication(root, &material_wrap, &identity_root)?;
        if promote_legacy_keychain {
            store_scoped_keychain_kek(root, &kek)?;
        }
        Ok(())
    }

    /// Unlock an existing vault using its persisted recovery bundle.
    ///
    /// The recovery phrase restores the active DEK directly (independent of
    /// the KEK), so it works even if the passphrase/keychain KEK is lost.
    pub fn unlock_with_recovery(root: &Path, phrase: &str) -> Result<Self> {
        let vault_lock = VaultLock::acquire(root)?;
        ensure_regular_file(&root.join(sv_recovery::RECOVERY_FILE), "recovery bundle")?;
        if let Some(journal) = read_lifecycle(root)? {
            match journal {
                LifecycleJournal::Bootstrap {
                    wrapped_phrase_b64: Some(_),
                    ..
                } => {}
                _ => {
                    return Err(CoreError::Misuse(
                        "a vault lifecycle operation is incomplete; unlock with normal custody to recover it before using recovery"
                            .into(),
                    ))
                }
            }
        }
        let recovered = sv_recovery::restore_master_key_with_version(root, phrase)?;
        let dek = recovered.master_key;
        let (vault, identity_root) = if keyring::exists(root) {
            let active = keyring::active_version(root)?;
            let recovered_version = recovered.dek_version.unwrap_or(active);
            if recovered_version != active {
                return Err(CoreError::Misuse(format!(
                    "recovery bundle contains DEK v{recovered_version}, but the vault requires active DEK v{active}"
                )));
            }
            let identity = load_authenticated_identity(root, &dek)?;
            let manifest_auth_key = sv_storage::derive_manifest_auth_key(&identity.root);
            if should_repair_keychain_after_recovery(root) {
                sv_keychain::ensure_available()?;
                let kek = MasterKey::generate();
                store_scoped_keychain_kek(root, &kek)?;
                keyring::replace_with_single_active_dek(root, &kek, active, &dek)?;
                let mut keys = std::collections::BTreeMap::new();
                keys.insert(recovered_version, dek);
                let vault = Vault::open_existing_with_keys_and_manifest_key(
                    root,
                    keys,
                    active,
                    manifest_auth_key,
                )?;
                finish_pending_bootstrap(root, &identity.root)?;
                return Ok(Self {
                    vault,
                    custody: CustodyMode::OsKeychain,
                    identity_root: identity.root,
                    _lock: vault_lock,
                });
            }
            let mut keys = std::collections::BTreeMap::new();
            keys.insert(recovered_version, dek);
            (
                Vault::open_existing_with_keys_and_manifest_key(
                    root,
                    keys,
                    active,
                    manifest_auth_key,
                )?,
                identity.root,
            )
        } else {
            return Err(legacy_manifest_migration_error(root));
        };
        finish_pending_bootstrap(root, &identity_root)?;
        Ok(Self {
            vault,
            custody: CustodyMode::Recovery,
            identity_root,
            _lock: vault_lock,
        })
    }

    /// Custody mode in use for this handle.
    pub fn custody(&self) -> CustodyMode {
        self.custody
    }

    /// Path to the vault root.
    pub fn root(&self) -> &Path {
        self.vault.root()
    }

    /// Derive the keyed HMAC key used to hash sensitive audit-log fields.
    ///
    /// The persistent identity root is independent of the active DEK, so this
    /// remains stable across custody changes and data-key rotations.
    pub fn audit_hmac_key(&self) -> [u8; 32] {
        sv_crypto::derive_subkey(&self.identity_root, b"sv-audit-hmac-v1")
    }

    /// Derive the keyed HMAC key used to hash agent tokens in `agents.json`.
    ///
    /// Like [`Self::audit_hmac_key`], this remains stable across custody
    /// changes and data-key rotations.
    pub fn agent_token_key(&self) -> [u8; 32] {
        sv_crypto::derive_subkey(&self.identity_root, b"sv-agent-token-v1")
    }

    // ---- agent registry (ADR-0008) ---------------------------------------

    /// Mint a new agent identity. Returns `(agent_id, one_time_token)`.
    pub fn create_agent(
        &self,
        name: &str,
        scopes: Vec<agents::AgentScope>,
    ) -> Result<(String, String)> {
        agents::create_agent(self.root(), &self.agent_token_key(), name, scopes)
    }

    /// List all registered agents.
    pub fn list_agents(&self) -> Result<Vec<agents::AgentRecord>> {
        agents::list_agents(self.root(), &self.agent_token_key())
    }

    /// Revoke an agent by id.
    pub fn revoke_agent(&self, agent_id: &str) -> Result<()> {
        agents::revoke_agent(self.root(), &self.agent_token_key(), agent_id)
    }

    /// Authenticate an agent against the registry by id + token.
    pub fn authenticate_agent(&self, agent_id: &str, token: &str) -> Result<agents::AgentRecord> {
        agents::authenticate(self.root(), &self.agent_token_key(), agent_id, token)
    }

    /// Ensure the built-in "Default" agent exists wrapping `pairing_secret`.
    /// Idempotent; used by the desktop migration.
    pub fn ensure_default_agent(&self, pairing_secret: &str) -> Result<()> {
        agents::ensure_default_agent(self.root(), &self.agent_token_key(), pairing_secret)
    }

    // ---- transit / signing / broker key material (ADR-0009) -------------

    /// Derive the wrapping key under which transit/signing/broker material is
    /// sealed. Derived from the ACTIVE DEK (HKDF), so it never exposes the DEK
    /// itself and changes after a rotation (material is re-wrapped on rotate).
    fn material_wrap_key(&self) -> MasterKey {
        MasterKey::from_bytes(self.vault.derive_subkey(MATERIAL_WRAP_CONTEXT))
    }

    /// Create a named symmetric transit key. Returns its metadata.
    pub fn transit_create_key(&self, name: &str) -> Result<transit::TransitKeyInfo> {
        transit::transit_create_key(self.root(), &self.material_wrap_key(), name)
    }

    /// List transit keys (metadata only).
    pub fn transit_list(&self) -> Result<Vec<transit::TransitKeyInfo>> {
        transit::transit_list(self.root())
    }

    /// Encrypt `plaintext` under `key_ref`, returning base64 ciphertext.
    pub fn transit_encrypt(&self, key_ref: &str, plaintext: &[u8]) -> Result<String> {
        transit::transit_encrypt(self.root(), &self.material_wrap_key(), key_ref, plaintext)
    }

    /// Decrypt base64 `ciphertext_b64` under `key_ref`.
    pub fn transit_decrypt(&self, key_ref: &str, ciphertext_b64: &str) -> Result<Vec<u8>> {
        transit::transit_decrypt(
            self.root(),
            &self.material_wrap_key(),
            key_ref,
            ciphertext_b64,
        )
    }

    /// Create an Ed25519 signing key. Returns metadata incl. the public key.
    pub fn signing_create_key(&self, name: &str) -> Result<transit::SigningKeyInfo> {
        transit::signing_create_key(self.root(), &self.material_wrap_key(), name)
    }

    /// List signing keys (metadata + public keys only).
    pub fn signing_list(&self) -> Result<Vec<transit::SigningKeyInfo>> {
        transit::signing_list(self.root())
    }

    /// Exportable base64 public key for `key_ref`.
    pub fn signing_public_key(&self, key_ref: &str) -> Result<String> {
        transit::signing_public_key(self.root(), key_ref)
    }

    /// Sign `payload` with `key_ref`, returning a base64 signature.
    pub fn signing_sign(&self, key_ref: &str, payload: &[u8]) -> Result<String> {
        transit::signing_sign(self.root(), &self.material_wrap_key(), key_ref, payload)
    }

    /// Create a brokered secret with a destination allowlist.
    pub fn broker_create(
        &self,
        name: &str,
        secret: &str,
        allow: Vec<transit::BrokerAllow>,
        injection: transit::BrokerInjection,
    ) -> Result<transit::BrokerSecretInfo> {
        transit::broker_create(
            self.root(),
            &self.material_wrap_key(),
            name,
            secret,
            allow,
            injection,
        )
    }

    /// List brokered secrets (metadata only).
    pub fn broker_list(&self) -> Result<Vec<transit::BrokerSecretInfo>> {
        transit::broker_list(self.root())
    }

    /// Resolve a brokered secret for in-process injection (not for agents).
    pub fn broker_resolve(&self, secret_ref: &str) -> Result<transit::ResolvedBrokerSecret> {
        transit::broker_resolve(self.root(), &self.material_wrap_key(), secret_ref)
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

    /// Effective mode for a container.
    pub fn container_mode(&self, container: &str) -> Result<SecurityMode> {
        Ok(self.vault.container_mode(container)?)
    }

    /// Change the passphrase for a passphrase-custody vault.
    ///
    /// O(1) in file data: re-derives the KEK under a new salt and re-wraps the
    /// DEK(s) in the keyring. No file is re-encrypted. Only valid for
    /// `Passphrase` custody.
    pub fn change_passphrase(&self, root: &Path, current: &str, new: &str) -> Result<()> {
        self.ensure_operation_root(root)?;
        if self.custody != CustodyMode::Passphrase {
            return Err(CoreError::Misuse(
                "change_passphrase is only valid for passphrase custody".into(),
            ));
        }
        let old_kek = derive_passphrase_kek(root, current)?;
        // Verify the current passphrase actually unwraps the keyring before
        // we overwrite the salt.
        keyring::load(root, &old_kek)?;
        validate_new_passphrase(new)?;
        let old_salt = read_salt(root)?;
        let new_salt = sv_crypto::random_salt()?;
        let new_kek = MasterKey::from_passphrase(new, &new_salt)?;
        keyring::stage_rewrap_under_new_kek(root, &old_kek, &new_kek)?;
        write_lifecycle(
            root,
            &LifecycleJournal::ChangePassphrase {
                old_salt_b64: B64.encode(old_salt),
                new_salt_b64: B64.encode(new_salt),
            },
        )?;
        write_atomic(&root.join(SALT_FILENAME), &new_salt)?;
        keyring::commit_staged(root)?;
        remove_lifecycle(root)?;
        Ok(())
    }

    /// Move a passphrase-custody vault to OS keychain custody.
    ///
    /// This re-wraps the keyring under a fresh random KEK stored in the native
    /// OS keychain. The passphrase salt is removed only after the new keychain
    /// entry has been stored and verified against the re-wrapped keyring.
    pub fn move_to_os_keychain(&mut self, root: &Path, current_passphrase: &str) -> Result<()> {
        self.ensure_operation_root(root)?;
        if self.custody != CustodyMode::Passphrase {
            return Err(CoreError::Misuse(
                "move_to_os_keychain is only valid for passphrase custody".into(),
            ));
        }

        sv_keychain::ensure_available()?;
        let old_kek = derive_passphrase_kek(root, current_passphrase)?;
        keyring::load(root, &old_kek)?;

        let new_kek = MasterKey::generate();
        keyring::stage_rewrap_under_new_kek(root, &old_kek, &new_kek)?;
        write_lifecycle(root, &LifecycleJournal::MoveToKeychain)?;
        store_scoped_keychain_kek(root, &new_kek)?;
        keyring::load_staged(root, &new_kek)?;
        keyring::commit_staged(root)?;
        remove_file_durable(&root.join(SALT_FILENAME))?;
        remove_lifecycle(root)?;
        self.custody = CustodyMode::OsKeychain;
        Ok(())
    }

    /// Rotate the data-encryption key.
    ///
    /// Generates a new DEK, re-seals every file and auxiliary secret forward,
    /// and re-issues the recovery phrase (the old phrase no longer decrypts
    /// the vault). Superseded wrapped DEKs are retained as a conservative
    /// rollback reserve. Requires the KEK, so pass the passphrase for
    /// passphrase custody (ignored for keychain custody). Returns the new
    /// recovery phrase.
    pub fn rotate_key(&mut self, root: &Path, passphrase: Option<&str>) -> Result<String> {
        self.ensure_operation_root(root)?;
        let kek = match self.custody {
            CustodyMode::OsKeychain => load_verified_keychain_kek(root)?,
            CustodyMode::Passphrase => {
                let pass = passphrase.ok_or_else(|| {
                    CoreError::Misuse("passphrase custody requires a passphrase to rotate".into())
                })?;
                derive_passphrase_kek(root, pass)?
            }
            CustodyMode::Recovery => {
                return Err(CoreError::Misuse(
                    "cannot rotate from a recovery-unlocked session".into(),
                ))
            }
        };

        if let Some(journal) = read_lifecycle(root)? {
            return Err(CoreError::Misuse(format!(
                "cannot start rotation while lifecycle operation {journal:?} is pending; unlock the vault to recover it"
            )));
        }

        // Capture the wrap key derived from the OLD active DEK before rotating.
        // Transit/signing/broker material is sealed under it; once the old DEK
        // is retired below we can no longer derive it, so we must re-wrap every
        // entry forward or it is permanently orphaned.
        let old_material_wrap = self.material_wrap_key();
        let old_version = keyring::active_version(root)?;
        let recovery_path = root.join(sv_recovery::RECOVERY_FILE);
        ensure_regular_file(&recovery_path, "recovery bundle")?;
        let recovery_backup = fs::read(recovery_path)?;

        let new_dek = MasterKey::generate();
        let predicted_new_version = old_version.checked_add(1).ok_or_else(|| {
            CoreError::Misuse("DEK version space exhausted; create a new vault".into())
        })?;
        let recovery_backup_b64 = B64.encode(recovery_backup);
        write_lifecycle(
            root,
            &LifecycleJournal::Rotate {
                old_version,
                new_version: predicted_new_version,
                recovery_backup_b64: recovery_backup_b64.clone(),
            },
        )?;
        let transaction = (|| -> Result<String> {
            let new_version = keyring::add_active_dek(root, &kek, &new_dek)?;
            if new_version != predicted_new_version {
                return Err(CoreError::Misuse(
                    "keyring DEK version changed concurrently during rotation".into(),
                ));
            }

            // Reopen with all versions so old files stay readable while we migrate.
            let unwrapped = keyring::load(root, &kek)?;
            let manifest_auth_key = sv_storage::derive_manifest_auth_key(&self.identity_root);
            let vault = Vault::open_existing_with_keys_and_manifest_key(
                root,
                unwrapped.keys,
                unwrapped.active_version,
                manifest_auth_key,
            )?;

            // Re-seal every file forward to the new active version.
            rewrap_all_files(&vault)?;
            self.vault = vault;

            // `self.vault` now derives from the new DEK; re-seal every transit /
            // signing / broker secret forward from the old wrap key to the new one.
            let new_material_wrap = self.material_wrap_key();
            transit::rewrap_all_material(root, &old_material_wrap, &new_material_wrap)?;

            // Commit recovery last. Until this durable replacement succeeds, an
            // interrupted transaction rolls every artifact back to the old DEK.
            ensure_destination_is_regular_or_missing(
                &root.join(sv_recovery::RECOVERY_FILE),
                "recovery bundle",
            )?;
            let recovery_phrase =
                sv_recovery::issue_recovery_phrase_for_version(root, &new_dek, new_version)?;
            remove_lifecycle(root)?;
            Ok(recovery_phrase)
        })();

        match transaction {
            Ok(phrase) => Ok(phrase),
            Err(operation_error) => {
                if let Err(rollback_error) = rollback_rotation(
                    root,
                    &kek,
                    old_version,
                    predicted_new_version,
                    &recovery_backup_b64,
                ) {
                    return Err(CoreError::Misuse(format!(
                        "rotation failed ({operation_error}); rollback also failed ({rollback_error}); unlock normal custody to resume recovery"
                    )));
                }
                let unwrapped = keyring::load(root, &kek)?;
                let manifest_auth_key = sv_storage::derive_manifest_auth_key(&self.identity_root);
                self.vault = Vault::open_existing_with_keys_and_manifest_key(
                    root,
                    unwrapped.keys,
                    unwrapped.active_version,
                    manifest_auth_key,
                )?;
                Err(operation_error)
            }
        }
    }

    fn ensure_operation_root(&self, root: &Path) -> Result<()> {
        let handle_root = self.root().canonicalize()?;
        let requested_root = root.canonicalize()?;
        if handle_root != requested_root {
            return Err(CoreError::Misuse(format!(
                "vault handle is locked for {}, not {}",
                handle_root.display(),
                requested_root.display()
            )));
        }
        Ok(())
    }
}

/// Harden permissions on the vault root directory and the known sensitive
/// core files inside it. Existing non-sensitive files are left untouched.
/// Does not follow symlinks: any symlink encountered is treated as an error.
fn harden_existing_core_permissions(root: &Path) -> Result<()> {
    secure_core_directory(root)?;
    for name in [
        VAULT_LOCK_FILE,
        LIFECYCLE_FILE,
        SALT_FILENAME,
        keyring::KEYRING_FILE,
        keyring::STAGED_KEYRING_FILE,
        sv_recovery::RECOVERY_FILE,
        transit::IDENTITY_FILE,
        transit::TRANSIT_FILE,
        transit::SIGNING_FILE,
        transit::BROKERS_FILE,
    ] {
        let path = root.join(name);
        if fs::symlink_metadata(&path).is_ok() {
            secure_core_regular_file(&path)?;
        }
    }
    Ok(())
}

/// Recursively create `path` as a private directory (0700 on Unix, no-op
/// elsewhere). On Unix the directory is created with mode 0700 and the
/// final path's permissions are verified; on non-Unix this is equivalent to
/// `fs::create_dir_all`.
fn create_private_directory_all(path: &Path) -> Result<()> {
    create_private_directory_all_impl(path)
}

#[cfg(unix)]
fn create_private_directory_all_impl(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(path)?;
    secure_core_directory(path)
}

#[cfg(not(unix))]
fn create_private_directory_all_impl(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    Ok(())
}

#[cfg(unix)]
fn secure_core_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = fs::symlink_metadata(path)?;
    ensure_directory_metadata(&metadata, "vault root")?;
    if metadata.permissions().mode() & 0o777 != 0o700 {
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_core_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn secure_core_regular_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = fs::symlink_metadata(path)?;
    ensure_regular_file_metadata(&metadata, "core file")?;
    if metadata.permissions().mode() & 0o777 != 0o600 {
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_core_regular_file(_path: &Path) -> Result<()> {
    Ok(())
}
#[cfg(unix)]
fn ensure_directory_metadata(metadata: &fs::Metadata, label: &str) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(CoreError::Misuse(format!(
            "{label} is not a real directory"
        )));
    }
    Ok(())
}
#[cfg(unix)]
fn ensure_regular_file_metadata(metadata: &fs::Metadata, label: &str) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(CoreError::Misuse(format!("{label} is not a regular file")));
    }
    Ok(())
}

fn custody_label(custody: CustodyMode) -> &'static str {
    match custody {
        CustodyMode::OsKeychain => "os_keychain",
        CustodyMode::Passphrase => "passphrase",
        CustodyMode::Recovery => "recovery",
    }
}

/// Deterministically derives the DEK-scoped wrapping key used to seal
/// persistent identity, transit, signing, and broker material. Callers
/// must supply the active DEK.
pub fn material_wrap_for_dek(dek: &MasterKey) -> MasterKey {
    MasterKey::from_bytes(sv_crypto::derive_subkey(dek, MATERIAL_WRAP_CONTEXT))
}

fn create_identity(root: &Path, active_dek: &MasterKey) -> Result<transit::IdentityState> {
    transit::load_or_create_identity(root, &material_wrap_for_dek(active_dek), None)
}

fn load_authenticated_identity(
    root: &Path,
    active_dek: &MasterKey,
) -> Result<transit::IdentityState> {
    let Some(identity) =
        transit::load_identity_if_present(root, &material_wrap_for_dek(active_dek))?
    else {
        return Err(legacy_manifest_migration_error(root));
    };
    if !identity.manifest_auth_required {
        return Err(legacy_manifest_migration_error(root));
    }
    Ok(identity)
}

fn legacy_manifest_migration_error(root: &Path) -> CoreError {
    match sv_storage::manifest_migration_digest(root) {
        Ok(digest) => CoreError::Misuse(format!(
            "legacy manifest authentication migration is required; review manifest.json, then call VaultHandle::migrate_manifest_authentication with SHA-256 {digest}"
        )),
        Err(error) => CoreError::Misuse(format!(
            "legacy manifest authentication migration is required, but its confirmation digest could not be computed: {error}"
        )),
    }
}

fn validate_new_passphrase(passphrase: &str) -> Result<()> {
    let length = passphrase.chars().count();
    if length < MIN_PASSPHRASE_CHARS {
        return Err(CoreError::Misuse(format!(
            "new passphrases must contain at least {MIN_PASSPHRASE_CHARS} characters (received {length}); use a long, unique passphrase"
        )));
    }
    Ok(())
}

fn audit_key(identity_root: &MasterKey) -> [u8; 32] {
    sv_crypto::derive_subkey(identity_root, b"sv-audit-hmac-v1")
}

fn ensure_bootstrap_audit(root: &Path, identity_root: &MasterKey) -> Result<()> {
    let key = audit_key(identity_root);
    match sv_audit::AuditLog::open(root, key) {
        Ok(_) => Ok(()),
        Err(sv_audit::AuditError::NotInitialized(_)) => {
            sv_audit::AuditLog::create(root, key)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn finish_pending_bootstrap(root: &Path, identity_root: &MasterKey) -> Result<()> {
    if matches!(
        read_lifecycle(root)?,
        Some(LifecycleJournal::Bootstrap {
            wrapped_phrase_b64: Some(_),
            ..
        })
    ) {
        ensure_bootstrap_audit(root, identity_root)?;
        remove_lifecycle(root)?;
    }
    Ok(())
}

fn lifecycle_path(root: &Path) -> PathBuf {
    root.join(LIFECYCLE_FILE)
}

fn read_lifecycle(root: &Path) -> Result<Option<LifecycleJournal>> {
    let path = lifecycle_path(root);
    match fs::symlink_metadata(&path) {
        Ok(_) => ensure_regular_file(&path, "lifecycle journal")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let raw = fs::read(&path)?;
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|error| CoreError::Misuse(format!("lifecycle journal: {error}")))
}

fn write_lifecycle(root: &Path, journal: &LifecycleJournal) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(journal)
        .map_err(|error| CoreError::Misuse(format!("lifecycle journal: {error}")))?;
    write_atomic(&lifecycle_path(root), &bytes)
}

fn remove_lifecycle(root: &Path) -> Result<()> {
    remove_file_durable(&lifecycle_path(root))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| CoreError::Misuse("atomic file has no parent directory".into()))?;
    ensure_directory(parent, "atomic destination parent")?;
    ensure_destination_is_regular_or_missing(path, "atomic destination")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| CoreError::Misuse("atomic file has an invalid name".into()))?;
    let (tmp, mut file) = create_secure_temp(parent, name)?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        ensure_destination_is_regular_or_missing(path, "atomic destination")?;
        atomicwrites::replace_atomic(&tmp, path)?;
        sync_parent(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn create_secure_temp(parent: &Path, name: &str) -> Result<(PathBuf, fs::File)> {
    for _ in 0..16 {
        let suffix = B64_URL.encode(sv_crypto::random_bytes(12)?);
        let path = parent.join(format!(".{name}.{suffix}.tmp"));
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
        "could not allocate a unique atomic temp file",
    )))
}

fn remove_file_durable(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => ensure_regular_file(path, "file removal target")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    match fs::remove_file(path) {
        Ok(()) => sync_parent(path.parent().unwrap_or(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<()> {
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_parent(parent: &Path) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(parent)?
        .sync_all()?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_parent(_parent: &Path) -> Result<()> {
    Ok(())
}

fn read_salt(root: &Path) -> Result<[u8; SALT_LEN]> {
    let path = root.join(SALT_FILENAME);
    ensure_regular_file(&path, "passphrase salt")?;
    let raw = fs::read(path)?;
    if raw.len() != SALT_LEN {
        return Err(CoreError::Misuse(format!(
            "master.salt has wrong length: {}",
            raw.len()
        )));
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&raw);
    Ok(salt)
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

fn path_entry_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn decode_salt(encoded: &str) -> Result<[u8; SALT_LEN]> {
    let raw = B64
        .decode(encoded.as_bytes())
        .map_err(|error| CoreError::Base64(error.to_string()))?;
    if raw.len() != SALT_LEN {
        return Err(CoreError::Misuse(format!(
            "journal salt has wrong length: {}",
            raw.len()
        )));
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&raw);
    Ok(salt)
}

fn seal_lifecycle_phrase(kek: &MasterKey, phrase: &str) -> Result<String> {
    Ok(B64.encode(sv_crypto::seal(kek, phrase.as_bytes(), LIFECYCLE_AAD)?))
}

fn open_lifecycle_phrase(kek: &MasterKey, encoded: &str) -> Result<String> {
    let sealed = B64
        .decode(encoded.as_bytes())
        .map_err(|error| CoreError::Base64(error.to_string()))?;
    let raw = sv_crypto::open(kek, &sealed, LIFECYCLE_AAD)?;
    String::from_utf8(raw)
        .map_err(|_| CoreError::Misuse("lifecycle recovery phrase is not UTF-8".into()))
}

fn rollback_incomplete_bootstrap(
    root: &Path,
    custody: &str,
    scoped_kek_fingerprint: Option<&str>,
) -> Result<()> {
    rollback_incomplete_bootstrap_with_cleanup(
        root,
        custody,
        scoped_kek_fingerprint,
        cleanup_matching_bootstrap_keychain_kek,
    )
}

fn rollback_incomplete_bootstrap_with_cleanup<F>(
    root: &Path,
    custody: &str,
    scoped_kek_fingerprint: Option<&str>,
    mut cleanup_keychain: F,
) -> Result<()>
where
    F: FnMut(&Path, &str) -> Result<bool>,
{
    for file in [
        "manifest.json",
        keyring::KEYRING_FILE,
        keyring::STAGED_KEYRING_FILE,
        sv_recovery::RECOVERY_FILE,
        transit::IDENTITY_FILE,
        SALT_FILENAME,
    ] {
        remove_file_durable(&root.join(file))?;
    }
    if custody == "os_keychain" {
        if let Some(expected) = scoped_kek_fingerprint {
            cleanup_keychain(root, expected)?;
        }
    }
    remove_lifecycle(root)
}

fn keychain_kek_fingerprint(kek: &MasterKey) -> String {
    scoped_credential_fingerprint(&B64.encode(kek.as_bytes()))
}

fn scoped_credential_fingerprint(encoded_kek: &str) -> String {
    B64_URL.encode(Sha256::digest(encoded_kek.as_bytes()))
}

fn cleanup_matching_bootstrap_keychain_kek(root: &Path, expected: &str) -> Result<bool> {
    cleanup_matching_bootstrap_keychain_kek_with(
        expected,
        || load_scoped_keychain_b64(root),
        || {
            sv_keychain::delete_master_key_for_account(&keychain_account_for_root(root))?;
            Ok(())
        },
    )
}

fn cleanup_matching_bootstrap_keychain_kek_with<L, D>(
    expected: &str,
    load: L,
    delete: D,
) -> Result<bool>
where
    L: FnOnce() -> Result<Option<String>>,
    D: FnOnce() -> Result<()>,
{
    let Some(encoded_kek) = load()? else {
        return Ok(false);
    };
    if scoped_credential_fingerprint(&encoded_kek) != expected {
        return Ok(false);
    }
    delete()?;
    Ok(true)
}

fn recover_lifecycle_for_unlock(
    root: &Path,
    custody: CustodyMode,
    passphrase: Option<&str>,
) -> Result<CustodyMode> {
    let Some(journal) = read_lifecycle(root)? else {
        return Ok(custody);
    };

    match journal {
        LifecycleJournal::Bootstrap {
            wrapped_phrase_b64: Some(_),
            ..
        } => Ok(custody),
        LifecycleJournal::Bootstrap { .. } => Err(CoreError::Misuse(
            "bootstrap was interrupted before completion; call bootstrap again with the intended custody mode"
                .into(),
        )),
        LifecycleJournal::ChangePassphrase {
            old_salt_b64,
            new_salt_b64,
        } => {
            if custody != CustodyMode::Passphrase {
                return Err(CoreError::Misuse(
                    "passphrase change is incomplete; unlock with passphrase custody to recover it"
                        .into(),
                ));
            }
            let passphrase = passphrase.ok_or_else(|| {
                CoreError::Misuse("passphrase custody requires a passphrase".into())
            })?;
            let current = read_salt(root)?;
            let old_salt = decode_salt(&old_salt_b64)?;
            let new_salt = decode_salt(&new_salt_b64)?;
            if current == old_salt {
                let old_kek = MasterKey::from_passphrase(passphrase, &old_salt)?;
                keyring::load(root, &old_kek)?;
                keyring::discard_staged(root)?;
            } else if current == new_salt {
                let new_kek = MasterKey::from_passphrase(passphrase, &new_salt)?;
                if keyring::load(root, &new_kek).is_err() {
                    keyring::load_staged(root, &new_kek)?;
                    keyring::commit_staged(root)?;
                } else {
                    keyring::discard_staged(root)?;
                }
            } else {
                return Err(CoreError::Misuse(
                    "master.salt does not match either side of the pending passphrase transaction"
                        .into(),
                ));
            }
            remove_lifecycle(root)?;
            Ok(CustodyMode::Passphrase)
        }
        LifecycleJournal::MoveToKeychain => {
            let candidates = match load_keychain_kek_candidates(root) {
                Ok(candidates) => candidates
                    .into_iter()
                    .map(|candidate| candidate.kek)
                    .collect(),
                Err(_) if custody == CustodyMode::Passphrase => Vec::new(),
                Err(error) => return Err(error),
            };
            recover_move_to_keychain(root, custody, passphrase, candidates)
        }
        LifecycleJournal::Rotate {
            old_version,
            new_version,
            recovery_backup_b64,
        } => {
            let kek = match custody {
                CustodyMode::Passphrase => {
                    let passphrase = passphrase.ok_or_else(|| {
                        CoreError::Misuse("passphrase custody requires a passphrase".into())
                    })?;
                    derive_passphrase_kek(root, passphrase)?
                }
                CustodyMode::OsKeychain => load_verified_keychain_kek(root)?,
                CustodyMode::Recovery => {
                    return Err(CoreError::Misuse(
                        "rotation recovery requires normal custody".into(),
                    ))
                }
            };
            rollback_rotation(
                root,
                &kek,
                old_version,
                new_version,
                &recovery_backup_b64,
            )?;
            Ok(custody)
        }
    }
}

fn finish_move_to_keychain(root: &Path, kek: &MasterKey) -> Result<()> {
    if keyring::load(root, kek).is_err() {
        keyring::load_staged(root, kek)?;
        keyring::commit_staged(root)?;
    } else {
        keyring::discard_staged(root)?;
    }
    remove_file_durable(&root.join(SALT_FILENAME))?;
    remove_lifecycle(root)
}

fn recover_move_to_keychain(
    root: &Path,
    custody: CustodyMode,
    passphrase: Option<&str>,
    keychain_candidates: Vec<MasterKey>,
) -> Result<CustodyMode> {
    for kek in keychain_candidates {
        if keyring::load(root, &kek).is_ok() || keyring::load_staged(root, &kek).is_ok() {
            finish_move_to_keychain(root, &kek)?;
            return Ok(CustodyMode::OsKeychain);
        }
    }

    if custody == CustodyMode::Passphrase {
        let passphrase = passphrase
            .ok_or_else(|| CoreError::Misuse("passphrase custody requires a passphrase".into()))?;
        let old_kek = derive_passphrase_kek(root, passphrase)?;
        keyring::load(root, &old_kek)?;
        keyring::discard_staged(root)?;
        remove_lifecycle(root)?;
        return Ok(CustodyMode::Passphrase);
    }

    Err(CoreError::Misuse(
        "OS keychain credential for the pending custody transaction is unavailable; unlock with the current passphrase to roll it back"
            .into(),
    ))
}

fn rollback_rotation(
    root: &Path,
    kek: &MasterKey,
    old_version: u32,
    new_version: u32,
    recovery_backup_b64: &str,
) -> Result<()> {
    let unwrapped = keyring::load(root, kek)?;
    if unwrapped.keys.contains_key(&new_version) {
        let old_dek = unwrapped
            .keys
            .get(&old_version)
            .ok_or_else(|| CoreError::Misuse("rotation rollback is missing the old DEK".into()))?;
        let new_dek = unwrapped
            .keys
            .get(&new_version)
            .ok_or_else(|| CoreError::Misuse("rotation rollback is missing the new DEK".into()))?;
        let old_wrap = material_wrap_for_dek(old_dek);
        let new_wrap = material_wrap_for_dek(new_dek);
        let identity = transit::load_identity(root, &new_wrap)
            .or_else(|_| transit::load_identity(root, &old_wrap))?;
        if !identity.manifest_auth_required {
            return Err(legacy_manifest_migration_error(root));
        }
        let manifest_auth_key = sv_storage::derive_manifest_auth_key(&identity.root);
        keyring::set_active_version(root, old_version)?;
        let unwrapped = keyring::load(root, kek)?;
        let vault = Vault::open_existing_with_keys_and_manifest_key(
            root,
            unwrapped.keys,
            unwrapped.active_version,
            manifest_auth_key,
        )?;
        rewrap_all_files(&vault)?;
        transit::rewrap_all_material(root, &new_wrap, &old_wrap)?;
    }

    let recovery_backup = B64
        .decode(recovery_backup_b64.as_bytes())
        .map_err(|error| CoreError::Base64(error.to_string()))?;
    write_atomic(&root.join(sv_recovery::RECOVERY_FILE), &recovery_backup)?;
    if keyring::active_version(root)? != old_version {
        keyring::set_active_version(root, old_version)?;
    }
    keyring::remove_version(root, new_version)?;
    remove_lifecycle(root)
}

fn rewrap_all_files(vault: &Vault) -> Result<()> {
    for container in vault.list_containers()? {
        for file in vault.list_files(&container.name)? {
            vault.rewrap_file(&container.name, &file.name)?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeychainKekSource {
    Scoped,
    Legacy,
}

struct KeychainKekCandidate {
    kek: MasterKey,
    source: KeychainKekSource,
}

fn unlock_with_keychain(root: &Path, vault_lock: VaultLock) -> Result<VaultHandle> {
    if path_entry_exists(&root.join(SALT_FILENAME)) {
        return Err(CoreError::Misuse(
            "this vault uses passphrase custody; unlock with passphrase or recovery instead".into(),
        ));
    }

    if !keyring::exists(root) {
        return Err(legacy_manifest_migration_error(root));
    }
    let (_, unwrapped) = load_keychain_unwrapped(root)?;
    let identity = load_authenticated_identity(root, &unwrapped.active_dek())?;
    let manifest_auth_key = sv_storage::derive_manifest_auth_key(&identity.root);
    let vault = Vault::open_existing_with_keys_and_manifest_key(
        root,
        unwrapped.keys,
        unwrapped.active_version,
        manifest_auth_key,
    )?;
    finish_pending_bootstrap(root, &identity.root)?;
    Ok(VaultHandle {
        vault,
        custody: CustodyMode::OsKeychain,
        identity_root: identity.root,
        _lock: vault_lock,
    })
}

fn load_verified_keychain_kek(root: &Path) -> Result<MasterKey> {
    let (kek, _) = load_keychain_unwrapped(root)?;
    Ok(kek)
}

fn should_repair_keychain_after_recovery(root: &Path) -> bool {
    if !keyring::exists(root) || path_entry_exists(&root.join(SALT_FILENAME)) {
        return false;
    }

    match load_keychain_unwrapped(root) {
        Ok(_) => false,
        Err(CoreError::Keychain(sv_keychain::KeychainError::Unavailable(_))) => false,
        Err(_) => sv_keychain::availability().available,
    }
}

fn load_keychain_unwrapped(root: &Path) -> Result<(MasterKey, keyring::Unwrapped)> {
    let candidates = load_keychain_kek_candidates(root)?;
    if candidates.is_empty() {
        return Err(CoreError::Misuse(
            "no key in OS keychain - bootstrap the vault first".into(),
        ));
    }

    for candidate in candidates {
        if let Ok(unwrapped) = keyring::load(root, &candidate.kek) {
            if candidate.source == KeychainKekSource::Legacy {
                store_scoped_keychain_kek(root, &candidate.kek)?;
            }
            return Ok((candidate.kek, unwrapped));
        }
    }

    Err(CoreError::Misuse(
        "OS keychain key could not unwrap this vault's keyring; use recovery unlock or restore the original OS keychain credential".into(),
    ))
}

fn load_keychain_kek_candidates(root: &Path) -> Result<Vec<KeychainKekCandidate>> {
    let mut candidates = Vec::new();
    let mut decode_error: Option<CoreError> = None;
    let scoped = load_scoped_keychain_b64(root)?;
    if let Some(b64) = scoped.as_deref() {
        match decode_keychain_kek(b64) {
            Ok(kek) => candidates.push(KeychainKekCandidate {
                kek,
                source: KeychainKekSource::Scoped,
            }),
            Err(error) => decode_error = Some(error),
        }
    }

    if let Some(b64) = sv_keychain::load_master_key()? {
        if scoped.as_deref() != Some(b64.as_str()) {
            match decode_keychain_kek(&b64) {
                Ok(kek) => candidates.push(KeychainKekCandidate {
                    kek,
                    source: KeychainKekSource::Legacy,
                }),
                Err(error) => decode_error = Some(error),
            }
        }
    }

    if candidates.is_empty() {
        if let Some(error) = decode_error {
            return Err(error);
        }
    }

    Ok(candidates)
}

fn load_scoped_keychain_b64(root: &Path) -> Result<Option<String>> {
    sv_keychain::load_master_key_for_account(&keychain_account_for_root(root))
        .map_err(CoreError::from)
}

fn store_scoped_keychain_kek(root: &Path, kek: &MasterKey) -> Result<()> {
    sv_keychain::store_master_key_for_account(
        &keychain_account_for_root(root),
        &B64.encode(kek.as_bytes()),
    )
    .map_err(CoreError::from)
}

fn has_keychain_kek(root: &Path) -> Result<bool> {
    if load_scoped_keychain_b64(root)?.is_some() {
        return Ok(true);
    }

    let has_manifest = path_entry_exists(&root.join("manifest.json"));
    let has_passphrase_salt = path_entry_exists(&root.join(SALT_FILENAME));
    if has_manifest && !has_passphrase_salt {
        return Ok(sv_keychain::load_master_key()?.is_some());
    }

    Ok(false)
}

fn keychain_account_for_root(root: &Path) -> String {
    let mut normalized = root
        .canonicalize()
        .unwrap_or_else(|_| root.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/");
    if cfg!(windows) {
        normalized = normalized.to_ascii_lowercase();
    }
    let digest = Sha256::digest(normalized.as_bytes());
    format!("master-key-{}", B64_URL.encode(&digest[..16]))
}

fn decode_keychain_kek(b64: &str) -> Result<MasterKey> {
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
    Ok(MasterKey::from_bytes(bytes))
}

fn derive_passphrase_kek(root: &Path, passphrase: &str) -> Result<MasterKey> {
    let salt = read_salt(root)?;
    MasterKey::from_passphrase(passphrase, &salt).map_err(CoreError::from)
}

#[async_trait::async_trait]
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
    fn create_container(
        &self,
        name: &str,
        mode: &str,
        description: Option<&str>,
    ) -> std::result::Result<(), String> {
        let parsed = SecurityMode::parse(mode).map_err(|e| e.to_string())?;
        VaultHandle::create_container(self, name, parsed, description.map(|s| s.to_string()))
            .map_err(|e| e.to_string())
    }
    fn container_mode(&self, container: &str) -> std::result::Result<SecurityMode, String> {
        VaultHandle::container_mode(self, container).map_err(|e| e.to_string())
    }

    fn destroy_container(&self, name: &str) -> std::result::Result<(), String> {
        VaultHandle::delete_container(self, name).map_err(|e| e.to_string())
    }

    fn custody_mode_label(&self) -> &'static str {
        match self.custody {
            CustodyMode::OsKeychain => "os_keychain",
            CustodyMode::Passphrase => "passphrase",
            CustodyMode::Recovery => "recovery",
        }
    }

    fn transit_create_key(
        &self,
        name: &str,
    ) -> std::result::Result<sv_mcp::TransitKeyInfo, String> {
        let info = VaultHandle::transit_create_key(self, name).map_err(|e| e.to_string())?;
        Ok(sv_mcp::TransitKeyInfo {
            name: info.name,
            version: info.version,
        })
    }

    fn transit_list(&self) -> std::result::Result<Vec<sv_mcp::TransitKeyInfo>, String> {
        VaultHandle::transit_list(self)
            .map_err(|e| e.to_string())
            .map(|items| {
                items
                    .into_iter()
                    .map(|info| sv_mcp::TransitKeyInfo {
                        name: info.name,
                        version: info.version,
                    })
                    .collect()
            })
    }

    fn transit_encrypt(
        &self,
        key_ref: &str,
        plaintext: &[u8],
    ) -> std::result::Result<String, String> {
        VaultHandle::transit_encrypt(self, key_ref, plaintext).map_err(|e| e.to_string())
    }

    fn transit_decrypt(
        &self,
        key_ref: &str,
        ciphertext_b64: &str,
    ) -> std::result::Result<Vec<u8>, String> {
        VaultHandle::transit_decrypt(self, key_ref, ciphertext_b64).map_err(|e| e.to_string())
    }

    fn sign(&self, key_ref: &str, payload: &[u8]) -> std::result::Result<String, String> {
        VaultHandle::signing_sign(self, key_ref, payload).map_err(|e| e.to_string())
    }

    fn signing_public_key(&self, key_ref: &str) -> std::result::Result<String, String> {
        VaultHandle::signing_public_key(self, key_ref).map_err(|e| e.to_string())
    }

    fn signing_create_key(
        &self,
        name: &str,
    ) -> std::result::Result<sv_mcp::SigningKeyInfo, String> {
        let info = VaultHandle::signing_create_key(self, name).map_err(|e| e.to_string())?;
        Ok(sv_mcp::SigningKeyInfo {
            name: info.name,
            version: info.version,
            public_key_b64: info.public_b64,
        })
    }

    fn signing_list(&self) -> std::result::Result<Vec<sv_mcp::SigningKeyInfo>, String> {
        VaultHandle::signing_list(self)
            .map_err(|e| e.to_string())
            .map(|items| {
                items
                    .into_iter()
                    .map(|info| sv_mcp::SigningKeyInfo {
                        name: info.name,
                        version: info.version,
                        public_key_b64: info.public_b64,
                    })
                    .collect()
            })
    }

    fn broker_create(
        &self,
        name: &str,
        secret: &str,
        allow: Vec<sv_mcp::BrokerAllow>,
        injection: sv_mcp::BrokerInjection,
    ) -> std::result::Result<sv_mcp::BrokerSecretInfo, String> {
        let allow = allow
            .into_iter()
            .map(|entry| transit::BrokerAllow {
                host: entry.host,
                path_prefix: entry.path_prefix,
                methods: entry.methods,
                allow_private_ip: entry.allow_private_ip,
            })
            .collect();
        let injection = match injection {
            sv_mcp::BrokerInjection::BearerAuth => transit::BrokerInjection::BearerAuth,
            sv_mcp::BrokerInjection::Header { name } => transit::BrokerInjection::Header { name },
        };
        let info = VaultHandle::broker_create(self, name, secret, allow, injection)
            .map_err(|e| e.to_string())?;
        Ok(sv_mcp::BrokerSecretInfo {
            name: info.name,
            allow: info
                .allow
                .into_iter()
                .map(|entry| sv_mcp::BrokerAllow {
                    host: entry.host,
                    path_prefix: entry.path_prefix,
                    methods: entry.methods,
                    allow_private_ip: entry.allow_private_ip,
                })
                .collect(),
            injection: match info.injection {
                transit::BrokerInjection::BearerAuth => sv_mcp::BrokerInjection::BearerAuth,
                transit::BrokerInjection::Header { name } => {
                    sv_mcp::BrokerInjection::Header { name }
                }
            },
        })
    }

    fn broker_list(&self) -> std::result::Result<Vec<sv_mcp::BrokerSecretInfo>, String> {
        VaultHandle::broker_list(self)
            .map_err(|e| e.to_string())
            .map(|items| {
                items
                    .into_iter()
                    .map(|info| sv_mcp::BrokerSecretInfo {
                        name: info.name,
                        allow: info
                            .allow
                            .into_iter()
                            .map(|entry| sv_mcp::BrokerAllow {
                                host: entry.host,
                                path_prefix: entry.path_prefix,
                                methods: entry.methods,
                                allow_private_ip: entry.allow_private_ip,
                            })
                            .collect(),
                        injection: match info.injection {
                            transit::BrokerInjection::BearerAuth => {
                                sv_mcp::BrokerInjection::BearerAuth
                            }
                            transit::BrokerInjection::Header { name } => {
                                sv_mcp::BrokerInjection::Header { name }
                            }
                        },
                    })
                    .collect()
            })
    }

    fn broker_enabled(&self) -> bool {
        broker::is_enabled()
    }

    async fn broker_request(
        &self,
        secret_ref: &str,
        method: &str,
        url: &str,
        headers: std::collections::BTreeMap<String, String>,
        body: Option<String>,
    ) -> std::result::Result<sv_mcp::BrokerOutcome, String> {
        let resolved = self.broker_resolve(secret_ref).map_err(|e| e.to_string())?;
        let request = broker::BrokerRequest {
            method: method.to_string(),
            url: url.to_string(),
            headers,
            body,
        };
        // Resolve the target host for audit attribution before the call.
        let host = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_default();
        let response = broker::execute(&request, &resolved)
            .await
            .map_err(|e| e.to_string())?;
        Ok(sv_mcp::BrokerOutcome {
            status: response.status,
            headers: response.headers,
            body: response.body,
            host,
            method: method.to_ascii_uppercase(),
        })
    }

    fn list_agents(&self) -> std::result::Result<Vec<sv_mcp::AgentInfo>, String> {
        VaultHandle::list_agents(self)
            .map(|v| {
                v.into_iter()
                    .map(|a| sv_mcp::AgentInfo {
                        agent_id: a.agent_id,
                        name: a.name,
                        scopes: a
                            .scopes
                            .into_iter()
                            .map(|s| sv_mcp::AgentScope {
                                container_glob: s.container_glob,
                                actions: s.actions,
                                mode_ceiling: s.mode_ceiling,
                            })
                            .collect(),
                        created_at: a.created_at.to_rfc3339(),
                        expires_at: a.expires_at.map(|t| t.to_rfc3339()),
                        revoked: a.revoked,
                    })
                    .collect()
            })
            .map_err(|e| e.to_string())
    }

    fn create_agent(
        &self,
        name: &str,
        scopes: Vec<sv_mcp::AgentScope>,
    ) -> std::result::Result<(String, String), String> {
        for scope in &scopes {
            sv_mcp::validate_agent_scope(scope)?;
        }
        let scopes: Vec<crate::agents::AgentScope> = scopes
            .into_iter()
            .map(|s| crate::agents::AgentScope {
                container_glob: s.container_glob,
                actions: s.actions,
                mode_ceiling: s.mode_ceiling,
            })
            .collect();
        VaultHandle::create_agent(self, name, scopes).map_err(|e| e.to_string())
    }

    fn revoke_agent(&self, agent_id: &str) -> std::result::Result<(), String> {
        VaultHandle::revoke_agent(self, agent_id).map_err(|e| e.to_string())
    }

    fn import_agents_atomically(
        &self,
        entries: Vec<sv_mcp::AgentImportEntry>,
        replace_existing: bool,
    ) -> std::result::Result<sv_mcp::AgentImportResult, String> {
        for entry in &entries {
            if entry.scopes.is_empty() {
                return Err(format!(
                    "cannot import unscoped agent {}; at least one concrete scope is required",
                    entry.name
                ));
            }
            for scope in &entry.scopes {
                sv_mcp::validate_agent_scope(scope)?;
            }
        }
        let entries = entries
            .into_iter()
            .map(|entry| crate::agents::AgentImportEntry {
                name: entry.name,
                scopes: entry
                    .scopes
                    .into_iter()
                    .map(|scope| crate::agents::AgentScope {
                        container_glob: scope.container_glob,
                        actions: scope.actions,
                        mode_ceiling: scope.mode_ceiling,
                    })
                    .collect(),
            })
            .collect();
        crate::agents::import_agents_atomically(
            self.root(),
            &self.agent_token_key(),
            entries,
            replace_existing,
        )
        .map(|result| sv_mcp::AgentImportResult {
            imported: result
                .imported
                .into_iter()
                .map(|agent| sv_mcp::ImportedAgent {
                    name: agent.name,
                    agent_id: agent.agent_id,
                    one_time_token: agent.one_time_token,
                })
                .collect(),
            skipped: result.skipped,
            revoked: result.revoked,
        })
        .map_err(|e| e.to_string())
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
    /// True if the OS keychain has a key entry (the KEK).
    pub has_keychain_entry: bool,
    /// Native keychain backend selected for this target.
    pub keychain_backend: &'static str,
    /// True if the current OS session can write, read, and delete keychain entries.
    pub keychain_available: bool,
    /// Human-readable keychain availability failure, when unavailable.
    pub keychain_error: Option<String>,
    /// True if the recovery bundle exists.
    pub has_recovery_bundle: bool,
    /// True if the keyring (`keyring.svault`) is present. False for legacy
    /// vaults that have not yet been migrated on first unlock.
    pub has_keyring: bool,
}

/// Probe the on-disk + keychain state of a vault root.
pub fn probe(root: &Path) -> Result<InitState> {
    let manifest = root.join("manifest.json");
    let salt = root.join(SALT_FILENAME);
    let keychain = sv_keychain::availability();
    let (has_keychain_entry, keychain_error) = match has_keychain_kek(root) {
        Ok(has_entry) => (has_entry, keychain.error.clone()),
        // The keychain is unreachable (no backend on this platform/session) or
        // the backend itself errored (e.g. no D-Bus Secret Service on a headless
        // Linux box). Either way we cannot observe an entry: report none and
        // surface the reason, rather than failing the whole probe. A passphrase
        // vault must remain probe-able without a working OS keychain.
        Err(CoreError::Keychain(
            sv_keychain::KeychainError::Unavailable(error)
            | sv_keychain::KeychainError::Backend(error),
        )) => (false, Some(error)),
        Err(error) => return Err(error),
    };
    Ok(InitState {
        initialized: path_entry_exists(&manifest),
        has_passphrase_salt: path_entry_exists(&salt),
        has_keychain_entry,
        keychain_backend: keychain.backend,
        keychain_available: keychain.available,
        keychain_error,
        has_recovery_bundle: sv_recovery::has_recovery_bundle(root),
        has_keyring: keyring::exists(root),
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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PASSPHRASE: &str = "correct horse battery staple";
    const NEW_TEST_PASSPHRASE: &str = "a different strong passphrase";

    fn tmp_dir(label: &str) -> PathBuf {
        let suffix = B64_URL.encode(sv_crypto::random_bytes(8).unwrap());
        std::env::temp_dir().join(format!("sv-core-unit-{label}-{suffix}"))
    }

    fn bootstrap_passphrase(label: &str) -> (PathBuf, BootstrapResult) {
        let root = tmp_dir(label);
        let boot =
            VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some(TEST_PASSPHRASE)).unwrap();
        (root, boot)
    }

    #[test]
    fn keychain_account_is_scoped_by_vault_root() {
        let base = std::env::temp_dir().join("sovereign-vault-keychain-account-test");
        let first = base.join("first");
        let second = base.join("second");

        let first_account = keychain_account_for_root(&first);
        let same_first_account = keychain_account_for_root(&first);
        let second_account = keychain_account_for_root(&second);

        assert_eq!(first_account, same_first_account);
        assert_ne!(first_account, second_account);
        assert!(first_account.starts_with("master-key-"));
        assert!(second_account.starts_with("master-key-"));
    }

    #[test]
    fn incomplete_bootstrap_is_rolled_back_before_retry() {
        let root = tmp_dir("bootstrap-incomplete");
        fs::create_dir_all(&root).unwrap();
        let salt = [7u8; SALT_LEN];
        write_lifecycle(
            &root,
            &LifecycleJournal::Bootstrap {
                custody: "passphrase".into(),
                salt_b64: Some(B64.encode(salt)),
                scoped_kek_fingerprint: None,
                wrapped_phrase_b64: None,
            },
        )
        .unwrap();
        write_atomic(&root.join(SALT_FILENAME), &salt).unwrap();
        write_atomic(&root.join("manifest.json"), b"interrupted").unwrap();
        write_atomic(&root.join(keyring::KEYRING_FILE), b"interrupted").unwrap();

        let boot =
            VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some(TEST_PASSPHRASE)).unwrap();
        assert!(!boot.recovery_phrase.is_empty());
        assert!(boot.handle.list_containers().unwrap().is_empty());
        assert!(read_lifecycle(&root).unwrap().is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_keychain_bootstrap_cleans_only_its_matching_scoped_kek() {
        use std::cell::Cell;

        let root = tmp_dir("bootstrap-keychain-cleanup");
        fs::create_dir_all(&root).unwrap();
        let kek = MasterKey::from_bytes([42u8; MASTER_KEY_LEN]);
        let encoded_kek = B64.encode(kek.as_bytes());
        let fingerprint = keychain_kek_fingerprint(&kek);
        write_lifecycle(
            &root,
            &LifecycleJournal::Bootstrap {
                custody: "os_keychain".into(),
                salt_b64: None,
                scoped_kek_fingerprint: Some(fingerprint.clone()),
                wrapped_phrase_b64: None,
            },
        )
        .unwrap();
        write_atomic(&root.join("manifest.json"), b"interrupted").unwrap();
        write_atomic(&root.join(keyring::KEYRING_FILE), b"interrupted").unwrap();

        let scoped_deleted = Cell::new(false);
        let legacy_deleted = Cell::new(false);
        rollback_incomplete_bootstrap_with_cleanup(
            &root,
            "os_keychain",
            Some(&fingerprint),
            |cleanup_root, expected| {
                assert_eq!(cleanup_root, root);
                cleanup_matching_bootstrap_keychain_kek_with(
                    expected,
                    || Ok(Some(encoded_kek.clone())),
                    || {
                        scoped_deleted.set(true);
                        Ok(())
                    },
                )
            },
        )
        .unwrap();

        assert!(scoped_deleted.get());
        assert!(!legacy_deleted.get());
        assert_ne!(keychain_account_for_root(&root), sv_keychain::ACCOUNT);
        assert!(!root.join("manifest.json").exists());
        assert!(!root.join(keyring::KEYRING_FILE).exists());
        assert!(read_lifecycle(&root).unwrap().is_none());

        let mismatch_deleted = Cell::new(false);
        let mismatched = cleanup_matching_bootstrap_keychain_kek_with(
            &fingerprint,
            || Ok(Some(B64.encode([7u8; MASTER_KEY_LEN]))),
            || {
                mismatch_deleted.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert!(!mismatched);
        assert!(!mismatch_deleted.get());

        let journal = serde_json::to_string(&LifecycleJournal::Bootstrap {
            custody: "os_keychain".into(),
            salt_b64: None,
            scoped_kek_fingerprint: Some(fingerprint),
            wrapped_phrase_b64: None,
        })
        .unwrap();
        assert!(!journal.contains(&encoded_kek));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn completed_bootstrap_journal_returns_the_same_recovery_phrase() {
        let (root, boot) = bootstrap_passphrase("bootstrap-completed");
        let phrase = boot.recovery_phrase.clone();
        drop(boot.handle);
        let salt = read_salt(&root).unwrap();
        let kek = MasterKey::from_passphrase(TEST_PASSPHRASE, &salt).unwrap();
        write_lifecycle(
            &root,
            &LifecycleJournal::Bootstrap {
                custody: "passphrase".into(),
                salt_b64: Some(B64.encode(salt)),
                scoped_kek_fingerprint: None,
                wrapped_phrase_b64: Some(seal_lifecycle_phrase(&kek, &phrase).unwrap()),
            },
        )
        .unwrap();

        let resumed =
            VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some(TEST_PASSPHRASE)).unwrap();
        assert_eq!(resumed.recovery_phrase, phrase);
        assert!(read_lifecycle(&root).unwrap().is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn bootstrap_commits_authenticated_audit_before_returning_recovery_phrase() {
        let (root, boot) = bootstrap_passphrase("bootstrap-audit");
        let audit = sv_audit::AuditLog::open(&root, boot.handle.audit_hmac_key()).unwrap();

        assert!(audit.verify_chain().unwrap().ok);
        assert!(read_lifecycle(&root).unwrap().is_none());
        drop(boot.handle);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unlock_finishes_audit_after_committed_bootstrap_interruption() {
        let (root, boot) = bootstrap_passphrase("bootstrap-audit-resume");
        let phrase = boot.recovery_phrase.clone();
        drop(boot.handle);
        fs::remove_file(root.join(sv_audit::AUDIT_FILE)).unwrap();
        fs::remove_file(root.join(sv_audit::CHECKPOINT_FILE)).unwrap();

        let salt = read_salt(&root).unwrap();
        let kek = MasterKey::from_passphrase(TEST_PASSPHRASE, &salt).unwrap();
        write_lifecycle(
            &root,
            &LifecycleJournal::Bootstrap {
                custody: "passphrase".into(),
                salt_b64: Some(B64.encode(salt)),
                scoped_kek_fingerprint: None,
                wrapped_phrase_b64: Some(seal_lifecycle_phrase(&kek, &phrase).unwrap()),
            },
        )
        .unwrap();

        let handle =
            VaultHandle::unlock(&root, CustodyMode::Passphrase, Some(TEST_PASSPHRASE)).unwrap();
        assert!(
            sv_audit::AuditLog::open(&root, handle.audit_hmac_key())
                .unwrap()
                .verify_chain()
                .unwrap()
                .ok
        );
        assert!(read_lifecycle(&root).unwrap().is_none());
        drop(handle);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn passphrase_change_before_salt_commit_rolls_back() {
        let (root, boot) = bootstrap_passphrase("passphrase-old-side");
        drop(boot.handle);
        let old_salt = read_salt(&root).unwrap();
        let old_kek = MasterKey::from_passphrase(TEST_PASSPHRASE, &old_salt).unwrap();
        let new_salt = [8u8; SALT_LEN];
        let new_kek = MasterKey::from_passphrase(NEW_TEST_PASSPHRASE, &new_salt).unwrap();
        keyring::stage_rewrap_under_new_kek(&root, &old_kek, &new_kek).unwrap();
        write_lifecycle(
            &root,
            &LifecycleJournal::ChangePassphrase {
                old_salt_b64: B64.encode(old_salt),
                new_salt_b64: B64.encode(new_salt),
            },
        )
        .unwrap();

        let handle =
            VaultHandle::unlock(&root, CustodyMode::Passphrase, Some(TEST_PASSPHRASE)).unwrap();
        assert_eq!(handle.custody(), CustodyMode::Passphrase);
        assert!(!root.join(keyring::STAGED_KEYRING_FILE).exists());
        assert!(read_lifecycle(&root).unwrap().is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn passphrase_change_after_salt_commit_promotes_staged_keyring() {
        let (root, boot) = bootstrap_passphrase("passphrase-new-side");
        drop(boot.handle);
        let old_salt = read_salt(&root).unwrap();
        let old_kek = MasterKey::from_passphrase(TEST_PASSPHRASE, &old_salt).unwrap();
        let new_salt = [9u8; SALT_LEN];
        let new_kek = MasterKey::from_passphrase(NEW_TEST_PASSPHRASE, &new_salt).unwrap();
        keyring::stage_rewrap_under_new_kek(&root, &old_kek, &new_kek).unwrap();
        write_lifecycle(
            &root,
            &LifecycleJournal::ChangePassphrase {
                old_salt_b64: B64.encode(old_salt),
                new_salt_b64: B64.encode(new_salt),
            },
        )
        .unwrap();
        write_atomic(&root.join(SALT_FILENAME), &new_salt).unwrap();

        VaultHandle::unlock(&root, CustodyMode::Passphrase, Some(NEW_TEST_PASSPHRASE)).unwrap();
        assert!(keyring::load(&root, &new_kek).is_ok());
        assert!(keyring::load(&root, &old_kek).is_err());
        assert!(read_lifecycle(&root).unwrap().is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn keychain_move_before_keychain_store_rolls_back_to_passphrase() {
        let (root, boot) = bootstrap_passphrase("move-before-keychain");
        drop(boot.handle);
        let old_salt = read_salt(&root).unwrap();
        let old_kek = MasterKey::from_passphrase(TEST_PASSPHRASE, &old_salt).unwrap();
        let new_kek = MasterKey::generate();
        keyring::stage_rewrap_under_new_kek(&root, &old_kek, &new_kek).unwrap();
        write_lifecycle(&root, &LifecycleJournal::MoveToKeychain).unwrap();

        let custody = recover_move_to_keychain(
            &root,
            CustodyMode::Passphrase,
            Some(TEST_PASSPHRASE),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(custody, CustodyMode::Passphrase);
        assert!(root.join(SALT_FILENAME).exists());
        assert!(keyring::load(&root, &old_kek).is_ok());
        assert!(!root.join(keyring::STAGED_KEYRING_FILE).exists());
        assert!(read_lifecycle(&root).unwrap().is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn keychain_move_after_keychain_store_commits_staged_keyring() {
        let (root, boot) = bootstrap_passphrase("move-after-keychain");
        drop(boot.handle);
        let old_salt = read_salt(&root).unwrap();
        let old_kek = MasterKey::from_passphrase(TEST_PASSPHRASE, &old_salt).unwrap();
        let new_kek = MasterKey::generate();
        keyring::stage_rewrap_under_new_kek(&root, &old_kek, &new_kek).unwrap();
        write_lifecycle(&root, &LifecycleJournal::MoveToKeychain).unwrap();

        let custody = recover_move_to_keychain(
            &root,
            CustodyMode::Passphrase,
            Some(TEST_PASSPHRASE),
            vec![new_kek.clone()],
        )
        .unwrap();
        assert_eq!(custody, CustodyMode::OsKeychain);
        assert!(!root.join(SALT_FILENAME).exists());
        assert!(keyring::load(&root, &new_kek).is_ok());
        assert!(read_lifecycle(&root).unwrap().is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_rotation_rolls_files_material_and_recovery_back() {
        let (root, boot) = bootstrap_passphrase("rotation-rollback");
        let old_phrase = boot.recovery_phrase.clone();
        let handle = boot.handle;
        handle
            .create_container("documents", SecurityMode::Direct, None)
            .unwrap();
        handle.write_file("documents", "a", b"alpha").unwrap();
        handle.write_file("documents", "b", b"beta").unwrap();
        handle.transit_create_key("service").unwrap();
        let old_wrap = handle.material_wrap_key();
        let old_salt = read_salt(&root).unwrap();
        let kek = MasterKey::from_passphrase(TEST_PASSPHRASE, &old_salt).unwrap();
        let old_version = keyring::active_version(&root).unwrap();
        let recovery_backup = fs::read(root.join(sv_recovery::RECOVERY_FILE)).unwrap();
        let new_dek = MasterKey::generate();
        let new_version = old_version + 1;
        write_lifecycle(
            &root,
            &LifecycleJournal::Rotate {
                old_version,
                new_version,
                recovery_backup_b64: B64.encode(recovery_backup),
            },
        )
        .unwrap();
        assert_eq!(
            keyring::add_active_dek(&root, &kek, &new_dek).unwrap(),
            new_version
        );
        let unwrapped = keyring::load(&root, &kek).unwrap();
        let manifest_auth_key = sv_storage::derive_manifest_auth_key(&handle.identity_root);
        let rotating = Vault::open_existing_with_keys_and_manifest_key(
            &root,
            unwrapped.keys,
            unwrapped.active_version,
            manifest_auth_key,
        )
        .unwrap();
        rotating.rewrap_file("documents", "a").unwrap();
        let new_wrap =
            MasterKey::from_bytes(sv_crypto::derive_subkey(&new_dek, MATERIAL_WRAP_CONTEXT));
        transit::rewrap_all_material(&root, &old_wrap, &new_wrap).unwrap();
        let _new_phrase =
            sv_recovery::issue_recovery_phrase_for_version(&root, &new_dek, new_version).unwrap();
        drop(handle);

        let recovered =
            VaultHandle::unlock(&root, CustodyMode::Passphrase, Some(TEST_PASSPHRASE)).unwrap();
        assert_eq!(recovered.read_file("documents", "a").unwrap(), b"alpha");
        assert_eq!(recovered.read_file("documents", "b").unwrap(), b"beta");
        let ciphertext = recovered.transit_encrypt("service", b"secret").unwrap();
        assert_eq!(
            recovered.transit_decrypt("service", &ciphertext).unwrap(),
            b"secret"
        );
        assert_eq!(keyring::active_version(&root).unwrap(), old_version);
        drop(recovered);
        VaultHandle::unlock_with_recovery(&root, &old_phrase).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn versioned_recovery_key_is_never_relabelled_as_active() {
        let (root, boot) = bootstrap_passphrase("recovery-version");
        let old_phrase = boot.recovery_phrase.clone();
        drop(boot.handle);
        let salt = read_salt(&root).unwrap();
        let kek = MasterKey::from_passphrase(TEST_PASSPHRASE, &salt).unwrap();
        keyring::add_active_dek(&root, &kek, &MasterKey::generate()).unwrap();

        let error = match VaultHandle::unlock_with_recovery(&root, &old_phrase) {
            Ok(_) => panic!("old versioned recovery key must not be relabelled"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("contains DEK v1"), "{error}");
        assert!(error.to_string().contains("active DEK v2"), "{error}");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lifecycle_journal_never_contains_passphrases_or_raw_keys() {
        let (root, boot) = bootstrap_passphrase("journal-secrets");
        drop(boot.handle);
        let old_salt = read_salt(&root).unwrap();
        let old_kek = MasterKey::from_passphrase(TEST_PASSPHRASE, &old_salt).unwrap();
        let new_salt = [11u8; SALT_LEN];
        let new_kek = MasterKey::from_passphrase(NEW_TEST_PASSPHRASE, &new_salt).unwrap();
        keyring::stage_rewrap_under_new_kek(&root, &old_kek, &new_kek).unwrap();
        write_lifecycle(
            &root,
            &LifecycleJournal::ChangePassphrase {
                old_salt_b64: B64.encode(old_salt),
                new_salt_b64: B64.encode(new_salt),
            },
        )
        .unwrap();
        let raw = fs::read(lifecycle_path(&root)).unwrap();
        assert!(!raw
            .windows(TEST_PASSPHRASE.len())
            .any(|window| window == TEST_PASSPHRASE.as_bytes()));
        assert!(!raw
            .windows(NEW_TEST_PASSPHRASE.len())
            .any(|window| window == NEW_TEST_PASSPHRASE.as_bytes()));
        assert!(!raw
            .windows(MASTER_KEY_LEN)
            .any(|window| window == old_kek.as_bytes()));
        assert!(!raw
            .windows(MASTER_KEY_LEN)
            .any(|window| window == new_kek.as_bytes()));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sensitive_writers_leave_no_temp_files() {
        let (root, boot) = bootstrap_passphrase("secure-temp");
        boot.handle.transit_create_key("service").unwrap();
        let names: Vec<_> = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().all(|name| !name.ends_with(".tmp")));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            for name in [
                SALT_FILENAME,
                keyring::KEYRING_FILE,
                sv_recovery::RECOVERY_FILE,
                transit::TRANSIT_FILE,
            ] {
                let mode = fs::metadata(root.join(name)).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "{name} must be owner-only");
            }
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn live_handle_excludes_contenders_and_drop_releases_lock() {
        let (root, boot) = bootstrap_passphrase("lock-contention");

        let error = match VaultHandle::unlock(&root, CustodyMode::Passphrase, Some(TEST_PASSPHRASE))
        {
            Ok(_) => panic!("a second live handle must not acquire the vault lock"),
            Err(error) => error,
        };
        assert!(matches!(error, CoreError::VaultLocked(_)), "{error}");
        assert!(
            probe(&root).unwrap().initialized,
            "probe must remain non-locking"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = fs::metadata(root.join(VAULT_LOCK_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        drop(boot.handle);
        VaultHandle::unlock(&root, CustodyMode::Passphrase, Some(TEST_PASSPHRASE)).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn failed_unlock_releases_lock() {
        let (root, boot) = bootstrap_passphrase("lock-failed-unlock");
        drop(boot.handle);

        assert!(VaultHandle::unlock(
            &root,
            CustodyMode::Passphrase,
            Some("incorrect but long passphrase"),
        )
        .is_err());
        VaultHandle::unlock(&root, CustodyMode::Passphrase, Some(TEST_PASSPHRASE)).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn vault_lock_child_process() {
        let Ok(root) = std::env::var("SV_TEST_LOCK_CHILD_ROOT") else {
            return;
        };
        let ready = std::env::var("SV_TEST_LOCK_CHILD_READY").unwrap();
        let _handle = VaultHandle::unlock(
            Path::new(&root),
            CustodyMode::Passphrase,
            Some(TEST_PASSPHRASE),
        )
        .unwrap();
        fs::write(ready, b"locked").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(60));
    }

    #[test]
    fn killed_process_releases_vault_lock() {
        use std::process::{Command, Stdio};

        let (root, boot) = bootstrap_passphrase("lock-process-crash");
        drop(boot.handle);
        let ready = root.join("child.ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::vault_lock_child_process", "--nocapture"])
            .env("SV_TEST_LOCK_CHILD_ROOT", &root)
            .env("SV_TEST_LOCK_CHILD_READY", &ready)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !ready.exists() && std::time::Instant::now() < deadline {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("lock-holder child exited before acquiring the lock: {status}");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(ready.exists(), "lock-holder child did not become ready");

        let error = match VaultHandle::unlock(&root, CustodyMode::Passphrase, Some(TEST_PASSPHRASE))
        {
            Ok(_) => panic!("parent acquired a lock held by a child process"),
            Err(error) => error,
        };
        assert!(matches!(error, CoreError::VaultLocked(_)), "{error}");

        child.kill().unwrap();
        child.wait().unwrap();
        let reopened =
            VaultHandle::unlock(&root, CustodyMode::Passphrase, Some(TEST_PASSPHRASE)).unwrap();
        drop(reopened);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_identity_migration_preserves_existing_agent_tokens() {
        let root = tmp_dir("identity-migration");
        fs::create_dir_all(&root).unwrap();
        let salt = sv_crypto::random_salt().unwrap();
        write_atomic(&root.join(SALT_FILENAME), &salt).unwrap();
        let legacy_dek = MasterKey::from_passphrase(TEST_PASSPHRASE, &salt).unwrap();
        let vault = Vault::open_or_init(&root, legacy_dek.clone()).unwrap();
        drop(vault);
        let legacy_agent_key = sv_crypto::derive_subkey(&legacy_dek, b"sv-agent-token-v1");
        let legacy_audit_key = sv_crypto::derive_subkey(&legacy_dek, b"sv-audit-hmac-v1");
        let (agent_id, token) =
            agents::create_agent(&root, &legacy_agent_key, "legacy", Vec::new()).unwrap();
        assert!(!root.join(transit::IDENTITY_FILE).exists());

        // Migrate the legacy vault: create keyring, authenticate manifest, enable manifest auth.
        let digest = VaultHandle::manifest_migration_digest(&root).unwrap();
        VaultHandle::migrate_manifest_authentication(
            &root,
            CustodyMode::Passphrase,
            Some(TEST_PASSPHRASE),
            &digest,
        )
        .unwrap();

        let handle =
            VaultHandle::unlock(&root, CustodyMode::Passphrase, Some(TEST_PASSPHRASE)).unwrap();
        assert!(root.join(transit::IDENTITY_FILE).exists());
        assert_eq!(handle.audit_hmac_key(), legacy_audit_key);
        assert_eq!(handle.agent_token_key(), legacy_agent_key);
        handle.authenticate_agent(&agent_id, &token).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_core_read_boundaries_never_read_outside_vault() {
        use std::os::unix::fs::symlink;

        for boundary in ["keyring", "salt", "recovery", "identity", "lifecycle"] {
            let case = tmp_dir(&format!("symlink-read-{boundary}"));
            let root = case.join("vault");
            let boot =
                VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some(TEST_PASSPHRASE))
                    .unwrap();
            let phrase = boot.recovery_phrase.clone();
            drop(boot.handle);

            let outside = case.join(format!("outside-{boundary}"));
            let boundary_path = match boundary {
                "keyring" => root.join(keyring::KEYRING_FILE),
                "salt" => root.join(SALT_FILENAME),
                "recovery" => root.join(sv_recovery::RECOVERY_FILE),
                "identity" => root.join(transit::IDENTITY_FILE),
                "lifecycle" => lifecycle_path(&root),
                _ => unreachable!(),
            };
            if boundary == "lifecycle" {
                fs::write(
                    &outside,
                    br#"{"operation":"bootstrap","custody":"passphrase","salt_b64":"AA=="}"#,
                )
                .unwrap();
            } else {
                fs::rename(&boundary_path, &outside).unwrap();
            }
            let sentinel = fs::read(&outside).unwrap();
            symlink(&outside, &boundary_path).unwrap();

            let result = if boundary == "recovery" {
                VaultHandle::unlock_with_recovery(&root, &phrase)
            } else {
                VaultHandle::unlock(&root, CustodyMode::Passphrase, Some(TEST_PASSPHRASE))
            };
            let error = match result {
                Ok(_) => panic!("symlinked {boundary} boundary was followed"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("not a regular file"),
                "{boundary}: {error}"
            );
            assert_eq!(fs::read(&outside).unwrap(), sentinel, "{boundary}");
            let _ = fs::remove_dir_all(case);
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_core_write_and_lock_boundaries_never_overwrite_outside_vault() {
        use std::os::unix::fs::symlink;

        let lock_case = tmp_dir("symlink-lock");
        let lock_root = lock_case.join("vault");
        fs::create_dir_all(&lock_root).unwrap();
        let lock_outside = lock_case.join("outside-lock");
        fs::write(&lock_outside, b"outside-lock-sentinel").unwrap();
        symlink(&lock_outside, lock_root.join(VAULT_LOCK_FILE)).unwrap();
        let error = match VaultHandle::bootstrap(
            &lock_root,
            CustodyMode::Passphrase,
            Some(TEST_PASSPHRASE),
        ) {
            Ok(_) => panic!("symlinked vault lock was followed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("not a regular file"), "{error}");
        assert_eq!(fs::read(&lock_outside).unwrap(), b"outside-lock-sentinel");
        let _ = fs::remove_dir_all(lock_case);

        for boundary in ["staged-keyring", "transit", "signing", "brokers"] {
            let case = tmp_dir(&format!("symlink-write-{boundary}"));
            let root = case.join("vault");
            let boot =
                VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some(TEST_PASSPHRASE))
                    .unwrap();
            let handle = boot.handle;
            let outside = case.join(format!("outside-{boundary}"));
            let boundary_path = match boundary {
                "staged-keyring" => {
                    fs::copy(root.join(keyring::KEYRING_FILE), &outside).unwrap();
                    root.join(keyring::STAGED_KEYRING_FILE)
                }
                "transit" => {
                    fs::write(&outside, br#"{"schema":1,"entries":[]}"#).unwrap();
                    root.join(transit::TRANSIT_FILE)
                }
                "signing" => {
                    fs::write(&outside, br#"{"schema":1,"entries":[]}"#).unwrap();
                    root.join(transit::SIGNING_FILE)
                }
                "brokers" => {
                    fs::write(&outside, br#"{"schema":1,"entries":[]}"#).unwrap();
                    root.join(transit::BROKERS_FILE)
                }
                _ => unreachable!(),
            };
            let sentinel = fs::read(&outside).unwrap();
            symlink(&outside, &boundary_path).unwrap();

            let result = match boundary {
                "staged-keyring" => {
                    let salt = read_salt(&root).unwrap();
                    let old_kek = MasterKey::from_passphrase(TEST_PASSPHRASE, &salt).unwrap();
                    keyring::stage_rewrap_under_new_kek(&root, &old_kek, &MasterKey::generate())
                }
                "transit" => handle.transit_create_key("blocked").map(|_| ()),
                "signing" => handle.signing_create_key("blocked").map(|_| ()),
                "brokers" => handle
                    .broker_create(
                        "blocked",
                        "secret",
                        Vec::new(),
                        transit::BrokerInjection::BearerAuth,
                    )
                    .map(|_| ()),
                _ => unreachable!(),
            };
            let error = result.unwrap_err();
            assert!(
                error.to_string().contains("not a regular file"),
                "{boundary}: {error}"
            );
            assert_eq!(fs::read(&outside).unwrap(), sentinel, "{boundary}");
            drop(handle);
            let _ = fs::remove_dir_all(case);
        }
    }

    #[cfg(unix)]
    #[test]
    fn vault_lock_rejects_symlink_to_outside_sentinel() {
        use std::os::unix::fs::symlink;

        let case = tmp_dir("vault-lock-symlink");
        let root = case.join("vault");
        fs::create_dir_all(&root).unwrap();

        // Create an outside sentinel file that must not be modified.
        let sentinel = case.join("sentinel.txt");
        fs::write(&sentinel, b"untouched").unwrap();
        let sentinel_hash = {
            let contents = fs::read(&sentinel).unwrap();
            Sha256::digest(&contents)
        };

        // Replace .vault.lock with a symlink to the sentinel.
        let lock_path = root.join(VAULT_LOCK_FILE);
        symlink(&sentinel, &lock_path).unwrap();

        // Acquiring the lock must fail.
        let result = VaultLock::acquire(&root);
        assert!(
            result.is_err(),
            "lock acquisition should have failed for a symlink"
        );
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("not a regular file"),
            "error should mention 'not a regular file': {error}"
        );

        // The sentinel must be untouched.
        let sentinel_after = fs::read(&sentinel).unwrap();
        assert_eq!(
            Sha256::digest(&sentinel_after),
            sentinel_hash,
            "sentinel file was modified"
        );

        // Bootstrap must also fail.
        let error =
            match VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some(TEST_PASSPHRASE)) {
                Ok(_) => panic!("bootstrap should reject symlinked lock"),
                Err(error) => error.to_string(),
            };
        assert!(
            error.contains("not a regular file"),
            "bootstrap should reject symlinked lock: {error}"
        );

        let _ = fs::remove_dir_all(case);
    }
}
