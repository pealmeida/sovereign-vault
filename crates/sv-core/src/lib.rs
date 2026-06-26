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

pub mod agents;
pub mod broker;
pub mod keyring;
pub mod transit;

use std::fs;
use std::path::{Path, PathBuf};

use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64_URL},
    Engine as _,
};
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
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, CoreError>;

const SALT_FILENAME: &str = "master.salt";

/// HKDF context for the key under which transit/signing/broker material is
/// sealed. Derived from the active DEK, so rotation must re-wrap material
/// forward (see [`transit::rewrap_all_material`]).
const MATERIAL_WRAP_CONTEXT: &[u8] = b"sv-transit-wrap-v1";

/// Live, unlocked vault handle.
///
/// Owns an open [`Vault`] (and therefore the master key). Drop the
/// handle to lock the vault — the underlying [`MasterKey`] zeroises on drop.
pub struct VaultHandle {
    vault: Vault,
    custody: CustodyMode,
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
            fs::create_dir_all(root)?;
        }

        if root.join("manifest.json").exists() || keyring::exists(root) {
            return Err(CoreError::Misuse(
                "vault already initialised on disk - call unlock instead".into(),
            ));
        }

        match custody {
            CustodyMode::OsKeychain => {
                sv_keychain::ensure_available()?;
                // Keychain holds the KEK; a fresh random DEK seals the data and
                // is wrapped under the KEK in the keyring.
                let kek = MasterKey::generate();
                let dek = MasterKey::generate();
                store_scoped_keychain_kek(root, &kek)?;
                keyring::create(root, &kek, &dek)?;
                let recovery_key = dek.clone();
                let vault = Vault::open_or_init(root, dek)?;
                let recovery_phrase = sv_recovery::issue_recovery_phrase(root, &recovery_key)?;
                Ok(BootstrapResult {
                    handle: Self { vault, custody },
                    recovery_phrase,
                })
            }
            CustodyMode::Passphrase => {
                let pass = passphrase.ok_or_else(|| {
                    CoreError::Misuse("passphrase custody requires a passphrase".into())
                })?;
                let salt_path = root.join(SALT_FILENAME);
                // Passphrase derives the KEK; a fresh random DEK seals the data.
                let salt = sv_crypto::random_salt()?;
                fs::write(&salt_path, salt)?;
                let kek = MasterKey::from_passphrase(pass, &salt)?;
                let dek = MasterKey::generate();
                keyring::create(root, &kek, &dek)?;
                let recovery_key = dek.clone();
                let vault = Vault::open_or_init(root, dek)?;
                let recovery_phrase = sv_recovery::issue_recovery_phrase(root, &recovery_key)?;
                Ok(BootstrapResult {
                    handle: Self { vault, custody },
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
        if custody == CustodyMode::OsKeychain {
            return unlock_with_keychain(root);
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
        // Legacy vaults sealed files directly with this key; promote it to
        // DEK v1 wrapped under itself so the keyring path works uniformly.
        keyring::migrate_legacy(root, &kek)?;
        let unwrapped = keyring::load(root, &kek)?;
        let vault = Vault::open_existing_with_keys(root, unwrapped.keys, unwrapped.active_version)?;
        Ok(Self { vault, custody })
    }

    /// Unlock an existing vault using its persisted recovery bundle.
    ///
    /// The recovery phrase restores the active DEK directly (independent of
    /// the KEK), so it works even if the passphrase/keychain KEK is lost.
    pub fn unlock_with_recovery(root: &Path, phrase: &str) -> Result<Self> {
        let dek = sv_recovery::restore_master_key(root, phrase)?;
        let vault = if keyring::exists(root) {
            let active = keyring::active_version(root)?;
            if should_repair_keychain_after_recovery(root) {
                sv_keychain::ensure_available()?;
                let kek = MasterKey::generate();
                store_scoped_keychain_kek(root, &kek)?;
                keyring::replace_with_single_active_dek(root, &kek, active, &dek)?;
                let mut keys = std::collections::BTreeMap::new();
                keys.insert(active, dek);
                let vault = Vault::open_existing_with_keys(root, keys, active)?;
                return Ok(Self {
                    vault,
                    custody: CustodyMode::OsKeychain,
                });
            }
            let mut keys = std::collections::BTreeMap::new();
            keys.insert(active, dek);
            Vault::open_existing_with_keys(root, keys, active)?
        } else {
            // Legacy vault: the recovery key is DEK v1.
            Vault::open_existing(root, dek)?
        };
        Ok(Self {
            vault,
            custody: CustodyMode::Recovery,
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
    /// Limitation: this key is derived from the ACTIVE DEK, so after a key
    /// rotation it changes and `hmac_value` only matches entries written
    /// under the current key.
    pub fn audit_hmac_key(&self) -> [u8; 32] {
        self.vault.derive_subkey(b"sv-audit-hmac-v1")
    }

    /// Derive the keyed HMAC key used to hash agent tokens in `agents.json`.
    ///
    /// Like [`Self::audit_hmac_key`], this is derived from the ACTIVE DEK, so
    /// after a key rotation existing token hashes no longer verify.
    pub fn agent_token_key(&self) -> [u8; 32] {
        self.vault.derive_subkey(b"sv-agent-token-v1")
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
        agents::list_agents(self.root())
    }

    /// Revoke an agent by id.
    pub fn revoke_agent(&self, agent_id: &str) -> Result<()> {
        agents::revoke_agent(self.root(), agent_id)
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
        if self.custody != CustodyMode::Passphrase {
            return Err(CoreError::Misuse(
                "change_passphrase is only valid for passphrase custody".into(),
            ));
        }
        let old_kek = derive_passphrase_kek(root, current)?;
        // Verify the current passphrase actually unwraps the keyring before
        // we overwrite the salt.
        keyring::load(root, &old_kek)?;
        let new_salt = sv_crypto::random_salt()?;
        let new_kek = MasterKey::from_passphrase(new, &new_salt)?;
        keyring::rewrap_under_new_kek(root, &old_kek, &new_kek)?;
        fs::write(root.join(SALT_FILENAME), new_salt)?;
        Ok(())
    }

    /// Move a passphrase-custody vault to OS keychain custody.
    ///
    /// This re-wraps the keyring under a fresh random KEK stored in the native
    /// OS keychain. The passphrase salt is removed only after the new keychain
    /// entry has been stored and verified against the re-wrapped keyring.
    pub fn move_to_os_keychain(&mut self, root: &Path, current_passphrase: &str) -> Result<()> {
        if self.custody != CustodyMode::Passphrase {
            return Err(CoreError::Misuse(
                "move_to_os_keychain is only valid for passphrase custody".into(),
            ));
        }

        sv_keychain::ensure_available()?;
        let old_kek = derive_passphrase_kek(root, current_passphrase)?;
        keyring::load(root, &old_kek)?;

        let new_kek = MasterKey::generate();
        store_scoped_keychain_kek(root, &new_kek)?;
        keyring::rewrap_under_new_kek(root, &old_kek, &new_kek)?;
        keyring::load(root, &new_kek)?;
        fs::remove_file(root.join(SALT_FILENAME))?;
        self.custody = CustodyMode::OsKeychain;
        Ok(())
    }

    /// Rotate the data-encryption key.
    ///
    /// Generates a new DEK, re-seals every file forward to it, retires the old
    /// versions, and re-issues the recovery phrase (the old phrase no longer
    /// decrypts the vault). Requires the KEK, so pass the passphrase for
    /// passphrase custody (ignored for keychain custody). Returns the new
    /// recovery phrase.
    pub fn rotate_key(&mut self, root: &Path, passphrase: Option<&str>) -> Result<String> {
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

        // Capture the wrap key derived from the OLD active DEK before rotating.
        // Transit/signing/broker material is sealed under it; once the old DEK
        // is retired below we can no longer derive it, so we must re-wrap every
        // entry forward or it is permanently orphaned.
        let old_material_wrap = self.material_wrap_key();

        let new_dek = MasterKey::generate();
        let new_version = keyring::add_active_dek(root, &kek, &new_dek)?;

        // Reopen with all versions so old files stay readable while we migrate.
        let unwrapped = keyring::load(root, &kek)?;
        let vault = Vault::open_existing_with_keys(root, unwrapped.keys, unwrapped.active_version)?;

        // Re-seal every file forward to the new active version.
        for container in vault.list_containers()? {
            for file in vault.list_files(&container.name)? {
                vault.rewrap_file(&container.name, &file.name)?;
            }
        }

        // Drop superseded DEK versions, then reopen with only the active key.
        keyring::retire_below(root, new_version)?;
        let unwrapped = keyring::load(root, &kek)?;
        self.vault =
            Vault::open_existing_with_keys(root, unwrapped.keys, unwrapped.active_version)?;

        // `self.vault` now derives from the new DEK; re-seal every transit /
        // signing / broker secret forward from the old wrap key to the new one.
        let new_material_wrap = self.material_wrap_key();
        transit::rewrap_all_material(root, &old_material_wrap, &new_material_wrap)?;

        // The old recovery phrase wrapped the old DEK; re-issue for the new one.
        let recovery_phrase = sv_recovery::issue_recovery_phrase(root, &new_dek)?;
        Ok(recovery_phrase)
    }
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

fn unlock_with_keychain(root: &Path) -> Result<VaultHandle> {
    if root.join(SALT_FILENAME).exists() {
        return Err(CoreError::Misuse(
            "this vault uses passphrase custody; unlock with passphrase or recovery instead".into(),
        ));
    }

    if !keyring::exists(root) {
        return unlock_legacy_with_keychain(root);
    }
    let (_, unwrapped) = load_keychain_unwrapped(root)?;
    let vault = Vault::open_existing_with_keys(root, unwrapped.keys, unwrapped.active_version)?;
    Ok(VaultHandle {
        vault,
        custody: CustodyMode::OsKeychain,
    })
}

fn load_verified_keychain_kek(root: &Path) -> Result<MasterKey> {
    let (kek, _) = load_keychain_unwrapped(root)?;
    Ok(kek)
}

fn should_repair_keychain_after_recovery(root: &Path) -> bool {
    if !keyring::exists(root) || root.join(SALT_FILENAME).exists() {
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

fn unlock_legacy_with_keychain(root: &Path) -> Result<VaultHandle> {
    let mut candidates = load_keychain_kek_candidates(root)?;
    if candidates.is_empty() {
        return Err(CoreError::Misuse(
            "no key in OS keychain - bootstrap the vault first".into(),
        ));
    }
    candidates.sort_by_key(|candidate| match candidate.source {
        KeychainKekSource::Legacy => 0,
        KeychainKekSource::Scoped => 1,
    });

    for candidate in candidates {
        let legacy_vault = match Vault::open_existing(root, candidate.kek.clone()) {
            Ok(vault) => vault,
            Err(_) => continue,
        };
        if validate_legacy_vault_key(&legacy_vault).is_err() {
            continue;
        }

        keyring::migrate_legacy(root, &candidate.kek)?;
        let unwrapped = keyring::load(root, &candidate.kek)?;
        if candidate.source == KeychainKekSource::Legacy {
            store_scoped_keychain_kek(root, &candidate.kek)?;
        }
        let vault = Vault::open_existing_with_keys(root, unwrapped.keys, unwrapped.active_version)?;
        return Ok(VaultHandle {
            vault,
            custody: CustodyMode::OsKeychain,
        });
    }

    Err(CoreError::Misuse(
        "OS keychain key could not open this legacy vault; use recovery unlock or restore the original OS keychain credential".into(),
    ))
}

fn validate_legacy_vault_key(vault: &Vault) -> Result<()> {
    for container in vault.list_containers()? {
        if let Some(file) = vault.list_files(&container.name)?.into_iter().next() {
            vault.read_file(&container.name, &file.name)?;
            return Ok(());
        }
    }
    Ok(())
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

    let has_manifest = root.join("manifest.json").exists();
    let has_passphrase_salt = root.join(SALT_FILENAME).exists();
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
    let salt_raw = fs::read(root.join(SALT_FILENAME)).map_err(|_| {
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
        initialized: manifest.exists(),
        has_passphrase_salt: salt.exists(),
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
}
