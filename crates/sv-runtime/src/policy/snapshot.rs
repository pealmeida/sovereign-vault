//! Immutable, validated policy snapshots and the store that swaps them.

use std::sync::{Arc, RwLock};

use sha2::{Digest, Sha256};

use crate::error::{Result, RuntimeError};
use crate::policy::document::PolicyDocument;
use crate::policy::validate::{check, ValidationWarning};
use crate::types::PolicyVersion;

const DIGEST_DOMAIN: &[u8] = b"sovereign-vault/policy-snapshot/v1\0";

/// An immutable, validated policy snapshot with a stable digest.
#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    document: PolicyDocument,
    version: PolicyVersion,
    digest: [u8; 32],
    warnings: Vec<ValidationWarning>,
}

impl PolicySnapshot {
    /// Returns the validated policy document.
    pub fn document(&self) -> &PolicyDocument {
        &self.document
    }

    /// Returns the snapshot version.
    pub fn version(&self) -> &PolicyVersion {
        &self.version
    }

    /// Returns the 32-byte SHA-256 digest of the canonical document.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns validation warnings produced when the snapshot was created.
    pub fn warnings(&self) -> &[ValidationWarning] {
        &self.warnings
    }
}

/// Validates a document, computes its canonical digest, and returns a snapshot.
pub fn validate(document: PolicyDocument, version: PolicyVersion) -> Result<PolicySnapshot> {
    let warnings = check(&document)?;
    let digest = compute_digest(&document)?;

    Ok(PolicySnapshot {
        document,
        version,
        digest,
        warnings,
    })
}

fn compute_digest(document: &PolicyDocument) -> Result<[u8; 32]> {
    // serde_json emits struct fields in declaration order, giving a canonical
    // representation that is stable across TOML formatting differences.
    let canonical = serde_json::to_vec(document).map_err(|_| RuntimeError::InvalidStructure)?;

    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(canonical);
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(digest)
}

/// Thread-safe store that atomically swaps the active policy snapshot.
pub struct PolicyStore {
    current: RwLock<Option<Arc<PolicySnapshot>>>,
}

impl PolicyStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self {
            current: RwLock::new(None),
        }
    }

    /// Returns the currently active snapshot, if any.
    pub fn current(&self) -> Result<Arc<PolicySnapshot>> {
        let guard = self
            .current
            .read()
            .map_err(|_| RuntimeError::PolicyUnavailable)?;
        guard
            .as_ref()
            .map(Arc::clone)
            .ok_or(RuntimeError::PolicyUnavailable)
    }

    /// Installs a new validated snapshot as the active policy.
    pub fn activate(&self, snapshot: PolicySnapshot) {
        let mut guard = self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(Arc::new(snapshot));
    }
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self::new()
    }
}
