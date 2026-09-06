//! The reference registry: entries, two-phase resolution, and lease settlement.
//!
//! Resolution is deliberately split in two (§5.4). Metadata resolution answers
//! "may this principal use this handle for this operation?" and returns nothing
//! but safe metadata. Material authorization is the separate, counted step that
//! yields a lease a trusted broker can redeem — and even that lease carries an
//! internal resource id, never the bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};

use chrono::{DateTime, Utc};

use crate::error::{Result, RuntimeError};
use crate::references::token::{id_hash_eq, ReferenceToken, RegistryKey};
use crate::types::{
    DestinationSelector, ExposureClass, InternalResourceId, OperationKind, PolicyVersion,
    PrincipalId, SessionId,
};

/// The safe projection of a reference, and the only view a model ever sees.
///
/// §5.5 forbids exposing secret length, prefix, suffix, vault path, checksum,
/// or a description copied from protected content. There is deliberately no
/// free-form description field, so none of that is representable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeMetadata {
    /// Coarse kind, e.g. `provider_credential`.
    pub kind: String,
    /// Operations this handle may be used for.
    pub allowed_actions: BTreeSet<OperationKind>,
    /// Destination selectors this handle may be used against.
    pub destination: Vec<DestinationSelector>,
    /// When the handle stops working.
    pub expires_at: DateTime<Utc>,
}

/// A stored reference.
#[derive(Debug, Clone)]
pub struct ReferenceEntry {
    /// Keyed hash of the token. The token itself is never stored.
    pub id_hash: [u8; 32],
    /// Internal resource this handle names.
    pub resource: InternalResourceId,
    /// Exposure class the resource itself imposes.
    pub class: ExposureClass,
    /// Principal permitted to use the handle, when it is bound to one.
    pub owner_principal: Option<PrincipalId>,
    /// Destinations the handle may be used against.
    pub audience: Vec<DestinationSelector>,
    /// Operations the handle may be used for.
    pub allowed_operations: BTreeSet<OperationKind>,
    /// When the handle was created.
    pub created_at: DateTime<Utc>,
    /// When the handle stops working.
    pub expires_at: DateTime<Utc>,
    /// Session the handle is bound to, when it is session-scoped.
    pub session_id: Option<SessionId>,
    /// Maximum number of material authorizations, when capped.
    pub max_uses: Option<u32>,
    /// Material authorizations so far.
    pub use_count: u32,
    /// The safe projection shown to a model.
    pub metadata_projection: SafeMetadata,
    /// Policy version in force when the handle was created.
    pub policy_version: PolicyVersion,
    /// Whether the handle has been revoked.
    pub revoked: bool,
}

/// The facts a resolution is checked against.
#[derive(Debug, Clone)]
pub struct ResolutionContext {
    /// Principal making the request.
    pub principal: Option<PrincipalId>,
    /// Session the request belongs to.
    pub session: Option<SessionId>,
    /// Operation being attempted.
    pub operation: OperationKind,
    /// Destination the request targets.
    pub destination: DestinationSelector,
    /// Current time, injected so expiry is testable.
    pub now: DateTime<Utc>,
}

/// What metadata resolution returns: safe fields and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedReferenceMetadata {
    /// The safe projection.
    pub metadata: SafeMetadata,
    /// Exposure class the resource imposes, for the policy floor.
    pub class: ExposureClass,
    /// Policy version the handle was created under.
    pub policy_version: PolicyVersion,
}

/// A request to authorize material use of a handle.
#[derive(Debug, Clone)]
pub struct MaterialUseGrant {
    /// Resolution facts.
    pub context: ResolutionContext,
    /// Digest of the operation policy and consent already approved.
    pub operation_digest: [u8; 32],
}

/// How a lease ended.
///
/// The distinction matters for replay: a consumed-but-unexecuted lease is safe
/// to retry, while one whose outcome is unknown may already have caused an
/// external effect and must not be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseOutcome {
    /// The use was counted but no external action was taken.
    ConsumedNotExecuted,
    /// An external action may or may not have happened.
    ExecutedUnknown,
    /// The action completed.
    Completed,
}

/// A typed capability handed only to a trusted broker.
///
/// Carries the internal resource id and the approved operation digest — never
/// the secret bytes. Not `Clone`, not `Copy`, and not `Serialize`, so it cannot
/// be duplicated into a second execution or written to a log.
#[derive(Debug)]
pub struct MaterialLease {
    resource: InternalResourceId,
    operation_digest: [u8; 32],
    id_hash: [u8; 32],
    settled: bool,
}

impl MaterialLease {
    /// The internal resource the broker may act on.
    pub fn resource(&self) -> &InternalResourceId {
        &self.resource
    }

    /// The operation digest this lease was approved for.
    pub fn operation_digest(&self) -> &[u8; 32] {
        &self.operation_digest
    }
}

impl Drop for MaterialLease {
    fn drop(&mut self) {
        // An unsettled lease is assumed to have executed: dropping one on an
        // error path must not be reported as "nothing happened", because the
        // external side effect may already have occurred.
        if !self.settled {
            // The registry records this through `settle`; a drop without one is
            // the fail-safe case and is surfaced by `unsettled_drops`.
            UNSETTLED_DROPS.with(|count| count.set(count.get() + 1));
        }
    }
}

thread_local! {
    static UNSETTLED_DROPS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Number of leases dropped without settlement on this thread.
///
/// Exposed so a caller — and the test suite — can detect the fail-safe path
/// where an external action may have happened but was never recorded.
pub fn unsettled_drops() -> u32 {
    UNSETTLED_DROPS.with(|count| count.get())
}

/// In-memory reference registry.
///
/// Session references are memory-only by default (§5.3). Durable storage needs
/// an encrypted, authenticated store and explicit operator creation, which is
/// not implemented yet: `new` rejects `durable`.
#[derive(Debug)]
pub struct ReferenceRegistry {
    entries: Mutex<BTreeMap<[u8; 32], ReferenceEntry>>,
    key: RegistryKey,
}

impl ReferenceRegistry {
    /// Creates a memory-only registry.
    ///
    /// `durable` is accepted only as `false`; a durable registry requires
    /// encrypted authenticated storage that a later slice adds.
    pub fn new(key: RegistryKey, durable: bool) -> Result<Self> {
        if durable {
            return Err(RuntimeError::InvalidStructure);
        }
        Ok(Self {
            entries: Mutex::new(BTreeMap::new()),
            key,
        })
    }

    /// Registers a handle and returns the token naming it.
    pub fn create(&self, mut entry: ReferenceEntry) -> Result<ReferenceToken> {
        let token = ReferenceToken::generate()?;
        entry.id_hash = token.id_hash(&self.key);
        entry.use_count = 0;

        let mut entries = self.lock()?;
        if entries.contains_key(&entry.id_hash) {
            // A 256-bit collision is not expected; refusing is still correct.
            return Err(RuntimeError::ReferenceInvalid);
        }
        entries.insert(entry.id_hash, entry);
        Ok(token)
    }

    /// Phase one: validates a handle and returns safe metadata only.
    ///
    /// Never returns the resource value, and never advances the use counter.
    pub fn metadata(
        &self,
        token: &ReferenceToken,
        context: &ResolutionContext,
    ) -> Result<ResolvedReferenceMetadata> {
        let id_hash = token.id_hash(&self.key);
        let entries = self.lock()?;
        let entry = Self::lookup(&entries, &id_hash)?;
        Self::check(entry, context)?;

        Ok(ResolvedReferenceMetadata {
            metadata: entry.metadata_projection.clone(),
            class: entry.class,
            policy_version: entry.policy_version.clone(),
        })
    }

    /// Phase two: consumes a use and returns a lease for the trusted broker.
    ///
    /// The counter is advanced under the same lock acquisition that authorizes
    /// the use, so a single-use handle cannot be redeemed twice even under
    /// concurrent callers. The use is consumed *before* execution, which is what
    /// makes replay impossible at the cost of a possible lost use on failure.
    pub fn authorize_material_use(
        &self,
        token: &ReferenceToken,
        grant: MaterialUseGrant,
    ) -> Result<MaterialLease> {
        let id_hash = token.id_hash(&self.key);
        let mut entries = self.lock()?;
        let entry = entries
            .get_mut(&id_hash)
            .filter(|entry| id_hash_eq(&entry.id_hash, &id_hash))
            .ok_or(RuntimeError::ReferenceInvalid)?;

        Self::check(entry, &grant.context)?;
        entry.use_count = entry
            .use_count
            .checked_add(1)
            .ok_or(RuntimeError::ReferenceExpired)?;

        Ok(MaterialLease {
            resource: entry.resource.clone(),
            operation_digest: grant.operation_digest,
            id_hash,
            settled: false,
        })
    }

    /// Records how a lease ended.
    pub fn settle(&self, mut lease: MaterialLease, outcome: LeaseOutcome) -> Result<()> {
        lease.settled = true;
        if outcome == LeaseOutcome::ConsumedNotExecuted {
            // Nothing external happened, so the use is returned to the handle.
            let mut entries = self.lock()?;
            if let Some(entry) = entries.get_mut(&lease.id_hash) {
                entry.use_count = entry.use_count.saturating_sub(1);
            }
        }
        Ok(())
    }

    /// Returns safe metadata for a handle without consuming a use.
    pub fn inspect(
        &self,
        token: &ReferenceToken,
        context: &ResolutionContext,
    ) -> Result<SafeMetadata> {
        Ok(self.metadata(token, context)?.metadata)
    }

    /// Revokes a handle. Idempotent.
    pub fn revoke(&self, token: &ReferenceToken) -> Result<()> {
        let id_hash = token.id_hash(&self.key);
        let mut entries = self.lock()?;
        let entry = entries
            .get_mut(&id_hash)
            .ok_or(RuntimeError::ReferenceInvalid)?;
        entry.revoked = true;
        Ok(())
    }

    /// Current use count, for tests and diagnostics.
    pub fn use_count(&self, token: &ReferenceToken) -> Result<u32> {
        let id_hash = token.id_hash(&self.key);
        let entries = self.lock()?;
        Ok(Self::lookup(&entries, &id_hash)?.use_count)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<[u8; 32], ReferenceEntry>>> {
        // A poisoned registry still holds valid entries; recovering keeps the
        // handle usable rather than turning one panic into a permanent outage.
        Ok(self.entries.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn lookup<'a>(
        entries: &'a BTreeMap<[u8; 32], ReferenceEntry>,
        id_hash: &[u8; 32],
    ) -> Result<&'a ReferenceEntry> {
        entries
            .get(id_hash)
            .filter(|entry| id_hash_eq(&entry.id_hash, id_hash))
            .ok_or(RuntimeError::ReferenceInvalid)
    }

    /// Validates an entry against a resolution context, in the order of §5.4.
    fn check(entry: &ReferenceEntry, context: &ResolutionContext) -> Result<()> {
        if entry.revoked {
            return Err(RuntimeError::ReferenceInvalid);
        }
        if context.now >= entry.expires_at {
            return Err(RuntimeError::ReferenceExpired);
        }
        if let Some(owner) = &entry.owner_principal {
            if context.principal.as_ref() != Some(owner) {
                return Err(RuntimeError::ReferenceAudienceDenied);
            }
        }
        if let Some(session) = &entry.session_id {
            if context.session.as_ref() != Some(session) {
                return Err(RuntimeError::ReferenceAudienceDenied);
            }
        }
        if !entry.allowed_operations.contains(&context.operation) {
            return Err(RuntimeError::ReferenceAudienceDenied);
        }
        if !entry.audience.is_empty() && !entry.audience.contains(&context.destination) {
            return Err(RuntimeError::ReferenceAudienceDenied);
        }
        if let Some(max) = entry.max_uses {
            if entry.use_count >= max {
                return Err(RuntimeError::ReferenceExpired);
            }
        }
        Ok(())
    }
}
