//! The opaque reference registry.
//!
//! A reference lets a model name a protected resource without receiving its
//! value. It is distinct from agent identity: `agents.json` controls *who* may
//! ask, while a reference constrains *what a particular handle may do* — which
//! destination it may be used against, for which operations, how often, and
//! until when.

/// Opaque tokens and the keyed hash the registry stores.
pub mod token;

/// Entries, two-phase resolution, and lease settlement.
pub mod registry;

pub use registry::{
    unsettled_drops, LeaseOutcome, MaterialLease, MaterialUseGrant, ReferenceEntry,
    ReferenceRegistry, ResolutionContext, ResolvedReferenceMetadata, SafeMetadata,
};
pub use token::{ReferenceToken, RegistryKey};
