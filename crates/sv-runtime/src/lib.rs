//! # sv-runtime
//!
//! Transport-independent mediation runtime for Sovereign Vault.
//!
//! This crate is the decision and orchestration layer of the system. It owns
//! **no** network listener and has **no** Tauri dependency: requests are handed
//! to it already parsed, in terms of the canonical types in [`types`], and it
//! returns decisions, plans, and audit intents in terms of the same types.
//! Transports (`sv-http`, `sv-mcp`, the desktop shell, the CLI) are thin
//! adapters that translate to and from [`types::MediationRequest`].
//!
//! The runtime is responsible for:
//!
//! * evaluating policy against a [`types::Principal`], [`types::Operation`],
//!   and [`types::Destination`];
//! * resolving references without releasing raw bytes;
//! * collecting and binding consent;
//! * orchestrating execution under [`types::ExecutionConstraint`];
//! * emitting audit records for every decision, including denials.
//!
//! It fails closed: when policy, consent, or audit data is unavailable, the
//! corresponding [`error::RuntimeError`] is returned rather than a permissive
//! default.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod policy;
pub mod references;
pub mod types;

pub use error::{Result, RuntimeError};
pub use types::{
    AuditIntent, CanonicalDestination, ConsentBinding, ConsentMode, ConsentRequirement,
    DataFragment, DecisionEffect, Destination, DestinationSelector, EffectiveLimits,
    ExecutionConstraint, ExposureClass, FragmentId, FragmentRole, InternalResourceId, MediaType,
    MediationPlan, MediationRequest, Operation, OperationKind, Origin, PolicyVersion,
    PreparedFragment, Principal, PrincipalId, PrincipalKind, Provenance, ReferenceUse, RequestId,
    ScalarValue, Scope, SensitiveBytes, SessionId, TransformationPlan, TransportKind,
};
