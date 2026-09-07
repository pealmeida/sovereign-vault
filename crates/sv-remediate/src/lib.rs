//! Remediation planning, verification, dry-run diffing, and — behind a
//! non-default feature — journalled file application for Sovereign Vault
//! (ADR-0017 §4, ADR-0019).
//!
//! ## Phase scope
//!
//! * Planning, verification, and dry-run diffing (this crate's default
//!   build) perform **no filesystem mutation of any kind**. A regression
//!   test (`tests/write_free.rs`) greps the crate's own source for raw
//!   filesystem-mutation calls and fails if one appears — with any feature
//!   set.
//! * The write path lives in [`apply`] and is compiled **only** with the
//!   non-default `apply` feature. Without the feature the crate cannot
//!   write: the write dependencies are not even built. With the feature
//!   on, dry-run is still the default — [`apply::ApplyMode::DryRun`] is
//!   the `Default` and [`apply::execute`] takes the mode explicitly. There
//!   is no bare function that writes.
//! * The per-file ordering in [`apply`] — verify, vault, recovery record,
//!   journal in-progress, atomic replace, journal done — is what makes an
//!   interrupted run recoverable rather than destructive (ADR-0019 §2).
//!   It is load-bearing; do not reorder it for efficiency.
//! * Multi-file runs are **not transactional**. The journal makes them
//!   resumable; nothing claims more.
//!
//! ## Why the digests are keyed
//!
//! Every digest in a [`plan::PlanItem`] is HMAC-SHA256 under a
//! caller-supplied [`plan::PlanKey`] — never a plain hash. An unkeyed hash
//! of a small-domain value (an 11-digit CPF, a phone number, a credit-card
//! number) is brute-forceable back to the very value it was meant to
//! protect: enumerate the candidates, hash, compare. It also makes identical
//! values linkable across files, which is exactly the correlation the vault
//! exists to prevent (ADR-0016 §Context). ADR-0019 §1 requires keyed digests;
//! this crate accepts nothing else.
//!
//! ## Key handling
//!
//! The key is supplied by the caller (the vault). This crate does not
//! derive it from any root material, does not store it, and does not
//! persist it; the key buffer is zeroized on drop. If you are looking for a
//! place to bootstrap the key from a passphrase — it is deliberately not
//! here.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod diff;
pub mod plan;
pub mod recovery;
pub mod trust;
pub mod verify;

/// The destructive path: journalled, per-file-atomic application of an
/// approved plan. Compiled only with the `apply` feature.
#[cfg(feature = "apply")]
pub mod apply;

/// Whole-file ingestion and the consumer adapters (ADR-0020). Compiled only
/// with the `apply` feature: ingestion removes the original file, which is
/// a tree mutation.
#[cfg(feature = "apply")]
pub mod managed;

pub use plan::{
    is_marker, keyed_digest, ByteSpan, Digest, FileIdentity, PlanItem, PlanItemDraft, PlanKey,
    RewritePlan, RulePin,
};
pub use recovery::{JournalEntry, JournalState, RecoveryRecord, RewriteJournal};
pub use trust::{default_selected, is_never_default};
pub use verify::{verify_plan_item, VerifyOutcome};

#[cfg(feature = "apply")]
pub use apply::{
    execute, restore, resume, ApplyError, ApplyMode, ApplyOutcome, FileApplyResult,
    FileApplyStatus, IdentityAssurance, RestoreOutcome, VaultSink,
};
#[cfg(feature = "apply")]
pub use managed::{
    authorization_record, check_eligibility, detect_unexpected_plaintext, ingest_managed_file,
    rotation_blast_radius, startup_check, AuthorizationRecord, ConsumerAdapter, Eligibility,
    ManagedFilePlan, ManagedIngestStatus, ManagedManifest, PermissionSnapshot, PlaintextStatus,
    SharedBinding, TempMaterial,
};

/// Errors raised while building or interpreting a remediation plan.
///
/// `Display` strings are deliberately generic: they identify the failure
/// class without echoing matched values. Structured detail (such as the path
/// of an overlapping span) is carried as data for the caller's own surfaces.
#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    /// The plan key was not exactly 32 bytes.
    #[error("plan key must be exactly 32 bytes")]
    InvalidKey,
    /// The path was absolute, escaped the project, or was empty.
    #[error("path must be relative and stay inside the project")]
    NotRelative,
    /// The span was empty, extended past the source, or was inverted.
    #[error("span out of bounds or empty")]
    SpanOutOfBounds,
    /// A span offset fell inside a multi-byte UTF-8 character.
    #[error("span is not on a UTF-8 character boundary")]
    SpanNotCharBoundary,
    /// The span already holds a durable locator marker; markers are never
    /// re-redacted (ADR-0017 §4).
    #[error("span already contains a durable locator marker")]
    MarkerSpan,
    /// Two items in the same file claimed overlapping spans. Overlaps are
    /// resolved before approval, never later (ADR-0019 §2).
    #[error("plan contains overlapping spans in one file")]
    OverlappingSpans {
        /// The file whose items overlap.
        path: std::path::PathBuf,
    },
    /// Plan serialization failed.
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    /// The OS did not expose a file identity for this metadata (unusual
    /// filesystems may decline).
    #[error("file identity unavailable on this platform or filesystem")]
    IdentityUnavailable,
    /// A digest was not 64 lowercase hex characters.
    #[error("invalid digest encoding")]
    InvalidDigest,
}

/// Convenience result type for this crate.
pub type Result<T> = std::result::Result<T, PlanError>;
