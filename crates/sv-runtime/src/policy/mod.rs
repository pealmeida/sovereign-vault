//! Policy engine: document model, validation, evaluation, and diff.

/// The strict policy document model and its TOML parser.
pub mod document;

/// Validation rules applied to a parsed policy document.
pub mod validate;

/// Immutable validated snapshots and the store that swaps them.
pub mod snapshot;

/// Path-aware glob matching for policy selectors.
pub mod glob;

/// Deny-overrides evaluation of a request against one snapshot.
pub mod evaluator;

/// Semantic diff between two validated policy snapshots.
pub mod diff;
