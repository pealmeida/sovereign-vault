//! Sovereign Vault project scanner: read-only discovery of secrets and
//! personal data in local project trees (per ADR-0017,
//! `docs/adr/0017-project-scanning-and-remediation-boundary.md`).
//!
//! This crate is **strictly read-only discovery**. It walks a project tree,
//! reports candidate secrets (via named rules) and PII (via [`sv_privacy`]),
//! and never writes, modifies, or deletes any file. Findings never carry the
//! matched value — only a masked preview and its location — so a scan report
//! is safe to display, log, or persist.
//!
//! Coverage is explicit: every file the scan did not examine is accounted
//! for in [`Coverage`] with a reason, because a scanner that silently skips
//! overstates its coverage.
//!
//! The crate depends on no other Sovereign Vault crate except `sv-privacy`
//! (for [`types::FindingKind::Pii`] categorisation).
//!
//! # Stability
//!
//! Pre-1.0. APIs subject to change.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod detect;
mod filter;
mod rules;
mod types;
mod walk;

pub use detect::{detect_jurisdiction, detect_pii, detect_secrets, mask, scan_project};
pub use rules::{Alphabet, SecretRule, RULES, SECRET_KEYWORDS};
pub use types::{
    Confidence, Coverage, FindingKind, ScanConfig, ScanFinding, ScanReport, SkipReason, Skipped,
    Suppressed, SuppressionReason, ALWAYS_SCAN, DEFAULT_EXCLUDES,
};
pub use walk::{walk, ScannedFile};

/// Errors returned by the scanner.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// The scan root does not exist or is not a directory.
    #[error("scan root is not a readable directory")]
    InvalidRoot,
    /// An ignore-pattern or walker construction error.
    #[error("walk failed: {0}")]
    Walk(String),
    /// A requested jurisdiction pack could not be loaded or failed validation.
    ///
    /// This is deliberately fatal. Continuing without a pack the caller asked
    /// for would produce a report that looks clean because rules were missing.
    #[error("pattern pack failed to load: {0}")]
    Pack(String),
}

/// Crate version string.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
