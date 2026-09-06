//! Sovereign Vault jurisdiction pattern packs (per ADR-0018,
//! `docs/adr/0018-jurisdiction-pattern-packs.md`).
//!
//! Pattern packs EXTEND baseline detection and can NEVER reduce it. Baseline
//! detection — `sv-privacy` categories and `sv-scan` secret rules — is always
//! on; the pack format has no ignore, allow, exempt, suppress, or disable
//! verb, so a pack can only ever ADD candidates. The worst a bad pack
//! achieves is noise, never silent loss of coverage.
//!
//! A pack is **untrusted input** that decides what counts as sensitive. It is
//! validated at load time: bounded sizes, compiled-under-limits patterns, and
//! positive and negative conformance vectors that must hold before any file
//! is scanned.
//!
//! Findings state **evidence, not legal conclusions**. A `regulatory_reference`
//! is an informational pointer; a checksum pass establishes structural
//! plausibility, never authenticity, ownership, sensitivity, or that any
//! legal regime applies to the data.
//!
//! # Stability
//!
//! Pre-1.0. APIs subject to change.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod engine;
mod pack;
mod validators;

pub use engine::{match_all, MatchBudget, MatchOutcome, PatternMatch, MAX_ENABLED_PACKS};
pub use pack::{
    CompiledRule, PatternPack, PatternRule, RuleConfidence, ValidatedPack, MAX_PATTERN_BYTES,
    MAX_RULES_PER_PACK,
};
pub use validators::ValidatorId;

/// Errors from parsing or validating a pack.
///
/// Messages never contain a matched value or file content. Pack ids, rule
/// ids, schema versions, and example indices are acceptable in messages.
#[derive(Debug, thiserror::Error)]
pub enum PackError {
    /// The TOML source could not be parsed as a pack. The underlying parse
    /// error is available as the error source.
    #[error("pack is not valid TOML")]
    InvalidToml(#[source] toml::de::Error),
    /// The schema version is not supported.
    #[error("unsupported pack schema version: {found}")]
    InvalidSchema {
        /// The schema version string that was found.
        found: String,
    },
    /// The pack id does not match `^[a-z0-9][a-z0-9-]{1,63}$`.
    #[error("pack id is invalid: {id}")]
    InvalidPackId {
        /// The rejected pack id.
        id: String,
    },
    /// The pack declares no rules.
    #[error("pack has no rules")]
    EmptyRules,
    /// The pack exceeds [`MAX_RULES_PER_PACK`] rules.
    #[error("pack has too many rules: {count} (max {MAX_RULES_PER_PACK})")]
    TooManyRules {
        /// The rule count that was found.
        count: usize,
    },
    /// A rule name does not match `^[a-z0-9][a-z0-9_-]{1,63}$`.
    #[error("rule name is invalid: {rule}")]
    InvalidRuleName {
        /// The rejected rule name.
        rule: String,
    },
    /// Two rules in the same pack share a name.
    #[error("duplicate rule name: {pack_id}/{rule}")]
    DuplicateRuleName {
        /// The pack that contains the duplicate.
        pack_id: String,
        /// The duplicated rule name.
        rule: String,
    },
    /// A rule's pattern source exceeds [`MAX_PATTERN_BYTES`].
    #[error("rule {rule}: pattern exceeds {MAX_PATTERN_BYTES} bytes")]
    PatternTooLarge {
        /// The rule whose pattern is too large.
        rule: String,
    },
    /// A rule's pattern failed to compile under the size limits.
    #[error("rule {rule}: pattern {reason}")]
    PatternCompile {
        /// The rule whose pattern failed to compile.
        rule: String,
        /// Why it failed, without embedding the pattern source.
        reason: &'static str,
    },
    /// A rule declares no positive conformance vectors.
    #[error("rule {rule}: examples_valid must not be empty")]
    EmptyValidExamples {
        /// The rule with no positive vectors.
        rule: String,
    },
    /// A positive vector did not match or failed validation.
    #[error("rule {rule}: examples_valid[{index}] does not match or fails validation")]
    ValidExampleFailed {
        /// The rule whose vector failed.
        rule: String,
        /// Index of the failing example within `examples_valid`.
        index: usize,
    },
    /// A negative vector produced a valid finding.
    #[error("rule {rule}: examples_invalid[{index}] produced a valid finding")]
    InvalidExampleMatched {
        /// The rule whose vector failed.
        rule: String,
        /// Index of the offending example within `examples_invalid`.
        index: usize,
    },
    /// No builtin pack has the requested id.
    #[error("unknown builtin pack: {id}")]
    UnknownBuiltin {
        /// The requested pack id.
        id: String,
    },
}

/// Crate version string.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// TOML sources of the packs bundled with this crate.
pub fn builtin_packs() -> Vec<&'static str> {
    vec![
        include_str!("../packs/br-lgpd.toml"),
        include_str!("../packs/eu-gdpr.toml"),
        include_str!("../packs/us.toml"),
    ]
}

/// Load and validate a bundled pack by id.
pub fn load_builtin(id: &str) -> Result<ValidatedPack, PackError> {
    let source = match id {
        "br-lgpd" => include_str!("../packs/br-lgpd.toml"),
        "eu-gdpr" => include_str!("../packs/eu-gdpr.toml"),
        "us" => include_str!("../packs/us.toml"),
        _ => return Err(PackError::UnknownBuiltin { id: id.to_string() }),
    };
    PatternPack::from_toml(source)?.validate()
}
