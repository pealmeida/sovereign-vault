//! Pack schema, parsing, and load-time validation (ADR-0018 §2).
//!
//! A pack is **untrusted input that decides what counts as sensitive**.
//! Validation exists to reject a pack that is inconsistent with its own
//! declared vectors before any file is scanned. The format has no ignore,
//! allow, exempt, suppress, or disable verb — a pack can only ever add
//! candidates, never remove baseline detection.

use serde::Deserialize;

use crate::validators::ValidatorId;

/// Maximum number of rules a single pack may declare.
pub const MAX_RULES_PER_PACK: usize = 200;
/// Maximum size in bytes of a single rule's pattern source.
pub const MAX_PATTERN_BYTES: usize = 4096;

/// A jurisdiction pattern pack, as parsed from TOML.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PatternPack {
    /// Schema version. Only "1" is accepted.
    pub schema: String,
    /// Stable pack identifier, e.g. `br-lgpd`. Lowercase, `[a-z0-9-]`.
    pub id: String,
    /// Semantic version of the pack contents.
    pub version: String,
    /// Human-readable name.
    pub name: String,
    /// ISO 3166-1 alpha-2 country codes, or a region code such as "EU".
    pub jurisdictions: Vec<String>,
    /// Optional pointers to the regime a rule relates to. NOT a legal claim.
    /// e.g. ["LGPD Art. 5"]. Purely informational.
    #[serde(default)]
    pub regulatory_references: Vec<String>,
    /// The detection rules. May be absent in TOML; an empty or absent rule
    /// list is rejected by [`PatternPack::validate`] as [`crate::PackError::EmptyRules`].
    #[serde(default)]
    pub rules: Vec<PatternRule>,
}

/// One detection rule.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PatternRule {
    /// Rule name, unique within the pack. Full id is `<pack id>/<name>`.
    pub name: String,
    /// What it detects, in plain language.
    pub description: String,
    /// Regular expression finding CANDIDATES. Validation is separate.
    pub pattern: String,
    /// Named validator applied to each candidate, if any.
    #[serde(default)]
    pub validator: Option<ValidatorId>,
    /// Confidence when the rule matches AND the validator passes.
    /// A hint only: never authorises redaction or a policy change.
    pub confidence: RuleConfidence,
    /// Values this rule MUST match. Checked at load time.
    pub examples_valid: Vec<String>,
    /// Values this rule MUST NOT match (or must fail validation).
    pub examples_invalid: Vec<String>,
}

/// Confidence declared by a rule. A hint for triage, never an authorisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleConfidence {
    /// Weak or purely structural signal.
    Low,
    /// Plausible format, weak or absent checksum.
    Medium,
    /// Checksummed or strongly constrained format.
    High,
}

/// A pack that passed validation, with every rule compiled once.
///
/// Compilation happens here, under explicit size limits, so a pathological
/// pattern fails to LOAD rather than consuming memory at match time.
#[derive(Debug, Clone)]
pub struct ValidatedPack {
    /// Stable pack identifier.
    pub id: String,
    /// Semantic version of the pack contents.
    pub version: String,
    /// Human-readable name.
    pub name: String,
    /// Country or region codes the pack relates to.
    pub jurisdictions: Vec<String>,
    /// Informational regulatory pointers. NOT legal claims.
    pub regulatory_references: Vec<String>,
    /// The compiled rules, in declaration order.
    pub rules: Vec<CompiledRule>,
}

/// One compiled rule inside a [`ValidatedPack`].
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// Rule name; the full id is `<pack id>/<name>`.
    pub name: String,
    /// What it detects, in plain language.
    pub description: String,
    /// The compiled candidate-finding expression.
    pub regex: regex::Regex,
    /// Named validator applied to each candidate, if any.
    pub validator: Option<ValidatorId>,
    /// Confidence declared by the rule.
    pub confidence: RuleConfidence,
}

impl PatternPack {
    /// Parse a pack from TOML source.
    pub fn from_toml(source: &str) -> Result<Self, crate::PackError> {
        toml::from_str(source).map_err(crate::PackError::InvalidToml)
    }

    /// Validate the pack, compiling every pattern under size limits and
    /// executing every conformance vector. Consumes `self` and returns a
    /// [`ValidatedPack`] on success.
    pub fn validate(self) -> Result<ValidatedPack, crate::PackError> {
        if self.schema != "1" {
            return Err(crate::PackError::InvalidSchema { found: self.schema });
        }
        if !valid_pack_id(&self.id) {
            return Err(crate::PackError::InvalidPackId {
                id: self.id.clone(),
            });
        }
        if self.rules.is_empty() {
            return Err(crate::PackError::EmptyRules);
        }
        if self.rules.len() > MAX_RULES_PER_PACK {
            return Err(crate::PackError::TooManyRules {
                count: self.rules.len(),
            });
        }

        let mut seen = std::collections::BTreeSet::new();
        let mut compiled = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            if !valid_rule_name(&rule.name) {
                return Err(crate::PackError::InvalidRuleName {
                    rule: rule.name.clone(),
                });
            }
            if !seen.insert(rule.name.clone()) {
                return Err(crate::PackError::DuplicateRuleName {
                    pack_id: self.id.clone(),
                    rule: rule.name.clone(),
                });
            }
            if rule.pattern.len() > MAX_PATTERN_BYTES {
                return Err(crate::PackError::PatternTooLarge {
                    rule: rule.name.clone(),
                });
            }
            let regex = regex::RegexBuilder::new(&rule.pattern)
                .size_limit(1 << 20)
                .dfa_size_limit(1 << 20)
                .build()
                .map_err(|e| crate::PackError::PatternCompile {
                    rule: rule.name.clone(),
                    reason: compile_reason(&e),
                });
            let regex = regex?;

            // Positive vectors: every entry must match AND pass validation.
            if rule.examples_valid.is_empty() {
                return Err(crate::PackError::EmptyValidExamples {
                    rule: rule.name.clone(),
                });
            }
            for (index, example) in rule.examples_valid.iter().enumerate() {
                let is_match = regex.is_match(example);
                let validated = rule.validator.is_none_or(|v| v.validate(example));
                if !(is_match && validated) {
                    return Err(crate::PackError::ValidExampleFailed {
                        rule: rule.name.clone(),
                        index,
                    });
                }
            }
            // Negative vectors: no entry may produce a valid finding.
            for (index, example) in rule.examples_invalid.iter().enumerate() {
                let is_match = regex.is_match(example);
                let rejected = rule.validator.is_some_and(|v| !v.validate(example));
                if is_match && !rejected {
                    return Err(crate::PackError::InvalidExampleMatched {
                        rule: rule.name.clone(),
                        index,
                    });
                }
            }

            compiled.push(CompiledRule {
                name: rule.name.clone(),
                description: rule.description.clone(),
                regex,
                validator: rule.validator,
                confidence: rule.confidence,
            });
        }

        Ok(ValidatedPack {
            id: self.id,
            version: self.version,
            name: self.name,
            jurisdictions: self.jurisdictions,
            regulatory_references: self.regulatory_references,
            rules: compiled,
        })
    }
}

/// Pack ids: lowercase alphanumeric with inner hyphens, 2-64 characters.
fn valid_pack_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    (2..=64).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// Rule names: lowercase alphanumeric with inner hyphens/underscores.
fn valid_rule_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (2..=64).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'_')
}

/// Human-readable reason a pattern failed to compile, without embedding the
/// pattern source (it is untrusted pack content).
fn compile_reason(error: &regex::Error) -> &'static str {
    match error {
        regex::Error::Syntax(_) => "syntax error",
        regex::Error::CompiledTooBig(_) => "pattern exceeds the compilation size limit",
        _ => "could not be compiled",
    }
}
