//! Pack matching under explicit budgets (ADR-0018 §2, §3).
//!
//! Matching is additive by construction: every enabled pack contributes
//! evidence, overlapping matches are all kept, and exhausting a budget is
//! reported as [`MatchOutcome::truncated`] — never as a clean result.

use crate::pack::{RuleConfidence, ValidatedPack};

/// Maximum number of packs that may be enabled for one match run.
pub const MAX_ENABLED_PACKS: usize = 64;

/// One match produced by a pack rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternMatch {
    /// Pack that produced it.
    pub pack_id: String,
    /// Pack version.
    pub pack_version: String,
    /// Full rule id, `<pack id>/<rule name>`.
    pub rule_id: String,
    /// Byte offsets into the input.
    pub start: usize,
    /// Byte offset just past the match.
    pub end: usize,
    /// Confidence declared by the rule (a hint only).
    pub confidence: RuleConfidence,
    /// Whether a validator ran and passed. `None` when the rule has no
    /// validator.
    pub validated: Option<bool>,
}

/// Limits applied while matching one input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchBudget {
    /// Maximum matches returned per input. Default 1000.
    pub max_matches: usize,
    /// Maximum input bytes examined. Default 1 MiB.
    pub max_input_bytes: usize,
}

impl Default for MatchBudget {
    fn default() -> Self {
        Self {
            max_matches: 1000,
            max_input_bytes: 1024 * 1024,
        }
    }
}

/// Result of matching, including whether a budget was exhausted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchOutcome {
    /// The matches found.
    pub matches: Vec<PatternMatch>,
    /// True when a budget stopped the scan early. The caller MUST treat this
    /// as incomplete coverage, never as a clean result.
    pub truncated: bool,
}

/// Run every enabled pack over `input`.
///
/// Candidates that fail their rule's validator are not returned: validation
/// is part of matching. Matches from different packs over the same span are
/// ALL returned — overlapping detections are information, not a conflict.
/// Results are sorted by `(start, rule_id)` so repeated runs over the same
/// input are identical. Never panics on any valid UTF-8 input.
pub fn match_all(packs: &[ValidatedPack], input: &str, budget: &MatchBudget) -> MatchOutcome {
    let mut truncated = false;

    let effective_packs = if packs.len() > MAX_ENABLED_PACKS {
        truncated = true;
        &packs[..MAX_ENABLED_PACKS]
    } else {
        packs
    };

    // Clamp the examined prefix to a character boundary.
    let mut scan_len = input.len().min(budget.max_input_bytes);
    if scan_len < input.len() {
        truncated = true;
    }
    while !input.is_char_boundary(scan_len) {
        scan_len -= 1;
    }
    let haystack = &input[..scan_len];

    let mut matches: Vec<PatternMatch> = Vec::new();
    'outer: for pack in effective_packs {
        for rule in &pack.rules {
            for regex_match in rule.regex.find_iter(haystack) {
                let candidate = &haystack[regex_match.start()..regex_match.end()];
                let validated = rule.validator.map(|v| v.validate(candidate));
                if validated == Some(false) {
                    continue;
                }
                matches.push(PatternMatch {
                    pack_id: pack.id.clone(),
                    pack_version: pack.version.clone(),
                    rule_id: format!("{}/{}", pack.id, rule.name),
                    start: regex_match.start(),
                    end: regex_match.end(),
                    confidence: rule.confidence,
                    validated,
                });
                if matches.len() >= budget.max_matches {
                    truncated = true;
                    break 'outer;
                }
            }
        }
    }

    matches.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(a.rule_id.cmp(&b.rule_id))
            .then(a.end.cmp(&b.end))
    });

    MatchOutcome { matches, truncated }
}
