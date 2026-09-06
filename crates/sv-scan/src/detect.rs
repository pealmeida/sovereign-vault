//! Deterministic secret and PII detectors, plus the scan orchestration seam.
//!
//! Secret matching is hand-rolled over bytes: for each [`SecretRule`] with a
//! literal prefix, find each occurrence of the prefix, consume the following
//! bytes that belong to the rule's [`Alphabet`], and validate the total token
//! length against the rule's `exact_len`/`len_range`. Two signal modifiers
//! then tune confidence (ADR-0017 §3):
//!
//! * **Keyword proximity** promotes a match one step when a credential-looking
//!   name (`api_key`, `token`, …) appears earlier on the same line.
//! * **Entropy** is *supporting* evidence only — it only ever *demotes* an
//!   otherwise implausibly low-entropy match, and never produces a finding on
//!   its own.
//!
//! Two invariants hold across the whole module: nothing is ever written, and
//! no finding ever carries the matched value — only a masked [`mask`] preview.
//! Already-redacted markers (`[REDACTED:…]`, `[SV:LOC:…]`) on the same line are
//! never re-flagged, so scanning an already-remediated tree is idempotent.

use std::path::Path;

use sv_privacy::Policy;

use crate::rules::{SecretRule, PEM_RULE_ID, RULES, SECRET_KEYWORDS};
use crate::types::{Confidence, FindingKind, ScanFinding};
use crate::{walk, ScanConfig, ScanError, ScanReport};

/// Minimum plausible Shannon entropy (bits per byte) for a token match. Below
/// this, an otherwise-matching token is suspicious and is demoted one step.
const ENTROPY_DEMOTE_THRESHOLD: f64 = 2.0;

/// The visible tail kept by [`mask`] is this many asterisks, fixed so the true
/// length of a value is never disclosed.
const MASK_STARS: &str = "********";

/// Detect secrets in one file's text.
///
/// Runs every rule in [`RULES`] over `content`, resolves overlapping matches
/// (higher confidence wins, then the longer span, then the rule id), and
/// returns findings ordered by start offset. Never panics on multi-byte UTF-8
/// and never emits the raw matched value.
pub fn detect_secrets(content: &str, path: &Path) -> Vec<ScanFinding> {
    let mut candidates: Vec<ScanFinding> = Vec::new();
    for rule in RULES {
        if rule.id == PEM_RULE_ID {
            scan_pem(content, path, rule, &mut candidates);
        } else {
            scan_rule(content, path, rule, &mut candidates);
        }
    }
    dedup_overlaps(candidates)
}

/// Detect PII in one file's text by delegating to `sv-privacy`.
///
/// Checksum-validated identifiers (CPF, CNPJ, credit card) are reported at
/// [`Confidence::High`]; structurally-validated categories (email, IPv4, phone,
/// SSN) at [`Confidence::Medium`]. Already-redacted markers are skipped so
/// re-scanning a processed tree stays idempotent. The preview is masked.
pub fn detect_pii(content: &str, path: &Path, policy: &Policy) -> Vec<ScanFinding> {
    sv_privacy::scan(content, policy)
        .into_iter()
        .filter(|f| !is_inside_marker(content, f.start))
        .map(|f| ScanFinding {
            path: path.to_path_buf(),
            line: line_number(content, f.start),
            start: f.start,
            end: f.end,
            confidence: pii_confidence(f.category),
            kind: FindingKind::Pii(f.category),
            preview: mask(&content[f.start..f.end]),
        })
        .collect()
}

/// Detect national identifiers using opt-in jurisdiction pattern packs.
///
/// Packs *extend* detection: they run alongside the baseline detectors and can
/// never disable or suppress them (ADR-0018 §1). Overlapping matches from two
/// packs are both reported, because agreement between rules is information
/// rather than a conflict to resolve.
///
/// A finding here is structural evidence only — that a value is well-formed for
/// an identifier type — never a claim that a legal regime applies to it.
pub fn detect_jurisdiction(
    content: &str,
    path: &Path,
    packs: &[sv_patterns::ValidatedPack],
    budget: &sv_patterns::MatchBudget,
) -> (Vec<ScanFinding>, bool) {
    if packs.is_empty() {
        return (Vec::new(), false);
    }
    let outcome = sv_patterns::match_all(packs, content, budget);
    let findings = outcome
        .matches
        .into_iter()
        .filter(|m| !is_inside_marker(content, m.start))
        .map(|m| ScanFinding {
            path: path.to_path_buf(),
            line: line_number(content, m.start),
            start: m.start,
            end: m.end,
            confidence: match m.confidence {
                sv_patterns::RuleConfidence::High => Confidence::High,
                sv_patterns::RuleConfidence::Medium => Confidence::Medium,
                sv_patterns::RuleConfidence::Low => Confidence::Low,
            },
            preview: mask(&content[m.start..m.end]),
            kind: FindingKind::Jurisdiction {
                pack_id: m.pack_id,
                pack_version: m.pack_version,
                rule_id: m.rule_id,
                validated: m.validated,
            },
        })
        .collect();
    (findings, outcome.truncated)
}

/// Mask a matched value for safe display: keep at most the first 4 characters,
/// replace the rest with a fixed number of asterisks so the true length is not
/// disclosed. A value of 4 characters or fewer is masked entirely.
pub fn mask(value: &str) -> String {
    let mut chars = value.chars();
    let first4: String = chars.by_ref().take(4).collect();
    if chars.next().is_none() {
        // Four or fewer characters: reveal nothing.
        return MASK_STARS.to_string();
    }
    let mut out = first4;
    out.push_str(MASK_STARS);
    out
}

/// Walk `root` and scan every readable text file for secrets and PII.
///
/// This is the crate's top-level entry point. Read-only: it scans the files
/// [`walk`] yields, sorts all findings deterministically by `(path, start)`,
/// and returns the [`crate::Coverage`] that `walk` produced unchanged.
pub fn scan_project(root: &Path, config: &ScanConfig) -> Result<ScanReport, ScanError> {
    let (files, mut coverage) = walk(root, config)?;
    let policy = Policy::all();

    // A pack that fails to load is a hard error, never a silent downgrade: a
    // scan that quietly ran with fewer rules than the user asked for would
    // report a clean result the user has no reason to trust (ADR-0018 §2).
    let packs = load_packs(&config.packs)?;
    let budget = sv_patterns::MatchBudget::default();

    let mut findings: Vec<ScanFinding> = Vec::new();
    for file in &files {
        let mut candidates = detect_secrets(&file.content, &file.path);
        candidates.extend(detect_pii(&file.content, &file.path, &policy));
        let (jurisdiction, truncated) =
            detect_jurisdiction(&file.content, &file.path, &packs, &budget);
        if truncated {
            // Budget exhaustion is incomplete coverage, not a clean file.
            coverage.record_skip(file.path.clone(), crate::SkipReason::BudgetExhausted);
        }
        candidates.extend(jurisdiction);

        for mut finding in candidates {
            // Context filters never add a finding. Almost all of them *demote*
            // rather than delete: "this file is generated" and "this value
            // looks like a placeholder" are statements about likelihood, and
            // each has a real counter-example (a leaked key inside a bundle, a
            // live password containing the word `sample`). Deleting on a
            // heuristic would hide precisely the finding that matters most, so
            // only structurally-impossible matches are dropped.
            match crate::filter::suppression_reason(&finding, &file.content, &file.path) {
                Some(reason) => {
                    coverage.record_suppression(reason);
                    if reason.is_removal() {
                        continue;
                    }
                    finding.confidence = Confidence::Low;
                    findings.push(finding);
                }
                None => {
                    finding.confidence = crate::filter::adjust_confidence(
                        &finding,
                        &file.content,
                        finding.confidence,
                    );
                    findings.push(finding);
                }
            }
        }
    }
    findings.sort_by(|a, b| a.path.cmp(&b.path).then(a.start.cmp(&b.start)));
    coverage.suppressed.sort_by_key(|s| s.reason);

    Ok(ScanReport { findings, coverage })
}

/// Load and validate every requested jurisdiction pack.
///
/// Both bundled ids and filesystem paths are accepted. A failure is returned
/// rather than skipped: silently running with fewer rules than requested would
/// produce a report the user cannot trust.
fn load_packs(ids: &[String]) -> Result<Vec<sv_patterns::ValidatedPack>, ScanError> {
    let mut packs = Vec::with_capacity(ids.len());
    for id in ids {
        let pack = if Path::new(id).is_file() {
            let source = std::fs::read_to_string(id)
                .map_err(|e| ScanError::Pack(format!("cannot read pack {id}: {e}")))?;
            sv_patterns::PatternPack::from_toml(&source)
                .and_then(|p| p.validate())
                .map_err(|e| ScanError::Pack(format!("pack {id}: {e}")))?
        } else {
            sv_patterns::load_builtin(id).map_err(|e| ScanError::Pack(format!("pack {id}: {e}")))?
        };
        packs.push(pack);
    }
    Ok(packs)
}

/// Scan `content` for one prefix-based rule, appending raw candidates.
///
/// For each occurrence of `rule.prefix`, consume the maximal run of following
/// bytes in the rule's alphabet, then check the total token length against the
/// rule's `exact_len`/`len_range`. All matching is on byte offsets along char
/// boundaries: prefix bytes are ASCII, and the consumed body is ASCII, so the
/// matched span is always a valid `&str` slice.
fn scan_rule(content: &str, path: &Path, rule: &SecretRule, out: &mut Vec<ScanFinding>) {
    let Some(prefix) = rule.prefix else { return };
    let prefix = prefix.as_bytes();
    let bytes = content.as_bytes();
    if prefix.len() > bytes.len() {
        return;
    }

    let mut i = 0usize;
    while i <= bytes.len() - prefix.len() {
        if &bytes[i..i + prefix.len()] == prefix {
            let mut end = i + prefix.len();
            while end < bytes.len() && rule.alphabet.contains(bytes[end]) {
                end += 1;
            }
            let matched = length_valid(rule, end - i)
                && content.is_char_boundary(i)
                && content.is_char_boundary(end);
            if matched {
                // Entropy may demote this token: it is a random-looking secret.
                push_secret(out, content, path, rule, i, end, true);
                // Skip past the consumed run; nested prefixes are re-examined on
                // the rules that follow this one.
                i = end.max(i + 1);
                continue;
            }
        }
        i += 1;
    }
}

/// Scan `content` for PEM private-key header lines.
///
/// Matches a line that begins with `-----BEGIN ` and ends with
/// `PRIVATE KEY-----`; the span covers the header line only, never the key
/// body. Entropy demotion is disabled here: a header line is a fixed-format
/// marker, not a random credential, so low entropy is expected, not suspicious.
fn scan_pem(content: &str, path: &Path, rule: &SecretRule, out: &mut Vec<ScanFinding>) {
    const BEGIN: &[u8] = b"-----BEGIN";
    const HEADER_PREFIX: &str = "-----BEGIN ";
    const END_MARKER: &str = "PRIVATE KEY-----";

    let bytes = content.as_bytes();
    if bytes.len() < BEGIN.len() {
        return;
    }

    let mut i = 0usize;
    while i <= bytes.len() - BEGIN.len() {
        if &bytes[i..i + BEGIN.len()] == BEGIN {
            // Find the end of this line, then trim a trailing `\r`.
            let mut line_end = i;
            while line_end < bytes.len() && bytes[line_end] != b'\n' {
                line_end += 1;
            }
            let mut tail = line_end;
            if tail > i && bytes[tail - 1] == b'\r' {
                tail -= 1;
            }
            if content.is_char_boundary(i) && content.is_char_boundary(tail) {
                let line = &content[i..tail];
                if line.starts_with(HEADER_PREFIX) && line.ends_with(END_MARKER) {
                    push_secret(out, content, path, rule, i, tail, false);
                    i = line_end.max(i + 1);
                    continue;
                }
            }
        }
        i += 1;
    }
}

/// Validate a total token length against the rule's fixed or ranged constraint.
fn length_valid(rule: &SecretRule, token_len: usize) -> bool {
    if let Some(exact) = rule.exact_len {
        return token_len == exact;
    }
    if let Some((lo, hi)) = rule.len_range {
        return (lo..=hi).contains(&token_len);
    }
    true
}

/// Build a [`ScanFinding`] for a secret match at `[start, end)`, applying the
/// keyword-proximity promotion and (unless `entropy_check` is off) the
/// low-entropy demotion, then append it to `out`.
///
/// No finding is emitted when the candidate sits inside an already-redacted
/// `[REDACTED:…]`/`[SV:LOC:…]` marker on its line. The preview is `mask`
/// applied to the matched value, never the value itself.
fn push_secret(
    out: &mut Vec<ScanFinding>,
    content: &str,
    path: &Path,
    rule: &SecretRule,
    start: usize,
    end: usize,
    entropy_check: bool,
) {
    if is_inside_marker(content, start) {
        return;
    }
    let value = &content[start..end];
    let mut confidence = rule.confidence;
    if keyword_before_on_line(content, start) {
        confidence = promote(confidence);
    }
    if entropy_check && shannon_entropy(value.as_bytes()) < ENTROPY_DEMOTE_THRESHOLD {
        confidence = demote(confidence);
    }
    out.push(ScanFinding {
        path: path.to_path_buf(),
        line: line_number(content, start),
        start,
        end,
        kind: FindingKind::Secret {
            rule_id: rule.id.to_string(),
        },
        confidence,
        preview: mask(value),
    });
}

/// Resolve overlapping matches. Candidates are taken best-first (higher
/// confidence, then longer span, then smaller rule id), keeping each only if
/// its span does not overlap an already-kept one, and the result is ordered by
/// start offset for determinism.
fn dedup_overlaps(mut candidates: Vec<ScanFinding>) -> Vec<ScanFinding> {
    candidates.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
            .then_with(|| secret_id(&a.kind).cmp(secret_id(&b.kind)))
    });

    let mut kept: Vec<ScanFinding> = Vec::with_capacity(candidates.len());
    for c in candidates {
        let overlaps = kept.iter().any(|k| c.start < k.end && k.start < c.end);
        if !overlaps {
            kept.push(c);
        }
    }
    kept.sort_by_key(|f| f.start);
    kept
}

/// The rule id for ordering, or an empty string for a non-secret finding.
fn secret_id(kind: &FindingKind) -> &str {
    match kind {
        FindingKind::Secret { rule_id } => rule_id,
        FindingKind::Jurisdiction { rule_id, .. } => rule_id,
        // `detect_secrets` never produces PII candidates; this is only a
        // deterministic fallback if the two lists are ever merged.
        FindingKind::Pii(_) => "",
    }
}

/// True when a [`SECRET_KEYWORDS`] name appears earlier on the same line as
/// the candidate at `start`. Matching is ASCII case-insensitive.
fn keyword_before_on_line(content: &str, start: usize) -> bool {
    let bytes = content.as_bytes();
    let mut line_start = start;
    while line_start > 0 && bytes[line_start - 1] != b'\n' {
        line_start -= 1;
    }
    let before = &bytes[line_start..start];
    SECRET_KEYWORDS
        .iter()
        .any(|kw| contains_ignore_ascii_case(before, kw.as_bytes()))
}

/// True when `needle` occurs in `haystack`, comparing bytes case-insensitively.
fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// True when the candidate at `start` lies inside an already-redacted
/// `[REDACTED:…]` or `[SV:LOC:…]` placeholder on its line (the marker's `[`
/// appears before it with no closing `]` in between). Prevents re-flagging an
/// already-remediated tree.
fn is_inside_marker(content: &str, start: usize) -> bool {
    let bytes = content.as_bytes();
    let mut line_start = start;
    while line_start > 0 && bytes[line_start - 1] != b'\n' {
        line_start -= 1;
    }
    let before = &content[line_start..start];

    // The nearest marker opening before the candidate on this line.
    let open = [before.rfind("[REDACTED:"), before.rfind("[SV:LOC:")]
        .into_iter()
        .flatten()
        .max();
    let Some(open) = open else { return false };

    // If a `]` closes the marker before the candidate, the candidate is outside
    // it; otherwise it is inside the still-open placeholder.
    !before[open..].contains(']')
}

/// Shannon entropy of `value`, in bits per byte. A purely supporting metric —
/// it only ever demotes a rule match and never creates a finding on its own.
fn shannon_entropy(value: &[u8]) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in value {
        counts[b as usize] += 1;
    }
    let len = value.len() as f64;
    let mut entropy = 0.0;
    for &count in counts.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// 1-indexed line number of the byte offset `start`, counted by `\n` before it.
fn line_number(content: &str, start: usize) -> u32 {
    content[..start].bytes().filter(|&b| b == b'\n').count() as u32 + 1
}

/// Raise confidence one step (`Low` → `Medium` → `High`; `High` stays `High`).
fn promote(confidence: Confidence) -> Confidence {
    match confidence {
        Confidence::Low => Confidence::Medium,
        Confidence::Medium => Confidence::High,
        Confidence::High => Confidence::High,
    }
}

/// Lower confidence one step (`High` → `Medium` → `Low`; `Low` stays `Low`).
fn demote(confidence: Confidence) -> Confidence {
    match confidence {
        Confidence::High => Confidence::Medium,
        Confidence::Medium => Confidence::Low,
        Confidence::Low => Confidence::Low,
    }
}

/// Confidence for a PII match: checksum-validated identifiers are `High`,
/// structurally-validated categories are `Medium`.
fn pii_confidence(category: sv_privacy::PiiCategory) -> Confidence {
    use sv_privacy::PiiCategory as C;
    match category {
        C::Cpf | C::Cnpj | C::CreditCard => Confidence::High,
        C::Email | C::Ipv4 | C::Phone | C::Ssn => Confidence::Medium,
    }
}
