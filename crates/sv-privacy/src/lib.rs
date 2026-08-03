//! Sovereign Vault privacy-mediation layer.
//!
//! This crate implements the **PII-masking half** of the thesis's *"Módulo de
//! Mediação e Filtro de Privacidade"* (reference architecture §3.6, module 3).
//! The cryptographic-intermediation half — signing/encrypting with a key that
//! never leaves the vault — lives in `sv-core::transit`. Together they let the
//! gateway *use* and *expose* local data without surrendering raw secrets or
//! raw personal data to an external model.
//!
//! It is deliberately a **leaf crate**: pure Rust, no regular-expression engine
//! and no other Sovereign Vault dependencies, so the detectors are auditable
//! line-by-line (relevant to the §3.9.2 privacy evaluation) and add no
//! supply-chain surface. The gateway (`sv-mcp`) applies [`redact`] to file
//! content read from `SecurityMode::ANONYMIZED` containers before it crosses
//! the agent boundary.
//!
//! # Detectors
//!
//! The default [`Policy`] enables every category in [`PiiCategory::ALL`]. The
//! set is biased toward the Brazilian / LGPD context of the thesis:
//!
//! * [`PiiCategory::Email`] — RFC-shaped `local@domain.tld`.
//! * [`PiiCategory::Cpf`] — Cadastro de Pessoas Físicas, check-digit validated.
//! * [`PiiCategory::Cnpj`] — Cadastro Nacional da Pessoa Jurídica, validated.
//! * [`PiiCategory::CreditCard`] — 13–19 digit PAN, Luhn validated.
//! * [`PiiCategory::Ipv4`] — dotted-quad with each octet `<= 255`.
//! * [`PiiCategory::Phone`] — conservative: requires an explicit `+` country
//!   code or a parenthesised area code, trading recall for precision so prose
//!   numbers are not over-masked.
//!
//! Detectors that validate a checksum (CPF, CNPJ, credit card) reject
//! syntactically-plausible-but-invalid numbers, which keeps the false-positive
//! rate low — the honest limitation is recall, documented per detector.
//!
//! # Stability
//!
//! Pre-1.0. APIs subject to change.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// A class of personally-identifiable information the layer can detect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiCategory {
    /// Email address (`local@domain.tld`).
    Email,
    /// Brazilian individual taxpayer registry (CPF).
    Cpf,
    /// Brazilian legal-entity registry (CNPJ).
    Cnpj,
    /// Payment-card primary account number (Luhn-valid).
    CreditCard,
    /// IPv4 dotted-quad address.
    Ipv4,
    /// Telephone number (explicitly formatted).
    Phone,
    /// US Social Security Number (`\d{3}-\d{2}-\d{4}`).
    Ssn,
}

impl PiiCategory {
    /// Every detectable category, in detector-precedence order (earlier wins an
    /// overlap tie — see [`redact`]).
    pub const ALL: [PiiCategory; 7] = [
        PiiCategory::Cnpj,
        PiiCategory::Cpf,
        PiiCategory::CreditCard,
        PiiCategory::Email,
        PiiCategory::Ipv4,
        PiiCategory::Phone,
        PiiCategory::Ssn,
    ];

    /// Stable uppercase label used in the redaction placeholder, e.g. `EMAIL`
    /// renders as `[REDACTED:EMAIL]`.
    pub fn label(self) -> &'static str {
        match self {
            PiiCategory::Email => "EMAIL",
            PiiCategory::Cpf => "CPF",
            PiiCategory::Cnpj => "CNPJ",
            PiiCategory::CreditCard => "CREDIT_CARD",
            PiiCategory::Ipv4 => "IPV4",
            PiiCategory::Phone => "PHONE",
            PiiCategory::Ssn => "SSN",
        }
    }

    /// Overlap-resolution precedence; higher wins when two findings overlap.
    /// Checksum-validated identifiers outrank looser patterns.
    fn priority(self) -> u8 {
        match self {
            PiiCategory::Cnpj => 6,
            PiiCategory::Cpf => 5,
            PiiCategory::CreditCard => 4,
            PiiCategory::Email => 3,
            PiiCategory::Ipv4 => 2,
            PiiCategory::Phone => 1,
            PiiCategory::Ssn => 2,
        }
    }
}

/// Which categories to mask. Construct with [`Policy::all`] (the default) or
/// [`Policy::only`] for a narrowed set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Enabled categories.
    pub categories: BTreeSet<PiiCategory>,
}

impl Default for Policy {
    fn default() -> Self {
        Self::all()
    }
}

impl Policy {
    /// Enable every category in [`PiiCategory::ALL`].
    pub fn all() -> Self {
        Self {
            categories: PiiCategory::ALL.into_iter().collect(),
        }
    }

    /// Enable only the given categories.
    pub fn only<I: IntoIterator<Item = PiiCategory>>(categories: I) -> Self {
        Self {
            categories: categories.into_iter().collect(),
        }
    }

    /// Whether `category` is masked under this policy.
    pub fn enabled(&self, category: PiiCategory) -> bool {
        self.categories.contains(&category)
    }
}

/// One located piece of PII in the input. Offsets are byte indices into the
/// original `&str`; because every detector matches ASCII, the offsets always
/// fall on UTF-8 character boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// The category that matched.
    pub category: PiiCategory,
    /// Byte offset of the first matched byte (inclusive).
    pub start: usize,
    /// Byte offset just past the last matched byte (exclusive).
    pub end: usize,
}

/// Result of [`redact`]: the masked text plus the findings that were replaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Redaction {
    /// Text with every finding replaced by `[REDACTED:<LABEL>]`.
    pub output: String,
    /// The findings that were masked, in document order.
    pub findings: Vec<Finding>,
}

impl Redaction {
    /// Number of PII spans masked.
    pub fn count(&self) -> usize {
        self.findings.len()
    }

    /// True when no PII was detected (the output equals the input).
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Count of masked spans grouped by category, for audit/eval reporting.
    pub fn counts_by_category(&self) -> Vec<(PiiCategory, usize)> {
        let mut out: Vec<(PiiCategory, usize)> = Vec::new();
        for category in PiiCategory::ALL {
            let n = self
                .findings
                .iter()
                .filter(|f| f.category == category)
                .count();
            if n > 0 {
                out.push((category, n));
            }
        }
        out
    }
}

/// Detect and mask PII in `input` according to `policy`.
///
/// Returns the masked string and the ordered list of [`Finding`]s. Overlapping
/// matches are resolved greedily from the left, preferring the higher-priority
/// category (see [`PiiCategory::priority`]); the input is never read or logged
/// elsewhere.
pub fn redact(input: &str, policy: &Policy) -> Redaction {
    let findings = scan(input, policy);
    let output = apply(input, &findings);
    Redaction { output, findings }
}

/// Detect PII without rewriting the text. Same matching as [`redact`].
pub fn scan(input: &str, policy: &Policy) -> Vec<Finding> {
    let bytes = input.as_bytes();
    let mut raw: Vec<Finding> = Vec::new();

    if policy.enabled(PiiCategory::Email) {
        find_emails(bytes, &mut raw);
    }
    if policy.enabled(PiiCategory::Ipv4) {
        find_ipv4(bytes, &mut raw);
    }
    if policy.enabled(PiiCategory::Cpf) {
        find_cpf(bytes, &mut raw);
    }
    if policy.enabled(PiiCategory::Cnpj) {
        find_cnpj(bytes, &mut raw);
    }
    if policy.enabled(PiiCategory::CreditCard) {
        find_credit_cards(bytes, &mut raw);
    }
    if policy.enabled(PiiCategory::Phone) {
        find_phones(bytes, &mut raw);
    }
    if policy.enabled(PiiCategory::Ssn) {
        find_ssns(bytes, &mut raw);
    }

    resolve_overlaps(raw)
}

/// Greedy left-to-right overlap resolution. At a given start offset the
/// higher-priority (and then longer) finding is kept; later findings that
/// overlap an already-kept span are dropped.
fn resolve_overlaps(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(b.category.priority().cmp(&a.category.priority()))
            .then((b.end - b.start).cmp(&(a.end - a.start)))
    });
    let mut kept: Vec<Finding> = Vec::with_capacity(findings.len());
    let mut last_end = 0usize;
    for f in findings {
        if f.start >= last_end {
            last_end = f.end;
            kept.push(f);
        }
    }
    kept
}

/// Rewrite `input`, replacing each (already non-overlapping, ordered) finding
/// with its placeholder token.
fn apply(input: &str, findings: &[Finding]) -> String {
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;
    for f in findings {
        if f.start > cursor {
            out.push_str(&input[cursor..f.start]);
        }
        out.push_str("[REDACTED:");
        out.push_str(f.category.label());
        out.push(']');
        cursor = f.end;
    }
    if cursor < input.len() {
        out.push_str(&input[cursor..]);
    }
    out
}

// ---- byte-level character classes ----------------------------------------

fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}

fn is_email_local(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_email_domain(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
}

/// True if the byte immediately bordering a numeric match is "separating"
/// (not a digit and not a dot), so we don't clip a longer number in half.
fn is_number_boundary(b: Option<u8>) -> bool {
    match b {
        None => true,
        Some(c) => !is_digit(c) && c != b'.',
    }
}

// ---- detectors ------------------------------------------------------------

/// `local@domain.tld`. The local part is non-empty; the domain must contain a
/// dot and end in a 2+ alphabetic TLD. Trailing `.`/`-` (e.g. a sentence-final
/// period) are excluded from the match.
fn find_emails(b: &[u8], out: &mut Vec<Finding>) {
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'@' {
            i += 1;
            continue;
        }
        // Expand the local part left.
        let mut start = i;
        while start > 0 && is_email_local(b[start - 1]) {
            start -= 1;
        }
        // Expand the domain right.
        let mut end = i + 1;
        while end < b.len() && is_email_domain(b[end]) {
            end += 1;
        }
        // Trim trailing separators that are punctuation, not part of the host.
        while end > i + 1 && matches!(b[end - 1], b'.' | b'-') {
            end -= 1;
        }
        if start < i && valid_email_domain(&b[i + 1..end]) {
            out.push(Finding {
                category: PiiCategory::Email,
                start,
                end,
            });
        }
        i = end.max(i + 1);
    }
}

fn valid_email_domain(domain: &[u8]) -> bool {
    if domain.is_empty() || domain[0] == b'.' {
        return false;
    }
    let Some(dot) = domain.iter().rposition(|&c| c == b'.') else {
        return false;
    };
    let tld = &domain[dot + 1..];
    tld.len() >= 2 && tld.iter().all(|c| c.is_ascii_alphabetic())
}

/// Dotted-quad IPv4 with each octet in `0..=255`, bounded by non-digit/non-dot.
fn find_ipv4(b: &[u8], out: &mut Vec<Finding>) {
    let mut i = 0;
    while i < b.len() {
        if !is_digit(b[i]) || !is_number_boundary(i.checked_sub(1).map(|j| b[j])) {
            i += 1;
            continue;
        }
        let mut end = i;
        let mut octets = 0;
        let mut ok = true;
        while octets < 4 {
            let seg_start = end;
            let mut val: u32 = 0;
            let mut len = 0;
            while end < b.len() && is_digit(b[end]) && len < 3 {
                val = val * 10 + (b[end] - b'0') as u32;
                end += 1;
                len += 1;
            }
            if len == 0 || val > 255 || (len > 1 && b[seg_start] == b'0') {
                ok = false;
                break;
            }
            octets += 1;
            if octets < 4 {
                if end < b.len() && b[end] == b'.' {
                    end += 1;
                } else {
                    ok = false;
                    break;
                }
            }
        }
        if ok && octets == 4 && is_number_boundary(b.get(end).copied()) {
            out.push(Finding {
                category: PiiCategory::Ipv4,
                start: i,
                end,
            });
            i = end;
        } else {
            i += 1;
        }
    }
}

/// Collect up to `max` digits starting at `i`, allowing single `sep` bytes
/// (space, `.`, `-`, `/`) between digits. Returns (digits, end_offset).
fn collect_grouped_digits(b: &[u8], i: usize, max: usize) -> (Vec<u8>, usize) {
    let mut digits = Vec::with_capacity(max);
    let mut end = i;
    while end < b.len() && digits.len() < max {
        let c = b[end];
        if is_digit(c) {
            digits.push(c - b'0');
            end += 1;
        } else if matches!(c, b' ' | b'.' | b'-' | b'/')
            && end + 1 < b.len()
            && is_digit(b[end + 1])
            && !digits.is_empty()
        {
            end += 1;
        } else {
            break;
        }
    }
    (digits, end)
}

/// CPF: `ddd.ddd.ddd-dd` or 11 bare digits, with valid check digits.
fn find_cpf(b: &[u8], out: &mut Vec<Finding>) {
    find_checked_id(b, 11, PiiCategory::Cpf, cpf_valid, out);
}

/// CNPJ: `dd.ddd.ddd/dddd-dd` or 14 bare digits, with valid check digits.
fn find_cnpj(b: &[u8], out: &mut Vec<Finding>) {
    find_checked_id(b, 14, PiiCategory::Cnpj, cnpj_valid, out);
}

/// Shared scanner for fixed-length, checksum-validated numeric identifiers.
fn find_checked_id(
    b: &[u8],
    len: usize,
    category: PiiCategory,
    validate: fn(&[u8]) -> bool,
    out: &mut Vec<Finding>,
) {
    let mut i = 0;
    while i < b.len() {
        if !is_digit(b[i]) || !is_number_boundary(i.checked_sub(1).map(|j| b[j])) {
            i += 1;
            continue;
        }
        let (digits, end) = collect_grouped_digits(b, i, len);
        if digits.len() == len && is_number_boundary(b.get(end).copied()) && validate(&digits) {
            out.push(Finding {
                category,
                start: i,
                end,
            });
            i = end;
        } else {
            i += 1;
        }
    }
}

/// Credit-card PAN: 13–19 digits (optionally space/dash grouped), Luhn-valid.
fn find_credit_cards(b: &[u8], out: &mut Vec<Finding>) {
    let mut i = 0;
    while i < b.len() {
        if !is_digit(b[i]) || !is_number_boundary(i.checked_sub(1).map(|j| b[j])) {
            i += 1;
            continue;
        }
        let (digits, end) = collect_grouped_digits(b, i, 19);
        if (13..=19).contains(&digits.len())
            && is_number_boundary(b.get(end).copied())
            && luhn_valid(&digits)
        {
            out.push(Finding {
                category: PiiCategory::CreditCard,
                start: i,
                end,
            });
            i = end;
        } else {
            i += 1;
        }
    }
}

/// Telephone numbers, deliberately conservative: a match must start with `+`
/// (international) or `(` (parenthesised area code). This avoids masking
/// ordinary numbers in prose at the cost of recall on bare local numbers.
fn find_phones(b: &[u8], out: &mut Vec<Finding>) {
    let mut i = 0;
    while i < b.len() {
        let lead = b[i];
        if lead != b'+' && lead != b'(' {
            i += 1;
            continue;
        }
        // Require a separating boundary before the lead so we don't match mid-token.
        if !is_number_boundary(i.checked_sub(1).map(|j| b[j])) {
            i += 1;
            continue;
        }
        let mut end = i + 1;
        let mut digits = 0;
        let mut saw_close_paren = false;
        while end < b.len() {
            let c = b[end];
            if is_digit(c) {
                digits += 1;
                end += 1;
            } else if matches!(c, b' ' | b'-' | b'.' | b'(' | b')') {
                if c == b')' {
                    saw_close_paren = true;
                }
                end += 1;
            } else {
                break;
            }
        }
        // Trim trailing non-digits from the match.
        while end > i && !is_digit(b[end - 1]) {
            end -= 1;
        }
        let parens_ok = lead != b'(' || saw_close_paren;
        if (10..=13).contains(&digits) && parens_ok {
            out.push(Finding {
                category: PiiCategory::Phone,
                start: i,
                end,
            });
            i = end.max(i + 1);
        } else {
            i += 1;
        }
    }
}

/// US Social Security Number: exactly `\d{3}-\d{2}-\d{4}`, bounded on both
/// sides by a non-digit non-hyphen character (or the string boundary).
fn find_ssns(b: &[u8], out: &mut Vec<Finding>) {
    let mut i = 0;
    while i < b.len() {
        // Must start with a digit.
        if !is_digit(b[i]) {
            i += 1;
            continue;
        }
        // Must have a non-digit/non-hyphen boundary before.
        let prev = i.checked_sub(1).map(|j| b[j]);
        if !is_ssn_boundary(prev) {
            i += 1;
            continue;
        }
        // Match exactly DDD-DD-DDDD.
        if i + 11 > b.len() {
            i += 1;
            continue;
        }
        let s = &b[i..i + 11];
        let valid = is_digit(s[0])
            && is_digit(s[1])
            && is_digit(s[2])
            && s[3] == b'-'
            && is_digit(s[4])
            && is_digit(s[5])
            && s[6] == b'-'
            && is_digit(s[7])
            && is_digit(s[8])
            && is_digit(s[9])
            && is_digit(s[10]);
        if valid && is_ssn_boundary(b.get(i + 11).copied()) {
            out.push(Finding {
                category: PiiCategory::Ssn,
                start: i,
                end: i + 11,
            });
            i += 11;
        } else {
            i += 1;
        }
    }
}

/// Boundary check for SSN: not a digit and not a hyphen (hyphens are
/// structural within the SSN itself).
fn is_ssn_boundary(b: Option<u8>) -> bool {
    match b {
        None => true,
        Some(c) => !is_digit(c) && c != b'-',
    }
}

// ---- checksum validators --------------------------------------------------

/// Luhn (mod-10) check over a slice of single digits.
fn luhn_valid(digits: &[u8]) -> bool {
    if digits.len() < 2 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut v = d as u32;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// CPF check-digit validation (rejects the all-equal degenerate inputs).
fn cpf_valid(d: &[u8]) -> bool {
    if d.len() != 11 || d.iter().all(|&x| x == d[0]) {
        return false;
    }
    let check = |upto: usize, start_weight: usize| -> u8 {
        let mut sum = 0usize;
        for (k, &digit) in d.iter().take(upto).enumerate() {
            sum += digit as usize * (start_weight - k);
        }
        let r = (sum * 10) % 11;
        if r == 10 {
            0
        } else {
            r as u8
        }
    };
    check(9, 10) == d[9] && check(10, 11) == d[10]
}

/// CNPJ check-digit validation (rejects the all-equal degenerate inputs).
fn cnpj_valid(d: &[u8]) -> bool {
    if d.len() != 14 || d.iter().all(|&x| x == d[0]) {
        return false;
    }
    let weights1 = [5usize, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    let weights2 = [6usize, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    let digit = |weights: &[usize]| -> u8 {
        let mut sum = 0usize;
        for (k, &w) in weights.iter().enumerate() {
            sum += d[k] as usize * w;
        }
        let r = sum % 11;
        if r < 2 {
            0
        } else {
            (11 - r) as u8
        }
    };
    digit(&weights1) == d[12] && digit(&weights2) == d[13]
}

/// Crate version string.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cats(r: &Redaction) -> Vec<PiiCategory> {
        r.findings.iter().map(|f| f.category).collect()
    }

    #[test]
    fn masks_email() {
        let r = redact(
            "contact me at jane.doe+spam@example.co.uk please",
            &Policy::all(),
        );
        assert_eq!(cats(&r), vec![PiiCategory::Email]);
        assert_eq!(r.output, "contact me at [REDACTED:EMAIL] please");
    }

    #[test]
    fn email_trailing_period_excluded() {
        let r = redact("write to a@b.com.", &Policy::all());
        assert_eq!(r.count(), 1);
        assert_eq!(r.output, "write to [REDACTED:EMAIL].");
    }

    #[test]
    fn masks_ipv4_but_not_out_of_range() {
        let r = redact("host 192.168.0.1 ok, 999.1.1.1 not", &Policy::all());
        assert_eq!(cats(&r), vec![PiiCategory::Ipv4]);
        assert!(r.output.contains("[REDACTED:IPV4]"));
        assert!(r.output.contains("999.1.1.1"));
    }

    #[test]
    fn ipv4_rejects_version_strings() {
        // Five groups / leading zeros are not valid dotted-quads.
        let r = redact("v1.2.3.4.5 and 01.02.03.04", &Policy::all());
        assert!(r.is_clean(), "unexpected: {:?}", r.findings);
    }

    #[test]
    fn masks_valid_cpf_formatted_and_bare() {
        // A known check-digit-valid CPF.
        let r = redact("CPF 529.982.247-25 e 52998224725", &Policy::all());
        assert_eq!(cats(&r), vec![PiiCategory::Cpf, PiiCategory::Cpf]);
    }

    #[test]
    fn rejects_invalid_cpf() {
        let r = redact(
            "not a cpf: 111.111.111-11 or 123.456.789-00",
            &Policy::only([PiiCategory::Cpf]),
        );
        assert!(r.is_clean(), "unexpected: {:?}", r.findings);
    }

    #[test]
    fn masks_valid_cnpj() {
        // Check-digit-valid CNPJ.
        let r = redact("empresa 11.222.333/0001-81 aqui", &Policy::all());
        assert_eq!(cats(&r), vec![PiiCategory::Cnpj]);
    }

    #[test]
    fn masks_luhn_valid_card_only() {
        // 4111 1111 1111 1111 is the canonical Luhn-valid test PAN.
        let r = redact(
            "card 4111 1111 1111 1111 vs 4111 1111 1111 1112",
            &Policy::all(),
        );
        assert_eq!(r.count(), 1);
        assert!(r.output.contains("[REDACTED:CREDIT_CARD]"));
        assert!(r.output.contains("4111 1111 1111 1112"));
    }

    #[test]
    fn masks_intl_and_paren_phone() {
        let r = redact(
            "call +55 11 91234-5678 or (011) 4002-8922",
            &Policy::only([PiiCategory::Phone]),
        );
        assert_eq!(r.count(), 2);
    }

    #[test]
    fn policy_can_disable_a_category() {
        let policy = Policy::only([PiiCategory::Email]);
        let r = redact("a@b.com and 192.168.0.1", &policy);
        assert_eq!(cats(&r), vec![PiiCategory::Email]);
        assert!(r.output.contains("192.168.0.1"));
    }

    #[test]
    fn clean_text_is_untouched() {
        let input = "the quick brown fox jumps over 42 lazy dogs";
        let r = redact(input, &Policy::all());
        assert!(r.is_clean());
        assert_eq!(r.output, input);
    }

    #[test]
    fn multiple_findings_ordered_and_counted() {
        let r = redact("e a@b.com ip 10.0.0.1 e cpf 529.982.247-25", &Policy::all());
        assert_eq!(
            cats(&r),
            vec![PiiCategory::Email, PiiCategory::Ipv4, PiiCategory::Cpf]
        );
        assert_eq!(r.count(), 3);
        let by_cat = r.counts_by_category();
        assert!(by_cat.contains(&(PiiCategory::Email, 1)));
    }

    #[test]
    fn masks_ssn_formatted() {
        // Clearly fake SSN used for test purposes only.
        let r = redact(r#""ssn":"123-45-6789""#, &Policy::all());
        assert_eq!(cats(&r), vec![PiiCategory::Ssn]);
        assert_eq!(r.output, r#""ssn":"[REDACTED:SSN]""#);
    }

    #[test]
    fn ssn_not_matched_without_hyphens() {
        // Bare digits without hyphens must NOT be matched as an SSN.
        let r = redact("123456789", &Policy::only([PiiCategory::Ssn]));
        assert!(r.is_clean(), "unexpected: {:?}", r.findings);
    }

    #[test]
    fn ssn_boundary_required() {
        // An SSN embedded mid-word (e.g. a longer digit run) must not match.
        let r = redact("1234-56-7890", &Policy::only([PiiCategory::Ssn]));
        // 4 leading digits disqualify the pattern starting at offset 0.
        assert!(r.is_clean(), "unexpected: {:?}", r.findings);
    }

    #[test]
    fn luhn_basic() {
        assert!(luhn_valid(&[
            4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
        ]));
        assert!(!luhn_valid(&[
            4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2
        ]));
    }
}
