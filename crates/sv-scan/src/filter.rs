//! Context filters that suppress structurally-implausible findings.
//!
//! The detectors in [`crate::detect`] are deliberately syntactic: they match a
//! shape, not a meaning. On a real project tree that produces false positives
//! which are not detector bugs but *context* failures — a Luhn-valid digit run
//! inside an SVG path, a `sk-` prefix inside a CSS `src-` fragment, a loopback
//! address in a bind call.
//!
//! These filters run *after* detection. They never create a finding and never
//! promote one, so a filter bug can cost attention but can never manufacture a
//! false report. Per ADR-0017 the deterministic detectors remain the
//! security-relevant path; everything here is a usability measure.
//!
//! **Demotion is the default; removal is the exception.** "This file is
//! generated", "this value looks like a placeholder", and "this address is
//! private" are statements about likelihood, not proof — a leaked key really
//! can sit inside a committed bundle, a live password really can contain the
//! word `sample`, and `10.23.4.5` really does identify a device inside the
//! network that owns it. Deleting a finding on a heuristic would hide exactly
//! the one the user most needs to see, so only structurally-impossible matches
//! are dropped (see [`SuppressionReason::is_removal`]); everything else
//! survives at [`Confidence::Low`].
//!
//! Nothing is filtered silently. Every judgement is counted in
//! [`crate::Coverage::suppressed`] by reason, so a report always states what
//! was down-weighted on the user's behalf.

use std::path::Path;

use sv_privacy::PiiCategory;

use crate::types::{Confidence, FindingKind, ScanFinding, SuppressionReason};

/// Longest digit run that a payment card can legitimately have.
const MAX_CARD_DIGITS: usize = 19;

/// Decide whether a finding survives, and why it does not when it fails.
///
/// Returns `None` when the finding stands, or the reason it was suppressed.
pub(crate) fn suppression_reason(
    finding: &ScanFinding,
    content: &str,
    path: &Path,
) -> Option<SuppressionReason> {
    if is_generated_path(path) {
        return Some(SuppressionReason::GeneratedFile);
    }
    match &finding.kind {
        FindingKind::Pii(PiiCategory::Ipv4) => {
            let value = &content[finding.start..finding.end];
            if is_non_identifying_ip(value) {
                return Some(SuppressionReason::NonIdentifyingAddress);
            }
            None
        }
        // Every checksum-validated numeric identifier shares one weakness: the
        // checksum is a handful of bits, so long runs of unrelated digits pass
        // it. CPF and CNPJ are as vulnerable as a card number, and a single
        // Android vector drawable produced 709 "card" and 56 "CNPJ" matches in
        // a real project, so all three route through the same context tests.
        FindingKind::Pii(
            PiiCategory::CreditCard | PiiCategory::Cpf | PiiCategory::Cnpj | PiiCategory::Ssn,
        ) => {
            if in_numeric_run(content, finding.start, finding.end) {
                return Some(SuppressionReason::EmbeddedInNumericRun);
            }
            if is_vector_graphic(content, path)
                || is_structured_numeric_context(content, finding.start)
            {
                return Some(SuppressionReason::StructuredNumericData);
            }
            None
        }
        // Pack rules find national identifiers, which are mostly digit runs
        // guarded by short checksums — the same weakness that made an Android
        // vector drawable yield 709 false "card numbers". They therefore go
        // through the same context tests as the built-in numeric categories.
        FindingKind::Jurisdiction { .. } => {
            // Only the "window into a longer run" test applies here. The
            // card-specific length ceiling must NOT: an IBAN carries up to 32
            // characters, so reusing `MAX_CARD_DIGITS` silently deleted every
            // valid IBAN. A pack rule already declares its own length bounds.
            if adjacent_to_digits(content, finding.start, finding.end) {
                return Some(SuppressionReason::EmbeddedInNumericRun);
            }
            if is_vector_graphic(content, path)
                || is_structured_numeric_context(content, finding.start)
            {
                return Some(SuppressionReason::StructuredNumericData);
            }
            None
        }
        FindingKind::Secret { rule_id } => {
            if is_placeholder_value(&content[finding.start..finding.end]) {
                return Some(SuppressionReason::PlaceholderValue);
            }
            if rule_id == "openai_api_key" && !plausible_openai_key(content, finding) {
                return Some(SuppressionReason::ImplausibleKeyContext);
            }
            None
        }
        _ => None,
    }
}

/// True when a path is generated, vendored, or otherwise not hand-written.
///
/// `DEFAULT_EXCLUDES` removes most of these at walk time; this is the
/// second line of defence for a caller who supplied a narrower exclude list,
/// and for suffixes that are awkward to express as a directory glob.
fn is_generated_path(path: &Path) -> bool {
    let text = path.to_string_lossy().replace('\\', "/");
    const GENERATED_DIRS: &[&str] = &[
        "/node_modules/",
        "/target/",
        "/dist/",
        "/build/",
        "/vendor/",
        "/.venv/",
        "/__pycache__/",
        "/.vite/",
        "/coverage/",
        "/.next/",
        "/.svelte-kit/",
    ];
    let probe = format!("/{text}");
    if GENERATED_DIRS.iter().any(|d| probe.contains(d)) {
        return true;
    }
    const GENERATED_SUFFIXES: &[&str] = &[
        ".min.js",
        ".min.css",
        ".map",
        ".fdb_latexmk",
        ".fls",
        ".aux",
        ".synctex.gz",
        ".lock",
        "-lock.json",
        ".bundle.js",
        ".chunk.js",
    ];
    GENERATED_SUFFIXES.iter().any(|s| text.ends_with(s))
}

/// True for addresses that identify a machine role rather than a person:
/// loopback, unspecified, link-local, broadcast, documentation ranges, and the
/// RFC 1918 private ranges.
///
/// `127.0.0.1` in a bind call is configuration, not personal data. Treating it
/// as PII buries the findings that matter.
fn is_non_identifying_ip(value: &str) -> bool {
    let mut parts = value.split('.');
    let octets: Option<Vec<u8>> = (0..4)
        .map(|_| parts.next().and_then(|p| p.parse::<u8>().ok()))
        .collect();
    let Some(o) = octets else { return false };
    if parts.next().is_some() {
        return false;
    }
    match (o[0], o[1], o[2], o[3]) {
        // Loopback, unspecified, broadcast.
        (127, _, _, _) | (0, _, _, _) | (255, 255, 255, 255) => true,
        // RFC 1918 private ranges.
        (10, _, _, _) => true,
        (172, b, _, _) if (16..=31).contains(&b) => true,
        (192, 168, _, _) => true,
        // Link-local and CGNAT.
        (169, 254, _, _) => true,
        (100, b, _, _) if (64..=127).contains(&b) => true,
        // Multicast and reserved.
        (a, _, _, _) if a >= 224 => true,
        // RFC 5737 documentation ranges.
        (192, 0, 2, _) | (198, 51, 100, _) | (203, 0, 113, _) => true,
        _ => false,
    }
}

/// True when the match is a slice of a longer digit run.
///
/// A card number is a whole field. When the surrounding bytes are also digits,
/// what matched is a window into a hash, an SVG path, a timestamp series, or a
/// build log — not a payment instrument.
fn in_numeric_run(content: &str, start: usize, end: usize) -> bool {
    if adjacent_to_digits(content, start, end) {
        return true;
    }
    // A separator-stripped run longer than any real card is not a card. This
    // ceiling is card-specific and must not be applied to other identifier
    // types: an IBAN legitimately carries up to 32 characters.
    let stripped = content[start..end]
        .bytes()
        .filter(u8::is_ascii_digit)
        .count();
    stripped > MAX_CARD_DIGITS
}

/// True when a digit sits immediately before or after the match, meaning the
/// match is a window into a longer run rather than a whole field.
///
/// This test is identifier-agnostic and safe for every numeric category.
fn adjacent_to_digits(content: &str, start: usize, end: usize) -> bool {
    let bytes = content.as_bytes();
    let before = bytes[..start]
        .iter()
        .rev()
        .take_while(|b| b.is_ascii_digit())
        .count();
    let after = bytes[end..]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    before > 0 || after > 0
}

/// True when the match sits in data that is numeric by construction: SVG path
/// geometry, a CSS transform, a coordinate array, or a base-N blob.
fn is_structured_numeric_context(content: &str, start: usize) -> bool {
    let line = line_slice(content, start);
    const GEOMETRY_MARKERS: &[&str] = &[
        "<path",
        " d=\"",
        "viewBox",
        "translate(",
        "matrix(",
        "cubic-bezier(",
        "polygon",
        "polyline",
        "stroke-dasharray",
        // Android vector drawables put geometry on its own attribute line, so
        // the `<path` element marker never appears beside the coordinates. One
        // such file produced 709 of 734 card "findings" in a real project.
        "pathData",
        "android:path",
        "clipPathData",
        "fillColor",
    ];
    if GEOMETRY_MARKERS.iter().any(|m| line.contains(m)) {
        return true;
    }
    // A line that is overwhelmingly digits and separators is data, not prose.
    // Path commands (M/L/C/Z and friends) count as separators here: a run of
    // SVG geometry is exactly digits, punctuation, and single command letters.
    let total = line.len();
    if total >= 80 {
        let numeric = line
            .bytes()
            .filter(|b| {
                b.is_ascii_digit()
                    || matches!(b, b'.' | b',' | b' ' | b'-' | b'+')
                    || matches!(
                        b,
                        b'M' | b'L'
                            | b'C'
                            | b'Z'
                            | b'H'
                            | b'V'
                            | b'S'
                            | b'Q'
                            | b'T'
                            | b'A'
                            | b'm'
                            | b'l'
                            | b'c'
                            | b'z'
                            | b'h'
                            | b'v'
                            | b's'
                            | b'q'
                            | b't'
                            | b'a'
                    )
            })
            .count();
        if numeric * 10 >= total * 9 {
            return true;
        }
    }
    false
}

/// True when the whole file is vector artwork.
///
/// Geometry can span many lines, so a per-line marker test misses coordinates
/// in the middle of a large `<vector>` or `<svg>` element. Payment data does
/// not live in artwork, so the file as a whole is the right unit here.
fn is_vector_graphic(content: &str, path: &Path) -> bool {
    let name = path.to_string_lossy().to_ascii_lowercase();
    if name.ends_with(".svg") {
        return true;
    }
    if !name.ends_with(".xml") {
        return false;
    }
    // Only inspect the head: enough to identify the document type without
    // scanning a large file twice.
    let head = &content[..content.len().min(4096)];
    head.contains("<vector") || head.contains("<svg") || head.contains("android:pathData")
}

/// True for values that read as documentation examples rather than live
/// credentials.
///
/// Deliberately narrow. A bare substring test would match a live password such
/// as `sampleCompany!2026`, and this only ever demotes, never deletes — but a
/// demotion still buries a finding, so the markers must be ones that do not
/// plausibly occur inside a real secret. Angle brackets and the bare words
/// `sample`/`fake` were tried and removed for exactly that reason.
fn is_placeholder_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    // Documentation-substitution markers: a real credential does not contain
    // these, because they are the shape of an instruction to the reader.
    const MARKERS: &[&str] = &[
        "your-api",
        "your_api",
        "your-key",
        "your_key",
        "your-token",
        "your_token",
        "changeme",
        "change-me",
        "change_me",
        "placeholder",
        "redacted",
        "insert-your",
        "insert_your",
        "replace-with",
        "replace_with",
        "xxxxxxxx",
        "aaaaaaaa",
        "12345678",
        "notarealkey",
        "example.com",
        "examplekey",
        "example-key",
        "example_key",
    ];
    if MARKERS.iter().any(|m| lower.contains(m)) {
        return true;
    }
    // A body of one repeated character is a fill pattern, never a credential.
    let body = lower
        .split(['-', '_'])
        .next_back()
        .unwrap_or(&lower)
        .trim_matches(|c: char| !c.is_ascii_alphanumeric());
    body.len() >= 8 && body.chars().all(|c| c == body.as_bytes()[0] as char)
}

/// Extra plausibility gate for the `sk-` family.
///
/// `sk-` is only three characters, so it collides with ordinary text such as
/// the CSS fragment `src-`. Require either a credential-shaped assignment on
/// the line or a body long enough to be a real key.
fn plausible_openai_key(content: &str, finding: &ScanFinding) -> bool {
    let value = &content[finding.start..finding.end];
    let body = value.strip_prefix("sk-").unwrap_or(value);
    if body.len() >= 40 {
        return true;
    }
    let line = line_slice(content, finding.start).to_ascii_lowercase();
    const ASSIGNMENT_HINTS: &[&str] = &[
        "api_key",
        "apikey",
        "api-key",
        "openai",
        "secret",
        "token",
        "key =",
        "key=",
        "key:",
        "bearer",
        "authorization",
    ];
    ASSIGNMENT_HINTS.iter().any(|h| line.contains(h))
}

/// The whole line containing byte offset `start`.
fn line_slice(content: &str, start: usize) -> &str {
    let bytes = content.as_bytes();
    let mut line_start = start.min(content.len());
    while line_start > 0 && bytes[line_start - 1] != b'\n' {
        line_start -= 1;
    }
    let mut line_end = start.min(content.len());
    while line_end < bytes.len() && bytes[line_end] != b'\n' {
        line_end += 1;
    }
    &content[line_start..line_end]
}

/// Demote a finding whose confidence the context makes less certain.
///
/// Never promotes. Returns the confidence unchanged when nothing applies.
pub(crate) fn adjust_confidence(
    finding: &ScanFinding,
    content: &str,
    current: Confidence,
) -> Confidence {
    if matches!(finding.kind, FindingKind::Pii(PiiCategory::CreditCard))
        && !has_card_context(content, finding.start)
        && current > Confidence::Low
    {
        // Luhn is a single decimal check digit — roughly 3.3 bits, so about one
        // in ten arbitrary digit runs passes it. In a source tree that is a
        // weak signal on its own. Without a supporting word on the line a
        // Luhn-valid run stays a candidate rather than a claim. Note the
        // converse does not hold: a real PAN needs no payment vocabulary
        // nearby, which is why this demotes and never suppresses.
        return Confidence::Low;
    }
    current
}

/// True when the line names something payment-related.
fn has_card_context(content: &str, start: usize) -> bool {
    let line = line_slice(content, start).to_ascii_lowercase();
    const CARD_WORDS: &[&str] = &[
        "card",
        "cartao",
        "cartão",
        "credit",
        "debit",
        "pan",
        "visa",
        "mastercard",
        "amex",
        "payment",
        "pagamento",
        "cvv",
        "cvc",
        "expiry",
        "validade",
    ];
    CARD_WORDS.iter().any(|w| line.contains(w))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_and_private_ranges_are_not_identifying() {
        for ip in [
            "127.0.0.1",
            "0.0.0.0",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "192.0.2.5",
        ] {
            assert!(is_non_identifying_ip(ip), "{ip} should be filtered");
        }
    }

    #[test]
    fn routable_addresses_are_still_reported() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "172.15.0.1",
            "172.32.0.1",
            "203.0.114.1",
        ] {
            assert!(!is_non_identifying_ip(ip), "{ip} should survive");
        }
    }

    #[test]
    fn malformed_addresses_are_not_treated_as_private() {
        for ip in ["999.0.0.1", "1.2.3", "1.2.3.4.5", "a.b.c.d"] {
            assert!(!is_non_identifying_ip(ip));
        }
    }

    #[test]
    fn digits_adjacent_to_the_match_mark_a_longer_run() {
        let content = "9994532015112830366123";
        assert!(in_numeric_run(content, 4, 20));
    }

    #[test]
    fn a_standalone_card_number_is_not_a_numeric_run() {
        let content = "card = 4532015112830366;";
        assert!(!in_numeric_run(content, 7, 23));
    }

    #[test]
    fn svg_geometry_is_structured_numeric_data() {
        let line = "<path d=\"M4532015112830366 12 34 56\" />";
        assert!(is_structured_numeric_context(line, 12));
    }

    #[test]
    fn prose_is_not_structured_numeric_data() {
        let line = "the card number is 4532015112830366 for testing";
        assert!(!is_structured_numeric_context(line, 20));
    }

    #[test]
    fn documentation_placeholders_are_recognised() {
        assert!(is_placeholder_value("sk-your-key-here"));
        assert!(is_placeholder_value("sk-CHANGEME"));
        assert!(is_placeholder_value("sk-replace-with-real"));
        assert!(is_placeholder_value("sk-xxxxxxxxxxxx"));
        assert!(is_placeholder_value("sk-aaaaaaaaaaaa"));
        assert!(!is_placeholder_value("sk-9f2b7c1d4e8a3f6b0c5d2e9a"));
    }

    #[test]
    fn real_secrets_containing_placeholder_like_words_survive() {
        // A live password may legitimately contain these words. The filter
        // demotes rather than deletes, but a demotion still buries a finding,
        // so these must not match at all.
        for value in [
            "sampleCompany!2026",
            "fakeNewsAggregator99",
            "<actual-secret-here>",
            "MySampleP4ssw0rd",
            "dummy-but-real-2026",
        ] {
            assert!(
                !is_placeholder_value(value),
                "{value} must not be treated as a placeholder"
            );
        }
    }

    #[test]
    fn generated_paths_are_filtered_at_any_depth() {
        assert!(is_generated_path(Path::new("ui/node_modules/x/y.js")));
        assert!(is_generated_path(Path::new("a/b/target/debug/x.rs")));
        assert!(is_generated_path(Path::new("ui/dist/app.js")));
        assert!(is_generated_path(Path::new("docs/paper.fdb_latexmk")));
        assert!(is_generated_path(Path::new("app.min.js")));
        assert!(!is_generated_path(Path::new("src/main.rs")));
        assert!(!is_generated_path(Path::new("crates/sv-scan/src/lib.rs")));
    }

    #[test]
    fn short_sk_prefix_needs_supporting_context() {
        let bare = "let src-abc = 1;";
        let finding = ScanFinding {
            path: Path::new("a.rs").to_path_buf(),
            line: 1,
            start: 4,
            end: 11,
            kind: FindingKind::Secret {
                rule_id: "openai_api_key".to_string(),
            },
            confidence: Confidence::Medium,
            preview: "src-****".to_string(),
        };
        assert!(!plausible_openai_key(bare, &finding));

        let assigned = "api_key = sk-abc";
        let f2 = ScanFinding {
            start: 10,
            end: 16,
            ..finding
        };
        assert!(plausible_openai_key(assigned, &f2));
    }
}
