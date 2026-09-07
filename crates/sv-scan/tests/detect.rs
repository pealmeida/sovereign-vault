//! Integration tests for the `sv-scan` secret and PII detectors.
//!
//! Every fixture is assembled at runtime by concatenating prefix and body
//! pieces, so this file never contains a complete example credential that a
//! secret scanner would flag in CI.

use std::path::Path;

use sv_scan::{detect_pii, detect_secrets, mask, scan_project, FindingKind, ScanConfig};

/// A path used for in-memory (no filesystem) detector calls.
const TOML: &str = "config.toml";

/// Build a synthetic fixed-length token: prefix + enough repeated body chars
/// that the total length is exactly `exact_len`. The body is chosen to satisfy
/// the rule's alphabet for the common alphanumeric cases.
fn fixed(prefix: &str, exact_len: usize, body: &str) -> String {
    let body_len = exact_len - prefix.len();
    let mut s = String::with_capacity(exact_len);
    s.push_str(prefix);
    while s.len() < prefix.len() + body_len {
        s.push_str(body);
    }
    s.truncate(exact_len);
    s
}

// ---- 1. Each High-confidence rule matches a synthetic positive example ----

#[test]
fn aws_access_key_id_matches() {
    let token = fixed("AKIA", 20, "IOSFODNN7EXAMPLE");
    let findings = detect_secrets(&format!("key = {token}"), Path::new(TOML));
    assert!(
        findings.iter().any(|f| matches!(
            &f.kind,
            FindingKind::Secret { rule_id } if rule_id == "aws_access_key_id"
        )),
        "expected aws match, got {:?}",
        findings
    );
}

#[test]
fn github_pat_matches() {
    let token = fixed("ghp_", 40, "aB3dEfGhIjKlMnOp");
    let findings = detect_secrets(&token, Path::new(TOML));
    assert!(findings.iter().any(|f| matches!(
        &f.kind,
        FindingKind::Secret { rule_id } if rule_id == "github_pat"
    )));
}

#[test]
fn github_oauth_matches() {
    let token = fixed("gho_", 40, "aB3dEfGhIjKlMnOp");
    let findings = detect_secrets(&token, Path::new(TOML));
    assert!(findings.iter().any(|f| matches!(
        &f.kind,
        FindingKind::Secret { rule_id } if rule_id == "github_oauth"
    )));
}

#[test]
fn github_fine_grained_pat_matches() {
    let body = concat!(
        "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXx",
        "0123456789yzAaBbCcDdEeFfGgHhIiJjK"
    );
    let token = format!("github_pat_{body}");
    assert!(
        token.len() >= 82 && token.len() <= 100,
        "len {}",
        token.len()
    );
    let findings = detect_secrets(&token, Path::new(TOML));
    assert!(findings.iter().any(|f| matches!(
        &f.kind,
        FindingKind::Secret { rule_id } if rule_id == "github_fine_grained_pat"
    )));
}

#[test]
fn slack_bot_token_matches() {
    let token = format!("xoxb-{}", "1234567890".repeat(3));
    let findings = detect_secrets(&token, Path::new(TOML));
    assert!(findings.iter().any(|f| matches!(
        &f.kind,
        FindingKind::Secret { rule_id } if rule_id == "slack_bot_token"
    )));
}

#[test]
fn slack_user_token_matches() {
    let token = format!("xoxp-{}", "1234567890".repeat(3));
    let findings = detect_secrets(&token, Path::new(TOML));
    assert!(findings.iter().any(|f| matches!(
        &f.kind,
        FindingKind::Secret { rule_id } if rule_id == "slack_user_token"
    )));
}

#[test]
fn stripe_secret_key_matches() {
    let token = format!("sk_live_{}", "4eC39HqLyjWDarjtT1zdp7dc");
    let findings = detect_secrets(&token, Path::new(TOML));
    assert!(findings.iter().any(|f| matches!(
        &f.kind,
        FindingKind::Secret { rule_id } if rule_id == "stripe_secret_key"
    )));
}

#[test]
fn anthropic_api_key_matches() {
    let token = format!("sk-ant-{}", "aB3dEfGhIjKlMnOpQrStUvWxYz01");
    let findings = detect_secrets(&token, Path::new(TOML));
    assert!(findings.iter().any(|f| matches!(
        &f.kind,
        FindingKind::Secret { rule_id } if rule_id == "anthropic_api_key"
    )));
}

#[test]
fn google_api_key_matches() {
    let token = fixed("AIza", 39, "aB3dEfGhIjKlMnOp_");
    let findings = detect_secrets(&token, Path::new(TOML));
    assert!(findings.iter().any(|f| matches!(
        &f.kind,
        FindingKind::Secret { rule_id } if rule_id == "google_api_key"
    )));
}

#[test]
fn npm_token_matches() {
    let token = fixed("npm_", 40, "aB3dEfGhIjKlMnOp");
    let findings = detect_secrets(&token, Path::new(TOML));
    assert!(findings.iter().any(|f| matches!(
        &f.kind,
        FindingKind::Secret { rule_id } if rule_id == "npm_token"
    )));
}

#[test]
fn private_key_pem_matches_header_line_only() {
    // Assembled at runtime from fragments so the literal PEM header never
    // appears in the source. It is only a header line and a nonsense body, but
    // a repository-wide secret scanner cannot tell that from a real key, and a
    // fixture that trips CI on every run trains people to ignore CI.
    let begin = format!("-----BEGIN RSA {} KEY-----", "PRIVATE");
    let end = format!("-----END RSA {} KEY-----", "PRIVATE");
    let content = format!("{begin}\nMIIblahbase64\n{end}");
    let body = begin;
    let findings = detect_secrets(&content, Path::new(TOML));
    let pem = findings
        .iter()
        .find(
            |f| matches!(&f.kind, FindingKind::Secret { rule_id } if rule_id == "private_key_pem"),
        )
        .expect("expected a PEM header finding");
    // The span covers only the header line, not the key body.
    let span = &content[pem.start..pem.end];
    assert_eq!(span, body);
}

// ---- 2. A prefix with the WRONG length does not match ----------------------

#[test]
fn wrong_length_does_not_match() {
    let token = format!("{}{}", "AKIA", "ABCDEFGHIJ"); // 14 bytes, not 20
    let findings = detect_secrets(&token, Path::new(TOML));
    assert!(
        findings.is_empty(),
        "wrong length must not match, got {:?}",
        findings
    );
}

// ---- 3. A prefix with an out-of-alphabet body does not match ----------------

#[test]
fn out_of_alphabet_body_does_not_match() {
    // lowercase letters are not in AWS's UpperAlnum alphabet.
    let token = format!("{}{}", "AKIA", "abcdefghijklmnop");
    let findings = detect_secrets(&token, Path::new(TOML));
    assert!(
        findings.is_empty(),
        "out-of-alphabet body must not match, got {:?}",
        findings
    );
}

// ---- 4. mask() ------------------------------------------------------------

#[test]
fn mask_hides_long_values_and_length() {
    let value = fixed("AKIA", 20, "IOSFODNN7EXAMPLE");
    let m = mask(&value);
    assert_ne!(m, value, "mask must not return the raw value");
    assert_eq!(m.len(), 12, "fixed mask length must not reveal true length");
    assert_eq!(m, format!("{}{}", &value[..4], "********"));
}

#[test]
fn mask_masks_short_values_entirely() {
    assert_eq!(mask("abcd"), "********");
    assert_eq!(mask("ab"), "********");
    assert_eq!(mask(""), "********");
}

// ---- 5. preview is never the raw matched value -----------------------------

#[test]
fn preview_is_never_the_raw_value() {
    let token = fixed("AKIA", 20, "IOSFODNN7EXAMPLE");
    let content = format!("aws = {token}");
    let findings = detect_secrets(&content, Path::new(TOML));
    assert!(!findings.is_empty());
    for f in &findings {
        assert_ne!(f.preview, token, "preview must be masked, not raw");
    }
}

// ---- 6. Keyword proximity promotes confidence -------------------------------

#[test]
fn keyword_proximity_promotes_confidence() {
    // stripe_test_key is Medium; `api_key = ` before it should raise it one step.
    let token = format!("sk_test_{}", "4eC39HqLyjWDarjtT1zdp7dc");
    let bare = detect_secrets(&token, Path::new(TOML));
    let with_kw = detect_secrets(&format!("api_key = {token}"), Path::new(TOML));

    let conf = |v: &[sv_scan::ScanFinding]| {
        v.iter()
            .find(|f| matches!(&f.kind, FindingKind::Secret { rule_id } if rule_id == "stripe_test_key"))
            .map(|f| f.confidence)
            .expect("expected a stripe_test_key finding")
    };
    let bare_conf = conf(&bare);
    let kw_conf = conf(&with_kw);
    assert!(
        kw_conf > bare_conf,
        "{kw_conf:?} should exceed {bare_conf:?}"
    );
}

// ---- 7. Entropy alone never creates a finding -------------------------------

#[test]
fn entropy_alone_never_creates_a_finding() {
    // A long, high-entropy alphanumeric string with no rule prefix matches
    // nothing: entropy is supporting evidence only, never a finding on its own.
    let blob = "aB3dEfGhIjKlMnOp".repeat(8);
    let findings = detect_secrets(&blob, Path::new(TOML));
    assert!(
        findings.is_empty(),
        "entropy alone must not create a finding, got {:?}",
        findings
    );
}

// ---- 8. Idempotency: redacted markers are not re-flagged -------------------

#[test]
fn redacted_markers_produce_no_findings() {
    let content = "[REDACTED:EMAIL] and [SV:LOC:v1:abc]";
    let findings = detect_secrets(content, Path::new(TOML));
    assert!(
        findings.is_empty(),
        "redacted markers must not be flagged, got {:?}",
        findings
    );
}

#[test]
fn secret_inside_redacted_marker_is_not_flagged() {
    // The same key flagged bare is silently inside a durable locator line.
    let token = fixed("AKIA", 20, "IOSFODNN7EXAMPLE");
    let bare = detect_secrets(&token, Path::new(TOML));
    assert!(!bare.is_empty(), "bare token should be flagged");

    let inside = format!("[SV:LOC:v1:{token}]");
    let flagged = detect_secrets(&inside, Path::new(TOML));
    assert!(
        flagged.is_empty(),
        "secret inside locator must not be re-flagged, got {:?}",
        flagged
    );
}

// ---- 9. PII delegation --------------------------------------------------------

#[test]
fn pii_delegation_finds_email_with_correct_offsets() {
    let content = "contact me at jane.doe+spam@example.co.uk please";
    let policy = sv_privacy::Policy::all();
    let findings = detect_pii(content, Path::new(TOML), &policy);
    let email = findings
        .iter()
        .find(|f| matches!(f.kind, FindingKind::Pii(sv_privacy::PiiCategory::Email)))
        .expect("expected an email finding");
    assert_eq!(
        &content[email.start..email.end],
        "jane.doe+spam@example.co.uk"
    );
    assert_eq!(email.line, 1);
    assert_eq!(email.path, Path::new(TOML));
}

// ---- 10. Multi-byte UTF-8 safety ---------------------------------------------

#[test]
fn multibyte_utf8_does_not_panic_and_offsets_are_bytes() {
    let token = fixed("AKIA", 20, "IOSFODNN7EXAMPLE");
    let content = format!("café — clé: {token} e fim ✓");
    let findings = detect_secrets(&content, Path::new(TOML));
    assert!(!findings.is_empty());
    for f in &findings {
        // Byte offsets must slice valid UTF-8 without panicking.
        let raw = &content[f.start..f.end];
        assert_ne!(f.preview, raw, "preview must be masked");
    }
}

#[test]
fn line_number_counts_by_newlines() {
    let token = fixed("AKIA", 20, "IOSFODNN7EXAMPLE");
    let content = format!("first line\nsecond line with {token}\nthird");
    let findings = detect_secrets(&content, Path::new(TOML));
    let f = findings
        .iter()
        .find(|f| matches!(&f.kind, FindingKind::Secret { rule_id } if rule_id == "aws_access_key_id"))
        .expect("expected aws finding");
    // The token is on the second line (`first line\nsecond line with …`).
    assert_eq!(f.line, 2);
}

// ---- 11. Findings are ordered deterministically -----------------------------

#[test]
fn findings_are_ordered_by_start_offset_and_repeatable() {
    let token = fixed("AKIA", 20, "IOSFODNN7EXAMPLE");
    let content = format!("a {token} b {token}");
    let first = detect_secrets(&content, Path::new(TOML));
    let second = detect_secrets(&content, Path::new(TOML));
    assert_eq!(first, second, "detection must be repeatable");
    assert!(first.windows(2).all(|w| w[0].start <= w[1].start));
    assert_eq!(first.len(), 2);
    assert!(first[0].start < first[1].start);
}

// ---- 12. Overlap dedup keeps the higher-confidence rule ----------------------

#[test]
fn overlap_dedup_keeps_higher_confidence_rule() {
    // "sk-ant-" is a prefix of "sk-" rules; anthropic is High, openai is Medium.
    // The Anthropic token also satisfies the raw "sk-" prefix range, so both
    // would match overlapping spans; the High (anthropic) finding must win.
    let token = format!("sk-ant-{}", "aB3dEfGhIjKlMnOpQrStUvWxYz01");
    let findings = detect_secrets(&token, Path::new(TOML));
    let kinds: Vec<&str> = findings
        .iter()
        .filter_map(|f| match &f.kind {
            FindingKind::Secret { rule_id } => Some(rule_id.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        kinds.contains(&"anthropic_api_key"),
        "anthropic should be kept"
    );
    assert!(
        !kinds.contains(&"openai_api_key"),
        "overlapping lower-confidence rule must be dropped, got {:?}",
        kinds
    );
}

// ---- Orchestration seam (scan_project) -------------------------------------

#[test]
fn scan_project_scans_files_and_sorts_findings_by_path_then_start() {
    let root = tempfile::tempdir().unwrap();
    let aws = fixed("AKIA", 20, "IOSFODNN7EXAMPLE");
    std::fs::write(root.path().join("b.txt"), format!("other {aws}")).unwrap();
    std::fs::write(root.path().join("a.txt"), format!("aws = {aws}")).unwrap();
    std::fs::write(
        root.path().join("c.txt"),
        "contact me at jane.doe@example.com\n",
    )
    .unwrap();

    let report = scan_project(root.path(), &ScanConfig::default()).unwrap();
    assert_eq!(report.coverage.files_scanned, 3);
    assert!(!report.findings.is_empty());

    // Sorted by (path, start).
    let keys: Vec<(&Path, usize)> = report
        .findings
        .iter()
        .map(|f| (f.path.as_path(), f.start))
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "findings must be sorted by (path, start)");

    // Paths are relative to the scan root, and previews are masked.
    for f in &report.findings {
        assert!(
            f.path.is_relative(),
            "{} must be relative",
            f.path.display()
        );
        if matches!(f.kind, FindingKind::Secret { .. }) {
            assert_ne!(f.preview, aws, "preview must be masked, not the raw value");
            assert!(f.preview.ends_with("********"));
        }
    }
}

#[test]
fn scan_project_on_missing_root_returns_invalid_root() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("nope");
    assert!(matches!(
        scan_project(&missing, &ScanConfig::default()),
        Err(sv_scan::ScanError::InvalidRoot)
    ));
}
