//! Trust defaults of ADR-0019 §5, as code.
//!
//! ## Measured basis
//!
//! The zero default is not an aesthetic choice. In the measured campaign
//! (71 real projects, 1,353 high-confidence and 7,009 medium-confidence
//! findings over 38,313 files scanned against 792,430 ignored), 1,002 of
//! the 1,027 `pii:credit_card` hits were Solidity build-artifact bytecode
//! passing the Luhn check by chance — a single decimal check digit
//! contributes about 3.3 bits, so roughly one arbitrary digit run in ten
//! passes. `pii:email` produced 6,215 hits, overwhelmingly documentation,
//! licenses, and CI metadata.
//!
//! **This is a measurement about one class.** It must not be generalized
//! into a false-positive rate for high-confidence findings as a whole. It
//! is the grounds for the default-selection rule below, not a precision
//! claim about the detectors.
//!
//! A later reader must not "optimize" [`default_selected`] into returning
//! `true` for high-confidence findings: preselection on confidence
//! manufactures consent at scale, and confidence is a detector signal,
//! never remediation eligibility.

use sv_privacy::PiiCategory;
use sv_scan::{FindingKind, ScanFinding};

/// The default selection state for a finding: **not selected**.
///
/// ADR-0019 §5: nothing is preselected — not even a high-confidence,
/// live-looking credential. The user arrives at an empty selection and
/// affirms each occurrence.
pub fn default_selected(_finding: &ScanFinding) -> bool {
    false
}

/// Whether a finding is in a class that must **never** be default-selected,
/// even if a future convenience feature reintroduces preselection for some
/// other class.
///
/// The classes and their reasons:
///
/// - `pii:email` — 6,215 measured hits, overwhelmingly docs, licenses, and
///   CI metadata;
/// - numeric PII (CPF, CNPJ, credit card, phone, SSN, IPv4) — dominated by
///   incidental digit runs and machine-role addresses;
/// - jurisdiction matches — national identifiers are numeric PII;
/// - generated-artifact paths (`out/`, `dist/`, `target/`, `build/`,
///   `node_modules/`);
/// - test fixtures (`*.test.*`, `.env.example`, `.env.fake`);
/// - by-prefix test credentials (rule ids like `stripe_test_key`).
pub fn is_never_default(finding: &ScanFinding) -> bool {
    if path_is_generated_artifact(&finding.path) || path_is_test_fixture(&finding.path) {
        return true;
    }
    match &finding.kind {
        FindingKind::Pii(category) => pii_is_never_default(*category),
        // National identifiers are numeric PII in structure, and validated
        // jurisdiction matches are exactly the "live-looking" hits the
        // zero default exists for.
        FindingKind::Jurisdiction { .. } => true,
        FindingKind::Secret { rule_id } => test_credential_rule(rule_id),
    }
}

fn pii_is_never_default(category: PiiCategory) -> bool {
    matches!(
        category,
        PiiCategory::Email
            | PiiCategory::Cpf
            | PiiCategory::Cnpj
            | PiiCategory::CreditCard
            | PiiCategory::Phone
            | PiiCategory::Ssn
            | PiiCategory::Ipv4
    )
}

fn test_credential_rule(rule_id: &str) -> bool {
    // `stripe_test_key` and friends: the rule id itself says the credential
    // is a test fixture. A live-looking prefix is not consulted here on
    // purpose — `sk_live_` and `sk_test_` differ by one character, and a
    // rule-id heuristic must err toward never-selecting.
    rule_id.contains("_test_") || rule_id.starts_with("test_")
}

fn path_is_generated_artifact(path: &std::path::Path) -> bool {
    path.to_string_lossy()
        .to_lowercase()
        .split(['/', '\\'])
        .any(|component| {
            matches!(
                component,
                "out" | "dist" | "target" | "build" | "node_modules"
            )
        })
}

fn path_is_test_fixture(path: &std::path::Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let name = name.to_lowercase();
    name == ".env.example" || name == ".env.fake" || name.contains(".test.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use sv_scan::Confidence;

    fn finding(path: &str, kind: FindingKind) -> ScanFinding {
        ScanFinding {
            path: PathBuf::from(path),
            line: 1,
            start: 0,
            end: 8,
            kind,
            confidence: Confidence::High,
            preview: "********".to_string(),
            matched_fingerprint: String::new(),
        }
    }

    fn secret(rule_id: &str) -> FindingKind {
        FindingKind::Secret {
            rule_id: rule_id.to_string(),
        }
    }

    /// ADR-0019 §5: the default is zero, even for a high-confidence,
    /// live-looking credential in a plausible location.
    #[test]
    fn default_selection_is_zero_even_for_live_looking_credentials() {
        let live = finding("config/app.toml", secret("aws_access_key_id"));
        assert!(!default_selected(&live));
        // Not being preselected is universal; the never-list is narrower.
        assert!(!is_never_default(&live));
    }

    #[test]
    fn never_default_classes_are_rejected_by_kind_and_path() {
        // pii:email, wherever it is.
        let email = finding("docs/contact.md", FindingKind::Pii(PiiCategory::Email));
        assert!(is_never_default(&email));

        // Numeric PII.
        let card = finding("data.csv", FindingKind::Pii(PiiCategory::CreditCard));
        assert!(is_never_default(&card));

        // By-prefix test credentials.
        let test_key = finding("config/app.toml", secret("stripe_test_key"));
        assert!(is_never_default(&test_key));

        // Generated-artifact paths: any component matches.
        let artifact = finding("node_modules/left-pad/index.js", secret("npm_token"));
        assert!(is_never_default(&artifact));
        let build_out = finding("target/debug/build/out.txt", secret("github_pat"));
        assert!(is_never_default(&build_out));

        // Test fixtures by file name.
        let example = finding(".env.example", secret("aws_access_key_id"));
        assert!(is_never_default(&example));
        let fake = finding(".env.fake", secret("aws_access_key_id"));
        assert!(is_never_default(&fake));
        let test_file = finding("src/app.test.ts", secret("github_pat"));
        assert!(is_never_default(&test_file));

        // Jurisdiction matches are numeric PII in structure.
        let jurisdiction = finding(
            "dados/clientes.csv",
            FindingKind::Jurisdiction {
                pack_id: "br-lgpd".to_string(),
                pack_version: "0.1.0".to_string(),
                rule_id: "br-lgpd/cpf".to_string(),
                validated: Some(true),
            },
        );
        assert!(is_never_default(&jurisdiction));
    }
}
