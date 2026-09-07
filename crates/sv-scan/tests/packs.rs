//! Integration tests for jurisdiction pattern packs inside `sv-scan`.
//!
//! The invariant under test is the one ADR-0018 exists to protect: a pack can
//! only ever *add* detection. No pack, however malformed or malicious, may
//! reduce what the baseline detectors find.

use std::fs;
use std::path::Path;

use sv_scan::{scan_project, Confidence, FindingKind, ScanConfig};

fn write(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

/// A file holding one baseline finding the detectors must always report.
fn fixture(root: &Path) {
    write(
        root,
        "app.rs",
        // Split so this test file is not itself flagged by a secret scanner.
        &format!(
            "let key = \"{}{}\";\nlet contact = \"person@example.org\";\n",
            "AKIA", "IOSFODNN7EXAMPLE"
        ),
    );
}

#[test]
fn baseline_detection_is_identical_with_and_without_packs() {
    // The load-bearing guarantee: enabling a pack never removes a baseline
    // finding. A pack that silently reduced detection would be the worst
    // possible failure, because the user would believe they had *increased*
    // their coverage.
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());

    let without = scan_project(root.path(), &ScanConfig::default()).unwrap();

    let with = scan_project(
        root.path(),
        &ScanConfig {
            packs: vec![
                "br-lgpd".to_string(),
                "eu-gdpr".to_string(),
                "us".to_string(),
            ],
            ..ScanConfig::default()
        },
    )
    .unwrap();

    let baseline = |report: &sv_scan::ScanReport| -> Vec<(String, usize)> {
        report
            .findings
            .iter()
            .filter(|f| !matches!(f.kind, FindingKind::Jurisdiction { .. }))
            .map(|f| (format!("{:?}", f.kind), f.start))
            .collect()
    };

    assert_eq!(
        baseline(&without),
        baseline(&with),
        "enabling packs must not change baseline findings"
    );
    assert!(
        !baseline(&with).is_empty(),
        "fixture should produce baseline findings"
    );
}

#[test]
fn packs_are_off_by_default() {
    let root = tempfile::tempdir().unwrap();
    // A checksum-valid CPF, which the br-lgpd pack would match.
    write(root.path(), "data.txt", "id 111.444.777-35\n");

    let report = scan_project(root.path(), &ScanConfig::default()).unwrap();
    assert!(
        !report
            .findings
            .iter()
            .any(|f| matches!(f.kind, FindingKind::Jurisdiction { .. })),
        "no jurisdiction findings should appear without an explicit opt-in"
    );
}

#[test]
fn an_enabled_pack_adds_findings_with_full_provenance() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "data.txt", "id 111.444.777-35\n");

    let report = scan_project(
        root.path(),
        &ScanConfig {
            packs: vec!["br-lgpd".to_string()],
            ..ScanConfig::default()
        },
    )
    .unwrap();

    let found = report
        .findings
        .iter()
        .find_map(|f| match &f.kind {
            FindingKind::Jurisdiction {
                pack_id,
                pack_version,
                rule_id,
                validated,
            } => Some((pack_id, pack_version, rule_id, validated)),
            _ => None,
        })
        .expect("br-lgpd should match a checksum-valid CPF");

    assert_eq!(found.0, "br-lgpd");
    assert!(!found.1.is_empty(), "pack version must be recorded");
    assert!(
        found.2.starts_with("br-lgpd/"),
        "rule ids are namespaced by pack: {}",
        found.2
    );
    assert_eq!(
        *found.3,
        Some(true),
        "a valid CPF should record a passing checksum"
    );
}

#[test]
fn an_unknown_pack_is_a_hard_error_not_a_silent_downgrade() {
    // Continuing without a requested pack would produce a report that looks
    // clean because rules were missing.
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());

    let err = scan_project(
        root.path(),
        &ScanConfig {
            packs: vec!["no-such-pack".to_string()],
            ..ScanConfig::default()
        },
    )
    .unwrap_err();

    assert!(
        matches!(err, sv_scan::ScanError::Pack(_)),
        "expected a pack error, got {err:?}"
    );
}

#[test]
fn pack_findings_are_masked_like_every_other_finding() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "data.txt", "id 111.444.777-35\n");

    let report = scan_project(
        root.path(),
        &ScanConfig {
            packs: vec!["br-lgpd".to_string()],
            ..ScanConfig::default()
        },
    )
    .unwrap();

    for finding in &report.findings {
        assert!(
            !finding.preview.contains("444.777"),
            "preview must never reproduce the matched value: {}",
            finding.preview
        );
    }
}

#[test]
fn long_identifiers_survive_the_card_length_ceiling() {
    // Regression: the credit-card filter drops any run of more than 19 digits,
    // because no card is longer. Reusing that ceiling for pack findings
    // silently deleted every valid IBAN (20 digits for a German account) —
    // a filter bug that removed a correct, checksum-validated finding.
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "bank.txt", "iban DE89370400440532013000 end\n");

    let report = scan_project(
        root.path(),
        &ScanConfig {
            packs: vec!["eu-gdpr".to_string()],
            ..ScanConfig::default()
        },
    )
    .unwrap();

    assert!(
        report.findings.iter().any(|f| matches!(
            &f.kind,
            FindingKind::Jurisdiction { rule_id, validated, .. }
                if rule_id.ends_with("/iban") && *validated == Some(true)
        )),
        "a checksum-valid IBAN must be reported, got {:?}",
        report.findings
    );
}

#[test]
fn pack_findings_pass_through_the_context_filters() {
    // National identifiers are digit runs guarded by short checksums, so they
    // inherit the geometry false-positive problem that produced 709 bogus card
    // matches in a real project. Vector artwork must not yield high-confidence
    // identity claims.
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        "logo.xml",
        "<vector xmlns:android=\"http://schemas.android.com/apk/res/android\">\n\
         <path android:pathData=\"M 111.444 777.35 L 111.444 777.35 C 529.982 123.456\" />\n\
         </vector>\n",
    );

    let report = scan_project(
        root.path(),
        &ScanConfig {
            packs: vec!["br-lgpd".to_string()],
            ..ScanConfig::default()
        },
    )
    .unwrap();

    assert!(
        report
            .findings
            .iter()
            .all(|f| f.confidence != Confidence::High),
        "vector geometry must not produce high-confidence identity findings"
    );
}
