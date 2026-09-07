//! `sovereign-vault scan` — read-only discovery over a project tree.
//!
//! The scan itself never writes to the scanned tree (ADR-0017): it reports what
//! sensitive material exists and where. Storing the report *in the vault* is
//! what makes the result usable by an agent: a report written to a container is
//! reachable through the existing `vault.list`/`vault.read` MCP tools, and is
//! therefore gated by that container's security mode. Putting reports in an
//! `APPROVAL` container means an agent asking to read one raises a desktop
//! prompt — the human-in-the-loop path, with no new consent machinery.
//!
//! Reports never contain secret values. Every finding carries a masked preview
//! only, so the report is safe to store, list, and show to a model.

use std::path::Path;

use sv_scan::{Confidence, FindingKind, ScanConfig, ScanReport};

/// Container that scan reports are written to by default.
///
/// `APPROVAL` mode is the point: reading a report through MCP raises a human
/// prompt.
pub const DEFAULT_REPORT_CONTAINER: &str = "scan-reports";

/// Render a report as human-readable text for the terminal.
pub fn render_text(report: &ScanReport, root: &Path, elapsed: std::time::Duration) -> String {
    let mut out = String::new();
    out.push_str(&format!("Sovereign Vault scan — {}\n", root.display()));
    out.push_str(&format!(
        "  scanned {} files ({} bytes) in {:.2}s\n",
        report.coverage.files_scanned,
        report.coverage.bytes_scanned,
        elapsed.as_secs_f64()
    ));
    out.push_str(&format!(
        "  not examined: {} unreadable, {} excluded by ignore rules\n",
        report.coverage.files_skipped, report.coverage.files_ignored
    ));
    if report.coverage.total_suppressed() > 0 {
        out.push_str(&format!(
            "  context filters: {} demoted, {} removed\n",
            report.coverage.total_demoted(),
            report.coverage.total_removed()
        ));
    }
    out.push('\n');

    if report.findings.is_empty() {
        out.push_str("No findings.\n");
    } else {
        let (high, medium, low) = confidence_split(report);
        out.push_str(&format!(
            "{} findings: {} high, {} medium, {} low\n\n",
            report.findings.len(),
            high,
            medium,
            low
        ));

        for (label, count) in counts_by_class(report) {
            out.push_str(&format!("  {count:>6}  {label}\n"));
        }
        out.push('\n');

        out.push_str("Highest-confidence findings:\n");
        let mut shown = 0usize;
        for finding in report
            .findings
            .iter()
            .filter(|f| f.confidence == Confidence::High)
            .take(40)
        {
            out.push_str(&format!(
                "  {}:{}  {}  {}\n",
                finding.path.display(),
                finding.line,
                class_label(&finding.kind),
                finding.preview
            ));
            shown += 1;
        }
        if shown == 0 {
            out.push_str("  (none at high confidence)\n");
        }
    }

    out.push_str("\nThis report lists what the deterministic detectors matched. ");
    out.push_str("Detector recall is bounded, so an empty or short report is\n");
    out.push_str("evidence of what was found, never proof that a project holds no secrets.\n");
    out
}

/// Findings grouped by class, in descending count order.
fn counts_by_class(report: &ScanReport) -> Vec<(String, usize)> {
    let mut map: std::collections::BTreeMap<String, usize> = Default::default();
    for finding in &report.findings {
        *map.entry(class_label(&finding.kind)).or_insert(0) += 1;
    }
    let mut out: Vec<(String, usize)> = map.into_iter().collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    out
}

/// Stable display label for a finding class.
///
/// A jurisdiction label names the rule that fired and whether its checksum
/// passed — evidence the reader can judge. It never asserts that a legal regime
/// applies to the value (ADR-0018 §6).
fn class_label(kind: &FindingKind) -> String {
    match kind {
        FindingKind::Secret { rule_id } => format!("secret:{rule_id}"),
        FindingKind::Pii(category) => format!("pii:{}", category.label().to_ascii_lowercase()),
        FindingKind::Jurisdiction {
            rule_id, validated, ..
        } => match validated {
            Some(true) => format!("id:{rule_id} (checksum passed)"),
            Some(false) => format!("id:{rule_id} (checksum failed)"),
            None => format!("id:{rule_id}"),
        },
    }
}

/// Counts of high, medium, and low confidence findings.
fn confidence_split(report: &ScanReport) -> (usize, usize, usize) {
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    for finding in &report.findings {
        match finding.confidence {
            Confidence::High => high += 1,
            Confidence::Medium => medium += 1,
            Confidence::Low => low += 1,
        }
    }
    (high, medium, low)
}

/// Build the JSON document stored in the vault and emitted by `--json`.
///
/// Carries the report plus the provenance a reader needs to judge it: what was
/// scanned, when, and with which scanner version.
pub fn report_document(report: &ScanReport, root: &Path) -> serde_json::Value {
    serde_json::json!({
        "schema": "sovereign-vault.scan-report.v1",
        "scanner_version": sv_scan::version(),
        "scanned_at": chrono_now(),
        "root": root.display().to_string(),
        "coverage": {
            "files_scanned": report.coverage.files_scanned,
            "files_skipped": report.coverage.files_skipped,
            "files_ignored": report.coverage.files_ignored,
            "bytes_scanned": report.coverage.bytes_scanned,
            "suppressed_demoted": report.coverage.total_demoted(),
            "suppressed_removed": report.coverage.total_removed(),
            "suppressed_by_reason": report.coverage.suppressed.iter().map(|s| {
                serde_json::json!({ "reason": s.reason.label(), "count": s.count })
            }).collect::<Vec<_>>(),
            "skipped": report.coverage.skipped.iter().map(|s| {
                serde_json::json!({
                    "path": s.path.display().to_string(),
                    "reason": format!("{:?}", s.reason).to_ascii_lowercase(),
                })
            }).collect::<Vec<_>>(),
        },
        "findings": report.findings.iter().map(|f| {
            serde_json::json!({
                "path": f.path.display().to_string(),
                "line": f.line,
                "start": f.start,
                "end": f.end,
                "class": class_label(&f.kind),
                "confidence": format!("{:?}", f.confidence).to_ascii_lowercase(),
                // Masked preview only. The matched value is never stored.
                "preview": f.preview,
                // Provenance for pack-derived findings, so a reader can trace a
                // match to the exact rule and pack version that produced it.
                "source": match &f.kind {
                    FindingKind::Jurisdiction { pack_id, pack_version, rule_id, validated } =>
                        serde_json::json!({
                            "kind": "jurisdiction_pack",
                            "pack_id": pack_id,
                            "pack_version": pack_version,
                            "rule_id": rule_id,
                            "checksum_validated": validated,
                        }),
                    FindingKind::Secret { rule_id } =>
                        serde_json::json!({ "kind": "secret_rule", "rule_id": rule_id }),
                    FindingKind::Pii(_) =>
                        serde_json::json!({ "kind": "baseline_pii" }),
                },
            })
        }).collect::<Vec<_>>(),
        "limits": [
            "Detector recall is bounded; absence of a finding is not proof of absence.",
            "Values are masked: this report never contains a secret.",
            "Files excluded by ignore rules were not examined (see files_ignored).",
            "A jurisdiction rule reports structural evidence only. A passing checksum \
             means a value is well-formed for its identifier type; it does not establish \
             authenticity, ownership, sensitivity, or that any data-protection regime applies.",
            "Redaction is not performed: this report describes the working tree and does \
             not alter it, nor does it affect Git history or existing backups.",
        ],
    })
}

/// Current UTC timestamp, RFC 3339.
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Minimal RFC-3339 rendering without pulling a new dependency into the CLI.
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's `civil_from_days`: days since the Unix epoch to y/m/d.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Name for the stored report file, unique per scan.
pub fn report_file_name(root: &Path) -> String {
    let slug: String = root
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".to_string())
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let stamp = chrono_now().replace([':', '-'], "").replace('T', "-");
    format!("{slug}-{stamp}.json")
}

/// Build the scanner configuration for one invocation.
pub fn build_config(max_file_bytes: u64, no_gitignore: bool, packs: Vec<String>) -> ScanConfig {
    ScanConfig {
        max_file_bytes,
        respect_gitignore: !no_gitignore,
        packs,
        ..ScanConfig::default()
    }
}

/// List the bundled jurisdiction packs.
pub fn render_pack_list() -> String {
    let mut out = String::from("Bundled jurisdiction packs:\n\n");
    for id in ["br-lgpd", "eu-gdpr", "us"] {
        match sv_patterns::load_builtin(id) {
            Ok(pack) => {
                out.push_str(&format!(
                    "  {:<10} v{:<8} {} [{}]\n",
                    pack.id,
                    pack.version,
                    pack.name,
                    pack.jurisdictions.join(", ")
                ));
                for rule in &pack.rules {
                    out.push_str(&format!("      {:<24} {}\n", rule.name, rule.description));
                }
                if !pack.regulatory_references.is_empty() {
                    out.push_str(&format!(
                        "      references: {}\n",
                        pack.regulatory_references.join(", ")
                    ));
                }
                out.push('\n');
            }
            Err(e) => out.push_str(&format!("  {id}: failed to load: {e}\n")),
        }
    }
    out.push_str(
        "Enable with --pack <id>, repeatable. A local pack may be given as a TOML path.\n",
    );
    out.push_str("Packs only ever ADD rules; they can never disable baseline detection.\n");
    out.push_str(
        "A match reports structural evidence, not a determination that any law applies.\n",
    );
    out
}

/// Drop findings below the requested confidence floor.
pub fn apply_min_confidence(mut report: ScanReport, min: Option<Confidence>) -> ScanReport {
    if let Some(min) = min {
        report.findings.retain(|f| f.confidence >= min);
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn civil_from_days_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
    }

    #[test]
    fn report_file_name_is_filesystem_safe() {
        let name = report_file_name(Path::new("/home/user/my project!"));
        assert!(!name.contains(' '));
        assert!(!name.contains('!'));
        assert!(name.ends_with(".json"));
    }

    #[test]
    fn min_confidence_filters_lower_findings() {
        let report = ScanReport {
            findings: vec![
                finding(Confidence::Low),
                finding(Confidence::Medium),
                finding(Confidence::High),
            ],
            coverage: Default::default(),
        };
        let filtered = apply_min_confidence(report, Some(Confidence::Medium));
        assert_eq!(filtered.findings.len(), 2);
    }

    fn finding(confidence: Confidence) -> sv_scan::ScanFinding {
        sv_scan::ScanFinding {
            path: PathBuf::from("a.rs"),
            line: 1,
            start: 0,
            end: 4,
            kind: FindingKind::Secret {
                rule_id: "test".to_string(),
            },
            confidence,
            preview: "****".to_string(),
        }
    }
}
