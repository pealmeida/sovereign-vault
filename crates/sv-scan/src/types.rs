//! Shared data types for the project scanner.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// What kind of sensitive material a finding represents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// Personally-identifiable information, detected by `sv-privacy`.
    Pii(sv_privacy::PiiCategory),
    /// A credential or key matched by a named secret rule.
    Secret {
        /// Stable identifier of the rule that matched, e.g. `aws_access_key_id`.
        rule_id: String,
    },
    /// A national identifier matched by an opt-in jurisdiction pattern pack.
    ///
    /// This records *structural* evidence and nothing more. A passing checksum
    /// establishes that a value is well-formed for its identifier type; it
    /// establishes neither authenticity, ownership, sensitivity, nor that any
    /// legal regime applies. Per ADR-0018 the report states what matched, never
    /// a legal conclusion about it.
    Jurisdiction {
        /// Pack that produced the match, e.g. `br-lgpd`.
        pack_id: String,
        /// Version of that pack, so a finding can be traced to exact rules.
        pack_version: String,
        /// Full rule id, `<pack id>/<rule name>`.
        rule_id: String,
        /// Whether a checksum validator ran and passed. `None` when the rule
        /// has no validator and the pattern alone decided.
        validated: Option<bool>,
    },
}

/// Confidence that a candidate is a true finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Weak signal; likely requires human review.
    Low,
    /// Plausible match with some corroboration.
    Medium,
    /// Near-certain match (e.g. checksum-validated).
    High,
}

/// One located piece of sensitive material. Never carries the matched value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanFinding {
    /// Path of the file, relative to the scan root.
    pub path: PathBuf,
    /// 1-indexed line number where the match starts.
    pub line: u32,
    /// Byte offset of the first matched byte, relative to file start.
    pub start: usize,
    /// Byte offset just past the last matched byte.
    pub end: usize,
    /// What matched.
    pub kind: FindingKind,
    /// How confident the detector is.
    pub confidence: Confidence,
    /// A masked preview. NEVER the raw matched value.
    pub preview: String,
    /// Process-local fingerprint of the matched bytes. Used only within the
    /// same process/session to detect that a file span changed before a UI
    /// reveal. It is deliberately NOT serialized: an unkeyed or leaked
    /// fingerprint would be a brute-force oracle for small-domain values and
    /// would link identical values across files. It is not a security boundary,
    /// only a safety check for interactive reveal.
    #[serde(skip)]
    pub matched_fingerprint: String,
}

/// Why a file was not examined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// Larger than the configured size limit.
    TooLarge,
    /// Detected as binary (a NUL byte in the sniffed prefix).
    Binary,
    /// Not valid UTF-8.
    NotUtf8,
    /// Excluded by an ignore rule or by the exclusion list.
    Ignored,
    /// Could not be read (permissions, I/O error).
    Unreadable,
    /// Pattern matching hit a budget limit, so the file was only partly
    /// examined. Reported as incomplete coverage, never as a clean file.
    BudgetExhausted,
}

/// One file that was not examined, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skipped {
    /// Path relative to the scan root.
    pub path: PathBuf,
    /// Why it was skipped.
    pub reason: SkipReason,
}

/// Why a context filter judged a finding less likely to be real.
///
/// A filter never creates a finding, so a filter bug can cost attention but
/// can never manufacture a false report.
///
/// Most reasons **demote** rather than remove. "Generated", "placeholder", and
/// "private address" are statements about *likelihood*, not proof: a real
/// password can contain the word `sample`, a genuine card number can sit on a
/// minified line, and `10.23.4.5` identifies a device inside the network that
/// owns it. Deleting on a heuristic would hide exactly the finding the user
/// most needs, so only [`SuppressionReason::is_removal`] cases are dropped —
/// those where the match is structurally impossible rather than merely
/// improbable. Everything else survives at [`Confidence::Low`] and is counted
/// here so the user can see what was down-weighted on their behalf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionReason {
    /// The file is generated, vendored, or a build artifact.
    GeneratedFile,
    /// A loopback, private, link-local, or reserved address: machine role
    /// rather than personal data.
    NonIdentifyingAddress,
    /// The match is a window into a longer run of digits.
    EmbeddedInNumericRun,
    /// The line is numeric by construction (SVG geometry, coordinates).
    StructuredNumericData,
    /// The value is an example or placeholder, not a live credential.
    PlaceholderValue,
    /// A short-prefix key rule matched without any supporting context.
    ImplausibleKeyContext,
}

impl SuppressionReason {
    /// Every reason, for reporting.
    pub const ALL: [SuppressionReason; 6] = [
        SuppressionReason::GeneratedFile,
        SuppressionReason::NonIdentifyingAddress,
        SuppressionReason::EmbeddedInNumericRun,
        SuppressionReason::StructuredNumericData,
        SuppressionReason::PlaceholderValue,
        SuppressionReason::ImplausibleKeyContext,
    ];

    /// Stable label for report output.
    pub fn label(self) -> &'static str {
        match self {
            SuppressionReason::GeneratedFile => "generated_file",
            SuppressionReason::NonIdentifyingAddress => "non_identifying_address",
            SuppressionReason::EmbeddedInNumericRun => "embedded_in_numeric_run",
            SuppressionReason::StructuredNumericData => "structured_numeric_data",
            SuppressionReason::PlaceholderValue => "placeholder_value",
            SuppressionReason::ImplausibleKeyContext => "implausible_key_context",
        }
    }

    /// Whether this reason removes the finding outright, rather than demoting
    /// it to [`Confidence::Low`].
    ///
    /// Removal is reserved for matches that are *structurally* impossible, not
    /// merely improbable: a digit window inside a longer run was never a whole
    /// field to begin with. Every judgement about likelihood — generated file,
    /// placeholder-looking value, private address, weak key context — demotes
    /// instead, because each has a real counter-example where the finding is
    /// genuine.
    pub fn is_removal(self) -> bool {
        matches!(self, SuppressionReason::EmbeddedInNumericRun)
    }
}

/// Count of findings discarded for one reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suppressed {
    /// Why they were discarded.
    pub reason: SuppressionReason,
    /// How many.
    pub count: u64,
}

/// Explicit accounting of what the scan did and did not examine.
///
/// A scanner that silently skips overstates its coverage, so what was *not*
/// examined is part of the result. Three distinct things are counted:
///
/// * [`files_skipped`](Coverage::files_skipped) — files the walker reached but
///   could not read (too large, binary, not UTF-8, unreadable).
/// * [`files_ignored`](Coverage::files_ignored) — files excluded by a
///   `.gitignore` rule or an exclude glob. These are counted rather than
///   silently dropped, because "the scanner never looked" and "the scanner
///   found nothing" are different claims.
/// * [`suppressed`](Coverage::suppressed) — candidate findings that a context
///   filter judged less likely to be real. Most were demoted to
///   [`Confidence::Low`] and are still present in the report; only the
///   structurally-impossible ones were removed. See [`SuppressionReason`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    /// Files read and scanned.
    pub files_scanned: u64,
    /// Files reached but not readable as text.
    pub files_skipped: u64,
    /// Files excluded by an ignore rule or exclude glob before being read.
    pub files_ignored: u64,
    /// Total bytes scanned.
    pub bytes_scanned: u64,
    /// Every skipped file with its reason.
    pub skipped: Vec<Skipped>,
    /// Findings discarded after detection, counted by reason.
    pub suppressed: Vec<Suppressed>,
}

impl Coverage {
    /// Record one file that was not fully examined.
    pub(crate) fn record_skip(&mut self, path: PathBuf, reason: SkipReason) {
        self.skipped.push(Skipped { path, reason });
        self.files_skipped = self.skipped.len() as u64;
    }

    /// Record one suppressed finding.
    pub(crate) fn record_suppression(&mut self, reason: SuppressionReason) {
        match self.suppressed.iter_mut().find(|s| s.reason == reason) {
            Some(entry) => entry.count += 1,
            None => self.suppressed.push(Suppressed { reason, count: 1 }),
        }
    }

    /// Total findings a context filter judged less likely to be real, whether
    /// demoted or removed.
    pub fn total_suppressed(&self) -> u64 {
        self.suppressed.iter().map(|s| s.count).sum()
    }

    /// Findings removed from the report entirely.
    pub fn total_removed(&self) -> u64 {
        self.suppressed
            .iter()
            .filter(|s| s.reason.is_removal())
            .map(|s| s.count)
            .sum()
    }

    /// Findings kept but demoted to [`Confidence::Low`] by a context filter.
    pub fn total_demoted(&self) -> u64 {
        self.total_suppressed() - self.total_removed()
    }

    /// Files the scanner did not read, for any reason.
    pub fn files_unexamined(&self) -> u64 {
        self.files_skipped + self.files_ignored
    }
}

/// The result of scanning a project tree.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    /// Findings in deterministic order: by path, then by start offset.
    pub findings: Vec<ScanFinding>,
    /// What was and was not examined.
    pub coverage: Coverage,
    /// Per-scan salt used to compute process-local fingerprints.
    ///
    /// Not serialized. A report loaded from disk will have an all-zero salt
    /// and empty fingerprints, so reveal operations cannot succeed across
    /// sessions.
    #[serde(skip)]
    pub config_salt: [u8; 32],
}

/// Files that are scanned even when an ignore rule would exclude them.
///
/// This list exists because the default configuration would otherwise defeat
/// the tool's purpose. `.env` is the single most common place a developer
/// keeps a live credential, and it is also one of the most commonly
/// `.gitignore`d paths — so honouring `.gitignore` unconditionally means the
/// scanner reliably skips exactly the file the user most needs it to read.
///
/// These patterns are re-included after ignore processing. They are narrow on
/// purpose: each names a file that carries configuration or credentials, not a
/// build artifact. Turning off `.gitignore` wholesale is not an acceptable
/// substitute — it pulls in `node_modules`, build output, and caches, which is
/// what produced 2,300 false positives before these lists were tuned.
pub const ALWAYS_SCAN: &[&str] = &[
    "**/.env",
    "**/.env.*",
    "**/*.env",
    "**/.envrc",
    "**/.npmrc",
    "**/.pypirc",
    "**/.netrc",
    "**/_netrc",
    "**/credentials",
    "**/credentials.*",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/id_rsa",
    "**/id_ed25519",
    "**/id_ecdsa",
    "**/.htpasswd",
    "**/secrets.*",
    "**/*.secrets",
    "**/service-account*.json",
    "**/serviceaccount*.json",
];

/// What a finding's `preview` field reveals about the matched value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PreviewMode {
    /// Never include any byte of the matched value: the preview is a fixed
    /// placeholder (`sv_scan::mask_opaque`). This is the default. A scan
    /// report is written to disk and handed to agents, and ADR-0017's claim
    /// that this is safe holds only while the report cannot carry secret
    /// material — not even a short prefix.
    #[default]
    Opaque,
    /// Reveal at most the first four characters of the matched value
    /// (`sv_scan::mask`). An explicit opt-in for interactive human review,
    /// never the default, and not meant for reports that are persisted or
    /// shared.
    RevealPrefix,
}

/// How to walk and what to examine.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Skip files larger than this. Default 5 MiB.
    pub max_file_bytes: u64,
    /// Honour .gitignore and friends. Default true.
    pub respect_gitignore: bool,
    /// Follow symbolic links. Default false.
    pub follow_symlinks: bool,
    /// Additional glob patterns to exclude.
    pub exclude: Vec<String>,
    /// Patterns scanned even when an ignore rule would exclude them.
    ///
    /// Defaults to [`ALWAYS_SCAN`]. Set to an empty vector to honour
    /// `.gitignore` with no exceptions.
    pub always_scan: Vec<String>,
    /// Jurisdiction pattern packs to enable, by id (e.g. `br-lgpd`).
    ///
    /// **Empty by default.** Packs extend detection and can never reduce it
    /// (ADR-0018), but enabling all of them at once turns every long digit run
    /// into a candidate: the checksums involved are weak — Luhn is a single
    /// decimal check digit, so roughly one arbitrary digit run in ten passes
    /// it. Opt in to the jurisdictions that matter for the data at hand.
    pub packs: Vec<String>,
    /// What finding previews reveal about the matched value.
    ///
    /// [`PreviewMode::Opaque`] (the default) never puts any byte of a matched
    /// value into the report. [`PreviewMode::RevealPrefix`] keeps the
    /// historical four-character reveal and exists for interactive review
    /// only; a report built with it must not be treated as safe to persist or
    /// share.
    pub preview_mode: PreviewMode,
    /// Per-scan salt for process-local matched-value fingerprints.
    ///
    /// Never serialized. It is generated fresh for each scan so that two
    /// identical values in different files or projects are not linkable and
    /// so that the fingerprint is not a brute-force oracle for the value.
    pub fingerprint_salt: [u8; 32],
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_file_bytes: 5 * 1024 * 1024,
            respect_gitignore: true,
            follow_symlinks: false,
            exclude: DEFAULT_EXCLUDES.iter().map(|s| s.to_string()).collect(),
            always_scan: ALWAYS_SCAN.iter().map(|s| s.to_string()).collect(),
            // Baseline detection is always on; packs are opt-in (ADR-0018 §5).
            packs: Vec::new(),
            // Opaque previews are what makes a report safe to write to disk
            // and hand to an agent (ADR-0017).
            preview_mode: PreviewMode::default(),
            // A new salt per scan kills linkability and brute-force recovery.
            fingerprint_salt: random_salt(),
        }
    }
}

fn random_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::fill(&mut salt);
    salt
}

/// Process-local keyed fingerprint of a matched value.
///
/// Uses the per-scan `config.fingerprint_salt`. Identical values in different
/// scans produce different outputs; an attacker with only the report cannot
/// brute-force small-domain values. This is not a security boundary and is
/// never persisted.
pub fn matched_fingerprint(value: &str, salt: [u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

/// Glob patterns excluded from every scan in addition to [`ScanConfig::exclude`].
///
/// Build artifacts, dependency trees, lockfiles, minified bundles, images,
/// fonts, and archives carry no reviewable text and would only inflate
/// coverage and false positives.
///
/// Every directory pattern is written `**/name/**` rather than `name/**`. A
/// leading segment anchors the glob to the scan root, so `node_modules/**`
/// would match only a *top-level* `node_modules` and would silently scan
/// `ui/node_modules`. Scanning a vendored tree is not merely slow: minified
/// bundles, SVG path data, and generated CSS are dense sources of
/// false-positive card numbers and key-shaped tokens.
pub const DEFAULT_EXCLUDES: &[&str] = &[
    "**/target/**",
    "**/node_modules/**",
    "**/.git/**",
    "**/dist/**",
    "**/build/**",
    "**/vendor/**",
    "**/.venv/**",
    "**/__pycache__/**",
    "**/.yarn/releases/**",
    "**/.yarn/cache/**",
    "**/.gradle/**",
    "**/Pods/**",
    "**/*.lock",
    "**/*.min.js",
    "**/*.min.css",
    "**/*.map",
    "**/*.png",
    "**/*.jpg",
    "**/*.jpeg",
    "**/*.gif",
    "**/*.svg",
    "**/*.pdf",
    "**/*.woff",
    "**/*.woff2",
    "**/*.ttf",
    "**/*.ico",
    "**/*.zip",
    "**/*.gz",
    "**/*.exe",
    "**/*.dll",
    "**/*.so",
    "**/*.dylib",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn finding_fingerprint_is_not_serialized() {
        let salt = [42u8; 32];
        let finding = ScanFinding {
            path: PathBuf::from("test.txt"),
            line: 1,
            start: 0,
            end: 4,
            kind: FindingKind::Secret {
                rule_id: "api_key".to_string(),
            },
            confidence: Confidence::High,
            preview: "****".to_string(),
            matched_fingerprint: matched_fingerprint("1234", salt),
        };
        let json = serde_json::to_string(&finding).expect("serialize");
        assert!(
            !json.contains("matched_fingerprint"),
            "fingerprint must not appear in serialized JSON: {json}"
        );
        assert!(
            !json.contains(&finding.matched_fingerprint),
            "fingerprint value must not appear in serialized JSON: {json}"
        );
    }

    #[test]
    fn report_salt_is_not_serialized() {
        let mut salt = [0u8; 32];
        salt[0] = 7;
        let report = ScanReport {
            config_salt: salt,
            ..ScanReport::default()
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(
            !json.contains("config_salt"),
            "salt must not appear in serialized JSON: {json}"
        );
        // Default (all-zero) salt after round-trip proves the salt was skipped.
        let round: ScanReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(round.config_salt, [0u8; 32]);
    }
}
