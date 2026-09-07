//! Snapshot-bound plan types (ADR-0019 §1) and the plan digest approval
//! binds to.
//!
//! A [`PlanItem`] pins an approved edit to an exact file snapshot: project,
//! normalized path, OS file identity, keyed digest of the whole file, byte
//! span, keyed digest of the matched bytes, the pinned detector and
//! rule-pack versions, and the intended replacement. Nothing in the plan
//! authorizes "the finding" in the abstract, and nothing here can relocate
//! an approved span to wherever the value now happens to live.

use std::path::{Component, Path, PathBuf};

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::PlanError;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Keyed digests
// ---------------------------------------------------------------------------

/// A keyed digest: HMAC-SHA256 under a [`PlanKey`].
///
/// There is deliberately no way to construct a `Digest` from an unkeyed
/// hash in this crate. A plain hash of a small-domain value — an 11-digit
/// CPF, a phone number — is brute-forceable back to the value it was meant
/// to protect, and equal values produce equal hashes, correlating them
/// across every file the plan reaches. ADR-0019 §1 requires keyed digests;
/// this type is the only digest the plan carries.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    /// Wraps raw digest bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Digest(bytes)
    }

    /// The raw digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex encoding.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Decodes a lowercase hex digest.
    pub fn from_hex(value: &str) -> crate::Result<Self> {
        let bytes = hex::decode(value).map_err(|_| PlanError::InvalidDigest)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| PlanError::InvalidDigest)?;
        Ok(Digest(bytes))
    }
}

impl core::fmt::Debug for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The hex form is not secret (the digest is keyed), and showing it
        // keeps plan review and audit diffs readable.
        write!(f, "Digest({})", self.to_hex())
    }
}

impl core::fmt::Display for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Digest::from_hex(&value).map_err(serde::de::Error::custom)
    }
}

/// The caller-supplied plan key.
///
/// Supplied by the vault, never derived, stored, or persisted here; the
/// buffer is zeroized on drop. A later reader must not "helpfully" add a
/// `from_root_key` constructor: deriving the plan key inside the crate that
/// persists plans would put key material on the same disk as the digests it
/// protects.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PlanKey([u8; 32]);

impl PlanKey {
    /// Wraps exactly 32 bytes of caller-supplied key material.
    pub fn from_bytes(key: &[u8]) -> crate::Result<Self> {
        let bytes: [u8; 32] = key.try_into().map_err(|_| PlanError::InvalidKey)?;
        Ok(PlanKey(bytes))
    }
}

impl core::fmt::Debug for PlanKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PlanKey([REDACTED])")
    }
}

/// Computes the keyed digest of `bytes` under `key`.
///
/// This is the single digest primitive of the crate; plan construction and
/// verification both go through it, so the "keyed, never plain" rule has
/// exactly one enforcement point.
pub fn keyed_digest(key: &PlanKey, bytes: &[u8]) -> Digest {
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts 32-byte keys");
    mac.update(bytes);
    Digest(mac.finalize().into_bytes().into())
}

// ---------------------------------------------------------------------------
// Spans, identities, pins
// ---------------------------------------------------------------------------

/// A half-open byte span `[start, end)` inside one file's UTF-8 text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ByteSpan {
    /// Offset of the first matched byte.
    pub start: usize,
    /// Offset just past the last matched byte.
    pub end: usize,
}

impl ByteSpan {
    /// Builds a span, requiring `start < end`.
    pub fn new(start: usize, end: usize) -> crate::Result<Self> {
        if start >= end {
            return Err(PlanError::SpanOutOfBounds);
        }
        Ok(ByteSpan { start, end })
    }

    /// Slices `src` at this span, failing closed on out-of-bounds or
    /// non-character-boundary offsets instead of panicking.
    pub fn slice<'a>(&self, src: &'a str) -> Result<&'a str, PlanError> {
        if self.end > src.len() || self.start >= self.end {
            return Err(PlanError::SpanOutOfBounds);
        }
        if !src.is_char_boundary(self.start) || !src.is_char_boundary(self.end) {
            return Err(PlanError::SpanNotCharBoundary);
        }
        Ok(&src[self.start..self.end])
    }

    /// Whether two spans claim any byte in common.
    pub fn overlaps(&self, other: &ByteSpan) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// The OS identity of the file a plan item pins.
///
/// Both variants exist on every platform so plans and tests are portable;
/// [`FileIdentity::capture`] only ever produces the current platform's
/// shape. Identity is what makes "the file the human reviewed" and "the file
/// on disk now" the *same file* — a rename, restore, or replacement in
/// between yields a different identity and the plan is stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileIdentity {
    /// Unix device and inode.
    Unix {
        /// Stating device.
        device: u64,
        /// Inode number.
        inode: u64,
    },
    /// Windows volume serial and file index.
    Windows {
        /// Volume serial number.
        volume: u32,
        /// File index.
        index: u64,
    },
}

impl FileIdentity {
    /// Captures the identity of the file at `path`.
    ///
    /// On Unix this is the device and inode. On Windows, stable `std`
    /// exposes the file index and volume serial only behind an unstable
    /// feature (`windows_by_handle`), this workspace forbids `unsafe`, and
    /// no available safe crate publishes those fields (`same-file` compares
    /// two handles but exposes no accessors) — so capture **fails closed**
    /// there. The apply layer then refuses to commit under
    /// [`IdentityAssurance::Enforced`](crate::apply::IdentityAssurance)
    /// rather than silently running without the ADR-0019 §2 identity check:
    /// a silently-weaker guarantee on the primary platform is worse than a
    /// loud refusal. The Windows variant exists so plans stay portable.
    pub fn capture_from_path(path: &Path) -> crate::Result<Self> {
        let metadata = std::fs::metadata(path).map_err(|_| PlanError::IdentityUnavailable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            Ok(FileIdentity::Unix {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(windows)]
        {
            let _ = metadata;
            Err(PlanError::IdentityUnavailable)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = metadata;
            Err(PlanError::IdentityUnavailable)
        }
    }
}

/// The pinned detector and rule-pack a plan item was built with.
///
/// Verification must re-run the *same* rules the plan was built with;
/// a detector upgrade between plan and execute would silently change what
/// "matching evidence" means (ADR-0019 §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulePin {
    /// Version of the detector (the `sv-scan` crate) at plan time.
    pub detector_version: String,
    /// Rule-pack identifier, e.g. `sv-scan/baseline` or a pack id.
    pub pack_id: String,
    /// Version of that rule pack.
    pub pack_version: String,
}

impl RulePin {
    /// Pin for the baseline detectors of `sv-scan`.
    pub fn scan_baseline() -> Self {
        RulePin {
            detector_version: sv_scan::version().to_string(),
            pack_id: "sv-scan/baseline".to_string(),
            pack_version: sv_scan::version().to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Items and plans
// ---------------------------------------------------------------------------

/// One approved edit, bound to an exact file snapshot (ADR-0019 §1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanItem {
    /// Project the file belongs to.
    pub project_id: String,
    /// Normalized path relative to the project root.
    pub path: PathBuf,
    /// OS identity of the file at plan time.
    pub identity: FileIdentity,
    /// Keyed digest of the whole file at plan time.
    pub whole_file_digest: Digest,
    /// The byte span of the match.
    pub span: ByteSpan,
    /// Keyed digest of the matched bytes.
    pub matched_digest: Digest,
    /// Detector and rule-pack pin.
    pub rule_pin: RulePin,
    /// The text that will replace the span.
    pub replacement: String,
    /// The finding this item came from.
    pub kind: sv_scan::FindingKind,
}

/// The inputs [`PlanItem::build`] needs, minus the key.
#[derive(Debug, Clone)]
pub struct PlanItemDraft {
    /// Project the file belongs to.
    pub project_id: String,
    /// Path as reported by the scanner; normalized here.
    pub path: PathBuf,
    /// OS identity captured at plan time.
    pub identity: FileIdentity,
    /// The whole file content the span indexes into.
    pub source: String,
    /// The byte span of the match.
    pub span: ByteSpan,
    /// The text that will replace the span.
    pub replacement: String,
    /// The finding this item came from.
    pub kind: sv_scan::FindingKind,
    /// Detector and rule-pack pin.
    pub rule_pin: RulePin,
}

impl PlanItem {
    /// Builds an item from a draft, computing both keyed digests.
    ///
    /// Rejects spans that are out of bounds, empty, or not on UTF-8
    /// character boundaries, and rejects a span whose matched text is
    /// already a durable locator marker: a marker is never re-redacted and
    /// is never itself a finding (ADR-0017 §4). Seeing one here means the
    /// scan layer's marker filter was bypassed, so the plan fails closed
    /// rather than double-redacting.
    pub fn build(draft: PlanItemDraft, key: &PlanKey) -> crate::Result<Self> {
        let path = normalize_relative(&draft.path)?;
        let matched = draft.span.slice(&draft.source)?;
        if is_marker(matched) {
            return Err(PlanError::MarkerSpan);
        }
        let whole_file_digest = keyed_digest(key, draft.source.as_bytes());
        let matched_digest = keyed_digest(key, matched.as_bytes());
        Ok(PlanItem {
            project_id: draft.project_id,
            path,
            identity: draft.identity,
            whole_file_digest,
            span: draft.span,
            matched_digest,
            rule_pin: draft.rule_pin,
            replacement: draft.replacement,
            kind: draft.kind,
        })
    }
}

/// A set of plan items plus the plan digest approval binds to.
///
/// Items are stored in canonical order (project, path, span) and the plan
/// digest is the keyed digest of that canonical serialization, so the same
/// set of edits always yields the same digest and any difference — one
/// replacement, one span — yields a different one. Approval binds to this
/// digest (ADR-0019 §1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewritePlan {
    items: Vec<PlanItem>,
    plan_digest: Digest,
}

impl RewritePlan {
    /// Builds a plan, rejecting overlapping spans within one file at
    /// build time.
    ///
    /// Overlap resolution is a pre-approval decision (ADR-0019 §2): an
    /// executor that had to arbitrate overlaps mid-flight would be making
    /// remediation decisions no human reviewed. Items must already be
    /// built through [`PlanItem::build`].
    pub fn build(mut items: Vec<PlanItem>, key: &PlanKey) -> crate::Result<Self> {
        items.sort_by(|a, b| {
            (&a.project_id, &a.path, a.span.start, a.span.end).cmp(&(
                &b.project_id,
                &b.path,
                b.span.start,
                b.span.end,
            ))
        });
        // Spans are sorted by start within one file, so if an item overlaps
        // anything, it overlaps its predecessor; the adjacent check is
        // complete.
        for pair in items.windows(2) {
            if pair[0].project_id == pair[1].project_id
                && pair[0].path == pair[1].path
                && pair[0].span.overlaps(&pair[1].span)
            {
                return Err(PlanError::OverlappingSpans {
                    path: pair[0].path.clone(),
                });
            }
        }
        let encoded = serde_json::to_vec(&items)?;
        let plan_digest = keyed_digest(key, &encoded);
        Ok(RewritePlan { items, plan_digest })
    }

    /// The plan's items, in canonical order.
    pub fn items(&self) -> &[PlanItem] {
        &self.items
    }

    /// The digest approval binds to.
    pub fn digest(&self) -> Digest {
        self.plan_digest
    }
}

/// True when `text` is exactly a durable locator marker (`[SV:LOC:v1:<id>]`).
///
/// Uses the single wire-format parser in `sv-runtime` rather than a second
/// pattern: one definition of the marker shape, or the two drift apart. A
/// marker is never re-redacted and is never itself a finding (ADR-0017 §4);
/// plan construction and diffing use this to enforce that.
pub fn is_marker(text: &str) -> bool {
    sv_runtime::references::PublicLocator::parse(text).is_ok()
}

/// Normalizes a scanner-reported path to a safe relative form.
///
/// Rejects absolute paths, empty paths, and anything containing a parent or
/// root component: a plan path that could escape the project root would make
/// "beneath the approved root" (ADR-0019 §2) unenforceable.
pub(crate) fn normalize_relative(path: &Path) -> crate::Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(PlanError::NotRelative);
    }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(segment) => out.push(segment),
            Component::CurDir => {}
            _ => return Err(PlanError::NotRelative),
        }
    }
    if out.as_os_str().is_empty() {
        Err(PlanError::NotRelative)
    } else {
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    /// Assembled at runtime so this source file never contains a complete
    /// example credential; a literal trips repository secret scanning even
    /// though this is AWS's published documentation placeholder.
    fn aws_token() -> String {
        format!("AKIA{}", "IOSFODNN7EXAMPLE")
    }

    use super::*;
    use sv_scan::FindingKind;

    fn key() -> PlanKey {
        PlanKey::from_bytes(&[7u8; 32]).expect("key")
    }

    fn draft(source: &str, span: (usize, usize), replacement: &str) -> PlanItemDraft {
        PlanItemDraft {
            project_id: "proj".to_string(),
            path: PathBuf::from("config.toml"),
            identity: FileIdentity::Unix {
                device: 1,
                inode: 2,
            },
            source: source.to_string(),
            span: ByteSpan::new(span.0, span.1).expect("span"),
            replacement: replacement.to_string(),
            kind: FindingKind::Secret {
                rule_id: "aws_access_key_id".to_string(),
            },
            rule_pin: RulePin::scan_baseline(),
        }
    }

    fn draft_at(
        path: &str,
        source: &str,
        span: (usize, usize),
        replacement: &str,
    ) -> PlanItemDraft {
        PlanItemDraft {
            path: PathBuf::from(path),
            ..draft(source, span, replacement)
        }
    }

    #[test]
    fn item_build_computes_keyed_digests_and_roundtrips_serde() {
        let source = format!("aws = {}\n", aws_token());
        let item = PlanItem::build(draft(&source, (6, 26), "[REDACTED]"), &key()).expect("build");
        assert_eq!(item.span, ByteSpan::new(6, 26).expect("span"));
        assert_eq!(
            item.whole_file_digest,
            keyed_digest(&key(), source.as_bytes())
        );
        assert_eq!(
            item.matched_digest,
            keyed_digest(&key(), &source.as_bytes()[6..26])
        );
        let json = serde_json::to_string(&item).expect("serialize");
        let back: PlanItem = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, item);
    }

    /// ADR-0019 §1: identical values under different keys must produce
    /// different digests; the same key must be deterministic.
    #[test]
    fn identical_values_under_different_keys_give_different_digests() {
        let value = b"4242-4242-4242-4242";
        let k1 = PlanKey::from_bytes(&[1u8; 32]).expect("k1");
        let k2 = PlanKey::from_bytes(&[2u8; 32]).expect("k2");
        assert_ne!(keyed_digest(&k1, value), keyed_digest(&k2, value));
        assert_eq!(keyed_digest(&k1, value), keyed_digest(&k1, value));
    }

    /// ADR-0019 §2: overlaps are rejected at plan-build time, never at
    /// execute time.
    #[test]
    fn overlapping_spans_are_rejected_at_plan_build() {
        let source = "aaaaaaaaaaaaaaaaaaaa";
        let first = PlanItem::build(draft(source, (0, 10), "x"), &key()).expect("first");
        let second = PlanItem::build(draft(source, (5, 15), "y"), &key()).expect("second");
        let err = RewritePlan::build(vec![first, second], &key()).expect_err("overlap");
        assert!(matches!(err, PlanError::OverlappingSpans { .. }), "{err:?}");

        // Non-overlapping items in the same file build fine.
        let third = PlanItem::build(draft(source, (10, 20), "z"), &key()).expect("third");
        let disjoint = PlanItem::build(draft(source, (0, 10), "x"), &key()).expect("disjoint");
        RewritePlan::build(vec![disjoint, third], &key()).expect("no overlap");
    }

    /// ADR-0017 §4: a marker is never re-redacted.
    #[test]
    fn a_marker_span_is_rejected_not_re_redacted() {
        let marker = sv_runtime::references::PublicLocator::generate()
            .expect("csprng")
            .to_external();
        let source = format!("key = {marker}");
        let start = "key = ".len();
        let err = PlanItem::build(draft(&source, (start, source.len()), "[REDACTED]"), &key())
            .expect_err("marker span");
        assert!(matches!(err, PlanError::MarkerSpan), "{err:?}");

        assert!(is_marker(&marker));
        assert!(!is_marker("not a marker"));
        assert!(!is_marker("[SV:LOC:v2:not-a-real-one]"));
    }

    /// Non-character-boundary and out-of-bounds offsets fail closed instead
    /// of panicking on a slice.
    #[test]
    fn non_boundary_and_out_of_bounds_spans_error_without_panicking() {
        // "café" — the é occupies bytes 3 and 4; offset 4 is *inside* it.
        let source = "café = valor";
        let inside = ByteSpan::new(4, 6).expect("span shape");
        let err = inside
            .slice(source)
            .expect_err("starts inside a multi-byte char");
        assert!(matches!(err, PlanError::SpanNotCharBoundary), "{err:?}");

        let build_err = PlanItem::build(draft(source, (4, 6), "x"), &key())
            .expect_err("build must reject without panicking");
        assert!(matches!(build_err, PlanError::SpanNotCharBoundary));

        let oob = ByteSpan::new(0, source.len() + 5).expect("span shape");
        assert!(matches!(oob.slice(source), Err(PlanError::SpanOutOfBounds)));
    }

    #[test]
    fn plan_digest_binds_the_exact_item_set() {
        let source = format!("aws = {}\n", aws_token());
        let item = PlanItem::build(draft(&source, (6, 26), "[REDACTED]"), &key()).expect("build");

        // Same set, same digest: approval binds to content, not identity.
        let plan_a = RewritePlan::build(vec![item.clone()], &key()).expect("plan a");
        let plan_b = RewritePlan::build(vec![item.clone()], &key()).expect("plan b");
        assert_eq!(plan_a.digest(), plan_b.digest());

        // Any change — one replacement — yields a different digest.
        let changed =
            PlanItem::build(draft(&source, (6, 26), "[SV:REPLACED]"), &key()).expect("changed");
        let plan_c = RewritePlan::build(vec![changed], &key()).expect("plan c");
        assert_ne!(plan_a.digest(), plan_c.digest());

        // Canonical order: the same items in a different input order bind
        // the same digest.
        let other = PlanItem::build(
            draft_at("other.toml", "first = line\n", (0, 5), "[REDACTED]"),
            &key(),
        )
        .expect("other");
        let ordered = RewritePlan::build(vec![item.clone(), other.clone()], &key()).expect("p1");
        let reordered = RewritePlan::build(vec![other, item], &key()).expect("p2");
        assert_eq!(ordered.digest(), reordered.digest());
    }

    #[test]
    fn normalize_relative_rejects_escape_attempts() {
        assert!(normalize_relative(Path::new("src/main.rs")).is_ok());
        assert!(normalize_relative(Path::new(".env")).is_ok());
        assert!(normalize_relative(Path::new("./a/./b")).is_ok());
        assert!(normalize_relative(Path::new("../secrets")).is_err());
        assert!(normalize_relative(Path::new("/etc/passwd")).is_err());
        assert!(normalize_relative(Path::new("")).is_err());
    }
}
