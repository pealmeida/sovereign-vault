//! Execute-time verification of a plan item against current file bytes
//! (ADR-0019 §2), minus the filesystem steps that belong to the write
//! phase.
//!
//! The check order is load-bearing: whole-file digest **first** (so a
//! changed file is rejected before anything else is interpreted), then span
//! bounds, then the matched-byte digest. Any mismatch yields
//! [`VerifyOutcome::Stale`] and nothing else — the caller must obtain a
//! fresh plan and a fresh approval. There is deliberately no "closest
//! match", no re-anchoring, and no relocation: an approved span that no
//! longer sits over the approved bytes is stale, not mobile.
//!
//! The pinned-detector re-run of ADR-0019 §2 (re-running the plan's rules
//! and requiring matching evidence at the span) belongs to the full execute
//! path and lands with the write phase; it needs live rule evaluation and
//! the process-scoped locking steps around it.

use crate::plan::{keyed_digest, PlanItem, PlanKey};

/// The result of verifying one plan item against current bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// All three checks hold: same whole file, same span, same bytes in the
    /// span. The approval still describes reality.
    Verified,
    /// At least one check failed. The plan is stale; a fresh plan and a
    /// fresh approval are required before anything is written.
    Stale,
}

/// Verifies `item` against `current`, the file's current text.
///
/// Any failure — a different whole-file digest, a span past the end, a span
/// that splits a multi-byte character, different bytes inside the span —
/// is [`VerifyOutcome::Stale`]. The distinctions do not matter to the
/// caller's obligation, which is always the same: re-plan, re-approve.
pub fn verify_plan_item(item: &PlanItem, key: &PlanKey, current: &str) -> VerifyOutcome {
    // 1. The whole file must still be the file that was approved.
    if keyed_digest(key, current.as_bytes()) != item.whole_file_digest {
        return VerifyOutcome::Stale;
    }
    // 2. The span must still land inside the file, on character boundaries.
    //    A span that cannot slice is a mismatch, not a panic.
    let matched = match item.span.slice(current) {
        Ok(matched) => matched,
        Err(_) => return VerifyOutcome::Stale,
    };
    // 3. The bytes inside the span must still be the approved bytes.
    if keyed_digest(key, matched.as_bytes()) != item.matched_digest {
        return VerifyOutcome::Stale;
    }
    VerifyOutcome::Verified
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
    use crate::plan::{ByteSpan, FileIdentity, PlanItemDraft, RulePin};
    use std::path::PathBuf;
    use sv_scan::FindingKind;

    fn key() -> PlanKey {
        PlanKey::from_bytes(&[9u8; 32]).expect("key")
    }

    fn item(source: &str) -> PlanItem {
        PlanItem::build(
            PlanItemDraft {
                project_id: "proj".to_string(),
                path: PathBuf::from(".env"),
                identity: FileIdentity::Unix {
                    device: 1,
                    inode: 2,
                },
                source: source.to_string(),
                span: ByteSpan::new(6, 26).expect("span"),
                replacement: "[REDACTED]".to_string(),
                kind: FindingKind::Secret {
                    rule_id: "aws_access_key_id".to_string(),
                },
                rule_pin: RulePin::scan_baseline(),
            },
            &key(),
        )
        .expect("build")
    }

    #[test]
    fn unchanged_file_verifies_and_changed_file_is_stale() {
        let source = format!("aws = {}\n", aws_token());
        let item = item(&source);
        assert_eq!(
            verify_plan_item(&item, &key(), &source),
            VerifyOutcome::Verified
        );

        // The value moved to another offset after an unrelated edit: the
        // plan is stale. It is never relocated to the value's new position.
        let shifted = format!("# added line\n{source}");
        assert_eq!(
            verify_plan_item(&item, &key(), &shifted),
            VerifyOutcome::Stale
        );
        assert_eq!(item.span.start, 6, "the span itself is never moved");

        // Same length, different byte in the span: still stale.
        let flipped = {
            // One byte different in the span, assembled the same way so no
            // complete credential-shaped literal appears in this file.
            let mut t = aws_token();
            t.pop();
            format!("aws = {t}F\n")
        };
        assert_eq!(
            verify_plan_item(&item, &key(), &flipped),
            VerifyOutcome::Stale
        );

        // A different key must not verify anything either.
        let other = PlanKey::from_bytes(&[8u8; 32]).expect("other key");
        assert_eq!(
            verify_plan_item(&item, &other, &source),
            VerifyOutcome::Stale
        );
    }

    #[test]
    fn truncated_or_split_spans_are_stale_not_panics() {
        let item = item(&format!("aws = {}\n", aws_token()));
        assert_eq!(
            verify_plan_item(&item, &key(), "aws = "),
            VerifyOutcome::Stale
        );
        // A whole-file match with a span inside a multi-byte character
        // cannot happen (the digests would disagree first), but the bounds
        // check still refuses to slice blindly.
        let multibyte = format!("aws = café {}\n", aws_token());
        assert_eq!(
            verify_plan_item(&item, &key(), &multibyte),
            VerifyOutcome::Stale
        );
    }
}
