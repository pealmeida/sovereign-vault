//! Recovery and journal types, specified up front as ADR-0017 §4 requires.
//!
//! These are the *types and their serde only* in this phase: no I/O, no
//! vault access, no filesystem. The write phase persists them, in the
//! vault-before-file order that makes an interrupted run recoverable
//! rather than destructive.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::plan::{ByteSpan, Digest, FileIdentity};

/// Owner-side record of one redaction, written for every item — including
/// `Opaque` discovery-policy ones (ADR-0017 §4). Redaction is never silent
/// data loss: the owner can always ask what was here and restore it.
///
/// The original bytes themselves live in the vault's encrypted storage;
/// this record carries only their keyed digest and the opaque storage
/// reference. It must never carry the bytes, and never a bearer token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryRecord {
    /// Plan whose approval produced this redaction.
    pub plan_digest: Digest,
    /// Project the file belongs to.
    pub project_id: String,
    /// Normalized path of the redacted file.
    pub path: PathBuf,
    /// OS identity of the file at plan time.
    pub identity: FileIdentity,
    /// Keyed digest of the original bytes, for integrity on restore.
    pub snapshot_digest: Digest,
    /// Opaque vault-side storage reference for the encrypted snapshot.
    pub snapshot_ref: String,
    /// The discovery policy that governed the marker choice.
    pub discovery: sv_runtime::DiscoveryPolicy,
    /// External wire form of the locator written into the file, when the
    /// policy was `Discoverable`. `None` for `Opaque`, which writes the
    /// anonymous form instead and has no public resolution path.
    pub locator: Option<String>,
    /// The span this record's redaction replaced. `None` on records written
    /// before this field existed; restore refuses such records rather than
    /// conflict-check against a state it cannot reconstruct.
    #[serde(default)]
    pub span: Option<ByteSpan>,
    /// The text the span was replaced with. Paired with [`RecoveryRecord::span`].
    #[serde(default)]
    pub replacement: Option<String>,
    /// When the redaction happened.
    pub created_at: DateTime<Utc>,
}

impl RecoveryRecord {
    /// Whether the record's locator field is consistent with its policy.
    ///
    /// `Opaque` must have no locator; `Discoverable` must have one that
    /// parses as a real marker. Encoded here so an inconsistent record
    /// fails loudly instead of pretending a marker exists.
    pub fn locator_consistent(&self) -> bool {
        match (self.discovery, &self.locator) {
            (sv_runtime::DiscoveryPolicy::Opaque, None) => true,
            (sv_runtime::DiscoveryPolicy::Discoverable, Some(external)) => {
                crate::plan::is_marker(external)
            }
            _ => false,
        }
    }
}

/// Progress journal for one planned run (ADR-0017 §4).
///
/// A multi-file run is *not* transactional; the journal is what makes it
/// resumable. Entries record how far each file got, in the
/// vault-before-file order, so an interrupted run can be completed or
/// rolled back from recorded fact rather than reconstructed guesswork.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteJournal {
    /// The plan this journal tracks; a journal covers exactly one plan.
    pub plan_digest: Digest,
    /// Project the run is scoped to.
    pub project_id: String,
    /// One entry per file the plan touches.
    pub entries: Vec<JournalEntry>,
}

/// The state of one file within a journalled run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Normalized path of the file.
    pub path: PathBuf,
    /// How far the run got with this file.
    pub state: JournalState,
    /// When this state was recorded.
    pub at: DateTime<Utc>,
}

/// Lifecycle states of one file in a journalled run, in ADR-0017 §4 order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalState {
    /// Approved and queued; nothing has happened yet.
    Pending,
    /// Vault material, locator, and recovery record are durably committed;
    /// the file has not been touched. The ordering is what makes a crash
    /// here harmless: the vault knows, the file is untouched. The locator
    /// committed for this redaction is recorded so a resumed run can report
    /// it without duplicating vault work.
    VaultStored {
        /// External wire form of the committed locator, if any.
        locator: Option<String>,
    },
    /// The file was replaced. The original remains recoverable through the
    /// recovery record until explicit recovery deletion.
    FileReplaced,
    /// The item failed; the reason is recorded, the run moves on.
    Failed {
        /// Generic failure class; never the matched value.
        reason: String,
    },
    /// The file was restored to its original bytes.
    RolledBack,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::PlanKey;

    fn key() -> PlanKey {
        PlanKey::from_bytes(&[5u8; 32]).expect("key")
    }

    fn digest_of(bytes: &[u8]) -> Digest {
        crate::plan::keyed_digest(&key(), bytes)
    }

    #[test]
    fn recovery_record_roundtrips_and_enforces_locator_policy_consistency() {
        let locator = sv_runtime::references::PublicLocator::generate()
            .expect("csprng")
            .to_external();
        let discoverable = RecoveryRecord {
            plan_digest: digest_of(b"plan-a"),
            project_id: "proj".to_string(),
            path: PathBuf::from(".env"),
            identity: FileIdentity::Unix {
                device: 1,
                inode: 2,
            },
            snapshot_digest: digest_of(b"original bytes"),
            snapshot_ref: "vault://snapshots/abc".to_string(),
            discovery: sv_runtime::DiscoveryPolicy::Discoverable,
            locator: Some(locator.clone()),
            span: Some(ByteSpan::new(6, 26).expect("span")),
            replacement: Some("[REDACTED]".to_string()),
            created_at: chrono::Utc::now(),
        };
        assert!(discoverable.locator_consistent());
        let json = serde_json::to_string(&discoverable).expect("serialize");
        let back: RecoveryRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, discoverable);

        // Opaque records carry no locator — that is what removes public
        // resolution, not owner recovery.
        let opaque = RecoveryRecord {
            discovery: sv_runtime::DiscoveryPolicy::Opaque,
            locator: None,
            ..discoverable.clone()
        };
        assert!(opaque.locator_consistent());
        assert!(!serde_json::to_string(&opaque).unwrap().contains("SV:LOC"));

        // A record claiming both is inconsistent and must not pass.
        let contradictory = RecoveryRecord {
            locator: Some(locator),
            ..opaque.clone()
        };
        assert!(!contradictory.locator_consistent());
    }

    #[test]
    fn journal_states_roundtrip_in_vault_before_file_order() {
        let journal = RewriteJournal {
            plan_digest: digest_of(b"plan-b"),
            project_id: "proj".to_string(),
            entries: vec![
                JournalEntry {
                    path: PathBuf::from(".env"),
                    state: JournalState::FileReplaced,
                    at: chrono::Utc::now(),
                },
                JournalEntry {
                    path: PathBuf::from("svc.json"),
                    state: JournalState::VaultStored {
                        locator: Some("[SV:LOC:v1:placeholder-not-real]".to_string()),
                    },
                    at: chrono::Utc::now(),
                },
                JournalEntry {
                    path: PathBuf::from("broken.pem"),
                    state: JournalState::Failed {
                        reason: "stale plan".to_string(),
                    },
                    at: chrono::Utc::now(),
                },
            ],
        };
        let json = serde_json::to_string(&journal).expect("serialize");
        assert!(json.contains("\"file_replaced\""));
        assert!(json.contains("\"vault_stored\""));
        let back: RewriteJournal = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, journal);
    }
}
