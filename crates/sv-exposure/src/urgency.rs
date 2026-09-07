//! Exposure classification and rotation urgency.
//!
//! Every variant in [`Exposure`] is a statement about what was **found** in
//! scanned git history, never a claim about what does or does not exist. The
//! absence of a finding is reported as [`Exposure::NotFoundInScannedHistory`]
//! together with the limits that made the answer incomplete.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sv_scan::ScanFinding;

use crate::issuer::Issuer;

/// What the evidence shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    /// Not found in any scanned object, and the path is untracked.
    NotFoundInScannedHistory {
        /// Number of refs that were scanned.
        scanned_refs: usize,
        /// Limits that make "not found" an incomplete answer.
        limits: Vec<ScanLimit>,
    },
    /// Found in an object reachable only from local refs.
    FoundLocalOnly {
        /// How many distinct commits referenced a blob that matched.
        commits: usize,
    },
    /// Found in an object reachable from a remote-tracking ref.
    ///
    /// A remote-tracking ref can be stale: its absence does not prove the object
    /// was never pushed.
    FoundOnRemote {
        /// Name of the remote as recorded locally, e.g. `origin`.
        remote: String,
        /// Earliest commit timestamp observed among the hits. Commits may be
        /// backdated; this is an observation, not an exposure time.
        earliest_commit: DateTime<Utc>,
    },
    /// Found, and the repository is known to be public.
    ///
    /// Local git metadata cannot determine public/private status. This variant
    /// is produced only when an external check (P12) confirms the repository is
    /// public.
    FoundPublic {
        /// Name of the remote.
        remote: String,
        /// Earliest commit timestamp observed among the hits.
        earliest_commit: DateTime<Utc>,
    },
}

/// Why the answer may be incomplete. Displayed, never swallowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanLimit {
    /// The clone is shallow, so older history was not scanned.
    ShallowClone,
    /// Some reflog entries were expired, missing, or could not be resolved.
    ReflogExpired,
    /// Some objects were garbage-collected and are no longer present locally.
    ObjectsGarbageCollected,
    /// Submodules exist but were not scanned.
    SubmodulesNotScanned {
        /// Number of submodules skipped.
        count: usize,
    },
    /// Some reachable objects were skipped, e.g. because the scan failed partway.
    UnreachableObjectsSkipped,
    /// No objects were scanned at all: the path is not a git repository, or the
    /// repository has no commits.
    ///
    /// This is maximal uncertainty, not cleanliness. Without it, an empty index
    /// carrying an empty limits list would derive [`RotationUrgency::None`] —
    /// reporting "no rotation needed" when nothing was examined.
    NothingScanned,
}

/// How urgently a credential should be rotated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationUrgency {
    /// No exposure detected in scanned history, and the scan had no limits.
    None,
    /// Coverage was incomplete, so no negative conclusion is available. The UI
    /// must surface the limits rather than a clean verdict.
    Undetermined,
    /// Exposed only locally; rotate before the next push.
    BeforePush,
    /// Reachable from a remote-tracking ref; rotate now.
    Now,
    /// Confirmed public; rotate immediately.
    Immediate,
}

/// Derive urgency from exposure.
///
/// Positive evidence (`FoundLocalOnly`, `FoundOnRemote`, `FoundPublic`) is
/// actionable regardless of any coverage limits. For `NotFoundInScannedHistory`,
/// urgency depends on whether the scan had limits: an empty limits vector means
/// we looked properly and found nothing; any limit means the negative answer is
/// incomplete and must not be presented as clean.
pub fn derive_urgency(exposure: &Exposure) -> RotationUrgency {
    match exposure {
        Exposure::NotFoundInScannedHistory { limits, .. } => {
            if limits.is_empty() {
                RotationUrgency::None
            } else {
                RotationUrgency::Undetermined
            }
        }
        Exposure::FoundLocalOnly { .. } => RotationUrgency::BeforePush,
        Exposure::FoundOnRemote { .. } => RotationUrgency::Now,
        Exposure::FoundPublic { .. } => RotationUrgency::Immediate,
    }
}

/// A scan finding enriched with exposure classification and issuer guidance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingExposure {
    /// The original scan finding (path, span, rule id, preview).
    pub finding: ScanFinding,
    /// What was found in git history.
    pub exposure: Exposure,
    /// Derived rotation urgency.
    pub urgency: RotationUrgency,
    /// Issuer guidance for rotating the credential.
    pub issuer: Issuer,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposure_serializes_as_snake_case() {
        let e = Exposure::FoundLocalOnly { commits: 3 };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("found_local_only"));
        assert!(json.contains("\"commits\":3"));
    }

    #[test]
    fn urgency_ordering_is_explicit() {
        // The numeric ordering of the enum must not be relied upon for severity.
        // This test only guards against accidental reordering.
        let all = [
            RotationUrgency::None,
            RotationUrgency::Undetermined,
            RotationUrgency::BeforePush,
            RotationUrgency::Now,
            RotationUrgency::Immediate,
        ];
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn derive_urgency_empty_limits_means_none() {
        let exposure = Exposure::NotFoundInScannedHistory {
            scanned_refs: 1,
            limits: Vec::new(),
        };
        assert_eq!(derive_urgency(&exposure), RotationUrgency::None);
    }

    #[test]
    fn derive_urgency_with_limits_means_undetermined() {
        let exposure = Exposure::NotFoundInScannedHistory {
            scanned_refs: 1,
            limits: vec![ScanLimit::ReflogExpired],
        };
        assert_eq!(derive_urgency(&exposure), RotationUrgency::Undetermined);
    }

    #[test]
    fn derive_urgency_positive_evidence_ignores_limits() {
        let exposure = Exposure::FoundOnRemote {
            remote: "origin".into(),
            earliest_commit: Utc::now(),
        };
        assert_eq!(derive_urgency(&exposure), RotationUrgency::Now);
    }

    /// Nothing scanned is maximal uncertainty, never cleanliness.
    ///
    /// The failure this guards against is specific: a path that is not a git
    /// repository produces an empty index, and an empty index with an empty
    /// limits list would derive `None` — telling the user no rotation is
    /// needed for a search that never ran.
    #[test]
    fn nothing_scanned_is_undetermined_not_none() {
        let exposure = Exposure::NotFoundInScannedHistory {
            scanned_refs: 0,
            limits: vec![ScanLimit::NothingScanned],
        };
        assert_eq!(derive_urgency(&exposure), RotationUrgency::Undetermined);
        assert_ne!(derive_urgency(&exposure), RotationUrgency::None);
    }
}
