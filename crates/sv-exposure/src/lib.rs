//! Sovereign Vault exposure classification.
//!
//! This crate answers the question "does this credential need rotating?" by
//! inspecting where the matched value has appeared in the local git history.
//! It does **not** check whether a credential is valid, whether it still works,
//! or whether it exists on a remote server except via evidence already present
//! in the local repository.
//!
//! The core rule is: a secret moved into the vault is still exposed if it ever
//! appeared in git history, because history is replicated by every clone and
//! fork. Only rotation removes the risk.
//!
//! # Invariants
//!
//! * Detected credential values are never passed as command-line arguments,
//!   written to logs, or sent to external services. Detection runs in-process
//!   over blob bytes loaded from `git cat-file`.
//! * The optional `github` feature transmits the user's GitHub connector token
//!   to GitHub's API. That token is a separately authorized connector credential,
//!   not a discovered secret. No discovered credential is ever sent to GitHub.
//! * Git runs with external diff/textconv helpers disabled and no implicit
//!   network fetch.
//! * A commit timestamp is reported as "earliest commit observed", never as an
//!   exposure time, because commits can be backdated.
//! * `Exposure` variants describe only what was found; absence of evidence is
//!   reported as `NotFoundInScannedHistory` together with the limits that made
//!   the answer incomplete.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod git;
mod issuer;
mod urgency;

#[cfg(feature = "github")]
mod github;

pub use git::{classify_finding, collect_blobs, BlobIndex, ClassificationError, GitRunError};
pub use issuer::{Issuer, IssuerRule, RotationState, RULE_ISSUERS};
pub use urgency::{derive_urgency, Exposure, FindingExposure, RotationUrgency, ScanLimit};

#[cfg(feature = "github")]
pub use github::{
    transient_fingerprint, GitHubClient, GitHubError, PushProtectionStatus, RepoId, RepoVisibility,
    RepositorySecurityPosture, SecretScanningAlert, SecretScanningAlerts,
};

/// Crate version string.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
