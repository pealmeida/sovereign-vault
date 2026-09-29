//! OS-attested human presence for protected approvals (ADR-0025).
//!
//! Platform-neutral pieces: the [`PresenceVerifier`] seam, the per-request
//! [`GateState`] machine, operation digests, and the [`PresenceCoordinator`]
//! that runs one native prompt at a time behind a bounded queue. The macOS
//! backend lives in [`macos`]; Windows is the separate `sv-presence-windows`
//! crate; Linux is always [`Availability::Unavailable`] (spec §5.3).

use std::sync::Arc;

mod gate;
mod op;

pub use gate::{AttemptId, GateError, GateState};
pub use op::{OpDescriptor, OpDigest};

/// How the device owner proved presence, as reported by the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modality {
    Biometric,
    Password,
    Pin,
    /// The backend does not say (Windows `Verified`, macOS completion).
    Unknown,
}

/// Why a system cannot attest presence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// No trustworthy mechanism on this platform (Linux, spec §5.3).
    UnsupportedPlatform,
    /// Windows below Build 22000 (spec §5.2).
    BelowMinimumBuild,
    NotConfigured,
    DisabledByPolicy,
    DeviceNotPresent,
}

impl Reason {
    pub fn message(&self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "no trustworthy OS presence check exists on this platform",
            Self::BelowMinimumBuild => {
                "Windows Hello presence requires Windows 11 (build 22000) or later"
            }
            Self::NotConfigured => "no biometric, PIN, or password verification is configured",
            Self::DisabledByPolicy => "OS presence verification is disabled by policy",
            Self::DeviceNotPresent => "no verification device is present",
        }
    }
}

/// Whether this system can attest presence right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    Protected { modalities: Vec<Modality> },
    Unavailable(Reason),
}

/// Why one verification did not succeed (spec §9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PresenceError {
    #[error("verification was cancelled")]
    Cancelled,
    #[error("verification failed")]
    Failed,
    #[error("the verification device is busy")]
    Busy,
    #[error("too many failed attempts; verification is locked out")]
    Exhausted,
    #[error("verification is disabled by policy")]
    DisabledByPolicy,
    #[error("no verification method is configured for this user")]
    NotConfigured,
    #[error("verification is unavailable")]
    Unavailable,
    #[error("verification timed out")]
    Timeout,
}

impl PresenceError {
    /// `true` for the four errors that return a request to `Pending`
    /// (spec §6.2); every other error denies the request.
    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::Cancelled | Self::Failed | Self::Busy | Self::Exhausted
        )
    }
}

/// A successful verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub modality: Modality,
}

/// Per-attempt cancellation, owned by the coordinator (plan D13). Each
/// verification gets its own signal, so a backend can never cancel another
/// attempt's prompt.
#[derive(Clone)]
pub struct CancelSignal(tokio::sync::watch::Receiver<bool>);

impl CancelSignal {
    /// A signal and the sender that fires it.
    pub fn new() -> (tokio::sync::watch::Sender<bool>, Self) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        (tx, Self(rx))
    }

    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }

    /// Resolves once the attempt is cancelled. A closed sender counts as
    /// cancelled: nobody is waiting for this prompt any more.
    pub async fn cancelled(&self) {
        let mut rx = self.0.clone();
        let _ = rx.wait_for(|cancelled| *cancelled).await;
    }
}

/// The seam every backend implements, reused by subproject A.
#[async_trait::async_trait]
pub trait PresenceVerifier: Send + Sync {
    fn availability(&self) -> Availability;

    /// Show the native prompt for `op` and return when it has ENDED — the
    /// final callback arrived or a native cancellation was confirmed. The
    /// coordinator relies on this to keep the prompt slot occupied (§6.1).
    ///
    /// Cancellation contract (D13): check `cancel.is_cancelled()`
    /// immediately before opening the native prompt and return
    /// `Err(Cancelled)` without opening it if set; if the platform can
    /// cancel, check again right after the native operation exists and race
    /// its completion against `cancel.cancelled()`, cancelling THIS
    /// operation only.
    async fn verify(
        &self,
        op: &OpDescriptor,
        cancel: &CancelSignal,
    ) -> Result<Outcome, PresenceError>;
}

/// The verifier for systems with no trustworthy mechanism.
pub struct UnavailableVerifier {
    reason: Reason,
}

impl UnavailableVerifier {
    pub fn new(reason: Reason) -> Self {
        Self { reason }
    }
}

#[async_trait::async_trait]
impl PresenceVerifier for UnavailableVerifier {
    fn availability(&self) -> Availability {
        Availability::Unavailable(self.reason.clone())
    }

    async fn verify(
        &self,
        _op: &OpDescriptor,
        _cancel: &CancelSignal,
    ) -> Result<Outcome, PresenceError> {
        Err(PresenceError::Unavailable)
    }
}

/// Verifier for the current platform. Windows is built by the desktop from
/// `sv-presence-windows`, because it needs the application's window.
pub fn platform_verifier() -> Arc<dyn PresenceVerifier> {
    Arc::new(UnavailableVerifier::new(Reason::UnsupportedPlatform))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_errors_are_exactly_the_four_of_section_6_2() {
        use PresenceError::*;
        for e in [Cancelled, Failed, Busy, Exhausted] {
            assert!(e.is_retryable(), "{e:?}");
        }
        for e in [DisabledByPolicy, NotConfigured, Unavailable, Timeout] {
            assert!(!e.is_retryable(), "{e:?}");
        }
    }

    #[tokio::test]
    async fn unavailable_verifier_never_verifies() {
        let v = UnavailableVerifier::new(Reason::UnsupportedPlatform);
        assert_eq!(
            v.availability(),
            Availability::Unavailable(Reason::UnsupportedPlatform)
        );
        let (_tx, cancel) = CancelSignal::new();
        assert_eq!(
            v.verify(&OpDescriptor::new("x"), &cancel).await,
            Err(PresenceError::Unavailable)
        );
    }
}
