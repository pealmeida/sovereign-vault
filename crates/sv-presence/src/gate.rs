//! Per-request attempt state (ADR-0025 §6.1).
//!
//! `Pending → Verifying` happens under the owner's lock, which is then
//! released while the native prompt runs; the finisher re-acquires the lock
//! and commits only if the same attempt is still `Verifying`, the digest the
//! verification was granted for equals the stored one and the current one,
//! and the deadline has not passed.

use std::time::Instant;

use crate::OpDigest;

/// Identity of one verification attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttemptId(u64);

impl AttemptId {
    /// Constructed only inside the crate; the coordinator (Task 3) is the
    /// non-test caller, so until it lands this is dead code outside tests.
    #[allow(dead_code)]
    pub(crate) fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GateState {
    #[default]
    Pending,
    Verifying {
        attempt: AttemptId,
        digest: OpDigest,
    },
    /// A verification bound to `digest` succeeded. Approval requests are
    /// removed at this point; OTP challenges stay here until the resend.
    Authenticated { digest: OpDigest },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GateError {
    #[error("a verification is already in progress for this request")]
    AlreadyVerifying,
    #[error("the request is not awaiting verification")]
    NotPending,
    #[error("the verification result belongs to an older attempt")]
    StaleAttempt,
    #[error("the request changed during verification")]
    DigestMismatch,
    #[error("the request expired during verification")]
    Expired,
}

impl GateState {
    pub fn begin(&mut self, attempt: AttemptId, digest: OpDigest) -> Result<(), GateError> {
        match self {
            Self::Pending => {
                *self = Self::Verifying { attempt, digest };
                Ok(())
            }
            Self::Verifying { .. } => Err(GateError::AlreadyVerifying),
            Self::Authenticated { .. } => Err(GateError::NotPending),
        }
    }

    pub fn finish(
        &mut self,
        attempt: AttemptId,
        granted: OpDigest,
        current: OpDigest,
        deadline: Instant,
        now: Instant,
    ) -> Result<(), GateError> {
        let Self::Verifying {
            attempt: active,
            digest,
        } = *self
        else {
            return Err(GateError::StaleAttempt);
        };
        if active != attempt {
            return Err(GateError::StaleAttempt);
        }
        if digest != granted || digest != current {
            *self = Self::Pending;
            return Err(GateError::DigestMismatch);
        }
        if now > deadline {
            *self = Self::Pending;
            return Err(GateError::Expired);
        }
        *self = Self::Authenticated { digest };
        Ok(())
    }

    /// A retryable failure (§6.2): back to `Pending`, only for this attempt.
    pub fn abort(&mut self, attempt: AttemptId) {
        if matches!(self, Self::Verifying { attempt: a, .. } if *a == attempt) {
            *self = Self::Pending;
        }
    }

    pub fn is_authenticated_for(&self, digest: OpDigest) -> bool {
        matches!(self, Self::Authenticated { digest: d } if *d == digest)
    }

    /// Any change of the underlying request clears the authenticated state
    /// (§7.3).
    pub fn reset(&mut self) {
        *self = Self::Pending;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OpDescriptor;
    use std::time::{Duration, Instant};

    fn d(kind: &'static str) -> OpDigest {
        OpDescriptor::new(kind).digest()
    }

    #[test]
    fn begin_then_finish_authenticates() {
        let mut g = GateState::default();
        let a = AttemptId::new(1);
        g.begin(a, d("x")).unwrap();
        let later = Instant::now() + Duration::from_secs(60);
        g.finish(a, d("x"), d("x"), later, Instant::now()).unwrap();
        assert!(g.is_authenticated_for(d("x")));
        assert!(!g.is_authenticated_for(d("y")));
    }

    #[test]
    fn second_begin_while_verifying_is_rejected() {
        let mut g = GateState::default();
        g.begin(AttemptId::new(1), d("x")).unwrap();
        assert_eq!(
            g.begin(AttemptId::new(2), d("x")),
            Err(GateError::AlreadyVerifying)
        );
    }

    #[test]
    fn stale_attempt_cannot_finish() {
        let mut g = GateState::default();
        g.begin(AttemptId::new(1), d("x")).unwrap();
        let later = Instant::now() + Duration::from_secs(60);
        assert_eq!(
            g.finish(AttemptId::new(2), d("x"), d("x"), later, Instant::now()),
            Err(GateError::StaleAttempt)
        );
        assert!(matches!(g, GateState::Verifying { .. }));
    }

    #[test]
    fn digest_mismatch_returns_to_pending() {
        let mut g = GateState::default();
        let a = AttemptId::new(1);
        g.begin(a, d("x")).unwrap();
        let later = Instant::now() + Duration::from_secs(60);
        assert_eq!(
            g.finish(a, d("x"), d("y"), later, Instant::now()),
            Err(GateError::DigestMismatch)
        );
        assert_eq!(g, GateState::Pending);
        g.begin(a, d("x")).unwrap();
        assert_eq!(
            g.finish(a, d("z"), d("x"), later, Instant::now()),
            Err(GateError::DigestMismatch)
        );
    }

    #[test]
    fn late_result_after_deadline_is_discarded() {
        let mut g = GateState::default();
        let a = AttemptId::new(1);
        g.begin(a, d("x")).unwrap();
        let deadline = Instant::now();
        let after = deadline + Duration::from_millis(1);
        assert_eq!(
            g.finish(a, d("x"), d("x"), deadline, after),
            Err(GateError::Expired)
        );
        assert!(!g.is_authenticated_for(d("x")));
    }

    #[test]
    fn abort_only_affects_the_matching_attempt() {
        let mut g = GateState::default();
        g.begin(AttemptId::new(1), d("x")).unwrap();
        g.abort(AttemptId::new(2));
        assert!(matches!(g, GateState::Verifying { .. }));
        g.abort(AttemptId::new(1));
        assert_eq!(g, GateState::Pending);
    }

    #[test]
    fn authenticated_is_not_pending() {
        let mut g = GateState::Authenticated { digest: d("x") };
        assert_eq!(
            g.begin(AttemptId::new(1), d("x")),
            Err(GateError::NotPending)
        );
        g.reset();
        assert_eq!(g, GateState::Pending);
    }
}
