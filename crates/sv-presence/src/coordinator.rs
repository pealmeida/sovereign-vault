//! One native prompt at a time, behind a bounded queue (ADR-0025 §6.1),
//! with per-attempt cancellation signals (plan D13).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{oneshot, watch, Semaphore};

use crate::gate::AttemptId;
use crate::{
    Availability, CancelSignal, OpDescriptor, OpDigest, Outcome, PresenceError, PresenceVerifier,
    Reason,
};

/// Requests allowed to wait while one prompt is active.
pub const MAX_WAITING: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    Protected,
    Unprotected(Reason),
}

impl Classification {
    pub fn is_protected(&self) -> bool {
        matches!(self, Self::Protected)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// Back to `Pending`; the user may try again (§6.2).
    Retryable(PresenceError),
    /// The request is denied (§6.2 mid-attempt unavailability).
    Denied(PresenceError),
    /// The deadline passed (while waiting, or with the prompt open).
    Expired,
    /// The 9th waiter while one prompt is active (§6.1).
    QueueFull,
    /// The owner invalidated the attempt: refusal, lock, or disconnect.
    Invalidated,
}

impl Denial {
    pub fn message(&self) -> String {
        match self {
            Self::Retryable(e) => format!("presence not confirmed: {e}; you can try again"),
            Self::Denied(e) => format!("presence verification denied: {e}"),
            Self::Expired => "presence verification expired".to_string(),
            Self::QueueFull => {
                "queue_full: too many requests are waiting for presence verification".to_string()
            }
            Self::Invalidated => {
                "presence verification invalidated: the request was refused, expired, or the vault locked"
                    .to_string()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    pub attempt: AttemptId,
    pub digest: OpDigest,
    pub outcome: Outcome,
}

type Registry = Arc<Mutex<HashMap<AttemptId, Arc<watch::Sender<bool>>>>>;

/// One verification attempt, registered for invalidation until dropped.
pub struct Attempt {
    id: AttemptId,
    fire: Arc<watch::Sender<bool>>,
    cancel: CancelSignal,
    registry: Registry,
}

impl Attempt {
    pub fn id(&self) -> AttemptId {
        self.id
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        // An abandoned attempt (e.g. its owner's future was aborted) must
        // still close its prompt where the backend can. Harmless after the
        // backend already returned.
        self.fire.send_replace(true);
        self.registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}

/// A queue place, returned on drop even if the waiting future is aborted.
struct QueuePlace(Arc<AtomicUsize>);

impl Drop for QueuePlace {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct PresenceCoordinator {
    verifier: Arc<dyn PresenceVerifier>,
    slot: Arc<Semaphore>,
    waiting: Arc<AtomicUsize>,
    seen_protected: AtomicBool,
    next_attempt: AtomicU64,
    registry: Registry,
}

impl PresenceCoordinator {
    pub fn new(verifier: Arc<dyn PresenceVerifier>) -> Self {
        Self {
            verifier,
            slot: Arc::new(Semaphore::new(1)),
            waiting: Arc::new(AtomicUsize::new(0)),
            seen_protected: AtomicBool::new(false),
            next_attempt: AtomicU64::new(0),
            registry: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a new attempt. Owners call this under their own lock, at
    /// `Pending -> Verifying`, so an invalidation can never be lost.
    pub fn begin_attempt(&self) -> Attempt {
        let id = AttemptId::new(self.next_attempt.fetch_add(1, Ordering::SeqCst) + 1);
        let (fire, cancel) = CancelSignal::new();
        let fire = Arc::new(fire);
        self.registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, Arc::clone(&fire));
        Attempt {
            id,
            fire,
            cancel,
            registry: Arc::clone(&self.registry),
        }
    }

    /// Classify a request at creation (§6.2). Sticky (plan D2): once this
    /// process has seen `Protected`, a later `Unavailable` still classifies
    /// as `Protected`, so `verify` denies instead of a click being offered.
    pub fn classify(&self) -> Classification {
        match self.verifier.availability() {
            Availability::Protected { .. } => {
                self.seen_protected.store(true, Ordering::SeqCst);
                Classification::Protected
            }
            Availability::Unavailable(_) if self.seen_protected.load(Ordering::SeqCst) => {
                Classification::Protected
            }
            Availability::Unavailable(reason) => Classification::Unprotected(reason),
        }
    }

    /// Invalidate one attempt (refusal, lock, disconnect) by firing ITS
    /// signal. Queued: it leaves the queue without prompting. Not yet
    /// opened: the backend never opens it. Open: the backend cancels that
    /// operation only; the slot stays occupied until the prompt ends.
    pub fn invalidate(&self, id: AttemptId) {
        let fire = self
            .registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .cloned();
        if let Some(fire) = fire {
            fire.send_replace(true);
        }
    }

    pub async fn verify(
        &self,
        attempt: &Attempt,
        op: &OpDescriptor,
        deadline: Instant,
    ) -> Result<Verified, Denial> {
        let id = attempt.id;
        let permit = match Arc::clone(&self.slot).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let before = self.waiting.fetch_add(1, Ordering::SeqCst);
                let _place = QueuePlace(Arc::clone(&self.waiting));
                if before >= MAX_WAITING {
                    return Err(Denial::QueueFull);
                }
                tokio::select! {
                    biased;
                    _ = attempt.cancel.cancelled() => return Err(Denial::Invalidated),
                    _ = tokio::time::sleep(remaining(deadline)) => return Err(Denial::Expired),
                    acquired = Arc::clone(&self.slot).acquire_owned() => match acquired {
                        Ok(permit) => permit,
                        Err(_) => return Err(Denial::Denied(PresenceError::Unavailable)),
                    },
                }
            }
        };
        if attempt.cancel.is_cancelled() {
            return Err(Denial::Invalidated);
        }
        if Instant::now() >= deadline {
            return Err(Denial::Expired);
        }

        let digest = op.digest();
        let (tx, rx) = oneshot::channel();
        let verifier = Arc::clone(&self.verifier);
        let cancel = attempt.cancel.clone();
        let op = op.clone();
        tokio::spawn(async move {
            let result = verifier.verify(&op, &cancel).await;
            // Released only now, when the backend reports the native prompt
            // ended — never merely because the attempt was invalidated.
            drop(permit);
            let _ = tx.send(result);
        });

        tokio::select! {
            biased;
            _ = attempt.cancel.cancelled() => Err(Denial::Invalidated),
            _ = tokio::time::sleep(remaining(deadline)) => {
                // Ask the backend to close this attempt's prompt.
                attempt.fire.send_replace(true);
                Err(Denial::Expired)
            }
            got = rx => match got {
                Ok(Ok(outcome)) => Ok(Verified { attempt: id, digest, outcome }),
                Ok(Err(PresenceError::Timeout)) => Err(Denial::Expired),
                Ok(Err(e)) if e.is_retryable() => Err(Denial::Retryable(e)),
                Ok(Err(e)) => Err(Denial::Denied(e)),
                Err(_) => Err(Denial::Denied(PresenceError::Failed)),
            },
        }
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeStep, FakeVerifier, APPROVED};
    use crate::{Availability, Modality};
    use std::time::Duration;

    fn op() -> OpDescriptor {
        OpDescriptor::new("read_file").field("file", "a.txt")
    }

    fn in_ms(ms: u64) -> Instant {
        Instant::now() + Duration::from_millis(ms)
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    /// Start one verification on a spawned task; returns its attempt id.
    fn spawn_verify(
        c: &Arc<PresenceCoordinator>,
        deadline: Instant,
    ) -> (AttemptId, tokio::task::JoinHandle<Result<Verified, Denial>>) {
        let attempt = c.begin_attempt();
        let id = attempt.id();
        let c = c.clone();
        (
            id,
            tokio::spawn(async move { c.verify(&attempt, &op(), deadline).await }),
        )
    }

    #[tokio::test]
    async fn approval_carries_the_digest_it_was_granted_for() {
        let fake = FakeVerifier::protected();
        fake.approve_next();
        let c = PresenceCoordinator::new(fake.clone());
        let a = c.begin_attempt();
        let v = c.verify(&a, &op(), in_ms(1_000)).await.unwrap();
        assert_eq!(v.digest, op().digest());
        assert_eq!(v.attempt, a.id());
        assert_eq!(v.outcome.modality, Modality::Unknown);
    }

    #[tokio::test]
    async fn error_classes_map_per_section_9_1() {
        for (err, expected) in [
            (
                PresenceError::Cancelled,
                Denial::Retryable(PresenceError::Cancelled),
            ),
            (
                PresenceError::Exhausted,
                Denial::Retryable(PresenceError::Exhausted),
            ),
            (
                PresenceError::Unavailable,
                Denial::Denied(PresenceError::Unavailable),
            ),
            (
                PresenceError::DisabledByPolicy,
                Denial::Denied(PresenceError::DisabledByPolicy),
            ),
            (
                PresenceError::NotConfigured,
                Denial::Denied(PresenceError::NotConfigured),
            ),
            (PresenceError::Timeout, Denial::Expired),
        ] {
            let fake = FakeVerifier::protected();
            fake.push(FakeStep::Return(Err(err)));
            let c = PresenceCoordinator::new(fake);
            let got = c.verify(&c.begin_attempt(), &op(), in_ms(1_000)).await;
            assert_eq!(got.unwrap_err(), expected, "{err:?}");
        }
    }

    #[tokio::test]
    async fn one_verification_satisfies_exactly_one_call() {
        let fake = FakeVerifier::protected();
        fake.approve_next();
        let c = PresenceCoordinator::new(fake.clone());
        assert!(c
            .verify(&c.begin_attempt(), &op(), in_ms(1_000))
            .await
            .is_ok());
        // Nothing is cached: the next call prompts again and, unscripted, fails.
        assert!(c
            .verify(&c.begin_attempt(), &op(), in_ms(1_000))
            .await
            .is_err());
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn deadline_expires_while_prompt_is_open() {
        let fake = FakeVerifier::protected();
        fake.push(FakeStep::Hold(APPROVED));
        let c = PresenceCoordinator::new(fake.clone());
        let got = c.verify(&c.begin_attempt(), &op(), in_ms(50)).await;
        assert_eq!(got.unwrap_err(), Denial::Expired);
        // The late approval is discarded: releasing it changes nothing here.
        fake.release();
    }

    #[tokio::test]
    async fn slot_held_until_backend_ends_without_cancel() {
        let fake = FakeVerifier::protected(); // cancel unsupported
        fake.push(FakeStep::Hold(APPROVED)); // A
        fake.approve_next(); // B
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        assert_eq!(
            c.verify(&c.begin_attempt(), &op(), in_ms(50))
                .await
                .unwrap_err(),
            Denial::Expired
        );
        let (_, b) = spawn_verify(&c, in_ms(2_000));
        settle().await;
        assert_eq!(
            fake.calls(),
            1,
            "B must not reach the backend while A's prompt is open"
        );
        fake.release(); // A's native prompt finally ends
        assert!(b.await.unwrap().is_ok());
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn expiry_requests_native_cancel_when_supported() {
        let fake = FakeVerifier::protected();
        fake.set_cancel_supported(true);
        fake.push(FakeStep::Hold(APPROVED));
        fake.approve_next();
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        assert_eq!(
            c.verify(&c.begin_attempt(), &op(), in_ms(50))
                .await
                .unwrap_err(),
            Denial::Expired
        );
        settle().await;
        assert_eq!(fake.cancels(), 1);
        assert!(c
            .verify(&c.begin_attempt(), &op(), in_ms(2_000))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn queue_full_denies_the_ninth_waiter_only() {
        let fake = FakeVerifier::protected();
        fake.push(FakeStep::Hold(APPROVED)); // the active prompt
        for _ in 0..MAX_WAITING {
            fake.approve_next();
        }
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        let (_, active) = spawn_verify(&c, in_ms(5_000));
        settle().await;
        let waiters: Vec<_> = (0..MAX_WAITING)
            .map(|_| spawn_verify(&c, in_ms(5_000)).1)
            .collect();
        settle().await;
        assert_eq!(
            c.verify(&c.begin_attempt(), &op(), in_ms(5_000))
                .await
                .unwrap_err(),
            Denial::QueueFull
        );
        fake.release();
        assert!(active.await.unwrap().is_ok());
        for w in waiters {
            assert!(
                w.await.unwrap().is_ok(),
                "queued requests are unaffected by the refusal"
            );
        }
    }

    #[tokio::test]
    async fn waiting_request_expires_without_reaching_the_backend() {
        let fake = FakeVerifier::protected();
        fake.push(FakeStep::Hold(APPROVED));
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        let _active = spawn_verify(&c, in_ms(5_000));
        settle().await;
        assert_eq!(
            c.verify(&c.begin_attempt(), &op(), in_ms(50))
                .await
                .unwrap_err(),
            Denial::Expired
        );
        assert_eq!(fake.calls(), 1);
        fake.release();
    }

    /// D13: a request refused (or locked) while queued never prompts.
    #[tokio::test]
    async fn invalidated_while_queued_never_prompts() {
        let fake = FakeVerifier::protected();
        fake.push(FakeStep::Hold(APPROVED));
        fake.approve_next(); // would be B's result if B ever prompted
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        let (_, active) = spawn_verify(&c, in_ms(5_000));
        settle().await;
        let (b_id, b) = spawn_verify(&c, in_ms(5_000));
        settle().await;
        c.invalidate(b_id);
        assert_eq!(b.await.unwrap().unwrap_err(), Denial::Invalidated);
        fake.release();
        assert!(active.await.unwrap().is_ok());
        settle().await;
        assert_eq!(fake.opened(), 1, "B never opened a prompt");
    }

    /// D13: invalidation that races ahead of `verify` is not lost.
    #[tokio::test]
    async fn invalidated_before_verify_starts_never_prompts() {
        let fake = FakeVerifier::protected();
        fake.approve_next();
        let c = PresenceCoordinator::new(fake.clone());
        let a = c.begin_attempt();
        c.invalidate(a.id());
        assert_eq!(
            c.verify(&a, &op(), in_ms(1_000)).await.unwrap_err(),
            Denial::Invalidated
        );
        assert_eq!(fake.calls(), 0);
    }

    #[tokio::test]
    async fn invalidating_the_active_attempt_requests_native_cancel() {
        let fake = FakeVerifier::protected();
        fake.set_cancel_supported(true);
        fake.push(FakeStep::Hold(APPROVED));
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        let (id, a) = spawn_verify(&c, in_ms(5_000));
        settle().await;
        c.invalidate(id);
        assert_eq!(a.await.unwrap().unwrap_err(), Denial::Invalidated);
        // Bounded wait: advance only when the backend confirmed the cancel.
        let confirmed = tokio::time::timeout(Duration::from_secs(2), async {
            while fake.cancels() != 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            confirmed.is_ok(),
            "the backend never confirmed the cancellation"
        );
        assert_eq!(fake.cancels(), 1);
    }

    /// D13: cancelling a finished attempt never reaches the next prompt.
    #[tokio::test]
    async fn cancel_never_reaches_the_next_attempt() {
        let fake = FakeVerifier::protected();
        fake.set_cancel_supported(true);
        fake.approve_next(); // A finishes at once
        fake.push(FakeStep::Hold(APPROVED)); // B stays open
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        let a = c.begin_attempt();
        let a_id = a.id();
        assert!(c.verify(&a, &op(), in_ms(1_000)).await.is_ok());
        let (_, b) = spawn_verify(&c, in_ms(5_000));
        settle().await;
        c.invalidate(a_id);
        assert_eq!(
            fake.cancels(),
            0,
            "A is no longer active; B must not be cancelled"
        );
        fake.release();
        assert!(b.await.unwrap().is_ok());
    }

    /// D13: aborted waiters give their queue place back (RAII guard).
    #[tokio::test]
    async fn aborted_waiters_do_not_leak_queue_places() {
        let fake = FakeVerifier::protected();
        fake.push(FakeStep::Hold(APPROVED));
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        let _active = spawn_verify(&c, in_ms(10_000));
        settle().await;
        for _round in 0..3 {
            let waiters: Vec<_> = (0..MAX_WAITING)
                .map(|_| spawn_verify(&c, in_ms(10_000)).1)
                .collect();
            settle().await;
            for w in &waiters {
                w.abort();
            }
            settle().await;
        }
        // With leaked places this would be QueueFull.
        assert_eq!(
            c.verify(&c.begin_attempt(), &op(), in_ms(50))
                .await
                .unwrap_err(),
            Denial::Expired
        );
        fake.release();
    }

    /// D13: invalidation landing between queue admission and the backend
    /// opening its prompt never opens it (barrier interleaving).
    #[tokio::test]
    async fn invalidated_between_admission_and_open_never_opens() {
        let fake = FakeVerifier::protected();
        fake.approve_next();
        fake.pause_before_open();
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        let (id, task) = spawn_verify(&c, in_ms(5_000));
        fake.wait_until_paused().await;
        c.invalidate(id);
        fake.resume();
        assert_eq!(task.await.unwrap().unwrap_err(), Denial::Invalidated);
        settle().await;
        assert_eq!(
            fake.opened(),
            0,
            "the backend saw the signal before opening"
        );
    }

    /// An owner aborted after the prompt opened still cancels it (the
    /// `Attempt` drop fires the signal).
    #[tokio::test]
    async fn aborted_owner_cancels_its_open_prompt() {
        let fake = FakeVerifier::protected();
        fake.set_cancel_supported(true);
        fake.push(FakeStep::Hold(APPROVED));
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        let (_, task) = spawn_verify(&c, in_ms(5_000));
        settle().await;
        assert_eq!(fake.opened(), 1);
        task.abort();
        // Bounded wait: advance only when the backend confirmed the cancel.
        let confirmed = tokio::time::timeout(Duration::from_secs(2), async {
            while fake.cancels() != 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            confirmed.is_ok(),
            "the backend never confirmed the cancellation"
        );
        assert_eq!(fake.cancels(), 1);
    }

    #[test]
    fn classification_is_sticky_once_protected() {
        let fake = FakeVerifier::protected();
        let c = PresenceCoordinator::new(fake.clone());
        assert_eq!(c.classify(), Classification::Protected);
        fake.set_availability(Availability::Unavailable(Reason::NotConfigured));
        assert_eq!(
            c.classify(),
            Classification::Protected,
            "D2: never downgrade in-process"
        );
    }

    #[test]
    fn unavailable_from_start_classifies_unprotected() {
        let c = PresenceCoordinator::new(FakeVerifier::unavailable());
        assert_eq!(
            c.classify(),
            Classification::Unprotected(Reason::UnsupportedPlatform)
        );
    }

    #[test]
    fn queue_full_message_names_the_reason() {
        assert!(Denial::QueueFull.message().starts_with("queue_full"));
    }
}
