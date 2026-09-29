//! macOS backend (ADR-0025 §5.1), written against a boundary trait so the
//! adapter rules are tested on every OS; `robius.rs` is the real boundary.
//!
//! Adapter rules: `start()` returning `Ok` means only "the prompt started";
//! the result arrives on the completion; a start error is a denial-class
//! error; a missing completion is handled by the coordinator's deadline,
//! and a late completion is discarded there (§6.1). An open LocalAuthentication
//! prompt cannot be cancelled through robius 0.3.1 (declared residual).

use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;

use crate::{
    Availability, CancelSignal, Modality, OpDescriptor, Outcome, PresenceError, PresenceVerifier,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaError {
    UserCanceled,
    AppCanceled,
    SystemCanceled,
    Authentication,
    Exhausted,
    Unavailable,
    NotEnrolled,
    PasscodeNotSet,
    NotInteractive,
    Other,
}

pub fn map_la_error(error: LaError) -> PresenceError {
    match error {
        LaError::UserCanceled | LaError::AppCanceled | LaError::SystemCanceled => {
            PresenceError::Cancelled
        }
        LaError::Authentication | LaError::Other => PresenceError::Failed,
        LaError::Exhausted => PresenceError::Exhausted,
        LaError::NotEnrolled | LaError::PasscodeNotSet => PresenceError::NotConfigured,
        LaError::Unavailable | LaError::NotInteractive => PresenceError::Unavailable,
    }
}

/// Called at most once with the prompt's final result.
pub type Completion = Box<dyn Fn(Result<(), LaError>) + Send + 'static>;

pub trait LaBoundary: Send + Sync + 'static {
    /// Start the native prompt with `reason` as its text. `Ok(())` means the
    /// prompt STARTED; success or failure arrives only through `done`.
    fn start(&self, reason: &str, done: Completion) -> Result<(), LaError>;
}

pub struct MacVerifier<B: LaBoundary> {
    boundary: B,
}

impl<B: LaBoundary> MacVerifier<B> {
    pub fn new(boundary: B) -> Self {
        Self { boundary }
    }
}

#[async_trait::async_trait]
impl<B: LaBoundary> PresenceVerifier for MacVerifier<B> {
    /// Plan D1: robius has no prompt-free probe and this crate forbids
    /// `unsafe`, so availability is assumed; a start-time `NotEnrolled` /
    /// `PasscodeNotSet` / `Unavailable` then DENIES the request (§6.2).
    fn availability(&self) -> Availability {
        Availability::Protected {
            modalities: vec![Modality::Unknown],
        }
    }

    async fn verify(
        &self,
        op: &OpDescriptor,
        cancel: &CancelSignal,
    ) -> Result<Outcome, PresenceError> {
        // D13 contract: never open a prompt for a cancelled attempt. robius
        // 0.3.1 exposes no way to cancel an OPEN prompt, so a cancellation
        // that lands after this check — including in the instant before
        // `start()` — lets the prompt run until the user or the system ends
        // it (declared residual, D13). The slot stays occupied meanwhile
        // (spec §6.1), and the coordinator discards the result.
        if cancel.is_cancelled() {
            return Err(PresenceError::Cancelled);
        }
        let (tx, rx) = oneshot::channel::<Result<(), LaError>>();
        let tx = Mutex::new(Some(tx));
        let done: Completion = Box::new(move |result| {
            if let Some(tx) = tx.lock().unwrap_or_else(|e| e.into_inner()).take() {
                let _ = tx.send(result);
            }
        });
        self.boundary
            .start(&op.prompt_text(), done)
            .map_err(map_la_error)?;
        match rx.await {
            // The completion carries no modality; never infer one (§8).
            Ok(Ok(())) => Ok(Outcome {
                modality: Modality::Unknown,
            }),
            Ok(Err(error)) => Err(map_la_error(error)),
            // The boundary dropped the completion without calling it.
            Err(_) => Err(PresenceError::Failed),
        }
    }
}

// Lets tests share a boundary with the verifier.
impl<B: LaBoundary> LaBoundary for Arc<B> {
    fn start(&self, reason: &str, done: Completion) -> Result<(), LaError> {
        (**self).start(reason, done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    /// Stores the completion instead of calling it, so the test decides when
    /// (and whether) the "native prompt" finishes.
    #[derive(Default)]
    struct FakeLa {
        start_error: Option<LaError>,
        started: std::sync::atomic::AtomicUsize,
        /// Barrier: notified once `start()` has stored the completion.
        started_signal: tokio::sync::Notify,
        completion: StdMutex<Option<Completion>>,
    }

    fn live() -> CancelSignal {
        // Keep the sender alive for the whole test: a closed sender counts
        // as cancelled.
        let (tx, cancel) = CancelSignal::new();
        std::mem::forget(tx);
        cancel
    }

    // Implemented for `FakeLa`; the tests pass `Arc<FakeLa>` through the
    // blanket `impl LaBoundary for Arc<B>` so they keep a handle on it.
    impl LaBoundary for FakeLa {
        fn start(&self, _reason: &str, done: Completion) -> Result<(), LaError> {
            self.started
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(e) = self.start_error {
                return Err(e);
            }
            *self.completion.lock().unwrap() = Some(done);
            self.started_signal.notify_one();
            Ok(())
        }
    }

    fn op() -> OpDescriptor {
        OpDescriptor::new("approve_request").field("action", "ReadFile")
    }

    #[tokio::test]
    async fn start_ok_is_not_success() {
        let la = Arc::new(FakeLa::default());
        let v = MacVerifier::new(la.clone());
        let pending =
            tokio::time::timeout(Duration::from_millis(100), v.verify(&op(), &live())).await;
        assert!(
            pending.is_err(),
            "Ok from start() must not resolve the verification"
        );
    }

    #[tokio::test]
    async fn completion_ok_verifies_with_unknown_modality() {
        let la = Arc::new(FakeLa::default());
        let v = Arc::new(MacVerifier::new(la.clone()));
        let v2 = v.clone();
        let task = tokio::spawn(async move { v2.verify(&op(), &live()).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let done = la.completion.lock().unwrap().take().unwrap();
        done(Ok(()));
        done(Ok(())); // a second callback is ignored, not a panic
        assert_eq!(
            task.await.unwrap(),
            Ok(Outcome {
                modality: Modality::Unknown
            })
        );
    }

    #[tokio::test]
    async fn start_error_is_a_denial_class_error() {
        for (e, expected) in [
            (LaError::NotEnrolled, PresenceError::NotConfigured),
            (LaError::PasscodeNotSet, PresenceError::NotConfigured),
            (LaError::Unavailable, PresenceError::Unavailable),
        ] {
            let la = Arc::new(FakeLa {
                start_error: Some(e),
                ..Default::default()
            });
            assert_eq!(
                MacVerifier::new(la).verify(&op(), &live()).await,
                Err(expected)
            );
        }
    }

    #[tokio::test]
    async fn dropped_completion_is_failure() {
        let la = Arc::new(FakeLa::default());
        let v = Arc::new(MacVerifier::new(la.clone()));
        let v2 = v.clone();
        let task = tokio::spawn(async move { v2.verify(&op(), &live()).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(la.completion.lock().unwrap().take());
        assert_eq!(task.await.unwrap(), Err(PresenceError::Failed));
    }

    /// D13: a cancelled attempt never starts LocalAuthentication.
    #[tokio::test]
    async fn cancelled_attempt_never_starts_the_prompt() {
        let la = Arc::new(FakeLa::default());
        let (tx, cancel) = CancelSignal::new();
        tx.send_replace(true);
        let got = MacVerifier::new(la.clone()).verify(&op(), &cancel).await;
        assert_eq!(got, Err(PresenceError::Cancelled));
        assert_eq!(la.started.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// D13 residual, pinned: a cancellation after `start()` cannot close
    /// the prompt; `verify` still returns only when the prompt ends.
    #[tokio::test]
    async fn cancellation_after_start_waits_for_the_prompt_to_end() {
        let la = Arc::new(FakeLa::default());
        let v = Arc::new(MacVerifier::new(la.clone()));
        let (tx, cancel) = CancelSignal::new();
        let v2 = v.clone();
        let mut task = tokio::spawn(async move { v2.verify(&op(), &cancel).await });
        la.started_signal.notified().await; // start() has run: the prompt is open
        tx.send_replace(true);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut task)
                .await
                .is_err(),
            "an open LocalAuthentication prompt cannot be cancelled"
        );
        let done = la.completion.lock().unwrap().take().unwrap();
        done(Err(LaError::UserCanceled));
        assert_eq!(task.await.unwrap(), Err(PresenceError::Cancelled));
    }

    #[test]
    fn error_mapping_follows_section_9_1() {
        use LaError::*;
        assert_eq!(map_la_error(UserCanceled), PresenceError::Cancelled);
        assert_eq!(map_la_error(AppCanceled), PresenceError::Cancelled);
        assert_eq!(map_la_error(SystemCanceled), PresenceError::Cancelled);
        assert_eq!(map_la_error(Authentication), PresenceError::Failed);
        assert_eq!(map_la_error(Exhausted), PresenceError::Exhausted);
        assert_eq!(map_la_error(NotInteractive), PresenceError::Unavailable);
        assert_eq!(map_la_error(Other), PresenceError::Failed);
    }

    #[test]
    fn availability_is_protected_unknown_per_d1() {
        let v = MacVerifier::new(Arc::new(FakeLa::default()));
        assert_eq!(
            v.availability(),
            Availability::Protected {
                modalities: vec![Modality::Unknown]
            }
        );
    }
}
