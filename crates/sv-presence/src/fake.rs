//! Scriptable verifier for coordinator and desktop tests. It proves nothing
//! about the real OS prompt (spec §9.2); the manual cases in
//! `docs/testing/presence-manual-cases.md` do. It honours the cancellation
//! contract of `PresenceVerifier::verify` exactly as real backends must.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use crate::{
    Availability, CancelSignal, Modality, OpDescriptor, Outcome, PresenceError, PresenceVerifier,
    Reason,
};

#[derive(Debug, Clone, Copy)]
pub enum FakeStep {
    /// Return immediately.
    Return(Result<Outcome, PresenceError>),
    /// Keep the "prompt" open until [`FakeVerifier::release`], or until the
    /// attempt is cancelled when cancellation is supported (`Cancelled`).
    Hold(Result<Outcome, PresenceError>),
}

pub const APPROVED: Result<Outcome, PresenceError> = Ok(Outcome {
    modality: Modality::Unknown,
});

pub struct FakeVerifier {
    availability: Mutex<Availability>,
    script: Mutex<VecDeque<FakeStep>>,
    /// `verify` was entered.
    calls: AtomicUsize,
    /// A "native prompt" was actually opened.
    opened: AtomicUsize,
    /// Open prompts closed by cancellation.
    cancels: AtomicUsize,
    cancel_supported: AtomicBool,
    release: Notify,
    pause_before_open: AtomicBool,
    paused: Notify,
    resume: Notify,
}

impl FakeVerifier {
    pub fn with_availability(availability: Availability) -> Arc<Self> {
        Arc::new(Self {
            availability: Mutex::new(availability),
            script: Mutex::new(VecDeque::new()),
            calls: AtomicUsize::new(0),
            opened: AtomicUsize::new(0),
            cancels: AtomicUsize::new(0),
            cancel_supported: AtomicBool::new(false),
            release: Notify::new(),
            pause_before_open: AtomicBool::new(false),
            paused: Notify::new(),
            resume: Notify::new(),
        })
    }

    pub fn protected() -> Arc<Self> {
        Self::with_availability(Availability::Protected {
            modalities: vec![Modality::Unknown],
        })
    }

    pub fn unavailable() -> Arc<Self> {
        Self::with_availability(Availability::Unavailable(Reason::UnsupportedPlatform))
    }

    pub fn set_availability(&self, availability: Availability) {
        *self.availability.lock().unwrap_or_else(|e| e.into_inner()) = availability;
    }

    pub fn push(&self, step: FakeStep) {
        self.script
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(step);
    }

    pub fn approve_next(&self) {
        self.push(FakeStep::Return(APPROVED));
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub fn opened(&self) -> usize {
        self.opened.load(Ordering::SeqCst)
    }

    pub fn cancels(&self) -> usize {
        self.cancels.load(Ordering::SeqCst)
    }

    pub fn set_cancel_supported(&self, supported: bool) {
        self.cancel_supported.store(supported, Ordering::SeqCst);
    }

    /// End one held prompt with its scripted result.
    pub fn release(&self) {
        self.release.notify_one();
    }

    /// Make the next `verify` stop just before it would open the prompt
    /// (a barrier for interleaving tests).
    pub fn pause_before_open(&self) {
        self.pause_before_open.store(true, Ordering::SeqCst);
    }

    /// Wait until a `verify` reached the barrier.
    pub async fn wait_until_paused(&self) {
        self.paused.notified().await;
    }

    pub fn resume(&self) {
        self.pause_before_open.store(false, Ordering::SeqCst);
        self.resume.notify_one();
    }
}

#[async_trait::async_trait]
impl PresenceVerifier for FakeVerifier {
    fn availability(&self) -> Availability {
        self.availability
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    async fn verify(
        &self,
        _op: &OpDescriptor,
        cancel: &CancelSignal,
    ) -> Result<Outcome, PresenceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.pause_before_open.load(Ordering::SeqCst) {
            self.paused.notify_one();
            self.resume.notified().await;
        }
        // The contract: never open a prompt for a cancelled attempt.
        if cancel.is_cancelled() {
            return Err(PresenceError::Cancelled);
        }
        self.opened.fetch_add(1, Ordering::SeqCst);
        let step = self
            .script
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
            // An unscripted prompt fails: a test that forgot to script an
            // approval must never pass by accident.
            .unwrap_or(FakeStep::Return(Err(PresenceError::Failed)));
        match step {
            FakeStep::Return(result) => result,
            FakeStep::Hold(result) => {
                let cancellable = self.cancel_supported.load(Ordering::SeqCst);
                tokio::select! {
                    _ = self.release.notified() => result,
                    _ = cancel.cancelled(), if cancellable => {
                        self.cancels.fetch_add(1, Ordering::SeqCst);
                        Err(PresenceError::Cancelled)
                    }
                }
            }
        }
    }
}
