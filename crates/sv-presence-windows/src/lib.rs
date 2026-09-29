//! Windows Hello presence backend (ADR-0025 §5.2).
//!
//! This is the ONLY crate in the workspace allowed to use `unsafe`, for
//! the HWND interop call and `RtlGetVersion`. Every block carries a
//! `// SAFETY:` comment; the lints below make that mandatory. Forbidden by
//! construction: the desktop window as prompt owner, window lookup by
//! title/class, synthetic keyboard input, and any credential-UI password
//! fallback. No password or PIN ever passes through this process.
//!
//! The adapter rules (D13 cancellation, result mapping) live here so they
//! compile and are tested on every OS; `sys.rs` (Windows only) holds the
//! native calls behind [`HelloOps`].
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

use std::sync::Arc;

use sv_presence::{
    Availability, CancelSignal, Modality, OpDescriptor, Outcome, PresenceError, Reason,
};

/// First build with `IUserConsentVerifierInterop::RequestVerificationForWindowAsync`.
pub const MIN_BUILD: u32 = 22000;

/// Returns the HWND (as `isize`) of a live Sovereign Vault window.
pub type WindowProvider = Arc<dyn Fn() -> Option<isize> + Send + Sync>;

/// Platform-neutral mirror of `UserConsentVerificationResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloResult {
    Verified,
    DeviceNotPresent,
    NotConfiguredForUser,
    DisabledByPolicy,
    DeviceBusy,
    RetriesExhausted,
    Canceled,
    Other,
}

/// Platform-neutral mirror of `UserConsentVerifierAvailability`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloAvailability {
    Available,
    DeviceNotPresent,
    NotConfiguredForUser,
    DisabledByPolicy,
    DeviceBusy,
    Other,
}

/// Only `Verified` approves. Hello PIN counts; modality is `unknown` (§8).
pub fn map_result(result: HelloResult) -> Result<Outcome, PresenceError> {
    match result {
        HelloResult::Verified => Ok(Outcome {
            modality: Modality::Unknown,
        }),
        HelloResult::DeviceNotPresent => Err(PresenceError::Unavailable),
        HelloResult::NotConfiguredForUser => Err(PresenceError::NotConfigured),
        HelloResult::DisabledByPolicy => Err(PresenceError::DisabledByPolicy),
        HelloResult::DeviceBusy => Err(PresenceError::Busy),
        HelloResult::RetriesExhausted => Err(PresenceError::Exhausted),
        HelloResult::Canceled => Err(PresenceError::Cancelled),
        HelloResult::Other => Err(PresenceError::Failed),
    }
}

/// Unknown input fails CLOSED: a `None` build applies no build cut, and a
/// `None`/`Other` state is reported as protected — the verification itself
/// decides, and it denies. Only states the OS actually REPORTS can make the
/// system `Unavailable`; a failed probe never degrades to a click.
pub fn map_availability(build: Option<u32>, availability: HelloAvailability) -> Availability {
    if let Some(b) = build {
        if b < MIN_BUILD {
            return Availability::Unavailable(Reason::BelowMinimumBuild);
        }
    }
    match availability {
        HelloAvailability::Available | HelloAvailability::DeviceBusy | HelloAvailability::Other => {
            Availability::Protected {
                modalities: vec![Modality::Unknown],
            }
        }
        HelloAvailability::NotConfiguredForUser => Availability::Unavailable(Reason::NotConfigured),
        HelloAvailability::DisabledByPolicy => Availability::Unavailable(Reason::DisabledByPolicy),
        HelloAvailability::DeviceNotPresent => Availability::Unavailable(Reason::DeviceNotPresent),
    }
}

/// Error from waiting on the native operation (platform-neutral).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloWaitError;

/// One open native prompt.
pub trait HelloPending: Clone + Send + Sync + 'static {
    /// Cancel THIS operation (best effort).
    fn cancel(&self);
    /// Block until the prompt ends (result, or error after a cancel/failure).
    fn wait(&self) -> Result<HelloResult, HelloWaitError>;
}

/// The native calls of one verification, abstracted so the adapter rules
/// are tested on every OS (the real impl is `sys::WinOps`).
pub trait HelloOps: Send + Sync {
    type Pending: HelloPending;
    /// The live Sovereign Vault window; `None` ⇒ Unavailable.
    fn window(&self) -> Option<isize>;
    /// Open the prompt. MUST check `cancel.is_cancelled()` as its last step
    /// before the native call and return `Err(PresenceError::Cancelled)`
    /// without opening if set (D13).
    fn open(
        &self,
        hwnd: isize,
        message: &str,
        cancel: &CancelSignal,
    ) -> Result<Self::Pending, PresenceError>;
}

/// D13 contract, platform-neutral.
pub async fn run_verification<O: HelloOps>(
    ops: &O,
    op: &OpDescriptor,
    cancel: &CancelSignal,
) -> Result<Outcome, PresenceError> {
    if cancel.is_cancelled() {
        return Err(PresenceError::Cancelled);
    }
    let hwnd = ops.window().ok_or(PresenceError::Unavailable)?;
    let message = op.prompt_text();
    let pending = ops.open(hwnd, &message, cancel)?;
    // A cancellation that raced the creation closes THIS operation at once.
    if cancel.is_cancelled() {
        pending.cancel();
    }
    let waiter = pending.clone();
    let mut done = tokio::task::spawn_blocking(move || waiter.wait());
    let waited = tokio::select! {
        waited = &mut done => waited,
        _ = cancel.cancelled() => { pending.cancel(); done.await }
    };
    match waited {
        Ok(Ok(result)) => map_result(result),
        // Preserve the classification: only a cancelled attempt is Cancelled.
        Ok(Err(HelloWaitError)) if cancel.is_cancelled() => Err(PresenceError::Cancelled),
        Ok(Err(HelloWaitError)) => Err(PresenceError::Failed),
        Err(_) => Err(PresenceError::Failed),
    }
}

#[cfg(windows)]
mod sys;
#[cfg(windows)]
pub use sys::WindowsHelloVerifier;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};

    #[test]
    fn only_verified_approves() {
        use HelloResult::*;
        assert_eq!(
            map_result(Verified),
            Ok(Outcome {
                modality: Modality::Unknown
            })
        );
        assert_eq!(
            map_result(DeviceNotPresent),
            Err(PresenceError::Unavailable)
        );
        assert_eq!(
            map_result(NotConfiguredForUser),
            Err(PresenceError::NotConfigured)
        );
        assert_eq!(
            map_result(DisabledByPolicy),
            Err(PresenceError::DisabledByPolicy)
        );
        assert_eq!(map_result(DeviceBusy), Err(PresenceError::Busy));
        assert_eq!(map_result(RetriesExhausted), Err(PresenceError::Exhausted));
        assert_eq!(map_result(Canceled), Err(PresenceError::Cancelled));
        assert_eq!(map_result(Other), Err(PresenceError::Failed));
    }

    #[test]
    fn below_build_22000_is_unavailable_whatever_hello_says() {
        assert_eq!(
            map_availability(Some(21999), HelloAvailability::Available),
            Availability::Unavailable(Reason::BelowMinimumBuild)
        );
        assert_eq!(
            map_availability(Some(22000), HelloAvailability::Available),
            Availability::Protected {
                modalities: vec![Modality::Unknown]
            }
        );
    }

    #[test]
    fn unknown_build_and_unknown_state_fail_closed() {
        assert_eq!(
            map_availability(None, HelloAvailability::Other),
            Availability::Protected {
                modalities: vec![Modality::Unknown]
            }
        );
        assert_eq!(
            map_availability(None, HelloAvailability::Available),
            Availability::Protected {
                modalities: vec![Modality::Unknown]
            }
        );
    }

    #[test]
    fn availability_states_map() {
        assert_eq!(
            map_availability(Some(22631), HelloAvailability::NotConfiguredForUser),
            Availability::Unavailable(Reason::NotConfigured)
        );
        assert_eq!(
            map_availability(Some(22631), HelloAvailability::DisabledByPolicy),
            Availability::Unavailable(Reason::DisabledByPolicy)
        );
        assert_eq!(
            map_availability(Some(22631), HelloAvailability::DeviceNotPresent),
            Availability::Unavailable(Reason::DeviceNotPresent)
        );
        // Busy is transient: the device exists, so the system is protected.
        assert_eq!(
            map_availability(Some(22631), HelloAvailability::DeviceBusy),
            Availability::Protected {
                modalities: vec![Modality::Unknown]
            }
        );
    }

    #[test]
    fn forbidden_apis_are_absent() {
        let src = concat!(include_str!("lib.rs"), include_str!("sys.rs"));
        for forbidden in [
            "GetDesktopWindow",
            "FindWindow",
            "SendInput",
            "keybd_event",
            "CredUIPromptForWindowsCredentials",
            "LogonUser",
        ] {
            let hits = src.matches(forbidden).count();
            // Each name appears exactly once: in this list.
            assert_eq!(hits, 1, "{forbidden} is forbidden by ADR-0025 §5.2");
        }
    }

    // --- fake ops for the platform-neutral adapter ------------------------

    struct Shared {
        opened: AtomicUsize,
        cancels: AtomicUsize,
        cancelled: AtomicBool,
        wait_error: AtomicBool,
        fire_after_create: AtomicBool,
        pause_in_window: AtomicBool,
        result: Mutex<HelloResult>,
        resumed: Mutex<bool>,
        resume_cv: Condvar,
        paused: std::sync::mpsc::Sender<()>,
        fire: Mutex<Option<Arc<tokio::sync::watch::Sender<bool>>>>,
    }

    fn shared_with(paused: std::sync::mpsc::Sender<()>) -> Arc<Shared> {
        Arc::new(Shared {
            opened: AtomicUsize::new(0),
            cancels: AtomicUsize::new(0),
            cancelled: AtomicBool::new(false),
            wait_error: AtomicBool::new(false),
            fire_after_create: AtomicBool::new(false),
            pause_in_window: AtomicBool::new(false),
            result: Mutex::new(HelloResult::Verified),
            resumed: Mutex::new(false),
            resume_cv: Condvar::new(),
            paused,
            fire: Mutex::new(None),
        })
    }

    fn new_shared() -> Arc<Shared> {
        let (tx, _rx) = std::sync::mpsc::channel();
        shared_with(tx)
    }

    #[derive(Clone)]
    struct FakeOps {
        shared: Arc<Shared>,
    }

    #[derive(Clone)]
    struct FakePending {
        shared: Arc<Shared>,
    }

    impl HelloPending for FakePending {
        fn cancel(&self) {
            // Idempotent: the second close of the same operation is a no-op.
            if !self.shared.cancelled.swap(true, Ordering::SeqCst) {
                self.shared.cancels.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn wait(&self) -> Result<HelloResult, HelloWaitError> {
            if self.shared.cancelled.load(Ordering::SeqCst)
                || self.shared.wait_error.load(Ordering::SeqCst)
            {
                Err(HelloWaitError)
            } else {
                Ok(*self.shared.result.lock().unwrap_or_else(|e| e.into_inner()))
            }
        }
    }

    impl HelloOps for FakeOps {
        type Pending = FakePending;

        fn window(&self) -> Option<isize> {
            if self.shared.pause_in_window.load(Ordering::SeqCst) {
                let _ = self.shared.paused.send(());
                let mut guard = self
                    .shared
                    .resumed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                while !*guard {
                    guard = self
                        .shared
                        .resume_cv
                        .wait(guard)
                        .unwrap_or_else(|e| e.into_inner());
                }
            }
            Some(1)
        }

        fn open(
            &self,
            _hwnd: isize,
            _message: &str,
            cancel: &CancelSignal,
        ) -> Result<FakePending, PresenceError> {
            // Honours the trait contract: the cancel check is the LAST step
            // before "opening" — a cancelled attempt never opens a prompt.
            if cancel.is_cancelled() {
                return Err(PresenceError::Cancelled);
            }
            self.shared.opened.fetch_add(1, Ordering::SeqCst);
            if self.shared.fire_after_create.load(Ordering::SeqCst) {
                // A cancellation that lands right after creation.
                let fire = self
                    .shared
                    .fire
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                if let Some(fire) = fire {
                    fire.send_replace(true);
                }
            }
            Ok(FakePending {
                shared: Arc::clone(&self.shared),
            })
        }
    }

    #[test]
    fn cancelled_before_open_never_opens() {
        let (paused_tx, paused_rx) = std::sync::mpsc::channel();
        let shared = shared_with(paused_tx);
        shared.pause_in_window.store(true, Ordering::SeqCst);
        let ops = FakeOps {
            shared: Arc::clone(&shared),
        };
        let (tx, cancel) = CancelSignal::new();
        let cancel_task = cancel.clone();
        let op = OpDescriptor::new("read_file");
        let worker = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(run_verification(&ops, &op, &cancel_task))
        });
        paused_rx.recv().unwrap();
        tx.send_replace(true);
        *shared.resumed.lock().unwrap_or_else(|e| e.into_inner()) = true;
        shared.resume_cv.notify_all();
        assert_eq!(worker.join().unwrap(), Err(PresenceError::Cancelled));
        assert_eq!(shared.opened.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn open_checks_cancel_last() {
        let (paused_tx, paused_rx) = std::sync::mpsc::channel();
        let shared = shared_with(paused_tx);
        shared.pause_in_window.store(true, Ordering::SeqCst);
        // An approval IS scripted: if the prompt ever opened it would pass.
        *shared.result.lock().unwrap_or_else(|e| e.into_inner()) = HelloResult::Verified;
        let ops = FakeOps {
            shared: Arc::clone(&shared),
        };
        let (tx, cancel) = CancelSignal::new();
        let cancel_task = cancel.clone();
        let op = OpDescriptor::new("read_file");
        let worker = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(run_verification(&ops, &op, &cancel_task))
        });
        paused_rx.recv().unwrap();
        // The cancellation lands between window() and open().
        tx.send_replace(true);
        *shared.resumed.lock().unwrap_or_else(|e| e.into_inner()) = true;
        shared.resume_cv.notify_all();
        assert_eq!(worker.join().unwrap(), Err(PresenceError::Cancelled));
        assert_eq!(shared.opened.load(Ordering::SeqCst), 0);
        assert_eq!(shared.cancels.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cancellation_racing_creation_cancels_the_operation() {
        let shared = new_shared();
        shared.fire_after_create.store(true, Ordering::SeqCst);
        let (tx, cancel) = CancelSignal::new();
        *shared.fire.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(tx));
        let ops = FakeOps {
            shared: Arc::clone(&shared),
        };
        let result = run_verification(&ops, &OpDescriptor::new("read_file"), &cancel).await;
        assert_eq!(result, Err(PresenceError::Cancelled));
        assert_eq!(shared.opened.load(Ordering::SeqCst), 1);
        assert_eq!(shared.cancels.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn wait_error_without_cancel_is_failed_not_cancelled() {
        let (_tx, cancel) = CancelSignal::new();
        let shared = new_shared();
        shared.wait_error.store(true, Ordering::SeqCst);
        let ops = FakeOps {
            shared: Arc::clone(&shared),
        };
        assert_eq!(
            run_verification(&ops, &OpDescriptor::new("read_file"), &cancel).await,
            Err(PresenceError::Failed)
        );
        assert_eq!(shared.opened.load(Ordering::SeqCst), 1);
        assert_eq!(shared.cancels.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn only_verified_approves_through_run_verification() {
        let (_tx, cancel) = CancelSignal::new();
        let shared = new_shared();
        let ops = FakeOps {
            shared: Arc::clone(&shared),
        };
        assert_eq!(
            run_verification(&ops, &OpDescriptor::new("read_file"), &cancel).await,
            Ok(Outcome {
                modality: Modality::Unknown
            })
        );
        let shared = new_shared();
        *shared.result.lock().unwrap_or_else(|e| e.into_inner()) = HelloResult::DisabledByPolicy;
        let ops = FakeOps {
            shared: Arc::clone(&shared),
        };
        assert_eq!(
            run_verification(&ops, &OpDescriptor::new("read_file"), &cancel).await,
            Err(PresenceError::DisabledByPolicy)
        );
    }
}
