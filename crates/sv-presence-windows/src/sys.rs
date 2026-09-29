use sv_presence::{
    Availability, CancelSignal, OpDescriptor, Outcome, PresenceError, PresenceVerifier,
};
use windows::core::{factory, HSTRING};
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Win32::Foundation::HWND;
use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
use windows_future::IAsyncOperation;

use crate::{
    map_availability, run_verification, HelloAvailability, HelloOps, HelloPending, HelloResult,
    HelloWaitError, WindowProvider, MIN_BUILD,
};

pub struct WindowsHelloVerifier {
    ops: WinOps,
}

impl WindowsHelloVerifier {
    pub fn new(window: WindowProvider) -> Self {
        Self {
            ops: WinOps { window },
        }
    }
}

/// One open native prompt; `wait` consumes a clone because WinRT's `get()`
/// takes the operation by value.
#[derive(Clone)]
struct WinPending(IAsyncOperation<UserConsentVerificationResult>);

impl HelloPending for WinPending {
    fn cancel(&self) {
        let _ = self.0.Cancel();
    }

    fn wait(&self) -> Result<HelloResult, HelloWaitError> {
        // Blocks until the prompt ends or the Cancel() is confirmed — exactly
        // the `PresenceVerifier::verify` waiting contract (slot rule, §6.1).
        self.0
            .clone()
            .get()
            .map(hello_result)
            .map_err(|_| HelloWaitError)
    }
}

/// The native calls of one verification, behind the platform-neutral
/// [`HelloOps`] seam so the adapter rules are testable on every OS.
struct WinOps {
    window: WindowProvider,
}

impl HelloOps for WinOps {
    type Pending = WinPending;

    fn window(&self) -> Option<isize> {
        // A real, live Sovereign Vault window — never the desktop window.
        (self.window)()
    }

    fn open(
        &self,
        hwnd: isize,
        message: &str,
        cancel: &CancelSignal,
    ) -> Result<WinPending, PresenceError> {
        let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
            .map_err(|_| PresenceError::Unavailable)?;
        let hwnd = HWND(hwnd as *mut core::ffi::c_void);
        let message = HSTRING::from(message);
        // D13, the last step before the native call: never open a prompt for
        // a cancelled attempt.
        if cancel.is_cancelled() {
            return Err(PresenceError::Cancelled);
        }
        // SAFETY: `hwnd` is the live main window of this process, obtained
        // from Tauri by the desktop just now; `message` outlives the call;
        // the returned operation is an owned COM reference.
        let operation: IAsyncOperation<UserConsentVerificationResult> =
            unsafe { interop.RequestVerificationForWindowAsync(hwnd, &message) }
                .map_err(|_| PresenceError::Unavailable)?;
        Ok(WinPending(operation))
    }
}

fn os_build() -> Option<u32> {
    use windows::Wdk::System::SystemServices::RtlGetVersion;
    use windows::Win32::System::SystemInformation::OSVERSIONINFOW;
    let mut info = OSVERSIONINFOW {
        dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` is a writable, correctly sized OSVERSIONINFOW whose
    // `dwOSVersionInfoSize` is set, which is all RtlGetVersion requires; it
    // does not retain the pointer.
    let status = unsafe { RtlGetVersion(&mut info) };
    if status.is_ok() {
        Some(info.dwBuildNumber)
    } else {
        None
    }
}

fn hello_availability() -> HelloAvailability {
    let Ok(Ok(value)) = UserConsentVerifier::CheckAvailabilityAsync().map(|op| op.get()) else {
        return HelloAvailability::Other;
    };
    match value {
        UserConsentVerifierAvailability::Available => HelloAvailability::Available,
        UserConsentVerifierAvailability::DeviceNotPresent => HelloAvailability::DeviceNotPresent,
        UserConsentVerifierAvailability::NotConfiguredForUser => {
            HelloAvailability::NotConfiguredForUser
        }
        UserConsentVerifierAvailability::DisabledByPolicy => HelloAvailability::DisabledByPolicy,
        UserConsentVerifierAvailability::DeviceBusy => HelloAvailability::DeviceBusy,
        _ => HelloAvailability::Other,
    }
}

fn hello_result(value: UserConsentVerificationResult) -> HelloResult {
    match value {
        UserConsentVerificationResult::Verified => HelloResult::Verified,
        UserConsentVerificationResult::DeviceNotPresent => HelloResult::DeviceNotPresent,
        UserConsentVerificationResult::NotConfiguredForUser => HelloResult::NotConfiguredForUser,
        UserConsentVerificationResult::DisabledByPolicy => HelloResult::DisabledByPolicy,
        UserConsentVerificationResult::DeviceBusy => HelloResult::DeviceBusy,
        UserConsentVerificationResult::RetriesExhausted => HelloResult::RetriesExhausted,
        UserConsentVerificationResult::Canceled => HelloResult::Canceled,
        _ => HelloResult::Other,
    }
}

#[async_trait::async_trait]
impl PresenceVerifier for WindowsHelloVerifier {
    fn availability(&self) -> Availability {
        // Build first: below 22000 the interop does not exist (§5.2), so the
        // Hello API is not even called there. An unknown build applies no
        // cut: fail closed, the verification itself decides.
        let build = os_build();
        if let Some(b) = build {
            if b < MIN_BUILD {
                return map_availability(build, HelloAvailability::Other);
            }
        }
        map_availability(build, hello_availability())
    }

    async fn verify(
        &self,
        op: &OpDescriptor,
        cancel: &CancelSignal,
    ) -> Result<Outcome, PresenceError> {
        run_verification(&self.ops, op, cancel).await
    }
}
