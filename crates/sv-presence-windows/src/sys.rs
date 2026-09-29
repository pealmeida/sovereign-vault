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

use crate::{map_availability, map_result, HelloAvailability, HelloResult, WindowProvider};

pub struct WindowsHelloVerifier {
    window: WindowProvider,
}

impl WindowsHelloVerifier {
    pub fn new(window: WindowProvider) -> Self {
        Self { window }
    }
}

fn os_build() -> u32 {
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
        info.dwBuildNumber
    } else {
        0
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
        // Build first: below 22000 the interop does not exist (§5.2).
        let build = os_build();
        if build < crate::MIN_BUILD {
            return map_availability(build, HelloAvailability::Other);
        }
        map_availability(build, hello_availability())
    }

    async fn verify(
        &self,
        op: &OpDescriptor,
        cancel: &CancelSignal,
    ) -> Result<Outcome, PresenceError> {
        // D13 contract, first check: never open a prompt for a cancelled attempt.
        if cancel.is_cancelled() {
            return Err(PresenceError::Cancelled);
        }
        // A real, live Sovereign Vault window — never the desktop window.
        let Some(raw) = (self.window)() else {
            return Err(PresenceError::Unavailable);
        };
        let hwnd = HWND(raw as *mut core::ffi::c_void);
        let message = HSTRING::from(op.prompt_text());
        let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
            .map_err(|_| PresenceError::Unavailable)?;
        // SAFETY: `hwnd` is the live main window of this process, obtained
        // from Tauri by the desktop just now; `message` outlives the call;
        // the returned operation is an owned COM reference.
        let operation: IAsyncOperation<UserConsentVerificationResult> =
            unsafe { interop.RequestVerificationForWindowAsync(hwnd, &message) }
                .map_err(|_| PresenceError::Unavailable)?;
        // Second check, now that THIS operation exists: a cancellation that
        // raced the creation closes it at once.
        if cancel.is_cancelled() {
            let _ = operation.Cancel();
        }
        // `get()` blocks until the prompt ends or `Cancel()` is confirmed,
        // which is exactly the contract of `PresenceVerifier::verify`.
        let waiter = operation.clone();
        let mut done = tokio::task::spawn_blocking(move || waiter.get());
        let waited = tokio::select! {
            waited = &mut done => waited,
            _ = cancel.cancelled() => {
                // Cancel only this attempt's operation, then wait for the
                // prompt to actually end before returning (slot rule, §6.1).
                let _ = operation.Cancel();
                done.await
            }
        };
        match waited {
            Ok(Ok(value)) => map_result(hello_result(value)),
            // Cancelled or failed inside WinRT.
            Ok(Err(_)) => Err(PresenceError::Cancelled),
            Err(_) => Err(PresenceError::Failed),
        }
    }
}
