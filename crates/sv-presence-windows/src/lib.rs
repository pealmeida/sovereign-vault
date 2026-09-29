//! Windows Hello presence backend (ADR-0025 §5.2).
//!
//! This is the ONLY crate in the workspace allowed to use `unsafe`, for
//! the HWND interop call and `RtlGetVersion`. Every block carries a
//! `// SAFETY:` comment; the lints below make that mandatory. Forbidden by
//! construction: the desktop window as prompt owner, window lookup by
//! title/class, synthetic keyboard input, and any credential-UI password
//! fallback. No password or PIN ever passes through this process.
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

use std::sync::Arc;

use sv_presence::{Availability, Modality, Outcome, PresenceError, Reason};

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

pub fn map_availability(build: u32, availability: HelloAvailability) -> Availability {
    if build < MIN_BUILD {
        return Availability::Unavailable(Reason::BelowMinimumBuild);
    }
    match availability {
        HelloAvailability::Available | HelloAvailability::DeviceBusy => Availability::Protected {
            modalities: vec![Modality::Unknown],
        },
        HelloAvailability::NotConfiguredForUser => Availability::Unavailable(Reason::NotConfigured),
        HelloAvailability::DisabledByPolicy => Availability::Unavailable(Reason::DisabledByPolicy),
        HelloAvailability::DeviceNotPresent | HelloAvailability::Other => {
            Availability::Unavailable(Reason::DeviceNotPresent)
        }
    }
}

#[cfg(windows)]
mod sys;
#[cfg(windows)]
pub use sys::WindowsHelloVerifier;

#[cfg(test)]
mod tests {
    use super::*;

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
            map_availability(21999, HelloAvailability::Available),
            Availability::Unavailable(Reason::BelowMinimumBuild)
        );
        assert_eq!(
            map_availability(22000, HelloAvailability::Available),
            Availability::Protected {
                modalities: vec![Modality::Unknown]
            }
        );
    }

    #[test]
    fn availability_states_map() {
        assert_eq!(
            map_availability(22631, HelloAvailability::NotConfiguredForUser),
            Availability::Unavailable(Reason::NotConfigured)
        );
        assert_eq!(
            map_availability(22631, HelloAvailability::DisabledByPolicy),
            Availability::Unavailable(Reason::DisabledByPolicy)
        );
        assert_eq!(
            map_availability(22631, HelloAvailability::DeviceNotPresent),
            Availability::Unavailable(Reason::DeviceNotPresent)
        );
        // Busy is transient: the device exists, so the system is protected.
        assert_eq!(
            map_availability(22631, HelloAvailability::DeviceBusy),
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
}
