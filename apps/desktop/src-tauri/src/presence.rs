//! Desktop wiring of ADR-0025: which verifier this platform uses, and the
//! helpers the gated commands share.

use std::sync::Arc;

use sv_presence::{PresenceCoordinator, PresenceVerifier};
use tauri::{AppHandle, Runtime};

pub(crate) fn build_coordinator<R: Runtime>(app: &AppHandle<R>) -> Arc<PresenceCoordinator> {
    #[cfg(windows)]
    let verifier: Arc<dyn PresenceVerifier> = {
        use tauri::Manager;
        let app = app.clone();
        Arc::new(sv_presence_windows::WindowsHelloVerifier::new(Arc::new(
            move || {
                // The real, kept-alive main window (ADR-0025 §5.2).
                app.get_webview_window("main")
                    .and_then(|w| w.hwnd().ok())
                    .map(|h| h.0 as isize)
            },
        )))
    };
    #[cfg(not(windows))]
    let verifier: Arc<dyn PresenceVerifier> = {
        let _ = app;
        sv_presence::platform_verifier()
    };
    Arc::new(PresenceCoordinator::new(verifier))
}

/// Modality mapping is 1:1; kept here so the audit writers never inline it.
/// Read by the gated commands (Tasks 8+).
#[allow(dead_code)]
pub(crate) fn audit_modality(m: sv_presence::Modality) -> sv_audit::PresenceModality {
    match m {
        sv_presence::Modality::Biometric => sv_audit::PresenceModality::Biometric,
        sv_presence::Modality::Password => sv_audit::PresenceModality::Password,
        sv_presence::Modality::Pin => sv_audit::PresenceModality::Pin,
        sv_presence::Modality::Unknown => sv_audit::PresenceModality::Unknown,
    }
}
