//! The real LocalAuthentication boundary via robius-authentication 0.3.1.
//! robius creates a fresh `LAContext` per `authenticate` call and keeps it
//! alive until the reply block fires (verified in its `sys/apple.rs`).

use robius_authentication::{AndroidText, Context, Error, PolicyBuilder, Text, WindowsText};

use crate::macos::{Completion, LaBoundary, LaError};

pub struct RobiusBoundary;

impl LaBoundary for RobiusBoundary {
    fn start(&self, reason: &str, done: Completion) -> Result<(), LaError> {
        // Biometrics + password, no companion/watch: LAPolicy
        // DeviceOwnerAuthentication (Touch ID or the Mac login password).
        let policy = PolicyBuilder::new()
            .companion(false)
            .wrist_detection(false)
            .build()
            .ok_or(LaError::Other)?;
        let text = Text {
            android: AndroidText {
                title: "Sovereign Vault",
                subtitle: None,
                description: None,
            },
            apple: reason,
            windows: WindowsText::new("Sovereign Vault", reason).ok_or(LaError::Other)?,
        };
        Context::new(())
            .authenticate(text, &policy, move |result| done(result.map_err(la_error)))
            .map_err(la_error)
    }
}

fn la_error(error: Error) -> LaError {
    match error {
        Error::UserCanceled | Error::UserFallback => LaError::UserCanceled,
        Error::AppCanceled => LaError::AppCanceled,
        Error::SystemCanceled => LaError::SystemCanceled,
        Error::Authentication => LaError::Authentication,
        Error::Exhausted => LaError::Exhausted,
        Error::Unavailable | Error::BiometryDisconnected | Error::NotPaired => LaError::Unavailable,
        Error::NotEnrolled => LaError::NotEnrolled,
        Error::PasscodeNotSet => LaError::PasscodeNotSet,
        Error::NotInteractive => LaError::NotInteractive,
        _ => LaError::Other,
    }
}
