//! Stable error contract for the Sovereign Vault mediation runtime.
//!
//! Every failure mode surfaced by [`sv_runtime`](crate) maps to exactly one
//! [`RuntimeError`] variant. [`RuntimeError::code`] returns a stable,
//! snake_case identifier that callers may persist, log, and branch on; the
//! identifier is part of the public contract and must never be renamed.
//!
//! `Display` messages are FIXED safe strings. They never interpolate
//! caller-supplied content, rejected values, credentials, paths, hosts, or any
//! other data that could leak information about the request or its principal.
//! Structured detail, when it is needed at all, is carried in small typed,
//! non-sensitive fields on the variant — never as free-form text.

use thiserror::Error;

/// Convenience alias used throughout the runtime crate.
pub type Result<T> = core::result::Result<T, RuntimeError>;

/// The single error type produced by the mediation runtime.
///
/// Variant order is irrelevant; only [`RuntimeError::code`] is stable.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RuntimeError {
    /// No authenticated principal was supplied with the request.
    #[error("authentication required")]
    AuthRequired,

    /// The supplied credentials or session could not be verified.
    #[error("authentication failed")]
    AuthInvalid,

    /// The authenticated principal has been revoked.
    #[error("principal has been revoked")]
    PrincipalRevoked,

    /// The principal is authenticated but lacks a required scope.
    #[error("required scope not granted")]
    ScopeDenied,

    /// The request is structurally valid but forbidden by policy.
    #[error("request denied by policy")]
    PolicyDenied,

    /// No policy decision could be reached because policy data was missing.
    #[error("policy unavailable")]
    PolicyUnavailable,

    /// The content media type or encoding is not supported.
    #[error("content type not supported")]
    UnsupportedContent,

    /// The request is structurally malformed.
    #[error("request structure is invalid")]
    InvalidStructure,

    /// The request exceeds at least one configured limit.
    #[error("configured limit exceeded")]
    LimitExceeded,

    /// A reference could not be resolved to a stored fragment.
    #[error("reference is invalid")]
    ReferenceInvalid,

    /// The referenced fragment is no longer valid.
    #[error("reference has expired")]
    ReferenceExpired,

    /// The reference was not issued for the requesting audience.
    #[error("reference audience not permitted")]
    ReferenceAudienceDenied,

    /// The operation cannot proceed until consent is granted.
    #[error("consent required")]
    ConsentRequired,

    /// Consent was requested and explicitly refused.
    #[error("consent denied")]
    ConsentDenied,

    /// A previously granted consent is no longer valid.
    #[error("consent has expired")]
    ConsentExpired,

    /// The consent grant does not bind to this request, principal, or destination.
    #[error("consent binding mismatch")]
    ConsentBindingMismatch,

    /// The audit log could not be written or read; mediation fails closed.
    #[error("audit log unavailable")]
    AuditUnavailable,

    /// The requested route is not permitted or does not exist.
    #[error("route denied")]
    RouteDenied,

    /// The requested execution profile is not available to this principal.
    #[error("execution profile denied")]
    ProfileDenied,

    /// The requested destination is not permitted for this operation.
    #[error("destination denied")]
    DestinationDenied,

    /// An upstream call exceeded its deadline.
    #[error("upstream request timed out")]
    UpstreamTimeout,

    /// An upstream peer violated the expected protocol.
    #[error("upstream protocol error")]
    UpstreamProtocolError,

    /// An execution finished but its audit record is incomplete.
    #[error("execution audit record incomplete")]
    ExecutedAuditIncomplete,
}

impl RuntimeError {
    /// Returns the stable, machine-readable snake_case code for this error.
    ///
    /// These strings are part of the wire contract and must not change.
    pub fn code(&self) -> &'static str {
        match self {
            RuntimeError::AuthRequired => "auth_required",
            RuntimeError::AuthInvalid => "auth_invalid",
            RuntimeError::PrincipalRevoked => "principal_revoked",
            RuntimeError::ScopeDenied => "scope_denied",
            RuntimeError::PolicyDenied => "policy_denied",
            RuntimeError::PolicyUnavailable => "policy_unavailable",
            RuntimeError::UnsupportedContent => "unsupported_content",
            RuntimeError::InvalidStructure => "invalid_structure",
            RuntimeError::LimitExceeded => "limit_exceeded",
            RuntimeError::ReferenceInvalid => "reference_invalid",
            RuntimeError::ReferenceExpired => "reference_expired",
            RuntimeError::ReferenceAudienceDenied => "reference_audience_denied",
            RuntimeError::ConsentRequired => "consent_required",
            RuntimeError::ConsentDenied => "consent_denied",
            RuntimeError::ConsentExpired => "consent_expired",
            RuntimeError::ConsentBindingMismatch => "consent_binding_mismatch",
            RuntimeError::AuditUnavailable => "audit_unavailable",
            RuntimeError::RouteDenied => "route_denied",
            RuntimeError::ProfileDenied => "profile_denied",
            RuntimeError::DestinationDenied => "destination_denied",
            RuntimeError::UpstreamTimeout => "upstream_timeout",
            RuntimeError::UpstreamProtocolError => "upstream_protocol_error",
            RuntimeError::ExecutedAuditIncomplete => "executed_audit_incomplete",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RuntimeError;

    const CANARY: &str = "CANARY-7f3a9c1e";

    #[test]
    fn every_code_is_snake_case_and_unique() {
        let codes = [
            RuntimeError::AuthRequired,
            RuntimeError::AuthInvalid,
            RuntimeError::PrincipalRevoked,
            RuntimeError::ScopeDenied,
            RuntimeError::PolicyDenied,
            RuntimeError::PolicyUnavailable,
            RuntimeError::UnsupportedContent,
            RuntimeError::InvalidStructure,
            RuntimeError::LimitExceeded,
            RuntimeError::ReferenceInvalid,
            RuntimeError::ReferenceExpired,
            RuntimeError::ReferenceAudienceDenied,
            RuntimeError::ConsentRequired,
            RuntimeError::ConsentDenied,
            RuntimeError::ConsentExpired,
            RuntimeError::ConsentBindingMismatch,
            RuntimeError::AuditUnavailable,
            RuntimeError::RouteDenied,
            RuntimeError::ProfileDenied,
            RuntimeError::DestinationDenied,
            RuntimeError::UpstreamTimeout,
            RuntimeError::UpstreamProtocolError,
            RuntimeError::ExecutedAuditIncomplete,
        ]
        .map(|e| e.code());

        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len(), "error codes must be unique");
        for code in codes {
            assert!(
                code.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "code {code:?} must be snake_case"
            );
        }
    }

    /// Display messages are fixed strings, so no variant can ever surface
    /// caller-supplied content. The canary stands in for a rejected value,
    /// credential, host, or path that must never reach an error message.
    #[test]
    fn display_is_a_fixed_safe_string() {
        for error in [
            RuntimeError::AuthInvalid,
            RuntimeError::PolicyDenied,
            RuntimeError::ReferenceInvalid,
            RuntimeError::ConsentBindingMismatch,
            RuntimeError::DestinationDenied,
            RuntimeError::UpstreamProtocolError,
        ] {
            let rendered = error.to_string();
            assert!(!rendered.contains(CANARY));
            assert!(!rendered.is_empty());
        }
    }
}
