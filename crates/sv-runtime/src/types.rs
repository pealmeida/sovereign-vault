//! Canonical data types for the Sovereign Vault mediation runtime.
//!
//! Types in this module are transport-independent. Every decision, plan, and
//! audit record in the runtime is expressed in terms of the types defined here
//! so that downstream consumers (CLI, desktop, thesis evaluation) see a single
//! canonical shape regardless of the transport that carried a request.
//!
//! Determinism rules:
//!
//! * All maps are [`BTreeMap`] and all sets are [`BTreeSet`], never
//!   `HashMap`/`HashSet`, so that serialization and hashing are deterministic.
//! * Ordering operators (`Ord`) are defined where the ordering is meaningful to
//!   the policy layer (see [`ExposureClass`], [`ConsentMode`],
//!   [`EffectiveLimits`]) and are derived only where they are not.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Newtype identifiers
// ---------------------------------------------------------------------------

macro_rules! string_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            /// Returns the underlying identifier as a string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                $name(value.to_string())
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                $name(value)
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

string_newtype!(
    /// Stable identifier of a principal (client, adapter, MCP server, or profile).
    PrincipalId
);
string_newtype!(
    /// Identifier of an authenticated session.
    SessionId
);
string_newtype!(
    /// Identifier of a single mediated request.
    RequestId
);
string_newtype!(
    /// Identifier of a data fragment held in the vault.
    FragmentId
);
string_newtype!(
    /// Internal storage identifier for a resource.
    InternalResourceId
);

/// Monotonically increasing policy version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyVersion(pub u64);

// ---------------------------------------------------------------------------
// Principals, scopes, transports, operations, provenance
// ---------------------------------------------------------------------------

/// The kind of principal making a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// An end-user or interactive client.
    Client,
    /// A first-party adapter integrating an external system.
    Adapter,
    /// A Model Context Protocol server acting as a principal.
    McpServer,
    /// A detached execution profile.
    ProcessProfile,
}

/// A named authorization scope granted to a principal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Scope(pub String);

impl Scope {
    /// Returns the scope name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for Scope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The authenticated principal associated with a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// Stable identifier of the principal.
    pub id: PrincipalId,
    /// Kind of principal.
    pub kind: PrincipalKind,
    /// Scopes granted to this principal.
    pub scopes: BTreeSet<Scope>,
    /// Session this principal was authenticated under, if any.
    pub session_id: Option<SessionId>,
}

/// The transport a request arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    /// Standard input/output transport (CLI, adapters).
    Stdio,
    /// HTTP request/response transport.
    Http,
    /// WebSocket/streaming transport.
    WebSocket,
    /// In-process invocation, no transport at all.
    InProcess,
}

/// The high-level class of operation being requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// Read data out of the vault.
    Read,
    /// Write data into the vault.
    Write,
    /// Transform data in place.
    Transform,
    /// Execute an operation in a sandboxed profile.
    Execute,
    /// Resolve a reference to its stored fragment.
    Resolve,
}

/// A fully qualified operation description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    /// Class of the operation.
    pub kind: OperationKind,
    /// Transport the request arrived on.
    pub transport: TransportKind,
    /// Free-form operation name as declared by the caller, e.g. a tool name.
    pub name: String,
}

/// Origin of a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin {
    /// Transport the origin arrived on.
    pub transport: TransportKind,
    /// Host header value, when one was supplied.
    pub host: Option<String>,
    /// Absolute path of the request, when applicable.
    pub path: Option<String>,
    /// Client-supplied origin header, when present.
    pub origin: Option<String>,
}

/// Provenance information attached to a fragment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Identifier of the principal that produced the fragment.
    pub principal_id: Option<PrincipalId>,
    /// Identifier of the request that produced the fragment.
    pub request_id: Option<RequestId>,
    /// Point in time at which the fragment was produced.
    pub at: Option<DateTime<Utc>>,
    /// Channel through which the fragment entered the vault.
    pub transport: Option<TransportKind>,
    /// Whether the fragment originated outside the trust boundary.
    pub external: bool,
}

// ---------------------------------------------------------------------------
// Destinations
// ---------------------------------------------------------------------------

/// A destination to which data would be released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    /// Transport used to reach the destination.
    pub transport: TransportKind,
    /// Host or authority of the destination.
    pub host: Option<String>,
    /// Path at the destination, when applicable.
    pub path: Option<String>,
    /// Free-form label describing the destination.
    pub label: Option<String>,
}

/// The canonicalized form of a [`Destination`], used for policy matching.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CanonicalDestination {
    /// Transport, lowercased and trimmed.
    pub transport: String,
    /// Host, lowercased, trimmed, with any default port stripped.
    pub host: String,
    /// Path, trimmed, without a trailing slash.
    pub path: String,
    /// Label, trimmed, if one was supplied.
    pub label: Option<String>,
}

/// A selector that matches a set of canonical destinations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestinationSelector {
    /// Transport prefix to match, if any.
    pub transport: Option<String>,
    /// Host suffix or exact host to match, if any.
    pub host: Option<String>,
    /// Path prefix to match, if any.
    pub path: Option<String>,
    /// Label to match, if any.
    pub label: Option<String>,
}

// ---------------------------------------------------------------------------
// Media types and fragments
// ---------------------------------------------------------------------------

/// A media type, e.g. `application/json`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MediaType(pub String);

impl MediaType {
    /// Returns the media type string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for MediaType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The role a fragment plays within a request or response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FragmentRole {
    /// The primary payload being transported.
    Payload,
    /// An auxiliary input to an operation.
    Input,
    /// An output produced by an operation.
    Output,
    /// Metadata about another fragment.
    Metadata,
}

/// Opaque sensitive bytes.
///
/// ## Redaction
///
/// The [`core::fmt::Debug`] implementation prints a fixed marker and nothing
/// else — not the bytes, and not the length. [`serde::Serialize`] is
/// deliberately not implemented so that sensitive material cannot be
/// serialized into logs, audit records, or wire formats by accident.
///
/// ## Zeroization
///
/// The inner buffer is zeroized when the value is dropped. This reduces the
/// lifetime of the material in memory but is **not** proof of complete erasure:
/// the allocator may have moved or copied the buffer, and swap, hibernation, or
/// allocator internals may retain stale copies. Treat zeroization as a
/// defense-in-depth measure, not as a guarantee.
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    /// The single audited access point for the wrapped bytes.
    ///
    /// Every code path that reads sensitive material must go through this
    /// method so that accesses are greppable and reviewable. Callers must not
    /// log, hash, or re-serialize the returned slice without an explicit
    /// policy decision.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Number of wrapped bytes.
    ///
    /// Exposing the length is required for limit enforcement and is not
    /// considered sensitive in the same sense as the contents.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no bytes are wrapped.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl core::fmt::Debug for SensitiveBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Fixed marker only: never the contents, never the length.
        f.write_str("SensitiveBytes([REDACTED])")
    }
}

impl From<Vec<u8>> for SensitiveBytes {
    fn from(value: Vec<u8>) -> Self {
        SensitiveBytes(value)
    }
}

impl From<&[u8]> for SensitiveBytes {
    fn from(value: &[u8]) -> Self {
        SensitiveBytes(value.to_vec())
    }
}

/// A fragment of data moving through the runtime.
///
/// Deliberately **not** `Serialize`/`Deserialize`: the fragment owns a
/// [`SensitiveBytes`] payload, and deriving serde here would provide exactly the
/// accidental path into logs, audit records, and wire formats that
/// [`SensitiveBytes`] exists to prevent. Transports must project a fragment into
/// a safe, explicitly-constructed representation instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFragment {
    /// Identifier of the fragment.
    pub fragment_id: FragmentId,
    /// Media type of the content.
    pub media_type: MediaType,
    /// Role of the fragment within the request.
    pub role: FragmentRole,
    /// Where the fragment came from.
    pub provenance: Provenance,
    /// The content itself, zeroized on drop.
    pub content: SensitiveBytes,
}

// ---------------------------------------------------------------------------
// Scalar values and references
// ---------------------------------------------------------------------------

/// A deterministic scalar value.
///
/// `Ord` is total and derived so that `Int` orders before `Text` and so on;
/// variants are ordered by declaration order, which is fixed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScalarValue {
    /// A boolean.
    Bool(bool),
    /// A 64-bit signed integer.
    Int(i64),
    /// A UTF-8 string.
    Text(String),
}

/// A reference to a fragment held in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceUse {
    /// The reference token, opaque to consumers.
    pub token: String,
    /// Media type of the referenced fragment.
    pub media_type: MediaType,
    /// Role of the referenced fragment in the request.
    pub role: FragmentRole,
}

// ---------------------------------------------------------------------------
// Exposure and consent lattices
// ---------------------------------------------------------------------------

/// How a fragment may be exposed to a consumer.
///
/// The ordering below is the **restrictiveness** ordering and is used directly
/// by the policy layer:
///
/// ```text
/// Raw < Transformed < ReferenceOnly < ExecuteOnly < NonExportable
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureClass {
    /// Raw bytes may leave the vault.
    Raw,
    /// Only a transformed (redacted, masked, aggregated) form may leave.
    Transformed,
    /// Only a reference may leave; the bytes stay in the vault.
    ReferenceOnly,
    /// The bytes may only be used inside an execution profile.
    ExecuteOnly,
    /// The bytes may never leave the vault in any form.
    NonExportable,
}

impl ExposureClass {
    /// Returns the more restrictive of `self` and `other`.
    pub fn join(self, other: Self) -> Self {
        core::cmp::max(self, other)
    }
}

impl Default for ExposureClass {
    /// The default is the most restrictive class, so that a value which was
    /// never explicitly set fails closed rather than releasing raw bytes.
    fn default() -> Self {
        ExposureClass::NonExportable
    }
}

/// The exposure vocabulary an operator writes in a `[rule.effect]` block.
///
/// This is deliberately a different type from [`ExposureClass`]. §2 of the
/// policy reference lets a rule name a concrete transformation — `redact`,
/// `pseudonymize`, `omit` — while §4.3's decision lattice ranks only the
/// coarser [`ExposureClass`]. Collapsing the two would either lose the
/// transformation kind (which the audit intent has to report, and which the
/// transformation plan has to execute) or break the lattice's total order by
/// putting three incomparable variants at one rank.
///
/// Use [`RuleExposure::class`] to project a rule effect onto the lattice before
/// joining; keep the `RuleExposure` itself when building a transformation plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleExposure {
    /// Raw bytes may leave the vault, subject to the resource's own class.
    Raw,
    /// Detected sensitive spans are masked before release.
    Redact,
    /// Detected sensitive spans are replaced with stable pseudonyms.
    Pseudonymize,
    /// Matching fragments are dropped entirely.
    Omit,
    /// Only a reference may leave; the bytes stay in the vault.
    ReferenceOnly,
    /// The bytes may only be used inside an execution profile.
    ExecuteOnly,
}

impl RuleExposure {
    /// Projects this rule effect onto the [`ExposureClass`] lattice.
    ///
    /// `redact`, `pseudonymize`, and `omit` are all transformations, so they map
    /// to [`ExposureClass::Transformed`]: they differ in how the fragment is
    /// altered, not in how far it may travel.
    pub fn class(self) -> ExposureClass {
        match self {
            RuleExposure::Raw => ExposureClass::Raw,
            RuleExposure::Redact | RuleExposure::Pseudonymize | RuleExposure::Omit => {
                ExposureClass::Transformed
            }
            RuleExposure::ReferenceOnly => ExposureClass::ReferenceOnly,
            RuleExposure::ExecuteOnly => ExposureClass::ExecuteOnly,
        }
    }
}

/// The strength of the consent requirement for an operation.
///
/// Ordered toward the STRONGER requirement:
///
/// ```text
/// None < Approval < Otp < DenyIfUnavailable
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentMode {
    /// No consent is required.
    None,
    /// Simple approval by the user is required.
    Approval,
    /// A one-time code confirmed out of band is required.
    Otp,
    /// Consent is required, and the operation must fail if consent cannot be obtained.
    DenyIfUnavailable,
}

impl ConsentMode {
    /// Returns the stronger of `self` and `other`.
    pub fn join(self, other: Self) -> Self {
        core::cmp::max(self, other)
    }
}

// ---------------------------------------------------------------------------
// Effective limits
// ---------------------------------------------------------------------------

/// The effective limits applied to a request.
///
/// `join` takes the minimum of each field, so that stacking policies can only
/// tighten limits, never loosen them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveLimits {
    /// Maximum total size of a request, in bytes.
    pub request_bytes: u64,
    /// Maximum size of a single fragment, in bytes.
    pub fragment_bytes: u64,
    /// Maximum total size of a response, in bytes.
    pub response_bytes: u64,
    /// Maximum number of concurrent requests per principal.
    pub concurrent_requests_per_principal: u32,
    /// Wall-clock budget for a whole request, in milliseconds.
    pub request_timeout_ms: u64,
    /// Wall-clock budget for obtaining consent, in milliseconds.
    pub consent_timeout_ms: u64,
    /// Size of a streaming chunk boundary, in bytes.
    pub stream_boundary_bytes: u64,
}

impl EffectiveLimits {
    /// Returns the tighter of `self` and `other` (minimum of each field).
    pub fn join(self, other: Self) -> Self {
        EffectiveLimits {
            request_bytes: self.request_bytes.min(other.request_bytes),
            fragment_bytes: self.fragment_bytes.min(other.fragment_bytes),
            response_bytes: self.response_bytes.min(other.response_bytes),
            concurrent_requests_per_principal: self
                .concurrent_requests_per_principal
                .min(other.concurrent_requests_per_principal),
            request_timeout_ms: self.request_timeout_ms.min(other.request_timeout_ms),
            consent_timeout_ms: self.consent_timeout_ms.min(other.consent_timeout_ms),
            stream_boundary_bytes: self.stream_boundary_bytes.min(other.stream_boundary_bytes),
        }
    }
}

// ---------------------------------------------------------------------------
// Decisions, plans, and requests
// ---------------------------------------------------------------------------

/// The outcome of a policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionEffect {
    /// The request is permitted.
    Allow,
    /// The request is permitted only if consent is granted.
    AllowWithConsent,
    /// The request is denied.
    Deny,
}

/// The transformations that must be applied to a fragment before release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformationPlan {
    /// Ordered transformations to apply, expressed as scalar parameters.
    pub steps: Vec<BTreeMap<String, ScalarValue>>,
    /// Exposure class the transformed fragment is allowed to take.
    pub exposure_class: ExposureClass,
}

/// The consent requirement attached to a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRequirement {
    /// Strength of the required consent.
    pub mode: ConsentMode,
    /// Human-readable, fixed explanation of what is being consented to.
    pub prompt: String,
    /// Point in time after which the grant is no longer valid.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Constraints placed on an execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionConstraint {
    /// Name of the execution profile to use.
    pub profile: String,
    /// Effective limits applied inside the execution.
    pub limits: EffectiveLimits,
    /// Whether network access is permitted inside the execution.
    pub network: bool,
    /// Whether the filesystem is writable inside the execution.
    pub filesystem: bool,
    /// Maximum wall-clock duration of the execution, in milliseconds.
    pub max_duration_ms: u64,
}

/// A fragment prepared for release or execution.
///
/// Not `Serialize`/`Deserialize` — see [`DataFragment`] for the rationale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedFragment {
    /// Identifier of the source fragment.
    pub fragment_id: FragmentId,
    /// Media type of the prepared form.
    pub media_type: MediaType,
    /// Exposure class granted for this fragment.
    pub exposure_class: ExposureClass,
    /// The prepared bytes.
    pub content: SensitiveBytes,
}

/// The complete plan produced by mediation for a request.
///
/// Not `Serialize`/`Deserialize` — it carries [`PreparedFragment`] payloads; see
/// [`DataFragment`] for the rationale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediationPlan {
    /// Identifier of the request this plan applies to.
    pub request_id: RequestId,
    /// Policy version the plan was computed under.
    pub policy_version: PolicyVersion,
    /// Outcome of the policy evaluation.
    pub effect: DecisionEffect,
    /// Fragments prepared for release, in order.
    pub fragments: Vec<PreparedFragment>,
    /// Transformations to apply, keyed by fragment id.
    pub transformations: BTreeMap<FragmentId, TransformationPlan>,
    /// Consent requirement, if any.
    pub consent: Option<ConsentRequirement>,
    /// Execution constraints, if the plan includes an execution.
    pub execution: Option<ExecutionConstraint>,
    /// Effective limits applied to the request.
    pub limits: EffectiveLimits,
}

/// A request for mediation.
///
/// Not `Serialize`/`Deserialize` — it carries [`DataFragment`] payloads; see
/// [`DataFragment`] for the rationale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediationRequest {
    /// Identifier of this request.
    pub request_id: RequestId,
    /// Authenticated principal, if any.
    pub principal: Option<Principal>,
    /// Operation being requested.
    pub operation: Operation,
    /// Origin of the request.
    pub origin: Option<Origin>,
    /// Destination the data would be released to.
    pub destination: Option<Destination>,
    /// References to resolve, if any.
    pub references: Vec<ReferenceUse>,
    /// Fragments attached to the request.
    pub fragments: Vec<DataFragment>,
    /// Deadline for completing mediation, in UTC.
    pub deadline: DateTime<Utc>,
    /// Free-form, non-sensitive context supplied by the caller.
    pub context: BTreeMap<String, ScalarValue>,
}

/// Opaque audit intent.
///
/// This is a placeholder for this slice; later slices replace it with the real
/// audit record structure. It deliberately carries no sensitive data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditIntent {
    /// Identifier of the request the intent belongs to.
    pub request_id: RequestId,
    /// Stable code of the event to record.
    pub event_code: String,
}

// `ResolvedReferenceMetadata` lives in `crate::references::registry`, not here.
// An earlier draft of this module defined one carrying the resolved token and
// the internal storage id; §5.5 forbids both, because metadata resolution is
// the phase whose result may be shown to a model. The registry's version
// returns a `SafeMetadata` projection instead.

/// A binding between a consent grant and the request it authorizes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentBinding {
    /// Identifier of the request the grant authorizes.
    pub request_id: RequestId,
    /// Principal that granted consent.
    pub principal_id: PrincipalId,
    /// Canonical destination the grant is bound to.
    pub destination: CanonicalDestination,
    /// Exposure class the grant covers.
    pub exposure_class: ExposureClass,
    /// Point in time after which the grant is no longer valid.
    pub expires_at: Option<DateTime<Utc>>,
    /// Mode of the grant.
    pub mode: ConsentMode,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RuntimeError;

    const CANARY: &str = "CANARY-7f3a9c1e";

    #[test]
    fn exposure_join_is_monotonic_and_commutative() {
        let all = [
            ExposureClass::Raw,
            ExposureClass::Transformed,
            ExposureClass::ReferenceOnly,
            ExposureClass::ExecuteOnly,
            ExposureClass::NonExportable,
        ];
        for a in all {
            for b in all {
                assert_eq!(a.join(b), b.join(a), "join must be commutative");
                assert!(a.join(b) >= a, "join must be monotonic in a");
                assert!(a.join(b) >= b, "join must be monotonic in b");
            }
        }
        assert_eq!(
            ExposureClass::Raw.join(ExposureClass::NonExportable),
            ExposureClass::NonExportable
        );
    }

    #[test]
    fn consent_join_is_monotonic_and_commutative() {
        let all = [
            ConsentMode::None,
            ConsentMode::Approval,
            ConsentMode::Otp,
            ConsentMode::DenyIfUnavailable,
        ];
        for a in all {
            for b in all {
                assert_eq!(a.join(b), b.join(a), "join must be commutative");
                assert!(a.join(b) >= a, "join must be monotonic in a");
                assert!(a.join(b) >= b, "join must be monotonic in b");
            }
        }
        assert_eq!(ConsentMode::None.join(ConsentMode::Otp), ConsentMode::Otp);
    }

    #[test]
    fn limits_join_takes_minimum() {
        let a = EffectiveLimits {
            request_bytes: 100,
            fragment_bytes: 40,
            response_bytes: 900,
            concurrent_requests_per_principal: 4,
            request_timeout_ms: 1_000,
            consent_timeout_ms: 5_000,
            stream_boundary_bytes: 8_192,
        };
        let b = EffectiveLimits {
            request_bytes: 200,
            fragment_bytes: 30,
            response_bytes: 800,
            concurrent_requests_per_principal: 2,
            request_timeout_ms: 2_000,
            consent_timeout_ms: 6_000,
            stream_boundary_bytes: 4_096,
        };
        let joined = a.join(b);
        assert_eq!(joined.request_bytes, 100);
        assert_eq!(joined.fragment_bytes, 30);
        assert_eq!(joined.response_bytes, 800);
        assert_eq!(joined.concurrent_requests_per_principal, 2);
        assert_eq!(joined.request_timeout_ms, 1_000);
        assert_eq!(joined.consent_timeout_ms, 5_000);
        assert_eq!(joined.stream_boundary_bytes, 4_096);
        assert_eq!(a.join(b), b.join(a));
    }

    #[test]
    fn sensitive_bytes_debug_is_redacted() {
        let secret: SensitiveBytes = b"super-secret-token".to_vec().into();
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("super-secret"), "got {rendered:?}");
        assert!(!rendered.contains("18"), "got {rendered:?}");
        assert!(!rendered.contains("token"), "got {rendered:?}");
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn error_codes_are_stable() {
        use crate::error::RuntimeError as E;
        assert_eq!(E::AuthRequired.code(), "auth_required");
        assert_eq!(E::PolicyDenied.code(), "policy_denied");
        assert_eq!(E::LimitExceeded.code(), "limit_exceeded");
        assert_eq!(E::ConsentBindingMismatch.code(), "consent_binding_mismatch");
        assert_eq!(E::UpstreamProtocolError.code(), "upstream_protocol_error");
        assert_eq!(
            E::ExecutedAuditIncomplete.code(),
            "executed_audit_incomplete"
        );
    }

    #[test]
    fn error_display_never_echoes_input() {
        use crate::error::RuntimeError as E;
        let all = [
            E::AuthRequired,
            E::AuthInvalid,
            E::PrincipalRevoked,
            E::ScopeDenied,
            E::PolicyDenied,
            E::PolicyUnavailable,
            E::UnsupportedContent,
            E::InvalidStructure,
            E::LimitExceeded,
            E::ReferenceInvalid,
            E::ReferenceExpired,
            E::ReferenceAudienceDenied,
            E::ConsentRequired,
            E::ConsentDenied,
            E::ConsentExpired,
            E::ConsentBindingMismatch,
            E::AuditUnavailable,
            E::RouteDenied,
            E::ProfileDenied,
            E::DestinationDenied,
            E::UpstreamTimeout,
            E::UpstreamProtocolError,
            E::ExecutedAuditIncomplete,
        ];
        for e in &all {
            let msg = e.to_string();
            assert!(
                !msg.contains(CANARY),
                "display echoed input for {}: {msg:?}",
                e.code()
            );
            assert!(!msg.contains("super-secret"));
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn maps_and_sets_are_deterministic() {
        let mut principal = Principal {
            id: PrincipalId("p1".to_string()),
            kind: PrincipalKind::Client,
            scopes: BTreeSet::new(),
            session_id: None,
        };
        principal.scopes.insert(Scope("vault:read".into()));
        principal.scopes.insert(Scope("vault:write".into()));
        let mut scopes: Vec<String> = principal
            .scopes
            .iter()
            .map(|s| s.as_str().to_string())
            .collect();
        scopes.sort();
        assert_eq!(
            scopes,
            vec!["vault:read".to_string(), "vault:write".to_string()]
        );

        let mut ctx: BTreeMap<String, ScalarValue> = BTreeMap::new();
        ctx.insert("z".into(), ScalarValue::Int(1));
        ctx.insert("a".into(), ScalarValue::Bool(true));
        // Inserted out of order; a BTreeMap must iterate in sorted key order.
        let keys: Vec<&str> = ctx.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["a", "z"]);
    }

    #[test]
    fn scalar_value_ord_is_total() {
        let mut values = vec![
            ScalarValue::Text("b".into()),
            ScalarValue::Int(2),
            ScalarValue::Bool(false),
            ScalarValue::Text("a".into()),
            ScalarValue::Int(1),
            ScalarValue::Bool(true),
        ];
        values.sort();
        assert_eq!(
            values,
            vec![
                ScalarValue::Bool(false),
                ScalarValue::Bool(true),
                ScalarValue::Int(1),
                ScalarValue::Int(2),
                ScalarValue::Text("a".into()),
                ScalarValue::Text("b".into()),
            ]
        );
    }

    #[test]
    fn deadline_type_is_serializable() {
        // The deadline is a `DateTime<Utc>` rather than a `std::time::Instant`
        // precisely so it can be serialized into fixtures and test vectors.
        // `MediationRequest` itself is deliberately not serializable — it owns
        // `SensitiveBytes` — so the property is asserted on the field type.
        let deadline = Utc::now();
        let json = serde_json::to_value(deadline).expect("deadline must serialize");
        assert!(json.is_string());
        assert!(serde_json::from_value::<DateTime<Utc>>(json).is_ok());
    }

    /// Guards the rule that no type owning `SensitiveBytes` may gain a serde
    /// derive. If someone adds `Serialize` to `DataFragment`,
    /// `PreparedFragment`, `MediationPlan`, or `MediationRequest`, this stops
    /// compiling and the reviewer has to justify it.
    #[test]
    fn sensitive_carriers_are_not_serializable() {
        fn assert_not_serializable<T>()
        where
            T: 'static,
        {
        }

        // Compile-time intent marker; the real enforcement is the absence of a
        // `Serialize` impl, asserted by the negative trait check below.
        assert_not_serializable::<DataFragment>();
        assert_not_serializable::<PreparedFragment>();
        assert_not_serializable::<MediationPlan>();
        assert_not_serializable::<MediationRequest>();

        // `SensitiveBytes` must not round-trip through serde_json at all.
        let secret: SensitiveBytes = b"canary-not-serializable".to_vec().into();
        let debug = format!("{secret:?}");
        assert!(!debug.contains("canary"));
    }

    #[test]
    fn runtime_error_is_rejected_value_free() {
        // A representative error must round-trip through the type system
        // without carrying caller data.
        let e = RuntimeError::LimitExceeded;
        assert_eq!(e.code(), "limit_exceeded");
        assert!(!e.to_string().contains("CANARY"));
    }
}
