//! The version 1 policy document and its strict TOML parser.
//!
//! This module contains only the **document model** and the **parser**. It
//! deliberately contains no semantic validation (uniqueness, reachability,
//! bound checks), no evaluation, and no diff: those live in later slices and
//! operate on the types defined here.
//!
//! Two rules are enforced here because they are security-relevant and cheap:
//!
//! * **No unknown fields.** Every struct below carries
//!   `#[serde(deny_unknown_fields)]`, so a key that this runtime does not know
//!   about is a hard [`RuntimeError::InvalidStructure`] failure instead of a
//!   silently ignored instruction. This is what makes "the operator wrote a
//!   rule that does nothing" detectable.
//! * **No unknown enum values.** Enumerations are closed sets; an unrecognised
//!   spelling fails rather than degrading to a default effect or exposure.
//!
//! Match selectors are globs. Regular expressions are not accepted anywhere in
//! version 1, so nothing in this model carries one.

use serde::{Deserialize, Serialize};

use crate::error::RuntimeError;
use crate::types::{ConsentMode, ExposureClass, RuleExposure};

// ---------------------------------------------------------------------------
// Kebab-case wire mirrors for the slice-1 lattices
// ---------------------------------------------------------------------------
//
// `ExposureClass` and `ConsentMode` are reused from `crate::types` (they are
// the lattices the runtime joins on), but their serde derive uses snake_case
// (`reference_only`, `deny_if_unavailable`) while the policy document spells
// them kebab-case (`reference-only`, `deny-if-unavailable`). `types.rs` is
// frozen in this slice, so the translation happens here through private
// mirror enums. An unrecognised spelling is rejected by the mirror enum's own
// deserializer, which is what makes the failure hard rather than silent.

/// Kebab-case wire mirror of [`ExposureClass`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ExposureClassRepr {
    /// Raw bytes may leave the vault.
    Raw,
    /// Only a transformed form may leave.
    Transformed,
    /// Only a reference may leave.
    ReferenceOnly,
    /// Usable only inside an execution profile.
    ExecuteOnly,
    /// Never leaves the vault in any form.
    NonExportable,
}

impl From<ExposureClassRepr> for ExposureClass {
    fn from(value: ExposureClassRepr) -> Self {
        match value {
            ExposureClassRepr::Raw => ExposureClass::Raw,
            ExposureClassRepr::Transformed => ExposureClass::Transformed,
            ExposureClassRepr::ReferenceOnly => ExposureClass::ReferenceOnly,
            ExposureClassRepr::ExecuteOnly => ExposureClass::ExecuteOnly,
            ExposureClassRepr::NonExportable => ExposureClass::NonExportable,
        }
    }
}

impl From<ExposureClass> for ExposureClassRepr {
    fn from(value: ExposureClass) -> Self {
        match value {
            ExposureClass::Raw => ExposureClassRepr::Raw,
            ExposureClass::Transformed => ExposureClassRepr::Transformed,
            ExposureClass::ReferenceOnly => ExposureClassRepr::ReferenceOnly,
            ExposureClass::ExecuteOnly => ExposureClassRepr::ExecuteOnly,
            ExposureClass::NonExportable => ExposureClassRepr::NonExportable,
        }
    }
}

/// Kebab-case wire mirror of [`ConsentMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ConsentModeRepr {
    /// No consent required.
    None,
    /// Simple approval required.
    Approval,
    /// One-time code required.
    Otp,
    /// Consent required; deny if it cannot be obtained.
    DenyIfUnavailable,
}

impl From<ConsentModeRepr> for ConsentMode {
    fn from(value: ConsentModeRepr) -> Self {
        match value {
            ConsentModeRepr::None => ConsentMode::None,
            ConsentModeRepr::Approval => ConsentMode::Approval,
            ConsentModeRepr::Otp => ConsentMode::Otp,
            ConsentModeRepr::DenyIfUnavailable => ConsentMode::DenyIfUnavailable,
        }
    }
}

impl From<ConsentMode> for ConsentModeRepr {
    fn from(value: ConsentMode) -> Self {
        match value {
            ConsentMode::None => ConsentModeRepr::None,
            ConsentMode::Approval => ConsentModeRepr::Approval,
            ConsentMode::Otp => ConsentModeRepr::Otp,
            ConsentMode::DenyIfUnavailable => ConsentModeRepr::DenyIfUnavailable,
        }
    }
}

/// `#[serde(with)]` target for a required `exposure` field, in kebab-case.
mod exposure {
    use super::{ExposureClass, ExposureClassRepr};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Deserializes a required `exposure` from its kebab-case spelling.
    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<ExposureClass, D::Error>
    where
        D: Deserializer<'de>,
    {
        ExposureClassRepr::deserialize(deserializer).map(ExposureClass::from)
    }

    /// Serializes a required `exposure` to its kebab-case spelling.
    pub(super) fn serialize<S>(value: &ExposureClass, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ExposureClassRepr::from(*value).serialize(serializer)
    }
}

/// `#[serde(with)]` target for an optional `consent` field, in kebab-case.
mod consent_option {
    use super::{ConsentMode, ConsentModeRepr};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Deserializes an optional `consent` from its kebab-case spelling.
    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Option<ConsentMode>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<ConsentModeRepr>::deserialize(deserializer).map(|repr| repr.map(ConsentMode::from))
    }

    /// Serializes an optional `consent` to its kebab-case spelling.
    pub(super) fn serialize<S>(
        value: &Option<ConsentMode>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            None => serializer.serialize_none(),
            Some(mode) => ConsentModeRepr::from(*mode).serialize(serializer),
        }
    }
}

// ---------------------------------------------------------------------------
// Document model
// ---------------------------------------------------------------------------

/// A complete version 1 policy document, as loaded from TOML.
///
/// The collection fields default to empty so that a minimal document is just
/// `schema`, `default_effect`, `policy_id`, and `[limits]`; the runtime's
/// default is already deny, so an empty rule list is a valid, maximally
/// restrictive document rather than an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    /// Document schema version. Only `1` is accepted.
    pub schema: u32,
    /// Effect applied when no rule matches. Only `"deny"` is accepted.
    pub default_effect: String,
    /// Stable identifier of this policy document.
    pub policy_id: String,
    /// Global limits that apply before any rule is considered.
    pub limits: LimitsDocument,
    /// Ordered rules. Higher `priority` is reported first.
    #[serde(default)]
    pub rule: Vec<RuleDocument>,
    /// Declared reference classes.
    #[serde(default)]
    pub reference_class: Vec<ReferenceClassDocument>,
    /// Declared provider routes.
    #[serde(default)]
    pub provider_route: Vec<ProviderRouteDocument>,
    /// Declared external MCP servers.
    #[serde(default)]
    pub mcp_server: Vec<McpServerDocument>,
    /// Declared detached execution profiles.
    #[serde(default)]
    pub process_profile: Vec<ProcessProfileDocument>,
}

/// The seven global limits from §1 of the policy reference.
///
/// Field types mirror [`crate::types::EffectiveLimits`] so that a document can
/// be converted into effective limits without a widening conversion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsDocument {
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

/// One `[[rule]]` entry: a selector plus the effect it produces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDocument {
    /// Stable identifier of the rule, used in audit records and explanations.
    pub id: String,
    /// Diagnostic ordering; higher numbers are reported first.
    pub priority: i64,
    /// Selector for the requests this rule applies to.
    #[serde(rename = "match")]
    pub match_: RuleMatch,
    /// Effect produced when the selector matches.
    pub effect: RuleEffect,
}

/// The `[rule.match]` selector.
///
/// Every field is optional and `None` means "matches anything". All list
/// fields are lists of globs or closed-set spellings interpreted by the
/// evaluator; none of them is a regular expression.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleMatch {
    /// Principal identifiers this rule applies to.
    pub principal_ids: Option<Vec<String>>,
    /// Principal kinds this rule applies to.
    pub principal_kinds: Option<Vec<String>>,
    /// Adapter identifiers this rule applies to.
    pub adapter_ids: Option<Vec<String>>,
    /// Transports this rule applies to.
    pub transports: Option<Vec<String>>,
    /// Operation names this rule applies to.
    pub operations: Option<Vec<String>>,
    /// Origin kinds this rule applies to.
    pub origin_kinds: Option<Vec<String>>,
    /// Destination kinds this rule applies to.
    pub destination_kinds: Option<Vec<String>>,
    /// Destination identifiers this rule applies to.
    pub destination_ids: Option<Vec<String>>,
    /// Destination host globs.
    pub host_globs: Option<Vec<String>>,
    /// Destination path prefixes.
    pub path_prefixes: Option<Vec<String>>,
    /// HTTP methods.
    pub methods: Option<Vec<String>>,
    /// Provider identifiers.
    pub provider_ids: Option<Vec<String>>,
    /// Model name globs.
    pub model_globs: Option<Vec<String>>,
    /// External MCP server identifiers.
    pub mcp_server_ids: Option<Vec<String>>,
    /// External MCP tool name globs.
    pub mcp_tool_globs: Option<Vec<String>>,
    /// Detached execution profile identifiers.
    pub process_profile_ids: Option<Vec<String>>,
    /// Container name globs.
    pub container_globs: Option<Vec<String>>,
    /// Resource kinds, e.g. `signing_key`.
    pub resource_kinds: Option<Vec<String>>,
    /// Exposure classes of the fragments involved.
    pub exposure_classes: Option<Vec<String>>,
    /// Media types of the fragments involved.
    pub media_types: Option<Vec<String>>,
    /// Fragment roles of the fragments involved.
    pub fragment_roles: Option<Vec<String>>,
    /// Labels that must all be present.
    pub labels_all: Option<Vec<String>>,
    /// Labels of which at least one must be present.
    pub labels_any: Option<Vec<String>>,
    /// Labels that must not be present.
    pub labels_none: Option<Vec<String>>,
    /// Classification states (`low`, `elevated`, `unknown`).
    pub classification_states: Option<Vec<String>>,
    /// Minimum authentication strength required for the rule to apply.
    pub min_auth_strength: Option<String>,
    /// Maximum age of the session, in seconds, for the rule to apply.
    pub session_max_age_seconds: Option<u64>,
    /// Optional trusted local time window in which the rule applies.
    #[serde(default)]
    pub time_window: Option<TimeWindowDocument>,
}

/// An optional trusted local time window (`[rule.match.time_window]`).
///
/// §2 names this "an optional trusted local time window" without fixing a
/// field name or shape, so it is modelled here as a half-open broker-local
/// interval with an optional day-of-week restriction. Local means
/// broker-local and trusted: a request cannot influence it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeWindowDocument {
    /// Inclusive start of the window, local time, `HH:MM`.
    pub start: String,
    /// Exclusive end of the window, local time, `HH:MM`.
    pub end: String,
    /// Days of week the window covers; empty means every day.
    #[serde(default)]
    pub days: Vec<String>,
}

/// The `[rule.effect]` block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleEffect {
    /// Whether matching requests are allowed or denied.
    pub access: AccessEffect,
    /// Exposure the rule requests for matched fragments, if any.
    ///
    /// This is a [`RuleExposure`], not an [`ExposureClass`]: §2 of the policy
    /// reference lets a rule name a concrete transformation (`redact`,
    /// `pseudonymize`, `omit`) that the §4.3 lattice does not rank. Project it
    /// with [`RuleExposure::class`] before joining.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure: Option<RuleExposure>,
    /// Consent strength required, if any.
    #[serde(
        default,
        with = "consent_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub consent: Option<ConsentMode>,
    /// Audit requirement for the matched request.
    pub audit: AuditRequirement,
    /// Identifier of the route this effect selects, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    /// Maximum number of times a grant derived from this rule may be used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,
    /// Lifetime of a grant derived from this rule, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

/// Whether a rule allows or denies the requests it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessEffect {
    /// Matching requests are permitted, subject to the rest of the effect.
    Allow,
    /// Matching requests are denied.
    Deny,
}

/// The audit requirement attached to an effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditRequirement {
    /// An audit record must be written for the request.
    Required,
}

// ---------------------------------------------------------------------------
// §4 reference classes
// ---------------------------------------------------------------------------

/// A `[[reference_class]]` entry describing how a class of references behaves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceClassDocument {
    /// Stable identifier of the reference class.
    pub id: String,
    /// Exposure class a resolved fragment may take.
    #[serde(with = "exposure")]
    pub exposure: ExposureClass,
    /// Operations the reference may be used with.
    #[serde(default)]
    pub allowed_operations: Vec<String>,
    /// Lifetime applied when a reference is issued without an explicit one.
    pub default_ttl_seconds: u64,
    /// Hard upper bound on a reference lifetime, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl_seconds: Option<u64>,
    /// Hard upper bound on the number of uses of one reference, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,
    /// Whether references of this class survive a broker restart.
    #[serde(default)]
    pub durable: bool,
}

// ---------------------------------------------------------------------------
// §5 provider routes
// ---------------------------------------------------------------------------

/// A `[[provider_route]]` entry describing one upstream provider route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRouteDocument {
    /// Stable identifier of the route.
    pub id: String,
    /// Wire protocol spoken by the route.
    pub protocol: String,
    /// Base URL of the upstream.
    pub base_url: String,
    /// Vault reference holding the route credential. Control-plane only; it is
    /// never exposed through the public reference registry.
    pub credential_ref: String,
    /// Models the route may be used with.
    #[serde(default)]
    pub allowed_models: Vec<String>,
    /// HTTP methods the route may be called with.
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    /// Path prefixes the route may be called on.
    #[serde(default)]
    pub allowed_path_prefixes: Vec<String>,
    /// Whether the route may follow redirects.
    pub follow_redirects: bool,
    /// Wall-clock budget for one upstream call, in milliseconds.
    pub request_timeout_ms: u64,
    /// Maximum accepted response size, in bytes.
    pub max_response_bytes: u64,
}

// ---------------------------------------------------------------------------
// §6 external MCP servers
// ---------------------------------------------------------------------------

/// An `[[mcp_server]]` entry registering one external MCP server.
///
/// §6 describes local (`stdio`) registrations in full and adds, for remote
/// registrations, "exact HTTPS origin, authentication reference, redirect
/// policy, and certificate defaults". Those remote-only keys are not spelled
/// out in the reference and are left to a later slice rather than guessed at
/// here; the strictness rules above mean adding them later cannot silently
/// invalidate an existing document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpServerDocument {
    /// Stable identifier of the server.
    pub id: String,
    /// Transport the server is reached over, e.g. `stdio`.
    pub transport: String,
    /// Executable to launch, for local servers. Absent for remote servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Arguments passed to the executable, for local servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    /// Tools that may be called on this server.
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    /// Tools that may never be called, even if also listed as allowed.
    #[serde(default)]
    pub denied_tools: Vec<String>,
    /// Environment variable names the server may receive.
    #[serde(default)]
    pub environment_allowlist: Vec<String>,
    /// Result policy applied to this server's responses.
    pub result_policy: String,
    /// Whether the server's tool schema must be approved before use.
    pub require_schema_approval: bool,
}

// ---------------------------------------------------------------------------
// §7 process profiles
// ---------------------------------------------------------------------------

/// A `[[process_profile]]` entry describing a detached execution profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessProfileDocument {
    /// Stable identifier of the profile.
    pub id: String,
    /// Absolute path of the executable the profile may run.
    pub executable: String,
    /// Pinned SHA-256 digest of the executable, when pinned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_sha256: Option<String>,
    /// Directory roots the profile may operate in.
    #[serde(default)]
    pub working_directory_roots: Vec<String>,
    /// Path of the JSON schema describing accepted arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argument_schema: Option<String>,
    /// Arguments always prepended to the invocation.
    #[serde(default)]
    pub fixed_args: Vec<String>,
    /// Hosts the profile may contact.
    #[serde(default)]
    pub network_hosts: Vec<String>,
    /// Whether the profile may spawn child processes.
    pub allow_children: bool,
    /// Wall-clock budget for one execution, in milliseconds.
    pub timeout_ms: u64,
    /// Maximum captured stdout, in bytes.
    pub max_stdout_bytes: u64,
    /// Maximum captured stderr, in bytes.
    pub max_stderr_bytes: u64,
    /// Secrets injected into the execution, never into the environment.
    #[serde(default)]
    pub secret: Vec<ProcessSecretDocument>,
}

/// A `[[process_profile.secret]]` entry describing one injected secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSecretDocument {
    /// Parameter name the secret is supplied as.
    pub parameter: String,
    /// Vault reference the secret is read from.
    pub vault_ref: String,
    /// Injection mechanism, e.g. `stdin-json-field`.
    pub injection: String,
    /// Field name inside the injected structure, when the mechanism needs one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parses a version 1 policy document from TOML.
///
/// The parser is strict: a TOML syntax error, an unknown key anywhere in the
/// document, an unknown enum spelling, `schema` other than `1`, or
/// `default_effect` other than `"deny"` all fail with
/// [`RuntimeError::InvalidStructure`].
///
/// The returned error never echoes the input. The underlying parser error is
/// mapped to the bare variant and its message — which may quote the rejected
/// line, key, or value — is discarded, so a failed parse cannot be used to
/// reflect policy content, credential references, or host names back to a
/// caller.
pub fn parse(input: &str) -> crate::error::Result<PolicyDocument> {
    let document: PolicyDocument =
        toml::from_str(input).map_err(|_| RuntimeError::InvalidStructure)?;

    if document.schema != 1 {
        return Err(RuntimeError::InvalidStructure);
    }
    if document.default_effect != "deny" {
        return Err(RuntimeError::InvalidStructure);
    }

    Ok(document)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::error::RuntimeError;
    use crate::types::{ConsentMode, ExposureClass, RuleExposure};

    /// Canary that must never appear in a rendered error.
    const CANARY: &str = "CANARY-2a91f";

    /// A minimal but complete document: header plus `[limits]`.
    const MINIMAL: &str = r#"
schema = 1
default_effect = "deny"
policy_id = "personal-default"

[limits]
request_bytes = 8_388_608
fragment_bytes = 1_048_576
response_bytes = 16_777_216
concurrent_requests_per_principal = 4
request_timeout_ms = 120_000
consent_timeout_ms = 120_000
stream_boundary_bytes = 256
"#;

    /// A document exercising every top-level collection exactly once.
    const FULL: &str = r#"
schema = 1
default_effect = "deny"
policy_id = "full-example"

[limits]
request_bytes = 8_388_608
fragment_bytes = 1_048_576
response_bytes = 16_777_216
concurrent_requests_per_principal = 4
request_timeout_ms = 120_000
consent_timeout_ms = 120_000
stream_boundary_bytes = 256

[[rule]]
id = "cloud-prompt-pii"
priority = 100

[rule.match]
principal_kinds = ["client"]
origin_kinds = ["user_prompt"]
destination_kinds = ["llm_provider"]
labels_any = ["pii.*"]
min_auth_strength = "mfa"
session_max_age_seconds = 3600

[rule.match.time_window]
start = "09:00"
end = "17:00"
days = ["mon", "tue"]

[rule.effect]
access = "allow"
exposure = "reference-only"
consent = "deny-if-unavailable"
audit = "required"
route = "provider:zai"
max_uses = 1
ttl_seconds = 120

[[reference_class]]
id = "provider-key"
exposure = "execute-only"
allowed_operations = ["provider.request"]
default_ttl_seconds = 3600
max_ttl_seconds = 86400
max_uses = 1000
durable = false

[[provider_route]]
id = "zai-production"
protocol = "openai-chat"
base_url = "https://api.z.ai/api/coding/paas/v4"
credential_ref = "vault://providers/zai/api-key"
allowed_models = ["glm-5.2"]
allowed_methods = ["POST"]
allowed_path_prefixes = ["/chat/completions"]
follow_redirects = false
request_timeout_ms = 120_000
max_response_bytes = 16_777_216

[[mcp_server]]
id = "issue-tracker"
transport = "stdio"
command = "C:/Program Files/IssueMCP/issue-mcp.exe"
args = ["serve"]
allowed_tools = ["issues.search"]
denied_tools = ["admin.*"]
environment_allowlist = ["SYSTEMROOT"]
result_policy = "external-mcp-default"
require_schema_approval = true

[[process_profile]]
id = "deploy-production"
executable = "C:/Program Files/Acme/deploy.exe"
executable_sha256 = "0123456789abcdef"
working_directory_roots = ["D:/Code/approved-projects"]
argument_schema = "schemas/deploy-production.schema.json"
fixed_args = ["deploy"]
network_hosts = ["deploy.acme.example"]
allow_children = false
timeout_ms = 300_000
max_stdout_bytes = 2_097_152
max_stderr_bytes = 1_048_576

[[process_profile.secret]]
parameter = "credential"
vault_ref = "vault://deploy/acme-token"
injection = "stdin-json-field"
field = "token"
"#;

    #[test]
    fn parses_minimal_valid_document() {
        let document = parse(MINIMAL).expect("minimal document must parse");
        assert_eq!(document.schema, 1);
        assert_eq!(document.default_effect, "deny");
        assert_eq!(document.policy_id, "personal-default");
        assert_eq!(document.limits.request_bytes, 8_388_608);
        assert_eq!(document.limits.stream_boundary_bytes, 256);
        assert!(document.rule.is_empty());
        assert!(document.reference_class.is_empty());
        assert!(document.provider_route.is_empty());
        assert!(document.mcp_server.is_empty());
        assert!(document.process_profile.is_empty());
    }

    #[test]
    fn parses_full_example() {
        let document = parse(FULL).expect("full document must parse");
        assert_eq!(document.rule.len(), 1);
        assert_eq!(document.reference_class.len(), 1);
        assert_eq!(document.provider_route.len(), 1);
        assert_eq!(document.mcp_server.len(), 1);
        assert_eq!(document.process_profile.len(), 1);
        assert_eq!(document.process_profile[0].secret.len(), 1);

        let rule = &document.rule[0];
        assert_eq!(rule.id, "cloud-prompt-pii");
        assert_eq!(rule.priority, 100);
        assert_eq!(
            rule.match_.labels_any.as_deref(),
            Some(["pii.*".to_string()].as_slice())
        );
        assert_eq!(rule.match_.session_max_age_seconds, Some(3600));
        assert_eq!(
            rule.match_.time_window.as_ref().map(|w| w.start.as_str()),
            Some("09:00")
        );
        assert_eq!(rule.effect.exposure, Some(RuleExposure::ReferenceOnly));
        assert_eq!(rule.effect.consent, Some(ConsentMode::DenyIfUnavailable));
        assert_eq!(rule.effect.route.as_deref(), Some("provider:zai"));

        assert_eq!(
            document.reference_class[0].exposure,
            ExposureClass::ExecuteOnly
        );
        assert_eq!(document.provider_route[0].request_timeout_ms, 120_000);
        assert!(document.mcp_server[0].require_schema_approval);
        assert_eq!(
            document.process_profile[0].secret[0].vault_ref,
            "vault://deploy/acme-token"
        );
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let document = format!("{MINIMAL}\n[extra_section]\nkey = 1\n");
        let error = parse(&document).expect_err("unknown top-level key must fail");
        assert_eq!(error, RuntimeError::InvalidStructure);
    }

    #[test]
    fn unknown_rule_field_is_rejected() {
        let document = format!(
            "{MINIMAL}\n[[rule]]\nid = \"r\"\npriority = 1\nsurprise = true\n\
             [rule.match]\n[rule.effect]\naccess = \"allow\"\naudit = \"required\"\n"
        );
        let error = parse(&document).expect_err("unknown rule key must fail");
        assert_eq!(error, RuntimeError::InvalidStructure);
    }

    #[test]
    fn unknown_nested_field_is_rejected() {
        let document = format!(
            "{MINIMAL}\n[[rule]]\nid = \"r\"\npriority = 1\n\
             [rule.match]\n[rule.effect]\naccess = \"allow\"\naudit = \"required\"\n\
             nonsense = 3\n"
        );
        let error = parse(&document).expect_err("unknown effect key must fail");
        assert_eq!(error, RuntimeError::InvalidStructure);
    }

    #[test]
    fn schema_must_be_one() {
        let document = MINIMAL.replace("schema = 1", "schema = 2");
        let error = parse(&document).expect_err("schema 2 must fail");
        assert_eq!(error, RuntimeError::InvalidStructure);
        assert_eq!(error.code(), "invalid_structure");
    }

    #[test]
    fn default_effect_must_be_deny() {
        let document = MINIMAL.replace("default_effect = \"deny\"", "default_effect = \"allow\"");
        let error = parse(&document).expect_err("default allow must fail");
        assert_eq!(error, RuntimeError::InvalidStructure);
    }

    #[test]
    fn unknown_enum_value_is_rejected() {
        let document = format!(
            "{MINIMAL}\n[[rule]]\nid = \"r\"\npriority = 1\n\
             [rule.match]\n[rule.effect]\naccess = \"allow\"\n\
             exposure = \"sorta-raw\"\naudit = \"required\"\n"
        );
        let error = parse(&document).expect_err("unknown exposure must fail");
        assert_eq!(error, RuntimeError::InvalidStructure);

        let document = format!(
            "{MINIMAL}\n[[rule]]\nid = \"r\"\npriority = 1\n\
             [rule.match]\n[rule.effect]\naccess = \"maybe\"\naudit = \"required\"\n"
        );
        let error = parse(&document).expect_err("unknown access must fail");
        assert_eq!(error, RuntimeError::InvalidStructure);

        let document = format!(
            "{MINIMAL}\n[[rule]]\nid = \"r\"\npriority = 1\n\
             [rule.match]\n[rule.effect]\naccess = \"allow\"\naudit = \"optional\"\n"
        );
        let error = parse(&document).expect_err("unknown audit must fail");
        assert_eq!(error, RuntimeError::InvalidStructure);
    }

    #[test]
    fn kebab_case_enum_values_parse() {
        let document = format!(
            "{MINIMAL}\n[[rule]]\nid = \"r\"\npriority = 1\n\
             [rule.match]\n[rule.effect]\naccess = \"allow\"\n\
             exposure = \"reference-only\"\nconsent = \"deny-if-unavailable\"\n\
             audit = \"required\"\n"
        );
        let parsed = parse(&document).expect("kebab-case spellings must parse");
        assert_eq!(
            parsed.rule[0].effect.exposure,
            Some(RuleExposure::ReferenceOnly)
        );
        assert_eq!(
            parsed.rule[0].effect.consent,
            Some(ConsentMode::DenyIfUnavailable)
        );

        // Every kebab-case spelling of both lattices must map to the slice-1
        // variant, and the required-`exposure` path must agree with the
        // optional one used by rules.
        // A rule effect uses the §2 vocabulary, which names concrete
        // transformations the §4.3 lattice does not rank.
        let rule_exposures = [
            ("raw", RuleExposure::Raw),
            ("redact", RuleExposure::Redact),
            ("pseudonymize", RuleExposure::Pseudonymize),
            ("omit", RuleExposure::Omit),
            ("reference-only", RuleExposure::ReferenceOnly),
            ("execute-only", RuleExposure::ExecuteOnly),
        ];
        for (spelling, expected) in rule_exposures {
            let document = format!(
                "{MINIMAL}\n[[rule]]\nid = \"r\"\npriority = 1\n\
                 [rule.match]\n[rule.effect]\naccess = \"allow\"\n\
                 exposure = \"{spelling}\"\naudit = \"required\"\n"
            );
            let parsed = parse(&document).expect("known rule exposure must parse");
            assert_eq!(parsed.rule[0].effect.exposure, Some(expected), "{spelling}");
        }

        // A reference class declares a lattice position directly.
        let class_exposures = [
            ("raw", ExposureClass::Raw),
            ("transformed", ExposureClass::Transformed),
            ("reference-only", ExposureClass::ReferenceOnly),
            ("execute-only", ExposureClass::ExecuteOnly),
            ("non-exportable", ExposureClass::NonExportable),
        ];
        for (spelling, expected) in class_exposures {
            let document = format!(
                "{MINIMAL}\n[[reference_class]]\nid = \"c\"\nexposure = \"{spelling}\"\n\
                 default_ttl_seconds = 60\n"
            );
            let parsed = parse(&document).expect("known class exposure must parse");
            assert_eq!(parsed.reference_class[0].exposure, expected, "{spelling}");
        }

        // The two vocabularies are not interchangeable: a rule may not name a
        // lattice-only position, and a class may not name a transformation.
        let rule_rejects = format!(
            "{MINIMAL}\n[[rule]]\nid = \"r\"\npriority = 1\n\
             [rule.match]\n[rule.effect]\naccess = \"allow\"\n\
             exposure = \"non-exportable\"\naudit = \"required\"\n"
        );
        assert_eq!(
            parse(&rule_rejects).expect_err("rules have no non-exportable effect"),
            RuntimeError::InvalidStructure
        );

        let class_rejects = format!(
            "{MINIMAL}\n[[reference_class]]\nid = \"c\"\nexposure = \"redact\"\n\
             default_ttl_seconds = 60\n"
        );
        assert_eq!(
            parse(&class_rejects).expect_err("classes have no redact position"),
            RuntimeError::InvalidStructure
        );

        let consents = [
            ("none", ConsentMode::None),
            ("approval", ConsentMode::Approval),
            ("otp", ConsentMode::Otp),
            ("deny-if-unavailable", ConsentMode::DenyIfUnavailable),
        ];
        for (spelling, expected) in consents {
            let document = format!(
                "{MINIMAL}\n[[rule]]\nid = \"r\"\npriority = 1\n\
                 [rule.match]\n[rule.effect]\naccess = \"allow\"\n\
                 consent = \"{spelling}\"\naudit = \"required\"\n"
            );
            let parsed = parse(&document).expect("known consent must parse");
            assert_eq!(parsed.rule[0].effect.consent, Some(expected), "{spelling}");
        }
    }

    #[test]
    fn error_never_echoes_input() {
        // The canary in a policy *value*...
        let value_cases = [
            // Rejected on schema grounds after a clean parse.
            MINIMAL
                .replace(
                    "policy_id = \"personal-default\"",
                    &format!("policy_id = \"{CANARY}\""),
                )
                .replace("schema = 1", "schema = 7"),
            // Rejected as an unknown enum spelling.
            format!(
                "{MINIMAL}\n[[rule]]\nid = \"{CANARY}\"\npriority = 1\n[rule.match]\n\
                 [rule.effect]\naccess = \"allow\"\nexposure = \"{CANARY}\"\naudit = \"required\"\n"
            ),
            // Rejected as a type mismatch.
            MINIMAL.replace(
                "policy_id = \"personal-default\"",
                &format!("policy_id = {CANARY}"),
            ),
            // Rejected as a malformed literal.
            format!("{MINIMAL}\npolicy_id = \"{CANARY}"),
            // Rejected as an unknown value for default_effect.
            MINIMAL.replace(
                "default_effect = \"deny\"",
                &format!("default_effect = \"{CANARY}\""),
            ),
        ];

        // ...and in a malformed or unknown *key*, at every nesting depth.
        let key_cases = [
            format!("{MINIMAL}\n[{CANARY}]\nkey = 1\n"),
            format!("{MINIMAL}\n[limits]\n{CANARY} = 1\n"),
            format!(
                "{MINIMAL}\n[[rule]]\nid = \"r\"\npriority = 1\n{CANARY} = true\n\
                 [rule.match]\n[rule.effect]\naccess = \"allow\"\naudit = \"required\"\n"
            ),
            format!("{MINIMAL}\n[[rule]]\nid = \"r\"\npriority = 1\n[rule.match]\n{CANARY} = 1\n"),
            format!(
                "{MINIMAL}\n[[rule]]\nid = \"r\"\npriority = 1\n[rule.match]\n\
                 [rule.effect]\naccess = \"allow\"\naudit = \"required\"\n{CANARY} = 1\n"
            ),
            format!(
                "{MINIMAL}\n[[rule]]\nid = \"r\"\npriority = 1\n[rule.match]\n\
                 [rule.match.time_window]\n{CANARY} = 1\n"
            ),
            format!("{MINIMAL}\n[[reference_class]]\nid = \"c\"\n{CANARY} = 1\n"),
            format!("{MINIMAL}\n[[provider_route]]\nid = \"c\"\n{CANARY} = 1\n"),
            format!("{MINIMAL}\n[[mcp_server]]\nid = \"c\"\n{CANARY} = 1\n"),
            format!("{MINIMAL}\n[[process_profile]]\nid = \"p\"\n{CANARY} = 1\n"),
            format!("{MINIMAL}\n[[process_profile.secret]]\n{CANARY} = 1\n"),
        ];

        for case in value_cases.iter().chain(key_cases.iter()) {
            let error = parse(case)
                .err()
                .unwrap_or_else(|| panic!("case must fail, but parsed:\n{case}"));
            let rendered = error.to_string();
            assert!(!rendered.contains(CANARY), "echoed input: {rendered:?}");
            assert!(
                !rendered.contains("pii"),
                "echoed policy content: {rendered:?}"
            );
            assert!(
                !rendered.contains("8_388_608"),
                "echoed limits: {rendered:?}"
            );
            assert!(
                !rendered.contains("vault://"),
                "echoed a reference: {rendered:?}"
            );
        }

        // The only variant this parser can return has a fixed message.
        assert_eq!(
            RuntimeError::InvalidStructure.to_string(),
            "request structure is invalid"
        );
    }

    #[test]
    fn parser_never_panics() {
        // Deterministic LCG (Knuth); no RNG dependency needed and the sequence
        // is reproducible from run to run.
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let next = |state: &mut u64| {
            *state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *state
        };

        let pristine = FULL.as_bytes().to_vec();
        let mut ok = 0usize;
        let mut err = 0usize;

        for iteration in 0..2000 {
            let draw = next(&mut state);
            let mut mutated = pristine.clone();
            // Flip bits at one or two positions, so both subtle and gross
            // corruptions are covered.
            let index = (draw as usize) % mutated.len();
            mutated[index] ^= (draw >> 33) as u8;
            if (draw >> 62) & 1 == 1 {
                let other = ((draw >> 17) as usize) % mutated.len();
                mutated[other] ^= (draw >> 45) as u8;
            }

            // Mutations routinely produce invalid UTF-8; `parse` takes `&str`.
            let text = String::from_utf8_lossy(&mutated).into_owned();
            match std::panic::catch_unwind(|| parse(&text)) {
                Ok(Ok(_)) => ok += 1,
                Ok(Err(_)) => err += 1,
                Err(_) => panic!("parse panicked on mutated input, iteration {iteration}"),
            }
        }

        assert_eq!(ok + err, 2000, "every iteration must return Ok or Err");
        assert!(err > 0, "expected at least one rejected mutation");
        assert!(ok > 0, "expected at least one accepted mutation");
    }
}
