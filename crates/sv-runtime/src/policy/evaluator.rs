//! The policy decision: deny-overrides evaluation against one snapshot.
//!
//! Evaluation follows §4.2 of the runtime specification in order, and composes
//! independent axes per §4.3. Two properties carry the security weight here and
//! are enforced structurally rather than by convention:
//!
//! * **Deny overrides.** Any matching deny rule denies the request. `priority`
//!   orders diagnostics only; a high-priority allow can never outrank a
//!   low-priority deny.
//! * **Effects only ratchet.** The mandatory floor implied by the resource's
//!   own exposure class is computed *first*, and rule effects are only ever
//!   `join`ed onto it. There is no code path that assigns an exposure or a
//!   consent mode, so an allow rule cannot weaken either one.

use std::collections::BTreeSet;

use crate::error::{Result, RuntimeError};
use crate::policy::document::{AccessEffect, RuleDocument, RuleMatch};
use crate::policy::glob;
use crate::policy::snapshot::PolicySnapshot;
use crate::types::{ConsentMode, EffectiveLimits, ExposureClass, PrincipalKind, TransportKind};

/// How a classifier rated the request, if one ran.
///
/// Classification is an elevation-only input (§4.2 step 7): `Elevated` may
/// raise the exposure and consent floors, and no state may ever lower them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClassificationState {
    /// The classifier saw nothing that warrants elevation.
    Low,
    /// The classifier found something that warrants elevation.
    Elevated,
    /// No classifier ran, or it could not reach a verdict.
    #[default]
    Unknown,
}

/// The trusted facts a decision is made from (§4.1).
///
/// These are supplied by the runtime after authentication and detection, never
/// taken from model text, MCP tool descriptions, or request-supplied labels:
/// those are untrusted claims that may hint at provenance but can never grant
/// access.
#[derive(Debug, Clone, Default)]
pub struct EvaluationFacts {
    /// Authenticated principal identifier.
    pub principal_id: Option<String>,
    /// Kind of the authenticated principal.
    pub principal_kind: Option<PrincipalKind>,
    /// Identifier of the adapter that carried the request, when there is one.
    pub adapter_id: Option<String>,
    /// Transport the request arrived on.
    pub transport: Option<TransportKind>,
    /// Operation name, e.g. `vault.read`.
    pub operation: Option<String>,
    /// Coarse origin kind, e.g. `user_prompt` or `external_mcp_result`.
    pub origin_kind: Option<String>,
    /// Coarse destination kind, e.g. `llm_provider` or `external_mcp`.
    pub destination_kind: Option<String>,
    /// Identifier of the destination, when it is a registered one.
    pub destination_id: Option<String>,
    /// Destination host, for host glob matching.
    pub host: Option<String>,
    /// Destination path, for path prefix matching.
    pub path: Option<String>,
    /// Destination method, when the transport has one.
    pub method: Option<String>,
    /// Registered MCP server the request targets.
    pub mcp_server_id: Option<String>,
    /// MCP tool the request targets.
    pub mcp_tool: Option<String>,
    /// Registered process profile the request targets.
    pub process_profile_id: Option<String>,
    /// Kinds of the resources the request touches.
    pub resource_kinds: BTreeSet<String>,
    /// Labels detected in the request's fragments.
    pub labels: BTreeSet<String>,
    /// Classifier verdict, if one ran.
    pub classification: ClassificationState,
    /// The immutable exposure floor implied by the resources themselves.
    ///
    /// This is the resource's own class, not anything a rule asked for. A rule
    /// can raise it and can never lower it.
    pub resource_exposure_floor: ExposureClass,
    /// Total request size, checked against the snapshot's limits.
    pub request_bytes: u64,
    /// Largest single fragment, checked against the snapshot's limits.
    pub largest_fragment_bytes: u64,
}

/// The outcome of evaluating one request against one snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    /// Identifiers of every rule that matched, highest priority first.
    pub matched_rules: Vec<String>,
    /// Effective exposure after joining the floor with every matching effect.
    pub exposure: ExposureClass,
    /// Effective consent requirement after joining.
    pub consent: ConsentMode,
    /// Effective limits after joining toward the minimum.
    pub limits: EffectiveLimits,
    /// The single route this decision resolves to, if any.
    pub route: Option<String>,
    /// Digest of the snapshot this decision was made against.
    pub policy_digest: [u8; 32],
}

/// Evaluates `facts` against `snapshot`, returning a decision or a denial.
///
/// Steps follow §4.2: one snapshot, hard invariants, explicit denies, scopes,
/// the mandatory exposure floor, configured transformations, elevation-only
/// classification, the consent floor, route and limits, and finally a decision
/// tied to the snapshot digest.
pub fn evaluate(snapshot: &PolicySnapshot, facts: &EvaluationFacts) -> Result<PolicyDecision> {
    let document = snapshot.document();

    // Step 2: hard invariants and size limits, before any rule is consulted.
    let limits = EffectiveLimits {
        request_bytes: document.limits.request_bytes,
        fragment_bytes: document.limits.fragment_bytes,
        response_bytes: document.limits.response_bytes,
        concurrent_requests_per_principal: document.limits.concurrent_requests_per_principal,
        request_timeout_ms: document.limits.request_timeout_ms,
        consent_timeout_ms: document.limits.consent_timeout_ms,
        stream_boundary_bytes: document.limits.stream_boundary_bytes,
    };
    if facts.request_bytes > limits.request_bytes
        || facts.largest_fragment_bytes > limits.fragment_bytes
    {
        return Err(RuntimeError::LimitExceeded);
    }

    // Rules are considered in descending priority purely so that diagnostics
    // read in the order an operator expects. Ordering does not affect the
    // outcome: denies are collected across the whole set below.
    let mut ordered: Vec<&RuleDocument> = document.rule.iter().collect();
    ordered.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then(left.id.cmp(&right.id))
    });

    let mut matched_rules = Vec::new();
    let mut matched_allows = 0usize;

    // Step 5: the mandatory floor comes from the resource, before any rule.
    let mut exposure = facts.resource_exposure_floor;
    let mut consent = ConsentMode::None;
    let mut routes: BTreeSet<String> = BTreeSet::new();

    for rule in &ordered {
        if !rule_matches(&rule.match_, facts) {
            continue;
        }
        matched_rules.push(rule.id.clone());

        // Step 3: any matching deny ends it, whatever its priority.
        if rule.effect.access == AccessEffect::Deny {
            return Err(RuntimeError::PolicyDenied);
        }

        matched_allows += 1;

        // Steps 6 and 8: transformations and consent only ever join upward.
        if let Some(requested) = rule.effect.exposure {
            exposure = exposure.join(requested.class());
        }
        if let Some(requested) = rule.effect.consent {
            consent = consent.join(requested);
        }
        if let Some(route) = &rule.effect.route {
            routes.insert(route.clone());
        }
    }

    // Step 4 / §3: no matching allow means deny. The document's declared
    // default is already `deny`, enforced by the parser.
    if matched_allows == 0 {
        return Err(RuntimeError::PolicyDenied);
    }

    // Step 7: classification may raise the floors and may never lower them.
    if facts.classification == ClassificationState::Elevated {
        exposure = exposure.join(ExposureClass::Transformed);
        consent = consent.join(ConsentMode::Approval);
    }

    // Step 9: the route must resolve to exactly one registered destination.
    let route = match routes.len() {
        0 => None,
        1 => routes.into_iter().next(),
        _ => return Err(RuntimeError::RouteDenied),
    };

    Ok(PolicyDecision {
        matched_rules,
        exposure,
        consent,
        limits,
        route,
        policy_digest: *snapshot.digest(),
    })
}

/// Returns whether every constraint present in `selector` holds.
///
/// An absent constraint matches anything; a present one must be satisfied. A
/// fact the request could not supply never satisfies a constraint that asks
/// about it, so a selector can only ever narrow what it matches.
fn rule_matches(selector: &RuleMatch, facts: &EvaluationFacts) -> bool {
    if !opt_in(&selector.principal_ids, facts.principal_id.as_deref()) {
        return false;
    }
    if let Some(kinds) = &selector.principal_kinds {
        let actual = facts.principal_kind.map(principal_kind_name);
        if !actual.is_some_and(|name| kinds.iter().any(|k| k == name)) {
            return false;
        }
    }
    if !opt_in(&selector.adapter_ids, facts.adapter_id.as_deref()) {
        return false;
    }
    if let Some(transports) = &selector.transports {
        let actual = facts.transport.map(transport_name);
        if !actual.is_some_and(|name| transports.iter().any(|t| t == name)) {
            return false;
        }
    }
    if !opt_in(&selector.operations, facts.operation.as_deref()) {
        return false;
    }
    if !opt_in(&selector.origin_kinds, facts.origin_kind.as_deref()) {
        return false;
    }
    if !opt_in(
        &selector.destination_kinds,
        facts.destination_kind.as_deref(),
    ) {
        return false;
    }
    if !opt_in(&selector.destination_ids, facts.destination_id.as_deref()) {
        return false;
    }
    if !opt_glob(&selector.host_globs, facts.host.as_deref()) {
        return false;
    }
    if let Some(prefixes) = &selector.path_prefixes {
        let Some(path) = facts.path.as_deref() else {
            return false;
        };
        if !prefixes.iter().any(|prefix| path.starts_with(prefix)) {
            return false;
        }
    }
    if !opt_in(&selector.methods, facts.method.as_deref()) {
        return false;
    }
    if !opt_in(&selector.mcp_server_ids, facts.mcp_server_id.as_deref()) {
        return false;
    }
    if !opt_glob(&selector.mcp_tool_globs, facts.mcp_tool.as_deref()) {
        return false;
    }
    if !opt_in(
        &selector.process_profile_ids,
        facts.process_profile_id.as_deref(),
    ) {
        return false;
    }
    if let Some(kinds) = &selector.resource_kinds {
        if !kinds.iter().any(|kind| facts.resource_kinds.contains(kind)) {
            return false;
        }
    }
    if let Some(required) = &selector.labels_all {
        if !required.iter().all(|pattern| label_hit(facts, pattern)) {
            return false;
        }
    }
    if let Some(any) = &selector.labels_any {
        if !any.iter().any(|pattern| label_hit(facts, pattern)) {
            return false;
        }
    }
    if let Some(none) = &selector.labels_none {
        if none.iter().any(|pattern| label_hit(facts, pattern)) {
            return false;
        }
    }
    if let Some(states) = &selector.classification_states {
        let actual = classification_name(facts.classification);
        if !states.iter().any(|state| state == actual) {
            return false;
        }
    }
    true
}

/// Matches an optional exact-value constraint.
fn opt_in(constraint: &Option<Vec<String>>, actual: Option<&str>) -> bool {
    match constraint {
        None => true,
        Some(allowed) => actual.is_some_and(|value| allowed.iter().any(|a| a == value)),
    }
}

/// Matches an optional glob constraint.
fn opt_glob(constraint: &Option<Vec<String>>, actual: Option<&str>) -> bool {
    match constraint {
        None => true,
        Some(patterns) => {
            actual.is_some_and(|value| patterns.iter().any(|p| glob::matches(p, value)))
        }
    }
}

/// Returns whether any detected label matches `pattern`.
fn label_hit(facts: &EvaluationFacts, pattern: &str) -> bool {
    facts
        .labels
        .iter()
        .any(|label| glob::matches(pattern, label))
}

fn principal_kind_name(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::Client => "client",
        PrincipalKind::Adapter => "adapter",
        PrincipalKind::McpServer => "mcp_server",
        PrincipalKind::ProcessProfile => "process_profile",
    }
}

fn transport_name(transport: TransportKind) -> &'static str {
    match transport {
        TransportKind::Stdio => "stdio",
        TransportKind::Http => "http",
        TransportKind::WebSocket => "websocket",
        TransportKind::InProcess => "in_process",
    }
}

fn classification_name(state: ClassificationState) -> &'static str {
    match state {
        ClassificationState::Low => "low",
        ClassificationState::Elevated => "elevated",
        ClassificationState::Unknown => "unknown",
    }
}
