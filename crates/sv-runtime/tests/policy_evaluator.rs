//! Decision composition: deny-overrides, ratcheting effects, and routing.
//!
//! These are the properties §4.3 of the runtime spec calls out as the ones an
//! allow rule must never be able to subvert.

use std::collections::BTreeSet;

use sv_runtime::error::RuntimeError;
use sv_runtime::policy::document::parse;
use sv_runtime::policy::evaluator::{evaluate, ClassificationState, EvaluationFacts};
use sv_runtime::policy::snapshot::{validate, PolicySnapshot};
use sv_runtime::types::{ConsentMode, ExposureClass, PolicyVersion};

const LIMITS: &str = r#"
schema = 1
default_effect = "deny"
policy_id = "evaluator-test"

[limits]
request_bytes = 8388608
fragment_bytes = 1048576
response_bytes = 16777216
concurrent_requests_per_principal = 4
request_timeout_ms = 120000
consent_timeout_ms = 120000
stream_boundary_bytes = 256
"#;

fn snapshot(extra: &str) -> PolicySnapshot {
    let document = parse(&format!("{LIMITS}{extra}")).expect("fixture must parse");
    validate(document, PolicyVersion(1)).expect("fixture must validate")
}

/// Facts for a plain provider request carrying no restricted material.
fn provider_facts() -> EvaluationFacts {
    EvaluationFacts {
        destination_kind: Some("llm_provider".to_string()),
        operation: Some("provider.request".to_string()),
        resource_exposure_floor: ExposureClass::Raw,
        ..EvaluationFacts::default()
    }
}

const ALLOW_PROVIDER: &str = r#"
[[rule]]
id = "allow-provider"
priority = 10
[rule.match]
destination_kinds = ["llm_provider"]
[rule.effect]
access = "allow"
exposure = "redact"
consent = "none"
audit = "required"
"#;

#[test]
fn allows_a_matching_request() {
    let decision = evaluate(&snapshot(ALLOW_PROVIDER), &provider_facts()).expect("allowed");
    assert_eq!(decision.matched_rules, vec!["allow-provider".to_string()]);
    assert_eq!(decision.exposure, ExposureClass::Transformed);
    assert_eq!(decision.consent, ConsentMode::None);
}

#[test]
fn no_matching_allow_denies() {
    let decision = evaluate(&snapshot(""), &provider_facts());
    assert_eq!(
        decision.expect_err("empty policy denies"),
        RuntimeError::PolicyDenied
    );
}

#[test]
fn a_non_matching_allow_denies() {
    let facts = EvaluationFacts {
        destination_kind: Some("external_mcp".to_string()),
        ..provider_facts()
    };
    assert_eq!(
        evaluate(&snapshot(ALLOW_PROVIDER), &facts).expect_err("no rule matches"),
        RuntimeError::PolicyDenied
    );
}

/// The central invariant: priority orders diagnostics, never outcomes. A
/// high-priority allow cannot outrank a low-priority deny.
#[test]
fn deny_overrides_allow_regardless_of_priority() {
    let policy = r#"
[[rule]]
id = "allow-high-priority"
priority = 1000
[rule.match]
destination_kinds = ["llm_provider"]
[rule.effect]
access = "allow"
exposure = "raw"
consent = "none"
audit = "required"

[[rule]]
id = "deny-low-priority"
priority = 1
[rule.match]
destination_kinds = ["llm_provider"]
[rule.effect]
access = "deny"
audit = "required"
"#;
    assert_eq!(
        evaluate(&snapshot(policy), &provider_facts()).expect_err("deny must win"),
        RuntimeError::PolicyDenied
    );
}

#[test]
fn deny_wins_from_either_declaration_order() {
    let deny_first = r#"
[[rule]]
id = "deny-first"
priority = 5
[rule.match]
destination_kinds = ["llm_provider"]
[rule.effect]
access = "deny"
audit = "required"
"#;
    let combined = format!("{ALLOW_PROVIDER}{deny_first}");
    let reversed = format!("{deny_first}{ALLOW_PROVIDER}");
    for policy in [combined.as_str(), reversed.as_str()] {
        assert_eq!(
            evaluate(&snapshot(policy), &provider_facts()).expect_err("deny must win"),
            RuntimeError::PolicyDenied
        );
    }
}

/// An allow rule asking for `raw` cannot lower the floor the resource's own
/// exposure class already established.
#[test]
fn allow_cannot_weaken_resource_class_floor() {
    let policy = r#"
[[rule]]
id = "allow-raw"
priority = 10
[rule.match]
destination_kinds = ["llm_provider"]
[rule.effect]
access = "allow"
exposure = "raw"
consent = "none"
audit = "required"
"#;
    for floor in [
        ExposureClass::Transformed,
        ExposureClass::ReferenceOnly,
        ExposureClass::ExecuteOnly,
        ExposureClass::NonExportable,
    ] {
        let facts = EvaluationFacts {
            resource_exposure_floor: floor,
            ..provider_facts()
        };
        let decision = evaluate(&snapshot(policy), &facts).expect("allowed");
        assert_eq!(
            decision.exposure, floor,
            "an allow rule weakened the floor for {floor:?}"
        );
    }
}

/// Exposure and consent join toward the more restrictive value across every
/// matching rule, whatever order they are declared in.
#[test]
fn effects_join_upward_across_rules() {
    let policy = r#"
[[rule]]
id = "allow-redact"
priority = 20
[rule.match]
destination_kinds = ["llm_provider"]
[rule.effect]
access = "allow"
exposure = "redact"
consent = "none"
audit = "required"

[[rule]]
id = "allow-reference-only"
priority = 10
[rule.match]
destination_kinds = ["llm_provider"]
[rule.effect]
access = "allow"
exposure = "reference-only"
consent = "otp"
audit = "required"
"#;
    let decision = evaluate(&snapshot(policy), &provider_facts()).expect("allowed");
    assert_eq!(decision.exposure, ExposureClass::ReferenceOnly);
    assert_eq!(decision.consent, ConsentMode::Otp);
    assert_eq!(decision.matched_rules.len(), 2);
}

/// Classification may raise the floors and may never lower them.
#[test]
fn classification_only_elevates() {
    let decision_low = evaluate(
        &snapshot(ALLOW_PROVIDER),
        &EvaluationFacts {
            classification: ClassificationState::Low,
            ..provider_facts()
        },
    )
    .expect("allowed");
    assert_eq!(decision_low.consent, ConsentMode::None);

    let decision_elevated = evaluate(
        &snapshot(ALLOW_PROVIDER),
        &EvaluationFacts {
            classification: ClassificationState::Elevated,
            ..provider_facts()
        },
    )
    .expect("allowed");
    assert_eq!(decision_elevated.consent, ConsentMode::Approval);
    assert!(decision_elevated.exposure >= decision_low.exposure);
}

#[test]
fn classification_cannot_lower_a_stronger_consent() {
    let policy =
        ALLOW_PROVIDER.replace(r#"consent = "none""#, r#"consent = "deny-if-unavailable""#);
    let decision = evaluate(
        &snapshot(&policy),
        &EvaluationFacts {
            classification: ClassificationState::Low,
            ..provider_facts()
        },
    )
    .expect("allowed");
    assert_eq!(decision.consent, ConsentMode::DenyIfUnavailable);
}

#[test]
fn evaluation_is_deterministic() {
    let snapshot = snapshot(ALLOW_PROVIDER);
    let facts = provider_facts();
    let first = evaluate(&snapshot, &facts).expect("allowed");
    for _ in 0..100 {
        assert_eq!(evaluate(&snapshot, &facts).expect("allowed"), first);
    }
}

#[test]
fn decision_carries_the_snapshot_digest() {
    let snapshot = snapshot(ALLOW_PROVIDER);
    let decision = evaluate(&snapshot, &provider_facts()).expect("allowed");
    assert_eq!(&decision.policy_digest, snapshot.digest());
}

#[test]
fn matched_rules_are_ordered_by_priority() {
    let policy = r#"
[[rule]]
id = "low"
priority = 1
[rule.match]
destination_kinds = ["llm_provider"]
[rule.effect]
access = "allow"
audit = "required"

[[rule]]
id = "high"
priority = 100
[rule.match]
destination_kinds = ["llm_provider"]
[rule.effect]
access = "allow"
audit = "required"
"#;
    let decision = evaluate(&snapshot(policy), &provider_facts()).expect("allowed");
    assert_eq!(
        decision.matched_rules,
        vec!["high".to_string(), "low".to_string()]
    );
}

#[test]
fn ambiguous_route_denies() {
    let policy = r#"
[[provider_route]]
id = "primary"
protocol = "openai-chat"
base_url = "https://one.example.com/v1"
credential_ref = "vault://one"
allowed_models = []
allowed_methods = ["POST"]
allowed_path_prefixes = ["/chat"]
follow_redirects = false
request_timeout_ms = 1000
max_response_bytes = 1024

[[provider_route]]
id = "secondary"
protocol = "openai-chat"
base_url = "https://two.example.com/v1"
credential_ref = "vault://two"
allowed_models = []
allowed_methods = ["POST"]
allowed_path_prefixes = ["/chat"]
follow_redirects = false
request_timeout_ms = 1000
max_response_bytes = 1024

[[rule]]
id = "route-one"
priority = 10
[rule.match]
destination_kinds = ["llm_provider"]
[rule.effect]
access = "allow"
audit = "required"
route = "primary"

[[rule]]
id = "route-two"
priority = 9
[rule.match]
destination_kinds = ["llm_provider"]
[rule.effect]
access = "allow"
audit = "required"
route = "secondary"
"#;
    assert_eq!(
        evaluate(&snapshot(policy), &provider_facts()).expect_err("ambiguity denies"),
        RuntimeError::RouteDenied
    );
}

#[test]
fn a_single_route_resolves() {
    let policy = r#"
[[provider_route]]
id = "primary"
protocol = "openai-chat"
base_url = "https://one.example.com/v1"
credential_ref = "vault://one"
allowed_models = []
allowed_methods = ["POST"]
allowed_path_prefixes = ["/chat"]
follow_redirects = false
request_timeout_ms = 1000
max_response_bytes = 1024

[[rule]]
id = "route-one"
priority = 10
[rule.match]
destination_kinds = ["llm_provider"]
[rule.effect]
access = "allow"
audit = "required"
route = "primary"
"#;
    let decision = evaluate(&snapshot(policy), &provider_facts()).expect("allowed");
    assert_eq!(decision.route.as_deref(), Some("primary"));
}

#[test]
fn oversized_request_is_rejected_before_rules() {
    let facts = EvaluationFacts {
        request_bytes: 8_388_609,
        ..provider_facts()
    };
    assert_eq!(
        evaluate(&snapshot(ALLOW_PROVIDER), &facts).expect_err("over the limit"),
        RuntimeError::LimitExceeded
    );

    let facts = EvaluationFacts {
        largest_fragment_bytes: 1_048_577,
        ..provider_facts()
    };
    assert_eq!(
        evaluate(&snapshot(ALLOW_PROVIDER), &facts).expect_err("fragment over the limit"),
        RuntimeError::LimitExceeded
    );
}

/// Label selectors are globs, and a `pii.*` selector matches one level only.
#[test]
fn label_selectors_use_glob_semantics() {
    let policy = r#"
[[rule]]
id = "pii-to-cloud"
priority = 10
[rule.match]
destination_kinds = ["llm_provider"]
labels_any = ["pii.*"]
[rule.effect]
access = "allow"
exposure = "pseudonymize"
consent = "none"
audit = "required"
"#;
    let mut labels = BTreeSet::new();
    labels.insert("pii.email".to_string());
    let facts = EvaluationFacts {
        labels,
        ..provider_facts()
    };
    let decision = evaluate(&snapshot(policy), &facts).expect("allowed");
    assert_eq!(decision.exposure, ExposureClass::Transformed);

    // A deeper label is a different selector and must not match.
    let mut deep = BTreeSet::new();
    deep.insert("pii.email.domain".to_string());
    let facts = EvaluationFacts {
        labels: deep,
        ..provider_facts()
    };
    assert_eq!(
        evaluate(&snapshot(policy), &facts).expect_err("deeper label does not match"),
        RuntimeError::PolicyDenied
    );
}

#[test]
fn labels_none_excludes() {
    let policy = r#"
[[rule]]
id = "allow-clean"
priority = 10
[rule.match]
destination_kinds = ["llm_provider"]
labels_none = ["secret.*"]
[rule.effect]
access = "allow"
consent = "none"
audit = "required"
"#;
    let mut labels = BTreeSet::new();
    labels.insert("secret.api_key".to_string());
    let facts = EvaluationFacts {
        labels,
        ..provider_facts()
    };
    assert_eq!(
        evaluate(&snapshot(policy), &facts).expect_err("excluded label denies"),
        RuntimeError::PolicyDenied
    );
}

/// A selector that asks about a fact the request never supplied must not match:
/// an absent fact can only narrow, never widen.
#[test]
fn absent_facts_do_not_satisfy_a_selector() {
    let policy = r#"
[[rule]]
id = "allow-known-adapter"
priority = 10
[rule.match]
adapter_ids = ["codex"]
[rule.effect]
access = "allow"
consent = "none"
audit = "required"
"#;
    assert_eq!(
        evaluate(&snapshot(policy), &provider_facts()).expect_err("no adapter id supplied"),
        RuntimeError::PolicyDenied
    );
}

/// A deny with no selector is a catch-all, which is how an operator disables a
/// capability outright.
#[test]
fn an_unselective_deny_matches_everything() {
    let policy = r#"
[[rule]]
id = "deny-everything"
priority = 1
[rule.match]
[rule.effect]
access = "deny"
audit = "required"
"#;
    assert_eq!(
        evaluate(&snapshot(policy), &provider_facts()).expect_err("catch-all deny"),
        RuntimeError::PolicyDenied
    );
}
