use sv_runtime::error::RuntimeError;
use sv_runtime::policy::document::{
    AccessEffect, AuditRequirement, LimitsDocument, PolicyDocument, ProcessProfileDocument,
    ProviderRouteDocument, RuleDocument, RuleEffect, RuleMatch,
};
use sv_runtime::policy::validate::{check, ValidationWarning};
use sv_runtime::types::RuleExposure;

fn limits() -> LimitsDocument {
    LimitsDocument {
        request_bytes: 1,
        fragment_bytes: 1,
        response_bytes: 1,
        concurrent_requests_per_principal: 1,
        request_timeout_ms: 1,
        consent_timeout_ms: 1,
        stream_boundary_bytes: 1,
    }
}

fn route() -> ProviderRouteDocument {
    ProviderRouteDocument {
        id: "route-1".to_string(),
        protocol: "openai-chat".to_string(),
        base_url: "https://api.example.com".to_string(),
        credential_ref: "vault://example/key".to_string(),
        allowed_models: vec![],
        allowed_methods: vec![],
        allowed_path_prefixes: vec![],
        follow_redirects: false,
        request_timeout_ms: 1,
        max_response_bytes: 1,
    }
}

fn rule(
    id: &str,
    effect: AccessEffect,
    route: Option<&str>,
    exposure: Option<RuleExposure>,
) -> RuleDocument {
    RuleDocument {
        id: id.to_string(),
        priority: 1,
        match_: RuleMatch {
            resource_kinds: Some(vec!["transit_key".to_string()]),
            ..RuleMatch::default()
        },
        effect: RuleEffect {
            access: effect,
            exposure,
            consent: None,
            audit: AuditRequirement::Required,
            route: route.map(|s| s.to_string()),
            max_uses: None,
            ttl_seconds: None,
        },
    }
}

fn valid_doc() -> PolicyDocument {
    PolicyDocument {
        schema: 1,
        default_effect: "deny".to_string(),
        policy_id: "valid".to_string(),
        limits: limits(),
        rule: vec![rule("rule-1", AccessEffect::Allow, Some("route-1"), None)],
        reference_class: vec![],
        provider_route: vec![route()],
        mcp_server: vec![],
        process_profile: vec![],
    }
}

fn expect_invalid(doc: &PolicyDocument) -> RuntimeError {
    check(doc).expect_err("document must be rejected")
}

#[test]
fn accepts_valid_document() {
    check(&valid_doc()).expect("valid document must be accepted");
}

#[test]
fn rejects_duplicate_rule_ids() {
    let mut doc = valid_doc();
    doc.rule.push(doc.rule[0].clone());
    assert_eq!(expect_invalid(&doc), RuntimeError::InvalidStructure);
}

#[test]
fn rejects_duplicate_route_ids() {
    let mut doc = valid_doc();
    doc.provider_route.push(doc.provider_route[0].clone());
    assert_eq!(expect_invalid(&doc), RuntimeError::InvalidStructure);
}

#[test]
fn rejects_unknown_route_reference() {
    let mut doc = valid_doc();
    doc.rule[0].effect.route = Some("missing".to_string());
    let err = expect_invalid(&doc);
    assert_eq!(err, RuntimeError::RouteDenied, "got {err:?}");
}

#[test]
fn rejects_http_route() {
    let mut doc = valid_doc();
    doc.provider_route[0].base_url = "http://api.example.com".to_string();
    assert_eq!(expect_invalid(&doc), RuntimeError::InvalidStructure);
}

#[test]
fn rejects_wildcard_host() {
    let mut doc = valid_doc();
    doc.provider_route[0].base_url = "https://*.example.com".to_string();
    assert_eq!(expect_invalid(&doc), RuntimeError::InvalidStructure);
}

#[test]
fn rejects_raw_exposure_for_restricted_kinds() {
    let mut doc = valid_doc();
    doc.rule[0].effect.exposure = Some(RuleExposure::Raw);
    for kind in ["transit_key", "signing_key", "provider_credential"] {
        doc.rule[0].match_.resource_kinds = Some(vec![kind.to_string()]);
        assert_eq!(
            expect_invalid(&doc),
            RuntimeError::InvalidStructure,
            "{kind}"
        );
    }
}

#[test]
fn rejects_zero_limits() {
    let base = valid_doc();
    let check_limit = |setter: fn(&mut LimitsDocument)| {
        let mut d = base.clone();
        setter(&mut d.limits);
        assert_eq!(expect_invalid(&d), RuntimeError::InvalidStructure);
    };
    check_limit(|l| l.request_bytes = 0);
    check_limit(|l| l.fragment_bytes = 0);
    check_limit(|l| l.response_bytes = 0);
    check_limit(|l| l.concurrent_requests_per_principal = 0);
    check_limit(|l| l.request_timeout_ms = 0);
    check_limit(|l| l.consent_timeout_ms = 0);
    check_limit(|l| l.stream_boundary_bytes = 0);
}

#[test]
fn rejects_shell_metacharacters_in_executable() {
    let mut doc = valid_doc();
    doc.process_profile = vec![ProcessProfileDocument {
        id: "profile-1".to_string(),
        executable: "C:/Program Files/Acme/deploy.exe".to_string(),
        executable_sha256: None,
        working_directory_roots: vec![],
        argument_schema: None,
        fixed_args: vec![],
        network_hosts: vec![],
        allow_children: false,
        timeout_ms: 1,
        max_stdout_bytes: 1,
        max_stderr_bytes: 1,
        secret: vec![],
    }];
    for bad in ["&", "|", ";", "`", "$", ">", "<", "\n"] {
        let mut d = doc.clone();
        d.process_profile[0].executable = format!("C:/tool{bad}cmd.exe");
        assert_eq!(
            expect_invalid(&d),
            RuntimeError::InvalidStructure,
            "{bad:?}"
        );
    }
}

#[test]
fn rejects_relative_executable() {
    let mut doc = valid_doc();
    doc.process_profile = vec![ProcessProfileDocument {
        id: "profile-1".to_string(),
        executable: "tool.exe".to_string(),
        executable_sha256: None,
        working_directory_roots: vec![],
        argument_schema: None,
        fixed_args: vec![],
        network_hosts: vec![],
        allow_children: false,
        timeout_ms: 1,
        max_stdout_bytes: 1,
        max_stderr_bytes: 1,
        secret: vec![],
    }];
    assert_eq!(expect_invalid(&doc), RuntimeError::InvalidStructure);
}

#[test]
fn unreachable_allow_is_a_warning() {
    let mut doc = valid_doc();
    doc.rule = vec![
        rule("deny-rule", AccessEffect::Deny, None, None),
        rule("allow-rule", AccessEffect::Allow, None, None),
    ];
    let warnings = check(&doc).expect("should warn, not err");
    assert!(warnings.contains(&ValidationWarning::UnreachableAllow {
        rule_id: "allow-rule".to_string(),
    }));
}

#[test]
fn errors_never_echo_policy_content() {
    const CANARY: &str = "CANARY-2b77e";
    let mut doc = valid_doc();
    doc.policy_id = CANARY.to_string();
    doc.provider_route[0].credential_ref = format!("vault://{CANARY}");
    doc.rule[0].effect.route = Some("missing".to_string());
    doc.provider_route[0].base_url = "http://evil".to_string();

    for err in [
        expect_invalid(&doc),
        {
            let mut d = doc.clone();
            d.rule.push(d.rule[0].clone());
            expect_invalid(&d)
        },
        {
            let mut d = doc.clone();
            d.limits.request_bytes = 0;
            expect_invalid(&d)
        },
    ] {
        let rendered = format!("{err}");
        assert!(!rendered.contains(CANARY), "echoed canary: {rendered:?}");
    }
}
