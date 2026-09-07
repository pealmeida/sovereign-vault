//! Validation rules exercised through the TOML parser.
//!
//! `policy_validate.rs` covers the same rules by constructing document structs
//! directly. This file drives them through `parse` instead, so the cases stay
//! honest about what an operator can actually write in a policy file, and it
//! adds the reference-integrity and warning cases that struct construction
//! makes awkward to express.

use sv_runtime::error::RuntimeError;
use sv_runtime::policy::document::parse;
use sv_runtime::policy::validate::{check, ValidationWarning};

/// A minimal valid document: one https route, one rule naming it, one profile.
fn valid_toml() -> String {
    r#"
schema = 1
default_effect = "deny"
policy_id = "test-policy"

[limits]
request_bytes = 8388608
fragment_bytes = 1048576
response_bytes = 16777216
concurrent_requests_per_principal = 4
request_timeout_ms = 120000
consent_timeout_ms = 120000
stream_boundary_bytes = 256

[[rule]]
id = "allow-provider"
priority = 100
[rule.match]
destination_kinds = ["llm_provider"]
[rule.effect]
access = "allow"
exposure = "redact"
consent = "none"
audit = "required"
route = "primary"

[[provider_route]]
id = "primary"
protocol = "openai-chat"
base_url = "https://api.example.com/v1"
credential_ref = "vault://providers/example/api-key"
allowed_models = ["m1"]
allowed_methods = ["POST"]
allowed_path_prefixes = ["/chat/completions"]
follow_redirects = false
request_timeout_ms = 120000
max_response_bytes = 16777216

[[process_profile]]
id = "deploy"
executable = "C:/Program Files/Acme/deploy.exe"
working_directory_roots = ["D:/Code/approved"]
fixed_args = ["deploy"]
network_hosts = ["deploy.example.com"]
allow_children = false
timeout_ms = 300000
max_stdout_bytes = 2097152
max_stderr_bytes = 1048576
"#
    .to_string()
}

fn check_toml(toml: &str) -> Result<Vec<ValidationWarning>, RuntimeError> {
    check(&parse(toml).expect("fixture must parse"))
}

fn expect_invalid(toml: &str) -> RuntimeError {
    check_toml(toml).expect_err("document must be rejected")
}

/// The realistic document, written the way an operator would write it, is
/// accepted — including an executable path containing a space. The executable
/// is spawned directly rather than through a shell, so a space is not shell
/// indirection, and the policy reference's own example has one.
#[test]
fn accepts_realistic_document_with_spaced_executable_path() {
    let warnings = check_toml(&valid_toml()).expect("valid document must be accepted");
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
}

#[test]
fn rejects_empty_host() {
    let toml = valid_toml().replace("https://api.example.com/v1", "https:///v1");
    assert_eq!(expect_invalid(&toml), RuntimeError::InvalidStructure);
}

#[test]
fn rejects_unknown_mcp_server_reference() {
    let toml = valid_toml().replace(
        r#"destination_kinds = ["llm_provider"]"#,
        r#"mcp_server_ids = ["nope"]"#,
    );
    assert_eq!(expect_invalid(&toml), RuntimeError::InvalidStructure);
}

#[test]
fn rejects_unknown_process_profile_reference() {
    let toml = valid_toml().replace(
        r#"destination_kinds = ["llm_provider"]"#,
        r#"process_profile_ids = ["nope"]"#,
    );
    assert_eq!(expect_invalid(&toml), RuntimeError::InvalidStructure);
}

/// Two rules with an identical match set naming different routes is an
/// ambiguity the operator must see, but the document is still coherent, so it
/// is reported rather than rejected.
#[test]
fn ambiguous_route_is_a_warning() {
    let mut toml = valid_toml();
    toml.push_str(
        r#"
[[provider_route]]
id = "secondary"
protocol = "openai-chat"
base_url = "https://second.example.com/v1"
credential_ref = "vault://providers/second/api-key"
allowed_models = ["m2"]
allowed_methods = ["POST"]
allowed_path_prefixes = ["/chat/completions"]
follow_redirects = false
request_timeout_ms = 1000
max_response_bytes = 1024

[[rule]]
id = "allow-provider-alt"
priority = 90
[rule.match]
destination_kinds = ["llm_provider"]
[rule.effect]
access = "allow"
exposure = "redact"
consent = "none"
audit = "required"
route = "secondary"
"#,
    );
    let warnings = check_toml(&toml).expect("ambiguity is a warning, not an error");
    assert!(
        warnings.contains(&ValidationWarning::AmbiguousRoute {
            rule_id: "allow-provider-alt".to_string(),
        }),
        "expected AmbiguousRoute, got {warnings:?}"
    );
}

/// Validation errors must never carry policy content back to the caller, even
/// when the offending value is what triggered the failure.
#[test]
fn errors_never_echo_policy_content() {
    const CANARY: &str = "CANARY-2b77e";

    let cases = [
        valid_toml()
            .replace("test-policy", CANARY)
            .replace(r#"route = "primary""#, r#"route = "missing""#),
        valid_toml()
            .replace("vault://providers/example/api-key", CANARY)
            .replace("https://api.example.com", "http://api.example.com"),
        valid_toml()
            .replace("C:/Program Files/Acme/deploy.exe", "relative.exe")
            .replace("test-policy", CANARY),
    ];

    for toml in cases {
        let rendered = expect_invalid(&toml).to_string();
        assert!(
            !rendered.contains(CANARY),
            "error echoed policy content: {rendered:?}"
        );
        assert!(!rendered.contains("vault://"));
    }
}
