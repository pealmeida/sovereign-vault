//! Reference registry: audience enforcement, expiry, and single-use atomicity.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::thread;

use chrono::{Duration, Utc};

use sv_runtime::error::RuntimeError;
use sv_runtime::references::{
    LeaseOutcome, MaterialUseGrant, ReferenceEntry, ReferenceRegistry, ReferenceToken, RegistryKey,
    ResolutionContext, SafeMetadata,
};
use sv_runtime::types::{
    DestinationSelector, ExposureClass, InternalResourceId, OperationKind, PolicyVersion,
    PrincipalId, SessionId,
};

fn registry() -> ReferenceRegistry {
    ReferenceRegistry::new(RegistryKey::derive(&[11u8; 32]), false).expect("memory-only registry")
}

fn destination(label: &str) -> DestinationSelector {
    DestinationSelector {
        transport: None,
        host: None,
        path: None,
        label: Some(label.to_string()),
    }
}

fn operations() -> BTreeSet<OperationKind> {
    let mut set = BTreeSet::new();
    set.insert(OperationKind::Execute);
    set
}

fn entry() -> ReferenceEntry {
    let expires_at = Utc::now() + Duration::hours(1);
    ReferenceEntry {
        id_hash: [0u8; 32],
        resource: InternalResourceId("vault://providers/zai/api-key".to_string()),
        class: ExposureClass::ExecuteOnly,
        owner_principal: Some(PrincipalId("codex".to_string())),
        audience: vec![destination("provider:production")],
        allowed_operations: operations(),
        created_at: Utc::now(),
        expires_at,
        session_id: Some(SessionId("session-1".to_string())),
        max_uses: None,
        use_count: 0,
        metadata_projection: SafeMetadata {
            kind: "provider_credential".to_string(),
            allowed_actions: operations(),
            destination: vec![destination("provider:production")],
            expires_at,
        },
        policy_version: PolicyVersion(1),
        revoked: false,
    }
}

fn context() -> ResolutionContext {
    ResolutionContext {
        principal: Some(PrincipalId("codex".to_string())),
        session: Some(SessionId("session-1".to_string())),
        operation: OperationKind::Execute,
        destination: destination("provider:production"),
        now: Utc::now(),
    }
}

fn grant() -> MaterialUseGrant {
    MaterialUseGrant {
        context: context(),
        operation_digest: [9u8; 32],
    }
}

#[test]
fn metadata_resolves_for_a_valid_handle() {
    let registry = registry();
    let token = registry.create(entry()).expect("created");
    let resolved = registry.metadata(&token, &context()).expect("resolves");
    assert_eq!(resolved.metadata.kind, "provider_credential");
    assert_eq!(resolved.class, ExposureClass::ExecuteOnly);
}

/// Metadata resolution answers a question; it does not spend a use.
#[test]
fn metadata_does_not_increment_use_count() {
    let registry = registry();
    let token = registry.create(entry()).expect("created");
    for _ in 0..5 {
        registry.metadata(&token, &context()).expect("resolves");
    }
    assert_eq!(registry.use_count(&token).expect("counted"), 0);
}

/// The safe projection must not carry the resource path, and nothing in the
/// resolved metadata may reveal it either.
#[test]
fn metadata_never_exposes_the_resource() {
    let registry = registry();
    let token = registry.create(entry()).expect("created");
    let resolved = registry.metadata(&token, &context()).expect("resolves");
    let rendered = format!("{resolved:?}");
    assert!(!rendered.contains("vault://"));
    assert!(!rendered.contains("api-key"));
    assert!(!rendered.contains(&token.to_external()));
}

#[test]
fn unknown_token_is_invalid() {
    let registry = registry();
    registry.create(entry()).expect("created");
    let stranger = ReferenceToken::generate().expect("csprng");
    assert_eq!(
        registry
            .metadata(&stranger, &context())
            .expect_err("unknown handle"),
        RuntimeError::ReferenceInvalid
    );
}

#[test]
fn revoked_reference_is_denied() {
    let registry = registry();
    let token = registry.create(entry()).expect("created");
    registry.revoke(&token).expect("revoked");
    assert_eq!(
        registry.metadata(&token, &context()).expect_err("revoked"),
        RuntimeError::ReferenceInvalid
    );
}

#[test]
fn expired_reference_is_denied() {
    let registry = registry();
    let token = registry.create(entry()).expect("created");
    let later = ResolutionContext {
        now: Utc::now() + Duration::hours(2),
        ..context()
    };
    assert_eq!(
        registry.metadata(&token, &later).expect_err("expired"),
        RuntimeError::ReferenceExpired
    );
}

#[test]
fn wrong_principal_is_denied() {
    let registry = registry();
    let token = registry.create(entry()).expect("created");
    let other = ResolutionContext {
        principal: Some(PrincipalId("someone-else".to_string())),
        ..context()
    };
    assert_eq!(
        registry.metadata(&token, &other).expect_err("wrong owner"),
        RuntimeError::ReferenceAudienceDenied
    );
}

#[test]
fn wrong_session_is_denied() {
    let registry = registry();
    let token = registry.create(entry()).expect("created");
    let other = ResolutionContext {
        session: Some(SessionId("session-2".to_string())),
        ..context()
    };
    assert_eq!(
        registry
            .metadata(&token, &other)
            .expect_err("wrong session"),
        RuntimeError::ReferenceAudienceDenied
    );
}

#[test]
fn disallowed_operation_is_denied() {
    let registry = registry();
    let token = registry.create(entry()).expect("created");
    let other = ResolutionContext {
        operation: OperationKind::Read,
        ..context()
    };
    assert_eq!(
        registry
            .metadata(&token, &other)
            .expect_err("wrong operation"),
        RuntimeError::ReferenceAudienceDenied
    );
}

#[test]
fn wrong_audience_is_denied() {
    let registry = registry();
    let token = registry.create(entry()).expect("created");
    let other = ResolutionContext {
        destination: destination("provider:staging"),
        ..context()
    };
    assert_eq!(
        registry
            .metadata(&token, &other)
            .expect_err("wrong destination"),
        RuntimeError::ReferenceAudienceDenied
    );
}

#[test]
fn material_use_yields_a_lease_without_the_secret() {
    let registry = registry();
    let token = registry.create(entry()).expect("created");
    let lease = registry
        .authorize_material_use(&token, grant())
        .expect("authorized");
    assert_eq!(lease.operation_digest(), &[9u8; 32]);
    // The lease names the resource; it does not carry its value.
    assert_eq!(lease.resource().0, "vault://providers/zai/api-key");
    registry
        .settle(lease, LeaseOutcome::Completed)
        .expect("settled");
}

/// A single-use handle is spent before execution, so a replay finds it gone.
#[test]
fn single_use_is_consumed_before_execution() {
    let registry = registry();
    let token = registry
        .create(ReferenceEntry {
            max_uses: Some(1),
            ..entry()
        })
        .expect("created");

    let lease = registry
        .authorize_material_use(&token, grant())
        .expect("first use");
    assert_eq!(registry.use_count(&token).expect("counted"), 1);
    registry
        .settle(lease, LeaseOutcome::Completed)
        .expect("settled");

    assert_eq!(
        registry
            .authorize_material_use(&token, grant())
            .expect_err("replay must fail"),
        RuntimeError::ReferenceExpired
    );
}

/// The counter must advance under the same lock that authorizes the use, or two
/// threads can both redeem a one-shot handle.
#[test]
fn concurrent_consumption_consumes_exactly_once() {
    let registry = Arc::new(registry());
    let token = Arc::new(
        registry
            .create(ReferenceEntry {
                max_uses: Some(1),
                ..entry()
            })
            .expect("created"),
    );

    let handles: Vec<_> = (0..16)
        .map(|_| {
            let registry = Arc::clone(&registry);
            let token = Arc::clone(&token);
            thread::spawn(
                move || match registry.authorize_material_use(&token, grant()) {
                    Ok(lease) => {
                        // Settle as completed so the use is not returned.
                        registry
                            .settle(lease, LeaseOutcome::Completed)
                            .expect("settled");
                        true
                    }
                    Err(_) => false,
                },
            )
        })
        .collect();

    let winners = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread must not panic"))
        .filter(|redeemed| *redeemed)
        .count();

    assert_eq!(
        winners, 1,
        "exactly one thread may redeem a one-shot handle"
    );
    assert_eq!(registry.use_count(&token).expect("counted"), 1);
}

/// A use that provably caused no external effect is returned to the handle.
#[test]
fn consumed_not_executed_returns_the_use() {
    let registry = registry();
    let token = registry
        .create(ReferenceEntry {
            max_uses: Some(1),
            ..entry()
        })
        .expect("created");

    let lease = registry
        .authorize_material_use(&token, grant())
        .expect("first use");
    assert_eq!(registry.use_count(&token).expect("counted"), 1);
    registry
        .settle(lease, LeaseOutcome::ConsumedNotExecuted)
        .expect("settled");
    assert_eq!(registry.use_count(&token).expect("counted"), 0);

    // The handle works again, because nothing external happened.
    let lease = registry
        .authorize_material_use(&token, grant())
        .expect("reusable after a no-op");
    registry
        .settle(lease, LeaseOutcome::Completed)
        .expect("settled");
}

/// An unknown outcome must not return the use: the action may have happened.
#[test]
fn executed_unknown_keeps_the_use_spent() {
    let registry = registry();
    let token = registry
        .create(ReferenceEntry {
            max_uses: Some(1),
            ..entry()
        })
        .expect("created");

    let lease = registry
        .authorize_material_use(&token, grant())
        .expect("first use");
    registry
        .settle(lease, LeaseOutcome::ExecutedUnknown)
        .expect("settled");

    assert_eq!(registry.use_count(&token).expect("counted"), 1);
    assert_eq!(
        registry
            .authorize_material_use(&token, grant())
            .expect_err("must not be reusable"),
        RuntimeError::ReferenceExpired
    );
}

/// Dropping a lease without settling is the fail-safe path and is observable.
#[test]
fn unsettled_lease_drop_is_recorded() {
    let registry = registry();
    let token = registry.create(entry()).expect("created");
    let before = sv_runtime::references::unsettled_drops();
    {
        let _lease = registry
            .authorize_material_use(&token, grant())
            .expect("authorized");
        // Dropped here without settle.
    }
    assert!(
        sv_runtime::references::unsettled_drops() > before,
        "an unsettled drop must be recorded"
    );
    // The use stays spent, because the action may have happened.
    assert_eq!(registry.use_count(&token).expect("counted"), 1);
}

#[test]
fn durable_registry_is_rejected_for_now() {
    assert_eq!(
        ReferenceRegistry::new(RegistryKey::derive(&[1u8; 32]), true)
            .expect_err("durable is not implemented"),
        RuntimeError::InvalidStructure
    );
}

/// An empty audience means "any destination", which is how an unscoped handle
/// is expressed; a non-empty one is enforced exactly.
#[test]
fn empty_audience_permits_any_destination() {
    let registry = registry();
    let token = registry
        .create(ReferenceEntry {
            audience: Vec::new(),
            ..entry()
        })
        .expect("created");
    let anywhere = ResolutionContext {
        destination: destination("provider:anything"),
        ..context()
    };
    registry.metadata(&token, &anywhere).expect("resolves");
}

#[test]
fn errors_never_echo_the_token() {
    let registry = registry();
    let token = registry.create(entry()).expect("created");
    registry.revoke(&token).expect("revoked");
    let error = registry.metadata(&token, &context()).expect_err("revoked");
    assert!(!error.to_string().contains(&token.to_external()));
    assert!(!error.to_string().contains("vault://"));
}
