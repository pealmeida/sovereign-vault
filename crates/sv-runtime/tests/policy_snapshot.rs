//! Snapshot digest stability and `PolicyStore` reload semantics.
//!
//! The two properties that matter here are from §4.4 of the runtime spec: a
//! digest identifies a policy's *meaning* rather than its text, and a request
//! that is already in flight keeps evaluating against the snapshot it started
//! with, even while a reload installs a different one.

use std::sync::Arc;
use std::thread;

use sv_runtime::error::RuntimeError;
use sv_runtime::policy::document::parse;
use sv_runtime::policy::snapshot::{validate, PolicySnapshot, PolicyStore};
use sv_runtime::types::PolicyVersion;

const BASE: &str = r#"
schema = 1
default_effect = "deny"
policy_id = "snapshot-test"

[limits]
request_bytes = 8388608
fragment_bytes = 1048576
response_bytes = 16777216
concurrent_requests_per_principal = 4
request_timeout_ms = 120000
consent_timeout_ms = 120000
stream_boundary_bytes = 256

[[rule]]
id = "deny-arbitrary-process"
priority = 100
[rule.match]
operations = ["process.exec_arbitrary"]
[rule.effect]
access = "deny"
audit = "required"
"#;

fn snapshot_of(toml: &str, version: u64) -> PolicySnapshot {
    let document = parse(toml).expect("fixture must parse");
    validate(document, PolicyVersion(version)).expect("fixture must validate")
}

#[test]
fn digest_is_stable_across_formatting() {
    // Same policy, three ways of writing it: comments, blank lines, and a
    // different order for the keys inside each table.
    let commented = format!("# a leading comment\n{BASE}\n# a trailing comment\n");
    let respaced = BASE.replace('\n', "\n\n");
    let reordered = r#"
default_effect = "deny"
policy_id = "snapshot-test"
schema = 1

[limits]
stream_boundary_bytes = 256
consent_timeout_ms = 120000
request_timeout_ms = 120000
concurrent_requests_per_principal = 4
response_bytes = 16777216
fragment_bytes = 1048576
request_bytes = 8388608

[[rule]]
priority = 100
id = "deny-arbitrary-process"
[rule.match]
operations = ["process.exec_arbitrary"]
[rule.effect]
audit = "required"
access = "deny"
"#;

    let base = snapshot_of(BASE, 1);
    for (label, variant) in [
        ("commented", commented.as_str()),
        ("respaced", respaced.as_str()),
        ("reordered", reordered),
    ] {
        assert_eq!(
            base.digest(),
            snapshot_of(variant, 1).digest(),
            "formatting-only change altered the digest: {label}"
        );
    }
}

#[test]
fn digest_ignores_version() {
    // The version identifies *when* a policy was activated; the digest
    // identifies *what* it says. Two activations of identical text agree.
    assert_eq!(
        snapshot_of(BASE, 1).digest(),
        snapshot_of(BASE, 99).digest()
    );
}

#[test]
fn digest_changes_when_semantics_change() {
    let flipped = BASE.replace(r#"access = "deny""#, r#"access = "allow""#);
    assert_ne!(
        snapshot_of(BASE, 1).digest(),
        snapshot_of(&flipped, 1).digest(),
        "flipping an effect must change the digest"
    );

    let retimed = BASE.replace("request_timeout_ms = 120000", "request_timeout_ms = 60000");
    assert_ne!(
        snapshot_of(BASE, 1).digest(),
        snapshot_of(&retimed, 1).digest(),
        "changing a limit must change the digest"
    );

    let renamed = BASE.replace("deny-arbitrary-process", "deny-shell");
    assert_ne!(
        snapshot_of(BASE, 1).digest(),
        snapshot_of(&renamed, 1).digest(),
        "renaming a rule must change the digest"
    );
}

#[test]
fn digest_is_domain_separated() {
    // The digest must not be a bare SHA-256 of the serialized document, or a
    // hash computed elsewhere over the same bytes would collide with it.
    let snapshot = snapshot_of(BASE, 1);
    let bare = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(snapshot.document()).expect("document serializes"));
        let out: [u8; 32] = hasher.finalize().into();
        out
    };
    assert_ne!(snapshot.digest(), &bare, "digest must be domain separated");
}

#[test]
fn validation_failure_produces_no_snapshot() {
    let invalid = BASE.replace("request_bytes = 8388608", "request_bytes = 0");
    let document = parse(&invalid).expect("document parses; it is validation that fails");
    assert_eq!(
        validate(document, PolicyVersion(1)).expect_err("zero limit must fail"),
        RuntimeError::InvalidStructure
    );
}

#[test]
fn policy_unavailable_when_never_loaded() {
    let store = PolicyStore::new();
    assert_eq!(
        store.current().expect_err("empty store must fail closed"),
        RuntimeError::PolicyUnavailable
    );
}

#[test]
fn activate_makes_a_snapshot_current() {
    let store = PolicyStore::new();
    let expected = *snapshot_of(BASE, 1).digest();
    store.activate(snapshot_of(BASE, 1));
    assert_eq!(
        store.current().expect("snapshot is active").digest(),
        &expected
    );
}

/// A request that already holds a snapshot must finish under it, even though a
/// reload has since installed different policy.
#[test]
fn reload_does_not_affect_held_snapshot() {
    let store = PolicyStore::new();
    store.activate(snapshot_of(BASE, 1));

    let held = store.current().expect("first snapshot");
    let held_digest = *held.digest();

    let replacement = BASE.replace(r#"access = "deny""#, r#"access = "allow""#);
    store.activate(snapshot_of(&replacement, 2));

    assert_eq!(
        held.digest(),
        &held_digest,
        "held snapshot changed under us"
    );
    assert_ne!(
        store.current().expect("second snapshot").digest(),
        &held_digest,
        "store did not swap"
    );
}

/// Readers racing a writer must always observe one of the two valid snapshots
/// — never a torn or absent one — and must never panic.
#[test]
fn concurrent_reload_and_read() {
    let store = Arc::new(PolicyStore::new());
    let replacement = BASE.replace(r#"access = "deny""#, r#"access = "allow""#);

    let digest_a = *snapshot_of(BASE, 1).digest();
    let digest_b = *snapshot_of(&replacement, 2).digest();
    store.activate(snapshot_of(BASE, 1));

    let writer = {
        let store = Arc::clone(&store);
        let replacement = replacement.clone();
        thread::spawn(move || {
            for round in 0..50 {
                let toml = if round % 2 == 0 { &replacement } else { BASE };
                store.activate(snapshot_of(toml, round));
            }
        })
    };

    let readers: Vec<_> = (0..8)
        .map(|_| {
            let store = Arc::clone(&store);
            thread::spawn(move || {
                for _ in 0..200 {
                    let snapshot = store.current().expect("a policy is always active");
                    let digest = *snapshot.digest();
                    assert!(
                        digest == digest_a || digest == digest_b,
                        "observed a snapshot that was never activated"
                    );
                }
            })
        })
        .collect();

    writer.join().expect("writer must not panic");
    for reader in readers {
        reader.join().expect("reader must not panic");
    }
}

#[test]
fn warnings_are_carried_on_the_snapshot() {
    let mut toml = BASE.to_string();
    toml.push_str(
        r#"
[[rule]]
id = "allow-arbitrary-process"
priority = 1
[rule.match]
operations = ["process.exec_arbitrary"]
[rule.effect]
access = "allow"
exposure = "redact"
audit = "required"
"#,
    );
    let snapshot = snapshot_of(&toml, 1);
    assert!(
        !snapshot.warnings().is_empty(),
        "an allow shadowed by an identical deny must be reported"
    );
}
