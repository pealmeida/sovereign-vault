//! Integration tests for the ADR-0007 key hierarchy: bootstrap/unlock,
//! legacy migration, O(1) passphrase change, and key rotation. All flows use
//! passphrase + recovery custody to avoid touching the OS keychain.

use std::path::PathBuf;

use sv_core::sv_crypto::{random_bytes, MasterKey};
use sv_core::sv_storage::{SecurityMode, Vault};
use sv_core::{transit, CustodyMode, VaultHandle};

fn tmp_dir(label: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let hex: String = random_bytes(8)
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    p.push(format!("sv-core-it-{label}-{hex}"));
    p
}

#[test]
fn audit_hmac_key_stable_across_unlocks() {
    let root = tmp_dir("audithmac");
    let boot = VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some("hunter2")).unwrap();
    let k1 = boot.handle.audit_hmac_key();
    drop(boot.handle);

    let h = VaultHandle::unlock(&root, CustodyMode::Passphrase, Some("hunter2")).unwrap();
    let k2 = h.audit_hmac_key();
    assert_eq!(k1, k2);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn passphrase_bootstrap_then_unlock_roundtrip() {
    let root = tmp_dir("bootstrap");
    let boot = VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some("hunter2")).unwrap();
    boot.handle
        .create_container("notes", SecurityMode::Direct, None)
        .unwrap();
    boot.handle.write_file("notes", "a.txt", b"secret").unwrap();
    drop(boot.handle);

    let h = VaultHandle::unlock(&root, CustodyMode::Passphrase, Some("hunter2")).unwrap();
    assert_eq!(h.read_file("notes", "a.txt").unwrap(), b"secret");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn legacy_vault_migrates_and_reads_old_files() {
    // Simulate a pre-keyring vault: salt on disk, files sealed directly with
    // the passphrase-derived key, and NO keyring.svault.
    let root = tmp_dir("legacy");
    std::fs::create_dir_all(&root).unwrap();
    let salt = sv_core::sv_crypto::random_salt().unwrap();
    std::fs::write(root.join("master.salt"), salt).unwrap();
    let legacy_key = MasterKey::from_passphrase("legacy-pass", &salt).unwrap();
    {
        let v = Vault::open_or_init(&root, legacy_key).unwrap();
        v.create_container("c", SecurityMode::Direct, None).unwrap();
        v.write_file("c", "old.txt", b"legacy-data").unwrap();
    }
    assert!(!root.join("keyring.svault").exists());

    // Unlock through the high-level handle: should migrate, then read.
    let h = VaultHandle::unlock(&root, CustodyMode::Passphrase, Some("legacy-pass")).unwrap();
    assert!(root.join("keyring.svault").exists());
    assert_eq!(h.read_file("c", "old.txt").unwrap(), b"legacy-data");

    // Migration is idempotent — a second unlock still reads fine.
    drop(h);
    let h2 = VaultHandle::unlock(&root, CustodyMode::Passphrase, Some("legacy-pass")).unwrap();
    assert_eq!(h2.read_file("c", "old.txt").unwrap(), b"legacy-data");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn change_passphrase_preserves_data_without_reencrypting() {
    let root = tmp_dir("changepass");
    let boot = VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some("old-pass")).unwrap();
    boot.handle
        .create_container("c", SecurityMode::Direct, None)
        .unwrap();
    boot.handle.write_file("c", "f.txt", b"keep-me").unwrap();

    boot.handle
        .change_passphrase(&root, "old-pass", "new-pass")
        .unwrap();
    drop(boot.handle);

    // Old passphrase no longer unwraps the keyring.
    assert!(VaultHandle::unlock(&root, CustodyMode::Passphrase, Some("old-pass")).is_err());
    // New passphrase opens the same data.
    let h = VaultHandle::unlock(&root, CustodyMode::Passphrase, Some("new-pass")).unwrap();
    assert_eq!(h.read_file("c", "f.txt").unwrap(), b"keep-me");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn rotate_key_reseals_files_and_reissues_recovery() {
    let root = tmp_dir("rotate");
    let boot = VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some("pass")).unwrap();
    let old_phrase = boot.recovery_phrase.clone();
    let mut handle = boot.handle;
    handle
        .create_container("c", SecurityMode::Direct, None)
        .unwrap();
    handle.write_file("c", "f.txt", b"rotate-me").unwrap();

    let new_phrase = handle.rotate_key(&root, Some("pass")).unwrap();
    assert_ne!(old_phrase, new_phrase);
    // Data still readable in the rotated session.
    assert_eq!(handle.read_file("c", "f.txt").unwrap(), b"rotate-me");
    drop(handle);

    // Passphrase still unlocks (KEK unchanged) and reads the re-sealed data.
    let h = VaultHandle::unlock(&root, CustodyMode::Passphrase, Some("pass")).unwrap();
    assert_eq!(h.read_file("c", "f.txt").unwrap(), b"rotate-me");
    drop(h);

    // New recovery phrase works; the old one no longer matches the bundle.
    let hr = VaultHandle::unlock_with_recovery(&root, &new_phrase).unwrap();
    assert_eq!(hr.read_file("c", "f.txt").unwrap(), b"rotate-me");
    assert!(VaultHandle::unlock_with_recovery(&root, &old_phrase).is_err());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn rotate_key_preserves_transit_signing_and_broker_material() {
    // Regression: `rotate_key` once re-sealed only container files and dropped
    // the old DEK, permanently orphaning all transit/signing/broker material
    // (which is wrapped under a subkey of the active DEK). The listings still
    // showed the keys, so the breakage was silent. Rotation must now re-wrap
    // every entry forward so encrypt/decrypt/sign/verify/resolve all survive.
    let root = tmp_dir("rotate-material");
    let boot = VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some("hunter2")).unwrap();
    let mut handle = boot.handle;

    // Transit key + a ciphertext produced BEFORE rotation.
    handle.transit_create_key("demo-key").unwrap();
    let pre_ct = handle
        .transit_encrypt("demo-key", b"rotate-me-please")
        .unwrap();
    assert_eq!(
        handle.transit_decrypt("demo-key", &pre_ct).unwrap(),
        b"rotate-me-please"
    );

    // Signing key + a signature produced BEFORE rotation.
    let sk = handle.signing_create_key("signer").unwrap();
    let pre_sig = handle.signing_sign("signer", b"payload").unwrap();

    // Brokered secret with a destination allowlist.
    let allow = vec![transit::BrokerAllow {
        host: "api.example.com".into(),
        path_prefix: "/v1".into(),
        methods: vec!["GET".into()],
        allow_private_ip: false,
    }];
    handle
        .broker_create(
            "stripe",
            "sk_live_xyz",
            allow.clone(),
            transit::BrokerInjection::BearerAuth,
        )
        .unwrap();

    // Rotate the DEK.
    let new_phrase = handle.rotate_key(&root, Some("hunter2")).unwrap();
    assert!(!new_phrase.is_empty());

    // Listings still show the keys (they always did — that was the trap).
    assert_eq!(handle.transit_list().unwrap().len(), 1);
    assert_eq!(handle.signing_list().unwrap().len(), 1);
    assert_eq!(handle.broker_list().unwrap().len(), 1);

    // Transit: the PRE-rotation ciphertext still decrypts, and a fresh
    // encrypt/decrypt round-trips under the rotated DEK.
    assert_eq!(
        handle.transit_decrypt("demo-key", &pre_ct).unwrap(),
        b"rotate-me-please"
    );
    let post_ct = handle
        .transit_encrypt("demo-key", b"after-rotation")
        .unwrap();
    assert_eq!(
        handle.transit_decrypt("demo-key", &post_ct).unwrap(),
        b"after-rotation"
    );

    // Signing: the PRE-rotation signature still verifies, and new signing works.
    assert!(transit::signing_verify(&sk.public_b64, b"payload", &pre_sig).unwrap());
    let post_sig = handle.signing_sign("signer", b"more").unwrap();
    assert!(transit::signing_verify(&sk.public_b64, b"more", &post_sig).unwrap());

    // Broker: resolve still yields the secret and its allowlist.
    let resolved = handle.broker_resolve("stripe").unwrap();
    assert_eq!(resolved.secret, "sk_live_xyz");
    assert_eq!(resolved.allow, allow);
    drop(handle);

    // Material also survives a fresh unlock from disk.
    let h = VaultHandle::unlock(&root, CustodyMode::Passphrase, Some("hunter2")).unwrap();
    assert_eq!(
        h.transit_decrypt("demo-key", &pre_ct).unwrap(),
        b"rotate-me-please"
    );
    assert!(transit::signing_verify(&sk.public_b64, b"payload", &pre_sig).unwrap());
    assert_eq!(h.broker_resolve("stripe").unwrap().secret, "sk_live_xyz");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn recovery_unlock_after_bootstrap() {
    let root = tmp_dir("recovery");
    let boot = VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some("pw")).unwrap();
    let phrase = boot.recovery_phrase.clone();
    boot.handle
        .create_container("c", SecurityMode::Direct, None)
        .unwrap();
    boot.handle.write_file("c", "f.txt", b"recover-me").unwrap();
    drop(boot.handle);

    let h = VaultHandle::unlock_with_recovery(&root, &phrase).unwrap();
    assert_eq!(h.read_file("c", "f.txt").unwrap(), b"recover-me");
    let _ = std::fs::remove_dir_all(&root);
}
