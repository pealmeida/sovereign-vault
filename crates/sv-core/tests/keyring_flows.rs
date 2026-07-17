//! Integration tests for the ADR-0007 key hierarchy: bootstrap/unlock,
//! legacy migration, O(1) passphrase change, and key rotation. All flows use
//! passphrase + recovery custody to avoid touching the OS keychain.

use std::path::PathBuf;

use sv_core::sv_crypto::{random_bytes, MasterKey};
use sv_core::sv_storage::{SecurityMode, Vault};
use sv_core::{keyring, material_wrap_for_dek, sv_recovery, transit, CustodyMode, VaultHandle};

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
    let boot = VaultHandle::bootstrap(
        &root,
        CustodyMode::Passphrase,
        Some("hunter2-is-not-a-real-password"),
    )
    .unwrap();
    let k1 = boot.handle.audit_hmac_key();
    drop(boot.handle);

    let h = VaultHandle::unlock(
        &root,
        CustodyMode::Passphrase,
        Some("hunter2-is-not-a-real-password"),
    )
    .unwrap();
    let k2 = h.audit_hmac_key();
    assert_eq!(k1, k2);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn identity_keys_and_agent_tokens_survive_all_lifecycle_changes() {
    let root = tmp_dir("identity-stability");
    let boot = VaultHandle::bootstrap(
        &root,
        CustodyMode::Passphrase,
        Some("identity-passphrase-before-change"),
    )
    .unwrap();
    let mut handle = boot.handle;
    let audit_key = handle.audit_hmac_key();
    let agent_key = handle.agent_token_key();
    let (agent_id, token) = handle.create_agent("stable-agent", Vec::new()).unwrap();

    handle
        .change_passphrase(
            &root,
            "identity-passphrase-before-change",
            "identity-passphrase-after-change",
        )
        .unwrap();
    assert_eq!(handle.audit_hmac_key(), audit_key);
    assert_eq!(handle.agent_token_key(), agent_key);
    handle.authenticate_agent(&agent_id, &token).unwrap();

    let recovery_phrase = handle
        .rotate_key(&root, Some("identity-passphrase-after-change"))
        .unwrap();
    assert_eq!(handle.audit_hmac_key(), audit_key);
    assert_eq!(handle.agent_token_key(), agent_key);
    handle.authenticate_agent(&agent_id, &token).unwrap();
    drop(handle);

    let unlocked = VaultHandle::unlock(
        &root,
        CustodyMode::Passphrase,
        Some("identity-passphrase-after-change"),
    )
    .unwrap();
    assert_eq!(unlocked.audit_hmac_key(), audit_key);
    assert_eq!(unlocked.agent_token_key(), agent_key);
    unlocked.authenticate_agent(&agent_id, &token).unwrap();
    drop(unlocked);

    let recovered = VaultHandle::unlock_with_recovery(&root, &recovery_phrase).unwrap();
    assert_eq!(recovered.audit_hmac_key(), audit_key);
    assert_eq!(recovered.agent_token_key(), agent_key);
    recovered.authenticate_agent(&agent_id, &token).unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn passphrase_bootstrap_then_unlock_roundtrip() {
    let root = tmp_dir("bootstrap");
    let boot = VaultHandle::bootstrap(
        &root,
        CustodyMode::Passphrase,
        Some("hunter2-is-not-a-real-password"),
    )
    .unwrap();
    boot.handle
        .create_container("notes", SecurityMode::Direct, None)
        .unwrap();
    boot.handle.write_file("notes", "a.txt", b"secret").unwrap();
    drop(boot.handle);

    let h = VaultHandle::unlock(
        &root,
        CustodyMode::Passphrase,
        Some("hunter2-is-not-a-real-password"),
    )
    .unwrap();
    assert_eq!(h.read_file("notes", "a.txt").unwrap(), b"secret");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn bootstrap_refuses_existing_vault_disk_state() {
    let root = tmp_dir("bootstrap-refuses-disk");
    let boot = VaultHandle::bootstrap(
        &root,
        CustodyMode::Passphrase,
        Some("hunter2-is-not-a-real-password"),
    )
    .unwrap();
    drop(boot);

    let err = match VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some("new-pass")) {
        Ok(_) => panic!("bootstrap must not overwrite an initialized vault"),
        Err(error) => error,
    };
    assert!(
        err.to_string().contains("already initialised on disk"),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn bootstrap_rejects_short_new_passphrase_without_initializing() {
    let root = tmp_dir("bootstrap-short-passphrase");
    let error = match VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some("too-short")) {
        Ok(_) => panic!("short passphrase must be rejected"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("at least 16 characters"),
        "{error}"
    );
    assert!(!root.join("manifest.json").exists());
    assert!(!root.join("keyring.svault").exists());
    assert!(!root.join(".lifecycle.json").exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn stale_passphrase_salt_without_vault_state_does_not_block_bootstrap() {
    let root = tmp_dir("bootstrap-stale-salt");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("master.salt"),
        [7u8; sv_core::sv_crypto::SALT_LEN],
    )
    .unwrap();

    let boot = VaultHandle::bootstrap(
        &root,
        CustodyMode::Passphrase,
        Some("hunter2-is-not-a-real-password"),
    )
    .unwrap();
    boot.handle
        .create_container("notes", SecurityMode::Direct, None)
        .unwrap();
    boot.handle.write_file("notes", "a.txt", b"secret").unwrap();
    drop(boot.handle);

    let h = VaultHandle::unlock(
        &root,
        CustodyMode::Passphrase,
        Some("hunter2-is-not-a-real-password"),
    )
    .unwrap();
    assert_eq!(h.read_file("notes", "a.txt").unwrap(), b"secret");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn passphrase_probe_does_not_report_unrelated_keychain_entry() {
    let root = tmp_dir("probe-passphrase-keychain");
    let boot = VaultHandle::bootstrap(
        &root,
        CustodyMode::Passphrase,
        Some("hunter2-is-not-a-real-password"),
    )
    .unwrap();
    drop(boot);

    let probe = sv_core::probe(&root).unwrap();
    assert!(probe.initialized);
    assert!(probe.has_passphrase_salt);
    assert!(!probe.has_keychain_entry);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn passphrase_vault_rejects_os_keychain_unlock_with_clear_error() {
    let root = tmp_dir("passphrase-rejects-keychain");
    let boot = VaultHandle::bootstrap(
        &root,
        CustodyMode::Passphrase,
        Some("hunter2-is-not-a-real-password"),
    )
    .unwrap();
    drop(boot);

    let err = match VaultHandle::unlock(&root, CustodyMode::OsKeychain, None) {
        Ok(_) => panic!("passphrase vault must not unlock through OS keychain"),
        Err(error) => error,
    };
    assert!(err.to_string().contains("uses passphrase custody"), "{err}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn fresh_vault_roundtrips_multiple_modes_and_file_extensions() {
    let root = tmp_dir("mode-extension-matrix");
    let boot = VaultHandle::bootstrap(
        &root,
        CustodyMode::Passphrase,
        Some("matrix-passphrase-for-tests"),
    )
    .unwrap();
    let handle = boot.handle;

    let modes = [
        ("direct", SecurityMode::Direct),
        ("approval", SecurityMode::Approval),
        ("otp", SecurityMode::Otp),
        ("anonymized", SecurityMode::Anonymized),
        ("zkp", SecurityMode::Zkp),
        ("native", SecurityMode::Native),
    ];
    let files = [
        (".env", b"API_KEY=fake-test-key\n".as_slice()),
        ("config.json", br#"{"enabled":true,"level":3}"#.as_slice()),
        ("notes.md", b"# Notes\nprivate local context\n".as_slice()),
        ("plain.txt", b"hello vault".as_slice()),
        ("table.csv", b"id,value\n1,alpha\n2,beta\n".as_slice()),
        ("blob.bin", &[0, 1, 2, 3, 250, 251, 252, 253][..]),
        (
            "private.pem",
            b"-----BEGIN TEST KEY-----\nfake\n-----END TEST KEY-----\n".as_slice(),
        ),
    ];

    for (container, mode) in modes {
        handle
            .create_container(container, mode, Some(format!("{mode:?} mode")))
            .unwrap();
        assert_eq!(handle.container_mode(container).unwrap(), mode);

        for (file_name, plaintext) in files {
            handle.write_file(container, file_name, plaintext).unwrap();
            assert_eq!(handle.read_file(container, file_name).unwrap(), plaintext);
        }
    }
    drop(handle);

    let unlocked = VaultHandle::unlock(
        &root,
        CustodyMode::Passphrase,
        Some("matrix-passphrase-for-tests"),
    )
    .unwrap();
    for (container, mode) in modes {
        assert_eq!(unlocked.container_mode(container).unwrap(), mode);
        let listed = unlocked.list_files(container).unwrap();
        assert_eq!(listed.len(), files.len());

        for (file_name, plaintext) in files {
            assert_eq!(unlocked.read_file(container, file_name).unwrap(), plaintext);
        }
    }

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

    // Migrate the legacy vault: first migrate manifest authentication, then unlock.
    let digest = VaultHandle::manifest_migration_digest(&root).unwrap();
    VaultHandle::migrate_manifest_authentication(
        &root,
        CustodyMode::Passphrase,
        Some("legacy-pass"),
        &digest,
    )
    .unwrap();

    // Unlock through the high-level handle: should read fine after migration.
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
    let boot = VaultHandle::bootstrap(
        &root,
        CustodyMode::Passphrase,
        Some("old-passphrase-for-tests"),
    )
    .unwrap();
    boot.handle
        .create_container("c", SecurityMode::Direct, None)
        .unwrap();
    boot.handle.write_file("c", "f.txt", b"keep-me").unwrap();

    boot.handle
        .change_passphrase(
            &root,
            "old-passphrase-for-tests",
            "new-passphrase-for-tests",
        )
        .unwrap();
    drop(boot.handle);

    // Old passphrase no longer unwraps the keyring.
    assert!(VaultHandle::unlock(
        &root,
        CustodyMode::Passphrase,
        Some("old-passphrase-for-tests")
    )
    .is_err());
    // New passphrase opens the same data.
    let h = VaultHandle::unlock(
        &root,
        CustodyMode::Passphrase,
        Some("new-passphrase-for-tests"),
    )
    .unwrap();
    assert_eq!(h.read_file("c", "f.txt").unwrap(), b"keep-me");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn rejected_short_passphrase_change_preserves_old_custody() {
    let root = tmp_dir("change-short-passphrase");
    let boot = VaultHandle::bootstrap(
        &root,
        CustodyMode::Passphrase,
        Some("existing-passphrase-for-tests"),
    )
    .unwrap();
    let error = boot
        .handle
        .change_passphrase(&root, "existing-passphrase-for-tests", "short")
        .unwrap_err();
    assert!(error.to_string().contains("at least 16 characters"));
    drop(boot.handle);

    assert!(VaultHandle::unlock(
        &root,
        CustodyMode::Passphrase,
        Some("existing-passphrase-for-tests")
    )
    .is_ok());
    assert!(!root.join(".lifecycle.json").exists());
    assert!(!root.join(keyring::STAGED_KEYRING_FILE).exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn rotate_key_reseals_files_and_reissues_recovery() {
    let root = tmp_dir("rotate");
    let boot = VaultHandle::bootstrap(
        &root,
        CustodyMode::Passphrase,
        Some("rotation-passphrase-for-tests"),
    )
    .unwrap();
    let old_phrase = boot.recovery_phrase.clone();
    let mut handle = boot.handle;
    handle
        .create_container("c", SecurityMode::Direct, None)
        .unwrap();
    handle.write_file("c", "f.txt", b"rotate-me").unwrap();

    let new_phrase = handle
        .rotate_key(&root, Some("rotation-passphrase-for-tests"))
        .unwrap();
    assert_ne!(old_phrase, new_phrase);
    // Data still readable in the rotated session.
    assert_eq!(handle.read_file("c", "f.txt").unwrap(), b"rotate-me");
    drop(handle);

    // Passphrase still unlocks (KEK unchanged) and reads the re-sealed data.
    let h = VaultHandle::unlock(
        &root,
        CustodyMode::Passphrase,
        Some("rotation-passphrase-for-tests"),
    )
    .unwrap();
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
    let boot = VaultHandle::bootstrap(
        &root,
        CustodyMode::Passphrase,
        Some("hunter2-is-not-a-real-password"),
    )
    .unwrap();
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
    let new_phrase = handle
        .rotate_key(&root, Some("hunter2-is-not-a-real-password"))
        .unwrap();
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
    let h = VaultHandle::unlock(
        &root,
        CustodyMode::Passphrase,
        Some("hunter2-is-not-a-real-password"),
    )
    .unwrap();
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
    let boot = VaultHandle::bootstrap(
        &root,
        CustodyMode::Passphrase,
        Some("recovery-passphrase-for-tests"),
    )
    .unwrap();
    let phrase = boot.recovery_phrase.clone();
    boot.handle
        .create_container("c", SecurityMode::Direct, None)
        .unwrap();
    boot.handle.write_file("c", "f.txt", b"recover-me").unwrap();
    drop(boot.handle);

    let h = VaultHandle::unlock_with_recovery(&root, &phrase).unwrap();
    assert_eq!(h.custody(), CustodyMode::Recovery);
    assert_eq!(h.read_file("c", "f.txt").unwrap(), b"recover-me");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn keyring_can_be_repaired_from_recovered_active_dek() {
    let root = tmp_dir("repair-keyring");
    let boot = VaultHandle::bootstrap(
        &root,
        CustodyMode::Passphrase,
        Some("recovery-passphrase-for-tests"),
    )
    .unwrap();
    let phrase = boot.recovery_phrase.clone();
    boot.handle
        .create_container("c", SecurityMode::Direct, None)
        .unwrap();
    boot.handle.write_file("c", "f.txt", b"recover-me").unwrap();
    drop(boot.handle);

    let active = keyring::active_version(&root).unwrap();
    let recovered_dek = sv_recovery::restore_master_key(&root, &phrase).unwrap();
    let repaired_kek = MasterKey::generate();
    keyring::replace_with_single_active_dek(&root, &repaired_kek, active, &recovered_dek).unwrap();

    // After keyring repair, the passphrase no longer unlocks (KEK was replaced).
    assert!(VaultHandle::unlock(
        &root,
        CustodyMode::Passphrase,
        Some("recovery-passphrase-for-tests")
    )
    .is_err());

    // Verify the repaired keyring unwraps correctly with the new KEK.
    let unwrapped = keyring::load(&root, &repaired_kek).unwrap();
    assert_eq!(unwrapped.active_version, active);

    // Open the vault with manifest authentication using the recovered DEK.
    let identity = transit::load_identity(&root, &material_wrap_for_dek(&recovered_dek)).unwrap();
    let manifest_auth_key = sv_core::sv_storage::derive_manifest_auth_key(&identity.root);
    let mut keys = std::collections::BTreeMap::new();
    keys.insert(active, recovered_dek);
    let vault =
        Vault::open_existing_with_keys_and_manifest_key(&root, keys, active, manifest_auth_key)
            .unwrap();
    assert_eq!(vault.read_file("c", "f.txt").unwrap(), b"recover-me");
    let _ = std::fs::remove_dir_all(&root);
}
