//! Secret-read budget for OS-keychain custody (perf/keychain-reads).
//!
//! An unsigned dev binary pays a macOS keychain authorization prompt for
//! every secret read of an item created by another binary. Status polling
//! must therefore read ZERO secrets, and unlocking a vault whose scoped
//! credential opens the keyring must read exactly ONE (the scoped entry),
//! never the legacy `master-key`. The fake backend (sv-keychain feature
//! `test-fake`) counts reads by account so these budgets are assertions,
//! not aspirations.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64_URL},
    Engine as _,
};
use sha2::{Digest, Sha256};
use sv_core::sv_keychain;
use sv_core::{CustodyMode, VaultHandle};

const LEGACY_ACCOUNT: &str = "master-key";
const PASSPHRASE: &str = "correct horse battery staple";

fn tmp_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("sv-core-keychain-reads-{label}-{nonce}"))
}

/// Mirror of sv-core's private `keychain_account_for_root`, kept in sync
/// the same way `os_keychain_live.rs` does.
fn scoped_account_for_root(root: &Path) -> String {
    let mut normalized = root
        .canonicalize()
        .unwrap_or_else(|_| root.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/");
    if cfg!(windows) {
        normalized = normalized.to_ascii_lowercase();
    }
    let digest = Sha256::digest(normalized.as_bytes());
    format!("master-key-{}", B64_URL.encode(&digest[..16]))
}

/// Bootstrap an OS-keychain custody vault through the fake backend and
/// return its root plus the scoped account name.
fn boot_os_keychain(label: &str) -> (PathBuf, String) {
    let root = tmp_root(label);
    let boot = VaultHandle::bootstrap(&root, CustodyMode::OsKeychain, None).unwrap();
    drop(boot);
    let account = scoped_account_for_root(&root);
    (root, account)
}

/// (ii) Unlock with a valid scoped credential: exactly one secret read,
/// the scoped account; the legacy master-key is never touched.
#[test]
fn unlock_with_valid_scoped_key_never_reads_legacy() {
    let _serialized = sv_keychain::fake::lock_for_test();
    let (root, scoped) = boot_os_keychain("scoped-valid");

    sv_keychain::fake::reset_reads();
    let handle = VaultHandle::unlock(&root, CustodyMode::OsKeychain, None).unwrap();
    drop(handle);

    assert_eq!(
        sv_keychain::fake::reads(),
        vec![scoped.clone()],
        "a healthy scoped credential must not cost a legacy read"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// (iii) No scoped entry but a legacy one: legacy is read, the vault
/// unlocks, and the credential is migrated into the scoped account.
#[test]
fn missing_scoped_falls_back_to_legacy_and_migrates() {
    let _serialized = sv_keychain::fake::lock_for_test();
    let (root, scoped) = boot_os_keychain("needs-migration");
    let legacy_kek = sv_keychain::fake::get(&scoped).expect("bootstrap stored scoped key");
    sv_keychain::fake::seed(LEGACY_ACCOUNT, &legacy_kek);
    // Drop the scoped entry so only the legacy credential remains.
    sv_keychain::fake::delete(&scoped).unwrap();

    sv_keychain::fake::reset_reads();
    let handle = VaultHandle::unlock(&root, CustodyMode::OsKeychain, None).unwrap();
    drop(handle);

    let reads = sv_keychain::fake::reads();
    assert_eq!(
        reads.first().map(String::as_str),
        Some(scoped.as_str()),
        "scoped is probed first"
    );
    assert!(
        reads.contains(&LEGACY_ACCOUNT.to_string()),
        "legacy must be consulted when the scoped entry is absent"
    );
    assert_eq!(
        sv_keychain::fake::get(&scoped).as_deref(),
        Some(legacy_kek.as_str()),
        "a successful legacy unlock migrates the credential to the scoped account"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// (iv) A scoped entry that cannot open the keyring (wrong key): only then
/// is the legacy credential consulted, and success rewrites the scoped
/// entry with the working key.
#[test]
fn incompatible_scoped_key_falls_back_to_legacy() {
    let _serialized = sv_keychain::fake::lock_for_test();
    let (root, scoped) = boot_os_keychain("scoped-wrong");
    let legacy_kek = sv_keychain::fake::get(&scoped).expect("bootstrap stored scoped key");
    sv_keychain::fake::seed(LEGACY_ACCOUNT, &legacy_kek);
    let wrong = B64.encode(sv_core::sv_crypto::random_bytes(32).unwrap());
    sv_keychain::fake::seed(&scoped, &wrong);

    sv_keychain::fake::reset_reads();
    let handle = VaultHandle::unlock(&root, CustodyMode::OsKeychain, None).unwrap();
    drop(handle);

    let reads = sv_keychain::fake::reads();
    assert!(
        reads.contains(&LEGACY_ACCOUNT.to_string()),
        "legacy consulted when scoped fails to open the keyring"
    );
    assert_eq!(
        sv_keychain::fake::get(&scoped).as_deref(),
        Some(legacy_kek.as_str()),
        "migration repairs the scoped credential"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// (v) A scoped READ that fails — denial or access error — propagates. It
/// must NOT degrade into a legacy read, which would let an unavailable
/// backend silently unlock under a different credential.
#[test]
fn denied_scoped_read_propagates_and_never_reads_legacy() {
    let _serialized = sv_keychain::fake::lock_for_test();
    let (root, _scoped) = boot_os_keychain("denied");

    sv_keychain::fake::reset_reads();
    sv_keychain::fake::deny_reads(Some("user denied access"));
    let error = VaultHandle::unlock(&root, CustodyMode::OsKeychain, None)
        .err()
        .expect("a denied scoped read must fail the unlock");
    sv_keychain::fake::deny_reads(None);

    assert!(
        error.to_string().contains("denied"),
        "the denial must reach the caller: {error}"
    );
    assert!(
        !sv_keychain::fake::reads().contains(&LEGACY_ACCOUNT.to_string()),
        "a denied scoped read must not fall through to the legacy credential"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// `probe_files` gathers the polling facts without a single keychain read,
/// unlike the live `probe` it joins in production.
#[test]
fn probe_files_reads_no_secrets() {
    let _serialized = sv_keychain::fake::lock_for_test();
    let root = tmp_root("fs-probe");
    let boot = VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some(PASSPHRASE)).unwrap();
    drop(boot);

    sv_keychain::fake::reset_reads();
    let state = sv_core::probe_files(&root).unwrap();
    assert!(state.initialized);
    assert!(state.has_passphrase_salt);
    assert!(state.has_keyring);
    assert!(sv_keychain::fake::reads().is_empty());
    let _ = std::fs::remove_dir_all(&root);
}
