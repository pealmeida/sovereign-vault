use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64_URL},
    Engine as _,
};
use sha2::{Digest, Sha256};
use sv_core::{
    sv_crypto::MasterKey, sv_keychain, sv_storage::SecurityMode, CustodyMode, VaultHandle,
};

struct Cleanup {
    roots: Vec<PathBuf>,
    accounts: Vec<String>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for account in &self.accounts {
            let _ = sv_keychain::delete_master_key_for_account(account);
        }
        for root in &self.roots {
            let _ = fs::remove_dir_all(root);
        }
    }
}

fn keychain_account_for_root(root: &Path) -> String {
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

#[test]
#[ignore = "touches the host OS keychain; run manually for local custody validation"]
fn os_keychain_supports_multiple_vault_roots_without_collision() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!(
        "sovereign-vault-os-keychain-live-{}-{nonce}",
        std::process::id()
    ));
    let first = base.join("first");
    let second = base.join("second");
    fs::create_dir_all(&first).unwrap();
    fs::create_dir_all(&second).unwrap();

    let _cleanup = Cleanup {
        roots: vec![base.clone()],
        accounts: vec![
            keychain_account_for_root(&first),
            keychain_account_for_root(&second),
        ],
    };

    let first_bootstrap = VaultHandle::bootstrap(&first, CustodyMode::OsKeychain, None).unwrap();
    first_bootstrap
        .handle
        .create_container("direct", SecurityMode::Direct, None)
        .unwrap();
    first_bootstrap
        .handle
        .write_file("direct", "first.txt", b"first vault data")
        .unwrap();
    drop(first_bootstrap);

    let second_bootstrap = VaultHandle::bootstrap(&second, CustodyMode::OsKeychain, None).unwrap();
    second_bootstrap
        .handle
        .create_container("direct", SecurityMode::Direct, None)
        .unwrap();
    second_bootstrap
        .handle
        .write_file("direct", "second.txt", b"second vault data")
        .unwrap();
    drop(second_bootstrap);

    let first_unlocked = VaultHandle::unlock(&first, CustodyMode::OsKeychain, None).unwrap();
    assert_eq!(
        first_unlocked.read_file("direct", "first.txt").unwrap(),
        b"first vault data"
    );

    let second_unlocked = VaultHandle::unlock(&second, CustodyMode::OsKeychain, None).unwrap();
    assert_eq!(
        second_unlocked.read_file("direct", "second.txt").unwrap(),
        b"second vault data"
    );
}

#[test]
#[ignore = "touches the host OS keychain; run manually for local custody validation"]
fn recovery_unlock_repairs_broken_os_keychain_entry() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "sovereign-vault-os-keychain-repair-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let account = keychain_account_for_root(&root);

    let _cleanup = Cleanup {
        roots: vec![root.clone()],
        accounts: vec![account.clone()],
    };

    let bootstrap = VaultHandle::bootstrap(&root, CustodyMode::OsKeychain, None).unwrap();
    let recovery_phrase = bootstrap.recovery_phrase.clone();
    bootstrap
        .handle
        .create_container("direct", SecurityMode::Direct, None)
        .unwrap();
    bootstrap
        .handle
        .write_file("direct", "secret.txt", b"repair me")
        .unwrap();
    drop(bootstrap);

    let wrong_kek = MasterKey::generate();
    sv_keychain::store_master_key_for_account(&account, &B64.encode(wrong_kek.as_bytes())).unwrap();
    assert!(VaultHandle::unlock(&root, CustodyMode::OsKeychain, None).is_err());

    let recovered = VaultHandle::unlock_with_recovery(&root, &recovery_phrase).unwrap();
    assert_eq!(recovered.custody(), CustodyMode::OsKeychain);
    assert_eq!(
        recovered.read_file("direct", "secret.txt").unwrap(),
        b"repair me"
    );
    drop(recovered);

    let keychain_unlocked = VaultHandle::unlock(&root, CustodyMode::OsKeychain, None).unwrap();
    assert_eq!(
        keychain_unlocked.read_file("direct", "secret.txt").unwrap(),
        b"repair me"
    );
}

#[test]
#[ignore = "touches the host OS keychain; run manually for local custody validation"]
fn passphrase_vault_can_move_to_os_keychain() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "sovereign-vault-os-keychain-convert-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let account = keychain_account_for_root(&root);

    let _cleanup = Cleanup {
        roots: vec![root.clone()],
        accounts: vec![account],
    };

    let bootstrap =
        VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some("move-me-passphrase")).unwrap();
    let mut handle = bootstrap.handle;
    handle
        .create_container("direct", SecurityMode::Direct, None)
        .unwrap();
    handle
        .write_file("direct", "secret.txt", b"converted")
        .unwrap();

    handle.move_to_os_keychain(&root, "move-me").unwrap();
    assert_eq!(handle.custody(), CustodyMode::OsKeychain);
    assert!(!root.join("master.salt").exists());
    drop(handle);

    let keychain_unlocked = VaultHandle::unlock(&root, CustodyMode::OsKeychain, None).unwrap();
    assert_eq!(
        keychain_unlocked.read_file("direct", "secret.txt").unwrap(),
        b"converted"
    );

    let probe = sv_core::probe(&root).unwrap();
    assert!(probe.keychain_available);
    assert!(probe.has_keychain_entry);
    assert!(!probe.has_passphrase_salt);
}
