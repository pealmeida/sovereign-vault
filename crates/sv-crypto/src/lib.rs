//! Sovereign Vault cryptographic primitives.
//!
//! Provides authenticated encryption (XChaCha20-Poly1305), key derivation
//! (Argon2id), and zeroizing buffers. All sensitive byte buffers implement
//! `Zeroize` so plaintext is cleared from memory promptly.
//!
//! # Envelope format
//!
//! [`seal`] returns `[24-byte nonce | ciphertext+tag]`. [`open`] reverses
//! the operation and verifies the AAD passed in. The framing here is the
//! whole-file MVP envelope; the chunked `.svault-v2` format defined in
//! ADR-003 wraps this primitive with a per-chunk frame.
//!
//! # Stability
//!
//! Pre-1.0. APIs subject to change. The on-disk format produced by callers
//! of this crate is versioned independently (see `sv-storage`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of the symmetric master key in bytes (XChaCha20-Poly1305 takes 32-byte keys).
pub const MASTER_KEY_LEN: usize = 32;

/// Length of the XChaCha20-Poly1305 nonce in bytes.
pub const NONCE_LEN: usize = 24;

/// Length of the salt used for [`MasterKey::from_passphrase`] in bytes.
pub const SALT_LEN: usize = 16;

/// Crate-wide error type.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// AEAD operation failed (authentication tag mismatch or malformed input).
    #[error("AEAD operation failed: {0}")]
    Aead(String),

    /// Key derivation failed.
    #[error("Key derivation failed: {0}")]
    Kdf(String),

    /// Encoding or framing error (sealed buffer too small, etc.).
    #[error("Encoding error: {0}")]
    Encoding(String),

    /// Random number generation failed.
    #[error("Random number generation failed: {0}")]
    Random(String),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Symmetric 256-bit master key.
///
/// The underlying buffer is zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; MASTER_KEY_LEN]);

impl MasterKey {
    /// Generate a fresh random master key from the OS RNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; MASTER_KEY_LEN];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Derive a master key from a UTF-8 passphrase using Argon2id.
    ///
    /// Uses OWASP-recommended defaults (m=19 MiB, t=2, p=1) which are
    /// `Params::DEFAULT` in `argon2 0.5`.
    pub fn from_passphrase(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<Self> {
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::DEFAULT);
        let mut out = [0u8; MASTER_KEY_LEN];
        argon
            .hash_password_into(passphrase.as_bytes(), salt, &mut out)
            .map_err(|e| CryptoError::Kdf(e.to_string()))?;
        Ok(Self(out))
    }

    /// Construct a key from raw bytes (e.g. after loading from the keychain).
    pub fn from_bytes(bytes: [u8; MASTER_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying bytes. Avoid persisting this slice.
    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(REDACTED)")
    }
}

/// Generate `n` cryptographically secure random bytes.
pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).map_err(|e| CryptoError::Random(e.to_string()))?;
    Ok(buf)
}

/// Generate a fresh 16-byte salt suitable for [`MasterKey::from_passphrase`].
pub fn random_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| CryptoError::Random(e.to_string()))?;
    Ok(salt)
}

/// Encrypt `plaintext` under `key`, binding the additional-associated-data `aad`.
///
/// Returns `[24-byte nonce | ciphertext || tag]`. The nonce is freshly drawn
/// from the OS RNG.
pub fn seal(key: &MasterKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| CryptoError::Aead(e.to_string()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a buffer produced by [`seal`], verifying `aad` matches.
///
/// Returns the plaintext or an error if the tag mismatches or the buffer is malformed.
pub fn open(key: &MasterKey, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN {
        return Err(CryptoError::Encoding(format!(
            "sealed buffer too short: {} < {}",
            sealed.len(),
            NONCE_LEN
        )));
    }
    let (nonce_bytes, ct) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, Payload { msg: ct, aad })
        .map_err(|e| CryptoError::Aead(e.to_string()))
}

/// Crate version string.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_version() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = MasterKey::generate();
        let pt = b"hello sovereign vault";
        let aad = b"container/file.txt";
        let sealed = seal(&key, pt, aad).expect("seal");
        let opened = open(&key, &sealed, aad).expect("open");
        assert_eq!(opened, pt);
    }

    #[test]
    fn open_rejects_wrong_aad() {
        let key = MasterKey::generate();
        let sealed = seal(&key, b"data", b"aad-1").unwrap();
        assert!(open(&key, &sealed, b"aad-2").is_err());
    }

    #[test]
    fn open_rejects_truncated_buffer() {
        let key = MasterKey::generate();
        assert!(open(&key, &[0u8; 4], b"x").is_err());
    }

    #[test]
    fn passphrase_derivation_is_deterministic() {
        let salt = [7u8; SALT_LEN];
        let a = MasterKey::from_passphrase("hunter2", &salt).unwrap();
        let b = MasterKey::from_passphrase("hunter2", &salt).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        let c = MasterKey::from_passphrase("hunter3", &salt).unwrap();
        assert_ne!(a.as_bytes(), c.as_bytes());
    }
}
