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
use hkdf::Hkdf;
use rand::Rng; // rand 0.10 renamed the core trait RngCore -> Rng (provides fill_bytes)
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of the symmetric master key in bytes (XChaCha20-Poly1305 takes 32-byte keys).
pub const MASTER_KEY_LEN: usize = 32;

/// Length of the XChaCha20-Poly1305 nonce in bytes.
pub const NONCE_LEN: usize = 24;

/// Length of the salt used for [`MasterKey::from_passphrase`] in bytes.
pub const SALT_LEN: usize = 16;

/// Length of an Ed25519 secret (signing) key in bytes.
pub const ED25519_SECRET_LEN: usize = 32;

/// Length of an Ed25519 public (verifying) key in bytes.
pub const ED25519_PUBLIC_LEN: usize = 32;

/// Length of an Ed25519 signature in bytes.
pub const ED25519_SIGNATURE_LEN: usize = 64;

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

    /// Signing-key material had the wrong length or was otherwise malformed.
    #[error("Invalid signing key: {0}")]
    SigningKey(String),
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
        rand::rng().fill_bytes(&mut bytes);
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

/// Derive a 32-byte subkey from `key` using HKDF-SHA256.
///
/// The input keying material is `key.as_bytes()`, no salt is used, and
/// `context` is passed as the HKDF `info` parameter so callers can derive
/// independent subkeys for distinct purposes from the same master key.
pub fn derive_subkey(key: &MasterKey, context: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, key.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(context, &mut out)
        .expect("32 is a valid HKDF-SHA256 output length");
    out
}

/// Generate `n` cryptographically secure random bytes.
pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).map_err(|e| CryptoError::Random(e.to_string()))?;
    Ok(buf)
}

/// Generate a fresh 16-byte salt suitable for [`MasterKey::from_passphrase`].
pub fn random_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| CryptoError::Random(e.to_string()))?;
    Ok(salt)
}

/// Encrypt `plaintext` under `key`, binding the additional-associated-data `aad`.
///
/// Returns `[24-byte nonce | ciphertext || tag]`. The nonce is freshly drawn
/// from the OS RNG.
pub fn seal(key: &MasterKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce: &XNonce = nonce_bytes[..]
        .try_into()
        .expect("XChaCha20 nonce has the protocol-defined length");
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
    let nonce: &XNonce = nonce_bytes
        .try_into()
        .expect("split nonce has the protocol-defined length");
    cipher
        .decrypt(nonce, Payload { msg: ct, aad })
        .map_err(|e| CryptoError::Aead(e.to_string()))
}

/// Generate a fresh Ed25519 signing keypair from the OS CSPRNG.
///
/// Returns `(secret_bytes, public_bytes)`. The secret half is the 32-byte
/// seed and must be wrapped before storage; the public half is exportable.
pub fn ed25519_generate() -> Result<([u8; ED25519_SECRET_LEN], [u8; ED25519_PUBLIC_LEN])> {
    let mut seed = [0u8; ED25519_SECRET_LEN];
    getrandom::fill(&mut seed).map_err(|e| CryptoError::Random(e.to_string()))?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public = signing.verifying_key().to_bytes();
    Ok((seed, public))
}

/// Derive the public key for an Ed25519 secret seed.
pub fn ed25519_public(secret: &[u8]) -> Result<[u8; ED25519_PUBLIC_LEN]> {
    let seed = ed25519_seed(secret)?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    Ok(signing.verifying_key().to_bytes())
}

/// Sign `msg` with the Ed25519 secret seed, returning a 64-byte signature.
pub fn ed25519_sign(secret: &[u8], msg: &[u8]) -> Result<[u8; ED25519_SIGNATURE_LEN]> {
    use ed25519_dalek::Signer as _;
    let seed = ed25519_seed(secret)?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    Ok(signing.sign(msg).to_bytes())
}

/// Verify an Ed25519 `signature` over `msg` against the 32-byte public key.
///
/// Returns `false` on any malformed input or tag mismatch (never errors on a
/// bad signature; only on a structurally invalid public key).
pub fn ed25519_verify(public: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool> {
    use ed25519_dalek::Verifier as _;
    let pk: [u8; ED25519_PUBLIC_LEN] = public
        .try_into()
        .map_err(|_| CryptoError::SigningKey(format!("public key len {}", public.len())))?;
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&pk)
        .map_err(|e| CryptoError::SigningKey(e.to_string()))?;
    let sig: [u8; ED25519_SIGNATURE_LEN] = match signature.try_into() {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig);
    Ok(verifying.verify(msg, &sig).is_ok())
}

fn ed25519_seed(secret: &[u8]) -> Result<[u8; ED25519_SECRET_LEN]> {
    secret
        .try_into()
        .map_err(|_| CryptoError::SigningKey(format!("secret key len {}", secret.len())))
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
    fn open_rejects_tampered_ciphertext() {
        let key = MasterKey::generate();
        let mut sealed = seal(&key, b"data", b"aad").unwrap();
        let last = sealed.last_mut().unwrap();
        *last ^= 0x01;
        assert!(open(&key, &sealed, b"aad").is_err());
    }

    #[test]
    fn open_rejects_truncated_buffer() {
        let key = MasterKey::generate();
        assert!(open(&key, &[0u8; 4], b"x").is_err());
    }

    #[test]
    fn derive_subkey_is_deterministic_and_context_separated() {
        let key = MasterKey::from_bytes([3u8; MASTER_KEY_LEN]);
        let a = derive_subkey(&key, b"sv-audit-hmac-v1");
        let b = derive_subkey(&key, b"sv-audit-hmac-v1");
        assert_eq!(a, b);
        let c = derive_subkey(&key, b"some-other-context");
        assert_ne!(a, c);
    }

    #[test]
    fn ed25519_sign_then_verify_true() {
        let (secret, public) = ed25519_generate().unwrap();
        let msg = b"sovereign vault payload";
        let sig = ed25519_sign(&secret, msg).unwrap();
        assert!(ed25519_verify(&public, msg, &sig).unwrap());
    }

    #[test]
    fn ed25519_tampered_payload_verify_false() {
        let (secret, public) = ed25519_generate().unwrap();
        let sig = ed25519_sign(&secret, b"original").unwrap();
        assert!(!ed25519_verify(&public, b"tampered", &sig).unwrap());
    }

    #[test]
    fn ed25519_public_is_deterministic_from_seed() {
        let (secret, public) = ed25519_generate().unwrap();
        assert_eq!(ed25519_public(&secret).unwrap(), public);
    }

    #[test]
    fn ed25519_malformed_signature_is_false_not_error() {
        let (_secret, public) = ed25519_generate().unwrap();
        assert!(!ed25519_verify(&public, b"x", &[0u8; 10]).unwrap());
    }

    #[test]
    fn passphrase_derivation_is_deterministic() {
        let salt = random_salt().unwrap();
        let a = MasterKey::from_passphrase("hunter2", &salt).unwrap();
        let b = MasterKey::from_passphrase("hunter2", &salt).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        let c = MasterKey::from_passphrase("hunter3", &salt).unwrap();
        assert_ne!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn random_salt_returns_fresh_full_length_values() {
        let first = random_salt().unwrap();
        let second = random_salt().unwrap();

        assert_eq!(first.len(), SALT_LEN);
        assert_eq!(second.len(), SALT_LEN);
        assert_ne!(first, second);
    }
}
