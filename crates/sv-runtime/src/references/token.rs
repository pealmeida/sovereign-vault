//! Opaque reference tokens and the keyed hash the registry stores.
//!
//! A token is bearer material with no internal structure: it carries no
//! resource name, path, type, length, or ciphertext, so holding one reveals
//! nothing about what it points at. Possession alone is also not a capability —
//! §5.2 requires an authenticated registry lookup and a policy decision before
//! any token does anything.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, RuntimeError};

type HmacSha256 = Hmac<Sha256>;

/// Prefix of the external form, including the format version.
const TOKEN_PREFIX: &str = "svref:v1:";

/// Raw length of a token, in bytes.
const TOKEN_BYTES: usize = 32;

/// HKDF info string separating the registry subkey from every other subkey.
const REGISTRY_INFO: &[u8] = b"sovereign-vault/reference-registry/v1";

/// The registry's HMAC subkey.
///
/// Derived from the runtime root key rather than shared with it, so that
/// compromising a token hash cannot be replayed against the audit log or any
/// other subsystem keyed from the same root.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RegistryKey([u8; 32]);

impl RegistryKey {
    /// Derives the registry subkey from the runtime root key.
    pub fn derive(root: &[u8; 32]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, root);
        let mut key = [0u8; 32];
        hkdf.expand(REGISTRY_INFO, &mut key)
            .expect("32 bytes is a valid HKDF output length");
        RegistryKey(key)
    }
}

impl core::fmt::Debug for RegistryKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RegistryKey([REDACTED])")
    }
}

/// An opaque handle to a protected resource.
///
/// Deliberately not `Serialize`/`Deserialize`, and its `Debug` prints a fixed
/// marker: a token that reached a log or an audit record would be a bearer
/// credential sitting in plaintext.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ReferenceToken([u8; TOKEN_BYTES]);

impl ReferenceToken {
    /// Generates a fresh token from the operating system CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; TOKEN_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| RuntimeError::InvalidStructure)?;
        Ok(ReferenceToken(bytes))
    }

    /// Parses a token from its external form.
    ///
    /// Strict: the exact `svref:v1:` prefix, the unpadded base64url alphabet,
    /// and exactly 32 decoded bytes. The error never echoes the input.
    pub fn parse(value: &str) -> Result<Self> {
        let encoded = value
            .strip_prefix(TOKEN_PREFIX)
            .ok_or(RuntimeError::ReferenceInvalid)?;
        let decoded = base64url_decode(encoded).ok_or(RuntimeError::ReferenceInvalid)?;
        let bytes: [u8; TOKEN_BYTES] = decoded
            .try_into()
            .map_err(|_| RuntimeError::ReferenceInvalid)?;
        Ok(ReferenceToken(bytes))
    }

    /// Renders the token in its external form.
    pub fn to_external(&self) -> String {
        format!("{TOKEN_PREFIX}{}", base64url_encode(&self.0))
    }

    /// Returns the keyed hash the registry stores in place of the token.
    pub fn id_hash(&self, key: &RegistryKey) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts any key length");
        mac.update(&self.0);
        mac.finalize().into_bytes().into()
    }
}

impl core::fmt::Debug for ReferenceToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ReferenceToken([REDACTED])")
    }
}

/// Compares two keyed hashes in constant time.
///
/// A registry lookup that short-circuits on the first differing byte leaks how
/// much of a guessed hash was correct, which turns an offline search into an
/// online one.
pub fn id_hash_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.ct_eq(right).into()
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encodes bytes as unpadded base64url.
fn base64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[(triple >> 18) as usize & 0x3F] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 0x3F] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(triple >> 6) as usize & 0x3F] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[triple as usize & 0x3F] as char);
        }
    }
    out
}

/// Decodes unpadded base64url, rejecting padding and any out-of-alphabet byte.
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() {
        return None;
    }
    let mut values = Vec::with_capacity(input.len());
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            // Padding and the standard alphabet's `+` and `/` are rejected, so
            // one token has exactly one valid spelling.
            _ => return None,
        };
        values.push(value);
    }

    // A group of one leftover character cannot encode a whole byte.
    if values.len() % 4 == 1 {
        return None;
    }

    let mut out = Vec::with_capacity(values.len() * 3 / 4);
    for chunk in values.chunks(4) {
        let mut triple = 0u32;
        for (index, value) in chunk.iter().enumerate() {
            triple |= (*value as u32) << (18 - 6 * index);
        }
        out.push((triple >> 16) as u8);
        if chunk.len() > 2 {
            out.push((triple >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(triple as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> RegistryKey {
        RegistryKey::derive(&[7u8; 32])
    }

    #[test]
    fn token_roundtrips_through_its_external_form() {
        let token = ReferenceToken::generate().expect("csprng");
        let parsed = ReferenceToken::parse(&token.to_external()).expect("roundtrip");
        assert!(id_hash_eq(&token.id_hash(&key()), &parsed.id_hash(&key())));
    }

    #[test]
    fn parse_rejects_malformed_tokens() {
        let valid = ReferenceToken::generate().expect("csprng").to_external();
        let encoded = valid.strip_prefix(TOKEN_PREFIX).expect("prefix");

        let cases = [
            String::new(),
            "svref".to_string(),
            format!("svref:v2:{encoded}"),
            format!("SVREF:V1:{encoded}"),
            encoded.to_string(),
            format!("{TOKEN_PREFIX}{}", &encoded[..encoded.len() - 1]),
            format!("{TOKEN_PREFIX}{encoded}AA"),
            format!("{TOKEN_PREFIX}{encoded}="),
            format!("{TOKEN_PREFIX}{}+", &encoded[..encoded.len() - 1]),
            format!("{TOKEN_PREFIX}{}/", &encoded[..encoded.len() - 1]),
            TOKEN_PREFIX.to_string(),
        ];
        for case in cases {
            assert_eq!(
                ReferenceToken::parse(&case).expect_err("must reject"),
                RuntimeError::ReferenceInvalid,
                "accepted malformed token"
            );
        }
    }

    /// A token must not reveal anything about the resource it names, so two
    /// tokens for the same resource share nothing beyond the format prefix.
    #[test]
    fn tokens_reveal_nothing_about_their_resource() {
        let externals: Vec<String> = (0..1000)
            .map(|_| ReferenceToken::generate().expect("csprng").to_external())
            .collect();

        for external in &externals {
            assert!(external.starts_with(TOKEN_PREFIX));
            assert!(!external.contains("vault"));
            assert!(!external.contains("provider"));
        }

        // No two tokens collide, and none shares a long prefix with another.
        let mut bodies: Vec<&str> = externals
            .iter()
            .map(|e| e.strip_prefix(TOKEN_PREFIX).expect("prefix"))
            .collect();
        bodies.sort_unstable();
        let before = bodies.len();
        bodies.dedup();
        assert_eq!(bodies.len(), before, "token collision");

        for pair in bodies.windows(2) {
            let shared = pair[0]
                .chars()
                .zip(pair[1].chars())
                .take_while(|(a, b)| a == b)
                .count();
            assert!(shared < 8, "tokens share a {shared}-character prefix");
        }
    }

    #[test]
    fn debug_is_redacted() {
        let token = ReferenceToken::generate().expect("csprng");
        let rendered = format!("{token:?}");
        assert_eq!(rendered, "ReferenceToken([REDACTED])");
        assert!(!rendered.contains(&token.to_external()));

        assert_eq!(format!("{:?}", key()), "RegistryKey([REDACTED])");
    }

    #[test]
    fn registry_key_is_derived_not_shared() {
        let root = [3u8; 32];
        let derived = RegistryKey::derive(&root);
        assert_ne!(derived.0, root, "subkey must not equal the root key");

        // A different root gives a different subkey.
        assert_ne!(derived.0, RegistryKey::derive(&[4u8; 32]).0);
    }

    #[test]
    fn id_hash_depends_on_both_token_and_key() {
        let token = ReferenceToken::generate().expect("csprng");
        let other = ReferenceToken::generate().expect("csprng");

        assert!(!id_hash_eq(&token.id_hash(&key()), &other.id_hash(&key())));
        assert!(!id_hash_eq(
            &token.id_hash(&key()),
            &token.id_hash(&RegistryKey::derive(&[9u8; 32]))
        ));
        // The stored hash is not the token itself.
        assert_ne!(token.id_hash(&key()), token.0);
    }

    #[test]
    fn base64url_roundtrips() {
        for length in 1..=48 {
            let input: Vec<u8> = (0..length).map(|i| i as u8).collect();
            let encoded = base64url_encode(&input);
            assert!(!encoded.contains('='));
            assert!(!encoded.contains('+'));
            assert!(!encoded.contains('/'));
            assert_eq!(base64url_decode(&encoded).expect("decodes"), input);
        }
    }

    #[test]
    fn errors_never_echo_the_token() {
        let canary = "CANARY-3f21a";
        let error =
            ReferenceToken::parse(&format!("{TOKEN_PREFIX}{canary}")).expect_err("malformed token");
        assert!(!error.to_string().contains(canary));
    }
}
