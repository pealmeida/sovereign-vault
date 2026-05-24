//! Transit, signing, and broker key material (ADR-0009).
//!
//! Three families of vault-held key material, none of which is ever returned
//! to the agent:
//!
//! * **Transit keys** — named 32-byte symmetric keys for encryption-as-a-service
//!   (`vault.encrypt` / `vault.decrypt`). Stored in `transit.svault`.
//! * **Signing keys** — Ed25519 keypairs; the private seed is wrapped, the
//!   public half is exportable (`vault.sign` / `vault.verify`). Stored in
//!   `signing.svault`.
//! * **Brokered secrets** — a stored credential plus a destination allowlist,
//!   injected into an outbound request by `vault.broker_request`. Stored in
//!   `brokers.svault`.
//!
//! Every secret byte (transit key, signing seed, broker secret) is sealed
//! under a subkey derived from the active DEK (HKDF, see
//! [`sv_crypto::derive_subkey`]) — the DEK itself is never exposed here. The
//! key/secret *names* and the broker allowlists are not secret and stored in
//! the clear alongside the wrapped material.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use sv_crypto::{
    ed25519_generate, ed25519_sign, open as aead_open, seal as aead_seal, MasterKey,
    ED25519_PUBLIC_LEN,
};

use crate::CoreError;

/// Filename of the transit-key store.
pub const TRANSIT_FILE: &str = "transit.svault";
/// Filename of the signing-key store.
pub const SIGNING_FILE: &str = "signing.svault";
/// Filename of the brokered-secret store.
pub const BROKERS_FILE: &str = "brokers.svault";

const TRANSIT_AAD: &[u8] = b"sv-transit-key-v1";
const SIGNING_AAD: &[u8] = b"sv-signing-key-v1";
const BROKER_AAD: &[u8] = b"sv-broker-secret-v1";

const TRANSIT_KEY_LEN: usize = 32;
const SCHEMA: u32 = 1;

type Result<T> = std::result::Result<T, CoreError>;

// ---- transit (symmetric) -------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransitEntry {
    name: String,
    version: u32,
    wrapped_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransitFile {
    schema: u32,
    entries: Vec<TransitEntry>,
}

impl Default for TransitFile {
    fn default() -> Self {
        Self {
            schema: SCHEMA,
            entries: Vec::new(),
        }
    }
}

/// Public metadata for a transit key (never includes the key bytes).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransitKeyInfo {
    /// Key name.
    pub name: String,
    /// Active version (`name:vN` is the `key_ref`).
    pub version: u32,
}

/// Create a new named transit key wrapped under `wrap_key`. Errors if a key of
/// that name already exists.
pub fn transit_create_key(root: &Path, wrap_key: &MasterKey, name: &str) -> Result<TransitKeyInfo> {
    validate_name(name)?;
    let mut file: TransitFile = read_json(root, TRANSIT_FILE)?;
    if file.entries.iter().any(|e| e.name == name) {
        return Err(CoreError::Misuse(format!(
            "transit key already exists: {name}"
        )));
    }
    let raw = sv_crypto::random_bytes(TRANSIT_KEY_LEN)?;
    let wrapped = aead_seal(wrap_key, &raw, TRANSIT_AAD)?;
    file.entries.push(TransitEntry {
        name: name.to_string(),
        version: 1,
        wrapped_b64: B64.encode(wrapped),
    });
    write_json(root, TRANSIT_FILE, &file)?;
    Ok(TransitKeyInfo {
        name: name.to_string(),
        version: 1,
    })
}

/// List all transit keys (metadata only).
pub fn transit_list(root: &Path) -> Result<Vec<TransitKeyInfo>> {
    let file: TransitFile = read_json(root, TRANSIT_FILE)?;
    Ok(file
        .entries
        .iter()
        .map(|e| TransitKeyInfo {
            name: e.name.clone(),
            version: e.version,
        })
        .collect())
}

fn transit_key_bytes(root: &Path, wrap_key: &MasterKey, key_ref: &str) -> Result<MasterKey> {
    let (name, version) = parse_key_ref(key_ref);
    let file: TransitFile = read_json(root, TRANSIT_FILE)?;
    let entry = file
        .entries
        .iter()
        .find(|e| e.name == name && version.map(|v| v == e.version).unwrap_or(true))
        .ok_or_else(|| CoreError::Misuse(format!("unknown transit key_ref: {key_ref}")))?;
    let sealed = B64
        .decode(entry.wrapped_b64.as_bytes())
        .map_err(|e| CoreError::Base64(e.to_string()))?;
    let raw = aead_open(wrap_key, &sealed, TRANSIT_AAD)?;
    let mut bytes = [0u8; TRANSIT_KEY_LEN];
    if raw.len() != TRANSIT_KEY_LEN {
        return Err(CoreError::Misuse("transit key wrong length".into()));
    }
    bytes.copy_from_slice(&raw);
    Ok(MasterKey::from_bytes(bytes))
}

/// Encrypt `plaintext` under the transit key, returning base64 ciphertext. The
/// `key_ref` name is bound as AAD so ciphertext cannot be replayed under
/// another key.
pub fn transit_encrypt(
    root: &Path,
    wrap_key: &MasterKey,
    key_ref: &str,
    plaintext: &[u8],
) -> Result<String> {
    let key = transit_key_bytes(root, wrap_key, key_ref)?;
    let (name, _) = parse_key_ref(key_ref);
    let sealed = aead_seal(&key, plaintext, name.as_bytes())?;
    Ok(B64.encode(sealed))
}

/// Decrypt base64 `ciphertext_b64` under the transit key.
pub fn transit_decrypt(
    root: &Path,
    wrap_key: &MasterKey,
    key_ref: &str,
    ciphertext_b64: &str,
) -> Result<Vec<u8>> {
    let key = transit_key_bytes(root, wrap_key, key_ref)?;
    let (name, _) = parse_key_ref(key_ref);
    let sealed = B64
        .decode(ciphertext_b64.as_bytes())
        .map_err(|e| CoreError::Base64(e.to_string()))?;
    Ok(aead_open(&key, &sealed, name.as_bytes())?)
}

// ---- signing (Ed25519) ---------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SigningEntry {
    name: String,
    version: u32,
    public_b64: String,
    wrapped_secret_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SigningFile {
    schema: u32,
    entries: Vec<SigningEntry>,
}

impl Default for SigningFile {
    fn default() -> Self {
        Self {
            schema: SCHEMA,
            entries: Vec::new(),
        }
    }
}

/// Public metadata for a signing key (includes the exportable public key).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigningKeyInfo {
    /// Key name.
    pub name: String,
    /// Active version.
    pub version: u32,
    /// Base64 Ed25519 public key.
    pub public_b64: String,
}

/// Create a new Ed25519 signing key; the private seed is wrapped under
/// `wrap_key`, the public half is stored in the clear and returned.
pub fn signing_create_key(
    root: &Path,
    wrap_key: &MasterKey,
    name: &str,
) -> Result<SigningKeyInfo> {
    validate_name(name)?;
    let mut file: SigningFile = read_json(root, SIGNING_FILE)?;
    if file.entries.iter().any(|e| e.name == name) {
        return Err(CoreError::Misuse(format!(
            "signing key already exists: {name}"
        )));
    }
    let (secret, public) = ed25519_generate()?;
    let wrapped = aead_seal(wrap_key, &secret, SIGNING_AAD)?;
    let info = SigningKeyInfo {
        name: name.to_string(),
        version: 1,
        public_b64: B64.encode(public),
    };
    file.entries.push(SigningEntry {
        name: name.to_string(),
        version: 1,
        public_b64: info.public_b64.clone(),
        wrapped_secret_b64: B64.encode(wrapped),
    });
    write_json(root, SIGNING_FILE, &file)?;
    Ok(info)
}

/// List all signing keys (metadata + public keys only).
pub fn signing_list(root: &Path) -> Result<Vec<SigningKeyInfo>> {
    let file: SigningFile = read_json(root, SIGNING_FILE)?;
    Ok(file
        .entries
        .iter()
        .map(|e| SigningKeyInfo {
            name: e.name.clone(),
            version: e.version,
            public_b64: e.public_b64.clone(),
        })
        .collect())
}

fn signing_entry(root: &Path, key_ref: &str) -> Result<SigningEntry> {
    let (name, version) = parse_key_ref(key_ref);
    let file: SigningFile = read_json(root, SIGNING_FILE)?;
    file.entries
        .into_iter()
        .find(|e| e.name == name && version.map(|v| v == e.version).unwrap_or(true))
        .ok_or_else(|| CoreError::Misuse(format!("unknown signing key_ref: {key_ref}")))
}

/// Exportable base64 public key for a signing key_ref.
pub fn signing_public_key(root: &Path, key_ref: &str) -> Result<String> {
    Ok(signing_entry(root, key_ref)?.public_b64)
}

/// Sign `payload` with the wrapped private key, returning a base64 signature.
/// The private key is unwrapped transiently and never returned.
pub fn signing_sign(
    root: &Path,
    wrap_key: &MasterKey,
    key_ref: &str,
    payload: &[u8],
) -> Result<String> {
    let entry = signing_entry(root, key_ref)?;
    let sealed = B64
        .decode(entry.wrapped_secret_b64.as_bytes())
        .map_err(|e| CoreError::Base64(e.to_string()))?;
    let secret = aead_open(wrap_key, &sealed, SIGNING_AAD)?;
    let sig = ed25519_sign(&secret, payload)?;
    Ok(B64.encode(sig))
}

/// Verify a base64 `signature_b64` over `payload` against a base64 public key.
pub fn signing_verify(public_b64: &str, payload: &[u8], signature_b64: &str) -> Result<bool> {
    let public = B64
        .decode(public_b64.as_bytes())
        .map_err(|e| CoreError::Base64(e.to_string()))?;
    if public.len() != ED25519_PUBLIC_LEN {
        return Err(CoreError::Misuse("public key wrong length".into()));
    }
    let sig = B64
        .decode(signature_b64.as_bytes())
        .map_err(|e| CoreError::Base64(e.to_string()))?;
    Ok(sv_crypto::ed25519_verify(&public, payload, &sig)?)
}

// ---- brokered secrets ----------------------------------------------------

/// One allowlist entry a brokered secret may be used against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrokerAllow {
    /// Exact lowercase host the request may target.
    pub host: String,
    /// Path prefix the request URL path must start with.
    pub path_prefix: String,
    /// Uppercase HTTP methods permitted.
    pub methods: Vec<String>,
    /// Opt in to otherwise-refused private/loopback/link-local target IPs.
    #[serde(default)]
    pub allow_private_ip: bool,
}

/// How the secret is injected into the outbound request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrokerInjection {
    /// `Authorization: Bearer <secret>`.
    BearerAuth,
    /// A custom header whose value is the raw secret.
    Header {
        /// Header name to set to the secret value.
        name: String,
    },
}

impl Default for BrokerInjection {
    fn default() -> Self {
        Self::BearerAuth
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrokerEntry {
    name: String,
    wrapped_secret_b64: String,
    allow: Vec<BrokerAllow>,
    #[serde(default)]
    injection: BrokerInjection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrokerFile {
    schema: u32,
    entries: Vec<BrokerEntry>,
}

impl Default for BrokerFile {
    fn default() -> Self {
        Self {
            schema: SCHEMA,
            entries: Vec::new(),
        }
    }
}

/// Public metadata for a brokered secret (never includes the secret value).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrokerSecretInfo {
    /// Secret name (the `secret_ref`).
    pub name: String,
    /// Destination allowlist.
    pub allow: Vec<BrokerAllow>,
    /// Injection strategy.
    pub injection: BrokerInjection,
}

/// A resolved brokered secret ready to inject — returned only inside the vault
/// process for the duration of one outbound call. Never serialized to an agent.
pub struct ResolvedBrokerSecret {
    /// The cleartext secret value (zeroized by the caller after use).
    pub secret: String,
    /// Destination allowlist.
    pub allow: Vec<BrokerAllow>,
    /// Injection strategy.
    pub injection: BrokerInjection,
}

/// Create a brokered secret. `secret` is wrapped under `wrap_key`; `allow`
/// is the (non-secret) destination allowlist.
pub fn broker_create(
    root: &Path,
    wrap_key: &MasterKey,
    name: &str,
    secret: &str,
    allow: Vec<BrokerAllow>,
    injection: BrokerInjection,
) -> Result<BrokerSecretInfo> {
    validate_name(name)?;
    let mut file: BrokerFile = read_json(root, BROKERS_FILE)?;
    if file.entries.iter().any(|e| e.name == name) {
        return Err(CoreError::Misuse(format!(
            "brokered secret already exists: {name}"
        )));
    }
    let wrapped = aead_seal(wrap_key, secret.as_bytes(), BROKER_AAD)?;
    file.entries.push(BrokerEntry {
        name: name.to_string(),
        wrapped_secret_b64: B64.encode(wrapped),
        allow: allow.clone(),
        injection: injection.clone(),
    });
    write_json(root, BROKERS_FILE, &file)?;
    Ok(BrokerSecretInfo {
        name: name.to_string(),
        allow,
        injection,
    })
}

/// List brokered secrets (metadata only; secret values are never returned).
pub fn broker_list(root: &Path) -> Result<Vec<BrokerSecretInfo>> {
    let file: BrokerFile = read_json(root, BROKERS_FILE)?;
    Ok(file
        .entries
        .into_iter()
        .map(|e| BrokerSecretInfo {
            name: e.name,
            allow: e.allow,
            injection: e.injection,
        })
        .collect())
}

/// Resolve a brokered secret for in-process injection. The returned value
/// holds the cleartext secret and MUST NOT be serialized to an agent.
pub fn broker_resolve(
    root: &Path,
    wrap_key: &MasterKey,
    secret_ref: &str,
) -> Result<ResolvedBrokerSecret> {
    let file: BrokerFile = read_json(root, BROKERS_FILE)?;
    let entry = file
        .entries
        .into_iter()
        .find(|e| e.name == secret_ref)
        .ok_or_else(|| CoreError::Misuse(format!("unknown brokered secret: {secret_ref}")))?;
    let sealed = B64
        .decode(entry.wrapped_secret_b64.as_bytes())
        .map_err(|e| CoreError::Base64(e.to_string()))?;
    let raw = aead_open(wrap_key, &sealed, BROKER_AAD)?;
    let secret =
        String::from_utf8(raw).map_err(|_| CoreError::Misuse("broker secret not utf8".into()))?;
    Ok(ResolvedBrokerSecret {
        secret,
        allow: entry.allow,
        injection: entry.injection,
    })
}

// ---- shared helpers ------------------------------------------------------

fn parse_key_ref(key_ref: &str) -> (String, Option<u32>) {
    match key_ref.rsplit_once(':') {
        Some((name, ver)) => match ver.trim_start_matches('v').parse::<u32>() {
            Ok(v) => (name.to_string(), Some(v)),
            Err(_) => (key_ref.to_string(), None),
        },
        None => (key_ref.to_string(), None),
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(CoreError::Misuse("name must be 1..=64 chars".into()));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(CoreError::Misuse(
            "name must be alphanumeric, hyphen, or underscore".into(),
        ));
    }
    Ok(())
}

fn store_path(root: &Path, file: &str) -> PathBuf {
    root.join(file)
}

fn read_json<T: Default + for<'de> Deserialize<'de>>(root: &Path, file: &str) -> Result<T> {
    let path = store_path(root, file);
    if !path.exists() {
        return Ok(T::default());
    }
    let raw = fs::read(&path)?;
    serde_json::from_slice(&raw).map_err(|e| CoreError::Misuse(format!("{file}: {e}")))
}

fn write_json<T: Serialize>(root: &Path, file: &str, value: &T) -> Result<()> {
    if !root.exists() {
        fs::create_dir_all(root)?;
    }
    let bytes =
        serde_json::to_vec_pretty(value).map_err(|e| CoreError::Misuse(format!("{file}: {e}")))?;
    let path = store_path(root, file);
    let tmp = path.with_extension("svault.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(label: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "sv-transit-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn wrap() -> MasterKey {
        MasterKey::from_bytes([9u8; 32])
    }

    #[test]
    fn transit_encrypt_decrypt_roundtrip() {
        let root = tmp_dir("transit-rt");
        let info = transit_create_key(&root, &wrap(), "api").unwrap();
        let key_ref = format!("{}:v{}", info.name, info.version);
        let ct = transit_encrypt(&root, &wrap(), &key_ref, b"secret data").unwrap();
        let pt = transit_decrypt(&root, &wrap(), &key_ref, &ct).unwrap();
        assert_eq!(pt, b"secret data");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn transit_list_never_returns_key_bytes() {
        let root = tmp_dir("transit-list");
        transit_create_key(&root, &wrap(), "api").unwrap();
        let raw = fs::read_to_string(root.join(TRANSIT_FILE)).unwrap();
        // The wrapped (sealed) bytes must be present, never raw key material we
        // can match — but the listing API must expose only name + version.
        let list = transit_list(&root).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "api");
        let json = serde_json::to_string(&list).unwrap();
        assert!(!json.contains("wrapped"));
        assert!(raw.contains("wrapped_b64"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn transit_decrypt_with_wrong_key_ref_fails() {
        let root = tmp_dir("transit-wrong");
        let a = transit_create_key(&root, &wrap(), "a").unwrap();
        transit_create_key(&root, &wrap(), "b").unwrap();
        let ct = transit_encrypt(&root, &wrap(), &format!("{}:v1", a.name), b"x").unwrap();
        assert!(transit_decrypt(&root, &wrap(), "b:v1", &ct).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn signing_sign_then_verify_true_and_private_never_exposed() {
        let root = tmp_dir("sign-rt");
        let info = signing_create_key(&root, &wrap(), "k").unwrap();
        let key_ref = "k:v1";
        let sig = signing_sign(&root, &wrap(), key_ref, b"payload").unwrap();
        let pub_b64 = signing_public_key(&root, key_ref).unwrap();
        assert!(signing_verify(&pub_b64, b"payload", &sig).unwrap());
        // No API returns the private seed.
        let list = serde_json::to_string(&signing_list(&root).unwrap()).unwrap();
        assert!(!list.contains("wrapped_secret"));
        assert_eq!(info.public_b64, pub_b64);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn signing_tampered_payload_verify_false() {
        let root = tmp_dir("sign-tamper");
        signing_create_key(&root, &wrap(), "k").unwrap();
        let sig = signing_sign(&root, &wrap(), "k:v1", b"original").unwrap();
        let pub_b64 = signing_public_key(&root, "k:v1").unwrap();
        assert!(!signing_verify(&pub_b64, b"tampered", &sig).unwrap());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn broker_resolve_roundtrips_secret_and_allowlist() {
        let root = tmp_dir("broker-rt");
        let allow = vec![BrokerAllow {
            host: "api.example.com".into(),
            path_prefix: "/v1".into(),
            methods: vec!["GET".into()],
            allow_private_ip: false,
        }];
        broker_create(
            &root,
            &wrap(),
            "stripe",
            "sk_live_xyz",
            allow.clone(),
            BrokerInjection::BearerAuth,
        )
        .unwrap();
        // The listing must not leak the secret.
        let list_json = serde_json::to_string(&broker_list(&root).unwrap()).unwrap();
        assert!(!list_json.contains("sk_live_xyz"));
        let resolved = broker_resolve(&root, &wrap(), "stripe").unwrap();
        assert_eq!(resolved.secret, "sk_live_xyz");
        assert_eq!(resolved.allow, allow);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn duplicate_names_rejected() {
        let root = tmp_dir("dup");
        transit_create_key(&root, &wrap(), "a").unwrap();
        assert!(transit_create_key(&root, &wrap(), "a").is_err());
        signing_create_key(&root, &wrap(), "s").unwrap();
        assert!(signing_create_key(&root, &wrap(), "s").is_err());
        let _ = fs::remove_dir_all(&root);
    }
}
