//! Per-agent identity registry (ADR-0008).
//!
//! Persists `agents.json` at the vault root. Each agent has its own
//! credential (a one-time token, of which only an HMAC-SHA256 hash keyed by a
//! stable identity-root-derived subkey is stored) and an optional set of scopes
//! that can only *narrow* the per-container security mode flow — never widen
//! it.
//!
//! Tokens are access-granting but lower-sensitivity than the identity root, so
//! we store only their hashes and compare in constant time.
//!
//! Schema v2 adds an authenticated integrity tag (HMAC-SHA256 over a
//! deterministic serialisation of the payload, domain-separated with
//! `sovereign-vault/agent-registry/v2\0`).  Every read verifies the tag with
//! `hmac::Mac::verify_slice` (constant-time) before returning records; every
//! write re-computes the tag before the atomic 0600 replacement.

use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::CoreError;

type HmacSha256 = Hmac<Sha256>;
type Result<T> = std::result::Result<T, CoreError>;

/// Filename of the agent registry inside the vault root.
pub const AGENTS_FILE: &str = "agents.json";

/// Registry schema version.
const AGENTS_SCHEMA: u32 = 2;

/// HMAC domain-separation prefix for the integrity tag.
const HMAC_DOMAIN: &[u8] = b"sovereign-vault/agent-registry/v2\0";

/// Name of the built-in agent that wraps the shared pairing secret for
/// backward compatibility.
pub const DEFAULT_AGENT_NAME: &str = "Default";

/// One scope grant attached to an agent. Scopes can only narrow access.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentScope {
    /// Glob matched against the container name (e.g. `notes/**`).
    pub container_glob: String,
    /// Actions the agent may perform on matching containers.
    pub actions: Vec<String>,
    /// Maximum security mode the agent may exercise; cannot widen the
    /// container's own mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode_ceiling: Option<String>,
}

/// One persisted agent identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRecord {
    /// Stable identifier, `ag_<random>`.
    pub agent_id: String,
    /// Human-readable name.
    pub name: String,
    /// Hex HMAC-SHA256 of the token, keyed by an identity-root-derived subkey.
    pub token_hash: String,
    /// Issue timestamp.
    pub created_at: DateTime<Utc>,
    /// Optional expiry; `None` means the token never expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether the agent has been revoked.
    #[serde(default)]
    pub revoked: bool,
    /// Scope grants. An empty list means unscoped (full surface, subject to
    /// the per-container mode flow).
    #[serde(default)]
    pub scopes: Vec<AgentScope>,
}

// ── on-disk structures ──────────────────────────────────────────────────────

/// The part of the registry that is integrity-protected.
#[derive(Debug, Clone, Serialize)]
struct AgentsPayload {
    schema: u32,
    agents: Vec<AgentRecord>,
}

/// Persisted registry file (schema v2).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentsFile {
    schema: u32,
    agents: Vec<AgentRecord>,
    /// Hex-encoded HMAC-SHA256 over the deterministic serialisation of
    /// `AgentsPayload`, keyed by the identity-root-derived subkey and
    /// domain-separated with `sovereign-vault/agent-registry/v2\0`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    integrity: String,
}

impl Default for AgentsFile {
    fn default() -> Self {
        Self {
            schema: AGENTS_SCHEMA,
            agents: Vec::new(),
            integrity: String::new(),
        }
    }
}

// ── path helpers ────────────────────────────────────────────────────────────

fn agents_path(root: &Path) -> PathBuf {
    root.join(AGENTS_FILE)
}

/// Whether an `agents.json` is present at `root`.
pub fn exists(root: &Path) -> bool {
    fs::symlink_metadata(agents_path(root)).is_ok()
}

// ── hex helpers ─────────────────────────────────────────────────────────────

fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(CoreError::Misuse("invalid hex integrity tag".into()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| CoreError::Misuse("invalid hex integrity tag".into()))
        })
        .collect()
}

// ── integrity tag ───────────────────────────────────────────────────────────

/// Compute the HMAC-SHA256 integrity tag for `payload`.
fn compute_integrity(hmac_key: &[u8; 32], payload: &AgentsPayload) -> String {
    let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC accepts any key length");
    mac.update(HMAC_DOMAIN);
    // Deterministic compact JSON – struct fields are serialised in definition
    // order and vectors in element order, so this is reproducible.
    let payload_bytes =
        serde_json::to_vec(payload).expect("AgentsPayload serialisation is infallible");
    mac.update(&payload_bytes);
    let bytes = mac.finalize().into_bytes();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verify the integrity tag in constant time via `hmac::Mac::verify_slice`.
fn verify_integrity(hmac_key: &[u8; 32], payload: &AgentsPayload, tag_hex: &str) -> Result<()> {
    let tag_bytes = hex_decode(tag_hex)?;
    let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC accepts any key length");
    mac.update(HMAC_DOMAIN);
    let payload_bytes = serde_json::to_vec(payload)
        .map_err(|e| CoreError::Misuse(format!("agents.json payload encode: {e}")))?;
    mac.update(&payload_bytes);
    mac.verify_slice(&tag_bytes).map_err(|_| {
        CoreError::Misuse(
            "agents.json: integrity tag mismatch (file may be corrupted or tampered; re-pair the agent registry)".into(),
        )
    })
}

// ── file I/O ────────────────────────────────────────────────────────────────

fn read_file(root: &Path, hmac_key: &[u8; 32]) -> Result<AgentsFile> {
    ensure_directory(root, "vault root")?;
    let path = agents_path(root);
    match fs::symlink_metadata(&path) {
        Ok(_) => ensure_regular_file(&path, "agent registry")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AgentsFile::default());
        }
        Err(error) => return Err(error.into()),
    }
    let raw = fs::read(&path)?;
    let file: AgentsFile =
        serde_json::from_slice(&raw).map_err(|e| CoreError::Misuse(format!("agents.json: {e}")))?;

    // Schema 1 is legacy – reject with an explicit migration error.
    if file.schema == 1 {
        return Err(CoreError::Misuse(
            "agents.json: schema v1 is no longer supported; re-pair the agent registry".into(),
        ));
    }

    if file.schema == 2 {
        if file.integrity.is_empty() {
            return Err(CoreError::Misuse(
                "agents.json: missing integrity tag; re-pair the agent registry".into(),
            ));
        }
        let payload = AgentsPayload {
            schema: file.schema,
            agents: file.agents.clone(),
        };
        verify_integrity(hmac_key, &payload, &file.integrity)?;
        return Ok(file);
    }

    Err(CoreError::Misuse(format!(
        "agents.json: unsupported schema version {}",
        file.schema
    )))
}

fn write_file(root: &Path, hmac_key: &[u8; 32], file: &AgentsFile) -> Result<()> {
    ensure_directory(root, "vault root")?;
    let payload = AgentsPayload {
        schema: file.schema,
        agents: file.agents.clone(),
    };
    let integrity = compute_integrity(hmac_key, &payload);
    let mut file_with_integrity = file.clone();
    file_with_integrity.integrity = integrity;

    let bytes = serde_json::to_vec_pretty(&file_with_integrity)
        .map_err(|e| CoreError::Misuse(format!("agents.json encode: {e}")))?;
    let path = agents_path(root);
    ensure_destination_is_regular_or_missing(&path, "agent registry destination")?;
    let (tmp, mut output) = create_secure_temp(root)?;
    let result = (|| -> Result<()> {
        output.write_all(&bytes)?;
        output.sync_all()?;
        drop(output);
        ensure_destination_is_regular_or_missing(&path, "agent registry destination")?;
        atomicwrites::replace_atomic(&tmp, &path)?;
        sync_parent(root)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

// ── filesystem safety ───────────────────────────────────────────────────────

fn ensure_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CoreError::Misuse(format!("{label} does not exist: {}", path.display()))
        } else {
            error.into()
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(CoreError::Misuse(format!(
            "{label} is not a real directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CoreError::Misuse(format!("{label} does not exist: {}", path.display()))
        } else {
            error.into()
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(CoreError::Misuse(format!(
            "{label} is not a regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_destination_is_regular_or_missing(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => ensure_regular_file(path, label),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn create_secure_temp(root: &Path) -> Result<(PathBuf, fs::File)> {
    for _ in 0..16 {
        let suffix =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sv_crypto::random_bytes(12)?);
        let path = root.join(format!(".{AGENTS_FILE}.{suffix}.tmp"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(CoreError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique agent registry temp file",
    )))
}

#[cfg(unix)]
fn sync_parent(root: &Path) -> Result<()> {
    fs::File::open(root)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_parent(root: &Path) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(root)?
        .sync_all()?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_parent(_root: &Path) -> Result<()> {
    Ok(())
}

// ── token hashing ───────────────────────────────────────────────────────────

/// Keyed HMAC-SHA256 (lowercase hex) of `token`.
fn token_hash(hmac_key: &[u8; 32], token: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC accepts any key length");
    mac.update(token.as_bytes());
    let bytes = mac.finalize().into_bytes();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generate a random `ag_<hex>` identifier.
fn fresh_agent_id() -> Result<String> {
    let bytes = sv_crypto::random_bytes(12)?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("ag_{hex}"))
}

/// Generate a fresh one-time token (URL-safe base64, 32 bytes of entropy).
fn fresh_token() -> Result<String> {
    let bytes = sv_crypto::random_bytes(32)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

// ── public API ──────────────────────────────────────────────────────────────

/// Mint a new agent. Returns `(agent_id, one_time_token)`; only the token's
/// hash is persisted, so the plaintext token is shown exactly once.
pub fn create_agent(
    root: &Path,
    hmac_key: &[u8; 32],
    name: &str,
    scopes: Vec<AgentScope>,
) -> Result<(String, String)> {
    let mut file = read_file(root, hmac_key)?;
    let agent_id = fresh_agent_id()?;
    let token = fresh_token()?;
    let record = AgentRecord {
        agent_id: agent_id.clone(),
        name: name.to_string(),
        token_hash: token_hash(hmac_key, &token),
        created_at: Utc::now(),
        expires_at: None,
        revoked: false,
        scopes,
    };
    file.agents.push(record);
    write_file(root, hmac_key, &file)?;
    Ok((agent_id, token))
}

/// Ensure a "Default" agent exists whose token is the current `pairing_secret`.
///
/// The pairing secret is regenerated every launch, so this UPSERTS: if a
/// Default agent already exists its `token_hash` is refreshed to the current
/// secret (otherwise a stale hash from a previous launch would reject the
/// shared-secret pairing that existing MCP clients rely on). Creates the agent
/// if absent. Other agents are left untouched.
pub fn ensure_default_agent(root: &Path, hmac_key: &[u8; 32], pairing_secret: &str) -> Result<()> {
    let mut file = read_file(root, hmac_key)?;
    let new_hash = token_hash(hmac_key, pairing_secret);
    if let Some(existing) = file
        .agents
        .iter_mut()
        .find(|a| a.name == DEFAULT_AGENT_NAME)
    {
        existing.token_hash = new_hash;
        existing.revoked = false;
        return write_file(root, hmac_key, &file);
    }
    file.agents.push(AgentRecord {
        agent_id: fresh_agent_id()?,
        name: DEFAULT_AGENT_NAME.to_string(),
        token_hash: new_hash,
        created_at: Utc::now(),
        expires_at: None,
        revoked: false,
        scopes: Vec::new(),
    });
    write_file(root, hmac_key, &file)
}

/// List all agents (including revoked ones, for display).
pub fn list_agents(root: &Path, hmac_key: &[u8; 32]) -> Result<Vec<AgentRecord>> {
    Ok(read_file(root, hmac_key)?.agents)
}

/// Revoke an agent by id. Returns an error if the agent is unknown.
pub fn revoke_agent(root: &Path, hmac_key: &[u8; 32], agent_id: &str) -> Result<()> {
    let mut file = read_file(root, hmac_key)?;
    let found = file
        .agents
        .iter_mut()
        .find(|a| a.agent_id == agent_id)
        .ok_or_else(|| CoreError::Misuse(format!("unknown agent: {agent_id}")))?;
    found.revoked = true;
    write_file(root, hmac_key, &file)
}

/// Authenticate `agent_id` + `token` against the registry. Rejects unknown,
/// revoked, or expired agents, and tokens that do not match (constant-time).
pub fn authenticate(
    root: &Path,
    hmac_key: &[u8; 32],
    agent_id: &str,
    token: &str,
) -> Result<AgentRecord> {
    let file = read_file(root, hmac_key)?;
    let record = file
        .agents
        .into_iter()
        .find(|a| a.agent_id == agent_id)
        .ok_or_else(|| CoreError::Misuse("unknown agent".into()))?;
    if record.revoked {
        return Err(CoreError::Misuse("agent revoked".into()));
    }
    if let Some(expiry) = record.expires_at {
        if Utc::now() >= expiry {
            return Err(CoreError::Misuse("agent expired".into()));
        }
    }
    let computed = token_hash(hmac_key, token);
    let ok: bool = computed
        .as_bytes()
        .ct_eq(record.token_hash.as_bytes())
        .into();
    if !ok {
        return Err(CoreError::Misuse("invalid token".into()));
    }
    Ok(record)
}

// ── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(label: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "sv-agents-test-{label}-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    const KEY: [u8; 32] = [7u8; 32];
    const KEY2: [u8; 32] = [9u8; 32];

    // ── happy-path round-trips ──────────────────────────────────────────

    #[test]
    fn create_then_authenticate_roundtrip() {
        let root = tmp_dir("roundtrip");
        let (id, token) = create_agent(&root, &KEY, "Claude", vec![]).unwrap();
        let rec = authenticate(&root, &KEY, &id, &token).unwrap();
        assert_eq!(rec.agent_id, id);
        assert_eq!(rec.name, "Claude");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn wrong_token_rejected() {
        let root = tmp_dir("wrong");
        let (id, _token) = create_agent(&root, &KEY, "Claude", vec![]).unwrap();
        assert!(authenticate(&root, &KEY, &id, "nope").is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn unknown_agent_rejected() {
        let root = tmp_dir("unknown");
        create_agent(&root, &KEY, "Claude", vec![]).unwrap();
        assert!(authenticate(&root, &KEY, "ag_missing", "x").is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn revoked_agent_rejected() {
        let root = tmp_dir("revoked");
        let (id, token) = create_agent(&root, &KEY, "Claude", vec![]).unwrap();
        revoke_agent(&root, &KEY, &id).unwrap();
        assert!(authenticate(&root, &KEY, &id, &token).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn expired_agent_rejected() {
        let root = tmp_dir("expired");
        let (id, token) = create_agent(&root, &KEY, "Claude", vec![]).unwrap();
        // Hand-edit the persisted expiry into the past.
        let mut file = read_file(&root, &KEY).unwrap();
        file.agents[0].expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        write_file(&root, &KEY, &file).unwrap();
        assert!(authenticate(&root, &KEY, &id, &token).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ensure_default_is_idempotent() {
        let root = tmp_dir("default");
        ensure_default_agent(&root, &KEY, "secret").unwrap();
        ensure_default_agent(&root, &KEY, "secret").unwrap();
        let agents = list_agents(&root, &KEY).unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name, DEFAULT_AGENT_NAME);
        // The default agent authenticates with the shared secret as its token.
        let id = agents[0].agent_id.clone();
        assert!(authenticate(&root, &KEY, &id, "secret").is_ok());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ensure_default_refreshes_token_on_relaunch() {
        // The pairing secret rotates every launch; the Default agent must track
        // the CURRENT secret, not a stale one from a previous launch.
        let root = tmp_dir("default-refresh");
        ensure_default_agent(&root, &KEY, "secret-launch-1").unwrap();
        // A user mints another agent — Default must still be refreshed, not skipped.
        create_agent(&root, &KEY, "Cursor", vec![]).unwrap();
        ensure_default_agent(&root, &KEY, "secret-launch-2").unwrap();

        let agents = list_agents(&root, &KEY).unwrap();
        let default = agents
            .iter()
            .find(|a| a.name == DEFAULT_AGENT_NAME)
            .expect("default present");
        // New secret works; the stale one does not.
        assert!(authenticate(&root, &KEY, &default.agent_id, "secret-launch-2").is_ok());
        assert!(authenticate(&root, &KEY, &default.agent_id, "secret-launch-1").is_err());
        // Exactly one Default agent, plus the user's agent.
        assert_eq!(
            agents
                .iter()
                .filter(|a| a.name == DEFAULT_AGENT_NAME)
                .count(),
            1
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn list_agents_and_revoke_with_key() {
        let root = tmp_dir("list-revoke");
        let (id1, _) = create_agent(&root, &KEY, "Alpha", vec![]).unwrap();
        let (id2, _) = create_agent(&root, &KEY, "Beta", vec![]).unwrap();

        let agents = list_agents(&root, &KEY).unwrap();
        assert_eq!(agents.len(), 2);

        revoke_agent(&root, &KEY, &id1).unwrap();
        let agents = list_agents(&root, &KEY).unwrap();
        assert!(agents.iter().find(|a| a.agent_id == id1).unwrap().revoked);
        assert!(!agents.iter().find(|a| a.agent_id == id2).unwrap().revoked);

        // Revoking unknown agent is an error.
        assert!(revoke_agent(&root, &KEY, "ag_nope").is_err());
        let _ = fs::remove_dir_all(&root);
    }

    // ── integrity-tag tests ─────────────────────────────────────────────

    #[test]
    fn field_tamper_rejected() {
        let root = tmp_dir("field-tamper");
        create_agent(&root, &KEY, "Claude", vec![]).unwrap();

        // Directly corrupt an agent field on disk without updating the tag.
        let path = agents_path(&root);
        let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        raw["agents"][0]["name"] = serde_json::Value::String("Evil".into());
        fs::write(&path, serde_json::to_vec_pretty(&raw).unwrap()).unwrap();

        // Any read must now fail because the integrity tag no longer matches.
        assert!(list_agents(&root, &KEY).is_err());
        assert!(authenticate(&root, &KEY, "any", "any").is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn tag_tamper_rejected() {
        let root = tmp_dir("tag-tamper");
        create_agent(&root, &KEY, "Claude", vec![]).unwrap();

        // Flip the integrity tag to a bogus value.
        let path = agents_path(&root);
        let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        raw["integrity"] = serde_json::Value::String(
            "0000000000000000000000000000000000000000000000000000000000000000".into(),
        );
        fs::write(&path, serde_json::to_vec_pretty(&raw).unwrap()).unwrap();

        assert!(list_agents(&root, &KEY).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_tag_rejected() {
        let root = tmp_dir("missing-tag");
        create_agent(&root, &KEY, "Claude", vec![]).unwrap();

        // Remove the integrity field entirely.
        let path = agents_path(&root);
        let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        raw.as_object_mut().unwrap().remove("integrity");
        fs::write(&path, serde_json::to_vec_pretty(&raw).unwrap()).unwrap();

        assert!(list_agents(&root, &KEY).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn wrong_key_rejected() {
        let root = tmp_dir("wrong-key");
        create_agent(&root, &KEY, "Claude", vec![]).unwrap();

        // Reading with a different key must fail integrity verification.
        assert!(list_agents(&root, &KEY2).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn legacy_schema_1_rejected() {
        let root = tmp_dir("legacy");
        // Write a schema-1 file by hand (no integrity tag).
        let legacy = serde_json::json!({
            "schema": 1,
            "agents": []
        });
        fs::write(
            agents_path(&root),
            serde_json::to_vec_pretty(&legacy).unwrap(),
        )
        .unwrap();

        let err = list_agents(&root, &KEY).unwrap_err();
        assert!(
            err.to_string().contains("schema v1"),
            "expected schema v1 rejection, got: {err}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_file_returns_empty_registry() {
        let root = tmp_dir("missing-file");
        // No agents.json at all – must succeed with empty list.
        let agents = list_agents(&root, &KEY).unwrap();
        assert!(agents.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    // ── filesystem-safety tests (preserved from v1) ─────────────────────

    #[test]
    fn secure_write_preserves_sentinel_and_cleans_up_unique_temp() {
        let root = tmp_dir("secure-write");
        let sentinel = root.join("agents.json.tmp");
        fs::write(&sentinel, b"sentinel").unwrap();

        create_agent(&root, &KEY, "Claude", vec![]).unwrap();

        assert_eq!(fs::read(&sentinel).unwrap(), b"sentinel");
        let transient_files: Vec<_> = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| {
                let name = name.to_string_lossy();
                name.starts_with(".agents.json.") && name.ends_with(".tmp")
            })
            .collect();
        assert!(transient_files.is_empty(), "{transient_files:?}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = fs::metadata(root.join(AGENTS_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn non_file_registry_is_rejected_without_temp_artifacts() {
        let root = tmp_dir("non-file-registry");
        fs::create_dir(root.join(AGENTS_FILE)).unwrap();

        let error = create_agent(&root, &KEY, "Claude", vec![]).unwrap_err();
        assert!(error.to_string().contains("not a regular file"));
        let transient_count = fs::read_dir(&root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".agents.json.")
            })
            .count();
        assert_eq!(transient_count, 0);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_registry_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;

        let case = tmp_dir("symlinked-registry");
        let root = case.join("vault");
        fs::create_dir(&root).unwrap();
        let outside = case.join("outside-agents.json");
        let sentinel = br#"{"schema":1,"agents":[]}"#;
        fs::write(&outside, sentinel).unwrap();
        symlink(&outside, root.join(AGENTS_FILE)).unwrap();

        assert!(list_agents(&root, &KEY)
            .unwrap_err()
            .to_string()
            .contains("not a regular file"));
        assert!(create_agent(&root, &KEY, "Claude", vec![]).is_err());
        assert_eq!(fs::read(&outside).unwrap(), sentinel);
        assert!(fs::read_dir(&root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".agents.json.")));
        let _ = fs::remove_dir_all(&case);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_vault_root_is_rejected() {
        use std::os::unix::fs::symlink;

        let case = tmp_dir("symlinked-root");
        let real_root = case.join("real-vault");
        let linked_root = case.join("linked-vault");
        fs::create_dir(&real_root).unwrap();
        symlink(&real_root, &linked_root).unwrap();

        let error = create_agent(&linked_root, &KEY, "Claude", vec![]).unwrap_err();
        assert!(error.to_string().contains("not a real directory"));
        assert!(!real_root.join(AGENTS_FILE).exists());
        let _ = fs::remove_dir_all(&case);
    }
}
