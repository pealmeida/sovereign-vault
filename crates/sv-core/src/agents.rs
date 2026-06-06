//! Per-agent identity registry (ADR-0008).
//!
//! Persists `agents.json` at the vault root. Each agent has its own
//! credential (a one-time token, of which only an HMAC-SHA256 hash keyed by a
//! DEK-derived subkey is stored) and an optional set of scopes that can only
//! *narrow* the per-container security mode flow — never widen it.
//!
//! Tokens are access-granting but lower-sensitivity than the DEK, so we store
//! only their hashes and compare in constant time.

use std::fs;
use std::io::Write;
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
const AGENTS_SCHEMA: u32 = 1;

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
    /// Hex HMAC-SHA256 of the one-time token, keyed by a DEK-derived subkey.
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentsFile {
    schema: u32,
    agents: Vec<AgentRecord>,
}

impl Default for AgentsFile {
    fn default() -> Self {
        Self {
            schema: AGENTS_SCHEMA,
            agents: Vec::new(),
        }
    }
}

fn agents_path(root: &Path) -> PathBuf {
    root.join(AGENTS_FILE)
}

/// Whether an `agents.json` is present at `root`.
pub fn exists(root: &Path) -> bool {
    agents_path(root).exists()
}

fn read_file(root: &Path) -> Result<AgentsFile> {
    let path = agents_path(root);
    if !path.exists() {
        return Ok(AgentsFile::default());
    }
    let raw = fs::read(path)?;
    serde_json::from_slice(&raw).map_err(|e| CoreError::Misuse(format!("agents.json: {e}")))
}

fn write_file(root: &Path, file: &AgentsFile) -> Result<()> {
    if !root.exists() {
        fs::create_dir_all(root)?;
    }
    let bytes = serde_json::to_vec_pretty(file)
        .map_err(|e| CoreError::Misuse(format!("agents.json encode: {e}")))?;
    let path = agents_path(root);
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.flush()?;
    }
    fs::rename(&tmp, &path)?;
    Ok(())
}

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

/// Mint a new agent. Returns `(agent_id, one_time_token)`; only the token's
/// hash is persisted, so the plaintext token is shown exactly once.
pub fn create_agent(
    root: &Path,
    hmac_key: &[u8; 32],
    name: &str,
    scopes: Vec<AgentScope>,
) -> Result<(String, String)> {
    let mut file = read_file(root)?;
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
    write_file(root, &file)?;
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
    let mut file = read_file(root)?;
    let new_hash = token_hash(hmac_key, pairing_secret);
    if let Some(existing) = file
        .agents
        .iter_mut()
        .find(|a| a.name == DEFAULT_AGENT_NAME)
    {
        existing.token_hash = new_hash;
        existing.revoked = false;
        return write_file(root, &file);
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
    write_file(root, &file)
}

/// List all agents (including revoked ones, for display).
pub fn list_agents(root: &Path) -> Result<Vec<AgentRecord>> {
    Ok(read_file(root)?.agents)
}

/// Revoke an agent by id. Returns an error if the agent is unknown.
pub fn revoke_agent(root: &Path, agent_id: &str) -> Result<()> {
    let mut file = read_file(root)?;
    let found = file
        .agents
        .iter_mut()
        .find(|a| a.agent_id == agent_id)
        .ok_or_else(|| CoreError::Misuse(format!("unknown agent: {agent_id}")))?;
    found.revoked = true;
    write_file(root, &file)
}

/// Authenticate `agent_id` + `token` against the registry. Rejects unknown,
/// revoked, or expired agents, and tokens that do not match (constant-time).
pub fn authenticate(
    root: &Path,
    hmac_key: &[u8; 32],
    agent_id: &str,
    token: &str,
) -> Result<AgentRecord> {
    let file = read_file(root)?;
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
        revoke_agent(&root, &id).unwrap();
        assert!(authenticate(&root, &KEY, &id, &token).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn expired_agent_rejected() {
        let root = tmp_dir("expired");
        let (id, token) = create_agent(&root, &KEY, "Claude", vec![]).unwrap();
        // Hand-edit the persisted expiry into the past.
        let mut file = read_file(&root).unwrap();
        file.agents[0].expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        write_file(&root, &file).unwrap();
        assert!(authenticate(&root, &KEY, &id, &token).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ensure_default_is_idempotent() {
        let root = tmp_dir("default");
        ensure_default_agent(&root, &KEY, "secret").unwrap();
        ensure_default_agent(&root, &KEY, "secret").unwrap();
        let agents = list_agents(&root).unwrap();
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

        let agents = list_agents(&root).unwrap();
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
}
