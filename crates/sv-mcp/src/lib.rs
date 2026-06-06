//! Model Context Protocol (MCP) server for Sovereign Vault.
//!
//! Exposes the v1.0 vault tool surface over two transports:
//!
//! * **Stdio** — for tools that spawn the vault as a subprocess.
//! * **WebSocket** — for long-running agents that connect to a running
//!   vault on `ws://127.0.0.1:9944`.
//!
//! Pairing handshake is required on the WS transport: clients fetch a
//! per-launch secret from the localhost-only HTTP endpoint
//! `/.well-known/mcp-pairing`, then send `vault.pair { secret }` as the
//! first message.
//!
//! # Stability
//!
//! Pre-1.0.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sv_audit::{AuditAction, AuditDecision, AuditEvent};
use sv_storage::{ContainerInfo, FileInfo, SecurityMode};
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{oneshot, Mutex};
use tokio_tungstenite::tungstenite::Message;

/// MCP layer errors.
#[derive(Debug, Error)]
pub enum McpError {
    /// Transport (stdio or WS) failure.
    #[error("Transport: {0}")]
    Transport(String),

    /// JSON-RPC protocol violation.
    #[error("Protocol: {0}")]
    Protocol(String),

    /// Unpaired client attempted a tool call.
    #[error("Unpaired connection")]
    Unpaired,

    /// Vault is locked.
    #[error("Vault is locked")]
    Locked,

    /// Underlying vault error.
    #[error("Vault: {0}")]
    Vault(String),

    /// I/O error.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, McpError>;

/// JSON-RPC error codes.
#[allow(dead_code)]
mod codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const UNPAIRED: i32 = -32001;
}

/// A sanitized brokered-response surface returned across the facade boundary,
/// so `sv-mcp` need not depend on `sv-core`'s broker types. The secret and any
/// injected auth header are already stripped by the implementor.
#[derive(Debug, Clone)]
pub struct BrokerOutcome {
    /// HTTP status code.
    pub status: u16,
    /// Sanitized response headers.
    pub headers: std::collections::BTreeMap<String, String>,
    /// Response body.
    pub body: String,
    /// Resolved target host (for audit; not secret).
    pub host: String,
    /// Uppercase HTTP method (for audit).
    pub method: String,
}

/// Abstracts over the underlying vault so this crate doesn't depend on
/// `sv-core` (which would form a dependency cycle). `sv-core` implements
/// this trait for `VaultHandle`.
#[async_trait]
pub trait VaultFacade: Send + Sync {
    /// List containers.
    fn list_containers(&self) -> std::result::Result<Vec<ContainerInfo>, String>;
    /// List files in a container.
    fn list_files(&self, container: &str) -> std::result::Result<Vec<FileInfo>, String>;
    /// Read and decrypt a file.
    fn read_file(&self, container: &str, file_name: &str) -> std::result::Result<Vec<u8>, String>;
    /// Write and encrypt a file.
    fn write_file(
        &self,
        container: &str,
        file_name: &str,
        plaintext: &[u8],
    ) -> std::result::Result<(), String>;
    /// Delete a file.
    fn delete_file(&self, container: &str, file_name: &str) -> std::result::Result<(), String>;
    /// Create a new empty container with the given security mode.
    fn create_container(
        &self,
        name: &str,
        mode: &str,
        description: Option<&str>,
    ) -> std::result::Result<(), String>;
    /// Effective mode for a container.
    fn container_mode(&self, container: &str) -> std::result::Result<SecurityMode, String>;

    /// Encrypt `plaintext` under a transit `key_ref`, returning base64 ciphertext.
    fn transit_encrypt(
        &self,
        key_ref: &str,
        plaintext: &[u8],
    ) -> std::result::Result<String, String>;
    /// Decrypt base64 ciphertext under a transit `key_ref`, returning plaintext.
    fn transit_decrypt(
        &self,
        key_ref: &str,
        ciphertext_b64: &str,
    ) -> std::result::Result<Vec<u8>, String>;
    /// Sign `payload` with `key_ref`, returning a base64 signature.
    fn sign(&self, key_ref: &str, payload: &[u8]) -> std::result::Result<String, String>;
    /// Exportable base64 public key for a signing `key_ref`.
    fn signing_public_key(&self, key_ref: &str) -> std::result::Result<String, String>;
    /// Whether brokering is enabled (default-off feature flag).
    fn broker_enabled(&self) -> bool;
    /// Broker an outbound request injecting the secret named `secret_ref`. The
    /// returned outcome never contains the secret or injected auth header.
    async fn broker_request(
        &self,
        secret_ref: &str,
        method: &str,
        url: &str,
        headers: std::collections::BTreeMap<String, String>,
        body: Option<String>,
    ) -> std::result::Result<BrokerOutcome, String>;
}

/// Shared, lockable, optional vault handle. `None` means the vault is locked.
pub type SharedVault<H> = Arc<Mutex<Option<H>>>;

/// Transport on which a tool call arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessTransport {
    /// Stdio JSON-RPC server.
    McpStdio,
    /// WebSocket JSON-RPC server.
    McpWs,
}

impl AccessTransport {
    fn as_str(self) -> &'static str {
        match self {
            Self::McpStdio => "mcp-stdio",
            Self::McpWs => "mcp-ws",
        }
    }
}

/// Tool-level action subject to approval and audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessAction {
    /// List all containers.
    ListContainers,
    /// List files in one container.
    ListFiles,
    /// Read a file.
    ReadFile,
    /// Write a file.
    WriteFile,
    /// Delete a file.
    DeleteFile,
    /// Create a container.
    CreateContainer,
    /// Encrypt with a transit key.
    Encrypt,
    /// Decrypt with a transit key.
    Decrypt,
    /// Sign a payload with a signing key.
    Sign,
    /// Verify a signature (needs only the public key).
    Verify,
    /// Broker an outbound request injecting a stored secret.
    Broker,
}

impl AccessAction {
    fn audit_action(self) -> AuditAction {
        match self {
            Self::ListContainers => AuditAction::ListContainers,
            Self::ListFiles => AuditAction::ListFiles,
            Self::ReadFile => AuditAction::ReadFile,
            Self::WriteFile => AuditAction::WriteFile,
            Self::DeleteFile => AuditAction::DeleteFile,
            Self::CreateContainer => AuditAction::CreateContainer,
            Self::Encrypt => AuditAction::Encrypt,
            Self::Decrypt => AuditAction::Decrypt,
            Self::Sign => AuditAction::Sign,
            Self::Verify => AuditAction::Verify,
            Self::Broker => AuditAction::Broker,
        }
    }
}

/// Normalized access request produced from one tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequest {
    /// Transport used for the request.
    pub transport: AccessTransport,
    /// Action being performed.
    pub action: AccessAction,
    /// Target container, when applicable.
    pub container: Option<String>,
    /// Target file, when applicable.
    pub file_name: Option<String>,
    /// Effective mode governing the action, when applicable.
    pub mode: Option<SecurityMode>,
    /// Byte size of the payload, when known.
    pub byte_size: Option<usize>,
    /// Identity of the agent that originated the request, when bound.
    pub agent_id: Option<String>,
    /// One-time code supplied by the caller for OTP-mode containers. The vault
    /// displays a fresh code on the trusted desktop; the agent resends the same
    /// request carrying that code here. Cross-channel: the code is shown in one
    /// place (desktop) and entered in another (agent), binding the session.
    pub otp: Option<String>,
}

/// A scope grant resolved for an authenticated agent. Scopes can only narrow
/// access, never widen it.
#[derive(Debug, Clone)]
pub struct ResolvedScope {
    /// Glob matched against the container name.
    pub container_glob: String,
    /// Actions the agent may perform on matching containers.
    pub actions: Vec<AccessAction>,
    /// Maximum security mode the agent may exercise, if any.
    pub mode_ceiling: Option<SecurityMode>,
}

/// The outcome of authenticating an agent: its id plus resolved scopes. An
/// empty `scopes` list means unscoped (full surface, still subject to the
/// per-container mode flow).
#[derive(Debug, Clone)]
pub struct ResolvedAgent {
    /// Stable agent identifier.
    pub agent_id: String,
    /// Resolved scope grants.
    pub scopes: Vec<ResolvedScope>,
}

/// Hook used to resolve an agent identity from a presented credential during
/// the WS handshake.
pub trait AgentAuthenticator: Send + Sync {
    /// Resolve `agent_id` + `token` to a [`ResolvedAgent`], or return an error
    /// string when the credential is unknown/expired/revoked/invalid. When
    /// `agent_id` is `None` the implementation should fall back to the
    /// built-in shared-secret "Default" agent gated by `token`.
    fn authenticate(
        &self,
        agent_id: Option<&str>,
        token: &str,
    ) -> std::result::Result<ResolvedAgent, String>;
}

/// Hook used to enforce approval policy for MCP calls.
#[async_trait]
pub trait AccessController: Send + Sync {
    /// Returns `Ok(())` when the request may proceed, or an error string
    /// when it should be rejected.
    async fn authorize(&self, request: AccessRequest) -> std::result::Result<(), String>;
}

/// Hook used to persist audit events.
pub trait AuditSink: Send + Sync {
    /// Record one audit event.
    fn record(&self, event: AuditEvent) -> std::result::Result<(), String>;
}

/// MCP server. Holds a shared vault handle + the per-launch pairing secret.
pub struct McpServer<H: VaultFacade + 'static> {
    handle: SharedVault<H>,
    pairing_secret: String,
    access_controller: Option<Arc<dyn AccessController>>,
    audit_sink: Option<Arc<dyn AuditSink>>,
    agent_authenticator: Option<Arc<dyn AgentAuthenticator>>,
}

impl<H: VaultFacade + 'static> McpServer<H> {
    /// Build a new server bound to the given vault state and pairing secret.
    pub fn new(handle: SharedVault<H>, pairing_secret: impl Into<String>) -> Self {
        Self {
            handle,
            pairing_secret: pairing_secret.into(),
            access_controller: None,
            audit_sink: None,
            agent_authenticator: None,
        }
    }

    /// Install an access controller used before each MCP tool call.
    pub fn with_access_controller(mut self, controller: Arc<dyn AccessController>) -> Self {
        self.access_controller = Some(controller);
        self
    }

    /// Install an audit sink used for all MCP tool outcomes.
    pub fn with_audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit_sink = Some(sink);
        self
    }

    /// Install an agent authenticator used to resolve per-agent identity on
    /// the WS handshake. When unset, only the shared pairing secret is
    /// accepted and requests carry no `agent_id`.
    pub fn with_agent_authenticator(mut self, authenticator: Arc<dyn AgentAuthenticator>) -> Self {
        self.agent_authenticator = Some(authenticator);
        self
    }

    /// Pairing secret in use.
    pub fn pairing_secret(&self) -> &str {
        &self.pairing_secret
    }

    /// Generate a fresh URL-safe-base64 32-byte pairing secret from the OS
    /// CSPRNG. Fails closed: if the OS entropy source is unavailable this
    /// returns an error rather than emitting guessable bytes.
    pub fn fresh_pairing_secret() -> Result<String> {
        let mut buf = [0u8; 32];
        getrandom_fill(&mut buf).map_err(|e| {
            McpError::Protocol(format!(
                "OS RNG unavailable, refusing to generate secret: {e}"
            ))
        })?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
    }

    /// Run an MCP server reading JSON-RPC line-delimited frames from `reader`,
    /// writing responses to `writer`.
    pub async fn serve_stdio<R, W>(&self, reader: R, mut writer: W) -> Result<()>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut lines = reader.lines();
        while let Some(line) = lines.next_line().await? {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let response = self
                .dispatch(
                    trimmed,
                    &mut PairState::AlreadyPaired(None),
                    AccessTransport::McpStdio,
                )
                .await;
            if let Some(resp) = response {
                let bytes =
                    serde_json::to_vec(&resp).map_err(|e| McpError::Protocol(e.to_string()))?;
                writer.write_all(&bytes).await?;
                writer.write_all(b"\n").await?;
                writer.flush().await?;
            }
        }
        Ok(())
    }

    /// Run a WebSocket server on `addr` until `shutdown` is signalled.
    pub async fn serve_ws(
        self: Arc<Self>,
        addr: SocketAddr,
        shutdown: oneshot::Receiver<()>,
    ) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| McpError::Transport(format!("bind {addr}: {e}")))?;
        self.serve_ws_listener(listener, shutdown).await
    }

    /// Serve using a pre-bound listener. Used by the desktop app to fail fast
    /// on bind errors before reporting the server as running.
    pub async fn serve_ws_listener(
        self: Arc<Self>,
        listener: tokio::net::TcpListener,
        mut shutdown: oneshot::Receiver<()>,
    ) -> Result<()> {
        let addr = listener
            .local_addr()
            .map_err(|e| McpError::Transport(e.to_string()))?;
        tracing::info!(%addr, "MCP WS listening");
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    tracing::info!("MCP WS shutdown");
                    return Ok(());
                }
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(error=%e, "accept failed");
                            continue;
                        }
                    };
                    if !peer.ip().is_loopback() {
                        tracing::warn!(?peer, "rejecting non-loopback peer");
                        continue;
                    }
                    let server = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_ws_conn(stream).await {
                            tracing::debug!(error=%e, "ws conn closed");
                        }
                    });
                }
            }
        }
    }

    async fn handle_ws_conn(&self, stream: tokio::net::TcpStream) -> Result<()> {
        let ws = tokio_tungstenite::accept_async(stream)
            .await
            .map_err(|e| McpError::Transport(e.to_string()))?;
        let (mut sink, mut source) = ws.split();
        let mut pair_state = PairState::Unpaired;
        while let Some(msg) = source.next().await {
            let msg = match msg {
                Ok(m) => m,
                Err(e) => return Err(McpError::Transport(e.to_string())),
            };
            let text = match msg {
                Message::Text(t) => t.to_string(),
                Message::Binary(b) => {
                    String::from_utf8(b.to_vec()).map_err(|e| McpError::Protocol(e.to_string()))?
                }
                Message::Ping(p) => {
                    sink.send(Message::Pong(p))
                        .await
                        .map_err(|e| McpError::Transport(e.to_string()))?;
                    continue;
                }
                Message::Close(_) => break,
                _ => continue,
            };
            let response = self
                .dispatch(text.trim(), &mut pair_state, AccessTransport::McpWs)
                .await;
            if let Some(resp) = response {
                let bytes =
                    serde_json::to_string(&resp).map_err(|e| McpError::Protocol(e.to_string()))?;
                sink.send(Message::Text(bytes.into()))
                    .await
                    .map_err(|e| McpError::Transport(e.to_string()))?;
            }
            if matches!(pair_state, PairState::Failed) {
                let _ = sink.send(Message::Close(None)).await;
                break;
            }
        }
        Ok(())
    }

    async fn dispatch(
        &self,
        raw: &str,
        pair: &mut PairState,
        transport: AccessTransport,
    ) -> Option<Value> {
        let req: Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(e) => {
                return Some(error_response(
                    Value::Null,
                    codes::PARSE_ERROR,
                    &e.to_string(),
                ))
            }
        };

        let id = req.get("id").cloned();
        let method = match req.get("method").and_then(|m| m.as_str()) {
            Some(m) => m.to_string(),
            None => return None,
        };
        let params = req.get("params").cloned().unwrap_or(Value::Null);

        let id = match id {
            Some(v) if !v.is_null() => v,
            _ => return None,
        };

        if matches!(pair, PairState::Unpaired) {
            if method == "vault.pair" {
                let agent_id = params.get("agent_id").and_then(|v| v.as_str());
                // Per-agent clients send `token`; legacy clients send `secret`.
                let token = params
                    .get("token")
                    .and_then(|v| v.as_str())
                    .or_else(|| params.get("secret").and_then(|v| v.as_str()))
                    .unwrap_or_default();
                match self.resolve_pairing(agent_id, token) {
                    Ok(agent) => {
                        let bound = agent.as_ref().map(|a| a.agent_id.clone());
                        *pair = PairState::AlreadyPaired(agent);
                        return Some(ok_response(
                            id,
                            json!({ "paired": true, "agent_id": bound }),
                        ));
                    }
                    Err(_) => {
                        *pair = PairState::Failed;
                        return Some(error_response(id, codes::UNPAIRED, "Unpaired connection"));
                    }
                }
            } else {
                *pair = PairState::Failed;
                return Some(error_response(id, codes::UNPAIRED, "Unpaired connection"));
            }
        }

        match method.as_str() {
            "initialize" => Some(ok_response(
                id,
                json!({
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "sovereign-vault",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                    "capabilities": { "tools": {} },
                }),
            )),
            "tools/list" => {
                let broker_enabled = {
                    let guard = self.handle.lock().await;
                    guard.as_ref().map(|h| h.broker_enabled()).unwrap_or(false)
                };
                Some(ok_response(
                    id,
                    json!({ "tools": tool_descriptors(broker_enabled) }),
                ))
            }
            "tools/call" => {
                let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
                let result = self
                    .call_tool(name, arguments, transport, pair.agent())
                    .await;
                Some(ok_response(id, tool_result(result)))
            }
            "vault.pair" => Some(ok_response(id, json!({ "paired": true }))),
            "ping" => Some(ok_response(id, json!({}))),
            other => Some(error_response(
                id,
                codes::METHOD_NOT_FOUND,
                &format!("method not found: {other}"),
            )),
        }
    }

    /// Resolve a pairing attempt to a bound agent (if any). With an
    /// authenticator installed, delegate to it (it owns the shared-secret
    /// "Default" fallback). Without one, accept only the shared secret and
    /// bind no agent identity (legacy behaviour).
    fn resolve_pairing(
        &self,
        agent_id: Option<&str>,
        token: &str,
    ) -> std::result::Result<Option<ResolvedAgent>, String> {
        if let Some(authenticator) = &self.agent_authenticator {
            return authenticator.authenticate(agent_id, token).map(Some);
        }
        if agent_id.is_none() && token == self.pairing_secret {
            Ok(None)
        } else {
            Err("Unpaired connection".into())
        }
    }

    async fn call_tool(
        &self,
        name: &str,
        args: Value,
        transport: AccessTransport,
        agent: Option<&ResolvedAgent>,
    ) -> std::result::Result<Value, String> {
        let mut access = {
            let guard = self.handle.lock().await;
            let handle = guard
                .as_ref()
                .ok_or_else(|| "vault is locked".to_string())?;
            self.build_access_request(handle, name, &args, transport)?
        };
        access.agent_id = agent.map(|a| a.agent_id.clone());

        // Scope enforcement: scopes may only narrow, never widen, access.
        if let Some(agent) = agent {
            if let Err(error) = enforce_scopes(agent, &access) {
                self.record_audit(&access, AuditDecision::Denied, None, Some(error.clone()));
                return Err(error);
            }
        }

        if let Some(controller) = &self.access_controller {
            if let Err(error) = controller.authorize(access.clone()).await {
                self.record_audit(&access, AuditDecision::Denied, None, Some(error.clone()));
                return Err(error);
            }
        }

        // Brokering performs network I/O and is async; everything else runs
        // synchronously against the locked handle.
        if name == "vault.broker_request" {
            let (result, detail) = self.execute_broker(&args).await;
            match &result {
                Ok(_) => self.record_audit(&access, AuditDecision::Allowed, detail, None),
                Err(error) => {
                    self.record_audit(&access, AuditDecision::Error, detail, Some(error.clone()))
                }
            }
            return result;
        }

        let result = {
            let guard = self.handle.lock().await;
            let handle = guard
                .as_ref()
                .ok_or_else(|| "vault is locked".to_string())?;
            self.execute_tool(handle, name, &args)
        };

        match &result {
            Ok(_) => self.record_audit(&access, AuditDecision::Allowed, None, None),
            Err(error) => {
                self.record_audit(&access, AuditDecision::Error, None, Some(error.clone()))
            }
        }

        result
    }

    /// Run the brokered request against the live handle. Returns the agent-safe
    /// result plus an audit detail string (host + method + status, no secret).
    async fn execute_broker(
        &self,
        args: &Value,
    ) -> (std::result::Result<Value, String>, Option<String>) {
        let secret_ref = match required_str(args, "secret_ref") {
            Ok(s) => s.to_string(),
            Err(e) => return (Err(e), None),
        };
        let method = match required_str(args, "method") {
            Ok(s) => s.to_string(),
            Err(e) => return (Err(e), None),
        };
        let url = match required_str(args, "url") {
            Ok(s) => s.to_string(),
            Err(e) => return (Err(e), None),
        };
        let headers: std::collections::BTreeMap<String, String> = args
            .get("headers")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let body = args
            .get("body")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let outcome = {
            let guard = self.handle.lock().await;
            let handle = match guard.as_ref() {
                Some(h) => h,
                None => return (Err("vault is locked".to_string()), None),
            };
            if !handle.broker_enabled() {
                return (
                    Err(
                        "broker disabled: set SV_ENABLE_BROKER to enable vault.broker_request"
                            .into(),
                    ),
                    None,
                );
            }
            handle
                .broker_request(&secret_ref, &method, &url, headers, body)
                .await
        };

        match outcome {
            Ok(o) => {
                let detail = Some(format!("broker {} {} -> {}", o.method, o.host, o.status));
                let value = json!({
                    "status": o.status,
                    "headers": o.headers,
                    "body": o.body,
                });
                (Ok(value), detail)
            }
            Err(e) => (Err(e), None),
        }
    }

    fn build_access_request(
        &self,
        handle: &H,
        name: &str,
        args: &Value,
        transport: AccessTransport,
    ) -> std::result::Result<AccessRequest, String> {
        match name {
            "vault.list" => {
                let container = args.get("container").and_then(|v| v.as_str());
                let mode = match container {
                    Some(container) => Some(handle.container_mode(container)?),
                    None => None,
                };
                Ok(AccessRequest {
                    transport,
                    action: if container.is_some() {
                        AccessAction::ListFiles
                    } else {
                        AccessAction::ListContainers
                    },
                    container: container.map(|s| s.to_string()),
                    file_name: None,
                    mode,
                    byte_size: None,
                    agent_id: None,
                    otp: args
                        .get("otp")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                })
            }
            "vault.read" => {
                let container = required_str(args, "container")?;
                let file_name = required_str(args, "file_name")?;
                Ok(AccessRequest {
                    transport,
                    action: AccessAction::ReadFile,
                    container: Some(container.to_string()),
                    file_name: Some(file_name.to_string()),
                    mode: Some(handle.container_mode(container)?),
                    byte_size: None,
                    agent_id: None,
                    otp: args
                        .get("otp")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                })
            }
            "vault.write" => {
                let container = required_str(args, "container")?;
                let file_name = required_str(args, "file_name")?;
                let content_b64 = required_str(args, "content_b64")?;
                let bytes = B64
                    .decode(content_b64.as_bytes())
                    .map_err(|e| format!("invalid base64: {e}"))?;
                Ok(AccessRequest {
                    transport,
                    action: AccessAction::WriteFile,
                    container: Some(container.to_string()),
                    file_name: Some(file_name.to_string()),
                    mode: Some(handle.container_mode(container)?),
                    byte_size: Some(bytes.len()),
                    agent_id: None,
                    otp: args
                        .get("otp")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                })
            }
            "vault.delete" => {
                let container = required_str(args, "container")?;
                let file_name = required_str(args, "file_name")?;
                Ok(AccessRequest {
                    transport,
                    action: AccessAction::DeleteFile,
                    container: Some(container.to_string()),
                    file_name: Some(file_name.to_string()),
                    mode: Some(handle.container_mode(container)?),
                    byte_size: None,
                    agent_id: None,
                    otp: args
                        .get("otp")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                })
            }
            "vault.create_container" => {
                let name = required_str(args, "name")?;
                let mode = args
                    .get("mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("DIRECT");
                Ok(AccessRequest {
                    transport,
                    action: AccessAction::CreateContainer,
                    container: Some(name.to_string()),
                    file_name: None,
                    mode: Some(SecurityMode::parse(mode).map_err(|e| e.to_string())?),
                    byte_size: None,
                    agent_id: None,
                    otp: args
                        .get("otp")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                })
            }
            "vault.encrypt" => {
                let _ = required_str(args, "key_ref")?;
                let _ = required_str(args, "plaintext_b64")?;
                Ok(simple_request(transport, AccessAction::Encrypt))
            }
            "vault.decrypt" => {
                let _ = required_str(args, "key_ref")?;
                let _ = required_str(args, "ciphertext_b64")?;
                Ok(simple_request(transport, AccessAction::Decrypt))
            }
            "vault.sign" => {
                let _ = required_str(args, "key_ref")?;
                let _ = required_str(args, "payload_b64")?;
                Ok(simple_request(transport, AccessAction::Sign))
            }
            "vault.verify" => {
                let _ = required_str(args, "public_key_b64")?;
                let _ = required_str(args, "payload_b64")?;
                let _ = required_str(args, "signature_b64")?;
                Ok(simple_request(transport, AccessAction::Verify))
            }
            "vault.broker_request" => {
                let _ = required_str(args, "secret_ref")?;
                let _ = required_str(args, "method")?;
                let _ = required_str(args, "url")?;
                Ok(simple_request(transport, AccessAction::Broker))
            }
            other => Err(format!("unknown tool: {other}")),
        }
    }

    fn execute_tool(
        &self,
        handle: &H,
        name: &str,
        args: &Value,
    ) -> std::result::Result<Value, String> {
        match name {
            "vault.list" => {
                let container = args.get("container").and_then(|v| v.as_str());
                if let Some(container) = container {
                    let files = handle.list_files(container)?;
                    Ok(serde_json::to_value(files).map_err(|e| e.to_string())?)
                } else {
                    let containers = handle.list_containers()?;
                    Ok(serde_json::to_value(containers).map_err(|e| e.to_string())?)
                }
            }
            "vault.read" => {
                let container = required_str(args, "container")?;
                let file_name = required_str(args, "file_name")?;
                let bytes = handle.read_file(container, file_name)?;
                Ok(json!({
                    "container": container,
                    "file_name": file_name,
                    "content_b64": B64.encode(&bytes),
                    "byte_size": bytes.len(),
                }))
            }
            "vault.write" => {
                let container = required_str(args, "container")?;
                let file_name = required_str(args, "file_name")?;
                let content_b64 = required_str(args, "content_b64")?;
                let bytes = B64
                    .decode(content_b64.as_bytes())
                    .map_err(|e| format!("invalid base64: {e}"))?;
                let byte_size = bytes.len();
                handle.write_file(container, file_name, &bytes)?;
                Ok(json!({ "ok": true, "byte_size": byte_size }))
            }
            "vault.delete" => {
                let container = required_str(args, "container")?;
                let file_name = required_str(args, "file_name")?;
                handle.delete_file(container, file_name)?;
                Ok(json!({ "ok": true }))
            }
            "vault.create_container" => {
                let name = required_str(args, "name")?;
                let mode = args
                    .get("mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("DIRECT");
                let description = args.get("description").and_then(|v| v.as_str());
                handle.create_container(name, mode, description)?;
                Ok(json!({ "ok": true, "name": name, "mode": mode }))
            }
            "vault.encrypt" => {
                let key_ref = required_str(args, "key_ref")?;
                let plaintext = B64
                    .decode(required_str(args, "plaintext_b64")?.as_bytes())
                    .map_err(|e| format!("invalid base64: {e}"))?;
                let ciphertext_b64 = handle.transit_encrypt(key_ref, &plaintext)?;
                Ok(json!({ "key_ref": key_ref, "ciphertext_b64": ciphertext_b64 }))
            }
            "vault.decrypt" => {
                let key_ref = required_str(args, "key_ref")?;
                let ciphertext_b64 = required_str(args, "ciphertext_b64")?;
                let plaintext = handle.transit_decrypt(key_ref, ciphertext_b64)?;
                Ok(json!({ "key_ref": key_ref, "plaintext_b64": B64.encode(&plaintext) }))
            }
            "vault.sign" => {
                let key_ref = required_str(args, "key_ref")?;
                let payload = B64
                    .decode(required_str(args, "payload_b64")?.as_bytes())
                    .map_err(|e| format!("invalid base64: {e}"))?;
                let signature_b64 = handle.sign(key_ref, &payload)?;
                let public_key_b64 = handle.signing_public_key(key_ref)?;
                Ok(json!({
                    "key_ref": key_ref,
                    "signature_b64": signature_b64,
                    "public_key_b64": public_key_b64,
                }))
            }
            "vault.verify" => {
                let public_key_b64 = required_str(args, "public_key_b64")?;
                let payload = B64
                    .decode(required_str(args, "payload_b64")?.as_bytes())
                    .map_err(|e| format!("invalid base64: {e}"))?;
                let signature = B64
                    .decode(required_str(args, "signature_b64")?.as_bytes())
                    .map_err(|e| format!("invalid base64: {e}"))?;
                let public = B64
                    .decode(public_key_b64.as_bytes())
                    .map_err(|e| format!("invalid base64: {e}"))?;
                let valid = sv_crypto::ed25519_verify(&public, &payload, &signature)
                    .map_err(|e| e.to_string())?;
                Ok(json!({ "valid": valid }))
            }
            other => Err(format!("unknown tool: {other}")),
        }
    }

    fn record_audit(
        &self,
        request: &AccessRequest,
        decision: AuditDecision,
        detail: Option<String>,
        error: Option<String>,
    ) {
        let Some(sink) = &self.audit_sink else {
            return;
        };

        let mut event = AuditEvent::new(
            request.action.audit_action(),
            decision,
            request.transport.as_str(),
        );
        event.container = request.container.clone();
        event.file_name = request.file_name.clone();
        event.mode = request.mode.map(|mode| mode.as_str().to_string());
        event.byte_size = request.byte_size;
        event.detail = detail;
        event.error = error;
        event.agent_id = request.agent_id.clone();
        let _ = sink.record(event);
    }
}

/// Enforce an authenticated agent's scopes against a request. Scopes can only
/// narrow access: at least one scope must match the container, allow the
/// action, and (if it sets a ceiling) not be widened by the container mode.
fn enforce_scopes(
    agent: &ResolvedAgent,
    request: &AccessRequest,
) -> std::result::Result<(), String> {
    // No scopes means unscoped: full surface, still subject to the mode flow.
    if agent.scopes.is_empty() {
        return Ok(());
    }
    // Requests without a container (e.g. list all containers) are always
    // allowed for scoped agents; per-container reads/writes are gated below.
    let Some(container) = request.container.as_deref() else {
        return Ok(());
    };
    for scope in &agent.scopes {
        if !glob_match(&scope.container_glob, container) {
            continue;
        }
        if !scope.actions.contains(&request.action) {
            continue;
        }
        if let (Some(ceiling), Some(mode)) = (scope.mode_ceiling, request.mode) {
            // The ceiling must not be weaker than the container's effective
            // mode — a scope may only require equal-or-stronger handling.
            if mode_rank(mode) > mode_rank(ceiling) {
                return Err(format!(
                    "agent scope mode_ceiling {} cannot widen container mode {}",
                    ceiling.as_str(),
                    mode.as_str()
                ));
            }
        }
        return Ok(());
    }
    Err(format!(
        "agent {} is not scoped for {:?} on container {container}",
        agent.agent_id, request.action
    ))
}

/// Relative strength ordering of security modes; higher means stronger
/// (more restrictive) handling.
fn mode_rank(mode: SecurityMode) -> u8 {
    match mode {
        SecurityMode::Direct => 0,
        SecurityMode::Approval => 1,
        SecurityMode::Otp => 2,
        SecurityMode::Anonymized => 3,
        SecurityMode::Zkp => 4,
        SecurityMode::Native => 5,
    }
}

/// Minimal glob matcher supporting `*` (any run within a path segment) and
/// `**` (any run including `/`).
fn glob_match(pattern: &str, value: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let v: Vec<char> = value.chars().collect();
    glob_inner(&p, &v)
}

fn glob_inner(p: &[char], v: &[char]) -> bool {
    if p.is_empty() {
        return v.is_empty();
    }
    if p[0] == '*' {
        // `**` matches across segments; single `*` stops at `/`.
        let double = p.len() >= 2 && p[1] == '*';
        let rest = if double { &p[2..] } else { &p[1..] };
        // Zero-width match.
        if glob_inner(rest, v) {
            return true;
        }
        let mut i = 0;
        while i < v.len() {
            if !double && v[i] == '/' {
                break;
            }
            i += 1;
            if glob_inner(rest, &v[i..]) {
                return true;
            }
        }
        return false;
    }
    if !v.is_empty() && p[0] == v[0] {
        return glob_inner(&p[1..], &v[1..]);
    }
    false
}

fn simple_request(transport: AccessTransport, action: AccessAction) -> AccessRequest {
    AccessRequest {
        transport,
        action,
        container: None,
        file_name: None,
        mode: None,
        byte_size: None,
        agent_id: None,
        otp: None,
    }
}

fn required_str<'a>(value: &'a Value, key: &str) -> std::result::Result<&'a str, String> {
    value
        .get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("missing required string field: {key}"))
}

#[derive(Debug)]
enum PairState {
    Unpaired,
    /// Paired; carries the bound agent identity when one was resolved.
    AlreadyPaired(Option<ResolvedAgent>),
    Failed,
}

impl PairState {
    fn agent(&self) -> Option<&ResolvedAgent> {
        match self {
            PairState::AlreadyPaired(agent) => agent.as_ref(),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Serialize, Deserialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

fn ok_response(id: Value, result: Value) -> Value {
    serde_json::to_value(JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    })
    .unwrap()
}

fn error_response(id: Value, code: i32, message: &str) -> Value {
    serde_json::to_value(JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.to_string(),
        }),
    })
    .unwrap()
}

fn tool_result(result: std::result::Result<Value, String>) -> Value {
    match result {
        Ok(value) => json!({
            "content": [{ "type": "text", "text": serde_json::to_string(&value).unwrap_or_default() }],
            "isError": false,
        }),
        Err(error) => json!({
            "content": [{ "type": "text", "text": error }],
            "isError": true,
        }),
    }
}

fn tool_descriptors(broker_enabled: bool) -> Value {
    let mut tools = base_tool_descriptors();
    if let Value::Array(items) = &mut tools {
        if broker_enabled {
            items.push(broker_tool_descriptor());
        }
    }
    tools
}

fn broker_tool_descriptor() -> Value {
    json!({
        "name": "vault.broker_request",
        "description":
            "Perform an outbound HTTPS request using a vault-stored secret WITHOUT exposing it. \
             The vault injects the credential, enforces the secret's destination allowlist and \
             SSRF protections, and returns only the sanitized response. Requires desktop approval.",
        "inputSchema": {
            "type": "object",
            "required": ["secret_ref", "method", "url"],
            "properties": {
                "secret_ref": { "type": "string", "description": "Name of the brokered secret to inject." },
                "method":     { "type": "string", "description": "HTTP method; must be allowed by the secret." },
                "url":        { "type": "string", "description": "HTTPS target URL; host+path must match the allowlist." },
                "headers":    { "type": "object", "description": "Optional extra request headers (auth headers are ignored)." },
                "body":       { "type": "string", "description": "Optional request body." }
            },
            "additionalProperties": false
        }
    })
}

fn base_tool_descriptors() -> Value {
    json!([
        {
            "name": "vault.list",
            "description":
                "List containers in the vault, or files in a single container. \
                 Requests for protected containers may require desktop approval.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "container": { "type": "string", "description": "Container name. Omit to list all containers." },
                    "otp": { "type": "string", "description": "One-time code shown on the trusted desktop (OTP-mode containers only). Resend the same request carrying this code to authorize." }
                },
                "additionalProperties": false
            }
        },
        {
            "name": "vault.read",
            "description":
                "Read and decrypt a single file from a container. Returns base64-encoded content.",
            "inputSchema": {
                "type": "object",
                "required": ["container", "file_name"],
                "properties": {
                    "container": { "type": "string" },
                    "file_name": { "type": "string" },
                    "otp": { "type": "string", "description": "One-time code shown on the trusted desktop (OTP-mode containers only). Resend the same request carrying this code to authorize." }
                },
                "additionalProperties": false
            }
        },
        {
            "name": "vault.write",
            "description":
                "Encrypt and write a file into a container. content_b64 is base64-encoded plaintext.",
            "inputSchema": {
                "type": "object",
                "required": ["container", "file_name", "content_b64"],
                "properties": {
                    "container": { "type": "string" },
                    "file_name": { "type": "string" },
                    "content_b64": { "type": "string", "description": "Base64-encoded plaintext content." },
                    "otp": { "type": "string", "description": "One-time code shown on the trusted desktop (OTP-mode containers only). Resend the same request carrying this code to authorize." }
                },
                "additionalProperties": false
            }
        },
        {
            "name": "vault.delete",
            "description": "Delete a file from a container.",
            "inputSchema": {
                "type": "object",
                "required": ["container", "file_name"],
                "properties": {
                    "container": { "type": "string" },
                    "file_name": { "type": "string" },
                    "otp": { "type": "string", "description": "One-time code shown on the trusted desktop (OTP-mode containers only). Resend the same request carrying this code to authorize." }
                },
                "additionalProperties": false
            }
        },
        {
            "name": "vault.create_container",
            "description":
                "Create a new empty container (directory) at the vault root. \
                 The mode determines the default security level inherited by files.",
            "inputSchema": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name":        { "type": "string", "description": "Alphanumeric, hyphen, underscore. <=64 chars." },
                    "mode":        { "type": "string", "enum": ["DIRECT", "APPROVAL", "OTP", "ANONYMIZED", "ZKP", "NATIVE"], "default": "DIRECT" },
                    "description": { "type": "string", "description": "Optional human-readable description." },
                    "otp": { "type": "string", "description": "One-time code shown on the trusted desktop (OTP-mode only). Resend the same request carrying this code to authorize." }
                },
                "additionalProperties": false
            }
        },
        {
            "name": "vault.encrypt",
            "description":
                "Encrypt plaintext under a named transit key held by the vault. The key never \
                 leaves the vault. Returns base64 ciphertext.",
            "inputSchema": {
                "type": "object",
                "required": ["key_ref", "plaintext_b64"],
                "properties": {
                    "key_ref":       { "type": "string", "description": "Transit key reference, e.g. `mykey` or `mykey:v1`." },
                    "plaintext_b64": { "type": "string", "description": "Base64-encoded plaintext." }
                },
                "additionalProperties": false
            }
        },
        {
            "name": "vault.decrypt",
            "description":
                "Decrypt base64 ciphertext produced by vault.encrypt under the same transit key.",
            "inputSchema": {
                "type": "object",
                "required": ["key_ref", "ciphertext_b64"],
                "properties": {
                    "key_ref":        { "type": "string" },
                    "ciphertext_b64": { "type": "string" }
                },
                "additionalProperties": false
            }
        },
        {
            "name": "vault.sign",
            "description":
                "Sign a payload with a vault-held Ed25519 key. The private key never leaves the \
                 vault. Returns a base64 signature and the public key.",
            "inputSchema": {
                "type": "object",
                "required": ["key_ref", "payload_b64"],
                "properties": {
                    "key_ref":     { "type": "string", "description": "Signing key reference." },
                    "payload_b64": { "type": "string", "description": "Base64-encoded payload to sign." }
                },
                "additionalProperties": false
            }
        },
        {
            "name": "vault.verify",
            "description":
                "Verify an Ed25519 signature over a payload against a public key. Stateless.",
            "inputSchema": {
                "type": "object",
                "required": ["public_key_b64", "payload_b64", "signature_b64"],
                "properties": {
                    "public_key_b64": { "type": "string" },
                    "payload_b64":    { "type": "string" },
                    "signature_b64":  { "type": "string" }
                },
                "additionalProperties": false
            }
        }
    ])
}

/// Fill `buf` with cryptographically secure bytes from the operating system's
/// CSPRNG. Returns an error if the OS entropy source is unavailable.
///
/// This MUST fail closed: there is deliberately no software fallback. A
/// predictable fallback (e.g. seeded from time/pid) would let an attacker guess
/// secret material such as pairing secrets, so on RNG failure we surface the
/// error to the caller rather than emitting guessable bytes.
fn getrandom_fill(buf: &mut [u8]) -> std::result::Result<(), getrandom::Error> {
    getrandom::fill(buf)
}

/// Crate version string.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubVault {
        containers: Vec<ContainerInfo>,
        files: std::sync::Mutex<std::collections::HashMap<(String, String), Vec<u8>>>,
        transit_keys: std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>>,
        signing_keys: std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>>,
        broker_enabled: bool,
    }

    impl StubVault {
        fn transit_key(&self, key_ref: &str) -> std::result::Result<[u8; 32], String> {
            let name = key_ref.split(':').next().unwrap_or(key_ref);
            let mut keys = self.transit_keys.lock().unwrap();
            Ok(*keys.entry(name.to_string()).or_insert([7u8; 32]))
        }
        fn signing_seed(&self, key_ref: &str) -> std::result::Result<[u8; 32], String> {
            let name = key_ref.split(':').next().unwrap_or(key_ref);
            let mut keys = self.signing_keys.lock().unwrap();
            if let Some(seed) = keys.get(name) {
                return Ok(*seed);
            }
            let (seed, _pub) = sv_crypto::ed25519_generate().map_err(|e| e.to_string())?;
            keys.insert(name.to_string(), seed);
            Ok(seed)
        }
    }

    #[async_trait]
    impl VaultFacade for StubVault {
        fn transit_encrypt(
            &self,
            key_ref: &str,
            plaintext: &[u8],
        ) -> std::result::Result<String, String> {
            let key = sv_crypto::MasterKey::from_bytes(self.transit_key(key_ref)?);
            let sealed =
                sv_crypto::seal(&key, plaintext, key_ref.as_bytes()).map_err(|e| e.to_string())?;
            Ok(B64.encode(sealed))
        }
        fn transit_decrypt(
            &self,
            key_ref: &str,
            ciphertext_b64: &str,
        ) -> std::result::Result<Vec<u8>, String> {
            let key = sv_crypto::MasterKey::from_bytes(self.transit_key(key_ref)?);
            let sealed = B64
                .decode(ciphertext_b64.as_bytes())
                .map_err(|e| e.to_string())?;
            sv_crypto::open(&key, &sealed, key_ref.as_bytes()).map_err(|e| e.to_string())
        }
        fn sign(&self, key_ref: &str, payload: &[u8]) -> std::result::Result<String, String> {
            let seed = self.signing_seed(key_ref)?;
            let sig = sv_crypto::ed25519_sign(&seed, payload).map_err(|e| e.to_string())?;
            Ok(B64.encode(sig))
        }
        fn signing_public_key(&self, key_ref: &str) -> std::result::Result<String, String> {
            let seed = self.signing_seed(key_ref)?;
            let public = sv_crypto::ed25519_public(&seed).map_err(|e| e.to_string())?;
            Ok(B64.encode(public))
        }
        fn broker_enabled(&self) -> bool {
            self.broker_enabled
        }
        async fn broker_request(
            &self,
            _secret_ref: &str,
            method: &str,
            url: &str,
            _headers: std::collections::BTreeMap<String, String>,
            _body: Option<String>,
        ) -> std::result::Result<BrokerOutcome, String> {
            // Stub: never touches the network; echoes a canned response.
            Ok(BrokerOutcome {
                status: 200,
                headers: Default::default(),
                body: "{}".into(),
                host: url.to_string(),
                method: method.to_ascii_uppercase(),
            })
        }

        fn list_containers(&self) -> std::result::Result<Vec<ContainerInfo>, String> {
            Ok(self.containers.clone())
        }

        fn list_files(&self, _container: &str) -> std::result::Result<Vec<FileInfo>, String> {
            Ok(vec![])
        }

        fn read_file(
            &self,
            container: &str,
            file_name: &str,
        ) -> std::result::Result<Vec<u8>, String> {
            self.files
                .lock()
                .unwrap()
                .get(&(container.into(), file_name.into()))
                .cloned()
                .ok_or_else(|| "not found".into())
        }

        fn write_file(
            &self,
            container: &str,
            file_name: &str,
            plaintext: &[u8],
        ) -> std::result::Result<(), String> {
            self.files
                .lock()
                .unwrap()
                .insert((container.into(), file_name.into()), plaintext.to_vec());
            Ok(())
        }

        fn delete_file(&self, container: &str, file_name: &str) -> std::result::Result<(), String> {
            self.files
                .lock()
                .unwrap()
                .remove(&(container.into(), file_name.into()));
            Ok(())
        }

        fn create_container(
            &self,
            _name: &str,
            _mode: &str,
            _description: Option<&str>,
        ) -> std::result::Result<(), String> {
            Ok(())
        }

        fn container_mode(&self, container: &str) -> std::result::Result<SecurityMode, String> {
            if self.containers.iter().any(|c| c.name == container) {
                Ok(SecurityMode::Approval)
            } else {
                Err("missing container".into())
            }
        }
    }

    struct DenyController;

    #[async_trait]
    impl AccessController for DenyController {
        async fn authorize(&self, request: AccessRequest) -> std::result::Result<(), String> {
            Err(format!("denied {:?}", request.action))
        }
    }

    struct MemoryAudit(std::sync::Mutex<Vec<AuditEvent>>);

    impl AuditSink for MemoryAudit {
        fn record(&self, event: AuditEvent) -> std::result::Result<(), String> {
            self.0.lock().unwrap().push(event);
            Ok(())
        }
    }

    fn make_vault(broker_enabled: bool) -> StubVault {
        StubVault {
            containers: vec![ContainerInfo {
                name: "notes".into(),
                mode: SecurityMode::Approval,
                file_count: 0,
                description: None,
            }],
            files: Default::default(),
            transit_keys: Default::default(),
            signing_keys: Default::default(),
            broker_enabled,
        }
    }

    fn server() -> McpServer<StubVault> {
        McpServer::new(Arc::new(Mutex::new(Some(make_vault(false)))), "test-secret")
    }

    #[tokio::test]
    async fn initialize_returns_protocol_version() {
        let server = server();
        let mut pair = PairState::AlreadyPaired(None);
        let response = server
            .dispatch(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
                &mut pair,
                AccessTransport::McpWs,
            )
            .await
            .unwrap();
        assert_eq!(response["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(response["result"]["serverInfo"]["name"], "sovereign-vault");
    }

    #[tokio::test]
    async fn tools_list_omits_broker_when_disabled() {
        let server = server();
        let mut pair = PairState::AlreadyPaired(None);
        let response = server
            .dispatch(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                &mut pair,
                AccessTransport::McpWs,
            )
            .await
            .unwrap();
        let tools = response["result"]["tools"].as_array().unwrap();
        // 5 file tools + encrypt/decrypt/sign/verify, broker omitted.
        assert_eq!(tools.len(), 9);
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"vault.encrypt"));
        assert!(names.contains(&"vault.sign"));
        assert!(!names.contains(&"vault.broker_request"));
    }

    #[tokio::test]
    async fn tools_list_includes_broker_when_enabled() {
        let server = McpServer::new(Arc::new(Mutex::new(Some(make_vault(true)))), "test-secret");
        let mut pair = PairState::AlreadyPaired(None);
        let response = server
            .dispatch(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                &mut pair,
                AccessTransport::McpWs,
            )
            .await
            .unwrap();
        let tools = response["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 10);
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"vault.broker_request"));
    }

    #[tokio::test]
    async fn transit_encrypt_then_decrypt_roundtrip() {
        let server = server();
        let mut pair = PairState::AlreadyPaired(None);
        let pt = B64.encode(b"top secret");
        let enc = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"vault.encrypt","arguments":{{"key_ref":"k1","plaintext_b64":"{pt}"}}}}}}"#
        );
        let resp = server
            .dispatch(&enc, &mut pair, AccessTransport::McpWs)
            .await
            .unwrap();
        let inner: Value =
            serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        let ct = inner["ciphertext_b64"].as_str().unwrap();
        // The transit key bytes must never appear in the response.
        assert!(!resp.to_string().contains("key bytes"));
        let dec = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"vault.decrypt","arguments":{{"key_ref":"k1","ciphertext_b64":"{ct}"}}}}}}"#
        );
        let resp = server
            .dispatch(&dec, &mut pair, AccessTransport::McpWs)
            .await
            .unwrap();
        let inner: Value =
            serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(inner["plaintext_b64"], pt);
    }

    #[tokio::test]
    async fn sign_then_verify_true() {
        let server = server();
        let mut pair = PairState::AlreadyPaired(None);
        let payload = B64.encode(b"sign me");
        let sign = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"vault.sign","arguments":{{"key_ref":"s1","payload_b64":"{payload}"}}}}}}"#
        );
        let resp = server
            .dispatch(&sign, &mut pair, AccessTransport::McpWs)
            .await
            .unwrap();
        let inner: Value =
            serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        let sig = inner["signature_b64"].as_str().unwrap();
        let pubk = inner["public_key_b64"].as_str().unwrap();
        let verify = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"vault.verify","arguments":{{"public_key_b64":"{pubk}","payload_b64":"{payload}","signature_b64":"{sig}"}}}}}}"#
        );
        let resp = server
            .dispatch(&verify, &mut pair, AccessTransport::McpWs)
            .await
            .unwrap();
        let inner: Value =
            serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(inner["valid"], true);
    }

    #[tokio::test]
    async fn broker_call_when_disabled_returns_error() {
        let server = server(); // broker disabled
        let mut pair = PairState::AlreadyPaired(None);
        let call = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault.broker_request","arguments":{"secret_ref":"s","method":"GET","url":"https://api.example.com/x"}}}"#;
        let resp = server
            .dispatch(call, &mut pair, AccessTransport::McpWs)
            .await
            .unwrap();
        assert_eq!(resp["result"]["isError"], true);
        assert!(resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("broker disabled"));
    }

    #[tokio::test]
    async fn unpaired_first_call_rejected() {
        let server = server();
        let mut pair = PairState::Unpaired;
        let response = server
            .dispatch(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
                &mut pair,
                AccessTransport::McpWs,
            )
            .await
            .unwrap();
        assert_eq!(response["error"]["code"], codes::UNPAIRED);
        assert!(matches!(pair, PairState::Failed));
    }

    #[tokio::test]
    async fn pairing_with_correct_secret_succeeds() {
        let server = server();
        let mut pair = PairState::Unpaired;
        let response = server
            .dispatch(
                r#"{"jsonrpc":"2.0","id":1,"method":"vault.pair","params":{"secret":"test-secret"}}"#,
                &mut pair,
                AccessTransport::McpWs,
            )
            .await
            .unwrap();
        assert_eq!(response["result"]["paired"], true);
        assert!(matches!(pair, PairState::AlreadyPaired(_)));
    }

    #[tokio::test]
    async fn pairing_with_wrong_secret_fails() {
        let server = server();
        let mut pair = PairState::Unpaired;
        let response = server
            .dispatch(
                r#"{"jsonrpc":"2.0","id":1,"method":"vault.pair","params":{"secret":"wrong"}}"#,
                &mut pair,
                AccessTransport::McpWs,
            )
            .await
            .unwrap();
        assert_eq!(response["error"]["code"], codes::UNPAIRED);
        assert!(matches!(pair, PairState::Failed));
    }

    #[tokio::test]
    async fn write_then_read_roundtrip() {
        let server = server();
        let mut pair = PairState::AlreadyPaired(None);
        let payload = B64.encode(b"hello vault");
        let write_request = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"vault.write","arguments":{{"container":"notes","file_name":"a.txt","content_b64":"{payload}"}}}}}}"#
        );
        let response = server
            .dispatch(&write_request, &mut pair, AccessTransport::McpWs)
            .await
            .unwrap();
        assert_eq!(response["result"]["isError"], false);

        let read_request = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault.read","arguments":{"container":"notes","file_name":"a.txt"}}}"#;
        let read_response = server
            .dispatch(read_request, &mut pair, AccessTransport::McpWs)
            .await
            .unwrap();
        let inner = read_response["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        let value: Value = serde_json::from_str(inner).unwrap();
        assert_eq!(value["content_b64"], payload);
    }

    #[tokio::test]
    async fn locked_vault_returns_error() {
        let vault: SharedVault<StubVault> = Arc::new(Mutex::new(None));
        let server = McpServer::new(vault, "x");
        let mut pair = PairState::AlreadyPaired(None);
        let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault.list","arguments":{}}}"#;
        let response = server
            .dispatch(request, &mut pair, AccessTransport::McpWs)
            .await
            .unwrap();
        assert_eq!(response["result"]["isError"], true);
    }

    #[tokio::test]
    async fn unknown_method_404() {
        let server = server();
        let mut pair = PairState::AlreadyPaired(None);
        let response = server
            .dispatch(
                r#"{"jsonrpc":"2.0","id":1,"method":"frobnicate"}"#,
                &mut pair,
                AccessTransport::McpWs,
            )
            .await
            .unwrap();
        assert_eq!(response["error"]["code"], codes::METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn denied_request_is_reported_and_audited() {
        let audit = Arc::new(MemoryAudit(Default::default()));
        let server = server()
            .with_access_controller(Arc::new(DenyController))
            .with_audit_sink(audit.clone());
        let mut pair = PairState::AlreadyPaired(None);
        let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault.read","arguments":{"container":"notes","file_name":"a.txt"}}}"#;
        let response = server
            .dispatch(request, &mut pair, AccessTransport::McpWs)
            .await
            .unwrap();
        assert_eq!(response["result"]["isError"], true);

        let events = audit.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].decision, AuditDecision::Denied);
        assert_eq!(events[0].action, AuditAction::ReadFile);
    }

    struct FakeAuthenticator {
        agent_id: String,
        token: String,
        scopes: Vec<ResolvedScope>,
    }

    impl AgentAuthenticator for FakeAuthenticator {
        fn authenticate(
            &self,
            agent_id: Option<&str>,
            token: &str,
        ) -> std::result::Result<ResolvedAgent, String> {
            // Default-agent fallback: shared secret with no agent_id.
            if agent_id.is_none() {
                if token == "test-secret" {
                    return Ok(ResolvedAgent {
                        agent_id: "ag_default".into(),
                        scopes: vec![],
                    });
                }
                return Err("invalid shared secret".into());
            }
            if agent_id == Some(self.agent_id.as_str()) && token == self.token {
                Ok(ResolvedAgent {
                    agent_id: self.agent_id.clone(),
                    scopes: self.scopes.clone(),
                })
            } else {
                Err("unknown agent".into())
            }
        }
    }

    fn authed_server(scopes: Vec<ResolvedScope>) -> McpServer<StubVault> {
        let auth = Arc::new(FakeAuthenticator {
            agent_id: "ag_1".into(),
            token: "tok-1".into(),
            scopes,
        });
        server().with_agent_authenticator(auth)
    }

    #[tokio::test]
    async fn shared_secret_still_pairs_with_authenticator() {
        let server = authed_server(vec![]);
        let mut pair = PairState::Unpaired;
        let response = server
            .dispatch(
                r#"{"jsonrpc":"2.0","id":1,"method":"vault.pair","params":{"secret":"test-secret"}}"#,
                &mut pair,
                AccessTransport::McpWs,
            )
            .await
            .unwrap();
        assert_eq!(response["result"]["paired"], true);
        assert_eq!(response["result"]["agent_id"], "ag_default");
    }

    #[tokio::test]
    async fn per_agent_token_binds_identity_and_stamps_audit() {
        let audit = Arc::new(MemoryAudit(Default::default()));
        let server = authed_server(vec![]).with_audit_sink(audit.clone());
        let mut pair = PairState::Unpaired;
        let pair_resp = server
            .dispatch(
                r#"{"jsonrpc":"2.0","id":1,"method":"vault.pair","params":{"agent_id":"ag_1","token":"tok-1"}}"#,
                &mut pair,
                AccessTransport::McpWs,
            )
            .await
            .unwrap();
        assert_eq!(pair_resp["result"]["agent_id"], "ag_1");

        let payload = B64.encode(b"hi");
        let write = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"vault.write","arguments":{{"container":"notes","file_name":"a.txt","content_b64":"{payload}"}}}}}}"#
        );
        let resp = server
            .dispatch(&write, &mut pair, AccessTransport::McpWs)
            .await
            .unwrap();
        assert_eq!(resp["result"]["isError"], false);
        let events = audit.0.lock().unwrap();
        assert_eq!(events.last().unwrap().agent_id.as_deref(), Some("ag_1"));
    }

    #[tokio::test]
    async fn wrong_agent_token_rejected() {
        let server = authed_server(vec![]);
        let mut pair = PairState::Unpaired;
        let response = server
            .dispatch(
                r#"{"jsonrpc":"2.0","id":1,"method":"vault.pair","params":{"agent_id":"ag_1","token":"bad"}}"#,
                &mut pair,
                AccessTransport::McpWs,
            )
            .await
            .unwrap();
        assert_eq!(response["error"]["code"], codes::UNPAIRED);
        assert!(matches!(pair, PairState::Failed));
    }

    #[tokio::test]
    async fn scope_denies_action_not_granted() {
        // Agent may only read "notes", so a write must be denied by scope.
        let server = authed_server(vec![ResolvedScope {
            container_glob: "notes".into(),
            actions: vec![AccessAction::ReadFile],
            mode_ceiling: None,
        }]);
        let mut pair = PairState::Unpaired;
        server
            .dispatch(
                r#"{"jsonrpc":"2.0","id":1,"method":"vault.pair","params":{"agent_id":"ag_1","token":"tok-1"}}"#,
                &mut pair,
                AccessTransport::McpWs,
            )
            .await
            .unwrap();
        let payload = B64.encode(b"hi");
        let write = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"vault.write","arguments":{{"container":"notes","file_name":"a.txt","content_b64":"{payload}"}}}}}}"#
        );
        let resp = server
            .dispatch(&write, &mut pair, AccessTransport::McpWs)
            .await
            .unwrap();
        assert_eq!(resp["result"]["isError"], true);
    }

    #[tokio::test]
    async fn scope_allows_granted_action() {
        let server = authed_server(vec![ResolvedScope {
            container_glob: "notes".into(),
            actions: vec![AccessAction::ReadFile, AccessAction::WriteFile],
            mode_ceiling: None,
        }]);
        let mut pair = PairState::Unpaired;
        server
            .dispatch(
                r#"{"jsonrpc":"2.0","id":1,"method":"vault.pair","params":{"agent_id":"ag_1","token":"tok-1"}}"#,
                &mut pair,
                AccessTransport::McpWs,
            )
            .await
            .unwrap();
        let payload = B64.encode(b"hi");
        let write = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"vault.write","arguments":{{"container":"notes","file_name":"a.txt","content_b64":"{payload}"}}}}}}"#
        );
        let resp = server
            .dispatch(&write, &mut pair, AccessTransport::McpWs)
            .await
            .unwrap();
        assert_eq!(resp["result"]["isError"], false);
    }

    #[test]
    fn glob_matches() {
        assert!(glob_match("notes", "notes"));
        assert!(glob_match("notes/**", "notes/sub/file"));
        assert!(glob_match("*", "notes"));
        assert!(!glob_match("*", "notes/sub"));
        assert!(!glob_match("notes", "other"));
    }
}
