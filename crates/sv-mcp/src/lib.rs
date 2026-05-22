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

/// Abstracts over the underlying vault so this crate doesn't depend on
/// `sv-core` (which would form a dependency cycle). `sv-core` implements
/// this trait for `VaultHandle`.
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
}

impl<H: VaultFacade + 'static> McpServer<H> {
    /// Build a new server bound to the given vault state and pairing secret.
    pub fn new(handle: SharedVault<H>, pairing_secret: impl Into<String>) -> Self {
        Self {
            handle,
            pairing_secret: pairing_secret.into(),
            access_controller: None,
            audit_sink: None,
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

    /// Pairing secret in use.
    pub fn pairing_secret(&self) -> &str {
        &self.pairing_secret
    }

    /// Generate a fresh URL-safe-base64 32-byte pairing secret.
    pub fn fresh_pairing_secret() -> String {
        let mut buf = [0u8; 32];
        if getrandom_fill(&mut buf).is_err() {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(31);
            }
        }
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
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
                .dispatch(trimmed, &mut PairState::AlreadyPaired, AccessTransport::McpStdio)
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
                Message::Text(t) => t,
                Message::Binary(b) => {
                    String::from_utf8(b).map_err(|e| McpError::Protocol(e.to_string()))?
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
                let secret = params
                    .get("secret")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if secret == self.pairing_secret {
                    *pair = PairState::AlreadyPaired;
                    return Some(ok_response(id, json!({ "paired": true })));
                } else {
                    *pair = PairState::Failed;
                    return Some(error_response(id, codes::UNPAIRED, "Unpaired connection"));
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
            "tools/list" => Some(ok_response(id, json!({ "tools": tool_descriptors() }))),
            "tools/call" => {
                let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
                let result = self.call_tool(name, arguments, transport).await;
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

    async fn call_tool(
        &self,
        name: &str,
        args: Value,
        transport: AccessTransport,
    ) -> std::result::Result<Value, String> {
        let access = {
            let guard = self.handle.lock().await;
            let handle = guard
                .as_ref()
                .ok_or_else(|| "vault is locked".to_string())?;
            self.build_access_request(handle, name, &args, transport)?
        };

        if let Some(controller) = &self.access_controller {
            if let Err(error) = controller.authorize(access.clone()).await {
                self.record_audit(&access, AuditDecision::Denied, None, Some(error.clone()));
                return Err(error);
            }
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
            Err(error) => self.record_audit(&access, AuditDecision::Error, None, Some(error.clone())),
        }

        result
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
                })
            }
            other => Err(format!("unknown tool: {other}")),
        }
    }

    fn execute_tool(&self, handle: &H, name: &str, args: &Value) -> std::result::Result<Value, String> {
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

        let mut event = AuditEvent::new(request.action.audit_action(), decision, request.transport.as_str());
        event.container = request.container.clone();
        event.file_name = request.file_name.clone();
        event.mode = request.mode.map(|mode| mode.as_str().to_string());
        event.byte_size = request.byte_size;
        event.detail = detail;
        event.error = error;
        let _ = sink.record(event);
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
    AlreadyPaired,
    Failed,
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

fn tool_descriptors() -> Value {
    json!([
        {
            "name": "vault.list",
            "description":
                "List containers in the vault, or files in a single container. \
                 Requests for protected containers may require desktop approval.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "container": { "type": "string", "description": "Container name. Omit to list all containers." }
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
                    "file_name": { "type": "string" }
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
                    "content_b64": { "type": "string", "description": "Base64-encoded plaintext content." }
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
                    "file_name": { "type": "string" }
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
                    "description": { "type": "string", "description": "Optional human-readable description." }
                },
                "additionalProperties": false
            }
        }
    ])
}

fn getrandom_fill(buf: &mut [u8]) -> std::result::Result<(), ()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_nanos();
    let pid = std::process::id() as u128;
    let mut state = nanos ^ (pid.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    for byte in buf.iter_mut() {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        *byte = (z & 0xFF) as u8;
    }
    Ok(())
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
    }

    impl VaultFacade for StubVault {
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

    fn server() -> McpServer<StubVault> {
        let vault = StubVault {
            containers: vec![ContainerInfo {
                name: "notes".into(),
                mode: SecurityMode::Approval,
                file_count: 0,
                description: None,
            }],
            files: Default::default(),
        };
        McpServer::new(Arc::new(Mutex::new(Some(vault))), "test-secret")
    }

    #[tokio::test]
    async fn initialize_returns_protocol_version() {
        let server = server();
        let mut pair = PairState::AlreadyPaired;
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
    async fn tools_list_has_five() {
        let server = server();
        let mut pair = PairState::AlreadyPaired;
        let response = server
            .dispatch(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                &mut pair,
                AccessTransport::McpWs,
            )
            .await
            .unwrap();
        assert_eq!(response["result"]["tools"].as_array().unwrap().len(), 5);
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
        assert!(matches!(pair, PairState::AlreadyPaired));
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
        let mut pair = PairState::AlreadyPaired;
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
        let inner = read_response["result"]["content"][0]["text"].as_str().unwrap();
        let value: Value = serde_json::from_str(inner).unwrap();
        assert_eq!(value["content_b64"], payload);
    }

    #[tokio::test]
    async fn locked_vault_returns_error() {
        let vault: SharedVault<StubVault> = Arc::new(Mutex::new(None));
        let server = McpServer::new(vault, "x");
        let mut pair = PairState::AlreadyPaired;
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
        let mut pair = PairState::AlreadyPaired;
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
        let mut pair = PairState::AlreadyPaired;
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
}
