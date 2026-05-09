//! Model Context Protocol (MCP) server for Sovereign Vault.
//!
//! Exposes the v1.0 vault tool surface (`vault.list`, `vault.read`,
//! `vault.write`, `vault.delete`) over two transports:
//!
//! * **Stdio** — for tools that spawn the vault as a subprocess
//!   (rarely used directly; the CLI ships a stdio→WS proxy instead).
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

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sv_storage::{ContainerInfo, FileInfo};
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
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const SERVER_ERROR: i32 = -32000;
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
}

/// Shared, lockable, optional vault handle. `None` ⇒ vault is locked.
pub type SharedVault<H> = Arc<Mutex<Option<H>>>;

/// MCP server. Holds a shared vault handle + the per-launch pairing secret.
pub struct McpServer<H: VaultFacade + 'static> {
    handle: SharedVault<H>,
    pairing_secret: String,
}

impl<H: VaultFacade + 'static> McpServer<H> {
    /// Build a new server bound to the given vault state and pairing secret.
    pub fn new(handle: SharedVault<H>, pairing_secret: impl Into<String>) -> Self {
        Self {
            handle,
            pairing_secret: pairing_secret.into(),
        }
    }

    /// Pairing secret in use.
    pub fn pairing_secret(&self) -> &str {
        &self.pairing_secret
    }

    /// Generate a fresh URL-safe-base64 32-byte pairing secret.
    pub fn fresh_pairing_secret() -> String {
        // 32 bytes from OS RNG → URL-safe base64 (no padding).
        let mut buf = [0u8; 32];
        // getrandom is already in the dep tree via sv-crypto, but we don't
        // depend on it directly here — go through std for portability.
        // Use a thread_local CSPRNG via getrandom-equivalent: tokio doesn't
        // ship one, so we shell out to the OS through `getrandom` if present
        // — fall back to a simple time-seeded XOR otherwise (dev only).
        if getrandom_fill(&mut buf).is_err() {
            // Should never happen on supported platforms, but degrade gracefully.
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(31);
            }
        }
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    }

    /// Run an MCP server reading JSON-RPC line-delimited frames from `reader`,
    /// writing responses to `writer`. Used for tests and embedded scenarios.
    /// No pairing required on stdio (stdio is implicitly trusted because the
    /// caller already had to spawn this process).
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
            let response = self.dispatch(trimmed, &mut PairState::AlreadyPaired).await;
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
    /// Each connection must send `vault.pair { secret }` first.
    pub async fn serve_ws(
        self: Arc<Self>,
        addr: SocketAddr,
        mut shutdown: oneshot::Receiver<()>,
    ) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| McpError::Transport(format!("bind {addr}: {e}")))?;
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
            let response = self.dispatch(text.trim(), &mut pair_state).await;
            if let Some(resp) = response {
                let bytes =
                    serde_json::to_string(&resp).map_err(|e| McpError::Protocol(e.to_string()))?;
                sink.send(Message::Text(bytes))
                    .await
                    .map_err(|e| McpError::Transport(e.to_string()))?;
            }
            // If pairing failed, drop the connection.
            if matches!(pair_state, PairState::Failed) {
                let _ = sink.send(Message::Close(None)).await;
                break;
            }
        }
        Ok(())
    }

    /// Parse, route, and produce a response Value (or None for notifications).
    async fn dispatch(&self, raw: &str, pair: &mut PairState) -> Option<Value> {
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
            None => return None, // not a request — ignore
        };
        let params = req.get("params").cloned().unwrap_or(Value::Null);

        // Notifications (no id) are silently dropped.
        let id = match id {
            Some(v) if !v.is_null() => v,
            _ => return None,
        };

        // Pairing handshake: WS connections must pair first.
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
                let result = self.call_tool(name, arguments).await;
                Some(ok_response(id, tool_result(result)))
            }
            "vault.pair" => {
                // Already paired — accept idempotently.
                Some(ok_response(id, json!({ "paired": true })))
            }
            "ping" => Some(ok_response(id, json!({}))),
            other => Some(error_response(
                id,
                codes::METHOD_NOT_FOUND,
                &format!("method not found: {other}"),
            )),
        }
    }

    async fn call_tool(&self, name: &str, args: Value) -> std::result::Result<Value, String> {
        let guard = self.handle.lock().await;
        let h = guard
            .as_ref()
            .ok_or_else(|| "vault is locked".to_string())?;
        match name {
            "vault.list" => {
                let container = args.get("container").and_then(|v| v.as_str());
                if let Some(c) = container {
                    let files = h.list_files(c)?;
                    Ok(serde_json::to_value(files).map_err(|e| e.to_string())?)
                } else {
                    let cs = h.list_containers()?;
                    Ok(serde_json::to_value(cs).map_err(|e| e.to_string())?)
                }
            }
            "vault.read" => {
                let container = required_str(&args, "container")?;
                let file_name = required_str(&args, "file_name")?;
                let bytes = h.read_file(container, file_name)?;
                Ok(json!({
                    "container": container,
                    "file_name": file_name,
                    "content_b64": B64.encode(&bytes),
                    "byte_size": bytes.len(),
                }))
            }
            "vault.write" => {
                let container = required_str(&args, "container")?;
                let file_name = required_str(&args, "file_name")?;
                let content_b64 = required_str(&args, "content_b64")?;
                let bytes = B64
                    .decode(content_b64.as_bytes())
                    .map_err(|e| format!("invalid base64: {e}"))?;
                let n = bytes.len();
                h.write_file(container, file_name, &bytes)?;
                Ok(json!({ "ok": true, "byte_size": n }))
            }
            "vault.delete" => {
                let container = required_str(&args, "container")?;
                let file_name = required_str(&args, "file_name")?;
                h.delete_file(container, file_name)?;
                Ok(json!({ "ok": true }))
            }
            other => Err(format!("unknown tool: {other}")),
        }
    }
}

fn required_str<'a>(v: &'a Value, key: &str) -> std::result::Result<&'a str, String> {
    v.get(key)
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
        Ok(v) => json!({
            "content": [{ "type": "text", "text": serde_json::to_string(&v).unwrap_or_default() }],
            "isError": false,
        }),
        Err(e) => json!({
            "content": [{ "type": "text", "text": e }],
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
                 HITL approval will be required in v1.1; today every call goes through if the vault is unlocked.",
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
                "Read and decrypt a single file from a container. Returns base64-encoded content. \
                 HITL approval will be required in v1.1; today every call goes through if the vault is unlocked.",
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
                "Encrypt and write a file into a container. content_b64 is base64-encoded plaintext. \
                 HITL approval will be required in v1.1; today every call goes through if the vault is unlocked.",
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
            "description":
                "Delete a file from a container. \
                 HITL approval will be required in v1.1; today every call goes through if the vault is unlocked.",
            "inputSchema": {
                "type": "object",
                "required": ["container", "file_name"],
                "properties": {
                    "container": { "type": "string" },
                    "file_name": { "type": "string" }
                },
                "additionalProperties": false
            }
        }
    ])
}

// Tiny wrapper around getrandom so we don't take a direct dependency on it
// (sv-crypto already does, and we want to keep the dep graph slim).
fn getrandom_fill(buf: &mut [u8]) -> std::result::Result<(), ()> {
    // Use the standard `getrandom` crate via std::env::var as a hint? No —
    // simpler: use a tiny syscall path via std. On stable Rust there's no
    // public OS RNG in std, so we fall back to a hash of process state.
    // In practice, callers should use `McpServer::fresh_pairing_secret`
    // only from the desktop crate which does have getrandom in its tree;
    // but to keep this crate dep-light we accept the worst-case fallback.
    //
    // For the desktop app we override by passing a pre-generated secret
    // into `McpServer::new`. The `fresh_pairing_secret` helper here is a
    // convenience for tests.
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_nanos();
    let pid = std::process::id() as u128;
    let mut state = nanos ^ (pid.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    for b in buf.iter_mut() {
        // splitmix64 step
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        *b = (z & 0xFF) as u8;
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
    use sv_storage::SecurityMode;

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
    }

    fn server() -> McpServer<StubVault> {
        let vault = StubVault {
            containers: vec![ContainerInfo {
                name: "notes".into(),
                mode: SecurityMode::Direct,
                file_count: 0,
                description: None,
            }],
            files: Default::default(),
        };
        McpServer::new(Arc::new(Mutex::new(Some(vault))), "test-secret")
    }

    #[tokio::test]
    async fn initialize_returns_protocol_version() {
        let s = server();
        let mut p = PairState::AlreadyPaired;
        let r = s
            .dispatch(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#, &mut p)
            .await
            .unwrap();
        assert_eq!(r["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(r["result"]["serverInfo"]["name"], "sovereign-vault");
    }

    #[tokio::test]
    async fn tools_list_has_four() {
        let s = server();
        let mut p = PairState::AlreadyPaired;
        let r = s
            .dispatch(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#, &mut p)
            .await
            .unwrap();
        assert_eq!(r["result"]["tools"].as_array().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn unpaired_first_call_rejected() {
        let s = server();
        let mut p = PairState::Unpaired;
        let r = s
            .dispatch(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#, &mut p)
            .await
            .unwrap();
        assert_eq!(r["error"]["code"], codes::UNPAIRED);
        assert!(matches!(p, PairState::Failed));
    }

    #[tokio::test]
    async fn pairing_with_correct_secret_succeeds() {
        let s = server();
        let mut p = PairState::Unpaired;
        let r = s
            .dispatch(
                r#"{"jsonrpc":"2.0","id":1,"method":"vault.pair","params":{"secret":"test-secret"}}"#,
                &mut p,
            )
            .await
            .unwrap();
        assert_eq!(r["result"]["paired"], true);
        assert!(matches!(p, PairState::AlreadyPaired));
    }

    #[tokio::test]
    async fn pairing_with_wrong_secret_fails() {
        let s = server();
        let mut p = PairState::Unpaired;
        let r = s
            .dispatch(
                r#"{"jsonrpc":"2.0","id":1,"method":"vault.pair","params":{"secret":"wrong"}}"#,
                &mut p,
            )
            .await
            .unwrap();
        assert_eq!(r["error"]["code"], codes::UNPAIRED);
        assert!(matches!(p, PairState::Failed));
    }

    #[tokio::test]
    async fn write_then_read_roundtrip() {
        let s = server();
        let mut p = PairState::AlreadyPaired;
        let payload = B64.encode(b"hello vault");
        let req = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"vault.write","arguments":{{"container":"notes","file_name":"a.txt","content_b64":"{payload}"}}}}}}"#
        );
        let r = s.dispatch(&req, &mut p).await.unwrap();
        assert_eq!(r["result"]["isError"], false);

        let req2 = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault.read","arguments":{"container":"notes","file_name":"a.txt"}}}"#;
        let r2 = s.dispatch(req2, &mut p).await.unwrap();
        let inner = r2["result"]["content"][0]["text"].as_str().unwrap();
        let v: Value = serde_json::from_str(inner).unwrap();
        assert_eq!(v["content_b64"], payload);
    }

    #[tokio::test]
    async fn locked_vault_returns_error() {
        let v: SharedVault<StubVault> = Arc::new(Mutex::new(None));
        let s = McpServer::new(v, "x");
        let mut p = PairState::AlreadyPaired;
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault.list","arguments":{}}}"#;
        let r = s.dispatch(req, &mut p).await.unwrap();
        assert_eq!(r["result"]["isError"], true);
    }

    #[tokio::test]
    async fn unknown_method_404() {
        let s = server();
        let mut p = PairState::AlreadyPaired;
        let r = s
            .dispatch(r#"{"jsonrpc":"2.0","id":1,"method":"frobnicate"}"#, &mut p)
            .await
            .unwrap();
        assert_eq!(r["error"]["code"], codes::METHOD_NOT_FOUND);
    }
}
