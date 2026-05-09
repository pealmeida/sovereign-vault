//! Model Context Protocol (MCP) server for Sovereign Vault.
//!
//! Exposes the v1.0 vault tool surface (`vault.list`, `vault.read`,
//! `vault.write`, `vault.delete`) over two transports:
//!
//! * **Stdio** — for tools that spawn the vault as a subprocess
//!   (e.g. Claude Desktop, Cursor).
//! * **WebSocket** — for long-running agents that connect to a running
//!   vault on `ws://127.0.0.1:9944`.
//!
//! Pairing handshake is required on the WS transport: clients fetch a
//! per-launch secret from the localhost-only HTTP endpoint
//! `/.well-known/mcp-pairing`, then send `vault.pair { secret }` as the
//! first message.
//!
//! Real implementation lands in M4.
//!
//! # Stability
//!
//! Pre-1.0.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use thiserror::Error;

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
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, McpError>;

/// Stub indicating the crate compiles. Replaced in M4.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
