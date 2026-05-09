//! Read-only HTTP service for Sovereign Vault.
//!
//! Exposes three localhost-only endpoints:
//!
//! * `GET /health` — liveness probe (no auth, no data).
//! * `GET /.well-known/agent.json` — A2A-style agent card describing the
//!   MCP tool surface for discovery.
//! * `GET /.well-known/mcp-pairing` — returns the per-launch pairing
//!   secret to MCP bridges spawned on the same machine.
//!
//! All endpoints reject non-loopback hosts. No mutation surface here —
//! state-changing calls go through MCP only.
//!
//! Real implementation lands in M4.
//!
//! # Stability
//!
//! Pre-1.0.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use thiserror::Error;

/// HTTP layer errors.
#[derive(Debug, Error)]
pub enum HttpError {
    /// Underlying I/O or transport failure.
    #[error("Transport: {0}")]
    Transport(String),

    /// Request from a non-loopback host (rejected).
    #[error("Forbidden: non-loopback host")]
    Forbidden,
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, HttpError>;

/// Stub indicating the crate compiles. Replaced in M4.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
