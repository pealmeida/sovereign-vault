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
//! # Stability
//!
//! Pre-1.0.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::convert::Infallible;
use std::net::SocketAddr;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::json;
use thiserror::Error;
use tokio::sync::oneshot;

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

/// Read-only HTTP server.
pub struct HttpServer {
    pairing_secret: String,
}

impl HttpServer {
    /// Build a new server using the given pairing secret for the
    /// `/.well-known/mcp-pairing` endpoint.
    pub fn new(pairing_secret: impl Into<String>) -> Self {
        Self {
            pairing_secret: pairing_secret.into(),
        }
    }

    /// Bind on `addr` (must be loopback) and serve until `shutdown` is signalled.
    pub async fn serve(&self, addr: SocketAddr, mut shutdown: oneshot::Receiver<()>) -> Result<()> {
        if !addr.ip().is_loopback() {
            return Err(HttpError::Forbidden);
        }
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| HttpError::Transport(format!("bind {addr}: {e}")))?;
        tracing::info!(%addr, "HTTP listening");
        let secret = self.pairing_secret.clone();
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    tracing::info!("HTTP shutdown");
                    return Ok(());
                }
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(p) => p,
                        Err(e) => { tracing::warn!(error=%e, "accept failed"); continue; }
                    };
                    if !peer.ip().is_loopback() {
                        tracing::warn!(?peer, "rejecting non-loopback peer");
                        continue;
                    }
                    let secret = secret.clone();
                    let io = TokioIo::new(stream);
                    tokio::spawn(async move {
                        let svc = service_fn(move |req| {
                            let secret = secret.clone();
                            async move { Ok::<_, Infallible>(handle(req, &secret).await) }
                        });
                        if let Err(e) = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, svc)
                            .await
                        {
                            tracing::debug!(error=%e, "http conn closed");
                        }
                    });
                }
            }
        }
    }
}

async fn handle(req: Request<Incoming>, pairing_secret: &str) -> Response<Full<Bytes>> {
    if req.method() != Method::GET {
        return json_response(
            StatusCode::METHOD_NOT_ALLOWED,
            &json!({ "error": "method not allowed" }),
        );
    }
    let path = req.uri().path();
    match path {
        "/health" => json_response(
            StatusCode::OK,
            &json!({
                "ok": true,
                "version": env!("CARGO_PKG_VERSION"),
                "service": "sovereign-vault",
            }),
        ),
        "/.well-known/agent.json" => json_response(StatusCode::OK, &agent_card()),
        "/.well-known/mcp-pairing" => {
            // Defence in depth: even though we bound to loopback, double-check
            // the Host header is loopback-y.
            if !host_is_loopback(&req) {
                return json_response(
                    StatusCode::FORBIDDEN,
                    &json!({ "error": "forbidden: non-loopback host" }),
                );
            }
            json_response(StatusCode::OK, &json!({ "secret": pairing_secret }))
        }
        _ => json_response(StatusCode::NOT_FOUND, &json!({ "error": "not found" })),
    }
}

fn host_is_loopback(req: &Request<Incoming>) -> bool {
    match req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
    {
        Some(host) => host.starts_with("localhost") || host.starts_with("127.0.0.1"),
        // No Host header = HTTP/1.0 client; reject for safety.
        None => false,
    }
}

fn json_response(status: StatusCode, body: &serde_json::Value) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .unwrap()
}

fn agent_card() -> serde_json::Value {
    json!({
        "name": "Sovereign Vault",
        "description": "Local-first encrypted file vault with MCP tool surface.",
        "version": env!("CARGO_PKG_VERSION"),
        "mcp_endpoint": "ws://127.0.0.1:9944/",
        "capabilities": ["mcp_tools"],
        "tools": [
            { "name": "vault.list",   "description": "List containers, or files in a single container." },
            { "name": "vault.read",   "description": "Read and decrypt a file. Returns base64." },
            { "name": "vault.write",  "description": "Encrypt and write a file (base64 input)." },
            { "name": "vault.delete", "description": "Delete a file." }
        ],
        "contact": { "type": "local", "host": "127.0.0.1", "ws_port": 9944, "http_port": 9943 }
    })
}

/// Crate version string.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
