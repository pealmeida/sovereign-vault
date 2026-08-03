//! Read-only HTTP service for Sovereign Vault.
//!
//! Exposes localhost-only endpoints:
//!
//! * `GET /health` — liveness probe (no auth, no data).
//! * `GET /.well-known/agent.json` — A2A-style agent card describing the
//!   MCP tool surface for discovery.
//! * `GET /.well-known/mcp-pairing` — optionally returns the per-launch
//!   pairing secret to MCP bridges spawned on the same machine.
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
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::json;
use thiserror::Error;
use tokio::sync::{oneshot, Semaphore};

const MAX_HTTP_CONNECTIONS: usize = 32;
const MAX_HTTP_HEADERS: usize = 32;
const HTTP_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);

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
    pairing_secret: Option<String>,
}

impl HttpServer {
    /// Build a new server using the given pairing secret for the
    /// `/.well-known/mcp-pairing` endpoint.
    pub fn new(pairing_secret: impl Into<String>) -> Self {
        Self {
            pairing_secret: Some(pairing_secret.into()),
        }
    }

    /// Build a server without the pairing-secret endpoint.
    ///
    /// Headless deployments use scoped agent credentials and must not expose
    /// any bearer credential through an unauthenticated loopback endpoint.
    pub fn without_pairing() -> Self {
        Self {
            pairing_secret: None,
        }
    }

    /// Bind on `addr` (must be loopback) and serve until `shutdown` is signalled.
    pub async fn serve(&self, addr: SocketAddr, shutdown: oneshot::Receiver<()>) -> Result<()> {
        if !addr.ip().is_loopback() {
            return Err(HttpError::Forbidden);
        }
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| HttpError::Transport(format!("bind {addr}: {e}")))?;
        self.serve_listener(listener, shutdown).await
    }

    /// Serve using a pre-bound listener.
    pub async fn serve_listener(
        &self,
        listener: tokio::net::TcpListener,
        mut shutdown: oneshot::Receiver<()>,
    ) -> Result<()> {
        let addr = listener
            .local_addr()
            .map_err(|e| HttpError::Transport(e.to_string()))?;
        if !addr.ip().is_loopback() {
            return Err(HttpError::Forbidden);
        }
        tracing::info!(%addr, "HTTP listening");
        let pairing_secret = self.pairing_secret.clone();
        let connection_limit = Arc::new(Semaphore::new(MAX_HTTP_CONNECTIONS));
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
                    let permit = match connection_limit.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            tracing::warn!(?peer, "rejecting HTTP connection: limit reached");
                            continue;
                        }
                    };
                    let pairing_secret = pairing_secret.clone();
                    let io = TokioIo::new(stream);
                    tokio::spawn(async move {
                        let _permit = permit;
                        let svc = service_fn(move |req| {
                            let pairing_secret = pairing_secret.clone();
                            async move { Ok::<_, Infallible>(handle(req, pairing_secret.as_deref()).await) }
                        });
                        let mut builder = hyper::server::conn::http1::Builder::new();
                        builder
                            .timer(TokioTimer::new())
                            .header_read_timeout(HTTP_HEADER_TIMEOUT)
                            .max_headers(MAX_HTTP_HEADERS)
                            .keep_alive(false);
                        match tokio::time::timeout(
                            HTTP_CONNECTION_TIMEOUT,
                            builder.serve_connection(io, svc),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => {
                                tracing::debug!(%error, "http conn closed");
                            }
                            Err(_) => {
                                tracing::debug!("http connection timed out");
                            }
                        }
                    });
                }
            }
        }
    }
}

async fn handle(req: Request<Incoming>, pairing_secret: Option<&str>) -> Response<Full<Bytes>> {
    if !host_is_loopback(&req) {
        return json_response(
            StatusCode::FORBIDDEN,
            &json!({ "error": "forbidden: non-loopback host" }),
        );
    }
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
        "/.well-known/mcp-pairing" => match pairing_secret {
            Some(secret) => json_response(StatusCode::OK, &json!({ "secret": secret })),
            None => json_response(StatusCode::NOT_FOUND, &json!({ "error": "not found" })),
        },
        _ => json_response(StatusCode::NOT_FOUND, &json!({ "error": "not found" })),
    }
}

fn host_is_loopback(req: &Request<Incoming>) -> bool {
    let mut hosts = req.headers().get_all(hyper::header::HOST).iter();
    let Some(host) = hosts.next().and_then(|value| value.to_str().ok()) else {
        // No Host header = HTTP/1.0 client; reject for safety.
        return false;
    };
    hosts.next().is_none() && authority_is_loopback(host)
}

fn authority_is_loopback(authority: &str) -> bool {
    let authority = authority.trim();
    let host = if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return false;
        };
        if !suffix.is_empty() && (!suffix.starts_with(':') || suffix[1..].parse::<u16>().is_err()) {
            return false;
        }
        host
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if port.parse::<u16>().is_err() {
            return false;
        }
        host
    } else {
        authority
    };

    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn json_response(status: StatusCode, body: &serde_json::Value) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header(CACHE_CONTROL, "no-store")
        .header(X_CONTENT_TYPE_OPTIONS, "nosniff")
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
            { "name": "vault.delete", "description": "Delete a file." },
            { "name": "vault.create_container", "description": "Create a container." },
            { "name": "vault.create_transit_key", "description": "Create a transit key held by the vault." },
            { "name": "vault.list_transit_keys", "description": "List transit-key metadata." },
            { "name": "vault.encrypt", "description": "Encrypt with a vault-held transit key." },
            { "name": "vault.decrypt", "description": "Decrypt with a vault-held transit key." },
            { "name": "vault.create_signing_key", "description": "Create a vault-held signing key." },
            { "name": "vault.list_signing_keys", "description": "List signing-key metadata." },
            { "name": "vault.sign", "description": "Sign with a vault-held Ed25519 key." },
            { "name": "vault.verify", "description": "Verify an Ed25519 signature." }
        ],
        "contact": { "type": "local", "host": "127.0.0.1", "ws_port": 9944, "http_port": 9943 }
    })
}

/// Crate version string.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn loopback_authority_requires_an_exact_host() {
        for allowed in [
            "localhost",
            "localhost:9943",
            "127.0.0.1:9943",
            "[::1]:9943",
        ] {
            assert!(authority_is_loopback(allowed), "{allowed}");
        }
        for denied in [
            "localhost.example.com",
            "localhost.example.com:9943",
            "127.0.0.1.example.com",
            "[::1]example.com",
            "localhost:",
            "https://localhost:9943",
            "user@localhost:9943",
        ] {
            assert!(!authority_is_loopback(denied), "{denied}");
        }
    }

    #[tokio::test]
    async fn prebound_non_loopback_listener_is_rejected() {
        let listener = match tokio::net::TcpListener::bind("0.0.0.0:0").await {
            Ok(listener) => listener,
            // Restricted CI sandboxes can prohibit non-loopback binds before
            // the server gets a chance to reject the listener itself.
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("binding non-loopback test listener: {error}"),
        };
        let (_shutdown_tx, shutdown_rx) = oneshot::channel();
        let error = HttpServer::new("secret")
            .serve_listener(listener, shutdown_rx)
            .await
            .unwrap_err();
        assert!(matches!(error, HttpError::Forbidden));
    }

    #[tokio::test]
    async fn every_endpoint_rejects_a_rebinding_host() {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("binding loopback test listener: {error}"),
        };
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            HttpServer::new("never-expose")
                .serve_listener(listener, shutdown_rx)
                .await
                .unwrap();
        });

        for path in [
            "/health",
            "/.well-known/agent.json",
            "/.well-known/mcp-pairing",
        ] {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let request = format!(
                "GET {path} HTTP/1.1\r\nHost: localhost.attacker.example\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            let response = String::from_utf8(response).unwrap();
            assert!(response.starts_with("HTTP/1.1 403"), "{path}: {response}");
            assert!(!response.contains("never-expose"));
        }

        let _ = shutdown_tx.send(());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn pairing_endpoint_can_be_disabled() {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("binding loopback test listener: {error}"),
        };
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            HttpServer::without_pairing()
                .serve_listener(listener, shutdown_rx)
                .await
                .unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                b"GET /.well-known/mcp-pairing HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 404"));

        let _ = shutdown_tx.send(());
        task.await.unwrap();
    }
}
