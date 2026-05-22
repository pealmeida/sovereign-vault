//! Sovereign Vault headless CLI.
//!
//! Subcommands:
//! * (none) — print version banner.
//! * `mcp-stdio` — proxy MCP JSON-RPC between stdin/stdout and the local
//!   vault's WebSocket server (`ws://127.0.0.1:9944`).
//!
//! The proxy is the binary that Claude Desktop, Cursor, Continue.dev, etc.
//! spawn as a subprocess. It fetches the per-launch pairing secret from
//! `http://127.0.0.1:9943/.well-known/mcp-pairing`, opens the WS connection,
//! sends `vault.pair { secret }`, and then forwards line-delimited JSON-RPC
//! frames in both directions.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_tungstenite::tungstenite::Message;

const VAULT_HTTP: &str = "http://127.0.0.1:9943";
const VAULT_WS: &str = "ws://127.0.0.1:9944";

#[derive(Parser, Debug)]
#[command(name = "sovereign-vault", version, about = "Sovereign Vault CLI")]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run a stdio→WebSocket MCP proxy targeting the local Sovereign Vault.
    McpStdio,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        None => {
            println!("Sovereign Vault v{}", sv_core::version());
            ExitCode::SUCCESS
        }
        Some(Cmd::McpStdio) => match run_mcp_stdio().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sovereign-vault mcp-stdio: {e}");
                ExitCode::from(1)
            }
        },
    }
}

async fn run_mcp_stdio() -> Result<(), String> {
    // Quiet logging unless the user opts in.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    // 1. Fetch pairing secret.
    let secret = fetch_pairing_secret().await.map_err(|e| {
        format!(
            "Sovereign Vault is not running or not unlocked. \
             Open the desktop app and unlock your vault first. ({e})"
        )
    })?;

    // 2. Open WS.
    let (ws, _resp) = tokio_tungstenite::connect_async(VAULT_WS)
        .await
        .map_err(|e| format!("connect {VAULT_WS}: {e}"))?;
    let (mut sink, mut source) = ws.split();

    // 3. Send pair message and await response.
    let pair_req = json!({
        "jsonrpc": "2.0",
        "id": "pair",
        "method": "vault.pair",
        "params": { "secret": secret }
    });
    sink.send(Message::Text(pair_req.to_string()))
        .await
        .map_err(|e| format!("send pair: {e}"))?;
    match source.next().await {
        Some(Ok(Message::Text(t))) => {
            let v: Value =
                serde_json::from_str(&t).map_err(|e| format!("malformed pair response: {e}"))?;
            if v.get("error").is_some() || v.get("result").and_then(|r| r.get("paired")).is_none() {
                return Err(format!("pairing rejected: {t}"));
            }
        }
        Some(Ok(other)) => return Err(format!("unexpected pair frame: {other:?}")),
        Some(Err(e)) => return Err(format!("ws error during pair: {e}")),
        None => return Err("ws closed during pair".into()),
    }

    // 4. Forward stdin → WS, WS → stdout, until either side closes.
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();
    let mut stdout = tokio::io::stdout();

    loop {
        tokio::select! {
            line = lines.next_line() => {
                match line {
                    Ok(Some(l)) => {
                        let l = l.trim();
                        if l.is_empty() { continue; }
                        if let Err(e) = sink.send(Message::Text(l.to_string())).await {
                            return Err(format!("ws send: {e}"));
                        }
                    }
                    Ok(None) => {
                        let _ = sink.send(Message::Close(None)).await;
                        return Ok(());
                    }
                    Err(e) => return Err(format!("stdin: {e}")),
                }
            }
            msg = source.next() => {
                match msg {
                    Some(Ok(Message::Text(t))) => {
                        if !is_supported_frame(&t) { continue; }
                        stdout.write_all(t.as_bytes()).await.map_err(|e| e.to_string())?;
                        stdout.write_all(b"\n").await.map_err(|e| e.to_string())?;
                        stdout.flush().await.map_err(|e| e.to_string())?;
                    }
                    Some(Ok(Message::Binary(b))) => {
                        if let Ok(t) = String::from_utf8(b) {
                            if is_supported_frame(&t) {
                                stdout.write_all(t.as_bytes()).await.map_err(|e| e.to_string())?;
                                stdout.write_all(b"\n").await.map_err(|e| e.to_string())?;
                                stdout.flush().await.map_err(|e| e.to_string())?;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Err(format!("ws recv: {e}")),
                }
            }
        }
    }
}

/// Drop server-pushed messages that aren't part of the MCP JSON-RPC spec
/// (e.g. broadcast events). Keep responses (`id` set) and `notifications/*`.
fn is_supported_frame(text: &str) -> bool {
    let v: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if v.get("id").is_some() {
        return true;
    }
    match v.get("method").and_then(|m| m.as_str()) {
        Some(m) => m.starts_with("notifications/"),
        None => false,
    }
}

async fn fetch_pairing_secret() -> Result<String, String> {
    let url = format!("{VAULT_HTTP}/.well-known/mcp-pairing");
    let resp = reqwest::get(&url).await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let body: Value = resp.json().await.map_err(|e| e.to_string())?;
    body.get("secret")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "no `secret` field in pairing response".into())
}
