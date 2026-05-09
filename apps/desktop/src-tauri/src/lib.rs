//! Sovereign Vault desktop entry point.
//!
//! Boots a Tauri window that loads the Svelte UI bundle and exposes
//! Tauri commands proxying to the `sv-core` integration crate.
//!
//! On unlock, also spins up:
//!   * MCP WebSocket server on `127.0.0.1:9944` (paired)
//!   * Read-only HTTP server on `127.0.0.1:9944` for `/health`,
//!     `/.well-known/agent.json`, `/.well-known/mcp-pairing`.
//!
//! Both share the live `VaultHandle` via `Arc<Mutex<Option<VaultHandle>>>`.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sv_core::sv_storage::{ContainerInfo, FileInfo, SecurityMode};
use sv_core::{CustodyMode, VaultHandle};
use tauri::async_runtime::{spawn, JoinHandle};
use tauri::{Manager, State};
use tokio::sync::{oneshot, Mutex};

const RPC_PORT: u16 = 9944;

type SharedHandle = Arc<Mutex<Option<VaultHandle>>>;

/// Shutdown signals for the MCP + HTTP background tasks.
struct ServersShutdown {
    ws_tx: Option<oneshot::Sender<()>>,
    http_tx: Option<oneshot::Sender<()>>,
    ws_task: Option<JoinHandle<()>>,
    http_task: Option<JoinHandle<()>>,
    pairing_secret: String,
    running: bool,
}

/// In-memory vault state held inside Tauri's managed state.
struct VaultState {
    handle: SharedHandle,
    servers: Mutex<Option<ServersShutdown>>,
}

impl Default for VaultState {
    fn default() -> Self {
        Self {
            handle: Arc::new(Mutex::new(None)),
            servers: Mutex::new(None),
        }
    }
}

/// Status payload returned by [`vault_status`].
#[derive(Debug, Serialize, Deserialize)]
struct VaultStatus {
    initialized: bool,
    unlocked: bool,
    custody: Option<String>,
    has_keychain_entry: bool,
    has_passphrase_salt: bool,
}

/// MCP integration status returned by [`mcp_status`].
#[derive(Debug, Serialize, Deserialize)]
struct McpStatus {
    running: bool,
    pairing_secret: Option<String>,
    ws_url: String,
    http_url: String,
}

fn estr<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn parse_custody(s: &str) -> Result<CustodyMode, String> {
    match s.to_ascii_uppercase().as_str() {
        "OSKEYCHAIN" | "OS_KEYCHAIN" | "KEYCHAIN" => Ok(CustodyMode::OsKeychain),
        "PASSPHRASE" => Ok(CustodyMode::Passphrase),
        other => Err(format!("unknown custody mode: {other}")),
    }
}

fn vault_root(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(estr)?;
    Ok(dir.join("sovereign-vault"))
}

#[tauri::command]
fn app_version() -> String {
    sv_core::version().to_string()
}

#[tauri::command]
async fn vault_status(
    app: tauri::AppHandle,
    state: State<'_, VaultState>,
) -> Result<VaultStatus, String> {
    let root = vault_root(&app)?;
    let probe = sv_core::probe(&root).map_err(estr)?;
    let guard = state.handle.lock().await;
    let custody = guard.as_ref().map(|h| match h.custody() {
        CustodyMode::OsKeychain => "OsKeychain".to_string(),
        CustodyMode::Passphrase => "Passphrase".to_string(),
    });
    Ok(VaultStatus {
        initialized: probe.initialized,
        unlocked: guard.is_some(),
        custody,
        has_keychain_entry: probe.has_keychain_entry,
        has_passphrase_salt: probe.has_passphrase_salt,
    })
}

#[tauri::command]
async fn vault_init(
    app: tauri::AppHandle,
    state: State<'_, VaultState>,
    custody: String,
    passphrase: Option<String>,
) -> Result<(), String> {
    let mode = parse_custody(&custody)?;
    let root = vault_root(&app)?;
    let probe = sv_core::probe(&root).map_err(estr)?;
    if probe.initialized {
        return Err("vault already initialised".into());
    }
    let handle = VaultHandle::bootstrap(&root, mode, passphrase.as_deref()).map_err(estr)?;
    {
        let mut guard = state.handle.lock().await;
        *guard = Some(handle);
    }
    start_servers(&state).await;
    Ok(())
}

#[tauri::command]
async fn vault_unlock(
    app: tauri::AppHandle,
    state: State<'_, VaultState>,
    custody: String,
    passphrase: Option<String>,
) -> Result<(), String> {
    let mode = parse_custody(&custody)?;
    let root = vault_root(&app)?;
    let handle = VaultHandle::unlock(&root, mode, passphrase.as_deref()).map_err(estr)?;
    {
        let mut guard = state.handle.lock().await;
        *guard = Some(handle);
    }
    start_servers(&state).await;
    Ok(())
}

#[tauri::command]
async fn vault_lock(state: State<'_, VaultState>) -> Result<(), String> {
    stop_servers(&state).await;
    let mut guard = state.handle.lock().await;
    *guard = None;
    Ok(())
}

async fn with_handle<R, F>(state: &State<'_, VaultState>, f: F) -> Result<R, String>
where
    F: FnOnce(&VaultHandle) -> Result<R, String>,
{
    let guard = state.handle.lock().await;
    let h = guard
        .as_ref()
        .ok_or_else(|| "vault is locked".to_string())?;
    f(h)
}

#[tauri::command]
async fn vault_list_containers(state: State<'_, VaultState>) -> Result<Vec<ContainerInfo>, String> {
    with_handle(&state, |h| h.list_containers().map_err(estr)).await
}

#[tauri::command]
async fn vault_create_container(
    state: State<'_, VaultState>,
    name: String,
    mode: String,
    description: Option<String>,
) -> Result<(), String> {
    let mode = SecurityMode::parse(&mode).map_err(estr)?;
    with_handle(&state, |h| {
        h.create_container(&name, mode, description).map_err(estr)
    })
    .await
}

#[tauri::command]
async fn vault_delete_container(state: State<'_, VaultState>, name: String) -> Result<(), String> {
    with_handle(&state, |h| h.delete_container(&name).map_err(estr)).await
}

#[tauri::command]
async fn vault_list_files(
    state: State<'_, VaultState>,
    container: String,
) -> Result<Vec<FileInfo>, String> {
    with_handle(&state, |h| h.list_files(&container).map_err(estr)).await
}

#[tauri::command]
async fn vault_write_file(
    state: State<'_, VaultState>,
    container: String,
    file_name: String,
    content: Vec<u8>,
) -> Result<(), String> {
    with_handle(&state, |h| {
        h.write_file(&container, &file_name, &content).map_err(estr)
    })
    .await
}

#[tauri::command]
async fn vault_read_file(
    state: State<'_, VaultState>,
    container: String,
    file_name: String,
) -> Result<Vec<u8>, String> {
    with_handle(&state, |h| {
        h.read_file(&container, &file_name).map_err(estr)
    })
    .await
}

#[tauri::command]
async fn vault_delete_file(
    state: State<'_, VaultState>,
    container: String,
    file_name: String,
) -> Result<(), String> {
    with_handle(&state, |h| {
        h.delete_file(&container, &file_name).map_err(estr)
    })
    .await
}

#[tauri::command]
async fn mcp_status(state: State<'_, VaultState>) -> Result<McpStatus, String> {
    let guard = state.servers.lock().await;
    let (running, pairing_secret) = match guard.as_ref() {
        Some(s) if s.running => (true, Some(s.pairing_secret.clone())),
        _ => (false, None),
    };
    Ok(McpStatus {
        running,
        pairing_secret,
        ws_url: format!("ws://127.0.0.1:{RPC_PORT}"),
        http_url: format!("http://127.0.0.1:{}", RPC_PORT - 1),
    })
}

#[tauri::command]
fn cli_binary_path() -> Result<String, String> {
    // For v0, resolve based on the running exe location:
    //   <target>/<profile>/sovereign-vault-desktop[.exe]  (current exe)
    //   <target>/<profile>/sovereign-vault[.exe]          (CLI binary, sibling)
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = me.parent().ok_or_else(|| "no parent dir".to_string())?;
    let exe_suffix = if cfg!(windows) { ".exe" } else { "" };
    let candidate = dir.join(format!("sovereign-vault{exe_suffix}"));
    if candidate.exists() {
        Ok(candidate.to_string_lossy().to_string())
    } else {
        // Fall back to the workspace target/debug location relative to CWD.
        Err(format!(
            "sovereign-vault binary not found next to {}",
            me.display()
        ))
    }
}

async fn start_servers(state: &State<'_, VaultState>) {
    // Stop any previous instance first (idempotent on re-unlock).
    stop_servers(state).await;

    let secret = match sv_core::fresh_pairing_secret() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[mcp] failed to generate pairing secret: {e}");
            return;
        }
    };

    let addr: SocketAddr = match format!("127.0.0.1:{RPC_PORT}").parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[mcp] bad addr: {e}");
            return;
        }
    };

    // MCP WS.
    let (ws_tx, ws_rx) = oneshot::channel::<()>();
    let ws_server = Arc::new(sv_mcp::McpServer::new(
        state.handle.clone() as sv_mcp::SharedVault<VaultHandle>,
        secret.clone(),
    ));
    let ws_task = spawn(async move {
        if let Err(e) = ws_server.serve_ws(addr, ws_rx).await {
            eprintln!("[mcp] WS server stopped: {e}");
        }
    });

    // HTTP.
    let http_addr = addr; // same port, but HTTP server uses a separate listener.
                          // To avoid port collision (only one listener can bind 9944), we put HTTP
                          // on RPC_PORT+1 and document this. The architecture diagram says both on
                          // 9944 — that requires multiplexing. For v1.0 we keep it simple: WS on
                          // 9944, HTTP on 9943 (one below). Update the well-known doc accordingly.
    let http_addr: SocketAddr = match format!("127.0.0.1:{}", RPC_PORT - 1).parse() {
        Ok(a) => a,
        Err(_) => http_addr,
    };
    let (http_tx, http_rx) = oneshot::channel::<()>();
    let http_secret = secret.clone();
    let http_task = spawn(async move {
        let server = sv_http::HttpServer::new(http_secret);
        if let Err(e) = server.serve(http_addr, http_rx).await {
            eprintln!("[http] server stopped: {e}");
        }
    });

    let mut guard = state.servers.lock().await;
    *guard = Some(ServersShutdown {
        ws_tx: Some(ws_tx),
        http_tx: Some(http_tx),
        ws_task: Some(ws_task),
        http_task: Some(http_task),
        pairing_secret: secret,
        running: true,
    });
}

async fn stop_servers(state: &State<'_, VaultState>) {
    let mut guard = state.servers.lock().await;
    if let Some(mut s) = guard.take() {
        if let Some(tx) = s.ws_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = s.http_tx.take() {
            let _ = tx.send(());
        }
        if let Some(t) = s.ws_task.take() {
            let _ = t.await;
        }
        if let Some(t) = s.http_task.take() {
            let _ = t.await;
        }
    }
}

/// Build and run the Tauri application.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            app.manage(VaultState::default());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_version,
            vault_status,
            vault_init,
            vault_unlock,
            vault_lock,
            vault_list_containers,
            vault_create_container,
            vault_delete_container,
            vault_list_files,
            vault_write_file,
            vault_read_file,
            vault_delete_file,
            mcp_status,
            cli_binary_path,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Sovereign Vault");
}
