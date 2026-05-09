//! Sovereign Vault desktop entry point.
//!
//! Boots a Tauri window that loads the Svelte UI bundle and exposes
//! Tauri commands proxying to the `sv-core` integration crate.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sv_core::sv_storage::{ContainerInfo, FileInfo, SecurityMode};
use sv_core::{CustodyMode, VaultHandle};
use tauri::{Manager, State};

/// In-memory vault state held inside Tauri's managed state.
#[derive(Default)]
struct VaultState {
    handle: Mutex<Option<VaultHandle>>,
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

/// Map any error into a string for the UI layer.
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

/// Echo the `sv-core` crate version. Kept for compatibility with the
/// pre-MVP shell.
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
    let guard = state
        .handle
        .lock()
        .map_err(|_| "state poisoned".to_string())?;
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
    let mut guard = state
        .handle
        .lock()
        .map_err(|_| "state poisoned".to_string())?;
    *guard = Some(handle);
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
    let mut guard = state
        .handle
        .lock()
        .map_err(|_| "state poisoned".to_string())?;
    *guard = Some(handle);
    Ok(())
}

#[tauri::command]
async fn vault_lock(state: State<'_, VaultState>) -> Result<(), String> {
    let mut guard = state
        .handle
        .lock()
        .map_err(|_| "state poisoned".to_string())?;
    *guard = None;
    Ok(())
}

fn with_handle<R>(
    state: &State<'_, VaultState>,
    f: impl FnOnce(&VaultHandle) -> Result<R, String>,
) -> Result<R, String> {
    let guard = state
        .handle
        .lock()
        .map_err(|_| "state poisoned".to_string())?;
    let h = guard
        .as_ref()
        .ok_or_else(|| "vault is locked".to_string())?;
    f(h)
}

#[tauri::command]
async fn vault_list_containers(state: State<'_, VaultState>) -> Result<Vec<ContainerInfo>, String> {
    with_handle(&state, |h| h.list_containers().map_err(estr))
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
}

#[tauri::command]
async fn vault_delete_container(state: State<'_, VaultState>, name: String) -> Result<(), String> {
    with_handle(&state, |h| h.delete_container(&name).map_err(estr))
}

#[tauri::command]
async fn vault_list_files(
    state: State<'_, VaultState>,
    container: String,
) -> Result<Vec<FileInfo>, String> {
    with_handle(&state, |h| h.list_files(&container).map_err(estr))
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running Sovereign Vault");
}
