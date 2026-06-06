//! Sovereign Vault desktop entry point.
//!
//! Boots a Tauri window that loads the Svelte UI bundle and exposes
//! Tauri commands proxying to the `sv-core` integration crate.
//!
//! On unlock, also spins up:
//!   * MCP WebSocket server on `127.0.0.1:9944` (paired)
//!   * Read-only HTTP server on `127.0.0.1:9943` for `/health`,
//!     `/.well-known/agent.json`, `/.well-known/mcp-pairing`
//!
//! Both share the live `VaultHandle` via `Arc<Mutex<Option<VaultHandle>>>`.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sv_audit::{AuditAction, AuditDecision, AuditEvent, AuditLog};
use sv_core::sv_storage::{ContainerInfo, FileInfo, SecurityMode};
use sv_core::{BootstrapResult, CustodyMode, VaultHandle};
use tauri::async_runtime::{spawn, JoinHandle};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{oneshot, Mutex};

const RPC_PORT: u16 = 9944;
const APPROVAL_EVENT: &str = "vault://approval-request";
const APPROVAL_CANCEL_EVENT: &str = "vault://approval-cancel";
/// How long a pending approval stays open before auto-cancelling. Kept short so
/// a caller that disconnects (e.g. its own MCP client timed out) doesn't leave a
/// stale modal lingering on screen.
const APPROVAL_TIMEOUT_SECS: u64 = 120;

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

struct PendingApproval {
    tx: oneshot::Sender<bool>,
    otp_code: Option<String>,
    /// Identity of the request (action + target + agent). Used to dedupe a
    /// retry storm: an identical request supersedes the older pending one.
    signature: String,
}

/// Stable identity for an access request so retries collapse onto one modal.
fn request_signature(request: &sv_mcp::AccessRequest) -> String {
    format!(
        "{:?}|{:?}|{:?}|{:?}",
        request.action, request.container, request.file_name, request.agent_id
    )
}

#[derive(Clone, Serialize)]
struct ApprovalCancel {
    id: u64,
}

enum ApprovalPromptKind {
    NotRequired,
    Click,
    /// OTP-mode container: cross-channel challenge/response. The vault shows a
    /// code on the desktop; the agent must resend the request carrying it.
    Otp,
}

/// How long an issued OTP challenge stays valid for the resend.
const OTP_TTL_SECS: u64 = 120;

struct ApprovalState {
    app: AppHandle,
    next_id: AtomicU64,
    pending: Mutex<HashMap<u64, PendingApproval>>,
    /// Outstanding OTP challenges keyed by request signature →
    /// (code, modal_id, issued_at). The code is shown on the desktop; the agent
    /// resends the request with it. Single-use, TTL-bounded.
    otp_pending: Mutex<HashMap<String, (String, u64, Instant)>>,
}

impl ApprovalState {
    fn new(app: AppHandle) -> Self {
        Self {
            app,
            next_id: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
            otp_pending: Mutex::new(HashMap::new()),
        }
    }

    /// OTP cross-channel flow. First call (no/invalid code): issue a fresh code,
    /// show it on the desktop (display-only), and return `otp_required` so the
    /// agent prompts for it. Second call carrying the matching code: consume it
    /// and allow. The code is never accepted from the same channel that shows
    /// it — it binds the agent session to a human at the trusted desktop.
    async fn handle_otp(&self, request: &sv_mcp::AccessRequest) -> Result<(), String> {
        let key = request_signature(request);

        if let Some(supplied) = request.otp.as_deref() {
            let mut store = self.otp_pending.lock().await;
            if let Some((code, modal_id, issued)) = store.get(&key) {
                let fresh = issued.elapsed() < Duration::from_secs(OTP_TTL_SECS);
                if fresh && supplied == code.as_str() {
                    let modal_id = *modal_id;
                    store.remove(&key);
                    drop(store);
                    // Consumed — close the display modal on the desktop.
                    let _ = self
                        .app
                        .emit(APPROVAL_CANCEL_EVENT, ApprovalCancel { id: modal_id });
                    return Ok(());
                }
            }
            // Wrong or expired code → fall through and issue a fresh challenge.
        }

        // Issue a new challenge.
        let code = generate_otp_code()?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut store = self.otp_pending.lock().await;
            // Supersede any prior challenge for this signature (close its modal).
            if let Some((_, old_modal, _)) = store.remove(&key) {
                let _ = self
                    .app
                    .emit(APPROVAL_CANCEL_EVENT, ApprovalCancel { id: old_modal });
            }
            store.insert(key, (code.clone(), id, Instant::now()));
        }

        let payload = ApprovalPrompt {
            id,
            action: format!("{:?}", request.action),
            container: request.container.clone(),
            file_name: request.file_name.clone(),
            mode: request.mode.map(|m| m.as_str().to_string()),
            byte_size: request.byte_size,
            otp_code: Some(code),
        };
        self.app.emit(APPROVAL_EVENT, payload).map_err(estr)?;
        Err(
            "otp_required: a one-time code is shown on the Sovereign Vault desktop. \
             Resend this exact request with the `otp` argument set to that code."
                .into(),
        )
    }

    async fn request(&self, request: sv_mcp::AccessRequest) -> Result<(), String> {
        match approval_requirement(&request)? {
            ApprovalPromptKind::NotRequired => return Ok(()),
            ApprovalPromptKind::Click => {}
            ApprovalPromptKind::Otp => return self.handle_otp(&request).await,
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let signature = request_signature(&request);
        let (tx, rx) = oneshot::channel();
        let superseded: Vec<u64> = {
            let mut pending = self.pending.lock().await;
            // Supersede any outstanding request with the same signature: a
            // duplicate almost always means the previous caller disconnected
            // and retried, so the old modal is stale. Cancel it (deny the old
            // call) instead of stacking a second modal.
            let stale: Vec<u64> = pending
                .iter()
                .filter(|(_, p)| p.signature == signature)
                .map(|(k, _)| *k)
                .collect();
            for old in &stale {
                if let Some(prev) = pending.remove(old) {
                    let _ = prev.tx.send(false);
                }
            }
            pending.insert(
                id,
                PendingApproval {
                    tx,
                    otp_code: None,
                    signature,
                },
            );
            stale
        };
        for old in superseded {
            let _ = self
                .app
                .emit(APPROVAL_CANCEL_EVENT, ApprovalCancel { id: old });
        }

        let payload = ApprovalPrompt {
            id,
            action: format!("{:?}", request.action),
            container: request.container.clone(),
            file_name: request.file_name.clone(),
            mode: request.mode.map(|m| m.as_str().to_string()),
            byte_size: request.byte_size,
            otp_code: None,
        };
        self.app.emit(APPROVAL_EVENT, payload).map_err(estr)?;

        match tokio::time::timeout(Duration::from_secs(APPROVAL_TIMEOUT_SECS), rx).await {
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false)) => Err("access denied by user".into()),
            Ok(Err(_)) => Err("approval channel closed".into()),
            Err(_) => {
                let mut pending = self.pending.lock().await;
                pending.remove(&id);
                drop(pending);
                // Tell the UI to drop the now-defunct modal.
                let _ = self.app.emit(APPROVAL_CANCEL_EVENT, ApprovalCancel { id });
                Err("approval timed out".into())
            }
        }
    }

    async fn respond(&self, id: u64, approved: bool, otp: Option<String>) -> Result<(), String> {
        let mut pending = self.pending.lock().await;
        if approved {
            if let Some(existing) = pending.get(&id) {
                if let Some(expected) = &existing.otp_code {
                    if otp.as_deref() != Some(expected.as_str()) {
                        return Err("incorrect confirmation code".into());
                    }
                }
            }
        }

        let Some(pending_request) = pending.remove(&id) else {
            return Err(format!("unknown approval request: {id}"));
        };
        pending_request
            .tx
            .send(approved)
            .map_err(|_| "approval request already closed".to_string())
    }
}

/// In-memory vault state held inside Tauri's managed state.
struct VaultState {
    app: AppHandle,
    handle: SharedHandle,
    approvals: Arc<ApprovalState>,
    servers: Mutex<Option<ServersShutdown>>,
}

impl VaultState {
    fn new(app: AppHandle) -> Self {
        let approvals = Arc::new(ApprovalState::new(app.clone()));
        Self {
            app,
            handle: Arc::new(Mutex::new(None)),
            approvals,
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
    has_recovery_bundle: bool,
    has_keyring: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultInitResponse {
    recovery_phrase: String,
}

/// MCP integration status returned by [`mcp_status`].
#[derive(Debug, Serialize, Deserialize)]
struct McpStatus {
    running: bool,
    pairing_secret: Option<String>,
    ws_url: String,
    http_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApprovalPrompt {
    id: u64,
    action: String,
    container: Option<String>,
    file_name: Option<String>,
    mode: Option<String>,
    byte_size: Option<usize>,
    otp_code: Option<String>,
}

struct DesktopAuditSink {
    root: PathBuf,
    hmac_key: [u8; 32],
}

impl DesktopAuditSink {
    fn new(root: PathBuf, hmac_key: [u8; 32]) -> Self {
        Self { root, hmac_key }
    }
}

impl sv_mcp::AuditSink for DesktopAuditSink {
    fn record(&self, event: AuditEvent) -> Result<(), String> {
        AuditLog::with_hmac_key(&self.root, self.hmac_key)
            .record(&event)
            .map_err(estr)
    }
}

struct DesktopAgentAuthenticator {
    root: PathBuf,
    token_key: [u8; 32],
    shared_secret: String,
}

fn parse_access_action(s: &str) -> Option<sv_mcp::AccessAction> {
    match s {
        "list" | "list_containers" => Some(sv_mcp::AccessAction::ListContainers),
        "list_files" => Some(sv_mcp::AccessAction::ListFiles),
        "read" | "read_file" => Some(sv_mcp::AccessAction::ReadFile),
        "write" | "write_file" => Some(sv_mcp::AccessAction::WriteFile),
        "delete" | "delete_file" => Some(sv_mcp::AccessAction::DeleteFile),
        "create_container" => Some(sv_mcp::AccessAction::CreateContainer),
        "encrypt" => Some(sv_mcp::AccessAction::Encrypt),
        "decrypt" => Some(sv_mcp::AccessAction::Decrypt),
        "sign" => Some(sv_mcp::AccessAction::Sign),
        "verify" => Some(sv_mcp::AccessAction::Verify),
        "broker" | "broker_request" => Some(sv_mcp::AccessAction::Broker),
        _ => None,
    }
}

fn resolve_scopes(scopes: &[sv_core::agents::AgentScope]) -> Vec<sv_mcp::ResolvedScope> {
    scopes
        .iter()
        .map(|s| sv_mcp::ResolvedScope {
            container_glob: s.container_glob.clone(),
            actions: s
                .actions
                .iter()
                .filter_map(|a| parse_access_action(a))
                .collect(),
            mode_ceiling: s
                .mode_ceiling
                .as_deref()
                .and_then(|m| SecurityMode::parse(m).ok()),
        })
        .collect()
}

impl sv_mcp::AgentAuthenticator for DesktopAgentAuthenticator {
    fn authenticate(
        &self,
        agent_id: Option<&str>,
        token: &str,
    ) -> Result<sv_mcp::ResolvedAgent, String> {
        // Legacy fallback: a bare shared secret resolves to the Default agent.
        let agent_id = match agent_id {
            Some(id) => id.to_string(),
            None => {
                if token != self.shared_secret {
                    return Err("invalid shared secret".into());
                }
                sv_core::agents::list_agents(&self.root)
                    .map_err(estr)?
                    .into_iter()
                    .find(|a| a.name == sv_core::agents::DEFAULT_AGENT_NAME && !a.revoked)
                    .map(|a| a.agent_id)
                    .ok_or_else(|| "no default agent".to_string())?
            }
        };
        let record = sv_core::agents::authenticate(&self.root, &self.token_key, &agent_id, token)
            .map_err(estr)?;
        Ok(sv_mcp::ResolvedAgent {
            agent_id: record.agent_id,
            scopes: resolve_scopes(&record.scopes),
        })
    }
}

struct DesktopAccessController {
    approvals: Arc<ApprovalState>,
}

#[async_trait]
impl sv_mcp::AccessController for DesktopAccessController {
    async fn authorize(&self, request: sv_mcp::AccessRequest) -> Result<(), String> {
        self.approvals.request(request).await
    }
}

fn estr<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn parse_custody(s: &str) -> Result<CustodyMode, String> {
    match s.to_ascii_uppercase().as_str() {
        "OSKEYCHAIN" | "OS_KEYCHAIN" | "KEYCHAIN" => Ok(CustodyMode::OsKeychain),
        "PASSPHRASE" => Ok(CustodyMode::Passphrase),
        "RECOVERY" => Ok(CustodyMode::Recovery),
        other => Err(format!("unknown custody mode: {other}")),
    }
}

fn vault_root(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(estr)?;
    Ok(dir.join("sovereign-vault"))
}

fn audit_root(state: &VaultState) -> Result<PathBuf, String> {
    vault_root(&state.app)
}

fn desktop_event(
    action: AuditAction,
    decision: AuditDecision,
    container: Option<String>,
    file_name: Option<String>,
    mode: Option<SecurityMode>,
    byte_size: Option<usize>,
    error: Option<String>,
) -> AuditEvent {
    let mut event = AuditEvent::new(action, decision, "desktop-ui");
    event.container = container;
    event.file_name = file_name;
    event.mode = mode.map(|m| m.as_str().to_string());
    event.byte_size = byte_size;
    event.error = error;
    event
}

fn record_desktop_event(state: &VaultState, event: AuditEvent) {
    let Ok(root) = audit_root(state) else {
        return;
    };
    let _ = AuditLog::new(&root).record(&event);
}

fn approval_requirement(request: &sv_mcp::AccessRequest) -> Result<ApprovalPromptKind, String> {
    // Broker is the highest-risk action and ALWAYS requires approval, never
    // DIRECT, regardless of any (absent) container mode.
    if matches!(request.action, sv_mcp::AccessAction::Broker) {
        return Ok(ApprovalPromptKind::Click);
    }
    // Transit + signing carry no container mode; gate them on a click, except
    // verify (public-key only, no secret material involved).
    match request.action {
        sv_mcp::AccessAction::Encrypt
        | sv_mcp::AccessAction::Decrypt
        | sv_mcp::AccessAction::Sign => return Ok(ApprovalPromptKind::Click),
        sv_mcp::AccessAction::Verify => return Ok(ApprovalPromptKind::NotRequired),
        _ => {}
    }
    match request.mode {
        Some(SecurityMode::Direct) | None => match request.action {
            sv_mcp::AccessAction::ListContainers | sv_mcp::AccessAction::CreateContainer => {
                Ok(ApprovalPromptKind::Click)
            }
            _ => Ok(ApprovalPromptKind::NotRequired),
        },
        Some(SecurityMode::Approval) => Ok(ApprovalPromptKind::Click),
        Some(SecurityMode::Otp) => Ok(ApprovalPromptKind::Otp),
        Some(SecurityMode::Anonymized) => {
            Err("ANONYMIZED mode is not implemented for live MCP access".into())
        }
        Some(SecurityMode::Zkp) => Err("ZKP mode is not implemented for live MCP access".into()),
        Some(SecurityMode::Native) => {
            Err("NATIVE mode is not implemented for live MCP access".into())
        }
    }
}

fn generate_otp_code() -> Result<String, String> {
    let bytes = sv_core::sv_crypto::random_bytes(4).map_err(estr)?;
    let n = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) % 1_000_000;
    Ok(format!("{n:06}"))
}

async fn with_handle<R, F>(state: &State<'_, VaultState>, f: F) -> Result<R, String>
where
    F: FnOnce(&VaultHandle) -> Result<R, String>,
{
    let guard = state.handle.lock().await;
    let handle = guard
        .as_ref()
        .ok_or_else(|| "vault is locked".to_string())?;
    f(handle)
}

async fn container_mode(state: &State<'_, VaultState>, container: &str) -> Option<SecurityMode> {
    with_handle(state, |handle| {
        handle.container_mode(container).map_err(estr)
    })
    .await
    .ok()
}

#[tauri::command]
fn app_version() -> String {
    sv_core::version().to_string()
}

#[tauri::command]
async fn vault_status(app: AppHandle, state: State<'_, VaultState>) -> Result<VaultStatus, String> {
    let root = vault_root(&app)?;
    let probe = sv_core::probe(&root).map_err(estr)?;
    let guard = state.handle.lock().await;
    let custody = guard.as_ref().map(|handle| match handle.custody() {
        CustodyMode::OsKeychain => "OsKeychain".to_string(),
        CustodyMode::Passphrase => "Passphrase".to_string(),
        CustodyMode::Recovery => "Recovery".to_string(),
    });
    Ok(VaultStatus {
        initialized: probe.initialized,
        unlocked: guard.is_some(),
        custody,
        has_keychain_entry: probe.has_keychain_entry,
        has_passphrase_salt: probe.has_passphrase_salt,
        has_recovery_bundle: probe.has_recovery_bundle,
        has_keyring: probe.has_keyring,
    })
}

#[tauri::command]
async fn vault_init(
    app: AppHandle,
    state: State<'_, VaultState>,
    custody: String,
    passphrase: Option<String>,
) -> Result<VaultInitResponse, String> {
    let mode = parse_custody(&custody)?;
    let root = vault_root(&app)?;
    let probe = sv_core::probe(&root).map_err(estr)?;
    if probe.initialized {
        return Err("vault already initialised".into());
    }

    let BootstrapResult {
        handle,
        recovery_phrase,
    } = match VaultHandle::bootstrap(&root, mode, passphrase.as_deref()) {
        Ok(result) => result,
        Err(error) => {
            record_desktop_event(
                &state,
                desktop_event(
                    AuditAction::VaultInit,
                    AuditDecision::Error,
                    None,
                    None,
                    None,
                    None,
                    Some(error.to_string()),
                ),
            );
            return Err(error.to_string());
        }
    };

    {
        let mut guard = state.handle.lock().await;
        *guard = Some(handle);
    }

    if let Err(error) = start_servers(&state).await {
        let mut guard = state.handle.lock().await;
        *guard = None;
        record_desktop_event(
            &state,
            desktop_event(
                AuditAction::VaultInit,
                AuditDecision::Error,
                None,
                None,
                None,
                None,
                Some(error.clone()),
            ),
        );
        return Err(error);
    }

    record_desktop_event(
        &state,
        desktop_event(
            AuditAction::VaultInit,
            AuditDecision::Allowed,
            None,
            None,
            None,
            None,
            None,
        ),
    );
    record_desktop_event(
        &state,
        desktop_event(
            AuditAction::RecoveryIssued,
            AuditDecision::Allowed,
            None,
            None,
            None,
            None,
            None,
        ),
    );
    Ok(VaultInitResponse { recovery_phrase })
}

#[tauri::command]
async fn vault_unlock(
    app: AppHandle,
    state: State<'_, VaultState>,
    custody: String,
    passphrase: Option<String>,
) -> Result<(), String> {
    let mode = parse_custody(&custody)?;
    let root = vault_root(&app)?;
    let handle = match VaultHandle::unlock(&root, mode, passphrase.as_deref()) {
        Ok(handle) => handle,
        Err(error) => {
            record_desktop_event(
                &state,
                desktop_event(
                    AuditAction::VaultUnlock,
                    AuditDecision::Error,
                    None,
                    None,
                    None,
                    None,
                    Some(error.to_string()),
                ),
            );
            return Err(error.to_string());
        }
    };
    {
        let mut guard = state.handle.lock().await;
        *guard = Some(handle);
    }
    if let Err(error) = start_servers(&state).await {
        let mut guard = state.handle.lock().await;
        *guard = None;
        record_desktop_event(
            &state,
            desktop_event(
                AuditAction::VaultUnlock,
                AuditDecision::Error,
                None,
                None,
                None,
                None,
                Some(error.clone()),
            ),
        );
        return Err(error);
    }
    record_desktop_event(
        &state,
        desktop_event(
            AuditAction::VaultUnlock,
            AuditDecision::Allowed,
            None,
            None,
            None,
            None,
            None,
        ),
    );
    Ok(())
}

#[tauri::command]
async fn vault_unlock_recovery(
    app: AppHandle,
    state: State<'_, VaultState>,
    phrase: String,
) -> Result<(), String> {
    let root = vault_root(&app)?;
    let handle = match VaultHandle::unlock_with_recovery(&root, &phrase) {
        Ok(handle) => handle,
        Err(error) => {
            record_desktop_event(
                &state,
                desktop_event(
                    AuditAction::VaultUnlockRecovery,
                    AuditDecision::Error,
                    None,
                    None,
                    None,
                    None,
                    Some(error.to_string()),
                ),
            );
            return Err(error.to_string());
        }
    };
    {
        let mut guard = state.handle.lock().await;
        *guard = Some(handle);
    }
    if let Err(error) = start_servers(&state).await {
        let mut guard = state.handle.lock().await;
        *guard = None;
        record_desktop_event(
            &state,
            desktop_event(
                AuditAction::VaultUnlockRecovery,
                AuditDecision::Error,
                None,
                None,
                None,
                None,
                Some(error.clone()),
            ),
        );
        return Err(error);
    }
    record_desktop_event(
        &state,
        desktop_event(
            AuditAction::VaultUnlockRecovery,
            AuditDecision::Allowed,
            None,
            None,
            None,
            None,
            None,
        ),
    );
    Ok(())
}

#[tauri::command]
async fn vault_lock(state: State<'_, VaultState>) -> Result<(), String> {
    stop_servers(&state).await;
    let mut guard = state.handle.lock().await;
    *guard = None;
    record_desktop_event(
        &state,
        desktop_event(
            AuditAction::VaultLock,
            AuditDecision::Allowed,
            None,
            None,
            None,
            None,
            None,
        ),
    );
    Ok(())
}

#[tauri::command]
async fn vault_change_passphrase(
    app: AppHandle,
    state: State<'_, VaultState>,
    current: String,
    new: String,
) -> Result<(), String> {
    let root = vault_root(&app)?;
    let result = with_handle(&state, |handle| {
        handle
            .change_passphrase(&root, &current, &new)
            .map_err(estr)
    })
    .await;
    record_desktop_event(
        &state,
        desktop_event(
            AuditAction::PassphraseChanged,
            if result.is_ok() {
                AuditDecision::Allowed
            } else {
                AuditDecision::Error
            },
            None,
            None,
            None,
            None,
            result.as_ref().err().cloned(),
        ),
    );
    result
}

#[tauri::command]
async fn vault_rotate_key(
    app: AppHandle,
    state: State<'_, VaultState>,
    passphrase: Option<String>,
) -> Result<VaultInitResponse, String> {
    let root = vault_root(&app)?;
    let result = {
        let mut guard = state.handle.lock().await;
        match guard.as_mut() {
            Some(handle) => handle
                .rotate_key(&root, passphrase.as_deref())
                .map_err(estr),
            None => Err("vault is locked".to_string()),
        }
    };
    record_desktop_event(
        &state,
        desktop_event(
            AuditAction::KeyRotated,
            if result.is_ok() {
                AuditDecision::Allowed
            } else {
                AuditDecision::Error
            },
            None,
            None,
            None,
            None,
            result.as_ref().err().cloned(),
        ),
    );
    result.map(|recovery_phrase| VaultInitResponse { recovery_phrase })
}

#[tauri::command]
async fn vault_list_containers(state: State<'_, VaultState>) -> Result<Vec<ContainerInfo>, String> {
    let result = with_handle(&state, |handle| handle.list_containers().map_err(estr)).await;
    match &result {
        Ok(_) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::ListContainers,
                AuditDecision::Allowed,
                None,
                None,
                None,
                None,
                None,
            ),
        ),
        Err(error) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::ListContainers,
                AuditDecision::Error,
                None,
                None,
                None,
                None,
                Some(error.clone()),
            ),
        ),
    }
    result
}

#[tauri::command]
async fn vault_create_container(
    state: State<'_, VaultState>,
    name: String,
    mode: String,
    description: Option<String>,
) -> Result<(), String> {
    let parsed_mode = SecurityMode::parse(&mode).map_err(estr)?;
    let result = with_handle(&state, |handle| {
        handle
            .create_container(&name, parsed_mode, description.clone())
            .map_err(estr)
    })
    .await;
    match &result {
        Ok(_) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::CreateContainer,
                AuditDecision::Allowed,
                Some(name.clone()),
                None,
                Some(parsed_mode),
                None,
                None,
            ),
        ),
        Err(error) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::CreateContainer,
                AuditDecision::Error,
                Some(name),
                None,
                Some(parsed_mode),
                None,
                Some(error.clone()),
            ),
        ),
    }
    result
}

#[tauri::command]
async fn vault_delete_container(state: State<'_, VaultState>, name: String) -> Result<(), String> {
    let mode = container_mode(&state, &name).await;
    let result = with_handle(&state, |handle| {
        handle.delete_container(&name).map_err(estr)
    })
    .await;
    match &result {
        Ok(_) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::DeleteContainer,
                AuditDecision::Allowed,
                Some(name.clone()),
                None,
                mode,
                None,
                None,
            ),
        ),
        Err(error) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::DeleteContainer,
                AuditDecision::Error,
                Some(name),
                None,
                mode,
                None,
                Some(error.clone()),
            ),
        ),
    }
    result
}

#[tauri::command]
async fn vault_list_files(
    state: State<'_, VaultState>,
    container: String,
) -> Result<Vec<FileInfo>, String> {
    let mode = container_mode(&state, &container).await;
    let result = with_handle(&state, |handle| handle.list_files(&container).map_err(estr)).await;
    match &result {
        Ok(_) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::ListFiles,
                AuditDecision::Allowed,
                Some(container.clone()),
                None,
                mode,
                None,
                None,
            ),
        ),
        Err(error) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::ListFiles,
                AuditDecision::Error,
                Some(container),
                None,
                mode,
                None,
                Some(error.clone()),
            ),
        ),
    }
    result
}

#[tauri::command]
async fn vault_write_file(
    state: State<'_, VaultState>,
    container: String,
    file_name: String,
    content: Vec<u8>,
) -> Result<(), String> {
    let mode = container_mode(&state, &container).await;
    let byte_size = content.len();
    let result = with_handle(&state, |handle| {
        handle
            .write_file(&container, &file_name, &content)
            .map_err(estr)
    })
    .await;
    match &result {
        Ok(_) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::WriteFile,
                AuditDecision::Allowed,
                Some(container.clone()),
                Some(file_name.clone()),
                mode,
                Some(byte_size),
                None,
            ),
        ),
        Err(error) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::WriteFile,
                AuditDecision::Error,
                Some(container),
                Some(file_name),
                mode,
                Some(byte_size),
                Some(error.clone()),
            ),
        ),
    }
    result
}

#[tauri::command]
async fn vault_read_file(
    state: State<'_, VaultState>,
    container: String,
    file_name: String,
) -> Result<Vec<u8>, String> {
    let mode = container_mode(&state, &container).await;
    let result = with_handle(&state, |handle| {
        handle.read_file(&container, &file_name).map_err(estr)
    })
    .await;
    match &result {
        Ok(bytes) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::ReadFile,
                AuditDecision::Allowed,
                Some(container.clone()),
                Some(file_name.clone()),
                mode,
                Some(bytes.len()),
                None,
            ),
        ),
        Err(error) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::ReadFile,
                AuditDecision::Error,
                Some(container),
                Some(file_name),
                mode,
                None,
                Some(error.clone()),
            ),
        ),
    }
    result
}

#[tauri::command]
async fn vault_delete_file(
    state: State<'_, VaultState>,
    container: String,
    file_name: String,
) -> Result<(), String> {
    let mode = container_mode(&state, &container).await;
    let result = with_handle(&state, |handle| {
        handle.delete_file(&container, &file_name).map_err(estr)
    })
    .await;
    match &result {
        Ok(_) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::DeleteFile,
                AuditDecision::Allowed,
                Some(container.clone()),
                Some(file_name.clone()),
                mode,
                None,
                None,
            ),
        ),
        Err(error) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::DeleteFile,
                AuditDecision::Error,
                Some(container),
                Some(file_name),
                mode,
                None,
                Some(error.clone()),
            ),
        ),
    }
    result
}

#[tauri::command]
async fn approval_respond(
    state: State<'_, VaultState>,
    id: u64,
    approved: bool,
    otp: Option<String>,
) -> Result<(), String> {
    state.approvals.respond(id, approved, otp).await
}

#[tauri::command]
async fn mcp_status(state: State<'_, VaultState>) -> Result<McpStatus, String> {
    let guard = state.servers.lock().await;
    let (running, pairing_secret) = match guard.as_ref() {
        Some(server) if server.running => (true, Some(server.pairing_secret.clone())),
        _ => (false, None),
    };
    Ok(McpStatus {
        running,
        pairing_secret,
        ws_url: format!("ws://127.0.0.1:{RPC_PORT}"),
        http_url: format!("http://127.0.0.1:{}", RPC_PORT - 1),
    })
}

/// One agent as surfaced to the UI (never includes the token).
#[derive(Debug, Serialize, Deserialize)]
struct AgentInfo {
    agent_id: String,
    name: String,
    created_at: String,
    expires_at: Option<String>,
    revoked: bool,
    scopes: Vec<sv_core::agents::AgentScope>,
}

/// Response for [`agent_create`]: the one-time token is shown exactly once.
#[derive(Debug, Serialize, Deserialize)]
struct AgentCreated {
    agent_id: String,
    token: String,
}

#[tauri::command]
async fn agent_create(
    app: AppHandle,
    state: State<'_, VaultState>,
    name: String,
    scopes: Option<Vec<sv_core::agents::AgentScope>>,
) -> Result<AgentCreated, String> {
    let _ = &app;
    let (agent_id, token) = with_handle(&state, |handle| {
        handle
            .create_agent(&name, scopes.unwrap_or_default())
            .map_err(estr)
    })
    .await?;
    Ok(AgentCreated { agent_id, token })
}

#[tauri::command]
async fn agent_list(state: State<'_, VaultState>) -> Result<Vec<AgentInfo>, String> {
    let agents = with_handle(&state, |handle| handle.list_agents().map_err(estr)).await?;
    Ok(agents
        .into_iter()
        .map(|a| AgentInfo {
            agent_id: a.agent_id,
            name: a.name,
            created_at: a.created_at.to_rfc3339(),
            expires_at: a.expires_at.map(|t| t.to_rfc3339()),
            revoked: a.revoked,
            scopes: a.scopes,
        })
        .collect())
}

#[tauri::command]
async fn agent_revoke(state: State<'_, VaultState>, agent_id: String) -> Result<(), String> {
    with_handle(&state, |handle| {
        handle.revoke_agent(&agent_id).map_err(estr)
    })
    .await
}

#[tauri::command]
async fn transit_create_key(
    state: State<'_, VaultState>,
    name: String,
) -> Result<sv_core::transit::TransitKeyInfo, String> {
    with_handle(&state, |handle| {
        handle.transit_create_key(&name).map_err(estr)
    })
    .await
}

#[tauri::command]
async fn transit_list_keys(
    state: State<'_, VaultState>,
) -> Result<Vec<sv_core::transit::TransitKeyInfo>, String> {
    with_handle(&state, |handle| handle.transit_list().map_err(estr)).await
}

#[tauri::command]
async fn signing_create_key(
    state: State<'_, VaultState>,
    name: String,
) -> Result<sv_core::transit::SigningKeyInfo, String> {
    with_handle(&state, |handle| {
        handle.signing_create_key(&name).map_err(estr)
    })
    .await
}

#[tauri::command]
async fn signing_list_keys(
    state: State<'_, VaultState>,
) -> Result<Vec<sv_core::transit::SigningKeyInfo>, String> {
    with_handle(&state, |handle| handle.signing_list().map_err(estr)).await
}

#[tauri::command]
async fn broker_create_secret(
    state: State<'_, VaultState>,
    name: String,
    secret: String,
    allow: Vec<sv_core::transit::BrokerAllow>,
    injection: Option<sv_core::transit::BrokerInjection>,
) -> Result<sv_core::transit::BrokerSecretInfo, String> {
    with_handle(&state, |handle| {
        handle
            .broker_create(&name, &secret, allow, injection.unwrap_or_default())
            .map_err(estr)
    })
    .await
}

#[tauri::command]
async fn broker_list_secrets(
    state: State<'_, VaultState>,
) -> Result<Vec<sv_core::transit::BrokerSecretInfo>, String> {
    with_handle(&state, |handle| handle.broker_list().map_err(estr)).await
}

#[tauri::command]
fn broker_enabled() -> bool {
    sv_core::broker::is_enabled()
}

#[tauri::command]
fn cli_binary_path() -> Result<String, String> {
    let me = std::env::current_exe().map_err(estr)?;
    let dir = me.parent().ok_or_else(|| "no parent dir".to_string())?;
    let exe_suffix = if cfg!(windows) { ".exe" } else { "" };
    let candidate = dir.join(format!("sovereign-vault{exe_suffix}"));
    if candidate.exists() {
        Ok(candidate.to_string_lossy().to_string())
    } else {
        Err(format!(
            "sovereign-vault binary not found next to {}",
            me.display()
        ))
    }
}

async fn start_servers(state: &State<'_, VaultState>) -> Result<(), String> {
    stop_servers(state).await;

    let secret = sv_core::fresh_pairing_secret().map_err(estr)?;
    let ws_addr: SocketAddr = format!("127.0.0.1:{RPC_PORT}").parse().map_err(estr)?;
    let http_addr: SocketAddr = format!("127.0.0.1:{}", RPC_PORT - 1)
        .parse()
        .map_err(estr)?;
    let ws_listener = tokio::net::TcpListener::bind(ws_addr).await.map_err(estr)?;
    let http_listener = tokio::net::TcpListener::bind(http_addr)
        .await
        .map_err(estr)?;

    let audit_root = audit_root(state)?;
    let vault_dir = vault_root(&state.app)?;
    let (audit_hmac_key, agent_token_key) = {
        let guard = state.handle.lock().await;
        let handle = guard
            .as_ref()
            .ok_or_else(|| "vault is locked".to_string())?;
        (handle.audit_hmac_key(), handle.agent_token_key())
    };

    // Migration: ensure a "Default" agent wraps the current shared secret so
    // existing pairing keeps working. Idempotent.
    sv_core::agents::ensure_default_agent(&vault_dir, &agent_token_key, &secret).map_err(estr)?;

    let controller = Arc::new(DesktopAccessController {
        approvals: state.approvals.clone(),
    });
    let sink = Arc::new(DesktopAuditSink::new(audit_root, audit_hmac_key));
    let authenticator = Arc::new(DesktopAgentAuthenticator {
        root: vault_dir,
        token_key: agent_token_key,
        shared_secret: secret.clone(),
    });

    let (ws_tx, ws_rx) = oneshot::channel::<()>();
    let ws_server = Arc::new(
        sv_mcp::McpServer::new(
            state.handle.clone() as sv_mcp::SharedVault<VaultHandle>,
            secret.clone(),
        )
        .with_access_controller(controller)
        .with_audit_sink(sink)
        .with_agent_authenticator(authenticator),
    );
    let ws_task = spawn(async move {
        if let Err(error) = ws_server.serve_ws_listener(ws_listener, ws_rx).await {
            eprintln!("[mcp] WS server stopped: {error}");
        }
    });

    let (http_tx, http_rx) = oneshot::channel::<()>();
    let http_secret = secret.clone();
    let http_task = spawn(async move {
        let server = sv_http::HttpServer::new(http_secret);
        if let Err(error) = server.serve_listener(http_listener, http_rx).await {
            eprintln!("[http] server stopped: {error}");
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
    Ok(())
}

async fn stop_servers(state: &State<'_, VaultState>) {
    let mut guard = state.servers.lock().await;
    if let Some(mut servers) = guard.take() {
        if let Some(tx) = servers.ws_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = servers.http_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = servers.ws_task.take() {
            let _ = task.await;
        }
        if let Some(task) = servers.http_task.take() {
            let _ = task.await;
        }
    }
}

/// Build and run the Tauri application.
pub fn run() {
    tauri::Builder::default()
        // Must be registered FIRST. A second launch focuses the existing
        // window instead of spawning another instance bound to the same vault.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            app.manage(VaultState::new(app.handle().clone()));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_version,
            vault_status,
            vault_init,
            vault_unlock,
            vault_unlock_recovery,
            vault_lock,
            vault_change_passphrase,
            vault_rotate_key,
            vault_list_containers,
            vault_create_container,
            vault_delete_container,
            vault_list_files,
            vault_write_file,
            vault_read_file,
            vault_delete_file,
            approval_respond,
            mcp_status,
            agent_create,
            agent_list,
            agent_revoke,
            transit_create_key,
            transit_list_keys,
            signing_create_key,
            signing_list_keys,
            broker_create_secret,
            broker_list_secrets,
            broker_enabled,
            cli_binary_path,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Sovereign Vault");
}
