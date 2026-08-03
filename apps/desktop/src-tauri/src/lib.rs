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
use subtle::ConstantTimeEq;

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
    /// Identity of the request (action + target + agent + content digest).
    /// Used to dedupe a retry storm: only an identical request supersedes the
    /// older pending one.
    signature: String,
}

/// Stable identity for an access request so retries collapse onto one modal.
fn request_signature(request: &sv_mcp::AccessRequest) -> String {
    format!(
        "{:?}|{:?}|{:?}|{:?}|{}",
        request.action,
        request.container,
        request.file_name,
        request.agent_id,
        request.authorization_context
    )
}

/// Compare a pending approval identity with a request. The authorization
/// context is part of both values, so a changed MCP argument envelope cannot
/// collapse onto (and inherit approval from) an earlier pending request.
fn matches_pending_approval(signature: &str, request: &sv_mcp::AccessRequest) -> bool {
    signature == request_signature(request)
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

/// Maximum number of wrong OTP attempts before lockout.
const OTP_MAX_ATTEMPTS: u8 = 5;

/// Lockout duration after exceeding max attempts.
const OTP_LOCKOUT_SECS: u64 = 300; // 5 minutes

/// Maximum number of concurrent pending OTP challenges. Prevents unbounded
/// memory growth from a flood of unique request signatures.
const OTP_MAX_PENDING: usize = 1024;

/// Production OTP challenge state with rate limiting.
#[derive(Clone)]
struct OtpChallenge {
    /// The OTP code (never logged).
    code: String,
    /// Modal ID shown on the desktop.
    modal_id: u64,
    /// When the challenge was issued.
    issued_at: Instant,
    /// Number of failed validation attempts.
    failed_attempts: u8,
    /// If locked out, the time until which requests are denied.
    lockout_until: Option<Instant>,
}

impl OtpChallenge {
    fn new(code: String, modal_id: u64) -> Self {
        Self {
            code,
            modal_id,
            issued_at: Instant::now(),
            failed_attempts: 0,
            lockout_until: None,
        }
    }

    /// Check if the challenge is expired (TTL exceeded).
    fn is_expired(&self) -> bool {
        self.issued_at.elapsed() > Duration::from_secs(OTP_TTL_SECS)
    }

    /// Check if the challenge is currently locked out.
    fn is_locked_out(&self) -> bool {
        self.lockout_until
            .map(|until| Instant::now() < until)
            .unwrap_or(false)
    }

    /// Record a failed attempt. Returns true if this triggers lockout.
    fn record_failure(&mut self) -> bool {
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        if self.failed_attempts >= OTP_MAX_ATTEMPTS {
            self.lockout_until = Some(Instant::now() + Duration::from_secs(OTP_LOCKOUT_SECS));
            true
        } else {
            false
        }
    }

    /// Validate an OTP code with constant-time comparison.
    fn validate(&self, supplied: &str) -> bool {
        if self.is_expired() || self.is_locked_out() {
            return false;
        }
        supplied.as_bytes().ct_eq(self.code.as_bytes()).into()
    }
}

/// Result of processing an OTP request.
enum OtpProcessResult {
    /// Challenge accepted; modal should be cancelled.
    Accepted { modal_id: u64 },
    /// Challenge required; caller should issue a fresh one via handle_otp_fresh.
    NeedFresh,
    /// Request denied due to lockout.
    LockedOut,
    /// Invalid code; challenge remains active.
    Invalid,
    /// Challenge expired; caller should issue a fresh one via handle_otp_fresh.
    Expired,
}

/// Process an OTP request against existing or new challenge state.
/// This is the pure state transition logic, testable without Tauri dependencies.
/// Does NOT generate new codes - returns NeedFresh/Expired when no challenge exists.
fn process_otp_request(
    challenge: Option<&mut OtpChallenge>,
    supplied_otp: Option<&str>,
) -> (OtpProcessResult, Option<OtpChallenge>) {
    // Case 1: Supplied OTP for validation
    if let Some(supplied) = supplied_otp {
        if let Some(chal) = challenge {
            // Check lockout first - denies even if code would match
            if chal.is_locked_out() {
                return (OtpProcessResult::LockedOut, Some(chal.clone()));
            }

            // Check expiry
            if chal.is_expired() {
                return (OtpProcessResult::Expired, None);
            }

            // Validate
            if chal.validate(supplied) {
                let modal_id = chal.modal_id;
                return (OtpProcessResult::Accepted { modal_id }, None);
            } else {
                // Record failure
                let _triggers_lockout = chal.record_failure();
                let updated = chal.clone();
                return (OtpProcessResult::Invalid, Some(updated));
            }
        } else {
            // No challenge exists for this signature - treat as expired/needs fresh
            return (OtpProcessResult::Expired, None);
        }
    }

    // Case 2: No-code request (initial or retry without OTP)
    if let Some(chal) = challenge {
        // Check lockout - no-code requests cannot bypass lockout
        if chal.is_locked_out() {
            return (OtpProcessResult::LockedOut, Some(chal.clone()));
        }

        // Check expiry
        if chal.is_expired() {
            return (OtpProcessResult::Expired, None);
        }

        // Reuse existing challenge - do NOT emit new modal
        return (OtpProcessResult::NeedFresh, Some(chal.clone()));
    }

    // Case 3: No existing challenge - signal need for fresh challenge
    (OtpProcessResult::NeedFresh, None)
}

/// Check whether a new OTP challenge can be admitted given the current store.
///
/// Existing signatures are always admissible (still processable) regardless of
/// store size. A **new** signature is denied when the store has reached
/// [`OTP_MAX_PENDING`], bounding memory usage against a flood of unique
/// request signatures.
///
/// This is a pure helper with no Tauri dependency, so it can be unit-tested in
/// isolation.
fn can_admit_challenge(store: &HashMap<String, OtpChallenge>, key: &str) -> bool {
    if store.contains_key(key) {
        return true;
    }
    store.len() < OTP_MAX_PENDING
}

/// Generate a 6-digit OTP code using cryptographically secure random bytes.
/// Fallible - no zero/predictable fallback.
fn generate_otp_code() -> Result<String, String> {
    let bytes = sv_core::sv_crypto::random_bytes(4).map_err(estr)?;
    let n = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) % 1_000_000;
    Ok(format!("{n:06}"))
}

struct ApprovalState {
    app: AppHandle,
    next_id: AtomicU64,
    pending: Mutex<HashMap<u64, PendingApproval>>,
    /// Outstanding OTP challenges keyed by request signature.
    /// Includes rate limiting state (failed attempts, lockout).
    otp_pending: Mutex<HashMap<String, OtpChallenge>>,
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

    /// Prune expired challenges and expired lockouts.
    fn prune_expired(&self, store: &mut HashMap<String, OtpChallenge>) {
        let now = Instant::now();
        store.retain(|_, chal| {
            // Keep if not expired OR if locked out but lockout hasn't expired
            !chal.is_expired() || chal.lockout_until.map(|until| now < until).unwrap_or(false)
        });
    }

    /// OTP cross-channel flow with production rate limiting.
    ///
    /// First call (no/invalid code): issue a fresh code, show it on the desktop
    /// (display-only), and return `otp_required` so the agent prompts for it.
    /// Subsequent no-code requests for the same signature reuse the current
    /// challenge without emitting a new modal.
    ///
    /// Wrong OTP increments attempt counter; after 5 failures, lock out for 5
    /// minutes and cancel the modal. Lockout cannot be bypassed by no-code requests.
    ///
    /// The pending challenge map is TTL-pruned and size-capped at
    /// [`OTP_MAX_PENDING`]; a **new** request signature is denied with the
    /// generic `otp_required` error when the cap is reached, while existing
    /// signatures remain fully processable.
    async fn handle_otp(&self, request: &sv_mcp::AccessRequest) -> Result<(), String> {
        let key = request_signature(request);
        let supplied = request.otp.as_deref();

        let mut store = self.otp_pending.lock().await;

        // Prune expired entries before processing
        self.prune_expired(&mut store);

        // Enforce size cap: deny new signatures when the map is full.
        // Existing signatures remain processable regardless of cap.
        if !can_admit_challenge(&store, &key) {
            drop(store);
            return Err(
                "otp_required: a one-time code is shown on the Sovereign Vault desktop. \
                 Resend this exact request with the `otp` argument set to that code."
                    .into(),
            );
        }

        // Get the existing challenge's modal_id before mutation (for reuse detection)
        let existing_modal_id = store.get(&key).map(|c| c.modal_id);

        // Process the request through pure state transition logic
        let existing = store.get_mut(&key);
        let (result, new_challenge) = process_otp_request(existing, supplied);

        match result {
            OtpProcessResult::Accepted { modal_id } => {
                // Valid OTP - remove challenge and cancel modal
                store.remove(&key);
                drop(store);
                let _ = self
                    .app
                    .emit(APPROVAL_CANCEL_EVENT, ApprovalCancel { id: modal_id });
                Ok(())
            }
            OtpProcessResult::NeedFresh => {
                // Handle fresh challenge or reuse
                if let Some(chal) = new_challenge {
                    let is_fresh =
                        existing_modal_id.is_none() || existing_modal_id != Some(chal.modal_id);
                    let should_emit_modal = if !is_fresh && existing_modal_id == Some(chal.modal_id)
                    {
                        // Reuse - just update the store with the same modal
                        store.insert(key.clone(), chal.clone());
                        false
                    } else {
                        // Fresh challenge - may need to cancel old modal first
                        if let Some(old_modal) = existing_modal_id {
                            if old_modal != chal.modal_id {
                                let _ = self
                                    .app
                                    .emit(APPROVAL_CANCEL_EVENT, ApprovalCancel { id: old_modal });
                            }
                        }
                        store.insert(key.clone(), chal.clone());
                        true
                    };

                    let modal_id = chal.modal_id;
                    let code = chal.code.clone();
                    drop(store);

                    // Only emit modal for fresh challenges (not reuse)
                    if should_emit_modal {
                        let payload = ApprovalPrompt {
                            id: modal_id,
                            action: format!("{:?}", request.action),
                            container: request.container.clone(),
                            file_name: request.file_name.clone(),
                            mode: request.mode.map(|m| m.as_str().to_string()),
                            byte_size: request.byte_size,
                            otp_code: Some(code),
                            import_summary: request.import_summary.clone(),
                        };
                        self.app.emit(APPROVAL_EVENT, payload).map_err(estr)?;
                    }

                    Err(
                        "otp_required: a one-time code is shown on the Sovereign Vault desktop. \
                         Resend this exact request with the `otp` argument set to that code."
                            .into(),
                    )
                } else {
                    // No challenge - need to issue fresh one
                    drop(store);
                    self.handle_otp_fresh(request).await
                }
            }
            OtpProcessResult::LockedOut => {
                drop(store);
                Err("otp_required: too many failed attempts; retry after 5 minutes".into())
            }
            OtpProcessResult::Invalid => {
                // Update store with incremented failure count
                if let Some(chal) = new_challenge {
                    if chal.is_locked_out() {
                        // Lockout just triggered - cancel the modal
                        let modal_id = chal.modal_id;
                        store.insert(key, chal);
                        drop(store);
                        let _ = self
                            .app
                            .emit(APPROVAL_CANCEL_EVENT, ApprovalCancel { id: modal_id });
                    } else {
                        store.insert(key, chal);
                        drop(store);
                    }
                } else {
                    drop(store);
                }
                Err("otp_required: invalid code".into())
            }
            OtpProcessResult::Expired => {
                // Remove expired challenge and issue fresh one
                store.remove(&key);
                drop(store);
                // Call handle_otp_fresh to issue a fresh challenge
                self.handle_otp_fresh(request).await
            }
        }
    }

    /// Issue a fresh OTP challenge (used after expiry or when no challenge exists).
    async fn handle_otp_fresh(&self, request: &sv_mcp::AccessRequest) -> Result<(), String> {
        let key = request_signature(request);
        let code = generate_otp_code()?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        let mut store = self.otp_pending.lock().await;
        self.prune_expired(&mut store);
        // The caller may have released the lock between the initial admission
        // check and this insertion. Re-check while holding it so concurrent
        // new requests cannot exceed the bounded pending-challenge store.
        if !can_admit_challenge(&store, &key) {
            return Err(
                "otp_required: a one-time code is shown on the Sovereign Vault desktop. \
                 Resend this exact request with the `otp` argument set to that code."
                    .into(),
            );
        }

        // Cancel any prior modal for this signature
        if let Some(old_chal) = store.remove(&key) {
            let _ = self.app.emit(
                APPROVAL_CANCEL_EVENT,
                ApprovalCancel {
                    id: old_chal.modal_id,
                },
            );
        }

        store.insert(key, OtpChallenge::new(code.clone(), id));
        drop(store);

        let payload = ApprovalPrompt {
            id,
            action: format!("{:?}", request.action),
            container: request.container.clone(),
            file_name: request.file_name.clone(),
            mode: request.mode.map(|m| m.as_str().to_string()),
            byte_size: request.byte_size,
            otp_code: Some(code),
            import_summary: request.import_summary.clone(),
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
                .filter(|(_, p)| matches_pending_approval(&p.signature, &request))
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
            import_summary: request.import_summary.clone(),
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
    keychain_backend: String,
    keychain_available: bool,
    keychain_error: Option<String>,
    has_passphrase_salt: bool,
    has_recovery_bundle: bool,
    has_keyring: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultInitResponse {
    recovery_phrase: String,
    /// Non-sensitive warning when the vault is initialized but the local
    /// gateway could not be started. The recovery phrase is still returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway_warning: Option<String>,
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
    /// Validated non-secret authority shown for agent imports.
    import_summary: Option<sv_mcp::ImportApprovalSummary>,
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
        let log = AuditLog::with_hmac_key(&self.root, self.hmac_key).map_err(estr)?;
        log.record(&event).map_err(estr)
    }
}

struct DesktopAgentAuthenticator {
    root: PathBuf,
    token_key: [u8; 32],
    shared_secret: String,
}

fn resolve_scopes(
    scopes: &[sv_core::agents::AgentScope],
) -> Result<Vec<sv_mcp::ResolvedScope>, String> {
    scopes
        .iter()
        .map(|s| {
            sv_mcp::AgentScope {
                container_glob: s.container_glob.clone(),
                actions: s.actions.clone(),
                mode_ceiling: s.mode_ceiling.clone(),
            }
            .resolve()
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
                let matches: bool = token.as_bytes().ct_eq(self.shared_secret.as_bytes()).into();
                if !matches {
                    return Err("invalid shared secret".into());
                }
                sv_core::agents::list_agents(&self.root, &self.token_key)
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
            scopes: resolve_scopes(&record.scopes)?,
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
    // Fail-closed best-effort: derive the audit HMAC key from the live handle.
    // If the vault is locked (no handle or the shared handle is contended),
    // silently skip recording rather than emitting an unauthenticated event.
    let Ok(guard) = state.handle.try_lock() else {
        return;
    };
    let Some(handle) = guard.as_ref() else {
        return;
    };
    let audit_hmac_key = handle.audit_hmac_key();
    if let Ok(log) = AuditLog::with_hmac_key(&root, audit_hmac_key) {
        let _ = log.record(&event);
    }
}

fn approval_requirement(request: &sv_mcp::AccessRequest) -> Result<ApprovalPromptKind, String> {
    // Broker and agent-management actions are high risk and ALWAYS require
    // explicit approval, regardless of any (absent) container mode.
    if matches!(
        request.action,
        sv_mcp::AccessAction::Broker
            | sv_mcp::AccessAction::ImportAgents
            | sv_mcp::AccessAction::ExportAgents
    ) {
        return Ok(ApprovalPromptKind::Click);
    }
    // Transit + signing carry no container mode; gate them on a click, except
    // verify (public-key only, no secret material involved).
    match request.action {
        sv_mcp::AccessAction::CreateTransitKey
        | sv_mcp::AccessAction::ListTransitKeys
        | sv_mcp::AccessAction::Encrypt
        | sv_mcp::AccessAction::Decrypt
        | sv_mcp::AccessAction::CreateSigningKey
        | sv_mcp::AccessAction::ListSigningKeys
        | sv_mcp::AccessAction::Sign => return Ok(ApprovalPromptKind::Click),
        sv_mcp::AccessAction::CreateBrokerSecret | sv_mcp::AccessAction::ListBrokerSecrets => {
            return Ok(ApprovalPromptKind::Click)
        }
        sv_mcp::AccessAction::Verify => return Ok(ApprovalPromptKind::NotRequired),
        _ => {}
    }
    match request.mode {
        // ANONYMIZED is auto-allowed without a consent prompt, exactly like
        // DIRECT: its protection is the PII masking sv-mcp applies to read
        // responses (thesis module 3b), not a human gate. Stored data is not
        // altered; only egress to the agent is sanitised.
        Some(SecurityMode::Direct) | Some(SecurityMode::Anonymized) | None => {
            match request.action {
                sv_mcp::AccessAction::ListContainers | sv_mcp::AccessAction::CreateContainer => {
                    Ok(ApprovalPromptKind::Click)
                }
                _ => Ok(ApprovalPromptKind::NotRequired),
            }
        }
        Some(SecurityMode::Approval) => Ok(ApprovalPromptKind::Click),
        Some(SecurityMode::Otp) => Ok(ApprovalPromptKind::Otp),
        Some(SecurityMode::Zkp) => Err("ZKP mode is not implemented for live MCP access".into()),
        Some(SecurityMode::Native) => {
            Err("NATIVE mode is not implemented for live MCP access".into())
        }
    }
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
        keychain_backend: probe.keychain_backend.to_string(),
        keychain_available: probe.keychain_available,
        keychain_error: probe.keychain_error,
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

    // Initialization is already durably committed at this point, and the
    // recovery phrase exists only in this response. A gateway bind failure
    // must never turn that successful bootstrap into an error that discards
    // the phrase and strands the vault. Keep the handle available for the
    // desktop UI and return a non-secret warning instead.
    let gateway_warning = start_servers(&state).await.err().map(|_| {
        "vault initialized, but the local MCP/HTTP gateway could not start; the recovery phrase below is valid and the gateway can be retried after resolving the local error".to_string()
    });

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
    Ok(VaultInitResponse {
        recovery_phrase,
        gateway_warning,
    })
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
    let probe = sv_core::probe(&root).map_err(estr)?;
    let handle_result = if mode == CustodyMode::OsKeychain && probe.has_passphrase_salt {
        let pass = passphrase.as_deref().ok_or_else(|| {
            "current passphrase is required to move this vault to OS Keychain".to_string()
        })?;
        VaultHandle::unlock(&root, CustodyMode::Passphrase, Some(pass)).and_then(|mut handle| {
            handle.move_to_os_keychain(&root, pass)?;
            Ok(handle)
        })
    } else {
        VaultHandle::unlock(&root, mode, passphrase.as_deref())
    };
    let handle = match handle_result {
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

    // Post-recovery re-bootstrap: recovery restores the DEK but bypasses the
    // KEK, so the manifest integrity check + agents registry may have been
    // written against older code paths. Trigger a list path so the audit log
    // records a recovery re-bootstrap marker; this also catches any drift
    // in agent/token state and logs an `AgentList` event for observability.
    {
        let guard = state.handle.lock().await;
        if let Some(handle) = guard.as_ref() {
            let _ = handle.list_agents();
        }
    }
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
    result.map(|recovery_phrase| VaultInitResponse {
        recovery_phrase,
        gateway_warning: None,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn modeless_request(action: sv_mcp::AccessAction) -> sv_mcp::AccessRequest {
        sv_mcp::AccessRequest {
            transport: sv_mcp::AccessTransport::McpWs,
            action,
            container: None,
            file_name: None,
            mode: None,
            byte_size: None,
            agent_id: Some("ag_test".into()),
            otp: None,
            authorization_context: String::new(),
            import_summary: None,
        }
    }

    fn container_request(mode: SecurityMode, authorization_context: &str) -> sv_mcp::AccessRequest {
        sv_mcp::AccessRequest {
            transport: sv_mcp::AccessTransport::McpWs,
            action: sv_mcp::AccessAction::ReadFile,
            container: Some("notes".into()),
            file_name: Some("entry.txt".into()),
            mode: Some(mode),
            byte_size: None,
            agent_id: Some("ag_test".into()),
            otp: None,
            authorization_context: authorization_context.into(),
            import_summary: None,
        }
    }

    fn import_request(context: &str) -> sv_mcp::AccessRequest {
        let mut request = modeless_request(sv_mcp::AccessAction::ImportAgents);
        request.authorization_context = context.into();
        request.import_summary = Some(sv_mcp::ImportApprovalSummary {
            mode: "create_only".into(),
            agent_count: 1,
            agents: vec![sv_mcp::ImportApprovalAgent {
                name: "limited-agent".into(),
                scopes: vec![sv_mcp::AgentScope {
                    container_glob: "notes/*".into(),
                    actions: vec!["read".into()],
                    mode_ceiling: Some("APPROVAL".into()),
                }],
            }],
        });
        request
    }

    #[test]
    fn agent_management_actions_require_desktop_approval() {
        for action in [
            sv_mcp::AccessAction::ImportAgents,
            sv_mcp::AccessAction::ExportAgents,
        ] {
            assert!(matches!(
                approval_requirement(&modeless_request(action)),
                Ok(ApprovalPromptKind::Click)
            ));
        }
    }

    #[test]
    fn import_approval_rejects_a_different_authorization_context() {
        let approved = import_request("context-for-limited-import");
        let changed = import_request("context-for-broader-import");
        let approved_signature = request_signature(&approved);

        assert!(matches_pending_approval(&approved_signature, &approved));
        assert!(
            !matches_pending_approval(&approved_signature, &changed),
            "an approval for one import envelope must not match another"
        );
    }

    #[test]
    fn create_or_replace_broader_scope_requires_fresh_content_bound_approval() {
        let create_only = import_request("digest:create_only:limited-agent:notes/*:read:APPROVAL");
        let mut replacement =
            import_request("digest:create_or_replace:limited-agent:**:read,write:OTP");
        replacement.import_summary.as_mut().unwrap().mode = "create_or_replace".into();
        replacement.import_summary.as_mut().unwrap().agents[0].scopes[0].container_glob =
            "**".into();
        replacement.import_summary.as_mut().unwrap().agents[0].scopes[0].actions =
            vec!["read".into(), "write".into()];
        replacement.import_summary.as_mut().unwrap().agents[0].scopes[0].mode_ceiling =
            Some("OTP".into());

        assert_ne!(
            request_signature(&create_only),
            request_signature(&replacement)
        );
        assert!(!matches_pending_approval(
            &request_signature(&create_only),
            &replacement
        ));
    }

    #[test]
    fn direct_approval_and_otp_container_requests_keep_their_normal_paths() {
        let direct = container_request(SecurityMode::Direct, "direct-context");
        let approval = container_request(SecurityMode::Approval, "approval-context");
        let otp = container_request(SecurityMode::Otp, "otp-context");

        assert!(matches!(
            approval_requirement(&direct),
            Ok(ApprovalPromptKind::NotRequired)
        ));
        assert!(matches!(
            approval_requirement(&approval),
            Ok(ApprovalPromptKind::Click)
        ));
        assert!(matches!(
            approval_requirement(&otp),
            Ok(ApprovalPromptKind::Otp)
        ));
        assert_eq!(request_signature(&approval), request_signature(&approval));
        assert_eq!(request_signature(&otp), request_signature(&otp));
    }

    /// Helper to create a test challenge with known state.
    fn make_test_challenge(code: &str, modal_id: u64) -> OtpChallenge {
        let mut chal = OtpChallenge::new(code.to_string(), modal_id);
        // Override issued_at to be "now" for testing
        chal.issued_at = Instant::now();
        chal
    }

    #[test]
    fn test_otp_challenge_new() {
        let chal = make_test_challenge("123456", 1);
        assert_eq!(chal.code, "123456");
        assert_eq!(chal.modal_id, 1);
        assert_eq!(chal.failed_attempts, 0);
        assert!(chal.lockout_until.is_none());
        assert!(!chal.is_expired());
        assert!(!chal.is_locked_out());
    }

    #[test]
    fn test_otp_challenge_validate_correct() {
        let chal = make_test_challenge("123456", 1);
        assert!(chal.validate("123456"));
    }

    #[test]
    fn test_otp_challenge_validate_wrong() {
        let chal = make_test_challenge("123456", 1);
        assert!(!chal.validate("654321"));
    }

    #[test]
    fn test_otp_challenge_expiry() {
        let mut chal = make_test_challenge("123456", 1);
        assert!(!chal.is_expired());

        // Artificially expire by moving issued_at back
        chal.issued_at = Instant::now() - Duration::from_secs(OTP_TTL_SECS + 1);
        assert!(chal.is_expired());
    }

    #[test]
    fn test_otp_challenge_lockout_after_five_failures() {
        let mut chal = make_test_challenge("123456", 1);

        // First 4 failures should not lock out
        for i in 1..=4 {
            assert!(!chal.record_failure(), "failure {} should not lock out", i);
            assert!(!chal.is_locked_out());
            assert_eq!(chal.failed_attempts, i);
        }

        // 5th failure triggers lockout
        assert!(chal.record_failure(), "failure 5 should lock out");
        assert!(chal.is_locked_out());
        assert_eq!(chal.failed_attempts, 5);
        assert!(chal.lockout_until.is_some());
    }

    #[test]
    fn test_otp_challenge_lockout_expires() {
        let mut chal = make_test_challenge("123456", 1);

        // Trigger lockout
        for _ in 0..5 {
            chal.record_failure();
        }
        assert!(chal.is_locked_out());

        // Artificially expire lockout
        chal.lockout_until = Some(Instant::now() - Duration::from_secs(1));
        assert!(!chal.is_locked_out());
    }

    #[test]
    fn test_process_otp_request_no_challenge_returns_needfresh() {
        // No challenge exists - should return NeedFresh, not generate a new code
        let (result, new_chal) = process_otp_request(None::<&mut OtpChallenge>, None);

        assert!(matches!(result, OtpProcessResult::NeedFresh));
        assert!(new_chal.is_none());
    }

    #[test]
    fn test_process_otp_request_reuse_on_duplicate_no_code() {
        let mut chal = make_test_challenge("123456", 42);

        let (result, returned_chal) = process_otp_request(Some(&mut chal), None);

        match result {
            OtpProcessResult::NeedFresh => {
                assert!(returned_chal.is_some());
            }
            _ => panic!("Expected NeedFresh result for reuse"),
        }
    }

    #[test]
    fn test_process_otp_request_wrong_code_increments_attempts() {
        let mut chal = make_test_challenge("123456", 42);

        let (result, returned_chal) = process_otp_request(Some(&mut chal), Some("wrong"));

        assert!(matches!(result, OtpProcessResult::Invalid));
        assert!(returned_chal.is_some());
        assert_eq!(returned_chal.unwrap().failed_attempts, 1);
    }

    #[test]
    fn test_process_otp_request_five_failures_locks() {
        let mut chal = make_test_challenge("123456", 42);

        // Record 4 failures first
        for _ in 0..4 {
            chal.record_failure();
        }
        assert_eq!(chal.failed_attempts, 4);

        // 5th failure via process_otp_request
        let (result, returned_chal) = process_otp_request(Some(&mut chal), Some("wrong"));

        assert!(matches!(result, OtpProcessResult::Invalid));
        assert!(returned_chal.is_some());
        let returned = returned_chal.unwrap();
        assert_eq!(returned.failed_attempts, 5);
        assert!(returned.is_locked_out());
    }

    #[test]
    fn test_process_otp_request_locked_out_blocks_no_code() {
        let mut chal = make_test_challenge("123456", 42);
        // Trigger lockout
        for _ in 0..5 {
            chal.record_failure();
        }
        assert!(chal.is_locked_out());

        let (result, _) = process_otp_request(Some(&mut chal), None);

        assert!(matches!(result, OtpProcessResult::LockedOut));
    }

    #[test]
    fn test_process_otp_request_locked_out_blocks_with_code() {
        let mut chal = make_test_challenge("123456", 42);
        // Trigger lockout
        for _ in 0..5 {
            chal.record_failure();
        }
        assert!(chal.is_locked_out());

        // Even correct code should be blocked during lockout
        let (result, _) = process_otp_request(Some(&mut chal), Some("123456"));

        assert!(matches!(result, OtpProcessResult::LockedOut));
    }

    #[test]
    fn test_process_otp_request_correct_code_accepts() {
        let mut chal = make_test_challenge("123456", 42);

        let (result, returned_chal) = process_otp_request(Some(&mut chal), Some("123456"));

        match result {
            OtpProcessResult::Accepted { modal_id } => {
                assert_eq!(modal_id, 42);
                assert!(returned_chal.is_none()); // Challenge consumed
            }
            _ => panic!("Expected Accepted result"),
        }
    }

    #[test]
    fn test_process_otp_request_expired_returns_expired() {
        let mut chal = make_test_challenge("123456", 42);
        // Artificially expire
        chal.issued_at = Instant::now() - Duration::from_secs(OTP_TTL_SECS + 1);

        let (result, _) = process_otp_request(Some(&mut chal), None);

        assert!(matches!(result, OtpProcessResult::Expired));
    }

    #[test]
    fn test_process_otp_request_no_existing_challenge_with_code_expires() {
        // No challenge exists - treated as expired/needs fresh
        let (result, _) = process_otp_request(None::<&mut OtpChallenge>, Some("123456"));

        assert!(matches!(result, OtpProcessResult::Expired));
    }

    // ------------------------------------------------------------------
    // OTP pending map size cap tests (pure helper, no AppHandle required)
    // ------------------------------------------------------------------

    #[test]
    fn test_otp_cap_allows_new_signature_below_cap() {
        let mut store = HashMap::new();
        // Fill to one below the cap so a new signature is still admissible.
        for i in 0..(OTP_MAX_PENDING - 1) {
            store.insert(format!("sig-{i}"), make_test_challenge("123456", i as u64));
        }
        assert_eq!(store.len(), OTP_MAX_PENDING - 1);

        assert!(can_admit_challenge(&store, "sig-new"));
    }

    #[test]
    fn test_otp_cap_denies_new_signature_at_cap() {
        let mut store = HashMap::new();
        for i in 0..OTP_MAX_PENDING {
            store.insert(format!("sig-{i}"), make_test_challenge("123456", i as u64));
        }
        assert_eq!(store.len(), OTP_MAX_PENDING);

        // New signature is denied when the cap is reached.
        assert!(!can_admit_challenge(&store, "sig-new"));
    }

    #[test]
    fn test_otp_cap_allows_existing_signature_at_cap() {
        let mut store = HashMap::new();
        for i in 0..OTP_MAX_PENDING {
            store.insert(format!("sig-{i}"), make_test_challenge("123456", i as u64));
        }
        assert_eq!(store.len(), OTP_MAX_PENDING);

        // Existing signatures remain processable even at the cap.
        assert!(can_admit_challenge(&store, "sig-0"));
        assert!(can_admit_challenge(&store, "sig-512"));
        assert!(can_admit_challenge(&store, "sig-1023"));
    }

    #[test]
    fn test_otp_cap_allows_empty_store() {
        let store: HashMap<String, OtpChallenge> = HashMap::new();
        assert!(can_admit_challenge(&store, "any-new-signature"));
    }
}
