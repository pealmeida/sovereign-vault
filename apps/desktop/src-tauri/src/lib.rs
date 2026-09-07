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

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

use sv_remediate::{
    managed::{ConsumerAdapter, ManagedFilePlan, ManagedIngestStatus},
    IdentityAssurance,
};
use sv_runtime::DiscoveryPolicy;

/// Default idle timeout for an unlocked desktop session.
///
/// A chatty MCP agent MUST NOT reset this timer (ADR-0020 §9). If activity were
/// counted from any source, a polling agent would keep the vault unlocked
/// forever, defeating the control.
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 15 * 60;

/// Default absolute cap on an unlocked desktop session.
///
/// Unlike the idle timer, this cap is never refreshed by any activity. It
/// bounds the total time a single unlock can remain valid.
const DEFAULT_ABSOLUTE_SESSION_SECS: u64 = 8 * 60 * 60;

/// Tick interval for the background session monitor.
const SESSION_MONITOR_INTERVAL_SECS: u64 = 30;

/// Event emitted to the UI when the session monitor locks the vault.
const AUTO_LOCK_EVENT: &str = "vault://auto-lock";

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sv_audit::{AuditAction, AuditDecision, AuditEvent, AuditLog};
use sv_core::sv_storage::{ContainerInfo, FileInfo, SecurityMode};
use sv_core::{BootstrapResult, CustodyMode, VaultHandle};
use sv_scan::{Confidence, FindingKind, ScanConfig, ScanReport};

/// Response for the session status command.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionStatus {
    locked: bool,
    idle_remaining_secs: Option<u64>,
    session_remaining_secs: Option<u64>,
}
use tauri::async_runtime::{spawn, JoinHandle};
use tauri::{AppHandle, Emitter, Manager, Runtime, State};
use tokio::sync::{oneshot, Mutex};

const RPC_PORT: u16 = 9944;
const APPROVAL_EVENT: &str = "vault://approval-request";
const APPROVAL_CANCEL_EVENT: &str = "vault://approval-cancel";
const WAKE_EVENT: &str = "vault://wake-request";
const WAKE_CANCEL_EVENT: &str = "vault://wake-cancel";
const WAKE_LEASE_EVENT: &str = "vault://wake-lease";
/// How long a pending approval stays open before auto-cancelling. Kept short so
/// a caller that disconnects (e.g. its own MCP client timed out) doesn't leave a
/// stale modal lingering on screen.
const APPROVAL_TIMEOUT_SECS: u64 = 120;

type SharedHandle = Arc<Mutex<Option<VaultHandle>>>;

/// Remediation persistence (plan P8): the desktop `VaultSink` over the
/// vault handle. P9 wires the plan registry and Tauri commands on top.
mod remediate;
mod tray;
use remediate::HandleSink;

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

struct ApprovalState<R: Runtime = tauri::Wry> {
    app: AppHandle<R>,
    next_id: AtomicU64,
    pending: Mutex<HashMap<u64, PendingApproval>>,
    /// Outstanding OTP challenges keyed by request signature.
    /// Includes rate limiting state (failed attempts, lockout).
    otp_pending: Mutex<HashMap<String, OtpChallenge>>,
}

/// Whether a click-approval is mirrored into the tray menu.
///
/// The tray exists so a user working in another application can answer an
/// AGENT's request (ADR-0022). A prompt the user raised themselves, in the
/// app, has no such audience.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrayMirror {
    /// Mirror to the tray: an agent is waiting and the user may be elsewhere.
    Yes,
    /// Do not mirror: the user raised this prompt and is looking at it.
    No,
}

impl<R: Runtime> ApprovalState<R> {
    fn new(app: AppHandle<R>) -> Self {
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
                        notify_once(
                            &self.app,
                            NotificationKind::Approval,
                            NOTIFICATION_APPROVAL_BODY,
                        );
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
        notify_once(
            &self.app,
            NotificationKind::Approval,
            NOTIFICATION_APPROVAL_BODY,
        );
        Err(
            "otp_required: a one-time code is shown on the Sovereign Vault desktop. \
             Resend this exact request with the `otp` argument set to that code."
                .into(),
        )
    }

    /// Prompt for explicit human confirmation, always as a click.
    ///
    /// Used by the desktop UI path. Unlike [`Self::request`], this never
    /// consults `approval_requirement` and so never routes to `handle_otp`:
    /// the caller has already decided that consent is required, and a
    /// cross-channel OTP is meaningless when the human at the desktop is the
    /// one asking (see `require_desktop_consent`).
    ///
    /// Shares the pending map, the supersede logic, and the timeout with the
    /// agent path, so a desktop prompt behaves like any other and is answerable
    /// from the same surfaces.
    async fn request_click_only(&self, request: sv_mcp::AccessRequest) -> Result<(), String> {
        // `Tray::No`: this prompt was raised BY the user, in the app, for an
        // action they just triggered. They are already looking at the modal, so
        // a tray row would be a duplicate control for a decision in front of
        // them. It also matters for OTP containers: ADR-0023 routes a desktop
        // OTP caller through this click path, and the tray renders while the
        // vault is locked, so mirroring it would put an OTP-container
        // confirmation on a surface the OTP escalation exists to avoid.
        self.request_click(request, TrayMirror::No).await
    }

    async fn request(&self, request: sv_mcp::AccessRequest) -> Result<(), String> {
        match approval_requirement(&request)? {
            ApprovalPromptKind::NotRequired => return Ok(()),
            ApprovalPromptKind::Click => {}
            ApprovalPromptKind::Otp => return self.handle_otp(&request).await,
        }
        // An agent's request: the user may be in another application, which is
        // the whole reason the tray menu exists (ADR-0022).
        self.request_click(request, TrayMirror::Yes).await
    }

    /// The click-approval flow: emit a modal, optionally mirror it to the tray,
    /// and wait for a decision.
    ///
    /// `mirror` decides whether the request also appears in the tray menu. It
    /// is a parameter rather than an inference from the request, because the
    /// distinction is about WHO IS WAITING -- an absent user or one already at
    /// the modal -- which the request itself does not record.
    async fn request_click(
        &self,
        request: sv_mcp::AccessRequest,
        mirror: TrayMirror,
    ) -> Result<(), String> {
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
            if let Some(tray_state) = self.app.try_state::<tray::TrayApprovals>() {
                tray_state.remove(old);
            }
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
        // Mirror this request into the tray menu. Only the click path does
        // this: an OTP request must stay answerable at the desktop only, and
        // `handle_otp` returns before ever reaching here.
        if mirror == TrayMirror::Yes {
            if let Some(tray_state) = self.app.try_state::<tray::TrayApprovals>() {
                tray_state.insert(tray::TrayApproval {
                    id,
                    action_label: tray::action_label(&request.action),
                    audit_action: audit_action_for(&request.action),
                });
            }
            tray::refresh(&self.app);
        }
        notify_once(
            &self.app,
            NotificationKind::Approval,
            NOTIFICATION_APPROVAL_BODY,
        );

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
                // A timed-out request must not stay clickable in the tray: the
                // channel is gone, so the menu row would be a dead control.
                if let Some(tray_state) = self.app.try_state::<tray::TrayApprovals>() {
                    tray_state.remove(id);
                }
                tray::refresh(&self.app);
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
        let sent = pending_request
            .tx
            .send(approved)
            .map_err(|_| "approval request already closed".to_string());
        // Whichever surface decided, the tray row is now stale.
        if let Some(tray_state) = self.app.try_state::<tray::TrayApprovals>() {
            tray_state.remove(id);
        }
        tray::refresh(&self.app);
        sent
    }
}

/// OS notifications (notifications step 1: plain notifications, no actions —
/// the plugin's Actions API is mobile-only). The text is deliberately fixed:
/// an OS notification is written to the notification-centre history and may
/// appear on a lock screen, so no request field — not even a resource name —
/// is ever interpolated into it. This includes hidden notification metadata,
/// which is not private.
const NOTIFICATION_TITLE: &str = "Sovereign Vault";
const NOTIFICATION_APPROVAL_BODY: &str =
    "An access request needs your review. Open Sovereign Vault to respond.";
const NOTIFICATION_WAKE_BODY: &str = "A local application requested your attention.";

/// Minimum interval between OS notifications. Deliberately shares the value of
/// [`WAKE_NOTIFICATION_COOLDOWN_SECS`]: the wake queue already coalesces
/// arrivals per request signature, and this bounds the notification stream
/// itself so a request storm cannot become a notification storm.
const OS_NOTIFICATION_COOLDOWN_SECS: u64 = WAKE_NOTIFICATION_COOLDOWN_SECS;

/// Master switch and coalescing state for OS notifications. Kept out of
/// `VaultState` so it is not generic over the Tauri runtime and can be read
/// from any emitter. In tests there is no managed state, so [`notify_once`]
/// silently does nothing and never fires an OS notification.
struct NotificationState {
    enabled: AtomicBool,
    /// Instant of the last OS notification of each kind, for coalescing. A std
    /// lock (not tokio): the check is non-blocking and the notification path
    /// must never wait on it.
    last_sent: std::sync::Mutex<LastSent>,
}

/// Last-sent instants, tracked per notification kind.
#[derive(Default)]
struct LastSent {
    approval: Option<Instant>,
    wake: Option<Instant>,
}

/// Which notification is being raised. Determines the cooldown slot.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NotificationKind {
    /// An agent is blocked waiting on a human decision.
    Approval,
    /// Some local process asked for attention (ADR-0021).
    Wake,
}

impl NotificationState {
    fn new() -> Self {
        Self {
            // On by default: the fixed text is designed to be safe to show,
            // and the setting exists so the user can turn the signal off.
            enabled: AtomicBool::new(true),
            last_sent: std::sync::Mutex::new(LastSent::default()),
        }
    }
}

/// Show one OS notification, coalesced. Best-effort and never blocking: if the
/// switch is off, the cooldown has not elapsed, the state lock is contended,
/// or the OS call fails, the notification is skipped. The in-app queue remains
/// the authoritative path to a pending request; a failed notification must
/// never fail the underlying approval or wake flow.
fn notify_once<R: Runtime>(app: &AppHandle<R>, kind: NotificationKind, body: &str) {
    use tauri_plugin_notification::NotificationExt;

    let Some(state) = app.try_state::<NotificationState>() else {
        return;
    };
    if !state.enabled.load(Ordering::Relaxed) {
        return;
    }
    // Cooldowns are per kind, not global. A wake says "some local process wants
    // your attention"; an approval says "an agent is blocked waiting on your
    // decision". Sharing one window lets the weaker signal suppress the
    // stronger one, so an approval could go unannounced because an anonymous
    // wake arrived first. Both are still individually coalesced, which is what
    // the storm requirement asks for.
    let Ok(mut last) = state.last_sent.try_lock() else {
        return;
    };
    let slot = match kind {
        NotificationKind::Approval => &mut last.approval,
        NotificationKind::Wake => &mut last.wake,
    };
    let now = Instant::now();
    if let Some(sent) = *slot {
        if now.duration_since(sent) < Duration::from_secs(OS_NOTIFICATION_COOLDOWN_SECS) {
            return;
        }
    }
    *slot = Some(now);
    drop(last);
    let _ = app
        .notification()
        .builder()
        .title(NOTIFICATION_TITLE)
        .body(body)
        .show();
}

/// Per-agent and global rate-limit state for wake requests.
const WAKE_MAX_PER_AGENT: usize = 10;
const WAKE_WINDOW_SECS: u64 = 60;
const WAKE_MAX_PENDING: usize = 256;
const WAKE_REQUEST_TTL_SECS: u64 = 300;
const WAKE_NOTIFICATION_COOLDOWN_SECS: u64 = 60;
const WAKE_LEASE_TTL_SECS: u64 = 120;

/// How long an unapproved remediation plan stays in the registry.
///
/// A plan is an authorization to delete a specific file, bound to that file's
/// content at plan time. A cancelled confirm dialog leaves one behind with no
/// UI referencing it, so plans expire rather than accumulate. Ten minutes is
/// long enough to read a confirm dialog and short enough that a stale
/// authorization does not sit around; re-planning is cheap.
const PLAN_TTL_SECS: i64 = 600;

/// Stable coalescing signature for a wake request. No secret material is
/// hashed.
fn wake_signature(agent_id: &str, opaque_resource_ref: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(agent_id.as_bytes());
    hasher.update(b"|");
    hasher.update(opaque_resource_ref.as_bytes());
    hex::encode(hasher.finalize())[..32].to_string()
}

/// Trait abstracting the event emission side of the wake queue. Production
/// uses Tauri; tests use a recording emitter.
trait WakeEmitter: Send + Sync + 'static {
    fn emit_wake(&self, prompt: WakePrompt);
    fn emit_cancel(&self, id: u64);
}

impl<R: Runtime> WakeEmitter for AppHandle<R> {
    fn emit_wake(&self, prompt: WakePrompt) {
        let _ = self.emit(WAKE_EVENT, prompt);
        // The wake queue already gates this call behind
        // WAKE_NOTIFICATION_COOLDOWN_SECS per signature; notify_once applies
        // the global OS-notification cooldown on top.
        notify_once(self, NotificationKind::Wake, NOTIFICATION_WAKE_BODY);
    }
    fn emit_cancel(&self, id: u64) {
        let _ = self.emit(WAKE_CANCEL_EVENT, WakeCancel { id });
    }
}

/// In-memory queue for wake requests. The wake path never resolves locators or
/// confirms resource existence; it only asks for human attention (ADR-0020 §8).
struct WakeQueue<E: WakeEmitter> {
    emitter: E,
    next_id: AtomicU64,
    requests: Mutex<Vec<WakeRequest>>,
    by_signature: Mutex<HashMap<String, usize>>,
    agent_rate: Mutex<HashMap<String, Vec<Instant>>>,
    global_rate: Mutex<Vec<Instant>>,
}

impl<E: WakeEmitter> WakeQueue<E> {
    fn new(emitter: E) -> Self {
        Self {
            emitter,
            next_id: AtomicU64::new(1),
            requests: Mutex::new(Vec::new()),
            by_signature: Mutex::new(HashMap::new()),
            agent_rate: Mutex::new(HashMap::new()),
            global_rate: Mutex::new(Vec::new()),
        }
    }

    /// Submit a wake request. Returns a generic status.
    ///
    /// INVARIANT: this function must never consult vault state to decide its
    /// return value. Doing so would reintroduce the existence oracle no matter
    /// how generic the enum appears. The response must be indistinguishable for
    /// references that exist, references that do not exist, and references the
    /// implementation does not understand (ADR-0020 §8).
    async fn request(&self, agent_id: String, opaque_resource_ref: String) -> WakeResult {
        let now = Instant::now();
        let signature = wake_signature(agent_id.as_str(), opaque_resource_ref.as_str());

        // Prune expired rate-limit entries.
        let window = Duration::from_secs(WAKE_WINDOW_SECS);
        {
            let mut agent_rate = self.agent_rate.lock().await;
            for timestamps in agent_rate.values_mut() {
                timestamps.retain(|t| now.duration_since(*t) < window);
            }
            agent_rate.retain(|_, ts| !ts.is_empty());
        }
        {
            let mut global_rate = self.global_rate.lock().await;
            global_rate.retain(|t| now.duration_since(*t) < window);
        }

        // Enforce per-agent and global rate limits.
        {
            let agent_rate = self.agent_rate.lock().await;
            if agent_rate
                .get(&agent_id)
                .map(|ts| ts.len() >= WAKE_MAX_PER_AGENT)
                .unwrap_or(false)
            {
                return WakeResult::Unavailable;
            }
            let global_rate = self.global_rate.lock().await;
            if global_rate.len() >= WAKE_MAX_PER_AGENT * 4 {
                return WakeResult::Unavailable;
            }
        }

        let mut requests = self.requests.lock().await;
        let mut by_signature = self.by_signature.lock().await;

        // Prune expired pending requests.
        let ttl = Duration::from_secs(WAKE_REQUEST_TTL_SECS);
        let expired: Vec<u64> = requests
            .iter()
            .filter(|r| now.duration_since(r.created_at) > ttl)
            .map(|r| r.id)
            .collect();
        for id in expired {
            if let Some(pos) = requests.iter().position(|r| r.id == id) {
                let sig = requests[pos].signature.clone();
                requests.remove(pos);
                by_signature.remove(&sig);
                self.emitter.emit_cancel(id);
            }
        }

        // Coalescing: identical pending request collapses into one.
        if let Some(_pos) = by_signature.get(&signature) {
            // Still notify if the cooldown has elapsed, so a retry storm still
            // produces at most one notification within the cooldown window.
            if let Some(existing) = requests.iter().find(|r| r.signature == signature) {
                let cooldown = Duration::from_secs(WAKE_NOTIFICATION_COOLDOWN_SECS);
                if existing
                    .notified_at
                    .map(|t| now.duration_since(t) >= cooldown)
                    .unwrap_or(true)
                {
                    let agent_for_prompt = existing.agent_id.clone();
                    let resource_for_prompt = existing.opaque_resource_ref.clone();
                    let existing_id = existing.id;
                    if let Some(idx) = requests.iter().position(|r| r.id == existing_id) {
                        requests[idx].notified_at = Some(now);
                    }
                    let prompt = WakePrompt {
                        id: existing_id,
                        agent_id: agent_for_prompt,
                        resource_ref: resource_for_prompt,
                    };
                    self.emitter.emit_wake(prompt);
                }
            }
            drop(requests);
            drop(by_signature);
            // Record this attempt for rate-limit accounting.
            self.agent_rate
                .lock()
                .await
                .entry(agent_id)
                .or_default()
                .push(now);
            self.global_rate.lock().await.push(now);
            return WakeResult::Queued;
        }

        // Bound total pending requests.
        if requests.len() >= WAKE_MAX_PENDING {
            return WakeResult::Unavailable;
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let request = WakeRequest {
            id,
            agent_id: agent_id.clone(),
            opaque_resource_ref: opaque_resource_ref.clone(),
            signature: signature.clone(),
            created_at: now,
            notified_at: Some(now),
        };
        by_signature.insert(signature, requests.len());
        requests.push(request);

        let prompt = WakePrompt {
            id,
            agent_id: agent_id.clone(),
            resource_ref: opaque_resource_ref.clone(),
        };
        self.emitter.emit_wake(prompt.clone());

        drop(requests);
        drop(by_signature);

        self.agent_rate
            .lock()
            .await
            .entry(agent_id)
            .or_default()
            .push(now);
        self.global_rate.lock().await.push(now);

        WakeResult::Queued
    }

    /// Return a snapshot of pending requests for the UI. Never reveals resource
    /// existence beyond what the queue already contains.
    async fn list(&self) -> Vec<WakePrompt> {
        let now = Instant::now();
        let requests = self.requests.lock().await;
        requests
            .iter()
            .filter(|r| {
                now.duration_since(r.created_at) <= Duration::from_secs(WAKE_REQUEST_TTL_SECS)
            })
            .map(|r| WakePrompt {
                id: r.id,
                agent_id: r.agent_id.clone(),
                resource_ref: r.opaque_resource_ref.clone(),
            })
            .collect()
    }

    /// Human responds to a wake request. Returns the request details if found.
    async fn respond(&self, id: u64, approved: bool) -> Option<WakeRequest> {
        let mut requests = self.requests.lock().await;
        let pos = requests.iter().position(|r| r.id == id)?;
        let request = requests.remove(pos);
        let mut by_signature = self.by_signature.lock().await;
        by_signature.remove(&request.signature);
        self.emitter.emit_cancel(id);
        if approved {
            Some(request)
        } else {
            None
        }
    }
}

/// Authorization granted by a human when responding to a wake request. A lease
/// is only issued for an exact operation+args when prepare_access is called,
/// after which per-mode behavior is applied.
#[derive(Debug, Clone)]
struct WakeAuthorization {
    agent_id: String,
    session_id: String,
    authorized_at: Instant,
}

/// In-memory store of active leases and wake authorizations.
struct LeaseStore {
    leases: Mutex<HashMap<String, Lease>>,
    authorized_wakes: Mutex<HashMap<String, WakeAuthorization>>,
}

impl LeaseStore {
    fn new() -> Self {
        Self {
            leases: Mutex::new(HashMap::new()),
            authorized_wakes: Mutex::new(HashMap::new()),
        }
    }

    /// Record that a human approved a wake request. This does not yet issue a
    /// lease; the lease is bound to the exact operation when it is requested.
    async fn record_authorized_wake(
        &self,
        resource_signature: &str,
        agent_id: &str,
        session_id: &str,
    ) {
        let auth = WakeAuthorization {
            agent_id: agent_id.to_string(),
            session_id: session_id.to_string(),
            authorized_at: Instant::now(),
        };
        self.authorized_wakes
            .lock()
            .await
            .insert(resource_signature.to_string(), auth);
    }

    /// Return true if a wake authorization exists for this agent/resource in the
    /// current session and has not expired.
    async fn has_authorized_wake(
        &self,
        resource_signature: &str,
        agent_id: &str,
        session_id: &str,
    ) -> bool {
        let auths = self.authorized_wakes.lock().await;
        matches!(
            auths.get(resource_signature),
            Some(a) if a.agent_id == agent_id
                && a.session_id == session_id
                && a.authorized_at.elapsed() <= Duration::from_secs(WAKE_REQUEST_TTL_SECS)
        )
    }

    /// Issue a lease bound to the requester, resource, operation and args,
    /// destination, session, and policy version.
    #[allow(clippy::too_many_arguments)]
    async fn issue(
        &self,
        agent_id: &str,
        resource_signature: &str,
        operation_digest: &str,
        args_digest: &str,
        destination: &str,
        session_id: &str,
        policy_version: &str,
    ) -> Lease {
        let id = fresh_lease_id();
        let lease = Lease {
            id: id.clone(),
            agent_id: agent_id.to_string(),
            resource_signature: resource_signature.to_string(),
            operation_digest: operation_digest.to_string(),
            args_digest: args_digest.to_string(),
            destination: destination.to_string(),
            session_id: session_id.to_string(),
            policy_version: policy_version.to_string(),
            expires_at: Instant::now() + Duration::from_secs(WAKE_LEASE_TTL_SECS),
            used: Arc::new(AtomicBool::new(false)),
        };
        self.leases.lock().await.insert(id.clone(), lease.clone());
        lease
    }

    /// Check out a lease for the exact operation/resource/args/session. Marks
    /// it used (single-use) and returns true if all bindings match and it has
    /// not expired.
    #[allow(clippy::too_many_arguments)]
    async fn checkout(
        &self,
        lease_id: &str,
        agent_id: &str,
        resource_signature: &str,
        operation_digest: &str,
        args_digest: &str,
        destination: &str,
        session_id: &str,
        policy_version: &str,
    ) -> bool {
        let mut leases = self.leases.lock().await;
        let Some(lease) = leases.get(lease_id) else {
            return false;
        };
        if Instant::now() > lease.expires_at {
            leases.remove(lease_id);
            return false;
        }
        if lease.used.swap(true, Ordering::SeqCst) {
            return false;
        }
        let same = lease.agent_id == agent_id
            && lease.resource_signature == resource_signature
            && lease.operation_digest == operation_digest
            && lease.args_digest == args_digest
            && lease.destination == destination
            && lease.session_id == session_id
            && lease.policy_version == policy_version;
        if !same {
            // Re-insert so future attempts also fail (the lease was consumed).
            return false;
        }
        leases.remove(lease_id);
        true
    }

    /// Prune expired leases; returns count removed.
    #[allow(dead_code)]
    async fn prune(&self) -> usize {
        let now = Instant::now();
        let mut leases = self.leases.lock().await;
        let before = leases.len();
        leases.retain(|_, l| now <= l.expires_at);
        before - leases.len()
    }
}

fn fresh_lease_id() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(sv_core::sv_crypto::random_bytes(32).unwrap_or_else(|_| vec![0u8; 32]));
    hasher.update(format!("{:?}", Instant::now()).as_bytes());
    format!("lease-{}", &hex::encode(hasher.finalize())[..32])
}

/// Fields needed by the background session monitor. Kept behind an `Arc` so
/// the monitor task owns its own copy and outlives any single command.
#[derive(Clone)]
struct SessionMonitorState<R: Runtime = tauri::Wry> {
    app: AppHandle<R>,
    handle: SharedHandle,
    servers: Arc<Mutex<Option<ServersShutdown>>>,
    timer: SessionTimer,
}

/// Self-contained desktop session timer. Kept separate from [`VaultState`] so
/// its behavior can be unit-tested without a Tauri runtime.
#[derive(Clone)]
struct SessionTimer {
    /// Last time a genuine human interaction happened in the desktop GUI.
    ///
    /// **Agent-originated activity must never update this.** MCP-serving paths
    /// and polling/status commands are intentionally excluded. This is the
    /// invariant that prevents a chatty agent from pinning the vault open
    /// (ADR-0020 §9).
    last_activity: Arc<Mutex<Instant>>,
    /// When the vault was unlocked, if it currently is.
    unlocked_at: Arc<Mutex<Option<Instant>>>,
    /// Seconds of inactivity before auto-lock.
    idle_timeout_secs: Arc<Mutex<u64>>,
    /// Maximum seconds a single unlock can last, regardless of activity.
    absolute_session_secs: Arc<Mutex<u64>>,
}

impl SessionTimer {
    fn new() -> Self {
        Self {
            last_activity: Arc::new(Mutex::new(Instant::now())),
            unlocked_at: Arc::new(Mutex::new(None)),
            idle_timeout_secs: Arc::new(Mutex::new(DEFAULT_IDLE_TIMEOUT_SECS)),
            absolute_session_secs: Arc::new(Mutex::new(DEFAULT_ABSOLUTE_SESSION_SECS)),
        }
    }

    /// Refresh the human-activity timestamp.
    ///
    /// **Call this only from human-initiated Tauri commands.** Do NOT call from
    /// MCP-serving paths or polling/status commands (`vault_status`,
    /// `mcp_status`, `audit_tail`, `scan_history_list`, etc.). A chatty agent
    /// must not keep the vault unlocked forever (ADR-0020 §9).
    fn touch_human_activity(&self) {
        if let Ok(mut guard) = self.last_activity.try_lock() {
            *guard = Instant::now();
        }
    }

    /// Record that the vault is now unlocked, starting both timers.
    fn set_unlocked(&self) {
        let now = Instant::now();
        if let Ok(mut guard) = self.unlocked_at.try_lock() {
            *guard = Some(now);
        }
        if let Ok(mut guard) = self.last_activity.try_lock() {
            *guard = now;
        }
    }

    /// Set the two session limits.
    fn set_limits(&self, idle_secs: u64, absolute_secs: u64) {
        if let Ok(mut guard) = self.idle_timeout_secs.try_lock() {
            *guard = idle_secs.max(1);
        }
        if let Ok(mut guard) = self.absolute_session_secs.try_lock() {
            *guard = absolute_secs.max(1);
        }
    }

    /// Compute remaining seconds before idle or absolute lock, if unlocked.
    fn remaining_secs(&self) -> (Option<u64>, Option<u64>) {
        let unlocked = match self.unlocked_at.try_lock().ok().and_then(|g| *g) {
            Some(t) => t,
            None => return (None, None),
        };
        let idle = match self.last_activity.try_lock().ok() {
            Some(g) => *g,
            None => return (None, None),
        };
        let idle_limit = self
            .idle_timeout_secs
            .try_lock()
            .map(|g| *g)
            .unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS);
        let absolute_limit = self
            .absolute_session_secs
            .try_lock()
            .map(|g| *g)
            .unwrap_or(DEFAULT_ABSOLUTE_SESSION_SECS);
        let idle_remaining = idle_limit.saturating_sub(idle.elapsed().as_secs());
        let absolute_remaining = absolute_limit.saturating_sub(unlocked.elapsed().as_secs());
        (Some(idle_remaining), Some(absolute_remaining))
    }
}

/// In-memory vault state held inside Tauri's managed state.
struct VaultState<R: Runtime = tauri::Wry> {
    app: AppHandle<R>,
    handle: SharedHandle,
    approvals: Arc<ApprovalState<R>>,
    servers: Arc<Mutex<Option<ServersShutdown>>>,
    /// Scan reports that were produced in this process and still have a live
    /// per-scan salt. Findings loaded from disk do not appear here, so their
    /// fingerprint is absent and reveal is refused.
    active_scans: Mutex<HashMap<String, ScanReport>>,
    /// Desktop session timer (idle + absolute cap).
    session_timer: SessionTimer,
    /// Pending wake requests and rate-limit state. In-memory only; a restart
    /// clears the queue, which is acceptable because a wake is just a request
    /// for human attention (ADR-0020 §8).
    wake_queue: Arc<WakeQueue<AppHandle<R>>>,
    /// Short-lived, single-use leases issued after human approval of a wake
    /// request (ADR-0020 §10).
    leases: Arc<LeaseStore>,
    /// Backend-held pending remediation plans (ADR-0020 §2). The renderer only
    /// sees opaque `plan_id`s; the real path lives here, resolved from the
    /// stored scan report.
    pending_plans: Arc<Mutex<HashMap<String, PendingPlan>>>,
    /// Handle to the session monitor task. Stored so we can avoid spawning
    /// duplicate monitors on every unlock (a leaked second monitor is harmless
    /// but noisy; we drop the old JoinHandle before spawning a new one).
    session_monitor: Mutex<Option<JoinHandle<()>>>,
}

impl<R: Runtime> VaultState<R> {
    fn new(app: AppHandle<R>) -> Self {
        let approvals = Arc::new(ApprovalState::<R>::new(app.clone()));
        Self {
            app: app.clone(),
            handle: Arc::new(Mutex::new(None)),
            approvals,
            servers: Arc::new(Mutex::new(None)),
            active_scans: Mutex::new(HashMap::new()),
            session_timer: SessionTimer::new(),
            wake_queue: Arc::new(WakeQueue::new(app.clone())),
            leases: Arc::new(LeaseStore::new()),
            pending_plans: Arc::new(Mutex::new(HashMap::new())),
            session_monitor: Mutex::new(None),
        }
    }

    /// Build a monitor-state snapshot for the background task.
    fn monitor_state(&self) -> SessionMonitorState<R> {
        SessionMonitorState {
            app: self.app.clone(),
            handle: self.handle.clone(),
            servers: self.servers.clone(),
            timer: self.session_timer.clone(),
        }
    }

    /// Replace any running session monitor with a new one bound to the current
    /// unlock. Called once per successful unlock/init.
    async fn restart_session_monitor(&self) {
        let mut guard = self.session_monitor.lock().await;
        if let Some(task) = guard.take() {
            task.abort();
        }
        *guard = Some(spawn_session_monitor(self.monitor_state()));
    }

    /// Refresh the human-activity timestamp.
    fn touch_human_activity(&self) {
        self.session_timer.touch_human_activity();
    }

    /// Record that the vault is now unlocked, starting both timers.
    fn set_unlocked(&self) {
        self.session_timer.set_unlocked();
    }

    /// Set the two session limits.
    fn set_limits(&self, idle_secs: u64, absolute_secs: u64) {
        self.session_timer.set_limits(idle_secs, absolute_secs);
    }

    /// Compute remaining seconds before idle or absolute lock, if unlocked.
    fn remaining_secs(&self) -> (Option<u64>, Option<u64>) {
        self.session_timer.remaining_secs()
    }

    fn session_id(&self) -> String {
        // The session is identified by the unlock instant, which changes on
        // every lock/unlock cycle. This is coarse but sufficient for lease
        // binding: a lease issued in one unlock cannot outlive the next lock.
        self.session_timer
            .unlocked_at
            .try_lock()
            .ok()
            .and_then(|g| g.map(|i| format!("{:?}", i)))
            .unwrap_or_else(|| "locked".into())
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

/// Read-only view of one audit event for the desktop Logs page.
/// Never exposes secret material; container/file paths remain the
/// HMAC-redacted values stored in the authenticated log.
#[derive(Debug, Serialize, Deserialize)]
struct AuditEventView {
    action: String,
    decision: String,
    transport: String,
    timestamp: String,
    error: Option<String>,
}

/// Paginated newest-first response for the Logs page.
#[derive(Debug, Serialize, Deserialize)]
struct AuditTailResponse {
    events: Vec<AuditEventView>,
    /// Records that could not be parsed. Shown separately so one corrupt or
    /// partially-written trailing line cannot hide the rest of the log.
    malformed_skipped: usize,
}

/// Read-only view of an audit chain verification report.
#[derive(Debug, Serialize, Deserialize)]
struct VerifyReportView {
    ok: bool,
    entries: usize,
    legacy_entries: usize,
    first_broken: Option<usize>,
    reason: Option<String>,
}

/// Read-only view of one scan finding for the Scans page.
/// Never carries the raw matched value — only a masked preview and location.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanFindingView {
    path: String,
    line: u32,
    start: usize,
    end: usize,
    kind: String,
    confidence: String,
    preview: String,
    /// Per-finding triage verdict persisted in vault state only.
    #[serde(skip_serializing_if = "Option::is_none")]
    verdict: Option<String>,
}

/// Read-only view of a scan coverage summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanCoverageView {
    files_scanned: u64,
    files_ignored: u64,
    files_skipped: u64,
    bytes_scanned: u64,
    suppressed: Vec<ScanSuppressedView>,
}

/// Count of findings suppressed for one reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanSuppressedView {
    reason: String,
    count: u64,
}

/// Read-only view of a full scan report.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanReportView {
    id: String,
    scanned_path: String,
    created_at: String,
    coverage: ScanCoverageView,
    findings: Vec<ScanFindingView>,
}

/// Short summary of a stored scan report for the history list.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanSummaryView {
    id: String,
    scanned_path: String,
    created_at: String,
    finding_count: usize,
}

/// Backend-held pending remediation plan. The renderer only ever receives the
/// opaque `plan_id`; the path is stored here and resolved from the stored scan
/// report, so a compromised renderer cannot supply an arbitrary filesystem path.
#[derive(Debug, Clone)]
struct PendingPlan {
    id: String,
    project_root: PathBuf,
    plan: ManagedFilePlan,
    snapshot_digest: sv_remediate::Digest,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// Read-only view of a pending remediation plan sent to the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlanView {
    plan_id: String,
    path: String,
    adapter: String,
    eligibility: String,
    manifest_path: String,
    identity_enforced: bool,
    /// Hex of the plan's snapshot digest, echoed back as `confirm_digest` to
    /// bind approval to this exact file content (ADR-0019 §2).
    ///
    /// Safe to hand to the renderer: it is an HMAC under a key derived from
    /// the vault identity root, which the renderer never sees, so it is an
    /// unguessable capability token rather than an oracle for the file's
    /// bytes. It is not a human-verifiable value and the UI must not present
    /// it as one.
    confirm_digest: String,
}

/// Result of a whole-file ingestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IngestView {
    status: String,
    manifest: Option<String>,
    reason: Option<String>,
    identity_enforced: bool,
}

/// Result of restoring a previously ingested file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RestoreView {
    restored: bool,
    reason: Option<String>,
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

/// Generic wake response; the agent MUST NOT be able to tell whether the
/// requested resource exists from this value (ADR-0020 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum WakeResult {
    Queued,
    Unavailable,
}

/// One pending wake request held in memory. No locator is resolved and no
/// resource existence is checked when this is created.
#[derive(Debug, Clone)]
struct WakeRequest {
    id: u64,
    agent_id: String,
    /// Opaque resource reference supplied by the agent. The wake path never
    /// interprets it.
    opaque_resource_ref: String,
    /// Stable key used for coalescing and cooldown.
    signature: String,
    created_at: Instant,
    notified_at: Option<Instant>,
}

/// UI payload for a pending wake request. Only fields derivable from the
/// vault's own state are shown; the agent can supply no self-description.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WakePrompt {
    id: u64,
    agent_id: String,
    resource_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WakeCancel {
    id: u64,
}

/// A short-lived, single-use authorization issued after a human approves a wake
/// request. Bound to agent identity, resource, operation and its arguments,
/// destination, session, and policy version (ADR-0020 §10).
#[derive(Debug, Clone)]
struct Lease {
    id: String,
    agent_id: String,
    resource_signature: String,
    operation_digest: String,
    args_digest: String,
    destination: String,
    session_id: String,
    policy_version: String,
    expires_at: Instant,
    used: Arc<AtomicBool>,
}

/// Result emitted to the agent when a lease is issued.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WakeLease {
    lease_id: String,
    expires_at_secs: u64,
}

/// Parameters used to compute the resource and argument digests for a lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LeaseParams {
    agent_id: String,
    resource_ref: String,
    operation: String,
    args: Vec<String>,
    destination: String,
    mode: String,
}

fn digest_string(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())[..32].to_string()
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

struct DesktopAccessController<R: Runtime = tauri::Wry> {
    approvals: Arc<ApprovalState<R>>,
}

#[async_trait]
impl<R: Runtime> sv_mcp::AccessController for DesktopAccessController<R> {
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

fn vault_root<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(estr)?;
    Ok(dir.join("sovereign-vault"))
}

fn audit_root<R: Runtime>(state: &VaultState<R>) -> Result<PathBuf, String> {
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

/// Apply an approval decision taken from the system-tray menu.
///
/// The tray is a lower-context surface than the in-app modal: it shows the
/// action class only, so the audit record must say where the decision came
/// from. The transport is `desktop-tray`, distinct from `desktop-ui`, so a
/// reviewer can tell a decision made against a full request view from one made
/// against a menu label.
///
/// Refuses while the vault is locked. `respond` would otherwise still resolve
/// the waiting channel, letting a decision land after the user deliberately
/// ended access; the pending set is cleared on lock, so this is a
/// belt-and-braces check against a request that arrived mid-transition.
async fn respond_from_tray<R: Runtime>(app: &AppHandle<R>, id: u64, approved: bool) {
    let Some(state) = app.try_state::<VaultState<R>>() else {
        return;
    };

    if state.handle.lock().await.is_none() {
        // Locked: drop the stale entry and re-render rather than deciding.
        if let Some(tray_state) = app.try_state::<tray::TrayApprovals>() {
            tray_state.remove(id);
        }
        tray::refresh(app);
        return;
    }

    // The action is read BEFORE responding, so the audit names the action that
    // was actually authorised rather than a placeholder. A request missing from
    // the registry is not decided here at all: without it there is nothing
    // truthful to record, and the app remains the way to answer.
    let Some(audit_action) = app
        .try_state::<tray::TrayApprovals>()
        .and_then(|s| s.snapshot().into_iter().find(|a| a.id == id))
        .map(|a| a.audit_action)
    else {
        tray::refresh(app);
        return;
    };

    // A tray click is a real human at the machine, exactly like a click in the
    // app, so it refreshes the idle timer the same way `approval_respond` does.
    state.touch_human_activity();

    // No OTP is ever passed from the tray: OTP-mode requests never enter the
    // tray registry, and `respond` rejects an approval whose pending entry
    // carries a code when none is supplied.
    let result = state.approvals.respond(id, approved, None).await;

    if result.is_ok() {
        let event = AuditEvent::new(
            audit_action,
            if approved {
                AuditDecision::Allowed
            } else {
                AuditDecision::Denied
            },
            "desktop-tray",
        );
        record_desktop_event(&state, event);
    }

    if let Some(tray_state) = app.try_state::<tray::TrayApprovals>() {
        tray_state.remove(id);
    }
    tray::refresh(app);
}

fn record_desktop_event<R: Runtime>(state: &VaultState<R>, event: AuditEvent) {
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

/// Minimal record envelope used only to extract the public `event` field.
/// The authenticated shape is owned by `sv_audit`; this struct deliberately
/// ignores every other field so the UI can read events without touching the
/// audit crate internals. Chain integrity is surfaced separately by
/// `audit_verify`.
#[derive(Debug, Clone, Deserialize)]
struct AuditRecordView {
    event: AuditEvent,
}

/// Outcome of a newest-first tail read.
struct AuditTailResult {
    events: Vec<AuditEventView>,
    malformed_skipped: usize,
}

/// Read audit events newest-first, stopping as soon as `offset + limit`
/// events have been collected. Never reads or materialises the whole log.
///
/// IMPORTANT: this reader parses the log OUTSIDE `AuditLog`. It does NOT
/// verify the hash chain. That is acceptable here ONLY because `audit_verify`
/// reports integrity separately on the same page. A later reader must not
/// mistake this path for a verified audit reader.
fn read_audit_tail(
    root: &std::path::Path,
    limit: usize,
    offset: usize,
) -> Result<AuditTailResult, String> {
    const ARCHIVE_PREFIX: &str = "audit-";
    const ARCHIVE_SUFFIX: &str = ".jsonl";
    const ARCHIVE_DIGITS: usize = 20;

    let need = offset.saturating_add(limit);

    let mut archives: BTreeMap<u64, PathBuf> = BTreeMap::new();
    let dir_entries = std::fs::read_dir(root).map_err(estr)?;
    for entry in dir_entries {
        let entry = entry.map_err(estr)?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(ARCHIVE_PREFIX) || !name.ends_with(ARCHIVE_SUFFIX) {
            continue;
        }
        let digits = &name[ARCHIVE_PREFIX.len()..name.len() - ARCHIVE_SUFFIX.len()];
        if digits.len() != ARCHIVE_DIGITS || !digits.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let segment = digits.parse::<u64>().map_err(estr)?;
        archives.insert(segment, entry.path());
    }

    let mut collected = Vec::new();
    let mut malformed_skipped = 0usize;

    // Newest first: active log, then archives by descending segment number.
    let active = root.join("audit.jsonl");
    if active.exists() {
        let (events, skipped) = read_audit_segment_newest_first(&active, need)?;
        malformed_skipped = malformed_skipped.saturating_add(skipped);
        collected.extend(events);
        if collected.len() >= need {
            return Ok(slice_page(collected, limit, offset, malformed_skipped));
        }
    }

    for path in archives.values().rev() {
        let (events, skipped) = read_audit_segment_newest_first(path, need - collected.len())?;
        malformed_skipped = malformed_skipped.saturating_add(skipped);
        collected.extend(events);
        if collected.len() >= need {
            break;
        }
    }

    Ok(slice_page(collected, limit, offset, malformed_skipped))
}

/// Read one segment's lines newest-first, skipping malformed records and
/// stopping early once `need` events have been collected.
fn read_audit_segment_newest_first(
    path: &std::path::Path,
    need: usize,
) -> Result<(Vec<AuditEventView>, usize), String> {
    let text = std::fs::read_to_string(path).map_err(estr)?;
    let mut lines: Vec<&str> = text.lines().collect();
    lines.reverse();

    let mut events = Vec::new();
    let mut malformed_skipped = 0usize;

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let record: AuditRecordView = match serde_json::from_str(line) {
            Ok(record) => record,
            Err(_) => {
                malformed_skipped = malformed_skipped.saturating_add(1);
                continue;
            }
        };
        events.push(AuditEventView {
            action: serde_json::to_string(&record.event.action)
                .map_err(estr)
                .unwrap_or_else(|_| {
                    format!("{:?}", record.event.action)
                        .trim_matches('"')
                        .to_string()
                }),
            decision: serde_json::to_string(&record.event.decision)
                .map_err(estr)
                .unwrap_or_else(|_| {
                    format!("{:?}", record.event.decision)
                        .trim_matches('"')
                        .to_string()
                }),
            transport: record.event.transport,
            timestamp: record.event.timestamp.to_rfc3339(),
            error: record.event.error,
        });
        if events.len() >= need {
            break;
        }
    }
    Ok((events, malformed_skipped))
}

/// Take the requested page from the newest-first buffer.
fn slice_page(
    mut events: Vec<AuditEventView>,
    limit: usize,
    offset: usize,
    malformed_skipped: usize,
) -> AuditTailResult {
    let start = offset.min(events.len());
    let end = offset.saturating_add(limit).min(events.len());
    events.truncate(end);
    let page = events.into_iter().skip(start).collect();
    AuditTailResult {
        events: page,
        malformed_skipped,
    }
}

/// Audit action corresponding to an access action.
///
/// `sv_mcp` keeps its own mapping private, so the desktop carries this one for
/// tray decisions. Exhaustive: a new action must be mapped here rather than
/// silently audited as something else.
fn audit_action_for(action: &sv_mcp::AccessAction) -> AuditAction {
    use sv_mcp::AccessAction as A;
    match action {
        A::ListContainers => AuditAction::ListContainers,
        A::ListFiles => AuditAction::ListFiles,
        A::ReadFile => AuditAction::ReadFile,
        A::WriteFile => AuditAction::WriteFile,
        A::DeleteFile => AuditAction::DeleteFile,
        A::CreateContainer => AuditAction::CreateContainer,
        A::DestroyContainer => AuditAction::DeleteContainer,
        A::CreateTransitKey => AuditAction::CreateTransitKey,
        A::ListTransitKeys => AuditAction::ListTransitKeys,
        A::Encrypt => AuditAction::Encrypt,
        A::Decrypt => AuditAction::Decrypt,
        A::CreateSigningKey => AuditAction::CreateSigningKey,
        A::ListSigningKeys => AuditAction::ListSigningKeys,
        A::Sign => AuditAction::Sign,
        A::Verify => AuditAction::Verify,
        A::CreateBrokerSecret => AuditAction::CreateBrokerSecret,
        A::ListBrokerSecrets => AuditAction::ListBrokerSecrets,
        A::Broker => AuditAction::Broker,
        A::VaultInfo => AuditAction::VaultInfo,
        A::ExportAgents => AuditAction::AgentExport,
        A::ImportAgents => AuditAction::AgentImport,
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

/// Check whether the vault is currently unlocked, without refreshing any
/// activity timer. Used by polling/status commands.
async fn is_unlocked(state: &State<'_, VaultState>) -> bool {
    state.handle.lock().await.is_some()
}

/// Require human consent for a desktop-originated action on a container.
///
/// # Why this exists
///
/// Until this was added, the security mode on a container was enforced only on
/// the MCP path. Desktop Tauri commands read `container_mode` solely to LABEL
/// the audit event and then performed the operation unconditionally. The audit
/// log therefore recorded rows carrying `mode: OTP` for reads no human ever
/// approved -- an authenticated, tamper-evident log asserting a control that
/// had not run. `sv-storage` states enforcement belongs to "the UI/MCP layer
/// above"; MCP did it and the UI did not.
///
/// # Why a desktop OTP becomes a click
///
/// OTP mode is a CROSS-CHANNEL check: the vault shows a code on the desktop
/// and the agent resends the request carrying it, which binds two channels
/// that an agent cannot straddle alone. When the caller IS the human at the
/// desktop, that loop is degenerate -- the code would be displayed to, and
/// retyped by, the same person on the same screen, adding friction while
/// binding nothing. `ApprovalState::handle_otp` also structurally cannot serve
/// this path: it returns `otp_required` and waits for a resend, which a UI
/// button click has no way to perform.
///
/// So a desktop caller is prompted for explicit confirmation for BOTH
/// `Approval` and `Otp` containers. The human gate runs; only the second
/// channel is dropped, because on this path there is no second channel. The
/// audit records `desktop-ui`, so a reviewer can always tell a desktop
/// confirmation from an agent's cross-channel OTP.
///
/// Returns `Err` when consent is refused, which callers propagate so the
/// operation does not run.
/// Whether a desktop-originated action on a container of `mode` needs explicit
/// human confirmation.
///
/// Split out from [`require_desktop_consent`] so the policy can be tested
/// without a live vault or a real prompt.
fn desktop_consent_required(mode: Option<SecurityMode>) -> Result<bool, String> {
    match mode {
        // No mode recorded means no policy has been set for this container.
        // Treat it as ungated, matching `approval_requirement`'s handling of a
        // modeless request, rather than inventing a gate the user never asked
        // for.
        None => Ok(false),
        Some(SecurityMode::Direct) | Some(SecurityMode::Anonymized) => Ok(false),
        Some(SecurityMode::Approval) | Some(SecurityMode::Otp) => Ok(true),
        // Not implemented for live access anywhere else in the app; fail
        // closed rather than silently allowing.
        Some(SecurityMode::Zkp) => Err("ZKP mode is not implemented for vault access".into()),
        Some(SecurityMode::Native) => Err("NATIVE mode is not implemented for vault access".into()),
    }
}

async fn require_desktop_consent<R: Runtime>(
    state: &VaultState<R>,
    action: sv_mcp::AccessAction,
    container: &str,
    file_name: Option<&str>,
    mode: Option<SecurityMode>,
) -> Result<(), String> {
    if !desktop_consent_required(mode)? {
        return Ok(());
    }

    let request = sv_mcp::AccessRequest {
        // The transport enum models agent channels only. `McpWs` is the
        // closest existing value; the AUDIT transport is set separately by
        // `desktop_event` and correctly reads `desktop-ui`, which is what a
        // reviewer sees.
        transport: sv_mcp::AccessTransport::McpWs,
        action,
        container: Some(container.to_string()),
        file_name: file_name.map(str::to_string),
        mode,
        byte_size: None,
        agent_id: None,
        otp: None,
        // Binds the prompt to this exact desktop operation.
        authorization_context: format!(
            "desktop-ui|{action:?}|{container}|{}",
            file_name.unwrap_or("")
        ),
        import_summary: None,
    };
    state.approvals.request_click_only(request).await
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
    // Polling command: do NOT touch_human_activity here.
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
    state.touch_human_activity();

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
    state.set_unlocked();
    state.restart_session_monitor().await;

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
    state.set_unlocked();
    state.restart_session_monitor().await;
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
    state.set_unlocked();
    state.restart_session_monitor().await;
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
    perform_vault_lock(&state, "manual").await;
    Ok(())
}

/// Internal lock path shared by the manual command and the session monitor.
///
/// `reason` is recorded in the audit event detail. `manual` is the explicit
/// user action; `idle-timeout` and `session-cap` come from the monitor.
///
/// ADR-0020 §9: locking cannot retract bytes already delivered to an agent or
/// process. Auto-lock stops future access; it does not recall what already left.
async fn perform_vault_lock(state: &VaultState, reason: &str) {
    let mut guard = state.handle.lock().await;
    *guard = None;
    // Pending plans do not survive a lock. A plan is a snapshot-bound
    // authorization to delete a specific file; carrying one across a lock
    // would let a decision taken in one session be executed in the next,
    // after the user deliberately ended their access. Re-planning after
    // unlock is cheap and re-reads the file, which is the behaviour we want
    // anyway.
    state.pending_plans.lock().await.clear();
    // Same reasoning for the tray menu: a pending Approve row is a live
    // authorization, and it must not survive the user ending their session.
    if let Some(tray_state) = state.app.try_state::<tray::TrayApprovals>() {
        tray_state.clear();
    }
    tray::refresh(&state.app);
    // Stop the local gateway; the monitor task has already ended by the time
    // it calls this, so there is no race with itself.
    {
        let mut server_guard = state.servers.lock().await;
        if let Some(mut servers) = server_guard.take() {
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
    // Clear session bookkeeping so the monitor stops counting against this session.
    if let Ok(mut guard) = state.session_timer.unlocked_at.try_lock() {
        *guard = None;
    }
    let mut event = desktop_event(
        AuditAction::VaultLock,
        AuditDecision::Allowed,
        None,
        None,
        None,
        None,
        None,
    );
    event.detail = Some(format!("reason={reason}"));
    record_desktop_event(state, event);
    let _ = state.app.emit(AUTO_LOCK_EVENT, reason);
}

/// Spawn the session monitor for this vault state. It ticks every 30s and
/// auto-locks when either the idle timeout or the absolute session cap is
/// exceeded. Only human desktop activity refreshes the idle timer; MCP/agent
/// activity and polling/status commands do not.
fn spawn_session_monitor<R: Runtime>(state: SessionMonitorState<R>) -> JoinHandle<()> {
    spawn(async move {
        let interval = Duration::from_secs(SESSION_MONITOR_INTERVAL_SECS);
        loop {
            tokio::time::sleep(interval).await;

            let (idle_remaining, absolute_remaining) = state.timer.remaining_secs();
            let idle_remaining = idle_remaining.unwrap_or(0);
            let absolute_remaining = absolute_remaining.unwrap_or(0);

            if idle_remaining == 0 || absolute_remaining == 0 {
                let reason = if absolute_remaining == 0 {
                    "session-cap"
                } else {
                    "idle-timeout"
                };
                perform_vault_lock_internal(&state, reason).await;
                // After locking, the monitor keeps running but sees no unlocked
                // session, so it will not lock again until the next unlock.
                continue;
            }
        }
    })
}

async fn perform_vault_lock_internal<R: Runtime>(state: &SessionMonitorState<R>, reason: &str) {
    let mut guard = state.handle.lock().await;
    *guard = None;
    {
        let mut server_guard = state.servers.lock().await;
        if let Some(mut servers) = server_guard.take() {
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
    if let Ok(mut guard) = state.timer.unlocked_at.try_lock() {
        *guard = None;
    }
    let mut event = desktop_event(
        AuditAction::VaultLock,
        AuditDecision::Allowed,
        None,
        None,
        None,
        None,
        None,
    );
    event.detail = Some(format!("reason={reason}"));
    record_monitor_lock_event(&state.app, &state.handle, event);
    let _ = state.app.emit(AUTO_LOCK_EVENT, reason);
}

/// Record an audit event from the background monitor, which owns a clone of
/// the SharedHandle but not a full VaultState. Best-effort: if the handle is
/// gone or contended, skip rather than emit an unauthenticated event.
fn record_monitor_lock_event<R: Runtime>(
    app: &AppHandle<R>,
    handle: &SharedHandle,
    event: AuditEvent,
) {
    let Ok(root) = vault_root(app) else {
        return;
    };
    let Ok(guard) = handle.try_lock() else {
        return;
    };
    let Some(h) = guard.as_ref() else {
        return;
    };
    let audit_hmac_key = h.audit_hmac_key();
    if let Ok(log) = AuditLog::with_hmac_key(&root, audit_hmac_key) {
        let _ = log.record(&event);
    }
}

#[tauri::command]
async fn vault_change_passphrase(
    app: AppHandle,
    state: State<'_, VaultState>,
    current: String,
    new: String,
) -> Result<(), String> {
    state.touch_human_activity();
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
    state.touch_human_activity();
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
/// Not gated: the user is creating their own container through a form they
/// just filled in. The submit click IS the consent, and there is no
/// pre-existing protected content to guard -- the container does not exist
/// yet. A confirm dialog here would ask the user to re-approve the action they
/// initiated one interaction ago.
async fn vault_create_container(
    state: State<'_, VaultState>,
    name: String,
    mode: String,
    description: Option<String>,
) -> Result<(), String> {
    state.touch_human_activity();
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
    state.touch_human_activity();
    let mode = container_mode(&state, &name).await;
    // Destroys every file in the container, so it is confirmed for every mode,
    // for the same reason as `vault_delete_file`.
    let delete_mode = match mode {
        Some(SecurityMode::Direct) | Some(SecurityMode::Anonymized) | None => {
            Some(SecurityMode::Approval)
        }
        other => other,
    };
    if let Err(denied) = require_desktop_consent(
        &state,
        sv_mcp::AccessAction::DestroyContainer,
        &name,
        None,
        delete_mode,
    )
    .await
    {
        record_desktop_event(
            &state,
            desktop_event(
                AuditAction::DeleteContainer,
                AuditDecision::Denied,
                Some(name.clone()),
                None,
                mode,
                None,
                Some(denied.clone()),
            ),
        );
        return Err(denied);
    }
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
async fn audit_tail(
    state: State<'_, VaultState>,
    limit: usize,
    offset: usize,
) -> Result<AuditTailResponse, String> {
    // Polling command: do NOT touch_human_activity here.
    let result = with_handle(&state, |_handle| {
        let root = vault_root(&state.app).map_err(estr)?;
        read_audit_tail(&root, limit, offset)
    })
    .await;

    match &result {
        Ok(_) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::VaultInfo,
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
                AuditAction::VaultInfo,
                AuditDecision::Error,
                None,
                None,
                None,
                None,
                Some(error.clone()),
            ),
        ),
    }
    result.map(|tail| AuditTailResponse {
        events: tail.events,
        malformed_skipped: tail.malformed_skipped,
    })
}

#[tauri::command]
async fn audit_verify(state: State<'_, VaultState>) -> Result<VerifyReportView, String> {
    // Polling command: do NOT touch_human_activity here.
    let result = with_handle(&state, |handle| {
        let root = vault_root(&state.app).map_err(estr)?;
        let log = AuditLog::with_hmac_key(&root, handle.audit_hmac_key()).map_err(estr)?;
        let report = log.verify_chain().map_err(estr)?;
        Ok(VerifyReportView {
            ok: report.ok,
            entries: report.entries,
            legacy_entries: report.legacy_entries,
            first_broken: report.first_broken,
            reason: report.reason,
        })
    })
    .await;

    match &result {
        Ok(_) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::VaultInfo,
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
                AuditAction::VaultInfo,
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

const SCAN_CONTAINER: &str = "sv-scans";
const SCAN_REPORT_FILE_PREFIX: &str = "report-";
const SCAN_TRIAGE_FILE_PREFIX: &str = "triage-";

fn scan_report_path(root: &std::path::Path, id: &str) -> Result<std::path::PathBuf, String> {
    validate_scan_id(id)?;
    Ok(root
        .join(SCAN_CONTAINER)
        .join(format!("{SCAN_REPORT_FILE_PREFIX}{id}.json")))
}

/// Load a stored scan report by id. The id is validated before use.
fn load_stored_scan_report(root: &std::path::Path, id: &str) -> Result<StoredScanReport, String> {
    let path = scan_report_path(root, id)?;
    let text = std::fs::read_to_string(&path).map_err(estr)?;
    serde_json::from_str(&text).map_err(estr)
}

fn scan_triage_path(root: &std::path::Path, id: &str) -> Result<std::path::PathBuf, String> {
    validate_scan_id(id)?;
    Ok(root
        .join(SCAN_CONTAINER)
        .join(format!("{SCAN_TRIAGE_FILE_PREFIX}{id}.json")))
}

/// Accept only the exact shape produced by `encode_scan_id`: ASCII letters,
/// digits, `-`, and `_`. Reject `.`, `/`, `\`, and any other character so a
/// frontend-supplied id can never escape the `sv-scans` container.
fn validate_scan_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("invalid scan id".to_string());
    }
    if id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Ok(())
    } else {
        Err("invalid scan id".to_string())
    }
}

fn encode_scan_id(timestamp: chrono::DateTime<chrono::Utc>, suffix: &str) -> String {
    format!("{}-{}", timestamp.timestamp_millis(), suffix)
}

fn scan_report_to_view(
    id: String,
    report: &ScanReport,
    scanned_path: String,
    triage: &TriageState,
) -> ScanReportView {
    ScanReportView {
        id,
        scanned_path,
        created_at: chrono::Utc::now().to_rfc3339(),
        coverage: ScanCoverageView {
            files_scanned: report.coverage.files_scanned,
            files_ignored: report.coverage.files_ignored,
            files_skipped: report.coverage.files_skipped,
            bytes_scanned: report.coverage.bytes_scanned,
            suppressed: report
                .coverage
                .suppressed
                .iter()
                .map(|s| ScanSuppressedView {
                    reason: s.reason.label().to_string(),
                    count: s.count,
                })
                .collect(),
        },
        findings: report
            .findings
            .iter()
            .enumerate()
            .map(|(index, f)| ScanFindingView {
                path: f.path.to_string_lossy().to_string(),
                line: f.line,
                start: f.start,
                end: f.end,
                kind: finding_kind_label(&f.kind),
                confidence: serde_json::to_string(&f.confidence)
                    .map_err(estr)
                    .unwrap_or_else(|_| {
                        format!("{:?}", f.confidence).trim_matches('"').to_string()
                    }),
                preview: f.preview.clone(),
                verdict: triage.verdicts.get(&index).cloned(),
            })
            .collect(),
    }
}

fn finding_kind_label(kind: &FindingKind) -> String {
    match kind {
        FindingKind::Pii(category) => {
            let label = serde_json::to_string(category)
                .map_err(estr)
                .unwrap_or_else(|_| format!("{:?}", category).trim_matches('"').to_string())
                .to_lowercase();
            format!("pii:{label}")
        }
        FindingKind::Secret { rule_id } => format!("secret:{rule_id}"),
        FindingKind::Jurisdiction {
            pack_id,
            rule_id,
            validated,
            ..
        } => {
            let validated_flag = match validated {
                Some(true) => ":valid",
                Some(false) => ":invalid",
                None => "",
            };
            format!("jurisdiction:{pack_id}/{rule_id}{validated_flag}")
        }
    }
}

/// Mints a random, opaque plan id. The id carries no path information.
fn mint_plan_id() -> String {
    let bytes = sv_core::sv_crypto::random_bytes(16)
        .expect("random_bytes must never fail in desktop runtime");
    format!("plan-{}", hex::encode(bytes))
}

fn parse_min_confidence(s: Option<String>) -> Result<Option<Confidence>, String> {
    match s {
        None => Ok(None),
        Some(text) => match text.to_ascii_lowercase().as_str() {
            "low" => Ok(Some(Confidence::Low)),
            "medium" => Ok(Some(Confidence::Medium)),
            "high" => Ok(Some(Confidence::High)),
            other => Err(format!("unknown confidence: {other}")),
        },
    }
}

/// In-memory triage state for a report. Persisted in vault state only.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TriageState {
    verdicts: std::collections::HashMap<usize, String>,
}

impl TriageState {
    fn load(root: &std::path::Path, id: &str) -> Self {
        let Ok(path) = scan_triage_path(root, id) else {
            return Self::default();
        };
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    fn save(&self, root: &std::path::Path, id: &str) -> Result<(), String> {
        let path = scan_triage_path(root, id)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(estr)?;
        }
        let text = serde_json::to_string(self).map_err(estr)?;
        std::fs::write(&path, text).map_err(estr)
    }
}

#[tauri::command]
async fn scan_run(
    state: State<'_, VaultState>,
    path: String,
    packs: Vec<String>,
    min_confidence: Option<String>,
) -> Result<ScanReportView, String> {
    state.touch_human_activity();
    let result = with_handle(&state, |_handle| {
        let root = std::path::Path::new(&path);
        if !root.is_dir() {
            return Err("scan path is not a directory".to_string());
        }
        let config = ScanConfig {
            packs,
            ..Default::default()
        };
        let mut report = sv_scan::scan_project(root, &config).map_err(estr)?;
        if let Some(min) = parse_min_confidence(min_confidence)? {
            report.findings.retain(|f| f.confidence >= min);
        }
        let id = encode_scan_id(chrono::Utc::now(), "run");
        let vault_root = vault_root(&state.app).map_err(estr)?;
        let report_path = scan_report_path(&vault_root, &id)?;
        if let Some(parent) = report_path.parent() {
            std::fs::create_dir_all(parent).map_err(estr)?;
        }
        // The on-disk copy intentionally drops the per-finding fingerprints,
        // so it is never a brute-force oracle for small-domain values and
        // cannot be used to link files after load.
        let stored = StoredScanReport {
            id: id.clone(),
            scanned_path: path,
            created_at: chrono::Utc::now(),
            report: report.clone(),
        };
        let text = serde_json::to_string(&stored).map_err(estr)?;
        std::fs::write(&report_path, text).map_err(estr)?;
        let triage = TriageState::default();
        Ok((id, report, stored.scanned_path, triage))
    })
    .await;

    // The in-memory report keeps its per-scan salt for the current session
    // only; reveal requires the live finding.
    let result = result.map(|(id, report, scanned_path, triage)| {
        state
            .active_scans
            .blocking_lock()
            .insert(id.clone(), report.clone());
        scan_report_to_view(id, &report, scanned_path, &triage)
    });

    match &result {
        Ok(_) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::ScanRun,
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
                AuditAction::ScanRun,
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

/// Stored scan report shape on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredScanReport {
    id: String,
    scanned_path: String,
    created_at: chrono::DateTime<chrono::Utc>,
    report: ScanReport,
}

#[tauri::command]
async fn scan_store(state: State<'_, VaultState>, report_id: String) -> Result<(), String> {
    state.touch_human_activity();
    let result = with_handle(&state, |handle| {
        let vault_root = vault_root(&state.app).map_err(estr)?;
        let report_path = scan_report_path(&vault_root, &report_id)?;
        if !report_path.exists() {
            return Err(format!("report {report_id} not found"));
        }
        ensure_scan_container(handle, &vault_root)?;
        let dest = std::path::Path::new(SCAN_CONTAINER)
            .join(format!("{SCAN_REPORT_FILE_PREFIX}{report_id}.json"));
        let source_text = std::fs::read_to_string(&report_path).map_err(estr)?;
        handle
            .write_file(
                SCAN_CONTAINER,
                &dest.to_string_lossy(),
                source_text.as_bytes(),
            )
            .map_err(estr)
    })
    .await;

    match &result {
        Ok(_) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::ScanStore,
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
                AuditAction::ScanStore,
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

fn ensure_scan_container(
    handle: &VaultHandle,
    _vault_root: &std::path::Path,
) -> Result<(), String> {
    let info = handle.list_containers().map_err(estr)?;
    if info.iter().any(|c| c.name == SCAN_CONTAINER) {
        return Ok(());
    }
    handle
        .create_container(
            SCAN_CONTAINER,
            SecurityMode::Direct,
            Some("Stored scan reports".to_string()),
        )
        .map_err(estr)
}

#[tauri::command]
async fn scan_history_list(state: State<'_, VaultState>) -> Result<Vec<ScanSummaryView>, String> {
    // Polling command: do NOT touch_human_activity here.
    let result = with_handle(&state, |_handle| {
        let vault_root = vault_root(&state.app).map_err(estr)?;
        let dir = vault_root.join(SCAN_CONTAINER);
        let mut summaries = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries {
                let entry = entry.map_err(estr)?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !name.starts_with(SCAN_REPORT_FILE_PREFIX) || !name.ends_with(".json") {
                    continue;
                }
                let text = std::fs::read_to_string(entry.path()).map_err(estr)?;
                if let Ok(stored) = serde_json::from_str::<StoredScanReport>(&text) {
                    summaries.push(ScanSummaryView {
                        id: stored.id,
                        scanned_path: stored.scanned_path,
                        created_at: stored.created_at.to_rfc3339(),
                        finding_count: stored.report.findings.len(),
                    });
                }
            }
        }
        summaries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(summaries)
    })
    .await;

    match &result {
        Ok(_) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::ScanRun,
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
                AuditAction::ScanRun,
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
async fn remediate_plan_file(
    state: State<'_, VaultState>,
    scan_id: String,
    finding_path: String,
    adapter: String,
) -> Result<PlanView, String> {
    state.touch_human_activity();

    let adapter_enum =
        ConsumerAdapter::parse(&adapter).ok_or_else(|| "invalid adapter".to_string())?;

    let result = with_handle(&state, |handle| {
        let vault_root = vault_root(&state.app).map_err(estr)?;
        let stored = load_stored_scan_report(&vault_root, &scan_id)?;
        let project_root = std::path::Path::new(&stored.scanned_path)
            .canonicalize()
            .map_err(estr)?;
        let project_id = stored.id.clone();

        let key = sv_remediate::PlanKey::from_bytes(&handle.remediation_plan_key())
            .map_err(|error| format!("invalid plan key: {error}"))?;

        let relative = std::path::Path::new(&finding_path);
        // The manifest lives beside the consumed file with a `.vault-manifest.json`
        // suffix so consumers never read it as the value.
        let manifest_name = format!(
            "{}.vault-manifest.json",
            relative
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| "invalid finding path".to_string())?
        );
        let manifest_path = relative.with_file_name(manifest_name);

        let plan = ManagedFilePlan::build(
            &project_id,
            relative,
            &project_root,
            adapter_enum,
            &manifest_path,
            sv_remediate::managed::SharedBinding::Independent,
            &key,
        )
        .map_err(|error| error.to_string())?;

        // Eligibility refusal comes back as a variant, not an error path.
        let eligibility = match sv_remediate::managed::check_eligibility(relative) {
            sv_remediate::managed::Eligibility::WhollySensitive => "wholly-sensitive".to_string(),
            sv_remediate::managed::Eligibility::PartlySensitive { reason } => reason,
        };

        let plan_id = mint_plan_id();
        let snapshot_digest = plan.snapshot_digest;
        let view = PlanView {
            plan_id: plan_id.clone(),
            path: plan.path.to_string_lossy().to_string(),
            adapter: plan.adapter.as_str().to_string(),
            eligibility,
            manifest_path: plan.manifest_path.to_string_lossy().to_string(),
            identity_enforced: cfg!(unix),
            confirm_digest: hex::encode(snapshot_digest.as_bytes()),
        };

        let pending = PendingPlan {
            id: plan_id,
            project_root,
            plan,
            snapshot_digest,
            created_at: chrono::Utc::now(),
        };

        // Holding the pending-plans lock across a synchronous vault call
        // keeps the registry consistent with the handle lifetime.
        state
            .pending_plans
            .blocking_lock()
            .insert(pending.id.clone(), pending);

        Ok(view)
    })
    .await;

    match &result {
        Ok(_) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::PlanCreate,
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
                AuditAction::PlanCreate,
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
async fn remediate_plan_list(state: State<'_, VaultState>) -> Result<Vec<PlanView>, String> {
    // Polling command: do NOT touch_human_activity here.
    let plans = state.pending_plans.lock().await;
    Ok(plans
        .values()
        .map(|p| PlanView {
            plan_id: p.id.clone(),
            path: p.plan.path.to_string_lossy().to_string(),
            adapter: p.plan.adapter.as_str().to_string(),
            eligibility: "wholly-sensitive".to_string(),
            manifest_path: p.plan.manifest_path.to_string_lossy().to_string(),
            identity_enforced: cfg!(unix),
            confirm_digest: hex::encode(p.snapshot_digest.as_bytes()),
        })
        .collect())
}

#[tauri::command]
async fn remediate_execute(
    state: State<'_, VaultState>,
    plan_id: String,
    confirm_digest: String,
) -> Result<IngestView, String> {
    state.touch_human_activity();

    let result = with_handle(&state, |handle| {
        let vault_root = vault_root(&state.app).map_err(estr)?;
        let key = sv_remediate::PlanKey::from_bytes(&handle.remediation_plan_key())
            .map_err(|error| format!("invalid plan key: {error}"))?;

        let plan = {
            let mut plans = state.pending_plans.blocking_lock();
            // Drop everything past its TTL first, so an expired plan is
            // indistinguishable from one that never existed.
            let now = chrono::Utc::now();
            plans.retain(|_, p| (now - p.created_at).num_seconds() < PLAN_TTL_SECS);
            let pending = plans
                .get(&plan_id)
                .ok_or_else(|| "unknown plan id".to_string())?
                .clone();
            let expected = hex::encode(pending.snapshot_digest.as_bytes());
            // `ct_eq` is only constant-time across equal-length slices, and
            // on unequal lengths it does not compare at all. Reject a
            // wrong-length input first, so the constant-time path is the
            // only one that can reach a comparison.
            if confirm_digest.len() != expected.len()
                || !bool::from(confirm_digest.as_bytes().ct_eq(expected.as_bytes()))
            {
                return Err("plan digest mismatch".to_string());
            }
            pending
        };

        let assurance = if cfg!(unix) {
            IdentityAssurance::Enforced
        } else {
            IdentityAssurance::AcknowledgedUnavailable
        };
        let identity_enforced = cfg!(unix);

        let mut sink = HandleSink::new(handle, vault_root);
        let ingest_status = sv_remediate::managed::ingest_managed_file(
            &plan.plan,
            &plan.project_root,
            &key,
            assurance,
            &mut sink,
        )
        .map_err(|error| error.to_string())?;

        // Terminal outcome: remove the plan from the registry regardless of
        // success, so a retry requires rebuilding and re-approving.
        state.pending_plans.blocking_lock().remove(&plan_id);

        let view = match ingest_status {
            ManagedIngestStatus::Ingested { manifest } => IngestView {
                status: "ingested".to_string(),
                manifest: Some(manifest.to_string_lossy().to_string()),
                reason: None,
                identity_enforced,
            },
            ManagedIngestStatus::StartupCheckFailed { reason } => IngestView {
                status: "startup-check-failed".to_string(),
                manifest: None,
                reason: Some(reason),
                identity_enforced,
            },
            ManagedIngestStatus::Ineligible { reason } => IngestView {
                status: "ineligible".to_string(),
                manifest: None,
                reason: Some(reason),
                identity_enforced,
            },
            ManagedIngestStatus::Failed { reason } => IngestView {
                status: "failed".to_string(),
                manifest: None,
                reason: Some(reason),
                identity_enforced,
            },
        };

        Ok(view)
    })
    .await;

    // The approval moment is its own audited event, separate from the
    // execution that follows it: a refused confirmation must leave a record
    // even though nothing was executed. It is emitted here rather than inside
    // the closure because `record_desktop_event` takes the handle mutex that
    // `with_handle` still holds in there, and would silently drop the event.
    record_desktop_event(
        &state,
        desktop_event(
            AuditAction::PlanApprove,
            match &result {
                Err(error) if error == "plan digest mismatch" => AuditDecision::Denied,
                _ => AuditDecision::Allowed,
            },
            None,
            None,
            None,
            None,
            None,
        ),
    );

    match &result {
        Ok(view) => {
            let decision = if view.status == "ingested" {
                AuditDecision::Allowed
            } else {
                AuditDecision::Error
            };
            record_desktop_event(
                &state,
                desktop_event(
                    AuditAction::PlanExecute,
                    decision,
                    None,
                    None,
                    None,
                    None,
                    view.reason.clone(),
                ),
            );
        }
        Err(error) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::PlanExecute,
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
async fn remediate_restore(
    state: State<'_, VaultState>,
    plan_id_or_ref: String,
) -> Result<RestoreView, String> {
    state.touch_human_activity();

    let result = with_handle(&state, |handle| {
        let vault_root = vault_root(&state.app).map_err(estr)?;
        let mut sink = HandleSink::new(handle, vault_root.clone());

        // If the argument matches a known plan id, prefer the stored plan
        // so the renderer cannot point restore at an arbitrary path.
        let (record, root) =
            if let Some(pending) = state.pending_plans.blocking_lock().remove(&plan_id_or_ref) {
                (
                    sv_remediate::RecoveryRecord {
                        plan_digest: pending.snapshot_digest,
                        project_id: pending.plan.project_id,
                        path: pending.plan.path.clone(),
                        identity: pending.plan.identity,
                        snapshot_digest: pending.snapshot_digest,
                        snapshot_ref: "".to_string(), // unused for spanless restore; ingest has not run
                        discovery: DiscoveryPolicy::Opaque,
                        locator: None,
                        span: None,
                        replacement: None,
                        created_at: pending.created_at,
                    },
                    pending.project_root,
                )
            } else {
                return Err("unknown plan id".to_string());
            };

        // Managed-file restore is a full-file rollback. For pending plans we
        // have not yet ingested, there is nothing to restore; report that.
        if record.snapshot_ref.is_empty() {
            return Ok(RestoreView {
                restored: false,
                reason: Some("plan has not been executed yet".to_string()),
            });
        }

        // Restore expects a recovery record written by the sink. Pending
        // plans do not have one, so this command cannot run against them.
        // Real restore requires loading the recovery record from the vault.
        let _ = (&record, &root, &mut sink);
        Err("pending plan cannot be restored before execution".to_string())
    })
    .await;

    match &result {
        Ok(RestoreView { restored: true, .. }) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::PlanExecute,
                AuditDecision::Allowed,
                None,
                None,
                None,
                None,
                None,
            ),
        ),
        _ => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::PlanExecute,
                AuditDecision::Error,
                None,
                None,
                None,
                None,
                result.as_ref().err().cloned(),
            ),
        ),
    }
    result
}

#[tauri::command]
async fn scan_report_get(
    state: State<'_, VaultState>,
    id: String,
) -> Result<ScanReportView, String> {
    state.touch_human_activity();
    let result = with_handle(&state, |_handle| {
        let vault_root = vault_root(&state.app).map_err(estr)?;
        let report_path = scan_report_path(&vault_root, &id)?;
        let text = std::fs::read_to_string(&report_path).map_err(estr)?;
        let stored: StoredScanReport = serde_json::from_str(&text).map_err(estr)?;
        let triage = TriageState::load(&vault_root, &id);
        Ok(scan_report_to_view(
            stored.id,
            &stored.report,
            stored.scanned_path,
            &triage,
        ))
    })
    .await;

    match &result {
        Ok(_) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::ScanRun,
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
                AuditAction::ScanRun,
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

/// Reveal the first four characters of a matched value.
///
/// This only works for scan reports produced in this process. The fingerprint
/// is dropped before the report is written to disk, so reports loaded from
/// a previous session cannot be revealed and must be re-scanned.
#[tauri::command]
async fn scan_reveal(
    state: State<'_, VaultState>,
    report_id: String,
    finding_index: usize,
) -> Result<String, String> {
    state.touch_human_activity();
    let result = with_handle(&state, |_handle| {
        // Reveal requires the in-memory report: the fingerprint salt never
        // left the process, and the fingerprints themselves are skipped on
        // serialization, so a loaded report cannot satisfy this check.
        let live_report = {
            let guard = state
                .active_scans
                .try_lock()
                .map_err(|_| "scan state unavailable; try again")?;
            guard
                .get(&report_id)
                .cloned()
                .ok_or("report loaded from disk; re-scan to reveal")?
        };
        let finding = live_report
            .findings
            .get(finding_index)
            .ok_or_else(|| format!("finding {finding_index} not found"))?;
        let vault_root = vault_root(&state.app).map_err(estr)?;
        let stored_path = scan_report_path(&vault_root, &report_id)?;
        let stored: StoredScanReport =
            serde_json::from_str(&std::fs::read_to_string(&stored_path).map_err(estr)?)
                .map_err(estr)?;
        let scanned_root = std::path::Path::new(&stored.scanned_path);
        let file_path = scanned_root.join(&finding.path);
        let content = std::fs::read_to_string(&file_path).map_err(estr)?;

        if finding.end > content.len()
            || !content.is_char_boundary(finding.start)
            || !content.is_char_boundary(finding.end)
        {
            return Err("file changed since scan; re-scan to reveal".to_string());
        }
        let value = &content[finding.start..finding.end];

        // Session-only fingerprint check. The salt is per-process and never
        // persisted, so this cannot be used to link values across scans.
        let current = matched_fingerprint(value, live_report.config_salt);
        if current
            .as_bytes()
            .ct_ne(finding.matched_fingerprint.as_bytes())
            .into()
        {
            return Err("file changed since scan; re-scan to reveal".to_string());
        }

        Ok(sv_scan::mask(value))
    })
    .await;

    let audit_event = match &result {
        Ok(_) => {
            let mut event = desktop_event(
                AuditAction::ScanReveal,
                AuditDecision::Allowed,
                Some(report_id.clone()),
                None,
                None,
                None,
                None,
            );
            event.detail = Some(format!("finding_index={finding_index}"));
            if let Ok(vault_root) = vault_root(&state.app) {
                if let Ok(report_path) = scan_report_path(&vault_root, &report_id) {
                    if let Ok(text) = std::fs::read_to_string(&report_path) {
                        if let Ok(stored) = serde_json::from_str::<StoredScanReport>(&text) {
                            if let Some(finding) = stored.report.findings.get(finding_index) {
                                event.file_name = Some(finding.path.to_string_lossy().to_string());
                            }
                        }
                    }
                }
            }
            event
        }
        Err(_) => {
            let mut event = desktop_event(
                AuditAction::ScanReveal,
                AuditDecision::Error,
                Some(report_id.clone()),
                None,
                None,
                None,
                result.as_ref().err().cloned(),
            );
            event.detail = Some(format!("finding_index={finding_index}"));
            event
        }
    };
    record_desktop_event(&state, audit_event);
    result
}

/// Compute a process-local fingerprint of matched bytes using the per-scan salt.
fn matched_fingerprint(value: &str, salt: [u8; 32]) -> String {
    sv_scan::matched_fingerprint(value, salt)
}

#[tauri::command]
async fn scan_triage_set(
    state: State<'_, VaultState>,
    report_id: String,
    finding_index: usize,
    verdict: String,
) -> Result<(), String> {
    state.touch_human_activity();
    if !matches!(
        verdict.as_str(),
        "accept" | "false_positive" | "ignore_rule"
    ) {
        return Err(format!("invalid verdict: {verdict}"));
    }
    let result = with_handle(&state, |_handle| {
        let vault_root = vault_root(&state.app).map_err(estr)?;
        let mut triage = TriageState::load(&vault_root, &report_id);
        triage.verdicts.insert(finding_index, verdict);
        triage.save(&vault_root, &report_id)
    })
    .await;

    match &result {
        Ok(_) => record_desktop_event(
            &state,
            desktop_event(
                AuditAction::PlanCreate,
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
                AuditAction::PlanCreate,
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
async fn vault_list_files(
    state: State<'_, VaultState>,
    container: String,
) -> Result<Vec<FileInfo>, String> {
    // Deliberately NOT gated, unlike read/write/delete.
    //
    // The MCP path does prompt for a listing in an Approval-mode container, but
    // the desktop calls this on every navigation into a container AND again
    // after each write (`fileStore.refresh`). Gating it would raise a second
    // prompt immediately after the write prompt the user just answered, for a
    // metadata listing that reveals names rather than content. Prompts that
    // arrive in pairs for one intended action are what trains a user to click
    // through without reading, which costs more than this listing protects.
    //
    // The consequence, stated plainly: a local operator at an unlocked vault
    // can enumerate file names in an Approval- or OTP-mode container without a
    // prompt. Reading, writing, or deleting any of them still prompts.
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
    lease_id: Option<String>,
    agent_id: Option<String>,
) -> Result<(), String> {
    state.touch_human_activity();
    let resource_ref = format!("container:{container}:file:{file_name}");
    let args = vec![
        container.clone(),
        file_name.clone(),
        format!("{}", content.len()),
    ];
    if !require_lease(
        &state,
        lease_id.as_deref().unwrap_or(""),
        agent_id.as_deref().unwrap_or(""),
        &resource_ref,
        "write_file",
        &args,
        &resource_ref,
    )
    .await
        && lease_id.is_some()
    {
        return Err("invalid or expired wake lease".into());
    }
    let mode = container_mode(&state, &container).await;
    let byte_size = content.len();
    if let Err(denied) = require_desktop_consent(
        &state,
        sv_mcp::AccessAction::WriteFile,
        &container,
        Some(&file_name),
        mode,
    )
    .await
    {
        record_desktop_event(
            &state,
            desktop_event(
                AuditAction::WriteFile,
                AuditDecision::Denied,
                Some(container.clone()),
                Some(file_name.clone()),
                mode,
                Some(byte_size),
                Some(denied.clone()),
            ),
        );
        return Err(denied);
    }
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
    lease_id: Option<String>,
    agent_id: Option<String>,
) -> Result<Vec<u8>, String> {
    state.touch_human_activity();
    let resource_ref = format!("container:{container}:file:{file_name}");
    let args = vec![container.clone(), file_name.clone()];
    if !require_lease(
        &state,
        lease_id.as_deref().unwrap_or(""),
        agent_id.as_deref().unwrap_or(""),
        &resource_ref,
        "read_file",
        &args,
        &resource_ref,
    )
    .await
        && lease_id.is_some()
    {
        return Err("invalid or expired wake lease".into());
    }
    let mode = container_mode(&state, &container).await;
    // Enforce the container's mode, do not merely label the audit with it.
    if let Err(denied) = require_desktop_consent(
        &state,
        sv_mcp::AccessAction::ReadFile,
        &container,
        Some(&file_name),
        mode,
    )
    .await
    {
        record_desktop_event(
            &state,
            desktop_event(
                AuditAction::ReadFile,
                AuditDecision::Denied,
                Some(container.clone()),
                Some(file_name.clone()),
                mode,
                None,
                Some(denied.clone()),
            ),
        );
        return Err(denied);
    }
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

/// Reveal the audit log in the OS file manager.
///
/// Opens the containing folder with the log selected rather than opening the
/// file itself, which would hand it to whatever application claims `.jsonl`.
///
/// Not gated and not audited: this reveals a location, not vault content. The
/// audit log is already readable in the app, and the folder is the user's own
/// application-data directory.
#[tauri::command]
async fn open_audit_folder(app: AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;

    let root = vault_root(&app)?;
    let active = root.join("audit.jsonl");
    // Reveal the log when it exists; otherwise fall back to the vault folder,
    // which does. Revealing a non-existent path fails on some platforms and
    // succeeds confusingly on others.
    let target = if active.exists() { active } else { root };
    app.opener().reveal_item_in_dir(&target).map_err(estr)
}

/// Decrypt one file and write it to a location the user picks.
///
/// # Why this is gated like a read, plus a marker
///
/// Export IS a read -- the plaintext is produced exactly as `vault_read_file`
/// produces it -- so it takes the same container-mode gate (ADR-0023). But it
/// does one more thing that a read does not: it leaves a decrypted copy
/// OUTSIDE the vault, where no mode, lock, or audit applies to it ever again.
/// That copy is the user's to manage and cannot be recalled.
///
/// So the audit records `AuditAction::ReadFile` -- which is what happened to
/// the vault -- with `detail` saying the bytes were exported. `AgentExport`
/// exists but means bulk export of agent identities; reusing it here would
/// file this under an unrelated action.
///
/// The destination path is NOT audited. It is chosen by the user in a native
/// dialog, it frequently contains a real name or project, and the audit log is
/// a durable artifact that gets shared. The fact of the export is what a
/// reviewer needs; where the user filed it is not.
///
/// Returns the destination as a display string for the confirmation toast, or
/// `None` when the user cancels the dialog.
#[tauri::command]
async fn vault_export_file(
    app: AppHandle,
    state: State<'_, VaultState>,
    container: String,
    file_name: String,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    state.touch_human_activity();
    let mode = container_mode(&state, &container).await;
    // Same gate as a read: this produces the same plaintext.
    if let Err(denied) = require_desktop_consent(
        &state,
        sv_mcp::AccessAction::ReadFile,
        &container,
        Some(&file_name),
        mode,
    )
    .await
    {
        let mut event = desktop_event(
            AuditAction::ReadFile,
            AuditDecision::Denied,
            Some(container.clone()),
            Some(file_name.clone()),
            mode,
            None,
            Some(denied.clone()),
        );
        event.detail = Some("export to disk".into());
        record_desktop_event(&state, event);
        return Err(denied);
    }

    // Ask for the destination BEFORE decrypting. A cancelled dialog then means
    // no plaintext was ever produced, rather than a decrypted buffer held in
    // memory for a save that never happens.
    let suggested = std::path::Path::new(&file_name);
    let mut builder = app.dialog().file().set_title("Export file");
    if let Some(name) = suggested.file_name().and_then(|n| n.to_str()) {
        builder = builder.set_file_name(name);
    }
    if let Some(ext) = suggested.extension().and_then(|e| e.to_str()) {
        builder = builder.add_filter(format!("{ext} file"), &[ext]);
    }
    let Some(dest) = builder.blocking_save_file() else {
        // User cancelled. Nothing was decrypted and nothing is recorded: no
        // access to the file's content took place.
        return Ok(None);
    };
    let dest_path = dest
        .into_path()
        .map_err(|e| format!("unusable destination path: {e}"))?;

    let bytes = match with_handle(&state, |handle| {
        handle.read_file(&container, &file_name).map_err(estr)
    })
    .await
    {
        Ok(bytes) => bytes,
        Err(error) => {
            let mut event = desktop_event(
                AuditAction::ReadFile,
                AuditDecision::Error,
                Some(container.clone()),
                Some(file_name.clone()),
                mode,
                None,
                Some(error.clone()),
            );
            event.detail = Some("export to disk".into());
            record_desktop_event(&state, event);
            return Err(error);
        }
    };

    let byte_size = bytes.len();
    // Write through a temporary file in the destination directory and rename,
    // so an interrupted export cannot leave a half-written file that looks
    // complete. `atomicwrites` is already used elsewhere in this crate.
    let write_result = {
        use atomicwrites::{AtomicFile, OverwriteBehavior};
        use std::io::Write;
        let file = AtomicFile::new(&dest_path, OverwriteBehavior::AllowOverwrite);
        file.write(|f| f.write_all(&bytes)).map_err(estr)
    };

    match write_result {
        Ok(()) => {
            let mut event = desktop_event(
                AuditAction::ReadFile,
                AuditDecision::Allowed,
                Some(container.clone()),
                Some(file_name.clone()),
                mode,
                Some(byte_size),
                None,
            );
            // Marks this read as one that left a decrypted copy outside the
            // vault. The destination is deliberately absent; see the doc above.
            event.detail = Some("export to disk".into());
            record_desktop_event(&state, event);
            Ok(Some(dest_path.display().to_string()))
        }
        Err(error) => {
            let mut event = desktop_event(
                AuditAction::ReadFile,
                AuditDecision::Error,
                Some(container),
                Some(file_name),
                mode,
                Some(byte_size),
                Some(error.clone()),
            );
            event.detail = Some("export to disk".into());
            record_desktop_event(&state, event);
            Err(error)
        }
    }
}

#[tauri::command]
async fn vault_delete_file(
    state: State<'_, VaultState>,
    container: String,
    file_name: String,
    lease_id: Option<String>,
    agent_id: Option<String>,
) -> Result<(), String> {
    state.touch_human_activity();
    let resource_ref = format!("container:{container}:file:{file_name}");
    let args = vec![container.clone(), file_name.clone()];
    if !require_lease(
        &state,
        lease_id.as_deref().unwrap_or(""),
        agent_id.as_deref().unwrap_or(""),
        &resource_ref,
        "delete_file",
        &args,
        &resource_ref,
    )
    .await
        && lease_id.is_some()
    {
        return Err("invalid or expired wake lease".into());
    }
    let mode = container_mode(&state, &container).await;
    // Deletion is irreversible, so it is confirmed for EVERY mode -- including
    // DIRECT. Elsewhere DIRECT means "no human gate", which is a statement
    // about reads and writes that can be repeated or corrected; a deleted file
    // cannot be. `require_desktop_consent` would return Ok for DIRECT, so the
    // prompt is raised explicitly here instead.
    let delete_mode = match mode {
        Some(SecurityMode::Direct) | Some(SecurityMode::Anonymized) | None => {
            Some(SecurityMode::Approval)
        }
        other => other,
    };
    if let Err(denied) = require_desktop_consent(
        &state,
        sv_mcp::AccessAction::DeleteFile,
        &container,
        Some(&file_name),
        delete_mode,
    )
    .await
    {
        record_desktop_event(
            &state,
            desktop_event(
                AuditAction::DeleteFile,
                AuditDecision::Denied,
                Some(container.clone()),
                Some(file_name.clone()),
                mode,
                None,
                Some(denied.clone()),
            ),
        );
        return Err(denied);
    }
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
    state.touch_human_activity();
    state.approvals.respond(id, approved, otp).await
}

/// Wake-on-demand request endpoint. The response is intentionally generic:
/// the agent cannot tell whether the resource exists (ADR-0020 §8). Wake
/// requests never unlock the vault and never refresh the idle timer.
#[tauri::command]
async fn wake_request(
    state: State<'_, VaultState>,
    agent_id: String,
    opaque_resource_ref: String,
) -> Result<WakeResult, String> {
    // Agent-originated activity must not refresh the idle timer (ADR-0020 §9).
    Ok(state
        .wake_queue
        .request(agent_id, opaque_resource_ref)
        .await)
}

/// List pending wake requests for the UI. Polling command: no idle refresh.
#[tauri::command]
async fn wake_list(state: State<'_, VaultState>) -> Result<Vec<WakePrompt>, String> {
    Ok(state.wake_queue.list().await)
}

/// Human responds to a wake request. This is a deliberate human action, so it
/// refreshes the idle timer. If approved, the request is recorded as an
/// authorized wake; the actual lease is issued when the agent later attempts
/// the specific operation (ADR-0020 §10).
#[tauri::command]
async fn wake_respond(state: State<'_, VaultState>, id: u64, approved: bool) -> Result<(), String> {
    state.touch_human_activity();
    let Some(request) = state.wake_queue.respond(id, approved).await else {
        return Err("wake request not found".into());
    };
    if approved {
        // Record an authorized wake for this agent/resource. The lease itself
        // is issued later, bound to the exact operation and arguments.
        state
            .leases
            .record_authorized_wake(&request.signature, &request.agent_id, &state.session_id())
            .await;
        record_desktop_event(
            &state,
            desktop_event(
                AuditAction::VaultInfo,
                AuditDecision::Allowed,
                None,
                None,
                None,
                None,
                Some(format!(
                    "wake-approved agent={} resource={}",
                    request.agent_id, request.opaque_resource_ref
                )),
            ),
        );
    } else {
        record_desktop_event(
            &state,
            desktop_event(
                AuditAction::VaultInfo,
                AuditDecision::Denied,
                None,
                None,
                None,
                None,
                Some(format!(
                    "wake-denied agent={} resource={}",
                    request.agent_id, request.opaque_resource_ref
                )),
            ),
        );
    }
    Ok(())
}

/// Prepare a material access after a wake authorization. Returns a lease id for
/// Direct mode, or an indication that further per-mode consent is required
/// (Approval / OTP). The lease is short-lived and single-use (ADR-0020 §10).
#[tauri::command]
async fn wake_prepare_access(
    state: State<'_, VaultState>,
    params: LeaseParams,
) -> Result<String, String> {
    // This is an explicit human/agent-initiated access preparation. Refreshing
    // the idle timer is acceptable here because it follows a wake approval and
    // represents an active access attempt.
    state.touch_human_activity();

    let resource_signature = wake_signature(&params.agent_id, &params.resource_ref);
    let authorized = state
        .leases
        .has_authorized_wake(&resource_signature, &params.agent_id, &state.session_id())
        .await;
    if !authorized {
        return Err("wake authorization required".into());
    }

    let operation_digest = digest_string(&params.operation);
    let args_digest = digest_string(&params.args.join("|"));

    match params.mode.to_ascii_uppercase().as_str() {
        "DIRECT" => {
            let lease = state
                .leases
                .issue(
                    &params.agent_id,
                    &resource_signature,
                    &operation_digest,
                    &args_digest,
                    &params.destination,
                    &state.session_id(),
                    "v1",
                )
                .await;
            let wake_lease = WakeLease {
                lease_id: lease.id.clone(),
                expires_at_secs: WAKE_LEASE_TTL_SECS,
            };
            let _ = state.app.emit(WAKE_LEASE_EVENT, wake_lease);
            Ok(lease.id)
        }
        "APPROVAL" => {
            Err("approval_required: explicit human approval needed for this operation".into())
        }
        "OTP" => Err("otp_required: one-time code required for this operation".into()),
        other => Err(format!("unsupported wake mode: {other}")),
    }
}

/// Check a lease for an exact operation and consume it. Returns true if a valid
/// lease was found and consumed. This helper enforces single-use binding to
/// agent, resource, operation, args, destination, session, and policy version.
async fn require_lease(
    state: &VaultState,
    lease_id: &str,
    agent_id: &str,
    resource_ref: &str,
    operation: &str,
    args: &[String],
    destination: &str,
) -> bool {
    if lease_id.is_empty() || agent_id.is_empty() {
        return false;
    }
    let resource_signature = wake_signature(agent_id, resource_ref);
    let operation_digest = digest_string(operation);
    let args_digest = digest_string(&args.join("|"));
    state
        .leases
        .checkout(
            lease_id,
            agent_id,
            &resource_signature,
            &operation_digest,
            &args_digest,
            destination,
            &state.session_id(),
            "v1",
        )
        .await
}

#[tauri::command]
async fn mcp_status(state: State<'_, VaultState>) -> Result<McpStatus, String> {
    // Polling command: do NOT touch_human_activity here.
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

/// Return current session status. This is a polling command and must NOT
/// refresh the idle timer (ADR-0020 §9). MCP agents or the UI status loop
/// calling this every few seconds would otherwise keep the vault unlocked.
#[tauri::command]
async fn session_status(state: State<'_, VaultState>) -> Result<SessionStatus, String> {
    let locked = !is_unlocked(&state).await;
    let (idle_remaining_secs, session_remaining_secs) = if locked {
        (None, None)
    } else {
        state.remaining_secs()
    };
    Ok(SessionStatus {
        locked,
        idle_remaining_secs,
        session_remaining_secs,
    })
}

/// Update the session limits. This is a deliberate human action in the settings
/// page, so it counts as human activity.
#[tauri::command]
async fn session_set_limits(
    state: State<'_, VaultState>,
    idle_secs: u64,
    absolute_secs: u64,
) -> Result<(), String> {
    state.touch_human_activity();
    state.set_limits(idle_secs, absolute_secs);
    Ok(())
}

/// Enable or disable OS notifications. A deliberate human action in the
/// settings page, so it counts as human activity.
#[tauri::command]
async fn notifications_set_enabled(
    state: State<'_, VaultState>,
    notifications: State<'_, NotificationState>,
    enabled: bool,
) -> Result<(), String> {
    state.touch_human_activity();
    notifications.enabled.store(enabled, Ordering::Relaxed);
    Ok(())
}

#[tauri::command]
async fn agent_create(
    app: AppHandle,
    state: State<'_, VaultState>,
    name: String,
    scopes: Option<Vec<sv_core::agents::AgentScope>>,
) -> Result<AgentCreated, String> {
    let _ = &app;
    state.touch_human_activity();
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
    state.touch_human_activity();
    with_handle(&state, |handle| {
        handle.revoke_agent(&agent_id).map_err(estr)
    })
    .await
}

#[tauri::command]
async fn transit_create_key(
    state: State<'_, VaultState>,
    name: String,
    lease_id: Option<String>,
    agent_id: Option<String>,
) -> Result<sv_core::transit::TransitKeyInfo, String> {
    state.touch_human_activity();
    let resource_ref = format!("transit:{name}");
    let args = vec![name.clone()];
    if !require_lease(
        &state,
        lease_id.as_deref().unwrap_or(""),
        agent_id.as_deref().unwrap_or(""),
        &resource_ref,
        "create_transit_key",
        &args,
        &resource_ref,
    )
    .await
        && lease_id.is_some()
    {
        return Err("invalid or expired wake lease".into());
    }
    with_handle(&state, |handle| {
        handle.transit_create_key(&name).map_err(estr)
    })
    .await
}

#[tauri::command]
async fn transit_list_keys(
    state: State<'_, VaultState>,
) -> Result<Vec<sv_core::transit::TransitKeyInfo>, String> {
    // Polling command: do NOT touch_human_activity here.
    with_handle(&state, |handle| handle.transit_list().map_err(estr)).await
}

#[tauri::command]
async fn signing_create_key(
    state: State<'_, VaultState>,
    name: String,
    lease_id: Option<String>,
    agent_id: Option<String>,
) -> Result<sv_core::transit::SigningKeyInfo, String> {
    state.touch_human_activity();
    let resource_ref = format!("signing:{name}");
    let args = vec![name.clone()];
    if !require_lease(
        &state,
        lease_id.as_deref().unwrap_or(""),
        agent_id.as_deref().unwrap_or(""),
        &resource_ref,
        "create_signing_key",
        &args,
        &resource_ref,
    )
    .await
        && lease_id.is_some()
    {
        return Err("invalid or expired wake lease".into());
    }
    with_handle(&state, |handle| {
        handle.signing_create_key(&name).map_err(estr)
    })
    .await
}

#[tauri::command]
async fn signing_list_keys(
    state: State<'_, VaultState>,
) -> Result<Vec<sv_core::transit::SigningKeyInfo>, String> {
    // Polling command: do NOT touch_human_activity here.
    with_handle(&state, |handle| handle.signing_list().map_err(estr)).await
}

#[tauri::command]
async fn broker_create_secret(
    state: State<'_, VaultState>,
    name: String,
    secret: String,
    allow: Vec<sv_core::transit::BrokerAllow>,
    injection: Option<sv_core::transit::BrokerInjection>,
    lease_id: Option<String>,
    agent_id: Option<String>,
) -> Result<sv_core::transit::BrokerSecretInfo, String> {
    state.touch_human_activity();
    let resource_ref = format!("broker:{name}");
    let args = vec![name.clone()];
    if !require_lease(
        &state,
        lease_id.as_deref().unwrap_or(""),
        agent_id.as_deref().unwrap_or(""),
        &resource_ref,
        "create_broker_secret",
        &args,
        &resource_ref,
    )
    .await
        && lease_id.is_some()
    {
        return Err("invalid or expired wake lease".into());
    }
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
    // Polling command: do NOT touch_human_activity here.
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

async fn start_servers<R: Runtime>(state: &State<'_, VaultState<R>>) -> Result<(), String> {
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

async fn stop_servers<R: Runtime>(state: &State<'_, VaultState<R>>) {
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
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            app.manage(VaultState::new(app.handle().clone()));
            app.manage(NotificationState::new());
            app.manage(tray::TrayApprovals::new());
            // The tray is the only surface that can carry Approve/Deny while
            // the user is in another app: the notification plugin's actions
            // API is mobile-only on this stack. A failure to create it must
            // not stop the app from starting -- the in-app queue remains the
            // authoritative path to every pending request.
            if let Err(error) = tray::build_tray(app.handle(), |app, id, approved| {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    respond_from_tray(&app, id, approved).await;
                });
            }) {
                eprintln!("tray unavailable: {error}");
            }
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
            audit_tail,
            audit_verify,
            scan_run,
            scan_store,
            scan_history_list,
            scan_report_get,
            scan_reveal,
            scan_triage_set,
            vault_list_files,
            vault_write_file,
            vault_read_file,
            vault_export_file,
            open_audit_folder,
            vault_delete_file,
            approval_respond,
            wake_request,
            wake_list,
            wake_respond,
            wake_prepare_access,
            mcp_status,
            session_status,
            session_set_limits,
            notifications_set_enabled,
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
            remediate_plan_file,
            remediate_plan_list,
            remediate_execute,
            remediate_restore,
            cli_binary_path,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Sovereign Vault");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The regression this change exists for.
    ///
    /// `vault_read_file` used to call `container_mode` only to LABEL the audit
    /// event, then read the file unconditionally. A real audit log on this
    /// machine holds 27,075 reads of one file, every row tagged `mode: OTP`,
    /// every one `allowed`, 99.8% of them less than a second apart -- an
    /// authenticated log asserting a human approval that never happened.
    #[test]
    fn otp_and_approval_modes_require_desktop_consent() {
        assert!(
            desktop_consent_required(Some(SecurityMode::Otp)).unwrap(),
            "an OTP container must gate a desktop read, not just label the audit"
        );
        assert!(
            desktop_consent_required(Some(SecurityMode::Approval)).unwrap(),
            "an APPROVAL container must gate a desktop read"
        );
    }

    #[test]
    fn direct_and_anonymized_modes_do_not_prompt() {
        assert!(!desktop_consent_required(Some(SecurityMode::Direct)).unwrap());
        assert!(!desktop_consent_required(Some(SecurityMode::Anonymized)).unwrap());
    }

    /// A container with no recorded mode has no policy set, so inventing a
    /// prompt would gate something the user never asked to gate. This mirrors
    /// `approval_requirement`, which treats a modeless request the same way.
    #[test]
    fn absent_mode_does_not_prompt() {
        assert!(!desktop_consent_required(None).unwrap());
    }

    /// Unimplemented modes fail closed rather than falling through to "no
    /// prompt needed", which is how an unimplemented control becomes an
    /// absent one.
    #[test]
    fn unimplemented_modes_fail_closed() {
        assert!(desktop_consent_required(Some(SecurityMode::Zkp)).is_err());
        assert!(desktop_consent_required(Some(SecurityMode::Native)).is_err());
    }

    /// Every `invoke(...)` the UI issues must name a registered command.
    ///
    /// `vault_export_file` was invoked by two components and never existed in
    /// Rust, so every Download click failed silently at the IPC boundary. A
    /// missing command is invisible to `cargo check`, to `svelte-check`, and to
    /// any test that mocks `invoke` -- which is every UI test -- so it is
    /// checked here, against the real handler list.
    #[test]
    fn every_command_the_ui_invokes_is_registered() {
        let lib = include_str!("lib.rs");
        let handler_start = lib
            .find("tauri::generate_handler![")
            .expect("generate_handler! must exist");
        let handler_end = lib[handler_start..]
            .find(']')
            .expect("handler list must terminate")
            + handler_start;
        let registered = &lib[handler_start..handler_end];

        // Walk the UI sources for `invoke<...>('name'` / `invoke('name'`.
        let ui_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../ui/src")
            .canonicalize()
            .expect("ui/src must exist");
        let mut invoked: Vec<String> = Vec::new();
        let mut stack = vec![ui_dir];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("readable ui dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let is_source = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e == "ts" || e == "svelte");
                if !is_source {
                    continue;
                }
                // Test files mock `invoke` and may name commands that do not
                // exist, deliberately.
                if path.to_string_lossy().contains(".test.") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("readable source");
                for (idx, _) in text.match_indices("invoke") {
                    let rest = &text[idx..];
                    let Some(open) = rest.find('(') else { continue };
                    // Skip a generic parameter list before the call parens.
                    let head = &rest[..open];
                    if head.contains(';') || head.contains('\n') {
                        continue;
                    }
                    let after = &rest[open + 1..];
                    let trimmed = after.trim_start();
                    let Some(quote) = trimmed.chars().next() else {
                        continue;
                    };
                    if quote != '\'' && quote != '"' && quote != '`' {
                        continue;
                    }
                    let body = &trimmed[1..];
                    let Some(end) = body.find(quote) else {
                        continue;
                    };
                    let name = &body[..end];
                    if !name.is_empty()
                        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    {
                        invoked.push(name.to_string());
                    }
                }
            }
        }
        invoked.sort();
        invoked.dedup();
        assert!(
            !invoked.is_empty(),
            "found no invoke() calls in the UI; the scan is broken, not the code"
        );

        let missing: Vec<&String> = invoked
            .iter()
            .filter(|name| {
                // Match the identifier as a whole list entry.
                !registered
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .any(|token| token == name.as_str())
            })
            .collect();
        assert!(
            missing.is_empty(),
            "the UI invokes commands that are not registered in generate_handler!: {missing:?}"
        );
    }

    /// Pins the gate at every vault-mutating desktop command. These read and
    /// write real user data; a future command added without a gate is exactly
    /// the defect this change fixes, so the count is asserted rather than
    /// left to review.
    #[test]
    fn every_mutating_desktop_command_enforces_mode() {
        let src = include_str!("lib.rs");
        let body = src.split("#[cfg(test)]").next().unwrap();
        for command in [
            "async fn vault_read_file",
            "async fn vault_write_file",
            "async fn vault_delete_file",
            "async fn vault_delete_container",
        ] {
            let start = body
                .find(command)
                .unwrap_or_else(|| panic!("{command} must exist"));
            // Scan to the next command boundary.
            let rest = &body[start..];
            let end = rest[1..]
                .find("#[tauri::command]")
                .map(|i| i + 1)
                .unwrap_or(rest.len());
            let fn_body = &rest[..end];
            assert!(
                fn_body.contains("require_desktop_consent"),
                "{command} must enforce the container mode, not merely record it"
            );
        }
    }

    /// Deletion is irreversible, so it is confirmed even in DIRECT mode, where
    /// reads and writes are not.
    #[test]
    fn deletion_prompts_even_in_direct_mode() {
        let src = include_str!("lib.rs");
        let body = src.split("#[cfg(test)]").next().unwrap();
        for command in [
            "async fn vault_delete_file",
            "async fn vault_delete_container",
        ] {
            let start = body.find(command).unwrap();
            let rest = &body[start..];
            let end = rest[1..]
                .find("#[tauri::command]")
                .map(|i| i + 1)
                .unwrap_or(rest.len());
            assert!(
                rest[..end].contains("delete_mode"),
                "{command} must upgrade DIRECT to a confirmation: deletion cannot be undone"
            );
        }
    }

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

    #[test]
    fn session_absolute_cap_is_not_extended_by_activity() {
        let timer = SessionTimer::new();
        // Set an absolute cap of 2 seconds and an idle timeout of 1 hour.
        timer.set_limits(3600, 2);
        timer.set_unlocked();

        let (_idle1, absolute1) = timer.remaining_secs();
        assert!(absolute1.unwrap() <= 2);

        // Simulate repeated human activity after 1 second.
        std::thread::sleep(Duration::from_secs(1));
        timer.touch_human_activity();

        let (idle2, absolute2) = timer.remaining_secs();
        // Idle timer resets to the full hour.
        assert!(idle2.unwrap() >= 3595, "idle timer should refresh");
        // Absolute cap should have shrunk, never grown.
        assert!(
            absolute2.unwrap() <= absolute1.unwrap(),
            "absolute cap must not increase with activity"
        );
    }

    #[test]
    fn polling_command_does_not_refresh_idle_timer() {
        let timer = SessionTimer::new();
        timer.set_limits(10, 3600);
        timer.set_unlocked();

        std::thread::sleep(Duration::from_secs(1));
        let (idle_before, _) = timer.remaining_secs();
        assert!(idle_before.unwrap() < 10);

        // Polling helpers read remaining_secs and must NOT call
        // touch_human_activity. We verify by reading the raw timer.
        let (idle_after_touch, _) = timer.remaining_secs();
        assert_eq!(
            idle_before.unwrap(),
            idle_after_touch.unwrap(),
            "timer unchanged without human activity"
        );

        // A genuine human action refreshes it.
        timer.touch_human_activity();
        let (idle_after_human, _) = timer.remaining_secs();
        assert!(
            idle_after_human.unwrap() > idle_before.unwrap(),
            "human activity must refresh idle timer"
        );
    }

    #[test]
    fn scan_id_validation_rejects_path_traversal() {
        let root = std::path::Path::new("/tmp/vault");
        assert!(scan_report_path(root, "../etc/passwd").is_err());
        assert!(scan_report_path(root, "C:/Users/pealm/.ssh/id_rsa").is_err());
        assert!(scan_triage_path(root, "../etc/passwd").is_err());
        assert!(scan_triage_path(root, "C:/Users/pealm/.ssh/id_rsa").is_err());

        // Valid shape produced by encode_scan_id.
        assert!(scan_report_path(root, "1234567890123-run").is_ok());
        assert!(scan_triage_path(root, "1234567890123-run").is_ok());
    }

    /// The set of commands that only poll or read state. They must never
    /// refresh the idle timer, otherwise a chatty UI loop or MCP agent keeps
    /// the vault unlocked forever (ADR-0020 §9).
    const POLLING_COMMANDS: &[&str] = &[
        "vault_status",
        "vault_list_containers",
        "vault_list_files",
        "mcp_status",
        "audit_tail",
        "audit_verify",
        "agent_list",
        "session_status",
        "scan_history_list",
        "transit_list_keys",
        "signing_list_keys",
        "broker_list_secrets",
    ];

    /// Regression guard: polling/status commands must not contain a call to
    /// `touch_human_activity()`. This is a structural test over the source file
    /// so a future edit cannot accidentally reintroduce the refresh in a status
    /// path.
    #[test]
    fn polling_commands_never_call_touch_human_activity() {
        let src = include_str!("lib.rs");
        for name in POLLING_COMMANDS {
            let fn_pos = src
                .find(&format!("async fn {name}"))
                .unwrap_or_else(|| panic!("polling command {name} not found in source"));
            // Function body runs until the next #[tauri::command] attribute or
            // the end of the file.
            let next_attr = src[fn_pos..]
                .find("\n#[tauri::command]")
                .map(|i| fn_pos + i);
            let body_end = next_attr.unwrap_or(src.len());
            let body = &src[fn_pos..body_end];
            assert!(
                !body.contains("touch_human_activity();"),
                "polling command {name} must not refresh idle activity"
            );
        }
    }

    /// Simulate a UI/MCP polling loop calling only status/read helpers and
    /// verify the idle timer still expires. This protects against the
    /// regression where any state access was incorrectly counted as activity.
    #[test]
    fn polling_loop_does_not_prevent_idle_timeout() {
        let timer = SessionTimer::new();
        // 3-second idle timeout, generous absolute cap.
        timer.set_limits(3, 3600);
        timer.set_unlocked();

        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            let (idle_remaining, _) = timer.remaining_secs();
            if idle_remaining.is_none() || idle_remaining.unwrap() == 0 {
                break;
            }
            // Simulate rapid status polling: only read timers, never touch.
            std::thread::sleep(Duration::from_millis(100));
        }

        let (idle_remaining, _) = timer.remaining_secs();
        assert!(
            idle_remaining.is_none() || idle_remaining.unwrap() == 0,
            "polling-only traffic must not keep the vault unlocked past idle timeout"
        );
    }

    // ------------------------------------------------------------------
    // Wake-on-demand tests (ADR-0020 §8-12)
    // ------------------------------------------------------------------

    #[derive(Clone, Default)]
    struct TestEmitter {
        wakes: Arc<std::sync::Mutex<Vec<WakePrompt>>>,
        cancels: Arc<std::sync::Mutex<Vec<u64>>>,
    }

    impl WakeEmitter for TestEmitter {
        fn emit_wake(&self, prompt: WakePrompt) {
            self.wakes.lock().unwrap().push(prompt);
        }
        fn emit_cancel(&self, id: u64) {
            self.cancels.lock().unwrap().push(id);
        }
    }

    fn test_queue() -> WakeQueue<TestEmitter> {
        WakeQueue::new(TestEmitter::default())
    }

    #[tokio::test]
    async fn wake_request_is_indistinguishable_across_resource_references() {
        // The in-memory WakeQueue has no access to vault state and therefore
        // cannot consult a resource registry. That is the correct design (ADR-0020
        // §8), but it means this test cannot prove the absence of an existence
        // leak by contrasting a real resource against a fake one. What it can prove
        // is that two *structurally different* opaque resource references
        // produce identical observable behavior: same return enum, same absence
        // of error, and same timing bucket.
        let q = test_queue();

        let start_real = Instant::now();
        let real = q
            .request("agent-1".into(), "resource-that-exists".into())
            .await;
        let real_duration = start_real.elapsed();

        let start_fake = Instant::now();
        let fake = q
            .request("agent-1".into(), "resource-that-does-not-exist".into())
            .await;
        let fake_duration = start_fake.elapsed();

        // Both new requests should queue with the same generic result.
        assert_eq!(real, WakeResult::Queued);
        assert_eq!(fake, WakeResult::Queued);

        // Timing bucket equality: both calls must complete in the same coarse
        // bucket. This is the best proxy for the no-oracle invariant available at
        // this layer, because a future implementation that resolves the reference
        // would necessarily take measurably longer for a hit.
        let bucket = Duration::from_millis(5);
        assert_eq!(
            real_duration.as_nanos() / bucket.as_nanos(),
            fake_duration.as_nanos() / bucket.as_nanos(),
            "wake request timing must not vary by resource reference"
        );

        // A second request for an already-pending reference coalesces and returns
        // the same generic status.
        let real2 = q
            .request("agent-1".into(), "resource-that-exists".into())
            .await;
        assert_eq!(real2, WakeResult::Queued);

        // Two distinct resources produced two notifications; the duplicate was
        // suppressed by the notification cooldown.
        let wakes = q.emitter.wakes.lock().unwrap();
        assert_eq!(wakes.len(), 2);
    }

    #[tokio::test]
    async fn wake_rapid_duplicate_requests_produce_one_notification_per_cooldown() {
        let q = test_queue();
        // Send many rapid requests for the exact same resource. Whether each is
        // Queued or Unavailable due to the per-agent rate limit is irrelevant:
        // the anti-fatigue requirement is that at most one notification is emitted
        // within the cooldown window.
        for _ in 0..20 {
            q.request("agent-1".into(), "same-resource".into()).await;
        }
        let wakes = q.emitter.wakes.lock().unwrap();
        assert_eq!(
            wakes.len(),
            1,
            "duplicate wake requests must coalesce into a single notification within the cooldown"
        );
    }

    #[tokio::test]
    async fn wake_per_agent_rate_limit_returns_unavailable() {
        let q = test_queue();
        for i in 0..WAKE_MAX_PER_AGENT {
            assert_eq!(
                q.request("agent-1".into(), format!("resource-{i}")).await,
                WakeResult::Queued
            );
        }
        // The next request from the same agent within the window is unavailable.
        assert_eq!(
            q.request("agent-1".into(), "one-more".into()).await,
            WakeResult::Unavailable
        );
        // A different agent is still allowed (subject to global cap).
        assert_eq!(
            q.request("agent-2".into(), "agent-2-resource".into()).await,
            WakeResult::Queued
        );
    }

    #[tokio::test]
    async fn wake_request_rate_limits_and_coalesces() {
        let q = test_queue();
        // First request queues and emits.
        assert_eq!(
            q.request("agent-1".into(), "res".into()).await,
            WakeResult::Queued
        );
        // Duplicate coalesces.
        assert_eq!(
            q.request("agent-1".into(), "res".into()).await,
            WakeResult::Queued
        );
        // Only one wake event so far (cooldown prevents second emission).
        assert_eq!(q.emitter.wakes.lock().unwrap().len(), 1);

        // Respond (approve) removes the pending request.
        let prompt = q.list().await.pop().unwrap();
        q.respond(prompt.id, true).await.unwrap();
        assert!(q.list().await.is_empty());
    }

    #[tokio::test]
    async fn lease_single_use_and_exact_binding() {
        let store = LeaseStore::new();
        let lease = store
            .issue(
                "agent-1",
                "resource-sig",
                "op-digest",
                "args-digest",
                "dest",
                "session-1",
                "v1",
            )
            .await;

        // First checkout with exact bindings succeeds.
        assert!(
            store
                .checkout(
                    &lease.id,
                    "agent-1",
                    "resource-sig",
                    "op-digest",
                    "args-digest",
                    "dest",
                    "session-1",
                    "v1",
                )
                .await
        );

        // Second checkout fails (single-use).
        assert!(
            !store
                .checkout(
                    &lease.id,
                    "agent-1",
                    "resource-sig",
                    "op-digest",
                    "args-digest",
                    "dest",
                    "session-1",
                    "v1",
                )
                .await
        );

        // A new lease with a different operation must not be usable for the
        // original operation.
        let lease2 = store
            .issue(
                "agent-1",
                "resource-sig",
                "other-op-digest",
                "args-digest",
                "dest",
                "session-1",
                "v1",
            )
            .await;
        assert!(
            !store
                .checkout(
                    &lease2.id,
                    "agent-1",
                    "resource-sig",
                    "op-digest",
                    "args-digest",
                    "dest",
                    "session-1",
                    "v1",
                )
                .await,
            "lease bound to a different operation must not cover the original operation"
        );

        // A lease bound to a different resource must not be usable.
        let lease3 = store
            .issue(
                "agent-1",
                "other-resource-sig",
                "op-digest",
                "args-digest",
                "dest",
                "session-1",
                "v1",
            )
            .await;
        assert!(
            !store
                .checkout(
                    &lease3.id,
                    "agent-1",
                    "resource-sig",
                    "op-digest",
                    "args-digest",
                    "dest",
                    "session-1",
                    "v1",
                )
                .await,
            "lease bound to a different resource must not cover this resource"
        );
    }

    #[tokio::test]
    async fn wake_authorization_allows_direct_lease_and_requires_consent_for_other_modes() {
        let store = LeaseStore::new();
        store
            .record_authorized_wake("resource-sig", "agent-1", "session-1")
            .await;

        assert!(
            store
                .has_authorized_wake("resource-sig", "agent-1", "session-1")
                .await
        );
        assert!(
            !store
                .has_authorized_wake("resource-sig", "agent-2", "session-1")
                .await
        );
        assert!(
            !store
                .has_authorized_wake("resource-sig", "agent-1", "session-2")
                .await
        );
    }

    #[test]
    fn wake_audit_event_contains_no_material_or_token() {
        let event = desktop_event(
            AuditAction::VaultInfo,
            AuditDecision::Allowed,
            None,
            None,
            None,
            None,
            Some("wake-approved agent=agent-1 resource=opaque-ref".into()),
        );
        let serialized = serde_json::to_string(&event).unwrap();
        assert!(!serialized.contains("secret-value"));
        assert!(!serialized.contains("bearer"));
        assert!(!serialized.contains("token"));
        assert!(serialized.contains("wake-approved"));
    }
}
