//! Desktop wiring of ADR-0025: which verifier this platform uses, and the
//! helpers the gated commands share.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use sv_audit::PresenceAudit;
use sv_presence::{OpDescriptor, OpDigest, PresenceCoordinator, PresenceVerifier};
use tauri::{AppHandle, Runtime};
use tokio::sync::Mutex;

pub(crate) fn build_coordinator<R: Runtime>(app: &AppHandle<R>) -> Arc<PresenceCoordinator> {
    #[cfg(windows)]
    let verifier: Arc<dyn PresenceVerifier> = {
        use tauri::Manager;
        let app = app.clone();
        Arc::new(sv_presence_windows::WindowsHelloVerifier::new(Arc::new(
            move || {
                // The real, kept-alive main window (ADR-0025 §5.2).
                app.get_webview_window("main")
                    .and_then(|w| w.hwnd().ok())
                    .map(|h| h.0 as isize)
            },
        )))
    };
    #[cfg(not(windows))]
    let verifier: Arc<dyn PresenceVerifier> = {
        let _ = app;
        sv_presence::platform_verifier()
    };
    Arc::new(PresenceCoordinator::new(verifier))
}

/// Modality mapping is 1:1; kept here so the audit writers never inline it.
pub(crate) fn audit_modality(m: sv_presence::Modality) -> sv_audit::PresenceModality {
    match m {
        sv_presence::Modality::Biometric => sv_audit::PresenceModality::Biometric,
        sv_presence::Modality::Password => sv_audit::PresenceModality::Password,
        sv_presence::Modality::Pin => sv_audit::PresenceModality::Pin,
        sv_presence::Modality::Unknown => sv_audit::PresenceModality::Unknown,
    }
}

/// A desktop operation that passed its ADR-0025 gate. It is consumed only
/// through `with_gated_handle`, which re-checks `epoch` under the handle
/// lock (plan D14).
pub(crate) struct GatePass {
    pub presence: PresenceAudit,
    pub digest: OpDigest,
    pub epoch: u64,
    pub operation_id: String,
}

/// A refused gate. `protected` is the operation's classification.
pub(crate) struct GateDenied {
    pub protected: bool,
    pub message: String,
    pub operation_id: String,
}

impl GateDenied {
    pub fn audit(&self) -> PresenceAudit {
        PresenceAudit::denied(self.protected).with_operation(self.operation_id.clone())
    }
}

impl GatePass {
    /// §6.3/§7.5: parameters derived from vault state must not have moved
    /// while the prompt was open.
    pub fn ensure_same(&self, op_now: &OpDescriptor) -> Result<(), GateDenied> {
        if op_now.digest() == self.digest {
            Ok(())
        } else {
            Err(GateDenied {
                protected: self.presence.protected,
                message: "operation changed during verification".into(),
                operation_id: self.operation_id.clone(),
            })
        }
    }
}

/// One pending desktop operation (plan D2): identity, deadline and
/// classification survive retries until a terminal outcome; `gate` makes
/// it exclusive — one verification at a time per operation.
#[derive(Clone)]
pub(crate) struct PendingDesktopOp {
    pub id: u64,
    pub deadline: Instant,
    pub protected: bool,
    pub gate: sv_presence::GateState,
}

#[derive(Default)]
pub(crate) struct DesktopOps {
    next: std::sync::atomic::AtomicU64,
    ops: Mutex<HashMap<OpDigest, PendingDesktopOp>>,
}

impl DesktopOps {
    /// Find or create the operation for `digest` and move it to
    /// `Verifying` with `attempt`. A concurrent call for the same operation
    /// gets `AlreadyVerifying` instead of starting a second verification.
    pub async fn begin(
        &self,
        digest: OpDigest,
        deadline: Instant,
        classify: impl FnOnce() -> bool,
        attempt: sv_presence::AttemptId,
    ) -> Result<PendingDesktopOp, sv_presence::GateError> {
        let mut ops = self.ops.lock().await;
        let now = Instant::now();
        ops.retain(|_, op| op.deadline > now);
        let op = ops.entry(digest).or_insert_with(|| PendingDesktopOp {
            id: self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1,
            deadline,
            protected: classify(),
            gate: sv_presence::GateState::Pending,
        });
        op.gate.begin(attempt, digest)?;
        Ok(op.clone())
    }

    /// A retryable failure: back to `Pending`, only if `id`/`attempt` still
    /// own the entry.
    pub async fn retry(&self, digest: OpDigest, id: u64, attempt: sv_presence::AttemptId) {
        if let Some(op) = self.ops.lock().await.get_mut(&digest) {
            if op.id == id {
                op.gate.abort(attempt);
            }
        }
    }

    /// A terminal outcome ends the operation — only the one with this `id`,
    /// never a successor registered under the same digest.
    pub async fn finish(&self, digest: OpDigest, id: u64) {
        let mut ops = self.ops.lock().await;
        if ops.get(&digest).is_some_and(|op| op.id == id) {
            ops.remove(&digest);
        }
    }

    /// Lock path: end every operation and invalidate its attempt in flight.
    pub async fn clear(&self, presence: &sv_presence::PresenceCoordinator) {
        let drained: Vec<PendingDesktopOp> =
            self.ops.lock().await.drain().map(|(_, op)| op).collect();
        for op in drained {
            if let sv_presence::GateState::Verifying { attempt, .. } = op.gate {
                presence.invalidate(attempt);
            }
        }
    }

    #[cfg(test)]
    pub async fn is_empty(&self) -> bool {
        self.ops.lock().await.is_empty()
    }
}

/// ADR-0024 contract (spec §7.4; plan D12). `submit_secret` and
/// `submit_secret_direct` do not exist yet. When implemented they MUST:
/// call `desktop_presence_gate` with this descriptor BEFORE the write;
/// perform the write inside `with_gated_handle_mut`; take no click
/// fallback on a protected system; deny on mid-attempt unavailability.
/// The digest binds the request, container, env var, the expected
/// revision (`None` for a new key, ADR-0024 spec §6) and the container
/// generation id (§4.3), so a verification can never commit a different
/// revision or a recreated namesake container.
/// Spec §7.4 stays OPEN until those submits exist and pass §9.2.
#[allow(dead_code)] // wired by the ADR-0024 implementation
pub(crate) fn secret_submit_op(
    request_id: &str,
    container: &str,
    env_var: &str,
    expected_revision: Option<u64>,
    expected_generation: &str,
) -> sv_presence::OpDescriptor {
    sv_presence::OpDescriptor::new("secret_submit")
        .field("container", container)
        .field("variable", env_var)
        .bind("request_id", request_id)
        .bind(
            "expected_revision",
            expected_revision
                .map(|r| r.to_string())
                .unwrap_or_else(|| "none".into()),
        )
        .bind("expected_generation", expected_generation)
}

#[cfg(test)]
mod tests {
    use super::secret_submit_op as op;

    #[test]
    fn secret_submit_digest_binds_revision_and_generation() {
        let base = op("r1", "c", "API_KEY", Some(7), "gen-a").digest();
        assert_ne!(base, op("r1", "c", "API_KEY", Some(8), "gen-a").digest());
        assert_ne!(base, op("r1", "c", "API_KEY", None, "gen-a").digest());
        assert_ne!(base, op("r1", "c", "API_KEY", Some(7), "gen-b").digest());
        assert_ne!(base, op("r2", "c", "API_KEY", Some(7), "gen-a").digest());
    }
}
