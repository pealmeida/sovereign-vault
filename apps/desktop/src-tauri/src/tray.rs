//! System-tray menu for pending approval requests.
//!
//! # Why this exists
//!
//! An OS notification on desktop cannot carry buttons: the notification
//! plugin's Actions API (`register_action_types`) is implemented only in its
//! mobile backend, and the desktop backend drops the `notify_rust` handle that
//! would receive a click. The tray is the one always-reachable surface that
//! *can* hold Approve/Deny controls while the user is working in another app.
//!
//! # What a menu item may say
//!
//! The tray menu is a shared-desktop surface. It renders whether or not the
//! vault is unlocked, it is visible to anyone at the machine, and on some
//! desktops its contents are read by accessibility services and screenshot
//! tooling. `ApprovalPrompt` carries `container` and `file_name`, which are
//! exactly the fields the OS-notification body refuses to interpolate for the
//! same class of reason.
//!
//! So a menu item names the ACTION CLASS ONLY -- "Read a file", "Broker an
//! outbound request" -- and never the container, file name, byte size, or
//! agent id. A user who wants to know *which* file opens the app, where the
//! request is shown behind the vault lock. This keeps the tray useful for the
//! common case (recognising the request you just triggered) without turning a
//! transient prompt into a durable on-screen disclosure.
//!
//! # What may be approved here
//!
//! Only click-approvals ever reach this menu. OTP-mode requests never become
//! pending approvals at all: `handle_otp` returns an error and requires the
//! agent to resend with a code shown on the desktop. That escalation exists
//! precisely so the decision requires presence at the machine, and the tray
//! must not offer a way around it. The type system does not enforce this --
//! the registry is populated only from the click path -- so
//! [`TrayApprovals::insert`] is where the invariant is written down.

use std::collections::HashMap;
use std::sync::Mutex;

use tauri::menu::{Menu, MenuBuilder, MenuEvent, MenuItemBuilder, SubmenuBuilder};
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::{AppHandle, Manager, Runtime};

/// Menu id prefixes. The id encodes the decision and the request id, because a
/// `MenuEvent` carries only the id string.
const APPROVE_PREFIX: &str = "sv-approve:";
const DENY_PREFIX: &str = "sv-deny:";
const OPEN_ID: &str = "sv-open";
const QUIT_ID: &str = "sv-quit";

/// Tray id, so the icon can be looked up again to refresh its menu.
pub const TRAY_ID: &str = "sv-main-tray";

/// Upper bound on approval rows rendered in the menu.
///
/// A request storm must not produce an unbounded native menu. Older entries
/// stay pending and are still answerable in the app; only the menu is capped.
const MAX_MENU_ROWS: usize = 8;

/// One pending request, reduced to what the tray is allowed to display.
///
/// Deliberately does NOT hold the container, the file name, the byte size, or
/// the agent id. Constructing this type is the point where those fields are
/// dropped, so a later edit cannot casually render them by reaching through to
/// a richer struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayApproval {
    /// Approval id, matching the id `approval_respond` expects.
    pub id: u64,
    /// Action-class label. Safe for a shared screen; see the module docs.
    pub action_label: &'static str,
    /// The action being decided, for the audit record.
    ///
    /// Never rendered: it exists so a tray decision is audited as the action
    /// it actually authorised rather than as a generic placeholder.
    pub audit_action: sv_audit::AuditAction,
}

/// Registry of the click-approvals currently awaiting a decision.
#[derive(Default)]
pub struct TrayApprovals {
    inner: Mutex<HashMap<u64, TrayApproval>>,
}

impl TrayApprovals {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a pending click-approval.
    ///
    /// Callers MUST pass only click-mode requests. An OTP request in here
    /// would render a one-click Approve for a decision whose whole purpose is
    /// to require a code read off the desktop.
    pub fn insert(&self, approval: TrayApproval) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.insert(approval.id, approval);
        }
    }

    /// Forget one request, after any decision or cancellation.
    pub fn remove(&self, id: u64) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.remove(&id);
        }
    }

    /// Drop every pending request.
    ///
    /// Called on lock: a decision authorised in one session must not remain
    /// clickable in the next, after the user deliberately ended access.
    pub fn clear(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.clear();
        }
    }

    /// Snapshot, ordered by id so the menu order is stable across rebuilds.
    pub fn snapshot(&self) -> Vec<TrayApproval> {
        let Ok(guard) = self.inner.lock() else {
            return Vec::new();
        };
        let mut items: Vec<TrayApproval> = guard.values().cloned().collect();
        items.sort_by_key(|a| a.id);
        items
    }
}

/// Human label for an action class.
///
/// Exhaustive on purpose: a new `AccessAction` variant must be given a label
/// here rather than defaulting to something that leaks its debug spelling.
pub fn action_label(action: &sv_mcp::AccessAction) -> &'static str {
    use sv_mcp::AccessAction as A;
    match action {
        A::ListContainers => "List containers",
        A::ListFiles => "List files",
        A::ReadFile => "Read a file",
        A::WriteFile => "Write a file",
        A::DeleteFile => "Delete a file",
        A::CreateContainer => "Create a container",
        A::DestroyContainer => "Destroy a container",
        A::CreateTransitKey => "Create an encryption key",
        A::ListTransitKeys => "List encryption keys",
        A::Encrypt => "Encrypt data",
        A::Decrypt => "Decrypt data",
        A::CreateSigningKey => "Create a signing key",
        A::ListSigningKeys => "List signing keys",
        A::Sign => "Sign a payload",
        A::Verify => "Verify a signature",
        A::CreateBrokerSecret => "Create a brokered secret",
        A::ListBrokerSecrets => "List brokered secrets",
        A::Broker => "Broker an outbound request",
        A::VaultInfo => "Read vault metadata",
        A::ExportAgents => "Export agent identities",
        A::ImportAgents => "Import agent identities",
    }
}

/// Parse a menu id into a decision. Returns `(id, approved)`.
pub fn parse_decision(menu_id: &str) -> Option<(u64, bool)> {
    if let Some(rest) = menu_id.strip_prefix(APPROVE_PREFIX) {
        return rest.parse().ok().map(|id| (id, true));
    }
    if let Some(rest) = menu_id.strip_prefix(DENY_PREFIX) {
        return rest.parse().ok().map(|id| (id, false));
    }
    None
}

/// Build the tray menu for the current pending set.
fn build_menu<R: Runtime>(app: &AppHandle<R>, pending: &[TrayApproval]) -> tauri::Result<Menu<R>> {
    let mut builder = MenuBuilder::new(app);

    if pending.is_empty() {
        // A disabled row, not an empty menu: an empty menu reads as broken.
        let empty = MenuItemBuilder::with_id("sv-empty", "No pending requests")
            .enabled(false)
            .build(app)?;
        builder = builder.item(&empty);
    } else {
        for approval in pending.iter().take(MAX_MENU_ROWS) {
            // Each request is its own submenu so Approve and Deny are never
            // adjacent in a flat list, where a mis-click lands on the opposite
            // decision. The submenu label carries the action class only.
            let approve =
                MenuItemBuilder::with_id(format!("{APPROVE_PREFIX}{}", approval.id), "Approve")
                    .build(app)?;
            let deny =
                MenuItemBuilder::with_id(format!("{DENY_PREFIX}{}", approval.id), "Deny")
                    .build(app)?;
            let sub = SubmenuBuilder::new(app, approval.action_label)
                .item(&deny)
                .separator()
                .item(&approve)
                .build()?;
            builder = builder.item(&sub);
        }
        if pending.len() > MAX_MENU_ROWS {
            let more = MenuItemBuilder::with_id(
                "sv-more",
                format!("{} more - open to review", pending.len() - MAX_MENU_ROWS),
            )
            .enabled(false)
            .build(app)?;
            builder = builder.item(&more);
        }
    }

    builder
        .separator()
        .text(OPEN_ID, "Open Sovereign Vault")
        .separator()
        .text(QUIT_ID, "Quit")
        .build()
}

/// Refresh the tray menu and its pending-count badge.
pub fn refresh<R: Runtime>(app: &AppHandle<R>) {
    let Some(state) = app.try_state::<TrayApprovals>() else {
        return;
    };
    let pending = state.snapshot();
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    if let Ok(menu) = build_menu(app, &pending) {
        let _ = tray.set_menu(Some(menu));
    }
    // The tooltip carries the count only -- never a request detail.
    let tooltip = match pending.len() {
        0 => "Sovereign Vault - no pending requests".to_string(),
        1 => "Sovereign Vault - 1 request awaiting your decision".to_string(),
        n => format!("Sovereign Vault - {n} requests awaiting your decision"),
    };
    let _ = tray.set_tooltip(Some(&tooltip));
}

/// Bring the main window to the front.
pub fn focus_main<R: Runtime>(app: &AppHandle<R>) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// Create the tray icon during setup.
pub fn build_tray<R: Runtime, F>(app: &AppHandle<R>, on_decision: F) -> tauri::Result<TrayIcon<R>>
where
    F: Fn(&AppHandle<R>, u64, bool) + Send + Sync + 'static,
{
    let menu = build_menu(app, &[])?;
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("Sovereign Vault - no pending requests")
        .menu(&menu)
        .on_menu_event(move |app: &AppHandle<R>, event: MenuEvent| {
            let id = event.id().0.as_str();
            match id {
                OPEN_ID => focus_main(app),
                QUIT_ID => app.exit(0),
                other => {
                    if let Some((approval_id, approved)) = parse_decision(other) {
                        on_decision(app, approval_id, approved);
                    }
                }
            }
        });
    if let Some(icon) = app.default_window_icon().cloned() {
        builder = builder.icon(icon);
    }
    builder.build(app)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_decision_round_trips_both_outcomes() {
        assert_eq!(parse_decision("sv-approve:42"), Some((42, true)));
        assert_eq!(parse_decision("sv-deny:7"), Some((7, false)));
    }

    #[test]
    fn parse_decision_rejects_unrelated_ids() {
        assert_eq!(parse_decision("sv-open"), None);
        assert_eq!(parse_decision("sv-quit"), None);
        assert_eq!(parse_decision("sv-approve:"), None);
        assert_eq!(parse_decision("sv-approve:not-a-number"), None);
        // A near-miss prefix must not be read as a decision.
        assert_eq!(parse_decision("sv-approve-all:1"), None);
    }

    #[test]
    fn snapshot_is_ordered_and_reflects_removal() {
        let reg = TrayApprovals::new();
        reg.insert(TrayApproval {
            id: 3,
            action_label: "Read a file",
            audit_action: sv_audit::AuditAction::ReadFile,
        });
        reg.insert(TrayApproval {
            id: 1,
            action_label: "Write a file",
            audit_action: sv_audit::AuditAction::WriteFile,
        });
        let ids: Vec<u64> = reg.snapshot().iter().map(|a| a.id).collect();
        assert_eq!(ids, vec![1, 3], "menu order must be stable by id");

        reg.remove(1);
        let ids: Vec<u64> = reg.snapshot().iter().map(|a| a.id).collect();
        assert_eq!(ids, vec![3]);
    }

    #[test]
    fn clear_drops_every_pending_request() {
        let reg = TrayApprovals::new();
        reg.insert(TrayApproval {
            id: 1,
            action_label: "Read a file",
            audit_action: sv_audit::AuditAction::ReadFile,
        });
        reg.insert(TrayApproval {
            id: 2,
            action_label: "Broker an outbound request",
            audit_action: sv_audit::AuditAction::Broker,
        });
        reg.clear();
        assert!(
            reg.snapshot().is_empty(),
            "a lock must leave no clickable authorization behind"
        );
    }

    /// The labels are the entire disclosure surface of this menu, so assert
    /// they are fixed action classes and carry no interpolation hook.
    #[test]
    fn action_labels_are_fixed_strings() {
        use sv_mcp::AccessAction as A;
        for action in [
            A::ReadFile,
            A::WriteFile,
            A::DeleteFile,
            A::Broker,
            A::ImportAgents,
            A::DestroyContainer,
        ] {
            let label = action_label(&action);
            assert!(!label.is_empty());
            assert!(
                !label.contains('{') && !label.contains('%'),
                "label must be a fixed string, got {label:?}"
            );
        }
    }

    /// The OTP escalation exists so a decision requires presence at the
    /// desktop. If the tray ever gained a second insert site, an OTP request
    /// could acquire a one-click Approve and quietly undo that. This pins the
    /// count of insert sites in the caller so adding one fails here first.
    #[test]
    fn tray_registry_has_exactly_one_insert_site() {
        let caller = include_str!("lib.rs");
        let sites = caller.matches("tray_state.insert(").count();
        assert_eq!(
            sites, 1,
            "exactly one call site may populate the tray: the click-approval              path. An OTP request reaching the tray would offer a one-click              approve for a decision that must require a code read off the              desktop."
        );
    }

    /// Guard the module invariant that the tray never renders request detail.
    ///
    /// Matches FIELD ACCESSES (`.container`, `.file_name`, ...), not bare
    /// words: action-class labels legitimately contain "container" in prose
    /// such as "List containers", and flagging those would make the guard
    /// noise rather than signal.
    #[test]
    fn source_does_not_access_request_detail_fields() {
        let src = include_str!("tray.rs");
        // Doc comments discuss these fields deliberately; scan code lines only,
        // and only the part above the test module.
        let code = src.split("#[cfg(test)]").next().unwrap();
        for forbidden in [".container", ".file_name", ".byte_size", ".otp_code"] {
            for line in code.lines() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                assert!(
                    !line.contains(forbidden),
                    "tray code must not read {forbidden}: {line}"
                );
            }
        }
    }

    /// The struct the tray renders from must not gain a detail field. This
    /// catches the case the source scan cannot: a field added to
    /// `TrayApproval` itself, which would then be legitimately readable as
    /// `approval.file_name` from inside this very module.
    #[test]
    fn tray_approval_carries_no_request_detail_field() {
        let src = include_str!("tray.rs");
        let start = src
            .find("pub struct TrayApproval {")
            .expect("TrayApproval struct must exist");
        let body = &src[start..];
        let end = body.find("
}").expect("struct must terminate");
        let fields = &body[..end];
        for forbidden in ["container", "file_name", "byte_size", "otp", "agent"] {
            for line in fields.lines() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                assert!(
                    !line.contains(forbidden),
                    "TrayApproval must not carry {forbidden}: {line}"
                );
            }
        }
    }
}
