# ADR-0022: Approve/Deny from the system-tray menu

## Status

Accepted.

## Context

A human approving an agent's access request had exactly one surface: the
in-app modal. An agent blocked on a decision stayed blocked until the user
switched to Sovereign Vault, which is the wrong cost for a request the user
triggered themselves moments earlier from another application.

The obvious fix — buttons on the OS notification — is not available on this
stack. `tauri-plugin-notification` implements `register_action_types` only in
its mobile backend (`src/mobile.rs`); the desktop backend's builder exposes
`title`, `body`, `icon`, `sound`, `show` and nothing else. `desktop::show()`
calls `notify_rust`'s `show()` and drops the returned handle inside a spawned
task, so even on Linux, where `notify_rust` supports actions, nothing can
receive the click. Verified against `tauri-plugin-notification` 2.4.0.

The system tray is the remaining always-reachable surface, and unlike a
notification card it can hold real controls and be re-rendered as state
changes.

## Decision

Add a tray icon whose menu lists pending approvals, each as a submenu with
**Deny** and **Approve**.

### The menu shows the action class only

`ApprovalPrompt` carries `container`, `file_name`, `mode`, and `byte_size`.
The tray renders **none of them**. A menu row reads "Read a file" or "Broker
an outbound request" — the action class and nothing more.

This matches the constraint already applied to the OS-notification body, for
the same reason and then some. The tray menu is a shared-desktop surface: it
renders whether or not the vault is unlocked, it is visible to anyone at the
machine, and on some desktops its contents are read by accessibility services
and screenshot tooling. A container or file name there is a durable on-screen
disclosure of exactly what the vault exists to keep private.

The consequence is deliberate and is the central trade of this ADR: **the tray
is for a request you already recognise.** A user who needs to know *which*
file is being read opens the app, where the request is shown behind the vault
lock. The tray makes a known decision fast; it does not make an unknown
decision informed.

Enforced by three tests: `TrayApproval` may not carry a detail field, tray
code may not read one, and every action label is a fixed string with no
interpolation hook.

### OTP requests never appear

Only click-approvals enter the tray. OTP-mode requests never become pending
approvals at all — `handle_otp` returns an error and requires the agent to
resend with a code displayed on the desktop. That escalation exists precisely
so the decision requires presence at the machine, and a one-click tray Approve
would silently undo it.

The type system does not enforce this: the registry is simply populated from
the click path only. A test pins the number of insert sites at one, so adding
a second fails there before it can reach a review.

### A tray decision is audited as a tray decision

Tray responses record `transport: "desktop-tray"`, distinct from the in-app
`"desktop-ui"`. A reviewer can then tell a decision made against a full
request view from one made against a menu label — a distinction that matters
precisely because the tray shows less.

The audit records the real action (`ReadFile`, `Broker`, ...), read from the
registry *before* responding. The desktop carries its own
`AccessAction -> AuditAction` mapping because `sv-mcp` keeps its own private;
both are exhaustive, so a new action must be mapped rather than silently
audited as something else.

### Lifecycle

- Inserted when a click-approval modal is emitted.
- Removed on decision (from either surface), supersede, or timeout — a menu
  row whose channel is gone would be a dead control.
- **Cleared on vault lock**, alongside pending remediation plans and for the
  same reason: a pending Approve row is a live authorization, and it must not
  survive the user deliberately ending their session. `respond_from_tray` also
  re-checks the lock, covering a request that arrived mid-transition.

### Bounds

At most 8 rows render; beyond that a disabled row reports the remainder and
directs the user to the app. A request storm must not produce an unbounded
native menu. Excess requests stay pending and answerable in the app.

Approve and Deny sit in a per-request submenu rather than a flat list, so a
mis-click cannot land on the opposite decision of an adjacent request.

## Consequences

- An agent's request can be answered without leaving the current application,
  which was the goal.
- The tray cannot tell the user what is being accessed. This is the accepted
  cost, not an oversight; the app remains the informed-decision surface.
- Tray creation failure is non-fatal — the app starts and the in-app queue
  remains the authoritative path to every pending request.
- `tauri`'s `tray-icon` feature is now enabled, which is not a default.

## Alternatives rejected

**Buttons on the OS notification.** Not implementable on desktop with this
plugin; see Context.

**Full request detail in the menu.** Would make the tray a
sufficient-information surface, at the cost of rendering container and file
names on a shared screen outside the vault lock. Rejected: it inverts the
protection the notification body already accepts.

**Approve-all / one-click approve of every pending request.** A single
gesture authorising a set the user has not enumerated, on a surface that does
not show what the set contains.
