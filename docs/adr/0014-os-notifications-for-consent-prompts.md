# ADR-0014 — OS notifications for consent prompts

- **Status:** Accepted
- **Date:** 2026-08-06
- **Deciders:** pealmeida

## Context

The consent gate (`T_hitl`) raises only an in-app modal via the
`vault://approval-request` event. When the Sovereign Vault window is unfocused
or minimized, the user never sees the prompt, the agent call blocks until the
120-second `APPROVAL_TIMEOUT_SECS` elapses, and the request fails with an
approval timeout. This is a usability failure of the human-in-the-loop control,
not a security failure: the gating still happens, it is simply not surfaced in
time.

The gap affects every prompt path: APPROVAL-mode click prompts, OTP-mode
challenges, and the mode-less sensitive actions (transit, signing, broker,
agent import/export, container create/list) that always gate on a click. In all
of them the only human-facing signal today is the webview event.

## Decision

Fire an OS-native device notification from the Rust side
(`tauri-plugin-notification`) at exactly the points where a consent prompt is
emitted: the three call sites that produce a `vault://approval-request` event
(the APPROVAL-mode click path, the OTP-mode challenge path, and the fresh-OTP
challenge path). A single helper, `emit_approval_prompt`, wraps the event emit
and the notification so the two channels stay in sync by construction.

Content is minimized to the action name alone. Container and file names stay
in the in-app modal: peer review
([R16](../thesis/review/R16-adr0014-security-deepseek.md)) noted that
lock-screen rendering and OS notification *history* expose notification text
beyond the unlocked session — a context that
[threat-model §C](../threat-model.md)'s disk-metadata reasoning does not
cover — so the notification is a pure attention signal. The one-time OTP code
is **never** included either; the OTP notification only says a code is pending
and that the user must open the app window to view it.

Delivery is best-effort. Notification errors (no daemon, denied permission,
unsupported platform) are swallowed (`let _ = ...`); the in-app modal remains
the authoritative consent channel and a missing notification daemon must never
fail or block the consent flow. The notification carries no approve/deny
actions, so consent itself cannot be given through the OS notification UI.

On Linux the implementation bypasses `tauri-plugin-notification` and talks to
`notify-rust` directly. The plugin drops the returned `NotificationHandle`,
which closes the D-Bus sender connection immediately; GNOME Shell then
destroys app-matched notification sources in `_onNameVanished`, so banners
were accepted by the daemon but never rendered (verified on GNOME Shell 50.1,
2026-08-06). The desktop path retains the handle for the lifetime of the
matching `vault://approval-request` and withdraws it on every
`vault://approval-cancel` path and on `approval_respond`, so the tray cannot
keep a stale alert after the in-app prompt is gone. A `desktop-entry` hint
equal to the bundled `.desktop` basename provides deterministic sender
identity. macOS/Windows keep the plugin, which already handles those
platforms' identity rituals correctly.

## Consequences

- **Positive.** Prompts are noticed when the window is unfocused or minimized,
  which restores the usability of the HITL control. A single wrapper keeps the
  event and the notification in sync, so no prompt can be emitted without a
  matching notification and vice-versa.
- **Negative.** The action name egresses to the OS notification service, where
  it may appear on the lock screen and persist in notification history;
  container/file names were initially included and were removed after peer
  review (R16) flagged precisely these surfaces. Linux now takes a direct
  dependency on `notify-rust` (already transitive via the plugin) so the
  handle can be retained and closed; that is a deliberate, bounded widening
  of the supply-chain surface governed by `deny.toml`. On macOS, notifications
  require a signed/bundled app to appear, which is consistent with the
  unsigned-builds residual risk already tracked in threat-model §5.
- **Linux transport note.** A missing or mismatched `.desktop` entry still
  degrades attribution in GNOME's notification settings, but it is no longer
  the cause of silent banner suppression — connection lifetime was.
## Alternatives considered

- **JS-side notifications from the Svelte UI.** Rejected: it would require
  relaxing the strict Content-Security-Policy and puts a security-adjacent
  signal in the webview, which is outside the vault's trust boundary.
- **Focusing/raising the window on each prompt.** Rejected: focus-stealing is
  hostile UX and platform-inconsistent, and it does not help when the window is
  minimized to a workspace the user is not viewing.
- **Keep `tauri-plugin-notification` on Linux and only install a `.desktop`
  entry.** Rejected after measurement: GNOME resolved the sender once a
  desktop entry existed, but still destroyed the notification within
  milliseconds because the plugin drops the D-Bus handle. Desktop integration
  is necessary for attribution; it is not sufficient for banner lifetime.
- **Hand-rolled persistent zbus connection / XDG Notification portal.**
  Deferred: more robust for Flatpak and multi-notification fan-out, but a
  larger API-shape change than retaining `notify-rust`'s handle for the
  consent lifetime. Revisit if packaging moves to a sandboxed portal path.
- **Do nothing.** Rejected: missed prompts break the HITL control's usability
  and turn every unfocused-window session into a 120-second timeout.

## References

- [ADR-0006](0006-mcp-integration.md) — MCP integration.
- [ADR-0013](0013-sensitivity-classifier-adaptive-consent.md) — adaptive
  consent.
- [docs/threat-model.md](../threat-model.md) §A (compromised agent) and §C
  (metadata is not confidential).
- [R16](../thesis/review/R16-adr0014-security-deepseek.md) — security peer
  review; its R1 finding removed container/file names from the notification
  body, and its R2 finding recorded the stale-notification limitation.
