# ADR-0025 — Security addendum (threat model and security review)

> **Note.** This file is a security addendum to [`docs/threat-model.md`](../threat-model.md)
> and [`docs/SECURITY-REVIEW.md`](../SECURITY-REVIEW.md) for
> [ADR-0025 — Presence-verified approvals](0025-presence-verified-approvals.md). It is kept
> in a separate file so that neither of those two documents is altered: both are cited by the
> monograph (`docs/thesis/`), which has been submitted and is under defence, and no document
> cited by the thesis may change while the submitted text stands. Nothing here modifies what
> those documents say. The two sections below are new material written as additions to them,
> and can be moved into `docs/threat-model.md` (as a new §3 row) and
> `docs/SECURITY-REVIEW.md` (as §6) once those documents may change again.

## Threat model — synthetic input driving the desktop UI

This is the content that would otherwise have been appended to `docs/threat-model.md` §3 as a
new subsection G (written here instead; docs/threat-model.md itself is unchanged), plus the supply-chain
sentence that would otherwise have been amended in §3.F.

### G. Synthetic input driving the desktop UI (ADR-0025)
- **Guarantee.** On a system the OS can attest, every operation classified
  `protected: true` — agent approvals, the tray and modal approve paths, the
  OTP reveal, and each gated desktop command — requires an OS-attested
  verification of the device owner (Touch ID / Mac login password on macOS,
  Windows Hello on Windows) before anything is released or mutated. Synthetic
  input (UI automation, accessibility APIs) can press the control but cannot
  pass the OS prompt, so it releases nothing beyond the MCP channel and does
  not unlock the vault. On a system classified `Unavailable` at creation the
  operation degrades to the **declared consent click** — audited
  `protected: false` with the permanent notice — never to "no gate"
  (`docs/development/specs/2026-09-28-presence-verified-approvals-design.md`
  §6.2, §7.5).
- **Declared limits.** (a) Linux is always `Unavailable`: no polkit, declared
  click everywhere (spec §5.3). (b) Windows below Build 22000 — the minimum
  supported client of the Hello interop — is `Unavailable` before any attempt
  (spec §5.2). (c) The modality is recorded only as the backend reports it:
  `unknown` on Windows (Hello PIN) and `unknown` on macOS, where robius 0.3.1
  exposes no modality and no prompt-free probe (plan D1). (d) A **denial**
  that happens while the vault is locked or not yet created cannot be
  HMAC-audited, because no key exists at that moment (plan D5, declared
  exception). (e) A lock plus a re-unlock between approval and consumption
  (plan D4) and an uncancellable open LocalAuthentication prompt (plan D13)
  are declared residuals, both fail-closed.
- **Declared without a gate, with the reason recorded in the spec (§7.5) and
  ADR-0025:** `vault_unlock` with passphrase custody and
  `vault_unlock_recovery` (they require knowledge the agent does not have);
  `vault_read_file` / `vault_export_file` on **DIRECT** containers (the same
  content is already reachable by any same-user process through the pairing
  endpoint `/.well-known/mcp-pairing`, §3.B above — revisit if §3.B changes);
  `vault_list_files` (metadata class, same standing as on-disk stat);
  `mcp_status` (the pairing secret it returns is already published to every
  local process). **Justified exceptions recorded in plan D8:** 
  `vault_list_containers` (container names are plaintext directory names and
  modes are plaintext in `manifest.json` — and MCP still asks for a click on
  `ListContainers`, author decision), `agent_list` (names and scopes, no
  tokens), `transit_create_key` / `signing_create_key` /
  `broker_create_secret` (they create material without releasing it, and every
  use still passes the MCP approval gate), `vault_change_passphrase` (requires
  the current passphrase), `notifications_set_enabled` and `scan_triage_set`
  (they change what the user notices, not what anyone may do). In
  `session_set_limits` a **decrease** is free and an **increase** is gated,
  because widening the limits keeps the vault unlocked longer (plan D15).

### Unsafe exception (§3.F of `docs/threat-model.md`, recorded here because that file is unchanged)

  Dependabot proposes dependency updates. `unsafe_code = "forbid"` is enforced workspace-wide, with one declared exception: `crates/sv-presence-windows` (ADR-0025), which needs two FFI calls into Windows and replaces the workspace lint with `#![deny(unsafe_op_in_unsafe_fn)]` and `#![deny(clippy::undocumented_unsafe_blocks)]` (see the Security review section below, §6.1).

## Security review

This is the content that would otherwise have been appended to `docs/SECURITY-REVIEW.md` as §6
(written here instead; docs/SECURITY-REVIEW.md itself is unchanged). The original heading
`## 6. ADR-0025 — Presence-verified approvals` and the intro below it are folded into this
section.

Review entry for the presence gate (decision:
[`docs/adr/0025-presence-verified-approvals.md`](0025-presence-verified-approvals.md);
spec:
[`docs/development/specs/2026-09-28-presence-verified-approvals-design.md`](../development/specs/2026-09-28-presence-verified-approvals-design.md)).

### 6.1 The `unsafe` exception

- **Where:** only in `crates/sv-presence-windows` — the one crate in the
  workspace allowed to use `unsafe`, declared as an exception in ADR-0025.
  Every own crate still opts into `[lints] workspace = true` except this one
  (`crates/sv-presence-windows/Cargo.toml:26-28` explains why).
- **The two calls:** `crates/sv-presence-windows/src/sys.rs:83`
  (`interop.RequestVerificationForWindowAsync(hwnd, &message)` — the `unsafe`
  interop method that owns the prompt window) and
  `crates/sv-presence-windows/src/sys.rs:99` (`RtlGetVersion(&mut info)`, used
  to read the Windows build number for the Build-22000 availability check).
- **The discipline:** `#![deny(unsafe_op_in_unsafe_fn)]`
  (`crates/sv-presence-windows/src/lib.rs:13`) and
  `#![deny(clippy::undocumented_unsafe_blocks)]`
  (`crates/sv-presence-windows/src/lib.rs:14`), with a `// SAFETY:` comment on
  every block. The forbidden fallbacks (`GetDesktopWindow` as prompt owner,
  title/class window hunting, synthetic keyboard input,
  `CredUIPromptForWindowsCredentialsW` / `LogonUserW`) are excluded by
  construction, not by configuration (spec §5.2).

### 6.2 Dependency risks

- **robius pin:** `robius-authentication = "=0.3.1"`, declared **only** under
  `[target.'cfg(target_os = "macos")'.dependencies]`
  (`crates/sv-presence/Cargo.toml:21`, `:23`), single maintainer, isolated
  behind the trait so it can be replaced without touching the gate (spec §11).
  The Windows backend is first-party over the workspace's existing `windows`
  0.61, so robius' own `windows` 0.56 pin never enters the graph.
- **`android-build` residual cost:** `android-build` (version 0.1.4,
  `Cargo.lock:57`) is an unconditional build-dependency of
  `robius-authentication` (`Cargo.lock:3869`), so the macOS-target restriction
  does **not** eliminate it: it still resolves and builds when compiling on
  macOS. Registered in ADR-0025 and spec §11 as a residual cost — decided and
  accepted, not claimed to be avoided.

### 6.3 Tray revision (ADR-0022)

- Tray **Approve** no longer decides from the menu: the item is now
  **"Review…"** and it opens the approval modal, which is where the native
  prompt can be hosted (`apps/desktop/src-tauri/src/tray.rs:191`; the rule is
  stated in the module docs at `apps/desktop/src-tauri/src/tray.rs:29-30`).
- **Deny stays direct** — refusing never requires presence (spec §2).
- The tray's action-class-only display rule is unchanged; what changed is that
  no one-click approve path remains for a decision whose purpose is a human
  decision.
