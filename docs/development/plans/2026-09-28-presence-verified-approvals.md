# Presence-verified approvals — implementation plan

> **Execution model (this repo):** the tasks are run one at a time by the
> Maestri OpenCode executors, each assigned by the orchestrator (Claude Code #2)
> according to the "Executor" line of the task. Codex (GPT-6-Astra) does not
> execute: it reviews at the three checkpoints marked **CHECKPOINT**. Steps use
> checkbox (`- [ ]`) syntax. **Commit steps run only after the orchestrator
> confirms that the user authorized commits for that PR**. Push, PR creation,
> and merge always need their own explicit request.

**Goal:** On every approval classified `protected: true`, and on every
desktop command that releases data or authority, an OS-native device-owner
verification must succeed before anything is committed. Where the platform
cannot attest presence, the declared consent click applies and the audit
records `protected: false`.

**Architecture:** A new crate `sv-presence` owns the pieces that do not
depend on a platform:
- the `PresenceVerifier` seam;
- the per-request `GateState` machine;
- `OpDescriptor`/`OpDigest`;
- the `PresenceCoordinator`, which runs one native prompt at a time with a
  queue of at most 8 waiting.

The macOS backend (robius-authentication 0.3.1) lives inside `sv-presence`.
The Windows backend is a separate crate, `sv-presence-windows`, the only
crate with a declared `unsafe` exception. Linux is always `Unavailable`.

The desktop app integrates in three places:
1. **Approvals.** `ApprovalState` fixes `protected` when the request is
   created. `respond` verifies before sending `true`.
2. **Desktop commands.** Desktop-originated commands go through one helper,
   `desktop_presence_gate`. On a protected system it opens the OS prompt;
   on a declared system it opens the consent modal.
3. **OTP.** The code is revealed only after a verification.

**Tech Stack:** Rust 1.88 (MSRV), tokio, async-trait, sha2 0.11, Tauri 2.11
(the `test` feature for `MockRuntime`), robius-authentication 0.3.1 (macOS
only), windows 0.61 (Windows only), Svelte 5 + vitest (UI).

**Spec:** `docs/development/specs/2026-09-28-presence-verified-approvals-design.md`
**Decision record:** `docs/adr/0025-presence-verified-approvals.md` (Proposed)

**Author decisions (2026-09-28, accepted):**
- D1: macOS is always classified protected.
- D5: denials on a locked or absent vault are not audited (declared exception).
- D8: `vault_list_containers` is a metadata exception.

**Plan review (Codex, adversarial):**
- round 1: 7 blockers;
- round 2: 6 blockers;
- round 3: 3 blockers;
- round 4: **approved with one caveat** (a timing-dependent test), applied.

Each blocker's fix is traced in D2, D4, D5, and D13–D15.

---

## Global Constraints

Copied from the spec and repo rules; they apply to every task.

- Own crates forbid `unsafe` (`[workspace.lints.rust] unsafe_code = "forbid"`, opted into with `[lints] workspace = true`). **Only** `crates/sv-presence-windows` is exempt, under `#![deny(unsafe_op_in_unsafe_fn)]` + `#![deny(clippy::undocumented_unsafe_blocks)]`, with a `// SAFETY:` comment on every block (spec §5.2).
- `robius-authentication = "=0.3.1"`, declared **only** under `[target.'cfg(target_os = "macos")'.dependencies]` (spec §5.1, §11).
- Windows backend on `windows` 0.61. Forbidden: `GetDesktopWindow` as prompt owner; finding the prompt window by title/class; synthetic keyboard input; `CredUIPromptForWindowsCredentialsW` / `LogonUserW` (spec §5.2).
- Windows minimum build for protection: **22000**; below it `availability()` = `Unavailable` (spec §5.2).
- One native prompt at a time; at most **8** waiting; the attempt that would be the 9th waiting is denied with `queue_full` (spec §6.1).
- The approval deadline stays `APPROVAL_TIMEOUT_SECS = 120` (`lib.rs:75`); the native prompt does not pause it (spec §6.1).
- Only these approve: macOS completion `Ok(())`, Windows `UserConsentVerificationResult::Verified`. `DisabledByPolicy` / `NotConfigured` / `Unavailable` mid-attempt **deny**; `Cancelled` / `Failed` / `Busy` / `Exhausted` return the request to `Pending`; `Timeout` → expired (spec §9.1).
- Modality is recorded only as the backend reports it, never inferred (spec §8).
- Audit `FORMAT_VERSION` stays **2**; new fields are optional and `skip_serializing_if = "Option::is_none"`.
- Refusing never requires presence (spec §2 goal 2).
- The renderer never supplies the verification outcome or the prompt text (spec §6.3).
- No edit under `docs/thesis/` (spec §12).
- Probes/scratch crates go outside the repo or carry an empty `[workspace]` table; run `git status` after any probe.
- CI gates each task must keep green: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --all-features`, and in `ui/`: `npm run check` and `npm test`.

## Implementation decisions beyond the spec (for Codex review at CHECKPOINT 1)

These decisions fill gaps the spec leaves open, and they fail closed. If
review rejects one, it is changed here before the owning task starts.

- **D1 — macOS availability and modality.** robius 0.3.1 has no probe that avoids showing a prompt, and `sv-presence` forbids `unsafe`, so it cannot call `canEvaluatePolicy` directly. So on macOS `availability()` is always `Protected { modalities: [Unknown] }`. If LocalAuthentication later reports `NotEnrolled`, `PasscodeNotSet`, or `Unavailable` when the prompt starts, the request is denied mid-attempt (spec §6.2), never downgraded to a click. The robius completion carries no modality, so macOS always records `modality: unknown`.
- **D2 — Operation identity, exclusivity, and sticky classification.** Each gated desktop operation is registered by its `op_digest` in `VaultState.desktop_ops`, with its own id, deadline, classification, and `GateState` (Task 11).
  - A retry of the same operation before its deadline reuses all four, as MCP requests do (spec §7.5).
  - A concurrent call for an operation already `Verifying` is refused with `AlreadyVerifying`; it never starts a second verification.
  - Only a terminal outcome ends the registration, and only for its own id, never a successor under the same digest. A lock clears the registry and invalidates any attempt in flight.
  - On top of that, the coordinator remembers any `Protected` it has seen during the process; after that, an `Unavailable` from `availability()` still classifies as `Protected`, so `verify()` denies instead of offering a click. Restarting the app resets this.
- **D3 — Two surfaces, one coordinator.** Agent-originated approvals keep the modal: Approve starts the OS prompt. Desktop-originated gated commands have no modal on a protected system — the user's click goes straight to the OS prompt. On a declared system they open the same consent modal they use today (`request_click`, `TrayMirror::No`).
- **D4 — Vault-state changes, from the prompt to the moment of consumption.** `SessionTimer` gets an `epoch: AtomicU64`.
  - **Where the epoch moves:** the handle and the epoch change together, under the same handle guard, and only through `publish_unlocked` / `publish_locked` (Task 7), before servers start or any access is released. The session id is derived from the epoch (`session-<epoch>`), so it can never be read inconsistently.
  - **Gate:** captures the epoch before the prompt and requires it unchanged after.
  - **Consumption:** the `GatePass` carries the epoch, and the release or mutation runs inside `with_gated_handle` / `with_gated_handle_mut`, which re-check it while holding the handle guard. Wake approval, keychain unlock, and init do their check-and-mutate under one guard too.
  - **MCP approvals:** `respond` records the Allowed event and sends `true` while holding the handle guard, and `DesktopAccessController::authorize` re-checks the epoch after approval.
  
  **Declared residual:** between `authorize` returning and sv-mcp taking the handle, a lock plus a **re-unlock** could let the approved request run in the new unlock. Closing this needs an sv-mcp change and is out of scope. It is bounded because a re-unlock needs the device owner: a keychain unlock is presence-gated, and a passphrase or recovery unlock needs knowledge. A lock alone still makes the request fail, because there is no handle.
  
  Locking also refuses every pending approval, invalidates their attempts and the desktop operations' attempts, and clears the OTP challenges.
- **D5 — Audit coverage.** Every presence decision (approve, deny, reveal) is recorded as a structured `presence` field with an `operation_id` that correlates all records of one operation:
  - `approval-<id>` for approvals;
  - `otp-<modal id>` for OTP;
  - `op-<desktop op id>` for desktop gates.
  
  **Allowed records are written with the handle held, before the decision takes effect:**
  - `respond`, before sending `true`;
  - OTP `Accepted`, before returning `Ok`;
  - desktop gates, inside `with_gated_handle`;
  - unlock/init, before publication.
  
  So a lock cannot drop an Allowed record while its effect survives. Denial records use `record_desktop_event_locked`, which awaits the handle instead of `try_lock`.
  
  **Declared exception (author decision):** a **denial** that happens while the vault is locked or not yet created cannot be HMAC-audited, because there is no key (`lib.rs:1834-1851`). This covers the denials of `vault_unlock` (keychain), `vault_init`, and any request refused because the vault locked mid-prompt. In all of these nothing is released, and the tests assert state and the absence of an Allowed record.
- **D6 — Where the approval decision is audited.** `ApprovalState::respond` writes its own `desktop-ui` record with the `presence` field, as `respond_from_tray` already does with `desktop-tray`. sv-mcp's own record is unchanged, and the `AccessController` signature does not change.
- **D7 — Which unlock is gated.** `vault_unlock` is gated whenever the requested custody is `OsKeychain`, including the passphrase→keychain migration path. It is the only unlock that can reach the keychain KEK.
- **D8 — Command classification.** Task 14 records a classification for each of the 49 registered commands. Some commands the spec does not name are recorded as *justified exceptions*, each with a reason:
  - `vault_list_containers`: returns container names and modes. Both are already readable by any same-user process: container names are plaintext directory names (`crates/sv-storage/src/lib.rs:379`), and modes live in the plaintext `manifest.json` (`crates/sv-storage/src/lib.rs:86`, `:765`). This is the same standing as `vault_list_files` (spec §7.5). **Author decision:** MCP still asks for a click on `ListContainers` (`lib.rs:2063`); the desktop listing adds nothing beyond `ls` + reading `manifest.json`.
  - `agent_list`: agent names and scopes, no tokens.
  - Key/secret creation (`transit_create_key`, `signing_create_key`, `broker_create_secret`): they create material without releasing it, and every use still passes the MCP approval gate.
  - `vault_change_passphrase`: requires the current passphrase.
  - `notifications_set_enabled`, `scan_triage_set`: they change what the user notices, not what anyone may do. No approval or release becomes possible without presence.
  
  `session_set_limits` is **not** an exception. Raising either limit keeps the vault unlocked longer, which widens exposure, so an increase is gated by presence; a decrease is free (Task 14, D15).
- **D9 — `remediate_restore` has no real restore today.** It always returns an error and removes the plan (`lib.rs:3615-3657`). The gate is placed before that removal, so a denied restore does not consume the plan.
- **D10 — Export destination.** The save dialog moves **before** the gate, so the export destination is part of `op_digest` (spec §7.5 item 2). A cancelled dialog still decrypts nothing and runs no gate.
- **D11 — Wake binding.** `wake_prepare_access` keeps its derived authorization, checked by `has_authorized_wake`: signature (agent + resource), agent, session, 300 s expiry. The per-operation binding stays in lease `checkout` (existing test `lease_single_use_and_exact_binding`). The session is now `session-<epoch>` of the approving unlock (D4).
- **D12 — ADR-0024 is a contract, and it stays open.** `submit_secret` / `submit_secret_direct` do not exist yet. This plan adds `secret_submit_op(request_id, container, env_var, expected_revision, expected_generation)`, binding both the revision (`null` → `"none"`) and the container generation id (ADR-0024 spec §4.3, §6). It also documents that the ADR-0024 implementation must call `desktop_presence_gate` with it and write through `with_gated_handle_mut`. **Spec §7.4 is NOT fulfilled by this plan.** It stays an open dependency, tracked in ADR-0025's implementation notes, until the submits exist and their §9.2 tests pass.
- **D13 — Cancellation is per attempt, and the backend owns it.** `PresenceCoordinator::begin_attempt()` returns an `Attempt` with its own `CancelSignal`, registered until dropped. `invalidate(id)` fires that attempt's signal; deadline expiry fires it too. The signal travels to the backend as a `verify` argument, which gives three guarantees:
  - a queued attempt leaves the queue without prompting;
  - a backend that has not opened its prompt yet never opens it — the contract is to check the signal immediately before opening (test with a barrier);
  - an open prompt is cancelled by its own backend, for that operation only. No global `cancel()` exists, so a cancel can never reach another attempt's prompt.
  
  The slot is released only when `verify` returns. The waiting counter uses an RAII guard, so an aborted waiter cannot leak a queue place.
  
  **Declared residual (macOS):** robius 0.3.1 cannot cancel an open LocalAuthentication prompt. This includes a cancellation that lands between the adapter's check and `start()`. Such a prompt stays until the user or the system ends it, it keeps the slot, and its result is discarded. The macOS adapter pins this in `cancellation_after_start_waits_for_the_prompt_to_end`.
  
  Dropping an `Attempt` fires its signal (for example, when the owner's future is aborted), so an abandoned attempt still cancels its backend operation where the platform can. `CancelSignal::cancelled()` treats a closed sender as cancelled.
- **D14 — `GatePass` is consumed under the handle lock.** Gated commands release or mutate only through `with_gated_handle(state, &pass, f)` / `with_gated_handle_mut`. These helpers lock the handle, re-check the epoch (D4), run `f`, and record the Allowed event with `pass.presence` before unlocking. `require_desktop_consent` returns the `GatePass`, not just its audit field.
- **D15 — Session limits.** `session_set_limits` is serialized by `VaultState.limits_change`, and it compares the requested values with the real current ones (atomics, no `try_lock` fallback).
  - A widening needs presence (op `session_limits`, current and requested values bound), and its pass is consumed through `with_gated_handle`.
  - A narrowing needs no presence.
  - A concurrent narrowing waits behind a pending widening; it never interleaves with it.

## Review Focus

These failure modes are implied by the spec but no single task naturally
covers them (item 6 was added after the Codex plan review, round 1). Each has a pinned test in the task named.

1. **An agent double-clicks Approve (or modal + stale tray) while the OS prompt is open.** Exactly one verification starts; the second call returns "verification already in progress" and does not deny the request (Task 8, `concurrent_approve_starts_one_verification`).
2. **A lock while the OS prompt is up.** The user presses Touch ID after the vault locked. Nothing is released and nothing is approved (Task 8 `lock_during_verification_denies`, Task 11 `lock_during_gate_releases_nothing`).
3. **A prompt that never ends** (no callback, no native cancel). Later requests queue, and those whose deadline passes expire. None skips the slot (Task 3 `slot_held_until_backend_ends_without_cancel`).
4. **An agent resends the exact correct OTP before anyone revealed it** (e.g. guessed or leaked by a timing channel). It is rejected and counts as a failed attempt, like a wrong code (Task 10 `correct_code_before_reveal_is_rejected`).
5. **An unprotected system's click modal for a desktop command is answered from the tray.** It is impossible: desktop clicks use `TrayMirror::No`, and the tray approve path never calls `respond(.., true)` (Task 9 `tray_approve_never_responds_true`).
6. **A lock plus a quick re-unlock between the gate passing and the data being released.** The release is refused, because the epoch is re-checked under the handle lock (Task 11 `relock_between_gate_and_consumption_denies`; Task 8 `mcp_authorize_rejects_approval_across_an_epoch_change`).

---

## File map

| File | Responsibility | Tasks |
|---|---|---|
| `Cargo.toml` (root) | members + workspace deps for the two new crates | 1, 5 |
| `crates/sv-presence/Cargo.toml` | new crate manifest | 1, 3, 4 |
| `crates/sv-presence/src/lib.rs` | public types, trait, `UnavailableVerifier`, `platform_verifier` | 1, 4 |
| `crates/sv-presence/src/op.rs` | `OpDescriptor`, `OpDigest`, prompt text | 1 |
| `crates/sv-presence/src/gate.rs` | `AttemptId`, `GateState`, `GateError` | 2 |
| `crates/sv-presence/src/coordinator.rs` | classification, slot + queue, deadlines | 3 |
| `crates/sv-presence/src/fake.rs` | `FakeVerifier` (feature `test-util`) | 3 |
| `crates/sv-presence/src/macos.rs` | `LaBoundary`, `MacVerifier`, error mapping (all OS) | 4 |
| `crates/sv-presence/src/robius.rs` | `RobiusBoundary` (macOS only) | 4 |
| `crates/sv-presence-windows/**` | Hello backend, result mapping | 5 |
| `crates/sv-audit/src/lib.rs` | `PresenceAudit` + `AuditEvent.presence` | 6 |
| `crates/sv-core/src/keyring.rs` | `active_dek_version` | 6 |
| `apps/desktop/src-tauri/Cargo.toml` | deps, dev-deps | 7 |
| `apps/desktop/src-tauri/src/presence.rs` (new) | coordinator construction, `desktop_presence_gate`, `GatePass`/`GateDenied`, op builders | 7, 11, 14 |
| `apps/desktop/src-tauri/src/lib.rs` | approvals, OTP, tray path, gated commands, tests | 7–14 |
| `apps/desktop/src-tauri/src/tray.rs` | doc update for the revised approve path | 9 |
| `ui/src/lib/types.ts`, `ui/src/stores/approvals.svelte.ts`, `ui/src/components/ApprovalModal.svelte`, `ui/src/components/OtpModal.svelte`, `ui/src/App.svelte` | protected label, reveal, focus event, unprotected notice | 8, 9, 10, 14 |
| `docs/threat-model.md`, `docs/SECURITY-REVIEW.md`, `docs/testing/presence-manual-cases.md` (new), `docs/adr/0025-…` | documentation | 15 |

## PR slicing

1. PR-A — Tasks 1–5: the crates. No desktop behavior change.
2. PR-B — Tasks 6–10: audit fields, desktop infrastructure, approvals, tray, OTP.
3. PR-C — Tasks 11–14: command gates, completeness test, notice, ADR-0024 contract.
4. PR-D — Task 15: docs.

Each PR is a branch off the updated `main`, and the 8 required checks must be green.

---

### Task 1: `sv-presence` crate — public types and `OpDescriptor`

**Executor:** OpenCode #4 (standard implementation).

**Files:**
- Modify: `Cargo.toml` (root): add `"crates/sv-presence"` to `members` after `"crates/sv-remediate"`; add `sv-presence = { path = "crates/sv-presence", version = "0.1.0" }` to `[workspace.dependencies]` after `sv-remediate`.
- Create: `crates/sv-presence/Cargo.toml`, `crates/sv-presence/src/lib.rs`, `crates/sv-presence/src/op.rs`

**Interfaces:**
- Produces: `Modality`, `Reason`, `Availability`, `PresenceError` (+ `is_retryable`), `Outcome`, `CancelSignal` (`new`, `is_cancelled`, `cancelled`), trait `PresenceVerifier` (`availability`, `verify(op, &CancelSignal)`), `UnavailableVerifier`, `OpDescriptor` (`new`, `field`, `bind`, `kind`, `digest`, `prompt_text`), `OpDigest` (`to_hex`).

- [ ] **Step 1: Create the manifest**

`crates/sv-presence/Cargo.toml`:

```toml
[package]
name        = "sv-presence"
version.workspace      = true
edition.workspace      = true
rust-version.workspace = true
license.workspace      = true
repository.workspace   = true
description = "OS-attested human presence for protected approvals (ADR-0025)."

[features]
# Exposes `fake::FakeVerifier` to dependents' tests.
test-util = []

[dependencies]
async-trait = "0.1"
hex         = { workspace = true }
sha2        = { workspace = true }
thiserror   = { workspace = true }
tokio       = { workspace = true }

[lints]
workspace = true
```

- [ ] **Step 2: Write the failing tests** in `crates/sv-presence/src/op.rs` (put the `#[cfg(test)] mod tests` at the bottom of the file you create in Step 4; write the tests first and a stub `impl` that `todo!()`s so they compile and fail):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_stable_for_equal_descriptions() {
        let a = OpDescriptor::new("read_file").field("container", "notes").field("file", "a.txt");
        let b = OpDescriptor::new("read_file").field("container", "notes").field("file", "a.txt");
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn digest_changes_with_any_field_kind_or_binding() {
        let base = OpDescriptor::new("read_file").field("container", "notes").bind("request_id", "1");
        assert_ne!(base.digest(), OpDescriptor::new("export_file").field("container", "notes").bind("request_id", "1").digest());
        assert_ne!(base.digest(), OpDescriptor::new("read_file").field("container", "other").bind("request_id", "1").digest());
        assert_ne!(base.digest(), OpDescriptor::new("read_file").field("container", "notes").bind("request_id", "2").digest());
    }

    #[test]
    fn digest_is_unambiguous_across_field_boundaries() {
        let a = OpDescriptor::new("k").field("x", "ab").field("y", "c");
        let b = OpDescriptor::new("k").field("x", "a").field("y", "bc");
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn shown_and_bound_fields_are_not_interchangeable() {
        let shown = OpDescriptor::new("k").field("x", "1");
        let bound = OpDescriptor::new("k").bind("x", "1");
        assert_ne!(shown.digest(), bound.digest());
    }

    #[test]
    fn prompt_text_strips_controls_and_quotes_and_truncates() {
        let op = OpDescriptor::new("read_file")
            .field("file", "evil\u{7}\n\"name\"")
            .field("container", "x".repeat(100))
            .bind("secret_binding", "never-shown");
        let text = op.prompt_text();
        assert!(!text.chars().any(char::is_control));
        assert!(!text.contains("never-shown"));
        assert!(text.starts_with("approve read file"));
        assert!(text.contains("file \"evil'name'\""));
        assert!(text.contains('…'));
        assert!(text.chars().count() <= MAX_PROMPT_CHARS);
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p sv-presence op::`
Expected: FAIL (panics at `todo!()` / not yet implemented).

- [ ] **Step 4: Implement `op.rs`**

```rust
//! What is being approved, and its digest (ADR-0025 §6.3).
//!
//! The digest is the contract between the prompt and the commit: the
//! finisher only commits when the digest the verification was granted for
//! equals the digest of the operation as it stands now. The prompt text is
//! derived from the same description, never supplied by the renderer.

use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"sv-presence-op-v1";
/// Longest field value shown in a native prompt, in characters.
pub(crate) const MAX_FIELD_CHARS: usize = 48;
/// Longest native prompt text, in characters.
pub(crate) const MAX_PROMPT_CHARS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Field {
    name: &'static str,
    value: String,
    /// Shown in the native prompt. Bound-only fields are part of the digest
    /// and never displayed (ids, digests, epochs).
    shown: bool,
}

/// A complete, immutable description of one protected operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpDescriptor {
    kind: &'static str,
    fields: Vec<Field>,
}

/// SHA-256 over a length-prefixed encoding of an [`OpDescriptor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpDigest([u8; 32]);

impl OpDigest {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl OpDescriptor {
    pub fn new(kind: &'static str) -> Self {
        Self { kind, fields: Vec::new() }
    }

    /// Add a field that is bound into the digest AND shown in the prompt.
    #[must_use]
    pub fn field(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.fields.push(Field { name, value: value.into(), shown: true });
        self
    }

    /// Add a field that is bound into the digest but never shown.
    #[must_use]
    pub fn bind(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.fields.push(Field { name, value: value.into(), shown: false });
        self
    }

    pub fn kind(&self) -> &'static str {
        self.kind
    }

    pub fn digest(&self) -> OpDigest {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        put(&mut hasher, self.kind.as_bytes());
        hasher.update((self.fields.len() as u64).to_be_bytes());
        for field in &self.fields {
            hasher.update([u8::from(field.shown)]);
            put(&mut hasher, field.name.as_bytes());
            put(&mut hasher, field.value.as_bytes());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        OpDigest(out)
    }

    /// Native prompt text: fixed words, then each shown field as
    /// `name "value"`, with control characters stripped, double quotes
    /// replaced, values truncated, and the whole bounded.
    pub fn prompt_text(&self) -> String {
        let mut text = format!("approve {}", self.kind.replace('_', " "));
        let shown: Vec<String> = self
            .fields
            .iter()
            .filter(|f| f.shown)
            .map(|f| format!("{} \"{}\"", f.name, sanitize(&f.value)))
            .collect();
        if !shown.is_empty() {
            text.push_str(" — ");
            text.push_str(&shown.join(", "));
        }
        truncate(&text, MAX_PROMPT_CHARS)
    }
}

fn put(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn sanitize(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == '"' { '\'' } else { c })
        .collect();
    truncate(&cleaned, MAX_FIELD_CHARS)
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut out: String = value.chars().take(max - 1).collect();
    out.push('…');
    out
}
```

- [ ] **Step 5: Implement `lib.rs`**

```rust
//! OS-attested human presence for protected approvals (ADR-0025).
//!
//! Platform-neutral pieces: the [`PresenceVerifier`] seam, the per-request
//! [`GateState`] machine, operation digests, and the [`PresenceCoordinator`]
//! that runs one native prompt at a time behind a bounded queue. The macOS
//! backend lives in [`macos`]; Windows is the separate `sv-presence-windows`
//! crate; Linux is always [`Availability::Unavailable`] (spec §5.3).

use std::sync::Arc;

mod op;

pub use op::{OpDescriptor, OpDigest};

/// How the device owner proved presence, as reported by the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modality {
    Biometric,
    Password,
    Pin,
    /// The backend does not say (Windows `Verified`, macOS completion).
    Unknown,
}

/// Why a system cannot attest presence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// No trustworthy mechanism on this platform (Linux, spec §5.3).
    UnsupportedPlatform,
    /// Windows below Build 22000 (spec §5.2).
    BelowMinimumBuild,
    NotConfigured,
    DisabledByPolicy,
    DeviceNotPresent,
}

impl Reason {
    pub fn message(&self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "no trustworthy OS presence check exists on this platform",
            Self::BelowMinimumBuild => "Windows Hello presence requires Windows 11 (build 22000) or later",
            Self::NotConfigured => "no biometric, PIN, or password verification is configured",
            Self::DisabledByPolicy => "OS presence verification is disabled by policy",
            Self::DeviceNotPresent => "no verification device is present",
        }
    }
}

/// Whether this system can attest presence right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    Protected { modalities: Vec<Modality> },
    Unavailable(Reason),
}

/// Why one verification did not succeed (spec §9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PresenceError {
    #[error("verification was cancelled")]
    Cancelled,
    #[error("verification failed")]
    Failed,
    #[error("the verification device is busy")]
    Busy,
    #[error("too many failed attempts; verification is locked out")]
    Exhausted,
    #[error("verification is disabled by policy")]
    DisabledByPolicy,
    #[error("no verification method is configured for this user")]
    NotConfigured,
    #[error("verification is unavailable")]
    Unavailable,
    #[error("verification timed out")]
    Timeout,
}

impl PresenceError {
    /// `true` for the four errors that return a request to `Pending`
    /// (spec §6.2); every other error denies the request.
    pub fn is_retryable(self) -> bool {
        matches!(self, Self::Cancelled | Self::Failed | Self::Busy | Self::Exhausted)
    }
}

/// A successful verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub modality: Modality,
}

/// Per-attempt cancellation, owned by the coordinator (plan D13). Each
/// verification gets its own signal, so a backend can never cancel another
/// attempt's prompt.
#[derive(Clone)]
pub struct CancelSignal(tokio::sync::watch::Receiver<bool>);

impl CancelSignal {
    /// A signal and the sender that fires it.
    pub fn new() -> (tokio::sync::watch::Sender<bool>, Self) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        (tx, Self(rx))
    }

    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }

    /// Resolves once the attempt is cancelled. A closed sender counts as
    /// cancelled: nobody is waiting for this prompt any more.
    pub async fn cancelled(&self) {
        let mut rx = self.0.clone();
        let _ = rx.wait_for(|cancelled| *cancelled).await;
    }
}

/// The seam every backend implements, reused by subproject A.
#[async_trait::async_trait]
pub trait PresenceVerifier: Send + Sync {
    fn availability(&self) -> Availability;

    /// Show the native prompt for `op` and return when it has ENDED — the
    /// final callback arrived or a native cancellation was confirmed. The
    /// coordinator relies on this to keep the prompt slot occupied (§6.1).
    ///
    /// Cancellation contract (D13): check `cancel.is_cancelled()`
    /// immediately before opening the native prompt and return
    /// `Err(Cancelled)` without opening it if set; if the platform can
    /// cancel, check again right after the native operation exists and race
    /// its completion against `cancel.cancelled()`, cancelling THIS
    /// operation only.
    async fn verify(&self, op: &OpDescriptor, cancel: &CancelSignal) -> Result<Outcome, PresenceError>;
}

/// The verifier for systems with no trustworthy mechanism.
pub struct UnavailableVerifier {
    reason: Reason,
}

impl UnavailableVerifier {
    pub fn new(reason: Reason) -> Self {
        Self { reason }
    }
}

#[async_trait::async_trait]
impl PresenceVerifier for UnavailableVerifier {
    fn availability(&self) -> Availability {
        Availability::Unavailable(self.reason.clone())
    }

    async fn verify(&self, _op: &OpDescriptor, _cancel: &CancelSignal) -> Result<Outcome, PresenceError> {
        Err(PresenceError::Unavailable)
    }
}

/// Verifier for the current platform. Windows is built by the desktop from
/// `sv-presence-windows`, because it needs the application's window.
pub fn platform_verifier() -> Arc<dyn PresenceVerifier> {
    Arc::new(UnavailableVerifier::new(Reason::UnsupportedPlatform))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_errors_are_exactly_the_four_of_section_6_2() {
        use PresenceError::*;
        for e in [Cancelled, Failed, Busy, Exhausted] {
            assert!(e.is_retryable(), "{e:?}");
        }
        for e in [DisabledByPolicy, NotConfigured, Unavailable, Timeout] {
            assert!(!e.is_retryable(), "{e:?}");
        }
    }

    #[tokio::test]
    async fn unavailable_verifier_never_verifies() {
        let v = UnavailableVerifier::new(Reason::UnsupportedPlatform);
        assert_eq!(v.availability(), Availability::Unavailable(Reason::UnsupportedPlatform));
        let (_tx, cancel) = CancelSignal::new();
        assert_eq!(
            v.verify(&OpDescriptor::new("x"), &cancel).await,
            Err(PresenceError::Unavailable)
        );
    }
}
```

(Task 4 replaces the body of `platform_verifier` with a `cfg` split.)

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p sv-presence`
Expected: PASS (7 tests).

- [ ] **Step 7: Lint and format**

Run: `cargo fmt --all && cargo clippy -p sv-presence --all-targets -- -D warnings`
Expected: no warnings.

- [ ] **Step 8: Commit** (after the orchestrator confirms authorization)

```bash
git add Cargo.toml Cargo.lock crates/sv-presence
git commit -m "feat(presence): criar o crate sv-presence com tipos e digest de operação"
```

---

### Task 2: `GateState` — the per-request state machine

**Executor:** OpenCode #4.

**Files:**
- Create: `crates/sv-presence/src/gate.rs`
- Modify: `crates/sv-presence/src/lib.rs` (add `mod gate;` and `pub use gate::{AttemptId, GateError, GateState};`)

**Interfaces:**
- Consumes: `OpDigest` (Task 1).
- Produces: `AttemptId(u64)` (constructed only inside the crate via `AttemptId::new`), `GateState { Pending, Verifying { attempt, digest }, Authenticated { digest } }`, methods `begin`, `finish`, `abort`, `is_authenticated_for`, `reset`; `GateError { AlreadyVerifying, NotPending, StaleAttempt, DigestMismatch, Expired }`.

- [ ] **Step 1: Write the failing tests** (bottom of `gate.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::OpDescriptor;
    use std::time::{Duration, Instant};

    fn d(kind: &'static str) -> OpDigest {
        OpDescriptor::new(kind).digest()
    }

    #[test]
    fn begin_then_finish_authenticates() {
        let mut g = GateState::default();
        let a = AttemptId::new(1);
        g.begin(a, d("x")).unwrap();
        let later = Instant::now() + Duration::from_secs(60);
        g.finish(a, d("x"), d("x"), later, Instant::now()).unwrap();
        assert!(g.is_authenticated_for(d("x")));
        assert!(!g.is_authenticated_for(d("y")));
    }

    #[test]
    fn second_begin_while_verifying_is_rejected() {
        let mut g = GateState::default();
        g.begin(AttemptId::new(1), d("x")).unwrap();
        assert_eq!(g.begin(AttemptId::new(2), d("x")), Err(GateError::AlreadyVerifying));
    }

    #[test]
    fn stale_attempt_cannot_finish() {
        let mut g = GateState::default();
        g.begin(AttemptId::new(1), d("x")).unwrap();
        let later = Instant::now() + Duration::from_secs(60);
        assert_eq!(
            g.finish(AttemptId::new(2), d("x"), d("x"), later, Instant::now()),
            Err(GateError::StaleAttempt)
        );
        assert!(matches!(g, GateState::Verifying { .. }));
    }

    #[test]
    fn digest_mismatch_returns_to_pending() {
        let mut g = GateState::default();
        let a = AttemptId::new(1);
        g.begin(a, d("x")).unwrap();
        let later = Instant::now() + Duration::from_secs(60);
        assert_eq!(g.finish(a, d("x"), d("y"), later, Instant::now()), Err(GateError::DigestMismatch));
        assert_eq!(g, GateState::Pending);
        g.begin(a, d("x")).unwrap();
        assert_eq!(g.finish(a, d("z"), d("x"), later, Instant::now()), Err(GateError::DigestMismatch));
    }

    #[test]
    fn late_result_after_deadline_is_discarded() {
        let mut g = GateState::default();
        let a = AttemptId::new(1);
        g.begin(a, d("x")).unwrap();
        let deadline = Instant::now();
        let after = deadline + Duration::from_millis(1);
        assert_eq!(g.finish(a, d("x"), d("x"), deadline, after), Err(GateError::Expired));
        assert!(!g.is_authenticated_for(d("x")));
    }

    #[test]
    fn abort_only_affects_the_matching_attempt() {
        let mut g = GateState::default();
        g.begin(AttemptId::new(1), d("x")).unwrap();
        g.abort(AttemptId::new(2));
        assert!(matches!(g, GateState::Verifying { .. }));
        g.abort(AttemptId::new(1));
        assert_eq!(g, GateState::Pending);
    }

    #[test]
    fn authenticated_is_not_pending() {
        let mut g = GateState::Authenticated { digest: d("x") };
        assert_eq!(g.begin(AttemptId::new(1), d("x")), Err(GateError::NotPending));
        g.reset();
        assert_eq!(g, GateState::Pending);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p sv-presence gate::`
Expected: FAIL to compile (`GateState` not defined).

- [ ] **Step 3: Implement `gate.rs`**

```rust
//! Per-request attempt state (ADR-0025 §6.1).
//!
//! `Pending → Verifying` happens under the owner's lock, which is then
//! released while the native prompt runs; the finisher re-acquires the lock
//! and commits only if the same attempt is still `Verifying`, the digest the
//! verification was granted for equals the stored one and the current one,
//! and the deadline has not passed.

use std::time::Instant;

use crate::OpDigest;

/// Identity of one verification attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttemptId(u64);

impl AttemptId {
    pub(crate) fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GateState {
    #[default]
    Pending,
    Verifying { attempt: AttemptId, digest: OpDigest },
    /// A verification bound to `digest` succeeded. Approval requests are
    /// removed at this point; OTP challenges stay here until the resend.
    Authenticated { digest: OpDigest },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GateError {
    #[error("a verification is already in progress for this request")]
    AlreadyVerifying,
    #[error("the request is not awaiting verification")]
    NotPending,
    #[error("the verification result belongs to an older attempt")]
    StaleAttempt,
    #[error("the request changed during verification")]
    DigestMismatch,
    #[error("the request expired during verification")]
    Expired,
}

impl GateState {
    pub fn begin(&mut self, attempt: AttemptId, digest: OpDigest) -> Result<(), GateError> {
        match self {
            Self::Pending => {
                *self = Self::Verifying { attempt, digest };
                Ok(())
            }
            Self::Verifying { .. } => Err(GateError::AlreadyVerifying),
            Self::Authenticated { .. } => Err(GateError::NotPending),
        }
    }

    pub fn finish(
        &mut self,
        attempt: AttemptId,
        granted: OpDigest,
        current: OpDigest,
        deadline: Instant,
        now: Instant,
    ) -> Result<(), GateError> {
        let Self::Verifying { attempt: active, digest } = *self else {
            return Err(GateError::StaleAttempt);
        };
        if active != attempt {
            return Err(GateError::StaleAttempt);
        }
        if digest != granted || digest != current {
            *self = Self::Pending;
            return Err(GateError::DigestMismatch);
        }
        if now > deadline {
            *self = Self::Pending;
            return Err(GateError::Expired);
        }
        *self = Self::Authenticated { digest };
        Ok(())
    }

    /// A retryable failure (§6.2): back to `Pending`, only for this attempt.
    pub fn abort(&mut self, attempt: AttemptId) {
        if matches!(self, Self::Verifying { attempt: a, .. } if *a == attempt) {
            *self = Self::Pending;
        }
    }

    pub fn is_authenticated_for(&self, digest: OpDigest) -> bool {
        matches!(self, Self::Authenticated { digest: d } if *d == digest)
    }

    /// Any change of the underlying request clears the authenticated state
    /// (§7.3).
    pub fn reset(&mut self) {
        *self = Self::Pending;
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p sv-presence gate::`
Expected: PASS (7 tests).

- [ ] **Step 5: Lint, format, commit** (commit after authorization)

```bash
cargo fmt --all && cargo clippy -p sv-presence --all-targets -- -D warnings
git add crates/sv-presence
git commit -m "feat(presence): adicionar a máquina de estados por tentativa"
```

---

### Task 3: `PresenceCoordinator` and `FakeVerifier`

**Executor:** OpenCode #3 (concurrency; hardest core logic).

**Files:**
- Create: `crates/sv-presence/src/coordinator.rs`, `crates/sv-presence/src/fake.rs`
- Modify: `crates/sv-presence/src/lib.rs` — add:

```rust
mod coordinator;

#[cfg(any(test, feature = "test-util"))]
pub mod fake;

pub use coordinator::{Attempt, Classification, Denial, PresenceCoordinator, Verified, MAX_WAITING};
```

**Interfaces:**
- Consumes: `PresenceVerifier`, `OpDescriptor`, `OpDigest`, `AttemptId`, `Availability`, `Reason`, `PresenceError`, `Outcome`.
- Produces:
  - `PresenceCoordinator::new(Arc<dyn PresenceVerifier>) -> Self`
  - `fn begin_attempt(&self) -> Attempt` — `Attempt` is registered for invalidation until dropped; `Attempt::id(&self) -> AttemptId`
  - `fn classify(&self) -> Classification` (sticky, D2)
  - `async fn verify(&self, attempt: &Attempt, op: &OpDescriptor, deadline: std::time::Instant) -> Result<Verified, Denial>`
  - `fn invalidate(&self, id: AttemptId)` (D13: fires that attempt's `CancelSignal` — queued → leaves without prompting; not yet opened → never opens; open → the backend cancels its own operation)
  - `Classification { Protected, Unprotected(Reason) }` + `is_protected()`
  - `Denial { Retryable(PresenceError), Denied(PresenceError), Expired, QueueFull, Invalidated }` + `message() -> String`
  - `Verified { attempt, digest, outcome }`
  - `fake::FakeVerifier` (`protected()`, `unavailable()`, `set_availability`, `push`, `approve_next`, `calls`, `opened`, `cancels`, `set_cancel_supported`, `release`, `pause_before_open`, `wait_until_paused`, `resume`) and `fake::FakeStep { Return(Result<Outcome, PresenceError>), Hold(Result<Outcome, PresenceError>) }`

- [ ] **Step 1: Implement `fake.rs`** (test infrastructure; the tests in Step 2 drive it)

```rust
//! Scriptable verifier for coordinator and desktop tests. It proves nothing
//! about the real OS prompt (spec §9.2); the manual cases in
//! `docs/testing/presence-manual-cases.md` do. It honours the cancellation
//! contract of `PresenceVerifier::verify` exactly as real backends must.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use crate::{Availability, CancelSignal, Modality, OpDescriptor, Outcome, PresenceError, PresenceVerifier, Reason};

#[derive(Debug, Clone, Copy)]
pub enum FakeStep {
    /// Return immediately.
    Return(Result<Outcome, PresenceError>),
    /// Keep the "prompt" open until [`FakeVerifier::release`], or until the
    /// attempt is cancelled when cancellation is supported (`Cancelled`).
    Hold(Result<Outcome, PresenceError>),
}

pub const APPROVED: Result<Outcome, PresenceError> = Ok(Outcome { modality: Modality::Unknown });

pub struct FakeVerifier {
    availability: Mutex<Availability>,
    script: Mutex<VecDeque<FakeStep>>,
    /// `verify` was entered.
    calls: AtomicUsize,
    /// A "native prompt" was actually opened.
    opened: AtomicUsize,
    /// Open prompts closed by cancellation.
    cancels: AtomicUsize,
    cancel_supported: AtomicBool,
    release: Notify,
    pause_before_open: AtomicBool,
    paused: Notify,
    resume: Notify,
}

impl FakeVerifier {
    pub fn with_availability(availability: Availability) -> Arc<Self> {
        Arc::new(Self {
            availability: Mutex::new(availability),
            script: Mutex::new(VecDeque::new()),
            calls: AtomicUsize::new(0),
            opened: AtomicUsize::new(0),
            cancels: AtomicUsize::new(0),
            cancel_supported: AtomicBool::new(false),
            release: Notify::new(),
            pause_before_open: AtomicBool::new(false),
            paused: Notify::new(),
            resume: Notify::new(),
        })
    }

    pub fn protected() -> Arc<Self> {
        Self::with_availability(Availability::Protected { modalities: vec![Modality::Unknown] })
    }

    pub fn unavailable() -> Arc<Self> {
        Self::with_availability(Availability::Unavailable(Reason::UnsupportedPlatform))
    }

    pub fn set_availability(&self, availability: Availability) {
        *self.availability.lock().unwrap_or_else(|e| e.into_inner()) = availability;
    }

    pub fn push(&self, step: FakeStep) {
        self.script.lock().unwrap_or_else(|e| e.into_inner()).push_back(step);
    }

    pub fn approve_next(&self) {
        self.push(FakeStep::Return(APPROVED));
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub fn opened(&self) -> usize {
        self.opened.load(Ordering::SeqCst)
    }

    pub fn cancels(&self) -> usize {
        self.cancels.load(Ordering::SeqCst)
    }

    pub fn set_cancel_supported(&self, supported: bool) {
        self.cancel_supported.store(supported, Ordering::SeqCst);
    }

    /// End one held prompt with its scripted result.
    pub fn release(&self) {
        self.release.notify_one();
    }

    /// Make the next `verify` stop just before it would open the prompt
    /// (a barrier for interleaving tests).
    pub fn pause_before_open(&self) {
        self.pause_before_open.store(true, Ordering::SeqCst);
    }

    /// Wait until a `verify` reached the barrier.
    pub async fn wait_until_paused(&self) {
        self.paused.notified().await;
    }

    pub fn resume(&self) {
        self.pause_before_open.store(false, Ordering::SeqCst);
        self.resume.notify_one();
    }
}

#[async_trait::async_trait]
impl PresenceVerifier for FakeVerifier {
    fn availability(&self) -> Availability {
        self.availability.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    async fn verify(&self, _op: &OpDescriptor, cancel: &CancelSignal) -> Result<Outcome, PresenceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.pause_before_open.load(Ordering::SeqCst) {
            self.paused.notify_one();
            self.resume.notified().await;
        }
        // The contract: never open a prompt for a cancelled attempt.
        if cancel.is_cancelled() {
            return Err(PresenceError::Cancelled);
        }
        self.opened.fetch_add(1, Ordering::SeqCst);
        let step = self
            .script
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
            // An unscripted prompt fails: a test that forgot to script an
            // approval must never pass by accident.
            .unwrap_or(FakeStep::Return(Err(PresenceError::Failed)));
        match step {
            FakeStep::Return(result) => result,
            FakeStep::Hold(result) => {
                let cancellable = self.cancel_supported.load(Ordering::SeqCst);
                tokio::select! {
                    _ = self.release.notified() => result,
                    _ = cancel.cancelled(), if cancellable => {
                        self.cancels.fetch_add(1, Ordering::SeqCst);
                        Err(PresenceError::Cancelled)
                    }
                }
            }
        }
    }
}
```

- [ ] **Step 2: Write the failing coordinator tests** (bottom of `coordinator.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeStep, FakeVerifier, APPROVED};
    use crate::{Availability, Modality};
    use std::time::Duration;

    fn op() -> OpDescriptor {
        OpDescriptor::new("read_file").field("file", "a.txt")
    }

    fn in_ms(ms: u64) -> Instant {
        Instant::now() + Duration::from_millis(ms)
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    /// Start one verification on a spawned task; returns its attempt id.
    fn spawn_verify(
        c: &Arc<PresenceCoordinator>,
        deadline: Instant,
    ) -> (AttemptId, tokio::task::JoinHandle<Result<Verified, Denial>>) {
        let attempt = c.begin_attempt();
        let id = attempt.id();
        let c = c.clone();
        (id, tokio::spawn(async move { c.verify(&attempt, &op(), deadline).await }))
    }

    #[tokio::test]
    async fn approval_carries_the_digest_it_was_granted_for() {
        let fake = FakeVerifier::protected();
        fake.approve_next();
        let c = PresenceCoordinator::new(fake.clone());
        let a = c.begin_attempt();
        let v = c.verify(&a, &op(), in_ms(1_000)).await.unwrap();
        assert_eq!(v.digest, op().digest());
        assert_eq!(v.attempt, a.id());
        assert_eq!(v.outcome.modality, Modality::Unknown);
    }

    #[tokio::test]
    async fn error_classes_map_per_section_9_1() {
        for (err, expected) in [
            (PresenceError::Cancelled, Denial::Retryable(PresenceError::Cancelled)),
            (PresenceError::Exhausted, Denial::Retryable(PresenceError::Exhausted)),
            (PresenceError::Unavailable, Denial::Denied(PresenceError::Unavailable)),
            (PresenceError::DisabledByPolicy, Denial::Denied(PresenceError::DisabledByPolicy)),
            (PresenceError::NotConfigured, Denial::Denied(PresenceError::NotConfigured)),
            (PresenceError::Timeout, Denial::Expired),
        ] {
            let fake = FakeVerifier::protected();
            fake.push(FakeStep::Return(Err(err)));
            let c = PresenceCoordinator::new(fake);
            let got = c.verify(&c.begin_attempt(), &op(), in_ms(1_000)).await;
            assert_eq!(got.unwrap_err(), expected, "{err:?}");
        }
    }

    #[tokio::test]
    async fn one_verification_satisfies_exactly_one_call() {
        let fake = FakeVerifier::protected();
        fake.approve_next();
        let c = PresenceCoordinator::new(fake.clone());
        assert!(c.verify(&c.begin_attempt(), &op(), in_ms(1_000)).await.is_ok());
        // Nothing is cached: the next call prompts again and, unscripted, fails.
        assert!(c.verify(&c.begin_attempt(), &op(), in_ms(1_000)).await.is_err());
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn deadline_expires_while_prompt_is_open() {
        let fake = FakeVerifier::protected();
        fake.push(FakeStep::Hold(APPROVED));
        let c = PresenceCoordinator::new(fake.clone());
        let got = c.verify(&c.begin_attempt(), &op(), in_ms(50)).await;
        assert_eq!(got.unwrap_err(), Denial::Expired);
        // The late approval is discarded: releasing it changes nothing here.
        fake.release();
    }

    #[tokio::test]
    async fn slot_held_until_backend_ends_without_cancel() {
        let fake = FakeVerifier::protected(); // cancel unsupported
        fake.push(FakeStep::Hold(APPROVED)); // A
        fake.approve_next(); // B
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        assert_eq!(
            c.verify(&c.begin_attempt(), &op(), in_ms(50)).await.unwrap_err(),
            Denial::Expired
        );
        let (_, b) = spawn_verify(&c, in_ms(2_000));
        settle().await;
        assert_eq!(fake.calls(), 1, "B must not reach the backend while A's prompt is open");
        fake.release(); // A's native prompt finally ends
        assert!(b.await.unwrap().is_ok());
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn expiry_requests_native_cancel_when_supported() {
        let fake = FakeVerifier::protected();
        fake.set_cancel_supported(true);
        fake.push(FakeStep::Hold(APPROVED));
        fake.approve_next();
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        assert_eq!(
            c.verify(&c.begin_attempt(), &op(), in_ms(50)).await.unwrap_err(),
            Denial::Expired
        );
        assert_eq!(fake.cancels(), 1);
        assert!(c.verify(&c.begin_attempt(), &op(), in_ms(2_000)).await.is_ok());
    }

    #[tokio::test]
    async fn queue_full_denies_the_ninth_waiter_only() {
        let fake = FakeVerifier::protected();
        fake.push(FakeStep::Hold(APPROVED)); // the active prompt
        for _ in 0..MAX_WAITING {
            fake.approve_next();
        }
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        let (_, active) = spawn_verify(&c, in_ms(5_000));
        settle().await;
        let waiters: Vec<_> = (0..MAX_WAITING).map(|_| spawn_verify(&c, in_ms(5_000)).1).collect();
        settle().await;
        assert_eq!(
            c.verify(&c.begin_attempt(), &op(), in_ms(5_000)).await.unwrap_err(),
            Denial::QueueFull
        );
        fake.release();
        assert!(active.await.unwrap().is_ok());
        for w in waiters {
            assert!(w.await.unwrap().is_ok(), "queued requests are unaffected by the refusal");
        }
    }

    #[tokio::test]
    async fn waiting_request_expires_without_reaching_the_backend() {
        let fake = FakeVerifier::protected();
        fake.push(FakeStep::Hold(APPROVED));
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        let _active = spawn_verify(&c, in_ms(5_000));
        settle().await;
        assert_eq!(
            c.verify(&c.begin_attempt(), &op(), in_ms(50)).await.unwrap_err(),
            Denial::Expired
        );
        assert_eq!(fake.calls(), 1);
        fake.release();
    }

    /// D13: a request refused (or locked) while queued never prompts.
    #[tokio::test]
    async fn invalidated_while_queued_never_prompts() {
        let fake = FakeVerifier::protected();
        fake.push(FakeStep::Hold(APPROVED));
        fake.approve_next(); // would be B's result if B ever prompted
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        let (_, active) = spawn_verify(&c, in_ms(5_000));
        settle().await;
        let (b_id, b) = spawn_verify(&c, in_ms(5_000));
        settle().await;
        c.invalidate(b_id);
        assert_eq!(b.await.unwrap().unwrap_err(), Denial::Invalidated);
        fake.release();
        assert!(active.await.unwrap().is_ok());
        settle().await;
        assert_eq!(fake.opened(), 1, "B never opened a prompt");
    }

    /// D13: invalidation that races ahead of `verify` is not lost.
    #[tokio::test]
    async fn invalidated_before_verify_starts_never_prompts() {
        let fake = FakeVerifier::protected();
        fake.approve_next();
        let c = PresenceCoordinator::new(fake.clone());
        let a = c.begin_attempt();
        c.invalidate(a.id());
        assert_eq!(c.verify(&a, &op(), in_ms(1_000)).await.unwrap_err(), Denial::Invalidated);
        assert_eq!(fake.calls(), 0);
    }

    #[tokio::test]
    async fn invalidating_the_active_attempt_requests_native_cancel() {
        let fake = FakeVerifier::protected();
        fake.set_cancel_supported(true);
        fake.push(FakeStep::Hold(APPROVED));
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        let (id, a) = spawn_verify(&c, in_ms(5_000));
        settle().await;
        c.invalidate(id);
        assert_eq!(a.await.unwrap().unwrap_err(), Denial::Invalidated);
        assert_eq!(fake.cancels(), 1);
    }

    /// D13: cancelling a finished attempt never reaches the next prompt.
    #[tokio::test]
    async fn cancel_never_reaches_the_next_attempt() {
        let fake = FakeVerifier::protected();
        fake.set_cancel_supported(true);
        fake.approve_next(); // A finishes at once
        fake.push(FakeStep::Hold(APPROVED)); // B stays open
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        let a = c.begin_attempt();
        let a_id = a.id();
        assert!(c.verify(&a, &op(), in_ms(1_000)).await.is_ok());
        let (_, b) = spawn_verify(&c, in_ms(5_000));
        settle().await;
        c.invalidate(a_id);
        assert_eq!(fake.cancels(), 0, "A is no longer active; B must not be cancelled");
        fake.release();
        assert!(b.await.unwrap().is_ok());
    }

    /// D13: aborted waiters give their queue place back (RAII guard).
    #[tokio::test]
    async fn aborted_waiters_do_not_leak_queue_places() {
        let fake = FakeVerifier::protected();
        fake.push(FakeStep::Hold(APPROVED));
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        let _active = spawn_verify(&c, in_ms(10_000));
        settle().await;
        for _round in 0..3 {
            let waiters: Vec<_> = (0..MAX_WAITING).map(|_| spawn_verify(&c, in_ms(10_000)).1).collect();
            settle().await;
            for w in &waiters {
                w.abort();
            }
            settle().await;
        }
        // With leaked places this would be QueueFull.
        assert_eq!(
            c.verify(&c.begin_attempt(), &op(), in_ms(50)).await.unwrap_err(),
            Denial::Expired
        );
        fake.release();
    }

    /// D13: invalidation landing between queue admission and the backend
    /// opening its prompt never opens it (barrier interleaving).
    #[tokio::test]
    async fn invalidated_between_admission_and_open_never_opens() {
        let fake = FakeVerifier::protected();
        fake.approve_next();
        fake.pause_before_open();
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        let (id, task) = spawn_verify(&c, in_ms(5_000));
        fake.wait_until_paused().await;
        c.invalidate(id);
        fake.resume();
        assert_eq!(task.await.unwrap().unwrap_err(), Denial::Invalidated);
        settle().await;
        assert_eq!(fake.opened(), 0, "the backend saw the signal before opening");
    }

    /// An owner aborted after the prompt opened still cancels it (the
    /// `Attempt` drop fires the signal).
    #[tokio::test]
    async fn aborted_owner_cancels_its_open_prompt() {
        let fake = FakeVerifier::protected();
        fake.set_cancel_supported(true);
        fake.push(FakeStep::Hold(APPROVED));
        let c = Arc::new(PresenceCoordinator::new(fake.clone()));
        let (_, task) = spawn_verify(&c, in_ms(5_000));
        settle().await;
        assert_eq!(fake.opened(), 1);
        task.abort();
        settle().await;
        assert_eq!(fake.cancels(), 1);
    }

    #[test]
    fn classification_is_sticky_once_protected() {
        let fake = FakeVerifier::protected();
        let c = PresenceCoordinator::new(fake.clone());
        assert_eq!(c.classify(), Classification::Protected);
        fake.set_availability(Availability::Unavailable(Reason::NotConfigured));
        assert_eq!(c.classify(), Classification::Protected, "D2: never downgrade in-process");
    }

    #[test]
    fn unavailable_from_start_classifies_unprotected() {
        let c = PresenceCoordinator::new(FakeVerifier::unavailable());
        assert_eq!(c.classify(), Classification::Unprotected(Reason::UnsupportedPlatform));
    }

    #[test]
    fn queue_full_message_names_the_reason() {
        assert!(Denial::QueueFull.message().starts_with("queue_full"));
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p sv-presence coordinator::`
Expected: FAIL to compile (`PresenceCoordinator` missing).

- [ ] **Step 4: Implement `coordinator.rs`**

```rust
//! One native prompt at a time, behind a bounded queue (ADR-0025 §6.1),
//! with per-attempt cancellation signals (plan D13).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{oneshot, watch, Semaphore};

use crate::gate::AttemptId;
use crate::{
    Availability, CancelSignal, OpDescriptor, OpDigest, Outcome, PresenceError, PresenceVerifier, Reason,
};

/// Requests allowed to wait while one prompt is active.
pub const MAX_WAITING: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    Protected,
    Unprotected(Reason),
}

impl Classification {
    pub fn is_protected(&self) -> bool {
        matches!(self, Self::Protected)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// Back to `Pending`; the user may try again (§6.2).
    Retryable(PresenceError),
    /// The request is denied (§6.2 mid-attempt unavailability).
    Denied(PresenceError),
    /// The deadline passed (while waiting, or with the prompt open).
    Expired,
    /// The 9th waiter while one prompt is active (§6.1).
    QueueFull,
    /// The owner invalidated the attempt: refusal, lock, or disconnect.
    Invalidated,
}

impl Denial {
    pub fn message(&self) -> String {
        match self {
            Self::Retryable(e) => format!("presence not confirmed: {e}; you can try again"),
            Self::Denied(e) => format!("presence verification denied: {e}"),
            Self::Expired => "presence verification expired".to_string(),
            Self::QueueFull => {
                "queue_full: too many requests are waiting for presence verification".to_string()
            }
            Self::Invalidated => {
                "presence verification invalidated: the request was refused, expired, or the vault locked"
                    .to_string()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    pub attempt: AttemptId,
    pub digest: OpDigest,
    pub outcome: Outcome,
}

type Registry = Arc<Mutex<HashMap<AttemptId, Arc<watch::Sender<bool>>>>>;

/// One verification attempt, registered for invalidation until dropped.
pub struct Attempt {
    id: AttemptId,
    fire: Arc<watch::Sender<bool>>,
    cancel: CancelSignal,
    registry: Registry,
}

impl Attempt {
    pub fn id(&self) -> AttemptId {
        self.id
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        // An abandoned attempt (e.g. its owner's future was aborted) must
        // still close its prompt where the backend can. Harmless after the
        // backend already returned.
        self.fire.send_replace(true);
        self.registry.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.id);
    }
}

/// A queue place, returned on drop even if the waiting future is aborted.
struct QueuePlace(Arc<AtomicUsize>);

impl Drop for QueuePlace {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct PresenceCoordinator {
    verifier: Arc<dyn PresenceVerifier>,
    slot: Arc<Semaphore>,
    waiting: Arc<AtomicUsize>,
    seen_protected: AtomicBool,
    next_attempt: AtomicU64,
    registry: Registry,
}

impl PresenceCoordinator {
    pub fn new(verifier: Arc<dyn PresenceVerifier>) -> Self {
        Self {
            verifier,
            slot: Arc::new(Semaphore::new(1)),
            waiting: Arc::new(AtomicUsize::new(0)),
            seen_protected: AtomicBool::new(false),
            next_attempt: AtomicU64::new(0),
            registry: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a new attempt. Owners call this under their own lock, at
    /// `Pending -> Verifying`, so an invalidation can never be lost.
    pub fn begin_attempt(&self) -> Attempt {
        let id = AttemptId::new(self.next_attempt.fetch_add(1, Ordering::SeqCst) + 1);
        let (fire, cancel) = CancelSignal::new();
        let fire = Arc::new(fire);
        self.registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, Arc::clone(&fire));
        Attempt { id, fire, cancel, registry: Arc::clone(&self.registry) }
    }

    /// Classify a request at creation (§6.2). Sticky (plan D2): once this
    /// process has seen `Protected`, a later `Unavailable` still classifies
    /// as `Protected`, so `verify` denies instead of a click being offered.
    pub fn classify(&self) -> Classification {
        match self.verifier.availability() {
            Availability::Protected { .. } => {
                self.seen_protected.store(true, Ordering::SeqCst);
                Classification::Protected
            }
            Availability::Unavailable(_) if self.seen_protected.load(Ordering::SeqCst) => {
                Classification::Protected
            }
            Availability::Unavailable(reason) => Classification::Unprotected(reason),
        }
    }

    /// Invalidate one attempt (refusal, lock, disconnect) by firing ITS
    /// signal. Queued: it leaves the queue without prompting. Not yet
    /// opened: the backend never opens it. Open: the backend cancels that
    /// operation only; the slot stays occupied until the prompt ends.
    pub fn invalidate(&self, id: AttemptId) {
        let fire = self.registry.lock().unwrap_or_else(|e| e.into_inner()).get(&id).cloned();
        if let Some(fire) = fire {
            fire.send_replace(true);
        }
    }

    pub async fn verify(
        &self,
        attempt: &Attempt,
        op: &OpDescriptor,
        deadline: Instant,
    ) -> Result<Verified, Denial> {
        let id = attempt.id;
        let permit = match Arc::clone(&self.slot).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let before = self.waiting.fetch_add(1, Ordering::SeqCst);
                let _place = QueuePlace(Arc::clone(&self.waiting));
                if before >= MAX_WAITING {
                    return Err(Denial::QueueFull);
                }
                tokio::select! {
                    biased;
                    _ = attempt.cancel.cancelled() => return Err(Denial::Invalidated),
                    _ = tokio::time::sleep(remaining(deadline)) => return Err(Denial::Expired),
                    acquired = Arc::clone(&self.slot).acquire_owned() => match acquired {
                        Ok(permit) => permit,
                        Err(_) => return Err(Denial::Denied(PresenceError::Unavailable)),
                    },
                }
            }
        };
        if attempt.cancel.is_cancelled() {
            return Err(Denial::Invalidated);
        }
        if Instant::now() >= deadline {
            return Err(Denial::Expired);
        }

        let digest = op.digest();
        let (tx, rx) = oneshot::channel();
        let verifier = Arc::clone(&self.verifier);
        let cancel = attempt.cancel.clone();
        let op = op.clone();
        tokio::spawn(async move {
            let result = verifier.verify(&op, &cancel).await;
            // Released only now, when the backend reports the native prompt
            // ended — never merely because the attempt was invalidated.
            drop(permit);
            let _ = tx.send(result);
        });

        tokio::select! {
            biased;
            _ = attempt.cancel.cancelled() => Err(Denial::Invalidated),
            _ = tokio::time::sleep(remaining(deadline)) => {
                // Ask the backend to close this attempt's prompt.
                attempt.fire.send_replace(true);
                Err(Denial::Expired)
            }
            got = rx => match got {
                Ok(Ok(outcome)) => Ok(Verified { attempt: id, digest, outcome }),
                Ok(Err(PresenceError::Timeout)) => Err(Denial::Expired),
                Ok(Err(e)) if e.is_retryable() => Err(Denial::Retryable(e)),
                Ok(Err(e)) => Err(Denial::Denied(e)),
                Err(_) => Err(Denial::Denied(PresenceError::Failed)),
            },
        }
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}
```

`lib.rs` re-exports `Attempt` too: `pub use coordinator::{Attempt, Classification, Denial, PresenceCoordinator, Verified, MAX_WAITING};`

- [ ] **Step 5: Run to verify pass**

Run: `cargo test -p sv-presence`
Expected: PASS (all tests, including 18 coordinator tests). Also run `cargo test -p sv-presence -- --test-threads=1` once, to catch timing flakiness; if any test flakes, raise its `settle()` sleep. Do not change assertions.

- [ ] **Step 6: Lint, format, commit** (after authorization)

```bash
cargo fmt --all && cargo clippy -p sv-presence --all-targets --all-features -- -D warnings
git add crates/sv-presence
git commit -m "feat(presence): coordenar um prompt nativo por vez com fila limitada"
```

---

### Task 4: macOS backend (robius-authentication 0.3.1)

**Executor:** OpenCode #4.

**Files:**
- Create: `crates/sv-presence/src/macos.rs` (compiled on every OS: boundary trait, adapter, mapping)
- Create: `crates/sv-presence/src/robius.rs` (macOS only)
- Modify: `crates/sv-presence/Cargo.toml`, `crates/sv-presence/src/lib.rs`

**Interfaces:**
- Consumes: `PresenceVerifier`, `OpDescriptor::prompt_text`, `Outcome`, `PresenceError`.
- Produces: `macos::{LaError, LaBoundary, Completion, MacVerifier, map_la_error}`; on macOS `platform_verifier()` returns `MacVerifier<RobiusBoundary>`.

- [ ] **Step 1: Add the target-restricted dependency** to `crates/sv-presence/Cargo.toml`:

```toml
[target.'cfg(target_os = "macos")'.dependencies]
# Pinned: single maintainer; isolated behind `LaBoundary` (spec §11).
robius-authentication = "=0.3.1"
```

- [ ] **Step 2: Write the failing tests** (bottom of `macos.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    /// Stores the completion instead of calling it, so the test decides when
    /// (and whether) the "native prompt" finishes.
    #[derive(Default)]
    struct FakeLa {
        start_error: Option<LaError>,
        started: std::sync::atomic::AtomicUsize,
        /// Barrier: notified once `start()` has stored the completion.
        started_signal: tokio::sync::Notify,
        completion: StdMutex<Option<Completion>>,
    }

    fn live() -> CancelSignal {
        // Keep the sender alive for the whole test: a closed sender counts
        // as cancelled.
        let (tx, cancel) = CancelSignal::new();
        std::mem::forget(tx);
        cancel
    }

    // Implemented for `FakeLa`; the tests pass `Arc<FakeLa>` through the
    // blanket `impl LaBoundary for Arc<B>` so they keep a handle on it.
    impl LaBoundary for FakeLa {
        fn start(&self, _reason: &str, done: Completion) -> Result<(), LaError> {
            self.started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(e) = self.start_error {
                return Err(e);
            }
            *self.completion.lock().unwrap() = Some(done);
            self.started_signal.notify_one();
            Ok(())
        }
    }

    fn op() -> OpDescriptor {
        OpDescriptor::new("approve_request").field("action", "ReadFile")
    }

    #[tokio::test]
    async fn start_ok_is_not_success() {
        let la = Arc::new(FakeLa::default());
        let v = MacVerifier::new(la.clone());
        let pending = tokio::time::timeout(Duration::from_millis(100), v.verify(&op(), &live())).await;
        assert!(pending.is_err(), "Ok from start() must not resolve the verification");
    }

    #[tokio::test]
    async fn completion_ok_verifies_with_unknown_modality() {
        let la = Arc::new(FakeLa::default());
        let v = Arc::new(MacVerifier::new(la.clone()));
        let v2 = v.clone();
        let task = tokio::spawn(async move { v2.verify(&op(), &live()).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let done = la.completion.lock().unwrap().take().unwrap();
        done(Ok(()));
        done(Ok(())); // a second callback is ignored, not a panic
        assert_eq!(task.await.unwrap(), Ok(Outcome { modality: Modality::Unknown }));
    }

    #[tokio::test]
    async fn start_error_is_a_denial_class_error() {
        for (e, expected) in [
            (LaError::NotEnrolled, PresenceError::NotConfigured),
            (LaError::PasscodeNotSet, PresenceError::NotConfigured),
            (LaError::Unavailable, PresenceError::Unavailable),
        ] {
            let la = Arc::new(FakeLa { start_error: Some(e), ..Default::default() });
            assert_eq!(MacVerifier::new(la).verify(&op(), &live()).await, Err(expected));
        }
    }

    #[tokio::test]
    async fn dropped_completion_is_failure() {
        let la = Arc::new(FakeLa::default());
        let v = Arc::new(MacVerifier::new(la.clone()));
        let v2 = v.clone();
        let task = tokio::spawn(async move { v2.verify(&op(), &live()).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(la.completion.lock().unwrap().take());
        assert_eq!(task.await.unwrap(), Err(PresenceError::Failed));
    }

    /// D13: a cancelled attempt never starts LocalAuthentication.
    #[tokio::test]
    async fn cancelled_attempt_never_starts_the_prompt() {
        let la = Arc::new(FakeLa::default());
        let (tx, cancel) = CancelSignal::new();
        tx.send_replace(true);
        let got = MacVerifier::new(la.clone()).verify(&op(), &cancel).await;
        assert_eq!(got, Err(PresenceError::Cancelled));
        assert_eq!(la.started.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// D13 residual, pinned: a cancellation after `start()` cannot close
    /// the prompt; `verify` still returns only when the prompt ends.
    #[tokio::test]
    async fn cancellation_after_start_waits_for_the_prompt_to_end() {
        let la = Arc::new(FakeLa::default());
        let v = Arc::new(MacVerifier::new(la.clone()));
        let (tx, cancel) = CancelSignal::new();
        let v2 = v.clone();
        let mut task = tokio::spawn(async move { v2.verify(&op(), &cancel).await });
        la.started_signal.notified().await; // start() has run: the prompt is open
        tx.send_replace(true);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut task).await.is_err(),
            "an open LocalAuthentication prompt cannot be cancelled"
        );
        let done = la.completion.lock().unwrap().take().unwrap();
        done(Err(LaError::UserCanceled));
        assert_eq!(task.await.unwrap(), Err(PresenceError::Cancelled));
    }

    #[test]
    fn error_mapping_follows_section_9_1() {
        use LaError::*;
        assert_eq!(map_la_error(UserCanceled), PresenceError::Cancelled);
        assert_eq!(map_la_error(AppCanceled), PresenceError::Cancelled);
        assert_eq!(map_la_error(SystemCanceled), PresenceError::Cancelled);
        assert_eq!(map_la_error(Authentication), PresenceError::Failed);
        assert_eq!(map_la_error(Exhausted), PresenceError::Exhausted);
        assert_eq!(map_la_error(NotInteractive), PresenceError::Unavailable);
        assert_eq!(map_la_error(Other), PresenceError::Failed);
    }

    #[test]
    fn availability_is_protected_unknown_per_d1() {
        let v = MacVerifier::new(Arc::new(FakeLa::default()));
        assert_eq!(
            v.availability(),
            Availability::Protected { modalities: vec![Modality::Unknown] }
        );
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p sv-presence macos::`
Expected: FAIL to compile.

- [ ] **Step 4: Implement `macos.rs`**

```rust
//! macOS backend (ADR-0025 §5.1), written against a boundary trait so the
//! adapter rules are tested on every OS; `robius.rs` is the real boundary.
//!
//! Adapter rules: `start()` returning `Ok` means only "the prompt started";
//! the result arrives on the completion; a start error is a denial-class
//! error; a missing completion is handled by the coordinator's deadline,
//! and a late completion is discarded there (§6.1). An open LocalAuthentication
//! prompt cannot be cancelled through robius 0.3.1 (declared residual).

use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;

use crate::{Availability, CancelSignal, Modality, OpDescriptor, Outcome, PresenceError, PresenceVerifier};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaError {
    UserCanceled,
    AppCanceled,
    SystemCanceled,
    Authentication,
    Exhausted,
    Unavailable,
    NotEnrolled,
    PasscodeNotSet,
    NotInteractive,
    Other,
}

pub fn map_la_error(error: LaError) -> PresenceError {
    match error {
        LaError::UserCanceled | LaError::AppCanceled | LaError::SystemCanceled => {
            PresenceError::Cancelled
        }
        LaError::Authentication | LaError::Other => PresenceError::Failed,
        LaError::Exhausted => PresenceError::Exhausted,
        LaError::NotEnrolled | LaError::PasscodeNotSet => PresenceError::NotConfigured,
        LaError::Unavailable | LaError::NotInteractive => PresenceError::Unavailable,
    }
}

/// Called at most once with the prompt's final result.
pub type Completion = Box<dyn Fn(Result<(), LaError>) + Send + 'static>;

pub trait LaBoundary: Send + Sync + 'static {
    /// Start the native prompt with `reason` as its text. `Ok(())` means the
    /// prompt STARTED; success or failure arrives only through `done`.
    fn start(&self, reason: &str, done: Completion) -> Result<(), LaError>;
}

pub struct MacVerifier<B: LaBoundary> {
    boundary: B,
}

impl<B: LaBoundary> MacVerifier<B> {
    pub fn new(boundary: B) -> Self {
        Self { boundary }
    }
}

#[async_trait::async_trait]
impl<B: LaBoundary> PresenceVerifier for MacVerifier<B> {
    /// Plan D1: robius has no prompt-free probe and this crate forbids
    /// `unsafe`, so availability is assumed; a start-time `NotEnrolled` /
    /// `PasscodeNotSet` / `Unavailable` then DENIES the request (§6.2).
    fn availability(&self) -> Availability {
        Availability::Protected { modalities: vec![Modality::Unknown] }
    }

    async fn verify(&self, op: &OpDescriptor, cancel: &CancelSignal) -> Result<Outcome, PresenceError> {
        // D13 contract: never open a prompt for a cancelled attempt. robius
        // 0.3.1 exposes no way to cancel an OPEN prompt, so a cancellation
        // that lands after this check — including in the instant before
        // `start()` — lets the prompt run until the user or the system ends
        // it (declared residual, D13). The slot stays occupied meanwhile
        // (spec §6.1), and the coordinator discards the result.
        if cancel.is_cancelled() {
            return Err(PresenceError::Cancelled);
        }
        let (tx, rx) = oneshot::channel::<Result<(), LaError>>();
        let tx = Mutex::new(Some(tx));
        let done: Completion = Box::new(move |result| {
            if let Some(tx) = tx.lock().unwrap_or_else(|e| e.into_inner()).take() {
                let _ = tx.send(result);
            }
        });
        self.boundary
            .start(&op.prompt_text(), done)
            .map_err(map_la_error)?;
        match rx.await {
            // The completion carries no modality; never infer one (§8).
            Ok(Ok(())) => Ok(Outcome { modality: Modality::Unknown }),
            Ok(Err(error)) => Err(map_la_error(error)),
            // The boundary dropped the completion without calling it.
            Err(_) => Err(PresenceError::Failed),
        }
    }
}

// Lets tests share a boundary with the verifier.
impl<B: LaBoundary> LaBoundary for Arc<B> {
    fn start(&self, reason: &str, done: Completion) -> Result<(), LaError> {
        (**self).start(reason, done)
    }
}
```

- [ ] **Step 5: Implement `robius.rs`** (macOS only)

```rust
//! The real LocalAuthentication boundary via robius-authentication 0.3.1.
//! robius creates a fresh `LAContext` per `authenticate` call and keeps it
//! alive until the reply block fires (verified in its `sys/apple.rs`).

use robius_authentication::{AndroidText, Context, Error, PolicyBuilder, Text, WindowsText};

use crate::macos::{Completion, LaBoundary, LaError};

pub struct RobiusBoundary;

impl LaBoundary for RobiusBoundary {
    fn start(&self, reason: &str, done: Completion) -> Result<(), LaError> {
        // Biometrics + password, no companion/watch: LAPolicy
        // DeviceOwnerAuthentication (Touch ID or the Mac login password).
        let policy = PolicyBuilder::new()
            .companion(false)
            .wrist_detection(false)
            .build()
            .ok_or(LaError::Other)?;
        let text = Text {
            android: AndroidText { title: "Sovereign Vault", subtitle: None, description: None },
            apple: reason,
            windows: WindowsText::new("Sovereign Vault", reason).ok_or(LaError::Other)?,
        };
        Context::new(())
            .authenticate(text, &policy, move |result| done(result.map_err(la_error)))
            .map_err(la_error)
    }
}

fn la_error(error: Error) -> LaError {
    match error {
        Error::UserCanceled | Error::UserFallback => LaError::UserCanceled,
        Error::AppCanceled => LaError::AppCanceled,
        Error::SystemCanceled => LaError::SystemCanceled,
        Error::Authentication => LaError::Authentication,
        Error::Exhausted => LaError::Exhausted,
        Error::Unavailable | Error::BiometryDisconnected | Error::NotPaired => LaError::Unavailable,
        Error::NotEnrolled => LaError::NotEnrolled,
        Error::PasscodeNotSet => LaError::PasscodeNotSet,
        Error::NotInteractive => LaError::NotInteractive,
        _ => LaError::Other,
    }
}
```

- [ ] **Step 6: Wire `lib.rs`**

```rust
pub mod macos;
#[cfg(target_os = "macos")]
mod robius;

pub fn platform_verifier() -> Arc<dyn PresenceVerifier> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(macos::MacVerifier::new(robius::RobiusBoundary))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Arc::new(UnavailableVerifier::new(Reason::UnsupportedPlatform))
    }
}
```

- [ ] **Step 7: Run the tests and the dependency-graph checks**

Run: `cargo test -p sv-presence`
Expected: PASS.

Run: `cargo tree -p sv-presence --target x86_64-unknown-linux-gnu -e normal | grep -c robius || true`
Expected: `0` (robius does not enter the Linux graph).

Run: `cargo tree -p sv-presence --target aarch64-apple-darwin -e normal,build | grep -E "robius|android-build"`
Expected: both appear. `android-build` is the accepted residual cost (spec §11).

Run: `cargo audit` and `cargo deny check` if they are installed (CI runs both). A new advisory or license failure: stop and report to the orchestrator. Do not add ignores.

- [ ] **Step 8: Lint, format, commit** (after authorization)

```bash
cargo fmt --all && cargo clippy -p sv-presence --all-targets --all-features -- -D warnings
git add crates/sv-presence Cargo.lock
git commit -m "feat(presence): backend macOS via robius-authentication 0.3.1"
```

---

### Task 5: `sv-presence-windows` — Windows Hello backend

**Executor:** OpenCode #3 (FFI + declared `unsafe`).

**Files:**
- Modify: `Cargo.toml` (root): member `"crates/sv-presence-windows"`; workspace dep `sv-presence-windows = { path = "crates/sv-presence-windows", version = "0.1.0" }`
- Create: `crates/sv-presence-windows/Cargo.toml`, `src/lib.rs`, `src/sys.rs`

**Interfaces:**
- Consumes: `sv_presence::{PresenceVerifier, Availability, Reason, Modality, Outcome, PresenceError, OpDescriptor}`.
- Produces: `HelloResult`, `HelloAvailability`, `MIN_BUILD = 22000`, `map_result`, `map_availability(build, availability)`, `WindowProvider = Arc<dyn Fn() -> Option<isize> + Send + Sync>`, and on Windows `WindowsHelloVerifier::new(WindowProvider)`.

> Verified against the registry sources (OpenCode #4, 2026-09-28):
> - In windows 0.61.3, `RequestVerificationForWindowAsync<T: Interface>(&self, appwindow: HWND, message: &HSTRING) -> Result<T>` is an `unsafe fn` (feature `Win32_System_WinRT`).
> - `HWND(pub *mut c_void)`.
> - `UserConsentVerifier::CheckAvailabilityAsync()` is safe (feature `Security_Credentials_UI`).
> - `IAsyncOperation` lives in the crate **`windows-future` 0.2**, with `get()` and `Cancel()`.
> - `RtlGetVersion(*mut OSVERSIONINFOW) -> NTSTATUS` (feature `Wdk_System_SystemServices`).
> - `windows_core::factory<C, I>() -> Result<I>`.
> - Tauri's `WebviewWindow::hwnd()` returns the same windows 0.61 `HWND`.

- [ ] **Step 1: Manifest**

```toml
[package]
name        = "sv-presence-windows"
version.workspace      = true
edition.workspace      = true
rust-version.workspace = true
license.workspace      = true
repository.workspace   = true
description = "Windows Hello presence backend (ADR-0025 §5.2). The workspace's one declared unsafe exception."

[dependencies]
async-trait = "0.1"
sv-presence = { workspace = true }

[target.'cfg(windows)'.dependencies]
tokio          = { workspace = true }
windows-future = "0.2"
windows        = { version = "0.61", features = [
    "Foundation",
    "Security_Credentials_UI",
    "Win32_Foundation",
    "Win32_System_WinRT",
    "Win32_System_SystemInformation",
    "Wdk_System_SystemServices",
] }

# Deliberately NOT `[lints] workspace = true`: the workspace forbids unsafe,
# and this crate is the exception declared in ADR-0025. The replacement
# discipline is in `src/lib.rs` (crate attributes).
```

- [ ] **Step 2: Failing tests for the mapping** (in `lib.rs`, run on every OS)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_verified_approves() {
        use HelloResult::*;
        assert_eq!(map_result(Verified), Ok(Outcome { modality: Modality::Unknown }));
        assert_eq!(map_result(DeviceNotPresent), Err(PresenceError::Unavailable));
        assert_eq!(map_result(NotConfiguredForUser), Err(PresenceError::NotConfigured));
        assert_eq!(map_result(DisabledByPolicy), Err(PresenceError::DisabledByPolicy));
        assert_eq!(map_result(DeviceBusy), Err(PresenceError::Busy));
        assert_eq!(map_result(RetriesExhausted), Err(PresenceError::Exhausted));
        assert_eq!(map_result(Canceled), Err(PresenceError::Cancelled));
        assert_eq!(map_result(Other), Err(PresenceError::Failed));
    }

    #[test]
    fn below_build_22000_is_unavailable_whatever_hello_says() {
        assert_eq!(
            map_availability(21999, HelloAvailability::Available),
            Availability::Unavailable(Reason::BelowMinimumBuild)
        );
        assert_eq!(
            map_availability(22000, HelloAvailability::Available),
            Availability::Protected { modalities: vec![Modality::Unknown] }
        );
    }

    #[test]
    fn availability_states_map() {
        assert_eq!(
            map_availability(22631, HelloAvailability::NotConfiguredForUser),
            Availability::Unavailable(Reason::NotConfigured)
        );
        assert_eq!(
            map_availability(22631, HelloAvailability::DisabledByPolicy),
            Availability::Unavailable(Reason::DisabledByPolicy)
        );
        assert_eq!(
            map_availability(22631, HelloAvailability::DeviceNotPresent),
            Availability::Unavailable(Reason::DeviceNotPresent)
        );
        // Busy is transient: the device exists, so the system is protected.
        assert_eq!(
            map_availability(22631, HelloAvailability::DeviceBusy),
            Availability::Protected { modalities: vec![Modality::Unknown] }
        );
    }

    #[test]
    fn forbidden_apis_are_absent() {
        let src = concat!(include_str!("lib.rs"), include_str!("sys.rs"));
        for forbidden in [
            "GetDesktopWindow",
            "FindWindow",
            "SendInput",
            "keybd_event",
            "CredUIPromptForWindowsCredentials",
            "LogonUser",
        ] {
            let hits = src.matches(forbidden).count();
            // Each name appears exactly once: in this list.
            assert_eq!(hits, 1, "{forbidden} is forbidden by ADR-0025 §5.2");
        }
    }
}
```

- [ ] **Step 3: Implement `lib.rs`**

```rust
//! Windows Hello presence backend (ADR-0025 §5.2).
//!
//! This is the ONLY crate in the workspace allowed to use `unsafe`, for
//! the HWND interop call and `RtlGetVersion`. Every block carries a
//! `// SAFETY:` comment; the lints below make that mandatory. Forbidden by
//! construction: `GetDesktopWindow` as prompt owner, locating the prompt
//! window, synthetic keyboard input, and any credential-UI password
//! fallback. No password or PIN ever passes through this process.
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

use std::sync::Arc;

use sv_presence::{Availability, Modality, Outcome, PresenceError, Reason};

/// First build with `IUserConsentVerifierInterop::RequestVerificationForWindowAsync`.
pub const MIN_BUILD: u32 = 22000;

/// Returns the HWND (as `isize`) of a live Sovereign Vault window.
pub type WindowProvider = Arc<dyn Fn() -> Option<isize> + Send + Sync>;

/// Platform-neutral mirror of `UserConsentVerificationResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloResult {
    Verified,
    DeviceNotPresent,
    NotConfiguredForUser,
    DisabledByPolicy,
    DeviceBusy,
    RetriesExhausted,
    Canceled,
    Other,
}

/// Platform-neutral mirror of `UserConsentVerifierAvailability`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloAvailability {
    Available,
    DeviceNotPresent,
    NotConfiguredForUser,
    DisabledByPolicy,
    DeviceBusy,
    Other,
}

/// Only `Verified` approves. Hello PIN counts; modality is `unknown` (§8).
pub fn map_result(result: HelloResult) -> Result<Outcome, PresenceError> {
    match result {
        HelloResult::Verified => Ok(Outcome { modality: Modality::Unknown }),
        HelloResult::DeviceNotPresent => Err(PresenceError::Unavailable),
        HelloResult::NotConfiguredForUser => Err(PresenceError::NotConfigured),
        HelloResult::DisabledByPolicy => Err(PresenceError::DisabledByPolicy),
        HelloResult::DeviceBusy => Err(PresenceError::Busy),
        HelloResult::RetriesExhausted => Err(PresenceError::Exhausted),
        HelloResult::Canceled => Err(PresenceError::Cancelled),
        HelloResult::Other => Err(PresenceError::Failed),
    }
}

pub fn map_availability(build: u32, availability: HelloAvailability) -> Availability {
    if build < MIN_BUILD {
        return Availability::Unavailable(Reason::BelowMinimumBuild);
    }
    match availability {
        HelloAvailability::Available | HelloAvailability::DeviceBusy => {
            Availability::Protected { modalities: vec![Modality::Unknown] }
        }
        HelloAvailability::NotConfiguredForUser => Availability::Unavailable(Reason::NotConfigured),
        HelloAvailability::DisabledByPolicy => Availability::Unavailable(Reason::DisabledByPolicy),
        HelloAvailability::DeviceNotPresent | HelloAvailability::Other => {
            Availability::Unavailable(Reason::DeviceNotPresent)
        }
    }
}

#[cfg(windows)]
mod sys;
#[cfg(windows)]
pub use sys::WindowsHelloVerifier;
```

- [ ] **Step 4: Implement `sys.rs`** (Windows only)

```rust
use sv_presence::{Availability, CancelSignal, OpDescriptor, Outcome, PresenceError, PresenceVerifier};
use windows::core::{factory, HSTRING};
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Win32::Foundation::HWND;
use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
use windows_future::IAsyncOperation;

use crate::{map_availability, map_result, HelloAvailability, HelloResult, WindowProvider};

pub struct WindowsHelloVerifier {
    window: WindowProvider,
}

impl WindowsHelloVerifier {
    pub fn new(window: WindowProvider) -> Self {
        Self { window }
    }
}

fn os_build() -> u32 {
    use windows::Wdk::System::SystemServices::RtlGetVersion;
    use windows::Win32::System::SystemInformation::OSVERSIONINFOW;
    let mut info = OSVERSIONINFOW {
        dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` is a writable, correctly sized OSVERSIONINFOW whose
    // `dwOSVersionInfoSize` is set, which is all RtlGetVersion requires; it
    // does not retain the pointer.
    let status = unsafe { RtlGetVersion(&mut info) };
    if status.is_ok() {
        info.dwBuildNumber
    } else {
        0
    }
}

fn hello_availability() -> HelloAvailability {
    let Ok(Ok(value)) = UserConsentVerifier::CheckAvailabilityAsync().map(|op| op.get()) else {
        return HelloAvailability::Other;
    };
    match value {
        UserConsentVerifierAvailability::Available => HelloAvailability::Available,
        UserConsentVerifierAvailability::DeviceNotPresent => HelloAvailability::DeviceNotPresent,
        UserConsentVerifierAvailability::NotConfiguredForUser => {
            HelloAvailability::NotConfiguredForUser
        }
        UserConsentVerifierAvailability::DisabledByPolicy => HelloAvailability::DisabledByPolicy,
        UserConsentVerifierAvailability::DeviceBusy => HelloAvailability::DeviceBusy,
        _ => HelloAvailability::Other,
    }
}

fn hello_result(value: UserConsentVerificationResult) -> HelloResult {
    match value {
        UserConsentVerificationResult::Verified => HelloResult::Verified,
        UserConsentVerificationResult::DeviceNotPresent => HelloResult::DeviceNotPresent,
        UserConsentVerificationResult::NotConfiguredForUser => HelloResult::NotConfiguredForUser,
        UserConsentVerificationResult::DisabledByPolicy => HelloResult::DisabledByPolicy,
        UserConsentVerificationResult::DeviceBusy => HelloResult::DeviceBusy,
        UserConsentVerificationResult::RetriesExhausted => HelloResult::RetriesExhausted,
        UserConsentVerificationResult::Canceled => HelloResult::Canceled,
        _ => HelloResult::Other,
    }
}

#[async_trait::async_trait]
impl PresenceVerifier for WindowsHelloVerifier {
    fn availability(&self) -> Availability {
        // Build first: below 22000 the interop does not exist (§5.2).
        let build = os_build();
        if build < crate::MIN_BUILD {
            return map_availability(build, HelloAvailability::Other);
        }
        map_availability(build, hello_availability())
    }

    async fn verify(&self, op: &OpDescriptor, cancel: &CancelSignal) -> Result<Outcome, PresenceError> {
        // D13 contract, first check: never open a prompt for a cancelled attempt.
        if cancel.is_cancelled() {
            return Err(PresenceError::Cancelled);
        }
        // A real, live Sovereign Vault window — never GetDesktopWindow.
        let Some(raw) = (self.window)() else {
            return Err(PresenceError::Unavailable);
        };
        let hwnd = HWND(raw as *mut core::ffi::c_void);
        let message = HSTRING::from(op.prompt_text());
        let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
            .map_err(|_| PresenceError::Unavailable)?;
        // SAFETY: `hwnd` is the live main window of this process, obtained
        // from Tauri by the desktop just now; `message` outlives the call;
        // the returned operation is an owned COM reference.
        let operation: IAsyncOperation<UserConsentVerificationResult> =
            unsafe { interop.RequestVerificationForWindowAsync(hwnd, &message) }
                .map_err(|_| PresenceError::Unavailable)?;
        // Second check, now that THIS operation exists: a cancellation that
        // raced the creation closes it at once.
        if cancel.is_cancelled() {
            let _ = operation.Cancel();
        }
        // `get()` blocks until the prompt ends or `Cancel()` is confirmed,
        // which is exactly the contract of `PresenceVerifier::verify`.
        let waiter = operation.clone();
        let mut done = tokio::task::spawn_blocking(move || waiter.get());
        let waited = tokio::select! {
            waited = &mut done => waited,
            _ = cancel.cancelled() => {
                // Cancel only this attempt's operation, then wait for the
                // prompt to actually end before returning (slot rule, §6.1).
                let _ = operation.Cancel();
                done.await
            }
        };
        match waited {
            Ok(Ok(value)) => map_result(hello_result(value)),
            // Cancelled or failed inside WinRT.
            Ok(Err(_)) => Err(PresenceError::Cancelled),
            Err(_) => Err(PresenceError::Failed),
        }
    }
}
```

`tokio`'s `spawn_blocking` needs the `rt` feature. The workspace tokio features already include `rt-multi-thread`, which implies `rt`.

- [ ] **Step 5: Run tests and cross-checks**

Run: `cargo test -p sv-presence-windows`
Expected: PASS (4 tests) on macOS/Linux.

This machine has no `rustup` (checked 2026-09-28), so `sys.rs` cannot be
type-checked locally. The `Rust windows-latest` CI job (clippy + test) is its
first compile. Push the PR-A branch **only when the user asks**; then read that
job's log. A compile error there is fixed in this task, not deferred.

Run: `cargo clippy -p sv-presence-windows --all-targets -- -D warnings`

- [ ] **Step 6: Commit** (after authorization)

```bash
git add Cargo.toml Cargo.lock crates/sv-presence-windows
git commit -m "feat(presence): backend Windows Hello em crate próprio com exceção de unsafe declarada"
```

**CHECKPOINT 1 — Codex adversarial review (token-lean).** The orchestrator
sends: decisions D1–D12, `git diff --stat main`, and the full text of
`coordinator.rs`, `gate.rs`, `macos.rs`, `sys.rs`. It asks for a terse
verdict in the fixed format (`VEREDITO` + `BLOQUEIOS` + `RESSALVAS`, at most
10 lines each). BLOQUEIOS are fixed before PR-A.

---

### Task 6: Audit fields and DEK version accessor

**Executor:** OpenCode #4.

**Files:**
- Modify: `crates/sv-audit/src/lib.rs` (types near `AuditEvent`, `lib.rs:203-253`)
- Modify: `crates/sv-core/src/keyring.rs` (public fn after `exists`, `:86`)

**Interfaces:**
- Produces: `sv_audit::{PresenceAudit, PresenceOutcome, PresenceModality}`; `AuditEvent.presence: Option<PresenceAudit>`; constructors `PresenceAudit::authenticated(PresenceModality)`, `PresenceAudit::click()`, `PresenceAudit::denied(protected: bool)`, and `.with_operation(id: impl Into<String>) -> Self` (sets `operation_id`, D5); `sv_core::keyring::active_dek_version(root: &Path) -> Result<Option<u32>, CoreError>`.

- [ ] **Step 1: Failing tests in sv-audit** (append to its test module)

```rust
#[test]
fn presence_serializes_as_nested_snake_case_and_is_optional() {
    let mut event = AuditEvent::new(AuditAction::ReadFile, AuditDecision::Allowed, "desktop-ui");
    let bare = serde_json::to_string(&event).unwrap();
    assert!(!bare.contains("presence"), "absent presence keeps old bytes");
    event.presence = Some(PresenceAudit::authenticated(PresenceModality::Unknown).with_operation("approval-7"));
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains(
        r#""presence":{"protected":true,"outcome":"device_owner_authenticated","modality":"unknown","operation_id":"approval-7"}"#
    ));
    let back: AuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.presence, event.presence);
    let old: AuditEvent = serde_json::from_str(&bare).unwrap();
    assert_eq!(old.presence, None);
}

#[test]
fn click_and_denied_shapes() {
    assert_eq!(
        serde_json::to_string(&PresenceAudit::click()).unwrap(),
        r#"{"protected":false,"outcome":"click"}"#
    );
    assert_eq!(
        serde_json::to_string(&PresenceAudit::denied(true)).unwrap(),
        r#"{"protected":true}"#
    );
}

#[test]
fn event_with_presence_verifies_in_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let log = AuditLog::with_hmac_key(dir.path(), [7u8; 32]).unwrap();
    let mut event = AuditEvent::new(AuditAction::ReadFile, AuditDecision::Denied, "desktop-ui");
    event.presence = Some(PresenceAudit::denied(true));
    log.record(&event).unwrap();
    assert!(log.verify_chain().unwrap().ok);
}
```

(If `verify_chain`'s return type is not a report with `.ok`, match the call
used by the existing chain tests in the same module.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p sv-audit presence`
Expected: FAIL to compile.

- [ ] **Step 3: Implement in sv-audit** (above `pub struct AuditEvent`)

```rust
/// What authorized a presence-gated decision (ADR-0025 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceOutcome {
    DeviceOwnerAuthenticated,
    Click,
}

/// Modality as reported by the verifier, never inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceModality {
    Biometric,
    Password,
    Pin,
    Unknown,
}

/// Presence facts of one gated decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceAudit {
    /// Was presence enforced for this decision.
    pub protected: bool,
    /// Absent on denials: nothing authorized them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<PresenceOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modality: Option<PresenceModality>,
    /// Correlates every record of one gated operation (plan D5):
    /// `approval-<id>`, `otp-<modal id>`, `op-<desktop op id>`. An opaque
    /// counter, never derived from names or content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}

impl PresenceAudit {
    pub fn authenticated(modality: PresenceModality) -> Self {
        Self {
            protected: true,
            outcome: Some(PresenceOutcome::DeviceOwnerAuthenticated),
            modality: Some(modality),
            operation_id: None,
        }
    }

    pub fn click() -> Self {
        Self { protected: false, outcome: Some(PresenceOutcome::Click), modality: None, operation_id: None }
    }

    pub fn denied(protected: bool) -> Self {
        Self { protected, outcome: None, modality: None, operation_id: None }
    }

    #[must_use]
    pub fn with_operation(mut self, id: impl Into<String>) -> Self {
        self.operation_id = Some(id.into());
        self
    }
}
```

Add the field at the end of `AuditEvent`, and `presence: None` in `AuditEvent::new`:

```rust
    /// Presence facts for gated decisions (ADR-0025 §8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence: Option<PresenceAudit>,
```

- [ ] **Step 4: Failing test in sv-core** (keyring test module; create `#[cfg(test)] mod tests` in `keyring.rs` if absent)

```rust
#[test]
fn active_dek_version_is_public_and_moves_on_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vault");
    let mut boot = crate::VaultHandle::bootstrap(&root, crate::CustodyMode::Passphrase, Some("correct horse battery staple")).unwrap();
    let before = active_dek_version(&root).unwrap();
    assert!(before.is_some());
    boot.handle.rotate_key(&root, Some("correct horse battery staple")).unwrap();
    assert_ne!(active_dek_version(&root).unwrap(), before);
}

#[test]
fn active_dek_version_is_none_without_keyring() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(active_dek_version(dir.path()).unwrap(), None);
}
```

(Use the field names of `BootstrapResult`, which are `handle` and
`recovery_phrase` (`lib.rs:2260`). If `tempfile` is not a sv-core
dev-dependency, add `tempfile = { workspace = true }` under
`[dev-dependencies]`.)

- [ ] **Step 5: Implement** in `keyring.rs` after `exists`:

```rust
/// The active DEK version from the keyring header, without unwrapping any
/// key. Version numbers are not secret (module docs). `None` for a vault
/// without a keyring.
pub fn active_dek_version(root: &Path) -> Result<Option<u32>> {
    if !exists(root) {
        return Ok(None);
    }
    Ok(Some(read_keyring(root)?.active_dek_version))
}
```

- [ ] **Step 6: Run and commit**

Run: `cargo test -p sv-audit && cargo test -p sv-core keyring && cargo clippy -p sv-audit -p sv-core --all-targets -- -D warnings`
Expected: PASS.

```bash
git add crates/sv-audit crates/sv-core
git commit -m "feat(audit): registrar presença em eventos e expor a versão ativa da DEK"
```

---

### Task 7: Desktop infrastructure — coordinator, test harness, epoch, `ClickRequest`

**Executor:** OpenCode #3.

**Files:**
- Modify: `apps/desktop/src-tauri/Cargo.toml`
- Create: `apps/desktop/src-tauri/src/presence.rs`
- Modify: `apps/desktop/src-tauri/src/lib.rs`

**Interfaces:**
- Consumes: `PresenceCoordinator`, `platform_verifier`, `WindowsHelloVerifier` (Windows), `FakeVerifier` (tests).
- Produces:
  - `presence::build_coordinator<R: Runtime>(app: &AppHandle<R>) -> Arc<PresenceCoordinator>`
  - `presence::audit_modality(sv_presence::Modality) -> sv_audit::PresenceModality`
  - `VaultState.presence: Arc<PresenceCoordinator>`, `VaultState.root_override: Option<PathBuf>`
  - `VaultState::new_with(app, presence, root_override)`, `fn state_root<R: Runtime>(state: &VaultState<R>) -> Result<PathBuf, String>`
  - `SessionTimer::{epoch(), set_locked()}`
  - `async fn with_handle_in<R: Runtime, T, F>(state: &VaultState<R>, f: F) -> Result<T, String>`
  - `async fn container_mode_in<R: Runtime>(state: &VaultState<R>, container: &str) -> Option<SecurityMode>`
  - `struct ClickRequest` + `ClickRequest::from_access(&AccessRequest)` + `ClickRequest::desktop(label, AuditAction, OpDescriptor)`
  - `fn op_for_access(&AccessRequest) -> OpDescriptor`
  - `ApprovalState::request_click(&self, click: ClickRequest, mirror: TrayMirror)`, `ApprovalState::clear_all(&self)`
  - `fn record_with_handle<R: Runtime>(state: &VaultState<R>, handle: &VaultHandle, event: AuditEvent)` and `async fn record_desktop_event_locked<R: Runtime>(state: &VaultState<R>, event: AuditEvent)` (D5)
  - test helper `tests::Harness` (with `audit_events() -> Vec<serde_json::Value>`)

- [ ] **Step 1: Dependencies** in `apps/desktop/src-tauri/Cargo.toml`

```toml
# under [dependencies]
sv-presence = { workspace = true }

[target.'cfg(windows)'.dependencies]
sv-presence-windows = { workspace = true }

[dev-dependencies]
sv-presence = { workspace = true, features = ["test-util"] }
tauri       = { version = "2", features = ["tray-icon", "test"] }
```

- [ ] **Step 2: Harness smoke test first** (tests module in `lib.rs`). It pins the assumption that `MockRuntime` can host `VaultState`. If it cannot, stop and report to the orchestrator, with the error, before any further step.

```rust
use sv_presence::fake::{FakeStep, FakeVerifier, APPROVED};
use tauri::test::MockRuntime;

const TEST_PASSPHRASE: &str = "correct horse battery staple";

struct Harness {
    app: tauri::App<MockRuntime>,
    _dir: tempfile::TempDir,
    root: PathBuf,
    fake: Arc<FakeVerifier>,
}

impl Harness {
    fn new(fake: Arc<FakeVerifier>) -> Self {
        let app = tauri::test::mock_app();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("sovereign-vault");
        let presence = Arc::new(sv_presence::PresenceCoordinator::new(fake.clone()));
        app.manage(VaultState::new_with(app.handle().clone(), presence, Some(root.clone())));
        Self { app, _dir: dir, root, fake }
    }

    /// A harness with a real passphrase-custody vault, unlocked.
    async fn unlocked(fake: Arc<FakeVerifier>) -> Self {
        let h = Self::new(fake);
        let boot = VaultHandle::bootstrap(&h.root, CustodyMode::Passphrase, Some(TEST_PASSPHRASE)).unwrap();
        let mut guard = h.state().handle.lock().await;
        h.state().publish_unlocked(&mut guard, boot.handle);
        drop(guard);
        h
    }

    /// A plain reference, so generic `_impl<R>` functions infer `R` without
    /// relying on deref coercion through `tauri::State`.
    fn state(&self) -> &VaultState<MockRuntime> {
        self.app.state::<VaultState<MockRuntime>>().inner()
    }

    /// Wait (bounded) for the next pending click-approval id.
    async fn next_pending_id(&self) -> u64 {
        for _ in 0..200 {
            if let Some(id) = self.state().approvals.pending.lock().await.keys().min().copied() {
                return id;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no pending approval appeared");
    }

    fn audit_text(&self) -> String {
        std::fs::read_to_string(self.root.join("audit.jsonl")).unwrap_or_default()
    }

    /// Structured audit events (the `event` object of each record), oldest
    /// first. Tests assert on these fields, never on substrings (D5).
    fn audit_events(&self) -> Vec<serde_json::Value> {
        self.audit_text()
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .map(|record| record["event"].clone())
            .collect()
    }

    /// Events carrying a `presence` field, as `(action, decision, presence)`.
    fn presence_events(&self) -> Vec<(String, String, serde_json::Value)> {
        self.audit_events()
            .into_iter()
            .filter(|e| !e["presence"].is_null())
            .map(|e| (e["action"].to_string(), e["decision"].to_string(), e["presence"].clone()))
            .collect()
    }
}

#[tokio::test]
async fn harness_hosts_vault_state_on_mock_runtime() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    assert!(h.state().handle.lock().await.is_some());
    assert_eq!(state_root(h.state()).unwrap(), h.root);
    assert!(h.state().presence.classify().is_protected());
}
```

Run: `cargo test -p sovereign-vault-desktop harness_hosts` → FAIL (items missing).

- [ ] **Step 3: `presence.rs`**

```rust
//! Desktop wiring of ADR-0025: which verifier this platform uses, and the
//! helpers the gated commands share.

use std::sync::Arc;

use sv_presence::{PresenceCoordinator, PresenceVerifier};
use tauri::{AppHandle, Runtime};

pub(crate) fn build_coordinator<R: Runtime>(app: &AppHandle<R>) -> Arc<PresenceCoordinator> {
    #[cfg(windows)]
    let verifier: Arc<dyn PresenceVerifier> = {
        use tauri::Manager;
        let app = app.clone();
        Arc::new(sv_presence_windows::WindowsHelloVerifier::new(Arc::new(move || {
            // The real, kept-alive main window (ADR-0025 §5.2).
            app.get_webview_window("main")
                .and_then(|w| w.hwnd().ok())
                .map(|h| h.0 as isize)
        })))
    };
    #[cfg(not(windows))]
    let verifier: Arc<dyn PresenceVerifier> = {
        let _ = app;
        sv_presence::platform_verifier()
    };
    Arc::new(PresenceCoordinator::new(verifier))
}

pub(crate) fn audit_modality(m: sv_presence::Modality) -> sv_audit::PresenceModality {
    match m {
        sv_presence::Modality::Biometric => sv_audit::PresenceModality::Biometric,
        sv_presence::Modality::Password => sv_audit::PresenceModality::Password,
        sv_presence::Modality::Pin => sv_audit::PresenceModality::Pin,
        sv_presence::Modality::Unknown => sv_audit::PresenceModality::Unknown,
    }
}
```

In `lib.rs`: `mod presence;` next to `mod remediate;`.

- [ ] **Step 4: `VaultState` and `SessionTimer`** (`lib.rs:1195-1387`)

- Add fields to `VaultState<R>`: `presence: Arc<sv_presence::PresenceCoordinator>` and `root_override: Option<PathBuf>` ("tests only: keeps a MockRuntime harness out of the real app-data directory").
- `VaultState::new(app)` becomes `Self::new_with(app.clone(), presence::build_coordinator(&app), None)`. `new_with` holds the current body of `new`, and passes `presence.clone()` into `ApprovalState::new(app.clone(), presence.clone())`.
- Add after `audit_root`:

```rust
/// The vault root for a state: the test override, else the app-data path.
fn state_root<R: Runtime>(state: &VaultState<R>) -> Result<PathBuf, String> {
    match &state.root_override {
        Some(root) => Ok(root.clone()),
        None => vault_root(&state.app),
    }
}
```

- Change `audit_root` to `state_root(state)`.
- `SessionTimer`: add `epoch: Arc<AtomicU64>` (initialized to `0`), and:

```rust
    /// Changes on every unlock and every lock (plan D4). A gate captures it
    /// before the native prompt and requires it unchanged afterwards.
    fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Record that the vault is now locked.
    fn set_locked(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut guard) = self.unlocked_at.try_lock() {
            *guard = None;
        }
    }
```

  In `set_unlocked`, add `self.epoch.fetch_add(1, Ordering::SeqCst);` as its first line.
- **Handle and epoch are published together (D4).** Add two methods, and make them the ONLY way production code changes the handle:

```rust
impl<R: Runtime> VaultState<R> {
    /// Publish an unlocked handle and advance the epoch under the SAME
    /// guard, before servers start or any access is released.
    fn publish_unlocked(&self, guard: &mut Option<VaultHandle>, handle: VaultHandle) {
        *guard = Some(handle);
        self.session_timer.set_unlocked();
    }

    /// Withdraw the handle and advance the epoch under the same guard.
    fn publish_locked(&self, guard: &mut Option<VaultHandle>) {
        *guard = None;
        self.session_timer.set_locked();
    }
}
```

  Call them with the tokio guard's contents (`&mut *guard`) at every assignment site:
  - `vault_init` `:2284`;
  - `vault_unlock` `:2369` and its `start_servers` failure `:2373`;
  - `vault_unlock_recovery` `:2432`, `:2436`;
  - `perform_vault_lock` `:2495`.
  
  Delete the later standalone `state.set_unlocked()` calls in those commands, and the `VaultState::set_unlocked` wrapper itself (`lib.rs:1362`); publication already did it. `perform_vault_lock_internal` (monitor, `:2577`) has no `VaultState`: there, write `*guard = None; state.timer.set_locked();` while the same guard is held, with a comment pointing at `publish_locked`.
- **Session id from the epoch.** Replace the body of `VaultState::session_id` (`lib.rs:1376-1386`, which uses `try_lock` and can return `"locked"` under contention) with `format!("session-{}", self.session_timer.epoch())`. A lock changes it; so does every unlock. Wake authorizations and leases are therefore bound to exactly one unlock.
- **Limits as atomics.** Change `idle_timeout_secs` / `absolute_session_secs` to `Arc<AtomicU64>`. `set_limits` stores them, and `remaining_secs` loads them, with no `try_lock` fallback that can silently skip a write. Add `fn limits(&self) -> (u64, u64)`.
- **Delete** both `if let Ok(mut guard) = …unlocked_at.try_lock() { *guard = None; }` blocks (in `perform_vault_lock`, `lib.rs:~2530`, and `perform_vault_lock_internal`, `lib.rs:~2596`). The epoch and `unlocked_at` already changed at the top of each lock path, under the handle guard (`publish_locked`, or `state.timer.set_locked()` right after `*guard = None` in the monitor). A second, later call outside publication could land after a fresh unlock and wrongly lock its timer. After this task, `set_locked` / `set_unlocked` are called **only** from `publish_locked` / `publish_unlocked` and that one monitor line. A source-scan test pins it (Step 7).
- Add `approvals: Arc<ApprovalState<R>>` to `SessionMonitorState`, set in `monitor_state()`. Call `state.approvals.clear_all().await;` in both lock paths, right after the handle is cleared.

- [ ] **Step 5: Generic helpers** (next to `with_handle`, `lib.rs:2078`)

```rust
async fn with_handle_in<R, T, F>(state: &VaultState<R>, f: F) -> Result<T, String>
where
    R: Runtime,
    F: FnOnce(&VaultHandle) -> Result<T, String>,
{
    let guard = state.handle.lock().await;
    let handle = guard.as_ref().ok_or_else(|| "vault is locked".to_string())?;
    f(handle)
}

async fn container_mode_in<R: Runtime>(state: &VaultState<R>, container: &str) -> Option<SecurityMode> {
    with_handle_in(state, |handle| handle.container_mode(container).map_err(estr)).await.ok()
}
```

Make `with_handle` and `container_mode` delegate to these (`with_handle_in(state, f).await`).

- [ ] **Step 6: `ClickRequest`** (above `impl<R: Runtime> ApprovalState<R>`)

```rust
/// What a click-approval modal shows and binds. Agent requests convert
/// from `AccessRequest`; desktop-originated gates (ADR-0025 §7.5) build one
/// directly, because most of them have no `AccessAction`.
#[derive(Clone)]
struct ClickRequest {
    action_label: String,
    audit_action: AuditAction,
    /// `Some` only for requests that may be mirrored to the tray.
    tray_label: Option<&'static str>,
    container: Option<String>,
    file_name: Option<String>,
    mode: Option<SecurityMode>,
    byte_size: Option<usize>,
    import_summary: Option<sv_mcp::ImportApprovalSummary>,
    signature: String,
    op: sv_presence::OpDescriptor,
    /// Consent that may complete while the vault is locked or absent. Set
    /// ONLY by `desktop_pre_unlock` (keychain unlock, init); an MCP request
    /// can never carry it (D5, round-3 review).
    pre_unlock: bool,
}

impl ClickRequest {
    fn from_access(request: &sv_mcp::AccessRequest) -> Self {
        Self {
            action_label: format!("{:?}", request.action),
            audit_action: audit_action_for(&request.action),
            tray_label: Some(tray::action_label(&request.action)),
            container: request.container.clone(),
            file_name: request.file_name.clone(),
            mode: request.mode,
            byte_size: request.byte_size,
            import_summary: request.import_summary.clone(),
            signature: request_signature(request),
            op: op_for_access(request),
            pre_unlock: false,
        }
    }

    fn desktop(label: &str, audit_action: AuditAction, op: sv_presence::OpDescriptor) -> Self {
        Self {
            action_label: label.to_string(),
            audit_action,
            tray_label: None,
            container: None,
            file_name: None,
            mode: None,
            byte_size: None,
            import_summary: None,
            signature: format!("desktop|{}", op.digest().to_hex()),
            op,
            pre_unlock: false,
        }
    }

    /// The declared consent click of `vault_unlock` (keychain) and
    /// `vault_init`: the only clicks that can be approved without a vault.
    /// Their audit happens at commit, under the handle guard (Task 13).
    fn desktop_pre_unlock(label: &str, audit_action: AuditAction, op: sv_presence::OpDescriptor) -> Self {
        Self { pre_unlock: true, ..Self::desktop(label, audit_action, op) }
    }
}

/// The complete description of an MCP request (§6.3). `request_click`
/// appends the request id.
fn op_for_access(request: &sv_mcp::AccessRequest) -> sv_presence::OpDescriptor {
    sv_presence::OpDescriptor::new("mcp_request")
        .field("action", format!("{:?}", request.action))
        .field("container", request.container.clone().unwrap_or_default())
        .field("file", request.file_name.clone().unwrap_or_default())
        .field("agent", request.agent_id.clone().unwrap_or_default())
        .bind("mode", request.mode.map(|m| m.as_str()).unwrap_or(""))
        .bind("byte_size", request.byte_size.map(|b| b.to_string()).unwrap_or_default())
        .bind("authorization_context", request.authorization_context.clone())
}
```

Refactor `request_click` (`lib.rs:580-672`) to take `click: ClickRequest`:
- the supersede filter compares `p.signature == click.signature`;
- `ApprovalPrompt` is built from the `click` fields;
- the tray insert happens only when `mirror == TrayMirror::Yes` **and** `click.tray_label` is `Some(label)`: `TrayApproval { id, action_label: label, audit_action: click.audit_action }`.

The callers change as follows:
- `request()` → `self.request_click(ClickRequest::from_access(&request), TrayMirror::Yes)`
- `request_click_only(request)` → `self.request_click(ClickRequest::from_access(&request), TrayMirror::No)`

`matches_pending_approval` becomes unused: delete it. Keep the existing tests that covered it working by comparing `request_signature` directly.

Add to `ApprovalState`:

```rust
    /// A lock ends every pending decision (spec §6.1): refuse each waiting
    /// approval, drop every OTP challenge, and clear their modals.
    async fn clear_all(&self) {
        let drained: Vec<(u64, PendingApproval)> = self.pending.lock().await.drain().collect();
        for (id, pending) in drained {
            let _ = pending.tx.send(false);
            let _ = self.app.emit(APPROVAL_CANCEL_EVENT, ApprovalCancel { id });
        }
        let challenges: Vec<OtpChallenge> =
            self.otp_pending.lock().await.drain().map(|(_, c)| c).collect();
        for chal in challenges {
            let _ = self.app.emit(APPROVAL_CANCEL_EVENT, ApprovalCancel { id: chal.modal_id });
        }
    }
```

- [ ] **Step 6b: Audit writers that cannot silently drop a decision (D5).** Next to `record_desktop_event` (`lib.rs:1834`):

```rust
/// Record with a handle the caller already holds. Used inside
/// `with_gated_handle`, so an Allowed record is written before the lock that
/// guards the release is released.
fn record_with_handle<R: Runtime>(state: &VaultState<R>, handle: &VaultHandle, event: AuditEvent) {
    let Ok(root) = audit_root(state) else {
        return;
    };
    if let Ok(log) = AuditLog::with_hmac_key(&root, handle.audit_hmac_key()) {
        let _ = log.record(&event);
    }
}

/// Like `record_desktop_event`, but waits for the handle instead of
/// skipping on contention. Only a locked vault (no key) skips: the declared
/// D5 exception. Never call it while holding `state.handle`.
async fn record_desktop_event_locked<R: Runtime>(state: &VaultState<R>, event: AuditEvent) {
    let guard = state.handle.lock().await;
    if let Some(handle) = guard.as_ref() {
        record_with_handle(state, handle, event);
    }
}
```

Test (same step):

```rust
#[tokio::test]
async fn locked_writer_records_under_contention() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    let state = h.state();
    let hold = state.handle.lock().await; // contention
    let writer = record_desktop_event_locked(
        state,
        AuditEvent::new(AuditAction::VaultInfo, AuditDecision::Allowed, "desktop-ui"),
    );
    let release = async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(hold);
    };
    tokio::join!(writer, release);
    assert!(h.audit_events().iter().any(|e| e["action"] == "VaultInfo"));
}
```

(Check the serialized spelling of `AuditAction::VaultInfo` in the existing sv-audit tests, and match it.)

- [ ] **Step 7: Tests for this task**

```rust
#[tokio::test]
async fn lock_refuses_pending_approvals_and_bumps_epoch() {
    let h = Harness::unlocked(FakeVerifier::unavailable()).await;
    let state = h.state();
    let epoch = state.session_timer.epoch();
    let approvals = state.approvals.clone();
    let waiting = tokio::spawn(async move {
        approvals.request(container_request(SecurityMode::Approval, "ctx")).await
    });
    let _ = h.next_pending_id().await;
    perform_vault_lock(state, "manual").await;
    assert_eq!(waiting.await.unwrap(), Err("access denied by user".into()));
    assert_ne!(state.session_timer.epoch(), epoch);
}
```

`perform_vault_lock` currently takes `&VaultState` (Wry). Make it generic: `async fn perform_vault_lock<R: Runtime>(state: &VaultState<R>, reason: &str)`. `container_request` is the existing test helper (`lib.rs:5250`).

```rust
/// Plan D4: the epoch and the unlocked timer move only at publication.
#[test]
fn session_transitions_happen_only_at_publication() {
    let src = include_str!("lib.rs");
    let body = src.split("#[cfg(test)]").next().unwrap();
    let calls = body.matches(".set_locked()").count() + body.matches(".set_unlocked()").count();
    // publish_locked, publish_unlocked, and the monitor's lock line.
    assert_eq!(calls, 3, "session transitions outside publication: {calls}");
}

/// A lock followed at once by an unlock: the old lock flow cannot touch
/// the new session, because it holds the handle guard until it finishes.
#[tokio::test]
async fn lock_then_immediate_unlock_leaves_the_new_session_intact() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    let state = h.state();
    let start = state.session_timer.epoch();
    let root = h.root.clone();
    let lock = perform_vault_lock(state, "manual");
    let unlock = async {
        tokio::task::yield_now().await;
        let handle = VaultHandle::unlock(&root, CustodyMode::Passphrase, Some(TEST_PASSPHRASE)).unwrap();
        let mut guard = state.handle.lock().await;
        state.publish_unlocked(&mut guard, handle);
    };
    tokio::join!(lock, unlock);
    assert_eq!(state.session_timer.epoch(), start + 2);
    assert!(state.handle.lock().await.is_some());
    assert!(state.session_timer.remaining_secs().0.is_some(), "the new session's timer is running");
}
```

(If `VaultHandle::unlock` fails because the old handle still holds the vault's file lock (`VaultLock`), have the `unlock` future wait for `state.handle.lock()` first, then build the handle while holding the guard. The assertion is unchanged.)

- [ ] **Step 8: Run all desktop tests**

Run: `cargo test -p sovereign-vault-desktop`
Expected: PASS, including every pre-existing test. The source-scan tests (`every_mutating_desktop_command_enforces_mode`, `polling_commands_never_call_touch_human_activity`, `every_command_the_ui_invokes_is_registered`) must stay green unchanged.

- [ ] **Step 9: Lint, format, commit** (after authorization)

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add apps/desktop/src-tauri Cargo.lock
git commit -m "refactor(desktop): preparar coordenador de presença, época do cofre e harness de testes"
```

---

### Task 8: Approvals verify presence before approving

**Executor:** OpenCode #3.

**Files:**
- Modify: `apps/desktop/src-tauri/src/lib.rs`:
  - `PendingApproval` `:95`, `request_click`, `respond` `:674`
  - `clear_all` (Task 7), `ApprovalPrompt` `:1554`, `DesktopAccessController` `:1716`
- Modify: `ui/src/lib/types.ts`, `ui/src/components/ApprovalModal.svelte`

**Interfaces:**
- Consumes: `ClickRequest`, `PresenceCoordinator::{classify, begin_attempt, verify, invalidate}`, `Attempt`, `GateState`, `PresenceAudit::with_operation`, `audit_modality`, `record_with_handle`, `record_desktop_event_locked`, `SessionTimer::epoch`.
- Produces:
  - `ApprovalPrompt.protected: bool`;
  - `ApprovalState::respond` with the §6.1 state machine;
  - `ApprovalState::refuse_from(id, transport)`;
  - one structured `desktop-ui` audit record per decision, `operation_id = "approval-<id>"` (D5, D6);
  - `DesktopAccessController::authorize` re-checks the epoch after approval (D4).

- [ ] **Step 1: Failing tests**

```rust
async fn spawn_agent_request(h: &Harness) -> (u64, tokio::task::JoinHandle<Result<(), String>>) {
    let approvals = h.state().approvals.clone();
    let task = tokio::spawn(async move {
        approvals.request(container_request(SecurityMode::Approval, "ctx")).await
    });
    (h.next_pending_id().await, task)
}

fn approval_presence(h: &Harness, id: u64) -> Vec<serde_json::Value> {
    let op = serde_json::Value::String(format!("approval-{id}"));
    h.presence_events()
        .into_iter()
        .filter(|(_, _, p)| p["operation_id"] == op)
        .map(|(_, decision, mut p)| {
            p["decision"] = serde_json::Value::String(decision.trim_matches('"').to_string());
            p
        })
        .collect()
}

/// The central test (spec §9.2).
#[tokio::test]
async fn approve_without_completed_verification_does_not_approve() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    h.fake.push(FakeStep::Return(Err(sv_presence::PresenceError::Cancelled)));
    let (id, task) = spawn_agent_request(&h).await;
    assert!(h.state().approvals.respond(id, true, None).await.is_err());
    assert!(!task.is_finished(), "a cancelled prompt leaves the request pending");
    assert!(h.state().approvals.pending.lock().await.contains_key(&id));
    h.state().approvals.respond(id, false, None).await.unwrap();
    assert_eq!(task.await.unwrap(), Err("access denied by user".into()));
    let records = approval_presence(&h, id);
    assert_eq!(records.len(), 1, "exactly one decision record: the refusal");
    assert_eq!(records[0]["decision"], "Denied");
    assert_eq!(records[0]["protected"], true);
}

#[tokio::test]
async fn verified_approval_approves_and_audits_presence() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    h.fake.approve_next();
    let (id, task) = spawn_agent_request(&h).await;
    h.state().approvals.respond(id, true, None).await.unwrap();
    assert_eq!(task.await.unwrap(), Ok(()));
    let records = approval_presence(&h, id);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["decision"], "Allowed");
    assert_eq!(records[0]["protected"], true);
    assert_eq!(records[0]["outcome"], "device_owner_authenticated");
    assert_eq!(records[0]["modality"], "unknown");
}

#[tokio::test]
async fn mid_attempt_unavailability_denies_and_never_clicks() {
    for err in [
        sv_presence::PresenceError::Unavailable,
        sv_presence::PresenceError::DisabledByPolicy,
        sv_presence::PresenceError::NotConfigured,
    ] {
        let h = Harness::unlocked(FakeVerifier::protected()).await;
        h.fake.push(FakeStep::Return(Err(err)));
        let (id, task) = spawn_agent_request(&h).await;
        assert!(h.state().approvals.respond(id, true, None).await.is_err());
        assert_eq!(task.await.unwrap(), Err("access denied by user".into()), "{err:?}");
        let records = approval_presence(&h, id);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["decision"], "Denied");
        assert_eq!(records[0]["protected"], true);
        assert!(records[0]["outcome"].is_null(), "never a click");
    }
}

#[tokio::test]
async fn concurrent_approve_starts_one_verification() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    h.fake.push(FakeStep::Hold(APPROVED));
    let (id, task) = spawn_agent_request(&h).await;
    let approvals = h.state().approvals.clone();
    let first = tokio::spawn(async move { approvals.respond(id, true, None).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let second = h.state().approvals.respond(id, true, None).await;
    assert!(second.unwrap_err().contains("already in progress"));
    h.fake.release();
    first.await.unwrap().unwrap();
    assert_eq!(task.await.unwrap(), Ok(()));
    assert_eq!(h.fake.calls(), 1);
}

#[tokio::test]
async fn refuse_during_verification_wins_and_cancels_the_prompt() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    h.fake.set_cancel_supported(true);
    h.fake.push(FakeStep::Hold(APPROVED));
    let (id, task) = spawn_agent_request(&h).await;
    let approvals = h.state().approvals.clone();
    let approving = tokio::spawn(async move { approvals.respond(id, true, None).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    h.state().approvals.respond(id, false, None).await.unwrap();
    assert!(approving.await.unwrap().is_err());
    assert_eq!(h.fake.cancels(), 1, "refusal requests native cancel (D13)");
    assert_eq!(task.await.unwrap(), Err("access denied by user".into()));
}

/// D13: a request refused while waiting behind another prompt never prompts.
#[tokio::test]
async fn refused_while_queued_never_prompts() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    h.fake.push(FakeStep::Hold(APPROVED)); // A's prompt stays open
    h.fake.approve_next(); // B's result, if B ever prompted
    let (a, task_a) = spawn_agent_request(&h).await;
    let approvals = h.state().approvals.clone();
    let approving_a = tokio::spawn(async move { approvals.respond(a, true, None).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let approvals = h.state().approvals.clone();
    let task_b = tokio::spawn(async move {
        approvals.request(container_request(SecurityMode::Approval, "ctx-b")).await
    });
    let b = loop {
        let ids: Vec<u64> = h.state().approvals.pending.lock().await.keys().copied().collect();
        if let Some(b) = ids.into_iter().find(|k| *k != a) {
            break b;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let approvals = h.state().approvals.clone();
    let approving_b = tokio::spawn(async move { approvals.respond(b, true, None).await });
    tokio::time::sleep(Duration::from_millis(30)).await; // B is queued behind A
    h.state().approvals.respond(b, false, None).await.unwrap();
    assert!(approving_b.await.unwrap().is_err());
    assert_eq!(task_b.await.unwrap(), Err("access denied by user".into()));
    h.fake.release();
    approving_a.await.unwrap().unwrap();
    task_a.await.unwrap().unwrap();
    assert_eq!(h.fake.calls(), 1, "B never reached the backend");
}

#[tokio::test]
async fn lock_during_verification_denies() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    h.fake.push(FakeStep::Hold(APPROVED));
    let (id, task) = spawn_agent_request(&h).await;
    let approvals = h.state().approvals.clone();
    let approving = tokio::spawn(async move { approvals.respond(id, true, None).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    perform_vault_lock(h.state(), "manual").await;
    h.fake.release();
    assert!(approving.await.unwrap().is_err());
    assert_eq!(task.await.unwrap(), Err("access denied by user".into()));
}

/// D4: an approval that lands after the vault's epoch moved is not honored
/// by the MCP path, even though the modal decision itself went through.
#[tokio::test]
async fn mcp_authorize_rejects_approval_across_an_epoch_change() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    h.fake.push(FakeStep::Hold(APPROVED));
    let controller = DesktopAccessController {
        approvals: h.state().approvals.clone(),
        timer: h.state().session_timer.clone(),
    };
    let authorizing = tokio::spawn(async move {
        sv_mcp::AccessController::authorize(&controller, container_request(SecurityMode::Approval, "ctx")).await
    });
    let id = h.next_pending_id().await;
    let approvals = h.state().approvals.clone();
    let approving = tokio::spawn(async move { approvals.respond(id, true, None).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    // An epoch change lands while the prompt is open, without the lock
    // path's clear (the narrowest interleaving the controller must catch).
    h.state().session_timer.set_unlocked();
    h.fake.release();
    approving.await.unwrap().unwrap();
    assert!(authorizing.await.unwrap().unwrap_err().contains("vault state changed"));
}

#[tokio::test]
async fn one_verification_does_not_satisfy_the_next_request() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    h.fake.approve_next();
    let (id1, t1) = spawn_agent_request(&h).await;
    h.state().approvals.respond(id1, true, None).await.unwrap();
    t1.await.unwrap().unwrap();
    let (id2, t2) = spawn_agent_request(&h).await;
    assert!(h.state().approvals.respond(id2, true, None).await.is_err(), "unscripted => fails");
    h.state().approvals.respond(id2, false, None).await.unwrap();
    let _ = t2.await;
}

#[tokio::test]
async fn declared_system_click_approves_with_protected_false() {
    let h = Harness::unlocked(FakeVerifier::unavailable()).await;
    let (id, task) = spawn_agent_request(&h).await;
    h.state().approvals.respond(id, true, None).await.unwrap();
    assert_eq!(task.await.unwrap(), Ok(()));
    assert_eq!(h.fake.calls(), 0);
    let records = approval_presence(&h, id);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["protected"], false);
    assert_eq!(records[0]["outcome"], "click");
}

/// Round-3 review: the declared consent click of a keychain unlock works
/// while the vault is locked...
#[tokio::test]
async fn pre_unlock_click_is_approvable_while_locked() {
    let h = Harness::new(FakeVerifier::unavailable()); // locked, declared system
    let approvals = h.state().approvals.clone();
    let op = sv_presence::OpDescriptor::new("vault_unlock").field("vault", "v");
    let task = tokio::spawn(async move {
        approvals
            .request_click(ClickRequest::desktop_pre_unlock("Unlock", AuditAction::VaultUnlock, op), TrayMirror::No)
            .await
    });
    let id = h.next_pending_id().await;
    h.state().approvals.respond(id, true, None).await.unwrap();
    assert_eq!(task.await.unwrap(), Ok(()));
}

/// ...but no MCP request can be approved while locked.
#[tokio::test]
async fn mcp_request_is_not_approvable_while_locked() {
    let h = Harness::new(FakeVerifier::unavailable());
    let approvals = h.state().approvals.clone();
    let task = tokio::spawn(async move {
        approvals.request(container_request(SecurityMode::Approval, "ctx")).await
    });
    let id = h.next_pending_id().await;
    assert_eq!(h.state().approvals.respond(id, true, None).await, Err("vault is locked".into()));
    assert!(task.await.unwrap().is_err());
}

#[tokio::test]
async fn classification_is_fixed_at_creation() {
    let h = Harness::unlocked(FakeVerifier::unavailable()).await;
    let (id, task) = spawn_agent_request(&h).await; // born unprotected
    h.fake.set_availability(sv_presence::Availability::Protected { modalities: vec![] });
    h.state().approvals.respond(id, true, None).await.unwrap();
    assert_eq!(task.await.unwrap(), Ok(()));
    assert_eq!(h.fake.calls(), 0, "a request born unprotected never silently becomes protected");
}
```

(`container_request` builds an agent `ReadFile` in `SecurityMode::Approval`.
`approval_requirement` yields `Click` for it, so `request()` reaches
`request_click`. Match the audit's serialized decision spelling (`"Allowed"` /
`"Denied"`) to what sv-audit emits; adjust the literals if it serializes
differently.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p sovereign-vault-desktop approve_ verified_ mid_attempt concurrent_ refuse lock_during mcp_authorize one_verification declared_system classification_is_fixed`
Expected: FAIL.

- [ ] **Step 3: Implement**

`PendingApproval` gains:

```rust
    /// Fixed when the request was created (§6.2); never re-evaluated.
    protected: bool,
    gate: sv_presence::GateState,
    deadline: Instant,
    op: sv_presence::OpDescriptor,
    audit_action: AuditAction,
    /// From `ClickRequest::pre_unlock`.
    pre_unlock: bool,
```

`ApprovalPrompt` also gains `pre_unlock: bool`, so the UI shows that prompt on the lock screen. Check `App.svelte:117-127`: if the global approval surface is hidden while locked, render it when `prompt.pre_unlock` is true.

`ApprovalState` gains the field `presence: Arc<sv_presence::PresenceCoordinator>` (constructor argument).

In `request_click`:
- compute `let protected = self.presence.classify().is_protected();` **before** taking the lock;
- set `op: click.op.clone().bind("request_id", id.to_string())` and `deadline: Instant::now() + Duration::from_secs(APPROVAL_TIMEOUT_SECS)`;
- add `protected` to the emitted `ApprovalPrompt`;
- in the timeout branch (`Err(_) =>`, `lib.rs:657`), when removing the entry, call `self.invalidate_entry(&entry)` so an attempt in flight is cancelled (D13).

Helpers on `ApprovalState`:

```rust
    /// D13: a refused, expired, or locked request must not keep (or later
    /// open) a native prompt.
    fn invalidate_entry(&self, entry: &PendingApproval) {
        if let sv_presence::GateState::Verifying { attempt, .. } = entry.gate {
            self.presence.invalidate(attempt);
        }
    }

    fn drop_tray_row(&self, id: u64) {
        if let Some(tray_state) = self.app.try_state::<tray::TrayApprovals>() {
            tray_state.remove(id);
        }
        tray::refresh(&self.app);
    }

    /// Plans D5/D6: the desktop records every decision with its presence
    /// facts and the request's operation id. Waits for the handle; a locked
    /// vault (no key) is the declared exception.
    async fn audit_decision(
        &self,
        operation_id: String,
        action: AuditAction,
        approved: bool,
        presence: sv_audit::PresenceAudit,
        transport: &str,
        error: Option<String>,
    ) {
        let Some(state) = self.app.try_state::<VaultState<R>>() else {
            return;
        };
        let decision = if approved { AuditDecision::Allowed } else { AuditDecision::Denied };
        let mut event = AuditEvent::new(action, decision, transport);
        event.presence = Some(presence.with_operation(operation_id));
        event.error = error;
        record_desktop_event_locked(&state, event).await;
    }

    /// Refuse `id` from `transport` ("desktop-ui" or "desktop-tray").
    async fn refuse_from(&self, id: u64, transport: &str) -> Result<(), String> {
        let removed = self.pending.lock().await.remove(&id);
        let Some(entry) = removed else {
            return Err(format!("unknown approval request: {id}"));
        };
        self.invalidate_entry(&entry);
        let sent = entry.tx.send(false).map_err(|_| "approval request already closed".to_string());
        self.audit_decision(format!("approval-{id}"), entry.audit_action, false, sv_audit::PresenceAudit::denied(entry.protected), transport, None)
            .await;
        self.drop_tray_row(id);
        sent
    }
```

Replace `respond`. Lock order is always **handle → pending**, the same as the lock path (`perform_vault_lock` holds the handle and then calls `clear_all`). An Allowed decision is recorded **with the handle held**, before `true` is sent, so a lock can never slip between the decision and its record (D5):

```rust
    fn allowed_event(&self, id: u64, action: AuditAction, presence: sv_audit::PresenceAudit) -> AuditEvent {
        let mut event = AuditEvent::new(action, AuditDecision::Allowed, "desktop-ui");
        event.presence = Some(presence.with_operation(format!("approval-{id}")));
        event
    }

    async fn respond(&self, id: u64, approved: bool, otp: Option<String>) -> Result<(), String> {
        if !approved {
            // Refusal is immediate and needs no presence (§2).
            return self.refuse_from(id, "desktop-ui").await;
        }
        let vault = self
            .app
            .try_state::<VaultState<R>>()
            .ok_or_else(|| "vault state unavailable".to_string())?;

        // Phase 1 (handle -> pending): the click path completes here; the
        // protected path registers its attempt (so a refusal cannot miss it).
        let (attempt, op, deadline) = {
            let handle_guard = vault.handle.lock().await;
            let mut pending = self.pending.lock().await;
            let entry = pending.get_mut(&id).ok_or_else(|| format!("unknown approval request: {id}"))?;
            if let Some(expected) = &entry.otp_code {
                if otp.as_deref() != Some(expected.as_str()) {
                    return Err("incorrect confirmation code".into());
                }
            }
            if !entry.protected {
                let entry = pending.remove(&id).expect("present above");
                drop(pending);
                let Some(handle) = handle_guard.as_ref() else {
                    if entry.pre_unlock {
                        // Keychain unlock / init consent: there is no vault
                        // yet to audit into; the commit records it under the
                        // handle guard, with this click (Task 13).
                        let sent = entry.tx.send(true).map_err(|_| "approval request already closed".to_string());
                        drop(handle_guard);
                        self.drop_tray_row(id);
                        return sent;
                    }
                    let _ = entry.tx.send(false);
                    drop(handle_guard);
                    self.drop_tray_row(id);
                    return Err("vault is locked".into());
                };
                record_with_handle(&vault, handle, self.allowed_event(id, entry.audit_action, sv_audit::PresenceAudit::click()));
                let sent = entry.tx.send(true).map_err(|_| "approval request already closed".to_string());
                drop(handle_guard);
                self.drop_tray_row(id);
                return sent;
            }
            let attempt = self.presence.begin_attempt();
            entry.gate.begin(attempt.id(), entry.op.digest()).map_err(|e| e.to_string())?;
            (attempt, entry.op.clone(), entry.deadline)
        };

        // Phase 2 (no locks held): the native prompt.
        let result = self.presence.verify(&attempt, &op, deadline).await;

        // Phase 3, the finisher (handle -> pending).
        let handle_guard = vault.handle.lock().await;
        let mut pending = self.pending.lock().await;
        let Some(entry) = pending.get_mut(&id) else {
            // Refused, expired, or locked while the prompt was open: the
            // result is discarded (§6.1); the refusal was already audited.
            return Err("approval request is no longer pending".into());
        };
        let denial = match result {
            Ok(verified) => {
                let current = entry.op.digest();
                match entry.gate.finish(attempt.id(), verified.digest, current, entry.deadline, Instant::now()) {
                    Err(error) => error.to_string(),
                    Ok(()) => {
                        let entry = pending.remove(&id).expect("present above");
                        drop(pending);
                        let Some(handle) = handle_guard.as_ref() else {
                            let _ = entry.tx.send(false);
                            drop(handle_guard);
                            self.drop_tray_row(id);
                            return Err("vault is locked".into());
                        };
                        let presence = sv_audit::PresenceAudit::authenticated(presence::audit_modality(verified.outcome.modality));
                        record_with_handle(&vault, handle, self.allowed_event(id, entry.audit_action, presence));
                        let sent = entry.tx.send(true).map_err(|_| "approval request already closed".to_string());
                        drop(handle_guard);
                        self.drop_tray_row(id);
                        return sent;
                    }
                }
            }
            Err(sv_presence::Denial::Retryable(error)) => {
                entry.gate.abort(attempt.id());
                return Err(sv_presence::Denial::Retryable(error).message());
            }
            Err(denial) => denial.message(),
        };
        let entry = pending.remove(&id).expect("present above");
        drop(pending);
        drop(handle_guard);
        let _ = entry.tx.send(false);
        self.audit_decision(
            format!("approval-{id}"),
            entry.audit_action,
            false,
            sv_audit::PresenceAudit::denied(true),
            "desktop-ui",
            Some(denial.clone()),
        )
        .await;
        self.drop_tray_row(id);
        Err(denial)
    }
```


In `clear_all` (Task 7), call `self.invalidate_entry(&pending)` for each drained entry before sending `false`.

In `respond_from_tray`, delete the block that builds `AuditEvent::new(audit_action, …, "desktop-tray")` and records it (`lib.rs:1815-1826`). `respond`/`refuse_from` already audit; Task 9 restricts the tray to `refuse_from(id, "desktop-tray")`.

`DesktopAccessController` (D4):

```rust
struct DesktopAccessController<R: Runtime = tauri::Wry> {
    approvals: Arc<ApprovalState<R>>,
    timer: SessionTimer,
}

#[async_trait]
impl<R: Runtime> sv_mcp::AccessController for DesktopAccessController<R> {
    async fn authorize(&self, request: sv_mcp::AccessRequest) -> Result<(), String> {
        let epoch = self.timer.epoch();
        self.approvals.request(request).await?;
        // An approval granted in one unlock is never consumed in the next.
        if self.timer.epoch() != epoch {
            return Err("vault state changed during approval; resend the request".into());
        }
        Ok(())
    }
}
```

Build it in `start_servers` with `timer: state.session_timer.clone()`.

`ApprovalPrompt` gains `protected: bool` (always sent).

- [ ] **Step 4: UI.** `ui/src/lib/types.ts`: add `protected: boolean;` to `ApprovalPrompt`. In `ApprovalModal.svelte`:
- The Approve button text is `{prompt.protected ? 'Approve — verify it’s you' : 'Approve'}`.
- Under the `<dl>`, add `{#if prompt.protected}<p style="color:var(--muted);font-size:0.8rem">Your OS will ask for Touch ID, Windows Hello, or your password. Refusing needs no verification.</p>{/if}`.
- On error, the existing `toastStore.setError(e)` stays, and the modal stays open. The store only removes the prompt on success, which is already its behavior.

Run: `cd ui && npm run check && npm test`
Expected: PASS.

- [ ] **Step 5: Run and commit**

Run: `cargo test -p sovereign-vault-desktop && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS.

```bash
git add apps/desktop/src-tauri ui/src
git commit -m "feat(desktop): exigir presença do SO para aprovar requisições protegidas"
```

---

### Task 9: Tray revision — Approve opens the modal (ADR-0022 revised)

**Executor:** OpenCode #4.

**Files:**
- Modify: `apps/desktop/src-tauri/src/lib.rs` (`respond_from_tray` `:1779-1832`; new const `APPROVAL_FOCUS_EVENT`)
- Modify: `apps/desktop/src-tauri/src/tray.rs` (module docs `:1-40` — describe the revised approve path)
- Modify: `ui/src/stores/approvals.svelte.ts`, `ui/src/App.svelte`

**Interfaces:**
- Consumes: `tray::focus_main`, `ApprovalState::refuse_from` (Task 8).
- Produces: event `vault://approval-focus` with payload `{ id }`; `approvalStore.focus(id)`.

- [ ] **Step 1: Failing tests**

```rust
/// ADR-0025 §7.2: the tray alone can never approve.
#[test]
fn tray_approve_never_responds_true() {
    let src = include_str!("lib.rs");
    let start = src.find("async fn respond_from_tray").unwrap();
    let body = &src[start..start + src[start..].find("\nfn record_desktop_event").unwrap()];
    assert!(!body.contains(".respond("), "the tray must not call respond at all");
    assert!(body.contains("refuse_from("), "tray Deny stays a direct refusal");
    assert!(body.contains("APPROVAL_FOCUS_EVENT"), "tray Approve opens the modal");
}

#[tokio::test]
async fn tray_approve_leaves_the_request_pending() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    let (id, task) = spawn_agent_request(&h).await;
    respond_from_tray(h.app.handle(), id, true).await;
    assert!(h.state().approvals.pending.lock().await.contains_key(&id));
    assert_eq!(h.fake.calls(), 0);
    respond_from_tray(h.app.handle(), id, false).await;
    assert_eq!(task.await.unwrap(), Err("access denied by user".into()));
}
```

`respond_from_tray` returns early when the id is missing from the tray
registry (`lib.rs:1797-1804`). Under `MockRuntime`, `TrayApprovals` is not
managed, so for this test call `h.app.manage(tray::TrayApprovals::new())`
first. `request()` mirrors with `TrayMirror::Yes`, so the row is inserted.

- [ ] **Step 2: Implement.** Add `const APPROVAL_FOCUS_EVENT: &str = "vault://approval-focus";` next to `APPROVAL_CANCEL_EVENT`. Restructure `respond_from_tray` as follows:
- keep the locked check and the registry lookup;
- keep `touch_human_activity`;
- then:

```rust
    if approved {
        // ADR-0025 §7.2 (revision of ADR-0022): the tray opens the request's
        // modal; approval happens there, behind the OS presence prompt.
        tray::focus_main(app);
        let _ = app.emit(APPROVAL_FOCUS_EVENT, ApprovalCancel { id });
        return;
    }
    let _ = state.approvals.refuse_from(id, "desktop-tray").await;
    if let Some(tray_state) = app.try_state::<tray::TrayApprovals>() {
        tray_state.remove(id);
    }
    tray::refresh(app);
```

Update the doc comment of `respond_from_tray` and the `tray.rs` module docs. The menu label stays "Approve" but now means "open to approve". Change the menu text to "Review…" in `tray.rs` (`MenuItemBuilder::with_id(format!("{APPROVE_PREFIX}{}", …), "Review…")`). If a `tray.rs` test pins the "Approve" label, update it.

- [ ] **Step 3: UI.** In `approvals.svelte.ts` add:

```ts
  /** Bring one request to the front (tray "Review…", ADR-0025 §7.2). */
  focus(id: number) {
    const idx = queue.findIndex((p) => p.id === id);
    if (idx > 0) {
      const [prompt] = queue.splice(idx, 1);
      queue = [prompt, ...queue];
    }
  },
```

In `App.svelte`, next to the `vault://approval-cancel` listener, add a listener for `'vault://approval-focus'` that calls `approvalStore.focus(ev.payload.id)`, and unlisten it in the same cleanup block.

- [ ] **Step 4: Run and commit**

Run: `cargo test -p sovereign-vault-desktop tray && (cd ui && npm run check && npm test)`
Expected: PASS.

```bash
git add apps/desktop/src-tauri ui/src
git commit -m "feat(desktop): bandeja abre o modal para aprovar; recusar segue direto"
```

---

### Task 10: OTP — reveal only after presence

**Executor:** OpenCode #3.

**Files:**
- Modify: `apps/desktop/src-tauri/src/lib.rs` (`OtpChallenge` `:151`, `process_otp_request` `:224`, `handle_otp` `:356`, `handle_otp_fresh` `:486`, new command `approval_reveal_otp`, `generate_handler!`)
- Modify: `ui/src/lib/types.ts`, `ui/src/components/OtpModal.svelte`

**Interfaces:**
- Consumes: `op_for_access`, `PresenceCoordinator`, `GateState`.
- Produces:
  - `OtpChallenge { …, protected: bool, gate: GateState, op: OpDescriptor, audit_action: AuditAction, revealed_modality: Option<sv_presence::Modality> }`
  - `ApprovalPrompt.otp_reveal_required: bool`
  - `ApprovalState::reveal_otp(modal_id: u64) -> Result<String, String>`
  - Tauri command `approval_reveal_otp(id: u64) -> Result<String, String>`

- [ ] **Step 1: Failing tests** (pure + integrated)

```rust
fn protected_challenge() -> OtpChallenge {
    let op = sv_presence::OpDescriptor::new("mcp_request").field("action", "ReadFile");
    OtpChallenge::new("123456".into(), 1, true, op, AuditAction::ReadFile)
}

#[test]
fn correct_code_before_reveal_is_rejected() {
    let mut chal = protected_challenge();
    let (result, updated) = process_otp_request(Some(&mut chal), Some("123456"));
    assert!(matches!(result, OtpProcessResult::Invalid));
    assert_eq!(updated.unwrap().failed_attempts, 1, "counts like a wrong code");
}

#[test]
fn revealed_code_is_accepted_once() {
    let mut chal = protected_challenge();
    let digest = chal.op.digest();
    chal.gate = sv_presence::GateState::Authenticated { digest };
    let (result, updated) = process_otp_request(Some(&mut chal), Some("123456"));
    assert!(matches!(result, OtpProcessResult::Accepted { .. }));
    assert!(updated.is_none(), "single use: the challenge is consumed");
}

#[test]
fn authentication_for_another_request_does_not_count() {
    let mut chal = protected_challenge();
    chal.gate = sv_presence::GateState::Authenticated {
        digest: sv_presence::OpDescriptor::new("mcp_request").field("action", "WriteFile").digest(),
    };
    let (result, _) = process_otp_request(Some(&mut chal), Some("123456"));
    assert!(matches!(result, OtpProcessResult::Invalid));
}

#[tokio::test]
async fn otp_code_is_absent_from_the_event_until_reveal() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    let req = container_request(SecurityMode::Otp, "ctx");
    let err = h.state().approvals.request(req.clone()).await.unwrap_err();
    assert!(err.starts_with("otp_required"));
    let (key, modal_id, code, revealed) = {
        let store = h.state().approvals.otp_pending.lock().await;
        let (k, c) = store.iter().next().unwrap();
        (k.clone(), c.modal_id, c.code.clone(), c.gate)
    };
    assert_eq!(revealed, sv_presence::GateState::Pending);
    // No verification yet: the correct code is rejected.
    let mut resend = req.clone();
    resend.otp = Some(code.clone());
    assert!(h.state().approvals.request(resend.clone()).await.is_err());
    // Reveal after presence, then the same code works exactly once.
    h.fake.approve_next();
    assert_eq!(h.state().approvals.reveal_otp(modal_id).await.unwrap(), code);
    assert!(h.state().approvals.request(resend.clone()).await.is_ok());
    assert!(!h.state().approvals.otp_pending.lock().await.contains_key(&key));
    assert!(h.state().approvals.request(resend).await.is_err(), "single use");
    // Correlated, structured records for this OTP operation (D5).
    let op = serde_json::Value::String(format!("otp-{modal_id}"));
    let records: Vec<_> = h
        .presence_events()
        .into_iter()
        .filter(|(_, _, p)| p["operation_id"] == op)
        .collect();
    assert!(records.iter().any(|(_, d, p)| d.contains("Allowed")
        && p["protected"] == true
        && p["outcome"] == "device_owner_authenticated"
        && p["modality"] == "unknown"));
}

#[tokio::test]
async fn lock_during_reveal_cancels_and_reveals_nothing() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    h.fake.set_cancel_supported(true);
    let _ = h.state().approvals.request(container_request(SecurityMode::Otp, "ctx")).await;
    let modal_id = h.state().approvals.otp_pending.lock().await.values().next().unwrap().modal_id;
    h.fake.push(FakeStep::Hold(APPROVED));
    let approvals = h.state().approvals.clone();
    let revealing = tokio::spawn(async move { approvals.reveal_otp(modal_id).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    perform_vault_lock(h.state(), "manual").await;
    assert!(revealing.await.unwrap().is_err());
    assert_eq!(h.fake.cancels(), 1);
}

#[tokio::test]
async fn reveal_is_denied_without_presence() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    let _ = h.state().approvals.request(container_request(SecurityMode::Otp, "ctx")).await;
    let modal_id = h.state().approvals.otp_pending.lock().await.values().next().unwrap().modal_id;
    h.fake.push(FakeStep::Return(Err(sv_presence::PresenceError::Cancelled)));
    assert!(h.state().approvals.reveal_otp(modal_id).await.is_err());
}

#[tokio::test]
async fn unprotected_system_shows_code_as_today() {
    let h = Harness::unlocked(FakeVerifier::unavailable()).await;
    let req = container_request(SecurityMode::Otp, "ctx");
    let _ = h.state().approvals.request(req.clone()).await;
    let code = h.state().approvals.otp_pending.lock().await.values().next().unwrap().code.clone();
    let mut resend = req;
    resend.otp = Some(code);
    assert!(h.state().approvals.request(resend).await.is_ok());
    assert_eq!(h.fake.calls(), 0);
}
```

A code revealed for request A never approves request B. This holds by
construction: challenges are keyed by the full `request_signature`, and the
authenticated digest is bound to `op_for_access` (see
`authentication_for_another_request_does_not_count`).

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p sovereign-vault-desktop otp`
Expected: FAIL.

- [ ] **Step 3: Implement**

- `OtpChallenge::new(code, modal_id, protected, op, audit_action)`: the new fields, with `gate: GateState::Pending`.
- `OtpChallenge::validate`: after the expiry/lockout check, add

```rust
        // ADR-0025 §7.3: on a protected request the code only works after a
        // successful verification bound to this request's digest.
        if self.protected && !self.gate.is_authenticated_for(self.op.digest()) {
            return false;
        }
```

  This makes a correct code before reveal fall into the existing `Invalid` branch, which records the failure.
- `handle_otp_fresh`:
  - `let protected = self.presence.classify().is_protected();`
  - `let op = op_for_access(request).bind("request_id", id.to_string());`
  - insert `OtpChallenge::new(code.clone(), id, protected, op, audit_action_for(&request.action))`;
  - emit `otp_code: if protected { None } else { Some(code) }` and `otp_reveal_required: protected`.
  - The reuse path in `handle_otp` (`NeedFresh` with `Some(chal)`, `lib.rs:393-445`) must set the same two fields from `chal.protected`. Never emit the code when `chal.protected` is true.
- On `OtpProcessResult::Accepted`, record the decision with `self.audit_decision(format!("otp-{modal_id}"), …)`.
  - Protected: `PresenceAudit::authenticated(audit_modality(chal.revealed_modality.unwrap_or(Modality::Unknown)))`. The modality is the one **stored at reveal**, never re-inferred (D5).
  - Unprotected: `PresenceAudit::denied(false)` with `outcome` set to `None` — a code relay, not a click.

  The audit action comes from the challenge removed by `store.remove(&key)`, so change it to `let removed = store.remove(&key);`.
- Wrong codes, lockouts, and mid-attempt denials of a protected challenge also record `Denied` with `operation_id = otp-<modal id>`, so every record of one OTP operation correlates.
- **Lock order and the Allowed record (D5).** When the request carries a code, `handle_otp` first takes the vault handle guard (`app.try_state::<VaultState<R>>()`), then `otp_pending`, the same order as the lock path. On `Accepted`, the Allowed record is written with `record_with_handle` **before** returning `Ok`, while both guards are held. If the handle is `None` (vault locked), return `Err("vault is locked")` instead of `Ok`.
- In `clear_all` (Task 7), for each drained challenge whose `gate` is `Verifying { attempt, .. }`, call `self.presence.invalidate(attempt)` before emitting the cancel (D13).
- New method:

```rust
    /// Reveal an OTP code after a presence verification bound to that
    /// request (§7.3). The approval itself still happens on the resend.
    async fn reveal_otp(&self, modal_id: u64) -> Result<String, String> {
        let (key, attempt, op, deadline) = {
            let mut store = self.otp_pending.lock().await;
            self.prune_expired(&mut store);
            let (key, chal) = store
                .iter_mut()
                .find(|(_, c)| c.modal_id == modal_id)
                .ok_or_else(|| "unknown or expired code request".to_string())?;
            if !chal.protected {
                return Ok(chal.code.clone());
            }
            let attempt = self.presence.begin_attempt();
            chal.gate.begin(attempt.id(), chal.op.digest()).map_err(|e| e.to_string())?;
            let deadline = chal.issued_at + Duration::from_secs(OTP_TTL_SECS);
            (key.clone(), attempt, chal.op.clone(), deadline)
        };
        let result = self.presence.verify(&attempt, &op, deadline).await;
        let mut store = self.otp_pending.lock().await;
        let chal = store
            .get_mut(&key)
            .filter(|c| c.modal_id == modal_id)
            .ok_or_else(|| "code request is no longer pending".to_string())?;
        match result {
            Ok(verified) => {
                let current = chal.op.digest();
                chal.gate
                    .finish(attempt.id(), verified.digest, current, deadline, Instant::now())
                    .map_err(|e| e.to_string())?;
                // Kept for the resend's audit record (D5).
                chal.revealed_modality = Some(verified.outcome.modality);
                Ok(chal.code.clone())
            }
            Err(sv_presence::Denial::Retryable(e)) => {
                chal.gate.abort(attempt.id());
                Err(sv_presence::Denial::Retryable(e).message())
            }
            Err(denial) => {
                // Mid-attempt unavailability denies the request (§6.2).
                let chal = store.remove(&key).expect("present above");
                drop(store);
                let _ = self.app.emit(APPROVAL_CANCEL_EVENT, ApprovalCancel { id: chal.modal_id });
                Err(denial.message())
            }
        }
    }
```

- Tauri command, registered in `generate_handler!` after `approval_respond`:

```rust
/// Reveal a protected OTP code after the OS presence prompt (ADR-0025 §7.3).
#[tauri::command]
async fn approval_reveal_otp(state: State<'_, VaultState>, id: u64) -> Result<String, String> {
    state.touch_human_activity();
    state.approvals.reveal_otp(id).await
}
```

- [ ] **Step 4: UI.** `types.ts`: add `otp_reveal_required: boolean;` to `ApprovalPrompt`. In `OtpModal.svelte`:
- keep a local `let code = $state<string | null>(prompt.otp_code);`;
- when `prompt.otp_reveal_required && !code`, show a primary button "Reveal code — verify it’s you" that calls `invoke<string>('approval_reveal_otp', { id: prompt.id })`, assigns the result to `code`, and shows errors with `toastStore.setError`;
- render `{code}` in the existing monospace banner.

Add `ui/src/components/OtpModal.test.ts`, mirroring `FileViewerModal.test.ts`'s mocking of `invoke`. It asserts that no code text is rendered for a prompt with `otp_code: null, otp_reveal_required: true`, and that the code appears after clicking Reveal with `invoke` resolving `'123456'`.

- [ ] **Step 5: Run and commit**

Run: `cargo test -p sovereign-vault-desktop && (cd ui && npm run check && npm test)`
Expected: PASS.

```bash
git add apps/desktop/src-tauri ui/src
git commit -m "feat(desktop): revelar o código OTP só após verificação de presença"
```

**CHECKPOINT 2 — Codex adversarial review.** Send it:
- `git diff main -- apps/desktop/src-tauri/src/lib.rs`, restricted to `respond`, `reveal_otp`, `respond_from_tray`, and `clear_all`;
- the test names added in Tasks 8–10.

Ask the same terse verdict format. Fix the BLOQUEIOS before PR-B.

---

### Task 11: `desktop_presence_gate` and the container-mode consent (ANONYMIZED / APPROVAL / OTP)

**Executor:** OpenCode #3.

**Files:**
- Modify: `apps/desktop/src-tauri/src/presence.rs` (`GatePass`, `GateDenied`, `DesktopOps`)
- Modify: `apps/desktop/src-tauri/src/lib.rs`:
  - `require_desktop_consent` `:2173`, `vault_read_file` `:4040`, `vault_export_file` `:4166`
  - the `vault_write_file`, `vault_delete_file`, `vault_delete_container` call sites
  - `VaultState` (new field `desktop_ops`)

**Interfaces:**
- Consumes: `ClickRequest::desktop`, `PresenceCoordinator::{classify, begin_attempt, verify}`, `Attempt`, `SessionTimer::epoch`, `request_click`, `PresenceAudit::with_operation`, `record_with_handle`, `record_desktop_event_locked`.
- Produces:
  - `presence::GatePass { presence: PresenceAudit, digest: OpDigest, epoch: u64, operation_id: String }`, with `fn ensure_same(&self, op_now: &OpDescriptor) -> Result<(), GateDenied>`.
  - `presence::GateDenied { protected: bool, message: String, operation_id: String }`, with `fn audit(&self) -> PresenceAudit` (denied + operation id).
  - `presence::DesktopOps` (`begin`, `retry`, `finish(digest, id)`, `clear(&PresenceCoordinator)`): the registry of D2, keyed by `OpDigest`. It is exclusive per operation (a concurrent call gets `AlreadyVerifying`), finishes by identity, and invalidates in-flight attempts on clear.
  - `async fn desktop_presence_gate<R: Runtime>(state: &VaultState<R>, click: ClickRequest) -> Result<GatePass, GateDenied>`
  - `async fn with_gated_handle<R, T, F>(state: &VaultState<R>, pass: &GatePass, f: F) -> Result<T, String>`, where `F: FnOnce(&VaultHandle) -> Result<(T, AuditEvent), String>`. D14: it re-checks the epoch under the handle lock, runs `f`, records the returned event with `pass` presence, then unlocks.
  - `with_gated_handle_mut`, the same with `&mut VaultHandle`.
  - `require_desktop_consent(..., operation: &str, destination: Option<&str>) -> Result<Option<GatePass>, GateDenied>`
  - `vault_read_file_impl<R>`, `vault_export_file_impl<R>`

- [ ] **Step 1: Failing tests**

```rust
async fn anonymized_fixture(h: &Harness, mode: SecurityMode) {
    with_handle_in(h.state(), |handle| {
        handle.create_container("anon", mode, None).map_err(estr)?;
        handle.write_file("anon", "a.txt", b"alice@example.com").map_err(estr)
    })
    .await
    .unwrap();
}

/// `(decision, presence)` of ReadFile events, oldest first.
fn read_presence(h: &Harness) -> Vec<(String, serde_json::Value)> {
    h.presence_events()
        .into_iter()
        .filter(|(action, _, _)| action.contains("ReadFile"))
        .map(|(_, d, p)| (d.trim_matches('"').to_string(), p))
        .collect()
}

#[tokio::test]
async fn anonymized_read_releases_nothing_without_presence() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    anonymized_fixture(&h, SecurityMode::Anonymized).await;
    h.fake.push(FakeStep::Return(Err(sv_presence::PresenceError::DisabledByPolicy)));
    let got = vault_read_file_impl(h.state(), "anon".into(), "a.txt".into(), None, None).await;
    assert!(got.is_err());
    assert_eq!(h.fake.calls(), 1);
    let records = read_presence(&h);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].0, "Denied");
    assert_eq!(records[0].1["protected"], true);
    assert!(records[0].1["operation_id"].as_str().unwrap().starts_with("op-"));
}

#[tokio::test]
async fn anonymized_read_releases_after_presence() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    anonymized_fixture(&h, SecurityMode::Anonymized).await;
    h.fake.approve_next();
    let got = vault_read_file_impl(h.state(), "anon".into(), "a.txt".into(), None, None).await;
    assert_eq!(got.unwrap(), b"alice@example.com");
    let records = read_presence(&h);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].0, "Allowed");
    assert_eq!(records[0].1["outcome"], "device_owner_authenticated");
}

/// D2: a retry of the same operation reuses its identity (and classification).
#[tokio::test]
async fn retry_reuses_the_operation_identity() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    anonymized_fixture(&h, SecurityMode::Anonymized).await;
    h.fake.push(FakeStep::Return(Err(sv_presence::PresenceError::Cancelled)));
    h.fake.approve_next();
    assert!(vault_read_file_impl(h.state(), "anon".into(), "a.txt".into(), None, None).await.is_err());
    assert!(vault_read_file_impl(h.state(), "anon".into(), "a.txt".into(), None, None).await.is_ok());
    let records = read_presence(&h);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].1["operation_id"], records[1].1["operation_id"]);
    assert!(h.state().desktop_ops.is_empty().await, "terminal success ends the operation");
}

/// D2/B3: two concurrent calls for the same operation start ONE verification.
#[tokio::test]
async fn concurrent_same_operation_verifies_once() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    anonymized_fixture(&h, SecurityMode::Anonymized).await;
    h.fake.push(FakeStep::Hold(APPROVED));
    let state = h.state();
    let first = async { vault_read_file_impl(state, "anon".into(), "a.txt".into(), None, None).await };
    let second = async {
        while h.fake.calls() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let got = vault_read_file_impl(state, "anon".into(), "a.txt".into(), None, None).await;
        h.fake.release();
        got
    };
    let (a, b) = tokio::join!(first, second);
    assert!(a.is_ok());
    assert!(b.unwrap_err().contains("already in progress"));
    assert_eq!(h.fake.calls(), 1);
}

#[tokio::test]
async fn anonymized_export_writes_nothing_without_presence() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    anonymized_fixture(&h, SecurityMode::Anonymized).await;
    let dest = h.root.parent().unwrap().join("out.txt");
    h.fake.push(FakeStep::Return(Err(sv_presence::PresenceError::Failed)));
    let got = vault_export_file_impl(h.state(), "anon".into(), "a.txt".into(), dest.clone()).await;
    assert!(got.is_err());
    assert!(!dest.exists());
}

#[tokio::test]
async fn declared_system_anonymized_read_takes_the_click_never_ungated() {
    let h = Harness::unlocked(FakeVerifier::unavailable()).await;
    anonymized_fixture(&h, SecurityMode::Anonymized).await;
    let state = h.state();
    let read = async { vault_read_file_impl(state, "anon".into(), "a.txt".into(), None, None).await };
    let click = async {
        let id = h.next_pending_id().await;
        state.approvals.respond(id, true, None).await.unwrap();
    };
    let (got, ()) = tokio::join!(read, click);
    assert!(got.is_ok());
    assert_eq!(h.fake.calls(), 0);
    let records = read_presence(&h);
    assert_eq!(records.last().unwrap().1["protected"], false);
    assert_eq!(records.last().unwrap().1["outcome"], "click");
}

#[tokio::test]
async fn direct_read_is_declared_ungated() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    anonymized_fixture(&h, SecurityMode::Direct).await;
    assert!(vault_read_file_impl(h.state(), "anon".into(), "a.txt".into(), None, None).await.is_ok());
    assert_eq!(h.fake.calls(), 0);
}

#[tokio::test]
async fn lock_during_gate_releases_nothing() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    anonymized_fixture(&h, SecurityMode::Anonymized).await;
    h.fake.push(FakeStep::Hold(APPROVED));
    let state = h.state();
    let read = async { vault_read_file_impl(state, "anon".into(), "a.txt".into(), None, None).await };
    let lock = async {
        while h.fake.calls() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        perform_vault_lock(state, "manual").await;
        h.fake.release();
    };
    let (got, ()) = tokio::join!(read, lock);
    assert!(got.is_err());
    assert!(read_presence(&h).iter().all(|(d, _)| d != "Allowed"));
}

/// D4/D14: a lock plus re-unlock between the gate and the release denies
/// the release, even though the gate itself passed.
#[tokio::test]
async fn relock_between_gate_and_consumption_denies() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    anonymized_fixture(&h, SecurityMode::Anonymized).await;
    h.fake.approve_next();
    let op = sv_presence::OpDescriptor::new("probe").field("x", "1");
    let pass = desktop_presence_gate(h.state(), ClickRequest::desktop("probe", AuditAction::ReadFile, op))
        .await
        .ok()
        .unwrap();
    // Lock, then re-unlock with the same vault.
    {
        let mut guard = h.state().handle.lock().await;
        let handle = guard.take().unwrap();
        h.state().publish_locked(&mut guard);
        h.state().publish_unlocked(&mut guard, handle);
    }
    let got = with_gated_handle(h.state(), &pass, |handle| {
        let bytes = handle.read_file("anon", "a.txt").map_err(estr)?;
        Ok((bytes, AuditEvent::new(AuditAction::ReadFile, AuditDecision::Allowed, "desktop-ui")))
    })
    .await;
    assert!(got.unwrap_err().contains("vault state changed"));
}

#[tokio::test]
async fn approval_mode_desktop_read_uses_presence_directly() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    anonymized_fixture(&h, SecurityMode::Approval).await;
    h.fake.approve_next();
    assert!(vault_read_file_impl(h.state(), "anon".into(), "a.txt".into(), None, None).await.is_ok());
    assert_eq!(h.fake.calls(), 1);
    assert!(h.state().approvals.pending.lock().await.is_empty(), "no modal on a protected system (D3)");
}
```

(`create_container` is `VaultHandle::create_container(name, mode, description)`,
`sv-core/src/lib.rs:883`. For `write_file`, use the exact call
`vault_write_file` makes; adjust the fixture to that signature. If
`VaultHandle` is not `Send`-movable out of the guard as written in
`relock_between_gate_and_consumption_denies`, replace the take/put with
`perform_vault_lock` followed by `VaultHandle::unlock(&h.root,
CustodyMode::Passphrase, Some(TEST_PASSPHRASE))` and `set_unlocked()`.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p sovereign-vault-desktop anonymized_ retry_reuses declared_system_anonymized direct_read lock_during_gate relock_between approval_mode_desktop`
Expected: FAIL.

- [ ] **Step 3: Implement the pass types and the operation registry** in `presence.rs`:

```rust
use std::collections::HashMap;
use std::time::Instant;

use sv_audit::PresenceAudit;
use sv_presence::{OpDescriptor, OpDigest};
use tokio::sync::Mutex;

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
        let drained: Vec<PendingDesktopOp> = self.ops.lock().await.drain().map(|(_, op)| op).collect();
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
```

Add `desktop_ops: Arc<presence::DesktopOps>` to `VaultState` (`Default`). Call `state.desktop_ops.clear(&state.presence).await` in both lock paths, next to `approvals.clear_all()`. The monitor state gets `Arc`s to `desktop_ops` and `presence`, like `approvals`.

- [ ] **Step 4: Implement the gate and the consumption helpers** in `lib.rs`:

```rust
/// ADR-0025 §7.5: one pending desktop operation. Protected systems go
/// straight to the OS prompt (plan D3); declared systems take the consent
/// modal. Classification is fixed when the operation is created (D2), and
/// the registry makes each operation exclusive (one verification at a time).
async fn desktop_presence_gate<R: Runtime>(
    state: &VaultState<R>,
    click: ClickRequest,
) -> Result<presence::GatePass, presence::GateDenied> {
    let epoch = state.session_timer.epoch();
    let digest = click.op.digest();
    let attempt = state.presence.begin_attempt();
    let op = state
        .desktop_ops
        .begin(
            digest,
            Instant::now() + Duration::from_secs(APPROVAL_TIMEOUT_SECS),
            || state.presence.classify().is_protected(),
            attempt.id(),
        )
        .await
        .map_err(|error| presence::GateDenied {
            protected: true,
            message: error.to_string(),
            operation_id: "op-busy".into(),
        })?;
    let operation_id = format!("op-{}", op.id);
    let denied = |protected: bool, message: String| presence::GateDenied {
        protected,
        message,
        operation_id: operation_id.clone(),
    };

    if !op.protected {
        let outcome = state.approvals.request_click(click, TrayMirror::No).await;
        state.desktop_ops.finish(digest, op.id).await;
        outcome.map_err(|message| denied(false, message))?;
        if state.session_timer.epoch() != epoch {
            return Err(denied(false, "vault state changed during confirmation".into()));
        }
        return Ok(presence::GatePass {
            presence: sv_audit::PresenceAudit::click().with_operation(operation_id.clone()),
            digest,
            epoch,
            operation_id,
        });
    }

    match state.presence.verify(&attempt, &click.op, op.deadline).await {
        Ok(verified) => {
            state.desktop_ops.finish(digest, op.id).await;
            if verified.digest != digest
                || Instant::now() > op.deadline
                || state.session_timer.epoch() != epoch
            {
                return Err(denied(true, "verification no longer applies to this operation".into()));
            }
            Ok(presence::GatePass {
                presence: sv_audit::PresenceAudit::authenticated(presence::audit_modality(
                    verified.outcome.modality,
                ))
                .with_operation(operation_id.clone()),
                digest,
                epoch,
                operation_id,
            })
        }
        // Retryable: the operation stays registered (back to Pending), so a
        // retry keeps its identity, deadline and classification (D2).
        Err(denial @ sv_presence::Denial::Retryable(_)) => {
            state.desktop_ops.retry(digest, op.id, attempt.id()).await;
            Err(denied(true, denial.message()))
        }
        Err(denial) => {
            state.desktop_ops.finish(digest, op.id).await;
            Err(denied(true, denial.message()))
        }
    }
}

/// D14: consume a `GatePass` under the handle lock. The epoch is re-checked
/// while the lock is held, so a lock (or lock + re-unlock) since the gate
/// denies; the Allowed event returned by `f` is recorded with the pass's
/// presence BEFORE the lock is released.
async fn with_gated_handle<R, T, F>(state: &VaultState<R>, pass: &presence::GatePass, f: F) -> Result<T, String>
where
    R: Runtime,
    F: FnOnce(&VaultHandle) -> Result<(T, AuditEvent), String>,
{
    let guard = state.handle.lock().await;
    let handle = guard.as_ref().ok_or_else(|| "vault is locked".to_string())?;
    if state.session_timer.epoch() != pass.epoch {
        return Err("vault state changed after verification; try again".into());
    }
    let (value, mut event) = f(handle)?;
    event.presence = Some(pass.presence.clone());
    record_with_handle(state, handle, event);
    Ok(value)
}

async fn with_gated_handle_mut<R, T, F>(state: &VaultState<R>, pass: &presence::GatePass, f: F) -> Result<T, String>
where
    R: Runtime,
    F: FnOnce(&mut VaultHandle) -> Result<(T, AuditEvent), String>,
{
    let mut guard = state.handle.lock().await;
    let handle = guard.as_mut().ok_or_else(|| "vault is locked".to_string())?;
    if state.session_timer.epoch() != pass.epoch {
        return Err("vault state changed after verification; try again".into());
    }
    let (value, mut event) = f(handle)?;
    event.presence = Some(pass.presence.clone());
    record_with_handle(state, handle, event);
    Ok(value)
}
```

Denials are recorded by the caller with `record_desktop_event_locked(state, event)`, where `event.presence = Some(denied.audit())`.

- [ ] **Step 5: Migrate `require_desktop_consent`.** New signature and body:

```rust
async fn require_desktop_consent<R: Runtime>(
    state: &VaultState<R>,
    action: sv_mcp::AccessAction,
    container: &str,
    file_name: Option<&str>,
    mode: Option<SecurityMode>,
    operation: &str,
    destination: Option<&str>,
) -> Result<Option<presence::GatePass>, presence::GateDenied> {
    let required = desktop_consent_required_for(action, mode).map_err(|message| presence::GateDenied {
        protected: false,
        message,
        operation_id: "op-none".into(),
    })?;
    if !required {
        return Ok(None);
    }
    let op = sv_presence::OpDescriptor::new("desktop_file")
        .field("operation", operation)
        .field("container", container)
        .field("file", file_name.unwrap_or(""))
        .bind("action", format!("{action:?}"))
        .bind("mode", mode.map(|m| m.as_str()).unwrap_or(""))
        .bind("destination", destination.unwrap_or(""));
    let mut click = ClickRequest::desktop(&format!("{action:?}"), audit_action_for(&action), op);
    click.container = Some(container.to_string());
    click.file_name = file_name.map(str::to_string);
    click.mode = mode;
    desktop_presence_gate(state, click).await.map(Some)
}
```

Update every call site:
- pass `operation`: `"read"`, `"export"`, `"write"`, `"delete"`, or `"delete_container"`;
- pass `destination` (`None` everywhere except export);
- on `Err(denied)`, record the existing Denied event with `event.presence = Some(denied.audit())` through `record_desktop_event_locked`, and return `Err(denied.message)`;
- on `Ok(Some(pass))`, perform the release or mutation through `with_gated_handle` / `with_gated_handle_mut`. The closure returns the value plus the Allowed event it used to record;
- on `Ok(None)` (ungated mode), keep the existing `with_handle` path and audit unchanged.

`request_click_only` becomes unused: delete it, and fix its doc references.

- [ ] **Step 6: Split read/export into testable impls.**
- `vault_read_file` keeps its signature and calls `vault_read_file_impl(&state, container, file_name, lease_id, agent_id).await`. The impl is the current body, generic over `R`: `with_handle` → `with_handle_in` / `with_gated_handle` (per Step 5), `container_mode` → `container_mode_in`, and `require_lease(&state, …)` made generic (`async fn require_lease<R: Runtime>(state: &VaultState<R>, …)`).
- `vault_export_file` does three things:
  1. runs the save dialog first (D10), returning `Ok(None)` on cancel;
  2. converts the path;
  3. calls `vault_export_file_impl(&state, container, file_name, dest_path).await.map(Some)`.
  
  The impl performs mode lookup → `require_desktop_consent(…, "export", Some(&dest_path.display().to_string()))` → decrypt **and** atomic write inside `with_gated_handle` (so a lock since the gate aborts before any byte is written) → audit, and returns `Result<String, String>` (the display path). On the ungated path, keep today's decrypt-then-write order. Move the doc comment's "ask for the destination BEFORE decrypting" paragraph to the wrapper, and note that the destination is now bound into the gate digest (and still never audited).

- [ ] **Step 7: Run and commit**

Run: `cargo test -p sovereign-vault-desktop && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS, including the pre-existing `every_mutating_desktop_command_enforces_mode` and `deletion_prompts_even_in_direct_mode` (the latter searches the source text `delete_mode`, which must remain).

```bash
git add apps/desktop/src-tauri
git commit -m "feat(desktop): gate de presença para consentimento por modo; ANONYMIZED troca o clique por presença"
```

---

### Task 12: Gates on `scan_reveal`, `agent_create`, `vault_rotate_key`

**Executor:** OpenCode #4.

**Files:**
- Modify: `apps/desktop/src-tauri/src/lib.rs` (`scan_reveal` `:3745`, `agent_create` `:4631`, `vault_rotate_key` `:2670`)

**Interfaces:**
- Consumes: `desktop_presence_gate`, `ClickRequest::desktop`, `GatePass::ensure_same`, `sv_core::keyring::active_dek_version`, `state_root`.
- Produces: `scan_reveal_impl<R>`, `agent_create_impl<R>`, `vault_rotate_key_impl<R>(state, root, passphrase)`.

Pattern for every command in this task: the Tauri command becomes a thin
wrapper that calls `<name>_impl(&state, …)`. The impl opens with
`state.touch_human_activity();` (exactly as before), builds the
`OpDescriptor`, and calls the gate **before any mutation or release**.
- On `Err(denied)`, it records the command's audit action as `Denied` with `presence = Some(denied.audit())`, via `record_desktop_event_locked`, and returns `Err(denied.message)`.
- On `Ok(pass)`, the release or mutation runs **only** inside `with_gated_handle` / `with_gated_handle_mut` (D14). The closure returns `(value, allowed_event)`, and the helper records that event with `pass.presence` before unlocking.
- State-derived parameters are re-derived **inside** the closure and checked with `pass.ensure_same`, so they cannot move between the check and the mutation.

- [ ] **Step 1: Failing tests**

```rust
#[tokio::test]
async fn scan_reveal_reveals_nothing_without_presence() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    h.fake.push(FakeStep::Return(Err(sv_presence::PresenceError::Cancelled)));
    let got = scan_reveal_impl(h.state(), "report-x".into(), 0).await;
    assert!(got.unwrap_err().contains("presence"));
    assert_eq!(h.fake.calls(), 1, "the gate runs before any report lookup");
    let reveals: Vec<_> = h.presence_events().into_iter().filter(|(a, _, _)| a.contains("ScanReveal")).collect();
    assert_eq!(reveals.len(), 1);
    assert!(reveals[0].1.contains("Denied"));
    assert_eq!(reveals[0].2["protected"], true);
    assert!(reveals[0].2["operation_id"].as_str().unwrap().starts_with("op-"));
}

#[tokio::test]
async fn agent_create_creates_no_agent_without_presence() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    let before = with_handle_in(h.state(), |x| x.list_agents().map_err(estr)).await.unwrap().len();
    h.fake.push(FakeStep::Return(Err(sv_presence::PresenceError::Failed)));
    assert!(agent_create_impl(h.state(), "bot".into(), None).await.is_err());
    let after = with_handle_in(h.state(), |x| x.list_agents().map_err(estr)).await.unwrap().len();
    assert_eq!(before, after, "observable state unchanged, not merely no token");
}

#[tokio::test]
async fn agent_create_returns_token_after_presence() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    h.fake.approve_next();
    let created = agent_create_impl(h.state(), "bot".into(), None).await.unwrap();
    assert!(!created.token.is_empty());
}

#[tokio::test]
async fn rotate_key_leaves_dek_unchanged_without_presence() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    let before = sv_core::keyring::active_dek_version(&h.root).unwrap();
    h.fake.push(FakeStep::Return(Err(sv_presence::PresenceError::Cancelled)));
    let got = vault_rotate_key_impl(h.state(), &h.root, Some(TEST_PASSPHRASE.into())).await;
    assert!(got.is_err());
    assert_eq!(sv_core::keyring::active_dek_version(&h.root).unwrap(), before);
}

#[tokio::test]
async fn rotate_key_denied_when_dek_moves_during_prompt() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    h.fake.push(FakeStep::Hold(APPROVED));
    let state = h.state();
    let s2 = state;
    let rotate = async { vault_rotate_key_impl(s2, &h.root, Some(TEST_PASSPHRASE.into())).await };
    let meddle = async {
        while h.fake.calls() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let mut guard = state.handle.lock().await;
        guard.as_mut().unwrap().rotate_key(&h.root, Some(TEST_PASSPHRASE)).unwrap();
        drop(guard);
        h.fake.release();
    };
    let (got, ()) = tokio::join!(rotate, meddle);
    assert!(got.unwrap_err().contains("changed during verification"));
}
```

- [ ] **Step 2: Run to verify failure** → FAIL.

- [ ] **Step 3: Implement**

A shared denial writer (put it next to `desktop_presence_gate`):

```rust
/// Record a refused gate for `action` and return the message (plan D5).
async fn record_gate_denial<R: Runtime>(
    state: &VaultState<R>,
    denied: presence::GateDenied,
    mut event: AuditEvent,
) -> String {
    event.decision = AuditDecision::Denied;
    event.presence = Some(denied.audit());
    event.error = Some(denied.message.clone());
    record_desktop_event_locked(state, event).await;
    denied.message
}
```

`scan_reveal_impl(state, report_id, finding_index)`:

```rust
    state.touch_human_activity();
    let op = sv_presence::OpDescriptor::new("scan_reveal")
        .field("report", report_id.clone())
        .field("finding", finding_index.to_string());
    let pass = match desktop_presence_gate(state, ClickRequest::desktop("Reveal scan finding", AuditAction::ScanReveal, op)).await {
        Ok(pass) => pass,
        Err(denied) => {
            let mut event = desktop_event(AuditAction::ScanReveal, AuditDecision::Denied, Some(report_id.clone()), None, None, None, None);
            event.detail = Some(format!("finding_index={finding_index}"));
            return Err(record_gate_denial(state, denied, event).await);
        }
    };
    with_gated_handle(state, &pass, |_handle| {
        // The existing body from `let live_report = …` to `Ok(sv_scan::mask(value))`,
        // with `vault_root(&state.app)` -> `state_root(state)`, producing `masked`.
        let masked: String = /* existing body */;
        let mut event = desktop_event(AuditAction::ScanReveal, AuditDecision::Allowed, Some(report_id.clone()), None, None, None, None);
        event.detail = Some(format!("finding_index={finding_index}"));
        // event.file_name: as the existing Allowed branch sets it (lib.rs:3813-3823).
        Ok((masked, event))
    })
    .await
```

The existing Error-branch audit (`lib.rs:3826-3838`) stays for failures returned by the closure. Record it after `with_gated_handle` returns `Err`, via `record_desktop_event_locked`.

The `/* existing body */` above means: move the current closure body verbatim. It is not a placeholder for new logic.

`agent_create_impl(state, name, scopes)`:

```rust
    state.touch_human_activity();
    let op = sv_presence::OpDescriptor::new("agent_create")
        .field("name", name.clone())
        .bind("scopes", serde_json::to_string(&scopes).map_err(estr)?);
    let pass = match desktop_presence_gate(state, ClickRequest::desktop("Create agent", AuditAction::AgentCreate, op)).await {
        Ok(pass) => pass,
        Err(denied) => {
            let event = desktop_event(AuditAction::AgentCreate, AuditDecision::Denied, None, None, None, None, None);
            return Err(record_gate_denial(state, denied, event).await);
        }
    };
    with_gated_handle(state, &pass, |handle| {
        let (agent_id, token) = handle.create_agent(&name, scopes.unwrap_or_default()).map_err(estr)?;
        // New Allowed record: the agent id only, never the token.
        let mut event = desktop_event(AuditAction::AgentCreate, AuditDecision::Allowed, None, None, None, None, None);
        event.agent_id = Some(agent_id.clone());
        Ok((AgentCreated { agent_id, token }, event))
    })
    .await
```

`vault_rotate_key_impl(state, root, passphrase)`:

```rust
    state.touch_human_activity();
    let dek_op = |root: &Path| -> Result<sv_presence::OpDescriptor, String> {
        let version = sv_core::keyring::active_dek_version(root).map_err(estr)?;
        Ok(sv_presence::OpDescriptor::new("vault_rotate_key")
            .bind("dek_version", version.map(|v| v.to_string()).unwrap_or_default()))
    };
    let pass = match desktop_presence_gate(state, ClickRequest::desktop("Rotate vault key", AuditAction::KeyRotated, dek_op(root)?)).await {
        Ok(pass) => pass,
        Err(denied) => {
            let event = desktop_event(AuditAction::KeyRotated, AuditDecision::Denied, None, None, None, None, None);
            return Err(record_gate_denial(state, denied, event).await);
        }
    };
    let result = with_gated_handle_mut(state, &pass, |handle| {
        // Re-derived under the handle lock: the DEK cannot move between this
        // check and the rotation (D14).
        pass.ensure_same(&dek_op(root)?).map_err(|denied| denied.message)?;
        let recovery_phrase = handle.rotate_key(root, passphrase.as_deref()).map_err(estr)?;
        let event = desktop_event(AuditAction::KeyRotated, AuditDecision::Allowed, None, None, None, None, None);
        Ok((recovery_phrase, event))
    })
    .await;
    if let Err(error) = &result {
        let event = desktop_event(AuditAction::KeyRotated, AuditDecision::Error, None, None, None, None, Some(error.clone()));
        record_desktop_event_locked(state, event).await;
    }
    result.map(|recovery_phrase| VaultInitResponse { recovery_phrase, gateway_warning: None })
```

"Operation changed" failures inside the closure are recorded as `Error`
with that message. The test asserts the message; make the closure's
`ensure_same` error text `"operation changed during verification"`, as
`GatePass::ensure_same` returns it.

- [ ] **Step 4: Run and commit**

Run: `cargo test -p sovereign-vault-desktop && cargo clippy --workspace --all-targets -- -D warnings`

```bash
git add apps/desktop/src-tauri
git commit -m "feat(desktop): presença antes de revelar achados, criar agentes e rotacionar a chave"
```

---

### Task 13: Gates on remediation, wake, keychain unlock, init

**Executor:** OpenCode #3.

**Files:**
- Modify: `apps/desktop/src-tauri/src/lib.rs`:
  - `remediate_execute` `:3464`, `remediate_restore` `:3609`
  - `wake_respond` `:4418` + `WakeQueue::peek`, `wake_prepare_access` tests
  - `vault_unlock` `:2329`, `vault_init` `:2246`

**Interfaces:**
- Consumes: `desktop_presence_gate`, `GatePass::ensure_same`, `WakeQueue`, `LeaseStore`.
- Produces:
  - `remediate_execute_impl<R>`, `remediate_restore_impl<R>`
  - `wake_respond_impl<R>`
  - `vault_unlock_impl<R>(state, root, custody, passphrase)`, `vault_init_impl<R>(state, root, custody, passphrase)`
  - `WakeQueue::peek(&self, id: u64) -> Option<WakeRequest>`
  - `LeaseStore::record_authorized_wake_at(…, at: Instant)` (`#[cfg(test)]`)

- [ ] **Step 1: Failing tests**

```rust
async fn plan_fixture(h: &Harness) -> (String, PathBuf) {
    let project = h.root.parent().unwrap().join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join(".env"), "API_KEY=sk-test-123\n").unwrap();
    let project = project.canonicalize().unwrap();
    let plan = {
        let guard = h.state().handle.lock().await;
        let handle = guard.as_ref().unwrap();
        let key = sv_remediate::PlanKey::from_bytes(&handle.remediation_plan_key()).unwrap();
        ManagedFilePlan::build(
            "proj",
            std::path::Path::new(".env"),
            &project,
            ConsumerAdapter::EnvInjection,
            std::path::Path::new(".env.vault-manifest.json"),
            sv_remediate::managed::SharedBinding::Independent,
            &key,
        )
        .unwrap()
    };
    let id = mint_plan_id();
    let snapshot_digest = plan.snapshot_digest;
    h.state().pending_plans.lock().unwrap().insert(
        id.clone(),
        PendingPlan { id: id.clone(), project_root: project.clone(), plan, snapshot_digest, created_at: chrono::Utc::now() },
    );
    (id, project.join(".env"))
}

#[tokio::test]
async fn remediate_execute_leaves_project_unchanged_without_presence() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    let (plan_id, file) = plan_fixture(&h).await;
    let before = std::fs::read(&file).unwrap();
    let digest = {
        let plans = h.state().pending_plans.lock().unwrap();
        hex::encode(plans[&plan_id].snapshot_digest.as_bytes())
    };
    h.fake.push(FakeStep::Return(Err(sv_presence::PresenceError::Cancelled)));
    let got = remediate_execute_impl(h.state(), plan_id.clone(), digest).await;
    assert!(got.is_err(), "a digest match alone is not enough");
    assert_eq!(std::fs::read(&file).unwrap(), before);
    assert!(h.state().pending_plans.lock().unwrap().contains_key(&plan_id), "plan not consumed");
}

#[tokio::test]
async fn remediate_restore_consumes_nothing_without_presence() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    let (plan_id, _) = plan_fixture(&h).await;
    h.fake.push(FakeStep::Return(Err(sv_presence::PresenceError::Cancelled)));
    assert!(remediate_restore_impl(h.state(), plan_id.clone()).await.is_err());
    assert!(h.state().pending_plans.lock().unwrap().contains_key(&plan_id));
}

#[tokio::test]
async fn wake_approval_records_no_authorization_without_presence() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    h.state().wake_queue.request("agent-1".into(), "res".into()).await;
    let id = h.state().wake_queue.list().await[0].id;
    h.fake.push(FakeStep::Return(Err(sv_presence::PresenceError::Cancelled)));
    assert!(wake_respond_impl(h.state(), id, true).await.is_err());
    let sig = wake_signature("agent-1", "res");
    assert!(!h.state().leases.has_authorized_wake(&sig, "agent-1", &h.state().session_id()).await);
    assert_eq!(h.state().wake_queue.list().await.len(), 1, "request still pending: verify before mutation");
}

#[tokio::test]
async fn wake_refusal_needs_no_presence() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    h.state().wake_queue.request("agent-1".into(), "res".into()).await;
    let id = h.state().wake_queue.list().await[0].id;
    wake_respond_impl(h.state(), id, false).await.unwrap();
    assert_eq!(h.fake.calls(), 0);
}

#[tokio::test]
async fn wake_prepare_access_refuses_without_current_authorization() {
    let store = LeaseStore::new();
    // Direct call with no approval.
    assert!(!store.has_authorized_wake("sig", "agent-1", "s1").await);
    // Expired authorization.
    store
        .record_authorized_wake_at("sig", "agent-1", "s1", Instant::now() - Duration::from_secs(WAKE_REQUEST_TTL_SECS + 1))
        .await;
    assert!(!store.has_authorized_wake("sig", "agent-1", "s1").await);
    // Session switch and scope (resource/agent) switch.
    store.record_authorized_wake("sig", "agent-1", "s1").await;
    assert!(!store.has_authorized_wake("sig", "agent-1", "s2").await);
    assert!(!store.has_authorized_wake("other-sig", "agent-1", "s1").await);
    assert!(!store.has_authorized_wake("sig", "agent-2", "s1").await);
}

#[tokio::test]
async fn keychain_unlock_does_not_unlock_without_presence() {
    let h = Harness::new(FakeVerifier::protected());
    h.fake.push(FakeStep::Return(Err(sv_presence::PresenceError::Cancelled)));
    let got = vault_unlock_impl(h.state(), &h.root, "OsKeychain".into(), None).await;
    assert!(got.is_err());
    assert!(h.state().handle.lock().await.is_none());
    assert_eq!(h.fake.calls(), 1, "gate runs before any keychain or probe access");
}

/// Declared exception (spec §7.5): only keychain custody needs presence.
/// A pure predicate, so the test never reaches `sv_core::probe`, which
/// touches the real OS keychain.
#[test]
fn only_keychain_unlock_requires_presence() {
    assert!(unlock_requires_presence(CustodyMode::OsKeychain));
    assert!(!unlock_requires_presence(CustodyMode::Passphrase));
    assert!(!unlock_requires_presence(CustodyMode::Recovery));
}

#[tokio::test]
async fn vault_init_creates_no_vault_without_presence() {
    let h = Harness::new(FakeVerifier::protected());
    h.fake.push(FakeStep::Return(Err(sv_presence::PresenceError::Cancelled)));
    let got = vault_init_impl(h.state(), &h.root, "Passphrase".into(), Some(TEST_PASSPHRASE.into())).await;
    assert!(got.is_err());
    assert!(!sv_core::probe(&h.root).map(|p| p.initialized).unwrap_or(false));
}
```

The passphrase unlock test can fail after the gate-free path, in
`start_servers` (a port bind in tests). It asserts only that no verification
ran. If `start_servers` binding 9944 is flaky in tests, leave it: the result
is ignored. `keychain_unlock` and `vault_init` denials are not audited (D5). The declared click of a keychain unlock is covered in Task 8 (`pre_unlock_click_is_approvable_while_locked`), not here: past consent, `vault_unlock` probes the real OS keychain (`sv_core::probe`), which tests must not touch.

- [ ] **Step 2: Run to verify failure** → FAIL.

- [ ] **Step 3: Implement**

**3a — `pending_plans` becomes a `std::sync::Mutex` (pre-existing defect).**
- `VaultState.pending_plans` is a `tokio::sync::Mutex` (`lib.rs:1312`). `remediate_plan_file`, `remediate_execute`, and `remediate_restore` call `blocking_lock()` on it inside async code (`lib.rs:3408`, `:3477`, `:3518`, `:3622`), and tokio documents that `blocking_lock` panics when called within an asynchronous execution context.
- Change the field to `Arc<std::sync::Mutex<HashMap<String, PendingPlan>>>`, and replace every async/blocking lock on it with `.lock().unwrap_or_else(std::sync::PoisonError::into_inner)`.
- Lock order is then always **handle → plans**, matching `perform_vault_lock` (`lib.rs:2494-2502`). Never hold a plans guard across an `.await`.

**3b — `remediate_execute_impl(state, plan_id, confirm_digest)`**

```rust
fn remediation_op(kind: &'static str, plan_id: &str, p: &PendingPlan) -> sv_presence::OpDescriptor {
    sv_presence::OpDescriptor::new(kind)
        .field("file", p.plan.path.to_string_lossy())
        .bind("plan", plan_id)
        .bind("snapshot", hex::encode(p.snapshot_digest.as_bytes()))
        .bind("manifest", p.plan.manifest_path.to_string_lossy())
        .bind("adapter", p.plan.adapter.as_str())
}

/// TTL-pruned lookup, exactly as `remediate_execute` does today.
fn live_plan(plans: &mut HashMap<String, PendingPlan>, plan_id: &str) -> Result<PendingPlan, String> {
    let now = chrono::Utc::now();
    plans.retain(|_, p| (now - p.created_at).num_seconds() < PLAN_TTL_SECS);
    plans.get(plan_id).cloned().ok_or_else(|| "unknown plan id".to_string())
}
```

Flow:
1. `touch_human_activity`.
2. `let snapshot = live_plan(&mut state.pending_plans.lock()…, &plan_id)?;` (the guard is dropped at the end of the statement). An unknown plan gets no gate.
3. Gate with `ClickRequest::desktop("Move secret file into the vault", AuditAction::PlanApprove, remediation_op("remediate_execute", &plan_id, &snapshot))`. On `Err(denied)`, return `Err(record_gate_denial(state, denied, desktop_event(AuditAction::PlanApprove, AuditDecision::Denied, None, None, None, None, None)).await)`.
4. `with_gated_handle(state, &pass, |handle| { … })`. Inside, in this order:
   1. lock plans;
   2. `let pending = live_plan(&mut plans, &plan_id)?;`
   3. `pass.ensure_same(&remediation_op("remediate_execute", &plan_id, &pending)).map_err(|d| d.message)?;`
   4. the existing length + `ct_eq` `confirm_digest` check (a digest match alone is not presence, spec §7.5 item 4);
   5. drop the plans guard;
   6. the existing ingest body;
   7. remove `plan_id` from plans;
   8. return `Ok((view, desktop_event(AuditAction::PlanApprove, AuditDecision::Allowed, None, None, None, None, None)))`.
5. Keep the existing `PlanExecute` record after the helper returns, via `record_desktop_event_locked`. A `"plan digest mismatch"` error is recorded as `PlanApprove` `Denied`, exactly as today.

**3c — `remediate_restore_impl(state, plan_id_or_ref)`.** It follows the same shape:
- snapshot with `live_plan`;
- gate with `remediation_op("remediate_restore", …)` and the label "Restore file from vault";
- then `with_gated_handle`, whose closure runs `ensure_same` and only then the existing `remove(&plan_id_or_ref)` and restore body (D9: a denied gate consumes nothing).

**3d — `wake_respond_impl(state, id, approved)`**
- Refusal (`approved == false`) is unchanged: no gate.
- Approval: look the request up with the new `WakeQueue::peek(id)` (below); a missing request returns `Err("wake request not found")`.
- Gate with the descriptor below, the label "Approve wake request", and the audit action `VaultInfo` (as the existing wake records use). On `Err(denied)`, record through `record_gate_denial` and return.
- On `Ok(pass)`, do everything under ONE handle guard, so no session transition can interleave (transitions only happen under this guard, Task 7):

```rust
    let guard = state.handle.lock().await;
    let Some(handle) = guard.as_ref() else {
        return Err("vault is locked".into());
    };
    if state.session_timer.epoch() != pass.epoch {
        return Err("vault state changed after verification; try again".into());
    }
    // The session the human approved in, derived from the pass, not re-read.
    let session = format!("session-{}", pass.epoch);
    let Some(request) = state.wake_queue.respond(id, true).await else {
        return Err("wake request not found".into());
    };
    state.leases.record_authorized_wake(&request.signature, &request.agent_id, &session).await;
    let mut event = desktop_event(AuditAction::VaultInfo, AuditDecision::Allowed, None, None, None, None,
        Some(format!("wake-approved agent={} resource={}", request.agent_id, request.opaque_resource_ref)));
    event.presence = Some(pass.presence.clone());
    record_with_handle(state, handle, event);
    drop(guard);
```

  `wake_queue` and `leases` use their own locks, which are never taken while waiting for the handle, so holding the handle here cannot deadlock. Add a test `wake_authorization_is_bound_to_the_approving_session`:
  - approve with presence;
  - lock and unlock with `publish_locked` / `publish_unlocked`;
  - assert `has_authorized_wake(sig, agent, &state.session_id())` is `false` (new session) and is `true` for `format!("session-{}", old_epoch)`.

```rust
    async fn peek(&self, id: u64) -> Option<WakeRequest> {
        self.requests.lock().await.iter().find(|r| r.id == id).cloned()
    }
```

```rust
    sv_presence::OpDescriptor::new("wake_respond")
        .field("agent", request.agent_id.clone())
        .field("resource", request.opaque_resource_ref.clone())
        .bind("wake_id", id.to_string())
        .bind("signature", request.signature.clone())
        .bind("session", state.session_id())
```

Add under `#[cfg(test)]` in `impl LeaseStore`:

```rust
    async fn record_authorized_wake_at(&self, sig: &str, agent_id: &str, session_id: &str, at: Instant) {
        let auth = WakeAuthorization { agent_id: agent_id.into(), session_id: session_id.into(), authorized_at: at };
        self.authorized_wakes.lock().await.insert(sig.into(), auth);
    }
```

**3e — `vault_unlock_impl(state, root, custody, passphrase)`**
- After `parse_custody`, and before `sv_core::probe`:

```rust
    let pass = if unlock_requires_presence(mode) {
        // ADR-0025 §7.5 item 9 (plan D7): the one unlock that needs no
        // knowledge. Presence comes first; denials here are not auditable
        // (locked vault, declared D5 exception).
        let op = sv_presence::OpDescriptor::new("vault_unlock")
            .field("vault", root.display().to_string())
            .bind("custody", "os_keychain");
        Some(
            desktop_presence_gate(state, ClickRequest::desktop_pre_unlock("Unlock vault with OS keychain", AuditAction::VaultUnlock, op))
                .await
                .map_err(|denied| denied.message)?,
        )
    } else {
        None
    };
```

- Define next to it:

```rust
/// ADR-0025 §7.5 item 9 / plan D7: the knowledge-free unlock is the gated one.
fn unlock_requires_presence(mode: CustodyMode) -> bool {
    mode == CustodyMode::OsKeychain
}
```

- Then restructure the existing body, so that the check, the unlock, the publication (handle + epoch), and the Allowed record all happen under **one** handle guard (D4, D5):

```rust
    {
        let mut guard = state.handle.lock().await;
        // Revalidate under the lock: still locked, same epoch (no unlock or
        // lock completed while the prompt was open).
        if let Some(pass) = &pass {
            if guard.is_some() || state.session_timer.epoch() != pass.epoch {
                return Err("vault state changed during verification".into());
            }
        }
        let probe = sv_core::probe(root).map_err(estr)?;
        let handle = /* the existing `handle_result` match (keychain migration or plain unlock), moved here unchanged */;
        let mut event = desktop_event(AuditAction::VaultUnlock, AuditDecision::Allowed, None, None, None, None, None);
        event.presence = pass.as_ref().map(|p| p.presence.clone());
        record_with_handle(state, &handle, event);
        state.publish_unlocked(&mut guard, handle);
    }
```

  Then `start_servers`. On its failure, `publish_locked` under a fresh guard, and record the existing Error event. Then the monitor restart. The later standalone `set_unlocked()` and the old Allowed record are removed, because both happened above.

**3f — `vault_init_impl(state, root, custody, passphrase)`**
- Gate **first**, before any `sv_core::probe` (which touches the OS keychain), with:
  - `OpDescriptor::new("vault_init").field("vault", root.display().to_string())`
  - `ClickRequest::desktop_pre_unlock("Create vault", AuditAction::VaultInit, op)` (its declared click must be approvable before any vault exists).
- Then take `state.handle.lock().await` and, under that guard, do three things:
  1. check `guard.is_none()`, `!sv_core::probe(root)?.initialized` (the existing "already initialised" check, moved here), and the epoch;
  2. run `VaultHandle::bootstrap`;
  3. write the `VaultInit` and `RecoveryIssued` Allowed records with `record_with_handle(state, &handle, …)` (presence from the pass), then `state.publish_unlocked(&mut guard, handle)`.
- The recovery phrase is returned only after all of that. The old post-hoc records and `set_unlocked()` are removed.

The wrappers compute `vault_root(&app)` and pass it in. `start_servers` takes `&State<'_, VaultState<R>>`; change it to take `&VaultState<R>` (all its uses deref), so the impls can call it.

- [ ] **Step 4: Run and commit**

Run: `cargo test -p sovereign-vault-desktop && cargo clippy --workspace --all-targets -- -D warnings`

```bash
git add apps/desktop/src-tauri
git commit -m "feat(desktop): presença em remediação, wake, desbloqueio por keychain e criação do cofre"
```

---

### Task 14: Completeness registry, unprotected notice, ADR-0024 contract

**Executor:** OpenCode #4.

**Files:**
- Modify: `apps/desktop/src-tauri/src/lib.rs` (tests module; command `presence_status`; `generate_handler!`)
- Modify: `apps/desktop/src-tauri/src/presence.rs` (`secret_submit_op`)
- Modify: `ui/src/App.svelte` (notice), `ui/src/lib/types.ts`

**Interfaces:**
- Produces:
  - `presence_status() -> PresenceStatus { protected: bool, reason: Option<String> }`
  - `session_set_limits_impl<R>(state, idle_secs, absolute_secs)` (D15)
  - `presence::secret_submit_op(request_id: &str, container: &str, env_var: &str, expected_revision: Option<u64>, expected_generation: &str) -> OpDescriptor`
  - const `COMMAND_GATES: &[(&str, Gate)]` in tests

- [ ] **Step 1: Failing completeness test**

```rust
#[derive(Debug, Clone, Copy)]
enum Gate {
    /// The command body calls the presence gate itself.
    Own(&'static str),
    /// Authorization derived from an earlier gated decision.
    Derived(&'static str),
    /// Justified exception (plan D8, spec §7.5 declared list).
    Exception(&'static str),
}

/// ADR-0025 §9.2: every registered command is classified; a new command
/// without a classification fails here.
const COMMAND_GATES: &[(&str, Gate)] = &[
    ("app_version", Gate::Exception("no vault data")),
    ("vault_status", Gate::Exception("status metadata; polling")),
    ("vault_init", Gate::Own("desktop_presence_gate")),
    ("vault_unlock", Gate::Own("desktop_presence_gate")), // keychain only; passphrase declared
    ("vault_unlock_recovery", Gate::Exception("needs the recovery phrase; keylogging is a non-goal")),
    ("vault_lock", Gate::Exception("reduces authority")),
    ("vault_change_passphrase", Gate::Exception("needs the current passphrase")),
    ("vault_rotate_key", Gate::Own("desktop_presence_gate")),
    ("vault_list_containers", Gate::Exception("names are plaintext dirs, modes in plaintext manifest.json (D8; author decision)")),
    ("vault_create_container", Gate::Exception("creates, releases nothing")),
    ("vault_delete_container", Gate::Own("require_desktop_consent")),
    ("audit_tail", Gate::Exception("audit stores HMAC'd names; polling")),
    ("audit_verify", Gate::Exception("integrity report only")),
    ("scan_run", Gate::Exception("scans a user-chosen path; findings are masked")),
    ("scan_store", Gate::Exception("persists a masked report")),
    ("scan_history_list", Gate::Exception("masked report metadata; polling")),
    ("scan_report_get", Gate::Exception("masked findings; the reveal is gated")),
    ("scan_reveal", Gate::Own("desktop_presence_gate")),
    ("scan_triage_set", Gate::Exception("changes what the user notices; grants no approval or release (D8)")),
    ("vault_list_files", Gate::Exception("metadata class, spec §7.5 declared")),
    ("vault_write_file", Gate::Own("require_desktop_consent")),
    ("vault_read_file", Gate::Own("require_desktop_consent")),
    ("vault_export_file", Gate::Own("require_desktop_consent")),
    ("open_audit_folder", Gate::Exception("reveals a location, not content")),
    ("vault_delete_file", Gate::Own("require_desktop_consent")),
    ("approval_respond", Gate::Own("approvals.respond")),
    ("approval_reveal_otp", Gate::Own("reveal_otp")),
    ("wake_request", Gate::Exception("creates a request; releases nothing")),
    ("wake_list", Gate::Exception("pending wake metadata; polling")),
    ("wake_respond", Gate::Own("desktop_presence_gate")),
    ("wake_prepare_access", Gate::Derived("has_authorized_wake")),
    ("mcp_status", Gate::Exception("pairing secret already public via /.well-known/mcp-pairing, spec §7.5")),
    ("session_status", Gate::Exception("timer metadata; polling")),
    ("session_set_limits", Gate::Own("desktop_presence_gate")), // increases only (D15)
    ("notifications_set_enabled", Gate::Exception("changes what the user notices; approvals still need presence (D8)")),
    ("agent_create", Gate::Own("desktop_presence_gate")),
    ("agent_list", Gate::Exception("metadata, no tokens (D8)")),
    ("agent_revoke", Gate::Exception("reduces authority")),
    ("transit_create_key", Gate::Exception("creates material; every use is MCP-gated (D8)")),
    ("transit_list_keys", Gate::Exception("key names; polling")),
    ("signing_create_key", Gate::Exception("creates material; every use is MCP-gated (D8)")),
    ("signing_list_keys", Gate::Exception("key names; polling")),
    ("broker_create_secret", Gate::Exception("stores a secret; every use is MCP-gated (D8)")),
    ("broker_list_secrets", Gate::Exception("secret names; polling")),
    ("broker_enabled", Gate::Exception("feature flag")),
    ("remediate_plan_file", Gate::Exception("plans only; execution is gated")),
    ("remediate_plan_list", Gate::Exception("plan metadata; polling")),
    ("remediate_execute", Gate::Own("desktop_presence_gate")),
    ("remediate_restore", Gate::Own("desktop_presence_gate")),
    ("cli_binary_path", Gate::Exception("install path")),
    ("presence_status", Gate::Exception("availability metadata")),
];

#[test]
fn every_registered_command_has_a_presence_classification() {
    let src = include_str!("lib.rs");
    let start = src.find("tauri::generate_handler![").unwrap();
    let end = start + src[start..].find(']').unwrap();
    let registered: Vec<&str> = src[start + "tauri::generate_handler![".len()..end]
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let body = src.split("#[cfg(test)]").next().unwrap();
    for name in &registered {
        let (_, gate) = COMMAND_GATES
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("{name} is registered but has no ADR-0025 classification"));
        let marker = match gate {
            Gate::Own(m) | Gate::Derived(m) => *m,
            Gate::Exception(reason) => {
                assert!(!reason.is_empty());
                continue;
            }
        };
        // The marker must appear in the command or in its `_impl`.
        let found = [format!("fn {name}("), format!("fn {name}_impl")].iter().any(|sig| {
            body.find(sig.as_str()).is_some_and(|pos| {
                let rest = &body[pos..];
                let end = rest[1..].find("\n#[tauri::command]").map(|i| i + 1).unwrap_or(rest.len());
                rest[..end].contains(marker)
            })
        });
        assert!(found, "{name} is classified {gate:?} but its body does not call {marker}");
    }
    for (name, _) in COMMAND_GATES {
        assert!(registered.contains(name), "{name} is classified but not registered");
    }
}
```

For impls located before their command, the search window from
`fn {name}_impl` to the next `#[tauri::command]` covers the impl body. If
an impl is placed after its command, the window from `fn {name}(` covers
it. Keep each `_impl` directly above its command.

- [ ] **Step 2: `presence_status` command + ADR-0024 contract**

```rust
#[derive(Debug, Serialize)]
struct PresenceStatus {
    protected: bool,
    reason: Option<String>,
}

/// Whether approvals on this system are presence-protected, for the
/// permanent notice (ADR-0025 §6.2). Polling: no idle refresh.
#[tauri::command]
async fn presence_status(state: State<'_, VaultState>) -> Result<PresenceStatus, String> {
    Ok(match state.presence.classify() {
        sv_presence::Classification::Protected => PresenceStatus { protected: true, reason: None },
        sv_presence::Classification::Unprotected(reason) => PresenceStatus {
            protected: false,
            reason: Some(reason.message().to_string()),
        },
    })
}
```

Register it; add `"presence_status"` to `POLLING_COMMANDS`.

In `presence.rs`:

```rust
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
        .bind("expected_revision", expected_revision.map(|r| r.to_string()).unwrap_or_else(|| "none".into()))
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
```

- [ ] **Step 2b: Gate increases of the session limits (D15).** `session_set_limits` becomes a wrapper around the function below. `VaultState` gains `limits_change: tokio::sync::Mutex<()>`. It serializes every limit change, so the comparison uses the real current values (atomics, Task 7), and nothing can change them between the check and the store:

```rust
async fn session_set_limits_impl<R: Runtime>(
    state: &VaultState<R>,
    idle_secs: u64,
    absolute_secs: u64,
) -> Result<(), String> {
    state.touch_human_activity();
    // Held across the gate: concurrent changes wait, they never interleave.
    let _serial = state.limits_change.lock().await;
    let (idle_now, absolute_now) = state.session_timer.limits();
    let widens = idle_secs.max(1) > idle_now || absolute_secs.max(1) > absolute_now;
    if !widens {
        state.set_limits(idle_secs, absolute_secs);
        return Ok(());
    }
    // Keeping the vault unlocked longer widens exposure: presence first,
    // and the pass is CONSUMED under the handle lock with the epoch check.
    let op = sv_presence::OpDescriptor::new("session_limits")
        .field("idle_secs", idle_secs.to_string())
        .field("absolute_secs", absolute_secs.to_string())
        .bind("from", format!("{idle_now}/{absolute_now}"));
    let pass = match desktop_presence_gate(state, ClickRequest::desktop("Extend session limits", AuditAction::VaultInfo, op)).await {
        Ok(pass) => pass,
        Err(denied) => {
            let mut event = desktop_event(AuditAction::VaultInfo, AuditDecision::Denied, None, None, None, None, None);
            event.detail = Some("session-limits-increase".into());
            return Err(record_gate_denial(state, denied, event).await);
        }
    };
    with_gated_handle(state, &pass, |_handle| {
        state.set_limits(idle_secs, absolute_secs);
        let mut event = desktop_event(AuditAction::VaultInfo, AuditDecision::Allowed, None, None, None, None, None);
        event.detail = Some("session-limits-increase".into());
        Ok(((), event))
    })
    .await
}
```

The `.max(1)` mirrors `set_limits`, which stores at least 1 (`lib.rs:1257-1260`), so a value that would be clamped is compared as stored.

Tests:

```rust
#[tokio::test]
async fn raising_session_limits_needs_presence() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    let before = h.state().session_timer.limits();
    h.fake.push(FakeStep::Return(Err(sv_presence::PresenceError::Cancelled)));
    assert!(session_set_limits_impl(h.state(), before.0 * 10, before.1).await.is_err());
    assert_eq!(h.state().session_timer.limits(), before, "no presence, no wider exposure");
}

/// B2: a concurrent reduction cannot turn a widening into a free change.
#[tokio::test]
async fn widening_is_judged_against_the_serialized_current_value() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    let (idle, abs) = h.state().session_timer.limits();
    h.fake.push(FakeStep::Hold(Err(sv_presence::PresenceError::Cancelled)));
    let state = h.state();
    let widen = async { session_set_limits_impl(state, idle * 10, abs).await };
    let shrink = async {
        while h.fake.calls() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // Waits behind the widening's gate; never interleaves with it.
        let got = session_set_limits_impl(state, idle / 2, abs).await;
        got
    };
    let release = async {
        while h.fake.calls() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
        h.fake.release();
    };
    let (w, s2, ()) = tokio::join!(widen, shrink, release);
    assert!(w.is_err(), "the widening was never verified");
    assert!(s2.is_ok());
    assert_eq!(h.state().session_timer.limits(), (idle / 2, abs));
}

#[tokio::test]
async fn lowering_session_limits_is_free() {
    let h = Harness::unlocked(FakeVerifier::protected()).await;
    let before = h.state().session_timer.limits();
    session_set_limits_impl(h.state(), before.0 / 2, before.1 / 2).await.unwrap();
    assert_eq!(h.fake.calls(), 0);
}
```

- [ ] **Step 3: UI notice.** In `App.svelte`, after unlock, call `invoke<{ protected: boolean; reason: string | null }>('presence_status')` once. When `protected` is false, render a permanent (non-dismissable) `notice-banner` at the top: "Unprotected approvals on this system — approvals are confirmed with a click because no OS presence check is available ({reason})." Add the type to `types.ts`.

- [ ] **Step 4: Run and commit**

Run: `cargo test -p sovereign-vault-desktop && (cd ui && npm run check && npm test)`

```bash
git add apps/desktop/src-tauri ui/src
git commit -m "test(desktop): classificar todo comando registrado quanto à presença; aviso permanente"
```

**CHECKPOINT 3 — Codex final review (branch).** Send it:
- `git diff --stat main`;
- the `COMMAND_GATES` table;
- the bodies of `desktop_presence_gate` and `require_desktop_consent`;
- the list of new test names.

Request the terse verdict. Fix the BLOQUEIOS before PR-C.

---

### Task 15: Documentation

**Executor:** OpenCode #5 (mechanical doc edits), then OpenCode #4 checks every `file:line` reference.

**Files:**
- Modify: `docs/threat-model.md`, `docs/SECURITY-REVIEW.md`, `docs/adr/0025-presence-verified-approvals.md`
- Create: `docs/testing/presence-manual-cases.md`

- [ ] **Step 1: `docs/testing/presence-manual-cases.md`.** One table per platform, with columns Case | Steps | Expected. Cover each spec §9.3 case verbatim:
  - macOS: Touch ID approve; Mac password approve; cancel / lock / refuse during the prompt.
  - Windows: Hello fingerprint; Hello PIN; locked/unavailable device.
  - Windows below build 22000: declared click + notice.
  - Linux: declared click + notice.
  - Real UI automation: AppleScript/Accessibility on macOS, UI Automation on Windows, pressing Approve and each gated command's button with no OS authentication → nothing commits.

  Add a column "Result / date / tester", left empty.
- [ ] **Step 2: `docs/threat-model.md`.** Add a subsection with:
  - the guarantee (per protected operation);
  - the declared limits: Linux unprotected, Windows < 22000 unprotected, modality `unknown` on Windows and macOS (D1);
  - the declared ungated commands with their reasons (§7.5 list + D8).
- [ ] **Step 3: `docs/SECURITY-REVIEW.md`.** Add an entry for ADR-0025 with:
  - the `unsafe` exception (crate, the two calls, the lints);
  - the robius pin and the `android-build` residual cost;
  - the tray revision.
- [ ] **Step 4: ADR-0025.** Add an "Implementation notes" section that points to this plan and lists D1–D15. It must state explicitly:
  - the declared audit exception of D5;
  - the **open dependency**: spec §7.4 (ADR-0024 submits) is not yet fulfilled.
  
  Keep **Status: Proposed**; the author decides the status.
- [ ] **Step 5: Verify.** Run `git diff --stat` and confirm nothing under `docs/thesis/` changed.

  Run the repo's link/citation checks if present: `python3 scripts/check_thesis_citations.py` or the command the CI "Thesis citation ranges resolve" step uses (see `.github/workflows/ci.yml:181`).
- [ ] **Step 6: Commit** (after authorization): `docs: registrar garantias, limites e casos manuais do ADR-0025`

---

## Spec coverage (self-review)

| Spec | Task |
|---|---|
| §4 crate, trait, insertion point | 1, 3, 8 |
| §5.1 macOS (Ok ≠ success, missing/late callback, fresh context) | 4 (+3 for late/timeout) |
| §5.2 Windows (HWND, forbidden APIs, only Verified, build 22000, unsafe rules) | 5 |
| §5.3 Linux Unavailable | 1 (`platform_verifier`), 7 |
| §6.1 states, lock release, finisher, one prompt, queue 8, slot held | 2, 3, 8 |
| §6.2 classification at creation, never degrade | 3 (D2), 8 |
| §6.3 digest, backend-derived prompt text | 1, 8, 11–13 |
| §7.1 modal | 8 |
| §7.2 tray revision | 9 |
| §7.3 OTP reveal/approve split, single use, A≠B | 10 |
| §7.4 programmatic paths; ADR-0024 submits | 11; 14 — contract only, **§7.4 stays open** until the ADR-0024 submits exist (D12) |
| §7.5 items 1–10, DIRECT/metadata/pairing exceptions, verify-before-mutation | 8, 11, 12, 13, 14 |
| §8 audit fields | 6, 8, 11–13 |
| §9.1 error mapping | 1, 3, 4, 5 |
| §9.2 automated tests | 2–14 |
| §9.3 manual | 15 |
| §11 dependency risks, docs | 4, 15 |
| §12 thesis untouched | Global Constraints, 15 |
