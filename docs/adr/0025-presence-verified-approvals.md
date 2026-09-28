# ADR-0025 — Presence-verified approvals

- **Status:** Proposed
- **Date:** 2026-09-28
- **Deciders:** pealmeida
- **Design spec:** [`docs/development/specs/2026-09-28-presence-verified-approvals-design.md`](../development/specs/2026-09-28-presence-verified-approvals-design.md)

## Context

Every approval in Sovereign Vault today proves intent at a surface — a click in
the modal, a click in the tray, an OTP resent by the agent — but none proves
the presence of the device owner. An agent running as the same OS user can
drive the UI through synthetic input (UI automation, accessibility APIs) or
read the OTP code shown on screen and resend it, approving its own request.
The threat model (docs/threat-model.md §3.B) treats the same OS user as
trusted and keeps memory scraping, ptrace, and keylogging out of scope; this
ADR does not move that boundary. It closes a narrower gap: a same-user agent
must not be able to approve its own request, and synthetic input must not
count as a human decision.

The approval machinery concentrates the decision in one place, which is what
makes this tractable. `ApprovalState::respond`
(apps/desktop/src-tauri/src/lib.rs:674) removes the pending entry under a
mutex and sends the boolean over a oneshot channel; `request_click`
(:580-672) arms it with a 120 s timeout (`APPROVAL_TIMEOUT_SECS`, :75); the
Tauri command `approval_respond` (:4355) and the tray path `respond_from_tray`
(:1779-1832) both land there, and so do the desktop-originated gates
`require_desktop_consent` (:2147-2179) and `request_click_only` (:551-560).
The OTP flow generates a six-digit code (`generate_otp_code`, :295-299),
delivers it in the `ApprovalPrompt.otp_code` event field (:517-526, issued by
`handle_otp_fresh` :486-538), and expects the agent to resend the request
carrying it (`handle_otp` :356-483, `process_otp_request` :224-275), with the
same 120 s TTL. Tauri commands are only invocable from the app's own webview,
so the surfaces that decide are exactly: modal, tray, and the OTP resend.

One premise needs to be stated precisely: `respond()` is the single decision
point for MCP request approvals — modal, tray, and the desktop consent gate —
not for every human action the app takes. Remediation originates entirely
from human UI actions (`scan_run` then `remediate_plan_file`, executed by
`remediate_execute` under a digest confirmation), and wake requests are
created only by the `wake_request` Tauri command (lib.rs:4369);
agent-originated wake entry depends on ADR-0021, which is Proposed and not
implemented. When this ADR gates those flows, the reason is not their origin
— it is UI automation: whatever a synthetic click can drive must release no
more than the agent already has.

There was also an existing gap, in three distinct layers. (a) Historically,
in an ANONYMIZED container, the desktop commands `vault_read_file`
(lib.rs:4014; gate only at :4040) and `vault_export_file` (:4140; gate at
:4151) returned or wrote PLAINTEXT without any consent, because
`desktop_consent_required` treated Anonymized as ungated (:2139) and the
desktop did not apply `sv-privacy`; the MCP path returns the same content
masked (crates/sv-mcp/src/lib.rs:1431-1460). (b) That specific gap is now
closed by PR #120, which added `desktop_consent_required_for` and put
ANONYMIZED reads and exports behind a desktop consent click. (c) What
remains for THIS ADR is the increment: presence in place of that click,
wherever the platform can attest it. Until (b) landed, driving the desktop
UI was worth more than the MCP channel — the opposite of the intended
design.

One workspace rule is deliberately broken here, and only here: first-party
crates forbid `unsafe` (crates/sv-mcp/src/lib.rs:18) — a thesis claim. The
Windows backend below needs FFI to the OS consent APIs, so this ADR declares a
narrow, written exception. Subproject A (biometric unlock) comes later and
reuses the trait defined here.

## Decision

1. **`sv-presence` crate.** A new first-party crate with an
   `Availability` enum (`Protected { modalities }` | `Unavailable(Reason)`)
   and a `PresenceVerifier` trait: `Send + Sync`, with
   `fn availability(&self) -> Availability` and
   `async fn verify(&self, op: &OpDescriptor) -> Result<Outcome,
   PresenceError>`. `PresenceError` is
   `Cancelled | Failed | Busy | Exhausted | DisabledByPolicy | NotConfigured
   | Unavailable | Timeout`. `Outcome` carries the modality actually used:
   `biometric | password | pin | unknown`.
2. **Backends, hybrid by design.** macOS: `robius-authentication` 0.3.1 as a
   dependency restricted to `target_os = "macos"`, using `LAPolicy`
   `DeviceOwnerAuthentication` (Touch ID or the Mac password) with a fresh
   `LAContext` per call. The adapter MUST wait for the final callback —
   `authenticate()` returning `Ok` means only that the prompt started — keep
   the involved objects alive until completion, treat prompt start-up errors
   as failures, a missing callback (deadline reached) as denial, and a late
   callback as discarded. Windows: a new first-party crate
   `crates/sv-presence-windows` over the `windows` crate the workspace already
   uses (0.61), calling `UserConsentVerifier::CheckAvailabilityAsync` and
   `IUserConsentVerifierInterop::RequestVerificationForWindowAsync` with a
   valid `HWND` of the Sovereign Vault window kept alive. The interop has a
   hard minimum: Windows Build 22000 (Windows 11 21H2) is the minimum
   supported client for `RequestVerificationForWindowAsync`; the UWP-only
   `UserConsentVerifier.RequestVerificationAsync` is not an option for a
   desktop Win32 app. `CheckAvailabilityAsync` exists since Windows 10
   (10.0.10240). In the `windows` 0.61 crate the interop method is an
   `unsafe fn` behind the `Win32_System_WinRT` feature, and
   `UserConsentVerifier` behind `Security_Credentials_UI`. Below Build 22000
   the backend reports `Unavailable` before any attempt — declared click,
   `protected: false`. Forbidden there:
   `GetDesktopWindow`, window search by title, synthetic keyboard input, and
   any own password fallback (`CredUIPromptForWindowsCredentialsW`,
   `LogonUserW`) — no password or PIN ever passes through this process. Only
   `UserConsentVerificationResult::Verified` approves;
   `DeviceNotPresent`, `NotConfiguredForUser`, `DisabledByPolicy`,
   `DeviceBusy`, `RetriesExhausted`, and `Canceled` map to distinct states.
   Linux: always `Unavailable` — no polkit, because a same-user process can
   register its own polkit agent and the available crate accepts cached or
   allow responses without a dialog.
3. **The `unsafe` exception.** `unsafe` is permitted ONLY inside
   `crates/sv-presence-windows`, kept minimal, with
   `#![deny(unsafe_op_in_unsafe_fn)]` and a SAFETY comment on every block.
   The exception is declared in this ADR and must be reflected in the
   workspace lint configuration; every other sv-* crate keeps the forbid.
4. **Insertion point.** The check lives in `ApprovalState::respond`. Denying
   a request never requires presence — only approving does.
5. **Audit.** Approval events gain a `presence` field:
   `protected: bool`, `outcome: device_owner_authenticated | click`, and
   `modality: biometric | password | pin | unknown`. The modality is never
   inferred from capability: Windows returns only `Verified`, so its modality
   is recorded as `unknown`.
6. **Per-request state machine.** Pending →(approve)→
   `Verifying(attempt_id, op_digest, deadline)` → Approved (the oneshot sends
   `true`), or back to Pending on `Cancelled | Failed | Busy | Exhausted`
   (the user may retry), or Expired/Denied on the 120 s deadline, a vault
   lock, an explicit refusal, or a disconnected caller — late callbacks are
   discarded. Pending →(deny)→ Denied, with no verification at all.
7. **Concurrency.** The Pending→Verifying transition happens under the mutex
   and the lock is released; `verify()` runs outside the lock; completion
   retakes the lock and approves only if the request is still in Verifying
   with the same `attempt_id`, the same `op_digest`, and a deadline that has
   not passed. A concurrent modal and tray row cannot start
   two verifications of the same request.
8. **Timeouts and the prompt slot.** The native prompt does not suspend the
   120 s approval window. Expiry, lock, refusal, or disconnection invalidate
   the attempt — denying or expiring the request — but they do not by
   themselves close the native prompt: the global queue slot stays occupied
   until the backend confirms the prompt's end (the final callback, or a
   native cancellation confirmed by the API). The queue does not advance
   before that confirmation; native cancellation is requested wherever the
   platform allows it.
9. **One native prompt at a time.** A bounded queue serializes native
   prompts: one active prompt plus at most 8 waiting requests; the attempt
   that would be the 9th waiting (the 10th concurrent while one prompt is
   active) is refused with a `queue_full` reason — a new UI state and error —
   and is DENIED to the agent rather than left pending. Deadlines keep
   running while queued; one authentication is good for exactly one request —
   never reused, never batched.
10. **No automatic fallback to click.** Whether a request is protected is
    FIXED when the request is created, from `availability()` BEFORE the
    attempt; the classification holds for every retry of that request.
    Click-only approval exists only where that initial check reported
    `Unavailable` (Linux, Windows below Build 22000, hardware with no
    verifier); those approvals record `protected: false` and the UI shows a
    permanent notice that approvals are not protected on this system. On a
    protected request, a `DisabledByPolicy`, `NotConfigured`, or
    `Unavailable` returned by `verify()` mid-attempt DENIES that request's
    approval — it never converts it into a click.
11. **Prompt text.** `op_digest` is a hash of the operation's immutable,
    complete description — request id, action, container, agent, and the
    operation's relevant parameters — computed in the backend. The attempt
    binds that description: a finished verification approves nothing except
    the operation it was started for. The native prompt's reason is derived
    from it: truncated names, control characters stripped, fields separated
    by fixed text. The webview renderer never supplies the verification
    result and never supplies the prompt text.
12. **Surfaces, including the ADR-0022 revision.** The modal approves by
    running `verify()` from the Sovereign Vault window. The TRAY changes:
    "approve" now OPENS THE MODAL for that request instead of deciding
    directly; "deny" remains direct. OTP containers reveal the code — it is
    sent in the event — only after a successful `verify()` bound to that
    request's `op_digest`. The authentication releases the REVELATION; the
    actual approval happens on the valid resend, and the code is accepted
    only while the request sits in its authenticated state for that
    `op_digest`, within the deadline, single-use. Where no protection is
    available the code appears as today, marked `protected: false`.
    `require_desktop_consent` keeps flowing through the same `respond()`, so
    desktop-originated actions are covered too. The ADR-0024 secret-entry
    commands (`submit_secret`, `submit_secret_direct`) do NOT flow through
    `respond()`; they are integrated explicitly: presence verification before
    the commit, through the same coordinator and queue, with an `op_digest`
    binding the container, the `env_var`, and the expected revision/generation
    — `protected: false` where no protection is available.
13. **Verification.** A fake `PresenceVerifier` makes the property testable
    without hardware. The central test: `approval_respond(id, true)` with no
    successful `verify()` does NOT approve when the request is protected; a
    callback after the deadline does not approve; refusal, lock, or
    disconnection during Verifying invalidates the attempt; concurrent
    modal+tray responses produce one verification; an authentication does not
    carry to the next request; a cancelled or failed verification never falls
    back to click. OTP: the code is not sent before `verify()`; a CORRECT
    code submitted before the verify is rejected, as are a missing code and a
    wrong one; an automated resend without the revelation fails. Tray approve
    opens the modal and does not approve on its own. The robius adapter treats
    start-up `Ok` as not-success and a missing callback as denial; Windows
    maps every `UserConsentVerificationResult` and only `Verified` approves.
    Further cases: queue saturation — one prompt active and 8 waiting, the
    next waiting attempt (the 10th concurrent) denied with `queue_full`; `availability()` flipping to unavailable during a protected
    attempt denies that attempt and never converts it into a click; a native
    cancellation that cannot be confirmed keeps the queue slot occupied; a
    real UI-automation pass (AppleScript/Accessibility on macOS, UI
    Automation on Windows) against a protected platform completes no
    approval — with the declaration that the fake verifier covers the
    coordinator's logic, not the resistance of the OS prompt itself, which
    only the platform-level automation runs exercise.
14. **Desktop command gates.** The guarantee extends beyond request
    approvals: on operations classified `protected: true`, driving the
    Sovereign Vault UI with synthetic input releases nothing the agent would
    not already get through MCP, and unlocks nothing. The same coordinator
    gates the app's own privileged commands, each through its distinct
    integration point. Every gated desktop operation becomes a pending
    operation with its own identifier, its own deadline, and a `protected`
    classification that is IMMUTABLE until a terminal state — retries do not
    re-run `availability()`, the same rule as MCP requests. A mid-attempt
    failure never falls back; where `availability()` is `Unavailable` BEFORE
    the attempt the command takes the declared consent click —
    `protected: false`, never ungated. Two assumptions bound the guarantee:
    a declared-click gate remains automatable and offers NO guarantee against
    synthetic input — MCP parity holds only for the DIRECT exception (see the
    mode table below; on ANONYMIZED a synthetic click through a declared
    click would still release plaintext the MCP path masks) — and the
    passphrase/recovery unlock paths assume the agent does not know the
    credential (keylogging is out of scope). Every container mode is covered
    explicitly: DIRECT reads and exports are DECLARED UNGATED (author
    decision, anchored on threat-model §3.B: any same-user process can fetch
    the pairing secret at /.well-known/mcp-pairing and pair as the unscoped
    Default agent, reading DIRECT content through MCP, so a desktop read
    yields no gain; if §3.B ever changes, this point must be revisited);
    ANONYMIZED reads and exports take the presence gate over the PR #120
    click; APPROVAL/OTP route through `require_desktop_consent` → `respond`
    → presence; ZKP/NATIVE fail closed. Gated:
    - `vault_read_file` and `vault_export_file` on ANONYMIZED containers:
      presence required, replacing the consent click PR #120 added
      (`desktop_consent_required_for`); on systems without presence that
      click remains. `op_digest`: container, file name, operation
      (read | export), export destination.
    - `remediate_restore`: `op_digest` = plan id or snapshot ref, relative
      file path, snapshot digest.
    - `remediate_execute`: `op_digest` = plan id, snapshot digest, relative
      path, manifest path, adapter. The existing `confirm_digest` comes from
      `remediate_plan_list` (the same channel) and proves nothing about
      presence.
    - `wake_respond`, only when approving: `op_digest` = wake id, signature,
      agent id, session id. `wake_prepare_access` carries a derived
      authorization, not its own gate: the backend must validate the CURRENT
      wake authorization (`has_authorized_wake`), bound to the request
      signature, the agent, the session, and the operation. Tests: a direct
      call with no approval, an expired authorization, and a session or
      scope switch are all refused.
    - `agent_create`: `op_digest` = agent name and requested scopes; the
      token is returned only after presence.
    - `vault_rotate_key`: `op_digest` = active DEK version; the new recovery
      phrase is returned only after presence.
    - `scan_reveal`: `op_digest` = report id and finding id.
    - `vault_unlock` with OsKeychain custody: `op_digest` = vault identifier
      plus "unlock". This is the one operation whose verification may START
      from the locked state; the attempt is invalidated by any vault-state
      change (another unlock completing, a lock), and the vault's identity
      and custody are revalidated before the KEK is read from the keychain.
      Relation to subproject A: presence here is an OS boolean checked
      before that read; A remains hardware-key unlock.
    - `vault_init` (author decision): gated where presence exists;
      `op_digest` = vault root plus "init"; the first recovery phrase is
      returned only after authentication; without presence, declared click.
    Declared ungated, with reasons: `vault_unlock` by passphrase and
    `vault_unlock_recovery` (they depend on knowledge the agent lacks;
    keylogging is out of scope); `vault_list_files` (names, sizes, dates —
    metadata); `mcp_status` (the pairing secret is already public through
    /.well-known/mcp-pairing, threat-model §3.B). `vault_init` is NOT on
    this list: it is gated (above). Mutating commands verify presence BEFORE
    any mutation — `agent_create`, `vault_rotate_key`, `vault_init`,
    `remediate_execute`, and `remediate_restore` — and a refusal must leave
    observable state unchanged, not merely omit a secret from the response:
    no agent created, DEK unchanged, no vault created, project not
    rewritten. Tests: (a) a source-scan test in the pattern of
    `every_mutating_desktop_command_enforces_mode` compares the COMPLETE
    Tauri command registry (`invoke_handler`) against a mandatory
    per-command classification — own gate | derived authorization |
    justified exception — and a new command without a classification fails
    the test; beyond the textual scan, the gated paths have executable
    tests; (b) per command, without a successful verify nothing is released
    and nothing is mutated — an ANONYMIZED read or export returns no
    plaintext, restore writes nothing, execute ingests nothing, wake
    authorizes nothing, agent_create creates no agent, rotate changes no
    DEK and returns no phrase, scan_reveal reveals nothing, keychain unlock
    does not unlock, init creates no vault; (c) on a system without
    presence, an ANONYMIZED read or export requires the consent click; (d)
    per-gate caveats: a success that arrives after the deadline or after a
    lock produces no effect, a parameter change during the prompt (a
    different `op_digest`) denies the attempt, and unavailability between
    classification and execution denies it.

## Consequences

- **Positive.** On a protected request (`protected: true`), a same-user agent
  can no longer approve it: the surfaces it can drive (synthetic clicks, tray
  menus) no longer decide anything, and the code it could read (OTP) is
  revealed only after the OS attested presence to the Sovereign Vault process.
  The same coordinator covers every approval surface through distinct
  integration points — `respond()` for approvals (modal, revised tray,
  desktop-originated consent) and the explicitly wired ADR-0024 secret-entry
  commands (`submit_secret`, `submit_secret_direct`). The
  guarantee is per protected request — it is not a blanket claim about macOS
  or Windows, and it does not extend to unprotected (`click`) approvals.
- **Positive.** The desktop's own command surface is covered (item 14):
  on operations classified `protected: true`, synthetic input to the
  Sovereign Vault window no longer yields plaintext
  ANONYMIZED content, key rotation phrases, agent tokens, wake authorizations,
  revealed scan findings, or an unlocked keychain-custody vault. The historical
  gap where desktop ANONYMIZED reads and exports bypassed the masking the MCP
  path applies was closed by PR #120's consent click, and this ADR replaces
  that click with presence where the platform can attest it; every gated
   command records `presence` in the audit like approvals do. As with
   approvals, the guarantee covers only `protected: true` operations: a
   declared-click gate remains automatable and offers no guarantee against
   synthetic input (MCP parity holds only for the DIRECT exception, item 14),
   and the passphrase and recovery unlock paths rest on the
   credential-knowledge assumption.
- **Positive (research).** The audit gains a countable signal: approvals
  split into `device_owner_authenticated` and `click` (unprotected), with the
  modality where the OS reports it. The share of protected approvals is a
  measurable property of each platform instead of an assumption.
- **Negative.** Linux ships with approvals unprotected, declared; Windows
  below Build 22000 is declared click; on Windows the
  modality is always `unknown`, so the audit cannot distinguish fingerprint
  from PIN there. The gated surface also grows: roughly ten desktop commands
   need their own `op_digest` binding and their own release tests, and the
   consent click PR #120 introduced for ANONYMIZED desktop reads and exports
   remains the gate on systems without presence — a real usability cost
   there — while this amendment's increment is presence verification on
   protected systems.
- **Negative.** The `unsafe`-forbidden claim now holds "except
  sv-presence-windows". That weakens a stated property of the artifact and
  must not be described as workspace-wide anymore.
- **Negative.** Dependency risks, registered: robius has a single
  maintainer; `android-build` is an unconditional build dependency of robius
  0.3.1, and restricting the robius dependency to the macOS target does NOT
  remove it when compiling on macOS — a residual supply-chain cost, neither
  eliminated nor unknown; robius's `windows` 0.56 requirement does not enter
  the tree because robius is macOS-only here.
- **Mitigation.** The `unsafe` surface is confined to one crate with
  `#![deny(unsafe_op_in_unsafe_fn)]` and per-block SAFETY comments; denial
   never requires presence, so the check cannot be used to lock the user out;
   no failed verification falls back to click; every authentication is bound
   to one request, one `op_digest`, and one deadline; the OTP revelation gate
   protects the cross-channel check rather than replacing it.
- **Thesis.** Nothing in docs/thesis/ is altered by this ADR: the evaluation
  harness measures a simulated policy and does not touch the real UI. The
  passages affected once this lands are listed for the author's decision:
  docs/thesis/TRACEABILITY.md:34 and :46, docs/thesis/paper.tex:353, :448,
  :456, and :780, and the unsafe claim (AGENTS.md; crates/sv-mcp/src/lib.rs:18).
  Listed additionally for the author's awareness, in three layers: (a) the
  evaluated artifact's desktop path in ANONYMIZED containers returned
  plaintext — a gap of the artifact's desktop layer, not of the evaluated
  MCP gateway, which masks; (b) PR #120 closed that gap with a consent click
  (`desktop_consent_required_for`); (c) this ADR's increment is presence in
  place of that click wherever the platform can attest it.

## Alternatives considered

- **robius-authentication on every platform.** Rejected: on Windows it
  requires the `windows` crate 0.56, incompatible with the 0.61 the workspace
  already uses (a duplicate in the supply chain), and 0.3.1 pulls
  `android-build` as an unconditional build dependency on every platform; on
  Linux it is polkit-based, rejected for the reason below. Restricting it to
  the macOS target keeps the objc2 versions the workspace already has and
  keeps the `windows` 0.56 pin out of the tree, but it does NOT remove the
  `android-build` build dependency when compiling on macOS — that residual
  cost is accepted and recorded under Consequences.
- **polkit on Linux.** Rejected: a same-user process can register its own
  polkit authentication agent, and the available crate accepts cached or
  allow authorizations without showing a dialog — it would attest nothing
  about who is at the machine.
- **An own Windows password fallback** (`CredUIPromptForWindowsCredentialsW`
  / `LogonUserW`). Rejected: it would route a password or PIN through the
  Sovereign Vault process, creating exactly the secret-handling surface the
  vault exists to avoid. No password fallback exists; only the OS verifier
  sees the credential.
- **`GetDesktopWindow` plus synthetic keyboard input.** Rejected: a prompt
  attached to the wrong window and synthetic input are the attack this ADR
  exists to prevent, not an implementation shortcut. Only a valid `HWND` of
  the Sovereign Vault window is used, kept alive for the call.
- **The tray approving without a window** (today's behavior, ADR-0022).
  Rejected going forward: a tray row that decides with no window cannot host
  a native presence prompt, so it would remain a synthetic-click target.
  Approve now opens the modal; deny stays direct.
- **Showing the OTP before authentication.** Rejected: the code shown on
  screen is readable by the same-user process the check is meant to stop;
  revealing it only after a successful `verify()` is what keeps the
  cross-channel check meaningful.
- **Cryptographic proof with a hardware key** (challenge signed by a security
  key / platform key). Deferred: out of scope here, re-examined alongside
  subproject A once the `PresenceVerifier` trait exists; it would strengthen
  attestation but does not change the approval flow this ADR specifies.

## References

- [ADR-0013](0013-sensitivity-classifier-adaptive-consent.md): the consent
  policy; this ADR adds a presence check beneath the existing click tier. It
  does not change the MCP consent tiers; the one desktop-side addition — a
  consent click for ANONYMIZED reads and exports where presence is
  unavailable — is recorded in item 14.
- [ADR-0014](0014-os-notifications-for-consent-prompts.md): the 120 s
  approval window and OS notification, which the native prompt must not
  suspend and which queues behind it.
- [ADR-0022](0022-tray-approval-menu.md): revised here — tray Approve opens
  the modal instead of deciding from the menu; Deny remains direct, and the
  tray's action-class-only display rule is unchanged.
- [ADR-0024](0024-agent-requested-secret-entry.md): the most recent extension
  of the approval flow; the same modal path, error-text conventions, and
  declared-limits style are reused here. Its secret-entry commands
  (`submit_secret`, `submit_secret_direct`) require presence verification
  before the commit — integrated explicitly, not through `respond()`.
- `docs/threat-model.md` §3.A–B: the same-user boundary this ADR narrows in
  practice — the new guarantee and the declared limits (Linux, Windows below
  Build 22000, `unknown` modality) are to be recorded there, including a new
  §3 row: an agent driving the Sovereign Vault desktop UI with synthetic
  input to obtain data or authority beyond MCP — Yes for the gated commands
  of item 14 on a protected system, with the declared limits otherwise.
