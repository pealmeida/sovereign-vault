# Presence-verified approvals: OS-attested human presence on every approve

- **Status:** Approved (ADR-0025 Proposed)
- **Date:** 2026-09-28
- **Decision record:** [ADR-0025](../../adr/0025-presence-verified-approvals.md)
- **Scope:** MVP

## 1. Problem

Today an approval proves that *a click happened*, not that *a human clicked*.
The desktop gate for **MCP request approvals** is a single decision point —
`ApprovalState::respond` (`apps/desktop/src-tauri/src/lib.rs:674`), which
removes the pending request under a mutex and sends a bool over a oneshot —
and every approval surface routes through it: the modal (`request_click`,
`lib.rs:580-672`, 120 s `APPROVAL_TIMEOUT_SECS`, `lib.rs:75`), the Tauri
command `approval_respond` (`lib.rs:4355`), the tray (`respond_from_tray`,
`lib.rs:1779-1832`, which approves **without opening a window**, ADR-0022),
and the consent checks `require_desktop_consent` (`lib.rs:2147-2179`) and
`request_click_only` (`lib.rs:551-560`). `respond` is the gate for
**approvals of MCP requests** — not for every human action: wake requests
are created only by the Tauri command `wake_request` (`lib.rs:4369`; the
agent-facing entry point is ADR-0021, Proposed and not implemented), and the
remediation chain is 100 % human-originated (`scan_run` → `remediate_plan_file`).
Those flows are gated later anyway (§7.5) — the reason is **UI automation**,
not request provenance. Tauri commands are only invocable by the webview,
but a process running as the same OS user can drive the webview with UI
automation. The OTP flow has the same shape: the code is generated
(`generate_otp_code`, `lib.rs:295-299`) and placed in the event
(`ApprovalPrompt.otp_code`, `lib.rs:517-526`, `handle_otp_fresh`
`lib.rs:486-538`), so an agent that can read the screen can read the code and
resend it (`handle_otp`, `lib.rs:356-483`; `process_otp_request`,
`lib.rs:224-275`; TTL 120 s).

An `ANONYMIZED` gap is in scope because it is the same synthetic-input
attack, and its baseline must be stated precisely in three parts. (a) In
the **evaluated artifact**, `vault_read_file` (`lib.rs:4014`) and
`vault_export_file` (`lib.rs:4140`) returned or wrote **cleartext with no
consent**: `desktop_consent_required` treated `Anonymized` as ungated
(`lib.rs:2139`) and the desktop never applied `sv-privacy`, while MCP masked
the same read (`sv-mcp/src/lib.rs:1431-1460`). (b) **PR #120 already fixed
that** by requiring the ordinary consent click for read-type actions in
`Anonymized` (`desktop_consent_required_for`, covering `ReadFile`) — both
commands take their consent gate as `AccessAction::ReadFile`, so the click
now applies to export too. (c) **This ADR's increment**: on top of that
baseline, replace the click with a presence verification where the system
supports it (§7.5), keeping the click as the declared path where it does
not.

The current threat model treats the same OS user as trusted and agents as
untrusted; memory scraping, ptrace and keylogging are out of scope. This
feature closes one specific gap inside that model: an agent running with the
user's own privileges must not be able to approve its own protected request
— neither with a synthetic click nor with a screen-scraped OTP. The
guarantee is then widened past approvals, which `respond` gates (§7.4 covers
the ADR-0024 submits, wired into the coordinator separately): **driving the
Sovereign Vault desktop UI with synthetic input must not release anything
beyond what the same agent could obtain over MCP, and must not unlock the
vault — for every operation classified `protected: true`**. The guarantee
is claimed per protected operation, not absolutely: on a declared system
the click itself remains automatable (§6.2), and the passphrase/recovery
unlock exceptions assume the agent does not know the credential
(keylogging stays an out-of-scope non-goal). Every data- or
authority-releasing command goes through the same presence coordinator
(§7.5).

**Subproject A** (biometric vault unlock) comes later and reuses the same
`PresenceVerifier` trait. This spec is **subproject B**: presence on
approvals.

## 2. Goals and success criteria

**Goals**

1. On every **protected request** (`protected: true`, classified when the
   request is created — §6.2), every **approve** passes an OS-native prompt
   that only the device owner can satisfy: biometric, or a password/PIN
   typed into the OS security subsystem — never into this application's
   process. Requests classified unprotected at creation take the declared-
   click path (§6.2); the anti-self-approval guarantee is claimed per
   protected request, not generically per platform.
2. **Refuse** stays immediate and needs no presence: declining must never be
   made harder than approving.
3. The OTP code is revealed to the agent's channel only after a presence
   verification tied to that request succeeded — and a resent code only
   approves a request that is in that authenticated state (§7.3).
4. The audit distinguishes presence-protected from unprotected approvals;
   no silent degradation.
5. Where no trustworthy mechanism exists (Linux; Windows below the Hello
   interop minimum), the app says so permanently and visibly.

**Success criteria**

- The central adversarial test (§9.2): `approval_respond(id, true)` with no
  completed verification does **not** approve a request classified
  `protected: true`.
- A synthetic click from a same-user process can open windows and press
  buttons; it cannot complete the OS prompt, so it cannot approve a
  protected request.
- The OTP never appears in the event stream before a successful verify bound
  to that request; a correct code resent before that verify is also rejected
  (§9.2); automated resend without a code fails exactly as a wrong code
  does.
- Tray "Approve" opens the request modal and never approves by itself.
- Unprotected approvals exist only where `availability()` reported
  `Unavailable` **when the request was created** — the classification is
  fixed for that request through every retry — are audited with
  `protected: false`, and the UI carries a permanent notice.

## 3. Threat model for this feature

| Vector | Covered | How |
|---|---|---|
| Synthetic click (UI automation / accessibility) approving an agent's own request | Yes — for protected requests (`protected: true`, classified at creation) | The approve transition only commits after `PresenceVerifier::verify` succeeds at `ApprovalState::respond` (§6) |
| Agent drives the SV desktop UI with synthetic input to obtain data or authority beyond MCP (reads, exports, restores, tokens, recovery phrases, wake approvals, unlocks) | Yes — for every gated command on a protected system (§7.5) | The same presence coordinator gates each listed command at its own integration point; the declared exceptions and their reasons are listed in §7.5 (passphrase/recovery unlock, DIRECT reads/exports per threat-model §3.B, list metadata, pairing secret) |
| Agent reads the OTP from screen/IPC and resends it | Yes — for protected requests | The code is revealed only after a successful verify bound to that request, and a resent code is accepted only while the request is in that authenticated state, in deadline, single-use (§7.3) |
| Tray approval without a window | Yes | Tray "Approve" opens the request modal instead of responding (revision of ADR-0022, §7.2); tray "Refuse" stays direct |
| Late or spoofed verification result | Yes | Attempt state machine: the finisher re-checks `Verifying` + `attempt_id` + `op_digest` + deadline under the lock; a late callback is discarded (§6) |
| One authentication reused across requests or batch-approved | Yes | One verify per request; nothing is cached or carried to the next (§6) |
| Password/PIN interception by this application | Yes | No path passes a secret through the process: macOS runs inside LocalAuthentication, Windows Hello never falls back to credential UI we drive (§5) |
| polkit agent registered by another same-user process answering prompts (Linux) | **No — Linux is declared unprotected** | Linux backend always reports `Unavailable`; approvals take the declared-click path (§5.3) |
| No enrolled biometric / Hello disabled by policy | Declared | The classification is made when the request is created: `availability() == Unavailable` → declared-click path with permanent notice, no prompt attempted (§6.2). A `DisabledByPolicy` / `NotConfigured` / `Unavailable` returned by `verify()` mid-attempt **denies** that request — it never degrades to a click (§9.1) |
| Same-user memory scraping, ptrace, keylogging | **No (declared)** | Existing non-goals of `docs/threat-model.md`; unchanged here |
| Fully-compromised account | **No (declared)** | Outside this feature; consistent with threat model §3.B. Note the scope line on locked vaults: "locked" as a general state stays outside, but the locked→unlocked **transition** through keychain custody is now in scope and gated (§7.5 item 9); the knowledge-gated unlock paths (passphrase, recovery phrase) remain declared exceptions |

Refusing is always available without presence: the gate constrains approval
only.

## 4. Component: `sv-presence`

New crate `crates/sv-presence`. Public shape:

```rust
pub enum Availability {
    Protected { modalities: Vec<Modality> },
    Unavailable(Reason),
}

pub enum Modality {
    Biometric,
    Password,
    Pin,
    Unknown,
}

pub trait PresenceVerifier: Send + Sync {
    fn availability(&self) -> Availability;
    async fn verify(&self, op: &OpDescriptor) -> Result<Outcome, PresenceError>;
}

pub enum PresenceError {
    Cancelled,
    Failed,
    Busy,
    Exhausted,
    DisabledByPolicy,
    NotConfigured,
    Unavailable,
    Timeout,
}

pub struct Outcome {
    pub modality: Modality, // Biometric | Password | Pin | Unknown
}
```

- The trait is the seam reused later by subproject A (biometric unlock).
- `OpDescriptor` carries what is being approved (§6, `op_digest`) and the
  derived prompt text.
- **Insertion point:** `ApprovalState::respond`. Refuse does not require
  presence. Every existing **approval** surface already funnels through this
  point (§1), so they share one gate — not one per window. The ADR-0024
  secret-entry submits (`submit_secret`, `submit_secret_direct`) do **not**
  route through `respond`: they are wired into the same coordinator
  explicitly (§7.4).
- `sv-presence` itself forbids `unsafe` like the rest of the workspace. The
  one exception is `sv-presence-windows` (§5.2), declared in ADR-0025 and
  in the thesis-impact list (§12).

## 5. Platform backends (hybrid)

### 5.1 macOS — robius-authentication

- Dependency `robius-authentication 0.3.1`, restricted in `Cargo.toml` to
  `target_os = "macos"`.
- Policy `DeviceOwnerAuthentication`: Touch ID **or the Mac login password**;
  a fresh `LAContext` per call (reuse can let a past success skip the
  prompt).
- The adapter **must** treat `authenticate()`'s `Ok(())` as "prompt started",
  never as authentication success — the library's own contract is that the
  result arrives on the completion callback. The adapter therefore:
  keeps the context and callback alive until completion; maps a start error
  to a denial; maps a missing callback (the request deadline passed with no
  result) to `Timeout` → denial; discards a late callback (§6 rules).
- The password typed under this policy goes through the LocalAuthentication
  framework, not through this process.

### 5.2 Windows — `sv-presence-windows` (new, own crate)

- Built directly on the `windows` crate already used in the workspace
  (0.61). No third-party biometric dependency.
- Flow: `UserConsentVerifier::CheckAvailabilityAsync`, then
  `IUserConsentVerifierInterop::RequestVerificationForWindowAsync` with the
  **HWND of a real, kept-alive Sovereign Vault window**.
- **Forbidden**, by ADR-0025, on this platform: `GetDesktopWindow` as the
  prompt owner; finding the prompt window by title/class; synthetic keyboard
  injection; and the credential-UI password fallback
  (`CredUIPromptForWindowsCredentialsW` / `LogonUserW`) — no password or PIN
  ever passes through this process.
- Only `UserConsentVerificationResult::Verified` approves.
  `DeviceNotPresent`, `NotConfiguredForUser`, `DisabledByPolicy`,
  `DeviceBusy`, `RetriesExhausted`, `Canceled` map to distinct
  `PresenceError` states (§9.1). Hello PIN counts as a valid verification;
  its modality is recorded as `unknown` (§8).
- `unsafe` is allowed **only in this crate**, kept minimal, under
  `#![deny(unsafe_op_in_unsafe_fn)]`, with a `// SAFETY:` comment on every
  block. The exception is declared in ADR-0025 — the workspace rule
  (thesis: no `unsafe` in own crates, `crates/sv-mcp/src/lib.rs:18`) is an
  author decision to reconcile (§12).
- Minimum Windows build, resolved: `IUserConsentVerifierInterop::
  RequestVerificationForWindowAsync` requires Windows Build 22000 (Windows 11
  21H2) as its minimum supported client (Microsoft Learn,
  `userconsentverifierinterop`). `UserConsentVerifier.RequestVerificationAsync`
  is UWP-only, so a desktop Win32 app must go through the interop with an
  HWND; `CheckAvailabilityAsync` exists since Windows 10 (10.0.10240). In the
  `windows` 0.61 crate the interop method is an `unsafe fn` behind the
  `Win32_System_WinRT` feature, and `UserConsentVerifier` behind
  `Security_Credentials_UI`. Below Build 22000, `availability()` reports
  `Unavailable` — declared click, `protected: false` — detected BEFORE any
  attempt (§6.2).

### 5.3 Linux — always `Unavailable`

- No polkit. Reasons, recorded in ADR-0025: a same-user process can register
  its own polkit authentication agent and answer prompts, and a
  `CheckAuthorization` success may come from policy defaults (`allow_*=yes`)
  or cached `auth_admin_keep` grants **without any dialogue**. Both defeat
  the whole point of the feature.
- Linux takes the declared-click path everywhere (§6): approvals work as
  today, are audited `protected: false`, and the UI shows the permanent
  notice. "Any presence on Linux" is out of scope (§10).

## 6. Flow, states, and errors

### 6.1 Per-request state machine

```
Pending --(Approve)--> Verifying { attempt_id, op_digest, deadline }
                          |
        Verified --------> Approved   (oneshot true; for OTP requests:
                                       reveal only — approval happens on
                                       the valid resend, §7.3)
        Cancelled/Failed/B
        sy/Exhausted ----> Pending    (retry allowed, same request)
        DisabledByPolicy/
        NotConfigured/
        Unavailable -----> Denied     (mid-attempt: deny, never click; §6.2)
        deadline / vault   Locked /
        lock / refuse /    agent disconnect
        disconnect -------> Expired / Denied   (late callback discarded)
Pending --(Refuse)--> Denied          (no verification at all)
```

- `Pending → Verifying` happens under the approval mutex, then the lock is
  **released**; `verify()` runs outside the lock. The finisher re-acquires it
  and commits **only if** the request is in `Verifying`, the `attempt_id`
  matches, the stored `op_digest` equals the one the verification was granted
  for (§6.3), and the deadline has not passed. A modal and the tray acting
  concurrently cannot start two verifications of the same request.
- The native prompt does **not** pause the 120 s clock: expiry, vault lock,
  user refusal, or disconnect invalidate the attempt, and the adapter
  requests native cancellation when the platform supports it.
- **One native prompt at a time**, behind a bounded queue: one active
  prompt plus at most **8** requests waiting. The attempt that would be the
  9th waiting (the 10th concurrent while a prompt is active) is refused with
  a `queue_full` reason — a new UI state and error — and is **denied to the
  agent**, not left pending. Queued requests keep running against the 120 s
  deadline.
- Invalidating an attempt does **not** close the OS prompt: the global
  prompt slot stays occupied until the backend confirms the prompt ended —
  the final callback arrived, or a native cancellation was confirmed. The
  queue does not advance before that confirmation; an expired or cancelled
  request may therefore hold the slot while its late result is discarded
  (§6.1 finisher rules). Where the platform cannot cancel and never calls
  back, the prompt keeps its slot until the platform itself terminates it.
- One verification satisfies exactly one request. Nothing is cached,
  remembered, or applied in batch; the next request prompts again.

### 6.2 Degradation is never automatic

- The `protected` classification is decided **when the request is created**
  — one `availability()` call before any attempt — and is fixed for that
  request through every retry: a request born protected never becomes a
  click request, and one born unprotected never silently becomes protected.
- Click-only approval exists **only** for requests classified at creation as
  `Unavailable`: Linux, Windows below Build 22000 (§5.2), hardware with
  nothing enrolled or available.
- Those approvals are audited `protected: false` and the UI carries a
  permanent notice: "unprotected approvals on this system".
- A `Cancelled`, `Failed`, `Busy`, or `Exhausted` result keeps the request
  `Pending` with the reason shown in the UI. A `DisabledByPolicy`,
  `NotConfigured`, or `Unavailable` returned by `verify()` **mid-attempt**
  — the mechanism disappeared after classification — **denies that
  request** outright. Neither class ever degrades to a bare click.

### 6.3 The prompt text is backend-derived; the digest is the contract

- `op_digest` is the hash of a **complete, immutable description** of the
  operation fixed at `Pending → Verifying`: request id, action, container,
  agent, and the relevant parameters (for a file action, the file name; for
  an ADR-0024 submit, container, `env_var`, and the expected
  `revision`/generation — §7.4). It is computed in the **backend**; the
  native prompt's reason string is derived from it: truncated names, control
  characters stripped, field content separated from fixed text.
- Finalization compares the digest stored in the attempt with the one the
  verification was granted for: a result can never approve a request whose
  description moved (modal reopened with different fields, request recycled
  under a new id). This is the §6.1 commit condition.
- The renderer never supplies the verification outcome, and never supplies
  the prompt text.

## 7. Surfaces

### 7.1 Modal

The "Approve" button triggers `verify` from the vault window
(macOS: LocalAuthentication; Windows: Hello bound to this window's HWND,
§5.2). Refuse stays immediate.

### 7.2 Tray (revision of ADR-0022)

- "Approve" **opens the request's modal** instead of responding; the tray
  alone can never approve.
- "Refuse" remains a direct action (no presence required to decline).
- The ADR-0025 record states this revision explicitly.

### 7.3 OTP flow — reveal and approval are two events

- Successful `verify` unlocks **reveal only**: the code (`generate_otp_code`)
  is placed in the event (`ApprovalPrompt.otp_code`) and the request enters
  the authenticated state for that request/op. The approval itself still
  happens on the agent's **resend**, not on the verify.
- The resend accepts the code only if **all three** hold: the request is in
  the authenticated state produced by a successful verify bound to the same
  `op_digest` (§6.3); the attempt deadline / TTL has not passed; and the
  code has not been used — consumption is single-use, and any state change
  of the underlying request (new description, retry, lock) clears the
  authenticated state and the revealed code.
- Consequences for the attack the flow is meant to stop: a code scraped
  from the screen before reveal does not exist yet; a correct code sent
  **before** the verify is rejected exactly like a wrong one; a code for
  request A never authorizes request B (the digest binds it).
- Where no presence mechanism is available, the flow appears as today,
  marked `protected: false`.
- The resend plumbing (`handle_otp`, `process_otp_request`) and the 120 s
  TTL are otherwise unchanged.

### 7.4 Programmatic paths

- `require_desktop_consent` and `request_click_only` pass through the same
  `ApprovalState::respond` and are therefore gated identically.
- **Exception, wired explicitly:** the ADR-0024 secret-entry submits
  (`submit_secret`, `submit_secret_direct`) do not create approval requests
  and do not route through `respond`. Before committing the write they call
  the **same presence coordinator**, with the **same native-prompt queue**
  (§6.1) and the same `op_digest` rules (§6.3): the description binds
  container, `env_var`, and the expected `revision`/`expected_generation`.
  Verification failure or mid-attempt unavailability denies the submit;
  there is no click fallback. Where the platform is classified `Unavailable`
  at submit time, the submit proceeds `protected: false`, audited and
  noticed like an unprotected approval.

### 7.5 Desktop command gates (extension)

The widened guarantee (§1) — **for every operation classified `protected: true`**:
synthetic input driving the UI must release nothing beyond the MCP channel
and must not unlock the vault. These commands are gated by the **same
presence coordinator**, each at its own integration point. Every gated
desktop operation becomes a **pending operation** with its own identifier,
its own deadline, and a `protected` classification that is **immutable until
a terminal state**: the classification comes from one `availability()` call
when the operation is created, retries do **not** re-run it — the same rule
as MCP requests (§6.2) — and there is no fallback during the attempt (§6.2
applies verbatim: mid-attempt `DisabledByPolicy` / `NotConfigured` /
`Unavailable` denies the operation).
Where `availability()` already reported `Unavailable` **before** the
attempt, the operation degrades to **declared consent-click** — never to
"no gate" — with `protected: false` audited and the permanent notice. The
prompt text and digest rules of §6.3 apply to every entry below.

Every container mode is covered explicitly: **DIRECT** reads and exports are
**declared ungated** — author decision, anchored on threat-model §3.B: any
same-user process can fetch the pairing secret at `/.well-known/mcp-pairing`
and pair as the unscoped Default agent, reading DIRECT content through MCP,
so a desktop read yields no gain for the agent beyond that capability, and
it is against exactly that capability that the "nothing beyond MCP"
guarantee is measured; if §3.B ever changes, this point must be revisited.
**ANONYMIZED** reads and exports take the presence gate over the PR #120
consent click (item 2). **APPROVAL/OTP** reads and exports already route
through `require_desktop_consent` → `respond` → presence (§7.4).
**ZKP/NATIVE** fail closed: nothing is released for those modes.

Gated commands:

1. `approval_respond` and the tray approve path (§§6–7.2) — the base
   surface of this spec.
2. `vault_read_file` and `vault_export_file` in **ANONYMIZED** mode: presence
   is required before cleartext leaves to the renderer or to disk. The
   baseline separates three layers (§1): (a) historically the desktop
   returned or wrote cleartext with no consent (`lib.rs:2139` treated
   `Anonymized` as ungated and the desktop never masked, while MCP masked via
   sv-privacy, `sv-mcp/src/lib.rs:1431-1460`); (b) **PR #120** already put
   these reads and exports behind the consent click
   (`desktop_consent_required_for`, covering `ReadFile`); (c) this gate's
   increment replaces **that click** with presence. On systems without
   presence the click remains (`protected: false`, never ungated).
   `op_digest`: container, file_name, operation
   (`read` | `export`), export destination.
3. `remediate_restore`: writes snapshot plaintext back to disk.
   `op_digest`: plan id or snapshot ref, file relative path,
   `snapshot_digest`.
4. `remediate_execute`: ingests the secret and rewrites the project file.
   `op_digest`: plan id, `snapshot_digest`, file relative path,
   manifest path, adapter. Its `confirm_digest` is **not** a presence
   proof — the same webview channel that calls `remediate_execute` can read
   the digest from `remediate_plan_list` (`lib.rs:3420`); the digest only
   binds which plan runs.
5. `wake_respond`, **only when approving** (refusing stays free):
   `op_digest`: wake request id, signature, agent_id, session id. Today
   wakes can only be created by the Tauri `wake_request` command
    (`lib.rs:4369`); the agent-facing entry is ADR-0021 (Proposed, not
    implemented) — when it lands, this gate already covers it.
    `wake_prepare_access` carries a **derived authorization**, not its own
    gate: the backend must validate the **current** wake authorization
    (`has_authorized_wake`), bound to the request signature, the agent, the
    session, and the operation. A direct call with no approval, an expired
    authorization, and a session or scope switch are all refused (§9.2).
6. `agent_create`: mints a live agent credential. `op_digest`: requested
   agent name and scopes. The token (`lib.rs:4555-4558`) is returned to the
   renderer **only after** a successful verification.
7. `vault_rotate_key`: `op_digest`: the active DEK version. The new recovery
   phrase is returned only after a successful verification.
8. `scan_reveal`: `op_digest`: report id and finding index. On a protected
   system the 4-character preview is released only after verification; on a
   declared system, after the consent click.
9. `vault_unlock` with **OsKeychain custody**: `op_digest`: vault identifier
   plus the literal `unlock`. Presence here is a bare OS boolean asked
   before the KEK is read from the keychain; it is **not** subproject A.
   Subproject A remains key-held biometric unlock (wrapping custody material
   behind the `PresenceVerifier` seam, §4); this gate only stops a synthetic
   click from turning an auto-unlock keychain into a passwordless master
   switch. This is the one operation whose verification may **start from the
   locked state**: the initial locked state is permitted, the attempt is
   invalidated by any vault-state change (another unlock completing, a lock),
   and the vault's identity and custody are revalidated before the KEK is
   read from the keychain.
10. `vault_init` (author decision): gated where presence exists.
    `op_digest`: the vault root plus the literal `init`. The vault is
    created only after verification, and the first recovery phrase is
    returned **only after** a successful authentication; without presence
    the operation takes the declared consent click.

Mutating commands verify presence **before any mutation** —
`agent_create`, `vault_rotate_key`, `vault_init`, `remediate_execute`,
`remediate_restore` — and a refusal must leave **observable state
unchanged**, not merely omit a secret or token from the response: no agent
created, DEK unchanged, no vault created, project not rewritten (§9.2
asserts this).

Declared **without a gate**, with the reason recorded here and in ADR-0025:

- `vault_unlock` with passphrase custody and `vault_unlock_recovery`: each
  requires knowledge the agent does not have (passphrase / recovery phrase);
  stealing that knowledge is keylogging, an existing declared non-goal.
  The OsKeychain unlock **is** gated (item 9) because it needs no knowledge.
- `vault_read_file` / `vault_export_file` on **DIRECT** containers: declared
  ungated (author decision) — the same content is already reachable by any
  same-user process through MCP pairing at `/.well-known/mcp-pairing`
  (threat-model §3.B), so gating the desktop command adds nothing; revisit
  if §3.B changes. The gate applies to ANONYMIZED (item 2).
- `vault_list_files`: exposes blob sizes and timestamps; metadata class,
  same standing as on-disk stat for a same-user process. Revisit if size
  ever becomes content-relevant.
- `mcp_status`: the pairing secret it returns is already published to every
  local process by `/.well-known/mcp-pairing` (threat model §3.B); gating
  the command without closing the endpoint would be theater.

## 8. Audit

New event fields on approval records:

| Field | Values | Meaning |
|---|---|---|
| `protected` | `true \| false` | Was presence enforced for this approval |
| `outcome` | `device_owner_authenticated \| click` | What actually authorized it |
| `modality` | `biometric \| password \| pin \| unknown` | Reported by the verifier, never inferred |

- The modality is recorded only from what the backend can report. Windows
  returns a bare `Verified` — modality `unknown`; it must never be inferred
  from the device's capability.
- Unprotected approvals (`protected: false`) remain auditable as a
  measurable, falsifiable signal, consistent with how `write_only_denied`
  is used as a research signal.

## 9. Errors and tests

### 9.1 Error mapping and UI behavior

| `PresenceError` | Request state after | UI |
|---|---|---|
| `Cancelled` | back to `Pending` | reason shown; retry allowed |
| `Failed` | back to `Pending` | reason shown; retry allowed |
| `Busy` | back to `Pending` | reason shown; retry allowed |
| `Exhausted` | back to `Pending` | lockout reason shown; retry allowed |
| `DisabledByPolicy` / `NotConfigured` / `Unavailable` returned **mid-attempt** | `Denied` — that request's approval is refused (§6.2; never degrades to a click) | reason shown |
| `Timeout` | `Expired`/`Denied` per §6.1 | as existing timeout |

`DisabledByPolicy` / `NotConfigured` / `Unavailable` reached by `verify()` are
denials, not reclassifications: the click path exists only for requests born
`Unavailable` at creation (§6.2), never discovered mid-attempt. Separately,
the coordinator-level `queue_full` (§6.1) refuses the attempt that would be
the 9th waiting (the 10th concurrent while one prompt is active) with a
denial to the agent; it is not a `PresenceError`.

### 9.2 Automated tests (no hardware; injected fake `PresenceVerifier`)

The fake verifier tests the **coordinator** — states, deadlines, queue,
digest binding. It proves nothing about the resistance of the real OS
prompt; that is covered by the UI-automation cases in §9.3.

- Central test: `approval_respond(id, true)` with no completed verify does
  **not** approve a request classified `Protected` at creation.
- A callback that fires after the deadline does not approve; late callbacks
  are discarded.
- Refusal, vault lock, or disconnect during `Verifying` invalidates the
  attempt.
- Mid-attempt unavailability: a fake verifier that starts protected and
  returns `Unavailable`, `DisabledByPolicy`, or `NotConfigured` during
  `verify` **denies** that request — it never falls back to a click, and
  the request's `protected` classification does not flip.
- Concurrent responses (modal + tray) start exactly one verification per
  request.
- A completed verification does not satisfy the next request.
- The queue respects deadlines while attempts wait.
- Queue saturation: with one prompt active and 8 requests waiting, the next
  waiting attempt (the 10th concurrent) is denied with
  `queue_full` (§6.1); requests already queued are unaffected.
- Slot release: an attempt whose request expired or was refused keeps the
  prompt slot occupied until the fake backend reports the prompt closed;
  the queue does not advance before that. Cover the case where native
  cancellation is **not** available and the prompt only ends on its own.
- Digest binding: a verification granted for one `op_digest` cannot approve
  a request whose description changed (finalizer mismatch).
- `Cancelled` / `Failed` never degrade to a click.
- OTP: the code is not present in the event before a successful verify; the
  **correct code resent before verify is rejected** like a wrong code; a
  revealed code stops working once the deadline passes or the code is used
  (single-use); a code revealed for request A never approves request B.
- Submits (ADR-0024 path, §7.4): with a protected classification,
  `submit_secret` / `submit_secret_direct` are denied when presence fails,
  and the `op_digest` binds the expected `revision`/`expected_generation`.
- Tray "Approve" opens the modal and never approves by itself.
- Desktop command gates (§7.5): a source-scan regression in the style of
  `every_mutating_desktop_command_enforces_mode` (lib.rs:5115) compares the
  **complete** Tauri command registry (`invoke_handler`) against a
  mandatory per-command classification — own gate | derived authorization |
  justified exception — and a new command **without a classification**
  fails the test. Beyond the textual scan, every gated path has an
  executable test.
- Per gated command, with the fake verifier reporting Protected and no
  verification performed: `vault_read_file` / `vault_export_file` on
  ANONYMIZED return nothing and write nothing; `remediate_restore` writes no
  plaintext; `remediate_execute` ingests nothing and leaves the project file
  unchanged (a digest match alone is not enough); `wake_respond` records no
  authorization; `agent_create` returns no token **and creates no agent**;
  `vault_rotate_key` returns no recovery phrase **and leaves the DEK
  unchanged**; `scan_reveal` reveals no preview; `vault_unlock` with
  OsKeychain custody does not unlock; `vault_init` **creates no vault** and
  returns no recovery phrase. Each denial is audited with
  `protected: true`. For the mutating commands the assertions check
  observable state — no agent created, DEK unchanged, no vault created,
  project not rewritten — not merely the absence of a token or phrase in
  the response.
- `wake_prepare_access` (derived authorization, §7.5 item 5): the backend
  validation of the current wake authorization refuses a direct call with
  no approval, an expired authorization, and a session or scope switch.
- Per-gate caveats, for **every** gated command: a verification success
  arriving after the deadline or after a vault lock produces no effect (no
  release, no mutation); a parameter change during the prompt (a different
  `op_digest`) denies the attempt; unavailability between classification
  and execution denies it.
- Declared-system behavior: with the fake verifier reporting `Unavailable`,
  ANONYMIZED `vault_read_file` / `vault_export_file` require the consent
  click (the PR #120 gate — never ungated) and the approval is audited
  `protected: false`.
- macOS adapter (unit-level with a fake robius boundary): a start-level `Ok`
  is not success; missing callback → denial; late callback → discarded.
- Windows adapter: each `UserConsentVerificationResult` maps per §9.1; only
  `Verified` approves.

### 9.3 Manual (`docs/testing/`)

- macOS: Touch ID approve; Mac password approve; cancel/lock/refuse paths.
- Windows: Hello fingerprint approve; Hello PIN approve; locked/unavailable
  device paths.
- Windows below Build 22000 (the Hello interop minimum): declared-click path
  with the unprotected notice.
- Linux: declared-click path with the unprotected notice.
- **Real UI automation on protected platforms** (the fake verifier cannot
  cover this): drive Approve with AppleScript / Accessibility on macOS and
  Windows UI Automation on Windows; with no device-owner authentication
  performed, no approval may commit. This is the direct test of the §1
  attack: the automation can press the button, it cannot pass the OS prompt.

## 10. Phases

- **MVP (§§4–9):** macOS via robius-authentication; Windows via
  `sv-presence-windows`; Linux declared-unprotected; tray revision; OTP
  reveal-after-verify; audit fields; desktop command gates (§7.5) —
  presence replacing the PR #120 ANONYMIZED consent click; tests with an
  injected fake.
- **Out of scope (declared):** biometric vault unlock (subproject A — reuses
  this trait afterwards); cryptographic proof of presence via hardware key;
  OS-suspend-triggered locking; any presence mechanism on Linux.

## 11. Risks and documentation

**Dependency risks to record:**

- `robius-authentication` is maintained by a single maintainer; the macOS
  backend is version-pinned to 0.3.1 and isolated behind the trait so the
  dependency can be replaced without touching the gate.
- The Windows backend is first-party (`sv-presence-windows` over the
  workspace's existing `windows` 0.61): robius' own `windows` 0.56 pin never
  enters the graph because the robius dependency is macOS-target-only, and
  the forbidden fallbacks are excluded by construction rather than by
  configuration. The `unsafe` exception stays inside one audited crate.
- `android-build`, an unconditional build-dependency of robius, is **not**
  eliminated by the macOS-target restriction: it still resolves and builds
  when compiling on macOS. Registered here and in ADR-0025 as a **residual
  cost** — decided and accepted, not an open question and not claimed to be
  avoided.

**Docs to update with the implementation:**

- `docs/adr/0025-presence-verified-approvals.md`: the decision; the
  desktop command gate list and the declared no-gate exceptions with
  reasons (§7.5); the
  `unsafe` exception for `sv-presence-windows`; the ADR-0022 revision; the
  rejected alternatives with reasons — robius as the Windows backend
  (desktop-window HWND owner, title-based focus tricks, synthetic Alt,
  silent password fallback), polkit on Linux, a bespoke Windows password
  fallback, `GetDesktopWindow` + synthetic keyboard, tray approvals without
  a window, and OTP shown before authentication.
- This spec: `docs/development/specs/2026-09-28-presence-verified-approvals-design.md`.
- `docs/threat-model.md`: the new guarantee and the declared limits (Linux
  unprotected; Windows below the interop minimum unprotected; modality
  `unknown` on Windows).
- `docs/SECURITY-REVIEW.md`.
- `docs/testing/`: the §9.3 cases.

## 12. Thesis impact (author decision)

Nothing in `docs/thesis/` is modified by this spec or its implementation
without an explicit author decision.

- **Unaffected evidence:** the chapter-4 measurements (AutoAllow, the
  simulated `HitlPolicy`) do not exercise the real desktop UI and are not
  changed by this feature.
- **Passages affected by the new guarantee — listed for the author:**
  `docs/thesis/TRACEABILITY.md:34` and `TRACEABILITY.md:46`
  (human-in-the-loop claims); `docs/thesis/paper.tex:353`, `:448`, `:456`,
  `:780` (approval-path and trust-boundary claims).
- **The `unsafe` claim:** the thesis states own crates forbid `unsafe`
  (workspace rule; `crates/sv-mcp/src/lib.rs:18`). `sv-presence-windows`
  is an own crate that needs minimal FFI `unsafe`, declared as an exception
  in ADR-0025. Whether the thesis wording is qualified or the exception is
  otherwise reconciled is the author's decision — do not edit silently.
- **Linux declaration:** any thesis text implying desktop approval
  presence across platforms must, if it changes at all, carry the declared
  Linux limitation.
- **The ANONYMIZED desktop gap (fact for the author):** in the evaluated
  artifact the *desktop* returned and exported ANONYMIZED container content
  in cleartext without consent (`lib.rs:2139` treats it ungated; no
  `sv-privacy` in the desktop), while the *gateway under evaluation* masked
  the same reads correctly (`sv-mcp/src/lib.rs:1431-1460`). This is an
  artifact gap in the desktop layer, not a defect of the measured MCP
  behavior: **PR #120** closed the gap with a consent click
  (`desktop_consent_required_for`), and this ADR's increment is presence in
  place of that click wherever the platform can attest it (§7.5) — which
  changes what the desktop does, and if any thesis passage describes
  desktop/ANONYMIZED behavior it should be re-read by the author. Nothing
  in `docs/thesis/` is altered here.
