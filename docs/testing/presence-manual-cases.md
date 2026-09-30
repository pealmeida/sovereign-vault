# Presence verification — manual test cases (ADR-0025)

> Companion to
> [`docs/development/specs/2026-09-28-presence-verified-approvals-design.md`](../development/specs/2026-09-28-presence-verified-approvals-design.md)
> §9.3 and to
> [`docs/development/plans/2026-09-28-presence-verified-approvals.md`](../development/plans/2026-09-28-presence-verified-approvals.md)
> Task 15.

The automated suite (spec §9.2) runs against an injected fake
`PresenceVerifier`, so it cannot exercise a real OS prompt. Every case below
needs real hardware, a real enrolment (fingerprint / PIN / password) and a real
prompt. Each table has one row per spec §9.3 case; the **Result / date /
tester** column stays empty until the case is executed and filled by hand.

**Rules that hold for every case**

- Refusing never requires presence (spec §2, goal 2): **Deny** works with no OS
  prompt.
- The approval deadline stays `APPROVAL_TIMEOUT_SECS = 120`
  (`apps/desktop/src-tauri/src/lib.rs:79`); the native prompt does not pause it
  (spec §6.1).
- One native prompt at a time; at most **8** waiting, and the attempt that
  would be the 9th waiting is refused with `queue_full` (spec §6.1).
- Only these two outcomes approve: macOS `Ok(())` on the robius completion, and
  Windows `UserConsentVerificationResult::Verified` (spec §9.1).
- `Cancelled` / `Failed` / `Busy` / `Exhausted` put the request back to
  `Pending`; `DisabledByPolicy` / `NotConfigured` / `Unavailable` returned
  **mid-attempt** deny the request outright (spec §9.1) — never a click.
- The modality is recorded only as the backend reports it; on macOS it is
  always `unknown`, and on Windows a Hello PIN is also recorded as `unknown`
  (spec §8, plan D1).

---

## macOS (protected system)

| Case | Steps | Expected | Result / date / tester |
|---|---|---|---|
| MAC-01 — Touch ID approve | From a connected agent, request an operation classified `protected: true` (APPROVAL container read, or any gated desktop command). In the approval modal press **Approve**. The system prompt appears; authenticate with Touch ID. | The native prompt completes successfully and the approval commits. An audit record for the decision carries the `presence` field with `operation_id` `approval-<id>` (plan D5), written while the handle is held, and `modality` as reported by the backend (`unknown`, plan D1). | |
| MAC-02 — Mac password approve | Same as MAC-01, but authenticate in the system prompt with the Mac login password instead of Touch ID (policy `DeviceOwnerAuthentication`). | Same as MAC-01: approval commits. The password is typed into LocalAuthentication and never passes through this process (spec §5.1). | |
| MAC-03 — Cancel during the prompt | Same as MAC-01, but dismiss/cancel the system prompt without authenticating. | `Cancelled` → the request returns to `Pending` with the reason shown and retry allowed (spec §9.1). Nothing is released or mutated, and no Allowed record exists for that decision. | |
| MAC-04 — Lock during the prompt | Same as MAC-01; while the system prompt is still open, lock the vault (manual lock or the session monitor). | The lock refuses every pending approval, invalidates the attempt in flight, clears OTP challenges, and clears the desktop operation registry (plan D4). Nothing commits. The prompt may still be on screen; its result is discarded. Declared exception (plan D5): a denial that happens while the vault is locked cannot be HMAC-audited, because there is no key. | |
| MAC-05 — Refuse during the prompt | Same as MAC-01; after the system prompt appears, press **Deny** in the approval modal (or deny from the tray before the prompt), with no OS authentication performed. | Refusal is immediate and requires no presence (spec §2). The decision is recorded as denied; no approval effect survives. | |
| MAC-06 — Deadline during the prompt | Same as MAC-01, but never authenticate; let the 120 s approval deadline elapse. | The request expires / is denied per spec §6.1; a missing completion callback maps to `Timeout` → denial (spec §5.1). Nothing commits. | |

## Windows (Build ≥ 22000, Hello available)

| Case | Steps | Expected | Result / date / tester |
|---|---|---|---|
| WIN-01 — Hello fingerprint approve | From a connected agent, request an operation classified `protected: true`. Press **Approve**. In the Windows Hello prompt authenticate with the fingerprint reader. | `UserConsentVerificationResult::Verified` → the approval commits, with the `presence` field and `operation_id` `approval-<id>` in the audit record. | |
| WIN-02 — Hello PIN approve | Same as WIN-01, but authenticate with the Hello PIN. | `Verified` → approval commits. The PIN counts as a valid verification and its modality is recorded as `unknown` (spec §5.2, §8). No password or PIN ever passes through this process. | |
| WIN-03 — Device locked or busy | Same as WIN-01, with the auth device unavailable at prompt time (device locked, reader busy). | `DeviceBusy` → `Busy` → request back to `Pending`, reason shown, retry allowed (spec §9.1). Nothing commits. | |
| WIN-04 — Unavailable / not configured / policy | Same as WIN-01, on a machine where Hello is missing (`DeviceNotPresent`), not configured for the user, or disabled by policy — discovered **after** the request was classified `protected: true`. | `DeviceNotPresent` → `Unavailable`, `NotConfiguredForUser` → `NotConfigured`, `DisabledByPolicy` → `DisabledByPolicy`: each **denies** the request mid-attempt, with no click fallback (spec §9.1, §6.2). Nothing commits. | |
| WIN-05 — Retries exhausted | Same as WIN-01, but fail the verification until Hello locks out. | `RetriesExhausted` → `Exhausted` → request back to `Pending`, lockout reason shown, retry allowed (spec §9.1). | |

## Windows below Build 22000 (Hello interop minimum)

| Case | Steps | Expected | Result / date / tester |
|---|---|---|---|
| WIN-LOW-01 — Declared click + notice | On a Windows machine below Build 22000, request an operation classified at creation as `Unavailable`. | No native prompt is attempted: the declared consent click remains, the decision is audited `protected: false`, and the permanent notice "unprotected approvals on this system" is shown (spec §5.2, §6.2). `availability()` reports `Unavailable` before any attempt. | |

## Linux

| Case | Steps | Expected | Result / date / tester |
|---|---|---|---|
| LNX-01 — Declared click + notice | On Linux, request an operation classified at creation as `Unavailable`. | Declared consent click everywhere (approvals behave as today), audited `protected: false`, permanent notice shown. No polkit prompt, ever (spec §5.3, §6.2). | |

## Real UI automation on protected platforms (spec §9.3)

The fake verifier cannot cover this: automation can press the button, it
cannot pass the OS prompt. This is the direct test of the §1 attack.

| Case | Steps | Expected | Result / date / tester |
|---|---|---|---|
| AUTO-01 — macOS automation presses Approve | With a `protected: true` request pending, drive the **Approve** control with AppleScript / the Accessibility API (no Touch ID, no password typed by the automation). | The OS prompt opens (or the attempt waits for it) and **no approval commits**, because no device-owner authentication is performed. Nothing is released beyond the MCP channel and the vault does not unlock. | |
| AUTO-02 — Windows automation presses Approve | With a `protected: true` request pending, drive the **Approve** control with Windows UI Automation (no Hello verification performed). | Same as AUTO-01: no approval commits. | |
| AUTO-03 — macOS automation presses each gated command | With the desktop UI reachable, press the button for each gated command (spec §7.5) one at a time using AppleScript / Accessibility, with no OS authentication: ANONYMIZED `vault_read_file` and `vault_export_file`, `scan_reveal`, `agent_create`, `vault_rotate_key`, `remediate_execute`, `remediate_restore`, tray/modal approve (`approval_respond`), wake approve, `vault_unlock` with OsKeychain custody, `vault_init`, and an increase of `session_set_limits`. | For every command: the native prompt is requested and, without device-owner authentication, **nothing commits** — no agent created (observable state unchanged), DEK unchanged, no vault created, no project rewritten, no cleartext released to the renderer or to disk, no secret phrase revealed (spec §7.5). | |
| AUTO-04 — Windows automation presses each gated command | Same as AUTO-03 on Windows ≥ 22000, driving the controls with UI Automation and performing no Hello verification. | Same expected result as AUTO-03. | |
| AUTO-05 — Automation on a declared system (control) | Run AUTO-03 on Linux, or on Windows below Build 22000. | The declared click path commits the operation (that is the declared design, spec §6.2), audited `protected: false`, with the permanent notice. This case documents the boundary; it is not a failure of the guarantee. | |

---

**Recording results:** fill **Result / date / tester** as `PASS/FAIL · YYYY-MM-DD · name`.
Any FAIL must be filed before the corresponding PR is merged.
