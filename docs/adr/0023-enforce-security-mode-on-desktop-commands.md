# ADR-0023: Enforce security mode on desktop commands

## Status

Accepted.

## Context

A container's `SecurityMode` was enforced on the MCP path only.

Desktop Tauri commands called `container_mode(...)` to obtain the mode, passed
it to `desktop_event(...)` so the audit row carried a `mode:` field, and then
performed the operation unconditionally. No `approval_requirement`, no
approval request. The gate is reached only through
`sv_mcp::AccessController::authorize`, which the UI path never calls.

All nine vault-touching desktop commands were affected: `vault_read_file`,
`vault_write_file`, `vault_delete_file`, `vault_delete_container`,
`vault_list_files`, `vault_list_containers`, `vault_create_container`,
`scan_store`, `audit_verify`.

`sv-storage` documents the intent: the storage crate "stores the mode but does
not enforce HITL — that is done by higher layers", naming the "UI/MCP layer
above". MCP enforced it; the UI did not.

### How it was found

Audit analysis of a real vault, prompted by a question about which containers
genuinely need OTP mode. Of 27,148 OTP-mode events, 27,139 were one container
and 27,075 were reads of a single 93,965-byte PDF:

- 99.8% of consecutive reads less than one second apart, median gap 36 ms
- peaks of ~28 reads/second, in two bursts (21,421 reads in 15 minutes;
  5,647 in 3 minutes)
- every row `decision: allowed`, `transport: desktop-ui`, `mode: OTP`

A UI render loop, not a user. No human answered 27,000 OTP challenges.

The loop is a bug in its own right. The security finding is what the log then
says about it: **an append-only, HMAC-chained audit asserting a human approval
that never occurred.** For a system whose contribution is auditable
human-in-the-loop mediation, a log that overstates the control is worse than a
missing gate — the gate's absence is discoverable, the false record is not.

## Decision

Route vault-mutating desktop commands through an explicit consent gate.

### A desktop OTP becomes a confirmation click

OTP mode is **cross-channel**: the vault shows a code on the desktop, and the
agent resends the request carrying it. Two channels an agent cannot straddle
alone.

When the caller *is* the human at the desktop, that loop is degenerate. The
code would be displayed to, and retyped by, the same person on the same
screen — friction that binds nothing. `handle_otp` also structurally cannot
serve this path: it returns `otp_required` and waits for a resend, which a UI
button click cannot perform.

So a desktop caller is prompted for explicit confirmation for **both**
`Approval` and `Otp` containers. The human gate runs; only the second channel
is dropped, because on this path there is no second channel. The audit records
`transport: desktop-ui`, so a reviewer can always distinguish a desktop
confirmation from an agent's cross-channel OTP.

### Deletion always confirms

`vault_delete_file` and `vault_delete_container` prompt in **every** mode,
including `Direct`. Elsewhere `Direct` means "no human gate", which is a
statement about reads and writes — operations that can be repeated or
corrected. A deleted file cannot be. Destroying a container destroys every
file in it.

### Unimplemented modes fail closed

`Zkp` and `Native` return an error rather than falling through to "no consent
needed". An unimplemented control must not silently become an absent one.

### Absent mode does not prompt

A container with no recorded mode has no policy set, so a prompt would gate
something the user never asked to gate. This matches `approval_requirement`,
which treats a modeless request the same way.

## What is deliberately NOT gated

**`vault_list_files`.** The MCP path does prompt for a listing in an
Approval-mode container. The desktop calls this on every navigation into a
container *and again after each write* (`fileStore.refresh`), so gating it
would raise a second prompt immediately after the write prompt the user just
answered — for a metadata listing that reveals names, not content. Prompts
arriving in pairs for one intended action are what train a user to click
through without reading, which costs more than this listing protects.

Stated plainly: **a local operator at an unlocked vault can enumerate file
names in an Approval- or OTP-mode container without a prompt.** Reading,
writing, or deleting any of them still prompts.

**`vault_create_container`.** The user is creating their own container through
a form they just filled in; the submit click is the consent, and there is no
pre-existing protected content to guard.

**`scan_store`.** User-initiated, and it writes to its own scan container
rather than a user container.

**`vault_list_containers` and `audit_verify`.** Read-only over metadata the UI
needs to render at all.

## Consequences

- Reading a file in an OTP or Approval container from the desktop now raises a
  confirmation. This is a **behaviour change for existing vaults** — those
  operations previously completed silently.
- The audit's `mode:` field now means the control ran, on both paths.
- Historical rows cannot be corrected. The chain is append-only, which is
  working as designed; the 27,075 rows above remain, and remain misleading
  about what they attest. Any analysis of pre-existing logs must treat
  `desktop-ui` rows carrying a `mode:` as unenforced.
- `AccessTransport` still models agent channels only (`McpStdio`, `McpWs`).
  The desktop path reuses `McpWs` for the request struct; the *audit*
  transport is set separately and correctly reads `desktop-ui`. A dedicated
  variant would be cleaner and is deliberately left out of this change, which
  is a security fix.

## Alternatives rejected

**Gate everything, including listings.** Produces paired prompts for single
user actions and trains click-through. Rejected on the grounds that a control
users learn to dismiss is worse than a scoped one they read.

**Show the OTP code on the desktop and have the user type it back.** This is
what the OTP path does for agents, and it is meaningless when both channels
are the same screen and the same person.

**Stop writing `mode:` on ungated desktop events.** Would make the audit
honest without adding a control. Rejected as strictly worse than enforcing:
the mode is set precisely because the user wants those operations gated.

**Leave it, and treat the desktop as trusted.** Defensible if the UI were
reachable only by the local human, but the vault is unlocked for the whole
session and the modes exist because the user asked for a gate. Silently not
honouring that is the defect.
