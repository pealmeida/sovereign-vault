# ADR-0020 — Managed files and wake-on-demand access

- **Status:** Proposed
- **Date:** 2026-09-07
- **Deciders:** pealmeida

## Context

Two user requirements go beyond the span-redaction model of
[ADR-0017](0017-project-scanning-and-remediation-boundary.md), which rewrites
*occurrences inside* files and leaves every file in place.

**R1 — whole sensitive files should be able to move into the vault.** A real
`.env`, a `.pem`, a `service-account.json` is not an occurrence inside a
config file; it *is* the sensitive artifact. The user wants it out of the
project tree and into the vault while the project keeps working.

**R2 — the vault should be easy to wake when vaulted material is needed.** By
an agent mid-task, or by the user. "Easy" is the requirement's word, and it
is the dangerous one.

The current state of the artifact makes the second requirement sharper than
it looks. The vault handle is `Option<Handle>`, where `None` means locked.
When locked, **every** MCP tool call fails with "vault is locked". There is
**no idle timeout** and **no unlocked-session cap anywhere** — an unlocked
vault stays unlocked until the user locks it by hand. Unlock requires the
passphrase typed into the desktop GUI. So today the vault is either a locked
wall that produces nothing but failures, or an open door with no timer on it.
"Easily" must not become "silently": the entire value of the human-in-the-loop
model is that material moves only when a person, seeing verified facts, says
so.

## Decision

### 1. Whole-file ingestion is not the primitive for a partly-sensitive file

Most sensitive-looking files are not wholly sensitive. A `docker-compose.yml`
with four keys among two hundred lines of legitimate configuration **stays in
place**: its keys are externalized through the toolchain's own mechanism —
compose secrets, `${VAR}` substitution — not by moving the file. Whole-file
ingestion is a candidate only for a file that is sensitive *as a whole*, where
no legitimate non-secret configuration would be lost by removing it.

This is also where a limit recorded in ADR-0019 becomes load-bearing: a
literal span marker can itself break execution. A `[SV:LOC:v1:…]` written
into a YAML value is still a string the parser hands to the application;
in-place redaction changes bytes, and there is no general way to know the
program still works. Whole-file ingestion sidesteps that for wholly-sensitive
files — and is therefore wrong for partly-sensitive ones, where the marker
strategy has no whole-file alternative to fall back on.

### 2. The ManagedFilePlan

Ingestion is planned, approved, and verified like any other mutation
(ADR-0019's pattern), through a `ManagedFilePlan` carrying:

- the encrypted file snapshot;
- the original relative path;
- the original permissions;
- a per-project binding;
- a `RecoveryRecord`;
- an **explicitly selected consumer adapter** (§3).

Removal of the original is **refused until that adapter passes a startup
check** — the project must demonstrably still work with the file vaulted
before the plaintext original is allowed to disappear. The plan never deletes
first and hopes.

### 3. What replaces the moved file

The hard question is not moving the file; it is what the consuming tool sees
afterward. dotenv-style loaders, PEM readers, and JSON credential loaders
have one thing in common: they want *bytes at a path*, and they will either
fail or — worse — consume a stand-in **as if it were the value**.

| Option | Verdict | Reason |
|---|---|---|
| Leave nothing | Reject | Consumers fail at startup; the project breaks. |
| Marker file at the consumed path | Reject | Readers consume the marker as if it were the value. dotenv exports the marker text; a PEM parser fails on it; a JSON loader hands `[SV:LOC:…]` to the application as a credential. |
| Toolchain-native stub | Conditional | Only where the toolchain explicitly supports indirection (compose `secrets:`, some secret-manager SDKs). Never assumed; verified per consumer. |
| Symlink into the vault | Reject for v1 | A symlink needs a plaintext target path on disk, creation needs privileges on Windows, and Git plus common tooling handle symlinks inconsistently across checkouts. |
| FUSE-style virtual mount | Defer | On Windows this means a driver or a service, with file-locking semantics, availability requirements (the mount must be up whenever any process opens the path), and ACL complexity — all of it on the security path. Not built in v1; not silently dropped either. |
| Launch adapter supplying environment variables or a supported stream | **Recommended** | The vault hands the material to the *process* at launch, through a channel the toolchain already consumes. No file exists to be read wrongly. |

A non-secret **manifest** may be left behind — describing what was vaulted
and how to launch — but at a path the consumer does **not** read, never at
the consumed pathname.

For a consumer that genuinely requires a *path*, the fallback is a
**restricted temporary file** materialized at launch, scoped to the launched
process, with cleanup and crash recovery. Stated plainly: this still exposes
plaintext to that process, to its descendants, to a debugger attached to it,
to backups, and to privileged software on the machine. It is a smaller
exposure than a permanent file in the tree, not the end of the exposure.

### 4. Re-creation cannot be prevented

Vault ingestion does not stop `cp .env.example .env`, and it does not stop
the next `npm run dev` from writing plaintext back to a managed path. Two
mitigations exist, and both have stated limits:

- a **launch-time check** can *reject* unexpected plaintext at a managed
  path and request reconciliation — before the process starts;
- a **watcher** can only *detect* re-creation after the fact.

Neither prevents the write. This ADR does not claim that the vault stops the
user's own tooling from putting plaintext back; it claims only that the
re-creation becomes visible and interruptible at defined points.

### 5. The same `.env` in 40 projects

The same file shape appears in dozens of checkouts. The default is
**independent logical resources** with independent permissions: each
project's copy is its own resource, revocable and auditable on its own.

An explicit **shared binding** is available, but the UI must show the
**rotation blast radius** before the user accepts it — how many projects
rotate together, and what breaks together. Internal encrypted-storage
deduplication (identical bytes stored once) must **never** imply shared
authorization: two projects referencing identical bytes remain two
authorization decisions, two audit trails, and two revocation targets.
Storage is an optimization; authority is never deduplicated.

### 6. Rollback

The encrypted original bytes and restoration metadata are retained until an
**explicit recovery deletion** — never auto-expired, because "put it back"
is the undo for a launch adapter that turned out not to fit the consumer.
Restore is destination-conflict-checked: if the destination has diverged
since ingestion, the user chooses, and nothing is silently overwritten.

Restoring a file restores the **historical bytes** — which is not necessarily
a still-valid credential, and is not a substitute for rotation if the value
was exposed (ADR-0019 §6). Git history and any pre-scan plaintext copies
remain exposed regardless of rollback, as ADR-0017 already records.

### 7. Wake requests human attention; wake never unlocks material

"Easy to wake" is implemented as *easy to ask*, and explicitly never as easy
to open. Rejected outright: a cached passphrase; a background daemon holding
the key hot; auto-unlock on agent request; long-lived tokens standing in for
unlock. Each of these converts the unlock act — the one point where a human
decision is structurally guaranteed — into ambient state, and every control
downstream of unlock becomes decoration.

### 8. The wake endpoint

A separate, minimal endpoint — Windows local IPC with restrictive ACLs —
accepts bounded, authenticated wake requests and returns a **generic**
queued/unavailable status.

Genericity is the design. The endpoint does **not** resolve locators and does
**not** confirm whether the requested resource exists: an unknown resource
and a pending one are indistinguishable in the response. That is what stops
the wake path from becoming an **existence oracle** over vault state — the
same defense as ADR-0019's exchange errors, applied to a new surface.

Requests queue in memory with per-agent and global rate limits, coalescing
(identical pending requests collapse), expiry, and notification cooldowns.
These are the anti-prompt-fatigue mechanism: an agent that retries in a loop
produces one notification, not forty.

The notification **opens the trusted GUI**; it does not approve anything. The
human types the passphrase into the GUI, and only then — authenticated and
inside the trusted surface — sees the verified requester, the intended
operation, and the destination. Passphrases are **never** collected through
MCP or any agent-supplied UI; an agent that asks for the passphrase is
itself the thing the passphrase protects against.

### 9. Idle auto-lock — add it

There is none today. This ADR adds a **configurable idle lock** plus an
**absolute unlocked-session cap**. Agent polling **must not** reset the idle
timer: a chatty agent polling once a minute would otherwise pin the vault
open forever, converting "no timeout today" into "no timeout, ever, in
practice".

Active operations need defined cancellation and checkpoint behavior at lock
time, so a lock mid-operation is a specified event rather than a corruption
risk. Locking **cannot retract bytes already delivered** — a lock revokes the
ability to ask for more, never what already left. The consequence is stated
plainly: long background jobs will cross the idle or absolute limit and will
require renewed human involvement. That is the accepted cost of §7, not an
oversight.

### 10. The lease

Unlock itself authorizes nothing. After unlock, each material access is
authorized by a **short-lived, single-use lease** bound to the agent
identity, the resource, the operation **and its arguments**, the
destination, the session, and the policy version in force.

The lease is enforced on **every material-access path, including transit and
export**. This is not an optimization note: an authorization checked on reads
but not on brokered transit or export is not an authorization — the
uncovered path *is* the bypass, and agents are exactly the kind of caller
that finds one.

### 11. Per-mode behavior

| Consent mode | Behavior after unlock |
|---|---|
| `Direct` | No further human interaction after unlock, subject to permissions. The unlock *was* the human decision. |
| `Approval` | Explicit per-operation approval, on top of unlock. |
| `Otp` | The OTP requirement stands unchanged. Interacting with the wake notification does **not** substitute for it — acknowledging "something is waiting" is not a second authentication factor. |

### 12. The audit record

A wake and the access it led to record: the requester, the protected resource
identifier, the operation digest, the decision, the authentication method,
the policy and session identifiers, the expiry, and the outcome. **Never the
material. Never a bearer token.** An audit log that carries what it audit-trails
is a second copy of the secret with worse access control.

## Consequences

- **Positive.** Wholly-sensitive files can leave the project tree without
  breaking consumers that accept supported injection, and the replacement
  table forces the marker-file failure mode to be argued with rather than
  shipped.
- **Positive.** The wake path gives agents a legitimate way to *ask*, which
  is strictly safer than the workaround that exists today: the user pasting
  the secret into the agent's context.
- **Positive.** Idle auto-lock and a session cap close an exposure the
  artifact currently has — an unlocked vault with no timer — rather than
  merely adding features to an already-safe baseline.
- **Positive.** Deduplication without shared authorization keeps per-project
  permission boundaries intact while still storing identical bytes once.
- **Negative.** Locked access stays human-dependent: someone must type a
  passphrase, see a GUI, and approve — and that is the accepted cost. Long
  background jobs will stall at the idle or absolute limit and require
  renewed human involvement.
- **Negative.** The path fallback of §3 still exposes plaintext to the
  launched process and everything that can inspect it. "Smaller exposure" is
  the honest claim, not "no exposure".
- **Negative.** Re-creation of plaintext by the user's own tooling is, at
  best, rejected at launch or detected after the fact. The vault does not
  prevent it.
- **Negative.** New compatibility surfaces — the IPC endpoint, consumer
  adapters, managed-path bookkeeping — are exactly the kind of durable
  surface ADR-0016 §Consequences warns about, and each needs the same
  versioning discipline.

### Thesis claims this decision does *not* support

Per `AGENTS.md`, stating the boundary is part of the decision. This work does
**not** establish:

- that a compromised but legitimately-authorized agent is stopped — an agent
  holding a valid lease for an access it intends to abuse is inside every
  control this ADR defines;
- that a human cannot be persuaded into approving something harmful — the GUI
  shows verified facts; it cannot show intent;
- that plaintext re-creation by the user's own tooling is prevented — it is
  rejected at launch or detected after the fact, nothing stronger (§4);
- that secrets are removed from Git history or backups — rollback restores
  bytes; exposure that already happened is not undone (§6);
- OS-level isolation of material handed to a launched process — the temp-file
  fallback hands plaintext to the process and its descendants (§3);
- that restoring a file restores a working credential — it restores
  historical bytes, whose validity is a property of the provider, not of the
  vault (§6).

## Alternatives considered

- **Marker file at the consumed path.** Rejected. dotenv exports the marker
  as the value, a PEM parser fails on it, a JSON loader hands it to the
  application as a credential — the reader cannot tell a stand-in from a
  value, and the failure mode is *silent* in exactly the case that matters.
- **Symlink into the vault.** Rejected for v1. A symlink's target is a
  plaintext path, creation requires privileges on Windows, and Git plus
  common tooling treat symlinks inconsistently across platforms and
  checkouts — the marker becomes either a breaking artifact or a plaintext
  pointer.
- **FUSE-style mount presenting vaulted files.** Deferred, not adopted. On
  Windows it requires a driver or service, must be available whenever any
  process opens the path, and drags locking and ACL semantics onto the
  security path. The complexity is real and the failure mode is
  availability: a mount that is down breaks every consumer at once.
- **Cached passphrase.** Rejected. It converts the vault's one structural
  human decision into a file on disk; everything downstream of unlock
  becomes theater.
- **Background daemon holding the key hot.** Rejected. A permanently
  unlocked daemon is a single high-value target whose compromise bypasses
  every consent surface at once; it also re-creates the "no timeout" problem
  by construction.
- **Auto-unlock on agent request.** Rejected. It makes "wake" synonymous
  with "unlock", and the human becomes either a rubber stamp after the fact
  or is not consulted at all — precisely the silent path this ADR exists to
  prevent.
- **Long-lived bearer token issued at unlock.** Rejected. It is ADR-0016's
  rejected durable-authorization pattern again: expiry and revocation lose
  meaning, and the token in a log or a leak is unlock-by-possession.
- **No wake path at all (locked vault hard-fails every call).** Rejected as
  the status quo. It is the behavior today, and it does not keep material
  safe — it trains the user to paste secrets into agent context or to leave
  the vault unlocked permanently. A legitimate, rate-limited, human-gated
  asking path is the safer alternative to the workaround it replaces.

## References
- Unlock and snapshot encryption rest on the key hierarchy of
  [ADR-0007](0007-root-key-data-key-hierarchy.md); wake never substitutes for
  unlocking the root.
- Lease binding, requester identity, and per-agent rate limits use the
  per-agent identities of [ADR-0008](0008-per-agent-identity.md).
- Per-mode behavior and the rule that no signal substitutes for consent are
  [ADR-0013](0013-sensitivity-classifier-adaptive-consent.md)'s, applied to
  wake notifications.
- Lease enforcement across every material-access path, including transit,
  extends the mediation stack of
  [ADR-0015](0015-runtime-mediation-stack.md).
- Locator-based markers and the `DiscoveryPolicy` gate are
  [ADR-0016](0016-durable-public-locators-and-discovery-policy.md)'s; the
  wake endpoint deliberately does not resolve locators.
- Managed-file ingestion extends, and is bounded by, the discovery/mutation
  boundary of [ADR-0017](0017-project-scanning-and-remediation-boundary.md).
- Plan-then-verify approval, keyed snapshots, and the existence-oracle
  defense follow [ADR-0019](0019-remediation-planning-and-trust-model.md).
