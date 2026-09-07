# ADR-0021 — Locked-state wake endpoint

- **Status:** Proposed
- **Date:** 2026-09-07
- **Deciders:** pealmeida

## Context

[ADR-0015](0015-runtime-mediation-stack.md) bound the MCP gateway to an
unlocked vault. In the current artifact, `start_servers`
(`apps/desktop/src-tauri/src/lib.rs:4081`) binds the WebSocket and HTTP
listeners only when the handle is present, and `perform_vault_lock`
(`lib.rs:2075`) sets the handle to `None` and shuts both listeners down inline.
While locked, **no listening socket exists at all**. That is the property that
makes "locked" mean something.

The consequence is that an agent whose only channel is the MCP socket has no
way to signal that it needs the vault. The user must notice the failure
manually. The workaround that users naturally adopt — leaving the vault
unlocked, or pasting the secret into agent context — is worse than a controlled
asking path. This ADR adds that path.

It is a **narrow, explicitly bounded amendment** to ADR-0015: one additional
per-user local IPC endpoint, carrying a signal and nothing else, active while the
vault is locked. It does not authenticate vault access, does not unlock, and
does not confirm anything about vault contents.

## Decision

### 1. A separate local IPC endpoint, not the MCP gateway

The endpoint is per-user and distinct from the MCP WebSocket:

- **Windows:** a named pipe ACL'd to the current user.
- **macOS / Linux:** a unix domain socket at mode `0600` in the user runtime
directory.

Transport-level caller restriction is achievable before unlock: the OS enforces
same-user access via the pipe ACL or the `0600` mode. This is worth having. But
same-user malware shares that identity, so the honest guarantee is only that
**only this OS user's processes can queue a wake**, and the product **cannot
tell which one**. The UI must never label a wake as coming from a specific
trusted agent.

### 2. Fixed one-word protocol with no parameters

```text
-> WAKE\n
<- QUEUED | RATE_LIMITED | DISABLED
```

That is the entire protocol. It deliberately carries:

- **no resource name** — naming one would make the endpoint an existence oracle
  over vault state. The unlocked `wake_request` command already carries an
  `opaque_resource_ref` for use after unlock; the locked-state endpoint carries
  nothing.
- **no agent identity** — an agent-supplied name is not evidence of anything.
  Displaying it would let any local process impersonate a trusted agent inside a
  security prompt.
- **no free text** — spoofed approval text is a real attack. The user must never
  read attacker-controlled prose inside a security decision.

The server bounds message size, accepts nothing but `WAKE`, and limits
concurrent connections.

### 3. What the endpoint must not do

- It must not unlock the vault, authenticate vault access, or authorize any
  operation.
- It must not confirm whether any named resource exists.
- It must not reset the idle timer or extend the absolute session cap.
- It must not focus or raise a window automatically.
- It must not let a request storm produce a prompt storm.

### 4. Rate limiting and notification policy

The endpoint maintains:

- **one pending wake flag**, not a queue of prompts;
- a **global notification cooldown**;
- rate limits on **rejected connections too** — per-agent limits are
  meaningless when identity is unverifiable;
- a **mute control**;
- an **enable/disable switch**.

The setting is offered during agent setup and uses the following copy:

> Allow local applications to request an unlock notification, even when MCP is
> disconnected. Requests do not unlock the vault or grant access — you unlock it
> here, and access is authorized under your existing rules.
>
> Sovereign Vault must be running. Enable **Start at sign-in** to keep wake
> requests available after login.

### 5. Audit qualification

The audit HMAC key derives from the live handle (ADR-0007), which does not exist
while locked. A wake received during lock therefore **cannot enter the
authenticated hash chain at the moment of receipt**.

The implementation records the receipt **after unlock**, explicitly qualified as
"received while locked; recorded on unlock". A product whose central claim is a
verifiable append-only log must not quietly insert entries it could not
authenticate when they happened.

### 6. Unlock does not approve

Unlocking **never approves the queued operation**. When the agent's actual MCP
request arrives after unlock, it is re-evaluated under the normal rules. A
wake is a request for attention, nothing more — and a different agent racing
in after the unlock gets no benefit from another's wake.

## Consequences

- **Positive.** There is a legitimate path for an agent to ask for the vault
  while locked, which is strictly safer than the workarounds it replaces.
- **Positive.** The OS-level same-user restriction is real and useful, even
  though it is weaker than agent authentication.
- **Positive.** The no-parameter protocol prevents the endpoint from becoming
  an existence oracle or a channel for spoofed security prose.
- **Negative.** The honest guarantee is bounded to the current OS user. Any
  process running as that user — including same-user malware — can queue a
  wake, and the product cannot distinguish them.
- **Negative.** Wake receipts during lock cannot be authenticated at receipt
  time; they are recorded only after unlock, qualified as delayed entries.
- **Negative.** The endpoint is a new durable surface that must be versioned,
  rate-limited, and audited with the same discipline as the MCP gateway.

### Thesis claims this decision does *not* support

Per `AGENTS.md`, the boundary is part of the decision. This work does **not**
establish:

- that an agent can unlock the vault without the passphrase;
- that a wake request identifies which agent sent it;
- that wake events are in the verified audit chain from the moment they arrive;
- OS-level isolation of the wake endpoint from other same-user processes;
- that enabling "Start at sign-in" makes the vault available before login.

## Alternatives considered

- **Filesystem drop directory.** Rejected. Requests persist into backups, permit
  replay, allow disk flooding, and bring symlink and ownership problems.
- **Notification click-through as the inbound mechanism.** Rejected.
  Notifications are presentation only; something must first receive the
  request.
- **Single-instance argv (`sovereign-vault --request-unlock`).** Retained only
  as a fallback when the app is not running. Carries no resource name, no token,
  and no free text, because argv is inspectable by other processes. Subject to
  the same rate limits as the IPC endpoint.
- **Carrying resource name, agent identity, or free text in the protocol.**
  Rejected for the reasons stated in §2.
- **Auto-unlock on wake.** Rejected. It would convert the wake signal into an
  unlock authorization, removing the structural human decision that every
  downstream control depends on.

## References

- [ADR-0007](0007-root-key-data-key-hierarchy.md) — the audit HMAC key and its
  dependence on the live handle.
- [ADR-0015](0015-runtime-mediation-stack.md) — the "no listener while locked"
  property that this ADR amends narrowly.
- [ADR-0020](0020-managed-files-and-wake-on-demand.md) — the unlocked-state wake
  queue, which carries an opaque resource reference; the locked-state endpoint
  carries none.
