# ADR-0006 — MCP integration architecture

* Status: Accepted
* Date: 2026-05-08
* Supersedes: —
* Superseded-by: —

## Context

Tier 2 of the Sovereign Vault MVP exposes the encrypted store to AI agents
(Claude Desktop, Cursor, Continue.dev, …) via the Model Context Protocol
(MCP). The desktop app must remain the single source of truth for the
unlocked `VaultHandle` — agents are guests, not co-owners of the master key.

## Decision

* The desktop app, on every successful `vault_init`/`vault_unlock`, starts
  two background tasks that share the live `Arc<Mutex<Option<VaultHandle>>>`:
  * an **MCP WebSocket server** on `127.0.0.1:9944` (`sv-mcp`)
  * a **read-only HTTP server** on `127.0.0.1:9943` (`sv-http`) serving
    `/health`, `/.well-known/agent.json`, `/.well-known/mcp-pairing`.
  Both shut down on `vault_lock` and on app exit.
* Agents that speak MCP-over-stdio (Claude Desktop, Cursor) spawn the
  bundled `sovereign-vault mcp-stdio` CLI, which proxies stdin↔WS to the
  desktop's WS server. The CLI fetches the per-launch pairing secret from
  the well-known endpoint, then sends `vault.pair { secret }` as the first
  WS message.
* A **fresh 32-byte URL-safe-base64 pairing secret is generated on every
  unlock** (rotation-on-unlock). Sleeping the laptop, locking the vault,
  or relaunching the app invalidates all previous agent connections. The
  secret never persists to disk.
* All sockets bind on `127.0.0.1` only — never `0.0.0.0`. As defence in
  depth, the HTTP layer also rejects requests whose `Host:` header is not
  a loopback name (`localhost` or `127.0.0.1`).
* MCP server-pushed messages are restricted to JSON-RPC responses and
  `notifications/*`. We do not broadcast MACE-style events on this socket;
  any other server frame is dropped by the stdio bridge.

## Why a stdio→WS proxy and not one extreme

Pure stdio (each agent spawns its own copy of the vault) breaks the
single-handle invariant: every spawn would need to unlock the vault again.
Pure WS (force every agent to speak WS directly) breaks compatibility with
Claude Desktop and other tools that only spawn stdio MCP servers. The
proxy gives both worlds: one master key, one HITL surface, multiple
concurrent agents.

## Consequences

* Port 9944 (WS) and 9943 (HTTP) become reserved for Sovereign Vault on
  the user's machine. Collisions are non-fatal — unlock still succeeds and
  `mcp_status` reports `running: false`.
* Agents must be relaunched when the vault is re-unlocked because the
  pairing secret rotates. This is the intended UX.
* No HITL approval modal is wired in v1.0 — every call against an unlocked
  vault goes through. The HITL queue (level-aware) lands in v1.1 alongside
  the audit-log writer.

## Open questions (deferred to v1.1)

* **Agent identity / capability tokens.** Today the pairing secret is
  process-wide; any agent that obtained it can call any tool. v1.1 will
  introduce per-agent pairing entries with scoped capability sets and
  optional per-call HITL prompts.
* **Multiplexing WS + HTTP on one port.** v1.0 splits them across 9944
  and 9943; v1.1 may upgrade hyper to handle WS upgrade and consolidate.
