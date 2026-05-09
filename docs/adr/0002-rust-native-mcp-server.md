# ADR-0002 — Rust-native MCP server (no Node child)

- **Status:** Accepted
- **Date:** 2026-05-08
- **Deciders:** pealmeida

## Context

The proof-of-concept inside `agentic-sovereign-ecosystem` runs the MCP server as a Node child process (`scripts/rpc-server.js` + `scripts/lib/synthetic-vault-service.js`, ~2k lines). This places JavaScript on the security-critical path: the Node process holds plaintext secrets, decides which paths are jailed, and enforces approval-key validation. Every Node dependency added widens the attack surface, and a vulnerability in a transitive npm package can compromise the vault.

## Decision

Re-implement the MCP server in Rust as the `sv-mcp` crate. The Tauri desktop app links against `sv-mcp` directly; there is no Node child process at runtime. Both transports — stdio (for tools that spawn the vault as a subprocess) and WebSocket (for long-running agents) — live in the same crate.

The Node-based PoC stays in `agentic-sovereign-ecosystem` for reference but is not migrated to this repo.

## Consequences

- **Positive.** Single trust boundary (Rust process). No Node dependency tree. Removes a documented residual risk from the threat model. Simpler deployment (one binary). Easier to mobile-port (Tauri Mobile already runs Rust crates).
- **Negative.** Reimplementation cost (~1 week of M4 work). Loses access to the Node ecosystem's MCP libraries (mature; growing).
- **Mitigation.** MCP wire protocol is small enough to implement directly. Use audited crates (`tokio-tungstenite`, `serde_json`, `tokio`) for transport.

## Alternatives considered

- **Keep Node bridge as-is.** Rejected: keeps the JS trust boundary and ties release engineering to two runtimes.
- **Port Node bridge to TypeScript + bundle as embedded V8.** Rejected: still requires a JS runtime in the security path.
- **Keep Node bridge but harden it.** Rejected as a long-term solution; acceptable as PoC only.

## References

- Design spec § 2 D4 — *Backend runtime: full Rust rewrite — no Node child process*.
