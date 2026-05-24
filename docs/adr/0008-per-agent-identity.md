# ADR-0008 — Per-agent identity and scoped capability grants

- **Status:** Accepted
- **Date:** 2026-05-23
- **Deciders:** pealmeida

## Context

The MCP server (`sv-mcp`) authenticates clients with a **single shared pairing secret** (`McpServer::new(handle, pairing_secret)`; served at `/.well-known/mcp-pairing`). Every agent that connects presents the same secret. Consequences:

- **No attribution.** Audit entries cannot say *which* agent read a file — only that "an MCP client" did.
- **No per-agent revocation.** Revoking one agent means rotating the secret and re-pairing every other agent.
- **Single point of compromise.** One leaked secret grants the full surface to anyone.

This is the weakest link flagged in `docs/analysis/2026-05-23-reference-vault-improvements.md`. Vault (AppRole) and Bitwarden Secrets Manager (machine accounts + access tokens) both give each non-human consumer its own identity and scoped credential. We should too — it is foundational to the agent-native positioning.

## Decision

Introduce **agent identities**, each with its own credential and scope.

### Data model
A registry at the vault root, `agents.json` (tokens are access-granting but lower-sensitivity than the DEK; we store only their hashes):

```jsonc
{
  "schema": 1,
  "agents": [
    {
      "agent_id": "ag_<random>",
      "name": "Claude Desktop",
      "token_hash": "<argon2id or HMAC-SHA256 of the token>",
      "created_at": "<rfc3339>",
      "expires_at": null,
      "revoked": false,
      "scopes": [
        { "container_glob": "notes/**", "actions": ["read","list"], "mode_ceiling": "APPROVAL" }
      ]
    }
  ]
}
```

### Token issuance / pairing
- The desktop UI mints an agent: generate `agent_id` + a one-time token (`fresh_pairing_secret`-style CSPRNG), display the token **once**, persist only its hash.
- The agent presents `agent_id` + token on connect; the server validates against `token_hash` (constant-time compare), then binds the live session to `agent_id`.

### Authorization & audit
- `sv_mcp::AccessRequest` gains `agent_id`. `AuditEvent` gains `agent_id` (attribution).
- Authorization order: (1) resolve agent → reject if unknown/expired/revoked; (2) check the request against the agent's `scopes` (container glob + action + `mode_ceiling`); (3) fall through to the existing per-container mode flow (DIRECT/APPROVAL/OTP). Scopes can only *narrow*, never widen, the container mode.
- Revocation: setting `revoked: true` (or deleting the entry) takes effect on the next request — no secret rotation needed.

### Migration / back-compat
On first start with no `agents.json`, mint a single default agent ("Default") wrapping the current pairing flow so existing setups keep working; the UI then lets the user split out per-agent identities.

## Consequences

- **Positive.** Per-agent revocation, per-agent audit attribution, scoped least-privilege, and a foundation for multi-agent delegation (ADR-future) and policy (roadmap). Removes the single-shared-secret SPOF.
- **Negative.** New persisted state (`agents.json`) and a pairing UX. `AccessRequest`/`AuditEvent` shape changes ripple through `sv-mcp`, `sv-core`, desktop, and the audit schema (coordinate with the audit hash-chain — adding a field is fine; it just becomes part of the chained bytes).
- **Mitigation.** Land behind the default-agent migration so nothing breaks on day one. Store only token hashes. Constant-time token comparison. Cover with tests: unknown/expired/revoked rejection, scope narrowing, attribution in audit.

## Alternatives considered
- **Keep the shared secret, add a separate ACL file.** Rejected: still no attribution; the secret remains a SPOF.
- **mTLS client certs per agent.** Deferred: stronger but heavier UX for local MCP clients; tokens are the pragmatic first step and can coexist with certs later.

## References
- `docs/analysis/2026-05-23-reference-vault-improvements.md` § agent-native differentiators.
- `docs/analysis/2026-05-23-agentic-positioning-strategy.md` (identity as the flagged weakness).
- Vault AppRole; Bitwarden Secrets Manager machine accounts + access tokens.
