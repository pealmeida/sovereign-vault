# ADR-0009 — Broker and transit MCP tools (use secrets without exposing them)

- **Status:** Accepted
- **Date:** 2026-05-23
- **Deciders:** pealmeida

## Context

The current MCP surface is five file operations (`vault.list/read/write/delete/create_container`). For high-sensitivity secrets, even `vault.read` is wrong: it hands the plaintext secret to the agent, which then lives in the model's context and any logs. The differentiating capability (see `docs/analysis/2026-05-23-agentic-positioning-strategy.md`) is **brokering** — the vault performs the operation and returns only the *result*, so the agent never sees the key. HashiCorp Vault's `transit` engine ("encryption as a service") is the proven model.

## Decision

Add three families of MCP tools. Implement in risk order: **transit first, broker last.**

### 1. Transit (symmetric) — `vault.encrypt` / `vault.decrypt`
Named transit keys (distinct from the file DEK), generated and stored by the vault, wrapped under the active DEK in the keyring (ADR-0007). The agent passes a `key_ref` + plaintext/ciphertext; never the key. Versioned like the keyring so transit keys can rotate. Returns base64 ciphertext / plaintext.

### 2. Signing (asymmetric) — `vault.sign` / `vault.verify`
Ed25519 keys (new dep `ed25519-dalek`), generated in-vault, private half wrapped under the DEK, public half exportable. `vault.sign(key_ref, payload)` returns a signature; the agent never receives the private key. `vault.verify` is convenience (verification needs only the public key).

### 3. Brokered outbound request — `vault.broker_request` (HIGHEST RISK)
The vault makes an outbound HTTP call, injecting a stored secret (e.g. `Authorization: Bearer <secret>`), and returns the response body/status. The credential never enters the agent's context. This is the moat — and the largest attack surface.

**Mandatory security controls (none optional):**
- **Per-secret destination allowlist.** Each brokerable secret declares the exact host(s) + path prefix(es) + method(s) it may be used against. A request outside the allowlist is denied.
- **SSRF defense.** Resolve the target and **refuse private/loopback/link-local/metadata ranges** (127.0.0.0/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1, fc00::/7) unless the secret's allowlist explicitly opts in. Re-validate after DNS resolution (no rebinding).
- **Method + scheme restriction.** HTTPS only by default; method must be in the allowlist.
- **Limits.** Hard timeout, max response size, max redirects = 0 by default (follow only if allowlisted).
- **Audit + redaction.** Every brokered call is audited (agent_id, target host, method, status) with the secret value and any sensitive headers redacted.
- **Gating.** `broker_request` requires `APPROVAL` (or an explicit policy grant) — never `DIRECT`. Default-off via a config flag until the allowlist UX ships.
- **No secret echo.** The response is returned to the agent, but the injected secret and request auth headers are stripped from anything returned/logged.

### Wiring
- `sv-mcp`: extend `AccessAction` (Encrypt/Decrypt/Sign/Broker), add tool descriptors + dispatch.
- `sv-crypto`: transit encrypt/decrypt helpers; ed25519 sign/verify.
- `sv-core`: `VaultFacade` methods; transit/signing key storage in/alongside the keyring.
- desktop: approval requirements for the new actions; secret/allowlist management UI.

## Consequences

- **Positive.** Delivers the brokering moat: agents *use* secrets without holding them. Transit/sign are clean wins; broker_request is the headline differentiator.
- **Negative.** `broker_request` is a genuine SSRF/exfiltration surface; done wrong it turns the vault into a confused-deputy proxy. New key types (transit, ed25519) expand key management.
- **Mitigation.** Ship transit + sign first (no network surface). Gate `broker_request` behind the allowlist + SSRF controls above, default-off, and require APPROVAL. Pair every broker feature with negative tests (blocked private IPs, off-allowlist host, oversized response).

## Alternatives considered
- **Just return secrets via `vault.read` and trust the agent.** Rejected: that *is* the status quo we are differentiating against; the secret ends up in model context.
- **Broker without an allowlist, rely on approval prompts.** Rejected: approval fatigue + a single careless approval = SSRF. The allowlist is non-negotiable.

## References
- `docs/analysis/2026-05-23-agentic-positioning-strategy.md` § the moat: brokering.
- HashiCorp Vault `transit` secrets engine.
- Depends on [ADR-0007](0007-root-key-data-key-hierarchy.md) (keys wrapped under the DEK) and [ADR-0008](0008-per-agent-identity.md) (per-agent audit attribution for brokered calls).
