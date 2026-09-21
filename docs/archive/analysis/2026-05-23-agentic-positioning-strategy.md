# Sovereign Vault → The Agent-Native Vault: Positioning Strategy

Date: 2026-05-23
Companion to: `2026-05-23-reference-vault-improvements.md`

## The category gap (our wedge)

None of the three reference systems is agent-native:

| | Built for | Agent story | Local-first | Human-in-loop | Secrets never leave |
|---|---|---|---|---|---|
| **Vault/OpenBao** | human ops + service infra | AppRole/identity, but no MCP, no interactive approval | no (server) | no | partial (transit) |
| **Bitwarden** | humans + machine accounts | SM machine accounts + access tokens | no (cloud/self-host) | org admin approval | no (client decrypts) |
| **Sovereign Vault** | **AI agents** | **MCP-native** | **yes** | **yes (desktop approval)** | **opportunity** |

The defensible position: **the only local-first, human-in-the-loop, MCP-native vault where secrets can be *used* without being *exposed*.** Vault has the crypto-as-a-service primitive (transit) but no agent UX. Bitwarden has the E2E model but hands plaintext to the client. We can own the intersection.

## The moat: brokering, not just storage

The strongest differentiator is **secret brokering** — the agent never receives plaintext for the highest-sensitivity items. Borrow Vault's **transit ("encryption as a service")**: the vault performs the operation and returns the *result*, not the key.

New MCP tools beyond the current 5 file ops:
- `vault.sign` / `vault.verify` — sign payloads with a key the agent never sees.
- `vault.encrypt` / `vault.decrypt` — transit-style crypto-as-a-service.
- `vault.broker_request` — vault makes an outbound API call using a stored credential, returns only the response body. The API key never enters the agent's context.

This maps directly to the roadmap's hinted `ZKP`/`NATIVE` modes and is the single biggest reason an agent operator would choose us over piping a Bitwarden/Vault token into the model's context.

## Table-stakes parity (must-have to be taken seriously)

These are covered in the companion doc; restating why they gate "main solution" status:

1. **Key hierarchy (root key → data key)** — without it, no rotation; enterprises won't adopt.
2. **Dynamic / short-lived secrets** — Vault's killer feature. Issue a TTL-bound credential to an agent; auto-expires. Caps blast radius of a compromised agent. Pairs with the lease/grant work (P4).
3. **Tamper-evident audit with per-agent attribution** — autonomous action demands provenance.

## Agent-native differentiators (where we win, not just match)

1. **Agent identity, not a shared pairing secret.** Today `sv-mcp` uses one pairing secret. Give each agent a distinct identity + scoped capability grant (cf. Vault AppRole, Bitwarden machine accounts + access tokens). Enables per-agent revocation and audit attribution. **This is also a current weakness** — a single shared secret is a single point of compromise.

2. **Policy engine for graduated autonomy.** Per-request approval doesn't scale to server/CI/autonomous agents. Declarative policy: "agent X may read container Y up to N times/hour without prompting; anything else escalates to approval." Removes approval fatigue while keeping a human gate for the long tail. (Roadmap already lists a policy engine.)

3. **Headless daemon mode + async approval.** The desktop-approval model assumes a human at a Tauri window. Autonomous agents run headless. Need: (a) a headless `sv-http`/daemon, and (b) async approval routed to a phone/push so the human can approve out-of-band. Without this we're a desktop toy, not infrastructure.

4. **Multi-agent delegation.** Agent A grants a *narrower* scoped sub-grant to Agent B; revoking A cascades to B. No reference system does agent→agent delegation natively.

## Distribution / DX (how it becomes *the* default)

To win the category, adoption friction must be near zero:
- **MCP registry presence** — be the secrets/files server people install first.
- **Framework integrations** — drop-in for the major agent frameworks; one-line install.
- **SDKs** for the broker/transit tools so non-MCP agents can use it too.
- **Open + auditable** — Bitwarden's open-source + paid third-party audits is a trust template; match it. (We're already Apache-2.0.)
- **Quickstart that proves the moat in 60s**: "your agent used your Stripe key and never saw it."

## Honest tradeoffs / sequencing

Don't build all of this at once — it would dilute the wedge. Recommended focus order:

1. **Fix agent identity** (replace shared pairing secret) + the PRNG bug — security debt that undermines every other claim.
2. **Ship the broker/transit tools** — the demonstrable moat; do this *before* breadth.
3. **Key hierarchy + dynamic short-lived secrets** — enterprise table stakes.
4. **Policy engine + headless/async approval** — unlocks autonomous/server use, the largest market.
5. **Delegation, MCP-registry distribution, SDKs** — scale.

**Risk to watch:** every step toward autonomy (policy auto-approve, headless) erodes the "human-in-the-loop" guarantee that is part of our identity. Keep the human gate as the *default* and make autonomy explicitly opt-in per policy, with the audit log as the backstop.
