# Sovereign Vault — End-to-End Test Plan

Status: living document · Owner: pealmeida · Last updated: 2026-05-25

## 1. Purpose & scope

Validate that Sovereign Vault works for its real job: an AI agent stores and uses a user's secrets (project `.env` files, financial data, personal notes) **without the user losing data and without the agent ever seeing more than it should**. Scope covers the full stack end to end — crypto → storage → keyring → custody → MCP server → `mcp-stdio` proxy → desktop UI — exercised the way a real user and a real MCP client (Claude Desktop / Cursor) drive it.

Out of scope: load/perf, multi-machine sync, mobile.

## 2. Golden rule for test data

**Use clearly-fake secrets only** (e.g. `sk-test-FAKE-…`, `postgres://user:fakepw@…`). Never put real credentials or real financial data into a test run. The agent driving the tests must not type the user's real passphrase or financial data — those are entered by the human.

## 3. Test layers

| Layer | Driver | What it proves | Where |
|---|---|---|---|
| **L1 Unit/integration** | `cargo test --workspace` | crypto, keyring, rotation, migration, audit chain/HMAC, agent registry, broker validation | repo |
| **L2 MCP simulation** | `scripts/e2e_mcp_usage.sh` → real `mcp-stdio` proxy → live vault | the exact agent path: pair → tools/call write/read/encrypt over WS | live, vault unlocked |
| **L3 Desktop GUI** | computer-use against installed app | bootstrap/unlock, container modes, file view, agents, transit/signing, approvals | live install |
| **L4 Lifecycle/ops** | mixed | passphrase change, key rotation, recovery, backup/restore, migration of an old vault | live |

## 4. Preconditions

- Build the **production** bundle with `cargo tauri build` (a plain `cargo build` produces a dev-mode exe that loads `devUrl` and shows a blank "can't reach localhost:1420" page — do not test that binary). Install the NSIS output (per-user, no UAC).
- Launch + unlock (OS keychain = one click; passphrase = human types it).
- For L2, the vault must be **unlocked** (MCP servers start on `127.0.0.1:9944`/`:9943` only after unlock).
- For broker cases, launch with `SV_ENABLE_BROKER=1`.

## 5. Realistic usage scenarios (happy path)

### S1 — Project `.env` storage (developer persona)
1. Create container `env-webapp`, mode **APPROVAL**.
2. Store a fake `.env` (via UI import or MCP `vault.write`). *Note: vault rejects leading-dot names; store as `webapp.env`.*
3. Read it back → exact plaintext round-trips.
4. **Expected:** ciphertext on disk contains no plaintext; UI view shows the fake values; APPROVAL prompts on MCP read.

### S2 — Financial data (privacy persona)
1. Container `finance`, mode **OTP**.
2. Store a fake statement/file (human enters real data only outside tests).
3. **No agent is scoped to `finance`.**
4. **Expected:** no MCP client can read `finance`; UI read by the human works; OTP gate fires for any MCP access.

### S3 — Personal sensitive notes
1. Container `personal`, mode **APPROVAL** or **OTP**. Store/read fake note. Same gating expectations as S1/S2.

### S4 — Use a secret without exposing it (the moat)
1. Create transit key `demo-key`; `vault.encrypt` then `vault.decrypt` round-trips — agent never receives the key.
2. Create signing key; `vault.sign` → `vault.verify` true; private key never returned.
3. (broker on) define a brokered secret with a host allowlist; `vault.broker_request` returns the response, never the secret.

## 6. Negative / security cases (must FAIL closed)

| ID | Case | Expected |
|---|---|---|
| N1 | MCP client pairs with wrong/expired/revoked token | rejected ("Unpaired"/denied) |
| N2 | Agent reads a container outside its scope | denied |
| N3 | Agent action exceeds scope `mode_ceiling` | denied (scope only narrows) |
| N4 | `broker_request` to off-allowlist host | denied |
| N5 | `broker_request` to private/loopback/link-local IP (v4+v6) | denied unless opted in |
| N6 | `broker_request` over plain HTTP / disallowed method | denied |
| N7 | `broker_request` while `SV_ENABLE_BROKER` unset | "broker disabled"; tool absent from `tools/list` |
| N8 | Oversized broker response (advertised or streamed) | rejected at the cap, no unbounded buffering |
| N9 | Tamper with / delete an `audit.jsonl` line | `verify_chain` reports the broken index |
| N10 | Inspect `audit.jsonl` | container/file names are HMAC hashes, not plaintext |
| N11 | Decrypt a file with a stale/wrong DEK version | fails (AEAD) |

## 7. Lifecycle & ops

| ID | Flow | Expected |
|---|---|---|
| L-1 | Bootstrap (keychain & passphrase) | recovery phrase shown once; keyring created |
| L-2 | **Migration** of a pre-keyring vault | opens on first unlock, zero re-encryption, old files read |
| L-3 | Change passphrase | data unchanged, recovery phrase unchanged, old passphrase rejected |
| L-4 | Rotate key | every file re-encrypts forward; **new** recovery phrase issued; old phrase stops working |
| L-5 | Recovery unlock | post-bootstrap and post-rotation phrases each open the vault |
| L-6 | **Backup/restore** | copy `keyring.svault` + recovery phrase offline; restore on a fresh profile and unlock |
| L-7 | Relaunch | shared-secret MCP pairing still works after multiple launches (Default-agent token refresh) |

## 8. Pass criteria

- L1: `cargo test --workspace` green; `cd ui && npm run check` 0 errors.
- L2: `scripts/e2e_mcp_usage.sh` pairs and returns successful results for create/write/read/encrypt; read round-trips the written plaintext.
- L3: each S/N row observed in the UI as specified.
- L4: each lifecycle row passes; **no data loss** at any step.

## 9. Known limitations / findings (track to closure)

1. **Leading-dot filenames rejected** — cannot store a file literally named `.env`; must use `webapp.env`. *Decide: allow dotfiles or document the convention.*
2. **Default-agent token refresh** — fixed (commit `e13cb5e`); without it, shared-secret pairing broke on the 2nd+ launch. Covered by `ensure_default_refreshes_token_on_relaunch`.
3. **Dev vs prod build** — only `cargo tauri build` produces a UI-baked exe; document so testers don't run the dev-mode binary.
4. **GUI automation needs an installed app** — computer-use can't grant an unregistered `target\debug` exe; install first.
5. **`record_desktop_event` (UI-origin audit)** still plaintext (not HMAC-keyed) — follow-up.
6. **Broker UI** — multi-allow-entry editing, custom-header injection, key rotate/delete not yet wired.

## 10. Traceability

- Key hierarchy / rotation / migration → ADR-0007.
- Per-agent identity / pairing → ADR-0008.
- Transit / signing / broker → ADR-0009.
- Operational how-to for real data → `docs/GETTING_STARTED.md`.
- Automated proofs → `crates/*/src/**` tests, `crates/sv-core/tests/{keyring_flows,mcp_e2e}.rs`.
