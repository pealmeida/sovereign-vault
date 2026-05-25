# MCP Test Cases — detailed

Companion to `e2e-test-plan.md`. These are the concrete, repeatable MCP-layer cases: exact JSON-RPC frames, preconditions, expected results, and approval behaviour. They exercise the **real** path a client (Claude Desktop / Cursor) uses — the `sovereign-vault mcp-stdio` proxy → `ws://127.0.0.1:9944`.

## How to run

Vault must be **unlocked** (servers bind only after unlock). The proxy auto-fetches the per-launch pairing secret from `http://127.0.0.1:9943/.well-known/mcp-pairing` and pairs the built-in **Default** agent.

```bash
{ printf '%s\n' '<frame1>' '<frame2>'; sleep 4; } | target/release/sovereign-vault.exe mcp-stdio
```

The trailing `sleep` keeps stdin open so responses flush before EOF. `scripts/e2e_mcp_usage.sh` wraps the happy path.

> **Approval-gated calls block.** Any tool that needs desktop approval will not return until a human approves in the UI — a scripted run without approval appears to "hang" then closes with no response. Run those interactively (see TC-APPROVE).

## Approval matrix (DIRECT container, Default agent)

| Tool | DIRECT | APPROVAL | OTP |
|---|---|---|---|
| `vault.read` / `vault.write` / `vault.delete` | no prompt | prompt | OTP prompt |
| `vault.list` / `vault.create_container` | **prompt** | prompt | OTP prompt |
| `vault.encrypt` / `vault.decrypt` / `vault.sign` | prompt | prompt | OTP prompt |
| `vault.verify` | none | none | none |
| `vault.broker_request` | always prompt (and default-OFF) | | |

## Pairing

| ID | Frame / action | Expected |
|---|---|---|
| TC-PAIR-1 | proxy pairs with current secret | `{"result":{"paired":true,...}}`; tool calls proceed |
| TC-PAIR-2 | pair with a wrong/old secret | `{"error":{"code":-32001,"message":"Unpaired connection"}}` |
| TC-PAIR-3 | relaunch vault, re-pair with new per-launch secret | succeeds (Default-agent token is refreshed each launch — regression guarded by `ensure_default_refreshes_token_on_relaunch`) |
| TC-PAIR-4 | per-agent token (from Settings → Agents) | pairs, binds that `agent_id`; revoked token rejected |

## Core data path (no approval — DIRECT container)

**Precondition:** a DIRECT container exists (e.g. `claude-test`).

- **TC-RW-1 write**
  `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault.write","arguments":{"container":"claude-test","file_name":"probe.env","content_b64":"<b64>"}}}`
  → `{"result":{"content":[{"text":"{\"byte_size\":N,\"ok\":true}"}],"isError":false}}`
- **TC-RW-2 read** (same args minus content)
  → `content_b64` equals what was written. **VERIFIED 2026-05-25:** wrote a fake `.env`, read returned the identical base64. ✅
- **TC-RW-3 on-disk check** — the `<container>/<file>.svault` blob contains no plaintext.
- **TC-RW-4** read a missing file → `isError:true`, "not found".
- **TC-RW-5** invalid name (leading dot `.env`, `..`, slash) → rejected by validation. *Known: leading-dot names are rejected; store `webapp.env`.*

## Tool discovery

- **TC-LIST-1** `tools/list` → returns `vault.list/read/write/delete/create_container` + `vault.encrypt/decrypt/sign/verify`. **VERIFIED.** `vault.broker_request` is **absent** unless `SV_ENABLE_BROKER=1`. ✅

## Transit & signing (approval-gated)

- **TC-TR-1** `vault.encrypt {key_ref:"demo-key", plaintext_b64}` → approve → base64 ciphertext; key never in response.
- **TC-TR-2** `vault.decrypt` with same `key_ref` → approve → original plaintext.
- **TC-SI-1** `vault.sign {key_ref, payload_b64}` → approve → `{signature_b64, public_key_b64}`; private key never returned.
- **TC-SI-2** `vault.verify {public_key_b64, payload_b64, signature_b64}` → no approval → `true`; tamper payload → `false`.

## Broker (default-OFF; launch with `SV_ENABLE_BROKER=1`)

- **TC-BR-1** disabled → tool absent from `tools/list`; calling returns "broker disabled". **VERIFIED disabled state.** ✅
- **TC-BR-2** enabled + on-allowlist host → approve → sanitized response; secret/auth headers never returned.
- **TC-BR-3** off-allowlist host → denied.
- **TC-BR-4** private/loopback/link-local target (v4+v6) → denied unless opted in.
- **TC-BR-5** plain HTTP or disallowed method → denied.
- **TC-BR-6** oversized response (advertised `Content-Length` or streamed) → rejected at the 1 MiB cap.

## Human-in-the-loop

- **TC-APPROVE** run `vault.list` (DIRECT) via the proxy in the background; the desktop shows an approval prompt; approve → list returns; deny → `isError`.
  > **Root cause found + fixed (commit `87c8ff8`), pending live re-verify:** the approval event reached nothing — frontend listened for `mcp-approval` vs backend `vault://approval-request`, and the modal lived only in FilesPage. Now listened correctly and hosted globally in App.svelte. Re-run this case after deploying the rebuilt app.

## Scopes (per-agent token)

- **TC-SCOPE-1** agent scoped to `env-*` reads `env-webapp` → allowed; reads `finance` → denied.
- **TC-SCOPE-2** scope `mode_ceiling` cannot widen a container's mode (DIRECT scope on an OTP container still requires OTP).

## Audit assertions (after a run)

- **TC-AUD-1** `audit.jsonl` gains one line per operation with `agent_id` set.
- **TC-AUD-2** container/file names are HMAC hex, not plaintext.
- **TC-AUD-3** `verify_chain` passes; editing any line breaks it at that index.
