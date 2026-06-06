# Architecture — Sovereign Vault

A system-level overview. For *why* decisions were made, see the ADRs in
[`docs/adr/`](./adr/); for the security boundary, see
[`threat-model.md`](./threat-model.md).

## Big picture

```
            ┌─────────────────────────────────────────────────────┐
            │  Desktop app (Tauri 2)                               │
   you ◀──▶ │  Svelte UI  ◀──Tauri commands──▶  approval state     │
            │                                     │                │
            └─────────────────────────────────────┼────────────────┘
                                                  │ in-process
                                          ┌───────▼────────┐
   MCP agent ──stdio──▶ sovereign-vault ──│   sv-core      │── files on disk
   (Claude,    mcp-stdio   (CLI proxy)  ws │  (unlocked     │   (encrypted)
    Cursor…)   │           ▲              │  VaultHandle)   │
               │           │ loopback     └───┬────┬───┬───┘
               └─pairing───┘ :9944/:9943      │    │   │
                 (sv-http)                  crypto keyring audit
```

- **Agents never talk to files.** They speak MCP to the `mcp-stdio` proxy, which
  pairs over loopback HTTP and forwards to the in-process MCP server. Every
  protected call routes through the approval/OTP gate the human controls.
- **The desktop app owns the unlocked key.** `sv-core::VaultHandle` holds the
  master key in memory only while unlocked; locking drops it and stops the servers.

## Crates (Rust workspace)

| Crate | Responsibility |
|---|---|
| `sv-crypto` | AEAD (XChaCha20-Poly1305), KDF (Argon2id), key wrap, zeroize |
| `sv-storage` | Containers, envelope format, manifest, name validation |
| `sv-keychain` | OS keychain entry (`service = "sovereign-vault"`) + passphrase fallback |
| `sv-recovery` | BIP39 24-word recovery phrase issue/verify |
| `sv-audit` | Append-only, hash-chained JSONL audit log; HMAC-hashed names |
| `sv-mcp` | MCP server (stdio + WS), tool dispatch, approval hook |
| `sv-http` | Read-only loopback HTTP: `/health`, agent card, MCP pairing |
| `sv-core` | Integration layer: custody, key hierarchy, transit/signing/broker, agents — the `VaultHandle` consumed by `apps/` |

**Apps:** `apps/cli` builds the headless `sovereign-vault` binary (including the
`mcp-stdio` proxy); `apps/desktop` is the Tauri 2 shell (Rust commands + approval
state) serving the `ui/` Svelte 5 frontend.

## Key hierarchy (ADR-0007)

```
OS keychain KEK   ─┐
   (or)            ├─ wraps ─▶  active DEK (vN)  ─ derives ─▶ subkeys
passphrase ─Argon2id┘                │                         ├─ container file sealing
                                     │                         └─ material-wrap key
                                     └─ rotation: new DEK, every container file AND
                                        every transit/signing/broker secret re-wrapped
                                        forward; a NEW recovery phrase is issued.
```

The DEK is rotatable in place. Transit keys, signing seeds, and broker secrets
are sealed under a subkey of the **active** DEK, so rotation must re-wrap them
forward (`sv-core::transit::rewrap_all_material`).

## Security modes

Per-container, inherited by files: `DIRECT` (no prompt), `APPROVAL` (desktop
confirm), `OTP` (cross-channel 6-digit code, single-use, 120s TTL).
`ANONYMIZED` / `ZKP` / `NATIVE` are reserved in the enum and rejected at runtime.

## MCP tools (9, +1 optional)

`vault.list` / `read` / `write` / `delete` / `create_container`, plus transit
`encrypt` / `decrypt` / `sign` / `verify`. `vault.broker_request` appears only
when `SV_ENABLE_BROKER=1`. Approval gating per tool/mode is documented in
[`testing/mcp-test-cases.md`](./testing/mcp-test-cases.md).

## On-disk layout

The vault root lives under the OS app-data dir for the desktop app
(`~/Library/Application Support/<bundle-id>/sovereign-vault` on macOS):

```
manifest.json     schema version, default mode, rules
keyring.svault    wrapped DEK(s)
recovery.svault   recovery-phrase verifier
transit.svault    wrapped transit keys
signing.svault    wrapped signing seeds
agents.json       agent registry (token hashes, scopes)
audit.jsonl       append-only, hash-chained log (HMAC-hashed names)
<container>/…     per-container encrypted file envelopes
```

Container/file **contents and names on disk are encrypted**; the audit log
records HMAC hashes of names, not plaintext.

## Request lifecycle (an APPROVAL read)

1. Agent → `mcp-stdio` proxy → pairs via `sv-http` loopback secret → MCP server.
2. Server resolves the agent's scope, sees the container is `APPROVAL`, and
   raises a desktop approval request (`vault://approval-request`).
3. The human clicks **Approve** (or **Deny**) in the global modal.
4. On approve, `sv-core` decrypts the file and returns base64 content; the call
   is recorded in the audit log with the agent id. Deny → `isError`.
