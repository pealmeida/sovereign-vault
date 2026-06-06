# Getting started — using Sovereign Vault with your projects

> **Status: pre-alpha (v0.0.0).** Single-user, single-machine, local-only. Schema and on-disk formats may still change. For genuinely sensitive production secrets, treat this as evaluation software: keep an independent copy of anything you store, and read the **Protect your data** section below before you rely on it.

## 1. Build and run

Prerequisites: Rust (stable, ≥1.85), Node.js + npm, and the Tauri prerequisites for your OS (WebView2 is preinstalled on Windows 10/11).

```bash
# from the repo root
cargo check --workspace        # sanity: should finish clean
cd ui && npm install && cd ..  # one-time: install UI deps

# run the desktop app (dev mode)
cargo tauri dev
# or, if the tauri CLI is not installed globally:
#   cargo install tauri-cli --version "^2"
#   cargo tauri dev
```

The desktop window is the control surface: bootstrap/unlock, manage containers and files, manage agents, and copy MCP client configs. The CLI binary (`sovereign-vault`) only provides the `mcp-stdio` proxy that agents spawn — it is not used for vault administration.

## 2. First launch — bootstrap

On first run the app initialises a vault. Choose a custody mode:

- **OS keychain** — a random key-encryption key (KEK) is stored in the platform keychain (Windows Credential Manager / macOS Keychain / Linux Secret Service). Convenient; unlock is automatic from that machine/user.
- **Passphrase** — the KEK is derived from your passphrase (Argon2id) + a stored salt. Nothing key-related is written in the clear.

A **24-word recovery phrase** is shown **once**. Write it down and store it offline. It is the independent way back into your data if you lose the passphrase or keychain entry.

## 3. Where your data lives

Everything is under the app data directory, e.g. on Windows `%APPDATA%\<app>\sovereign-vault\`:

| File | What it is | Secret? |
|---|---|---|
| `manifest.json` | container list + security-mode rules | no |
| `master.salt` | Argon2id salt (passphrase custody) | no |
| `keyring.svault` | the data-encryption key(s), wrapped under your KEK | **yes — back this up** |
| `recovery.svault` | the data key wrapped by your recovery phrase | yes |
| `agents.json` | per-agent identities (only token *hashes*) | no |
| `transit.svault` / `signing.svault` / `brokers.svault` | transit/signing keys & brokered secrets, wrapped under the data key | yes |
| `<container>/<file>.svault` | your files, XChaCha20-Poly1305 sealed | encrypted |
| `audit.jsonl` | append-only, hash-chained audit log (container/file names HMAC-redacted) | no plaintext paths |

## 4. Store secrets

Create **containers** (folders) and set a per-container security mode that governs live MCP access:

- `DIRECT` — agents read/write without prompting.
- `APPROVAL` — every protected MCP operation pops a desktop approval.
- `OTP` — approval requires typing a one-time code.

Put low-sensitivity material in `DIRECT`, real secrets in `APPROVAL`/`OTP`.

## 5. Connect your AI agents (MCP)

1. Unlock the vault (the MCP WebSocket + pairing HTTP servers start automatically on `127.0.0.1:9944` / `:9943`).
2. In **Settings → MCP server**, copy the config for Claude Desktop / Cursor / Continue.dev. It points the client at the `sovereign-vault mcp-stdio` proxy.
3. **Per-agent identity (recommended):** in **Settings → Agents**, create an agent — you get a one-time token shown once. Give each tool its own agent so you can revoke or audit it individually. Without a per-agent token, the shared pairing secret binds a single "Default" agent (back-compat).

Agents then call the MCP tools: `vault.list/read/write/delete/create_container`.

## 6. Use secrets without exposing them

For high-value secrets, do not hand the plaintext to the model. Use the brokering tools (Settings → *Transit & signing keys* / *Brokered secrets*):

- `vault.encrypt` / `vault.decrypt` — crypto-as-a-service with a named key the agent never sees.
- `vault.sign` / `vault.verify` — ed25519 signing; the private key never leaves the vault.
- `vault.broker_request` — the **vault** makes the outbound HTTPS call and injects the stored secret; the agent gets the response, never the credential.

`broker_request` is **disabled by default** and `APPROVAL`-gated. To enable it, set the environment variable `SV_ENABLE_BROKER=1` before launching, and define each brokered secret's destination **allowlist** (host + path prefix + methods). Requests off the allowlist, to private/loopback IPs, or over plain HTTP are refused.

## Protect your data (read before storing anything important)

- **Back up `keyring.svault` AND your recovery phrase, stored separately.** Losing both = permanent data loss; the encryption is real and there is no backdoor.
- **Changing the passphrase** re-wraps the keyring only (no re-encryption) and does **not** change the recovery phrase.
- **Rotating the key** (Settings → Key management) re-encrypts every file and **issues a new recovery phrase — the old one stops working.** Save the new one immediately.
- **Keep an independent copy** of any secret you cannot afford to lose while this is pre-alpha.
- The audit log is tamper-evident (hash-chained) and redacts container/file names, but it is not itself encrypted.

## Verify your build is sound

```bash
cargo test --workspace          # crypto, storage, keyring, audit, MCP, identity, broker
cd ui && npm run check          # frontend type-check
```
