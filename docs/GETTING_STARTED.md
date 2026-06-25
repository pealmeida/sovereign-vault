# Getting started - using Sovereign Vault with your projects

> **Status: pre-alpha (v0.0.0).** Single-user, single-machine, local-only. Schema and on-disk formats may still change. For genuinely sensitive production secrets, treat this as evaluation software: keep an independent copy of anything you store, and read the **Protect your data** section below before you rely on it.

## 1. Build and run

Prerequisites: Rust stable (>= 1.88), Node.js + npm, and the Tauri prerequisites for your OS (WebView2 is preinstalled on Windows 10/11).

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

The desktop window is the control surface: bootstrap/unlock, manage containers and files, manage agents, and copy MCP client configs. The CLI binary (`sovereign-vault`) provides the `mcp-stdio` proxy plus `agents print/install/list-targets` for generated command packs; vault administration still lives in the desktop app.

## 2. First launch - bootstrap

On first run the app initializes a vault. Choose a custody mode:

- **OS keychain** - a random key-encryption key (KEK) is stored in the platform keychain (Windows Credential Manager / macOS Keychain / Linux Secret Service). Convenient; unlock is automatic from that machine/user.
- **Passphrase** - the KEK is derived from your passphrase (Argon2id) plus a stored salt. Nothing key-related is written in the clear.

A **24-word recovery phrase** is shown **once**. Write it down and store it offline. It is the independent way back into your data if you lose the passphrase or keychain entry.

## 3. Where your data lives

Everything is under the app data directory, for example on Windows `%APPDATA%\<app>\sovereign-vault\`:

| File | What it is | Secret? |
|---|---|---|
| `manifest.json` | container list + security-mode rules | no |
| `master.salt` | Argon2id salt (passphrase custody) | no |
| `keyring.svault` | the data-encryption key(s), wrapped under your KEK | **yes - back this up** |
| `recovery.svault` | the data key wrapped by your recovery phrase | yes |
| `agents.json` | per-agent identities (only token hashes) | no |
| `transit.svault` / `signing.svault` / `brokers.svault` | transit/signing keys and brokered secrets, wrapped under the data key | yes |
| `<container>/<file>.svault` | your files, XChaCha20-Poly1305 sealed | encrypted |
| `audit.jsonl` | append-only, hash-chained audit log (container/file names HMAC-redacted) | no plaintext paths |

## 4. Store secrets

Create **containers** (folders) and set a per-container security mode that governs live MCP access:

- `DIRECT` - agents read/write without prompting.
- `APPROVAL` - every protected MCP operation pops a desktop approval.
- `OTP` - approval requires typing a one-time code.

Put low-sensitivity material in `DIRECT`, real secrets in `APPROVAL` or `OTP`.

## 5. Connect your AI agents (MCP)

1. Unlock the vault. The MCP WebSocket and pairing HTTP servers start automatically on `127.0.0.1:9944` and `127.0.0.1:9943`.
2. In **Settings -> MCP server**, copy the config for Claude Desktop / Cursor / Continue.dev. It points the client at the `sovereign-vault mcp-stdio` proxy.
3. In **Settings -> Agents**, create a dedicated agent when you want scoped attribution and revocation.
4. Set `SV_AGENT_ID=<agent id>` and `SV_PAIRING_TOKEN=<token>` in that client's environment for scoped pairing. Without those vars, `mcp-stdio` falls back to the shared per-launch secret and binds the Default agent.
5. Install a generated command pack when the client supports slash-command or skill files:

```bash
sovereign-vault agents list-targets
sovereign-vault agents install --target claude-code
sovereign-vault agents install --target codex
```

Agents then call the MCP tools for file access, transit/signing key management, encryption/decryption, signing/verification, and optionally broker-secret creation plus `vault.broker_request`.

## 6. Use secrets without exposing them

For high-value secrets, do not hand plaintext to the model. Use the brokering tools instead:

- `vault.create_transit_key`, `vault.list_transit_keys`, `vault.encrypt`, and `vault.decrypt` for crypto-as-a-service with a named key the agent never sees.
- `vault.create_signing_key`, `vault.list_signing_keys`, `vault.sign`, and `vault.verify` for Ed25519 signing where the private key never leaves the vault.
- `vault.create_broker_secret`, `vault.list_broker_secrets`, and `vault.broker_request` so the **vault** injects the stored credential and the agent receives only the response.

Broker features are **disabled by default** and approval-gated. To enable them, set `SV_ENABLE_BROKER=1` before launching and define each brokered secret's destination allowlist (host + path prefix + methods). Requests off the allowlist, to private/loopback IPs, or over plain HTTP are refused.

## Protect your data

- **Back up `keyring.svault` and your recovery phrase, stored separately.** Losing both means permanent data loss.
- **Changing the passphrase** re-wraps the keyring only. It does not change the recovery phrase.
- **Rotating the key** re-encrypts every file and issues a new recovery phrase. The old one stops working.
- **Keep an independent copy** of any secret you cannot afford to lose while this is pre-alpha.
- The audit log is tamper-evident (hash-chained) and redacts container/file names, but it is not itself encrypted.

## Verify your build is sound

```bash
cargo test --workspace
cd ui && npm run check
```
