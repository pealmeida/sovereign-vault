# Sovereign Vault — User Guide

The complete reference for installing, configuring, and using Sovereign Vault as an
agentic secrets vault. Covers every feature, configuration option, CLI command, MCP
tool, security mode, and integration pattern.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Installation & Build](#3-installation--build)
4. [First-Time Setup & Custody](#4-first-time-setup--custody)
5. [Containers & Security Modes](#5-containers--security-modes)
6. [MCP Integration](#6-mcp-integration)
7. [Agents & Scopes](#7-agents--scopes)
8. [Audit Log](#8-audit-log)
9. [Recovery](#9-recovery)
10. [CLI Reference](#10-cli-reference)
11. [Desktop App](#11-desktop-app)
12. [Client Loaders (sv-secrets)](#12-client-loaders-sv-secrets)
13. [Configuration Reference](#13-configuration-reference)
14. [Agentic Patterns](#14-agentic-patterns)
15. [Troubleshooting](#15-troubleshooting)
16. [Best Agentic Vault Tool — Gaps & Improvements](#16-best-agentic-vault-tool--gaps--improvements)

---

## 1. Overview

Sovereign Vault is a **local-first, human-in-the-loop secrets vault** built for AI
agents. It exposes secrets to MCP-aware agents (Claude, Cursor, Continue, Codex,
or any MCP client) while keeping custody with the user: every protected operation
requires explicit human approval on the desktop, and every access is written to a
tamper-evident audit log.

**Design principles:**

- **Local-first** — no cloud, no remote sync. The vault root lives on your machine
  under the OS app-data directory.
- **Human-in-the-loop** — agents *ask*; you *decide*. APPROVAL/OTP containers
  raise a desktop prompt for every access.
- **MCP-native** — secrets are accessed via the [Model Context Protocol](https://modelcontextprotocol.io),
  the standard for tool use by LLMs.
- **Use without exposing** — transit encrypt/decrypt/sign and the optional broker
  let an agent *use* a key without receiving its bytes.
- **Scoped agent identities** — each agent gets its own token and capability scope.
- **Tamper-evident audit** — the log is append-only, MAC-authenticated JSONL.
  Tampering breaks the chain.

**Thesis context:** Sovereign Vault is the reference implementation (Design Science
Research instantiation) of an MBA thesis (USP/ICMC, 2026) on data sovereignty for
personal AI agents. See `docs/thesis/oliveira-2026-soberania-de-dados-agentes-ia.pdf`.

---

## 2. Architecture

**Crate map** (`crates/`):

| Crate | Purpose |
|---|---|
| `sv-crypto` | AEAD (XChaCha20-Poly1305), KDF (Argon2id), key wrap, zeroize |
| `sv-storage` | Containers, envelope format, manifest, name validation, HMAC integrity |
| `sv-keychain` | OS keychain abstraction (Secret Service / macOS Keychain / Windows Credential Manager) |
| `sv-recovery` | BIP39 24-word recovery phrase provider |
| `sv-audit` | Append-only, MAC-authenticated JSONL audit log with checkpoints |
| `sv-privacy` | PII detection & masking (email, phone, credit-card, SSN, CPF, CNPJ) |
| `sv-mcp` | MCP server (stdio + WebSocket), tool dispatch, approval hook, scope enforcement |
| `sv-http` | Loopback HTTP health/pairing surface |
| `sv-core` | Integration crate consumed by apps (`VaultHandle`, custody, keyring) |

**Apps** (`apps/`):

| App | Purpose |
|---|---|
| `desktop` | Tauri 2 app (Rust commands + approval state + Svelte UI) |
| `cli` | Headless `sovereign-vault` binary (`mcp-stdio`, `agents`) |
| `thesis-eval` | DSR evaluation harness (`latency`, `micro`, `adversarial`) |

**Surfaces** (`clients/`):

- **Node**: `sv-secrets.mjs` — dependency-free, auto-fallback loader
- **Python**: `sv_secrets.py` — stdlib only (Python ≥3.8)
- **Shell**: `sv-secrets.sh` — wraps the Node loader by default

---

## 3. Installation & Build

### Prerequisites

- **Rust** ≥ 1.88 (stable)
- **Node.js** ≥ 20
- **Tauri 2 platform dependencies** — see <https://tauri.app/start/prerequisites/>
  - Linux: `webkit2gtk-4.1`, `libsoup-3.0`, `libayatana-appindicator3`, etc.
- **Tauri CLI**: `cargo install tauri-cli --version "^2.0.0"`

### Build from source

```bash
git clone https://github.com/pealmeida/sovereign-vault.git
cd sovereign-vault

# Verify
cargo check --workspace

# Install UI deps
( cd ui && npm install )

# Build the Tauri desktop bundle (embeds dist/)
( cd ui && npm run build )
cargo tauri build
```

**Build the desktop app with `cargo tauri build`, not plain `cargo build`.** A plain
`cargo build --release` binary loads the dev-server URL and shows a connection error.
If you must skip the Tauri CLI, build the UI first and add
`--features sovereign-vault-desktop/custom-protocol`.

**Note:** `cargo tauri build` does not accept `--manifest-path` in tauri-cli ≥2.11.
Run it with `workdir = apps/desktop/src-tauri` (it discovers `tauri.conf.json` from cwd).

### Artifacts

Build outputs land under `target/release/`:

- `target/release/sovereign-vault` — CLI binary
- `target/release/sovereign-vault-desktop` — Tauri desktop binary (custom-protocol, embedded UI)
- `target/release/bundle/` — installer bundles:
  - `deb/Sovereign Vault_0.1.0_amd64.deb`
  - `rpm/Sovereign Vault-0.1.0-1.x86_64.rpm`
  - `appimage/Sovereign Vault_0.1.0_amd64.AppImage`

### macOS Gatekeeper

macOS may block the unsigned bundle. Clear the quarantine flag:

```bash
xattr -dr com.apple.quarantine "target/release/bundle/macos/Sovereign Vault.app"
```

---

## 4. First-Time Setup & Custody

On first launch the desktop app presents a setup wizard. You choose a **custody
mode** that governs how the master key (KEK) is stored:

| Mode | Where the KEK lives | Unlock per session | Recovery |
|---|---|---|---|
| **OS Keychain** | OS keyring (Secret Service / macOS Keychain / Windows Credential Manager) | OS prompts on access (if keyring locked); otherwise silent | 24-word BIP39 phrase |
| **Passphrase** | Derived from your passphrase via Argon2id | **Passphrase prompt every unlock** | 24-word BIP39 phrase |
| **Recovery** | Derived from BIP39 phrase | BIP39 phrase prompt | N/A (it's the recovery) |

**Recommendation:** OS Keychain for convenience; Passphrase if you want a per-unlock
password challenge. Recovery is used only to restore access when the primary
custody is lost.

The setup wizard generates a **24-word BIP39 recovery phrase** and shows it **once**.
Write it down offline. It's your only recovery path if keychain access or the
passphrase is lost.

After setup, the vault root is created at:

- Linux: `~/.local/share/com.sovereignvault.desktop/sovereign-vault/`
- macOS: `~/Library/Application Support/com.sovereignvault.desktop/sovereign-vault/`
- Windows: `%APPDATA%\com.sovereignvault.desktop\sovereign-vault\`

---

## 5. Containers & Security Modes

A **container** is a named directory inside the vault root holding encrypted files.
The container's **security mode** determines how the gateway mediates access.

### Modes

| Mode | Behavior | Use case |
|---|---|---|
| `DIRECT` | No prompt. Reads/writes are silent. | Working data, non-sensitive |
| `APPROVAL` | Every access raises a desktop modal (Approve / Deny) | Daily-use secrets |
| `OTP` | Cross-channel: desktop shows a 6-digit code; agent resends with `otp=<code>`. Single-use, 120s TTL | Irreversible/regulated data |
| `ANONYMIZED` | Reads return content with PII masked (email, phone, credit-card, SSN, CPF, CNPJ). Binary content passes through unscanned | Sensitive content that the agent can analyse but not see |
| `ZKP` | **Reserved.** Rejected at runtime. | Future |
| `NATIVE` | **Reserved.** Rejected at runtime. | Future |

### Rules / patterns

The manifest (`manifest.json`) stores an ordered list of rules that override the
default mode for matching containers:

```json
{
  "schemaVersion": 1,
  "defaultMode": "DIRECT",
  "integrity": { "version": 1, "hmacSha256": "..." },
  "rules": [
    { "pattern": "secrets-cloud/**", "mode": "APPROVAL", "description": "Cloud-provider keys" },
    { "pattern": "personal-id/**",    "mode": "OTP",      "description": "IDs and recovery codes" }
  ]
}
```

A `pattern` is a glob matched against `<container>/<file>`. The most specific rule
wins.

### Container creation

Containers are created via the **desktop app** (Vault → New container), or via MCP
with `vault.create_container` (requires desktop approval — container creation always
prompts, regardless of the container's mode).

---

## 6. MCP Integration

### Architecture

```
Agent (MCP client)
   │  JSON-RPC over stdio (e.g. mcp-stdio proxy)
   ▼
sovereign-vault mcp-stdio   ──┐
                              │  WebSocket
                              ▼
              sv-mcp::McpServer (binds 127.0.0.1:9944)
                              │
                              ▼
                 sv-core::VaultHandle
```

The desktop app starts the **MCP WebSocket server** on `ws://127.0.0.1:9944` and a
**loopback HTTP pairing endpoint** on `http://127.0.0.1:9943/.well-known/mcp-pairing`
when the vault is unlocked.

### mcp-stdio proxy

Clients that prefer stdio (e.g. Claude Desktop, Cursor, opencode) use the bundled
proxy:

```bash
sovereign-vault mcp-stdio
```

The proxy connects to the WebSocket gateway, auto-fetches the per-launch pairing
secret, and bridges stdio JSON-RPC ↔ WebSocket.

### Pairing handshake

On connect, the client calls `vault.pair`:

- **Default agent** (shared-secret): `vault.pair` with no args, or with the current
  per-launch pairing secret from the desktop.
- **Scoped agent**: `vault.pair { agent_id, token }` with the one-time token from the
  desktop (Settings → Agents → New agent).

### Headless systemd gateway

`sovereign-vault serve` never creates or accepts the shared Default-agent pairing
secret. Before installing `apps/cli/systemd/sovereign-vault.serve.service`, create a
dedicated agent with at least one concrete scope in **Settings → Agents** and save its
one-time token. Provision the service credentials for the user that runs the unit:

```bash
install -d -m 0700 ~/.config/sovereign-vault
install -m 0600 /dev/null ~/.config/sovereign-vault/agent.token
# Paste only the scoped agent's one-time token into ~/.config/sovereign-vault/agent.token.
install -m 0600 /dev/null ~/.config/sovereign-vault/serve.env
```

Set the following two lines in `~/.config/sovereign-vault/serve.env` (with no quotes):

```text
SV_AGENT_ID=ag_...
SV_AGENT_TOKEN_FILE=/home/your-user/.config/sovereign-vault/agent.token
```

The shipped unit loads this owner-only environment file and refuses to start without
both values. It does not print a pairing secret to the journal.

### MCP tools (15)

| Tool | Arguments | Mode gating |
|---|---|---|
| `vault.info` | `{}` | Always available to authenticated agents (global) |
| `vault.list` | `{container?}` | Lists files in a container (or all containers if omitted). Global listing → approval prompt. Per-container → follows container mode. |
| `vault.read` | `{container, file_name}` | DIRECT: silent. APPROVAL/OTP: prompt. ANONYMIZED: PII-masked. |
| `vault.write` | `{container, file_name, content_b64}` | Same mode gating as read. |
| `vault.delete` | `{container, file_name}` | Same. |
| `vault.create_container` | `{name, mode, description?}` | **Always prompts** (creation is a policy decision). `otp` field for OTP-mode containers. |
| `vault.destroy` | `{name}` | Irreversible. Prompts for APPROVAL/OTP. |
| `vault.create_transit_key` | `{key_ref, algorithm?}` | Transit key creation → approval. |
| `vault.list_transit_keys` | `{}` | Global → approval. |
| `vault.encrypt` | `{key_ref, plaintext_b64, aad?}` | Transit → approval. |
| `vault.decrypt` | `{key_ref, ciphertext_b64, aad?}` | Transit → approval. |
| `vault.create_signing_key` | `{key_ref, algorithm?}` | Approval. |
| `vault.list_signing_keys` | `{}` | Global → approval. |
| `vault.sign` | `{key_ref, message_b64}` | Approval. |
| `vault.verify` | `{key_ref, message_b64, signature_b64}` | Approval. |
| `vault.broker_request` | `{secret_ref, request_payload}` | Off by default; enable with `SV_ENABLE_BROKER=1`. Approval. |
| `vault.create_broker_secret` | `{name, ...}` | Off by default. Approval. |
| `vault.list_broker_secrets` | `{}` | Off by default. Global → approval. |

(Read/write/delete/list on a specific DIRECT container are promptless. Transit,
signing, broker, global listing, and container creation always prompt.)

---

## 7. Agents & Scopes

### Agents

Every MCP caller authenticates as an **agent**. The agents registry (`agents.json`)
is MAC-authenticated (schema 2). Each agent has:

- `agent_id` — opaque identifier
- `name` — human-readable
- `token_hash` — Argon2-derived hash of the one-time token (token never stored plaintext)
- `scopes` — list of `{pattern, actions}`
- `revoked` — boolean

### Default agent

A built-in "Default" agent exists. Its token tracks the **per-launch pairing secret**
generated by the desktop when the gateway starts. This enables shared-secret pairing
without minting a scoped agent. Clients using only `SV_PAIRING_TOKEN` (no
`SV_AGENT_ID`) fall back to the Default agent.

### Scoped agents

Mint in **Settings → Agents → New agent** in the desktop. The one-time token is
shown exactly once. Set `SV_AGENT_ID` and `SV_PAIRING_TOKEN` in the client's env.

Scopes are glob patterns over `<container>/<file>` with allowed actions
(`read`, `list`, `write`, `delete`, `destroy`, `transit`, `signing`, `broker`).
An unscoped agent has the full surface, still subject to mode-mediated prompts.

### Revocation

Revoke from the desktop (Agents panel). The token hash is marked revoked; subsequent
`vault.pair` with that token is rejected.

---

## 8. Audit Log

The audit log (`audit.jsonl` at the vault root) records every action. Each record:

```json
{
  "format_version": 1,
  "sequence": 42,
  "prev_mac": "...",
  "event": {
    "timestamp": "2026-07-31T...",
    "action": "ReadFile",
    "decision": "Allowed",
    "transport": "desktop-ui" | "mcp-ws",
    "container": "env-myproject",
    "file_name": ".env",
    "mode": "APPROVAL",
    "byte_size": 1024,
    "detail": "approved via desktop modal",
    "error": null,
    "agent_id": "ag_..."
  },
  "mac": "..."
}
```

**Key properties:**

- **MAC-authenticated chain** — each record's `mac` is HMAC-SHA256 over
  `(format_version, sequence, prev_mac, event)`, keyed by the vault's audit key.
  `prev_mac` links to the previous record's `mac`. Tampering breaks the chain.
- **Checkpoint** (`audit.head.json`) — an independently authenticated snapshot of
  the chain head (`head_mac` + `record_count`). Detects selective modification or
  deletion relative to the checkpoint.
- **Vault root detection** — `first_audit_artifact` distinguishes "fresh vault" from
  "legacy vault missing checkpoint."
- **Sensitive path redaction** — file paths in events are HMAC-redacted on disk
  by default (sv-audit `with_hmac_key`).

**Action enum** (snake_case): `VaultInit`, `VaultUnlock`, `VaultUnlockRecovery`,
`VaultLock`, `RecoveryIssued`, `PassphraseChanged`, `KeyRotated`, `ListContainers`,
`ListFiles`, `ReadFile`, `WriteFile`, `DeleteFile`, `CreateContainer`,
`DeleteContainer`, `AgentCreate`, `AgentList`, `AgentRevoke`, `CreateTransitKey`,
`ListTransitKeys`, `Encrypt`, `Decrypt`, `CreateSigningKey`, `ListSigningKeys`,
`Sign`, `Verify`, `CreateBrokerSecret`, `ListBrokerSecrets`, `Broker`, `VaultInfo`.

**Decision enum:** `attempted`, `allowed`, `denied`, `error`.

---

## 9. Recovery

A **24-word BIP39 phrase** is generated at first launch and shown once. It restores
the active DEK directly, independent of the KEK (passphrase or keychain), so it
works even if primary custody is lost.

**Unlock with recovery:**

In the desktop app's unlock screen, choose "Unlock with recovery phrase" and enter
the 24 words.

Programmatically: `VaultHandle::unlock_with_recovery(root, phrase)`.

Recovery is **read-only** for some operations: it restores the DEK but does not
re-create keychain entries. After unlocking with recovery, you may want to
re-bootstrap keychain custody.

---

## 10. CLI Reference

```
sovereign-vault [COMMAND]

Commands:
  mcp-stdio       Run a stdio→WebSocket MCP proxy targeting the local vault
  agents          Print or install agent command packs and skills
  help            Print help
  -V, --version   Print version
```

### `mcp-stdio`

No flags. Connects to the local vault gateway (`ws://127.0.0.1:9944`) and bridges
stdio JSON-RPC. The vault must be unlocked.

### `agents`

```
sovereign-vault agents <SUBCOMMAND>

Subcommands:
  print       --target <TARGET>            Print the rendered command pack to stdout
  install     --target <TARGET>            Install into the target's default path
               [--dir <DIR>]               Override install directory
               [--force]                   Overwrite existing file
  list-targets                              List supported targets and their default paths
```

**Targets:** `claude-code`, `opencode`, `hermes`, `codex`, `generic`.

These render command packs (slash-command files for Claude/Hermes/Codex) that
dispatch into the `sovereign-vault` MCP server. Install once per project or per
agent runtime.

---

## 11. Desktop App

The Tauri 2 app (Rust commands + Svelte UI). Launch with:

```bash
./target/release/sovereign-vault-desktop
# or use the bundled AppImage/deb
```

### Tauri commands (internal, called from the UI)

`app_version`, `vault_status`, `vault_init`, `vault_unlock`, `vault_unlock_recovery`,
`vault_lock`, `vault_change_passphrase`, `vault_rotate_key`, `vault_list_containers`,
`vault_create_container`, `vault_delete_container`, `vault_list_files`,
`vault_write_file`, `vault_read_file`, `vault_delete_file`, `approval_respond`,
`mcp_status`, `agent_create`, `agent_list`, `agent_revoke`, `transit_create_key`,
`transit_list_keys`, `signing_create_key`, `signing_list_keys`,
`broker_create_secret`, `broker_list_secrets`, `broker_enabled`, `cli_binary_path`.

### UI sections

- **Vault** — container list, create/delete, file browse, read/write
- **Settings → Agents** — list, mint (new agent), revoke
- **Settings → MCP server** — status, pairing secret, copy config for clients
- **Settings → Audit** — open audit folder
- **Recovery phrase** — shown once at first launch

---

## 12. Client Loaders (sv-secrets)

The `clients/` directory ships loaders for Node, Python, and Shell. All are
dependency-free (Node ≥18 stdlib; Python ≥3.8 stdlib; Shell wraps Node by default).

### Node — `sv-secrets.mjs`

```js
import { loadSecrets } from "./sv-secrets.mjs";
const { source, vars } = await loadSecrets({ container: "env-myproject" });
Object.assign(process.env, vars);
```

### Python — `sv_secrets.py`

```python
from sv_secrets import load_secrets
src, vars = load_secrets(container="env-myproject")
for k, v in vars.items():
    os.environ[k] = v
```

### Shell — `sv-secrets.sh`

```bash
source sv-secrets.sh
sv_load env-myproject        # loads into current shell
eval "$(bash sv-secrets.sh env-myproject --export)"
```

### `SECRETS_SOURCE` modes

| Value | Behavior |
|---|---|
| `auto` (default) | Try vault; on any failure (locked, timeout, OTP, denied) → fall back to `.env` with a stderr warning |
| `vault` | Vault only; throw if unavailable. Use in CI gates |
| `env` | Local `.env` only; never touch the vault |

### Other knobs

| Env var | Default | Description |
|---|---|---|
| `SV_BIN` | auto (PATH or `../../target/release/sovereign-vault`) | Path to the vault CLI |
| `SV_TIMEOUT_MS` | 30000 | Approval/lock wait |
| `SV_OTP` | — | OTP code for OTP containers |
| `SV_CACHE_TTL_MS` | 0 (off) | Cache successful reads to a 0600 temp file |
| `SV_AGENT_ID` | — | Scoped agent ID (with `SV_PAIRING_TOKEN`) |
| `SV_PAIRING_TOKEN` | — | Scoped agent one-time token |

The session cache writes *decrypted* secrets to your temp dir for the TTL window —
that partially defeats the vault. Off by default. Use short TTLs, `--clear-cache`
when done, and never enable it on shared machines.

### CLI usage

```bash
# Print .env to stdout (no values committed anywhere)
node sv-secrets.mjs --container env-myproject

# Materialize a 0600 runtime file (for shell sourcing or env loading)
node sv-secrets.mjs --container env-myproject --out .env.runtime

# Force local (skip vault)
SECRETS_SOURCE=env node sv-secrets.mjs --container env-myproject
```

---

## 13. Configuration Reference

### Vault

- **Vault root path** — OS app-data dir + `com.sovereignvault.desktop/sovereign-vault`
- **Recovery file** — `<vault-root>/recovery.svault` (encrypted DEK copy)
- **Keyring file** — `<vault-root>/keyring.svault` (wrapped KEK)
- **Audit log** — `<vault-root>/audit.jsonl` + checkpoint `<vault-root>/audit.head.json`
- **Agents registry** — `<vault-root>/agents.json` (schema 2)
- **Manifest** — `<vault-root>/manifest.json` (HMAC-authenticated after migration)

### Desktop app (Tauri)

Config: `apps/desktop/src-tauri/tauri.conf.json`. Identifier: `com.sovereignvault.desktop`.
Ports: WebSocket `127.0.0.1:9944`, HTTP pairing `127.0.0.1:9943`.

### MCP client (opencode example)

```jsonc
{
  "mcp": {
    "anymodel": {
      "type": "local",
      "command": ["node", "/path/to/anymodel-plugin/plugins/anymodel/scripts/mcp-server.mjs"],
      "enabled": true,
      "env": { "ANYMODEL_ENV_FILE": "/path/to/.anymodel.env.runtime" }
    }
  }
}
```

### Sovereign Vault as an MCP client (for projects)

```jsonc
{
  "mcp": {
    "sovereign-vault": {
      "type": "local",
      "command": ["sovereign-vault", "mcp-stdio"]
    }
  }
}
```

Add `SV_AGENT_ID` and `SV_PAIRING_TOKEN` to scope the client.

### Environment variables summary

| Var | Used by | Purpose |
|---|---|---|
| `SV_BIN` | sv-secrets.mjs | Path to the vault CLI |
| `SV_TIMEOUT_MS` | sv-secrets.mjs | Approval timeout (ms) |
| `SV_OTP` | sv-secrets.mjs | OTP code for OTP containers |
| `SV_CACHE_TTL_MS` | sv-secrets.mjs | Session cache TTL (0 = off) |
| `SV_AGENT_ID` | mcp-stdio | Scoped agent ID |
| `SV_PAIRING_TOKEN` | mcp-stdio | Scoped agent one-time token |
| `SV_ENABLE_BROKER` | vault (feature gate) | Enable broker tools (`vault.broker_request`, etc.) |
| `SECRETS_SOURCE` | sv-secrets | `auto` (default) / `vault` / `env` |
| `CODEX_HOME` | anymodel-plugin | Override codex CLI config dir |
| `ANYMODEL_ENV_FILE` | anymodel-plugin | Path to env file (provider keys) |
| `ANYMODEL_BRIDGE` | anymodel-plugin | `builtin` or `litellm` |

---

## 14. Agentic Patterns

### Per-project scoped agent (recommended)

For each project that uses the vault, mint a scoped agent and set its scopes to
exactly that project's containers. A compromised client reaches only what you
granted.

```bash
# 1. Desktop → Settings → Agents → New agent
#    Name: myproject-prod, copy the one-time token
# 2. Add scopes in the Agents panel:
#    glob: env-myproject/*,  actions: read,list
# 3. In the project's MCP client env:
export SV_AGENT_ID="ag_..."
export SV_PAIRING_TOKEN="..."
```

### Vault-as-primary with .env fallback

Use the vault as your main secrets manager, but keep a local `.env` as an
automatic fallback so a locked/buggy vault never blocks a project. The loader
warns to stderr on fallback.

### Wrapper script (e.g., `with-vault-env.sh`)

Load from vault (fallback `.env`) and exec the target command with
`ANYMODEL_ENV_FILE` pointed at the materialized runtime env. See
`plugins/anymodel/scripts/with-vault-env.sh` for a reference implementation.

### Auto-start on login

For Linux, drop a `.desktop` file in `~/.config/autostart/` pointing at the desktop
binary (or a stable symlink in `~/.local/bin/`). With passphrase custody, enter
the passphrase once per boot; the fallback loader covers the gap pre-unlock.

---

## 15. Troubleshooting

### Legacy-format blockers (from older vaults)

If your vault was created with an earlier version, you may hit:

- **"manifest authentication migration is required"** — run
  `VaultHandle::migrate_manifest_authentication(root, custody, passphrase, digest)`.
  See `docs/ARCHITECTURE.md` for the helper.
- **"agents.json: schema v1 is no longer supported"** — delete
  `agents.json` (back it up); the vault regenerates it on next unlock via
  `ensure_default_agent`.
- **"checkpoint is missing while audit artifacts exist"** — the audit v2 checkpoint
  was never written (older format). Cleanest fix: re-initialize the vault (archive
  the old root; redo the setup wizard). The audit chain is per-vault, so a fresh
  init starts a valid v2 chain.

### Keychain access (Linux)

The vault uses `dbus-secret-service` (GNOME Keyring / KWallet). If the session has
no Secret Service provider, `ensure_available` fails. Ensure
`gnome-keyring-daemon` (or `kwalletd`) is running in the session.

If the GNOME "login" keyring is already unlocked (auto-unlock at login), vault
access is silent — no per-access prompt. To force a prompt per vault unlock, use
**passphrase custody** instead.

### Port conflicts

The gateway binds `127.0.0.1:9944` (WS) and `127.0.0.1:9943` (HTTP). If another
service holds these ports, the gateway fails to start. Free the ports or
reconfigure (no CLI flag yet — change the constants in `apps/desktop/src-tauri/src/lib.rs`).

### Approval timeouts

`SV_TIMEOUT_MS` (default 30s) controls how long sv-secrets.mjs waits for a desktop
approval. Increase if you need longer to react to the prompt.

### "fetch failed" from z.ai

Some model providers are flaky for agentic loops. Use the routing policy: long
deterministic commands → in-house; knowledge work → ollama/deepseek; one-shot
reviews → any provider.

---

## 16. Best Agentic Vault Tool — Gaps & Improvements

To make Sovereign Vault the **best agentic vault tool**, here is a critical
assessment of current limitations and proposed improvements.

### Current strengths

- **Strong threat model** — local-first, human-in-the-loop, tamper-evident audit.
- **MCP-native** — works with every major MCP client out of the box.
- **Defense-in-depth** — custody + scopes + mode-mediated prompts + audit + recovery.
- **Zero-dependency loaders** — sv-secrets.mjs is pure Node stdlib; deployable
  anywhere.
- **Graceful degradation** — `SECRETS_SOURCE=auto` falls back to `.env` so a
  locked vault never blocks a project.
- **Cross-platform keychain** — Secret Service / macOS Keychain / Windows Credential
  Manager.

### Gaps & proposed improvements

#### UX & onboarding

- **No headless gateway / daemon mode.** The gateway lives inside the desktop GUI;
  no `sovereign-vault serve` for systemd. *Proposal:* add a headless mode
  (`sovereign-vault serve` or `sv-vaultd`) that runs the MCP gateway without the
  Tauri UI, suitable for systemd --user. Enables auto-unlock from keychain on
  boot without a GUI session.
- **No auto-unlock.** The desktop always shows the unlock screen. *Proposal:*
  optional auto-unlock from keychain custody when the keyring is unlocked
  (opt-in, behind a setting). Document the tradeoff.
- **Per-container PII policy not configurable.** All `ANONYMIZED` containers use
  the same `Policy::all()`. *Proposal:* store a per-container `Policy` in the
  manifest (Phase 1 of `docs/thesis/EVOLUTION.md`).
- **Recovery bundle portability.** Recovery unlocks the DEK but doesn't migrate
  keychain entries. *Proposal:* a "post-recovery re-bootstrap" wizard that
  re-wraps the DEK under the chosen custody.

#### Security & auditability

- **No structured PII redaction counts in the audit log.** `detail` is a free-form
  string; `sv-audit` doesn't carry `pii_redactions: usize`. *Proposal:* add an
  optional `redaction_count` field to `AuditEvent`.
- **Recall / precision of the PII filter is unmeasured.** No labelled corpus
  evaluation. *Proposal:* a recall study on a labelled dataset; document the
  curve (Phase 1 of EVOLUTION).
- **Adversarial battery is small (10 probes).** No malformed-JSON-RPC, oversized
  payload, or fuzzing coverage. *Proposal:* property-test the dispatch surface;
  expand the battery (Phase 1 of EVOLUTION).
- **Audit chain integrity check** — no CLI subcommand to verify a chain offline
  (the `VerifyReport` API exists; expose `sovereign-vault audit verify`).

#### Performance & scale

- **Index rebuild on every unlock** (proposed for context containers in ADR-0012)
  is O(N) in document count. Acceptable at single-user scale; needs an encrypted
  index cache for larger corpora.
- **No key rotation cadence.** `KeyRotated` action exists but no automated
  rotation. *Proposal:* optional rotation interval.
- **No bulk import/export.** The `.svault-v2` chunked format and `.svault-bundle`
  export are proposed (ADR-0003) but not implemented.

#### Agentic ecosystem

- **Limited agent-pack targets** — Claude Code, opencode, Hermes, Codex, generic.
  No VS Code / Windsurf / Continue packs (they use the stdio proxy directly via
  MCP config, which works, but no guided install).
- **No agent telemetry / usage dashboard.** How many approvals per agent? What
  scope-violation attempts? The audit log has the data; no UI.
- **No multi-user support.** Single-user, single-machine by design. Multi-user
  would require a sync model (local-first sync, CRDT, ephemeral cloud —
  Phase 3 of EVOLUTION).

#### Documentation & developer experience

- **This user guide consolidates docs** — but currently the docs are scattered
  across `README.md`, `GETTING_STARTED.md`, `USAGE_REAL.md`, `ARCHITECTURE.md`,
  `threat-model.md`, ADRs, and thesis materials. A single canonical guide is
  needed (this document is a step toward that).
- **No "quickstart" in <2 minutes.** The fastest path is: build → launch desktop →
  wizard → mint agent → wire MCP → load. A single script (`scripts/quickstart.sh`)
  would help.
- **No example projects beyond `mock-ai-project`.** A richer set of example
  integrations (Node app, Python app, shell script, CI pipeline) would showcase
  the loader patterns.

#### Roadmap alignment

The thesis already lays out a phased roadmap in `docs/thesis/EVOLUTION.md`:

- **Phase 1 (thesis window)** — per-container PII policy, recall study, broader
  attack battery, release-mode results appendix. Two of five items are done
  (this session).
- **Phase 2 (§2.3–§2.4 thesis vision)** — context containers (documents),
  on-device embeddings + ANN, `vault.search`, privacy-filtered RAG egress.
  ADR-0012 is Proposed.
- **Phase 3** — ZKP/NATIVE modes, pluggable recovery, local-first sync, mobile.

### Prioritization for "best agentic vault tool"

Top three improvements (impact × effort):

1. **Headless gateway + systemd --user auto-start** — unblocks the "auto-start
   after OS boot" use case fully (no GUI needed). High impact.
2. **Per-container PII policy + recall study** — strengthens Chapter 4 (thesis)
   and gives operators fine-grained control. Medium impact, medium effort.
3. **Structured redaction counts in the audit log + `audit verify` CLI** —
   enables real-time PII filtering dashboards and tamper-evidence verification.
   Medium impact, low effort.

---

## Appendix: Quick reference card

```
┌─ Vault ────────────────────────────────────────────────────────────────┐
│  Build:     cargo tauri build                                        │
│  Launch:    ./target/release/sovereign-vault-desktop                 │
│  Vault root: ~/.local/share/com.sovereignvault.desktop/sovereign-vault │
│  Ports:      9944 (WS), 9943 (HTTP pairing)                          │
└────────────────────────────────────────────────────────────────────────┘

┌─ CLI ────────────────────────────────────────────────────────────────────┐
│  sovereign-vault mcp-stdio                  # MCP proxy                  │
│  sovereign-vault agents list-targets        # agent packs                │
│  sovereign-vault agents install --target claude-code                   │
└────────────────────────────────────────────────────────────────────────┘

┌─ MCP (client → vault) ───────────────────────────────────────────────────┐
│  vault.info / vault.list / vault.read / vault.write / vault.delete      │
│  vault.create_container / vault.destroy                                │
│  vault.create_transit_key / vault.encrypt / vault.decrypt                │
│  vault.create_signing_key / vault.sign / vault.verify                    │
│  vault.broker_request (if SV_ENABLE_BROKER=1)                           │
│  vault.pair { agent_id, token }  → scoped, or { token } → Default       │
└────────────────────────────────────────────────────────────────────────┘

┌─ Loader (sv-secrets) ─────────────────────────────────────────────────────┐
│  SECRETS_SOURCE=auto|vault|env     (auto = vault + .env fallback)      │
│  SV_BIN  SV_TIMEOUT_MS  SV_OTP  SV_CACHE_TTL_MS                        │
│  SV_AGENT_ID + SV_PAIRING_TOKEN  → scoped agent                        │
└────────────────────────────────────────────────────────────────────────┘
```
