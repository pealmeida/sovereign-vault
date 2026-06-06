# Sovereign Vault

**The local-first, human-in-the-loop secrets vault built for AI agents.**

[![CI](https://github.com/pealmeida/sovereign-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/pealmeida/sovereign-vault/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange.svg)](#)
[![Rust](https://img.shields.io/badge/Rust-stable-informational.svg)](https://www.rust-lang.org/)

Your API keys, `.env` files, and sensitive data stay encrypted on *your* machine. AI agents (Claude, Cursor, Continue, any MCP client) request access through the [Model Context Protocol](https://modelcontextprotocol.io) — and **you** approve or deny each protected operation from a desktop app. Every access is written to a tamper-evident audit log.

> _Screenshot/GIF of the approval modal goes here — the human-in-the-loop prompt is the core differentiator. (Capture from the running desktop app.)_

No cloud. No plaintext sprawl. No agent ever sees a secret you didn't release.

> **Status: pre-alpha (v0.0.0).** Usable today for local, single-user evaluation on one machine. Expect rough edges and schema churn. Keep independent backups.

> **Academic research project.** Sovereign Vault is the Design Science Research *instantiation* for a USP/ICMC MBA thesis on data sovereignty for personal AI agents — see [`docs/thesis/`](./docs/thesis/) and the [research paper](./docs/thesis/oliveira-2026-soberania-de-dados-agentes-ia.pdf). [Academic context ↓](#academic-context)

---

## Why Sovereign Vault

Agents today hoard secrets in plaintext — `.env` files, env vars, scattered config. One compromised agent leaks everything.

Sovereign Vault inverts the trust model:

- **Secrets live encrypted**, wrapped by an OS-keychain key or a passphrase (XChaCha20-Poly1305 + Argon2id, key hierarchy with rotation).
- **Agents ask; you decide.** Reads/writes flow over MCP. Protected containers raise a desktop prompt — Approve, Deny, or enter a one-time code.
- **Use secrets without exposing them.** Transit `encrypt`/`decrypt`/`sign` and the optional outbound *broker* let an agent *use* a key without ever receiving its bytes.
- **Scoped agent identities.** Each agent gets its own token and capability scope — a compromised client only reaches what you granted it.
- **Everything is audited.** Append-only, hash-chained JSONL log. Tampering breaks the chain.

That combination — local-first **+** human-in-the-loop **+** MCP-native **+** secret brokering — is what makes it a *sovereign* vault: you keep custody and control.

### How it compares

| | Sovereign Vault | HashiCorp Vault / OpenBao | Bitwarden / 1Password | `.env` files |
|---|---|---|---|---|
| Runs fully local, no server | ✅ | ❌ (server/cluster) | ❌ (cloud sync) | ✅ |
| Per-operation human approval | ✅ | ❌ | ❌ | ❌ |
| MCP-native (agents ask via tools) | ✅ | ❌ | ❌ | ❌ |
| Use a key without revealing it (transit/sign/broker) | ✅ | ✅ | ❌ | ❌ |
| Tamper-evident audit log | ✅ (hash-chained) | ✅ | partial | ❌ |
| Secrets encrypted at rest | ✅ | ✅ | ✅ | ❌ |

Built for the single-developer / single-agent-fleet case that the server-grade
tools over-serve and `.env` files under-serve.

## What's inside (implemented)

- **Single root vault** per OS user, with sub-containers and per-container security modes.
- **Security modes:** `DIRECT` (no prompt), `APPROVAL` (desktop confirm), `OTP` (cross-channel one-time code — shown on desktop, entered by the agent), `ANONYMIZED` (auto-allowed reads with PII masked out of the response).
- **9 MCP tools:** `vault.list` / `read` / `write` / `delete` / `create_container`, plus transit `encrypt` / `decrypt` / `sign` / `verify`. Optional `vault.broker_request` behind `SV_ENABLE_BROKER=1`.
- **Key hierarchy:** OS-keychain or passphrase wraps a rotatable data key (rotate re-encrypts in place).
- **Per-agent identity & scopes** — mint/revoke tokens from the desktop; scopes can only narrow access.
- **Hash-chained audit log** over both desktop and MCP operations.
- **BIP39 24-word recovery phrase** generated at first launch.
- **Drop-in client loaders** (`clients/`) for Node, Python, and shell — vault-primary with automatic `.env` fallback.
- **PII privacy mediation** (`sv-privacy`): reads from `ANONYMIZED` containers are scanned and masked (email, CPF/CNPJ, credit card, IPv4, phone) before they reach the agent.

## Not implemented yet

- `ZKP`, `NATIVE` live-access modes (reserved in the enum; rejected at runtime).
- Chunked `.svault-v2` format and encrypted `.svault-bundle` export.
- Sync, mobile, memory/RAG, and the broader policy engine.

---

## Install

Pre-1.0; no signed releases yet — build from source.

**Prerequisites**
- [Rust stable](https://www.rust-lang.org/tools/install) (≥ 1.88)
- [Node.js](https://nodejs.org/) (≥ 20)
- Tauri 2 platform deps — see <https://tauri.app/start/prerequisites/>
- Tauri CLI: `cargo install tauri-cli --version "^2.0.0"`

**Build & run**

```bash
git clone https://github.com/pealmeida/sovereign-vault.git
cd sovereign-vault

cargo check --workspace          # verify the Rust workspace
( cd ui && npm install )         # frontend deps

# Dev (hot reload):
cargo tauri dev --manifest-path apps/desktop/src-tauri/Cargo.toml

# Production bundle (build the UI FIRST, then bundle):
( cd ui && npm run build )
cargo tauri build --manifest-path apps/desktop/src-tauri/Cargo.toml
# Installers land in the workspace target dir: target/release/bundle/
#   macOS:   target/release/bundle/dmg/Sovereign Vault_<ver>_x64.dmg  (+ .app under bundle/macos/)
#   Linux:   target/release/bundle/{deb,appimage}/
#   Windows: target/release/bundle/{nsis,msi}/
```

> First launch walks you through custody (OS keychain or passphrase) and shows your recovery phrase **once** — write it down.

> **macOS Gatekeeper:** the bundle is unsigned (pre-1.0), so the first launch may be blocked. Clear the quarantine flag: `xattr -dr com.apple.quarantine "target/release/bundle/macos/Sovereign Vault.app"`.

---

## Use it (5 minutes)

**1. Create containers.** In the desktop app → **Vault → New vault**, pick a mode:
`env-myproject` (APPROVAL), `secrets-cloud` (APPROVAL), `personal-id` (OTP)…

**2. Connect an agent.** Point any MCP client at the stdio proxy — it auto-pairs:

```jsonc
// Claude Code / Cursor / Continue MCP config
{
  "mcpServers": {
    "sovereign-vault": {
      "command": "/abs/path/to/target/release/sovereign-vault",
      "args": ["mcp-stdio"]
    }
  }
}
```

The vault must be **unlocked** for clients to connect (lock = servers stop).

**3. Read secrets in your app — with `.env` fallback.** Use a client loader so a locked vault never blocks you:

```js
import { loadSecrets } from "./clients/node/sv-secrets.mjs";
const { source, vars } = await loadSecrets({ container: "env-myproject" });
Object.assign(process.env, vars);   // source: "vault" | "env" | "cache"
```

Flip the source with one env var — `SECRETS_SOURCE=auto|vault|env`. Python (`clients/python/sv_secrets.py`) and shell (`clients/shell/sv-secrets.sh`) ports behave identically.

**Full walkthrough:** [`docs/USAGE_REAL.md`](./docs/USAGE_REAL.md) — container layout, per-agent scoped tokens, `.env` migration playbook, OTP flow, session cache, backups.

---

## Modify / contribute

```text
crates/
  sv-crypto      AEAD, KDF, key wrap, zeroize
  sv-storage     containers, envelope format, manifest, name validation
  sv-keychain    OS keychain + passphrase fallback
  sv-recovery    BIP39 recovery phrase
  sv-audit       append-only, hash-chained JSONL audit log
  sv-privacy     PII detection + masking for ANONYMIZED containers
  sv-mcp         MCP server (stdio + WS), tool dispatch, approval hook
  sv-http        read-only HTTP (/health, agent card, MCP pairing)
  sv-core        integration crate consumed by apps/

apps/desktop     Tauri 2 app (Rust commands + approval state)
apps/cli         headless `sovereign-vault` binary (incl. `mcp-stdio` proxy)
apps/thesis-eval DSR evaluation harness (latency + adversarial block-rate)
ui/              Svelte 5 + Vite frontend
clients/         Node / Python / shell secret loaders (vault + .env fallback)
examples/        ready-to-paste MCP client configs + an end-to-end script
docs/            threat model, architecture, ADRs, test plans, thesis mapping
scripts/         build/run helpers (macOS .command) + e2e MCP usage script
```

- Verify before claiming done: `cargo check --workspace`, `cargo test --workspace`, and `( cd ui && npm run check )`.
- Architecture decisions live in `docs/adr/`. New behavior → add an ADR + tests.
- Security model: [`docs/`](./docs/) threat model and `SECURITY.md`.

## Academic context

Sovereign Vault is the reference implementation — the Design Science Research **instantiation** artifact — of an academic research project:

> **Oliveira, Pedro.** *Arquitetura de Soberania de Dados para Agentes de IA Pessoais: Um Modelo Local-First Baseado em Protocolos Descentralizados.* USP/ICMC — MBA em Inteligência Artificial e Big Data, 2026.

The research paper lives in [`docs/thesis/`](./docs/thesis/) ([PDF](./docs/thesis/oliveira-2026-soberania-de-dados-agentes-ia.pdf)), alongside a [code ↔ thesis traceability map](./docs/thesis/TRACEABILITY.md), the [evaluation & reproduction guide](./docs/thesis/EVALUATION.md) (the §3.9 latency + adversarial protocols), and the [evolution roadmap](./docs/thesis/EVOLUTION.md). Design decisions are recorded as [ADRs](./docs/adr/).

```bibtex
@mastersthesis{oliveira2026soberania,
  author = {Oliveira, Pedro},
  title  = {Arquitetura de Soberania de Dados para Agentes de IA Pessoais: Um Modelo Local-First Baseado em Protocolos Descentralizados},
  school = {Universidade de S{\~a}o Paulo (USP), Instituto de Ci{\^e}ncias Matem{\'a}ticas e de Computa{\c{c}}{\~a}o (ICMC)},
  type   = {MBA em Intelig{\^e}ncia Artificial e Big Data},
  year   = {2026}
}
```

> The paper PDF is the author's academic work and is **not** covered by the repository's Apache-2.0 code license.

## License

Apache-2.0 — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Lineage

Originated as a proof-of-concept inside [agentic-sovereign-ecosystem](https://github.com/pealmeida/agentic-sovereign-ecosystem); rewritten Rust-native to drop the Node bridge and the Mission Control / Digital Twin coupling.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md). Report vulnerabilities via [SECURITY.md](./SECURITY.md), not the public issue tracker.
