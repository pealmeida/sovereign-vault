# Sovereign Vault

**The local-first, human-in-the-loop secrets vault built for AI agents.**

[![CI](https://github.com/pealmeida/sovereign-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/pealmeida/sovereign-vault/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange.svg)](#)
[![Rust](https://img.shields.io/badge/Rust-stable-informational.svg)](https://www.rust-lang.org/)

Your API keys, `.env` files, and sensitive data stay encrypted on *your* machine. AI agents (Claude, Cursor, Continue, or any MCP client) request access through the [Model Context Protocol](https://modelcontextprotocol.io), and **you** approve or deny each protected operation from a desktop app. Every access is written to a tamper-evident audit log.

> Screenshot/GIF of the approval modal should live here. The human approval prompt is the core differentiator.

No cloud. No plaintext sprawl. No agent ever sees a secret you did not release.

> **Status: pre-alpha (v0.0.0).** Usable today for local, single-user evaluation on one machine. Expect rough edges and schema churn. Keep independent backups.

> **Academic research project.** Sovereign Vault is the Design Science Research instantiation for a USP/ICMC MBA thesis on data sovereignty for personal AI agents. Start with the [docs index](./docs/README.md), then use the [research track](./docs/research/README.md) and the [thesis materials](./docs/thesis/README.md).

## Why Sovereign Vault

Agents today hoard secrets in plaintext: `.env` files, env vars, and scattered config. One compromised agent leaks everything.

Sovereign Vault inverts that trust model:

- **Secrets live encrypted**, wrapped by an OS-keychain key or a passphrase using XChaCha20-Poly1305 and Argon2id.
- **Agents ask; you decide.** Reads and writes flow over MCP. Protected containers raise a desktop prompt to approve, deny, or provide a one-time code.
- **Use secrets without exposing them.** Transit `encrypt`/`decrypt`/`sign` and the optional outbound broker let an agent use a key without receiving its bytes.
- **Scoped agent identities.** Each agent gets its own token and capability scope, so a compromised client reaches only what you granted it.
- **Everything is audited.** The log is append-only and hash-chained. Tampering breaks the chain.

That combination of local-first, human-in-the-loop, MCP-native, and secret brokering is what makes it a sovereign vault: you keep custody and control.

### How it compares

| | Sovereign Vault | HashiCorp Vault / OpenBao | Bitwarden / 1Password | `.env` files |
|---|---|---|---|---|
| Runs fully local, no server | Yes | No (server/cluster) | No (cloud sync) | Yes |
| Per-operation human approval | Yes | No | No | No |
| MCP-native (agents ask via tools) | Yes | No | No | No |
| Use a key without revealing it (transit/sign/broker) | Yes | Yes | No | No |
| Tamper-evident audit log | Yes (hash-chained) | Yes | Partial | No |
| Secrets encrypted at rest | Yes | Yes | Yes | No |

Built for the single-developer and single-agent-fleet case that server-grade tools over-serve and `.env` files under-serve.

## What's implemented

- **Single root vault** per OS user, with sub-containers and per-container security modes.
- **Security modes:** `DIRECT`, `APPROVAL`, `OTP`, and `ANONYMIZED`.
- **15 default MCP tools:** file/container operations (including `vault.destroy` and a read-only `vault.info`) plus transit-key and signing-key management, encryption/decryption, signing, and verification. Operations are gated by their container's security mode — only `APPROVAL`/`OTP`/`ZKP` raise a desktop prompt; `DIRECT` and key operations run without one. Optional broker-secret management and `vault.broker_request` are gated behind `SV_ENABLE_BROKER=1`.
- **Key hierarchy:** an OS-keychain key or passphrase wraps a rotatable data key.
- **Keychain custody hardening:** vault-root-scoped keychain entries, backend availability probing, passphrase-to-keychain migration, and recovery-based repair of broken keychain wrappers.
- **Per-agent identity and scopes** managed from the desktop.
- **Hash-chained audit log** covering desktop and MCP operations.
- **BIP39 24-word recovery phrase** generated at first launch.
- **Drop-in client loaders** in [`clients/`](./clients/) for Node, Python, and shell with vault-first and `.env` fallback behavior.
- **PII privacy mediation** in `sv-privacy` for `ANONYMIZED` containers — masks email, phone, credit-card, US SSN, CPF, and CNPJ values on read.

## Not implemented yet

- `ZKP` and `NATIVE` live-access modes are still reserved and rejected at runtime.
- Chunked `.svault-v2` format and encrypted `.svault-bundle` export.
- Sync, mobile, memory/RAG, and the broader policy engine.

## Install

Pre-1.0; no signed releases yet. Build from source.

**Prerequisites**

- [Rust stable](https://www.rust-lang.org/tools/install) (>= 1.88)
- [Node.js](https://nodejs.org/) (>= 20)
- Tauri 2 platform dependencies: <https://tauri.app/start/prerequisites/>
- Tauri CLI: `cargo install tauri-cli --version "^2.0.0"`

**Build and run**

```bash
git clone https://github.com/pealmeida/sovereign-vault.git
cd sovereign-vault

cargo check --workspace
( cd ui && npm install )

# Development
cargo tauri dev --manifest-path apps/desktop/src-tauri/Cargo.toml

# Production bundle
( cd ui && npm run build )
cargo tauri build --manifest-path apps/desktop/src-tauri/Cargo.toml
```

Installers land under `target/release/bundle/`.

> Build the desktop app with `cargo tauri build`, not plain `cargo build`.
> A plain `cargo build --release` binary loads the dev-server URL instead of
> the embedded UI and shows a connection error. If you must skip the Tauri
> CLI, build the UI first and add
> `--features sovereign-vault-desktop/custom-protocol`.

> First launch walks you through custody (OS keychain or passphrase) and shows the recovery phrase once. Write it down.

> macOS Gatekeeper may block the unsigned bundle. Clear the quarantine flag with `xattr -dr com.apple.quarantine "target/release/bundle/macos/Sovereign Vault.app"`.

## Use it in 5 minutes

**1. Create containers.** In the desktop app, create containers such as `env-myproject` (APPROVAL), `secrets-cloud` (APPROVAL), or `personal-id` (OTP).

**2. Connect an agent.** Point any MCP client at the stdio proxy:

```jsonc
{
  "mcpServers": {
    "sovereign-vault": {
      "command": "/abs/path/to/target/release/sovereign-vault",
      "args": ["mcp-stdio"]
    }
  }
}
```

The vault must be unlocked for clients to connect.

**3. Install an agent command pack.**

```bash
sovereign-vault agents list-targets
sovereign-vault agents install --target claude-code
```

Generated command packs live from the canonical definitions under
[`integrations/agents/`](./integrations/agents/README.md).

**4. Read secrets in your app, with `.env` fallback.**

```js
import { loadSecrets } from "./clients/node/sv-secrets.mjs";

const { source, vars } = await loadSecrets({ container: "env-myproject" });
Object.assign(process.env, vars); // source: "vault" | "env" | "cache"
```

Flip the source with `SECRETS_SOURCE=auto|vault|env`. Python and shell ports behave the same way.

**Full walkthrough:** [`docs/USAGE_REAL.md`](./docs/USAGE_REAL.md)

## Documentation lanes

- **Start here:** [`docs/README.md`](./docs/README.md)
- **Development track:** [`docs/development/README.md`](./docs/development/README.md)
- **Research track:** [`docs/research/README.md`](./docs/research/README.md)

Use `docs/testing/` for reproducible engineering validation, `docs/thesis/` for thesis-facing artifacts, and `docs/archive/` only for historical material that should not drive current implementation work.

## Repo map

```text
crates/
  sv-crypto      AEAD, KDF, key wrap, zeroize
  sv-storage     containers, envelope format, manifest, name validation
  sv-keychain    OS keychain custody layer
  sv-recovery    BIP39 recovery phrase
  sv-audit       append-only, hash-chained JSONL audit log
  sv-privacy     PII detection and masking for ANONYMIZED containers
  sv-mcp         MCP server (stdio + WS), tool dispatch, approval hook
  sv-http        loopback HTTP health/pairing surface
  sv-core        integration crate consumed by apps

apps/desktop     Tauri 2 app (Rust commands + approval state)
apps/cli         headless `sovereign-vault` binary, including `mcp-stdio` and agent-pack install/export commands
apps/thesis-eval DSR evaluation harness
ui/              Svelte 5 + Vite frontend
clients/         Node / Python / shell secret loaders
examples/        MCP client configs and end-to-end examples
docs/            navigation hub, architecture, ADRs, testing, thesis mapping
scripts/         build/run helpers and local automation
```

`docs/README.md` is the navigation hub for active work. `docs/development/README.md` defines where to add engineering evidence, and `docs/research/README.md` defines where to add thesis-facing material.

## Modify and contribute

- Verify before claiming done: `cargo check --workspace`, `cargo test --workspace`, and `( cd ui && npm run check )`.
- Architecture decisions live in [`docs/adr/`](./docs/adr/). New behavior should land with tests, and an ADR when the design boundary changes.
- Security model references live in [`docs/threat-model.md`](./docs/threat-model.md) and [`SECURITY.md`](./SECURITY.md).

## Academic context

Sovereign Vault is the reference implementation, the Design Science Research instantiation artifact, of an academic research project:

> **Oliveira, Pedro.** *Arquitetura de Soberania de Dados para Agentes de IA Pessoais: Um Modelo Local-First Baseado em Protocolos Descentralizados.* USP/ICMC - MBA em Inteligencia Artificial e Big Data, 2026.

The research paper lives in [`docs/thesis/`](./docs/thesis/) ([PDF](./docs/thesis/oliveira-2026-soberania-de-dados-agentes-ia.pdf)), alongside the [code-to-thesis traceability map](./docs/thesis/TRACEABILITY.md), the [evaluation and reproduction guide](./docs/thesis/EVALUATION.md), and the [evolution roadmap](./docs/thesis/EVOLUTION.md). The higher-level research entry point is [`docs/research/README.md`](./docs/research/README.md).

```bibtex
@mastersthesis{oliveira2026soberania,
  author = {Oliveira, Pedro},
  title  = {Arquitetura de Soberania de Dados para Agentes de IA Pessoais: Um Modelo Local-First Baseado em Protocolos Descentralizados},
  school = {Universidade de Sao Paulo (USP), Instituto de Ciencias Matematicas e de Computacao (ICMC)},
  type   = {MBA em Inteligencia Artificial e Big Data},
  year   = {2026}
}
```

> The paper PDF is the author's academic work and is **not** covered by the repository's Apache-2.0 code license.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Lineage

Originated as a proof-of-concept inside [agentic-sovereign-ecosystem](https://github.com/pealmeida/agentic-sovereign-ecosystem), then rewritten Rust-native to drop the Node bridge and the Mission Control / Digital Twin coupling.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md). Report vulnerabilities via [SECURITY.md](./SECURITY.md), not the public issue tracker.
