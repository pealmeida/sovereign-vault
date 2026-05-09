# Sovereign Vault

**Vaults for AI Agents — Safeguarding Memory, Access, and Control.**

A local-first encrypted file vault for AI agents. Agents request access via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io); users approve or deny each access from a desktop UI; every access is audited.

> **Status: pre-alpha (v0.0.0).** This repository is the foundation for the v1.0 milestone. Not yet usable. See the [design spec](https://github.com/pealmeida/agentic-sovereign-ecosystem/blob/main/docs/superpowers/specs/2026-05-08-sovereign-vault-oss-extraction-design.md) for the full plan.

---

## Why

Today, AI agents hold user secrets in plaintext: environment variables, `.env` files, scattered config. A compromised agent leaks the lot.

Sovereign Vault inverts the trust model:

- Secrets live encrypted in the vault, wrapped by an OS-keychain-backed master key (or a passphrase, your choice).
- Agents request reads/writes through MCP — they do not see plaintext until you allow it.
- Per-container security modes (DIRECT / APPROVAL / OTP) gate access. Sensitive data requires a human click; some requires an OTP.
- Every read, write, delete, approve, and deny is recorded in an append-only audit log.

## v1.0 — what ships

- Single root vault per OS user with sub-containers (folders that may carry a default security mode).
- Files up to 100 MB, chunked AEAD encryption (XChaCha20-Poly1305).
- 4 MCP tools: `vault.list`, `vault.read`, `vault.write`, `vault.delete`.
- HITL approval modal in a Tauri desktop app (Windows / macOS / Linux).
- Append-only JSONL audit log.
- BIP39 24-word recovery phrase generated at first launch.
- Encrypted `.svault-bundle` snapshot for backup + restore on another device.

Deferred to v1.1+ (per [design spec § 4](https://github.com/pealmeida/agentic-sovereign-ecosystem/blob/main/docs/superpowers/specs/2026-05-08-sovereign-vault-oss-extraction-design.md#4-v10-feature-set)): hash-chained audit, agent identity + capability tokens, policy engine, JIT secret injection, memory/RAG, mobile apps, sync.

## Install

Pre-1.0; no signed releases yet. Build from source:

### Prerequisites

- [Rust stable](https://www.rust-lang.org/tools/install) (≥ 1.78)
- [Node.js](https://nodejs.org/) (≥ 20)
- Platform deps for Tauri 2 — see <https://tauri.app/start/prerequisites/>
- Tauri CLI: `cargo install tauri-cli --version "^2.0.0"`

### Build

```bash
git clone https://github.com/pealmeida/sovereign-vault.git
cd sovereign-vault

# Workspace check (no Tauri assets needed)
cargo check --workspace

# UI install
( cd ui && npm install )

# Run desktop app in dev mode (requires apps/desktop/src-tauri/icons/icon.png)
cargo tauri dev --manifest-path apps/desktop/src-tauri/Cargo.toml
```

> **Note**: An icon must exist at `apps/desktop/src-tauri/icons/icon.png` before the first Tauri build. Drop in any 512×512 PNG; final art comes in M5.

## Repo layout

```
crates/
  sv-crypto      AEAD, KDF, key wrap, zeroize
  sv-storage     Containers, chunked file format, manifest
  sv-keychain    OS keychain abstraction + passphrase fallback
  sv-recovery    Pluggable recovery providers (BIP39 v1.0)
  sv-audit       Append-only JSONL audit log
  sv-mcp         MCP server (stdio + WS)
  sv-http        Read-only HTTP (/health, agent card, MCP pairing)
  sv-core        Integration crate consumed by apps/

apps/
  desktop        Tauri 2 desktop app
  cli            Headless `sovereign-vault` binary
  mobile         Tauri Mobile target (post-v1.0)

ui/              Svelte 5 + Vite frontend
docs/            Threat model, architecture, MCP protocol, ADRs
examples/        Claude Desktop / Cursor / Continue.dev integration samples
```

## License

Apache-2.0 — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Lineage

This codebase originated as a proof-of-concept inside [agentic-sovereign-ecosystem](https://github.com/pealmeida/agentic-sovereign-ecosystem). v1.0 is a clean Rust-native rewrite to drop the original Node bridge and remove the Mission Control / Digital Twin coupling.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md). Security disclosures go via [SECURITY.md](./SECURITY.md), not the public issue tracker.
