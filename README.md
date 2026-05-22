# Sovereign Vault

**Vaults for AI Agents - Safeguarding Memory, Access, and Control.**

A local-first encrypted file vault for AI agents. Agents request access through the [Model Context Protocol (MCP)](https://modelcontextprotocol.io), users approve or deny protected operations from a desktop UI, and each operation is audited.

> **Status: pre-alpha (v0.0.0).** The repository is usable for local, single-user evaluation flows on one machine. Expect rough edges, schema churn, and missing hardening outside the implemented scope below.

---

## Why

Today, AI agents often hold user secrets in plaintext: environment variables, `.env` files, and scattered config. A compromised agent leaks the lot.

Sovereign Vault inverts the trust model:

- Secrets live encrypted in the vault, wrapped by an OS-keychain-backed master key or a passphrase.
- Agents request reads and writes through MCP; they do not see plaintext until the vault allows it.
- Per-container security modes (`DIRECT`, `APPROVAL`, `OTP`) gate access.
- Every read, write, delete, create, approve, and deny is recorded in an append-only audit log.

## Current scope

- Single root vault per OS user with sub-containers.
- Whole-file XChaCha20-Poly1305 envelopes with path-bound AAD.
- 5 MCP tools: `vault.list`, `vault.read`, `vault.write`, `vault.delete`, `vault.create_container`.
- Desktop approval flow for MCP requests against protected containers.
- `DIRECT`, `APPROVAL`, and `OTP` container modes for live MCP access.
- Append-only JSONL audit log covering desktop and MCP operations.
- BIP39 24-word recovery phrase generated at first launch, with `recovery.svault` master-key wrap.

## Not implemented yet

- Chunked `.svault-v2` storage format.
- Encrypted `.svault-bundle` backup/export workflow.
- Hash-chained audit entries.
- Agent identity and capability tokens.
- `ANONYMIZED`, `ZKP`, and `NATIVE` live-access flows.
- Sync, mobile targets, memory/RAG, and policy engine work from the broader design.

## Install

Pre-1.0; no signed releases yet. Build from source:

### Prerequisites

- [Rust stable](https://www.rust-lang.org/tools/install) (>= 1.78)
- [Node.js](https://nodejs.org/) (>= 20)
- Platform dependencies for Tauri 2 - see <https://tauri.app/start/prerequisites/>
- Tauri CLI: `cargo install tauri-cli --version "^2.0.0"`

### Build

```bash
git clone https://github.com/pealmeida/sovereign-vault.git
cd sovereign-vault

# Workspace check
cargo check --workspace

# UI install
( cd ui && npm install )

# Run desktop app in dev mode
cargo tauri dev --manifest-path apps/desktop/src-tauri/Cargo.toml
```

> **Note**: An icon must exist at `apps/desktop/src-tauri/icons/icon.png` before the first Tauri build.

## Repo layout

```text
crates/
  sv-crypto      AEAD, KDF, key wrap, zeroize
  sv-storage     Containers, envelope format, manifest
  sv-keychain    OS keychain abstraction + passphrase fallback
  sv-recovery    BIP39 recovery phrase support
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

Apache-2.0 - see [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Lineage

This codebase originated as a proof-of-concept inside [agentic-sovereign-ecosystem](https://github.com/pealmeida/agentic-sovereign-ecosystem). v1.0 is a clean Rust-native rewrite to drop the original Node bridge and remove the Mission Control / Digital Twin coupling.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md). Security disclosures go via [SECURITY.md](./SECURITY.md), not the public issue tracker.
