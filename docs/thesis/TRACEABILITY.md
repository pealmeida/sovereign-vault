# Thesis ↔ artifact traceability

This document maps Pedro Oliveira's USP/ICMC MBA thesis — *"Arquitetura de
Soberania de Dados para Agentes de IA Pessoais: Um Modelo Local-First Baseado em
Protocolos Descentralizados"* — onto the Sovereign Vault codebase, the
**instantiation** artifact of its Design Science Research (§3.5, March & Smith
*model / method / instantiation*).

It is written to be lifted into the LaTeX paper: every row ties a thesis
construct to a concrete, verifiable location in the source tree. References use
`crate::symbol` or `path:line`; symbols are stable even when line numbers drift.

> **Scope honesty (for the defense).** The artifact instantiates the proposal in
> the *secrets/credentials* domain, as the thesis itself states in §3.5
> (*"operando no controle de credenciais e segredos locais como representação
> empírica da proposta"*). The broader vision of §2.3–§2.4 (edge RAG, vector
> context) is the documented evolution path — see [EVOLUTION.md](EVOLUTION.md).

## 1. Reference architecture (§3.6) → code

| # | Thesis module (§3.6) | Realised by | Key locations | Status |
|---|---|---|---|---|
| 1 | **Cofre de Dados Local** — encrypted local storage, security permissions, logical barrier | `sv-crypto` + `sv-storage` + `sv-core` | XChaCha20-Poly1305 + Argon2id (`sv-crypto`); whole-file envelope + per-container modes ([`sv-storage/src/lib.rs`](../../crates/sv-storage/src/lib.rs)); KEK/DEK hierarchy ([`sv-core/src/keyring.rs`](../../crates/sv-core/src/keyring.rs)) | ✅ |
| 2 | **Servidor MCP Local** — active security gateway in Rust, intercepts agent requests | `sv-mcp` + `sv-http` | tool dispatch + gating ([`sv-mcp/src/lib.rs`](../../crates/sv-mcp/src/lib.rs), `call_tool`); loopback pairing ([`sv-http`](../../crates/sv-http/src/lib.rs)) | ✅ |
| 3a | **Mediação e Filtro** — cryptographic intermediation (sign/encrypt, key never revealed) | `sv-core::transit` | [`sv-core/src/transit.rs`](../../crates/sv-core/src/transit.rs); MCP `vault.encrypt/decrypt/sign` | ✅ |
| 3b | **Mediação e Filtro** — **PII masking** (*mascaramento de PII*) | `sv-privacy` + `sv-mcp` | [`sv-privacy/src/lib.rs`](../../crates/sv-privacy/src/lib.rs) (`redact`); applied in `sv-mcp::call_tool` (`apply_privacy_filter`) | ✅ **(new)** |
| 4 | **Mecanismo Human-in-the-loop** — Tauri desktop, hash-chained logs, consent by sensitivity | `apps/desktop` + `ui` + `sv-audit` | approval state machine ([`apps/desktop/src-tauri/src/lib.rs`](../../apps/desktop/src-tauri/src/lib.rs), `ApprovalState`); hash-chained log ([`sv-audit/src/lib.rs`](../../crates/sv-audit/src/lib.rs)) | ✅ |

### Consent modes (§3.6 module 4) — exact mapping

| Thesis term | Enum variant | Gate behaviour |
|---|---|---|
| Modo Direto | `SecurityMode::Direct` | no prompt |
| Aprovação Explícita | `SecurityMode::Approval` | desktop confirm (click) |
| Senha de Uso Único | `SecurityMode::Otp` | cross-channel 6-digit code |
| *(filtragem de privacidade)* | `SecurityMode::Anonymized` | auto-allow read + PII mask **(new)** |

Defined at [`sv-storage/src/lib.rs:100`](../../crates/sv-storage/src/lib.rs#L100); gate policy in `apps/desktop` `approval_requirement`.

## 2. Specific objectives (§1.4.2) → status

| # | Objective | Evidence | Status |
|---|---|---|---|
| 1 | Investigate MCP as a decoupling interface | Rust-native MCP server, stdio + WS, 15 tools, pairing ([ADR-0002](../adr/0002-rust-native-mcp-server.md), [ADR-0006](../adr/0006-mcp-integration.md)) | ✅ |
| 2 | Local context vault in a memory-safe language | `forbid(unsafe_code)` workspace-wide ([`Cargo.toml:26`](../../Cargo.toml#L26)); whole vault in Rust | ✅ |
| 3 | Human-in-the-loop layer for runtime auditing/approval | `apps/desktop` approval/OTP modals + hash-chained `sv-audit` | ✅ |
| 4 | Evaluate latency + exfiltration-blocking vs. cloud | `apps/thesis-eval` (`latency`, `adversarial`) — see [EVALUATION.md](EVALUATION.md) | ✅ **(new)** |

## 3. Research questions (§1.3) → where answered

| RQ | Question (paraphrased) | Answered by |
|---|---|---|
| RQ1 | Securely **mediate and filter** contextual queries to local data | Scope + approval gating (`sv-mcp`); crypto-intermediation (`sv-core::transit`); **PII filter** (`sv-privacy`, [ADR-0010](../adr/0010-privacy-mediation-layer.md)) |
| RQ2 | **Latency** impact of a local interception/audit layer | Latency decomposition harness, Equation 1 mapping — [EVALUATION.md §1](EVALUATION.md) |
| RQ3 | OS-level **isolation** mitigating lateral exfiltration | Memory-safe Rust (`forbid(unsafe_code)`); loopback-only binding + per-launch pairing; scope enforcement; adversarial block-rate — [EVALUATION.md §2](EVALUATION.md) |

## 4. Methodology (§3.3, §3.5) → repo

| Construct | Realisation |
|---|---|
| March & Smith **instantiation** | the whole repository (a runnable artifact) |
| March & Smith **model** (§3.6) | the 4-module reference architecture, §1 of this doc |
| March & Smith **method** (§3.7) | the runtime mediation/isolation protocol: pairing → scope → consent → execute → **filter** → audit (`sv-mcp::call_tool`) |
| Architecture Decision Records (§3.3 rigor cycle) | [`docs/adr/`](../adr/) — 11 ADRs, incl. [ADR-0010](../adr/0010-privacy-mediation-layer.md) (privacy) and [ADR-0011](../adr/0011-dsr-evaluation-harness.md) (evaluation) added for this work |

## 5. Theoretical anchors (§2) → realisation

| Reference | In the artifact |
|---|---|
| MCP (Anthropic, 2024) | `sv-mcp` server, JSON-RPC 2024-11-05, 15 tools |
| Local-First (Kleppmann, 2019) | single-machine, no server; data + processing on the device |
| Memory safety (NSA, 2022) | Rust + `forbid(unsafe_code)` (RQ3 evidence) |
| Privacy by Design (Cavoukian, 2011) | privacy controls native to the code: `ANONYMIZED` masking, no-key-return transit |
| Surveillance capitalism / LGPD (Zuboff 2019; Lorenzon 2021) | CPF/CNPJ-aware PII detectors in `sv-privacy` |
| Tauri vs. Electron (§3.8) | `apps/desktop` Tauri 2 shell |

## Verifying these references

```bash
cargo test --workspace          # 86+ tests across the crates cited above
cargo run -p thesis-eval -- all # regenerates the §3.9 evaluation evidence
```

Line numbers were checked against the working tree on 2026-06-06. If a symbol
moves, search by name (e.g. `rg "fn apply_privacy_filter"`).
