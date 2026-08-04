# Evolution path

How the artifact grows from its current, deliberately-scoped instantiation
(local secrets/credentials) toward the full vision of the thesis (§2.3–§2.4: a
local-first *context* substrate for personal AI agents). Each item is tagged
with the thesis section that motivates it, so this doc doubles as raw material
for the *Trabalhos Futuros* chapter.

## Where it is now (2026-07-31)

The four reference-architecture modules (§3.6) are realised; see
[TRACEABILITY.md](TRACEABILITY.md). The three gaps that previously blocked the
evaluation chapter are closed:

- **PII masking** (module 3b / RQ1) — `sv-privacy` + `ANONYMIZED` semantics
  ([ADR-0010](../adr/0010-privacy-mediation-layer.md)).
- **Latency instrument** (§3.9.1) — `TimingSink` + `thesis-eval latency`.
- **Adversarial harness** (§3.9.2) — `thesis-eval adversarial`
  ([ADR-0011](../adr/0011-dsr-evaluation-harness.md)).

Two Phase 1 evaluation-hardening items are now complete:

- **Release-mode benchmark runs + cross-platform table** — reproduced on a
  second host (Linux; kernel version not preserved in the preliminary capture,
  i7-11600H, 30 GiB, rustc 1.96.1); the central §3.9.1
  finding is host-invariant (see [EVALUATION.md §1](EVALUATION.md)).
- **Component micro-measurements (isolated decrypt vs. filter)** — the
  `thesis-eval micro` subcommand times `sv_storage` decrypt+read and
  `sv_privacy::redact` in a tight loop outside the gateway, confirming that
  gateway dispatch overhead is small and bounded relative to the component costs
  (see [EVALUATION.md §1](EVALUATION.md)).

Scope today: single-user, single-machine, **secrets/credentials** domain.

## Phase 1 — harden the evaluation (thesis window)

Low-risk work that strengthens Chapter 4 for the defense.

| Item | Why (thesis) | Sketch | Status |
|---|---|---|---|
| Release-mode benchmark runs + host/methodology table | §3.9.1 rigor | run `thesis-eval --release`, capture host specs; commit a results appendix | ✅ Done (Linux host added) |
| Component micro-measurements (isolated decrypt vs. filter) | §3.9.1 Eq. 1 completeness | add a sub-mode to the harness that times `sv-privacy::redact` and raw `read_file` directly | ✅ Done (`thesis-eval micro`) |
| Per-container / per-agent PII policy | RQ1 (configurable filtering) | store a `Policy` (category set) per `ANONYMIZED` container in the manifest | |
| Recall study + more detectors (names, addresses, RG, e-mail in headers) | §3.9.2 honesty | measure precision/recall on a labelled corpus; document the curve | |
| Broaden the attack battery (malformed JSON-RPC, oversized payloads, fuzzing) | §3.9.2 coverage | property-test the dispatch surface; report block-rate over a larger set | |

## Phase 2 — from secrets to context (the §2.3–§2.4 thesis vision)

The headline generalisation: the same gateway + mediation + HITL pattern, but
over *contextual* data (documents, notes, e-mail), with retrieval on the edge.

| Item | Why (thesis) | Sketch |
|---|---|---|
| Context containers (documents, not just secrets) | §2.1, §2.3 | a container kind whose files are text/chunks rather than credentials |
| On-device vector index + retrieval | §2.1 (RAG, Lewis 2020), §2.3 | local embeddings + ANN search; a `vault.search` MCP tool returning chunks |
| Privacy filter on RAG egress | §3.6 module 3b, RQ1 | run `sv-privacy` over retrieved chunks before they leave the gateway — the filter already sits at the egress boundary |
| Stateless-cloud contract | §2.3 | formalise that the model receives only filtered chunks and retains nothing (prompt/audit conventions) |

This is the largest conceptual step and the natural body of a follow-on work;
the current architecture is intentionally shaped to receive it (the filter,
gateway, scopes, and audit already operate at the right boundary).

## Phase 3 — reserved modes, recovery, sync, mobile

| Item | Why (thesis) | Status today |
|---|---|---|
| `ZKP` security mode | §3.6 (richer mediation) | reserved enum, rejected at runtime |
| `NATIVE` (no-network) mode | §3.6 | reserved enum, rejected at runtime |
| Pluggable recovery providers | resilience | [ADR-0004](../adr/0004-pluggable-recovery-provider.md) (proposed) |
| Chunked `.svault-v2` format | large-file context | [ADR-0003](../adr/0003-svault-v2-chunked-format.md) (proposed) |
| Local-first **sync** (CRDT, ephemeral cloud) | §2.3 (Kleppmann: cloud as secondary) | not started |
| Mobile (Tauri Mobile) | reach | not started |

## One-line summary for the paper

> The instantiation realises the full four-module reference architecture for the
> secrets/credentials domain and is evaluated against both §3.9 protocols; the
> evolution path generalises the same mediated, human-in-the-loop, edge-local
> pattern from secrets to retrieval-augmented *context* (§2.3–§2.4), which is the
> proposed future work.
