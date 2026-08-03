# Thesis materials

Supporting documentation tying Sovereign Vault to Pedro Oliveira's USP/ICMC MBA
thesis (*Inteligência Artificial e Big Data*): **"Arquitetura de Soberania de
Dados para Agentes de IA Pessoais: Um Modelo Local-First Baseado em Protocolos
Descentralizados."**

The repository is the Design Science Research **instantiation** artifact (§3.5).
These documents make the code ↔ thesis relationship explicit and reproducible,
and are written to be lifted into the LaTeX paper.

**Paper:** [`oliveira-2026-soberania-de-dados-agentes-ia.pdf`](oliveira-2026-soberania-de-dados-agentes-ia.pdf) — the research project. It is the author's academic work and is *not* covered by the repository's Apache-2.0 code license.

| Document | Purpose | Thesis tie |
|---|---|---|
| [TRACEABILITY.md](TRACEABILITY.md) | Maps every module, objective, research question, and theoretical anchor to a verifiable code location | §1.3, §1.4, §3.6, §2 |
| [EVALUATION.md](EVALUATION.md) | How to reproduce the results chapter; Equation 1 mapping; latency + adversarial tables | §3.9.1, §3.9.2 |
| [EVOLUTION.md](EVOLUTION.md) | Phased roadmap from the current secrets-domain instantiation to the edge-RAG context vision | §2.3–§2.4, Trabalhos Futuros |
| [EVIDENCE-CAPTURE.md](EVIDENCE-CAPTURE.md) | Plan for turning real daily usage into longitudinal operational evidence (audit-log sampling, loader telemetry) | §4.3, RQ1–RQ3 |

Design decisions follow the §3.3 rigor cycle as Architecture Decision Records in
[`../adr/`](../adr/). The two added for the thesis-readiness work:

- [ADR-0010](../adr/0010-privacy-mediation-layer.md) — privacy-mediation layer (`sv-privacy`) and `ANONYMIZED` semantics (module 3b / RQ1).
- [ADR-0011](../adr/0011-dsr-evaluation-harness.md) — DSR evaluation harness (`thesis-eval`) for §3.9.
- [ADR-0012](../adr/0012-context-containers.md) — (Proposed) context containers, on-device embedding index, and privacy-filtered RAG egress — the Phase 2 design from [EVOLUTION.md](EVOLUTION.md).

## Quick reproduction

```bash
cargo test --workspace                                   # all unit/integration tests
cargo run --release -p thesis-eval -- all                # regenerate §3.9 evidence
#   → target/thesis-eval/{latency,adversarial}.{csv,md}
```

See also the broader [`../ARCHITECTURE.md`](../ARCHITECTURE.md),
[`../threat-model.md`](../threat-model.md), and [`../../README.md`](../../README.md).
