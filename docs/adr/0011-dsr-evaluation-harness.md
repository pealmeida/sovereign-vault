# ADR-0011 — DSR evaluation harness (latency decomposition + adversarial block-rate)

- **Status:** Accepted
- **Date:** 2026-06-06
- **Deciders:** pealmeida

## Context

The thesis follows Design Science Research: an artifact must be *evaluated*
(§3.9), and the evaluation plan is specific — §3.9.1 decomposes end-to-end
latency per Equation 1 (`T_total = T_vault + T_filter + T_hitl + T_wan +
T_inference`), and §3.9.2 quantifies privacy resilience as the **block-rate**
of a black-box prompt-injection / exfiltration battery. The repository had no
instrument to produce either: no timing instrumentation, no adversarial suite.
Chapter 4 (results) therefore could not be generated from the real artifact.

## Decision

Two pieces: a permanent, opt-in instrument in the gateway, and an external
harness that drives it.

### 1. `sv-mcp::TimingSink` (in-artifact instrument)
An optional sink, installed like `AuditSink`, that receives a `StageTimings`
per tool call. The gateway measures four legs of each call and maps them onto
Equation 1: `validate` (parsing + name/path validation + scope) and `filter`
(PII masking) compose `T_filter`; `authorize` is `T_hitl`; `execute` is
`T_vault` for reads. The external legs `T_wan`/`T_inference` are not
gateway-observable and are out of scope. With **no sink installed the gateway
does no timing work** — zero production overhead.

### 2. `apps/thesis-eval` (external harness, `publish = false`)
A binary with two subcommands that build a throwaway vault and drive the *real*
gateway, writing CSV + Markdown under `--out`:

- `latency` — seeds containers in each mode and payloads of several sizes,
  installs a capturing `TimingSink` + an auto-allow controller, drives N reads
  per cell over `serve_stdio`, and reports per-stage mean/p50/p95. T_hitl is
  flagged as gateway-overhead only (a real human gate is an external parameter).
- `adversarial` — serves over the authenticated **WebSocket** transport so the
  *real* `enforce_scopes`, path validation, and a headless mirror of the desktop
  consent policy are all exercised. A least-privilege agent and the unscoped
  Default agent run an attack battery (out-of-scope reads/writes/deletes, path
  traversal, container enumeration, no-consent secret reads) plus legitimate
  controls. Reports block-rate (attacks blocked) and availability (controls
  allowed).

## Consequences

- **Positive.** Chapter 4 is reproducible from the artifact (`cargo run -p
  thesis-eval -- all`). The adversarial battery exercises real authorization
  code, not a mock, so its block-rate is defensible. The latency decomposition
  maps directly onto the thesis equation.
- **Negative.** Latency figures are environment- and build-dependent; the
  harness must be run with `--release` for representative numbers, and absolute
  values are not portable across machines. The auto-allow controller cannot
  represent human T_hitl. The attack battery is finite — it demonstrates the
  enforced controls, not the absence of all bypasses.
- **Mitigation.** Report methodology (build profile, iterations, host) alongside
  results; treat T_hitl(human) as a separately-stated parameter; frame
  block-rate as coverage of the modelled threat set (§3.9.2), with broader
  fuzzing listed as future work.

## Alternatives considered
- **Criterion micro-benchmarks.** Rejected as the primary tool: it benchmarks
  functions in isolation, whereas §3.9.1 wants the end-to-end gateway path with
  the stages attributed. The harness can still call `sv-privacy`/decrypt
  directly for component figures.
- **Run attacks over `serve_stdio`.** Rejected for the scope attacks: stdio
  binds no agent identity, so `enforce_scopes` would not run. WebSocket pairing
  is the honest path that exercises the isolation claim (RQ3).
- **Bake the harness into `cargo test`.** Rejected: evaluation runs are slow and
  measurement-oriented; keeping them in a separate binary keeps CI fast and the
  instrument explicit.

## References
- Thesis §3.9 (evaluation plan), Equation 1 (§3.9.1), §3.9.2 (prompt-injection
  block-rate), RQ2 (latency) and RQ3 (isolation).
- Exercises [ADR-0010](0010-privacy-mediation-layer.md) (filter latency),
  [ADR-0008](0008-per-agent-identity.md) (scopes), and the OTP/approval flow.
