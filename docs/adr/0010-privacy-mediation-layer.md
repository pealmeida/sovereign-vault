# ADR-0010 — Privacy-mediation layer and ANONYMIZED container semantics

- **Status:** Accepted
- **Date:** 2026-06-06
- **Deciders:** pealmeida

## Context

The thesis reference architecture (§3.6) defines module 3, the *"Módulo de
Mediação e Filtro de Privacidade"*, as having two halves: (a) cryptographic
intermediation — sign/encrypt with a key that never leaves the vault — and (b)
**masking of PII** (*"mascaramento de PII"*) before context crosses to an
external model. Half (a) shipped in [ADR-0009](0009-broker-and-transit-tools.md)
(`sv-core::transit`). Half (b) did not exist: `SecurityMode::Anonymized` was a
reserved enum variant that the desktop access controller *rejected at runtime*
(`"ANONYMIZED mode is not implemented for live MCP access"`). Research question
RQ1 ("how to securely mediate and **filter** contextual queries") and the
privacy evaluation (§3.9.2) both depend on this half existing.

## Decision

Add a dedicated leaf crate **`sv-privacy`** and give `SecurityMode::Anonymized`
a real runtime meaning.

### 1. `sv-privacy` — detection + masking
A pure-Rust crate (no regex engine, no other `sv-*` deps) so its detectors are
auditable line-by-line and add no supply-chain surface. It exposes
`redact(&str, &Policy) -> Redaction` and `scan(...) -> Vec<Finding>`. Detectors,
biased to the Brazilian/LGPD context: **email, CPF, CNPJ, credit card (Luhn),
IPv4, phone**. Checksum-validated identifiers (CPF/CNPJ/card) reject
plausible-but-invalid numbers, trading recall for a low false-positive rate.
Matches are masked to `[REDACTED:<LABEL>]`; overlaps resolve greedily by
priority.

### 2. ANONYMIZED = auto-allow + mask-on-read
A container in `ANONYMIZED` mode is treated like `DIRECT` by the consent gate —
no human prompt — because the protection is the masking, not a click. The
gateway (`sv-mcp::call_tool`) applies `sv-privacy::redact` to the decrypted
content of an `ANONYMIZED` read **after** the vault op and **before** the
response crosses the agent boundary. The response gains `anonymized: true` and
`pii_redactions: N`. Stored data is never altered — only egress is sanitised.
Non-UTF-8 (binary) content passes through unscanned (documented limitation).

### Wiring
- `sv-mcp`: depend on `sv-privacy`; add `apply_privacy_filter` in `call_tool`;
  emit redaction count to the audit detail.
- `apps/desktop`: route `Anonymized` through the same gate as `Direct` (it was
  an `Err`), so the mask path runs.
- The UI already lists `ANONYMIZED` in the container-creation modal; it is now
  functional rather than rejected.

## Consequences

- **Positive.** Closes module 3(b); makes RQ1 answerable and §3.9.2's
  privacy-resilience claim measurable. The crate is independently testable and
  citable. `ANONYMIZED` becomes a usable third egress-control mode alongside
  `APPROVAL`/`OTP`.
- **Negative.** Detectors are heuristic: recall is bounded (e.g. unformatted
  phone numbers, names, addresses are not detected), and masking only applies to
  UTF-8 text. PII detection is not a security boundary on its own — it
  complements, not replaces, scope + approval.
- **Mitigation.** Validate checksums to keep false positives low; document
  recall limits per detector; treat `ANONYMIZED` as a reduce-exposure mode, not
  a guarantee. The evaluation harness ([ADR-0011](0011-dsr-evaluation-harness.md))
  measures the filter's latency and the gateway's block-rate.

## Alternatives considered
- **Mask inside `sv-storage` at rest.** Rejected: that would corrupt the user's
  own data; the thesis model masks *egress*, not storage.
- **Add a regex crate with a rule pack.** Rejected for now: a new
  supply-chain/`deny.toml` surface and a black-box for an academic artifact;
  hand-rolled, explainable detectors fit the thesis better. Revisit if recall
  needs to grow.
- **A new top-level security mode name.** Rejected: `ANONYMIZED` already exists
  in the enum, the manifest schema, the MCP tool descriptor, and the UI — wiring
  it is lower-churn than adding a parallel concept (consistent with
  [ADR-0005](0005-unified-container-model.md)).

## References
- Thesis §3.6 (module 3), RQ1, §3.9.2 (privacy evaluation), §2.2 (LGPD / Privacy
  by Design).
- Builds on [ADR-0009](0009-broker-and-transit-tools.md) (crypto-intermediation
  half) and [ADR-0005](0005-unified-container-model.md) (one container type, mode
  varies behaviour).
- Evaluated by [ADR-0011](0011-dsr-evaluation-harness.md).
