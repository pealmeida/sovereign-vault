# Reviewer B — DSR methodology & statistics

**Model:** `zai/glm-5.2` (anymodel, independent voice) · **Lens:** Design Science Research + statistics · **Run:** 2026-08 · black-box (paper text only, no repo access).

## VERDICT: accept-with-revisions

The revision is substantially defensible — overclaims removed, threat model boxed, indicator-term decomposition adopted, two-arm protocol honestly demoted to future work. Remaining flaws are concrete and correctable; none invalidates the proposal, but two are factual inconsistencies that must be fixed before any defense.

## MAJOR ISSUES

1. **§3.9.1 Eq. (3.1) vs. methodology table — false "escopo" measurement.** The harness drives `serve_stdio`, which enters `PairState::AlreadyPaired(None)`; `call_tool` invokes `enforce_scopes` only when a scoped agent is resolved. Therefore the term `T_parse+validação+escopo` and the table cell "Medido: validação/escopo" are *not* what the CSV contains — scope enforcement was never timed. *Fix:* either re-time on the authenticated WS path (the adversarial battery already uses it) or rename the term/cell to "validação (sem agente/escopo no stdio)" and add an explicit "scope-enforcement cost not measured" caveat.

2. **§3.9.2 / §4.3 — adversarial battery does not exercise desktop mediation.** The battery injects a test-double `HitlPolicy`, not the desktop `ApprovalState` controller; transport/pairing errors are counted as "blocked" with no per-probe attribution preserved. Yet the threat-model box and the evidence table attribute "mediação desktop WS" to the 10/10 result. *Fix:* relabel as "integração WS com política HITL simulada," log per-probe JSON-RPC response / error class / expected audit event, separate transport failures, and either run once against the real desktop controller or strike the desktop-mediation claim for this battery.

3. **§3.9.1 Eq. (3.2) `T_e2e` — estimand undefined.** No operational boundary (one MCP call vs. multi-turn agentic task; client serialization; model planning; tool↔model round-trips). `T_cliente↔WAN` and `T_rede_resposta` overlap semantically. The equation currently does no analytical work — unmeasurable and unfalsifiable. *Fix:* restrict to a single instrumented MCP call with explicit timestamps/exclusions, or model the task with N turns and named client/orchestration terms. Do not use Eq. (3.2) for any user-experience inference until then.

4. **§3.3 / §3.9 — Venable FEDS quadrant not positioned.** FEDS is cited generically as "naturalistic and artificial methodologies," but its two axes (artificial↔naturalistic × formative↔summative) are never mapped. The current evaluation is *artificial summative*; the future two-arm is *naturalistic summative*. *Fix:* state the quadrant explicitly so the reader understands evaluation strategy and its generalizability ceiling.

5. **Microbenchmark statistical reporting.** N=1000/cell, single host, single run, no CIs, no warmup/exclusion protocol, no across-run dispersion; p95 reported without dispersion. Borderline acceptable as preliminary evidence, but §4 / appendix call the figures "representativas" while admitting storage/power-mode "to be recorded on final run." *Fix:* k≥3 independent sessions; per-cell 95% bootstrap CI; explicit warmup/exclusion rule; relabel as "execução preliminar de desenvolvimento."

6. **§3.4 Peffers — retrospective risk.** Peffers is presented as forward planning, but the artifact pre-dates the proposal; reverse-fitting is likely. *Fix:* either reframe as retrospective Peffers trace or strengthen formative-evidence (ADR log) showing genuine build-evaluate iteration (the A9/A10 NATIVE fix is a good example — surface it as a rigor-cycle artifact).

7. **§3.3 Hevner rigor cycle is thin.** Presently only NSA/MCP/Kleppmann. To defend empirical security/privacy claims, the rigor cycle should also cite security-evaluation methodology and PII-measurement literature.

## MINOR ISSUES

- §4.2 "Tabela 3.2" is a manual cross-ref that breaks under abntex2 auto-numbering; no `\label`/`\ref` exists for any table. Add labels.
- Appendix admits "to be recorded on final run" while Chapter 4 calls numbers "representative" — internal inconsistency; reconcile.
- §3.5 March&Smith *Model* (reference architecture) is asserted but never separately evaluated; add one-line limitation.
- Eq. (3.1) uses `T_espera_humana` inside the indicator but §3.9.1 prose still implies it is a per-call µs overhead for APPROVAL/OTP — ensure the prose mirrors the "report as distribution" rule.

## STRENGTHS

- Threat-model box is now explicit and internally consistent with `threat-model.md`.
- Indicator-term decomposition of Eq. (3.1) is methodologically cleaner than the prior single additive sum.
- `EVAL-PROTOCOL.md` is exemplary future-work framing: pre-registered outcomes, paired A–B design, bootstrap CIs, explicit "no equivalence without significance" caveat.
- RQ↔objective↔artifact alignment is coherent after P0.1 / P1.4 / P1.5; Objective 4 (Option A) is honestly scoped.
- Evidence-boundary table opening Chapter 4 is best-practice DSR rigor and should be retained verbatim.
- ADR-anchored DSR design cycle (esp. the NATIVE→consent-gate fix) is genuine iteration evidence — surface it more prominently in §3.3.
