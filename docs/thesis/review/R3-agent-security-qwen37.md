# Reviewer C — AI-agent security & threat modeling

**Model:** `opencode-go/qwen3.7-max` (anymodel, independent voice) · **Lens:** agent security / threat model · **Run:** 2026-08 · black-box (paper text only).

> Note (editor): an earlier attempt with `opencode-go/grok-4.5` returned `Router.Unavailable`; `zai/glm-5.1` entered a tool-call loop. This clean run is the retained R3.

## VERDICT: major-revision

## MAJOR ISSUES

1. **§3.9.2 Adversarial eval overclaims desktop mediation** — The battery ran against a SIMULATED HITL policy, not the real desktop consent controller. Attributing "10/10 blocked" to desktop mediation is unjustified. **Fix:** Explicitly state the eval validates WS-transport + simulated-policy enforcement only. Remove any causal attribution to the desktop UI/controller. Either add a separate eval of the real desktop consent path or explicitly exclude it from RQ3 evidence.

2. **§Threat model omits token theft and adaptive attacker** — Adversary = "compromised authenticated MCP agent" but doesn't address how tokens are stolen/leaked, or an attacker who probes and adapts after blocks. **Fix:** Add token theft and adaptive attacker to threat model (in-scope with mitigations, or out-of-scope with justification).

3. **§Limitations Headless scope-erasure is a P0 vulnerability, not a limitation** — Headless authenticator returns empty scopes → full access; headless controller allows crypto ops without mode → oracle. This is a critical security flaw. **Fix:** Move from "limitations/future work" to a critical security disclosure. State headless mode is fundamentally broken and must not be deployed until fixed. Add CVE-style warning.

4. **§Data-flow DIRECT mode exfiltration absent from eval** — DIRECT mode (no prompt) allows reads without consent. Eval doesn't test exfiltration via permitted DIRECT reads. **Fix:** Add DIRECT-mode exfiltration probes to adversarial battery, or explicitly exclude DIRECT mode from security guarantees with user-facing warning.

5. **§PII masking recall gaps understate leakage** — ANONYMIZED mode excludes RG/CEP/names/addresses/unformatted phones. Paper lists this but doesn't quantify leakage or warn users of incomplete protection. **Fix:** Add concrete example (e.g., "João Silva, Rua X, CEP 12345-678" passes unmasked). Recommend user-facing warning when ANONYMIZED mode is active.

## MINOR ISSUES

- **§Crypto Oracle disclosure phrasing** — "não elimina risco de uso como oráculo" is honest but buried. Move to prominent "Security Warnings" section.
- **§Eval reproducibility** — ONE run, 10 probes = no statistical confidence. State explicitly or add confidence intervals.
- **§Audit rollback** — "evidência de adulteração" without external anchor is weak. Clarify that OS-level attacker can replace entire audit log.

## STRENGTHS

- Honest scope boundaries (explicit out-of-scope list)
- Acknowledges oracle risk and headless exclusion from mediation guarantee
- HMAC-chained audit with tamper evidence (even if limited)
- Pre-specified adversarial battery (reduces p-hacking)
- Distinguishes transport-layer enforcement from consent UI
