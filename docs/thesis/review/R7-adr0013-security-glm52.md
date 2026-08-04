# Reviewer G — ADR-0013 security review (scoring, pipeline inversion, adversary model)

**Model:** `zai/glm-4.6` (anymodel, independent voice) · **Lens:** systems security / adversarial analysis · **Run:** 2026-08 · black-box (ADR text only).

## VERDICT: request-major-revisions — the elevation threshold is a calibration heuristic dressed as a security boundary; the scoring formula is structurally defeatable by the primary adversary, and the pre-consent decrypt creates an undeclared computational oracle.

---

## BLOCKING

### 1. Density-per-KiB makes elevation trivially defeatable for any single-category finding (§4, Q5)

**Design flaw, not implementation detail.** The score is `S = sum(weight_c per distinct category) + 2·max(C−1,0) + min(10, ceil(2·D))` where `D = Σn_c / KiB`. Every individual category weight is below the default threshold `S ≥ 8` (CPF/credit card = 6, CNPJ/SSN = 5, email/phone = 2, IPv4 = 1). The category weight is added **once per distinct category regardless of finding count**, so repeated findings of the same type only affect the density term — and density is diluted linearly by document size.

**Concrete attack:** an agent writes a document containing one CPF (`123.456.789-00`, weight 6) padded with 10 KiB of innocuous text. `K = 10`, `D = 1/10 = 0.1`, density term = `ceil(0.2) = 1`. Score `S = 6 + 0 + 1 = 7 < 8`. The DIRECT container releases the CPF to the agent without consent elevation. This works for **every** single PII finding in every category, because no category weight reaches 8 alone.

Worse: the agent can store **N** CPFs and pad to `2·N` KiB, keeping `D ≤ 0.5` and the density term at 1, so `S = 7` regardless of N. A document with 100 CPFs in 200 KiB of filler scores 7. Same-category volume does not meaningfully raise the score because the diversity term only triggers across **distinct** categories.

The ADR does not treat dilution. It describes density as a signal that "repeated findings increase" but never considers the inverse. **Fix:** floor the density term per category (e.g., `min(10, ceil(2·n_c))` before dividing), or require that any single checksum-validated finding (CPF/credit card/SSN) triggers elevation unconditionally regardless of overall score, or drop density for the elevation decision and use it only for OTP-tier escalation.

### 2. Threshold is not a security boundary against a write-controlling adversary (§3/§4, Q4)

**Design gap — not considered by the ADR.** The primary adversary in the thesis threat model is "an authenticated MCP agent, potentially compromised." Such an agent can write to the vault (store user-provided data, save generated documents). The scoring formula, weights, and threshold are all in the open-source repository, so the adversary knows them exactly.

**Concrete attack:** a compromised agent receives sensitive data from the user (e.g., via a chat form) and stores it split across multiple small documents or padded to dilute density (see Finding 1), keeping each document's score below 8. It then issues read requests for each document; each DIRECT read scores < 8, no consent prompt fires, and the data crosses the agent boundary without the user ever being asked. The elevation mechanism provides **zero** protection against the adversary it is designed to stop, because the adversary controls the input to the classifier.

The ADR frames the threshold as a precision/recall calibration problem ("must be calibrated against a predeclared labeled dataset") and tests it with probe A11 (high-sensitivity content must trigger consent). It never considers an adversary who shapes content to **avoid** the threshold. **Fix:** either acknowledge explicitly that adaptive consent is a best-effort UX safety net that does not resist an adversary with write access (and scope the security claim accordingly), or add a defense: per-container minimum findings count that triggers elevation regardless of score, or rate-limit reads by the same agent, or require consent for any agent-initiated read of content the agent itself wrote.

---

## RELEVANT

### 3. Classification is a computational oracle observable before consent (§5, Q1)

**Design oversight.** The ADR argues "reading to classify is not release" because plaintext stays in gateway memory and does not cross the agent boundary. For **direct content exposure** this is correct within the threat model (no memory inspection, no SO compromise). But the argument ignores that classification performs content-dependent **computational work** whose side effects (timing, error messages, resource consumption) are observable by the agent **before** the consent decision.

**Concrete attack:** the agent requests a read of container C in a DIRECT container. The gateway decrypts and scans. If C contains many findings, scanning takes measurably longer than for an empty document. The agent measures the time between its request and the consent prompt (or the denial) and infers finding density. Even on a **denied** read, the agent has learned whether the container holds PII and roughly how much. In the old pipeline, no content-dependent work happened before consent; the inversion introduces this oracle. If a scanner throws on malformed content, the error returned before consent reveals that the content matches a pathological pattern.

The ADR says "the buffer must not be logged or included in audit detail" — this addresses the buffer, not the timing/error channel from the classify stage itself. **Fix:** add constant-time or noise-added scanning for the pre-consent path, or document this oracle as an accepted limitation and restrict pre-consent classification to a binary high/unknown result that does not vary with finding count.

### 4. Recorded score is a content side-channel via audit (§4, Q6)

**Design oversight.** The ADR states "Configuration changes and the effective threshold should be auditable without recording content" and treats the score as safe-to-log metadata. But `S` is a deterministic, invertible function of the content's finding composition. Given the public weights, `S = 6` reveals "exactly one CPF, no other category, low density"; `S = 15` reveals "CPF + credit card + high density."

**Concrete attack:** the agent triggers a read of a container it suspects holds sensitive data. Consent is required; the user denies. The audit logs the score `S = 13`. The agent now knows the container contains CPF + credit card combinations — information it never saw. By triggering reads (even denied ones) across containers and reading the audit log (if accessible via an MCP tool), the agent builds a map of which containers hold which PII categories, entirely through denied requests.

**Fix:** log only the consent decision and the effective mode (`DIRECT → APPROVAL: elevated`), never the numeric score, finding counts, or category breakdown. If the score must be logged for debugging, gate it behind a separate trusted-local-only debug log distinct from the auditable consent trail.

### 5. Bounded arithmetic is a stated requirement with no specification (§4, Q2)

**Implementation gap — acknowledged but unresolved.** The ADR says "Counts and arithmetic must be bounded so adversarially large input cannot overflow or create unbounded work." This is correct as a requirement but the ADR is `Proposed` and gives no bound, type, or saturation rule. If `n_c` is a `u32` and an agent writes a document with > 2³² detector matches (feasible with a large generated document of repeated CPF-like strings), the counter wraps to a small value and the score drops, defeating elevation — a concrete instance of Finding 1's evasion via arithmetic rather than padding.

The "elevation-only" invariant in §3 is a safety contract, but the join logic lives in the gateway, not in `sv-classify`. If the gateway catches a panic from `sv-classify` and falls back to configured-only mode (a natural Rust error-handling pattern), `DIRECT + panic → DIRECT` silently releases without consent. The ADR requires regression tests for this, which is the right call, but the invariant is not yet enforced by type or architecture — only by convention and future tests. **Fix:** specify saturation arithmetic and a panic-→-deny contract at the gateway boundary, not just in `sv-classify`.

### 6. Undeclared surface enlargement: agent-influenced content drives plaintext parsers pre-consent (§5/§6, Q7)

**Design oversight.** Before this ADR, the gateway's computational surface on decrypted plaintext was limited to `sv-privacy` masking. After inversion, decrypted plaintext is fed to `sv-classify` scoring **and potentially a regex engine** (§6 reopens ADR-0010), all processing input that an agent can influence through writes. A pathological document crafted to trigger catastrophic regex backtracking or scanner complexity now causes DoS or error-based leakage on the **pre-consent** path — a path that handles plaintext the agent has not been authorized to see. The ADR notes new crate/dependency surface under "Consequences → Negative" but frames it as maintenance cost, not as attack surface on sensitive data.

Additionally: §4 specifies "per-container override controlled through trusted local configuration" and claims "an agent request cannot supply or relax it." But the threat model places the agent on the same machine, same account. If the configuration file is a local file under that account and the agent has filesystem write access, the agent lowers the threshold to 0 by editing the file directly — not via the request API the ADR's claim covers. Whether this is "malware under the same account" (out of scope) or "compromised agent privilege" (in scope) is ambiguous. **Fix:** declare the pre-consent parser surface explicitly and require fuzzer/complexity bounds on any scanner running on plaintext before consent; clarify whether config-file integrity is in or out of scope.

---

## MENOR

### 7. "Operations without returned content" skips classification — boundary is imprecise (§5, Q3)

§5 applies the new classify-then-consent order only to "egress-producing reads" and says "operations without returned content keep the existing order." The ADR does not define which operations qualify. A list/search/snippet operation that returns content fragments (e.g., a search-hit preview containing a CPF) but is categorized as "metadata" or "non-egress" bypasses classification entirely, and a DIRECT container's content leaks without score or consent. **Fix:** define the egress boundary as "any operation whose response includes bytes originating from container plaintext," and route all such operations through classification regardless of operation type.

### 8. Unknown × ANONYMIZED join is implied but not explicitly specified (§3, Q3)

§3 states that a high score adds APPROVAL to ANONYMIZED "without removing its masking," and that Unknown "must require explicit approval for an otherwise no-prompt release." But the combination `Unknown + ANONYMIZED` is not explicitly enumerated. If the gateway interprets Unknown as "no elevation floor" (neither high nor explicitly low), ANONYMIZED masking is preserved by configured-mode authority, which is fail-closed — but the ADR should state this explicitly for every mode × state pair, as it does for APPROVAL and OTP.

---

## Notes on well-treated risks (resolved in one line each)

- **Determinism and auditability over LLM** (§2): correct rejection; no new risk introduced.
- **Elevation-only as invariant** (§3): the invariant is correctly stated; the gap is enforcement (Finding 5), not intent.
- **Candidate-tier gating for ambiguous detectors** (§6): appropriately conservative; no security issue.
- **Plaintext buffer must not be logged / must be discarded** (§5): correct for the buffer; does not cover the computational oracle (Finding 3).
