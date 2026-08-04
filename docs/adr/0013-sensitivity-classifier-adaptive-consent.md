Exit code: 0
Wall time: 1.3 seconds
Output:
# ADR-0013 — Deterministic sensitivity classification and adaptive consent

- **Status:** Proposed
- **Date:** 2026-08-03
- **Deciders:** pealmeida

## Context

Gateway mediation is currently static. A container is configured once as DIRECT,
APPROVAL, OTP, or ANONYMIZED, and the consent gate derives its decision only
from that configured mode. Consequently, highly sensitive content stored in a
DIRECT container can cross the agent boundary without a prompt. The sequence
diagram produced for the Metodologia III course described a different behavior:
High/Low Criticality would determine whether consent was required. That
content-dependent mediation was a design intention, not a capability of the
evaluated artifact.

The gap matters to QP1 only as a usability gap. Static container policy gives
the user control at configuration time, but it cannot react when the syntactic
signals in one item differ from the rest of its container. Adaptive consent is a
usability safety net that reduces accidental exposure of sensitive content in
low-friction containers; it is not a security control. It does not resist the
primary threat-model adversary: an authenticated, compromised MCP agent with
write access. Such an agent knows the public weights and threshold and controls
the content that the classifier sees. The configured container mode, capability
scopes, path validation, and audit trail remain the security controls. The
classifier can only add a consent requirement and never substitutes for any of
them.

The available input is deliberately narrow. sv-privacy currently reports
findings for email, CPF, CNPJ, Luhn-valid credit-card numbers, IPv4,
conservatively formatted phone numbers, and SSN through scan(&str, &Policy) ->
Vec<Finding>. CPF, CNPJ, and credit-card detectors validate checksums. The phone
detector requires either an explicit + form or a parenthesized area code. These
choices trade recall for fewer false positives. The classifier decided here
consumes those findings; it does not create evidence that the current detectors
cover semantic sensitivity or all categories of personal data.

The score is strictly syntactic and is not an assessment of identifiability
under LGPD Art. 5º. A document without formatted PII can remain identifiable
through context, including a full name plus an address. Nor does a high score
mean greater LGPD protection. The classifier is structurally unable to detect
the sensitive-data categories in LGPD Art. 5º, II—racial or ethnic origin,
religious conviction, political opinion, trade-union affiliation or membership
of a religious, philosophical, or political organization, data concerning health
or sex life, genetic data, and biometric data—because those categories do not
have a reliable syntactic form. These are precisely categories to which the law
gives heightened protection.

This decision is also the explicit revisit anticipated by
[ADR-0010](0010-privacy-mediation-layer.md). That ADR rejected a regular-expression
crate plus rule pack *for then-current masking needs* because the supply-chain
and opacity costs outweighed the expected recall gain, while recording that the
choice should be revisited if recall needed to grow. Adaptive consent makes
recall and false positives inputs to a user-experience decision, and the
proposed Brazilian categories enlarge the detector problem. The premise has
therefore changed. Revisiting the trade-off is continuity of the earlier
reasoning, not a contradiction of it.

## Decision

Implement content-dependent mediation as a separate, deterministic classifier
that computes a sensitivity result and may add a consent requirement before
content is released. The implementation remains future work while this ADR has
Proposed status.

### 1. Put DECIDE in a new sv-classify crate

Create a new crate, sv-classify, which depends on sv-privacy and consumes
Finding values. Keep detection and masking in sv-privacy; keep scoring and the
derivation of an adaptive consent floor in sv-classify.

Keeping the classifier as a module inside sv-privacy would reduce workspace
surface and avoid one package boundary. It would also make reuse of private
detector details convenient. However, it would combine two materially different
responsibilities: DETECT (locate and optionally mask data) and DECIDE (influence
whether data may be released). It would also pressure the deliberately small
leaf crate from ADR-0010 to know about gateway security modes or consent policy.

A separate crate preserves sv-privacy as a leaf with no dependency on other
sv-* crates and keeps its detectors auditable in isolation. sv-classify must
depend on the public sv-privacy API, not duplicate detectors or inspect their
private implementation. It returns classification facts and a consent floor
rather than calling the UI or vault directly. The gateway remains responsible
for joining that floor with configured policy.

### 2. Use a deterministic classifier, not an LLM

The classifier is a deterministic function of findings and a user-owned policy.
A local large language model is rejected for three reasons:

1. **Latency.** Local inference would be expected to add orders of magnitude to
   T_gateway and make classification dominate the path measured in thesis
   §3.9.1. No local-model benchmark has been run, so this is an architectural
   cost expectation rather than a new experimental result.
2. **Determinism.** The DSR harness must reproduce a classification from the
   same input and configuration. Model, sampler, and hardware variability would
   complicate that requirement.
3. **Auditability.** An explicit scoring function is inspectable and consistent
   with the Local-First argument of user control and with ADR-0010's rejection
   of an opaque rule pack for an academic artifact. Running a black box locally
   would preserve locality but not explainability.

The accepted cost is bounded recall. Text can reveal health, political,
financial, or other sensitive facts without containing explicit PII. Detecting
that semantic sensitivity is out of scope for this classifier and must remain a
stated limitation.

### 3. Make elevation-only behavior a safety invariant

The configured mode remains authoritative. The classifier produces an
additional consent floor, and the gateway computes the effective release policy
as the join of configured requirements and that floor. The classifier may only
make release stricter; it may never remove masking, approval, OTP, or any other
configured protection. It is therefore an addition to, and not a replacement
for, the gateway's security controls.

ANONYMIZED is not treated as a point in a total ordering of modes: masking is an
egress transformation, while approval and OTP are consent requirements. The
complete mode × state join is:

| Configured mode | Low | Elevated | Unknown |
|---|---|---|---|
| DIRECT | DIRECT | at least APPROVAL | APPROVAL, or deny if approval cannot be obtained |
| APPROVAL | APPROVAL | APPROVAL | APPROVAL, or deny if approval cannot be obtained |
| OTP | OTP | OTP | OTP, or deny if OTP cannot be obtained |
| ANONYMIZED | ANONYMIZED with masking | ANONYMIZED with masking plus APPROVAL | ANONYMIZED with masking plus APPROVAL, or deny if approval cannot be obtained |

Version one uses one elevation boundary: an elevated result raises a no-prompt
read to at least APPROVAL; it does not synthesize OTP from content alone. This
is a version-one limitation, not an implied second threshold.

Classification error, unsupported text encoding, invalid policy, unavailable
classifier state, or a captured panic is Unknown, not Low. At the gateway
boundary, any classifier panic must deny egress; it must never fall back to the
configured-only mode. This fail-closed behavior follows an existing gateway
precedent: the ANONYMIZED path denies non-UTF-8 content because it cannot be
safely redacted (crates/sv-mcp/src/lib.rs:1446). It does not solve silent
misclassification: scan() returns Vec<Finding> rather than Result, so a wrong
low classification can occur without an exception. That residual error is
measured through the pre-registered evaluation rather than misdescribed as an
Unknown path.

Where the local user acts as controller, the classifier is an automated decision
aid under that user's policy; it is not a substitute for legal judgment about
the treatment of personal data.

Required regression tests must prove at least that: sensitive content in a
DIRECT container requires approval; low-scoring content cannot turn APPROVAL
into DIRECT; OTP cannot be downgraded; ANONYMIZED retains masking when approval
is added; and every classifier failure path either adds approval or denies
release. This invariant is part of the security contract, not merely an
implementation convention.

### 4. Use unconditional natural-person identifiers and category volume

The prior density term was structurally defeatable: category risk was added only
once per distinct category, while repeated findings affected a per-KiB density
that an attacker could dilute with filler. Direct calculation of the former
formula gave S=8 for one CPF in 256 B but S=7 for one CPF in 10 KiB of filler,
100 CPFs in 200 KiB, and 1,000 CPFs in 2 MB. This is build–evaluate evidence for
redesign before calibration, not an implementation result.

A validated identifier of a natural person—CPF or SSN—elevates
unconditionally, regardless of document size, score, or count. This closes the
dilution vector for the category that directly identifies a natural person.
CNPJ and credit-card findings do not elevate unconditionally: a supplier CNPJ
on an invoice and a card number on a receipt are common, and unconditional
elevation would create consent fatigue. The latter can make users approve
without reading and defeat the usability purpose of the gate.

For the remaining score calculation, let n_c be the finding count for each
elevation-eligible category c; let C be the number of distinct categories with
at least one finding; and define a sublinear, non-dilutable volume term:

    V_c = min(6, ceil(log2(n_c + 1)))

    S = sum(weight_c for each distinct category c)
        + 2 * max(C - 1, 0)
        + sum(V_c for each distinct category c)

The initial category weights are: CPF 6, credit card 6, CNPJ 5, SSN 5, email 2,
formatted phone 2, and IPv4 1. The proposed default elevation threshold is
S >= 8; CPF and SSN bypass this comparison through the unconditional rule.
Arithmetic and counts must be saturating, never wrapping, and implementation
limits must bound both input work and retained findings.

The structure—not the numerical constants—is decided here: volume replaces
density, with an unconditional rule for validated natural-person identifiers.
The volume cap, logarithm base, weights, diversity increment, and threshold are
starting values subject to the empirical calibration protocol in §7. The
checked examples at threshold 8 are: CNPJ invoice S=6, 50 IPv4 findings S=7,
50 card findings S=12, and 20 emails plus 20 phones S=16. CPF dilution attacks
elevate through the unconditional rule. These values do not claim validated
precision or recall.

The threshold is user-configurable, with a vault-wide default and an optional
per-container override controlled through trusted local configuration. An agent
request cannot supply or relax it. Configuration changes and the effective mode
may be auditable, but audit records must never contain the numerical score,
finding counts, or category composition; they record only the decision and
effective mode. Integrity of the configuration file against a process running
as the same OS user is out of scope under the existing same-user-process
boundary; only the request/API path is in scope here. A deployment that treats
that file as crossing a trust boundary must add integrity protection before
relying on the setting.

### 5. Classify after a local read and before consent and release

The current read order is authentication, request validation, scope enforcement,
consent, vault operation, optional ANONYMIZED filtering, then audit. Content
cannot be classified before it is decrypted, so genuinely content-dependent
consent requires a privileged local read before the consent decision.

The egress boundary is any operation whose response includes bytes originating
from container plaintext, irrespective of operation type. It includes reads,
search results, snippets, previews, and any future operation returning plaintext
fragments. For that boundary, the new order is:

    authenticate -> validate -> enforce scope -> read/decrypt into gateway memory
    -> shared scan/classify -> join configured policy with adaptive consent floor
    -> obtain required consent -> apply ANONYMIZED masking if configured
    -> release response -> audit outcome

Reading to classify is not release: the candidate plaintext remains inside the
trusted local gateway and no data crosses the agent boundary before the joined
decision. Nevertheless, it creates a plaintext exposure window in gateway
memory after decryption and before consent that has no formal memory-isolation
or verified-zeroization guarantee. The buffer must not be logged or included in
audit detail, must be discarded after denial or failure, and must not be
converted into an agent-visible response before consent.

Pre-consent parsing is an enlarged attack surface: parsers process plaintext
that an agent can influence through writes. Every scanner, parser, or later
regex engine used on this path must have explicit complexity and input-size
limits and be subjected to fuzzing before use. The public pre-consent result
must be only the policy decision with generic errors, never a score or finding
detail. Timing, resource-use, or generic-error differences can nevertheless
remain a content-dependent oracle observable even when egress is denied; this
is an accepted limitation of this proposed design, not a claim of constant-time
classification.

Operations whose responses contain no plaintext bytes keep the existing order.
Thesis §3.7 and Figure 3 must eventually make the pre-consent local read
explicit, but only after implementation and evidence exist; this ADR does not
update docs/thesis/paper.tex.

### 6. Add Brazilian detectors in confidence tiers

RG, CEP, full name, address, date of birth, and unformatted phone remain desired
detector categories because their absence is already recorded in Chapter 4,
Limitations and Future Work item (iii). Detector ownership remains in
sv-privacy; sv-classify only assigns evaluated findings a classification role.

The categories do not have equal detector confidence. CPF, CNPJ, and payment
cards have check digits; names and addresses have no comparable structure and
can collide extensively with ordinary prose. RG formats vary by issuing state,
while CEP, dates, and unformatted phone numbers can collide with unrelated digit
sequences. Treating every pattern as equally authoritative would reverse
ADR-0010's deliberate preference for fewer false positives and could create
consent fatigue.

New ambiguous detectors therefore enter a candidate tier: disabled by default,
available for opt-in masking and offline evaluation, and excluded from adaptive
mode elevation until category-specific performance is measured on the labeled
dataset against a pre-registered acceptance rule. Even when enabled, ambiguous
detectors do not prove coverage of personal data; absence of syntactic detection
does not imply absence of personal data. No acceptance value is justified yet.
A detector may become elevation-eligible only through a reviewed policy change
backed by those results. Full-name and address detection remain especially
limited. Version one selects no contextual rule for them; any proposed rule must
be enumerated, evaluated, and reviewed before it is claimed to reduce false
positives.

ADR-0010's regex decision is reopened under the same evidence discipline. An
opaque external rule pack remains rejected. A small, vetted regex engine with
patterns owned in this repository is now admissible if a detector design shows
that it is clearer or measurably improves recall, and only after license,
deny.toml, performance, complexity-limit, fuzzing, and line-by-line rule review.
This ADR does not select or add a dependency. Hand-written scanners remain the
default until that case is demonstrated.

### 7. Extend the DSR evaluation harness

The latency notation in the thesis is the current reference, not the older
additive notation in [ADR-0011](0011-dsr-evaluation-harness.md). For the
affected path, this ADR uses its indicator form:

    T_gateway = T_parse+validation+scope + T_vault
              + I_adaptive(T_scan + T_classify)
              + I_anon(T_filter) + I_consent(T_consent)

T_vault begins after parsing, validation, and scope enforcement and ends when
the local read/decrypt has produced gateway-resident plaintext; it excludes
scanning and classification. T_scan + T_classify begins with that plaintext and
ends after the adaptive floor is joined. The scan is a single shared pass, whose
cost belongs only to T_scan; T_filter is only the masking transformation over
already obtained findings and is zero for non-ANONYMIZED egress. T_consent begins
after the joined decision and ends at consent outcome. The harness must record
timestamps at each of these boundaries. ADR-0011's old notation is therefore
out of date relative to the revised thesis; this ADR records that divergence
without editing ADR-0011 or the thesis.

The evaluation design must gain:

- an ADAPTIVE condition in the microbenchmark, including clean, low-score,
  threshold-boundary, high-score, and Unknown inputs across payload sizes;
- adversarial probes A11 and A12 over the authenticated WebSocket transport,
  where enforce_scopes runs: A11 verifies that eligible sensitive content in a
  DIRECT container requires consent, and A12 verifies that classification can
  never downgrade the configured mode;
- final elevation-decision precision and recall measured per document, plus
  detector precision and recall per finding and category;
- before any execution, a versioned pre-registration of a justified pair
  (recall_floor, precision_floor) for the elevation decision. The values are an
  a-priori author choice, not a reported result. If either floor is missed, the
  QP1 capability claim is not supported: the negative result and observed
  coverage must be reported rather than describing the capability as delivered;
- a versioned train/calibration/test split with its proportions and seed fixed
  before execution. Calibration is conducted only on the calibration split; all
  weights, the volume cap and base, diversity increment, and threshold are
  frozen before the test split is accessed; and the search procedure is versioned
  beside the labeled dataset. This B2 protocol depends on the B0 redesign: a
  structurally defeatable formula is not calibrated;
- a sensitivity analysis for the auxiliary constants, including the volume cap,
  logarithm base, diversity increment, and threshold;
- a synthetic dataset whose generator is independent from detector vocabulary,
  checksums, and heuristics. Its class prevalence and generation seed are
  versioned before calibration, and results are stratified by category as well
  as reported overall;
- an explicit external-validity qualification: synthetic performance may not
  generalize to real Brazilian data, especially for RG, CEP, names, and
  addresses whose linguistic, geographic, and orthographic context synthetic
  data may not reproduce. Any coverage claim must state that limitation.

Without a labeled dataset and the pre-registration above, classifier capability
is not evaluable and no claim about its effectiveness is supported.

## Consequences

- **Positive.** Adaptive consent can reduce accidental exposure of syntactically
  signaled content in low-friction containers while preserving explicit
  container protections. DETECT remains separate from DECIDE, and the decision
  is reproducible and auditable without exposing score details. For QP1, the
  proposed capability is only reduction of accidental exposure of sensitive
  content in low-friction containers, contingent on satisfying the
  pre-registered recall floor; it is not a content-aware security boundary.
- **Negative.** Every adaptive egress decrypts content before consent and adds
  scan and classification latency. False negatives can leave syntactically
  signaled content below the adaptive threshold; false positives can create
  consent fatigue. The classifier cannot detect LGPD Art. 5º, II sensitive data
  (racial or ethnic origin, religious conviction, political opinion,
  trade-union affiliation or membership of a religious, philosophical, or
  political organization, data concerning health or sex life, genetic data, or
  biometric data), because those categories lack a reliable syntactic form.
  High scoring must not be read as stronger LGPD protection. Binary content and
  classifier failures become Unknown; version one cannot synthesize OTP from
  content; and plaintext exists in a pre-consent memory window without formal
  isolation guarantees. A write-controlling adversary can shape content to
  evade the heuristic, and pre-consent timing or resource use can act as a
  limited oracle. A new crate and possible future detector dependency increase
  maintenance, supply-chain, and pre-consent parser attack surface.
- **Mitigation.** Preserve configured modes, scopes, path validation, and audit
  as the security baseline; preserve elevation-only and fail-closed behavior as
  regression invariants; use saturating arithmetic; bound and fuzz plaintext
  parsers; keep plaintext local until consent; and record only the decision and
  effective mode in audit. Gate ambiguous detectors on labeled evidence and
  report precision, recall, latency, dataset limits, and negative results
  without tuning them away. No part of this decision claims LGPD compliance; it
  describes reduction of accidental exposure only.

## Alternatives considered

- **Put classification inside sv-privacy.** Rejected: fewer packages do not
  compensate for coupling detection/masking to an authorization decision and
  weakening the leaf-crate boundary established by ADR-0010.
- **Use a local LLM for semantic classification.** Rejected: expected inference
  latency, non-determinism, model/dependency footprint, and black-box behavior
  conflict with the latency, reproducibility, and auditability requirements of
  this artifact. The loss of semantic coverage is accepted and documented.
- **Use a fixed author-selected score or threshold.** Rejected: it is not
  empirically justified and removes a material privacy choice from the user.
- **Classify only after the existing consent gate.** Rejected: it cannot add
  consent to a DIRECT release and therefore does not implement G1.
- **Classify once when content is written and persist the label.** Rejected as
  the primary mechanism: labels can become stale after content or policy
  changes, imported legacy data has no label, and persisted sensitivity metadata
  creates another disclosure surface. A cache may be considered later only with
  binding to content hash, policy version, and invalidation rules.
- **Defend the adaptive mechanism against a write-controlling agent now.**
  Deferred as future work. Candidate defenses are consent for an agent to read
  content that it wrote itself, and a per-container minimum-finding rule that
  elevates independently of the score. The author instead scopes this version
  as a usability safety net.
- **Import an opaque regex rule pack immediately.** Rejected: the recall need
  now justifies reopening ADR-0010's trade-off, but not outsourcing rules or
  claiming improvement without detector-level evidence. A vetted engine with
  in-repository patterns remains conditionally admissible as described above.

## References

- Thesis §3.6 (reference architecture and privacy mediation), §3.7 (execution
  model), Figure 3 (sequence of mediation), §3.9 (evaluation), Equation 1
  (§3.9.1), QP1, and Chapter 4, Limitations and Future Work item (iii).
- Extends [ADR-0010](0010-privacy-mediation-layer.md) (PII detection, masking,
  and the explicit recall revisit condition).
- Must be evaluated through [ADR-0011](0011-dsr-evaluation-harness.md) (latency
  decomposition, adversarial probes, and reproducible evidence).
- Preserves the configured-mode semantics of
  [ADR-0005](0005-unified-container-model.md).

## Revision history

- **2026-08-03 — revised after R6/R7/R8 peer reviews.** Resolved the density
  dilution blocker by adopting unconditional elevation for validated CPF/SSN
  identifiers and a sublinear per-category volume term; added the DSR
  pre-registration and calibration protocol; and added the LGPD syntactic-scope
  qualifications. Incorporated the accepted relevant and minor findings on
  shared scanning, latency notation and timestamps, authenticated WebSocket
  probes, audit and timing side channels, saturating arithmetic and
  panic-to-deny behavior, pre-consent parser surface, egress definition,
  complete mode × state semantics, synthetic-data limits, evaluator granularity,
  version-one OTP limits, and contextual-rule scope. The author chose to
  downgrade the security claim: adaptive consent is a usability safety net that
  reduces accidental exposure and does not resist a write-controlling adversary.
