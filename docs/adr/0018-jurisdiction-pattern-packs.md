# ADR-0018 — Jurisdiction pattern packs and the detection-extension boundary

- **Status:** Proposed
- **Date:** 2026-09-06
- **Deciders:** pealmeida

## Context

`sv-privacy` detects a fixed set of categories chosen for the Brazilian/LGPD
context of the thesis: email, CPF, CNPJ, Luhn-valid card numbers, IPv4,
conservatively-formatted phone numbers, and US SSN. That set is deliberate and
its calibration is thesis-locked ([ADR-0010](0010-privacy-mediation-layer.md)).

It is also, for a user outside Brazil, close to useless. A German user's
Steuer-ID, a UK NINO, an Italian Codice Fiscale, an Indian Aadhaar, a Spanish
DNI, and an IBAN are all personal data under their respective regimes, and the
artifact detects none of them. The requested capability is to let users — and
companies deploying the vault — add pattern sets matching the identifiers their
own jurisdiction's data-protection law cares about, and to do so as a
distributable artifact rather than a code change.

Three constraints shape the design.

**`sv-privacy` must not change.** Its single-dependency property and its
measured calibration are load-bearing for the thesis. Any extension mechanism
has to live outside it.

**A pattern pack is untrusted input that decides what counts as sensitive.**
This inverts the usual risk. A pack that matches *nothing* is more dangerous
than one that matches too much: it silently reduces detection while the user
believes they have increased it. The failure is invisible by construction.

**National identifier formats are genuinely irregular.** IBAN is variable-length
per country with a mod-97 check over a reordered, alphabet-mapped string.
Codice Fiscale mixes letters and digits with an odd/even character map. CURP
embeds a date. A "small declarative matcher" that covers these honestly becomes
a regex engine with less scrutiny than a real one.

## Decision

Add a crate **`sv-patterns`** holding declarative jurisdiction packs, wire it
into `sv-scan` as an opt-in detection *extension*, and leave `sv-privacy`
untouched.

### 1. Packs extend detection; they never redefine protection

This is the invariant the rest of the design serves.

- Baseline detection — `sv-privacy` categories and the `sv-scan` secret rules —
  is **always on**, regardless of which packs are enabled. Enabling a pack
  cannot turn any of it off.
- A pack may not reuse a baseline rule id, suppress a baseline finding, or
  express an exemption. There is no "ignore" or "allow" verb in the pack format.
- Disabling baseline detection, if it is ever supported, is a separate and
  visible configuration change, never a side effect of loading a pack.
- Pack-supplied confidence is a *hint*. It never by itself authorises a
  redaction or changes an access policy.

A pack can therefore only ever *add* candidates. The worst a bad pack achieves
is noise or wasted work — never a silent reduction in coverage.

### 2. Packs are validated before use, with explicit budgets

A pack is parsed into a `ValidatedPack` before any file is scanned. Validation
requires:

- a schema version, and rule ids namespaced by pack id;
- bounded lengths, non-empty matchers, and a validator drawn from the known set;
- **positive and negative test vectors for every rule**, executed as a
  conformance check at load time. Self-authored examples establish internal
  consistency, not detection quality — but a rule whose own examples fail is
  rejected outright.

Evaluation runs under explicit budgets: maximum pack size, rule count, candidate
length, per-file evaluation work, and findings per file. Exhausting a budget, or
rejecting a pack, is reported as **incomplete coverage** — never as a clean
scan. This matters because the equivalent of catastrophic backtracking still
exists without a regex engine: overlapping length ranges and optional separator
runs can be explored combinatorially.

Enabled packs are pinned by version and content digest. Updates show added,
removed, and changed rules before being applied; nothing updates silently.
Signatures, where present, establish publisher identity — not correctness. A
locally imported unsigned pack is allowed with its provenance recorded.

### 3. Overlapping matches keep all their evidence

When a baseline detector and one or more pack rules match the same span, the
span carries multiple `RuleEvidence` entries rather than one winner. Pack
ordering never erases evidence. The user sees that a value looked like both a
CPF and a generic 11-digit identifier, which is information, not a conflict to
be resolved silently.

### 4. A reviewed regex engine, scoped to `sv-patterns`

[ADR-0010](0010-privacy-mediation-layer.md) rejected a regex crate *for the
then-current masking needs*, and explicitly recorded that the decision should be
revisited if recall needed to grow. **That condition is now met.** Supporting a
dozen national identifier formats is exactly the recall growth anticipated.

The engine is confined to `sv-patterns`. `sv-privacy` keeps its single
dependency and its calibration. The trade-off is accepted deliberately: at the
point where a hand-rolled matcher needs alternation, optional separators,
nested repetition, and Unicode semantics, maintaining it is *more* risk than
depending on a reviewed, pinned engine with documented complexity bounds. The
selected engine must be reviewed for its dependency closure, licence
(`deny.toml` allowlist applies), and compilation limits; regex *compilation*
itself is budgeted, not just execution.

Structure-matching and validation are separated: the pattern finds a candidate,
and identifier-specific code validates it. Validators are **named and
versioned** — `ValidatorId::IbanV1`, `ValidatorId::VerhoeffV1` — not a coarse
`Mod11`/`Mod97` enum, because a bare modulus does not specify normalisation,
weighting, excluded sentinel values, checksum position, or per-country length.
Each validator carries independently-sourced test vectors.

### 5. Default is baseline plus explicit opt-in

Enabling every pack means every 9-to-18 digit run matches something, and the
checksums are weak: Luhn is a single decimal check digit (~3.3 bits), so roughly
one arbitrary digit run in ten passes it. A single Android vector drawable in a
real project produced 709 false card matches and 56 false CNPJ matches from path
geometry.

So: baseline detectors always on, packs **explicitly opted into**. The user's
locale may *suggest* packs; it never defines coverage, because locale-only
selection misses exactly the multinational customer dataset that most needs
scanning. Curated presets are offered, and the active scope is displayed
prominently in every report.

### 6. Reports state evidence, not legal conclusions

A pack declares optional `regulatory_references` — *not* a `legal_basis` field.
The distinction is the point. A finding reports the pack id, pack version, rule
id, candidate type, supporting evidence, and confidence:

> candidate Brazilian CPF; checksum passed; pack `br-lgpd@1.2.0`, rule
> `br-lgpd/cpf`

It does **not** report "this is personal data under LGPD Art. 5". Checksum
success establishes structural plausibility. It cannot establish authenticity,
ownership, sensitivity, or that any legal regime applies. The artifact is not
in a position to make that determination and must not appear to.

### 7. This is a detection-rule format, not a plugin runtime

Packs are declarative data: patterns, validators, and metadata. There is no code
execution, no dynamic library loading, and no WASM. Calling this a "plugin
system" for tools and models would overstate it, and that claim is not made —
here or in the thesis text.

## Consequences

- **Positive.** The artifact becomes useful outside Brazil without touching the
  thesis-calibrated crate, and jurisdiction coverage becomes a distributable
  artifact rather than a code change.
- **Positive.** The extend-never-replace invariant means the dangerous failure
  mode — a pack that silently reduces detection — is not representable.
- **Negative.** A regex engine enters the workspace, reversing part of
  ADR-0010's reasoning. Confined to `sv-patterns`, budgeted, and pinned, but
  real.
- **Negative.** Pack quality is unmeasured. Conformance vectors prove internal
  consistency only; precision and recall of a third-party pack against real data
  are unknown, and the report must not imply otherwise.
- **Negative.** More enabled packs means more false positives, given weak
  checksums over digit runs. Opt-in plus prominent scope display mitigates but
  does not eliminate this.
- **Open.** Whether a curated distribution channel is worth operating, and who
  vets packs for it, is not decided here.

### Thesis claims this decision does *not* support

- That the artifact determines legal applicability of any data-protection
  regime, or classifies data under LGPD, GDPR, or any other law.
- That pack-based detection has measured precision or recall.
- That this constitutes a general plugin interface for external tools or models.
- Any change to `sv-privacy`'s measured calibration, which is unchanged.

## Alternatives considered

- **Extend `sv-privacy` with new categories directly.** Rejected: it would
  change a thesis-calibrated crate's measured behaviour and add a regex engine
  to the one crate whose auditability claim depends on having none.
- **Hand-roll a declarative matcher struct with no regex engine.** Rejected
  after review. It survives CPF/SSN-shaped formats but not IBAN, Codice Fiscale,
  or CURP; supporting those means implementing alternation, optional separators,
  and character-class maps — a regex engine with less scrutiny than a real one.
- **Enable all packs by default for maximum coverage.** Rejected: with weak
  checksums this converts every long digit run into a finding, and the resulting
  noise is itself a safety failure because it buries true positives.
- **Executable plugins (dynamic libraries or WASM).** Rejected for v1: it puts
  third-party code on the security path of a vault, for a capability that
  declarative data already covers.
- **Let packs express exemptions or allow-lists.** Rejected: an exemption verb
  is precisely the mechanism by which a malicious pack would silently disable
  protection.
- **A `legal_basis` field naming the applicable statute.** Rejected: it invites
  the report to state a legal conclusion the artifact cannot support.

## References
- Revisits the regex/rule-pack rejection recorded in
  [ADR-0010](0010-privacy-mediation-layer.md) under the revisit condition that
  ADR stated.
- Extends the scanner boundary set by
  [ADR-0017](0017-project-scanning-and-remediation-boundary.md).
- Consistent with [ADR-0013](0013-sensitivity-classifier-adaptive-consent.md):
  content-derived signals are usability measures, never security controls, and
  cannot detect the LGPD Art. 5º II categories that have no syntactic form.
- Workspace layout convention from [ADR-0001](0001-cargo-workspace-layout.md).
