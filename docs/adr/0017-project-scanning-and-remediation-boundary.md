# ADR-0017 — Project scanning and the discovery/remediation boundary

- **Status:** Proposed
- **Date:** 2026-09-06
- **Deciders:** pealmeida

## Context

The vault currently receives data that the user hands it. Nothing in the
artifact goes looking for sensitive material already scattered across the user's
machine — the `.env` files, hard-coded keys, and personal data in project
directories that the README names as the problem the vault exists to solve. The
requested capability closes that loop: scan local project directories for
secrets, keys, PII, and other personal data; store what is found in the vault;
rewrite the working files so the sensitive bytes are gone but the material stays
findable through the durable locators of
[ADR-0016](0016-durable-public-locators-and-discovery-policy.md).

Three constraints shape where that code can live.

**`sv-privacy` is deliberately dependency-free.** It depends on `serde` and
nothing else, because [ADR-0010](0010-privacy-mediation-layer.md) rejected a
regex engine and rule pack on supply-chain and auditability grounds. A scanner
needs gitignore-aware directory walking, binary sniffing, bounded reads, and
probably rule-pack parsing. Putting any of that inside `sv-privacy` would
silently reverse a recorded decision and enlarge the audit surface of the crate
whose whole claim is that its detectors are readable line by line.

**Rewriting a user's source files is destructive.** It is the first operation in
the artifact that mutates data the vault does not own, in a directory the user
did not hand over, based on a heuristic detector whose recall limits are already
documented as bounded. A false positive does not produce a bad answer; it
corrupts a file. This is a different risk class from everything the artifact
does today and cannot be sequenced as an afterthought of detection.

**Detection quality is unmeasured for this use case.** `sv-privacy`'s detectors
were built and evaluated for masking egress text, not for sweeping a repository.
Their precision and recall against real project trees — configuration files,
lockfiles, test fixtures, vendored code, minified assets — is not known. Driving
an irreversible rewrite from an unmeasured detector inverts the correct order of
operations.

There is also a scope conflation in the request worth naming. "Vulnerabilities"
and "sensitive data" are different findings with different remedies. A leaked
key is remediated by moving it into the vault and redacting it. A vulnerable
dependency is remediated by upgrading it; redacting it would be meaningless.
They share a scanner and a report, not a remediation path.

## Decision

Separate **discovery** from **mutation**, in both crate layout and delivery
order.

### 1. Crate boundaries

| Crate | Responsibility |
|---|---|
| `sv-privacy` | Unchanged. Pure PII detection and masking; `serde` only. |
| `sv-scan` *(new)* | Read-only discovery: directory walking with ignore semantics, bounded reads, binary detection, secret-format rules, `ScanFinding`, and explicit coverage/skip accounting. |
| `sv-runtime` | Locator and reference contracts, discovery authorization, policy, consent. Gains the `PublicLocator` and `DiscoveryPolicy` types of ADR-0016. |
| `sv-remediate` *(new, later phase)* | Mutation: `RewritePlan`, encrypted `RecoveryRecord`, `RewriteJournal`. Composes vault storage, runtime authorization, and filesystem replacement. |
| `apps/cli`, `apps/desktop` | Orchestration and presentation only. |

`sv-scan` depends on `sv-privacy` for PII detection and adds its own detectors
for secret formats. It performs no writes and holds no vault credentials, which
makes it reviewable in isolation and keeps the dependency growth (a directory
walker, and later a regex engine for rule packs) out of `sv-privacy`.

`sv-remediate` is the only crate permitted to modify files outside the vault.
Isolating that authority in one crate makes the destructive surface auditable at
a glance.

### 2. Discovery is read-only and reports masked

`sv-scan` returns findings; it never returns the matched secret. A `ScanFinding`
carries the file path, the byte span, the category or rule that matched, and a
masked preview — never the raw value. A scan report is therefore itself safe to
show to an agent, write to disk, or attach to a thesis artifact.

Coverage is reported explicitly. Files skipped for size, for being binary, for
an unreadable encoding, or by ignore rules are counted and surfaced. A scanner
that silently skips is a scanner that overstates its own coverage; the count of
what was *not* examined is part of the result.

### 3. Detection: deterministic first, no model in phase 1

The security-relevant detection path stays deterministic. Phase 1 adds
inexpensive recall improvements over the existing `sv-privacy` categories:

- known-key **format checks** (prefix, length, alphabet) for well-published
  credential shapes;
- **keyword proximity** (an assignment to a name like `api_key`, `secret`,
  `token`, `password` raises confidence in an adjacent candidate);
- **entropy** as *supporting* evidence only, never as a finding on its own —
  entropy alone is noisy on lockfiles, hashes, and encoded assets.

A local LLM or ML model is **not** shipped in phase 1. It is deferred to a later,
measured experiment under the terms of
[ADR-0013](0013-sensitivity-classifier-adaptive-consent.md): a model may only
**add** candidates for human confirmation, may never suppress a deterministic
finding, and may never authorize a rewrite. Adopting one requires recording
precision, incremental recall, review burden, latency, and memory — not an
assertion that it helps. Note that the workspace `unsafe_code = "forbid"` lint
constrains first-party code and says nothing about an inference backend's own
safety or supply chain.

Rule packs from established scanners (gitleaks and similar) are treated as
**versioned, licensed, reviewed inputs**, adopted as a small supported
vocabulary. Calling a rule pack "data rather than a dependency" does not remove
the supply-chain question or the need for a regex engine to execute it. Licenses
must clear `deny.toml`; AGPL-3.0-licensed scanners are studied for technique
only and are not vendored or depended upon.

### 4. Mutation, when it arrives, is journalled and per-file atomic

`sv-remediate` is specified now and built after phase 1:

- **Diff first.** A `RewritePlan` is produced, reviewed, and approved before any
  byte is written. Dry-run is the default, not a flag.
- **Vault before file.** The original value is durably stored in the vault and
  its locator mapping committed *before* the file is replaced. The ordering is
  what makes an interrupted run recoverable rather than destructive.
- **Per-file atomic, journalled — not a transaction.** Each file is replaced
  atomically (`atomicwrites`, with `fs4` locking, both already workspace
  dependencies). A multi-file run is *not* atomic; a `RewriteJournal` records
  progress so an interrupted run can be resumed or rolled back, and crash
  recovery is a supported path rather than a manual cleanup.
- **Idempotent.** An existing `[SV:LOC:v1:...]` or `[REDACTED:...]` marker is
  never re-redacted, and a marker is never itself treated as a finding.
- **Restorable.** Every redaction writes an encrypted owner-side
  `RecoveryRecord`, including for `Opaque` discovery policy. Restoration is
  conflict-checked: if the file changed after the rewrite, the user is told
  rather than silently overwritten.

### 5. Vulnerability findings are reported, not redacted

Vulnerability scanning (dependency advisories via the existing `cargo-audit` and
`cargo-deny` posture, and comparable ecosystem sources) shares the scan report
and remediation *adapters*, but never the redaction path. A vulnerable
dependency is not a secret to be moved into the vault.

### 6. Relation to the ADR-0015 sequence

The implementation order fixed by
[ADR-0015](0015-runtime-mediation-stack.md) — `sv-runtime` → LLM gateway → MCP
router → process broker — governs the **mediation data plane**. A read-only
scanner is orthogonal to it and is not blocked by it. Agent-facing *resolution*
of locators and any brokered use of recovered material do sit on that path and
must respect its sequencing.

## Consequences

- **Positive.** Phase 1 ships something genuinely useful and genuinely safe: a
  read-only inventory of what sensitive material exists in the user's projects,
  with honest coverage accounting, that cannot corrupt a file because it cannot
  write one.
- **Positive.** The destructive capability is confined to one crate, arrives
  after detection quality is measurable, and is specified with journalling and
  recovery from the start rather than retrofitted.
- **Positive.** `sv-privacy` keeps its single-dependency property and the
  auditability claim of ADR-0010 stays true.
- **Negative.** The user's stated goal — redact and vault — is not fully
  delivered by phase 1. Detection lands first; rewriting follows. This is
  sequencing, not refusal, and the reason is that an irreversible rewrite driven
  by an unmeasured detector corrupts source files.
- **Negative.** Two new crates enlarge the workspace, and `sv-scan` introduces a
  directory-walking dependency the workspace does not have today.
- **Negative.** Scanner recall is bounded by the same detector limits already
  recorded in ADR-0010. A clean report is evidence of what the detectors found,
  never proof that a project contains no secrets, and must never be presented as
  the latter.

### Thesis claims this decision does *not* support

Per `AGENTS.md`, stating the boundary is part of the decision. This work does
**not** establish:

- that scanning finds all secrets or all personal data in a project — recall is
  bounded and unmeasured against real project trees until evaluated;
- any semantic, embedding-based, vector-index, or RAG capability;
- any OS-level isolation of the scanned material;
- that redaction removes data from Git history, backups, or copies made before
  the scan;
- that a local model improves detection — no model ships in phase 1, and any
  future adoption requires measured precision and incremental recall.

## Alternatives considered

- **Put scanning inside `sv-privacy`.** Rejected. It reverses ADR-0010's
  dependency decision by adding a walker and a regex engine to the crate whose
  auditability claim rests on having neither.
- **Ship scanning and rewriting together in phase 1.** Rejected. Rewriting is
  irreversible and would be driven by a detector whose precision on project
  trees is unmeasured; a false positive corrupts a source file. Detection first
  makes the error rate observable before it can do damage.
- **Ship a local model in phase 1 for better recall.** Rejected for now. It
  would add an inference backend and its supply chain to the security path, and
  the thesis cannot claim a recall improvement that has not been measured.
  Deferred to a measured experiment under ADR-0013's terms.
- **Shell out to gitleaks or trufflehog.** Rejected as a dependency. It puts an
  external binary on the security path, makes findings depend on an unmanaged
  installation, and TruffleHog's AGPL-3.0 license is outside the `deny.toml`
  allowlist. Their *rules and techniques* are studied; their code is not
  vendored.
- **Rewrite files in place with a plain backup copy.** Rejected as insufficient.
  A `.bak` beside the original leaves the secret in plaintext on disk — the
  precise outcome the feature exists to eliminate — and offers no crash
  recovery. Hence the encrypted `RecoveryRecord` plus journal.
- **Make the multi-file run transactional.** Rejected as not achievable over an
  ordinary filesystem for an arbitrary user directory. Per-file atomicity plus a
  resumable journal is the honest guarantee, and is stated as such rather than
  overclaimed.

## References
- Consumes the locator and `DiscoveryPolicy` decisions of
  [ADR-0016](0016-durable-public-locators-and-discovery-policy.md).
- Constrained by the dependency decision in
  [ADR-0010](0010-privacy-mediation-layer.md) §"Alternatives considered".
- Model adoption governed by
  [ADR-0013](0013-sensitivity-classifier-adaptive-consent.md).
- Orthogonal to, and not blocked by, the sequencing in
  [ADR-0015](0015-runtime-mediation-stack.md).
- Workspace layout convention from
  [ADR-0001](0001-cargo-workspace-layout.md).
