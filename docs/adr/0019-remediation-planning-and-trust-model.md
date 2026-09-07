# ADR-0019 — Remediation planning and the trust model

- **Status:** Proposed
- **Date:** 2026-09-07
- **Deciders:** pealmeida

## Context

[ADR-0017](0017-project-scanning-and-remediation-boundary.md) separated
discovery from mutation and specified the mutation side before building it.
This ADR fixes the part of that specification that decides whether a
remediation can be trusted: what an approval approves, what the executor
verifies before it touches a byte, what is selected by default, and what each
artifact in the flow — plan, suppression file, marker, audit record — may and
may not reveal.

Two structural facts shape the whole decision.

**Approval and execution see different bytes.** `sv-scan` never returns the
matched value; it returns masked previews (opaque by default since the
2026-09-07 amendment to ADR-0017 §2). `sv-remediate` must nevertheless place
the *raw* value durably into the vault and remove the *raw* bytes from the
file. Every remediation therefore re-reads bytes from disk at execute time,
after a human has approved a plan built from masks. The plan format and the
execute algorithm below exist to make that gap safe rather than to deny it.

**Confidence and remediation-worthiness are different properties.** The scan
campaign recorded in §5 — 71 real projects, 1,353 high-confidence and 7,009
medium-confidence findings over 38,313 files scanned, against 792,430 files
ignored — shows that a high-confidence label is not a remediation instruction.
A selection surface designed as if it were would manufacture consent at scale.

## Decision

### 1. The plan-execution gap: approval binds to an exact file snapshot

Because the executor re-reads bytes the human never saw, approval cannot be
bound to "the finding" in the abstract. It is bound to an exact file snapshot,
and an approved edit is **never silently relocated**: if the file the plan
describes is not the file on disk, the plan fails; it does not follow the
bytes somewhere else.

A `PlanItem` therefore carries:

- the project id and the normalized relative path beneath the approved root;
- the OS file identity (device and inode on Unix, file index and volume on
  Windows), so a file replaced, renamed, or restored between scan and execute
  is detected as a different file;
- a **keyed** digest of the whole file bytes;
- the byte span of the match;
- a **keyed** digest of the matched bytes;
- the pinned detector version and rule-pack version the plan was built with;
- the intended replacement.

The digests are keyed under a vault key, not plain hashes. An unkeyed digest
of a small-domain value — a CPF has on the order of 10¹¹ possibilities, and
real phone numbers far fewer — is brute-forceable back to the very value it
was meant to protect: hash the candidate values, compare, recover. This is
the same reasoning that puts keyed HMACs on the audit log's sensitive fields;
a plan file must be storable and reviewable without becoming a side channel
on its own contents.

### 2. The execute algorithm

For each `PlanItem`, in this order:

1. Open the file beneath the approved root only, rejecting symlink and
   reparse-point traversal and any unexpected file identity.
2. Take the `fs4` cooperative lock.
3. Verify the keyed digest of the whole file.
4. Verify the span bounds against that file.
5. Verify the keyed digest of the matched bytes at that span.
6. Re-run the **pinned** detector — the same rule and rule-pack versions the
   plan was built with — and require matching evidence at exactly that span.
7. On **any** mismatch, stop that file and require a fresh plan and a fresh
   approval. A mismatch is never healed, retried, or re-anchored.
8. Overlapping findings were already resolved before approval. Overlap
   resolution never happens at execute time; execution is mechanical by
   construction.
9. Commit the vault material, the locator mapping, the encrypted
   `RecoveryRecord`, and the journal entry **before** the atomic replace —
   the vault-before-file ordering of ADR-0017 §4, which is what makes an
   interrupted run recoverable rather than destructive.

### 3. What this design does not cover

Stated plainly, because the guarantees above are easy to overread:

- **A cooperative lock is not a guarantee.** `fs4` locking stops only writers
  that cooperate, and atomic replace is not compare-and-swap: a
  non-cooperating writer can race between the last verification and the
  replacement. v1 therefore *requires quiescent files* — the UI says so, and
  the operator is responsible for it. This is an honest limitation, not a
  solved problem.
- **Redaction does not preserve source semantics.** Inserting a
  `[SV:LOC:…]` marker can break a config parser, a fixed-width field, or a
  running service that reads the file. The dry-run diff exists precisely so a
  human judges this before approval; the tool does not, and cannot, promise
  the rewritten file still works.
- **Redaction is not history deletion.** It does not remove the secret from
  Git history, from backups, or from copies made before the scan (see §6).
- **Multi-file runs are not transactional.** They are per-file atomic and
  resumable through the journal, as decided in ADR-0017.

### 4. Masked approval authorizes an occurrence, not a classification

Approving a masked finding authorizes **one specific occurrence and one
specific operation**. It does **not** establish that the classification is
correct — that the match is a live credential, that it belongs to the user,
or that redacting it is wise. The UI shows the location and minimal context,
offers an explicit *audited reveal* (`ScanReveal`) for a human who needs to
see more, and **never infers consent from a confidence score** — the same
principle ADR-0013 applies to model-produced signals: a signal may inform a
human, never substitute for one.

### 5. Default selection is zero, on measured grounds

Nothing is preselected. Not even a high-confidence, live-looking credential.
The user arrives at an empty selection and affirms each occurrence.

The classes that are **never** preselected, and the measured reasons:

- `pii:email` — 6,215 hits in the campaign below, overwhelmingly
  documentation, licenses, and CI metadata;
- numeric PII generally — dominated by incidental digit runs;
- generated-artifact paths (`out/`, `dist/`, `target/`, `node_modules/`);
- test fixtures (`*.test.*`, `.env.example`, `.env.fake`);
- by-prefix test credentials (`stripe_test_key`).

The measured basis: scanning 71 real projects produced 1,353
high-confidence and 7,009 medium-confidence findings over 38,313 files
scanned, against 792,430 files ignored. Of the 1,027 `pii:credit_card` hits,
1,002 were Solidity build-artifact bytecode passing the Luhn check by chance —
a single decimal check digit contributes about 3.3 bits (log₂ 10), so
roughly one arbitrary digit run in ten passes it.

This is a measurement about **one class** and must **not** be generalized
into a false-positive rate for high-confidence findings as a whole. It is the
grounds for the zero-selection default, not a precision claim. Confidence is
a detector signal; remediation eligibility is a human decision.

### 6. Redaction is not the remedy for an exposed credential — rotation is

The campaign found two committed `GITHUB_TOKEN=gho_` values in tracked,
non-gitignored `.env` files. For such a finding, rewriting the working file
removes the bytes from the working tree and does nothing else: the value is
already in Git history, and it is already on the provider's side the moment
it left the machine. The remedy for an exposed credential is to **rotate or
revoke it**. The UI leads with rotate/revoke for credential-class findings;
redaction is containment of the remaining copy, not the cure.

### 7. Suppression state, split by trust

- **In-repo `.svignore` — an untrusted proposal.** It holds a namespaced
  rule id, a narrow path scope, a reason, an **expiry**, and an opaque
  finding id — and **no values and no value-derived hashes** (a hash of the
  value would be the brute-force oracle of §1 in miniature). The file is
  git-reviewable, which is its value, and attacker-editable, which is its
  limit: a contributor can add an entry that hides a live credential from the
  next scan. Every entry is therefore a proposal that requires **local
  acceptance** before it suppresses anything, and it rots on its expiry date.
- **Encrypted vault state — trusted, but local.** Occurrence fingerprints and
  scan history live in vault state, which the repo cannot forge. It does not
  travel with the repo: a fresh clone re-reviews everything. That friction is
  accepted deliberately.
- **Inline pragmas — rejected.** Same editability as `.svignore`, no expiry,
  no review surface. Nothing in a source file may suppress its own finding.

Suppressed findings are always reported as counts, and an unsuppressed view
is always available. Silence about suppression would be a scanner overstating
its own coverage — the exact failure ADR-0017 §2 forbids.

### 8. Marker format: random, non-authorizing, value-blind

The durable marker is `[SV:LOC:v1:<random-opaque-id>]`. The id is random,
carries **no authority**, and encodes **no category and no value-derived
digest**. A marker that revealed `stripe_secret_key` would tell an attacker
reading the repo — or its history — exactly what to hunt for and, with the
commit timestamps, where to hunt. The category-to-occurrence mapping lives
only in the vault registry, where markers are resolved.

Honest limit: marker *placement* itself still reveals that a redaction
happened there and what its contextual meaning probably is. No marker format
eliminates that, and this ADR does not claim to.

Unknown or forged markers — ids that resolve to nothing in the registry —
are **flagged**, never silently trusted. An existing marker is never
re-redacted, and a marker is never itself a finding (ADR-0017 §4
idempotence).

### 9. Audit actions, and what a verified chain proves

Seven new `AuditAction` variants record the loop end to end: `ScanRun`,
`ScanStore`, `ScanReveal`, `PlanCreate`, `PlanApprove`, `PlanExecute`,
`RedactionRestore`. They are appended at the end of the enum so existing
serialized logs continue to parse.

The chain-verify banner is labelled **"log integrity verified"** and nothing
stronger. A valid HMAC chain proves the log was not tampered with — and
nothing else. It is not evidence that any remediation was correct, that any
approval was informed, or that anyone reviewed anything. The wording must not
imply otherwise.

### 10. Delivery order as the safety argument

P0 — opaque preview defaults and the audit actions.
P1 — Logs page.
P2 — Scans page and triage.
P3 — these ADRs.
P4 — `PublicLocator` and `DiscoveryPolicy` in `sv-runtime` (ADR-0016).
P5 — `sv-remediate` plan, verify, and dry-run diff, writing nothing.
P6 — journalled atomic write, `RecoveryRecord`, and restore;
feature-flagged, dry-run as the default.

The ordering *is* the safety argument: everything read-only lands before
anything that can write to a file the vault does not own. By the time the
first mutating commit exists, its plan format, verification, approval
surface, and audit trail have already shipped and been exercised.

## Consequences

- **Positive.** Approval is bound to an exact snapshot; a file that changed
  between review and execution fails closed instead of being edited under a
  stale approval.
- **Positive.** The trust split — `.svignore` proposes, vault state decides —
  means repository contents can never silently suppress their own findings.
- **Positive.** The zero default turns approval into an affirmative,
  per-occurrence act, and the measured basis for it is recorded rather than
  asserted.
- **Positive.** Leading with rotate/revoke matches the remedy to the actual
  threat for exposed credentials instead of performing containment and
  calling it a fix.
- **Negative.** Suppression does not travel with the repo; a fresh clone
  re-reviews everything. The friction is accepted on purpose.
- **Negative.** The quiescent-file requirement is an operator burden, and a
  real race window against non-cooperating writers remains (§3).
- **Negative.** Keyed digests make plan files unverifiable without the vault
  key: debugging a digest mismatch requires the vault unlocked. Accepted; the
  alternative reopens the brute-force channel.
- **Negative.** The write path arrives behind a feature flag with dry-run as
  the default, which delays the user's stated goal further — a continuation
  of ADR-0017's sequencing, not a departure from it.

### Thesis claims this decision does *not* support

Per `AGENTS.md`, stating the boundary is part of the decision. This work does
**not** establish:

- that scanning finds all secrets — recall remains bounded and unmeasured;
  ADR-0017's limit stands unchanged;
- any semantic, embedding-based, vector-index, or RAG capability;
- any OS-level isolation of scanned or remediated material;
- that redaction removes data from Git history, backups, or copies made
  before the scan — §6 exists precisely because it does not;
- that the credit-card false-positive measurement generalizes — it is a
  statement about one class and must not be read as a false-positive rate for
  other classes or for high-confidence findings as a whole;
- that a verified audit chain is evidence that a remediation decision was
  correct — it is evidence only that the log was not tampered with.

## Alternatives considered

- **Unkeyed digests in the plan.** Rejected. A plain hash of a small-domain
  value is brute-forceable back to the value; the digest would protect
  nothing.
- **Put the raw values in the plan file.** Rejected. The plan would become a
  plaintext secrets store on disk — the outcome the whole feature exists to
  eliminate — and reviews would leak material to any log that echoes the
  plan.
- **Preselect high-confidence findings.** Rejected. The measured campaign
  shows volume dominated by documentation, artifacts, and chance checksum
  passes; preselection on that signal manufactures consent at scale and
  trains the user to approve without reading.
- **Inline suppression pragmas in source files.** Rejected. Same
  editability as `.svignore` with no expiry and no review surface; nothing in
  a scanned file may decide what the scanner reports about it.
- **Category- or rule-encoding markers.** Rejected. A marker naming its rule
  is an attacker oracle in the repo and its history; the registry already
  holds the mapping, and the marker does not need to.
- **Treat the cooperative lock plus atomic replace as transactional safety.**
  Rejected as an overclaim. The race window between verify and replace is
  real; it is disclosed in §3 rather than designed around rhetorically.
- **Make multi-file runs transactional.** Rejected, consistent with
  ADR-0017: not achievable over an ordinary filesystem for an arbitrary user
  directory. Per-file atomicity plus a resumable journal is the honest
  guarantee.

## References
- Extends the mutation specification of
  [ADR-0017](0017-project-scanning-and-remediation-boundary.md), whose §4
  sketch this ADR turns into a plan format, an execute algorithm, and a trust
  model, and whose §2 amendment (opaque previews) this ADR assumes.
- Consumes the locator and `DiscoveryPolicy` decisions of
  [ADR-0016](0016-durable-public-locators-and-discovery-policy.md); §8's
  markers resolve through that registry and P4 delivers its types.
- Keyed-digest reasoning and the auditability posture follow
  [ADR-0010](0010-privacy-mediation-layer.md).
- The rule that no signal substitutes for human consent is
  [ADR-0013](0013-sensitivity-classifier-adaptive-consent.md)'s, applied here
  to confidence scores.
- Brokered reveal of recovered material sits on the sequencing fixed by
  [ADR-0015](0015-runtime-mediation-stack.md).
- Rule-pack versions pinned into plans are the versioned vocabulary of
  [ADR-0018](0018-jurisdiction-pattern-packs.md).
