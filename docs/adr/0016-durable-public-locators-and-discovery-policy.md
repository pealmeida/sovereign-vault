# ADR-0016 — Durable public locators and the discovery-policy gate

- **Status:** Proposed
- **Date:** 2026-09-06
- **Deciders:** pealmeida

## Context

[ADR-0010](0010-privacy-mediation-layer.md) masks PII on *egress*: a value
detected by `sv-privacy` is replaced with `[REDACTED:<LABEL>]` in the response
that crosses the agent boundary. That placeholder is deliberately anonymous and
one-way. It names a category and nothing else, so nothing can be asked of it
later.

A new use case breaks that assumption. The user wants to scan their own project
directories, move the secrets and personal data found there *into* the vault,
and leave the working files rewritten so that the sensitive bytes are gone but
the material remains **findable**: an agent that encounters the rewritten file
must be able to ask the vault for access to what used to be there, and a human
must be able to recover it. `[REDACTED:EMAIL]` cannot support that. It carries
no identity.

The obvious move — write a `ReferenceToken` into the file — is wrong, and the
reason is a lifetime mismatch rather than a cryptographic one.
`sv-runtime::references::ReferenceToken` (see
[ADR-0015](0015-runtime-mediation-stack.md)) is an *authorization* artifact. It
is bound to a principal and optionally a session, it expires, it counts uses
against `max_uses`, and it can be revoked. Those properties are correct for a
handle passed inside one mediated operation and wrong for a marker that will sit
in a source file for years, be committed to Git, copied into a second checkout,
restored from a backup, and read by whoever opens the file next. A durable
marker that is also an authorization is an authorization that leaks by design.

A second candidate — write a content-addressed digest of the original value —
fails for two independent reasons. The values in scope have low-entropy
preimages: an email address, a CPF, a phone number, or a US SSN can be
enumerated offline against a published digest, so the digest is a disclosure of
the value rather than a substitute for it. And a digest is equal wherever the
value is equal, which correlates the same person or the same credential across
every repository, branch, and backup the marker reaches. Both are unacceptable
for a marker whose whole purpose is to be published into files.

There is also a gap in the existing policy vocabulary. `ExposureClass`
(`Raw < Transformed < ReferenceOnly < ExecuteOnly < NonExportable`, joined to
the most restrictive) governs *what form* a resource may leave the vault in. It
does not state whether the **existence** of a resource may be disclosed at all.
Publishing a resolvable marker is precisely an existence disclosure: it tells
any reader of the file that a specific protected resource is registered in this
user's vault and can be requested. That question has to be answered explicitly
rather than inferred from a class that was designed to answer a different one.

## Decision

Introduce a durable **public locator** as a first-class type, distinct from
`ReferenceToken`, and gate its emission on a new explicit **discovery policy**.

### 1. `PublicLocator` — durable identity, zero authority

A new type in `sv-runtime::references`:

```text
[SV:LOC:v1:<base64url(32 random bytes)>]
```

- **Random, never derived.** The identifier is drawn from the CSPRNG. It is not
  a hash, digest, HMAC, or any function of the original value, so it cannot be
  attacked offline and reveals nothing about what it stands for.
- **Fresh per occurrence.** Two occurrences of the same value in two files, or
  in two places in one file, receive two unrelated locators. Equality of the
  underlying value is not observable from the markers.
- **Versioned.** The `v1` segment allows the format to change without ambiguity.
- **Not an authorization.** Possession of a locator conveys no access and no
  consent. It is an index key and nothing more.

The vault stores an encrypted, authenticated mapping from locator to
`InternalResourceId`. The mapping is vault-side; the file holds only the opaque
identifier.

### 2. Exchange, not resolution

A locator is never dereferenced directly. It is **exchanged**: the holder
presents it to the vault, the vault authenticates the principal, evaluates the
policy in force *now*, and — if the request is permitted — issues a freshly
scoped, expiring `ReferenceToken` for that resource. Every existing control
therefore applies at exchange time rather than at rewrite time.

Three consequences are load-bearing:

- **Exchange is not a bypass of revocation.** If the underlying resource is
  revoked, or the reference registry entry is revoked, exchange fails. A locator
  that is still legible in a file is not a resurrection path.
- **Exchange respects aggregate limits.** Re-exchanging a locator does not reset
  `use_count` or evade `max_uses` on the resource; the limits are properties of
  the resource, not of the handle issued for it.
- **"Request access" does not mean "receive bytes."** The exchanged token
  carries the resource's `ExposureClass` unchanged. For `ReferenceOnly`,
  `ExecuteOnly`, and `NonExportable` the successful outcome of an exchange is a
  handle usable only in the ways that class already permits — a broker
  operation, an execution profile — never plaintext delivered to the model.
  Exchange widens *discoverability*, never exposure.

### 3. `DiscoveryPolicy` — an explicit gate on existence disclosure

A new policy dimension, evaluated alongside `ExposureClass`, decides whether a
resolvable marker may be emitted at all:

- `Discoverable` — a `PublicLocator` may be written into the file.
- `Opaque` — the file receives the anonymous `[REDACTED:<LABEL>]` form of
  [ADR-0010](0010-privacy-mediation-layer.md); no public resolution path exists.

`NonExportable` resources default to `Opaque`. The default is deliberately
conservative: for a resource whose bytes may never leave the vault in any form,
advertising its existence in a file that will be committed and shared is a
disclosure with no corresponding benefit to the agent workflow.

`Opaque` removes *public* resolution, not *owner* recovery. The rewrite pipeline
records an encrypted, owner-side recovery record (see
[ADR-0017](0017-project-scanning-and-remediation-boundary.md)) for every
redaction, including opaque ones, so that redaction is never silent data loss.
The distinction is who can ask: an agent holding the file cannot, the vault
owner authenticating to their own vault can.

### 4. Durable markers carry no metadata

A locator is the identifier alone. No category label, no `SafeMetadata`
projection, no kind, no expiry is written into the file. This extends §5.5 of
[ADR-0015](0015-runtime-mediation-stack.md) — which already forbids exposing a
secret's length, prefix, suffix, vault path, checksum, or description — to the
durable on-disk form, where the exposure is permanent rather than
per-operation.

## Consequences

- **Positive.** A rewritten file becomes navigable: an agent can discover that
  protected material belongs at a position and can request it through the
  mediated path, while the file itself holds no secret bytes and no attackable
  function of them. The security decision moves from write time to exchange
  time, so policy changes, revocation, and expiry apply retroactively to markers
  already written into files.
- **Positive.** Separating `PublicLocator` from `ReferenceToken` keeps the
  authorization type's invariants intact. `ReferenceToken` remains
  short-lived, principal-scoped, and revocable precisely because it is never the
  thing written to disk.
- **Negative — position leaks purpose.** A locator on a line reading
  `stripe_key = "[SV:LOC:v1:...]"` tells the reader that a Stripe credential
  exists, regardless of the locator carrying no metadata. Source context,
  variable names, file paths, and directory layout are outside the marker's
  control and are not protected by it.
- **Negative — copies are provenance.** A marker copied to a second location
  reveals that the two locations reference the same resource, even though two
  independently generated markers for the same value do not. The scanner does
  not observe copies made after the rewrite.
- **Negative — history is not rewritten.** A file's Git history, existing
  backups, and any copy made before the scan still contain the original value.
  Redaction protects the working tree going forward; it does not retroactively
  scrub what already left. This must be stated plainly to the user, and must not
  be claimed otherwise in the thesis text.
- **Negative — a new durable format.** `[SV:LOC:v1:...]` becomes a
  compatibility surface. The `v1` segment is the mitigation, and the
  locator-to-resource mapping is vault state that now requires backup and
  recovery consideration alongside the vault itself.
- **Open.** `SafeMetadata.kind` remains a free `String`. A controlled vocabulary
  is desirable but is not decided here; it is a separate change to
  `sv-runtime::references`.

## Alternatives considered

- **Write the `ReferenceToken` into the file.** Rejected. It converts a
  short-lived, revocable authorization into a durable published one, and the
  properties that make it safe per-operation (expiry, use counting, principal
  binding) either become meaningless in a file or make the file break silently
  when they fire.
- **Write a content-addressed digest of the value.** Rejected on two grounds.
  The preimages in scope (email, CPF, CNPJ, phone, SSN, and many key formats)
  are low-entropy and enumerable offline, so the digest discloses the value. And
  digest equality correlates the same value across every file, repository, and
  backup it reaches, which is exactly the linkage the vault exists to prevent.
- **Keep `[REDACTED:<LABEL>]` and hold the mapping only in a sidecar file.**
  Rejected as the primary mechanism: the mapping is positional, so any edit that
  shifts offsets — a human editing the file, an agent reformatting it, a merge —
  silently corrupts it. An in-band identifier survives edits that a positional
  sidecar does not. A sidecar remains appropriate for the *recovery* record,
  which is owner-side and not required to survive third-party edits.
- **Derive the locator as an HMAC of the value under a vault key.** Rejected.
  It restores digest-style linkage (equal values yield equal locators) for no
  gain over a random identifier, and it makes every published marker a target
  tied to a single key whose compromise would relink the entire corpus.
- **Emit resolvable markers for every class and let exchange refuse.** Rejected.
  It treats existence disclosure as free. For `NonExportable` the refusal at
  exchange time still leaves a permanent published statement that the resource
  exists, which is the disclosure `DiscoveryPolicy` is introduced to control.

## References
- Extends the masking placeholder of [ADR-0010](0010-privacy-mediation-layer.md)
  with a resolvable form.
- Builds on the reference-registry primitives and the "reference, do not reveal"
  invariant of [ADR-0015](0015-runtime-mediation-stack.md) §5.5.
- Consumed by [ADR-0017](0017-project-scanning-and-remediation-boundary.md),
  which decides where scanning and rewriting live.
- Related to [ADR-0013](0013-sensitivity-classifier-adaptive-consent.md): both
  concern content-derived signals, and neither is a security control on its own.
