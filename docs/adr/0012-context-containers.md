# ADR-0012 — Context containers, on-device embedding index, and privacy-filtered RAG egress

- **Status:** Proposed
- **Date:** 2026-07-31
- **Deciders:** pealmeida

## Context

The thesis reference architecture (§3.6) and the evolution roadmap
([EVOLUTION.md](../thesis/EVOLUTION.md)) define Phase 2 as the
generalisation from *secrets/credentials* to *context* — documents, notes,
e-mail, and other textual data that a personal AI agent retrieves to ground
its responses (§2.1, §2.3). The current artifact operates exclusively in the
secrets domain: every container holds opaque files accessed by name, and the
MCP tool surface (`vault.read`, `vault.write`, `vault.list`)
assumes the agent already knows which file it needs.

Phase 2 requires three new capabilities that the current architecture is
intentionally shaped to receive:

1. **Context containers** — a container kind whose files are text/chunks
   rather than credentials, with different access patterns (search, not
   point-read).
2. **On-device vector index + retrieval** — local embeddings and approximate
   nearest-neighbour (ANN) search so the agent can ask *"what do I have about
   X?"* without shipping all documents to a cloud embedding service (Lewis et
   al. 2020, RAG; Kleppmann 2019, local-first).
3. **Privacy filter on RAG egress** — the `sv-privacy` crate already sits at
   the gateway egress boundary ([ADR-0010](0010-privacy-mediation-layer.md));
   retrieved chunks must pass through it before they leave the vault, so the
   external model never sees unmasked PII even from documents.

The thesis itself scopes the instantiation to secrets (§3.5: *"operando no
controle de credenciais e segredos locais como representação empírica da
proposta"*) and lists context containers as the natural body of follow-on
work. This ADR designs that follow-on work so it slots into the existing
four-module architecture without redesign.

## Decision

Three new pieces, all gated behind a Cargo feature flag (`context-containers`)
so the secrets-domain artifact is unchanged until the feature is stabilised.

### 1. Context containers in `sv-storage`

A new container kind, `ContainerKind::Context`, stored alongside the existing
`ContainerKind::Standard` (the current secrets containers). The on-disk
representation reuses the existing envelope format (`sv-storage`), the same
AEAD encryption (`sv-crypto`), and the same manifest schema with one
extension field:

```rust
// sv-storage/src/lib.rs (sketch)
pub enum ContainerKind {
    Standard,  // existing: secrets/credentials
    Context,   // new: documents, notes, chunks
}
```

A `Context` container differs from a `Standard` container in three ways:

- **Content model.** Files are UTF-8 text documents, not arbitrary bytes.
  Binary files are rejected on write (return error; documented limitation).
- **Index maintenance.** On every `vault.write` to a `Context`
  container, the storage layer emits a `IndexInvalidated` event (see §2).
  The index is rebuilt lazily on the next search.
- **Security modes.** `Context` containers support `DIRECT`, `APPROVAL`,
  `OTP`, and `ANONYMIZED` — the same modes as `Standard` containers. The
  consent gate (`sv-mcp`) treats them identically: `APPROVAL`/`OTP` raise a
  desktop prompt; `DIRECT` does not; `ANONYMIZED` auto-allows and masks on
  egress.

**Why not a separate container type in the manifest schema?** The unified
container model ([ADR-0005](0005-unified-container-model.md)) already
demonstrates that varying behaviour by a discriminator field is lower-churn
than adding a parallel type hierarchy. `ContainerKind` extends that pattern.

### 2. On-device embedding + ANN index (`sv-storage`, new module)

A new module `sv-storage::index` provides:

- **Embedding.** A lightweight, pure-Rust embedding pipeline that runs
  entirely on-device. The initial implementation uses a bundled
  quantised model (e.g., `all-MiniLM-L6-v2` ONNX via `ort` or a
  `fastembed`-style Rust crate) so there is **no network call** to an
  external embedding service. The model weights are downloaded once at build
  or first-run time and cached locally.
- **Chunking.** Documents are split into overlapping chunks (configurable
  size, default 512 tokens with 64-token overlap) using a simple
  sentence-boundary-aware splitter. Chunk metadata (source document path,
  chunk index, byte range) is stored alongside the embedding.
- **ANN index.** An in-memory approximate nearest-neighbour index (e.g.,
  HNSW via `hnsw_rs` or a brute-force cosine-similarity scan for small
  corpora) that is rebuilt from all documents in all `Context` containers
  when invalidated. The index is **not persisted to disk** in the initial
  implementation — it is rebuilt on vault unlock. This avoids storing
  embeddings (which could leak document content) in plaintext on disk; the
  source documents remain AEAD-encrypted in the vault.

**Index lifecycle:**

```
vault unlock → scan all Context containers → chunk → embed → build ANN index
write(Context) → invalidate index flag
next vault.search → rebuild index if flag is set → search
vault lock → drop index from memory
```

**Why not persist the index?** Persisting embeddings creates a secondary
data surface that must be encrypted and audited. Rebuilding on unlock is
acceptable for the single-user, single-machine scope (a few thousand
documents). If rebuild latency becomes a problem, a future ADR can add an
AEAD-encrypted index cache.

### 3. `vault.search` MCP tool + privacy-filtered egress (`sv-mcp`)

A new MCP tool exposed by `sv-mcp`:

```
vault.search(query: string, top_k?: number, container?: string) → SearchResult[]
```

Where `SearchResult` contains:

```jsonc
{
  "chunk_text": "…",          // the retrieved chunk (already privacy-filtered)
  "source_document": "…",     // relative path within the container
  "chunk_index": 0,
  "score": 0.87,              // cosine similarity
  "anonymized": true|false,   // whether PII was redacted from this chunk
  "pii_redactions": 3         // count of redacted spans
}
```

**Egress path (the key design decision):**

```
agent calls vault.search("project X credentials")
  → sv-mcp::call_tool
    → enforce_scopes (agent must have read scope on the container)
    → consent gate (APPROVAL/OTP if the container requires it)
    → sv-storage::index::search (embed query → ANN → top-k chunks)
    → for each chunk: decrypt source document (sv-crypto)
    → for each chunk: sv-privacy::redact(chunk_text, policy)  ← THE FILTER
    → assemble SearchResult[] with redacted text
    → audit log entry (event.action: "search", event.container, event.mode,
       event.detail: "returned N chunks, M PII spans redacted")
    → return to agent
```

The privacy filter (`sv-privacy`) is applied **after** retrieval and
**before** the response crosses the agent boundary — exactly where it
already sits for `ANONYMIZED` reads ([ADR-0010](0010-privacy-mediation-layer.md)).
This means:

- For `DIRECT`/`APPROVAL`/`OTP` `Context` containers: the filter is **not**
  applied (the human already approved the release of raw content).
- For `ANONYMIZED` `Context` containers: the filter **is** applied to every
  chunk, and the response carries `anonymized: true` with per-chunk
  redaction counts.
- The filter runs on *chunks*, not whole documents, so the latency cost is
  proportional to `top_k × chunk_size`, not total document size. This is a
  meaningful optimisation for large document collections.

**Stateless-cloud contract (thesis §2.3).** The `vault.search` tool
description (exposed via `tools/list`) includes a usage note:

> The returned chunks have been privacy-filtered according to the container's
> security policy. The calling model MUST NOT retain or log chunk text beyond
> the current conversation turn. The vault does not store query history.

This is a convention, not a technical enforcement, but it is consistent with
the thesis's position that the vault is the *sovereign* boundary and the
model is an untrusted external processor.

### Feature flag and crate impact

| Crate | Change | Gated by |
|---|---|---|
| `sv-storage` | `ContainerKind::Context`, `index` module (embedding, chunking, ANN) | `context-containers` |
| `sv-mcp` | `vault.search` tool, search egress path with privacy-filter integration | `context-containers` |
| `sv-privacy` | No changes — already exposes `redact(&str, &Policy) -> Redaction` | — |
| `sv-audit` | New audit action variant `Search` in `AuditAction` enum | — |
| `sv-crypto` | No changes — decrypts chunks as it decrypts files today | — |
| `apps/desktop` | UI for creating `Context` containers; search-result display (future) | `context-containers` |
| `apps/thesis-eval` | New subcommand `rag-latency` for Phase 2 evaluation (future ADR) | `context-containers` |

## Consequences

- **Positive.**
  - Realises the Phase 2 vision of [EVOLUTION.md](../thesis/EVOLUTION.md):
    the same gateway + mediation + HITL pattern generalises from secrets to
    context without architectural redesign.
  - The privacy filter reuses `sv-privacy` unchanged — the filter was
    designed for exactly this egress boundary, and this ADR proves that
    design decision was correct.
  - On-device embeddings mean no document text ever leaves the machine for
    indexing; the external model sees only filtered chunks. This is the
    strongest form of the local-first contract (§2.1, §2.3).
  - The `vault.search` tool is a natural MCP primitive: agents already use
    `vault.read` for point reads; `vault.search` adds retrieval when
    the agent does not know which file to read.
  - Feature-gated: zero impact on the secrets-domain artifact until
    stabilised.

- **Negative.**
  - Embedding model weights add a binary dependency (~40–90 MB for a
    quantised MiniLM model). This must be documented and the download must
    be opt-in (lazy, on first `vault.search`).
  - Index rebuild on every unlock is O(N) in document count. For the
    single-user scope this is acceptable; for larger corpora it will need an
    encrypted index cache (future ADR).
  - Chunk-level filtering means PII that spans a chunk boundary may be
    partially masked. Overlapping chunks mitigate this but do not eliminate
    it. Document the limitation.
  - The `ANONYMIZED` filter on search results is a *per-chunk* operation;
    the latency cost scales with `top_k × chunk_size`. The evaluation
    harness will need a `rag-latency` subcommand to measure this (future
    work, listed in [EVOLUTION.md](../thesis/EVOLUTION.md) Phase 1).
  - `vault.search` is a new tool surface; it must be added to the scope
    system (agents need `search` scope on `Context` containers) and the
    adversarial battery ([ADR-0011](0011-dsr-evaluation-harness.md)).

- **Mitigation.**
  - Keep the embedding model small and quantised; document the size and
    provenance.
  - Set a reasonable `top_k` default (10) and maximum (50) to bound filter
    latency.
  - Overlap chunks by ≥64 tokens to reduce boundary-split PII risk.
  - Add `vault.search` probes to the adversarial battery in a follow-on ADR
    (prompt injection asking the agent to search for secrets, path traversal
    in the `container` parameter, oversized `top_k`).
  - The feature flag stays `context-containers` (not default) until the
    index rebuild latency and embedding model distribution are validated.

## Alternatives considered

- **Ship documents to a cloud embedding service (OpenAI Embeddings,
  Cohere).** Rejected: this violates the local-first contract (§2.1) and
  would require sending raw document text to a third party before the
  privacy filter runs. The thesis's entire argument is that data should not
  leave the device unmediated.
- **Add a separate `sv-rag` crate.** Rejected for now: the embedding + ANN
  logic is tightly coupled to `sv-storage` (it indexes the vault's own
  containers). A separate crate would create a circular dependency or an
  awkward trait abstraction. If the index grows complex enough to warrant
  its own crate, it can be extracted later.
- **Use the existing `vault.read` + agent-side chunking.** Rejected:
  this would require the agent to read entire documents to search them,
  which (a) defeats the purpose of retrieval, (b) sends full documents
  through the gateway, and (c) cannot benefit from ANN indexing.
- **Persist embeddings in plaintext.** Rejected: embeddings can be inverted
  to recover document content (Morris et al. 2023). Rebuilding on unlock
  avoids this risk entirely.
- **Make `vault.search` a separate MCP server.** Rejected: the search tool
  needs access to the same vault, the same scope system, the same consent
  gate, and the same audit log. Running it in-process with `sv-mcp` is
  simpler and keeps the security boundary unified.

## References

- Thesis §2.1 (RAG, Lewis et al. 2020; local-first, Kleppmann 2019), §2.3
  (context substrate vision), §2.4 (future work), §3.6 (module 3b — privacy
  filter at egress boundary).
- [EVOLUTION.md](../thesis/EVOLUTION.md) Phase 2 — the four items
  this ADR addresses: context containers, on-device vector index,
  privacy-filtered RAG egress, and the stateless-cloud contract.
- [ADR-0010](0010-privacy-mediation-layer.md) — the privacy filter this ADR
  reuses at the RAG egress boundary.
- [ADR-0011](0011-dsr-evaluation-harness.md) — the evaluation harness that
  will need a `rag-latency` extension.
- [ADR-0005](0005-unified-container-model.md) — the unified container model
  that `ContainerKind` extends.
- [ADR-0008](0008-per-agent-identity.md) — per-agent scopes that will govern
  `vault.search` access.
- Morris, J. X., et al. (2023). "Text Embeddings Reveal (Almost) As Much As
  Text." — motivates not persisting embeddings in plaintext.
