# ADR-0003 — `.svault-v2` chunked file format

- **Status:** Proposed (byte layout TBD in M2)
- **Date:** 2026-05-08
- **Deciders:** pealmeida

## Context

> **Implementation status (note):** this ADR is **Proposed** and the chunked
> `.svault-v2` format is **not yet implemented**. This repo currently seals files
> with **whole-file XChaCha20-Poly1305** (not AES-256-GCM — the AES reference
> below describes the original pre-extraction PoC, not the shipped code). The
> memory motivation still holds for the future chunked format.

v1.0 stores files up to 100 MB. The original PoC used whole-file AES-256-GCM envelopes, which require loading the full plaintext into memory before encrypting or decrypting. This is fine for credentials (KB-sized) but unworkable for the broader use case (financial documents, scans, images), especially on mobile devices with constrained memory.

## Decision

Define a chunked AEAD format, `.svault-v2`:

- **AEAD:** XChaCha20-Poly1305 (extended-nonce; misuse-resistant against random-nonce reuse at scale).
- **Chunk size:** 1 MB (configurable per-file; default 1 MB).
- **Per-file key:** random 32 bytes, generated at create time, wrapped by the master key (key wrap algorithm TBD in M2 — leading candidates: XChaCha20-Poly1305 with a label-domain-separated nonce, or AES-KW).
- **Framing:** TBD in M2 — must include magic bytes, format version (`u8`), key version (`u32`), wrapped file-key, IV/nonce-base, chunk count, then `[chunk_nonce_suffix || ciphertext || tag]` per chunk.
- **Streaming:** read/write APIs are streaming (no full-file buffering required).

Backwards compatibility: `.svault-v2` files carry an explicit `key_version: u32`. v1.1+ may rotate AEAD or KDF without breaking v1.0 vaults.

## Consequences

- **Positive.** Streaming I/O. Memory ceiling is one chunk + tag. Suitable for mobile. Per-chunk authentication catches partial corruption early.
- **Negative.** More complex than whole-file envelopes. Random-access reads still load full chunks (1 MB). Must define explicit framing and document it.
- **Mitigation.** ADR will be amended in M2 with the final byte layout, magic bytes, and reference encoder/decoder in `sv-crypto`.

## Open questions (resolve in M2)

- Exact byte layout and magic bytes.
- AEAD nonce strategy: per-chunk random suffix vs. counter-based with deterministic IV.
- Filename privacy: cleartext (v1.0) vs. encrypted (deferred to v1.1, "ANONYMIZED" mode).

## References

- Design spec § 2 D13 — *File size + format*.
- Design spec § 8 — *Open questions*.
