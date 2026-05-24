# ADR-0007 — Root key / data key hierarchy (the keyring)

- **Status:** Accepted
- **Date:** 2026-05-23
- **Deciders:** pealmeida

## Context

Today the master key — derived from the passphrase via Argon2id, or held in the OS keychain — **directly** seals every file in `sv-storage`. Two consequences fall out of this:

1. **Changing the passphrase requires re-encrypting the entire vault**, because the key that protects the data is the key derived from the passphrase.
2. **Key rotation is impossible** without re-encrypting everything. The 5-byte storage envelope header already reserves a 4-byte `key_version` (`sv-storage` writes `[fmt][key_version][sealed]`), but it is dead weight — there is only ever one key.

Both HashiCorp Vault/OpenBao (root key → keyring → data) and Bitwarden (Stretched Master Key → Protected Symmetric Key) independently converged on the same answer: **never let the user-derived key encrypt data directly.** Put a generated key in the middle.

This also unifies custody. Today the keychain stores the master key, the BIP39 recovery bundle separately wraps a copy of the master key, and a passphrase derives the master key. These are three ad-hoc paths to the *same* secret. A single indirection layer turns them into N independent wraps of one data key.

## Decision

Introduce a two-layer key hierarchy.

- **Data Encryption Key (DEK)** — a random 32-byte XChaCha20-Poly1305 key generated once at vault init. **All file envelopes are sealed with the active DEK.** The DEK is versioned; the envelope `key_version` selects which DEK version sealed a given file.
- **Custody wraps** — the DEK is never stored in the clear. Each custody method independently wraps (seals) the active DEK and stores the wrapped blob:
  - OS keychain: a Key-Encryption-Key (KEK) lives in the keychain; `keyring.svault` holds `seal(KEK, DEK)`.
  - Passphrase: KEK = `Argon2id(passphrase, salt)`; same wrapped-DEK entry, different KEK source.
  - Recovery (BIP39 today; Shamir later per [ADR-0004](0004-pluggable-recovery-provider.md)): `recovery.svault` holds `seal(recovery_key, DEK)`.

A new `keyring.svault` stores the wrapped DEK(s) and metadata: `{ active_version, min_decryption_version, entries: [{ version, wrapped_by_kek_b64 }] }`.

**Rotation** (closes the roadmap gap): generate DEK v(n+1), set it active, re-wrap it under every custody method, and bump `key_version` on subsequent writes. Old files keep decrypting via their recorded `key_version` so long as that version is ≥ `min_decryption_version` (the Vault-transit "working set" idea — raising `min_decryption_version` retires old ciphertext access without a bulk rewrite). Optional lazy rewrap on next write migrates files forward.

**Passphrase change** becomes O(1): re-derive the KEK, re-wrap the DEK, rewrite `keyring.svault`. No file is touched.

## Migration (existing vaults — no re-encryption)

Critical: existing vaults have files already sealed with the master key, and no `keyring.svault`. On unlock, if `keyring.svault` is absent:

1. Treat the current master key **as DEK v1** (existing files were sealed with it — they must keep decrypting).
2. Generate a fresh KEK from the existing custody source (new keychain entry, or re-derive from the same passphrase + a new salt).
3. Write `keyring.svault` = `seal(KEK, DEK_v1)`; replace the keychain's stored *master key* with the *KEK*.
4. The existing `recovery.svault` already wraps the master key (= DEK v1), so recovery continues to work unchanged.

This migration re-encrypts **zero** file data — only the small keyring blob is written. It is idempotent (guard on `keyring.svault` presence) and must be covered by a test that opens a pre-migration vault fixture, migrates, and reads a file sealed under the old scheme.

## Consequences

- **Positive.** Passphrase change and key rotation become O(1) metadata operations. `key_version` becomes meaningful. Custody methods unify into independent wraps of one DEK, simplifying [ADR-0004](0004-pluggable-recovery-provider.md) Shamir/hardware additions (each is just another wrap). Unblocks an audit-log HMAC subkey derived from the DEK (see audit hardening, P3) and the `.svault-v2` work in [ADR-0003](0003-svault-v2-chunked-format.md).
- **Negative.** Adds a load-bearing `keyring.svault`; losing it (without recovery) bricks the vault just as losing the master key does today — but it is now the single most important file to back up. The migration path is a sharp edge: a bug there can make existing data unreadable.
- **Mitigation.** Write `keyring.svault` atomically (tempfile + rename, as `sv-storage` already does for files). Keep all retired DEK versions in the keyring until `min_decryption_version` is explicitly raised. Gate the whole change behind tests: round-trip rotate, passphrase-change-without-rewrite, and the pre-migration fixture above. Implement with TDD; do not delegate the migration blind.

## Alternatives considered

- **Keep the flat model, re-encrypt on rotation/passphrase change.** Rejected: O(vault size) per operation, and unsafe to interrupt (partial rewrite). Untenable as vaults grow.
- **Per-file random keys wrapped by the DEK (full envelope-per-file).** Deferred: finer-grained but more metadata; the chunked `.svault-v2` format (ADR-0003) is the better place to revisit per-object keys.

## References

- [ADR-0003](0003-svault-v2-chunked-format.md) — chunked storage format (consumes versioned DEK).
- [ADR-0004](0004-pluggable-recovery-provider.md) — recovery providers become DEK wraps.
- `docs/analysis/2026-05-23-reference-vault-improvements.md` § Priority 1.
- Vault transit working-set / `min_decryption_version`; Bitwarden Protected Symmetric Key.
