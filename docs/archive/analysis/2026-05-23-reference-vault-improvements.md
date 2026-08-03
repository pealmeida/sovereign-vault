# Reference-Vault Analysis → Sovereign Vault Improvements

Date: 2026-05-23
Sources: OpenBao, HashiCorp Vault, Bitwarden clients (security whitepaper + arch docs)

## Current state (recap)
- `sv-crypto`: XChaCha20-Poly1305 whole-file seal, Argon2id (`Params::DEFAULT`), zeroize.
- `sv-storage`: single `MasterKey` seals every file directly; `key_version=1` byte exists but **no rotation path**.
- `sv-keychain`: OS keychain or passphrase-derived KEK custody.
- `sv-recovery`: BIP39 phrase wraps the master key directly.
- `sv-audit`: plaintext JSONL, no hash chain, no rotation, paths/values in clear.
- `sv-mcp`: 5 tools, DIRECT/APPROVAL/OTP modes, pairing secret.

---

## Priority 1 — Key hierarchy / barrier (unblocks rotation & passphrase change)

**Borrowed from:** OpenBao "root key → keyring → data" barrier; Bitwarden "Stretched Master Key → Protected Symmetric Key".

**Problem today:** the passphrase/keychain-derived `MasterKey` *directly* seals every file. So:
- Changing the passphrase ⇒ re-encrypt the entire vault.
- Rotating the encryption key ⇒ re-encrypt the entire vault.
- `key_version` byte is dead weight because there is only ever one key.

**Change:** introduce two layers in `sv-crypto`/`sv-storage`:
1. **Root key (KEK)** — derived from passphrase (Argon2id) or held in OS keychain.
2. **Vault Data Key (DEK)** — random 32 bytes, generated once, **wrapped** by the root key and stored in a `keyring.svault`. Files are sealed with the DEK.

**Payoff:**
- Passphrase change = re-wrap the DEK only (O(1), not O(files)).
- Key rotation = add DEK v2, mark active, lazily/again-wrap old files; `key_version` byte becomes meaningful. Closes the "key rotation" gap and complements the planned `.svault-v2` chunked format (ADR-0003).
- Mirrors the model both Vault and Bitwarden converged on independently — strong validation.

---

## Priority 2 — Auth/verify separation + tunable, stored KDF params

**Borrowed from:** Bitwarden (Master Key vs Master Password Hash; KDF type+iterations stored per account, upgradeable; PBKDF2 600k / Argon2id).

**Problem today:** `Argon2::Params::DEFAULT` is hard-coded and not persisted. No way to (a) verify an unlock attempt without attempting a full decrypt, (b) raise cost factors later for existing vaults.

**Change:**
- Persist KDF descriptor in the manifest: `{ algo: argon2id, m, t, p, salt }`. Validate/upgrade on unlock.
- Store a separate **unlock verifier** (HMAC or a sealed sentinel) so a wrong passphrase is rejected fast and uniformly — don't rely on AEAD-open failure of a data file as the auth signal.
- Document chosen Argon2id cost vs Bitwarden's 600k PBKDF2 baseline.

---

## Priority 3 — Harden the audit log

**Borrowed from:** Vault audit devices — HMAC-SHA256 of sensitive string values; hash-chained integrity; list-response eliding.

**Changes to `sv-audit`:**
1. **Hash-chain** each entry (`prev_sha256`) — already on the roadmap; do it now, it's cheap and makes tamper-evidence real.
2. **HMAC sensitive fields** (container names, file names, request args) with a keyed hash instead of logging them in clear, so the audit log isn't itself a secrets-leak surface. Keep a `/audit-hash`-style helper to match a known value to its HMAC for investigations.
3. **Elide large list bodies** (store count, not the full key list) for `vault.list` responses.
4. Rotation/size cap so the 4.5 MB-and-growing log doesn't grow unbounded.

---

## Priority 4 — Time-bound, revocable access grants (leases)

**Borrowed from:** Vault leases/TTL + revocation; Bitwarden device-approval flow.

**Problem today:** APPROVAL/OTP appear to gate per-request with no concept of a grant that lives for a bounded window or can be revoked early.

**Change:** when a user approves MCP access, mint a **capability grant** `{ container, actions, expires_at, grant_id }`. The agent presents it on subsequent calls until it expires; the user can **revoke** a grant_id from the desktop UI. This is the foundation for the roadmap's "agent identity and capability tokens" and reduces approval fatigue without weakening control.

---

## Priority 5 — Recovery options beyond a single phrase

**Borrowed from:** OpenBao/Vault Shamir Secret Sharing; auto-unseal/recovery keys.

**Change:** keep BIP39 as default, but offer **Shamir split** of the recovery secret into N shares with threshold K (e.g. 2-of-3) so a user can distribute shares across guardians/devices. `sv-recovery` already abstracts a `RecoveryProvider` trait (ADR-0004) — add a `ShamirRecovery` impl alongside `Bip39Recovery`.

---

## SECURITY BUG (fix regardless of roadmap)

`crates/sv-mcp/src/lib.rs` `getrandom_fill` falls back to a deterministic LCG/splitmix seeded from time+pid when the OS RNG is unavailable. Any secret drawn through this path (pairing secrets, nonces, OTP) would be **predictable**. A vault must **fail closed** — return an error rather than emit attacker-guessable randomness. Verify whether this path feeds `fresh_pairing_secret`/OTP generation and remove the fallback.

---

## Suggested sequencing
1. Fix the PRNG fallback (small, security-critical).
2. Key hierarchy (P1) — unblocks rotation + cheap passphrase change; touches `sv-crypto`, `sv-storage`, `sv-recovery`.
3. Audit hardening (P3) — independent, low-risk.
4. KDF persistence/verifier (P2).
5. Leases (P4) and Shamir recovery (P5) as feature work.
