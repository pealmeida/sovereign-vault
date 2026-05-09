# ADR-0004 — Pluggable recovery provider

- **Status:** Accepted
- **Date:** 2026-05-08
- **Deciders:** pealmeida

## Context

Lost passphrase = lost data is brutal UX. Different users want different recovery trade-offs:

- A consumer wants something like "write down 24 words and stash them somewhere".
- A power user might split shares across trusted parties (Shamir).
- An enterprise wants hardware-token-based recovery.
- Some users want an opt-in encrypted backup in their own cloud storage.

We must not freeze v1.0 to a single recovery model.

## Decision

Define a `RecoveryProvider` trait in the `sv-recovery` crate. v1.0 ships exactly **one** implementation — a 24-word BIP39 phrase generated at first launch. The phrase wraps a copy of the master key stored in `recovery.svault`. Future providers (Shamir, hardware token, cloud-escrowed backup) plug in without breaking v1.0 vaults.

The trait signature is frozen in v1.0 so future providers are additive only.

## Consequences

- **Positive.** Extensible without breaking existing vaults. Recovery method choice is per-user, not per-codebase. Audit story: each provider can emit its own audit events for re-issuance.
- **Negative.** Trait must be designed carefully now to accommodate Shamir (multiple independent shares) and hardware (interactive challenge-response). Premature abstraction risk.
- **Mitigation.** Validate the trait against three sketched implementations before freezing in M3: BIP39, Shamir-3-of-5, YubiKey-PIV. Adjust if any of them cannot be expressed cleanly.

## Alternatives considered

- **No recovery in v1.0.** Rejected: passphrase loss is too punishing without a fallback.
- **BIP39 only, no trait.** Rejected: locks v1.0 architecture; future Shamir/hardware adds would force breaking changes.

## References

- Design spec § 2 D14 — *Key recovery*.
