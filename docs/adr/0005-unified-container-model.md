# ADR-0005 — Unified container model

- **Status:** Accepted (carry-forward from `agentic-sovereign-ecosystem`)
- **Date:** 2026-05-08
- **Deciders:** pealmeida

## Context

Earlier iterations of the PoC distinguished three concepts:

1. The single root **Vault** (one per OS user).
2. **Sub-Vaults** with a default security mode and "wholly encrypted" semantics.
3. **Folders** that organize files but have no default mode.

This produced four mental concepts (Vault, Sub-Vault, Folder, per-file mode) for what is, in practice, a derived view of one piece of state: each container's `security_mode`. Inheritance rules between Sub-Vault and nested Folder were ambiguous.

## Decision

Use a **single container type**. Every container has:

- A `security_mode` field (`DIRECT` | `APPROVAL` | `OTP` | `ANONYMIZED` (v1.1) | `ZKP` (v1.1)).
- An optional default for child files (`inherit_to_children: bool`).

UI rendering rules:

- `mode != DIRECT` → render with vault icon + colored mode pill ("sub-vault" appearance).
- `mode == DIRECT` → render with folder icon ("folder" appearance).

Backend treats them identically. Same code path, same on-disk layout (a directory with optional manifest rule).

## Consequences

- **Positive.** Three concepts → one. No inheritance ambiguity. Single API surface. Easier to reason about and test. UI-only distinction is cheap to evolve.
- **Negative.** Some users may expect "Sub-Vaults" to be a stronger isolation primitive (e.g. independent master key); v1.0 deliberately does not provide that. Document explicitly.
- **Mitigation.** README + threat model both clarify that "all containers share the same master key in v1.0; per-vault keys arrive in v2.0 if multi-vault demand surfaces".

## References

- Memory: `agentic-sovereign-ecosystem/.claude/.../memory/project_vault_unified_container_model.md`.
- Design spec § 2 D15 — *Multi-vault*.
