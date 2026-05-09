# ADR-0001 — Cargo workspace with layered crates

- **Status:** Accepted
- **Date:** 2026-05-08
- **Deciders:** pealmeida

## Context

Sovereign Vault must ship as: (1) a signed cross-platform desktop app, (2) reusable Rust libraries published to crates.io, and (3) future Tauri Mobile apps for iOS + Android. All three share security-critical primitives (encryption, key wrap, audit). A monolithic crate would make independent auditing of those primitives harder and prevent partial library publication.

## Decision

Use a Cargo workspace with eight layered crates under `crates/` plus three application targets under `apps/`:

- `sv-crypto`, `sv-storage`, `sv-keychain`, `sv-recovery`, `sv-audit`, `sv-mcp`, `sv-http`, `sv-core`
- `apps/desktop` (Tauri 2), `apps/cli`, `apps/mobile` (post-v1.0)
- `ui/` (Svelte 5 + Vite) is built once and embedded by both desktop and mobile

Workspace-wide dependency versions live in `[workspace.dependencies]` so every crate inherits the same revisions.

## Consequences

- **Positive.** Independent auditability of `sv-crypto`/`sv-keychain`/`sv-recovery`. Selective publication to crates.io. Mobile target reuses the entire Rust core. Faster compilation (crate-level parallelism + caching).
- **Negative.** More files at the repo root. Cross-crate refactors require touching multiple `Cargo.toml` files. New contributors must learn the layering.
- **Mitigation.** README and `CONTRIBUTING.md` document the layering. Workspace inheritance keeps versions in lock-step.

## Alternatives considered

- **Single crate, single binary.** Rejected: blocks library publication and makes the security-critical primitives less auditable.
- **Polyrepo from day 1.** Rejected: discoverability split kills OSS adoption when a single repo would suffice.

## References

- Design spec § 3 — *Repo + module layout*.
