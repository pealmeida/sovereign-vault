# Contributing to Sovereign Vault

Thanks for your interest. This project is an early release; expect rough edges and shifting APIs. PRs are welcome — please open a discussion first for non-trivial changes so we can align on direction.

## Ground rules

1. Be kind. See [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).
2. Security issues go through [SECURITY.md](./SECURITY.md), **not** the public issue tracker.
3. We follow the [design spec](https://github.com/pealmeida/agentic-sovereign-ecosystem/blob/main/docs/superpowers/specs/2026-05-08-sovereign-vault-oss-extraction-design.md). Material deviations need an Architecture Decision Record (ADR) under `docs/adr/`.

## Development setup

### Prerequisites

- Rust stable (≥ 1.88) with `rustfmt` + `clippy`
- Node.js 20+ (for the Svelte UI)
- Tauri 2 prerequisites — see <https://tauri.app/start/prerequisites/>

### Build & test

```bash
# Workspace check
cargo check --workspace

# Lints (must be clean before PR)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Tests
cargo test --workspace --all-features

# UI typecheck
( cd ui && npm ci && npm run check )
```

### Running the desktop app in dev mode

```bash
cargo tauri dev --manifest-path apps/desktop/src-tauri/Cargo.toml
```

This launches Vite at `http://localhost:1420`, then opens a Tauri window pointed at it. Hot-reload works for the Svelte UI; Rust changes require a restart.

## Code style

- **Rust**: `rustfmt` defaults. `clippy` clean. `unsafe` is forbidden at the workspace level (`#![forbid(unsafe_code)]`); reach out before proposing exceptions.
- **TypeScript / Svelte**: strict mode on. `svelte-check` clean.
- **Commits**: [Conventional Commits](https://www.conventionalcommits.org/). Examples:
  - `feat(sv-storage): add chunked file writer`
  - `fix(sv-mcp): reject unpaired tools/call before dispatch`
  - `docs(adr): add ADR-006 for key version field`

## Pull request checklist

- [ ] PR description explains the *why*, not just the *what*.
- [ ] Tests added or updated for new behaviour.
- [ ] `cargo fmt`, `cargo clippy`, `cargo test`, and `npm run check` all pass locally.
- [ ] No new public APIs without doc comments.
- [ ] No new dependencies without justification (security blast radius matters).
- [ ] If the change affects the threat model, `docs/threat-model.md` is updated (or a follow-up issue opened).

## Developer Certificate of Origin (DCO)

By contributing, you certify that you wrote the code or otherwise have the right to submit it under the project's Apache-2.0 license. Sign your commits with `git commit -s`. Each commit message will pick up a `Signed-off-by:` line; the contents read:

> *Developer Certificate of Origin 1.1 — see <https://developercertificate.org/>.*

We do not require a separate Contributor License Agreement (CLA).

## Reviewing PRs

Maintainers will:

- Triage within 5 business days.
- Aim for first substantive review within 10 business days.
- Prioritize bug fixes and security work over new features.

Slow reviews are not silent rejections; nudge the PR if it has gone quiet for two weeks.
