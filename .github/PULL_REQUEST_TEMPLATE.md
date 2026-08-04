<!-- Thanks for contributing to Sovereign Vault! -->

## What & why

<!-- Describe the change and the motivation. Link any issue: Closes #123 -->

## Checklist

- [ ] Conventional Commit title (e.g. `fix(mcp): …`, `feat(ui): …`)
- [ ] `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings` pass
- [ ] `cargo test --workspace` passes; new behavior has tests
- [ ] `cd ui && npm run check` passes (if UI changed)
- [ ] Docs updated (README / docs/ / ADR) if behavior or interfaces changed
- [ ] If this affects the threat model, [`docs/threat-model.md`](../docs/threat-model.md) is updated
- [ ] No secrets, personal paths, or machine-local config committed

## Security impact

<!-- Does this touch crypto, keys, the audit log, MCP scopes, or the broker?
     If yes, explain the impact. If no, write "none". -->
