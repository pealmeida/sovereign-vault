# Development Track

This lane is for implementation work, verification, and operational hardening.

## Read in this order

1. [`../../README.md`](../../README.md)
2. [`../GETTING_STARTED.md`](../GETTING_STARTED.md)
3. [`../ARCHITECTURE.md`](../ARCHITECTURE.md)
4. [`../threat-model.md`](../threat-model.md)

## Active engineering references

- [`../testing/e2e-test-plan.md`](../testing/e2e-test-plan.md): broad end-to-end validation coverage.
- [`../testing/mcp-test-cases.md`](../testing/mcp-test-cases.md): MCP tool behavior matrix.
- [`../testing/ui-test-cases.md`](../testing/ui-test-cases.md): desktop/UI behavior checks.
- [`../testing/live-vault-safety-suite-2026-06-19.md`](../testing/live-vault-safety-suite-2026-06-19.md): latest live custody and MCP safety run.
- [`../adr/`](../adr/): design decisions that should stay stable across implementation iterations.

## Where to put new work

- Add implementation validation plans and result logs to `docs/testing/`.
- Add architecture decisions to `docs/adr/` when the system boundary or security model changes.
- Keep transient brainstorming out of the root; move superseded material to `docs/archive/`.

## Current focus areas

- Vault custody hardening and recovery reliability.
- Desktop approval UX and operator clarity.
- MCP behavior validation across all supported security modes.
