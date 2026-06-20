# Docs Index

Use this folder as the navigation hub for active work.

## Start here

- [`../README.md`](../README.md): product overview, install, and repo map.
- [`GETTING_STARTED.md`](./GETTING_STARTED.md): first local build and custody bootstrap flow.
- [`USAGE_REAL.md`](./USAGE_REAL.md): realistic operator workflow, agent pairing, backups, and `.env` migration.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md): crate/app boundaries, request lifecycle, and on-disk model.
- [`threat-model.md`](./threat-model.md): security assumptions and attack surface.

## Work lanes

- [`development/README.md`](./development/README.md): engineering track for implementation, ADRs, and validation.
- [`research/README.md`](./research/README.md): research track for thesis alignment, evaluation, and evolution planning.

## Canonical locations

- `adr/`: architectural decisions that change long-lived design boundaries.
- `testing/`: reproducible engineering test plans, manual validation suites, and behavior checklists.
- `thesis/`: thesis-facing traceability, evaluation, and paper artifacts.
- `archive/`: historical notes and superseded materials that should not drive current implementation work.

## Placement rules

- New feature design decisions go in `adr/` when they change the architecture or security boundary.
- New validation plans and run results go in `testing/`.
- New thesis-facing material goes in `thesis/` and should cross-reference code or ADRs.
- Old material moves to `archive/` instead of staying in the active path.
