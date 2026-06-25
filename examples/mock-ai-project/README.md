# Mock AI Provider Project

This is a small, offline mock project for validating Sovereign Vault in a
real-project shape without using real credentials. It is meant for demos,
feature-status checks, and MBA thesis evidence.

The project contains only fake keys in `.env.fake`. Do not replace them with
real provider keys.

## What It Validates

The live validator drives the same MCP path an AI agent uses:

- MCP tool discovery.
- Container creation for `DIRECT`, `APPROVAL`, `ANONYMIZED`, and `OTP`.
- Fake `.env` write/read round-trip.
- Approval-gated write behavior.
- PII masking on `ANONYMIZED` reads.
- OTP challenge behavior.
- Transit key create/encrypt/decrypt.
- Signing key create/sign/verify.
- Broker-secret creation and fail-closed behavior when `SV_ENABLE_BROKER=1`.

## Run The Mock App

This does not call any provider. It only confirms fake keys are present and
prints masked values.

```bash
node src/mock-provider-client.mjs
```

or:

```bash
npm run mock:app
```

## Validate Sovereign Vault Live Usage

Preconditions:

- Build the CLI: `cargo build -p sovereign-vault`.
- Open and unlock the Sovereign Vault desktop app.
- Approve desktop prompts raised during the run.
- Optional: relaunch Sovereign Vault with `SV_ENABLE_BROKER=1` to validate broker-secret creation.

Run from this directory:

```bash
npm run vault:validate
```

or from the repo root:

```bash
node examples/mock-ai-project/scripts/validate-sovereign-vault.mjs
```

Outputs are written to:

```text
target/mock-ai-project/<run-id>/feature-status.json
target/mock-ai-project/<run-id>/feature-status.md
```

Use `SV_MOCK_RUN_ID=<id>` to make the container names and output path stable.
Use `SV_MOCK_TIMEOUT_MS=<ms>` if desktop approvals need more time.
Use `SV_CLI=<path>` to test a specific `sovereign-vault` binary.

## Research Fit

This fixture is not a replacement for `apps/thesis-eval`. It is a live-project
validation companion:

- Use this fixture to show operational feature status with a realistic fake AI
  project.
- Use `cargo run --release -p thesis-eval -- all` for controlled latency and
  adversarial measurements.
- Attach the generated Markdown status table to the thesis evaluation appendix
  when you need reproducible live-project evidence.
