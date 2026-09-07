# Runtime Mediation Implementation Roadmap

## 1. Delivery principles

- Preserve current vault/MCP behavior while extracting common policy.
- Land one testable vertical slice at a time.
- Keep all new network/process surfaces default-off.
- Do not update thesis capability claims until implementation and required
  evaluation are complete.
- Every security-relevant change includes regression tests and threat-model
  updates.
- New dependencies require license/advisory/supply-chain review under
  `deny.toml`.

## 2. Target workspace layout

```text
crates/
  sv-runtime/
    policy/
    references/
    consent/
    audit/
    mediation/
  sv-llm-gateway/
    openai/
    anthropic/
    sanitize/
    stream/
    routes/
  sv-mcp-router/
    local/
    external/
    namespace/
    result_filter/
  sv-process-broker/
    profiles/
    injection/
    spawn/
    output_filter/
  sv-protocol-fixtures/       # test/dev only if a separate crate is justified
apps/
  cli/                        # new runtime/adapter/profile/policy commands
  desktop/                    # consent and configuration UI
docs/runtime/
```

Avoid an `adapters` Rust crate until shared behavior exists. Client adapters can
start as modules under `apps/cli/src/adapters/` while all policy remains in
`sv-runtime`.

## 3. Phase 0 — governance and baseline

ADR-0015 has been accepted. Its architectural constraints are fixed; the
remaining Phase 0 work prepares a trustworthy implementation baseline.

### Deliverables

- Obtain independent architecture/security/privacy review of accepted ADR-0015;
  substantive changes require an ADR amendment rather than silent drift.
- Repair the corrupted repository/index state before implementation.
- Record AnyModel/Codex provenance and license obligations.
- Freeze current `sv-mcp` behavior with characterization tests.
- Create a synthetic no-network provider/MCP/process fixture suite.
- Define feature flags and default-off configuration.
- Update the current threat model with a clearly planned section only after ADR
  acceptance.

### Exit gate

Clean Git history/worktree, working `cargo test --workspace`, dependency audit,
approved ADR, and deterministic baseline tests. No runtime feature code starts
before this gate.

## 4. Phase 1 — `sv-runtime` policy kernel

### Work packages

1. Canonical principal, destination, operation, fragment, and provenance types.
2. Strict TOML policy parser, validator, snapshot reload, and semantic diff.
3. Deny-overrides/elevation-only evaluator and effective-limit join.
4. Runtime integration with existing agent scopes and container modes.
5. Reference registry with session-only opaque references.
6. Consent canonicalization, one-shot grant, and injected consent provider.
7. Intent/outcome audit events backed by `sv-audit`.
8. No-op/synthetic adapter used only for unit/integration tests.

### Migration

Wrap one existing local `vault.read` path with runtime planning while retaining
current `sv-mcp` enforcement. Compare decisions in tests. Expand operation by
operation; do not remove existing gates until equivalence and negative tests
pass.

### Exit gate

All policy/reference/consent/audit invariants in `sv-runtime.md` pass without a
network listener. Existing MCP tests remain green.

## 5. Phase 2 — OpenAI gateway vertical slice

### Work packages

1. Authenticated loopback server and lifecycle tied to vault lock.
2. `POST /v1/responses`, non-streaming text only, local fixture provider.
3. Ingress text scan/redaction/pseudonymization.
4. Brokered provider transport with route policy and late-bound credential.
5. Egress text sanitizer and safe error mapping.
6. Streaming text with boundary-safe buffering.
7. Function-call accumulation, authorization, and continuation.
8. `POST /v1/chat/completions`, `/v1/models`, and health/diagnostics.

### Exit gate

Codex and a generic OpenAI client pass local conformance fixtures. Secret/PII
canaries do not reach the fixture provider or client output contrary to policy.
No client process contains a real provider key.

## 6. Phase 3 — MCP router

### Work packages

1. Compose existing `sv-mcp` local backend under router namespace.
2. Generic client stdio adapter and identity bootstrap.
3. External stdio server registration and process-profile launch.
4. Tool discovery/schema hashing and change approval.
5. Argument mediation and result content-block filtering.
6. Resources/prompts mediation.
7. Remote HTTP MCP through broker destination controls.
8. Capability, timeout, crash, and circuit-breaker lifecycle.

### Exit gate

Generic MCP and supported clients expose only registered tools. Malicious MCP
fixtures cannot leak canaries, mutate schemas silently, escape limits, or
receive unrelated environment credentials.

## 7. Phase 4 — process broker

### Work packages

1. Strict profile schema/digest and trusted control-plane management.
2. Direct executable spawn with typed parameters and minimal environment.
3. Anonymous-pipe/stdin injection.
4. Output stream limits and sanitizer.
5. Executable identity, working-directory containment, cancellation, and child
   cleanup for Windows, Linux, and macOS.
6. Environment compatibility mode with explicit weaker label.
7. Optional temporary-file mode only after dedicated threat tests.
8. Representative provider/deploy/database/signing/MCP profiles.

### Exit gate

No API path accepts arbitrary shell strings. Secret canaries never appear in
argv, audit, logs, errors, or released output. Platform-specific tests document
what is and is not isolated.

## 8. Phase 5 — Anthropic and client adapters

### Work packages

1. Anthropic Messages non-streaming and streaming mappings.
2. Tool-use/tool-result and error/usage conformance.
3. Codex adapter detect/plan/apply/verify/status/remove/doctor.
4. Claude Code adapter and supported hooks.
5. OpenCode adapter and provider/MCP/hook probes.
6. Generic MCP packaging.
7. Coverage report covering the five exposure routes per client/version.

### Exit gate

Each supported version passes a clean-install fixture and publishes no silent
coverage gaps. Unsupported versions fail safely.

## 9. Phase 6 — hardening and release readiness

- Parser and canonicalization fuzzing.
- Adversarial bypass suite across gateway/router/broker/adapters.
- Rate/concurrency/load/cancellation/lock-race tests.
- Audit truncation/rollback/error-path tests.
- Dependency, license, SBOM, signing, and packaging review.
- Windows/Linux/macOS operational matrix.
- Performance evaluation with release builds and required independent sessions.
- Independent reviewers for methodology, security, and privacy.
- Threat model, architecture, user guide, and traceability updates based only on
  implemented/evidenced behavior.

## 10. Suggested CLI surface

```text
sovereign-vault runtime serve [--foreground]
sovereign-vault runtime status
sovereign-vault runtime lock

sovereign-vault policy validate|diff|activate|rollback|explain
sovereign-vault reference create|inspect|revoke
sovereign-vault provider add|test|enable|disable
sovereign-vault mcp-server add|inspect|approve-schema|disable
sovereign-vault profile add|validate|test|enable|disable
sovereign-vault process run <profile> --params <json>
sovereign-vault adapter detect|plan|apply|verify|status|doctor|remove
```

Commands that would print protected values require a separate explicit UX and
are not part of the runtime's simple path.

## 11. Configuration migrations

- Never auto-convert `.env` provider keys into active routes without user
  review.
- Import places values directly into encrypted vault storage, then reports and
  optionally removes legacy plaintext only through an explicit recoverable
  operation.
- Existing `ANYMODEL_ENV_FILE`/`.env.runtime` guidance is deprecated only after
  a working broker path exists.
- Adapter changes are planned/diffed before apply and retain rollback metadata
  without copying provider secrets.
- Policy/profile schema migrations are atomic and keep previous authenticated
  versions for rollback.

## 12. Definition of done per work package

Each package requires:

- code with `unsafe` forbidden;
- unit, integration, and relevant negative tests;
- no ambient real-network dependency;
- threat-model and component-doc update;
- stable safe errors and audit events;
- limits and cancellation behavior;
- license/advisory checks for new dependencies;
- executed `cargo test --workspace` and targeted release-mode validation;
- explicit list of unsupported fields/platforms and remaining bypasses.
